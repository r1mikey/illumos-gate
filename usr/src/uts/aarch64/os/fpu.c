/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 1992, 2011, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc. */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T   */
/*		All Rights Reserved				*/

/*	Copyright (c) 1987, 1988 Microsoft Corporation		*/
/*		All Rights Reserved				*/

/*
 * Copyright (c) 2009, Intel Corporation.
 * All rights reserved.
 */

/*
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2026 Michael van der Westhuizen
 */

/*
 * AArch64 FPU management.
 *
 * This implementation follows the same flag-driven design as the x86
 * FPU code (intel/os/fpu.c).  The key mechanisms are:
 *
 *   - fpu_flags on fpu_ctx_t drives all save/restore decisions.
 *   - Context-switch ctxops use exact flag equality checks so that
 *     FPU_VALID and FPU_KERNEL automatically suppress unwanted
 *     saves and restores.
 *   - PCB_UPDATE_FPU coordinates deferred reloads via the
 *     return-to-user path.
 *   - Lazy first-use: the FPU is disabled for new threads; the first
 *     FP instruction traps into fp_fenflt() which installs ctxops
 *     and enables the FPU.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/signal.h>
#include <sys/regset.h>
#include <sys/privregs.h>
#include <sys/psw.h>
#include <sys/trap.h>
#include <sys/fault.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/pcb.h>
#include <sys/lwp.h>
#include <sys/cpuvar.h>
#include <sys/thread.h>
#include <sys/disp.h>
#include <sys/siginfo.h>
#include <sys/archsystm.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/fp.h>
#include <sys/kfpu.h>

/* Forward declarations */
static struct ctxop *fp_ctxop_allocate(fpu_ctx_t *);

/*
 * Enable the FPU by setting CPACR_EL1.FPEN.
 */
static void
fpu_enable(void)
{
	write_cpacr_el1((read_cpacr_el1() & ~CPACR_FPEN_MASK) |
	    CPACR_FPEN_EN);
	isb();
}

/*
 * Disable the FPU by clearing CPACR_EL1.FPEN.
 */
static void
fpu_disable(void)
{
	isb();
	write_cpacr_el1(read_cpacr_el1() & ~CPACR_FPEN_MASK);
}

/*
 * Initialize the FPU hardware to a clean state: enable the FPU,
 * zero all V0-V31 registers, and load FPCR_INIT / FPSR=0.
 */
static void
fpinit(void)
{
	static const kfpu_t zeroed = {
		.kfpu_cr = FPCR_INIT,
		.kfpu_sr = 0
	};

	fpu_enable();
	fp_restore_hw((kfpu_t *)&zeroed);
}

/* ------------------------------------------------------------------ */
/*  Context-switch ctxop callbacks                                    */
/* ------------------------------------------------------------------ */

/*
 * Save FPU state on context switch out.
 *
 * The exact equality check (flags == FPU_EN) is critical:
 *   - FPU_EN only:                 save hardware state, set FPU_VALID
 *   - FPU_EN|FPU_VALID:            already saved, skip
 *   - FPU_EN|FPU_KERNEL:           kernel owns FPU, skip
 *   - FPU_EN|FPU_VALID|FPU_KERNEL: both set, skip
 *
 * The FPU is always disabled after save, matching x86 STTS behaviour.
 */
static void
fpsave_ctxt(void *arg)
{
	fpu_ctx_t *fp = (fpu_ctx_t *)arg;

	if (fp->fpu_flags == FPU_EN) {
		fp_save_hw(&fp->fpu_regs);
		fp->fpu_flags = FPU_EN | FPU_VALID;
	}
	fpu_disable();
}

/*
 * Restore FPU state on context switch in.
 *
 * The exact equality check (flags == FPU_EN|FPU_VALID):
 *   - Match:          state is in memory, load it and clear FPU_VALID.
 *   - FPU_EN only:    state is live in registers, nothing to do.
 *   - FPU_KERNEL set: kernel owns the FPU - kernel ctxop handles it.
 */
static void
fprestore_ctxt(void *arg)
{
	fpu_ctx_t *fp = (fpu_ctx_t *)arg;

	if (fp->fpu_flags == (FPU_EN | FPU_VALID)) {
		fpu_enable();
		fp_restore_hw(&fp->fpu_regs);
		fp->fpu_flags = FPU_EN;
	}
}

/*
 * Fork/lwp_create callback - copy FPU state to child.
 */
static void
fp_new_lwp(void *parent, void *child)
{
	kthread_id_t t = parent;
	kthread_id_t ct = child;
	pcb_t *pcb = &ttolwp(t)->lwp_pcb;
	pcb_t *cpcb = &ttolwp(ct)->lwp_pcb;
	fpu_ctx_t *fp = &pcb->pcb_fpu;
	fpu_ctx_t *cfp = &cpcb->pcb_fpu;

	/*
	 * If the parent is the current thread and has live hardware
	 * state (FPU_EN set, FPU_VALID clear), save it first.
	 */
	if (t == curthread && (fp->fpu_flags & FPU_EN) &&
	    !(fp->fpu_flags & FPU_VALID)) {
		fp_save(fp);
	}

	memcpy(&cfp->fpu_regs, &fp->fpu_regs, sizeof (cfp->fpu_regs));
	cfp->fpu_flags = FPU_EN | FPU_VALID;
	PCB_SET_UPDATE_FPU(cpcb);

	ctxop_attach(ct, fp_ctxop_allocate(cfp));
}

/*
 * Free callback -- mark state as saved and disable FPU.
 */
static void
fpfree_ctxt(void *arg, int isexec __unused)
{
	fp_free((fpu_ctx_t *)arg);
}

static struct ctxop *
fp_ctxop_allocate(fpu_ctx_t *fp)
{
	const struct ctxop_template tpl = {
		.ct_rev		= CTXOP_TPL_REV,
		.ct_save	= fpsave_ctxt,
		.ct_restore	= fprestore_ctxt,
		.ct_fork	= fp_new_lwp,
		.ct_lwp_create	= fp_new_lwp,
		.ct_free	= fpfree_ctxt
	};
	return (ctxop_allocate(&tpl, fp));
}

/* ------------------------------------------------------------------ */
/*  Public FPU API                                                    */
/* ------------------------------------------------------------------ */

/*
 * Save the current thread's live FPU state to the given fpu_ctx_t.
 * Sets FPU_VALID and PCB_SET_UPDATE_FPU so the state gets reloaded
 * before returning to userland.
 *
 * Guards:
 *   - FPU_VALID already set: already saved, skip.
 *   - FPU_EN not set: FPU not in use, skip.
 */
void
fp_save(fpu_ctx_t *fp)
{
	kpreempt_disable();

	ASSERT(fp != NULL);

	if ((fp->fpu_flags & FPU_VALID) ||
	    !(fp->fpu_flags & FPU_EN)) {
		kpreempt_enable();
		return;
	}

	ASSERT(curthread->t_lwp != NULL &&
	    fp == &curthread->t_lwp->lwp_pcb.pcb_fpu);

	fp_save_hw(&fp->fpu_regs);
	fp->fpu_flags |= FPU_VALID;
	PCB_SET_UPDATE_FPU(&curthread->t_lwp->lwp_pcb);

	kpreempt_enable();
}

/*
 * Restore FPU state from the given fpu_ctx_t into hardware.
 * Clears FPU_VALID (hardware is now authoritative).
 */
void
fp_restore(fpu_ctx_t *fp)
{
	if (!(fp->fpu_flags & FPU_VALID))
		return;

	fp_restore_hw(&fp->fpu_regs);
	fp->fpu_flags &= ~FPU_VALID;
}

/*
 * Initialize FPU for a new execution context (exec, first-use).
 * Installs ctxops, loads clean hardware state, sets FPU_EN.
 */
void
fp_exec(void)
{
	pcb_t *pcb = &ttolwp(curthread)->lwp_pcb;
	fpu_ctx_t *fp = &pcb->pcb_fpu;
	struct ctxop *ctx = fp_ctxop_allocate(fp);

	kpreempt_disable();
	ctxop_attach(curthread, ctx);

	bzero(&fp->fpu_regs, sizeof (fp->fpu_regs));
	fp->fpu_regs.kfpu_cr = FPCR_INIT;
	fp->fpu_regs.kfpu_sr = 0;
	fpu_enable();
	fp_restore_hw(&fp->fpu_regs);
	fp->fpu_flags = FPU_EN;

	kpreempt_enable();
}

/*
 * Mark FPU state as saved and disable FPU.  Called on thread teardown
 * and from restorecontext -> setfpregs.
 */
void
fp_free(fpu_ctx_t *fp)
{
	kpreempt_disable();

	fp->fpu_flags |= FPU_VALID;
	if (curthread->t_lwp != NULL &&
	    fp == &curthread->t_lwp->lwp_pcb.pcb_fpu) {
		fpu_disable();
	}

	kpreempt_enable();
}

/*
 * Install FPU ctxops on an LWP that has never used the FPU.
 * Called from setfpregs when a debugger writes FPU state to a thread
 * that has not yet executed any FP instructions.  Does not enable the
 * FPU or load any state -- the caller sets FPU_VALID and
 * PCB_UPDATE_FPU so the return-to-user path handles the reload.
 */
void
fp_lwp_init(klwp_t *lwp)
{
	fpu_ctx_t *fp = &lwp->lwp_pcb.pcb_fpu;

	ASSERT(!(fp->fpu_flags & FPU_EN));

	ctxop_attach(lwptot(lwp), fp_ctxop_allocate(fp));
	fp->fpu_flags |= FPU_EN;
}

/*
 * Handle FPU-disabled trap (first use or re-enable after kernel FPU).
 *
 * If FPU_EN is set, the thread has used the FPU before but it's
 * currently disabled (e.g., after a context switch or kernel_fpu_end).
 * Re-enable and restore if FPU_VALID is set.
 *
 * If FPU_EN is not set, this is the thread's first FPU use --
 * call fp_exec() to install ctxops and initialize.
 */
int
fp_fenflt(void)
{
	fpu_ctx_t *fp = &curthread->t_lwp->lwp_pcb.pcb_fpu;

	kpreempt_disable();

	if (fp->fpu_flags & FPU_EN) {
		/*
		 * Previously used FPU, currently disabled.
		 * Re-enable and restore saved state if present.
		 */
		fpu_enable();
		if (fp->fpu_flags & FPU_VALID) {
			fp_restore(fp);
		}
	} else {
		/*
		 * First FPU use by this thread.
		 */
		fp_exec();
	}

	kpreempt_enable();
	return (0);
}

/*
 * Return-to-user check: reload FPU state if PCB_UPDATE_FPU is set.
 * Called from the assembly return-to-user path when pcb_rupdate is
 * non-zero.
 */
void
pcb_return_check(void)
{
	pcb_t *pcb = &curthread->t_lwp->lwp_pcb;

	if (PCB_NEED_UPDATE_FPU(pcb)) {
		fprestore_ctxt(&pcb->pcb_fpu);
		PCB_CLEAR_UPDATE_FPU(pcb);
	}
}

/* ------------------------------------------------------------------ */
/*  Kernel FPU support                                                */
/* ------------------------------------------------------------------ */

/*
 * State-backed kernel FPU save area.  Allocated via kernel_fpu_alloc()
 * for callers that need FPU use to survive preemption or that run in
 * contexts where LWP-based modes are unsuitable (e.g., interrupt threads).
 */
struct kfpu_state {
	kfpu_t		kfps_regs;
	kthread_id_t	kfps_curthread;	/* thread currently using this state */
};

/*
 * Kernel FPU ctxop callbacks.
 * arg is NULL for KFPU_USE_LWP (saves to pcb_fpu).
 * arg is non-NULL for state-backed mode (saves to kfpu_state_t).
 */
static void
kernel_fpu_ctx_save(void *arg)
{
	kfpu_state_t *kfpu = arg;

	if (kfpu == NULL) {
		/* KFPU_USE_LWP: save to pcb_fpu */
		fpu_ctx_t *pf = &curthread->t_lwp->lwp_pcb.pcb_fpu;
		ASSERT(curthread->t_procp->p_flag & SSYS);
		ASSERT((pf->fpu_flags & FPU_VALID) == 0);
		fp_save_hw(&pf->fpu_regs);
		pf->fpu_flags |= FPU_VALID;
	} else {
		/* State-backed: save to kfpu's own area */
		fp_save_hw(&kfpu->kfps_regs);
	}

	fpu_disable();
	curthread->t_flag &= ~T_KFPU;
}

static void
kernel_fpu_ctx_restore(void *arg)
{
	kfpu_state_t *kfpu = arg;

	fpu_enable();

	if (kfpu == NULL) {
		/* KFPU_USE_LWP: restore from pcb_fpu */
		fpu_ctx_t *pf = &curthread->t_lwp->lwp_pcb.pcb_fpu;
		ASSERT(curthread->t_procp->p_flag & SSYS);
		ASSERT(pf->fpu_flags & FPU_VALID);
		fp_restore_hw(&pf->fpu_regs);
		pf->fpu_flags &= ~FPU_VALID;
	} else {
		/* State-backed: restore from kfpu's own area */
		fp_restore_hw(&kfpu->kfps_regs);
	}

	curthread->t_flag |= T_KFPU;
}

static const struct ctxop_template kfpu_ctxop_tpl = {
	.ct_rev		= CTXOP_TPL_REV,
	.ct_save	= kernel_fpu_ctx_save,
	.ct_restore	= kernel_fpu_ctx_restore,
};

void
kernel_fpu_begin(kfpu_state_t *kfpu, uint_t flags)
{
	struct ctxop *ctx;
	klwp_t *pl = curthread->t_lwp;

	if ((curthread->t_flag & T_KFPU) != 0)
		panic("curthread attempting to nest kernel FPU states");

	/* KFPU_USE_LWP and KFPU_NO_STATE are mutually exclusive. */
	ASSERT((flags & (KFPU_USE_LWP | KFPU_NO_STATE)) !=
	    (KFPU_USE_LWP | KFPU_NO_STATE));

	if (flags & KFPU_NO_STATE) {
		/*
		 * Short-burst kernel FPU use.  Caller must hold
		 * kpreempt_disable() across the begin/end pair.
		 */
		ASSERT(curthread->t_preempt > 0);
		ASSERT(kfpu == NULL);

		if (pl != NULL) {
			fp_save(&pl->lwp_pcb.pcb_fpu);
			pl->lwp_pcb.pcb_fpu.fpu_flags |= FPU_KERNEL;
		}

		curthread->t_flag |= T_KFPU;
		fpinit();
		return;
	}

	if (flags & KFPU_USE_LWP) {
		/*
		 * Kernel thread with LWP (SSYS) reusing pcb_fpu.
		 * Preemption is allowed -- the ctxop handles
		 * save/restore across context switches.
		 */
		fpu_ctx_t *pf;

		VERIFY(pl != NULL);
		VERIFY(curthread->t_procp->p_flag & SSYS);
		VERIFY(kfpu == NULL);

		pf = &pl->lwp_pcb.pcb_fpu;
		ASSERT((pf->fpu_flags & FPU_EN) == 0);

		ctx = ctxop_allocate(&kfpu_ctxop_tpl, NULL);
		kpreempt_disable();

		ctxop_attach(curthread, ctx);
		curthread->t_flag |= T_KFPU;

		fpinit();
		pf->fpu_flags = FPU_EN | FPU_KERNEL;

		kpreempt_enable();
		return;
	}

	/*
	 * State-backed mode.  Save user FPU state if present, install
	 * a kernel ctxop that saves/restores to kfpu's own save area,
	 * and load clean FPU state.  This mode works from any context
	 * (user thread, kernel thread, interrupt thread) and allows
	 * preemption -- the ctxop handles save/restore across context
	 * switches.
	 */
	VERIFY(kfpu != NULL);
	VERIFY((flags & (KFPU_NO_STATE | KFPU_USE_LWP)) == 0);

	ctx = ctxop_allocate(&kfpu_ctxop_tpl, kfpu);
	kpreempt_disable();

	if (kfpu->kfps_curthread != NULL) {
		panic("attempting to reuse kernel FPU state at %p when "
		    "another thread already is using", kfpu);
	}

	kfpu->kfps_curthread = curthread;

	if (pl != NULL) {
		fpu_ctx_t *pf = &pl->lwp_pcb.pcb_fpu;
		if (pf->fpu_flags & FPU_EN) {
			fp_save(pf);
			pf->fpu_flags |= FPU_KERNEL;
		}
	}

	ctxop_attach(curthread, ctx);
	curthread->t_flag |= T_KFPU;

	fpinit();

	kpreempt_enable();
}

void
kernel_fpu_end(kfpu_state_t *kfpu, uint_t flags)
{
	if ((curthread->t_flag & T_KFPU) == 0)
		panic("curthread attempting to clear kernel FPU state "
		    "without using it");

	if (!(flags & KFPU_NO_STATE)) {
		kpreempt_disable();
	} else {
		ASSERT(curthread->t_preempt > 0);
	}

	if (kfpu != NULL) {
		/*
		 * State-backed: remove the kernel ctxop and disable
		 * FPU.  We do not save the kernel FPU state back to
		 * kfpu, matching x86 behaviour, the kfpu API is
		 * not intended as a persistent save location across
		 * begin/end pairs.
		 * Clear FPU_KERNEL before kpreempt_enable so the
		 * flag state is consistent if we're preempted.
		 */
		if (kfpu->kfps_curthread != curthread) {
			panic("attempting to end kernel FPU state "
			    "for %p, but active thread is not "
			    "curthread", kfpu);
		}
		curthread->t_flag &= ~T_KFPU;
		ctxop_remove(curthread, &kfpu_ctxop_tpl, kfpu);
		fpu_disable();
		kfpu->kfps_curthread = NULL;
		if (curthread->t_lwp != NULL) {
			curthread->t_lwp->lwp_pcb.pcb_fpu.fpu_flags &=
			    ~FPU_KERNEL;
		}
		kpreempt_enable();
	} else if (flags & KFPU_USE_LWP) {
		/*
		 * USE_LWP: remove the kernel ctxop, disable FPU,
		 * and clear both FPU_EN and FPU_KERNEL before
		 * kpreempt_enable.
		 */
		curthread->t_flag &= ~T_KFPU;
		ctxop_remove(curthread, &kfpu_ctxop_tpl, NULL);
		fpu_disable();
		curthread->t_lwp->lwp_pcb.pcb_fpu.fpu_flags &=
		    ~(FPU_EN | FPU_KERNEL);
		kpreempt_enable();
	} else {
		/*
		 * NO_STATE: only disable the FPU for kernel threads
		 * that are not interrupt threads.  User threads keep
		 * FPU enabled so fpsave_ctxt can save on the next
		 * context switch.  The FPU_VALID flag prevents
		 * fpsave_ctxt from saving kernel-clobbered state
		 * over the user's saved state.
		 */
		curthread->t_flag &= ~T_KFPU;
		ASSERT(flags & KFPU_NO_STATE);
		if ((curthread->t_procp->p_flag & SSYS) != 0 &&
		    curthread->t_intr == NULL) {
			fpu_disable();
		}
		if (curthread->t_lwp != NULL) {
			curthread->t_lwp->lwp_pcb.pcb_fpu.fpu_flags &=
			    ~FPU_KERNEL;
		}
	}
}

/*
 * Validate that the thread is not switching off-cpu while actively
 * using the FPU within the kernel (KFPU_NO_STATE mode).
 */
void
kernel_fpu_no_swtch(void)
{
	if ((curthread->t_flag & T_KFPU) != 0)
		panic("curthread swtch-ing while the kernel is using "
		    "the FPU");
}

kfpu_state_t *
kernel_fpu_alloc(int kmflags)
{
	return (kmem_zalloc(sizeof (kfpu_state_t), kmflags));
}

void
kernel_fpu_free(kfpu_state_t *kfpu)
{
	kmem_free(kfpu, sizeof (kfpu_state_t));
}
