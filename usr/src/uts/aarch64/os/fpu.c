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
 * FPU Management for aarch64
 * ==========================
 *
 * Overview
 * --------
 *
 * The AArch64 FPU subsystem manages the SIMD/FP register file
 * (V0-V31, FPCR, FPSR) for both user threads and kernel consumers.
 * Access is controlled via CPACR_EL1.FPEN: when cleared, any
 * FP/SIMD instruction traps with T_SIMDFP_ACCESS.
 *
 * The implementation is flag-driven.  All save/restore decisions
 * are determined by three flags in fpu_ctx_t.fpu_flags:
 *
 *   FPU_EN      FPU has been enabled for this LWP; user ctxops
 *               (fpsave_ctxt/fprestore_ctxt) are installed.
 *               Note that this flag is set, and stays set, if
 *               the FPU has ever been enabled for this LWP, and
 *               does not reflect the current state of the
 *               CPACR_EL1.FPEN register bit.
 *
 *   FPU_VALID   FPU register state has been saved to fpu_regs
 *               and is authoritative.  Hardware may contain
 *               stale or kernel-clobbered data.  In other
 *               words, when this is set the FPU state is in
 *               memory, and when it is clear the authoritative
 *               state is live in the hardware registers.
 *
 *   FPU_KERNEL  Kernel owns the FPU.  Acts as an implicit
 *               barrier that suppresses user ctxops (discussed
 *               below).
 *
 *
 * User FPU Lifecycle
 * ------------------
 *
 * Lazy first-use:
 *   New threads start with fpu_flags=0 and CPACR.FPEN cleared.
 *   The first FP instruction traps (T_SIMDFP_ACCESS from EL0)
 *   into fp_fenflt(), which calls fp_exec() to install ctxops,
 *   zero the register file, and set FPU_EN.
 *
 * Steady-state:
 *   While the thread runs FP code, fpu_flags == FPU_EN and the
 *   hardware registers are authoritative (FPU_VALID is clear).
 *
 * Context switch out (fpsave_ctxt):
 *   Saves V0-V31/FPCR/FPSR to fpu_regs, sets FPU_VALID, then
 *   disables the FPU.
 *     FPU_EN -> FPU_EN|FPU_VALID
 *
 * Context switch in (fprestore_ctxt):
 *   Loads fpu_regs into hardware, clears FPU_VALID, enables FPU.
 *     FPU_EN|FPU_VALID -> FPU_EN
 *
 * Three restore paths exist, all converging on the same result:
 *   (a) Context switch in -- fprestore_ctxt fires.
 *   (b) FPU-disabled trap -- fp_fenflt() re-enables and restores.
 *   (c) Return-to-user -- pcb_return_check() calls fprestore_ctxt
 *       when PCB_UPDATE_FPU is set (e.g. after fork/setfpregs).
 *
 *
 * Exact-Equality ctxop Checks
 * ---------------------------
 *
 * The ctxop callbacks use exact equality (==) rather than bitmask
 * tests.  This is the central mechanism that makes kernel FPU use
 * safe without explicit "am I in kernel mode?" checks:
 *
 *   fpsave_ctxt:    fires only when flags == FPU_EN
 *   fprestore_ctxt: fires only when flags == FPU_EN|FPU_VALID
 *
 * Any additional flag causes the equality check to fail,
 * silently suppressing the operation:
 *
 *   flags       fpsave_ctxt     fprestore_ctxt
 *   -----       -----------     --------------
 *   0           skip            skip
 *   E           SAVE            skip
 *   E|V         skip            RESTORE
 *   E|K         skip            skip
 *   E|V|K       skip            skip
 *   K           skip            skip
 *
 * FPU_KERNEL never needs to be explicitly tested in ctxop
 * callbacks -- its mere presence prevents both from matching.
 * The correctness of the entire scheme depends on these checks
 * remaining exact equalities; they must never be relaxed to
 * bitmask tests.
 *
 *
 * Kernel FPU Modes
 * ----------------
 *
 * Three modes are provided for kernel code that needs FP/SIMD:
 *
 * a. State-backed: kernel_fpu_begin(kfpu, 0)
 *
 *   Requires a kfpu_state_t from kernel_fpu_alloc().  Installs a
 *   kernel ctxop that saves/restores to kfpu->kfps_regs, allowing
 *   preemption.  Works from any context: user threads, kernel
 *   threads, softint/interrupt threads.
 *
 *   On entry:
 *     - If the current LWP has live FPU state (FPU_EN set,
 *       FPU_VALID clear), save via fp_save_hw() and set
 *       FPU_VALID.  We use fp_save_hw() directly rather than
 *       fp_save() because:
 *       (1) fp_save() asserts curthread owns the fpu_ctx_t,
 *           which is wrong on softint threads even though the
 *           borrowed t_lwp makes the pointer check pass.
 *       (2) fp_save() sets PCB_UPDATE_FPU, which is unnecessary
 *           and wrong from softint context.
 *     - Set FPU_KERNEL to suppress user ctxops.
 *     - Attach kernel ctxop, set T_KFPU, fpinit().
 *
 *   On exit:
 *     - Remove kernel ctxop, disable FPU, clear FPU_KERNEL.
 *     - User state restores via fp_fenflt (trap) or
 *       fprestore_ctxt (context switch).
 *
 *   Preemption:
 *     kernel_fpu_ctx_save:  saves to kfpu->kfps_regs, disables
 *     fpsave_ctxt:          flags has FPU_KERNEL -> skip
 *     fprestore_ctxt:       flags has FPU_KERNEL -> skip
 *     kernel_fpu_ctx_restore: restores from kfpu->kfps_regs
 *
 *   Primary consumer: UEFI Runtime Services (efirt), which runs
 *   from the clock() softint via tod_get().
 *
 * b. KFPU_NO_STATE: kernel_fpu_begin(NULL, KFPU_NO_STATE)
 *
 *   Lightweight, preemption-disabled mode.  No ctxops installed,
 *   no save area allocated.  Caller must hold kpreempt_disable()
 *   across the entire begin/end pair.
 *
 *   On entry:
 *     - Save user state via fp_save_hw() if FPU_EN && !FPU_VALID.
 *     - Set FPU_KERNEL, T_KFPU, fpinit().
 *
 *   On exit:
 *     - Clear FPU_KERNEL.
 *     - If FPU_EN is set (ctxops exist): leave FPU enabled.
 *       FPU_VALID prevents fpsave_ctxt from saving the
 *       kernel-clobbered registers; fprestore_ctxt restores
 *       the user's saved state on the next switch-in.
 *     - If FPU_EN is NOT set (no ctxops): disable the FPU.
 *       This ensures the lazy first-use trap (fp_fenflt)
 *       still fires.  Without this, fpinit() would leave
 *       the FPU enabled, the user's first FP instruction
 *       would not trap, no ctxops would be installed, and
 *       FPU state would be silently lost on context switch.
 *     - SSYS threads without an LWP always get fpu_disable().
 *
 * c. KFPU_USE_LWP: kernel_fpu_begin(NULL, KFPU_USE_LWP)
 *
 *   For SSYS kernel threads that have an LWP but no user FPU
 *   context.  Reuses pcb_fpu as the kernel's own save area.
 *   Preemption is allowed -- a kernel ctxop handles save/restore.
 *
 *   On entry:
 *     - VERIFY(t_lwp != NULL), VERIFY(SSYS), ASSERT(!FPU_EN).
 *     - Install kernel ctxop (NULL arg distinguishes from
 *       state-backed in callbacks).
 *     - Set fpu_flags = FPU_EN + FPU_KERNEL, fpinit().
 *
 *   On exit:
 *     - Remove ctxop, disable FPU, clear FPU_EN + FPU_KERNEL.
 *     - Flags return to 0.
 *
 *   This mode must not be used on user threads -- they have
 *   user FPU state in pcb_fpu that would be clobbered.
 *
 *
 * softint Safety
 * --------------
 *
 * Softint threads borrow the pinned thread's t_lwp via
 * dosoftint_prolog (it->t_lwp = t->t_lwp).  This means
 * curthread->t_lwp is non-NULL and points to the pinned user
 * thread's LWP, including its pcb_fpu.
 *
 * State-backed mode is the only kernel FPU mode used from
 * softint context (UEFI RT calls via clock -> tod_get).  The
 * key safety properties:
 *
 *   - fp_save_hw() is used instead of fp_save() to avoid the
 *     assertion and the PCB_UPDATE_FPU side-effect.
 *   - FPU_KERNEL suppresses user ctxops on the borrowed pcb_fpu.
 *   - The kernel ctxop is attached to the softint thread, not
 *     the pinned thread.  Removed before softint completes.
 *   - After kernel_fpu_end, FPU is disabled and flags are
 *     FPU_EN + FPU_VALID.  The pinned thread restores its
 *     state via fp_fenflt or fprestore_ctxt after resuming.
 *
 *
 * Trap Handling
 * -------------
 *
 * T_SIMDFP_ACCESS from EL0 (user mode):
 *   Calls fp_fenflt().  If FPU_EN is set, re-enables FPU and
 *   restores saved state.  If not set, calls fp_exec() for
 *   lazy first-use initialisation.
 *
 * T_SIMDFP_ACCESS from EL1 (kernel mode):
 *   Unconditionally panics via die().  A kernel FPU-disabled
 *   trap is always a bug: kernel_fpu_begin() enables the FPU
 *   explicitly, so a trap means the caller failed to bracket
 *   FPU use.  Allowing fp_fenflt() here would silently restore
 *   user state into a kernel context, corrupting the user's
 *   saved registers when kernel code clobbers them.
 *
 *
 * PCB_SET_UPDATE_FPU
 * ------------------
 *
 * PCB_SET_UPDATE_FPU is set by fp_new_lwp() (when copying FPU
 * state to the new child process), fp_save() (the public API
 * used by fork and /proc) and by setfpregs() (when FP registers
 * are altered via /proc).  It causes pcb_return_check() to call
 * fprestore_ctxt() on return to user.
 *
 * None of the kernel FPU modes set PCB_UPDATE_FPU:
 *   - State-backed and NO_STATE leave the FPU disabled (or
 *     FPU_VALID set), so the trap or context-switch restore
 *     path handles reload.
 *   - Setting it from a softint would write to the pinned
 *     thread's PCB, which is conceptually wrong.
 *   - KFPU_USE_LWP runs on SSYS threads that never return
 *     to user.
 *
 *
 * Lock Ordering and Preemption
 * ----------------------------
 *
 * fpsave_ctxt and fprestore_ctxt run with preemption already
 * disabled (ctxop callbacks called from the dispatcher).
 *
 * fp_save() and fp_fenflt() bracket their critical sections
 * with kpreempt_disable()/kpreempt_enable().
 *
 * kernel_fpu_begin/end in state-backed and USE_LWP modes use
 * kpreempt_disable() around ctxop attach/detach and flag
 * manipulation, then kpreempt_enable() to allow preemption
 * during actual FPU use.
 *
 * KFPU_NO_STATE requires the caller to hold kpreempt_disable()
 * for the entire begin/end window.  kernel_fpu_no_swtch()
 * (called from swtch) panics if T_KFPU is set, catching
 * violations.
 *
 * There are no directly used mutexes in the FPU code, but
 * ctxop allocation/deallocation and kernel_fpu_alloc/free
 * could acquire mutexes.
 *
 *
 * Future: SVE/SME
 * ---------------
 *
 * SVE adds a variable-length register file (Z0-Z31, P0-P15,
 * FFR) that extends the base SIMD V0-V31.  SME adds further
 * matrix state.  When SVE/SME support is added:
 *   - The save area will need to be dynamically sized based
 *     on the implementation's vector length.
 *   - CPACR_EL1.ZEN and SMCR_EL1 will gate access, following
 *     the same lazy-enable pattern as FPEN.
 *   - Signal frame FPU state will need a variable-size
 *     scratch buffer (fpu_signal).
 *   - The kernel FPU modes will need to specify whether
 *     SVE/SME state should be preserved or can be discarded.
 *   - Many other complications may arise.
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
 * Initialise the FPU hardware to a clean state: enable the FPU,
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

/*
 * Context-switch ctxop callbacks for user lwps.
 */

/*
 * Save FPU state on context switch out.
 *
 * The exact equality check (flags == FPU_EN) is critical:
 *   - FPU_EN only:                 save hardware state, set FPU_VALID
 *   - FPU_EN|FPU_VALID:            already saved, skip
 *   - FPU_EN|FPU_KERNEL:           kernel owns FPU, skip
 *   - FPU_EN|FPU_VALID|FPU_KERNEL: both set, skip
 *
 * The FPU is always disabled after save.
 */
static void
fpsave_ctxt(void *arg)
{
	fpu_ctx_t *fp = (fpu_ctx_t *)arg;

	if (fp->fpu_flags == FPU_EN) {
		fpu_enable();
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

/*
 *  Public FPU API
 */

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

	fpu_enable();
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
 * Initialise the FPU for a new execution context (exec, first-use).
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
 * If FPU_EN is not set, this is the thread's first FPU use -- call
 * fp_exec() to install ctxops and initialise.
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

/*
 *  Kernel FPU support
 */

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
		fpu_enable();
		fp_save_hw(&pf->fpu_regs);
		pf->fpu_flags |= FPU_VALID;
	} else {
		/* State-backed: save to kfpu's own area */
		fpu_enable();
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
			fpu_ctx_t *pf = &pl->lwp_pcb.pcb_fpu;
			if ((pf->fpu_flags & FPU_EN) &&
			    !(pf->fpu_flags & FPU_VALID)) {
				fpu_enable();
				fp_save_hw(&pf->fpu_regs);
				pf->fpu_flags |= FPU_VALID;
			}
			pf->fpu_flags |= FPU_KERNEL;
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
		/*
		 * We can run on a softint thread (i.e. via softclock), so
		 * we can't fall foul of the fp_save assertion that checks
		 * that we're saving from the process thread rather than
		 * the LWP thread.
		 */
		fpu_ctx_t *pf = &pl->lwp_pcb.pcb_fpu;
		if ((pf->fpu_flags & FPU_EN) && !(pf->fpu_flags & FPU_VALID)) {
			fpu_enable();
			fp_save_hw(&pf->fpu_regs);
			pf->fpu_flags |= FPU_VALID;
		}
		pf->fpu_flags |= FPU_KERNEL;
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
		 * kfpu, the kfpu API is not intended as a persistent
		 * save location across begin/end pairs.
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
		 * NO_STATE: clear FPU_KERNEL and decide whether to leave
		 * the FPU enabled.  If the thread has user FPU ctxops
		 * (FPU_EN set), leave the FPU enabled -- fpsave_ctxt
		 * will handle the next context switch, and FPU_VALID
		 * prevents it from saving kernel-clobbered registers
		 * over the user's saved state.  If the thread has never
		 * used the FPU (FPU_EN not set, no ctxops), disable the
		 * FPU so the lazy first-use trap (fp_fenflt) still
		 * fires.  SSYS threads without an interrupt stack always
		 * get the FPU disabled.
		 */
		curthread->t_flag &= ~T_KFPU;
		ASSERT(flags & KFPU_NO_STATE);
		if (curthread->t_lwp != NULL) {
			fpu_ctx_t *pf = &curthread->t_lwp->lwp_pcb.pcb_fpu;
			pf->fpu_flags &= ~FPU_KERNEL;
			if (!(pf->fpu_flags & FPU_EN)) {
				fpu_disable();
			}
		} else if ((curthread->t_procp->p_flag & SSYS) != 0 &&
		    curthread->t_intr == NULL) {
			fpu_disable();
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
