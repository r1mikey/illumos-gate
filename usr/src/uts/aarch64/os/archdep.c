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
 * Copyright 2017 Hayashi Naoyuki
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include <sys/param.h>
#include <sys/types.h>
#include <sys/vmparam.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/machlock.h>
#include <sys/panic.h>
#include <sys/privregs.h>
#include <sys/regset.h>
#include <sys/pcb.h>
#include <sys/psw.h>
#include <sys/frame.h>
#include <sys/stack.h>
#include <sys/archsystm.h>
#include <sys/dtrace.h>
#include <sys/cmn_err.h>
#include <sys/cpu.h>
#include <sys/spl.h>
#include <sys/fp.h>
#include <sys/time.h>
#include <sys/machlock.h>
#include <sys/kobj.h>
#include <sys/promif.h>
#include <sys/sysmacros.h>

/*
 * From intel/os/archdep.c
 *
 * void setfpregs(klwp_t *lwp, fpregset_t *fp)
 * void getfpregs(klwp_t *lwp, fpregset_t *fp)
 * void setfpregs32(klwp_t *lwp, fpregset32_t *fp)
 * void getfpregs32(klwp_t *lwp, fpregset32_t *fp)
 * void getgregs(klwp_t *lwp, gregset_t grp)
 * void getgregs32(klwp_t *lwp, gregset32_t grp)
 * void ucontext_32ton(const ucontext32_t *src, ucontext_t *dst)
 * greg_t getuserpc()
 * void setgregs(klwp_t *lwp, gregset_t grp)
 * int getpcstack(pc_t *pcstack, int pcstack_limit)
 * void bind_hwcap(void)
 * void sync_icache(caddr_t addr, uint_t len)
 * void sync_data_memory(caddr_t va, size_t len)
 * int __ipltospl(int ipl)
 * void panic_saveregs(panic_data_t *pdp, struct regs *rp)
 * void traceback(caddr_t fpreg)
 * void traceregs(struct regs *rp)
 * void exec_set_sp(size_t stksize)
 * hrtime_t gethrtime_waitfree(void)
 * hrtime_t gethrtime(void)
 * hrtime_t gethrtime_unscaled(void)
 * void scalehrtime(hrtime_t *hrt)
 * uint64_t unscalehrtime(hrtime_t nsecs)
 * void gethrestime(timespec_t *tp)
 * void __adj_hrestime(void)
 * int xcopyin(const void *uaddr, void *kaddr, size_t count)
 * int xcopyout(const void *kaddr, void *uaddr, size_t count)
 *
 *
 * From sparc/os/archdep.c:
 *
 * int getpcstack(pc_t *pcstack, int pcstack_limit)
 * void bind_hwcap(void)
 * int __ipltospl(int ipl)
 * void traceback(caddr_t sp)
 * void traceregs(struct regs *rp)
 * void exec_set_sp(size_t stksize)
 * void * boot_virt_alloc(void *addr, size_t size)
 * int xcopyin_nta(const void *uaddr, void *kaddr, size_t count, int dummy)
 * int xcopyout_nta(const void *kaddr, void *uaddr, size_t count, int dummy)
 * int kcopy_nta(const void *from, void *to, size_t count, int dummy)
 *
 * This implementation:
 *
 * void sync_icache(caddr_t addr, uint_t len)
 * void sync_data_memory(caddr_t addr, size_t len)
 * void traceback(caddr_t fpreg)
 * void traceregs(struct regs *rp)
 * void exec_set_sp(size_t stksize)
 * void gethrtime_waitfree(void)
 * hrtime_t gethrtime(void)
 * hrtime_t gethrtime_unscaled(void)
 * void scalehrtime(hrtime_t *hrt)
 * uint64_t unscalehrtime(hrtime_t nsec)
 * void gethrestime(timespec_t *tp)
 * hrtime_t dtrace_gethrtime(void)
 * void __adj_hrestime(void)
 * void panic_saveregs(panic_data_t *pdp, struct regs *rp)
 * void setfpregs(klwp_t *lwp, fpregset_t *fp)
 * void getfpregs(klwp_t *lwp, fpregset_t *fp)
 * greg_t getuserpc()
 * int getpcstack(pc_t *pcstack, int pcstack_limit)
 * void getgregs(klwp_t *lwp, gregset_t grp)
 * void setgregs(klwp_t *lwp, gregset_t grp)
 * int scanc(size_t length, u_char *string, u_char table[], u_char mask)
 * int __ipltospl(int ipl)
 */

uint_t adj_shift;

static void
clean_dcache_impl(caddr_t addr, uint_t len)
{
	uint64_t line_size = CTR_TO_DATA_LINESIZE(read_ctr_el0());
	uintptr_t va_start = ((uintptr_t)addr & ~(line_size - 1));
	uintptr_t va_end = ((uintptr_t)(addr + len + line_size - 1) & ~(line_size - 1));
	for (uintptr_t va = va_start; va < va_end; va += line_size) {
		clean_data_cache_poc(va);
	}
}

static void
flush_dcache_impl(caddr_t addr, uint_t len)
{
	uint64_t line_size = CTR_TO_DATA_LINESIZE(read_ctr_el0());
	uintptr_t va_start = ((uintptr_t)addr & ~(line_size - 1));
	uintptr_t va_end = ((uintptr_t)(addr + len + line_size - 1) & ~(line_size - 1));
	for (uintptr_t va = va_start; va < va_end; va += line_size) {
		flush_data_cache(va);
	}
}

void
sync_icache(caddr_t addr, uint_t len)
{
	clean_dcache_impl(addr, len);
	dsb(ish);

	// for VIPT
	invalidate_instruction_cache_allis();
	dsb(ish);
	isb();
}

void
sync_data_memory(caddr_t addr, size_t len)
{
	flush_dcache_impl(addr, len);
	dsb(ish);
}

extern char *dump_stack_scratch;

void
traceback(caddr_t fpreg)
{
	struct frame	*fp = (struct frame *)fpreg;
	struct frame	*nextfp;
	uintptr_t	pc, nextpc;
	ulong_t		off;
	uint_t		offset = 0;
	uint_t		next_offset = 0;
	char		stack_buffer[1024];
	char		*sym;

	if (!panicstr)
		printf("traceback: %%fp = %p\n", (void *)fp);

	if (panicstr && !dump_stack_scratch) {
		printf("Warning - stack not written to the dump buffer\n");
	}

	if ((uintptr_t)fp < KERNELBASE)
		goto out;

	pc = fp->fr_savpc;
	fp = (struct frame *)fp->fr_savfp;

	while ((uintptr_t)fp >= KERNELBASE) {
		/*
		 * XX64 Until port is complete tolerate 8-byte aligned
		 * frame pointers but flag with a warning so they can
		 * be fixed.
		 */
		if (((uintptr_t)fp & (STACK_ALIGN - 1)) != 0) {
			printf(
			    "  >> mis-aligned %%fp = %p\n", (void *)fp);
			break;
		}

		nextpc = (uintptr_t)fp->fr_savpc;
		nextfp = (struct frame *)fp->fr_savfp;
		if ((sym = kobj_getsymname(pc, &off)) != NULL) {
			printf("%016lx %s:%s+%lx\n", (uintptr_t)fp,
			    mod_containing_pc((caddr_t)pc), sym, off);
			(void) snprintf(stack_buffer, sizeof (stack_buffer),
			    "%s:%s+%lx | ",
			    mod_containing_pc((caddr_t)pc), sym, off);
		} else {
			printf("%016lx %lx\n",
			    (uintptr_t)fp, pc);
			(void) snprintf(stack_buffer, sizeof (stack_buffer),
			    "%lx | ", pc);
		}

		if (panicstr && dump_stack_scratch) {
			next_offset = offset + strlen(stack_buffer);
			if (next_offset < STACK_BUF_SIZE) {
				bcopy(stack_buffer, dump_stack_scratch + offset,
				    strlen(stack_buffer));
				offset = next_offset;
			} else {
				/*
				 * In attempting to save the panic stack
				 * to the dumpbuf we have overflowed that area.
				 * Print a warning and continue to printf the
				 * stack to the msgbuf
				 */
				printf("Warning: stack in the dump buffer"
				    " may be incomplete\n");
				offset = next_offset;
			}
		}

		pc = nextpc;
		fp = nextfp;
	}
out:
	if (!panicstr) {
		printf("end of traceback\n");
		DELAY(2 * MICROSEC);
	} else if (dump_stack_scratch) {
		dump_stack_scratch[offset] = '\0';
	}
}

void
traceregs(struct regs *rp)
{
	traceback((caddr_t)rp->r_x29);
}

void
exec_set_sp(size_t stksize)
{
	klwp_t *lwp = ttolwp(curthread);

	lwptoregs(lwp)->r_sp = (uintptr_t)curproc->p_usrstack - stksize;
}

void hrtime_init(void)
{
	extern int gethrtime_hires;
	gethrtime_hires = 1;
}

hrtime_t
gethrtime_waitfree(void)
{
	return (dtrace_gethrtime());
}

hrtime_t
gethrtime(void)
{
	uint64_t pct = read_cntpct();
	uint64_t timer_freq = read_cntfrq();

	uint64_t x = pct / timer_freq;
	uint64_t y = pct % timer_freq;
	hrtime_t nsec = x * NANOSEC + y * NANOSEC / timer_freq;
	return nsec;
}

hrtime_t
gethrtime_unscaled(void)
{
	return (hrtime_t)read_cntpct();
}

void
scalehrtime(hrtime_t *hrt)
{
	hrtime_t pct = *hrt;
	uint64_t timer_freq = read_cntfrq();

	uint64_t x = pct / timer_freq;
	uint64_t y = pct % timer_freq;
	hrtime_t nsec = x * NANOSEC + y * NANOSEC / timer_freq;
	*hrt = nsec;
}

uint64_t
unscalehrtime(hrtime_t nsec)
{
	uint64_t timer_freq = read_cntfrq();

	uint64_t x = nsec / NANOSEC;
	uint64_t y = nsec % NANOSEC;
	uint64_t pct = x * timer_freq + y * timer_freq / NANOSEC;
	return pct;
}

void
gethrestime(timespec_t *tp)
{
	pc_gethrestime(tp);
}

hrtime_t
dtrace_gethrtime(void)
{
	uint64_t pct = read_cntpct();
	uint64_t timer_freq = read_cntfrq();

	uint64_t x = pct / timer_freq;
	uint64_t y = pct % timer_freq;
	hrtime_t nsec = x * NANOSEC + y * NANOSEC / timer_freq;
	return nsec;
}

extern int one_sec;
extern int max_hres_adj;

void
__adj_hrestime(void)
{
	long long adj;

	if (hrestime_adj == 0)
		adj = 0;
	else if (hrestime_adj > 0) {
		if (hrestime_adj < max_hres_adj)
			adj = hrestime_adj;
		else
			adj = max_hres_adj;
	} else {
		if (hrestime_adj < -max_hres_adj)
			adj = -max_hres_adj;
		else
			adj = hrestime_adj;
	}

	timedelta -= adj;
	hrestime_adj = timedelta;
	hrestime.tv_nsec += adj;

	while (hrestime.tv_nsec >= NANOSEC) {
		one_sec++;
		hrestime.tv_sec++;
		hrestime.tv_nsec -= NANOSEC;
	}
}

/*
 * The panic code invokes panic_saveregs() to record the contents of a
 * regs structure into the specified panic_data structure for debuggers.
 */
void
panic_saveregs(panic_data_t *pdp, struct regs *rp)
{
	panic_nv_t *pnv = PANICNVGET(pdp);

	PANICNVADD(pnv, "x0", rp->r_x0);
	PANICNVADD(pnv, "x1", rp->r_x1);
	PANICNVADD(pnv, "x2", rp->r_x2);
	PANICNVADD(pnv, "x3", rp->r_x3);
	PANICNVADD(pnv, "x4", rp->r_x4);
	PANICNVADD(pnv, "x5", rp->r_x5);
	PANICNVADD(pnv, "x6", rp->r_x6);
	PANICNVADD(pnv, "x7", rp->r_x7);
	PANICNVADD(pnv, "x8", rp->r_x8);
	PANICNVADD(pnv, "x9", rp->r_x9);
	PANICNVADD(pnv, "x10", rp->r_x10);
	PANICNVADD(pnv, "x11", rp->r_x11);
	PANICNVADD(pnv, "x12", rp->r_x12);
	PANICNVADD(pnv, "x13", rp->r_x13);
	PANICNVADD(pnv, "x14", rp->r_x14);
	PANICNVADD(pnv, "x15", rp->r_x15);
	PANICNVADD(pnv, "x16", rp->r_x16);
	PANICNVADD(pnv, "x17", rp->r_x17);
	PANICNVADD(pnv, "x18", rp->r_x18);
	PANICNVADD(pnv, "x19", rp->r_x19);
	PANICNVADD(pnv, "x20", rp->r_x20);
	PANICNVADD(pnv, "x21", rp->r_x21);
	PANICNVADD(pnv, "x22", rp->r_x22);
	PANICNVADD(pnv, "x23", rp->r_x23);
	PANICNVADD(pnv, "x24", rp->r_x24);
	PANICNVADD(pnv, "x25", rp->r_x25);
	PANICNVADD(pnv, "x26", rp->r_x26);
	PANICNVADD(pnv, "x27", rp->r_x27);
	PANICNVADD(pnv, "x28", rp->r_x28);
	PANICNVADD(pnv, "x29", rp->r_x29);
	PANICNVADD(pnv, "x30", rp->r_x30);
	PANICNVADD(pnv, "sp", rp->r_sp);
	PANICNVADD(pnv, "pc", rp->r_pc);
	PANICNVADD(pnv, "spsr", rp->r_spsr);
	PANICNVADD(pnv, "tpidr_el0", read_tpidr_el0());
	PANICNVADD(pnv, "tpidr_el1", read_tpidr_el1());
	PANICNVADD(pnv, "ttbr0", read_ttbr0());
	PANICNVADD(pnv, "ttbr1", read_ttbr1());
	PANICNVADD(pnv, "tcr", read_tcr());

	PANICNVSET(pdp, pnv);
}

/*
 * Set floating-point registers from a native fpregset_t.
 */
void
setfpregs(klwp_t *lwp, fpregset_t *fp)
{
	struct fpu_ctx *fpu = &lwp->lwp_pcb.pcb_fpu;
	pcb_t *pcb = &lwp->lwp_pcb;

	kpreempt_disable();
	fpu->fpu_regs.kfpu_cr = fp->fp_cr;
	fpu->fpu_regs.kfpu_sr = fp->fp_sr;
	bcopy(fp->d_fpregs, fpu->fpu_regs.kfpu_regs, sizeof(fpu->fpu_regs.kfpu_regs));
	if (ttolwp(curthread) == lwp) {
		fp_restore(pcb);
	}
	kpreempt_enable();
}

/*
 * Get floating-point registers into a native fpregset_t.
 */
void
getfpregs(klwp_t *lwp, fpregset_t *fp)
{
	struct fpu_ctx *fpu = &lwp->lwp_pcb.pcb_fpu;
	pcb_t *pcb = &lwp->lwp_pcb;

	kpreempt_disable();
	if (ttolwp(curthread) == lwp) {
		fp_save(pcb);
	}

	fp->fp_cr = fpu->fpu_regs.kfpu_cr;
	fp->fp_sr = fpu->fpu_regs.kfpu_sr;
	bcopy(fpu->fpu_regs.kfpu_regs, fp->d_fpregs, sizeof(fp->d_fpregs));

	kpreempt_enable();
}

#if defined(_SYSCALL32_IMPL)

static void
fpregset_nto32(const fpregset_t *src, fpregset32_t *dst)
{
	panic("fpregset_nto32 is not ready yet");
}

static void
fpregset_32ton(const fpregset32_t *src, fpregset_t *dst)
{
	panic("fpregset_32ton is not ready yet");
}

#endif

#if defined(_SYSCALL32_IMPL)

/*
 * Set floating-point registers from an fpregset32_t.
 */
void
setfpregs32(klwp_t *lwp, fpregset32_t *fp)
{
	fpregset_t fpregs;

	fpregset_32ton(fp, &fpregs);
	setfpregs(lwp, &fpregs);
}

/*
 * Get floating-point registers into an fpregset32_t.
 */
void
getfpregs32(klwp_t *lwp, fpregset32_t *fp)
{
	fpregset_t fpregs;

	getfpregs(lwp, &fpregs);
	fpregset_nto32(&fpregs, fp);
}

#endif

/*
 * Return the user-level PC.
 * If in a system call, return the address of the syscall trap.
 */
greg_t
getuserpc()
{
	greg_t upc = lwptoregs(ttolwp(curthread))->r_pc;

	if (curthread->t_sysnum != 0)
		upc -= 4;

	return upc;
}

/*
 * Get a pc-only stacktrace.  Used for kmem_alloc() buffer ownership tracking.
 * Returns MIN(current stack depth, pcstack_limit).
 */
int
getpcstack(pc_t *pcstack, int pcstack_limit)
{
	struct frame *fp = (struct frame *)getfp();
	struct frame *nextfp, *minfp, *stacktop;
	int depth = 0;
	int on_intr;
	uintptr_t pc;

	if ((on_intr = CPU_ON_INTR(CPU)) != 0)
		stacktop = (struct frame *)(CPU->cpu_intr_stack + SA(MINFRAME));
	else
		stacktop = (struct frame *)curthread->t_stk;
	minfp = fp;

	while (depth < pcstack_limit) {
		nextfp = (struct frame *)fp->fr_savfp;
		pc = fp->fr_savpc - 4;	/* XXXAARCH64 */
		if (nextfp <= minfp || nextfp >= stacktop) {
			if (on_intr) {
				/*
				 * Hop from interrupt stack to thread stack.
				 */
				stacktop = (struct frame *)curthread->t_stk;
				minfp = (struct frame *)curthread->t_stkbase;
				on_intr = 0;
				continue;
			}
			break;
		}
		pcstack[depth++] = (pc_t)pc;
		fp = nextfp;
		minfp = fp;
	}

	return depth;
}


/*
 * Return the general registers
 */
void
getgregs(klwp_t *lwp, gregset_t grp)
{
	struct regs *rp = lwptoregs(lwp);

	grp[REG_X0] = rp->r_x0;
	grp[REG_X1] = rp->r_x1;
	grp[REG_X2] = rp->r_x2;
	grp[REG_X3] = rp->r_x3;
	grp[REG_X4] = rp->r_x4;
	grp[REG_X5] = rp->r_x5;
	grp[REG_X6] = rp->r_x6;
	grp[REG_X7] = rp->r_x7;
	grp[REG_X8] = rp->r_x8;
	grp[REG_X9] = rp->r_x9;
	grp[REG_X10] = rp->r_x10;
	grp[REG_X11] = rp->r_x11;
	grp[REG_X12] = rp->r_x12;
	grp[REG_X13] = rp->r_x13;
	grp[REG_X14] = rp->r_x14;
	grp[REG_X15] = rp->r_x15;
	grp[REG_X16] = rp->r_x16;
	grp[REG_X17] = rp->r_x17;
	grp[REG_X18] = rp->r_x18;
	grp[REG_X19] = rp->r_x19;
	grp[REG_X20] = rp->r_x20;
	grp[REG_X21] = rp->r_x21;
	grp[REG_X22] = rp->r_x22;
	grp[REG_X23] = rp->r_x23;
	grp[REG_X24] = rp->r_x24;
	grp[REG_X25] = rp->r_x25;
	grp[REG_X26] = rp->r_x26;
	grp[REG_X27] = rp->r_x27;
	grp[REG_X28] = rp->r_x28;
	grp[REG_X29] = rp->r_x29;
	grp[REG_X30] = rp->r_x30;
	grp[REG_SP] = rp->r_sp;
	grp[REG_PC] = rp->r_pc;
	grp[REG_PSR] = rp->r_spsr;

	if (ttolwp(curthread) == lwp) {
		grp[REG_TP] = read_tpidr_el0();
	} else {
		grp[REG_TP] = lwp->lwp_pcb.pcb_tpidr;
	}
}

#if defined(_SYSCALL32_IMPL)
void
getgregs32(klwp_t *lwp, gregset32_t grp)
{
	struct regs *rp = lwptoregs(lwp);

	grp[REG_X0] = rp->r_x0;
	grp[REG_X1] = rp->r_x1;
	grp[REG_X2] = rp->r_x2;
	grp[REG_X3] = rp->r_x3;
	grp[REG_X4] = rp->r_x4;
	grp[REG_X5] = rp->r_x5;
	grp[REG_X6] = rp->r_x6;
	grp[REG_X7] = rp->r_x7;
	grp[REG_X8] = rp->r_x8;
	grp[REG_X9] = rp->r_x9;
	grp[REG_X10] = rp->r_x10;
	grp[REG_X11] = rp->r_x11;
	grp[REG_X12] = rp->r_x12;
	grp[REG_X13] = rp->r_x13;
	grp[REG_X14] = rp->r_x14;
	grp[REG_X15] = rp->r_x15;
	grp[REG_X16] = rp->r_x16;
	grp[REG_X17] = rp->r_x17;
	grp[REG_X18] = rp->r_x18;
	grp[REG_X19] = rp->r_x19;
	grp[REG_X20] = rp->r_x20;
	grp[REG_X21] = rp->r_x21;
	grp[REG_X22] = rp->r_x22;
	grp[REG_X23] = rp->r_x23;
	grp[REG_X24] = rp->r_x24;
	grp[REG_X25] = rp->r_x25;
	grp[REG_X26] = rp->r_x26;
	grp[REG_X27] = rp->r_x27;
	grp[REG_X28] = rp->r_x28;
	grp[REG_X29] = rp->r_x29;
	grp[REG_X30] = rp->r_x30;
	grp[REG_SP] = rp->r_sp;
	grp[REG_PC] = rp->r_pc;
	grp[REG_PSR] = rp->r_spsr;

	if (ttolwp(curthread) == lwp) {
		grp[REG_TP] = read_tpidr_el0();
	} else {
		grp[REG_TP] = lwp->lwp_pcb.pcb_tpidr;
	}
}
#endif

/*
 * Set general registers.
 */
void
setgregs(klwp_t *lwp, gregset_t grp)
{
	struct regs *rp = lwptoregs(lwp);

	rp->r_x0 = grp[REG_X0];
	rp->r_x1 = grp[REG_X1];
	rp->r_x2 = grp[REG_X2];
	rp->r_x3 = grp[REG_X3];
	rp->r_x4 = grp[REG_X4];
	rp->r_x5 = grp[REG_X5];
	rp->r_x6 = grp[REG_X6];
	rp->r_x7 = grp[REG_X7];
	rp->r_x8 = grp[REG_X8];
	rp->r_x9 = grp[REG_X9];
	rp->r_x10 = grp[REG_X10];
	rp->r_x11 = grp[REG_X11];
	rp->r_x12 = grp[REG_X12];
	rp->r_x13 = grp[REG_X13];
	rp->r_x14 = grp[REG_X14];
	rp->r_x15 = grp[REG_X15];
	rp->r_x16 = grp[REG_X16];
	rp->r_x17 = grp[REG_X17];
	rp->r_x18 = grp[REG_X18];
	rp->r_x19 = grp[REG_X19];
	rp->r_x20 = grp[REG_X20];
	rp->r_x21 = grp[REG_X21];
	rp->r_x22 = grp[REG_X22];
	rp->r_x23 = grp[REG_X23];
	rp->r_x24 = grp[REG_X24];
	rp->r_x25 = grp[REG_X25];
	rp->r_x26 = grp[REG_X26];
	rp->r_x27 = grp[REG_X27];
	rp->r_x28 = grp[REG_X28];
	rp->r_x29 = grp[REG_X29];
	rp->r_x30 = grp[REG_X30];
	rp->r_sp = grp[REG_SP];
	rp->r_pc = grp[REG_PC];
	rp->r_spsr = (rp->r_spsr & ~PSR_USERMASK) | (grp[REG_PSR] & PSR_USERMASK);

	if (ttolwp(curthread) == lwp) {
		write_tpidr_el0(grp[REG_TP]);
	} else {
		lwp->lwp_pcb.pcb_tpidr = grp[REG_TP];
	}
}

/*
 * The following ELF header fields are defined as processor-specific
 * in the V8 ABI:
 *
 *	e_ident[EI_DATA]	encoding of the processor-specific
 *				data in the object file
 *	e_machine		processor identification
 *	e_flags			processor-specific flags associated
 *				with the file
 */

/*
 * The value of at_flags reflects a platform's cpu module support.
 * at_flags is used to check for allowing a binary to execute and
 * is passed as the value of the AT_FLAGS auxiliary vector.
 */
int at_flags = 0;

/*
 * Check the processor-specific fields of an ELF header.
 *
 * returns 1 if the fields are valid, 0 otherwise
 */
int
elfheadcheck(
	unsigned char e_data,
	Elf32_Half e_machine,
	Elf32_Word e_flags)
{
	if (e_data != ELFDATA2LSB)
		return (0);
	return (e_machine == EM_AARCH64);
}
uint_t auxv_hwcap_include = 0;	/* patch to enable unrecognized features */
uint_t auxv_hwcap_exclude = 0;	/* patch for broken cpus, debugging */

int
scanc(size_t length, u_char *string, u_char table[], u_char mask)
{
	const u_char *end = &string[length];

	while (string < end && (table[*string] & mask) == 0)
		string++;
	return (end - string);
}

int
__ipltospl(int ipl)
{
	return (ipltospl(ipl));
}

#ifdef _SYSCALL32_IMPL
void ucontext_32ton(const ucontext32_t *src, ucontext_t *dst)
{
	bcopy(src, dst, MIN(sizeof(*src), sizeof(*dst)));
}
#endif

/*
 * Allocate a region of virtual address space, unmapped.
 * Stubbed out except on sparc, at least for now.
 *
 * XXXAARCH64: what is this used for?
 *
 * Called in kmem_firewall_va_alloc in uts/common/os/kmem.c
 */
/*ARGSUSED*/
void *
boot_virt_alloc(void *addr, size_t size)
{
        return (addr);
}
