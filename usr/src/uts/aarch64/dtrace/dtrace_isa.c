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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2013, 2014 by Delphix. All rights reserved.
 * Copyright (c) 2017 Joyent, Inc.
 */

#include <sys/dtrace_impl.h>
#include <sys/stack.h>
#include <sys/frame.h>
#include <sys/cmn_err.h>
#include <sys/privregs.h>
#include <sys/sysmacros.h>
#include <sys/siginfo.h>
#include <sys/promif.h>

extern uintptr_t kernelbase;

int	dtrace_ustackdepth_max = 2048;

void
dtrace_getpcstack(pc_t *pcstack, int pcstack_limit, int aframes,
    uint32_t *intrpc)
{
	struct frame *fp = (struct frame *)dtrace_getfp();
	struct frame *nextfp, *minfp, *stacktop;
	int depth = 0;
	int on_intr, last = 0;
	uintptr_t pc;
	uintptr_t caller = CPU->cpu_dtrace_caller;

	if ((on_intr = CPU_ON_INTR(CPU)) != 0)
		stacktop = (struct frame *)(CPU->cpu_intr_stack + SA(MINFRAME));
	else
		stacktop = (struct frame *)curthread->t_stk;
	minfp = fp;

	aframes++;

	if (intrpc != NULL && depth < pcstack_limit)
		pcstack[depth++] = (pc_t)intrpc;

	while (depth < pcstack_limit) {
		if (fp->fr_savpc == (pc_t)dtrace_invop_callsite) {
			struct regs *rp = (struct regs *)(fp->fr_savfp);
			fp = (struct frame *)(rp->r_x29);
			prom_printf("%s:%d aframes = %d depth = %d\n",__func__,__LINE__, aframes, depth);
		}
		nextfp = (struct frame *)fp->fr_savfp;
		pc = fp->fr_savpc;

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

			/*
			 * This is the last frame we can process; indicate
			 * that we should return after processing this frame.
			 */
			last = 1;
		}

		if (aframes > 0) {
			if (--aframes == 0 && caller != 0) {
				/*
				 * We've just run out of artificial frames,
				 * and we have a valid caller -- fill it in
				 * now.
				 */
				ASSERT(depth < pcstack_limit);
				pcstack[depth++] = (pc_t)caller;
				caller = 0;
			}
		} else {
			if (depth < pcstack_limit)
				pcstack[depth++] = (pc_t)pc;
		}

		if (last) {
			while (depth < pcstack_limit)
				pcstack[depth++] = 0;
			return;
		}

		fp = nextfp;
		minfp = fp;
	}
}

static int
dtrace_getustack_common(uint64_t *pcstack, int pcstack_limit, uintptr_t pc, uintptr_t sp)
{
	uintptr_t oldsp;
	volatile uint16_t *flags =
	    (volatile uint16_t *)&cpu_core[CPU->cpu_id].cpuc_dtrace_flags;
	int ret = 0;

	ASSERT(pcstack == NULL || pcstack_limit > 0);
	ASSERT(dtrace_ustackdepth_max > 0);

	while (pc != 0) {
		/*
		 * We limit the number of times we can go around this
		 * loop to account for a circular stack.
		 */
		if (ret++ >= dtrace_ustackdepth_max) {
			*flags |= CPU_DTRACE_BADSTACK;
			cpu_core[CPU->cpu_id].cpuc_dtrace_illval = sp;
			break;
		}

		if (pcstack != NULL) {
			*pcstack++ = (uint64_t)pc;
			pcstack_limit--;
			if (pcstack_limit <= 0)
				break;
		}

		if (sp == 0)
			break;

		oldsp = sp;

		struct frame *fr = (struct frame *)sp;
		pc = dtrace_fulword(&fr->fr_savpc);
		sp = dtrace_fulword(&fr->fr_savfp);

		if (sp == oldsp) {
			*flags |= CPU_DTRACE_BADSTACK;
			cpu_core[CPU->cpu_id].cpuc_dtrace_illval = sp;
			break;
		}

		/*
		 * This is totally bogus:  if we faulted, we're going to clear
		 * the fault and break.  This is to deal with the apparently
		 * broken Java stacks on x86.
		 */
		if (*flags & CPU_DTRACE_FAULT) {
			*flags &= ~CPU_DTRACE_FAULT;
			break;
		}
	}

	return (ret);
}

void
dtrace_getupcstack(uint64_t *pcstack, int pcstack_limit)
{
	klwp_t *lwp = ttolwp(curthread);
	proc_t *p = curproc;
	struct regs *rp;
	uintptr_t pc, fp;
	int n;

	ASSERT(DTRACE_CPUFLAG_ISSET(CPU_DTRACE_NOFAULT));

	if (DTRACE_CPUFLAG_ISSET(CPU_DTRACE_FAULT))
		return;

	if (pcstack_limit <= 0)
		return;

	/*
	 * If there's no user context we still need to zero the stack.
	 */
	if (lwp == NULL || p == NULL || (rp = lwp->lwp_regs) == NULL)
		goto zero;

	*pcstack++ = (uint64_t)p->p_pid;
	pcstack_limit--;

	if (pcstack_limit <= 0)
		return;

	pc = rp->r_pc;
	fp = rp->r_x29;

	if (DTRACE_CPUFLAG_ISSET(CPU_DTRACE_ENTRY)) {
		*pcstack++ = (uint64_t)pc;
		pcstack_limit--;
		if (pcstack_limit <= 0)
			return;

		pc = rp->r_x30;
	}

	n = dtrace_getustack_common(pcstack, pcstack_limit, pc, fp);
	ASSERT(n >= 0);
	ASSERT(n <= pcstack_limit);

	pcstack += n;
	pcstack_limit -= n;

zero:
	while (pcstack_limit-- > 0)
		*pcstack++ = 0;
}

int
dtrace_getustackdepth(void)
{
	klwp_t *lwp = ttolwp(curthread);
	proc_t *p = curproc;
	struct regs *rp;
	uintptr_t pc, fp;
	int n = 0;

	if (lwp == NULL || p == NULL || (rp = lwp->lwp_regs) == NULL)
		return (0);

	if (DTRACE_CPUFLAG_ISSET(CPU_DTRACE_FAULT))
		return (-1);

	pc = rp->r_pc;
	fp = rp->r_x29;

	if (DTRACE_CPUFLAG_ISSET(CPU_DTRACE_ENTRY)) {
		n++;
		pc = rp->r_x30;
	}

	n += dtrace_getustack_common(NULL, 0, pc, fp);

	return (n);
}

void
dtrace_getufpstack(uint64_t *pcstack, uint64_t *fpstack, int pcstack_limit)
{
	klwp_t *lwp = ttolwp(curthread);
	proc_t *p = curproc;
	struct regs *rp;
	uintptr_t pc, sp;
	volatile uint16_t *flags =
	    (volatile uint16_t *)&cpu_core[CPU->cpu_id].cpuc_dtrace_flags;

	if (*flags & CPU_DTRACE_FAULT)
		return;

	if (pcstack_limit <= 0)
		return;

	/*
	 * If there's no user context we still need to zero the stack.
	 */
	if (lwp == NULL || p == NULL || (rp = lwp->lwp_regs) == NULL)
		goto zero;

	*pcstack++ = (uint64_t)p->p_pid;
	pcstack_limit--;

	if (pcstack_limit <= 0)
		return;

	if (DTRACE_CPUFLAG_ISSET(CPU_DTRACE_ENTRY)) {
		*pcstack++ = (uint64_t)rp->r_pc;
		*fpstack++ = 0;
		pcstack_limit--;
		if (pcstack_limit <= 0)
			return;

		*pcstack++ = (uint64_t)rp->r_x30;
		*fpstack++ = (uint64_t)rp->r_sp;
		pcstack_limit--;
	} else {
		*pcstack++ = (uint64_t)rp->r_pc;
		*fpstack++ = (uint64_t)rp->r_sp;
		pcstack_limit--;
	}

	sp = (uint64_t)rp->r_x29;
	while (sp != 0) {
		if (pcstack_limit <= 0)
			return;

		struct frame *fr = (struct frame *)sp;
		pc = dtrace_fulword(&fr->fr_savpc);
		sp = dtrace_fulword(&fr->fr_savfp);
		if (pc == 0)
			break;

		*pcstack++ = pc;
		*fpstack++ = sp;
		pcstack_limit--;
	}

zero:
	while (pcstack_limit-- > 0)
		*pcstack++ = 0;
}

/*ARGSUSED*/
uint64_t
dtrace_getarg(int arg, int aframes)
{
	uintptr_t val;
	struct frame *fp = (struct frame *)dtrace_getfp();
	uintptr_t *stack;
	int i;
	/*
	 * A total of 8 arguments are passed via registers; any argument with
	 * index of 7 or lower is therefore in a register.
	 */
	int inreg = 7;

	for (i = 1; i <= aframes; i++) {
		fp = (struct frame *)(fp->fr_savfp);
		if (fp == 0)
			break;

		if (fp->fr_savpc == (pc_t)dtrace_invop_callsite) {
			struct regs *rp = (struct regs *)(fp->fr_savfp);

			if (arg <= inreg) {
				stack = (uintptr_t *)&rp->r_x0;
			} else {
				stack = (uintptr_t *)((uintptr_t)rp + REG_FRAME);
				arg -= inreg;
			}
			prom_printf("%s:%d aframes = %d i = %d\n",__func__,__LINE__, aframes, i);
			goto load;
		}

	}

	DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
	return (0);
load:
	DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
	val = stack[arg];
	DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);

	return (val);
}

/*ARGSUSED*/
int
dtrace_getstackdepth(int aframes)
{
	struct frame *fp = (struct frame *)dtrace_getfp();
	struct frame *nextfp, *minfp, *stacktop;
	int depth = 0;
	int last = 0;
	int on_intr;

	if ((on_intr = CPU_ON_INTR(CPU)) != 0)
		stacktop = (struct frame *)(CPU->cpu_intr_stack + SA(MINFRAME));
	else
		stacktop = (struct frame *)curthread->t_stk;
	minfp = fp;

	aframes++;
	depth++;

	for (;;) {
		if (fp->fr_savpc == (pc_t)dtrace_invop_callsite) {
			struct regs *rp = (struct regs *)(fp->fr_savfp);
			fp = (struct frame *)(rp->r_x29);
			prom_printf("%s:%d aframes = %d depth = %d\n",__func__,__LINE__, aframes, depth);
		}

		nextfp = (struct frame *)fp->fr_savfp;
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
			last = 1;
		}
		depth++;

		if (last)
			break;

		fp = nextfp;
		minfp = fp;
	}

	prom_printf("%s:%d aframes = %d depth = %d\n",__func__,__LINE__, aframes, depth);
	if (depth <= aframes)
		return (0);

	return (depth - aframes);
}

ulong_t
dtrace_getreg(struct regs *rp, uint_t reg)
{
	switch (reg) {
	case REG_X0:
		return rp->r_x0;
	case REG_X1:
		return rp->r_x1;
	case REG_X2:
		return rp->r_x2;
	case REG_X3:
		return rp->r_x3;
	case REG_X4:
		return rp->r_x4;
	case REG_X5:
		return rp->r_x5;
	case REG_X6:
		return rp->r_x6;
	case REG_X7:
		return rp->r_x7;
	case REG_X8:
		return rp->r_x8;
	case REG_X9:
		return rp->r_x9;
	case REG_X10:
		return rp->r_x10;
	case REG_X11:
		return rp->r_x11;
	case REG_X12:
		return rp->r_x12;
	case REG_X13:
		return rp->r_x13;
	case REG_X14:
		return rp->r_x14;
	case REG_X15:
		return rp->r_x15;
	case REG_X16:
		return rp->r_x16;
	case REG_X17:
		return rp->r_x17;
	case REG_X18:
		return rp->r_x18;
	case REG_X19:
		return rp->r_x19;
	case REG_X20:
		return rp->r_x20;
	case REG_X21:
		return rp->r_x21;
	case REG_X22:
		return rp->r_x22;
	case REG_X23:
		return rp->r_x23;
	case REG_X24:
		return rp->r_x24;
	case REG_X25:
		return rp->r_x25;
	case REG_X26:
		return rp->r_x26;
	case REG_X27:
		return rp->r_x27;
	case REG_X28:
		return rp->r_x28;
	case REG_X29:
		return rp->r_x29;
	case REG_X30:
		return rp->r_x30;
	case REG_SP:
		return rp->r_sp;
	case REG_PC:
		return rp->r_pc;
	case REG_PSR:
		return rp->r_spsr;
	default:
		DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
	}
	return 0;
}

void
dtrace_setreg(struct regs *rp, uint_t reg, ulong_t val)
{
	switch (reg) {
	case REG_X0:
		rp->r_x0 = val;
		break;
	case REG_X1:
		rp->r_x1 = val;
		break;
	case REG_X2:
		rp->r_x2 = val;
		break;
	case REG_X3:
		rp->r_x3 = val;
		break;
	case REG_X4:
		rp->r_x4 = val;
		break;
	case REG_X5:
		rp->r_x5 = val;
		break;
	case REG_X6:
		rp->r_x6 = val;
		break;
	case REG_X7:
		rp->r_x7 = val;
		break;
	case REG_X8:
		rp->r_x8 = val;
		break;
	case REG_X9:
		rp->r_x9 = val;
		break;
	case REG_X10:
		rp->r_x10 = val;
		break;
	case REG_X11:
		rp->r_x11 = val;
		break;
	case REG_X12:
		rp->r_x12 = val;
		break;
	case REG_X13:
		rp->r_x13 = val;
		break;
	case REG_X14:
		rp->r_x14 = val;
		break;
	case REG_X15:
		rp->r_x15 = val;
		break;
	case REG_X16:
		rp->r_x16 = val;
		break;
	case REG_X17:
		rp->r_x17 = val;
		break;
	case REG_X18:
		rp->r_x18 = val;
		break;
	case REG_X19:
		rp->r_x19 = val;
		break;
	case REG_X20:
		rp->r_x20 = val;
		break;
	case REG_X21:
		rp->r_x21 = val;
		break;
	case REG_X22:
		rp->r_x22 = val;
		break;
	case REG_X23:
		rp->r_x23 = val;
		break;
	case REG_X24:
		rp->r_x24 = val;
		break;
	case REG_X25:
		rp->r_x25 = val;
		break;
	case REG_X26:
		rp->r_x26 = val;
		break;
	case REG_X27:
		rp->r_x27 = val;
		break;
	case REG_X28:
		rp->r_x28 = val;
		break;
	case REG_X29:
		rp->r_x29 = val;
		break;
	case REG_X30:
		rp->r_x30 = val;
		break;
	case REG_SP:
		rp->r_sp = val;
		break;
	case REG_PC:
		rp->r_pc = val & ~0x3ul;
		break;
	case REG_PSR:
		rp->r_spsr = (rp->r_spsr & ~PSR_USERMASK) | (val & PSR_USERMASK);
		break;
	default:
		DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
		return;
	}
}

void
dtrace_probe_error(dtrace_state_t *state, dtrace_epid_t epid, int arg0, int arg1, int arg2, uintptr_t arg3)
{
	dtrace_probe(dtrace_probeid_error, (uintptr_t)state, epid, arg0, arg1, arg2);
}

uint64_t
dtrace_getvmreg(uint_t ndx, volatile uint16_t *flags)
{
	*flags |= CPU_DTRACE_ILLOP;

	return (0);
}

greg_t
dtrace_getfp(void)
{
	return (greg_t)__builtin_frame_address(0);
}

uintptr_t
dtrace_caller(int l)
{
	struct frame *fp = (struct frame *)dtrace_getfp();
	for (int i = 0; i < l; i++) {
		if (fp == 0)
			return -1ul;
		if (fp->fr_savpc == (pc_t)dtrace_invop_callsite)
			return -1ul;
		fp = (struct frame *)(fp->fr_savfp);
	}
	if (fp == 0)
		return -1ul;
	return fp->fr_savpc;
}

uint32_t
dtrace_cas32(uint32_t *target, uint32_t cmp, uint32_t newval)
{ return __sync_val_compare_and_swap(target, cmp, newval); }

void *
dtrace_casptr(void *target, void *cmp, void *newval)
{ return __sync_val_compare_and_swap((void **)target, cmp, newval); }

static int
dtrace_copycheck(uintptr_t uaddr, uintptr_t kaddr, size_t size)
{
	ASSERT(kaddr >= kernelbase && kaddr + size >= kaddr);

	if (uaddr + size >= kernelbase || uaddr + size < uaddr) {
		DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
		cpu_core[CPU->cpu_id].cpuc_dtrace_illval = uaddr;
		return (0);
	}

	return (1);
}

static uint8_t
load8_from_user(uint8_t *uaddr)
{
	uint8_t v;
	asm volatile ("ldtrb %w0, %1":"=&r"(v):"Q"(uaddr):"memory");
	return v;
}

static uint16_t
load16_from_user(uint16_t *uaddr)
{
	uint16_t v;
	asm volatile ("ldtrh %w0, %1":"=&r"(v):"Q"(uaddr):"memory");
	return v;
}

static uint32_t
load32_from_user(uint32_t *uaddr)
{
	uint32_t v;
	asm volatile ("ldtr %w0, %1":"=&r"(v):"Q"(uaddr):"memory");
	return v;
}

static uint64_t
load64_from_user(uint64_t *uaddr)
{
	uint64_t v;
	asm volatile ("ldtr %0, %1":"=&r"(v):"Q"(uaddr):"memory");
	return v;
}

static void
store8_to_user(uint8_t *uaddr, uint8_t val)
{
	asm volatile ("sttrb %w1, %0": "+Q"(uaddr):"r"(val):"memory");
}

/*ARGSUSED*/
void
dtrace_copyin(uintptr_t uaddr, uintptr_t kaddr, size_t size,
    volatile uint16_t *flags)
{
	if (!dtrace_copycheck(uaddr, kaddr, size))
		return;

	while (size != 0) {
		*(uint8_t *)kaddr = load8_from_user((uint8_t *)uaddr);
		if (*flags & CPU_DTRACE_FAULT)
			break;
		kaddr++;
		uaddr++;
		size--;
	}
}

/*ARGSUSED*/
void
dtrace_copyout(uintptr_t kaddr, uintptr_t uaddr, size_t size,
    volatile uint16_t *flags)
{
	if (!dtrace_copycheck(uaddr, kaddr, size))
		return;

	while (size != 0) {
		store8_to_user((uint8_t*)uaddr, *(uint8_t *)kaddr);
		if (*flags & CPU_DTRACE_FAULT)
			break;
		kaddr++;
		uaddr++;
		size--;
	}
}

void
dtrace_copyinstr(uintptr_t uaddr, uintptr_t kaddr, size_t size,
    volatile uint16_t *flags)
{
	if (!dtrace_copycheck(uaddr, kaddr, size))
		return;

	while (size != 0) {
		uint8_t v = load8_from_user((uint8_t *)uaddr);
		*(uint8_t *)kaddr = v;
		if (*flags & CPU_DTRACE_FAULT)
			break;
		if (v == 0)
			break;
		kaddr++;
		uaddr++;
		size--;
	}
}

void
dtrace_copyoutstr(uintptr_t kaddr, uintptr_t uaddr, size_t size,
    volatile uint16_t *flags)
{
	if (!dtrace_copycheck(uaddr, kaddr, size))
		return;

	while (size != 0) {
		uint8_t v = *(uint8_t *)kaddr;
		store8_to_user((uint8_t *)uaddr, v);
		if (*flags & CPU_DTRACE_FAULT)
			break;
		if (v == 0)
			break;
		kaddr++;
		uaddr++;
		size--;
	}
}

uint8_t
dtrace_fuword8(void *uaddr)
{
	if ((uintptr_t)uaddr >= _userlimit) {
		DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
		cpu_core[CPU->cpu_id].cpuc_dtrace_illval = (uintptr_t)uaddr;
		return (0);
	}
	return load8_from_user((uint8_t *)uaddr);
}

uint16_t
dtrace_fuword16(void *uaddr)
{
	if ((uintptr_t)uaddr >= _userlimit) {
		DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
		cpu_core[CPU->cpu_id].cpuc_dtrace_illval = (uintptr_t)uaddr;
		return (0);
	}
	return load16_from_user((uint16_t *)uaddr);
}

uint32_t
dtrace_fuword32(void *uaddr)
{
	if ((uintptr_t)uaddr >= _userlimit) {
		DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
		cpu_core[CPU->cpu_id].cpuc_dtrace_illval = (uintptr_t)uaddr;
		return (0);
	}
	return load32_from_user((uint32_t *)uaddr);
}

uint64_t
dtrace_fuword64(void *uaddr)
{
	if ((uintptr_t)uaddr >= _userlimit) {
		DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
		cpu_core[CPU->cpu_id].cpuc_dtrace_illval = (uintptr_t)uaddr;
		return (0);
	}
	return load64_from_user((uint64_t *)uaddr);
}

uintptr_t
dtrace_fulword(void *uaddr)
{
	if ((uintptr_t)uaddr >= _userlimit) {
		DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
		cpu_core[CPU->cpu_id].cpuc_dtrace_illval = (uintptr_t)uaddr;
		return (0);
	}
	return load64_from_user((uintptr_t *)uaddr);
}
