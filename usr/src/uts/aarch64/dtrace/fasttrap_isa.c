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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/fasttrap_isa.h>
#include <sys/fasttrap_impl.h>
#include <sys/dtrace.h>
#include <sys/dtrace_impl.h>
#include <sys/cmn_err.h>
#include <sys/regset.h>
#include <sys/privregs.h>
#include <sys/sysmacros.h>
#include <sys/trap.h>
#include <sys/archsystm.h>
#include <sys/controlregs.h>
#include <sys/fp.h>
#include <stdbool.h>
#include <sys/promif.h>

void dtrace_set_sreg(int reg, const uint32_t* val);
void dtrace_set_dreg(int reg, const uint64_t* val);
void dtrace_set_qreg(int reg, const __uint128_t* val);

static ulong_t fasttrap_getreg(struct regs *, uint_t);

static uint64_t
fasttrap_anarg(struct regs *rp, int argno)
{
	uint64_t value;

	uintptr_t *stack;

	if (argno < 8)
		return fasttrap_getreg(rp, argno);

	stack = (uintptr_t *)rp->r_sp;
	DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
	value = dtrace_fulword(&stack[argno - 8]);
	DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT | CPU_DTRACE_BADADDR);

	return (value);
}

/*ARGSUSED*/
int
fasttrap_tracepoint_init(proc_t *p, fasttrap_tracepoint_t *tp, uintptr_t pc,
    fasttrap_probe_type_t type)
{
	uint32_t instr;

	if (uread(p, &instr, sizeof(instr), pc) != 0)
		return (-1);

	tp->ftt_instr = instr;

	if ((instr & 0x3b200c00) == 0x38200000) {
		cmn_err(CE_NOTE, "atomic instruction is not supported %08x at %lx", instr, pc);
		return -1;
	}
	if ((instr & 0xff000010) == 0x54000000)
		tp->ftt_type = FASTTRAP_T_B_COND;	// b.cond <label>
	else if ((instr & 0xff000000) == 0x1c000000)
		tp->ftt_type = FASTTRAP_T_LDR_LITERAL;	// ldr <St>, <label>
	else if ((instr & 0xff000000) == 0x5c000000)
		tp->ftt_type = FASTTRAP_T_LDR_LITERAL;	// ldr <Dt>, <label>
	else if ((instr & 0xff000000) == 0x9c000000)
		tp->ftt_type = FASTTRAP_T_LDR_LITERAL;	// ldr <Qt>, <label>
	else if ((instr & 0xff000000) == 0x18000000)
		tp->ftt_type = FASTTRAP_T_LDR_LITERAL;	// ldr <Wt>, <label>
	else if ((instr & 0xff000000) == 0x58000000)
		tp->ftt_type = FASTTRAP_T_LDR_LITERAL;	// ldr <Xt>, <label>
	else if ((instr & 0xff000000) == 0x98000000)
		tp->ftt_type = FASTTRAP_T_LDR_LITERAL;	// ldrsw <Xt>, <label>
	else if ((instr & 0xff000000) == 0x34000000)
		tp->ftt_type = FASTTRAP_T_CBZ;		// cbz <Wt>, <label>
	else if ((instr & 0xff000000) == 0x35000000)
		tp->ftt_type = FASTTRAP_T_CBZ;		// cbnz <Wt>, <label>
	else if ((instr & 0xff000000) == 0xb4000000)
		tp->ftt_type = FASTTRAP_T_CBZ;		// cbz <Xt>, <label>
	else if ((instr & 0xff000000) == 0xb5000000)
		tp->ftt_type = FASTTRAP_T_CBZ;		// cbnz <Xt>, <label>
	else if ((instr & 0xff000000) == 0x36000000)
		tp->ftt_type = FASTTRAP_T_TBZ;		// tbz <Wt>, #<imm>, <label>
	else if ((instr & 0xff000000) == 0x37000000)
		tp->ftt_type = FASTTRAP_T_TBZ;		// tbnz <Wt>, #<imm>, <label>
	else if ((instr & 0xff000000) == 0xb6000000)
		tp->ftt_type = FASTTRAP_T_TBZ;		// tbz <Xt>, #<imm>, <label>
	else if ((instr & 0xff000000) == 0xb7000000)
		tp->ftt_type = FASTTRAP_T_TBZ;		// tbnz <Xt>, #<imm>, <label>
	else if ((instr & 0xfc000000) == 0x14000000)
		tp->ftt_type = FASTTRAP_T_B;		// b <label>
	else if ((instr & 0xfc000000) == 0x94000000)
		tp->ftt_type = FASTTRAP_T_BL;		// bl <label>
	else if ((instr & 0xfffffc1f) == 0xd63f0000)
		tp->ftt_type = FASTTRAP_T_BLR;		// blr <Xt>
	else if ((instr & 0xfffffc1f) == 0xd61f0000)
		tp->ftt_type = FASTTRAP_T_BR;		// br <Xt>
	else if ((instr & 0xfffffc1f) == 0xd65f0000)
		tp->ftt_type = FASTTRAP_T_RET;		// ret <Xt>
	else if ((instr & 0x9f000000) == 0x10000000)
		tp->ftt_type = FASTTRAP_T_ADR;		// adr <Xt>, <label>
	else if ((instr & 0x9f000000) == 0x90000000)
		tp->ftt_type = FASTTRAP_T_ADR;		// adrp <Xt>, <label>
	else
		tp->ftt_type = FASTTRAP_T_COMMON;

	return (0);
}

int
fasttrap_tracepoint_install(proc_t *p, fasttrap_tracepoint_t *tp)
{
	fasttrap_instr_t instr = FASTTRAP_INSTR;

	if (uwrite(p, &instr, sizeof(instr), tp->ftt_pc) != 0)
		return (-1);

	return (0);
}

int
fasttrap_tracepoint_remove(proc_t *p, fasttrap_tracepoint_t *tp)
{
	uint32_t instr;

	/*
	 * Distinguish between read or write failures and a changed
	 * instruction.
	 */
	if (uread(p, &instr, sizeof(instr), tp->ftt_pc) != 0)
		return (0);
	if (instr != FASTTRAP_INSTR)
		return (0);
	if (uwrite(p, &tp->ftt_instr, sizeof(tp->ftt_instr), tp->ftt_pc) != 0)
		return (-1);

	return (0);
}

static uintptr_t
fasttrap_fulword_noerr(const void *uaddr)
{
	uintptr_t ret;

	if (fasttrap_fulword(uaddr, &ret) == 0)
		return (ret);

	return (0);
}

static void
fasttrap_return_common(struct regs *rp, uintptr_t pc, pid_t pid,
    uintptr_t new_pc)
{
	fasttrap_tracepoint_t *tp;
	fasttrap_bucket_t *bucket;
	fasttrap_id_t *id;
	kmutex_t *pid_mtx;

	pid_mtx = &cpu_core[CPU->cpu_id].cpuc_pid_lock;
	mutex_enter(pid_mtx);
	bucket = &fasttrap_tpoints.fth_table[FASTTRAP_TPOINTS_INDEX(pid, pc)];

	for (tp = bucket->ftb_data; tp != NULL; tp = tp->ftt_next) {
		if (pid == tp->ftt_pid && pc == tp->ftt_pc &&
		    tp->ftt_proc->ftpc_acount != 0)
			break;
	}

	/*
	 * Don't sweat it if we can't find the tracepoint again; unlike
	 * when we're in fasttrap_pid_probe(), finding the tracepoint here
	 * is not essential to the correct execution of the process.
	 */
	if (tp == NULL) {
		mutex_exit(pid_mtx);
		return;
	}

	for (id = tp->ftt_retids; id != NULL; id = id->fti_next) {
		/*
		 * If there's a branch that could act as a return site, we
		 * need to trace it, and check here if the program counter is
		 * external to the function.
		 */
		if (tp->ftt_type != FASTTRAP_T_RET &&
		    new_pc - id->fti_probe->ftp_faddr <
		    id->fti_probe->ftp_fsize)
			continue;

		dtrace_probe(id->fti_probe->ftp_id,
		    pc - id->fti_probe->ftp_faddr,
		    rp->r_x0, rp->r_x1, 0, 0);
	}

	mutex_exit(pid_mtx);
}

static void
fasttrap_usdt_args(fasttrap_probe_t *probe, struct regs *rp, int argc,
    uintptr_t *argv)
{
	int i, x, cap = MIN(argc, probe->ftp_nargs);
	uintptr_t *stack = (uintptr_t *)rp->r_sp;

	for (i = 0; i < cap; i++) {
		x = probe->ftp_argmap[i];

		if (x < 8)
			argv[i] = (&rp->r_x0)[x];
		else
			argv[i] = fasttrap_fulword_noerr(&stack[x]);
	}

	for (; i < argc; i++) {
		argv[i] = 0;
	}
}

static uint64_t
sign_extend(uint64_t v, int num)
{
	return ((v + (1ul << (num - 1))) & ((1ul << num) - 1)) - (1ul << (num - 1));
}

static uint64_t
extract_literal_offset(uint32_t instr, int lo, int width)
{
	return sign_extend((instr >> lo) & ((1ul << width) - 1), width) << 2;
}

int
fasttrap_pid_probe(struct regs *rp)
{
	proc_t *p = curproc;
	uintptr_t pc = rp->r_pc - 4, new_pc = 0;
	fasttrap_bucket_t *bucket;
	kmutex_t *pid_mtx;
	fasttrap_tracepoint_t *tp, tp_local;
	pid_t pid;
	dtrace_icookie_t cookie;
	uint_t is_enabled = 0;

	/*
	 * It's possible that a user (in a veritable orgy of bad planning)
	 * could redirect this thread's flow of control before it reached the
	 * return probe fasttrap. In this case we need to kill the process
	 * since it's in a unrecoverable state.
	 */
	if (curthread->t_dtrace_step) {
		ASSERT(curthread->t_dtrace_on);
		fasttrap_sigtrap(p, curthread, pc);
		return (0);
	}

	/*
	 * Clear all user tracing flags.
	 */
	curthread->t_dtrace_ft = 0;
	curthread->t_dtrace_pc = 0;
	curthread->t_dtrace_npc = 0;
	curthread->t_dtrace_scrpc = 0;
	curthread->t_dtrace_astpc = 0;

	/*
	 * Treat a child created by a call to vfork(2) as if it were its
	 * parent. We know that there's only one thread of control in such a
	 * process: this one.
	 */
	while (p->p_flag & SVFORK) {
		p = p->p_parent;
	}

	pid = p->p_pid;
	pid_mtx = &cpu_core[CPU->cpu_id].cpuc_pid_lock;
	mutex_enter(pid_mtx);
	bucket = &fasttrap_tpoints.fth_table[FASTTRAP_TPOINTS_INDEX(pid, pc)];

	/*
	 * Lookup the tracepoint that the process just hit.
	 */
	for (tp = bucket->ftb_data; tp != NULL; tp = tp->ftt_next) {
		if (pid == tp->ftt_pid && pc == tp->ftt_pc &&
		    tp->ftt_proc->ftpc_acount != 0)
			break;
	}

	/*
	 * If we couldn't find a matching tracepoint, either a tracepoint has
	 * been inserted without using the pid<pid> ioctl interface (see
	 * fasttrap_ioctl), or somehow we have mislaid this tracepoint.
	 */
	if (tp == NULL) {
		mutex_exit(pid_mtx);
		return (-1);
	}

	/*
	 * Set the program counter to the address of the traced instruction
	 * so that it looks right in ustack() output.
	 */
	rp->r_pc = pc;

	if (tp->ftt_ids != NULL) {
		fasttrap_id_t *id;

		for (id = tp->ftt_ids; id != NULL; id = id->fti_next) {
			fasttrap_probe_t *probe = id->fti_probe;

			if (id->fti_ptype == DTFTP_ENTRY) {
				/*
				 * We note that this was an entry
				 * probe to help ustack() find the
				 * first caller.
				 */
				cookie = dtrace_interrupt_disable();
				DTRACE_CPUFLAG_SET(CPU_DTRACE_ENTRY);
				dtrace_probe(probe->ftp_id, rp->r_x0,
				    rp->r_x1, rp->r_x2, rp->r_x3,
				    rp->r_x4);
				DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_ENTRY);
				dtrace_interrupt_enable(cookie);
			} else if (id->fti_ptype == DTFTP_IS_ENABLED) {
				/*
				 * Note that in this case, we don't
				 * call dtrace_probe() since it's only
				 * an artificial probe meant to change
				 * the flow of control so that it
				 * encounters the true probe.
				 */
				is_enabled = 1;
			} else if (probe->ftp_argmap == NULL) {
				dtrace_probe(probe->ftp_id, rp->r_x0,
				    rp->r_x1, rp->r_x2, rp->r_x3,
				    rp->r_x4);
			} else {
				uintptr_t t[5];

				fasttrap_usdt_args(probe, rp,
				    sizeof (t) / sizeof (t[0]), t);

				dtrace_probe(probe->ftp_id, t[0], t[1],
				    t[2], t[3], t[4]);
			}
		}
	}

	/*
	 * We're about to do a bunch of work so we cache a local copy of
	 * the tracepoint to emulate the instruction, and then find the
	 * tracepoint again later if we need to light up any return probes.
	 */
	tp_local = *tp;
	mutex_exit(pid_mtx);
	tp = &tp_local;

	/*
	 * If there's an is-enabled probe connected to this tracepoint it
	 * means that there was a 'xorl %eax, %eax' or 'xorq %rax, %rax'
	 * instruction that was placed there by DTrace when the binary was
	 * linked. As this probe is, in fact, enabled, we need to stuff 1
	 * into %eax or %rax. Accordingly, we can bypass all the instruction
	 * emulation logic since we know the inevitable result. It's possible
	 * that a user could construct a scenario where the 'is-enabled'
	 * probe was on some other instruction, but that would be a rather
	 * exotic way to shoot oneself in the foot.
	 */
	if (is_enabled) {
		rp->r_x0 = 1;
		new_pc = rp->r_pc;
		goto done;
	}

	/*
	 * We emulate certain types of instructions to ensure correctness
	 * (in the case of position dependent instructions) or optimize
	 * common cases. The rest we have the thread execute back in user-
	 * land.
	 */
	uint32_t instr = tp->ftt_instr;
	switch (tp->ftt_type) {
	case FASTTRAP_T_LDR_LITERAL:
		{
			unsigned regno = (instr & 0x1f);
			uintptr_t addr = pc + extract_literal_offset(instr, 5, 19);
			int opc = (instr >> 30);

			if (instr & (1u << 26)) {
				ASSERT(opc == 0 || opc == 1 || opc == 2);
				if (opc == 0) {
					// LDR (literal, SIMD&FP) - 32-bit variant
					uint32_t val;
					if (copyin((void *)addr, &val, sizeof(val))) {
						fasttrap_sigtrap(p, curthread, pc);
						new_pc = pc;
					} else {
						fp_fenflt();
						dtrace_set_sreg(regno, &val);
						new_pc = pc + 4;
					}
				}
				else if (opc == 1) {
					// LDR (literal, SIMD&FP) - 64-bit variant
					uint64_t val;
					if (copyin((void *)addr, &val, sizeof(val))) {
						fasttrap_sigtrap(p, curthread, pc);
						new_pc = pc;
					} else {
						fp_fenflt();
						dtrace_set_dreg(regno, &val);
						new_pc = pc + 4;
					}
				}
				else if (opc == 2) {
					// LDR (literal, SIMD&FP) - 128-bit variant
					__uint128_t val;
					if (copyin((void *)addr, &val, sizeof(val))) {
						fasttrap_sigtrap(p, curthread, pc);
						new_pc = pc;
					} else {
						fp_fenflt();
						dtrace_set_qreg(regno, &val);
						new_pc = pc + 4;
					}
				}
			} else {
				ASSERT(opc == 0 || opc == 1 || opc == 2);
				if (opc == 0) {
					// LDR (literal) - 32-bit variant
					uint32_t val;
					if (copyin((void *)addr, &val, sizeof(val))) {
						fasttrap_sigtrap(p, curthread, pc);
						new_pc = pc;
					} else {
						if (regno != 0x1f)
							(&rp->r_x0)[regno] = val;
						new_pc = pc + 4;
					}
				}
				else if (opc == 1) {
					// LDR (literal) - 64-bit variant
					uint64_t val;
					if (copyin((void *)addr, &val, sizeof(val))) {
						fasttrap_sigtrap(p, curthread, pc);
						new_pc = pc;
					} else {
						if (regno != 0x1f)
							(&rp->r_x0)[regno] = val;
						new_pc = pc + 4;
					}
				}
				else if (opc == 2) {
					// LDRSW (literal)
					uint32_t val;
					if (copyin((void *)addr, &val, sizeof(val))) {
						fasttrap_sigtrap(p, curthread, pc);
						new_pc = pc;
					} else {
						if (regno != 0x1f)
							(&rp->r_x0)[regno] = sign_extend(val, 32);
						new_pc = pc + 4;
					}
				}
			}
		}
		break;
	case FASTTRAP_T_BLR:
		{
			unsigned regno = ((instr >> 5) & 0x1f);
			new_pc = (regno == 0x1f)? 0: fasttrap_getreg(rp, regno);
			rp->r_x30 = pc + 4;
		}
		break;
	case FASTTRAP_T_RET:
	case FASTTRAP_T_BR:
		{
			unsigned regno = ((instr >> 5) & 0x1f);
			new_pc = (regno == 0x1f)? 0: fasttrap_getreg(rp, regno);
		}
		break;
	case FASTTRAP_T_TBZ:
		{
			unsigned regno = (instr & 0x1f);
			int index = (((instr >> 31) & 1) << 5) | (((instr >> 19) & 0x1f) << 0);
			uint64_t v = (regno == 0x1f)? 0: fasttrap_getreg(rp, regno);
			bool cond = !!(v & (1ul << index));
			if (instr & (1 << 24))
				cond = !cond;
			uint64_t offset = cond? extract_literal_offset(instr, 5, 14): 4;
			new_pc = pc + offset;
		}
		break;
	case FASTTRAP_T_CBZ:
		{
			unsigned regno = (instr & 0x1f);
			uint64_t v = (regno == 0x1f)? 0: fasttrap_getreg(rp, regno);
			if ((instr & (1u << 31)) == 0)
				v &= 0xfffffffful;
			bool cond = (v == 0);
			if (instr & (1 << 24))
				cond = !cond;
			uint64_t offset = cond? extract_literal_offset(instr, 5, 19): 4;
			new_pc = pc + offset;
		}
		break;
	case FASTTRAP_T_B_COND:
		{
			bool cond;
			switch (instr & 0xf) {
			case 0: cond = !!(rp->r_spsr & PSR_Z); break;
			case 1: cond = !(rp->r_spsr & PSR_Z); break;
			case 2: cond = !!(rp->r_spsr & PSR_C); break;
			case 3: cond = !(rp->r_spsr & PSR_C); break;
			case 4: cond = !!(rp->r_spsr & PSR_N); break;
			case 5: cond = !(rp->r_spsr & PSR_N); break;
			case 6: cond = !!(rp->r_spsr & PSR_V); break;
			case 7: cond = !(rp->r_spsr & PSR_V); break;
			case 8: cond = !!(rp->r_spsr & PSR_C) && !(rp->r_spsr & PSR_Z); break;
			case 9: cond = !(rp->r_spsr & PSR_C) || !!(rp->r_spsr & PSR_Z); break;
			case 10: cond = !!(rp->r_spsr & PSR_N) == !!(rp->r_spsr & PSR_V); break;
			case 11: cond = !!(rp->r_spsr & PSR_N) != !!(rp->r_spsr & PSR_V); break;
			case 12: cond = !(rp->r_spsr & PSR_Z) && (!!(rp->r_spsr & PSR_N) == !!(rp->r_spsr & PSR_V)); break;
			case 13: cond = !!(rp->r_spsr & PSR_Z) || (!!(rp->r_spsr & PSR_N) != !!(rp->r_spsr & PSR_V)); break;
			default:
				 cond = true;
			}
			uint64_t offset = cond? extract_literal_offset(instr, 5, 19): 4;
			new_pc = pc + offset;
		}
		break;
	case FASTTRAP_T_B:
		{
			new_pc = pc + extract_literal_offset(instr, 0, 26);
		}
		break;
	case FASTTRAP_T_BL:
		{
			new_pc = pc + extract_literal_offset(instr, 0, 26);
			rp->r_x30 = pc + 4;
		}
		break;
	case FASTTRAP_T_ADR:
		{
			unsigned regno = (instr & 0x1f);
			if (regno != 0x1f) {
				uint64_t offset = (((instr >> 5) & ((1u << 19) - 1)) << 2) | ((instr >> 29) & ((1u << 2) - 1));
				offset = sign_extend(offset, 21);
				(&rp->r_x0)[regno] = ((instr & (1u << 31))? (pc & ~0xffful) + (offset << 12): pc + offset);
			}
			new_pc = pc + 4;
		}
		break;
	case FASTTRAP_T_COMMON:
	{
		uintptr_t addr;
		uint32_t scratch[2];

		addr = read_tpidr_el0();
		addr += sizeof (void *);

		/*
		 * Generic Instruction Tracing
		 * ---------------------------
		 *
		 * 	<original instruction>
		 *	svc #T_DTRACE_RET
		 */
		scratch[0] = instr;
		scratch[1] = FASTTRAP_RET_INSTR;
		if (copyout(scratch, (void*)addr, sizeof(scratch))) {
			fasttrap_sigtrap(p, curthread, pc);
			new_pc = pc;
		} else {
			clean_data_cache_pou(addr);
			dsb(ish);
			invalidate_instruction_cache(addr);
			dsb(ish);
			uintptr_t line_size = 4 * (1ul << (read_ctr_el0() & 0xF));
			if ((addr & ~(line_size - 1)) != ((addr + 4) & ~(line_size - 1))) {
				clean_data_cache_pou(addr + 4);
				dsb(ish);
				invalidate_instruction_cache(addr + 4);
				dsb(ish);
			}

			curthread->t_dtrace_step = 1;
			curthread->t_dtrace_ret = 1;
			curthread->t_dtrace_pc = pc;
			curthread->t_dtrace_npc = pc + 4;
			curthread->t_dtrace_on = 1;
			new_pc = curthread->t_dtrace_astpc = curthread->t_dtrace_scrpc = addr;
		}
		break;
	}

	default:
		panic("fasttrap: mishandled an instruction");
	}

done:
	/*
	 * If there were no return probes when we first found the tracepoint,
	 * we should feel no obligation to honor any return probes that were
	 * subsequently enabled -- they'll just have to wait until the next
	 * time around.
	 */
	if (tp->ftt_retids != NULL) {
		/*
		 * We need to wait until the results of the instruction are
		 * apparent before invoking any return probes. If this
		 * instruction was emulated we can just call
		 * fasttrap_return_common(); if it needs to be executed, we
		 * need to wait until the user thread returns to the kernel.
		 */
		if (tp->ftt_type != FASTTRAP_T_COMMON) {
			/*
			 * Set the program counter to the address of the traced
			 * instruction so that it looks right in ustack()
			 * output. We had previously set it to the end of the
			 * instruction to simplify %rip-relative addressing.
			 */
			rp->r_pc = pc;

			fasttrap_return_common(rp, pc, pid, new_pc);
		} else {
			ASSERT(curthread->t_dtrace_ret != 0);
			ASSERT(curthread->t_dtrace_pc == pc);
			ASSERT(curthread->t_dtrace_scrpc != 0);
			ASSERT(new_pc == curthread->t_dtrace_astpc);
		}
	}

	rp->r_pc = new_pc;

	return (0);
}

int
fasttrap_return_probe(struct regs *rp)
{
	proc_t *p = curproc;
	uintptr_t pc = curthread->t_dtrace_pc;
	uintptr_t npc = curthread->t_dtrace_npc;

	curthread->t_dtrace_pc = 0;
	curthread->t_dtrace_npc = 0;
	curthread->t_dtrace_scrpc = 0;
	curthread->t_dtrace_astpc = 0;

	/*
	 * Treat a child created by a call to vfork(2) as if it were its
	 * parent. We know that there's only one thread of control in such a
	 * process: this one.
	 */
	while (p->p_flag & SVFORK) {
		p = p->p_parent;
	}

	/*
	 * We set rp->r_pc to the address of the traced instruction so
	 * that it appears to dtrace_probe() that we're on the original
	 * instruction, and so that the user can't easily detect our
	 * complex web of lies. dtrace_return_probe() (our caller)
	 * will correctly set %pc after we return.
	 */
	rp->r_pc = pc;

	fasttrap_return_common(rp, pc, p->p_pid, npc);

	return (0);
}

/*ARGSUSED*/
uint64_t
fasttrap_pid_getarg(void *arg, dtrace_id_t id, void *parg, int argno,
    int aframes)
{
	return (fasttrap_anarg(ttolwp(curthread)->lwp_regs, argno));
}

/*ARGSUSED*/
uint64_t
fasttrap_usdt_getarg(void *arg, dtrace_id_t id, void *parg, int argno,
    int aframes)
{
	return (fasttrap_anarg(ttolwp(curthread)->lwp_regs, argno));
}

static ulong_t
fasttrap_getreg(struct regs *rp, uint_t reg)
{
	switch (reg) {
	case REG_X0:		return (rp->r_x0);
	case REG_X1:		return (rp->r_x1);
	case REG_X2:		return (rp->r_x2);
	case REG_X3:		return (rp->r_x3);
	case REG_X4:		return (rp->r_x4);
	case REG_X5:		return (rp->r_x5);
	case REG_X6:		return (rp->r_x6);
	case REG_X7:		return (rp->r_x7);
	case REG_X8:		return (rp->r_x8);
	case REG_X9:		return (rp->r_x9);
	case REG_X10:		return (rp->r_x10);
	case REG_X11:		return (rp->r_x11);
	case REG_X12:		return (rp->r_x12);
	case REG_X13:		return (rp->r_x13);
	case REG_X14:		return (rp->r_x14);
	case REG_X15:		return (rp->r_x15);
	case REG_X16:		return (rp->r_x16);
	case REG_X17:		return (rp->r_x17);
	case REG_X18:		return (rp->r_x18);
	case REG_X19:		return (rp->r_x19);
	case REG_X20:		return (rp->r_x20);
	case REG_X21:		return (rp->r_x21);
	case REG_X22:		return (rp->r_x22);
	case REG_X23:		return (rp->r_x23);
	case REG_X24:		return (rp->r_x24);
	case REG_X25:		return (rp->r_x25);
	case REG_X26:		return (rp->r_x26);
	case REG_X27:		return (rp->r_x27);
	case REG_X28:		return (rp->r_x28);
	case REG_X29:		return (rp->r_x29);
	case REG_X30:		return (rp->r_x30);
	case REG_SP:		return (rp->r_sp);
	case REG_PC:		return (rp->r_pc);
	case REG_PSR:		return (rp->r_spsr);
	case REG_TP:		return read_tpidr_el0();
	}

	panic("dtrace: illegal register constant");
}

