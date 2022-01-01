/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 */

#include <sys/asm_linkage.h>
#include <sys/machparam.h>
#include "assym.h"

	/*
	 * NOTE: t0stack should be the first thing in the data section so that
	 * if it ever overflows, it will fault on the last kernel text page.
	 */
	.data
	.globl	t0stack
	.type	t0stack, @object
	.align	MMU_PAGESHIFT
t0stack:
	.zero	DEFAULTSTKSZ
	SET_SIZE(t0stack)

	/*
	 * Memory for t0 itself is placed immediately after the t0stack, which
	 * is not a requirement, but is easy to reason about.
	 */
	.globl	t0
	.type	t0, @object
	.align	MMU_PAGESHIFT
t0:
	.zero	MMU_PAGESIZE
	SET_SIZE(t0)

	.text
	.extern	sysp
	.extern	bootops
	.extern	bootopsp
	.extern mlsetup
	.extern panic

	/*
	 * eboot hands off to us here
	 *
	 * void _start(struct xboot_info *xbp) __noreturn;
	 */
	ENTRY(_start)
	/*
	 * Use the t0 stack for fakebop/kobj startup, as it's substantially
	 * larger than the eboot stack (and we can control the stack size).
	 *
	 * Note that we still leave space for a struct regs, just like in
	 * _locore_start, though we don't use it here.  We do this to avoid
	 * leaving rubbish in the struct regs area.
	 */
	mov	x17, #1
	msr	SPSel, x17
	ldr	x17, =t0stack		/* load up the stack memory location */
	add	x17, x17, #DEFAULTSTKSZ	/* add the stack size (grows down) */
	mov	x16, #REGSIZE		/* grab the size of struct regs */
	sub	x17, x17, x16		/* create space for struct regs */
	bic	sp, x17, #0x7		/* align the stack pointer into sp */
	adrp	x1, aarch64_vector_table
	add	x1, x1, :lo12:aarch64_vector_table
	msr	vbar_el1, x1
	adrp	x1, fakebop_start
	add	x1, x1, :lo12:fakebop_start
	br	x1
	SET_SIZE(_start)

	/*
	 * kobj_init() vectors us back to here with the boot services vector
	 * in x0 and the boot ops in x1.
	 *
	 * The boot ops argument is of type 'struct bootops *', and the boot
	 * services argument is of type 'struct boot_syscalls *'.
	 *
	 * These are both exactly as passed to kobj_boot (and then on to
	 * kobj_init) by _start, which you can find in os/fakebop.c.
	 */
	ENTRY(_locore_start)
	/*
	 * sysp = (struct boot_syscalls *)x0;
	 *
	 * After this is done we should have a working panic.
	 */
	adrp	x16, sysp
	add	x16, x16, :lo12:sysp
	str	x0, [x16]

	/*
	 * bootops = (struct boot_syscalls *)x1;
	 */
	adrp	x16, bootops
	add	x16, x16, :lo12:bootops
	str	x1, [x16]

	/*
	 * *bootopsp = bootops;
	 */
	adrp	x17, bootopsp
	add	x17, x17, :lo12:bootopsp
	str	x16, [x17]

	/*
	 * Hook up the thread 0 stack, leaving space for a struct regs.
	 *
	 * The pointer to the created struct regs is left in x0 for passing to
	 * mlsetup.
	 */
	ldr	x17, =t0stack		/* load up the stack memory location */
	add	x17, x17, #DEFAULTSTKSZ	/* add the stack size (grows down) */
	mov	x16, #REGSIZE		/* grab the size of struct regs */
	sub	x17, x17, x16		/* create space for struct regs */
	mov	x0, x17			/* struct regs is passed to mlsetup */
	bic	sp, x17, #0x7		/* align the stack pointer into sp */

	/*
	 * Set up an empty stackframe so that backtraces don't go past here.
	 */
	mov	lr, #0
	mov	fp, #0
	stp	xzr, xzr, [sp, #-16]!	/* create a terminal stackframe */
	mov	fp, sp			/* backtraces stop here */

	/*
	 * XXXAARCH64: Enable alignment check faults etc.
	 */

	/*
	 * We could/should set all registers to a known state here,
	 * then stash them into the regset we've made space for.
	 */

	/*
	 * btsl    $X86FSET_CPUID, x86_featureset(%rip)
	 * What does this do? CPU identification part 0, but what are we
	 * collecting and where will be use it?
	 */

	/*
	 * Set our current thread pointer to t0 so that curcpup can find us in
	 * C code.
	 */
	adrp	x16, t0
	add	x16, x16, :lo12:t0
	msr	tpidr_el1, x16

	/*
	 * Set up an early vector table to catch mistakes.  This will be
	 * patched out to support the full kernel once we're closer to
	 * running.
	 *
	 * We could/should do this immediately after setting up the stack.
	 */
	adrp	x16, aarch64_vector_table
	add	x16, x16, :lo12:aarch64_vector_table
	msr	vbar_el1, x16

	ldr	x16, =edata		/* why is this needed? */

	/*
	 * Call mlsetup with our struct regs as the first and only argument.
	 */
	bl	mlsetup

	/*
	 * Main takes no arguments and is not supposed to return.  If it does,
	 * we panic.
	 */
	bl	main

	adrp	x0, __return_from_main
	add	x0, x0, :lo12:__return_from_main
	bl	panic
	msr	daifset, #15
1:	wfe
	b	1b
	SET_SIZE(_locore_start)

	.type	__return_from_main, @object
	.align	3
__return_from_main:
	.string	"main() returned"
	SET_SIZE(__return_from_main)

	ENTRY(__just_chill)
9:	b	9b
	SET_SIZE(__just_chill)

	/*
	 * The exception table consists of four sets of four entries. Each entry
	 * is 16 instructions long.
	 */
	.text
	.type	aarch64_vector_table, @object
	.balign	0x800
aarch64_vector_table:
	/*
	 * Current EL with SP0
	 */
	ENTRY(__cur_el_sp0_sync)
	b	__cur_el_sp0_sync
	.balign	0x80
	SET_SIZE(__cur_el_sp0_sync)
	ENTRY(__cur_el_sp0_irq)
	b	__cur_el_sp0_irq
	.balign	0x80
	SET_SIZE(__cur_el_sp0_irq)
	ENTRY(__cur_el_sp0_fiq)
	b	__cur_el_sp0_fiq
	.balign	0x80
	SET_SIZE(__cur_el_sp0_fiq)
	ENTRY(__cur_el_sp0_serr)
	b	__cur_el_sp0_serr
	.balign	0x80
	SET_SIZE(__cur_el_sp0_serr)
	/*
	 * Current EL with SPx
	 */
	ENTRY(__cur_el_spx_sync)
	b	__cur_el_spx_sync
	.balign	0x80
	SET_SIZE(__cur_el_spx_sync)
	ENTRY(__cur_el_spx_irq)
	b	__cur_el_spx_irq
	.balign	0x80
	SET_SIZE(__cur_el_spx_irq)
	ENTRY(__cur_el_spx_fiq)
	b	__cur_el_spx_fiq
	.balign	0x80
	SET_SIZE(__cur_el_spx_fiq)
	ENTRY(__cur_el_spx_serr)
	b	__cur_el_spx_serr
	.balign	0x80
	SET_SIZE(__cur_el_spx_serr)
	/*
	 * Lower EL using AArch64
	 */
	ENTRY(__lwr_el_aa64_sync)
	b	__lwr_el_aa64_sync
	.balign	0x80
	SET_SIZE(__lwr_el_aa64_sync)
	ENTRY(__lwr_el_aa64_irq)
	b	__lwr_el_aa64_irq
	.balign	0x80
	SET_SIZE(__lwr_el_aa64_irq)
	ENTRY(__lwr_el_aa64_fiq)
	b	__lwr_el_aa64_fiq
	.balign	0x80
	SET_SIZE(__lwr_el_aa64_fiq)
	ENTRY(__lwr_el_aa64_serr)
	b	__lwr_el_aa64_serr
	.balign	0x80
	SET_SIZE(__lwr_el_aa64_serr)
	/*
	 * Lower EL using AArch32
	 */
	ENTRY(__lwr_el_aa32_sync)
	b	__lwr_el_aa32_sync
	.balign	0x80
	SET_SIZE(__lwr_el_aa32_sync)
	ENTRY(__lwr_el_aa32_irq)
	b	__lwr_el_aa32_irq
	.balign	0x80
	SET_SIZE(__lwr_el_aa32_irq)
	ENTRY(__lwr_el_aa32_fiq)
	b	__lwr_el_aa32_fiq
	.balign	0x80
	SET_SIZE(__lwr_el_aa32_fiq)
	ENTRY(__lwr_el_aa32_serr)
	b	__lwr_el_aa32_serr
	.balign	0x80
	SET_SIZE(__lwr_el_aa32_serr)
	SET_SIZE(aarch64_vector_table)

	/*
	 * XXXAARCH64: disable this for now, we want something more like Intel
	 */
	ENTRY(_XXXAARCH64_start)
	mov	x1, #1
	msr	SPSel, x1
	ldr	x1, =t0stack
	ldr	x2, =DEFAULTSTKSZ
	add	x1, x1, x2
	mov	x29, x1
	mov	sp, x1

	// XXAARCH64: stitch this together like Intel, not like sparc
	// bl	kobj_start
	mov	x0, sp
	bl	mlsetup
	bl	main
1:	b	1b

	SET_SIZE(_XXXAARCH64_start)

	.text
	.balign 4096
	.globl secondary_vec_start
secondary_vec_start:
	// disable smp
	mrs	x0, midr_el1
	mov	w0, w0
	lsr	w1, w0, #24
	cmp	w1, #0x41
	b.ne	.Lnot_arm_core

	// cpuectlr SMPEN -> 1
	mrs	x0, s3_1_c15_c2_1
	tbnz	x0, #6, .Lnot_arm_core
	orr	x1, x0, #(1 << 6)
	msr	s3_1_c15_c2_1, x0
	isb

.Lnot_arm_core:
	// invalidate cache (data/inst)
	bl	dcache_invalidate_all
	ic	iallu
	dsb	ish
	isb

	tlbi vmalle1is
	dsb	ish
	isb

	// copy to secondary_vec_end from cpu_startup_data
	adr	x0, secondary_vec_end
	ldr	x1, [x0, #STARTUP_MAIR]
	msr	mair_el1, x1
	ldr	x1, [x0, #STARTUP_TCR]
	msr	tcr_el1, x1
	ldr	x1, [x0, #STARTUP_TTBR0]
	msr	ttbr0_el1, x1
	ldr	x1, [x0, #STARTUP_TTBR1]
	msr	ttbr1_el1, x1
	isb
	ldr	x1, [x0, #STARTUP_SCTLR]
	msr	sctlr_el1, x1
	isb

	mrs	x0, CurrentEL
	cmp	x0, #0xc
	b.eq	el3

	cmp	x0, #0x8
	b.eq	el2

	b	el1
el3:
	b	el3

el2:
	bl	0f
	b	el1
0:
	adr	x0, .Lcnthctl_el2_val
	ldr	x0, [x0]
	msr	cnthctl_el2, x0
	msr	cntvoff_el2, xzr

	mov	x0, #CPTR_EL2_RES1
	msr	cptr_el2, x0

	msr	vttbr_el2, xzr
	msr	vbar_el2, xzr

	mrs	x0, midr_el1
	msr	vpidr_el2, x0

	mrs	x0, mpidr_el1
	msr	vmpidr_el2, x0

	mov	x0, #HCR_RW
	msr	hcr_el2, x0

	mov	x0, #SPSR_EL2_VAL
	msr	spsr_el2, x0
	msr	elr_el2, x30
	eret
	.balign 8
.Lcnthctl_el2_val:
	.quad (CNTHCTL_EL1PCEN | CNTHCTL_EL1PCTEN)
el1:
	// invalidate cache (data/inst)
	bl	dcache_invalidate_all
	ic	iallu
	dsb	sy
	isb

	tlbi vmalle1is
	dsb	sy
	isb

	// can access kernel data
	ldr	x0, =cpu
	mov	x1, #0

1:	cmp	x1, #NCPU
	b.eq	faild
	ldr	x2, [x0]	// x2 (struct cpu *)

	cbz	x2, 2f
	ldr	x3, [x2, #CPU_AFFINITY]
	mrs	x4, mpidr_el1
	ldr	x5, =MPIDR_AFF_MASK
	and	x4, x4, x5
	cmp	x3, x4
	b.eq	cpu_found

2:	add	x0, x0, #8
	add	x1, x1, #1
	b	1b

cpu_found:
	ldr	x1, [x2, #CPU_THREAD]
	msr	tpidr_el1, x1

	ldr	x29, [x1, #T_LABEL_X29]
	ldr	x30, [x1, #T_LABEL_PC]
	ldr	x0,  [x1, #T_LABEL_SP]
	mov	sp, x0
	// return entry point
	ret

faild:
	wfi
	b	faild

dcache_invalidate_all:
	mrs	x0, clidr_el1
	and	w3, w0, #0x07000000
	lsr	w3, w3, #23
	cbz	w3, 4f
	mov	w10, #0
	mov	w8, #1
0:	add	w2, w10, w10, lsr #1
	lsr	w1, w0, w2
	and	w1, w1, #0x7
	cmp	w1, #2
	b.lt	3f
	msr	csselr_el1, x10
	isb
	mrs	x1, ccsidr_el1
	and	w2, w1, #7
	add	w2, w2, #4
	ubfx	w4, w1, #3, #10
	clz	w5, w4
	lsl	w9, w4, w5
	lsl	w16, w8, w5
1:	ubfx	w7, w1, #13, #15
	lsl	w7, w7, w2
	lsl	w17, w8, w2
2:	orr	w11, w10, w9
	orr	w11, w11, w7
	dc	isw, x11
	subs	w7, w7, w17
	b.ge	2b
	subs	x9, x9, x16
	b.ge	1b
3:	add	w10, w10, #2
	cmp	w3, w10
	dsb	ish
	b.gt	0b
4:	ret
	.ltorg

	.globl secondary_vec_end
secondary_vec_end:

	.balign 4096
	.size	secondary_vec_start, [.-secondary_vec_start]
