/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2024 Michael van der Westhuizen
 */

	.file	"smccc_impl.s"

/*
 * SMCCC call implementations
 *
 * See DEN0028: SMC Calling Convention
 *
 * There are two types of call, 32bit and 64bit. It is mandatory for an
 * implementation to support 32bit calls, as identification functions use
 * this call format.
 *
 * 64bit callers should use the 64bit functions where available.
 *
 * There are two conduits to SMC APIs: Secure Monitor (SMC) and
 * Hypervisor (HVC).
 *
 * 32bit call implementations (i_smccc_smc_call32 and i_smccc_hvc_call32)
 * take a smccc32_args_t structure, where the first argument (w0) is a
 * function identifier at call time. At return time, w0-w7 are populated with
 * the values returned by the firmware.
 *
 * 64bit call implementations (i_smccc_smc_call64 and i_smccc_hvc_call64)
 * take a smccc64_args_t structure, where the first argument (x0) is a
 * function identifier (but this _is_ a 32bit value, loaded into w0) at call
 * time. At return time, x0-x17 are populated with the values returned by the
 * firmware.
 *
 * This whole file is an implementation detail.
 */

#include <sys/asm_linkage.h>
#include "assym.h"

/*
 * void
 * i_smccc_smc_call32(smccc32_args_t *args);
 */
	ENTRY(i_smccc_smc_call32)
	stp	x0, x28, [sp, #-16]!
	mov	x28, x0
	ldp	w0, w1, [x28, #REGOFF_SMCCC32_W0]
	ldp	w2, w3, [x28, #REGOFF_SMCCC32_W2]
	ldp	w4, w5, [x28, #REGOFF_SMCCC32_W4]
	ldp	w6, w7, [x28, #REGOFF_SMCCC32_W6]
	smc	#0
	ldr	x28, [sp]
	stp	w0, w1, [x28, #REGOFF_SMCCC32_W0]
	stp	w2, w3, [x28, #REGOFF_SMCCC32_W2]
	stp	w4, w5, [x28, #REGOFF_SMCCC32_W4]
	stp	w6, w7, [x28, #REGOFF_SMCCC32_W6]
	ldp	xzr, x28, [sp], #16
	ret
	SET_SIZE(i_smccc_smc_call32)

/*
 * void
 * i_smccc_hvc_call32(smccc32_args_t *args);
 */
	ENTRY(i_smccc_hvc_call32)
	stp	x0, x28, [sp, #-16]!
	mov	x28, x0
	ldp	w0, w1, [x28, #REGOFF_SMCCC32_W0]
	ldp	w2, w3, [x28, #REGOFF_SMCCC32_W2]
	ldp	w4, w5, [x28, #REGOFF_SMCCC32_W4]
	ldp	w6, w7, [x28, #REGOFF_SMCCC32_W6]
	hvc	#0
	ldr	x28, [sp]
	stp	w0, w1, [x28, #REGOFF_SMCCC32_W0]
	stp	w2, w3, [x28, #REGOFF_SMCCC32_W2]
	stp	w4, w5, [x28, #REGOFF_SMCCC32_W4]
	stp	w6, w7, [x28, #REGOFF_SMCCC32_W6]
	ldp	xzr, x28, [sp], #16
	ret
	SET_SIZE(i_smccc_hvc_call32)

/*
 * void
 * i_smccc_smc_call64(smccc64_args_t *args);
 */
	ENTRY(i_smccc_smc_call64)
	stp	x0, x28, [sp, #-16]!
	mov	x28, x0
	ldp	x0, x1, [x28, #REGOFF_SMCCC64_X0]
	ldp	x2, x3, [x28, #REGOFF_SMCCC64_X2]
	ldp	x4, x5, [x28, #REGOFF_SMCCC64_X4]
	ldp	x6, x7, [x28, #REGOFF_SMCCC64_X6]
	ldp	x8, x9, [x28, #REGOFF_SMCCC64_X8]
	ldp	x10, x11, [x28, #REGOFF_SMCCC64_X10]
	ldp	x12, x13, [x28, #REGOFF_SMCCC64_X12]
	ldp	x14, x15, [x28, #REGOFF_SMCCC64_X14]
	ldp	x16, x17, [x28, #REGOFF_SMCCC64_X16]
	smc	#0
	ldr	x28, [sp]
	stp	x0, x1, [x28, #REGOFF_SMCCC64_X0]
	stp	x2, x3, [x28, #REGOFF_SMCCC64_X2]
	stp	x4, x5, [x28, #REGOFF_SMCCC64_X4]
	stp	x6, x7, [x28, #REGOFF_SMCCC64_X6]
	stp	x8, x9, [x28, #REGOFF_SMCCC64_X8]
	stp	x10, x11, [x28, #REGOFF_SMCCC64_X10]
	stp	x12, x13, [x28, #REGOFF_SMCCC64_X12]
	stp	x14, x15, [x28, #REGOFF_SMCCC64_X14]
	stp	x16, x17, [x28, #REGOFF_SMCCC64_X16]
	ldp	xzr, x28, [sp], #16
	ret
	SET_SIZE(i_smccc_smc_call64)

/*
 * void
 * i_smccc_hvc_call64(smccc64_args_t *args);
 */
	ENTRY(i_smccc_hvc_call64)
	stp	x0, x28, [sp, #-16]!
	mov	x28, x0
	ldp	x0, x1, [x28, #REGOFF_SMCCC64_X0]
	ldp	x2, x3, [x28, #REGOFF_SMCCC64_X2]
	ldp	x4, x5, [x28, #REGOFF_SMCCC64_X4]
	ldp	x6, x7, [x28, #REGOFF_SMCCC64_X6]
	ldp	x8, x9, [x28, #REGOFF_SMCCC64_X8]
	ldp	x10, x11, [x28, #REGOFF_SMCCC64_X10]
	ldp	x12, x13, [x28, #REGOFF_SMCCC64_X12]
	ldp	x14, x15, [x28, #REGOFF_SMCCC64_X14]
	ldp	x16, x17, [x28, #REGOFF_SMCCC64_X16]
	hvc	#0
	ldr	x28, [sp]
	stp	x0, x1, [x28, #REGOFF_SMCCC64_X0]
	stp	x2, x3, [x28, #REGOFF_SMCCC64_X2]
	stp	x4, x5, [x28, #REGOFF_SMCCC64_X4]
	stp	x6, x7, [x28, #REGOFF_SMCCC64_X6]
	stp	x8, x9, [x28, #REGOFF_SMCCC64_X8]
	stp	x10, x11, [x28, #REGOFF_SMCCC64_X10]
	stp	x12, x13, [x28, #REGOFF_SMCCC64_X12]
	stp	x14, x15, [x28, #REGOFF_SMCCC64_X14]
	stp	x16, x17, [x28, #REGOFF_SMCCC64_X16]
	ldp	xzr, x28, [sp], #16
	ret
	SET_SIZE(i_smccc_hvc_call64)
