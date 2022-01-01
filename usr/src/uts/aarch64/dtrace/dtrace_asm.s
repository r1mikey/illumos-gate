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

#include <sys/asm_linkage.h>
#include <sys/regset.h>

	// void dtrace_set_sreg(int reg, const uint32_t* val)
	ENTRY(dtrace_set_sreg)
	cmp	w0, #0; b.ne	1f; ldr	s0, [x1]; ret; 1:
	cmp	w0, #1; b.ne	1f; ldr	s1, [x1]; ret; 1:
	cmp	w0, #2; b.ne	1f; ldr	s2, [x1]; ret; 1:
	cmp	w0, #3; b.ne	1f; ldr	s3, [x1]; ret; 1:
	cmp	w0, #4; b.ne	1f; ldr	s4, [x1]; ret; 1:
	cmp	w0, #5; b.ne	1f; ldr	s5, [x1]; ret; 1:
	cmp	w0, #6; b.ne	1f; ldr	s6, [x1]; ret; 1:
	cmp	w0, #7; b.ne	1f; ldr	s7, [x1]; ret; 1:
	cmp	w0, #8; b.ne	1f; ldr	s8, [x1]; ret; 1:
	cmp	w0, #9; b.ne	1f; ldr	s9, [x1]; ret; 1:
	cmp	w0, #10; b.ne	1f; ldr	s10, [x1]; ret; 1:
	cmp	w0, #11; b.ne	1f; ldr	s11, [x1]; ret; 1:
	cmp	w0, #12; b.ne	1f; ldr	s12, [x1]; ret; 1:
	cmp	w0, #13; b.ne	1f; ldr	s13, [x1]; ret; 1:
	cmp	w0, #14; b.ne	1f; ldr	s14, [x1]; ret; 1:
	cmp	w0, #15; b.ne	1f; ldr	s15, [x1]; ret; 1:
	cmp	w0, #16; b.ne	1f; ldr	s16, [x1]; ret; 1:
	cmp	w0, #17; b.ne	1f; ldr	s17, [x1]; ret; 1:
	cmp	w0, #18; b.ne	1f; ldr	s18, [x1]; ret; 1:
	cmp	w0, #19; b.ne	1f; ldr	s19, [x1]; ret; 1:
	cmp	w0, #20; b.ne	1f; ldr	s20, [x1]; ret; 1:
	cmp	w0, #21; b.ne	1f; ldr	s21, [x1]; ret; 1:
	cmp	w0, #22; b.ne	1f; ldr	s22, [x1]; ret; 1:
	cmp	w0, #23; b.ne	1f; ldr	s23, [x1]; ret; 1:
	cmp	w0, #24; b.ne	1f; ldr	s24, [x1]; ret; 1:
	cmp	w0, #25; b.ne	1f; ldr	s25, [x1]; ret; 1:
	cmp	w0, #26; b.ne	1f; ldr	s26, [x1]; ret; 1:
	cmp	w0, #27; b.ne	1f; ldr	s27, [x1]; ret; 1:
	cmp	w0, #28; b.ne	1f; ldr	s28, [x1]; ret; 1:
	cmp	w0, #29; b.ne	1f; ldr	s29, [x1]; ret; 1:
	cmp	w0, #30; b.ne	1f; ldr	s30, [x1]; ret; 1:
	cmp	w0, #31; b.ne	1f; ldr	s31, [x1]; ret; 1:
	ret
	SET_SIZE(dtrace_set_sreg)

	// void dtrace_set_dreg(int reg, const uint64_t* val)
	ENTRY(dtrace_set_dreg)
	cmp	w0, #0; b.ne	1f; ldr	d0, [x1]; ret; 1:
	cmp	w0, #1; b.ne	1f; ldr	d1, [x1]; ret; 1:
	cmp	w0, #2; b.ne	1f; ldr	d2, [x1]; ret; 1:
	cmp	w0, #3; b.ne	1f; ldr	d3, [x1]; ret; 1:
	cmp	w0, #4; b.ne	1f; ldr	d4, [x1]; ret; 1:
	cmp	w0, #5; b.ne	1f; ldr	d5, [x1]; ret; 1:
	cmp	w0, #6; b.ne	1f; ldr	d6, [x1]; ret; 1:
	cmp	w0, #7; b.ne	1f; ldr	d7, [x1]; ret; 1:
	cmp	w0, #8; b.ne	1f; ldr	d8, [x1]; ret; 1:
	cmp	w0, #9; b.ne	1f; ldr	d9, [x1]; ret; 1:
	cmp	w0, #10; b.ne	1f; ldr	d10, [x1]; ret; 1:
	cmp	w0, #11; b.ne	1f; ldr	d11, [x1]; ret; 1:
	cmp	w0, #12; b.ne	1f; ldr	d12, [x1]; ret; 1:
	cmp	w0, #13; b.ne	1f; ldr	d13, [x1]; ret; 1:
	cmp	w0, #14; b.ne	1f; ldr	d14, [x1]; ret; 1:
	cmp	w0, #15; b.ne	1f; ldr	d15, [x1]; ret; 1:
	cmp	w0, #16; b.ne	1f; ldr	d16, [x1]; ret; 1:
	cmp	w0, #17; b.ne	1f; ldr	d17, [x1]; ret; 1:
	cmp	w0, #18; b.ne	1f; ldr	d18, [x1]; ret; 1:
	cmp	w0, #19; b.ne	1f; ldr	d19, [x1]; ret; 1:
	cmp	w0, #20; b.ne	1f; ldr	d20, [x1]; ret; 1:
	cmp	w0, #21; b.ne	1f; ldr	d21, [x1]; ret; 1:
	cmp	w0, #22; b.ne	1f; ldr	d22, [x1]; ret; 1:
	cmp	w0, #23; b.ne	1f; ldr	d23, [x1]; ret; 1:
	cmp	w0, #24; b.ne	1f; ldr	d24, [x1]; ret; 1:
	cmp	w0, #25; b.ne	1f; ldr	d25, [x1]; ret; 1:
	cmp	w0, #26; b.ne	1f; ldr	d26, [x1]; ret; 1:
	cmp	w0, #27; b.ne	1f; ldr	d27, [x1]; ret; 1:
	cmp	w0, #28; b.ne	1f; ldr	d28, [x1]; ret; 1:
	cmp	w0, #29; b.ne	1f; ldr	d29, [x1]; ret; 1:
	cmp	w0, #30; b.ne	1f; ldr	d30, [x1]; ret; 1:
	cmp	w0, #31; b.ne	1f; ldr	d31, [x1]; ret; 1:
	ret
	SET_SIZE(dtrace_set_dreg)

	// void dtrace_set_qreg(int reg, const __uint128_t* val)
	ENTRY(dtrace_set_qreg)
	cmp	w0, #0; b.ne	1f; ldr	q0, [x1]; ret; 1:
	cmp	w0, #1; b.ne	1f; ldr	q1, [x1]; ret; 1:
	cmp	w0, #2; b.ne	1f; ldr	q2, [x1]; ret; 1:
	cmp	w0, #3; b.ne	1f; ldr	q3, [x1]; ret; 1:
	cmp	w0, #4; b.ne	1f; ldr	q4, [x1]; ret; 1:
	cmp	w0, #5; b.ne	1f; ldr	q5, [x1]; ret; 1:
	cmp	w0, #6; b.ne	1f; ldr	q6, [x1]; ret; 1:
	cmp	w0, #7; b.ne	1f; ldr	q7, [x1]; ret; 1:
	cmp	w0, #8; b.ne	1f; ldr	q8, [x1]; ret; 1:
	cmp	w0, #9; b.ne	1f; ldr	q9, [x1]; ret; 1:
	cmp	w0, #10; b.ne	1f; ldr	q10, [x1]; ret; 1:
	cmp	w0, #11; b.ne	1f; ldr	q11, [x1]; ret; 1:
	cmp	w0, #12; b.ne	1f; ldr	q12, [x1]; ret; 1:
	cmp	w0, #13; b.ne	1f; ldr	q13, [x1]; ret; 1:
	cmp	w0, #14; b.ne	1f; ldr	q14, [x1]; ret; 1:
	cmp	w0, #15; b.ne	1f; ldr	q15, [x1]; ret; 1:
	cmp	w0, #16; b.ne	1f; ldr	q16, [x1]; ret; 1:
	cmp	w0, #17; b.ne	1f; ldr	q17, [x1]; ret; 1:
	cmp	w0, #18; b.ne	1f; ldr	q18, [x1]; ret; 1:
	cmp	w0, #19; b.ne	1f; ldr	q19, [x1]; ret; 1:
	cmp	w0, #20; b.ne	1f; ldr	q20, [x1]; ret; 1:
	cmp	w0, #21; b.ne	1f; ldr	q21, [x1]; ret; 1:
	cmp	w0, #22; b.ne	1f; ldr	q22, [x1]; ret; 1:
	cmp	w0, #23; b.ne	1f; ldr	q23, [x1]; ret; 1:
	cmp	w0, #24; b.ne	1f; ldr	q24, [x1]; ret; 1:
	cmp	w0, #25; b.ne	1f; ldr	q25, [x1]; ret; 1:
	cmp	w0, #26; b.ne	1f; ldr	q26, [x1]; ret; 1:
	cmp	w0, #27; b.ne	1f; ldr	q27, [x1]; ret; 1:
	cmp	w0, #28; b.ne	1f; ldr	q28, [x1]; ret; 1:
	cmp	w0, #29; b.ne	1f; ldr	q29, [x1]; ret; 1:
	cmp	w0, #30; b.ne	1f; ldr	q30, [x1]; ret; 1:
	cmp	w0, #31; b.ne	1f; ldr	q31, [x1]; ret; 1:
	ret
	SET_SIZE(dtrace_set_qreg)

