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
 * Copyright 2022 Michael van der Westhuizen
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/asm_linkage.h>
#include <sys/errno.h>
#include "assym.h"

	/*
	 * aarch64pte_t * do_remap_page(aarch64pte_t *pte_to_window, aarch64pte_t *window, aarch64pte_t npte)
	 */
	ENTRY(do_remap_page)
	stp	x29, x30, [sp, #-32]!
	mov	x29, sp
	stp	x1, x2, [sp, #16]

	/* clean and invalidate the window in x1 */
	mrs	x2, ctr_el0
	lsr	x2, x2, #16
	and	x2, x2, #0xf
	lsl	x2, x2, #4	/* data cache line size is in x2 */
	bic	x1, x1, #0xfff	/* align the window */
	add	x3, x1, #0x1000	/* x3 holds the end of the range */
1:	dc	civac, x1	/* clean/invalidate the cacheline */
	add	x1, x1, x2	/* add a cacheline to the target */
	cmp	x1, x3		/* compare to the end of range */
	b.lo	1b		/* more to do? loop */
	dsb	sy		/* ensure data is flushed */
	isb

	/* restore trashed arguments */
	ldp	x1, x2, [sp, #16]

	tlbi	vaae1is, x1	/* invalidate the TLB entry for the window */

	/* write the pte in npte to pte_to_window */
	str	x2, [x0]	/* store the PTE */
	/* clean the pte_to_window */
	dc	cvac, x0	/* persist the PTE to memory */
	dsb	sy		/* ensure that the write is complete */
	isb

	mov	x0, x1		/* we'll return the window */
	ldp	x29, x30, [sp], #32
	ret
	SET_SIZE(do_remap_page)

	/*
	 * Invalidate a single page table entry in the TLB
	 * XXXAARCH64: We _should_ be using 'tlbi vaae1os', but it's not in the
	 * base armv8.0.
	 */
	ENTRY(mmu_invlpg)
	dmb	ish
	dc	civac, x0
	dsb	sy
	tlbi	vaae1is, x0
	isb
	ret
	SET_SIZE(mmu_invlpg)

	/*
	 * void dc_clean_range_poc(uint64_t start, uint64_t size)
	 */
	ENTRY(dc_clean_range_poc)
	mrs	x2, ctr_el0
	lsr	x2, x2, #16
	and	x2, x2, #0xf
	lsl	x2, x2, #4
	add	x1, x0, x1
	cmp	x0, x1
	b.eq	2f
	dmb	st
1:	dc	cvac, x0
	add	x0, x0, x2
	cmp	x0, x1
	b.lo	1b
	dsb	sy
2:	ret
	SET_SIZE(dc_clean_range_poc)

	/*
	 * void dc_clean_invalidate_range_poc(uint64_t start, uint64_t size)
	 */
	ENTRY(dc_clean_invalidate_range_poc)
	mrs	x2, ctr_el0
	lsr	x2, x2, #16
	and	x2, x2, #0xf
	lsl	x2, x2, #4
	add	x1, x0, x1
	cmp	x0, x1
	b.eq	2f
	dmb	st
1:	dc	civac, x0
	add	x0, x0, x2
	cmp	x0, x1
	b.lo	1b
	dsb	sy
2:	ret
	SET_SIZE(dc_clean_invalidate_range_poc)

	/*
	 * void dc_invalidate_range_poc(uint64_t start, uint64_t size)
	 */
	ENTRY(dc_invalidate_range_poc)
	mrs	x2, ctr_el0
	lsr	x2, x2, #16
	and	x2, x2, #0xf
	lsl	x2, x2, #4
	add	x1, x0, x1
	cmp	x0, x1
	b.eq	2f
	dmb	st
1:	dc	ivac, x0
	add	x0, x0, x2
	cmp	x0, x1
	b.lo	1b
	dsb	sy
2:	ret
	SET_SIZE(dc_invalidate_range_poc)

	/*
	 * void tlbi_vaae1is(uint64_t addr)
	 */
	ENTRY(tlbi_vaae1is)
	dsb	ish
	isb
	tlbi	vaae1is, x0
	dmb	ish
	ret
	SET_SIZE(tlbi_vaae1is)

	/*
	 * void tlbi_pages(uint64_t start, uint64_t num)
	 */
	ENTRY(tlbi_pages)
	cbz	x1, 2f
	lsr	x0, x0, #12
	lsl	x0, x0, #12
1:	tlbi	vaae1is, x0
	add	x0, x0, #0x1000
	sub	x1, x1, #1
	cbz	x1, 2f
	b	1b
2:	ret
	SET_SIZE(tlbi_pages)

	/*
	 * Clean and invalidate the entire data cache by set/way
	 *
	 * This touches a *lot* of registers, and doesn't attempt to preserve
	 * any, so stash anything you want before calling it. (>=17 is safe).
	 *
	 * Registers trashed:
	 * w0, w1, w2, w3, w4, w5, w7, w8, w9, w10, w11, w16, w17
	 * x0, x1, x9, x10, x11, x16,
	 *
	 * Cache maintenance by set/way is not intended to be used once you've
	 * got more than one CPU up.
	 *
	 * void flush_data_cache_all(void);
	 *
	 * See page 2660 of the DDI0487-G, "Performing cache maintenance
	 * instructions" for full details.
	 *
	 * Note that this assumes the cache size ID register is 32 bits, which
	 * should probably be fixed.
	 */
	ENTRY(flush_data_cache_all)
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
	dc	cisw, x11
	subs	w7, w7, w17
	b.ge	2b
	subs	x9, x9, x16
	b.ge	1b
3:	add	w10, w10, #2
	cmp	w3, w10
	dsb	sy
	b.gt	0b
4:	ret
	SET_SIZE(flush_data_cache_all)

	/*
	 * Clean the entire data cache by set/way
	 *
	 * As with flush_data_cache_all, trashes a lot of registers.  See the
	 * comment there for what's safe.
	 *
	 * Cache maintenance by set/way is not intended to be used once you've
	 * got more than one CPU up.
	 *
	 * void clean_data_cache_all(void);
	 */
	ENTRY(clean_data_cache_all)
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
	dc	csw, x11
	subs	w7, w7, w17
	b.ge	2b
	subs	x9, x9, x16
	b.ge	1b
3:	add	w10, w10, #2
	cmp	w3, w10
	dsb	sy
	b.gt	0b
4:	ret
	SET_SIZE(clean_data_cache_all)
