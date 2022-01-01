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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma once

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/pte.h>
#include <sys/machparam.h>

/*
 * The idea of "level" refers to the level where the page table is used in the
 * the hardware address translation steps. The level values correspond to the
 * following level numbers used in the aarch64 documents, and you'll notice that
 * the illumos numbering is the oppoosite of the aarch64 numbering.
 *
 * While one could argue that illumos should reflect the aarch64 numbering, this
 * would make use of a "level -1" page for 52 bit VA support with a 4KiB
 * translation granule very difficult to support.  TL;DR: in illumos the root
 * of the hierarchy is 0 and the leaf either 4 or 5 (for now, 4).  In aarch64
 * the root of the hierarchy is either 0 or -1 (0 for now) and the leaf is
 * always 3.
 */
#define	MAX_NUM_LEVEL		4	/* assumes 48 bit VA */
#define	MAX_PAGE_LEVEL		2	/* 4KiB, 2MiB and 1GiB pages */
#define	MIN_PAGE_LEVEL		0	/* 4KiB leaf level */
typedef int32_t level_t;		/* int8_t in i86pc */

#define	LEVEL_SHIFT(l)		(mmu.level_shift[l])
#define	LEVEL_SIZE(l)		(mmu.level_size[l])
#define	LEVEL_OFFSET(l)		(mmu.level_offset[l])
#define	LEVEL_MASK(l)		(mmu.level_mask[l])
#if 0
/* XXXAARCH64: versions above mimic i86pc */
#define	LEVEL_SHIFT(l)		(MMU_PAGESHIFT + (l) * NPTESHIFT)
#define	LEVEL_SIZE(l)		(1ul << LEVEL_SHIFT(l))
#define	LEVEL_OFFSET(l)		(LEVEL_SIZE(l)-1)
#define	LEVEL_MASK(l)		(~LEVEL_OFFSET(l))
#endif


/*
 * The software bits are used by the HAT to track attributes.
 * Note that the attributes are inclusive as the values increase.
 *
 * PT_NOSYNC - The PT_REF/PT_MOD bits are not sync'd to page_t.
 *             The hat will install them as always set.
 *
 * PT_NOCONSIST - There is no hment entry for this mapping.
 *
 */
#define	PAGE_LEVEL		(0)

#define	PTE_SOFTWARE		(PT_SOFTWARE)
#define	PTE_NOSYNC		(PT_NOSYNC)
#define	PTE_NOCONSIST		(PT_NOCONSIST)

#define	PTE_ISVALID(pte)	((pte) & PTE_VALID)
/*
 * XXXAARCH64: This is vomitworthy - what about DBM?
 * See i86pc for a fuller version
 */
#define	PTE_EQUIV(a, b)		(((a) | PTE_AF) == ((b) | PTE_AF))

#define	MAKEPTP(pfn, l)		(PFN_TO_PT_OA((pfn)) | mmu.ptp_bits[(l) + 1])
#define	MAKEPTE(pfn, l)		(PFN_TO_PT_OA((pfn)) | mmu.pte_bits[l])

/*
 * HAT/MMU parameters that depend on kernel mode and/or processor type
 */
struct htable;
struct hat_mmu_info {
#if 0
	aarch64pte_t pt_nx;		/* either 0 or PT_NX */
	aarch64pte_t pt_global;	/* either 0 or PT_GLOBAL */
#else
	aarch64pte_t pt_uxn;	/* user execute-never */
	aarch64pte_t pt_pxn;	/* privileged execute-never */
	aarch64pte_t pt_ng;	/* non-global, always set */
#endif
	pfn_t highest_pfn;	/* highest pfn possible */

	uint_t num_level;	/* number of page table levels in use */
	uint_t max_level;	/* just num_level - 1 */
	uint_t max_page_level;	/* maximum level at which we can map a page */

	uint_t umax_page_level;	/* max user page map level */
	uint_t ptes_per_table;	/* # of entries in lower level page tables */
	uint_t top_level_count;	/* # of entries in top-level page table */
#if 0
	uint_t top_level_uslots; /* # of user slots in top-level page table */
	uint_t num_copied_ents;	/* # of PCP-copied PTEs to create */
	/* 32-bit versions of values */
	uint_t top_level_uslots32;
	uint_t max_level32;
	uint_t num_copied_ents32;
#endif

	uint_t hash_cnt;	/* cnt of entries in htable_hash_cache */
	uint_t hat32_hash_cnt;	/* cnt of entries in 32-bit htable_hash_cache */

#if 0
	uint_t pae_hat;		/* either 0 or 1 */
#endif
	uintptr_t hole_start;	/* start of VA hole (or -1 if none) */
	uintptr_t hole_end;	/* end of VA hole (or 0 if none) */

	struct htable **kmap_htables; /* htables for segmap + 32 bit heap */
	aarch64pte_t *kmap_ptes;	/* mapping of pagetables that map kmap XXXAARCH64 fix this type */
	uintptr_t kmap_addr;	/* start addr of kmap */
	uintptr_t kmap_eaddr;	/* end addr of kmap */

	uint_t pte_size;			/* either 4 or 8 */
	uint_t pte_size_shift;			/* either 2 or 3 */
	aarch64pte_t ptp_bits[MAX_NUM_LEVEL];	/* bits set for interior PTP */
	aarch64pte_t pte_bits[MAX_NUM_LEVEL];	/* bits set for leaf PTE */

#if 0
	/*
	 * A range of VA used to window pages in the i86pc/vm code.
	 * See PWIN_XXX macros.
	 */
	caddr_t pwin_base;
	caddr_t pwin_pte_va;
	paddr_t pwin_pte_pa;
#endif
	/*
	 * The following tables are equivalent to PAGEXXXXX at different levels
	 * in the page table hierarchy.
	 */
	uint_t level_shift[MAX_NUM_LEVEL];	/* PAGESHIFT for given level */
	uintptr_t level_size[MAX_NUM_LEVEL];	/* PAGESIZE for given level */
	uintptr_t level_offset[MAX_NUM_LEVEL];	/* PAGEOFFSET for given level */
	uintptr_t level_mask[MAX_NUM_LEVEL];	/* PAGEMASK for given level */

	uint32_t max_asid;
	uintptr_t kernelbase;			/* XXXAARCH64: why is this needed? */
};
extern struct hat_mmu_info mmu;

#define	PT_INDEX_PTR(p, x)	((aarch64pte_t *)((uintptr_t)(p) + ((x) << PTE_BITS)))

#define	PT_INDEX_PHYSADDR(p, x) \
	((paddr_t)(p) + ((x) << mmu.pte_size_shift))

#define	pfn_to_pa(pfn)		mmu_ptob((paddr_t)(pfn))
#define	pa_to_pfn(pa)		((pa) >> MMU_PAGESHIFT)
#define	pa_to_kseg(pa)		((void *)((paddr_t)SEGKPM_BASE|(paddr_t)(pa)))
#define	pfn_to_kseg(pfn)	pa_to_kseg(pfn_to_pa(pfn))

#define	IN_VA_HOLE(va)		(mmu.hole_start <= (va) && (va) < mmu.hole_end)
#if 0
#define	IN_VA_HOLE(va)		(HOLE_START <= (va) && (va) < HOLE_END)
#endif
#define	FMT_PTE			"0x%lx"
#define	GET_PTE(ptr)		(*(volatile aarch64pte_t *)(ptr))
#define	SET_PTE(ptr, pte)	(*(volatile aarch64pte_t *)(ptr) = (pte))

#define	PTE_SET(p, f)		((p) |= (f))
#define	PTE_CLR(p, f)		((p) &= ~(aarch64pte_t)(f))
#define	PTE_GET(p, f)		((p) & (f))

#define	PTE2PFN(p, lvl)		((PTE_TO_PA(p)) >> (MMU_PAGESHIFT))
#define	CAS_PTE(ptr, x, y)	atomic_cas_64(ptr, x, y)

/*
 * Utilities for use by the HAT layer
 */
#define	PTE_HAS_DBM(__pte)	(((__pte) & PT_ATTR_DBM) || \
	((__pte) & PT_SOFT_DBM))
#define PTE_IS_DIRTY(__pte)	(PTE_HAS_DBM((__pte)) && \
	(((__pte) & PTE_AP_RO) == 0))
#define PTE_IS_ACCESSED(__pte)	((__pte) & PTE_AF)

#ifdef	__cplusplus
}
#endif

