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
 */

#ifndef _PTE_H
#define _PTE_H

#ifndef _ASM
#include <sys/types.h>
#endif /* _ASM */

#include <sys/arm/armv8_mair.h>

#ifdef	__cplusplus
extern "C" {
#endif

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
 * Copyright 2022 Michael van der Westhuizen
 */


/*
 * This is all from the original port
 */
typedef uint64_t pte_t;

#define NPTESHIFT	(MMU_PAGESHIFT - PTE_BITS)

#define NPTEPERPT	(MMU_PAGESIZE / sizeof(pte_t))


/* tweaked to line up with the MAIR stuff, need to coalesce some time */
/* actual config bits are kept in controlregs - we need a vm_machdep.h for this stuff */
#define MAIR_STRONG_ORDER	5	/* no analogue in FreeBSD */
#define MAIR_DEVICE		3	/* FreeBSD has device nGnRnE as device, and wants to move to nGnRE, leaving nGnRnE for PCI config space */
#define MAIR_NORMAL_MEMORY	0	/* writeback - 2 in FreeBSD */
#define MAIR_NORMAL_MEMORY_WT	1	/* writethrough - 3 in FreeBSD */
#define MAIR_NORMAL_MEMORY_UC	2	/* uncacheable - 1 in FreeBSD */
#define MAIR_UNORDERED		4	/* no analogue in FreeBSD */

#define PTE_TYPE_MASK		0x3

#define PTE_SFW_SHIFT		(55)
#define PTE_SFW_MASK		(0xFull << PTE_SFW_SHIFT)
#define PTE_UXN			(1ull << 54)
#define PTE_PXN			(1ull << 53)
#define PTE_CONTIG_HINT		(1ull << 52)
#define PTE_NG			(1ull << 11)
#define PTE_AF			(1ull << 10)
#define PTE_SH_MASK		(3ull << 8)
#define PTE_SH_INNER		(3ull << 8)
#define PTE_SH_OUTER		(2ull << 8)
#define PTE_SH_NONSHARE		(0ull << 8)
#define PTE_AP_MASK		(3ull << 6)
#define PTE_AP_RO		(1ull << 7)
#define PTE_AP_USER		(1ull << 6)
#define PTE_AP_KRWUNA		0
#define PTE_AP_KRWURW		PTE_AP_USER
#define PTE_AP_KROUNA		PTE_AP_RO
#define PTE_AP_KROURO		(PTE_AP_RO | PTE_AP_USER)

#define PTE_NS			(1ull << 5)
#define PTE_ATTR_SHIFT		(2)
#define PTE_ATTR_MASK		(7ull << PTE_ATTR_SHIFT)
#define PTE_ATTR_STRONG		((pte_t)MAIR_STRONG_ORDER  << PTE_ATTR_SHIFT)
#define PTE_ATTR_DEVICE		((pte_t)MAIR_DEVICE        << PTE_ATTR_SHIFT)
#define PTE_ATTR_NORMEM		((pte_t)MAIR_NORMAL_MEMORY << PTE_ATTR_SHIFT)
#define PTE_ATTR_NORMEM_WT	((pte_t)MAIR_NORMAL_MEMORY_WT << PTE_ATTR_SHIFT)
#define PTE_ATTR_NORMEM_UC	((pte_t)MAIR_NORMAL_MEMORY_UC << PTE_ATTR_SHIFT)
#define PTE_ATTR_UNORDERED	((pte_t)MAIR_UNORDERED << PTE_ATTR_SHIFT)

#define PTE_TABLE_NST		(1ull << 63)
#define PTE_TABLE_APT_MASK	(3ull << 61)
#define PTE_TABLE_APT_RO	(2ull << 61)
#define PTE_TABLE_APT_NOUSER	(1ull << 61)
#define PTE_TABLE_UXNT		(1ull << 60)
#define PTE_TABLE_PXNT		(1ull << 59)

#define	PTE_PFN_MASK		PT_OA_BITS

/*
 * Chosen Memory Attribute Indirection Register indices and configurations
 * for aarch64, which is defined to contain the VMSAv8 MMU and MAIR.
 *
 * The chosen configuration is loaded into the MAIR_EL1 register by bootstrap
 * code and the indices are then used by the HAT layer in realising MMU
 * configuration.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * For device memory, the following mnemonics are used for the low bits:
 * nG/G: (non-)Gathering
 * nR/R: (non-)Reordering
 * nE/E: (non-)Early Write Acknowledgement
 *
 * Device-nGnRnE is equivalent to strongly ordered
 * Device-nGnRE is the device memory type from armv7-a
 * Device-nGRE Use of barriers is required here (due to reordering)
 * Device-GRE Similar to normal memory, but speculative access is forbidden
 */

/*
 * These are processed by hat_devload only.
 *
 * HAT_STRICTORDER -> Device-nGnRnE
 * HAT_UNORDERED_OK -> Device-nGRE
 * HAT_MERGING_OK -> Device-GRE
 * HAT_LOADCACHING_OK -> implies merging, so Device-GRE (don't know if we can
 * cache these - unless they're normal memory)
 * HAT_STORECACHING_OK -> imlies load caching, so also Device-GRE (don't know
 * if we can cache thes - unless they're normal memorye)
 * ^^ loadcache would be inner/outer write-through, read-allocate
 * ^^ storecache would be intter/outer writethrough, write allocate
 * ^^ both of the above would have to be normal memory
 */

/*
 * We have:
 * MAIR_DEVICE_NGNRNE
 * MAIR_DEVICE_NGNRE
 * We also need MAIR_DEVICE_NGRE
 * We also need MAIR_DEVICE_GRE
 * MAIR_NORMAL_NC is normal, non-cached
 * MAIR_NORMAL_WT is normal, write-through
 * MAIR_NORMAL_WB is normal, write-back
 */

/*
 * FreeBSD has an interesting note where they say that device memory can be
 * switched over to nGnRE when all PCI drivers use nGnRnE for their config
 * space. For now, we do the same thing they do, and just use nGnRnE everywhere.
 *
 * We may not end up needing all of these, but we can clean that all up later.
 *
 * We have four types of device memory:
 * Normal
 * Strongly ordered << usable for memory too!
 * Reordered
 * Relaxed
 *
 * Then we have three types of memory:
 * Uncached
 * Write Through (write allocate, read allocate)
 * Writeback (write allocate, read allocate)
 */
#define	MIDX_DEVICE			3
#define	MIDX_DEVICE_SO			5
#define	MIDX_DEVICE_REORDERED		4
#define	MIDX_DEVICE_RELAXED		6
#define	MIDX_MEMORY_NC			2
#define	MIDX_MEMORY_WT			1
#define	MIDX_MEMORY_WB			0	/* the default in FreeBSD */

#define	MATTR_DEVICE			MAIR_DEVICE_NGNRNE
#define	MATTR_DEVICE_SO			MAIR_DEVICE_NGNRNE	/* needed? */
#define	MATTR_DEVICE_REORDERED		MAIR_DEVICE_NGRE
#define	MATTR_DEVICE_RELAXED		MAIR_DEVICE_GRE		/* needed? */
#define	MATTR_MEMORY_NC			MAIR_NORMAL_ONC_INC
#define	MATTR_MEMORY_WT			MAIR_NORMAL_OWT_RA_WA_IWT_RA_WA
#define	MATTR_MEMORY_WB			MAIR_NORMAL_OWB_RA_WA_IWB_RA_WA

/*
 * MATTR_MEMORY_WB is the default memory type in FreeBSD.
 *
 * In FreeBSD, VM_MEMATTR_WRITE_COMBINING is defined to MATTR_MEMORY_WT.
 */

/*
 * MAIR_EL1 setup contents.
 *
 * Loaded into MAIR_EL1 prior to activating bootstrap page tables.
 */
#define	MAKE_MAIR(__idx, __attr)	(((uint64_t)(__attr)) << ((__idx) * 8))
#define	MAIR_EL1_CONTENTS						\
	(MAKE_MAIR(MIDX_MEMORY_WB, MATTR_MEMORY_WB) |			\
	MAKE_MAIR(MIDX_MEMORY_WT, MATTR_MEMORY_WT) |			\
	MAKE_MAIR(MIDX_MEMORY_NC, MATTR_MEMORY_NC) |			\
	MAKE_MAIR(MIDX_DEVICE, MATTR_DEVICE) |				\
	MAKE_MAIR(MIDX_DEVICE_REORDERED, MATTR_DEVICE_REORDERED) |	\
	MAKE_MAIR(MIDX_DEVICE_SO, MATTR_DEVICE_SO) |			\
	MAKE_MAIR(MIDX_DEVICE_RELAXED, MIDX_DEVICE_RELAXED))
/* #undef MAKE_MAIR */


#define	TWO_MEG		(2 * 1024 * 1024)
#define	ONE_GIG		(1024 * 1024 * 1024)

typedef uint64_t aarch64pte_t;

#define	PTE_VALID	0x1UL
#define	PTE_TABLE	0x3UL
#define	PTE_BLOCK	0x1UL
#define PTE_PAGE	PTE_TABLE
#define PTE_VALID_MASK	0x3UL

#define	PTE_IS_TABLE(x, l)	(((l) > 0) && (((x) & PTE_VALID) == PTE_VALID) \
    && (((x) & PTE_VALID_MASK) == PTE_TABLE))
#define	PTE_IS_BLOCK(x, l)	((((l) > 0) && ((l) < 3)) && \
    (((x) & PTE_VALID) == PTE_VALID) && (((x) & PTE_VALID_MASK) == PTE_BLOCK))
#define	PTE_IS_LEAF_PAGE(x, l)	(((l) == 0) && \
    (((x) & PTE_VALID) == PTE_VALID) && (((x) & PTE_VALID_MASK) == PTE_PAGE))
#define	PTE_IS_VALID(x, l)	((((x) & PTE_VALID) == PTE_VALID) && \
    (PTE_IS_TABLE((x), (l)) || PTE_IS_BLOCK((x), (l)) || PTE_IS_LEAF_PAGE((x), (l))))
#define	PTE_IS_PAGE(x, l)		(PTE_IS_LEAF_PAGE((x), (l)) || \
    PTE_IS_BLOCK((x), (l)))
#define	PTE_ISPAGE(x, l)	(PTE_IS_PAGE((x), (l)))
#define	PTE_IS_LGPG(x, l)	((l) > 0 && (PTE_IS_BLOCK((x), (l))))


#define L0IDX(__va)     (((__va) >> 39) & 0x1ff)
#define L0_TABLE_MASK   (((1UL << 48) - 1) & ~0xfff)
#define L0_TABLE        0x3UL
#define L1IDX(__va)     (((__va) >> 30) & 0x1ff)
#define L1_BLOCK_MASK   L0_TABLE_MASK
#define L1_TABLE_MASK   L0_TABLE_MASK
#define L1_BLOCK        0x1UL
#define L1_TABLE        0x3UL
#define L2IDX(__va)     (((__va) >> 21) & 0x1ff)
#define L2_TABLE_MASK   L1_TABLE_MASK
#define L2_BLOCK_MASK   L1_BLOCK_MASK
#define L2_BLOCK        0x1UL
#define L2_TABLE        0x3UL
#define L3IDX(__va)     (((__va) >> 12) & 0x1ff)
#define L3_PAGE_MASK    L2_BLOCK_MASK
#define L3_PAGE         0x3UL

#define	IS_PTE_VALID(pte)	((((pte) & PTE_VALID_MASK) == PTE_TABLE) || \
    (((pte) & PTE_VALID_MASK) == PTE_BLOCK))

/*
 * Defines for the bits in aarch64 Page Tables
 *
 * "If the Effective value of TCR_ELx.DS or VTCR_EL2.DS is 1:"
 * ^^ we musy ensure thay these are 0, or things will blow up
 * however, it would be nice to support 52 bit OA at some stage.
 *
 * "Bits[47:12] are bits[47:12] of the address of the required next-level table"
 * again, "Effective value of TCR_ELx.DS or VTCR_EL2.DS is 1" MUST NOT BE TRUE.
 *
 * PSTATE.PAN is interesting.
 *
 * FEAT_BTI along with the GP bit is worth investigating.
 *
 * FEAT_E0PD should be checked and enabled to prevent access to higher half
 * transations from EL0.
 *
 * See also: SCTLR_ELx.WXN
 *
 * In Armv8.0, the Access flag is managed by software (access fault, set the
 * bit to 1)
 * From Armv8.1, the Access flag can be managed by hardware (FEAT_HAFDBS, DBM).
 * TCR_EL1.HA - Look into this!
 * "The Access flag might be set to 1 as a result of speculative accesses by
 * the PE."
 *
 * Dirty state can be managed by hardware (AP[2], S2AP[1] and DBM). Investiagte.
 * Can only be enabled when hardware management of the access flag is enabled.
 * TCR_EL1.HD.  AP[2] and DBM - PE will change the page from R/O to R/W.
 * Speculation cannot mark a page or block dirty.
 *
 * Contiguous entries have an interaction with hardware management of these bits
 * in that, if an implementation maintains a single TLB entry for the
 * translation, then it's possible that only one PTE in a group will be updated,
 * which is kinda sucky, because we'd love to know that we need to disolve
 * large pages when they become dirty so as to better track dirtiness at the
 * most efficient granularity.  To this end, perhaps we shold only enable DBM
 * for non-contiguous mappings... we can take the "hit" on accessed pages.
 *
 * For the 4KiB granule, the contiguous bit refers to 16 contiguous entries,
 * yielding blocks of 64KiB, 32MiB and 16GiB in addition to the existing 4KiB,
 * 2MiB and 1GiB sizes.
 *
 * "The contiguous output address range must be aligned to size of 16
 * translation table entries at the same translation table level.", so therefore
 * they must be aligned to their size (and this makes a lot of maths easier).
 *
 * "Using a translation table entry that has the nT bit set might significantly
 * impact the performance of the translation." (and a lot of other information)
 * Generally, it doesn't really seem like we have a great reason to use this
 * bit.
 *
 * "Effective value of TCR_ELx.DS"... sharability attributes get weird when this
 * is not true.
 *
 * The sharable attribute is only meaningful for normal, cacheable memory.
 * Device and non-cacheable normal memory is always treated as outer sharable.
 *
 * [58:55] are available for software use (unless they've been configured for
 * non-portable hardware use.
 */
#define	PT_VALID	(0x01)	/* a valid translation is present */

/* block, levels -1, 0, 1 and 2 */
#define	PT_NT		(0x1ULL << 16)

#define	PT_NSTABLE	(0x1UL << 63)	/* RES0: we're not in secure state */
#define	PT_APTABLE(v)	((v) << 61)	/* Can be disabled, so ignore it */
#define	PT_UXNTABLE	(0x1ULL << 60)	/* Can be disabled, so ignore it */
#define	PT_PXNTABLE	(0x1ULL << 59)	/* Can be disabled, so ignore it */

/*
 * Upper attributes
 *
 * [63] is ignored
 * [62:59] are PHBA bits, the meaning of which is implementation-defined
 */
#define	PT_ATTR_58	(0x1ULL << 58)		/* software use */
#define	PT_ATTR_57	(0x1ULL << 57)		/* software use */
#define	PT_ATTR_56	(0x1ULL << 56)		/* software use */
#define	PT_ATTR_55	(0x1ULL << 55)		/* software use */

#define	PT_ATTR_UXN	(0x1ULL << 54)		/* User XN */
#define	PT_ATTR_PXN	(0x1ULL << 53)		/* Priv XN */
#define	PT_ATTR_CONTIG	(0x1ULL << 52)		/* Contiguous */
#define	PT_ATTR_DBM	(0x1ULL << 51)		/* Dirty bit modifier */
#define	PT_ATTR_GP	(0x1ULL << 50)		/* Guarded page iff FEAT_BTI */

/*
 * Address to output address - needs support for 52 bit PA
 */
#define	PT_OA_BITS		(0xfffffffff000)
#define	PA_TO_PT_OA(pa)		((pa) & PT_OA_BITS)
#define	PFN_TO_PT_OA(pfn)	(((pfn) << MMU_PAGESHIFT) & PT_OA_BITS)
#define	PT_TO_PA(pt)		(PA_TO_PT_OA((pt)))
#define	PTE_TO_PA(pt)		(PA_TO_PT_OA((pt)))

/*
 * Random "middle" attribute"
 */
#define	PT_ATTR_NT	(0x1ULL << 16)		/* Block iff FEAT_BBM */

/*
 * Lower Attributes
 */
#define	PT_ATTR_NG	(0x1ULL << 11)		/* Non-global */
#define	PT_ATTR_AF	(0x1ULL << 10)		/* Access Flag */
#define	PT_ATTR_SH(v)	(((v) & 0x3) << 8)	/* Sharability */
#define	PT_ATTR_AP(v)	(((v) & 0x3) << 6)	/* Access Permissions */
#define	PT_ATTR_NS	(0x1ULL << 5)		/* Non-secure */
#define	PT_MATTR(v)	(((v) & 0x7) << 2)	/* MAIR index */

#define	PT_AP_PRW	(0x0)			/* Priv R/W, User N/A */
#define	PT_AP_PRW_URW	(0x1)			/* Priv R/W, User R/W */
#define	PT_AP_PRO	(0x2)			/* Priv R/O, User N/A */
#define	PT_AP_PRO_URO	(0x3)			/* Priv R/O, User R/O */

#define	PT_SH_ATTR_NS	(0x0)
#define	PT_SH_ATTR_IS	(0x1)
#define	PT_SH_ATTR_OS	(0x2)

#define	PT_SH_NS	(0x0)				/* Non-sharable */
#define	PT_SH_01	(PT_SH_ATTR_IS)		/* Constrained unpredictable */
#define	PT_SH_OS	(PT_SH_ATTR_OS)			/* Outer sharable */
#define	PT_SH_IS	(PT_SH_ATTR_OS|PT_SH_ATTR_IS)	/* Inner sharable */

/*
 * Test whether a PTE is writable
 *
 * Only valid for BLOCK or PAGE entries.
 * Only valid for kernel use.
 */
#define	PT_IS_WRITABLE(pt)	((((pt) >> 6) & 0x3) == PT_AP_PRW)

/*
 * Test whether a PTE is an executable entry.
 *
 * Only valid for BLOCK or PAGE entries.
 * Only valid for kernel use.
 */
#define	PT_IS_EXECUTABLE(pt)	(!((pt) & PT_ATTR_PXN))


#if 0
#define PT_VALID        (0x001) /* a valid translation is present */
#define PT_WRITABLE     (0x002) /* the page is writable */
#define PT_USER         (0x004) /* the page is accessible by user mode */
#define PT_WRITETHRU    (0x008) /* write back caching is disabled (non-PAT) */
#define PT_NOCACHE      (0x010) /* page is not cacheable (non-PAT) */
#define PT_REF          (0x020) /* page was referenced */
#define PT_MOD          (0x040) /* page was modified */
#define PT_PAGESIZE     (0x080) /* above level 0, indicates a large page */
#define PT_PAT_4K       (0x080) /* at level 0, used for write combining */
#define PT_GLOBAL       (0x100) /* the mapping is global */
#define PT_SOFTWARE     (0xe00) /* software bits */

#define PT_PAT_LARGE    (0x1000)        /* PAT bit for large pages */

#define PT_PTPBITS      (PT_VALID | PT_USER | PT_WRITABLE | PT_REF)
#define PT_FLAGBITS     (0xfff) /* for masking off flag bits */
#endif

#define	PT_PTPBITS	(PT_ATTR_UXN | PT_ATTR_PXN | PT_ATTR_AF | \
    PT_ATTR_SH(PT_AP_PRW) | PT_ATTR_AF | PT_ATTR_SH(PT_SH_OS) | \
    PT_ATTR_AP(PT_AP_PRW) | PT_MATTR(MIDX_MEMORY_WB) | PTE_PAGE)

/*
 * The software bits are used by the HAT to track attributes.
 * Note that the attributes are inclusive as the values increase.
 *
 * PT_NOSYNC - The PT_REF/PT_MOD bits are not sync'd to page_t.
 *             The hat will install them as always set.
 *
 * PT_NOCONSIST - There is no hment entry for this mapping.
 *
 * PT_SOFT_DBM - Dirty state of a PTE is managed by software
 */
#define	PT_SOFT_DBM	(PT_ATTR_56)	/* software dirty bit modifier */
#define	PT_SOFTWARE	(0x3UL << 57)	/* Mask for software bits */
#define	PT_NOSYNC	(PT_ATTR_57)	/* Created with HAT_NOSYNC */
#define	PT_NOCONSIST	(PT_ATTR_58)	/* Created with HAT_LOAD_NOCONSIST */

#ifdef __cplusplus
}
#endif

#endif	/* _PTE_H */
