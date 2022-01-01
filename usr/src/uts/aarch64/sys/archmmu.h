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

#ifndef _ARCHMMU_H
#define	_ARCHMMU_H

#include <sys/arm/armv8_mair.h>

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
#if 0
#define	MAKE_MAIR(__idx, __attr)	((__attr) << ((__idx) * 8))
#define	MAIR_EL1_CONTENTS						\
	(MAKE_MAIR(MIDX_MEMORY_WB, MATTR_MEMORY_WB) |			\
	MAKE_MAIR(MIDX_MEMORY_WT, MATTR_MEMORY_WT) |			\
	MAKE_MAIR(MIDX_MEMORY_NC, MATTR_MEMORY_NC) |			\
	MAKE_MAIR(MIDX_DEVICE, MATTR_DEVICE) |				\
	MAKE_MAIR(MIDX_DEVICE_REORDERED, MATTR_DEVICE_REORDERED) |	\
	MAKE_MAIR(MIDX_DEVICE_SO, MATTR_DEVICE_SO) |			\
	MAKE_MAIR(MIDX_DEVICE_RELAXED, MIDX_DEVICE_RELAXED))
/* #undef MAKE_MAIR */
#endif


#define	TWO_MEG		(2 * 1024 * 1024)
#define	ONE_GIG		(1024 * 1024 * 1024)

#ifdef __cplusplus
}
#endif

#endif	/* _ARCHMMU_H */
