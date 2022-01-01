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

#ifndef _ARMV8_MAIR_H
#define	_ARMV8_MAIR_H

/*
 * Provides building blocks for the Memory Attribute Indirection Register
 * in ARMv8-A.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * MAIR entries have the following layout:
 * Bits [7:4]
 * 0b0000: Device Memory
 * 0b00RW: RW not 00, Normal Memory, Outer Write-through transient.
 * 0b0100: Normal Memory, Outer Non-Cacheable.
 * 0b01RW: RW not 00, Normal Memory, Outer Write-back transient.
 * 0b10RW: Normal Memory, Outer Write-through non-transient.
 * 0b11RW: Normal Memory, Outer Write-back non-transient.
 *
 * In the Device Memory case ([7:4] == 0b0000), bits [3:0] are:
 * 0b0000: Device-nGnRnE memory
 * 0b0100: Device-nGnRE memory
 * 0b1000: Device-nGRE memory
 * 0b1100: Device-GRE memory
 *
 * In the non-device case ([7:4] != 0b0000), bits [3:0] are:
 * 0b00RW: RW not 00, Normal Memory, Inner Write-through transient.
 * 0b0100: Normal memory, Inner Non-Cacheable.
 * 0b01RW: RW not 00, Normal Memory, Inner Write-back transient.
 * 0b1000: Normal Memory, Inner Write-through non-transient (RW=00)
 * 0b10RW: RW not 00, Normal Memory, Inner Write-through non-transient
 * 0b1100: Normal Memory, Inner Write-back non-transient (RW=00)
 * 0b11RW: RW not 00, Normal Memory, Inner Write-back non-transient
 *
 * The RW bits represent the outer read and write allocate policy
 * respectively, and have the following meanings:
 * 0: Do not allocate
 * 1: Allocate
 *
 * For device memory, the following mnemonics are used for the low bits:
 * nG/G: (non-)Gathering
 * nR/R: (non-)Reordering
 * nE/E: (non-)Early Write Acknowledgement
 *
 * Device-nGnRnE is equivalent to strongly ordered
 * Device-nGnRE is the device memory type from armv7-a
 * Device-nGRE Use of barriers is required here (due to reordering)
 * Device-GRE Similar to normal memory, but speculative access is forbidden
 *
 * A point to note is that speculative access to any device memory type is
 * forbidden.
 *
 * Also note: "... two writes of device memory type to the same location might
 * be merged before they reach the endpoint, unless both writes have the
 * non-Gathering attribute or there is an ordered-before relationship between
 * the two writes."  This can be accomplished using a DMB instruction.
 *
 * Finally, and very important, "... hardware does not prevent speculative
 * instruction fetches from a memory location with any of the Device memory
 * attributes unless the memory location is also marked as execute-never _for
 * all Exception levels_." - we're not entirely in control of this, but we can
 * do our part.
 */

#define	MAIR_WRITE_ALLOCATE_SHIFT	0
#define	MAIR_READ_ALLOCATE_SHIFT	1
#define	MAIR_NO_ALLOCATE		0
#define	MAIR_ALLOCATE			1

#define	MAIR_HI(v, ra, wa)		((v)	\
	| ((ra) << (MAIR_READ_ALLOCATE_SHIFT))	\
	| ((wa) << (MAIR_WRITE_ALLOCATE_SHIFT)))

#define	MAIR_HI_DEVICE			0x0 /* Device */
#define	MAIR_HI_NORMAL_OWT_T		0x0 /* Outer Write-through transient */
#define	MAIR_HI_NORMAL_ONC		0x4 /* Outer Non-Cacheable */
#define	MAIR_HI_NORMAL_OWB_T		0x4 /* Outer Write-back transient */
#define	MAIR_HI_NORMAL_OWT		0x8 /* Outer Write-through */
#define	MAIR_HI_NORMAL_OWB		0xc /* Outer Write-back */

#define	MAIR_HI_NORMAL_OWT_T_RA		\
	MAIR_HI(MAIR_HI_NORMAL_OWT_T, MAIR_ALLOCATE, MAIR_NO_ALLOCATE)
#define	MAIR_HI_NORMAL_OWT_T_WA		\
	MAIR_HI(MAIR_HI_NORMAL_OWT_T, MAIR_NO_ALLOCATE, MAIR_ALLOCATE)
#define	MAIR_HI_NORMAL_OWT_T_RA_WA	\
	MAIR_HI(MAIR_HI_NORMAL_OWT_T, MAIR_ALLOCATE, MAIR_ALLOCATE)
#if 0
#if !defined(_ASM)
#undef MAIR_HI_NORMAL_OWT_T	/* RW may not be 0b00 */
#endif	/* !_ASM */
#endif

#define	MAIR_HI_NORMAL_OWB_T_RA		\
	MAIR_HI(MAIR_HI_NORMAL_OWB_T, MAIR_ALLOCATE, MAIR_NO_ALLOCATE)
#define	MAIR_HI_NORMAL_OWB_T_WA		\
	MAIR_HI(MAIR_HI_NORMAL_OWB_T, MAIR_NO_ALLOCATE, MAIR_ALLOCATE)
#define	MAIR_HI_NORMAL_OWB_T_RA_WA	\
	MAIR_HI(MAIR_HI_NORMAL_OWB_T, MAIR_ALLOCATE, MAIR_ALLOCATE)
#if 0
#if !defined(_ASM)
#undef MAIR_HI_NORMAL_OWB_T	/* RW may not be 0b00 */
#endif	/* !_ASM */
#endif

#define	MAIR_HI_NORMAL_OWT_RA		\
	MAIR_HI(MAIR_HI_NORMAL_OWT, MAIR_ALLOCATE, MAIR_NO_ALLOCATE)
#define	MAIR_HI_NORMAL_OWT_WA		\
	MAIR_HI(MAIR_HI_NORMAL_OWT, MAIR_NO_ALLOCATE, MAIR_ALLOCATE)
#define	MAIR_HI_NORMAL_OWT_RA_WA	\
	MAIR_HI(MAIR_HI_NORMAL_OWT, MAIR_ALLOCATE, MAIR_ALLOCATE)

#define	MAIR_HI_NORMAL_OWB_RA		\
	MAIR_HI(MAIR_HI_NORMAL_OWB, MAIR_ALLOCATE, MAIR_NO_ALLOCATE)
#define	MAIR_HI_NORMAL_OWB_WA		\
	MAIR_HI(MAIR_HI_NORMAL_OWB, MAIR_NO_ALLOCATE, MAIR_ALLOCATE)
#define	MAIR_HI_NORMAL_OWB_RA_WA	\
	MAIR_HI(MAIR_HI_NORMAL_OWB, MAIR_ALLOCATE, MAIR_ALLOCATE)

#if 0
#if !defined(_ASM)
#undef MAIR_HI
#endif	/* !_ASM */
#endif

#define	MAIR_LO(v, ra, wa)		((v)	\
	| ((ra) << (MAIR_READ_ALLOCATE_SHIFT))	\
	| ((wa) << (MAIR_WRITE_ALLOCATE_SHIFT)))

#define	MAIR_LO_DEVICE_NGNRNE		0x0
#define	MAIR_LO_DEVICE_NGNRE		0x4
#define	MAIR_LO_DEVICE_NGRE		0x8
#define	MAIR_LO_DEVICE_GRE		0xc

#define	MAIR_LO_NORMAL_IWT_T		0x0 /* Inner Write-through transient */
#define	MAIR_LO_NORMAL_INC		0x4 /* Inner Non-Cacheable */
#define	MAIR_LO_NORMAL_IWB_T		0x4 /* Inner Write-back transient */
#define	MAIR_LO_NORMAL_IWT		0x8 /* Inner Write-through */
#define	MAIR_LO_NORMAL_IWB		0xc /* Inner Write-back */

#define	MAIR_LO_NORMAL_IWT_T_RA		\
	MAIR_LO(MAIR_LO_NORMAL_IWT_T, MAIR_ALLOCATE, MAIR_NO_ALLOCATE)
#define	MAIR_LO_NORMAL_IWT_T_WA		\
	MAIR_LO(MAIR_LO_NORMAL_IWT_T, MAIR_NO_ALLOCATE, MAIR_ALLOCATE)
#define	MAIR_LO_NORMAL_IWT_T_RA_WA	\
	MAIR_LO(MAIR_LO_NORMAL_IWT_T, MAIR_ALLOCATE, MAIR_ALLOCATE)
#if 0
#if !defined(_ASM)
#undef MAIR_LO_NORMAL_IWT_T	/* RW may not be 0b00 */
#endif	/* !_ASM */
#endif

#define	MAIR_LO_NORMAL_IWB_T_RA		\
	MAIR_LO(MAIR_LO_NORMAL_IWB_T, MAIR_ALLOCATE, MAIR_NO_ALLOCATE)
#define	MAIR_LO_NORMAL_IWB_T_WA		\
	MAIR_LO(MAIR_LO_NORMAL_IWB_T, MAIR_NO_ALLOCATE, MAIR_ALLOCATE)
#define	MAIR_LO_NORMAL_IWB_T_RA_WA	\
	MAIR_LO(MAIR_LO_NORMAL_IWB_T, MAIR_ALLOCATE, MAIR_ALLOCATE)
#if 0
#if !defined(_ASM)
#undef MAIR_LO_NORMAL_IWB_T	/* RW may not be 0b00 */
#endif	/* !_ASM */
#endif

#define	MAIR_LO_NORMAL_IWT_RA		\
	MAIR_LO(MAIR_LO_NORMAL_IWT, MAIR_ALLOCATE, MAIR_NO_ALLOCATE)
#define	MAIR_LO_NORMAL_IWT_WA		\
	MAIR_LO(MAIR_LO_NORMAL_IWT, MAIR_NO_ALLOCATE, MAIR_ALLOCATE)
#define	MAIR_LO_NORMAL_IWT_RA_WA	\
	MAIR_LO(MAIR_LO_NORMAL_IWT, MAIR_ALLOCATE, MAIR_ALLOCATE)

#define	MAIR_LO_NORMAL_IWB_RA		\
	MAIR_LO(MAIR_LO_NORMAL_IWB, MAIR_ALLOCATE, MAIR_NO_ALLOCATE)
#define	MAIR_LO_NORMAL_IWB_WA		\
	MAIR_LO(MAIR_LO_NORMAL_IWB, MAIR_NO_ALLOCATE, MAIR_ALLOCATE)
#define	MAIR_LO_NORMAL_IWB_RA_WA	\
	MAIR_LO(MAIR_LO_NORMAL_IWB, MAIR_ALLOCATE, MAIR_ALLOCATE)

#if 0
#if !defined(_ASM)
#undef MAIR_LO
#endif	/* !_ASM */
#endif

#define	MAIR_HI_SHIFT			4
#define	MAIR(hi, lo)			(((hi) << MAIR_HI_SHIFT) | (lo))

/*
 * And, finally, the supported MAIR values.
 */

/*
 * Device memory, non-Gathering, non-Reordering, no Early Write Acknowledgement
 */
#define	MAIR_DEVICE_NGNRNE			\
	MAIR(MAIR_HI_DEVICE, MAIR_LO_DEVICE_NGNRNE)

/*
 * Device memory, non-Gathering, non-Reordering, Early Write Acknowledgement
 */
#define	MAIR_DEVICE_NGNRE			\
	MAIR(MAIR_HI_DEVICE, MAIR_LO_DEVICE_NGNRE)

/*
 * Device memory, non-Gathering, Reordering, Early Write Acknowledgement
 */
#define	MAIR_DEVICE_NGRE			\
	MAIR(MAIR_HI_DEVICE, MAIR_LO_DEVICE_NGRE)

/*
 * Device memory, Gathering, Reordering, Early Write Acknowledgement
 */
#define	MAIR_DEVICE_GRE				\
	MAIR(MAIR_HI_DEVICE, MAIR_LO_DEVICE_GRE)

#if 0
#if !defined(_ASM)
#undef MAIR_HI_DEVICE
#undef MAIR_LO_DEVICE_NGNRNE
#undef MAIR_LO_DEVICE_NGNRE
#undef MAIR_LO_DEVICE_NGRE
#undef MAIR_LO_DEVICE_GRE
#endif	/* !_ASM */
#endif

/*
 * Normal Memory
 * Outer uncached
 * Inner uncached
 */
#define	MAIR_NORMAL_ONC_INC			\
	MAIR(MAIR_HI_NORMAL_ONC, MAIR_LO_NORMAL_INC)

/*
 * Normal Memory
 * Outer uncached
 * Inner write-through, transient, read-allocate
 */
#define	MAIR_NORMAL_ONC_IWT_T_RA		\
	MAIR(MAIR_HI_NORMAL_ONC, MAIR_LO_NORMAL_IWT_T_RA)

/*
 * Normal Memory
 * Outer uncached
 * Inner write-through, transient, write-allocate
 */
#define	MAIR_NORMAL_ONC_IWT_T_WA		\
	MAIR(MAIR_HI_NORMAL_ONC, MAIR_LO_NORMAL_IWT_T_WA)

/*
 * Normal Memory
 * Outer uncached
 * Inner write-through, transient, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_ONC_IWT_T_RA_WA		\
	MAIR(MAIR_HI_NORMAL_ONC, MAIR_LO_NORMAL_IWT_T_RA_WA)

/*
 * Normal Memory
 * Outer uncached
 * Inner write-back, transient, read-allocate
 */
#define	MAIR_NORMAL_ONC_IWB_T_RA		\
	MAIR(MAIR_HI_NORMAL_ONC, MAIR_LO_NORMAL_IWB_T_RA)

/*
 * Normal Memory
 * Outer uncached
 * Inner write-back, transient, write-allocate
 */
#define	MAIR_NORMAL_ONC_IWB_T_WA		\
	MAIR(MAIR_HI_NORMAL_ONC, MAIR_LO_NORMAL_IWB_T_WA)

/*
 * Normal Memory
 * Outer uncached
 * Inner write-back, transient, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_ONC_IWB_T_RA_WA		\
	MAIR(MAIR_HI_NORMAL_ONC, MAIR_LO_NORMAL_IWB_T_RA_WA)

/*
 * Normal Memory
 * Outer uncached
 * Inner write-through
 */
#define	MAIR_NORMAL_ONC_IWT			\
	MAIR(MAIR_HI_NORMAL_ONC, MAIR_LO_NORMAL_IWT)

/*
 * Normal Memory
 * Outer uncached
 * Inner write-through, read-allocate
 */
#define	MAIR_NORMAL_ONC_IWT_RA			\
	MAIR(MAIR_HI_NORMAL_ONC, MAIR_LO_NORMAL_IWT_RA)

/*
 * Normal Memory
 * Outer uncached
 * Inner write-through, write-allocate
 */
#define	MAIR_NORMAL_ONC_IWT_WA			\
	MAIR(MAIR_HI_NORMAL_ONC, MAIR_LO_NORMAL_IWT_WA)

/*
 * Normal Memory
 * Outer uncached
 * Inner write-through, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_ONC_IWT_RA_WA		\
	MAIR(MAIR_HI_NORMAL_ONC, MAIR_LO_NORMAL_IWT_RA_WA)

/*
 * Normal Memory
 * Outer uncached
 * Inner write-back
 */
#define	MAIR_NORMAL_ONC_IWB			\
	MAIR(MAIR_HI_NORMAL_ONC, MAIR_LO_NORMAL_IWB)

/*
 * Normal Memory
 * Outer uncached
 * Inner write-back, read-allocate
 */
#define	MAIR_NORMAL_ONC_IWB_RA			\
	MAIR(MAIR_HI_NORMAL_ONC, MAIR_LO_NORMAL_IWB_RA)

/*
 * Normal Memory
 * Outer uncached
 * Inner write-back, write-allocate
 */
#define	MAIR_NORMAL_ONC_IWB_WA			\
	MAIR(MAIR_HI_NORMAL_ONC, MAIR_LO_NORMAL_IWB_WA)

/*
 * Normal Memory
 * Outer uncached
 * Inner write-back, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_ONC_IWB_RA_WA		\
	MAIR(MAIR_HI_NORMAL_ONC, MAIR_LO_NORMAL_IWB_RA_WA)

/*
 * Normal Memory
 * Outer write-through, transient, read-allocate
 * Inner uncached
 */
#define	MAIR_NORMAL_OWT_T_RA_INC		\
	MAIR(MAIR_HI_NORMAL_OWT_T_RA, MAIR_LO_NORMAL_INC)

/*
 * Normal Memory
 * Outer write-through, transient, read-allocate
 * Inner write-through, transient, read-allocate
 */
#define	MAIR_NORMAL_OWT_T_RA_IWT_T_RA		\
	MAIR(MAIR_HI_NORMAL_OWT_T_RA, MAIR_LO_NORMAL_IWT_T_RA)

/*
 * Normal Memory
 * Outer write-through, transient, read-allocate
 * Inner write-through, transient, write-allocate
 */
#define	MAIR_NORMAL_OWT_T_RA_IWT_T_WA		\
	MAIR(MAIR_HI_NORMAL_OWT_T_RA, MAIR_LO_NORMAL_IWT_T_WA)

/*
 * Normal Memory
 * Outer write-through, transient, read-allocate
 * Inner write-through, transient, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWT_T_RA_IWT_T_RA_WA	\
	MAIR(MAIR_HI_NORMAL_OWT_T_RA, MAIR_LO_NORMAL_IWT_T_RA_WA)

/*
 * Normal Memory
 * Outer write-through, transient, read-allocate
 * Inner write-back, transient, read-allocate
 */
#define	MAIR_NORMAL_OWT_T_RA_IWB_T_RA		\
	MAIR(MAIR_HI_NORMAL_OWT_T_RA, MAIR_LO_NORMAL_IWB_T_RA)

/*
 * Normal Memory
 * Outer write-through, transient, read-allocate
 * Inner write-back, transient, write-allocate
 */
#define	MAIR_NORMAL_OWT_T_RA_IWB_T_WA		\
	MAIR(MAIR_HI_NORMAL_OWT_T_RA, MAIR_LO_NORMAL_IWB_T_WA)

/*
 * Normal Memory
 * Outer write-through, transient, read-allocate
 * Inner write-back, transient, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWT_T_RA_IWB_T_RA_WA	\
	MAIR(MAIR_HI_NORMAL_OWT_T_RA, MAIR_LO_NORMAL_IWB_T_RA_WA)

/*
 * Normal Memory
 * Outer write-through, transient, read-allocate
 * Inner write-through
 */
#define	MAIR_NORMAL_OWT_T_RA_IWT		\
	MAIR(MAIR_HI_NORMAL_OWT_T_RA, MAIR_LO_NORMAL_IWT)

/*
 * Normal Memory
 * Outer write-through, transient, read-allocate
 * Inner write-through, read-allocate
 */
#define	MAIR_NORMAL_OWT_T_RA_IWT_RA		\
	MAIR(MAIR_HI_NORMAL_OWT_T_RA, MAIR_LO_NORMAL_IWT_RA)

/*
 * Normal Memory
 * Outer write-through, transient, read-allocate
 * Inner write-through, write-allocate
 */
#define	MAIR_NORMAL_OWT_T_RA_IWT_WA		\
	MAIR(MAIR_HI_NORMAL_OWT_T_RA, MAIR_LO_NORMAL_IWT_WA)

/*
 * Normal Memory
 * Outer write-through, transient, read-allocate
 * Inner write-through, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWT_T_RA_IWT_RA_WA		\
	MAIR(MAIR_HI_NORMAL_OWT_T_RA, MAIR_LO_NORMAL_IWT_RA_WA)

/*
 * Normal Memory
 * Outer write-through, transient, read-allocate
 * Inner write-back
 */
#define	MAIR_NORMAL_OWT_T_RA_IWB		\
	MAIR(MAIR_HI_NORMAL_OWT_T_RA, MAIR_LO_NORMAL_IWB)

/*
 * Normal Memory
 * Outer write-through, transient, read-allocate
 * Inner write-back, read-allocate
 */
#define	MAIR_NORMAL_OWT_T_RA_IWB_RA		\
	MAIR(MAIR_HI_NORMAL_OWT_T_RA, MAIR_LO_NORMAL_IWB_RA)

/*
 * Normal Memory
 * Outer write-through, transient, read-allocate
 * Inner write-back, write-allocate
 */
#define	MAIR_NORMAL_OWT_T_RA_IWB_WA		\
	MAIR(MAIR_HI_NORMAL_OWT_T_RA, MAIR_LO_NORMAL_IWB_WA)

/*
 * Normal Memory
 * Outer write-through, transient, read-allocate
 * Inner write-back, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWT_T_RA_IWB_RA_WA		\
	MAIR(MAIR_HI_NORMAL_OWT_T_RA, MAIR_LO_NORMAL_IWB_RA_WA)

/*
 * Normal Memory
 * Outer write-through, transient, write-allocate
 * Inner uncached
 */
#define	MAIR_NORMAL_OWT_T_WA_INC		\
	MAIR(MAIR_HI_NORMAL_OWT_T_WA, MAIR_LO_NORMAL_INC)

/*
 * Normal Memory
 * Outer write-through, transient, write-allocate
 * Inner write-through, transient, read-allocate
 */
#define	MAIR_NORMAL_OWT_T_WA_IWT_T_RA		\
	MAIR(MAIR_HI_NORMAL_OWT_T_WA, MAIR_LO_NORMAL_IWT_T_RA)

/*
 * Normal Memory
 * Outer write-through, transient, write-allocate
 * Inner write-through, transient, write-allocate
 */
#define	MAIR_NORMAL_OWT_T_WA_IWT_T_WA		\
	MAIR(MAIR_HI_NORMAL_OWT_T_WA, MAIR_LO_NORMAL_IWT_T_WA)

/*
 * Normal Memory
 * Outer write-through, transient, write-allocate
 * Inner write-through, transient, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWT_T_WA_IWT_T_RA_WA	\
	MAIR(MAIR_HI_NORMAL_OWT_T_WA, MAIR_LO_NORMAL_IWT_T_RA_WA)

/*
 * Normal Memory
 * Outer write-through, transient, write-allocate
 * Inner write-back, transient, read-allocate
 */
#define	MAIR_NORMAL_OWT_T_WA_IWB_T_RA		\
	MAIR(MAIR_HI_NORMAL_OWT_T_WA, MAIR_LO_NORMAL_IWB_T_RA)

/*
 * Normal Memory
 * Outer write-through, transient, write-allocate
 * Inner write-back, transient, write-allocate
 */
#define	MAIR_NORMAL_OWT_T_WA_IWB_T_WA		\
	MAIR(MAIR_HI_NORMAL_OWT_T_WA, MAIR_LO_NORMAL_IWB_T_WA)

/*
 * Normal Memory
 * Outer write-through, transient, write-allocate
 * Inner write-back, transient, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWT_T_WA_IWB_T_RA_WA	\
	MAIR(MAIR_HI_NORMAL_OWT_T_WA, MAIR_LO_NORMAL_IWB_T_RA_WA)

/*
 * Normal Memory
 * Outer write-through, transient, write-allocate
 * Inner write-through
 */
#define	MAIR_NORMAL_OWT_T_WA_IWT		\
	MAIR(MAIR_HI_NORMAL_OWT_T_WA, MAIR_LO_NORMAL_IWT)

/*
 * Normal Memory
 * Outer write-through, transient, write-allocate
 * Inner write-through, read-allocate
 */
#define	MAIR_NORMAL_OWT_T_WA_IWT_RA		\
	MAIR(MAIR_HI_NORMAL_OWT_T_WA, MAIR_LO_NORMAL_IWT_RA)

/*
 * Normal Memory
 * Outer write-through, transient, write-allocate
 * Inner write-through, write-allocate
 */
#define	MAIR_NORMAL_OWT_T_WA_IWT_WA		\
	MAIR(MAIR_HI_NORMAL_OWT_T_WA, MAIR_LO_NORMAL_IWT_WA)

/*
 * Normal Memory
 * Outer write-through, transient, write-allocate
 * Inner write-through, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWT_T_WA_IWT_RA_WA		\
	MAIR(MAIR_HI_NORMAL_OWT_T_WA, MAIR_LO_NORMAL_IWT_RA_WA)

/*
 * Normal Memory
 * Outer write-through, transient, write-allocate
 * Inner write-back
 */
#define	MAIR_NORMAL_OWT_T_WA_IWB		\
	MAIR(MAIR_HI_NORMAL_OWT_T_WA, MAIR_LO_NORMAL_IWB)

/*
 * Normal Memory
 * Outer write-through, transient, write-allocate
 * Inner write-back, read-allocate
 */
#define	MAIR_NORMAL_OWT_T_WA_IWB_RA		\
	MAIR(MAIR_HI_NORMAL_OWT_T_WA, MAIR_LO_NORMAL_IWB_RA)

/*
 * Normal Memory
 * Outer write-through, transient, write-allocate
 * Inner write-back, write-allocate
 */
#define	MAIR_NORMAL_OWT_T_WA_IWB_WA		\
	MAIR(MAIR_HI_NORMAL_OWT_T_WA, MAIR_LO_NORMAL_IWB_WA)

/*
 * Normal Memory
 * Outer write-through, transient, write-allocate
 * Inner write-back, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWT_T_WA_IWB_RA_WA		\
	MAIR(MAIR_HI_NORMAL_OWT_T_WA, MAIR_LO_NORMAL_IWB_RA_WA)

/*
 * Normal Memory
 * Outer write-through, transient, read-allocate, write-allocate
 * Inner uncached
 */
#define	MAIR_NORMAL_OWT_T_RA_WA_INC		\
	MAIR(MAIR_HI_NORMAL_OWT_T_RA_WA, MAIR_LO_NORMAL_INC)

/*
 * Normal Memory
 * Outer write-through, transient, read-allocate, write-allocate
 * Inner write-through, transient, read-allocate
 */
#define	MAIR_NORMAL_OWT_T_RA_WA_IWT_T_RA	\
	MAIR(MAIR_HI_NORMAL_OWT_T_RA_WA, MAIR_LO_NORMAL_IWT_T_RA)

/*
 * Normal Memory
 * Outer write-through, transient, read-allocate, write-allocate
 * Inner write-through, transient, write-allocate
 */
#define	MAIR_NORMAL_OWT_T_RA_WA_IWT_T_WA	\
	MAIR(MAIR_HI_NORMAL_OWT_T_RA_WA, MAIR_LO_NORMAL_IWT_T_WA)

/*
 * Normal Memory
 * Outer write-through, transient, read-allocate, write-allocate
 * Inner write-through, transient, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWT_T_RA_WA_IWT_T_RA_WA	\
	MAIR(MAIR_HI_NORMAL_OWT_T_RA_WA, MAIR_LO_NORMAL_IWT_T_RA_WA)

/*
 * Normal Memory
 * Outer write-through, transient, read-allocate, write-allocate
 * Inner write-back, transient, read-allocate
 */
#define	MAIR_NORMAL_OWT_T_RA_WA_IWB_T_RA	\
	MAIR(MAIR_HI_NORMAL_OWT_T_RA_WA, MAIR_LO_NORMAL_IWB_T_RA)

/*
 * Normal Memory
 * Outer write-through, transient, read-allocate, write-allocate
 * Inner write-back, transient, write-allocate
 */
#define	MAIR_NORMAL_OWT_T_RA_WA_IWB_T_WA	\
	MAIR(MAIR_HI_NORMAL_OWT_T_RA_WA, MAIR_LO_NORMAL_IWB_T_WA)

/*
 * Normal Memory
 * Outer write-through, transient, read-allocate, write-allocate
 * Inner write-back, transient, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWT_T_RA_WA_IWB_T_RA_WA	\
	MAIR(MAIR_HI_NORMAL_OWT_T_RA_WA, MAIR_LO_NORMAL_IWB_T_RA_WA)

/*
 * Normal Memory
 * Outer write-through, transient, read-allocate, write-allocate
 * Inner write-through
 */
#define	MAIR_NORMAL_OWT_T_RA_WA_IWT		\
	MAIR(MAIR_HI_NORMAL_OWT_T_RA_WA, MAIR_LO_NORMAL_IWT)

/*
 * Normal Memory
 * Outer write-through, transient, read-allocate, write-allocate
 * Inner write-through, read-allocate
 */
#define	MAIR_NORMAL_OWT_T_RA_WA_IWT_RA		\
	MAIR(MAIR_HI_NORMAL_OWT_T_RA_WA, MAIR_LO_NORMAL_IWT_RA)

/*
 * Normal Memory
 * Outer write-through, transient, read-allocate, write-allocate
 * Inner write-through, write-allocate
 */
#define	MAIR_NORMAL_OWT_T_RA_WA_IWT_WA		\
	MAIR(MAIR_HI_NORMAL_OWT_T_RA_WA, MAIR_LO_NORMAL_IWT_WA)

/*
 * Normal Memory
 * Outer write-through, transient, read-allocate, write-allocate
 * Inner write-through, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWT_T_RA_WA_IWT_RA_WA	\
	MAIR(MAIR_HI_NORMAL_OWT_T_RA_WA, MAIR_LO_NORMAL_IWT_RA_WA)

/*
 * Normal Memory
 * Outer write-through, transient, read-allocate, write-allocate
 * Inner write-back
 */
#define	MAIR_NORMAL_OWT_T_RA_WA_IWB		\
	MAIR(MAIR_HI_NORMAL_OWT_T_RA_WA, MAIR_LO_NORMAL_IWB)

/*
 * Normal Memory
 * Outer write-through, transient, read-allocate, write-allocate
 * Inner write-back, read-allocate
 */
#define	MAIR_NORMAL_OWT_T_RA_WA_IWB_RA		\
	MAIR(MAIR_HI_NORMAL_OWT_T_RA_WA, MAIR_LO_NORMAL_IWB_RA)

/*
 * Normal Memory
 * Outer write-through, transient, read-allocate, write-allocate
 * Inner write-back, write-allocate
 */
#define	MAIR_NORMAL_OWT_T_RA_WA_IWB_WA		\
	MAIR(MAIR_HI_NORMAL_OWT_T_RA_WA, MAIR_LO_NORMAL_IWB_WA)

/*
 * Normal Memory
 * Outer write-through, transient, read-allocate, write-allocate
 * Inner write-back, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWT_T_RA_WA_IWB_RA_WA	\
	MAIR(MAIR_HI_NORMAL_OWT_T_RA_WA, MAIR_LO_NORMAL_IWB_RA_WA)

/*
 * Normal Memory
 * Outer write-back, transient, read-allocate
 * Inner uncached
 */
#define	MAIR_NORMAL_OWB_T_RA_INC		\
	MAIR(MAIR_HI_NORMAL_OWB_T_RA, MAIR_LO_NORMAL_INC)

/*
 * Normal Memory
 * Outer write-back, transient, read-allocate
 * Inner write-through, transient, read-allocate
 */
#define	MAIR_NORMAL_OWB_T_RA_IWT_T_RA		\
	MAIR(MAIR_HI_NORMAL_OWB_T_RA, MAIR_LO_NORMAL_IWT_T_RA)

/*
 * Normal Memory
 * Outer write-back, transient, read-allocate
 * Inner write-through, transient, write-allocate
 */
#define	MAIR_NORMAL_OWB_T_RA_IWT_T_WA		\
	MAIR(MAIR_HI_NORMAL_OWB_T_RA, MAIR_LO_NORMAL_IWT_T_WA)

/*
 * Normal Memory
 * Outer write-back, transient, read-allocate
 * Inner write-through, transient, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWB_T_RA_IWT_T_RA_WA	\
	MAIR(MAIR_HI_NORMAL_OWB_T_RA, MAIR_LO_NORMAL_IWT_T_RA_WA)

/*
 * Normal Memory
 * Outer write-back, transient, read-allocate
 * Inner write-back, transient, read-allocate
 */
#define	MAIR_NORMAL_OWB_T_RA_IWB_T_RA		\
	MAIR(MAIR_HI_NORMAL_OWB_T_RA, MAIR_LO_NORMAL_IWB_T_RA)

/*
 * Normal Memory
 * Outer write-back, transient, read-allocate
 * Inner write-back, transient, write-allocate
 */
#define	MAIR_NORMAL_OWB_T_RA_IWB_T_WA		\
	MAIR(MAIR_HI_NORMAL_OWB_T_RA, MAIR_LO_NORMAL_IWB_T_WA)

/*
 * Normal Memory
 * Outer write-back, transient, read-allocate
 * Inner write-back, transient, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWB_T_RA_IWB_T_RA_WA	\
	MAIR(MAIR_HI_NORMAL_OWB_T_RA, MAIR_LO_NORMAL_IWB_T_RA_WA)

/*
 * Normal Memory
 * Outer write-back, transient, read-allocate
 * Inner write-through
 */
#define	MAIR_NORMAL_OWB_T_RA_IWT		\
	MAIR(MAIR_HI_NORMAL_OWB_T_RA, MAIR_LO_NORMAL_IWT)

/*
 * Normal Memory
 * Outer write-back, transient, read-allocate
 * Inner write-through, read-allocate
 */
#define	MAIR_NORMAL_OWB_T_RA_IWT_RA		\
	MAIR(MAIR_HI_NORMAL_OWB_T_RA, MAIR_LO_NORMAL_IWT_RA)

/*
 * Normal Memory
 * Outer write-back, transient, read-allocate
 * Inner write-through, write-allocate
 */
#define	MAIR_NORMAL_OWB_T_RA_IWT_WA		\
	MAIR(MAIR_HI_NORMAL_OWB_T_RA, MAIR_LO_NORMAL_IWT_WA)

/*
 * Normal Memory
 * Outer write-back, transient, read-allocate
 * Inner write-through, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWB_T_RA_IWT_RA_WA		\
	MAIR(MAIR_HI_NORMAL_OWB_T_RA, MAIR_LO_NORMAL_IWT_RA_WA)

/*
 * Normal Memory
 * Outer write-back, transient, read-allocate
 * Inner write-back
 */
#define	MAIR_NORMAL_OWB_T_RA_IWB		\
	MAIR(MAIR_HI_NORMAL_OWB_T_RA, MAIR_LO_NORMAL_IWB)

/*
 * Normal Memory
 * Outer write-back, transient, read-allocate
 * Inner write-back, read-allocate
 */
#define	MAIR_NORMAL_OWB_T_RA_IWB_RA		\
	MAIR(MAIR_HI_NORMAL_OWB_T_RA, MAIR_LO_NORMAL_IWB_RA)

/*
 * Normal Memory
 * Outer write-back, transient, read-allocate
 * Inner write-back, write-allocate
 */
#define	MAIR_NORMAL_OWB_T_RA_IWB_WA		\
	MAIR(MAIR_HI_NORMAL_OWB_T_RA, MAIR_LO_NORMAL_IWB_WA)

/*
 * Normal Memory
 * Outer write-back, transient, read-allocate
 * Inner write-back, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWB_T_RA_IWB_RA_WA		\
	MAIR(MAIR_HI_NORMAL_OWB_T_RA, MAIR_LO_NORMAL_IWB_RA_WA)

/*
 * Normal Memory
 * Outer write-back, transient, write-allocate
 * Inner uncached
 */
#define	MAIR_NORMAL_OWB_T_WA_INC		\
	MAIR(MAIR_HI_NORMAL_OWB_T_WA, MAIR_LO_NORMAL_INC)

/*
 * Normal Memory
 * Outer write-back, transient, write-allocate
 * Inner write-through, transient, read-allocate
 */
#define	MAIR_NORMAL_OWB_T_WA_IWT_T_RA		\
	MAIR(MAIR_HI_NORMAL_OWB_T_WA, MAIR_LO_NORMAL_IWT_T_RA)

/*
 * Normal Memory
 * Outer write-back, transient, write-allocate
 * Inner write-through, transient, write-allocate
 */
#define	MAIR_NORMAL_OWB_T_WA_IWT_T_WA		\
	MAIR(MAIR_HI_NORMAL_OWB_T_WA, MAIR_LO_NORMAL_IWT_T_WA)

/*
 * Normal Memory
 * Outer write-back, transient, write-allocate
 * Inner write-through, transient, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWB_T_WA_IWT_T_RA_WA	\
	MAIR(MAIR_HI_NORMAL_OWB_T_WA, MAIR_LO_NORMAL_IWT_T_RA_WA)

/*
 * Normal Memory
 * Outer write-back, transient, write-allocate
 * Inner write-back, transient, read-allocate
 */
#define	MAIR_NORMAL_OWB_T_WA_IWB_T_RA		\
	MAIR(MAIR_HI_NORMAL_OWB_T_WA, MAIR_LO_NORMAL_IWB_T_RA)

/*
 * Normal Memory
 * Outer write-back, transient, write-allocate
 * Inner write-back, transient, write-allocate
 */
#define	MAIR_NORMAL_OWB_T_WA_IWB_T_WA		\
	MAIR(MAIR_HI_NORMAL_OWB_T_WA, MAIR_LO_NORMAL_IWB_T_WA)

/*
 * Normal Memory
 * Outer write-back, transient, write-allocate
 * Inner write-back, transient, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWB_T_WA_IWB_T_RA_WA	\
	MAIR(MAIR_HI_NORMAL_OWB_T_WA, MAIR_LO_NORMAL_IWB_T_RA_WA)

/*
 * Normal Memory
 * Outer write-back, transient, write-allocate
 * Inner write-through
 */
#define	MAIR_NORMAL_OWB_T_WA_IWT		\
	MAIR(MAIR_HI_NORMAL_OWB_T_WA, MAIR_LO_NORMAL_IWT)

/*
 * Normal Memory
 * Outer write-back, transient, write-allocate
 * Inner write-through, read-allocate
 */
#define	MAIR_NORMAL_OWB_T_WA_IWT_RA		\
	MAIR(MAIR_HI_NORMAL_OWB_T_WA, MAIR_LO_NORMAL_IWT_RA)

/*
 * Normal Memory
 * Outer write-back, transient, write-allocate
 * Inner write-through, write-allocate
 */
#define	MAIR_NORMAL_OWB_T_WA_IWT_WA		\
	MAIR(MAIR_HI_NORMAL_OWB_T_WA, MAIR_LO_NORMAL_IWT_WA)

/*
 * Normal Memory
 * Outer write-back, transient, write-allocate
 * Inner write-through, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWB_T_WA_IWT_RA_WA		\
	MAIR(MAIR_HI_NORMAL_OWB_T_WA, MAIR_LO_NORMAL_IWT_RA_WA)

/*
 * Normal Memory
 * Outer write-back, transient, write-allocate
 * Inner write-back
 */
#define	MAIR_NORMAL_OWB_T_WA_IWB		\
	MAIR(MAIR_HI_NORMAL_OWB_T_WA, MAIR_LO_NORMAL_IWB)

/*
 * Normal Memory
 * Outer write-back, transient, write-allocate
 * Inner write-back, read-allocate
 */
#define	MAIR_NORMAL_OWB_T_WA_IWB_RA		\
	MAIR(MAIR_HI_NORMAL_OWB_T_WA, MAIR_LO_NORMAL_IWB_RA)

/*
 * Normal Memory
 * Outer write-back, transient, write-allocate
 * Inner write-back, write-allocate
 */
#define	MAIR_NORMAL_OWB_T_WA_IWB_WA		\
	MAIR(MAIR_HI_NORMAL_OWB_T_WA, MAIR_LO_NORMAL_IWB_WA)

/*
 * Normal Memory
 * Outer write-back, transient, write-allocate
 * Inner write-back, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWB_T_WA_IWB_RA_WA		\
	MAIR(MAIR_HI_NORMAL_OWB_T_WA, MAIR_LO_NORMAL_IWB_RA_WA)

/*
 * Normal Memory
 * Outer write-back, transient, read-allocate, write-allocate
 * Inner uncached
 */
#define	MAIR_NORMAL_OWB_T_RA_WA_INC		\
	MAIR(MAIR_HI_NORMAL_OWB_T_RA_WA, MAIR_LO_NORMAL_INC)

/*
 * Normal Memory
 * Outer write-back, transient, read-allocate, write-allocate
 * Inner write-through, transient, read-allocate
 */
#define	MAIR_NORMAL_OWB_T_RA_WA_IWT_T_RA	\
	MAIR(MAIR_HI_NORMAL_OWB_T_RA_WA, MAIR_LO_NORMAL_IWT_T_RA)

/*
 * Normal Memory
 * Outer write-back, transient, read-allocate, write-allocate
 * Inner write-through, transient, write-allocate
 */
#define	MAIR_NORMAL_OWB_T_RA_WA_IWT_T_WA	\
	MAIR(MAIR_HI_NORMAL_OWB_T_RA_WA, MAIR_LO_NORMAL_IWT_T_WA)

/*
 * Normal Memory
 * Outer write-back, transient, read-allocate, write-allocate
 * Inner write-through, transient, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWB_T_RA_WA_IWT_T_RA_WA	\
	MAIR(MAIR_HI_NORMAL_OWB_T_RA_WA, MAIR_LO_NORMAL_IWT_T_RA_WA)

/*
 * Normal Memory
 * Outer write-back, transient, read-allocate, write-allocate
 * Inner write-back, transient, read-allocate
 */
#define	MAIR_NORMAL_OWB_T_RA_WA_IWB_T_RA	\
	MAIR(MAIR_HI_NORMAL_OWB_T_RA_WA, MAIR_LO_NORMAL_IWB_T_RA)

/*
 * Normal Memory
 * Outer write-back, transient, read-allocate, write-allocate
 * Inner write-back, transient, write-allocate
 */
#define	MAIR_NORMAL_OWB_T_RA_WA_IWB_T_WA	\
	MAIR(MAIR_HI_NORMAL_OWB_T_RA_WA, MAIR_LO_NORMAL_IWB_T_WA)

/*
 * Normal Memory
 * Outer write-back, transient, read-allocate, write-allocate
 * Inner write-back, transient, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWB_T_RA_WA_IWB_T_RA_WA	\
	MAIR(MAIR_HI_NORMAL_OWB_T_RA_WA, MAIR_LO_NORMAL_IWB_T_RA_WA)

/*
 * Normal Memory
 * Outer write-back, transient, read-allocate, write-allocate
 * Inner write-through
 */
#define	MAIR_NORMAL_OWB_T_RA_WA_IWT		\
	MAIR(MAIR_HI_NORMAL_OWB_T_RA_WA, MAIR_LO_NORMAL_IWT)

/*
 * Normal Memory
 * Outer write-back, transient, read-allocate, write-allocate
 * Inner write-through, read-allocate
 */
#define	MAIR_NORMAL_OWB_T_RA_WA_IWT_RA		\
	MAIR(MAIR_HI_NORMAL_OWB_T_RA_WA, MAIR_LO_NORMAL_IWT_RA)

/*
 * Normal Memory
 * Outer write-back, transient, read-allocate, write-allocate
 * Inner write-through, write-allocate
 */
#define	MAIR_NORMAL_OWB_T_RA_WA_IWT_WA		\
	MAIR(MAIR_HI_NORMAL_OWB_T_RA_WA, MAIR_LO_NORMAL_IWT_WA)

/*
 * Normal Memory
 * Outer write-back, transient, read-allocate, write-allocate
 * Inner write-through, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWB_T_RA_WA_IWT_RA_WA	\
	MAIR(MAIR_HI_NORMAL_OWB_T_RA_WA, MAIR_LO_NORMAL_IWT_RA_WA)

/*
 * Normal Memory
 * Outer write-back, transient, read-allocate, write-allocate
 * Inner write-back
 */
#define	MAIR_NORMAL_OWB_T_RA_WA_IWB		\
	MAIR(MAIR_HI_NORMAL_OWB_T_RA_WA, MAIR_LO_NORMAL_IWB)

/*
 * Normal Memory
 * Outer write-back, transient, read-allocate, write-allocate
 * Inner write-back, read-allocate
 */
#define	MAIR_NORMAL_OWB_T_RA_WA_IWB_RA		\
	MAIR(MAIR_HI_NORMAL_OWB_T_RA_WA, MAIR_LO_NORMAL_IWB_RA)

/*
 * Normal Memory
 * Outer write-back, transient, read-allocate, write-allocate
 * Inner write-back, write-allocate
 */
#define	MAIR_NORMAL_OWB_T_RA_WA_IWB_WA		\
	MAIR(MAIR_HI_NORMAL_OWB_T_RA_WA, MAIR_LO_NORMAL_IWB_WA)

/*
 * Normal Memory
 * Outer write-back, transient, read-allocate, write-allocate
 * Inner write-back, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWB_T_RA_WA_IWB_RA_WA	\
	MAIR(MAIR_HI_NORMAL_OWB_T_RA_WA, MAIR_LO_NORMAL_IWB_RA_WA)

/*
 * Normal Memory
 * Outer write-through
 * Inner uncached
 */
#define	MAIR_NORMAL_OWT_INC			\
	MAIR(MAIR_HI_NORMAL_OWT, MAIR_LO_NORMAL_INC)

/*
 * Normal Memory
 * Outer write-through
 * Inner write-through, transient, read-allocate
 */
#define	MAIR_NORMAL_OWT_IWT_T_RA		\
	MAIR(MAIR_HI_NORMAL_OWT, MAIR_LO_NORMAL_IWT_T_RA)

/*
 * Normal Memory
 * Outer write-through
 * Inner write-through, transient, write-allocate
 */
#define	MAIR_NORMAL_OWT_IWT_T_WA		\
	MAIR(MAIR_HI_NORMAL_OWT, MAIR_LO_NORMAL_IWT_T_WA)

/*
 * Normal Memory
 * Outer write-through
 * Inner write-through, transient, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWT_IWT_T_RA_WA		\
	MAIR(MAIR_HI_NORMAL_OWT, MAIR_LO_NORMAL_IWT_T_RA_WA)

/*
 * Normal Memory
 * Outer write-through
 * Inner write-back, transient, read-allocate
 */
#define	MAIR_NORMAL_OWT_IWB_T_RA		\
	MAIR(MAIR_HI_NORMAL_OWT, MAIR_LO_NORMAL_IWB_T_RA)

/*
 * Normal Memory
 * Outer write-through
 * Inner write-back, transient, write-allocate
 */
#define	MAIR_NORMAL_OWT_IWB_T_WA		\
	MAIR(MAIR_HI_NORMAL_OWT, MAIR_LO_NORMAL_IWB_T_WA)

/*
 * Normal Memory
 * Outer write-through
 * Inner write-back, transient, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWT_IWB_T_RA_WA		\
	MAIR(MAIR_HI_NORMAL_OWT, MAIR_LO_NORMAL_IWB_T_RA_WA)

/*
 * Normal Memory
 * Outer write-through
 * Inner write-through
 */
#define	MAIR_NORMAL_OWT_IWT			\
	MAIR(MAIR_HI_NORMAL_OWT, MAIR_LO_NORMAL_IWT)

/*
 * Normal Memory
 * Outer write-through
 * Inner write-through, read-allocate
 */
#define	MAIR_NORMAL_OWT_IWT_RA			\
	MAIR(MAIR_HI_NORMAL_OWT, MAIR_LO_NORMAL_IWT_RA)

/*
 * Normal Memory
 * Outer write-through
 * Inner write-through, write-allocate
 */
#define	MAIR_NORMAL_OWT_IWT_WA			\
	MAIR(MAIR_HI_NORMAL_OWT, MAIR_LO_NORMAL_IWT_WA)

/*
 * Normal Memory
 * Outer write-through
 * Inner write-through, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWT_IWT_RA_WA		\
	MAIR(MAIR_HI_NORMAL_OWT, MAIR_LO_NORMAL_IWT_RA_WA)

/*
 * Normal Memory
 * Outer write-through
 * Inner write-back
 */
#define	MAIR_NORMAL_OWT_IWB			\
	MAIR(MAIR_HI_NORMAL_OWT, MAIR_LO_NORMAL_IWB)

/*
 * Normal Memory
 * Outer write-through
 * Inner write-back, read-allocate
 */
#define	MAIR_NORMAL_OWT_IWB_RA			\
	MAIR(MAIR_HI_NORMAL_OWT, MAIR_LO_NORMAL_IWB_RA)

/*
 * Normal Memory
 * Outer write-through
 * Inner write-back, write-allocate
 */
#define	MAIR_NORMAL_OWT_IWB_WA			\
	MAIR(MAIR_HI_NORMAL_OWT, MAIR_LO_NORMAL_IWB_WA)

/*
 * Normal Memory
 * Outer write-through
 * Inner write-back, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWT_IWB_RA_WA		\
	MAIR(MAIR_HI_NORMAL_OWT, MAIR_LO_NORMAL_IWB_RA_WA)

/*
 * Normal Memory
 * Outer write-through, read-allocate
 * Inner uncached
 */
#define	MAIR_NORMAL_OWT_RA_INC			\
	MAIR(MAIR_HI_NORMAL_OWT_RA, MAIR_LO_NORMAL_INC)

/*
 * Normal Memory
 * Outer write-through, read-allocate
 * Inner write-through, transient, read-allocate
 */
#define	MAIR_NORMAL_OWT_RA_IWT_T_RA		\
	MAIR(MAIR_HI_NORMAL_OWT_RA, MAIR_LO_NORMAL_IWT_T_RA)

/*
 * Normal Memory
 * Outer write-through, read-allocate
 * Inner write-through, transient, write-allocate
 */
#define	MAIR_NORMAL_OWT_RA_IWT_T_WA		\
	MAIR(MAIR_HI_NORMAL_OWT_RA, MAIR_LO_NORMAL_IWT_T_WA)

/*
 * Normal Memory
 * Outer write-through, read-allocate
 * Inner write-through, transient, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWT_RA_IWT_T_RA_WA		\
	MAIR(MAIR_HI_NORMAL_OWT_RA, MAIR_LO_NORMAL_IWT_T_RA_WA)

/*
 * Normal Memory
 * Outer write-through, read-allocate
 * Inner write-back, transient, read-allocate
 */
#define	MAIR_NORMAL_OWT_RA_IWB_T_RA		\
	MAIR(MAIR_HI_NORMAL_OWT_RA, MAIR_LO_NORMAL_IWB_T_RA)

/*
 * Normal Memory
 * Outer write-through, read-allocate
 * Inner write-back, transient, write-allocate
 */
#define	MAIR_NORMAL_OWT_RA_IWB_T_WA		\
	MAIR(MAIR_HI_NORMAL_OWT_RA, MAIR_LO_NORMAL_IWB_T_WA)

/*
 * Normal Memory
 * Outer write-through, read-allocate
 * Inner write-back, transient, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWT_RA_IWB_T_RA_WA		\
	MAIR(MAIR_HI_NORMAL_OWT_RA, MAIR_LO_NORMAL_IWB_T_RA_WA)

/*
 * Normal Memory
 * Outer write-through, read-allocate
 * Inner write-through
 */
#define	MAIR_NORMAL_OWT_RA_IWT			\
	MAIR(MAIR_HI_NORMAL_OWT_RA, MAIR_LO_NORMAL_IWT)

/*
 * Normal Memory
 * Outer write-through, read-allocate
 * Inner write-through, read-allocate
 */
#define	MAIR_NORMAL_OWT_RA_IWT_RA		\
	MAIR(MAIR_HI_NORMAL_OWT_RA, MAIR_LO_NORMAL_IWT_RA)

/*
 * Normal Memory
 * Outer write-through, read-allocate
 * Inner write-through, write-allocate
 */
#define	MAIR_NORMAL_OWT_RA_IWT_WA		\
	MAIR(MAIR_HI_NORMAL_OWT_RA, MAIR_LO_NORMAL_IWT_WA)

/*
 * Normal Memory
 * Outer write-through, read-allocate
 * Inner write-through, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWT_RA_IWT_RA_WA		\
	MAIR(MAIR_HI_NORMAL_OWT_RA, MAIR_LO_NORMAL_IWT_RA_WA)

/*
 * Normal Memory
 * Outer write-through, read-allocate
 * Inner write-back
 */
#define	MAIR_NORMAL_OWT_RA_IWB			\
	MAIR(MAIR_HI_NORMAL_OWT_RA, MAIR_LO_NORMAL_IWB)

/*
 * Normal Memory
 * Outer write-through, read-allocate
 * Inner write-back, read-allocate
 */
#define	MAIR_NORMAL_OWT_RA_IWB_RA		\
	MAIR(MAIR_HI_NORMAL_OWT_RA, MAIR_LO_NORMAL_IWB_RA)

/*
 * Normal Memory
 * Outer write-through, read-allocate
 * Inner write-back, write-allocate
 */
#define	MAIR_NORMAL_OWT_RA_IWB_WA		\
	MAIR(MAIR_HI_NORMAL_OWT_RA, MAIR_LO_NORMAL_IWB_WA)

/*
 * Normal Memory
 * Outer write-through, read-allocate
 * Inner write-back, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWT_RA_IWB_RA_WA		\
	MAIR(MAIR_HI_NORMAL_OWT_RA, MAIR_LO_NORMAL_IWB_RA_WA)

/*
 * Normal Memory
 * Outer write-through, write-allocate
 * Inner uncached
 */
#define	MAIR_NORMAL_OWT_WA_INC			\
	MAIR(MAIR_HI_NORMAL_OWT_WA, MAIR_LO_NORMAL_INC)

/*
 * Normal Memory
 * Outer write-through, write-allocate
 * Inner write-through, transient, read-allocate
 */
#define	MAIR_NORMAL_OWT_WA_IWT_T_RA		\
	MAIR(MAIR_HI_NORMAL_OWT_WA, MAIR_LO_NORMAL_IWT_T_RA)

/*
 * Normal Memory
 * Outer write-through, write-allocate
 * Inner write-through, transient, write-allocate
 */
#define	MAIR_NORMAL_OWT_WA_IWT_T_WA		\
	MAIR(MAIR_HI_NORMAL_OWT_WA, MAIR_LO_NORMAL_IWT_T_WA)

/*
 * Normal Memory
 * Outer write-through, write-allocate
 * Inner write-through, transient, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWT_WA_IWT_T_RA_WA		\
	MAIR(MAIR_HI_NORMAL_OWT_WA, MAIR_LO_NORMAL_IWT_T_RA_WA)

/*
 * Normal Memory
 * Outer write-through, write-allocate
 * Inner write-back, transient, read-allocate
 */
#define	MAIR_NORMAL_OWT_WA_IWB_T_RA		\
	MAIR(MAIR_HI_NORMAL_OWT_WA, MAIR_LO_NORMAL_IWB_T_RA)

/*
 * Normal Memory
 * Outer write-through, write-allocate
 * Inner write-back, transient, write-allocate
 */
#define	MAIR_NORMAL_OWT_WA_IWB_T_WA		\
	MAIR(MAIR_HI_NORMAL_OWT_WA, MAIR_LO_NORMAL_IWB_T_WA)

/*
 * Normal Memory
 * Outer write-through, write-allocate
 * Inner write-back, transient, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWT_WA_IWB_T_RA_WA		\
	MAIR(MAIR_HI_NORMAL_OWT_WA, MAIR_LO_NORMAL_IWB_T_RA_WA)

/*
 * Normal Memory
 * Outer write-through, write-allocate
 * Inner write-through
 */
#define	MAIR_NORMAL_OWT_WA_IWT			\
	MAIR(MAIR_HI_NORMAL_OWT_WA, MAIR_LO_NORMAL_IWT)

/*
 * Normal Memory
 * Outer write-through, write-allocate
 * Inner write-through, read-allocate
 */
#define	MAIR_NORMAL_OWT_WA_IWT_RA		\
	MAIR(MAIR_HI_NORMAL_OWT_WA, MAIR_LO_NORMAL_IWT_RA)

/*
 * Normal Memory
 * Outer write-through, write-allocate
 * Inner write-through, write-allocate
 */
#define	MAIR_NORMAL_OWT_WA_IWT_WA		\
	MAIR(MAIR_HI_NORMAL_OWT_WA, MAIR_LO_NORMAL_IWT_WA)

/*
 * Normal Memory
 * Outer write-through, write-allocate
 * Inner write-through, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWT_WA_IWT_RA_WA		\
	MAIR(MAIR_HI_NORMAL_OWT_WA, MAIR_LO_NORMAL_IWT_RA_WA)

/*
 * Normal Memory
 * Outer write-through, write-allocate
 * Inner write-back
 */
#define	MAIR_NORMAL_OWT_WA_IWB			\
	MAIR(MAIR_HI_NORMAL_OWT_WA, MAIR_LO_NORMAL_IWB)

/*
 * Normal Memory
 * Outer write-through, write-allocate
 * Inner write-back, read-allocate
 */
#define	MAIR_NORMAL_OWT_WA_IWB_RA		\
	MAIR(MAIR_HI_NORMAL_OWT_WA, MAIR_LO_NORMAL_IWB_RA)

/*
 * Normal Memory
 * Outer write-through, write-allocate
 * Inner write-back, write-allocate
 */
#define	MAIR_NORMAL_OWT_WA_IWB_WA		\
	MAIR(MAIR_HI_NORMAL_OWT_WA, MAIR_LO_NORMAL_IWB_WA)

/*
 * Normal Memory
 * Outer write-through, write-allocate
 * Inner write-back, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWT_WA_IWB_RA_WA		\
	MAIR(MAIR_HI_NORMAL_OWT_WA, MAIR_LO_NORMAL_IWB_RA_WA)

/*
 * Normal Memory
 * Outer write-through, read-allocate, write-allocate
 * Inner uncached
 */
#define	MAIR_NORMAL_OWT_RA_WA_INC		\
	MAIR(MAIR_HI_NORMAL_OWT_RA_WA, MAIR_LO_NORMAL_INC)

/*
 * Normal Memory
 * Outer write-through, read-allocate, write-allocate
 * Inner write-through, transient, read-allocate
 */
#define	MAIR_NORMAL_OWT_RA_WA_IWT_T_RA		\
	MAIR(MAIR_HI_NORMAL_OWT_RA_WA, MAIR_LO_NORMAL_IWT_T_RA)

/*
 * Normal Memory
 * Outer write-through, read-allocate, write-allocate
 * Inner write-through, transient, write-allocate
 */
#define	MAIR_NORMAL_OWT_RA_WA_IWT_T_WA		\
	MAIR(MAIR_HI_NORMAL_OWT_RA_WA, MAIR_LO_NORMAL_IWT_T_WA)

/*
 * Normal Memory
 * Outer write-through, read-allocate, write-allocate
 * Inner write-through, transient, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWT_RA_WA_IWT_T_RA_WA	\
	MAIR(MAIR_HI_NORMAL_OWT_RA_WA, MAIR_LO_NORMAL_IWT_T_RA_WA)

/*
 * Normal Memory
 * Outer write-through, read-allocate, write-allocate
 * Inner write-back, transient, read-allocate
 */
#define	MAIR_NORMAL_OWT_RA_WA_IWB_T_RA		\
	MAIR(MAIR_HI_NORMAL_OWT_RA_WA, MAIR_LO_NORMAL_IWB_T_RA)

/*
 * Normal Memory
 * Outer write-through, read-allocate, write-allocate
 * Inner write-back, transient, write-allocate
 */
#define	MAIR_NORMAL_OWT_RA_WA_IWB_T_WA		\
	MAIR(MAIR_HI_NORMAL_OWT_RA_WA, MAIR_LO_NORMAL_IWB_T_WA)

/*
 * Normal Memory
 * Outer write-through, read-allocate, write-allocate
 * Inner write-back, transient, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWT_RA_WA_IWB_T_RA_WA	\
	MAIR(MAIR_HI_NORMAL_OWT_RA_WA, MAIR_LO_NORMAL_IWB_T_RA_WA)

/*
 * Normal Memory
 * Outer write-through, read-allocate, write-allocate
 * Inner write-through
 */
#define	MAIR_NORMAL_OWT_RA_WA_IWT		\
	MAIR(MAIR_HI_NORMAL_OWT_RA_WA, MAIR_LO_NORMAL_IWT)

/*
 * Normal Memory
 * Outer write-through, read-allocate, write-allocate
 * Inner write-through, read-allocate
 */
#define	MAIR_NORMAL_OWT_RA_WA_IWT_RA		\
	MAIR(MAIR_HI_NORMAL_OWT_RA_WA, MAIR_LO_NORMAL_IWT_RA)

/*
 * Normal Memory
 * Outer write-through, read-allocate, write-allocate
 * Inner write-through, write-allocate
 */
#define	MAIR_NORMAL_OWT_RA_WA_IWT_WA		\
	MAIR(MAIR_HI_NORMAL_OWT_RA_WA, MAIR_LO_NORMAL_IWT_WA)

/*
 * Normal Memory
 * Outer write-through, read-allocate, write-allocate
 * Inner write-through, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWT_RA_WA_IWT_RA_WA		\
	MAIR(MAIR_HI_NORMAL_OWT_RA_WA, MAIR_LO_NORMAL_IWT_RA_WA)

/*
 * Normal Memory
 * Outer write-through, read-allocate, write-allocate
 * Inner write-back
 */
#define	MAIR_NORMAL_OWT_RA_WA_IWB		\
	MAIR(MAIR_HI_NORMAL_OWT_RA_WA, MAIR_LO_NORMAL_IWB)

/*
 * Normal Memory
 * Outer write-through, read-allocate, write-allocate
 * Inner write-back, read-allocate
 */
#define	MAIR_NORMAL_OWT_RA_WA_IWB_RA		\
	MAIR(MAIR_HI_NORMAL_OWT_RA_WA, MAIR_LO_NORMAL_IWB_RA)

/*
 * Normal Memory
 * Outer write-through, read-allocate, write-allocate
 * Inner write-back, write-allocate
 */
#define	MAIR_NORMAL_OWT_RA_WA_IWB_WA		\
	MAIR(MAIR_HI_NORMAL_OWT_RA_WA, MAIR_LO_NORMAL_IWB_WA)

/*
 * Normal Memory
 * Outer write-through, read-allocate, write-allocate
 * Inner write-back, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWT_RA_WA_IWB_RA_WA		\
	MAIR(MAIR_HI_NORMAL_OWT_RA_WA, MAIR_LO_NORMAL_IWB_RA_WA)

/*
 * Normal Memory
 * Outer write-back
 * Inner uncached
 */
#define	MAIR_NORMAL_OWB_INC			\
	MAIR(MAIR_HI_NORMAL_OWB, MAIR_LO_NORMAL_INC)

/*
 * Normal Memory
 * Outer write-back
 * Inner write-through, transient, read-allocate
 */
#define	MAIR_NORMAL_OWB_IWT_T_RA		\
	MAIR(MAIR_HI_NORMAL_OWB, MAIR_LO_NORMAL_IWT_T_RA)

/*
 * Normal Memory
 * Outer write-back
 * Inner write-through, transient, write-allocate
 */
#define	MAIR_NORMAL_OWB_IWT_T_WA		\
	MAIR(MAIR_HI_NORMAL_OWB, MAIR_LO_NORMAL_IWT_T_WA)

/*
 * Normal Memory
 * Outer write-back
 * Inner write-through, transient, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWB_IWT_T_RA_WA		\
	MAIR(MAIR_HI_NORMAL_OWB, MAIR_LO_NORMAL_IWT_T_RA_WA)

/*
 * Normal Memory
 * Outer write-back
 * Inner write-back, transient, read-allocate
 */
#define	MAIR_NORMAL_OWB_IWB_T_RA		\
	MAIR(MAIR_HI_NORMAL_OWB, MAIR_LO_NORMAL_IWB_T_RA)

/*
 * Normal Memory
 * Outer write-back
 * Inner write-back, transient, write-allocate
 */
#define	MAIR_NORMAL_OWB_IWB_T_WA		\
	MAIR(MAIR_HI_NORMAL_OWB, MAIR_LO_NORMAL_IWB_T_WA)

/*
 * Normal Memory
 * Outer write-back
 * Inner write-back, transient, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWB_IWB_T_RA_WA		\
	MAIR(MAIR_HI_NORMAL_OWB, MAIR_LO_NORMAL_IWB_T_RA_WA)

/*
 * Normal Memory
 * Outer write-back
 * Inner write-through
 */
#define	MAIR_NORMAL_OWB_IWT			\
	MAIR(MAIR_HI_NORMAL_OWB, MAIR_LO_NORMAL_IWT)

/*
 * Normal Memory
 * Outer write-back
 * Inner write-through, read-allocate
 */
#define	MAIR_NORMAL_OWB_IWT_RA			\
	MAIR(MAIR_HI_NORMAL_OWB, MAIR_LO_NORMAL_IWT_RA)

/*
 * Normal Memory
 * Outer write-back
 * Inner write-through, write-allocate
 */
#define	MAIR_NORMAL_OWB_IWT_WA			\
	MAIR(MAIR_HI_NORMAL_OWB, MAIR_LO_NORMAL_IWT_WA)

/*
 * Normal Memory
 * Outer write-back
 * Inner write-through, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWB_IWT_RA_WA		\
	MAIR(MAIR_HI_NORMAL_OWB, MAIR_LO_NORMAL_IWT_RA_WA)

/*
 * Normal Memory
 * Outer write-back
 * Inner write-back
 */
#define	MAIR_NORMAL_OWB_IWB			\
	MAIR(MAIR_HI_NORMAL_OWB, MAIR_LO_NORMAL_IWB)

/*
 * Normal Memory
 * Outer write-back
 * Inner write-back, read-allocate
 */
#define	MAIR_NORMAL_OWB_IWB_RA			\
	MAIR(MAIR_HI_NORMAL_OWB, MAIR_LO_NORMAL_IWB_RA)

/*
 * Normal Memory
 * Outer write-back
 * Inner write-back, write-allocate
 */
#define	MAIR_NORMAL_OWB_IWB_WA			\
	MAIR(MAIR_HI_NORMAL_OWB, MAIR_LO_NORMAL_IWB_WA)

/*
 * Normal Memory
 * Outer write-back
 * Inner write-back, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWB_IWB_RA_WA		\
	MAIR(MAIR_HI_NORMAL_OWB, MAIR_LO_NORMAL_IWB_RA_WA)

/*
 * Normal Memory
 * Outer write-back, read-allocate
 * Inner uncached
 */
#define	MAIR_NORMAL_OWB_RA_INC			\
	MAIR(MAIR_HI_NORMAL_OWB_RA, MAIR_LO_NORMAL_INC)

/*
 * Normal Memory
 * Outer write-back, read-allocate
 * Inner write-through, transient, read-allocate
 */
#define	MAIR_NORMAL_OWB_RA_IWT_T_RA		\
	MAIR(MAIR_HI_NORMAL_OWB_RA, MAIR_LO_NORMAL_IWT_T_RA)

/*
 * Normal Memory
 * Outer write-back, read-allocate
 * Inner write-through, transient, write-allocate
 */
#define	MAIR_NORMAL_OWB_RA_IWT_T_WA		\
	MAIR(MAIR_HI_NORMAL_OWB_RA, MAIR_LO_NORMAL_IWT_T_WA)

/*
 * Normal Memory
 * Outer write-back, read-allocate
 * Inner write-through, transient, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWB_RA_IWT_T_RA_WA		\
	MAIR(MAIR_HI_NORMAL_OWB_RA, MAIR_LO_NORMAL_IWT_T_RA_WA)

/*
 * Normal Memory
 * Outer write-back, read-allocate
 * Inner write-back, transient, read-allocate
 */
#define	MAIR_NORMAL_OWB_RA_IWB_T_RA		\
	MAIR(MAIR_HI_NORMAL_OWB_RA, MAIR_LO_NORMAL_IWB_T_RA)

/*
 * Normal Memory
 * Outer write-back, read-allocate
 * Inner write-back, transient, write-allocate
 */
#define	MAIR_NORMAL_OWB_RA_IWB_T_WA		\
	MAIR(MAIR_HI_NORMAL_OWB_RA, MAIR_LO_NORMAL_IWB_T_WA)

/*
 * Normal Memory
 * Outer write-back, read-allocate
 * Inner write-back, transient, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWB_RA_IWB_T_RA_WA		\
	MAIR(MAIR_HI_NORMAL_OWB_RA, MAIR_LO_NORMAL_IWB_T_RA_WA)

/*
 * Normal Memory
 * Outer write-back, read-allocate
 * Inner write-through
 */
#define	MAIR_NORMAL_OWB_RA_IWT			\
	MAIR(MAIR_HI_NORMAL_OWB_RA, MAIR_LO_NORMAL_IWT)

/*
 * Normal Memory
 * Outer write-back, read-allocate
 * Inner write-through, read-allocate
 */
#define	MAIR_NORMAL_OWB_RA_IWT_RA		\
	MAIR(MAIR_HI_NORMAL_OWB_RA, MAIR_LO_NORMAL_IWT_RA)

/*
 * Normal Memory
 * Outer write-back, read-allocate
 * Inner write-through, write-allocate
 */
#define	MAIR_NORMAL_OWB_RA_IWT_WA		\
	MAIR(MAIR_HI_NORMAL_OWB_RA, MAIR_LO_NORMAL_IWT_WA)

/*
 * Normal Memory
 * Outer write-back, read-allocate
 * Inner write-through, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWB_RA_IWT_RA_WA		\
	MAIR(MAIR_HI_NORMAL_OWB_RA, MAIR_LO_NORMAL_IWT_RA_WA)

/*
 * Normal Memory
 * Outer write-back, read-allocate
 * Inner write-back
 */
#define	MAIR_NORMAL_OWB_RA_IWB			\
	MAIR(MAIR_HI_NORMAL_OWB_RA, MAIR_LO_NORMAL_IWB)

/*
 * Normal Memory
 * Outer write-back, read-allocate
 * Inner write-back, read-allocate
 */
#define	MAIR_NORMAL_OWB_RA_IWB_RA		\
	MAIR(MAIR_HI_NORMAL_OWB_RA, MAIR_LO_NORMAL_IWB_RA)

/*
 * Normal Memory
 * Outer write-back, read-allocate
 * Inner write-back, write-allocate
 */
#define	MAIR_NORMAL_OWB_RA_IWB_WA		\
	MAIR(MAIR_HI_NORMAL_OWB_RA, MAIR_LO_NORMAL_IWB_WA)

/*
 * Normal Memory
 * Outer write-back, read-allocate
 * Inner write-back, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWB_RA_IWB_RA_WA		\
	MAIR(MAIR_HI_NORMAL_OWB_RA, MAIR_LO_NORMAL_IWB_RA_WA)

/*
 * Normal Memory
 * Outer write-back, write-allocate
 * Inner uncached
 */
#define	MAIR_NORMAL_OWB_WA_INC			\
	MAIR(MAIR_HI_NORMAL_OWB_WA, MAIR_LO_NORMAL_INC)

/*
 * Normal Memory
 * Outer write-back, write-allocate
 * Inner write-through, transient, read-allocate
 */
#define	MAIR_NORMAL_OWB_WA_IWT_T_RA		\
	MAIR(MAIR_HI_NORMAL_OWB_WA, MAIR_LO_NORMAL_IWT_T_RA)

/*
 * Normal Memory
 * Outer write-back, write-allocate
 * Inner write-through, transient, write-allocate
 */
#define	MAIR_NORMAL_OWB_WA_IWT_T_WA		\
	MAIR(MAIR_HI_NORMAL_OWB_WA, MAIR_LO_NORMAL_IWT_T_WA)

/*
 * Normal Memory
 * Outer write-back, write-allocate
 * Inner write-through, transient, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWB_WA_IWT_T_RA_WA		\
	MAIR(MAIR_HI_NORMAL_OWB_WA, MAIR_LO_NORMAL_IWT_T_RA_WA)

/*
 * Normal Memory
 * Outer write-back, write-allocate
 * Inner write-back, transient, read-allocate
 */
#define	MAIR_NORMAL_OWB_WA_IWB_T_RA		\
	MAIR(MAIR_HI_NORMAL_OWB_WA, MAIR_LO_NORMAL_IWB_T_RA)

/*
 * Normal Memory
 * Outer write-back, write-allocate
 * Inner write-back, transient, write-allocate
 */
#define	MAIR_NORMAL_OWB_WA_IWB_T_WA		\
	MAIR(MAIR_HI_NORMAL_OWB_WA, MAIR_LO_NORMAL_IWB_T_WA)

/*
 * Normal Memory
 * Outer write-back, write-allocate
 * Inner write-back, transient, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWB_WA_IWB_T_RA_WA		\
	MAIR(MAIR_HI_NORMAL_OWB_WA, MAIR_LO_NORMAL_IWB_T_RA_WA)

/*
 * Normal Memory
 * Outer write-back, write-allocate
 * Inner write-through
 */
#define	MAIR_NORMAL_OWB_WA_IWT			\
	MAIR(MAIR_HI_NORMAL_OWB_WA, MAIR_LO_NORMAL_IWT)

/*
 * Normal Memory
 * Outer write-back, write-allocate
 * Inner write-through, read-allocate
 */
#define	MAIR_NORMAL_OWB_WA_IWT_RA		\
	MAIR(MAIR_HI_NORMAL_OWB_WA, MAIR_LO_NORMAL_IWT_RA)

/*
 * Normal Memory
 * Outer write-back, write-allocate
 * Inner write-through, write-allocate
 */
#define	MAIR_NORMAL_OWB_WA_IWT_WA		\
	MAIR(MAIR_HI_NORMAL_OWB_WA, MAIR_LO_NORMAL_IWT_WA)

/*
 * Normal Memory
 * Outer write-back, write-allocate
 * Inner write-through, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWB_WA_IWT_RA_WA		\
	MAIR(MAIR_HI_NORMAL_OWB_WA, MAIR_LO_NORMAL_IWT_RA_WA)

/*
 * Normal Memory
 * Outer write-back, write-allocate
 * Inner write-back
 */
#define	MAIR_NORMAL_OWB_WA_IWB			\
	MAIR(MAIR_HI_NORMAL_OWB_WA, MAIR_LO_NORMAL_IWB)

/*
 * Normal Memory
 * Outer write-back, write-allocate
 * Inner write-back, read-allocate
 */
#define	MAIR_NORMAL_OWB_WA_IWB_RA		\
	MAIR(MAIR_HI_NORMAL_OWB_WA, MAIR_LO_NORMAL_IWB_RA)

/*
 * Normal Memory
 * Outer write-back, write-allocate
 * Inner write-back, write-allocate
 */
#define	MAIR_NORMAL_OWB_WA_IWB_WA		\
	MAIR(MAIR_HI_NORMAL_OWB_WA, MAIR_LO_NORMAL_IWB_WA)

/*
 * Normal Memory
 * Outer write-back, write-allocate
 * Inner write-back, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWB_WA_IWB_RA_WA		\
	MAIR(MAIR_HI_NORMAL_OWB_WA, MAIR_LO_NORMAL_IWB_RA_WA)

/*
 * Normal Memory
 * Outer write-back, read-allocate, write-allocate
 * Inner uncached
 */
#define	MAIR_NORMAL_OWB_RA_WA_INC		\
	MAIR(MAIR_HI_NORMAL_OWB_RA_WA, MAIR_LO_NORMAL_INC)

/*
 * Normal Memory
 * Outer write-back, read-allocate, write-allocate
 * Inner write-through, transient, read-allocate
 */
#define	MAIR_NORMAL_OWB_RA_WA_IWT_T_RA		\
	MAIR(MAIR_HI_NORMAL_OWB_RA_WA, MAIR_LO_NORMAL_IWT_T_RA)

/*
 * Normal Memory
 * Outer write-back, read-allocate, write-allocate
 * Inner write-through, transient, write-allocate
 */
#define	MAIR_NORMAL_OWB_RA_WA_IWT_T_WA		\
	MAIR(MAIR_HI_NORMAL_OWB_RA_WA, MAIR_LO_NORMAL_IWT_T_WA)

/*
 * Normal Memory
 * Outer write-back, read-allocate, write-allocate
 * Inner write-through, transient, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWB_RA_WA_IWT_T_RA_WA	\
	MAIR(MAIR_HI_NORMAL_OWB_RA_WA, MAIR_LO_NORMAL_IWT_T_RA_WA)

/*
 * Normal Memory
 * Outer write-back, read-allocate, write-allocate
 * Inner write-back, transient, read-allocate
 */
#define	MAIR_NORMAL_OWB_RA_WA_IWB_T_RA		\
	MAIR(MAIR_HI_NORMAL_OWB_RA_WA, MAIR_LO_NORMAL_IWB_T_RA)

/*
 * Normal Memory
 * Outer write-back, read-allocate, write-allocate
 * Inner write-back, transient, write-allocate
 */
#define	MAIR_NORMAL_OWB_RA_WA_IWB_T_WA		\
	MAIR(MAIR_HI_NORMAL_OWB_RA_WA, MAIR_LO_NORMAL_IWB_T_WA)

/*
 * Normal Memory
 * Outer write-back, read-allocate, write-allocate
 * Inner write-back, transient, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWB_RA_WA_IWB_T_RA_WA	\
	MAIR(MAIR_HI_NORMAL_OWB_RA_WA, MAIR_LO_NORMAL_IWB_T_RA_WA)

/*
 * Normal Memory
 * Outer write-back, read-allocate, write-allocate
 * Inner write-through
 */
#define	MAIR_NORMAL_OWB_RA_WA_IWT		\
	MAIR(MAIR_HI_NORMAL_OWB_RA_WA, MAIR_LO_NORMAL_IWT)

/*
 * Normal Memory
 * Outer write-back, read-allocate, write-allocate
 * Inner write-through, read-allocate
 */
#define	MAIR_NORMAL_OWB_RA_WA_IWT_RA		\
	MAIR(MAIR_HI_NORMAL_OWB_RA_WA, MAIR_LO_NORMAL_IWT_RA)

/*
 * Normal Memory
 * Outer write-back, read-allocate, write-allocate
 * Inner write-through, write-allocate
 */
#define	MAIR_NORMAL_OWB_RA_WA_IWT_WA		\
	MAIR(MAIR_HI_NORMAL_OWB_RA_WA, MAIR_LO_NORMAL_IWT_WA)

/*
 * Normal Memory
 * Outer write-back, read-allocate, write-allocate
 * Inner write-through, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWB_RA_WA_IWT_RA_WA		\
	MAIR(MAIR_HI_NORMAL_OWB_RA_WA, MAIR_LO_NORMAL_IWT_RA_WA)

/*
 * Normal Memory
 * Outer write-back, read-allocate, write-allocate
 * Inner write-back
 */
#define	MAIR_NORMAL_OWB_RA_WA_IWB		\
	MAIR(MAIR_HI_NORMAL_OWB_RA_WA, MAIR_LO_NORMAL_IWB)

/*
 * Normal Memory
 * Outer write-back, read-allocate, write-allocate
 * Inner write-back, read-allocate
 */
#define	MAIR_NORMAL_OWB_RA_WA_IWB_RA		\
	MAIR(MAIR_HI_NORMAL_OWB_RA_WA, MAIR_LO_NORMAL_IWB_RA)

/*
 * Normal Memory
 * Outer write-back, read-allocate, write-allocate
 * Inner write-back, write-allocate
 */
#define	MAIR_NORMAL_OWB_RA_WA_IWB_WA		\
	MAIR(MAIR_HI_NORMAL_OWB_RA_WA, MAIR_LO_NORMAL_IWB_WA)

/*
 * Normal Memory
 * Outer write-back, read-allocate, write-allocate
 * Inner write-back, read-allocate, write-allocate
 */
#define	MAIR_NORMAL_OWB_RA_WA_IWB_RA_WA		\
	MAIR(MAIR_HI_NORMAL_OWB_RA_WA, MAIR_LO_NORMAL_IWB_RA_WA)

#if 0
#if !defined(_ASM)
#undef MAIR_HI_SHIFT
#undef MAIR

#undef MAIR_HI_NORMAL_ONC
#undef MAIR_HI_NORMAL_OWT_T_RA
#undef MAIR_HI_NORMAL_OWT_T_WA
#undef MAIR_HI_NORMAL_OWT_T_RA_WA
#undef MAIR_HI_NORMAL_OWB_T_RA
#undef MAIR_HI_NORMAL_OWB_T_WA
#undef MAIR_HI_NORMAL_OWB_T_RA_WA
#undef MAIR_HI_NORMAL_OWT
#undef MAIR_HI_NORMAL_OWT_RA
#undef MAIR_HI_NORMAL_OWT_WA
#undef MAIR_HI_NORMAL_OWT_RA_WA
#undef MAIR_HI_NORMAL_OWB
#undef MAIR_HI_NORMAL_OWB_RA
#undef MAIR_HI_NORMAL_OWB_WA
#undef MAIR_HI_NORMAL_OWB_RA_WA

#undef MAIR_LO_NORMAL_INC
#undef MAIR_LO_NORMAL_IWT_T_RA
#undef MAIR_LO_NORMAL_IWT_T_WA
#undef MAIR_LO_NORMAL_IWT_T_RA_WA
#undef MAIR_LO_NORMAL_IWB_T_RA
#undef MAIR_LO_NORMAL_IWB_T_WA
#undef MAIR_LO_NORMAL_IWB_T_RA_WA
#undef MAIR_LO_NORMAL_IWT
#undef MAIR_LO_NORMAL_IWT_RA
#undef MAIR_LO_NORMAL_IWT_WA
#undef MAIR_LO_NORMAL_IWT_RA_WA
#undef MAIR_LO_NORMAL_IWB
#undef MAIR_LO_NORMAL_IWB_RA
#undef MAIR_LO_NORMAL_IWB_WA
#undef MAIR_LO_NORMAL_IWB_RA_WA

#undef MAIR_WRITE_ALLOCATE_SHIFT
#undef MAIR_READ_ALLOCATE_SHIFT
#undef MAIR_NO_ALLOCATE
#undef MAIR_ALLOCATE
#endif	/* !_ASM */
#endif

#ifdef __cplusplus
}
#endif

#endif	/* _ARMV8_MAIR_H */
