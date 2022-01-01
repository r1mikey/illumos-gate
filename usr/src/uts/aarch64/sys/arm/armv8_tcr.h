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

#ifndef _ARMV8_TCR_H
#define	_ARMV8_TCR_H

/*
 * Provides building blocks for the Translation Control Block in ARMv8-A.
 *
 * See DDI0487G (B), ARMv8 Architechture Reference Manual
 * D13.2.123: TCR_EL1, Translation Control Register (EL1)
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 63:60	RES0
 * 59		DS
 * 58		TCMA1
 * 57		TCMA0
 * 56		E0PD1
 * 55		E0PD0
 * 54		NFD1
 * 53		NFD0
 * 52		TBID1
 * 51		TBID0
 * 50		HWU162
 * 49		HWU161
 * 48		HWU160
 * 47		HWU159
 * 46		HWU062
 * 45		HWU061
 * 44		HWU060
 * 43		HWU059
 * 42		HPD1
 * 41		HPD0
 * 40		HD
 * 39		HA
 * 38		TBI1
 * 37		TBI0
 * 36		AS
 * 35		RES0
 * 34:32	IPS 
 * 31:30	TG1
 * 29:28	SH1
 * 27:26	ORGN1
 * 25:24	IRGN1
 * 23		EPD1
 * 22		A1
 * 21:16	T1SZ
 * 15:14	TG0
 * 13:12	SH0
 * 11:10	ORGN0
 * 9:8		IRGN0
 * 7		EPD0
 * 6		RES0
 * 5:0		T0SZ
 */
#define	TCR_RES0_MASK	0xf000000800000040ULL
/* 63:60: RES0 */

#define	TCR_DS_MASK	0x01ULL
#define	TCR_DS_SHIFT	59
#define	TCR_DS(X)	(((X) & (TCR_DS_MASK)) << (TCR_DS_SHIFT))

#define	TCR_TCMA1_MASK	0x01ULL
#define	TCR_TCMA1_SHIFT	58
#define	TCR_TCMA1(X)	(((X) & (TCR_TCMA1_MASK)) << (TCR_TCMA1_SHIFT))

#define	TCR_TCMA0	(0x01ULL << 57)
#define	TCR_E0PD1	(0x01ULL << 56)
#define	TCR_E0PD0	(0x01ULL << 55)
#define	TCR_NFD1	(0x01ULL << 54)
#define	TCR_NFD0	(0x01ULL << 53)
#define	TCR_TBID1	(0x01ULL << 52)
#define	TCR_TBID0	(0x01ULL << 51)
#define	TCR_HWU162	(0x01ULL << 50)
#define	TCR_HWU161	(0x01ULL << 49)
#define	TCR_HWU160	(0x01ULL << 48)
#define	TCR_HWU159	(0x01ULL << 47)
#define	TCR_HWU062	(0x01ULL << 46)
#define	TCR_HWU061	(0x01ULL << 45)
#define	TCR_HWU060	(0x01ULL << 44)
#define	TCR_HWU059	(0x01ULL << 43)
#define	TCR_HPD1	(0x01ULL << 42)
#define	TCR_HPD0	(0x01ULL << 41)
#define	TCR_HD		(0x01ULL << 40)
#define	TCR_HA		(0x01ULL << 39)
#define	TCR_TBI1	(0x01ULL << 38)
#define	TCR_TBI0	(0x01ULL << 37)
#define	TCR_AS		(0x01ULL << 36)
/* 35: RES0 */
#define	TCR_IPS		(0x07ULL << 32)
#define	TCR_TG1		(0x03ULL << 30)
#define	TCR_SH1		(0x03ULL << 28)
#define	TCR_ORGN1	(0x03ULL << 26)
#define	TCR_IRGN1	(0x03ULL << 24)
#define	TCR_EPD1	(0x01ULL << 23)
#define	TCR_A1		(0x01ULL << 22)
#define	TCR_T1SZ	(0x3fULL << 16)
#define	TCR_TG0		(0x03ULL << 14)
#define	TCR_SH0		(0x03ULL << 12)
#define	TCR_ORGN0	(0x03ULL << 10)
#define	TCR_IRGN0	(0x03ULL <<  8)
#define	TCR_EPD0	(0x01ULL <<  7)
/* 6: RES0 */
#define	TCR_T0SZ	(0x3fULL <<  0)

#ifdef __cplusplus
}
#endif

#endif /* _ARMV8_TCR_H */
