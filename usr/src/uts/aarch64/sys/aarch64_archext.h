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

#ifndef _SYS_AARCH64_ARCHEXT_H
#define	_SYS_AARCH64_ARCHEXT_H

/*
 * CPU and hardware identification data
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This list is sorted by extension and by the armv8 revision that a feature
 * was introduced or backported.  This is similar in principle to how
 * capabilities work for userspace, but this list is significantly more
 * fine-grained (for now anyway).  The capabilities list will map roughly to
 * what the compiler can generate code for.
 *
 * Some features were backported to previous architecture revisions from later
 * revisions.  These have been placed in the later architecture revision.
 *
 * As you can see, this makes the definition of "this is an armv8.x" revision
 * platform quite vague: it's really the presence of all mandatory
 * functionality for that platform - including instruction set features,
 * debug features, processor features and memory model features.
 */

/*
 * See DDI0487A_a_armv8_arm.pdf for the original armv8-a specification.
 */
/*
 * From ID_AA64DFR0_EL1
 *
 * CTX_CMPs: Number of breakpoints that are context-aware, minus 1. These are
 * the highest numbered breakpoints.
 *
 * WRPs: Number of watchpoints, minus 1. The value of 0b0000 is reserved.
 *
 * BRPs: Number of breakpoints, minus 1. The value of 0b0000 is reserved.
 *
 * PMUVer: This is PMUv3
 *
 * TraceVer: Indicates whether trace extension system registers are implemented
 *
 * DebugVer: Fixed at 0110 for v8-A debug architecture.
 */
#define	FEAT_PMUv3			0		/* DONE */
#define	FEAT_TRACE			1		/* DONE */
#define	FEAT_DEBUGv8			2		/* DONE */

/*
 * From ID_AA64ISAR0_EL1
 *
 * CRC32
 * SHA2
 * SHA1
 * AES
 */
#define	FEAT_CRC32			3		/* DONE */

/*
 * The armv8 cryptographic extension
 */
#define	FEAT_SHA256			4		/* DONE */
#define	FEAT_SHA1			5		/* DONE */
#define	FEAT_AES			6		/* DONE */
#define	FEAT_PMULL			7		/* DONE */

/*
 * From ID_AA64MMFR0_EL1
 * These belong to the MMU side of the world
 *
 * TGran4
 * TGran64
 * TGran16
 * BigEndEL0
 * SNSMem
 * BigEnd
 * ASIDBits
 * PARange
 */

/*
 * From ID_AA64PFR0_EL1
 *
 * GIC
 * AdvSIMD
 * FP
 * EL3 - do we need to know? no
 * EL2 - do we need to know? no
 * EL1 - do we need to know? we're always aarch64, so no
 * EL0 - do we need to know? we're always aarch64, so no
 */
#define	FEAT_GICv3			8		/* DONE */
#define	FEAT_AdvSIMD			9		/* DONE */
#define	FEAT_FP				10		/* DONE */

/* XXX: bump this and move it down as I wade further into this complexity */
#define	NUM_AARCH64_FEATURES		11

#if 0
/*
 * See See DDI0487B_a_armv8_arm.pdf for the original armv8.1-a specification.
 * This document is a bit messy, as it contains beta information for armv8.2,
 * so careful reading is required.
 */
#define	FEAT_PMUv3p1			118
#define	FEAT_DEBUGv8p1			42		/* DONE */
#define	FEAT_RDM			125
#define	FEAT_LSE			89

/* pfr0 */
#define	FEAT_RAS			123

/*
 * See <first 8.2-a spec>
 */

/*
 * See <first 8.3-a spec>
 */

/*
 * See <first 8.4-a spec>
 */

/*
 * See <first 8.5-a spec>
 */

/*
 * See <first 8.6-a spec>
 */

/*
 * See <first 8.7-a spec>
 */

/*
 * See <first 8.8-a spec>
 */

/*
 * Optional functionality in the Armv8 architecture
 */

/*
 * Features added to Armv8.0 in later releases
 */
#define	FEAT_SB				131
#define	FEAT_SSBS			145
#define	FEAT_SSBS2			146
#define	FEAT_CSV2			19
#define	FEAT_CSV2_2			20
#define	FEAT_CSV2_1p1			21
#define	FEAT_CSV2_1p2			22
#define	FEAT_CSV3			23
#define	FEAT_SPECRES			141
#define	FEAT_CP15SDISABLE2		17		/* only when EL3 is aarch32 */
#define	FEAT_DoubleLock			33
#define	FEAT_DGH			28
#define	FEAT_ETS			48
#define	FEAT_nTLBPA			102
#define	FEAT_PCSRv8			113

/*
 * The Armv8 Cryptographic Extension
 */

/*
 * The Armv8.1 architecture extension
 * Architectural features added by Armv8.1
 */
#define	FEAT_LOR			81
#define	FEAT_HPDS			73
#define	FEAT_HAFDBS			70
#define	FEAT_PAN			108
#define	FEAT_VMID16			166
#define	FEAT_VHE			165

/*
 * Features added to the Armv8.1 extension in later releases
 */

/*
 * The Armv8.2 architecture extension
 * Architectural features added by Armv8.2
 */
#define	FEAT_ASMv8p2			-1
#define	FEAT_PAN2			109
#define	FEAT_FP16			59		/* DONE */
#define	FEAT_DotProd			-1
#define	FEAT_FHM			55
#define	FEAT_LSMAOC			91		/* AArch32 Load/Store Multiple instruction atomicity and ordering controls */
#define	FEAT_UAO			164
#define	FEAT_DPB			34
#define	FEAT_VPIPT			167
#define	FEAT_AA32HPD			1		/* delete this */
#define	FEAT_HPDS2			74
#define	FEAT_LPA			82
#define	FEAT_LVA			92
#define	FEAT_TTCNP			160
#define	FEAT_XNX			170
#define	FEAT_Debugv8p2			25
#define	FEAT_PCSRv8p2			114
#define	FEAT_IESB			78

/* XXX where is PMUv3?, where is FEAT_Debugv8p1? */

/*
 * Armv8.2 extensions to the Cryptographic Extension
 */
#define	FEAT_SHA512			136		/* DONE */
#define	FEAT_SHA3			135		/* DONE */
#define	FEAT_SM3			137		/* DONE */
#define	FEAT_SM4			138		/* DONE */

/*
 * Features added to the Armv8.2 extension in later releases
 */
#define	FEAT_EVT			49
#define	FEAT_DPB2			35
#define	FEAT_BF16			9
#define	FEAT_AA32BF16			0		/* delete this */
#define	FEAT_I8MM			76
#define	FEAT_AA32I8MM			2		/* delete this */

/*
 * The Armv8.3 architecture extension
 * Architectural features added by Armv8.3
 */
#define	FEAT_FCMA			53
#define	FEAT_JSCVT			80
#define	FEAT_LRCPC			84
#define	FEAT_NV				103
#define	FEAT_CCIDX			13
#define	FEAT_PAuth			111

/*
 * Additional requirements of Armv8.3
 * If FEAT_PMUv3 is implemented, FEAT_PMUv3p4 is OPTIONAL in Armv8.3 implementations.
 */

/*
 * Features added to the Armv8.3 extension in later releases
 */
#define	FEAT_SPEv1p1			142
#define	FEAT_DoPD			30
#define	FEAT_PAuth2			112
#define	FEAT_FPAC			60

/*
 * The Armv8.4 architecture extension
 * Architectural features added by Armv8.4
 */
#define	FEAT_DIT			29
#define	FEAT_FlagM			56
#define	FEAT_LRCPC2			85
#define	FEAT_LSE2			90
#define	FEAT_TLBIOS			155
#define	FEAT_TLBIRANGE			156
#define	FEAT_TTL			161
#define	FEAT_S2FWB			130
#define	FEAT_TTST			162
#define	FEAT_BBM			8
#define	FEAT_SEL2			132
#define	FEAT_NV2			104
#define	FEAT_IDST			77
#define	FEAT_CNTSC			15
#define	FEAT_Debugv8p4			26
#define	FEAT_TRF			159
#define	FEAT_PMUv3p4			119
#define	FEAT_RASv1p1			124
#define	FEAT_DoubleFault		32

/*
 * The existing functionality of OS Double Lock is added as a feature mnemonic in Armv8.0
 */

/*
 * The Armv8.5 architecture extension
 * Architectural features added by Armv8.5
 */
#define	FEAT_FlagM2			57
#define	FEAT_FRINTTS			62
#define	FEAT_ExS			50
#define	FEAT_GTG			69
#define	FEAT_BTI			12
#define	FEAT_E0PD			36
#define	FEAT_RNG			127
#define	FEAT_MTE			97
#define	FEAT_MTE2			98
#define	FEAT_PMUv3p5			120

/*
 * The Armv8.6 architecture extension
 * Architectural features added by Armv8.6
 */
#define	FEAT_ECV			37
#define	FEAT_FGT			54
#define	FEAT_TWED			163
#define	FEAT_AMUv1p1			7
#define	FEAT_MTPMU			100

/*
 * The Armv8.7 architecture extension
 * Architectural features added by Armv8.7
 */
#define	FEAT_AFP			5
#define	FEAT_RPRES			129
#define	FEAT_LS64			86
#define	FEAT_LS64_V			88
#define	FEAT_LS64_ACCDATA		87
#define	FEAT_WFxT			168
#define	FEAT_WFxT2			169
#define	FEAT_HCX			72
#define	FEAT_LPA2			83
#define	FEAT_XS				171
#define	FEAT_PMUv3p7			121
#define	FEAT_SPEv1p2			143
#define	FEAT_PAN3			110
#define	FEAT_MTE3			99


#define	FEAT_AMUv1			6
#define	FEAT_BRBE			10
#define	FEAT_BRBEv1p1			11
#define	FEAT_CMOW			14
#define	FEAT_CONSTPACFIELD		16
#define	FEAT_Debugv8p1			24
#define	FEAT_Debugv8p8			27
#define	FEAT_DotProd2			31
#define	FEAT_EPAC			38
#define	FEAT_ETE			39
#define	FEAT_ETEv1p1			40
#define	FEAT_ETMv4			41
#define	FEAT_ETMv4p1			42
#define	FEAT_ETMv4p2			43
#define	FEAT_ETMv4p3			44
#define	FEAT_ETMv4p4			45
#define	FEAT_ETMv4p5			46
#define	FEAT_ETMv4p6			47
#define	FEAT_F32MM			51
#define	FEAT_F64MM			52
#define	FEAT_FPACCOMBINE		61
#define	FEAT_GICv3_NMI			64
#define	FEAT_GICv3_TDIR			65
#define	FEAT_GICv3p1			66
#define	FEAT_GICv4			67
#define	FEAT_GICv4p1			68
#define	FEAT_HBC			71
#define	FEAT_HPMN0			75
#define	FEAT_IVIPT			79
#define	FEAT_MOPS			93
#define	FEAT_MPAM			94
#define	FEAT_MPAMv0p1			95
#define	FEAT_MPAMv1p1			96
#define	FEAT_NMI			101
#define	FEAT_PACIMP			105
#define	FEAT_PACQARMA3			106
#define	FEAT_PACQARMA5			107
#define	FEAT_PMUv3_TH			117
#define	FEAT_PMUv3p8			122
#define	FEAT_RME			126
#define	FEAT_RNG_TRAP			128
#define	FEAT_SME			139
#define	FEAT_SPE			140
#define	FEAT_SPEv1p3			144
#define	FEAT_SVE			147
#define	FEAT_SVE_AES			148
#define	FEAT_SVE_BitPerm		149
#define	FEAT_SVE_PMULL128		150
#define	FEAT_SVE_SHA3			151
#define	FEAT_SVE_SM4			152
#define	FEAT_SVE2			153
#define	FEAT_TIDCP1			154
#define	FEAT_TME			157
#define	FEAT_TRBE			158

#endif

#if 0
/*
 * Architectural features within Armv8.0 architecture
 * Features added to Armv8.0 in later releases
 * FEAT_SB, Speculation Barrier
 * FEAT_SSBS, FEAT_SBSS2, Speculative Store Bypass Safe
 * FEAT_CSV2 and FEAT_CSV2_2, Cache Speculation Variant 2
 * FEAT_CSV2_1p1 and FEAT_CSV2_1p2, Cache Speculation Variant 2
 * FEAT_CSV3, Cache Speculation Variant 3
 * FEAT_SPECRES, Speculation restriction instructions
 * FEAT_CP15SDISABLE2, CP15SDISABLE2
 * FEAT_DoubleLock, Double Lock
 * FEAT_DGH, Data Gathering Hint
 * FEAT_ETS, Enhanced Translation Synchronization
 * FEAT_nTLBPA, Intermediate caching of translation table walks
 * FEAT_PCSRv8, PC Sample-based Profiling Extension
 *
 * ^^ these should all be recorded where they belong
 */

/*
 * The Armv8.1 architecture extension
 * Architectural features added by Armv8.1
 * FEAT_LSE, Large System Extensions
 * FEAT_RDM, Advanced SIMD rounding double multiply accumulate instructions
 * FEAT_LOR, Limited ordering regions
 * FEAT_HPDS, Hierarchical permission disables
 * FEAT_HAFDBS, Hardware management of the Access flag and dirty state
 * FEAT_PAN, Privileged access never
 * FEAT_VMID16, 16-bit VMID
 * FEAT_VHE, Virtualization Host Extensions
 * FEAT_PMUv3p1, PMU Extensions v3.1
 *
 * Armv8.1 is required to implement the CRC32 instructions
 * See ID_AA64ISAR0_EL1.CRC32, ID_ISAR5_EL1.CRC32, ID_ISAR5.CRC32
 *
 * Features added to Armv8.1 in later releases
 * FEAT_PAN3, Support for SCTLR_ELx.EPAN
 *
 * Features made OPTIONAL in Armv8.1
 * FEAT_PAN2
 */

/*
 * Armv8.2
 * FEAT_ASMv8p2, Armv8.2 changes to the A64 ISA
 * FEAT_PAN2, AT S1E1R and AT S1E1W instruction variants affected by PSTATE.PAN
 * FEAT_FP16, Half-precision floating-point data processing
 * FEAT_DotProd, Advanced SIMD dot product instructions
 * FEAT_FHM, Floating-point half-precision multiplication instructions
 * FEAT_LSMAOC, AArch32 Load/Store Multiple instruction atomicity and ordering controls
 * FEAT_UAO, Unprivileged Access Override control
 * FEAT_DPB, DC CVAP instruction
 * FEAT_VPIPT, VMID-aware PIPT instruction cache
 * FEAT_AA32HPD, AArch32 hierarchical permission disables
 * FEAT_HPDS2, Translation table page-based hardware attributes
 * FEAT_LPA, Large PA and IPA support
 * FEAT_LVA, Large VA support
 * FEAT_TTCNP, Translation table Common not private translations
 * FEAT_XNX, Translation table stage 2 Unprivileged Execute-never
 * FEAT_Debugv8p2, Debug v8.2
 * FEAT_PCSRv8p2, PC Sample-based profiling
 * FEAT_IESB, Implicit Error Synchronization event
 * (RAS must be implemented)
 * (FEAT_PMUv3 is implemented, the feature FEAT_PMUv3p4)
 *
 * Features added to Armv8.2 in later releases
 * FEAT_EVT, Enhanced Virtualization Traps
 * FEAT_DPB2, DC CVADP instruction
 * FEAT_BF16, AArch64 BFloat16 instructions
 * FEAT_AA32BF16, AArch32 BFloat16 instructions
 * FEAT_I8MM, AArch64 Int8 matrix multiplication instructions
 * FEAT_AA32I8MM, AArch32 Int8 matrix multiplication instructions
 *
 * Features made OPTIONAL in Armv8.2 implementations
 * FEAT_FlagM on page A2-91.
 * FEAT_LSE2 on page A2-91.
 * FEAT_LRCPC2 on page A2-91.
 *
 * The Armv8.3 architecture extension
 * FEAT_FCMA, Floating-point complex number instructions
 * FEAT_JSCVT, JavaScript conversion instructions
 * FEAT_LRCPC, Load-Acquire RCpc instructions
 * FEAT_NV, Nested virtualization support
 * FEAT_CCIDX, Extended cache index
 * FEAT_PAuth, Pointer authentication
 *
 * Additional requirements of Armv8.3
 * If FEAT_PMUv3 is implemented, FEAT_PMUv3p4 is OPTIONAL in Armv8.3 implementations.
 *
 * Features added to the Armv8.3 extension in later releases
 * FEAT_SPEv1p1, Armv8.3 Statistical Profiling Extensions
 * FEAT_DoPD, Debug over Powerdown
 * FEAT_PAuth2, Enhancements to pointer authentication
 * FEAT_FPAC, Faulting on AUT* instructions
 *
 * The Armv8.4 architecture extension
 * FEAT_DIT, Data Independent Timing instructions
 * FEAT_FlagM, Flag manipulation instructions v2
 * FEAT_LRCPC2, Load-Acquire RCpc instructions v2
 * FEAT_LSE2, Large System Extensions v2
 * FEAT_TLBIOS, TLB invalidate instructions in Outer Shareable domain
 * FEAT_TLBIRANGE, TLB invalidate range instructions
 * FEAT_TTL, Translation Table Level
 * FEAT_S2FWB, Stage 2 forced Write-Back
 * FEAT_TTST, Small translation tables
 * FEAT_BBM, Translation table break-before-make levels
 * FEAT_SEL2, Secure EL2
 * FEAT_NV2, Enhanced nested virtualization support
 * FEAT_IDST, ID space trap handling
 * FEAT_CNTSC, Generic Counter Scaling
 * FEAT_Debugv8p4, Debug v8.4
 * FEAT_TRF, Self-hosted Trace Extensions
 * FEAT_PMUv3p4, PMU Extensions v3.4
 * FEAT_RASv1p1, RAS Extension v1.1
 * FEAT_DoubleFault, Double Fault Extension
 *
 * Features added to earlier extensions
 * The existing functionality of OS Double Lock is added as a feature mnemonic in Armv8.0, see FEAT_DoubleLock on page A2-70.
 *
 * The Armv8.5 architecture extension
 * Architectural features added by Armv8.5
 * FEAT_FlagM2, Enhancements to flag manipulation instructions
 * FEAT_FRINTTS, Floating-point to integer instructions
 * FEAT_ExS, Context synchronization and exception handling
 * FEAT_GTG, Guest translation granule size
 * FEAT_BTI, Branch Target Identification
 * FEAT_E0PD, Preventing EL0 access to halves of address maps
 * FEAT_RNG, Random number generator
 * FEAT_MTE and FEAT_MTE2, Memory Tagging Extension
 * FEAT_PMUv3p5, PMU Extensions v3.5
 *
 * Features added to earlier extensions
 * FEAT_SB on page A2-68.
 * FEAT_SSBS on page A2-68.
 * FEAT_CSV2 on page A2-68.
 * FEAT_CSV3 on page A2-69.
 * FEAT_SPECRES on page A2-69.
 * FEAT_CP15SDISABLE2 on page A2-70.
 * FEAT_EVT on page A2-84.
 * FEAT_DPB2 on page A2-84.
 * FEAT_SPEv1p1 on page A2-89.
 * FEAT_DoPD on page A2-89.
 *
 * Features added to the Armv8.5 extension in later releases
 * FEAT_MTE3, MTE Asymmetric Fault Handling
 *
 * The Armv8.6 architecture extension
 * Architectural features added by Armv8.6
 * FEAT_ECV, Enhanced Counter Virtualization
 * FEAT_FGT, Fine Grain Traps
 * FEAT_TWED, Delayed Trapping of WFE
 * FEAT_AMUv1p1, AMU Extensions v1.1
 * FEAT_MTPMU, Multi-threaded PMU Extensions
 *
 * Additional requirements of Armv8.6
 * The frequency of CNTFRQ_EL0 is standardized to a frequency of 1GHz.
 *
 * Features added to earlier extensions
 * FEAT_DGH on page A2-70.
 * FEAT_ETS on page A2-70.
 * FEAT_BF16 on page A2-85.
 * FEAT_AA32BF16 on page A2-85.
 * FEAT_I8MM on page A2-85.
 * FEAT_AA32I8MM on page A2-86.
 * FEAT_PAuth2 on page A2-89.
 * FEAT_FPAC on page A2-89.
 *
 * The Armv8.7 architecture extension
 * Architectural features added by Armv8.7
 * FEAT_AFP, Alternate floating-point behavior
 * FEAT_RPRES, Increased precision of Reciprocal Estimate and Reciprocal Square Root Estimate
 * FEAT_LS64, FEAT_LS64_V, FEAT_LS64_ACCDATA, Support for 64 byte loads/stores
 * FEAT_WFxT and FEAT_WFxT2, WFE and WFI instructions with timeout
 * FEAT_HCX, Support for the HCRX_EL2 register
 * FEAT_LPA2, Larger physical address for 4KB and 16KB translation granules
 * FEAT_XS, XS attribute
 * FEAT_PMUv3p7, Armv8.7 PMU extensions
 * FEAT_SPEv1p2, Armv8.7 SPE features
 *
 * Additional requirements of Armv8.7
 * FEAT_ETS, Enhanced Translation Synchronization is now required
 *
 * Features added to earlier extensions
 * FEAT_PAN3 on page A2-77.
 * FEAT_MTE3 on page A2-99
 *
 * Cryptographic Extension
 * Armv8.0
 * FEAT_AES
 * FEAT_PMULL
 * FEAT_SHA1
 * FEAT_SHA256
 * Armv8.2
 * FEAT_SHA512, Advanced SIMD SHA512 instructions
 * FEAT_SHA3, Advanced SIMD SHA3 instructions
 * FEAT_SM3, Advanced SIMD SM3 instructions
 * FEAT_SM4, Advanced SIMD SM4 instructions
 *
 * The Performance Monitors Extension
 * ID_AA64DFR0_EL1.PMUVer indicates whether the Performance Monitors Extension is implemented
 * FEAT_PMUv3p1.
 * FEAT_PMUv3p4.
 * FEAT_PMUv3p5.
 * FEAT_MTPMU.
 * FEAT_PMUv3p7.
 *
 * The Reliability, Availability, and Serviceability Extension
 * ID_AA64PFR0_EL1.RAS
 * FEAT_IESB.
 * FEAT_RASv1p1.
 * FEAT_DoubleFault.
 *
 * The Statistical Profiling Extension (SPE)
 * ID_AA64DFR0_EL1.PMSVer
 * FEAT_SPEv1p1.
 * FEAT_SPEv1p2.
 *
 * The Scalable Vector Extension (SVE)
 * ID_AA64PFR0_EL1.SVE
 *
 * The Activity Monitors Extension (AMU)
 * FEAT_AMUv1
 * ID_AA64PFR0_EL1.AMU, ID_PFR0_EL1.AMU, ID_PFR0.AMU, EDPFR.AMU
 *
 * The Memory Partitioning and Monitoring (MPAM) Extension
 * FEAT_MPAM
 * ID_AA64PFR0_EL1.MPAM, EDPFR.MPAM
 */

/* Enhanced Counter Virtualization */
#define	AARCH64SET_FEAT_ECV		0
/* As above, but includes support for CNTHCTL_EL2.ECV and CNTPOFF_EL2 */
#define	AARCH64SET_FEAT_ECV2		1
/* Fine-Grained Trap */
#define	AARCH64SET_FEAT_FGT		2
/* Support for disabling context synchronizing exception entry and exit */
#define	AARCH64SET_FEAT_EXS		3
/* Support for 4KB memory granule size at stage 2 */
#define	AARCH64SET_FEAT_TGRAN4_2	4
/* 4KB granule at stage 2 supports 52-bit input and output addresses */
#define	AARCH64SET_FEAT_TGRAN4_2_52	5
/* Support for 64KB memory granule size at stage 2 */
#define	AARCH64SET_FEAT_TGRAN64_2	6
/* Support for 16KB memory granule size at stage 2 */
#define	AARCH64SET_FEAT_TGRAN16_2	7
/* 16KB granule at stage 2 supports 52-bit input and output addresses */
#define	AARCH64SET_FEAT_TGRAN16_2_52	8
/* Support for 4KB memory translation granule size */
#define	AARCH64SET_FEAT_TGRAN4		9
/* 4KB granule supports 52-bit input and output addresses */
#define	AARCH64SET_FEAT_TGRAN4_52	10
/* Support for 64KB memory translation granule size */
#define	AARCH64SET_FEAT_TGRAN64		11
/* Support for 16KB memory translation granule size */
#define	AARCH64SET_FEAT_TGRAN16		12
/* 16KB granule supports 52-bit input and output addresses */
#define	AARCH64SET_FEAT_TGRAN16_52	13
/* Support for mixed-endian at EL0 only */
#define	AARCH64SET_FEAT_BIGENDEL0	14
/* Support for a distinction between Secure and Non-secure Memory */
#define	AARCH64SET_FEAT_SNSMEM		15
/* Support for mixed-endian configuration */
#define	AARCH64SET_FEAT_BIGEND		16
/* Number of ASID bits */
#define	AARCH64SET_FEAT_ASID8		17
#define	AARCH64SET_FEAT_ASID16		18
/* Physical Address range supported */
#define	AARCH64SET_FEAT_PARANGE_4G	19
#define	AARCH64SET_FEAT_PARANGE_64G	20
#define	AARCH64SET_FEAT_PARANGE_1T	21
#define	AARCH64SET_FEAT_PARANGE_4T	22
#define	AARCH64SET_FEAT_PARANGE_16T	23
#define	AARCH64SET_FEAT_PARANGE_256T	24
#define	AARCH64SET_FEAT_PARANGE_4P	25
#endif

#if !defined(_ASM)

#if defined(_KERNEL) || defined(_KMEMUSER)

extern uchar_t aarch64_featureset[];

extern boolean_t is_aarch64_feature(void *featureset, uint_t feature);
extern void add_aarch64_feature(void *featureset, uint_t feature);
extern void remove_aarch64_feature(void *featureset, uint_t feature);
extern boolean_t compare_aarch64_featureset(void *setA, void *setB);
extern void print_aarch64_featureset(void *featureset);

#endif	/* _KERNEL || _KMEMUSER */

#if defined(_KERNEL)

struct cpuid_info;

extern void cpuid_pass1(struct cpu *, uchar_t *);
extern void cpuid_pass2(struct cpu *);

extern void cpuid_get_addrsize(struct cpu *, uint_t *, uint_t *);

extern int cpuid_checkpass(struct cpu *, int);
extern uint32_t cpuid_get_apicid(struct cpu *);

extern void determine_platform(void);
extern int get_hwenv(void);

/*
 * Defined hardware environments
 */
#define	HW_NATIVE	(1 << 0)	/* Running on bare metal */

#endif	/* _KERNEL */

#endif	/* !_ASM */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_AARCH64_ARCHEXT_H */
