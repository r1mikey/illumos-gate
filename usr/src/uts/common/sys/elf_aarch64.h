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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2013, Richard Lowe
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2022 Michael van der Westhuizen
 */

#ifndef _SYS_ELF_AARCH64_H
#define	_SYS_ELF_AARCH64_H

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * Static relocation codes for ELF64 object files begin at (257); dynamic ones
 * at (1024). Both (0) and (256) should be accepted as values of
 * R_AARCH64_NONE, the null relocation.
 *
 * Static relocation codes for ELF32 object files begin at [1]; dynamic ones
 * at [180].
 *
 * All unallocated type codes are reserved for future allocation.
 */
#define	R_AARCH64_NONE					0
#define	R_AARCH64_P32_NONE				R_AARCH64_NONE
#define	R_AARCH64_P32_ABS32				1
#define	R_AARCH64_P32_ABS16				2
#define	R_AARCH64_P32_PREL32				3
#define	R_AARCH64_P32_PREL16				4
#define	R_AARCH64_P32_MOVW_UABS_G0			5
#define	R_AARCH64_P32_MOVW_UABS_G0_NC			6
#define	R_AARCH64_P32_MOVW_UABS_G1			7
#define	R_AARCH64_P32_MOVW_SABS_G0			8
#define	R_AARCH64_P32_LD_PREL_LO19			9
#define	R_AARCH64_P32_ADR_PREL_LO21			10
#define	R_AARCH64_P32_ADR_PREL_PG_HI21			11
#define	R_AARCH64_P32_ADD_ABS_LO12_NC			12
#define	R_AARCH64_P32_LDST8_ABS_LO12_NC			13
#define	R_AARCH64_P32_LDST16_ABS_LO12_NC		14
#define	R_AARCH64_P32_LDST32_ABS_LO12_NC		15
#define	R_AARCH64_P32_LDST64_ABS_LO12_NC		16
#define	R_AARCH64_P32_LDST128_ABS_LO12_NC		17
#define	R_AARCH64_P32_TSTBR14				18
#define	R_AARCH64_P32_CONDBR19				19
#define	R_AARCH64_P32_JUMP26				20
#define	R_AARCH64_P32_CALL26				21
#define	R_AARCH64_P32_MOVW_PREL_G0			22
#define	R_AARCH64_P32_MOVW_PREL_G0_NC			23
#define	R_AARCH64_P32_MOVW_PREL_G1			24
#define	R_AARCH64_P32_GOT_LD_PREL19			25
#define	R_AARCH64_P32_ADR_GOT_PAGE			26
#define	R_AARCH64_P32_LD32_GOT_LO12_NC			27
#define	R_AARCH64_P32_LD32_GOTPAGE_LO14			28
#define	R_AARCH64_P32_PLT32				29
#define	R_AARCH64_P32_TLSGD_ADR_PREL21			80
#define	R_AARCH64_P32_TLSGD_ADR_PAGE21			81
#define	R_AARCH64_P32_TLSGD_ADD_LO12_NC			82
#define	R_AARCH64_P32_TLSLD_ADR_PREL21			83
#define	R_AARCH64_P32_TLSLD_ADR_PAGE21			84
#define	R_AARCH64_P32_TLSLD_ADD_LO12_NC			85
#define	R_AARCH64_P32_TLSLD_LD_PREL19			86
#define	R_AARCH64_P32_TLSLD_MOVW_DTPREL_G1		87
#define	R_AARCH64_P32_TLSLD_MOVW_DTPREL_G0		88
#define	R_AARCH64_P32_TLSLD_MOVW_DTPREL_G0_NC		89
#define	R_AARCH64_P32_TLSLD_ADD_DTPREL_HI12		90
#define	R_AARCH64_P32_TLSLD_ADD_DTPREL_LO12		91
#define	R_AARCH64_P32_TLSLD_ADD_DTPREL_LO12_NC		92
#define	R_AARCH64_P32_TLSLD_LDST8_DTPREL_LO12		93
#define	R_AARCH64_P32_TLSLD_LDST8_DTPREL_LO12_NC	94
#define	R_AARCH64_P32_TLSLD_LDST16_DTPREL_LO12		95
#define	R_AARCH64_P32_TLSLD_LDST16_DTPREL_LO12_NC	96
#define	R_AARCH64_P32_TLSLD_LDST32_DTPREL_LO12		97
#define	R_AARCH64_P32_TLSLD_LDST32_DTPREL_LO12_NC	98
#define	R_AARCH64_P32_TLSLD_LDST64_DTPREL_LO12		99
#define	R_AARCH64_P32_TLSLD_LDST64_DTPREL_LO12_NC	100
#define	R_AARCH64_P32_TLSLD_LDST128_DTPREL_LO12		101
#define	R_AARCH64_P32_TLSLD_LDST128_DTPREL_LO12_NC	102
#define	R_AARCH64_P32_TLSIE_ADR_GOTTPREL_PAGE21		103
#define	R_AARCH64_P32_TLSIE_LD32_GOTTPREL_LO12_NC	104
#define	R_AARCH64_P32_TLSIE_LD_GOTTPREL_PREL19		105
#define	R_AARCH64_P32_TLSLE_MOVW_TPREL_G1		106
#define	R_AARCH64_P32_TLSLE_MOVW_TPREL_G0		107
#define	R_AARCH64_P32_TLSLE_MOVW_TPREL_G0_NC		108
#define	R_AARCH64_P32_TLSLE_ADD_TPREL_HI12		109
#define	R_AARCH64_P32_TLSLE_ADD_TPREL_LO12		110
#define	R_AARCH64_P32_TLSLE_ADD_TPREL_LO12_NC		111
#define	R_AARCH64_P32_TLSLE_LDST8_TPREL_LO12		112
#define	R_AARCH64_P32_TLSLE_LDST8_TPREL_LO12_NC		113
#define	R_AARCH64_P32_TLSLE_LDST16_TPREL_LO12		114
#define	R_AARCH64_P32_TLSLE_LDST16_TPREL_LO12_NC	115
#define	R_AARCH64_P32_TLSLE_LDST32_TPREL_LO12		116
#define	R_AARCH64_P32_TLSLE_LDST32_TPREL_LO12_NC	117
#define	R_AARCH64_P32_TLSLE_LDST64_TPREL_LO12		118
#define	R_AARCH64_P32_TLSLE_LDST64_TPREL_LO12_NC	119
#define	R_AARCH64_P32_TLSLE_LDST128_TPREL_LO12		120
#define	R_AARCH64_P32_TLSLE_LDST128_TPREL_LO12_NC	121
#define	R_AARCH64_P32_TLSDESC_LD_PREL19			122
#define	R_AARCH64_P32_TLSDESC_ADR_PREL21		123
#define	R_AARCH64_P32_TLSDESC_ADR_PAGE21		124
#define	R_AARCH64_P32_TLSDESC_LD32_LO12			125
#define	R_AARCH64_P32_TLSDESC_ADD_LO12			126
#define	R_AARCH64_P32_TLSDESC_CALL			127
#define	R_AARCH64_P32_COPY				180
#define	R_AARCH64_P32_GLOB_DAT				181
#define	R_AARCH64_P32_JUMP_SLOT				182
#define	R_AARCH64_P32_RELATIVE				183
#define	R_AARCH64_P32_TLS_IMPDEF1			184
#define	R_AARCH64_P32_TLS_DTPMOD			\
	R_AARCH64_P32_TLS_IMPDEF1
#define	R_AARCH64_P32_TLS_IMPDEF2			185
#define	R_AARCH64_P32_TLS_DTPREL			\
	R_AARCH64_P32_TLS_IMPDEF2
#define	R_AARCH64_P32_TLS_TPREL				186
#define	R_AARCH64_P32_TLSDESC				187
#define	R_AARCH64_P32_IRELATIVE				188
#define	R_AARCH64_NONE_WITHDRAWN			256
#define	R_AARCH64_ABS64					257
#define	R_AARCH64_ABS32					258
#define	R_AARCH64_ABS16					259
#define	R_AARCH64_PREL64				260
#define	R_AARCH64_PREL32				261
#define	R_AARCH64_PREL16				262
#define	R_AARCH64_MOVW_UABS_G0				263
#define	R_AARCH64_MOVW_UABS_G0_NC			264
#define	R_AARCH64_MOVW_UABS_G1				265
#define	R_AARCH64_MOVW_UABS_G1_NC			266
#define	R_AARCH64_MOVW_UABS_G2				267
#define	R_AARCH64_MOVW_UABS_G2_NC			268
#define	R_AARCH64_MOVW_UABS_G3				269
#define	R_AARCH64_MOVW_SABS_G0				270
#define	R_AARCH64_MOVW_SABS_G1				271
#define	R_AARCH64_MOVW_SABS_G2				272
#define	R_AARCH64_LD_PREL_LO19				273
#define	R_AARCH64_ADR_PREL_LO21				274
#define	R_AARCH64_ADR_PREL_PG_HI21			275
#define	R_AARCH64_ADR_PREL_PG_HI21_NC			276
#define	R_AARCH64_ADD_ABS_LO12_NC			277
#define	R_AARCH64_LDST8_ABS_LO12_NC			278
#define	R_AARCH64_TSTBR14				279
#define	R_AARCH64_CONDBR19				280
#define	R_AARCH64_JUMP26				282
#define	R_AARCH64_CALL26				283
#define	R_AARCH64_LDST16_ABS_LO12_NC			284
#define	R_AARCH64_LDST32_ABS_LO12_NC			285
#define	R_AARCH64_LDST64_ABS_LO12_NC			286
#define	R_AARCH64_MOVW_PREL_G0				287
#define	R_AARCH64_MOVW_PREL_G0_NC			288
#define	R_AARCH64_MOVW_PREL_G1				289
#define	R_AARCH64_MOVW_PREL_G1_NC			290
#define	R_AARCH64_MOVW_PREL_G2				291
#define	R_AARCH64_MOVW_PREL_G2_NC			292
#define	R_AARCH64_MOVW_PREL_G3				293
#define	R_AARCH64_LDST128_ABS_LO12_NC			299
#define	R_AARCH64_MOVW_GOTOFF_G0			300
#define	R_AARCH64_MOVW_GOTOFF_G0_NC			301
#define	R_AARCH64_MOVW_GOTOFF_G1			302
#define	R_AARCH64_MOVW_GOTOFF_G1_NC			303
#define	R_AARCH64_MOVW_GOTOFF_G2			304
#define	R_AARCH64_MOVW_GOTOFF_G2_NC			305
#define	R_AARCH64_MOVW_GOTOFF_G3			306
#define	R_AARCH64_GOTREL64				307
#define	R_AARCH64_GOTREL32				308
#define	R_AARCH64_GOT_LD_PREL19				309
#define	R_AARCH64_LD64_GOTOFF_LO15			310
#define	R_AARCH64_ADR_GOT_PAGE				311
#define	R_AARCH64_LD64_GOT_LO12_NC			312
#define	R_AARCH64_LD64_GOTPAGE_LO15			313
#define	R_AARCH64_PLT32					314
#define	R_AARCH64_TLSGD_ADR_PREL21			512
#define	R_AARCH64_TLSGD_ADR_PAGE21			513
#define	R_AARCH64_TLSGD_ADD_LO12_NC			514
#define	R_AARCH64_TLSGD_MOVW_G1				515
#define	R_AARCH64_TLSGD_MOVW_G0_NC			516
#define	R_AARCH64_TLSLD_ADR_PREL21			517
#define	R_AARCH64_TLSLD_ADR_PAGE21			518
#define	R_AARCH64_TLSLD_ADD_LO12_NC			519
#define	R_AARCH64_TLSLD_MOVW_G1				520
#define	R_AARCH64_TLSLD_MOVW_G0_NC			521
#define	R_AARCH64_TLSLD_LD_PREL19			522
#define	R_AARCH64_TLSLD_MOVW_DTPREL_G2			523
#define	R_AARCH64_TLSLD_MOVW_DTPREL_G1			524
#define	R_AARCH64_TLSLD_MOVW_DTPREL_G1_NC		525
#define	R_AARCH64_TLSLD_MOVW_DTPREL_G0			526
#define	R_AARCH64_TLSLD_MOVW_DTPREL_G0_NC		527
#define	R_AARCH64_TLSLD_ADD_DTPREL_HI12			528
#define	R_AARCH64_TLSLD_ADD_DTPREL_LO12			529
#define	R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC		530
#define	R_AARCH64_TLSLD_LDST8_DTPREL_LO12		531
#define	R_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC		532
#define	R_AARCH64_TLSLD_LDST16_DTPREL_LO12		533
#define	R_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC		534
#define	R_AARCH64_TLSLD_LDST32_DTPREL_LO12		535
#define	R_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC		536
#define	R_AARCH64_TLSLD_LDST64_DTPREL_LO12		537
#define	R_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC		538
#define	R_AARCH64_TLSIE_MOVW_GOTTPREL_G1		539
#define	R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC		540
#define	R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21		541
#define	R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC		542
#define	R_AARCH64_TLSIE_LD_GOTTPREL_PREL19		543
#define	R_AARCH64_TLSLE_MOVW_TPREL_G2			544
#define	R_AARCH64_TLSLE_MOVW_TPREL_G1			545
#define	R_AARCH64_TLSLE_MOVW_TPREL_G1_NC		546
#define	R_AARCH64_TLSLE_MOVW_TPREL_G0			547
#define	R_AARCH64_TLSLE_MOVW_TPREL_G0_NC		548
#define	R_AARCH64_TLSLE_ADD_TPREL_HI12			549
#define	R_AARCH64_TLSLE_ADD_TPREL_LO12			550
#define	R_AARCH64_TLSLE_ADD_TPREL_LO12_NC		551
#define	R_AARCH64_TLSLE_LDST8_TPREL_LO12		552
#define	R_AARCH64_TLSLE_LDST8_TPREL_LO12_NC		553
#define	R_AARCH64_TLSLE_LDST16_TPREL_LO12		554
#define	R_AARCH64_TLSLE_LDST16_TPREL_LO12_NC		555
#define	R_AARCH64_TLSLE_LDST32_TPREL_LO12		556
#define	R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC		557
#define	R_AARCH64_TLSLE_LDST64_TPREL_LO12		558
#define	R_AARCH64_TLSLE_LDST64_TPREL_LO12_NC		559
#define	R_AARCH64_TLSDESC_LD_PREL19			560
#define	R_AARCH64_TLSDESC_ADR_PREL21			561
#define	R_AARCH64_TLSDESC_ADR_PAGE21			562
#define	R_AARCH64_TLSDESC_LD64_LO12			563
#define	R_AARCH64_TLSDESC_ADD_LO12			564
#define	R_AARCH64_TLSDESC_OFF_G1			565
#define	R_AARCH64_TLSDESC_OFF_G0_NC			566
#define	R_AARCH64_TLSDESC_LDR				567
#define	R_AARCH64_TLSDESC_ADD				568
#define	R_AARCH64_TLSDESC_CALL				569
#define	R_AARCH64_TLSLE_LDST128_TPREL_LO12		570
#define	R_AARCH64_TLSLE_LDST128_TPREL_LO12_NC		571
#define	R_AARCH64_TLSLD_LDST128_DTPREL_LO12		572
#define	R_AARCH64_TLSLD_LDST128_DTPREL_LO12_NC		573
#define	R_AARCH64_COPY					1024
#define	R_AARCH64_GLOB_DAT				1025
#define	R_AARCH64_JUMP_SLOT				1026
#define	R_AARCH64_RELATIVE				1027
#define	R_AARCH64_TLS_IMPDEF1				1028
#define	R_AARCH64_TLS_DTPMOD				R_AARCH64_TLS_IMPDEF1
#define	R_AARCH64_TLS_DTPMOD64				R_AARCH64_TLS_DTPMOD
#define	R_AARCH64_TLS_IMPDEF2				1029
#define	R_AARCH64_TLS_DTPREL				R_AARCH64_TLS_IMPDEF2
#define	R_AARCH64_TLS_DTPREL64				R_AARCH64_TLS_DTPREL
#define	R_AARCH64_TLS_TPREL				1030
#define	R_AARCH64_TLS_TPREL64				R_AARCH64_TLS_TPREL
#define	R_AARCH64_TLSDESC				1031
#define	R_AARCH64_IRELATIVE				1032

#define	R_AARCH64_NUM					1033


/*
 * XXXAARCH64: this should be 0x10000 as per LLVM? (defaultMaxPageSize)
 * https://github.com/llvm-mirror/lld/blob/master/ELF/Arch/AArch64.cpp
 *
 * The actual maximum is pretty huge, but I _think_ it's 2MiB, not 1MiB.
 * TODO: check all of this any what it might mean.
 */
#define	ELF_AARCH64_MAXPGSZ	0x100000	/* maximum page size */

/*
 * processor specific section types
 */
/* Reserved for Object file compatibility attributes */
#define	SHT_AARCH64_ATTRIBUTES	0x70000003

/*
 * st_other values
 */
#define	STO_AARCH64_VARIANT_PCS	0x80		/* follows an alternate PCS */

/*
 * NOTE: PT_SUNW_UNWIND is defined in the OS specific range
 *	 to conform with the aarch64 psABI.
 *
 * ^^^ is this true here?
 */
#define	PT_AARCH64_ARCHEXT	0x70000000
#define	PT_AARCH64_UNWIND	0x70000001

/*
 * There are consumers of this file that want to include elf defines for
 * all architectures.  This is a problem for the defines below, because
 * while they are architecture specific they have common names.  Hence to
 * prevent attempts to redefine these variables we'll check if any of
 * the other elf architecture header files have been included.  If
 * they have then we'll just stick with the existing definitions.
 */
#if !defined(_SYS_ELF_MACH_COMMON)
#define	_SYS_ELF_MACH_COMMON
#define	_SYS_ELF_MACH_AARCH64

/*
 * Plt and Got information; the first few .got and .plt entries are reserved
 *	PLT[0]	jump to dynamic linker
 *	GOT[0]	address of _DYNAMIC
 */
#define	M_PLT_INSSIZE		4	/* single plt instruction size */
#define	M_PLT_XNumber		2	/* PLT[0..1] reserved */
#define	M_GOT_XDYNAMIC		0	/* got index for _DYNAMIC */
#define	M_GOT_XLINKMAP		1	/* got index for link map */
#define	M_GOT_XRTLD		2	/* got index for rtbinder */
#define	M_GOT_XNumber		3	/* reserved no. of got entries */

/*
 * ELF64 bit PLT constants
 */
#define	M64_WORD_ALIGN		8
#define	M64_PLT_ENTSIZE		16	/* plt entry size in bytes */
#define	M64_PLT_ALIGN		16	/* alignment of .plt section */
#define	M64_GOT_ENTSIZE		8	/* got entry size in bytes */
#define	M64_PLT_RESERVSZ	(M_PLT_XNumber * M64_PLT_ENTSIZE)

/*
 * ELF32 bit PLT constants
 */
#define	M32_WORD_ALIGN		4
#define	M32_PLT_ENTSIZE		16	/* plt entry size in bytes */
#define	M32_PLT_ALIGN		16	/* alignment of .plt section */
#define	M32_GOT_ENTSIZE		4	/* got entry size in bytes */
#define	M32_PLT_RESERVSZ	(M_PLT_XNumber * M64_PLT_ENTSIZE)

/*
 * Make common alias for the 64 bit specific defines based on the ELF class.
 */
#if defined(_ELF64)
#define	M_WORD_ALIGN		M64_WORD_ALIGN
#define	M_PLT_ENTSIZE		M64_PLT_ENTSIZE
#define	M_PLT_ALIGN		M64_PLT_ALIGN
#define	M_PLT_RESERVSZ		M64_PLT_RESERVSZ
#define	M_GOT_ENTSIZE		M64_GOT_ENTSIZE
#else
#define	M_WORD_ALIGN		M32_WORD_ALIGN
#define	M_PLT_ENTSIZE		M32_PLT_ENTSIZE
#define	M_PLT_ALIGN		M32_PLT_ALIGN
#define	M_PLT_RESERVSZ		M32_PLT_RESERVSZ
#define	M_GOT_ENTSIZE		M32_GOT_ENTSIZE
#endif /* _ELF64 */

#endif /* _SYS_ELF_MACH_COMMON */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ELF_AARCH64_H */
