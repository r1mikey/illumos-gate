/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source. A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2013, Richard Lowe.
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2022 Michael van der Westhuizen
 */

#ifndef	_MACHDEP_AARCH64_H
#define	_MACHDEP_AARCH64_H

#include <link.h>
#include <sys/machelf.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Elf header information.
 */
#define	M_MACH			EM_AARCH64
#define	M_MACH_64		EM_AARCH64

#ifdef _ELF64
#define	M_CLASS			ELFCLASS64
#else
#define	M_CLASS			ELFCLASS32
#endif

#define	M_MACHPLUS		M_MACH
#define	M_DATA			ELFDATA2LSB
#define	M_FLAGSPLUS		0

/*
 * Page boundary Macros: truncate to previous page boundary and round to
 * next page boundary (refer to generic macros in ../sgs.h also).
 */
#define	M_PTRUNC(X)	((X) & ~(syspagsz - 1))
#define	M_PROUND(X)	(((X) + syspagsz - 1) & ~(syspagsz - 1))

/*
 * Segment boundary macros: truncate to previous segment boundary and round
 * to next page boundary.
 *
 * XXX: check this against amd64 and sparcv9
 */
#define	M_SEGSIZE	ELF_AARCH64_MAXPGSZ

#define	M_STRUNC(X)	((X) & ~(M_SEGSIZE - 1))
#define	M_SROUND(X)	(((X) + M_SEGSIZE - 1) & ~(M_SEGSIZE - 1))

/*
 * Relocation type macro.
 */
#define	M_RELOC		Rela

/*
 * TLS static segments must be rounded to the following requirements,
 * due to libthread stack allocation.
 */
#define	M_TLSSTATALIGN	0x10

/*
 * Other machine dependent entities
 *
 * XXX: needed? Correct?
 * XXX: check this against amd64 and sparcv9
 */
#define	M_SEGM_ALIGN	0x00010000

#define	M_BIND_ADJ	4		/* adjustment for end of */
					/*	elf_rtbndr() address */
/*
 * Provide default starting addresses.  64-bit programs can also be restricted
 * to a 32-bit address space (SF1_SUNW_ADDR32), and these programs provide an
 * alternative origin.
 *
 * XXXAARCH64: figure this out for the ELF32 class
 */
#define	M_SEGM_ORIGIN	(Addr)0x200000ULL	/* default 1st segment origin */
#define	M_SEGM_AORIGIN	(Addr)0x10000ULL	/* alternative 1st segment */
						/*    origin */

/*
 * Make common relocation information transparent to the common code
 */
#define	M_REL_DT_TYPE	DT_RELA		/* .dynamic entry */
#define	M_REL_DT_SIZE	DT_RELASZ	/* .dynamic entry */
#define	M_REL_DT_ENT	DT_RELAENT	/* .dynamic entry */
#define	M_REL_DT_COUNT	DT_RELACOUNT	/* .dynamic entry */
#define	M_REL_SHT_TYPE	SHT_RELA	/* section header type */
#define	M_REL_ELF_TYPE	ELF_T_RELA	/* data buffer type */

/*
 * Make common relocation types transparent to the common code
 */
#ifdef _ELF64
#define	M_R_NONE	R_AARCH64_NONE
#define	M_R_GLOB_DAT	R_AARCH64_GLOB_DAT
#define	M_R_COPY	R_AARCH64_COPY
#define	M_R_RELATIVE	R_AARCH64_RELATIVE
#define	M_R_JMP_SLOT	R_AARCH64_JUMP_SLOT
#define	M_R_FPTR	R_AARCH64_NONE
/* XXX: what is this? */
#define	M_R_ARRAYADDR	R_AARCH64_GLOB_DAT
#define	M_R_NUM		R_AARCH64_NUM
#else
#define	M_R_NONE	R_AARCH64_P32_NONE
#define	M_R_GLOB_DAT	R_AARCH64_P32_GLOB_DAT
#define	M_R_COPY	R_AARCH64_P32_COPY
#define	M_R_RELATIVE	R_AARCH64_P32_RELATIVE
#define	M_R_JMP_SLOT	R_AARCH64_P32_JUMP_SLOT
#define	M_R_FPTR	R_AARCH64_P32_NONE
/* XXX: what is this? */
#define	M_R_ARRAYADDR	R_AARCH64_P32_GLOB_DAT
/* XXXAARCH64: could constrain this a bit - would be cool */
#define	M_R_NUM		R_AARCH64_NUM
#endif

/*
 * The following are defined as M_R_NONE so that checks
 * for these relocations can be performed in common code - although
 * the checks are really only relevant to SPARC.
 */
#define	M_R_REGISTER	M_R_NONE

/*
 * DT_REGISTER is not valid on aarch64
 *
 * XXX: confirm this
 */
#define	M_DT_REGISTER	0xffffffff

/*
 * Make plt section information transparent to the common code.
 */
#define	M_PLT_SHF_FLAGS	(SHF_ALLOC | SHF_EXECINSTR)

/*
 * Make default data segment and stack flags transparent to the common code.
 */
#define	M_DATASEG_PERM	(PF_R | PF_W)
#define	M_STACK_PERM	(PF_R | PF_W)

/*
 * Define a set of identifiers for special sections.  These allow the sections
 * to be ordered within the output file image.  These values should be
 * maintained consistently, where appropriate, in each platform specific header
 * file.
 *
 *  -	null identifies that this section does not need to be added to the
 *	output image (ie. shared object sections or sections we're going to
 *	recreate (sym tables, string tables, relocations, etc.)).
 *
 *  -	any user defined section will be first in the associated segment.
 *
 *  -	interp and capabilities sections are next, as these are accessed
 *	immediately the first page of the image is mapped.
 *
 *  -	objects that do not provide an interp normally have a read-only
 *	.dynamic section that comes next (in this case, there is no need to
 *	update a DT_DEBUG entry at runtime).
 *
 *  -	the syminfo, hash, dynsym, dynstr and rel's are grouped together as
 *	these will all be accessed together by ld.so.1 to perform relocations.
 *
 *  -	the got and dynamic are grouped together as these may also be
 *	accessed first by ld.so.1 to perform relocations, fill in DT_DEBUG
 *	(executables only), and .got[0].
 *
 *  -	unknown sections (stabs, comments, etc.) go at the end.
 *
 * Note that .tlsbss/.bss are given the largest identifiers.  This ensures that
 * if any unknown sections become associated to the same segment as the .bss,
 * the .bss sections are always the last section in the segment.
 *
 * XXX: this is copied verbatim from amd64 and is probably not right
 */
#define	M_ID_NULL	0x00
#define	M_ID_USER	0x01

#define	M_ID_INTERP	0x02			/* SHF_ALLOC */
#define	M_ID_CAP	0x03
#define	M_ID_CAPINFO	0x04
#define	M_ID_CAPCHAIN	0x05

#define	M_ID_DYNAMIC	0x06			/* if no .interp, then no */
						/*    DT_DEBUG is required */
#define	M_ID_UNWINDHDR	0x07
#define	M_ID_UNWIND	0x08

#define	M_ID_SYMINFO	0x09
#define	M_ID_HASH	0x0a
#define	M_ID_LDYNSYM	0x0b			/* always right before DYNSYM */
#define	M_ID_DYNSYM	0x0c
#define	M_ID_DYNSTR	0x0d
#define	M_ID_VERSION	0x0e
#define	M_ID_DYNSORT	0x0f
#define	M_ID_REL	0x10
#define	M_ID_PLT	0x11			/* SHF_ALLOC + SHF_EXECINSTR */
#define	M_ID_ARRAY	0x12
#define	M_ID_TEXT	0x13
#define	M_ID_DATA	0x20

/*	M_ID_USER	0x01			dual entry - listed above */
#define	M_ID_GOT	0x03			/* SHF_ALLOC + SHF_WRITE */
/*	M_ID_DYNAMIC	0x06			dual entry - listed above */
/*	M_ID_UNWIND	0x08			dual entry - listed above */

#define	M_ID_UNKNOWN	0xfb			/* just before TLS */

#define	M_ID_TLS	0xfc			/* just before bss */
#define	M_ID_TLSBSS	0xfd
#define	M_ID_BSS	0xfe
#define	M_ID_LBSS	0xff

#define	M_ID_SYMTAB_NDX	0x02			/* ! SHF_ALLOC */
#define	M_ID_SYMTAB	0x03
#define	M_ID_STRTAB	0x04
#define	M_ID_DYNSYM_NDX	0x05
#define	M_ID_NOTE	0x06


#ifdef __cplusplus
}
#endif

#endif /* _MACHDEP_AARCH64_H */
