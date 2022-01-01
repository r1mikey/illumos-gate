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


#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/bootconf.h>
#include <sys/modctl.h>
#include <sys/elf.h>
#include <sys/kobj.h>
#include <sys/kobj_impl.h>
#include <sys/dtrace.h>
#include <sys/controlregs.h>
#include <vm/hat.h>
#include <sys/sdt_impl.h>

#include "reloc.h"

#define	SDT_NOP	0xd503201f

static int
sdt_reloc_resolve(struct module *mp, char *symname, unsigned int rtype,
    uint32_t *instr)
{
	sdt_probedesc_t	*sdp;
	int i;

	/*
	 * The SDT mechanism works by replacing calls to the undefined routine
	 * __dtrace_probe_[name] with nop instructions.  The relocations are
	 * logged, and SDT itself will later patch the running binary
	 * appropriately.
	 */
	if (strncmp(symname, sdt_prefix, strlen(sdt_prefix)) != 0)
		return (1);

	/*
	 * In aarch64 we do a R_AARCH64_CALL26 to dtrace, by virtue of us being
	 * either an executable (unix) or a relocatable object (everything
	 * else).  We built to avoid veneers (specifically the PLT) so that our
	 * relocations are simple.
	 */
	if (rtype != R_AARCH64_CALL26) {
		if (kobj_debug & D_RELOCATIONS) {
			_kobj_printf(ops, "%s: module %s, symbol %s, "
			    "relocation %s, addr 0x%p, instruction 0x%08x "
			    "unsupported for SDT\n", __func__,
			    mp->filename ? mp->filename : "(null)",
			    symname, conv_reloc_aarch64_type(rtype),
			    instr, *instr);
		}
		return (1);
	}

	symname += strlen(sdt_prefix);

	sdp = kobj_alloc(sizeof (sdt_probedesc_t), KM_WAIT);
	sdp->sdpd_name = kobj_alloc(strlen(symname) + 1, KM_WAIT);
	bcopy(symname, sdp->sdpd_name, strlen(symname) + 1);

	sdp->sdpd_offset = (uintptr_t)instr;
	sdp->sdpd_next = mp->sdt_probes;
	mp->sdt_probes = sdp;

	*instr = SDT_NOP;
	return (0);
}

int
/* ARGSUSED2 */
do_relocate(struct module *mp, char *reltbl, int nreloc, int relocsize,
    Addr baseaddr)
{
	unsigned long stndx;
	unsigned long P;
	unsigned long reladdr, rend;
	unsigned int rtype;
	unsigned long S;
	unsigned long X;
	Elf64_Sxword A;
	Sym *symref = NULL;
	int err = 0;
	int symnum;
	reladdr = (unsigned long)reltbl;
	rend = reladdr + nreloc * relocsize;

#ifdef	KOBJ_DEBUG
	if (kobj_debug & D_RELOCATIONS) {
		_kobj_printf(ops, "krtld:\ttype\t\t\toffset\t   addend"
		    "      symbol\n");
		_kobj_printf(ops, "krtld:\t\t\t\t\t   value\n");
	}
#endif

	symnum = -1;
	/* loop through relocations */
	while (reladdr < rend) {
		symnum++;
		rtype = ELF_R_TYPE(((Rela *)reladdr)->r_info);
		P = ((Rela *)reladdr)->r_offset;
		stndx = ELF_R_SYM(((Rela *)reladdr)->r_info);
		if (stndx >= mp->nsyms) {
			_kobj_printf(ops, "do_relocate: bad strndx %d\n",
			    symnum);
			return (-1);
		}
		if ((rtype > R_AARCH64_NUM) || IS_TLS_INS(rtype)) {
			_kobj_printf(ops, "krtld: invalid relocation type %d",
			    rtype);
			_kobj_printf(ops, " at 0x%lx:", P);
			_kobj_printf(ops, " file=%s\n", mp->filename);
			err = 1;
			return (-1);
		}

		A = (long)(((Rela *)reladdr)->r_addend);
		reladdr += relocsize;

		if (rtype == R_AARCH64_NONE)
			continue;

		/*
		 * Many aarch64 relocations need special consideration, such
		 * as page-based massaging of values.  Ensure that we don't
		 * silently do the wrong thing on relocation types that have
		 * not been tested.
		 */
		switch (rtype) {
		case R_AARCH64_ABS64:			/* fallthrough */
		case R_AARCH64_ADD_ABS_LO12_NC:		/* fallthrough */
		case R_AARCH64_ADR_PREL_PG_HI21:	/* fallthrough */
		case R_AARCH64_CALL26:			/* fallthrough */
		case R_AARCH64_JUMP26:			/* fallthrough */
		case R_AARCH64_LDST16_ABS_LO12_NC:	/* fallthrough */
		case R_AARCH64_LDST32_ABS_LO12_NC:	/* fallthrough */
		case R_AARCH64_LDST64_ABS_LO12_NC:	/* fallthrough */
		case R_AARCH64_LDST8_ABS_LO12_NC:
			break;
		default:
			_kobj_printf(ops, "krtld: unsupported relocation "
			    "type %d", rtype);
			_kobj_printf(ops, " at 0x%lx:", P);
			_kobj_printf(ops, " file=%s\n", mp->filename);
			err = 1;
			return (-1);
		}

#ifdef	KOBJ_DEBUG
		if (kobj_debug & D_RELOCATIONS) {
			Sym *	symp;
			symp = (Sym *)
			    (mp->symtbl+(stndx * mp->symhdr->sh_entsize));
			_kobj_printf(ops, "krtld:\t%s",
			    conv_reloc_aarch64_type(rtype));
			_kobj_printf(ops, "\t0x%8lx", P);
			_kobj_printf(ops, " %8lld", (longlong_t)A);
			_kobj_printf(ops, "  %s\n",
			    (const char *)mp->strings + symp->st_name);
		}
#endif

		if (!(mp->flags & KOBJ_EXEC))
			P += baseaddr;

		/*
		 * if R_AARCH64_RELATIVE, simply add base addr
		 * to reloc location
		 */

		if (rtype == R_AARCH64_RELATIVE) {
			/*
			 * XXXAARCH64: aarch64 has special handling for the
			 * null ELF symbol.
			 *
			 * Don't worry about this right now, since this reloc
			 * is not in the tested list yet.
			 */
			S = baseaddr;
		} else {
			/*
			 * get symbol table entry - if symbol is local
			 * value is base address of this object
			 */
			symref = (Sym *)
			    (mp->symtbl+(stndx * mp->symhdr->sh_entsize));

			if (ELF_ST_BIND(symref->st_info) == STB_LOCAL) {
				/* *** this is different for .o and .so */
				S = symref->st_value;
			} else {
				/*
				 * It's global. Allow weak references.  If
				 * the symbol is undefined, give dtrace a
				 * chance to see if it's a probe site, and fix
				 * it up if so.
				 */
				if (symref->st_shndx == SHN_UNDEF &&
				    sdt_reloc_resolve(mp, mp->strings +
				    symref->st_name, rtype,
				    (uint32_t *)P) == 0)
					continue;

				if (symref->st_shndx == SHN_UNDEF) {
					if (ELF_ST_BIND(symref->st_info)
					    != STB_WEAK) {
						_kobj_printf(ops,
						    "not found: %s\n",
						    mp->strings +
						    symref->st_name);
						err = 1;
					}
					continue;
				}

				/*
				 * symbol found  - relocate
				 *
				 * calculate location of definition
				 * - symbol value plus base address of
				 * containing shared object
				 */
				S = symref->st_value;
			} /* end global or weak */
		} /* end not R_AARCH64_RELATIVE */

#define	Page(expr)	((expr) & UINT64_C(0xFFFFFFFFFFFFF000))

		/*
		 * calculate final value -
		 * if PC-relative, subtract ref addr
		 */
		if (IS_PC_RELATIVE(rtype)) {
			if (rtype == R_AARCH64_ADR_PREL_PG_HI21) {
				X = Page(S+A) - Page(P);
			} else {
				X = S + A - P;
			}
		} else {
			X = S + A;
		}

#ifdef	KOBJ_DEBUG
		if (kobj_debug & D_RELOCATIONS) {
			_kobj_printf(ops, "krtld:\t\t\t\t0x%8lx", P);
			_kobj_printf(ops, " 0x%8lx\n", X);
		}
#endif

		if (do_reloc_krtld(rtype, (unsigned char *)P, &X,
		    (const char *)mp->strings + symref->st_name,
		    mp->filename) == 0)
			err = 1;
	} /* end of while loop */
	if (err)
		return (-1);

	/* XXXAARCH64: amd64 does tnf_splice_probes here */
	return (0);
}

int
do_relocations(struct module *mp)
{
	uint_t shn;
	Shdr *shp, *rshp;
	uint_t nreloc;

	/* do the relocations */
	for (shn = 1; shn < mp->hdr.e_shnum; shn++) {
		rshp = (Shdr *)
		    (mp->shdrs + shn * mp->hdr.e_shentsize);
		if (rshp->sh_type == SHT_REL) {
			_kobj_printf(ops, "%s can't process type SHT_REL\n",
			    mp->filename);
			return (-1);
		}
		if (rshp->sh_type != SHT_RELA)
			continue;
		if (rshp->sh_link != mp->symtbl_section) {
			_kobj_printf(ops, "%s reloc for non-default symtab\n",
			    mp->filename);
			return (-1);
		}
		if (rshp->sh_info >= mp->hdr.e_shnum) {
			_kobj_printf(ops, "do_relocations: %s ", mp->filename);
			_kobj_printf(ops, " sh_info out of range %d\n", shn);
			goto bad;
		}
		nreloc = rshp->sh_size / rshp->sh_entsize;

		/* get the section header that this reloc table refers to */
		shp = (Shdr *)
		    (mp->shdrs + rshp->sh_info * mp->hdr.e_shentsize);
		/*
		 * Do not relocate any section that isn't loaded into memory.
		 * Most commonly this will skip over the .rela.stab* sections
		 */
		if (!(shp->sh_flags & SHF_ALLOC))
			continue;
#ifdef	KOBJ_DEBUG
		if (kobj_debug & D_RELOCATIONS) {
			_kobj_printf(ops, "krtld: relocating: file=%s ",
			    mp->filename);
			_kobj_printf(ops, " section=%d\n", shn);
		}
#endif
		if (do_relocate(mp, (char *)rshp->sh_addr,
		    nreloc, rshp->sh_entsize, shp->sh_addr) < 0) {
			_kobj_printf(ops,
			    "do_relocations: %s do_relocate failed\n",
			    mp->filename);
			goto bad;
		}
		kobj_free((void *)rshp->sh_addr, rshp->sh_size);
		rshp->sh_addr = 0;
	}
	mp->flags |= KOBJ_RELOCATED;
	return (0);
bad:
	kobj_free((void *)rshp->sh_addr, rshp->sh_size);
	rshp->sh_addr = 0;
	return (-1);
}
