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
 * Portions:
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright 2022 Michael van der Westhuizen
 */

/*
 * Implemented document reference:
 *	Name: ELF for the Arm® 64-bit Architecture (AArch64)
 *	Version: 2021Q1
 *	Date of Issue: 12th April 2021
 */

/*
 * XXXARM: Luckily, to some degree, a lot of the target-specific things in the
 * link-editor aren't _exactly_ target specific, and a reasonable
 * approximation of them can be derived from the implementations of the other
 * targets.  That is what we're doing in this file right now -- Large chunks
 * are directly derived from the intel implementation.
 *
 * It is possible, and in fact likely, that I have misunderstood the
 * commonality of various pieces of this with the intel implementation and in
 * doing so have introduced bugs.
 *
 * I should also state that the comments describing various functions are
 * actually describing my understanding thereof.  It is not unlikely that my
 * understanding is flawed.
 */

#define	DO_RELOC_LIBLD_AARCH64

#include	<sys/elf_aarch64.h>
#include	<stdio.h>
#include	<strings.h>
#include	<debug.h>
#include	<reloc.h>
#include	<aarch64/machdep_aarch64.h>
#include	"msg.h"
#include	"_libld.h"

#define	AARCH64_PAGE(V)	(((Xword)(V)) & ~((Xword)0xFFF))

/*
 * This module uses do_reloc_ld() to execute several synthesized relocations.
 * That function expects to be passed two things that we need to construct
 * here:
 *
 * 1)	A Rel_desc descriptor for each relocation type, from which the
 *	rel_rtype field, and nothing else, is obtained. This is easily
 *	handled by constructing the necessary descriptors.
 * 2)	A function, which called with the Rel_desc descriptor, returns
 *	a string representing the name of the symbol associated with
 *	the descriptor. The usual function for this is ld_reloc_sym_name().
 *	However, that function will not work in this case, as these synthetic
 *	relocations do not have an associated symbol. We supply the
 *	syn_rdesc_sym_name() function to simply return the fixed name.
 */
static Rel_desc rdesc_r_aarch64_adr_prel_pg_hi21 = {
    NULL, NULL, NULL, 0, 0, 0, R_AARCH64_ADR_PREL_PG_HI21 };
static Rel_desc rdesc_r_aarch64_ldst64_abs_lo12_nc = {
    NULL, NULL, NULL, 0, 0, 0, R_AARCH64_LDST64_ABS_LO12_NC };
static Rel_desc rdesc_r_aarch64_add_abs_lo12_nc = {
    NULL, NULL, NULL, 0, 0, 0, R_AARCH64_ADD_ABS_LO12_NC };

/*ARGSUSED*/
static const char *
syn_rdesc_sym_name(Rel_desc *rdesc)
{
	return (MSG_ORIG(MSG_SYM_PLTENT));
}

/*
 * Search the GOT index list for a GOT entry with a matching reference and the
 * proper addend.
 */
static Gotndx *
ld_find_got_ndx(Alist *alp, Gotref gref, Ofl_desc *ofl, Rel_desc *rdesc)
{
	Aliste	idx;
	Gotndx	*gnp;

	assert(rdesc != 0);

	if ((gref == GOT_REF_TLSLD) && ofl->ofl_tlsldgotndx)
		return (ofl->ofl_tlsldgotndx);

	for (ALIST_TRAVERSE(alp, idx, gnp)) {
		if ((rdesc->rel_raddend == gnp->gn_addend) &&
		    (gnp->gn_gotref == gref)) {
			return (gnp);
		}
	}
	return (NULL);
}

static Xword
ld_calc_got_offset(Rel_desc *rdesc, Ofl_desc *ofl)
{
	Os_desc		*osp = ofl->ofl_osgot;
	Sym_desc	*sdp = rdesc->rel_sym;
	Xword		gotndx;
	Gotref		gref;
	Gotndx		*gnp;

	if (rdesc->rel_flags & FLG_REL_DTLS)
		gref = GOT_REF_TLSGD;
	else if (rdesc->rel_flags & FLG_REL_MTLS)
		gref = GOT_REF_TLSLD;
	else if (rdesc->rel_flags & FLG_REL_STLS)
		gref = GOT_REF_TLSIE;
	else
		gref = GOT_REF_GENERIC;

	gnp = ld_find_got_ndx(sdp->sd_GOTndxs, gref, ofl, rdesc);
	assert(gnp);

	gotndx = (Xword)gnp->gn_gotndx;

	/* XXXAARCH64: complete guesswork */
	if ((rdesc->rel_flags & FLG_REL_DTLS) &&
	    ((rdesc->rel_rtype == R_AARCH64_TLS_DTPREL) ||
	    (rdesc->rel_rtype == R_AARCH64_TLS_DTPMOD) ||
	    (rdesc->rel_rtype == R_AARCH64_P32_TLS_DTPREL) ||
	    (rdesc->rel_rtype == R_AARCH64_P32_TLS_DTPMOD)))
		gotndx++;

	return ((Xword)(osp->os_shdr->sh_addr + (gotndx * M_GOT_ENTSIZE)));
}

static Word
ld_init_rel(Rel_desc *reld, Word *typedata, void *reloc)
{
	Rela	*rel = (Rela *)reloc;

	/* LINTED */
	reld->rel_rtype = (Word)ELF_R_TYPE(rel->r_info, M_MACH);
	reld->rel_roffset = rel->r_offset;
	reld->rel_raddend = rel->r_addend;
	/* XXXAARCH64: amd64 sets this to 0 */
	*typedata = (Word)ELF_R_TYPE_DATA(rel->r_info);

	reld->rel_flags |= FLG_REL_RELA;

	return ((Word)ELF_R_SYM(rel->r_info));
}

static void
ld_mach_eflags(Ehdr *ehdr, Ofl_desc *ofl)
{
	ofl->ofl_dehdr->e_flags |= ehdr->e_flags;
}

static void
ld_mach_make_dynamic(Ofl_desc *ofl, size_t *cnt)
{
	if (!(ofl->ofl_flags & FLG_OF_RELOBJ)) {
		/*
		 * Create this entry if we are going to create a PLT.
		 */
		if (ofl->ofl_pltcnt)
			(*cnt)++;		/* DT_PLTGOT */
	}
}

static void
ld_mach_update_odynamic(Ofl_desc *ofl, Dyn **dyn)
{
	if (((ofl->ofl_flags & FLG_OF_RELOBJ) == 0) && ofl->ofl_pltcnt) {
		(*dyn)->d_tag = DT_PLTGOT;
		if (ofl->ofl_osgot)
			(*dyn)->d_un.d_ptr = ofl->ofl_osgot->os_shdr->sh_addr;
		else
			(*dyn)->d_un.d_ptr = 0;
		(*dyn)++;
	}
}

static Xword
ld_calc_plt_addr(Sym_desc *sdp, Ofl_desc *ofl)
{
	Xword	value;

	value = (Xword)(ofl->ofl_osplt->os_shdr->sh_addr) +
	    M_PLT_RESERVSZ + ((sdp->sd_aux->sa_PLTndx - 1) * M_PLT_ENTSIZE);
	return (value);
}

/*
 * Build a single plt entry - code is:
 *	adrp x16, Page(&(.plt.got[n]))
 *	ldr  x17, [x16, Offset(&(.plt.got[n]))]
 *	add  x16, x16, Offset(&(.plt.got[n]))
 *	br   x17
 *
 * See the comment for ld_fillin_pltgot() for a more complete description.
 */
static uchar_t pltn_template[M_PLT_ENTSIZE] = {
	0x10, 0x00, 0x00, 0x90,	/* adrp x16, Page(&(.plt.got[n])) */
	0x11, 0x02, 0x40, 0xf9,	/* ldr  x17, [x16, Offset(&(.plt.got[n]))] */
	0x10, 0x02, 0x00, 0x91,	/* add  x16, x16, Offset(&(.plt.got[n])) */
	0x20, 0x02, 0x1f, 0xd6	/* br   x17 */
};

/* ARGSUSED */
static uintptr_t
plt_entry(Ofl_desc *ofl, Sym_desc *sdp)
{
	uchar_t		*plt0, *pltent, *gotent;
	Sword		plt_off;
	Word		got_off;
	Xword		val1;
	Addr		got_addr, plt_addr;
	int		bswap = (ofl->ofl_flags1 & FLG_OF1_ENCDIFF) != 0;

	got_off = sdp->sd_aux->sa_PLTGOTndx * M_GOT_ENTSIZE;
	plt_off = M_PLT_RESERVSZ + ((sdp->sd_aux->sa_PLTndx - 1) *
	    M_PLT_ENTSIZE);
	plt0 = (uchar_t *)(ofl->ofl_osplt->os_outdata->d_buf);
	pltent = plt0 + plt_off;
	gotent = (uchar_t *)(ofl->ofl_osgot->os_outdata->d_buf) + got_off;
	got_addr = ofl->ofl_osgot->os_shdr->sh_addr + got_off;
	plt_addr = ofl->ofl_osplt->os_shdr->sh_addr + plt_off;

	bcopy(pltn_template, pltent, sizeof (pltn_template));

	/*
	 * Fill in the got entry with the address of the start of the PLT.
	 */
	/* LINTED */
	*(Word *)gotent = ofl->ofl_osplt->os_shdr->sh_addr;
	if (bswap)
		/* LINTED */
		*(Word *)gotent = ld_bswap_Word(*(Word *)gotent);

	/*
	 * If '-z noreloc' is specified - skip the do_reloc_ld stage.
	 */
	if (!OFL_DO_RELOC(ofl))
		return (1);

	/*
	 * patchup:
	 *	adrp x16, Page(&(.plt.got[n]))
	 */
	val1 = AARCH64_PAGE(got_addr) - AARCH64_PAGE(plt_addr);

	if (do_reloc_ld(&rdesc_r_aarch64_adr_prel_pg_hi21,
	    &pltent[0 * M_PLT_INSSIZE], &val1, syn_rdesc_sym_name,
	    MSG_ORIG(MSG_SPECFIL_PLTENT), bswap, ofl->ofl_lml) == 0) {
		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_PLT_PLTNFAIL),
		    sdp->sd_aux->sa_PLTndx, demangle(sdp->sd_name));
		return (S_ERROR);
	}

	/*
	 * patchup:
	 *	ldr  x17, [x16, Offset(&(.plt.got[n]))]
	 */
	val1 = (Xword)got_addr;

	if (do_reloc_ld(&rdesc_r_aarch64_ldst64_abs_lo12_nc,
	    &pltent[1 * M_PLT_INSSIZE], &val1, syn_rdesc_sym_name,
	    MSG_ORIG(MSG_SPECFIL_PLTENT), bswap, ofl->ofl_lml) == 0) {
		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_PLT_PLTNFAIL),
		    sdp->sd_aux->sa_PLTndx, demangle(sdp->sd_name));
		return (S_ERROR);
	}

	/*
	 * patchup:
	 *	add  x16, x16, Offset(&(.plt.got[n]))
	 */
	val1 = (Xword)got_addr;

	if (do_reloc_ld(&rdesc_r_aarch64_add_abs_lo12_nc,
	    &pltent[2 * M_PLT_INSSIZE], &val1, syn_rdesc_sym_name,
	    MSG_ORIG(MSG_SPECFIL_PLTENT), bswap, ofl->ofl_lml) == 0) {
		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_PLT_PLTNFAIL),
		    sdp->sd_aux->sa_PLTndx, demangle(sdp->sd_name));
		return (S_ERROR);
	}

	return (1);
}

/*
 * Insert an appropriate dynamic relocation into the output image in the
 * appropriate relocation section.
 *
 * Primarily, this is not particularly target-specific, and involves
 * calculating the correct offset for the relocation entry to be written, and
 * accounting for some complicated edge cases.
 *
 * Heavily taken from the Intel implementation.
 */
static uintptr_t
ld_perform_outreloc(Rel_desc *orsp, Ofl_desc *ofl, Boolean *remain_seen)
{
	Os_desc		*relosp, *osp = NULL;
	Word		ndx;
	Xword		roffset, value;
	Sxword		raddend;
	Rela		rea;
	char		*relbits;
	Sym_desc	*sdp, *psym = NULL;
	int		sectmoved = 0;

	raddend = orsp->rel_raddend;
	sdp = orsp->rel_sym;

	/*
	 * If the section this relocation is against has been discarded
	 * (-zignore), then also discard (skip) the relocation itself.
	 */
	if (orsp->rel_isdesc && ((orsp->rel_flags &
	    (FLG_REL_GOT | FLG_REL_BSS | FLG_REL_PLT | FLG_REL_NOINFO)) == 0) &&
	    (orsp->rel_isdesc->is_flags & FLG_IS_DISCARD)) {
		DBG_CALL(Dbg_reloc_discard(ofl->ofl_lml, M_MACH, orsp));
		return (1);
	}

	/*
	 * If this is a relocation against a move table, or expanded move
	 * table, adjust the relocation entries.
	 */
	if (RELAUX_GET_MOVE(orsp))
		ld_adj_movereloc(ofl, orsp);

	/*
	 * If this is a relocation against a section then we need to adjust the
	 * raddend field to compensate for the new position of the input section
	 * within the new output section.
	 */
	if (ELF_ST_TYPE(sdp->sd_sym->st_info) == STT_SECTION) {
		if (ofl->ofl_parsyms &&
		    (sdp->sd_isc->is_flags & FLG_IS_RELUPD) &&
		    /* LINTED */
		    (psym = ld_am_I_partial(orsp, orsp->rel_raddend))) {
			DBG_CALL(Dbg_move_outsctadj(ofl->ofl_lml, psym));
			sectmoved = 1;
			if (ofl->ofl_flags & FLG_OF_RELOBJ)
				raddend = psym->sd_sym->st_value;
			else
				raddend = psym->sd_sym->st_value -
				    psym->sd_isc->is_osdesc->os_shdr->sh_addr;
			/* LINTED */
			raddend += (Off)_elf_getxoff(psym->sd_isc->is_indata);
			if (psym->sd_isc->is_shdr->sh_flags & SHF_ALLOC)
				raddend +=
				    psym->sd_isc->is_osdesc->os_shdr->sh_addr;
		} else {
			/* LINTED */
			raddend += (Off)_elf_getxoff(sdp->sd_isc->is_indata);
			if (sdp->sd_isc->is_shdr->sh_flags & SHF_ALLOC)
				raddend +=
				    sdp->sd_isc->is_osdesc->os_shdr->sh_addr;
		}
	}

	value = sdp->sd_sym->st_value;

	if (orsp->rel_flags & FLG_REL_GOT) {
		/*
		 * XXXAARCH64: amd64 discards the addend here
		 * This is done since the addend was relevant to
		 * the reference, not the data item being referenced.
		 * TODO: check sparcv9
		 */
		raddend = 0;
		osp = ofl->ofl_osgot;
		roffset = ld_calc_got_offset(orsp, ofl);
	} else if (orsp->rel_flags & FLG_REL_PLT) {
		/*
		 * Note that relocations for PLTs actually cause a relocation
		 * against the GOT
		 */
		osp = ofl->ofl_osplt;
		roffset = (ofl->ofl_osgot->os_shdr->sh_addr) +
		    sdp->sd_aux->sa_PLTGOTndx * M_GOT_ENTSIZE;
		/* XXXAARCH64: check this */
		raddend = 0;
		if (plt_entry(ofl, sdp) == S_ERROR)
			return (S_ERROR);
	} else if (orsp->rel_flags & FLG_REL_BSS) {
		/*
		 * This must be an R_AARCH64_COPY.  For these set the roffset to
		 * point to the new symbol's location.
		 */
		osp = ofl->ofl_isbss->is_osdesc;
		roffset = value;

		/*
		 * XXXAARCH64: check this
		 * The raddend doesn't mean anything in a R_AARCH64_COPY
		 * relocation.  Null it out because it can confuse people.
		 */
		raddend = 0;
	} else {
		osp = RELAUX_GET_OSDESC(orsp);

		/*
		 * Calculate virtual offset of reference point; equals offset
		 * into section + vaddr of section for loadable sections, or
		 * offset plus section displacement for nonloadable sections.
		 */
		roffset = orsp->rel_roffset +
		    (Off)_elf_getxoff(orsp->rel_isdesc->is_indata);
		if (!(ofl->ofl_flags & FLG_OF_RELOBJ))
			roffset += orsp->rel_isdesc->is_osdesc->
			    os_shdr->sh_addr;
	}

	if ((osp == NULL) || ((relosp = osp->os_relosdesc) == NULL))
		relosp = ofl->ofl_osrel;

	/*
	 * Assign the symbols index for the output relocation.  If the
	 * relocation refers to a SECTION symbol then it's index is based upon
	 * the output sections symbols index.  Otherwise the index can be
	 * derived from the symbols index itself.
	 */
	if (orsp->rel_rtype == R_AARCH64_RELATIVE) {
		ndx = STN_UNDEF;
	} else if ((orsp->rel_flags & FLG_REL_SCNNDX) ||
	    (ELF_ST_TYPE(sdp->sd_sym->st_info) == STT_SECTION)) {
		if (sectmoved == 0) {
			/*
			 * Check for a null input section.  This can occur if
			 * this relocation references a symbol generated by
			 * sym_add_sym()
			 */
			if (sdp->sd_isc && sdp->sd_isc->is_osdesc)
				ndx = sdp->sd_isc->is_osdesc->os_identndx;
			else
				ndx = sdp->sd_shndx;
		} else
			ndx = ofl->ofl_parexpnndx;
	} else
		ndx = sdp->sd_symndx;

	/*
	 * Add the symbol's 'value' to the addend field.
	 */
	if (orsp->rel_flags & FLG_REL_ADVAL)
		raddend += value;

#if 0
	/*
	 * XXXAARCH64: check this
	 * The addend field for R_AARCH64_TLS_DTPMOD means nothing.  The addend
	 * is propagated in the corresponding R_AMD64_DTPOFF64 relocation.
	 */
	if (orsp->rel_rtype == R_AARCH64_TLS_DTPMOD)
		raddend = 0;
#endif

	if ((orsp->rel_rtype != M_R_NONE) &&
	    (orsp->rel_rtype != M_R_RELATIVE)) {
		if (ndx == 0) {
			Conv_inv_buf_t	inv_buf;
			Is_desc *isp = orsp->rel_isdesc;

			ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_REL_NOSYMBOL),
			    conv_reloc_type(ofl->ofl_nehdr->e_machine,
			    orsp->rel_rtype, 0, &inv_buf),
			    isp->is_file->ifl_name, EC_WORD(isp->is_scnndx),
			    isp->is_name, EC_XWORD(roffset));
			return (S_ERROR);
		}
	}

	rea.r_info = ELF_R_INFO(ndx, orsp->rel_rtype);
	rea.r_offset = roffset;
	rea.r_addend = raddend;
	DBG_CALL(Dbg_reloc_out(ofl, ELF_DBG_LD, SHT_RELA, &rea, relosp->os_name,
	    ld_reloc_sym_name(orsp)));

	/*
	 * Assert we haven't walked off the end of our relocation table.
	 */
	assert(relosp->os_szoutrels <= relosp->os_shdr->sh_size);

	relbits = (char *)relosp->os_outdata->d_buf;

	(void) memcpy((relbits + relosp->os_szoutrels),
	    (char *)&rea, sizeof (Rela));
	relosp->os_szoutrels += (Xword)sizeof (Rela);

	/*
	 * Determine if this relocation is against a non-writable, allocatable
	 * section.  If so we may need to provide a text relocation diagnostic.
	 * Note that relocations against the .plt (R_AARCH64_JUMP_SLOT) actually
	 * result in modifications to the .got.
	 */
	if (orsp->rel_rtype == R_AARCH64_JUMP_SLOT)
		osp = ofl->ofl_osgot;

	ld_reloc_remain_entry(orsp, osp, ofl, remain_seen);
	return (1);
}

static Fixupret
tls_fixups(Ofl_desc *ofl, Rel_desc *arsp)
{
	assert(0 && "Relocation claiming to need TLS fixups");
	return (FIX_ERROR);
}

#if 0
#define	MYDEBUG_ACTIVE	1
#define	MYDBG(X)	do {						\
	if (arsp->rel_rtype == R_AARCH64_ADR_PREL_LO21 ||		\
	    arsp->rel_rtype == R_AARCH64_ADR_PREL_PG_HI21) {		\
		printf X;						\
		fflush(stdout);						\
	}								\
} while (0)
#else
#undef	MYDEBUG_ACTIVE
#define	MYDBG(X)
#endif

/*
 * XXX: this is pretty horrible!  I'm going to rewrite this mess of conditionals
 *      to simply perform the calculations in aaelf64.
 *
 * Our goal here is simple, work out X!
 *
 * X is the result of a relocation operation, before any masking or
 * bit-selection operation is applied
 *
 * Relocation operations:
 * S			(when used on its own) is the (linked) address of the
 *			symbol.
 * A			is the addend for the relocation.
 * P			is the (linked) address of the place being relocated
 *			(derived from r_offset).
 * Page(expr)		is the page address of the expression expr, defined as
 *			(expr & ~0xFFF).
 * GOT			is the address of the Global Offset Table, the table of
 *			code and data addresses to be resolved at dynamic link
 *			time. The GOT and each entry in it must be, 64-bit
 *			aligned for ELF64 or 32-bit aligned for ELF32.
 * GDAT(S+A)		represents a pointer-sized entry in the GOT for address
 *			S+A. The entry will be relocated at run time with
 *			relocation R_<CLS>_GLOB_DAT(S+A).
 * G(expr)		is the address of the GOT entry for the expression expr.
 * Delta(S)		if S is a normal symbol, resolves to the difference
 *			between the static link address of S and the execution
 *			address of S. If S is the null symbol (ELF symbol index
 *			0), resolves to the difference between the static link
 *			address of P and the execution address of P.
 * Indirect(expr)	represents the result of calling expr as a function. The
 *			result is the return value from the function that is
 *			returned in r0. The arguments passed to the function are
 *			defined by the platform ABI.
 *
 * Relocation operations for Thread Local Storage:
 * GLDM(S)		represents a consecutive pair of pointer-sized entries
 *			in the GOT for the load module index of the symbol S.
 *			The first pointer-sized entry will be relocated with
 *			R_<CLS>_TLS_DTPMOD(S); the second pointer-sized entry
 *			will contain the constant 0.
 * GTLSIDX(S,A)		represents a consecutive pair of pointer-sized entries
 *			in the GOT. The entry contains a tls_index structure
 *			describing the thread-local variable located at offset A
 *			from thread-local symbol S. The first pointer-sized
 *			entry will be relocated with R_<CLS>_TLS_DTPMOD(S), the
 *			second pointer-sized entry will be relocated with
 *			R_<CLS>_TLS_DTPREL(S+A).
 * GTPREL(S+A)		represents a pointer-sized entry in the GOT for the
 *			offset from the current thread pointer (TP) of the
 *			thread-local variable located at offset A from the
 *			symbol S. The entry will be relocated with
 *			R_<CLS>_TLS_TPREL(S+A).
 * GTLSDESC(S+A)	represents a consecutive pair of pointer-sized entries
 *			in the GOT which contain a tlsdesc structure describing
 *			the thread-local variable located at offset A from
 *			thread-local symbol S. The first entry holds a pointer
 *			to the variable's TLS descriptor resolver function and
 *			the second entry holds a platform-specific offset or
 *			pointer. The pair of pointer-sized entries will be
 *			relocated with R_<CLS>_TLSDESC(S+A).
 * LDM(S)		resolves to the load module index of the symbol S.
 * DTPREL(S+A)		resolves to the offset from its module's TLS block of
 *			the thread local variable located at offset A from
 *			thread-local symbol S.
 * TPREL(S+A)		resolves to the offset from the current thread pointer
 *			(TP) of the thread local variable located at offset A
 *			from thread-local symbol S.
 * TLSDESC(S+A)		resolves to a contiguous pair of pointer-sized values,
 *			as created by GTLSDESC(S+A).
 */
/*
 *  A is simply rel_raddend, but there's a little fiddling to get it pointed to
 *	the output section.  Specifically, if the symbol points to a section
 *	(STT_SECTION) and the XXX flags include FLG_IS_RELUPD _and_ the symbol
 *	is partial, then the value is saved from the symbol, and the addend is
 *	updated to reflect the moved symbol displacement.  From this point on
 *	the rel_raddend field is read-only.
 *  S is simply the symbol value, but as with A it needs to be pointed to the
 *	output file virtual addresses.  There's a _lot_ of code that tries to
 *	tweak this based on various flags, but we ultimately end up with the
 *	value as 'A' (but need to ensure that it's not trying to deal with too
 *	many calculations).
 *
 * Simple S + A Relocaitons
 *  R_AARCH64_ABS64
 *  R_AARCH64_ABS32
 *  R_AARCH64_P32_ABS32
 *  R_AARCH64_ABS16
 *  R_AARCH64_P32_ABS16
 *  R_AARCH64_MOVW_UABS_G0
 *  R_AARCH64_P32_MOVW_UABS_G0
 *  R_AARCH64_MOVW_UABS_G0_NC
 *  R_AARCH64_P32_MOVW_UABS_G0_NC
 *  R_AARCH64_MOVW_UABS_G1
 *  R_AARCH64_P32_MOVW_UABS_G1
 *  R_AARCH64_MOVW_UABS_G1_NC
 *  R_AARCH64_MOVW_UABS_G2
 *  R_AARCH64_MOVW_UABS_G2_NC
 *  R_AARCH64_MOVW_UABS_G3
 *  R_AARCH64_MOVW_SABS_G0
 *  R_AARCH64_P32_MOVW_SABS_G0
 *  R_AARCH64_MOVW_SABS_G1
 *  R_AARCH64_MOVW_SABS_G2
 *  R_AARCH64_ADD_ABS_LO12_NC
 *  R_AARCH64_P32_ADD_ABS_LO12_NC
 *  R_AARCH64_LDST8_ABS_LO12_NC
 *  R_AARCH64_P32_LDST8_ABS_LO12_NC
 *  R_AARCH64_LDST16_ABS_LO12_NC
 *  R_AARCH64_P32_LDST16_ABS_LO12_NC
 *  R_AARCH64_LDST32_ABS_LO12_NC
 *  R_AARCH64_P32_LDST32_ABS_LO12_NC
 *  R_AARCH64_LDST64_ABS_LO12_NC
 *  R_AARCH64_P32_LDST64_ABS_LO12_NC
 *  R_AARCH64_LDST128_ABS_LO12_NC
 *  R_AARCH64_P32_LDST128_ABS_LO12_NC
 *  (dynamic) R_ARCH64_GLOB_DAT
 *  (dynamic) R_AARCH64_P32_GLOB_DAT
 *  (dynamic) R_ARCH64_JUMP_SLOT
 *  (dynamic) R_AARCH64_P32_JUMP_SLOT
 *
 * S + A - P Relocations
 *  R_AARCH64_PREL64
 *  R_AARCH64_PREL32
 *  R_AARCH64_P32_PREL32
 *  R_AARCH64_PREL16
 *  R_AARCH64_P32_PREL16
 *  R_AARCH64_PLT32
 *  R_AARCH64_P32_PLT32
 *  R_<CLS>_LD_PREL_LO19
 *  R_<CLS>_ADR_PREL_LO21
 *  R_<CLS>_TSTBR14
 *  R_<CLS>_CONDBR19
 *  R_<CLS>_JUMP26
 *  R_<CLS>_CALL26
 *  R_<CLS>_MOVW_PREL_G0
 *  R_<CLS>_MOVW_PREL_G0_NC
 *  R_<CLS>_MOVW_PREL_G1
 *  R_<CLS>_MOVW_PREL_G1_NC
 *  R_<CLS>_MOVW_PREL_G2
 *  R_<CLS>_MOVW_PREL_G2_NC
 *  R_<CLS>_MOVW_PREL_G3
 */
static uintptr_t
ld_do_one_activereloc(Ofl_desc *ofl, Rel_desc *arsp, Gotref gref)
{
	uchar_t		*addr;
	Xword		value;
	Sym_desc	*sdp;
	const char	*ifl_name;
	Xword		refaddr;
	Os_desc		*osp;
	int		moved = 0;
	uintptr_t	return_code = 1;
	ofl_flag_t	flags = ofl->ofl_flags;

	MYDBG(("%s: ELF_ST_TYPE is %u, rel_flags is 0x%08x, rel_roffset is "
	    "0x%08x (%d)\n", __func__,
	    ELF_ST_TYPE(arsp->rel_sym->sd_sym->st_info),
	    arsp->rel_flags, arsp->rel_roffset, arsp->rel_roffset));

	sdp = arsp->rel_sym;

	if (ELF_ST_TYPE(arsp->rel_sym->sd_sym->st_info) == STT_SECTION &&
	    !((arsp->rel_flags & FLG_REL_CLVAL) ||
	    (arsp->rel_flags & FLG_REL_GOTCL))) {
		Sym_desc	*sym;

		/*
		 * The value for a symbol pointing to a SECTION
		 * is based off of that sections position.
		 */
		if (sdp && (sdp->sd_isc->is_flags & FLG_IS_RELUPD) &&
		    /* LINTED */
		    (sym = ld_am_I_partial(arsp, arsp->rel_raddend))) {
			/*
			 * The symbol was moved, so adjust the value
			 * relative to the new section.
			 */
			MYDBG(("%s: value decided by condition 2.1\n",
			    __func__));
			value = sym->sd_sym->st_value;
			moved = 1;

			/*
			 * The original raddend covers the displacement
			 * from the section start to the desired
			 * address. The value computed above gets us
			 * from the section start to the start of the
			 * symbol range. Adjust the old raddend to
			 * remove the offset from section start to
			 * symbol start, leaving the displacement
			 * within the range of the symbol.
			 */
			arsp->rel_raddend -= sym->sd_osym->st_value;
		}
	}

	refaddr = arsp->rel_roffset +
	    (Off)_elf_getxoff(arsp->rel_isdesc->is_indata);
	MYDBG(("%s: refaddr starts as 0x%llx (rel_roffset: 0x%llx, xoff: "
	    "0x%llx)\n", __func__, refaddr, arsp->rel_roffset,
	    (Off)_elf_getxoff(arsp->rel_isdesc->is_indata)));

	if ((arsp->rel_flags & FLG_REL_CLVAL) ||
	    (arsp->rel_flags & FLG_REL_GOTCL)) {
		value = 0;
		MYDBG(("%s: value decided by condition 1\n", __func__));
	} else if (ELF_ST_TYPE(sdp->sd_sym->st_info) == STT_SECTION) {
		if (moved != 1) {
			MYDBG(("%s: value decided by condition 2.2\n",
			    __func__));
			value = _elf_getxoff(sdp->sd_isc->is_indata);
			MYDBG(("%s: sdp->sd_isc->is_indata is 0x%llx\n",
			    __func__, sdp->sd_isc->is_indata));
			if (sdp->sd_isc->is_shdr->sh_flags & SHF_ALLOC) {
				value += sdp->sd_isc->is_osdesc->
				    os_shdr->sh_addr;
				MYDBG(("%s: adjusted value to the output "
				    "section address, now 0x%llx\n",
				    __func__, value));
			} else {
				MYDBG(("%s: value is not an alloc section, "
				    "remains as 0x%llx\n",
				    __func__, value));
			}
		}
		if (sdp->sd_isc->is_shdr->sh_flags & SHF_TLS) {
			value -= ofl->ofl_tlsphdr->p_vaddr;
			MYDBG(("%s: value adjusted by condition 2.3\n",
			    __func__));
		}

	} else if (IS_SIZE(arsp->rel_rtype)) {
		/*
		 * Size relocations require the symbol's size.
		 */
		value = sdp->sd_sym->st_size;
		MYDBG(("%s: value decided by condition 3\n", __func__));

	} else if ((sdp->sd_flags & FLG_SY_CAP) &&
	    sdp->sd_aux && sdp->sd_aux->sa_PLTndx) {
		/*
		 * If relocation is against a capabilities symbol, we
		 * need to jump to an associated PLT, so that at runtime
		 * ld.so.1 is involved to determine the best binding
		 * choice. Otherwise, the value is the symbols value.
		 */
		value = ld_calc_plt_addr(sdp, ofl);
		MYDBG(("%s: value decided by condition 4\n", __func__));
	} else {
		value = sdp->sd_sym->st_value;
		MYDBG(("%s: value decided by condition 5 (sym value)\n",
		    __func__));
	}

	MYDBG(("%s: value starts as 0x%llx\n", __func__, value));

	/*
	 * Relocation against the GLOBAL_OFFSET_TABLE
	 */
	if ((arsp->rel_flags & FLG_REL_GOT) &&
	    !ld_reloc_set_aux_osdesc(ofl, arsp, ofl->ofl_osgot))
		return (S_ERROR);
	osp = RELAUX_GET_OSDESC(arsp);

	/*
	 * If loadable and not producing a relocatable object add the
	 * sections virtual address to the reference address.
	 */
	if ((arsp->rel_flags & FLG_REL_LOAD) &&
	    ((flags & FLG_OF_RELOBJ) == 0)) {
		MYDBG(("%s: adjusting refaddr (0x%llx) by adding output section"
		    " address (0x%llx)\n", __func__, refaddr,
		    arsp->rel_isdesc->is_osdesc->os_shdr->sh_addr));
		refaddr += arsp->rel_isdesc->is_osdesc->
		    os_shdr->sh_addr;
		MYDBG(("%s: refaddr adjusted to 0x%llx (relocatable, "
		    "loadable)\n", __func__, refaddr));
	}

	MYDBG(("%s: P is 0x%llx (0x%llu)\n", __func__, refaddr, refaddr));

	/*
	 * If this entry has a PLT assigned to it, its value is actually
	 * the address of the PLT (and not the address of the function).
	 */
	if (IS_PLT(arsp->rel_rtype)) {
		MYDBG(("%s: rtype is PLT, sd_aux is 0x%p\n",
		    __func__, sdp->sd_aux));
#if defined(MYDEBUG_ACTIVE)
		if (sdp->sd_aux)
			MYDBG(("%s:   sdp->sd_aux->sa_PLTndx is %u\n",
			    __func__, sdp->sd_aux->sa_PLTndx));
#endif
		if (sdp->sd_aux && sdp->sd_aux->sa_PLTndx) {
			value = ld_calc_plt_addr(sdp, ofl);
			MYDBG(("%s: value pointed to plt address instead of "
			    "function address: 0x%llx\n", __func__, value));
		}
	}

	/*
	 * Add relocations addend to value.  Add extra
	 * relocation addend if needed.
	 *
	 * XXXAARCH64: check this
	 * Note: For GOT relative relocations on aarch64 we discard the
	 * addend.  It was relevant to the reference - not to the
	 * data item being referenced (ie: that -4 thing).
	 *
	 * On aarch64 we use non-GOT-relative relocations for low page bits (got
	 * page offset),
	 * and we still need to deal with Page(expr) macros.
	 *
	 * XXXAARCH64: add a FLG_REL_LOW_PAGE_BITS_ONLY or something more sanely
	 * named
	 */
#if 1
	if ((arsp->rel_flags & FLG_REL_GOT) == 0) {
		MYDBG(("%s: S = %llu (0x%llx), A = %lld (0x%llx)\n", __func__,
		    value, value, arsp->rel_raddend, arsp->rel_raddend));
		MYDBG(("%s: value: 0x%llx (%llu), addend 0x%llx (%lld)\n",
		    __func__, value, value, arsp->rel_raddend,
		    arsp->rel_raddend));
		value += arsp->rel_raddend;
		MYDBG(("%s: value adjusted by the addend (%lld), now 0x%llx "
		    "(%lld)\n", __func__, arsp->rel_raddend, value, value));
	} else {
		MYDBG(("%s: got-relative, discarding addend, still 0x%llx\n",
		    __func__, value));
		MYDBG(("%s: S = %llu (0x%llx), A = %lld (0x%llx)\n",
		    __func__, value, value, 0, 0));
	}

	if (IS_PAGEPC(arsp->rel_rtype)) {
		MYDBG(("%s: page pc-relative detected, tweaking S+A to "
		    "Page(S+A)\n", __func__));
		value = AARCH64_PAGE(value);
		MYDBG(("%s: value: 0x%llx (%llu)\n", __func__, value, value));
	}
#endif

	/*
	 * Determine whether the value needs further adjustment. Filter
	 * through the attributes of the relocation to determine what
	 * adjustment is required.  Note, many of the following cases
	 * are only applicable when a .got is present.  As a .got is
	 * not generated when a relocatable object is being built,
	 * any adjustments that require a .got need to be skipped.
	 */
	if ((arsp->rel_flags & FLG_REL_GOT) &&
	    ((flags & FLG_OF_RELOBJ) == 0)) {
		Xword		R1addr;
		uintptr_t	R2addr;
		Word		gotndx;
		Gotndx		*gnp;

		MYDBG(("%s: relocating directly against the GOT\n", __func__));
		/*
		 * Perform relocation against GOT table. Since this
		 * doesn't fit exactly into a relocation we place the
		 * appropriate byte in the GOT directly.
		 *
		 * Calculate offset into GOT at which to apply the
		 * relocation.
		 */
		gnp = ld_find_got_ndx(sdp->sd_GOTndxs, gref, ofl, arsp);
		assert(gnp);

		/* XXXAARCH64: port me */
#if 0
		if (arsp->rel_rtype == R_AMD64_DTPOFF64)
			gotndx = gnp->gn_gotndx + 1;
		else
#endif
			gotndx = gnp->gn_gotndx;

		R1addr = (Xword)(gotndx * M_GOT_ENTSIZE);

		MYDBG(("%s: gotndx <%u>, M_GOT_ENTSIZE <%u>, R1addr <0x%llx>\n",
		    __func__, gotndx, M_GOT_ENTSIZE, R1addr));

		/*
		 * Add the GOT's data offset.
		 */
		R2addr = R1addr + (uintptr_t)osp->os_outdata->d_buf;

		DBG_CALL(Dbg_reloc_doact(ofl->ofl_lml, ELF_DBG_LD_ACT,
		    M_MACH, SHT_RELA, arsp, R1addr, value,
		    ld_reloc_sym_name));

		MYDBG(("%s: writing value <0x%x> to GOT index %u\n",
		    __func__, value, gotndx));
		/*
		 * And do it.
		 */
		if (ofl->ofl_flags1 & FLG_OF1_ENCDIFF)
			*(Xword *)R2addr = ld_bswap_Xword(value);
		else
			*(Xword *)R2addr = value;
		return (0);

	} else if (IS_GOT_BASED(arsp->rel_rtype) &&
	    ((flags & FLG_OF_RELOBJ) == 0)) {
		value -= ofl->ofl_osgot->os_shdr->sh_addr;
		MYDBG(("%s: GOT-based relocation, value adjusted to 0x%llx\n",
		    __func__, value));

	} else if (IS_GOTPCREL(arsp->rel_rtype) &&
	    ((flags & FLG_OF_RELOBJ) == 0)) {
		Gotndx	*gnp;

		/*
		 * AARCH64: check this: Calculation:
		 * 	G + GOT + A - P
		 */
		gnp = ld_find_got_ndx(sdp->sd_GOTndxs, gref, ofl, arsp);
		assert(gnp);
		value = (Xword)(ofl->ofl_osgot->os_shdr->sh_addr) +
		    ((Xword)gnp->gn_gotndx * M_GOT_ENTSIZE) +
		    arsp->rel_raddend - refaddr;
		MYDBG(("%s: GOT-pc-relative relocation, value adjusted to "
		    "0x%llx\n", __func__, value));

	} else if (IS_GOT_PC(arsp->rel_rtype) &&
	    ((flags & FLG_OF_RELOBJ) == 0)) {
		value = (Xword)(ofl->ofl_osgot->os_shdr->sh_addr) -
		    refaddr + arsp->rel_raddend;
		MYDBG(("%s: GOT-pc relocation, value adjusted to 0x%llx\n",
		    __func__, value));

	} else if ((IS_PC_RELATIVE(arsp->rel_rtype)) &&
	    (((flags & FLG_OF_RELOBJ) == 0) ||
	    (osp == sdp->sd_isc->is_osdesc))) {
		if (IS_PAGEPC(arsp->rel_rtype)) {
			MYDBG(("%s: page pc relative relocation, subtracting "
			    "the place (Page(S+A) = 0x%llx, "
			    "Page(P) = 0x%llx)\n",
			    __func__, value, AARCH64_PAGE(refaddr)));
			value -= AARCH64_PAGE(refaddr);
			MYDBG(("%s: page pc relative relocation, value "
			    "adjusted to 0x%llx "
			    "(%lld)\n", __func__, value, value));
		} else {
			MYDBG(("%s: pc relative relocation, subtracting the "
			    "place (S+A = 0x%llx, P = 0x%llx)\n",
			    __func__, value, refaddr));
			value -= refaddr;
			MYDBG(("%s: pc relative relocation, value adjusted "
			    "to 0x%llx " "(%lld)\n", __func__, value, value));
		}

	} else if (IS_TLS_INS(arsp->rel_rtype) &&
	    IS_GOT_RELATIVE(arsp->rel_rtype) &&
	    ((flags & FLG_OF_RELOBJ) == 0)) {
		assert(0 && "TLS_INS active relocation unimplemented");
		Gotndx	*gnp;

		gnp = ld_find_got_ndx(sdp->sd_GOTndxs, gref, ofl, arsp);
		assert(gnp);
		value = (Xword)gnp->gn_gotndx * M_GOT_ENTSIZE;

	} else if (IS_GOT_RELATIVE(arsp->rel_rtype) &&
	    ((flags & FLG_OF_RELOBJ) == 0)) {
		Gotndx *gnp;

		gnp = ld_find_got_ndx(sdp->sd_GOTndxs, gref, ofl, arsp);
		assert(gnp);
		/* in aarch64 this is GDAT(S+A), which is never used alone... */
		value = (Xword)gnp->gn_gotndx * M_GOT_ENTSIZE;
		/*
		 * ... it's always G(GDAT(S+A))...
		 * G(expr) where expr is GDAT(S+A)
		 */
		value += ofl->ofl_osgot->os_shdr->sh_addr;
		MYDBG(("%s: GOT relative relocation, value set to GOT entry: "
		    "0x%llx\n", __func__, value));

		/*
		 * Left hand side is Page(G(GDAT(S+A))) - apply the Page() part
		 * now
		 */
		if (arsp->rel_rtype == R_AARCH64_ADR_GOT_PAGE) {
			MYDBG(("%s _ADR_GOT_PAGE detected, take the page of "
			    "the LHS\n", __func__));
			value = AARCH64_PAGE(value);
		}

		if (arsp->rel_rtype == R_AARCH64_LD64_GOTPAGE_LO15) {
			/*
			 * Right hand side is Page(GOT)
			 */
			MYDBG(("%s: LD64_GOTPAGE_LO15 - subtracting Page(GOT) "
			    "- value starts as 0x%llx, GOT is 0x%p, Page(GOT) "
			    "is 0x%llx\n", __func__,
			    value, ofl->ofl_osgot->os_shdr->sh_addr,
			    AARCH64_PAGE(ofl->ofl_osgot->os_shdr->sh_addr)));
			value -= AARCH64_PAGE(ofl->ofl_osgot->os_shdr->sh_addr);
			MYDBG(("%s: LD64_GOTPAGE_LO15 - value is now 0x%llx\n",
			    __func__, value));
		} else if (arsp->rel_rtype == R_AARCH64_ADR_GOT_PAGE) {
			/*
			 * Right hand side is Page(P)
			 */
			MYDBG(("%s: ADR_GOT_PAGE - subtracting Page(P) - value "
			    "starts as 0x%llx, P is 0x%p, Page(P) is 0x%llx\n",
			    __func__, value, refaddr, AARCH64_PAGE(refaddr)));
			value -= AARCH64_PAGE(refaddr);
			MYDBG(("%s: ADR_GOT_PAGE - value is now 0x%llx\n",
			    __func__, value));
		}

	} else if ((arsp->rel_flags & FLG_REL_STLS) &&
	    ((flags & FLG_OF_RELOBJ) == 0)) {
		/* XXXAARCH64: fix me */
		assert(0 && "FLG_REL_STLS unimplemented");
		Xword	tlsstatsize;

		/*
		 * This is the LE TLS reference model.  Static
		 * offset is hard-coded.
		 */
		tlsstatsize = S_ROUND(ofl->ofl_tlsphdr->p_memsz,
		    M_TLSSTATALIGN);

		value = tlsstatsize - value;

		/*
		 * Since this code is fixed up, it assumes a negative
		 * offset that can be added to the thread pointer.
		 */
#if 0
		if (arsp->rel_rtype == R_AMD64_TPOFF32)
			value = -value;
#endif
	}

	if (IS_SEG_RELATIVE(arsp->rel_rtype)) {
		MYDBG(("%s: this is segment relative - FML\n", __func__));
	} else {
		MYDBG(("%s: not segment relative - phew\n", __func__));
	}
#if 0
	if (IS_SEG_RELATIVE(arsp->rel_rtype)) {
		Sg_desc	*oseg = NULL;

		/*
		 * XXXARM: For the NULL symbol and BASE_PREL, we're
		 * meant to act as for _GLOBAL_OFFSET_TABLE_
		 */
		if (sdp->sd_isc == NULL) {
			switch (sdp->sd_aux->sa_symspec) {
			case SDAUX_ID_GOT:
				oseg = ofl->ofl_osgot->os_sgdesc;
				break;
			case SDAUX_ID_PLT:
				oseg = ofl->ofl_osplt->os_sgdesc;
				break;
			case SDAUX_ID_DYN:
				oseg = ofl->ofl_osdynamic->os_sgdesc;
				break;
			default:
				assert(0 &&
				    "unsupported special symbol in "
				    "segment-relative relocation");
			}
		} else {
			oseg = sdp->sd_isc->is_osdesc->os_sgdesc;
		}

		value = oseg->sg_phdr.p_vaddr - refaddr;
	}
#endif

	if (arsp->rel_isdesc->is_file)
		ifl_name = arsp->rel_isdesc->is_file->ifl_name;
	else
		ifl_name = MSG_INTL(MSG_STR_NULL);

	/*
	 * Make sure we have data to relocate.  Compiler and assembler
	 * developers have been known to generate relocations against
	 * invalid sections (normally .bss), so for their benefit give
	 * them sufficient information to help analyze the problem.
	 * End users should never see this.
	 */
	if (arsp->rel_isdesc->is_indata->d_buf == NULL) {
		Conv_inv_buf_t	inv_buf;

		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_REL_EMPTYSEC),
		    conv_reloc_aarch64_type(arsp->rel_rtype, 0, &inv_buf),
		    ifl_name, ld_reloc_sym_name(arsp),
		    EC_WORD(arsp->rel_isdesc->is_scnndx),
		    arsp->rel_isdesc->is_name);
		return (S_ERROR);
	}

	/*
	 * Get the address of the data item we need to modify.
	 */
	addr = (uchar_t *)((uintptr_t)arsp->rel_roffset +
	    (uintptr_t)_elf_getxoff(arsp->rel_isdesc->is_indata));

	DBG_CALL(Dbg_reloc_doact(ofl->ofl_lml, ELF_DBG_LD_ACT,
	    M_MACH, SHT_RELA, arsp, EC_NATPTR(addr), value,
	    ld_reloc_sym_name));
	addr += (uintptr_t)osp->os_outdata->d_buf;

	if ((((uintptr_t)addr - (uintptr_t)ofl->ofl_nehdr) >
	    ofl->ofl_size) || (arsp->rel_roffset >
	    osp->os_shdr->sh_size)) {
		Conv_inv_buf_t	inv_buf;
		int		class;

		if (((uintptr_t)addr - (uintptr_t)ofl->ofl_nehdr) >
		    ofl->ofl_size)
			class = ERR_FATAL;
		else
			class = ERR_WARNING;

		ld_eprintf(ofl, class, MSG_INTL(MSG_REL_INVALOFFSET),
		    conv_reloc_aarch64_type(arsp->rel_rtype, 0, &inv_buf),
		    ifl_name, EC_WORD(arsp->rel_isdesc->is_scnndx),
		    arsp->rel_isdesc->is_name, ld_reloc_sym_name(arsp),
		    EC_ADDR((uintptr_t)addr -
		    (uintptr_t)ofl->ofl_nehdr));

		if (class == ERR_FATAL) {
			return (S_ERROR);
		}
	}

	/*
	 * XXXAARCH64: this is a bit iffy
	 * The relocation is additive.  Ignore the previous symbol
	 * value if this local partial symbol is expanded.
	 */
	if (moved) {
		MYDBG(("%s: doing iffy final move adjustment\n", __func__));
		value -= *addr;
	}

	/*
	 * If '-z noreloc' is specified - skip the do_reloc_ld stage.
	 */
	if (OFL_DO_RELOC(ofl)) {
		/*
		 * If this is a PROGBITS section and the running linker
		 * has a different byte order than the target host,
		 * tell do_reloc_ld() to swap bytes.
		 */
		if (do_reloc_ld(arsp, addr, &value, ld_reloc_sym_name,
		    ifl_name, OFL_SWAP_RELOC_DATA(ofl, arsp),
		    ofl->ofl_lml) == 0) {
			ofl->ofl_flags |= FLG_OF_FATAL;
			return (S_ERROR);
		}
	}

	return (return_code);
}

/*
 * The way we handle relocations takes a bit of explaining, in comparison to
 * how the AEABI documents (and most others) document them.
 *
 * ld_do_activerlocs handles active (in the AEABI document "static")
 * relocations.  That is relocations which are resolved in or under this call
 * by the link-editor.
 *
 * There are also output relocations, in the AEABI document "dynamic"
 * relocations, those placed into the output image and resolved by the linker
 * at runtime.  You should see ld_add_outrel and ld_perform_outreloc for
 * descriptions of these.
 *
 * Support for actually performing relocations is split into two parts.  This
 * function (and counterparts in rtld and krtld) calculate the relocation's
 * value, without reference to the addend.  The other part, implemented as a
 * common do_reloc_* function (with 3 names, based on the linker using it),
 * actually includes the addend and updates the output location. (this code is
 * in uts/arm/krtld).
 *
 * This code, given: R_ARM_CALL == (((S + A) | T) - P)
 *
 * decomposes that into X = (S + A) (calculated in this function), and X + A
 * (calculated by do_reloc).
 *
 * T is always 0, except in the case of Thumb interworking, which we do not
 * support (if we wanted to support it, note that T always sets the low bit,
 * so is safely decomposable.)
 *
 * XXXARM: This code is, largely, taken after the intel implementation with
 * which we share sufficient similarily.  This means that there is support for
 * certain relocations here which we have not actually seen generated or used
 * yet.  While that code is _probably_ right, it is not _definitely_ right.
 */
/*
 * R_AARCH64_JUMP26		S+A-P		X=S-P, X+A (overflow check etc.)
 *  ^^ sets a branch immediate to bits [27:2] of X; check that -2^27 <= X < 2^27
 */
static uintptr_t
ld_do_activerelocs(Ofl_desc *ofl)
{
	Rel_desc	*arsp;
	Rel_cachebuf	*rcbp;
	Aliste		idx;
	uintptr_t	return_code = 1;

	if (aplist_nitems(ofl->ofl_actrels.rc_list) != 0)
		DBG_CALL(Dbg_reloc_doact_title(ofl->ofl_lml));

	/*
	 * Process active relocations
	 */
	REL_CACHE_TRAVERSE(&ofl->ofl_actrels, idx, rcbp, arsp) {
		Gotref		gref;
#if defined(MYDEBUG_ACTIVE)
		Conv_inv_buf_t	inv_buf;
#endif

		if (arsp->rel_rtype == R_AARCH64_NONE ||
		    arsp->rel_rtype == R_AARCH64_NONE_WITHDRAWN)
			continue;

		MYDBG(("%s: >>> processing reloc %s (%u)\n", __func__,
		    conv_reloc_aarch64_type(arsp->rel_rtype, 0, &inv_buf),
		    arsp->rel_rtype));

		/*
		 * If the section this relocation is against has been discarded
		 * (-zignore), then discard (skip) the relocation itself.
		 */
		if ((arsp->rel_isdesc->is_flags & FLG_IS_DISCARD) &&
		    ((arsp->rel_flags & (FLG_REL_GOT | FLG_REL_BSS |
		    FLG_REL_PLT | FLG_REL_NOINFO)) == 0))
			continue;

		/*
		 * We determine what the 'got reference' model (if required)
		 * at this point.  This needs to be done before tls_fixup()
		 * since it may 'transition' our instructions.
		 *
		 * The got table entries have already been assigned,
		 * and we bind to those initial entries.
		 */
		if (arsp->rel_flags & FLG_REL_DTLS) {
			MYDBG(("%s: gref is GOT_REF_TLSGD [FLG_REL_DTLS]\n",
			    __func__));
			gref = GOT_REF_TLSGD;
		} else if (arsp->rel_flags & FLG_REL_MTLS) {
			MYDBG(("%s: gref is GOT_REF_TLSLD [FLG_REL_MTLS]\n",
			    __func__));
			gref = GOT_REF_TLSLD;
		} else if (arsp->rel_flags & FLG_REL_STLS) {
			MYDBG(("%s: gref is GOT_REF_TLSIE [FLG_REL_STLS]\n",
			    __func__));
			gref = GOT_REF_TLSIE;
		} else {
			MYDBG(("%s: gref is GOT_REF_GENERIC\n", __func__));
			gref = GOT_REF_GENERIC;
		}

		/*
		 * Perform any required TLS fixups.
		 */
		if (arsp->rel_flags & FLG_REL_TLSFIX) {
			Fixupret	ret;

			if ((ret = tls_fixups(ofl, arsp)) == FIX_ERROR)
				return (S_ERROR);
			if (ret == FIX_DONE)
				continue;
		}

		/*
		 * If this is a relocation against a move table, or expanded
		 * move table, adjust the relocation entries
		 */
		if (RELAUX_GET_MOVE(arsp))
			ld_adj_movereloc(ofl, arsp);

		if (ld_do_one_activereloc(ofl, arsp, gref) == S_ERROR)
			return_code = S_ERROR;
	}

	return (return_code);
}

/*
 * Record an output relocation to be entered into the output file, update any
 * metadata regarding it, set any dynamic flags as appropriate and provide
 * diagnostics about comprimised displacement.
 *
 * The relocation is actually placed into the output image by
 * ld_perform_outreloc().
 *
 * XXXARM: This is in almost every respect not actually target-specific, and
 * taken from the amd64 implementation.
 */
static uintptr_t
ld_add_outrel(Word flags, Rel_desc *rsp, Ofl_desc *ofl)
{
	Rel_desc	*orsp;
	Sym_desc	*sdp = rsp->rel_sym;

	/*
	 * Static executables *do not* want any relocations against them.
	 * Since our engine still creates relocations against a WEAK UNDEFINED
	 * symbol in a static executable, it's best to disable them here
	 * instead of through out the relocation code.
	 */
	if (OFL_IS_STATIC_EXEC(ofl))
		return (1);

	/*
	 * If the symbol will be reduced, we can't leave outstanding
	 * relocations against it, as nothing will ever be able to satisfy them
	 * (and the symbol won't be in .dynsym.
	 */
	if ((sdp != NULL) &&
	    (sdp->sd_sym->st_shndx == SHN_UNDEF) &&
	    (rsp->rel_rtype != M_R_NONE) &&
	    (rsp->rel_rtype != M_R_RELATIVE)) {
		if (ld_sym_reducable(ofl, sdp))
			return (1);
	}

	/*
	 * If we are adding an output relocation against a section symbol
	 * (non-RELATIVE) then mark that section.  These sections will be
	 * added to the .dynsym symbol table
	 */
	if (sdp && (rsp->rel_rtype != M_R_RELATIVE) &&
	    ((flags & FLG_REL_SCNNDX) ||
	    (ELF_ST_TYPE(sdp->sd_sym->st_info) == STT_SECTION))) {

		/*
		 * If this is a COMMON symbol - no output section exists yet -
		 * (it's created as part of sym_validate()).  So - we mark
		 * here that when it's created it should be tagged with the
		 * FLG_OS_OUTREL flag.
		 */
		if ((sdp->sd_flags & FLG_SY_SPECSEC) &&
		    (sdp->sd_sym->st_shndx == SHN_COMMON)) {
			if (ELF_ST_TYPE(sdp->sd_sym->st_info) != STT_TLS)
				ofl->ofl_flags1 |= FLG_OF1_BSSOREL;
			else
				ofl->ofl_flags1 |= FLG_OF1_TLSOREL;
		} else {
			Os_desc *osp;
			Is_desc *isp = sdp->sd_isc;

			if (isp && ((osp = isp->is_osdesc) != NULL) &&
			    ((osp->os_flags & FLG_OS_OUTREL) == 0)) {
				ofl->ofl_dynshdrcnt++;
				osp->os_flags |= FLG_OS_OUTREL;
			}
		}
	}

	/* Enter it into the output relocation cache */
	if ((orsp = ld_reloc_enter(ofl, &ofl->ofl_outrels, rsp, flags)) == NULL)
		return (S_ERROR);

	if (flags & FLG_REL_GOT)
		ofl->ofl_relocgotsz += (Xword)sizeof (Rela);
	else if (flags & FLG_REL_PLT)
		ofl->ofl_relocpltsz += (Xword)sizeof (Rela);
	else if (flags & FLG_REL_BSS)
		ofl->ofl_relocbsssz += (Xword)sizeof (Rela);
	else if (flags & FLG_REL_NOINFO)
		ofl->ofl_relocrelsz += (Xword)sizeof (Rela);
	else
		RELAUX_GET_OSDESC(orsp)->os_szoutrels += (Xword)sizeof (Rela);

	if (orsp->rel_rtype == M_R_RELATIVE)
		ofl->ofl_relocrelcnt++;

	/*
	 * We don't perform sorting on PLT relocations because they have
	 * already been assigned a PLT index and if we were to sort them we
	 * would have to re-assign the plt indexes.
	 */
	if (!(flags & FLG_REL_PLT))
		ofl->ofl_reloccnt++;

	/*
	 * Ensure a GLOBAL_OFFSET_TABLE is generated if required.
	 */
	if (IS_GOT_REQUIRED(orsp->rel_rtype))
		ofl->ofl_flags |= FLG_OF_BLDGOT;

	/*
	 * Identify and possibly warn of a displacement relocation.
	 */
	if (orsp->rel_flags & FLG_REL_DISP) {
		ofl->ofl_dtflags_1 |= DF_1_DISPRELPND;

		if (ofl->ofl_flags & FLG_OF_VERBOSE)
			ld_disp_errmsg(MSG_INTL(MSG_REL_DISPREL4), orsp, ofl);
	}
	DBG_CALL(Dbg_reloc_ors_entry(ofl->ofl_lml, ELF_DBG_LD, SHT_RELA,
	    M_MACH, orsp));

	return (1);
}


/*
 * Deal with relocations against symbols which are bound locally, as described
 * ld_process_sym_reloc()
 *
 * Symbols which must be bound locally need to be treated specially to make
 * sure that they, post-relocation, actually do refer to their locally
 * appropriate values.  In most cases we end up doing this with an active
 * relocation resolved during the link-edit, if that for some reason can't be
 * done, we emit R_AARCH64_RELATIVE to ensure we reach the right symbol.
 *
 * XXXAARCH64: The implementation here is, again, a carbon copy of the amd64
 * implementation, which is an almost copy of the SPARC implementation (where
 * more relocations avoid R_..._RELATIVE).
 */
static uintptr_t
ld_reloc_local(Rel_desc *rsp, Ofl_desc *ofl)
{
	ofl_flag_t	flags = ofl->ofl_flags;
	Sym_desc	*sdp = rsp->rel_sym;
	Word		shndx = sdp->sd_sym->st_shndx;
	Word		ortype = rsp->rel_rtype;

	/*
	 * XXXAARCH64: Might need to constraint this more, like the block below
	 */
	if ((flags & FLG_OF_RELOBJ) && IS_PAGEPC(rsp->rel_rtype)) {
		return (ld_add_outrel(0, rsp, ofl));
	}

	/*
	 * if ((shared object) and (not pc relative relocation) and
	 *    (not against ABS symbol))
	 * then
	 *	build R_AARCH64_RELATIVE
	 * fi
	 */
	if ((flags & FLG_OF_SHAROBJ) && (rsp->rel_flags & FLG_REL_LOAD) &&
	    !(IS_PC_RELATIVE(rsp->rel_rtype)) && !(IS_SIZE(rsp->rel_rtype)) &&
	    !(IS_GOT_BASED(rsp->rel_rtype)) &&
	    !(rsp->rel_isdesc != NULL &&
	    (rsp->rel_isdesc->is_shdr->sh_type == SHT_SUNW_dof)) &&
	    (((sdp->sd_flags & FLG_SY_SPECSEC) == 0) ||
	    (shndx != SHN_ABS) || (sdp->sd_aux && sdp->sd_aux->sa_symspec))) {

		/*
		 * R_AARCH64_RELATIVE updates a 64bit address, if this
		 * relocation isn't a 64bit binding then we can not
		 * simplify it to a RELATIVE relocation.
		 */
		if (reloc_table[ortype].re_fsize != sizeof (Addr)) {
			return (ld_add_outrel(0, rsp, ofl));
		}

		rsp->rel_rtype = R_AARCH64_RELATIVE;
		if (ld_add_outrel(FLG_REL_ADVAL, rsp, ofl) == S_ERROR)
			return (S_ERROR);
		rsp->rel_rtype = ortype;
		return (1);
	}

	/*
	 * If the relocation is against a 'non-allocatable' section
	 * and we can not resolve it now - then give a warning
	 * message.
	 *
	 * We can not resolve the symbol if either:
	 *	a) it's undefined
	 *	b) it's defined in a shared library and a
	 *	   COPY relocation hasn't moved it to the executable
	 *
	 * Note: because we process all of the relocations against the text
	 *	segment before any others - we known whether or not a copy
	 *	relocation will be generated before we get here (see
	 *	reloc_init()->reloc_segments()).
	 */
	if (!(rsp->rel_flags & FLG_REL_LOAD) &&
	    ((shndx == SHN_UNDEF) ||
	    ((sdp->sd_ref == REF_DYN_NEED) &&
	    ((sdp->sd_flags & FLG_SY_MVTOCOMM) == 0)))) {
		Conv_inv_buf_t	inv_buf;
		Os_desc		*osp = RELAUX_GET_OSDESC(rsp);

		/*
		 * If the relocation is against a SHT_SUNW_ANNOTATE section -
		 * then silently ignore that the relocation cannot be
		 * resolved
		 */
		if (osp && (osp->os_shdr->sh_type == SHT_SUNW_ANNOTATE))
			return (0);
		ld_eprintf(ofl, ERR_WARNING, MSG_INTL(MSG_REL_EXTERNSYM),
		    conv_reloc_aarch64_type(rsp->rel_rtype, 0, &inv_buf),
		    rsp->rel_isdesc->is_file->ifl_name,
		    ld_reloc_sym_name(rsp), osp->os_name);
		return (1);
	}

	/*
	 * Perform relocation.
	 */
	return (ld_add_actrel(0, rsp, ofl));
}

/* ARGSUSED */
static uintptr_t
ld_reloc_TLS(Boolean local, Rel_desc *rsp, Ofl_desc *ofl)
{
	Word		rtype = rsp->rel_rtype;
	Sym_desc	*sdp = rsp->rel_sym;
	ofl_flag_t	flags = ofl->ofl_flags;
	Gotndx		*gnp;

	/*
	 * If we're building an executable - use either the IE or LE access
	 * model.  If we're building a shared object process any IE model.
	 */
	if ((flags & FLG_OF_EXEC) || (IS_TLS_IE(rtype))) {
		/*
		 * Set the DF_STATIC_TLS flag.
		 */
		ofl->ofl_dtflags |= DF_STATIC_TLS;

		if (!local || ((flags & FLG_OF_EXEC) == 0)) {
			/*
			 * Assign a GOT entry for static TLS references.
			 */
			if ((gnp = ld_find_got_ndx(sdp->sd_GOTndxs,
			    GOT_REF_TLSIE, ofl, rsp)) == NULL) {

				if (ld_assign_got_TLS(local, rsp, ofl, sdp,
				    gnp, GOT_REF_TLSIE, FLG_REL_STLS,
				    rtype, R_AARCH64_TLS_TPREL, 0) == S_ERROR)
					return (S_ERROR);
			}

			/*
			 * IE access model.
			 */
			if (IS_TLS_IE(rtype))
				return (ld_add_actrel(FLG_REL_STLS, rsp, ofl));

			assert(0 && "ld_reloc_TLS - fixups not implemented");
			/*
			 * Fixups are required for other executable models.
			 */
			return (ld_add_actrel((FLG_REL_TLSFIX | FLG_REL_STLS),
			    rsp, ofl));
		}

		/*
		 * LE access model.
		 */
		if (IS_TLS_LE(rtype))
			return (ld_add_actrel(FLG_REL_STLS, rsp, ofl));

		return (ld_add_actrel((FLG_REL_TLSFIX | FLG_REL_STLS),
		    rsp, ofl));
	}

	/*
	 * Building a shared object.
	 *
	 * Assign a GOT entry for a dynamic TLS reference.
	 */
	if (IS_TLS_LD(rtype) && ((gnp = ld_find_got_ndx(sdp->sd_GOTndxs,
	    GOT_REF_TLSLD, ofl, rsp)) == NULL)) {

		if (ld_assign_got_TLS(local, rsp, ofl, sdp, gnp, GOT_REF_TLSLD,
		    FLG_REL_MTLS, rtype, R_AARCH64_TLS_DTPMOD, 0) == S_ERROR)
			return (S_ERROR);

	} else if (IS_TLS_GD(rtype) &&
	    ((gnp = ld_find_got_ndx(sdp->sd_GOTndxs, GOT_REF_TLSGD,
	    ofl, rsp)) == NULL)) {

		if (ld_assign_got_TLS(local, rsp, ofl, sdp, gnp, GOT_REF_TLSGD,
		    FLG_REL_DTLS, rtype, R_AARCH64_TLS_DTPMOD,
		    R_AARCH64_TLS_DTPREL) == S_ERROR)
			return (S_ERROR);
	}

	if (IS_TLS_LD(rtype))
		return (ld_add_actrel(FLG_REL_MTLS, rsp, ofl));

	return (ld_add_actrel(FLG_REL_DTLS, rsp, ofl));
}

/*
 * XXXAARCH64: This is taken directly from the amd64 version.
 */
/* ARGSUSED */
static uintptr_t
ld_assign_got_ndx(Alist **alpp, Gotndx *pgnp, Gotref gref, Ofl_desc *ofl,
    Rel_desc *rsp, Sym_desc *sdp)
{
	Xword		raddend;
	Gotndx		gn, *gnp;
	Aliste		idx;
	uint_t		gotents;

	raddend = rsp->rel_raddend;
	if (pgnp && (pgnp->gn_addend == raddend) && (pgnp->gn_gotref == gref))
		return (1);

	if ((gref == GOT_REF_TLSGD) || (gref == GOT_REF_TLSLD))
		gotents = 2;
	else
		gotents = 1;

	gn.gn_addend = raddend;
	gn.gn_gotndx = ofl->ofl_gotcnt;
	gn.gn_gotref = gref;

	ofl->ofl_gotcnt += gotents;

	if (gref == GOT_REF_TLSLD) {
		if (ofl->ofl_tlsldgotndx == NULL) {
			if ((gnp = libld_malloc(sizeof (Gotndx))) == NULL)
				return (S_ERROR);
			(void) memcpy(gnp, &gn, sizeof (Gotndx));
			ofl->ofl_tlsldgotndx = gnp;
		}
		return (1);
	}

	idx = 0;
	for (ALIST_TRAVERSE(*alpp, idx, gnp)) {
		if (gnp->gn_addend > raddend)
			break;
	}

	/*
	 * GOT indexes are maintained on an Alist, where there is typically
	 * only one index.  The use of this list is to scan the list to find
	 * an index, and then apply that index immediately to a relocation.
	 * Thus there are no external references to these GOT index structures
	 * that can be compromised by the Alist being reallocated.
	 */
	if (alist_insert(alpp, &gn, sizeof (Gotndx),
	    AL_CNT_SDP_GOT, idx) == NULL)
		return (S_ERROR);

	return (1);
}

static void
ld_assign_plt_ndx(Sym_desc * sdp, Ofl_desc *ofl)
{
	sdp->sd_aux->sa_PLTndx = 1 + ofl->ofl_pltcnt++;
	sdp->sd_aux->sa_PLTGOTndx = ofl->ofl_gotcnt++;
	ofl->ofl_flags |= FLG_OF_BLDGOT;
}

static uchar_t plt0_template[M_PLT_RESERVSZ] = {
	0xf0, 0x7b, 0xbf, 0xa9, /* stp  x16, x30, [sp,#-16]! */
	0x10, 0x00, 0x00, 0x90, /* adrp x16, Page(&(.plt.got[2])) */
	0x11, 0x02, 0x40, 0xf9, /* ldr  x17, [x16, Offset(&(.plt.got[2]))] */
	0x10, 0x02, 0x00, 0x91, /* add  x16, x16, Offset(&(.plt.got[2])) */
	0x20, 0x02, 0x1f, 0xd6,	/* br   x17 */
	0x1f, 0x20, 0x03, 0xd5, /* nop */
	0x1f, 0x20, 0x03, 0xd5, /* nop */
	0x1f, 0x20, 0x03, 0xd5  /* nop */
};


/* XXXAARCH64: needs porting */
/*
 * Set up the PLT/PLTGOT.
 *
 * Each entry in the PLT is, from the AEABI:
 *
 *	add	ip,  pc, #__PLTGOT(X) & 0x0ff00000
 *	add	ip,  ip, #__PLTGOT(X) & 0x000ff000
 *	ldr	pc, [ip, #__PLTGOT(X) & 0x00000fff]!
 *
 *      adrp    x16, #0x20000
 *      ldr     x17, [x16, #0x468]
 *      add     x16, x16, #0x468
 *      br      x17
 *
 * Where __PLTGOT(X) is the displacement between the GOT entry for X and the
 * PLT entry for X.  Thus, ip = pc+<displacement>, and pc = *ip, branching to
 * the address pointed to by the GOT entry matching this PLT entry.
 *
 * At startup, the GOT entry for every entry in the PLT is the address of
 * plt[0], a reserved entry containing the code:
 *
 *  0xa9bf7bf0    stp    x16, x30, [sp,#-16]!
 *  0x90000010    adrp   x16, Page(&(.plt.got[2]))
 *  0xf9400211    ldr    x17, [x16, Offset(&(.plt.got[2]))]
 *  0x91000210    add    x16, x16, Offset(&(.plt.got[2]))
 *  0xd61f0220    br     x17
 *  0xd503201f    nop
 *  0xd503201f    nop
 *  0xd503201f    nop
 *
 */
/*
 * Initialises .got[0] with the _DYNAMIC symbol value.
 */
static uintptr_t
ld_fillin_gotplt(Ofl_desc *ofl)
{
	int	bswap = (ofl->ofl_flags1 & FLG_OF1_ENCDIFF) != 0;

	if (ofl->ofl_osgot) {
		Sym_desc	*sdp;

		if ((sdp = ld_sym_find(MSG_ORIG(MSG_SYM_DYNAMIC_U),
		    SYM_NOHASH, NULL, ofl)) != NULL) {
			uchar_t	*genptr;

			genptr = ((uchar_t *)ofl->ofl_osgot->os_outdata->d_buf +
			    (M_GOT_XDYNAMIC * M_GOT_ENTSIZE));
			/* LINTED */
			*(Xword *)genptr = sdp->sd_sym->st_value;
			if (bswap)
				/* LINTED */
				*(Xword *)genptr =
				    /* LINTED */
				    ld_bswap_Xword(*(Xword *)genptr);
		}
	}

	if ((ofl->ofl_flags & FLG_OF_DYNAMIC) && ofl->ofl_osplt) {
		uchar_t	*pltent;
		Xword	val1;

		pltent = (uchar_t *)ofl->ofl_osplt->os_outdata->d_buf;
		bcopy(plt0_template, pltent, sizeof (plt0_template));

		/*
		 * If '-z noreloc' is specified - skip the do_reloc_ld
		 * stage.
		 */
		if (!OFL_DO_RELOC(ofl))
			return (1);

		/*
		 * XXXAARCH64: test this
		 */

		/*
		 * patchup:
		 *	adrp   x16, Page(&(.plt.got[2]))
		 */
		val1 = AARCH64_PAGE((ofl->ofl_osgot->os_shdr->sh_addr) +
		    (M_GOT_XRTLD * M_GOT_ENTSIZE)) - AARCH64_PAGE(
		    ofl->ofl_osplt->os_shdr->sh_addr + M_PLT_INSSIZE);

		if (do_reloc_ld(&rdesc_r_aarch64_adr_prel_pg_hi21,
		    &pltent[1 * M_PLT_INSSIZE], &val1, syn_rdesc_sym_name,
		    MSG_ORIG(MSG_SPECFIL_PLTENT), bswap, ofl->ofl_lml) == 0) {
			ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_PLT_PLT0FAIL));
			return (S_ERROR);
		}

		/*
		 * patchup:
		 *	ldr    x17, [x16, Offset(&(.plt.got[2]))]
		 */
		val1 = ofl->ofl_osgot->os_shdr->sh_addr +
		    (M_GOT_XRTLD * M_GOT_ENTSIZE);

		if (do_reloc_ld(&rdesc_r_aarch64_ldst64_abs_lo12_nc,
		    &pltent[2 * M_PLT_INSSIZE], &val1, syn_rdesc_sym_name,
		    MSG_ORIG(MSG_SPECFIL_PLTENT), bswap, ofl->ofl_lml) == 0) {
			ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_PLT_PLT0FAIL));
			return (S_ERROR);
		}

		/*
		 * patchup:
		 *	add    x16, x16, Offset(&(.plt.got[2]))
		 */
		val1 = ofl->ofl_osgot->os_shdr->sh_addr +
		    (M_GOT_XRTLD * M_GOT_ENTSIZE);

		if (do_reloc_ld(&rdesc_r_aarch64_add_abs_lo12_nc,
		    &pltent[3 * M_PLT_INSSIZE], &val1, syn_rdesc_sym_name,
		    MSG_ORIG(MSG_SPECFIL_PLTENT), bswap, ofl->ofl_lml) == 0) {
			ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_PLT_PLT0FAIL));
			return (S_ERROR);
		}
	}

	return (1);
}


/*
 * XXXAARCH64: check byte order of the ret instruction
 * Template for generating "void (*)(void)" function.
 */
static const uchar_t nullfunc_tmpl[] = {
	0x1f, 0x20, 0x03, 0xd5,  /* nop */
	0xd6, 0x5f, 0x03, 0xc0	/* ret */
};


/*
 * XXXAARCH64: maybe provide execfill.
 */

/*
 * XXXAARCH64: this is NULL in amd64.
 */
/* ARGSUSED */
static uintptr_t
ld_reloc_GOTOP(Boolean local, Rel_desc *rsp, Ofl_desc *ofl)
{
	assert(0 && "ld_reloc_GOTOP");
	return (0);
}

const Target *
ld_targ_init_aarch64(void)
{
	static const Target _ld_targ = {
		.t_m = {
			.m_mach			= M_MACH,
			.m_machplus		= M_MACHPLUS,
			.m_flagsplus		= M_FLAGSPLUS,
			.m_class		= M_CLASS,
			.m_data			= M_DATA,

			.m_segm_align		= M_SEGM_ALIGN,
			.m_segm_origin		= M_SEGM_ORIGIN,
			.m_segm_aorigin		= M_SEGM_AORIGIN,
			.m_dataseg_perm		= M_DATASEG_PERM,
			.m_stack_perm		= M_STACK_PERM,
			.m_word_align		= M_WORD_ALIGN,
			.m_def_interp		=
				MSG_ORIG(MSG_PTH_RTLD_AARCH64),

			.m_r_arrayaddr		= M_R_ARRAYADDR,
			.m_r_copy		= M_R_COPY,
			.m_r_glob_dat		= M_R_GLOB_DAT,
			.m_r_jmp_slot		= M_R_JMP_SLOT,
			.m_r_num		= M_R_NUM,
			.m_r_none		= M_R_NONE,
			.m_r_relative		= M_R_RELATIVE,
			.m_r_register		= M_R_REGISTER,

			.m_rel_dt_count		= M_REL_DT_COUNT,
			.m_rel_dt_ent		= M_REL_DT_ENT,
			.m_rel_dt_size		= M_REL_DT_SIZE,
			.m_rel_dt_type		= M_REL_DT_TYPE,
			.m_rel_sht_type		= M_REL_SHT_TYPE,

			.m_got_entsize		= M_GOT_ENTSIZE,
			.m_got_xnumber		= M_GOT_XNumber,

			.m_plt_align		= M_PLT_ALIGN,
			.m_plt_entsize		= M_PLT_ENTSIZE,
			.m_plt_reservsz		= M_PLT_RESERVSZ,
			.m_plt_shf_flags	= M_PLT_SHF_FLAGS,

			.m_sht_unwind		= SHT_PROGBITS,

			.m_dt_register		= M_DT_REGISTER
		},
		.t_id = {
			.id_array	= M_ID_ARRAY,
			.id_bss		= M_ID_BSS,
			.id_cap		= M_ID_CAP,
			.id_capinfo	= M_ID_CAPINFO,
			.id_capchain	= M_ID_CAPCHAIN,
			.id_data	= M_ID_DATA,
			.id_dynamic	= M_ID_DYNAMIC,
			.id_dynsort	= M_ID_DYNSORT,
			.id_dynstr	= M_ID_DYNSTR,
			.id_dynsym	= M_ID_DYNSYM,
			.id_dynsym_ndx	= M_ID_DYNSYM_NDX,
			.id_got		= M_ID_GOT,
			.id_gotdata	= M_ID_UNKNOWN,
			.id_hash	= M_ID_HASH,
			.id_interp	= M_ID_INTERP,
			.id_lbss	= M_ID_UNKNOWN,
			.id_ldynsym	= M_ID_LDYNSYM,
			.id_note	= M_ID_NOTE,
			.id_null	= M_ID_NULL,
			.id_plt		= M_ID_PLT,
			.id_rel		= M_ID_REL,
			.id_strtab	= M_ID_STRTAB,
			.id_syminfo	= M_ID_SYMINFO,
			.id_symtab	= M_ID_SYMTAB,
			.id_symtab_ndx	= M_ID_SYMTAB_NDX,
			.id_text	= M_ID_TEXT,
			.id_tls		= M_ID_TLS,
			.id_tlsbss	= M_ID_TLSBSS,
			.id_unknown	= M_ID_UNKNOWN,
			.id_unwind	= M_ID_UNWIND,
			.id_unwindhdr	= M_ID_UNWINDHDR,
			.id_user	= M_ID_USER,
			.id_version	= M_ID_VERSION,
		},
		.t_nf = {
			.nf_template	= nullfunc_tmpl,
			.nf_size	= sizeof (nullfunc_tmpl),
		},
		.t_ff = {
			/*
			 * XXXAARCH64: This will use 0x0, but we should
			 * probbaly be using a proper NOP (and checking
			 * alignment constraints).
			 */
			.ff_execfill	= NULL,
		},
		.t_mr = {
			.mr_reloc_table			= reloc_table,
			.mr_init_rel			= ld_init_rel,
			.mr_mach_eflags			= ld_mach_eflags,
			.mr_mach_make_dynamic		= ld_mach_make_dynamic,
			.mr_mach_update_odynamic	=
				ld_mach_update_odynamic,
			.mr_calc_plt_addr		= ld_calc_plt_addr,
			.mr_perform_outreloc		= ld_perform_outreloc,
			.mr_do_activerelocs		= ld_do_activerelocs,
			.mr_add_outrel			= ld_add_outrel,
			.mr_reloc_register		= NULL,
			.mr_reloc_local			= ld_reloc_local,
			.mr_reloc_GOTOP			= ld_reloc_GOTOP,
			.mr_reloc_TLS			= ld_reloc_TLS,
			.mr_assign_got			= NULL,
			.mr_find_got_ndx		= ld_find_got_ndx,
			.mr_calc_got_offset		= ld_calc_got_offset,
			.mr_assign_got_ndx		= ld_assign_got_ndx,
			.mr_assign_plt_ndx		= ld_assign_plt_ndx,
			.mr_allocate_got		= NULL,
			.mr_fillin_gotplt		= ld_fillin_gotplt,
		},
		.t_ms = {
			.ms_reg_check		= NULL,
			.ms_mach_sym_typecheck	= NULL,
			.ms_is_regsym		= NULL,
			.ms_reg_find		= NULL,
			.ms_reg_enter		= NULL,
		}
	};

	return (&_ld_targ);
}
