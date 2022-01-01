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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <sys/modctl.h>
#include <sys/dtrace.h>
#include <sys/kobj.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/conf.h>
#include <sys/param.h>
#include <sys/controlregs.h>
#include <vm/hat.h>
#include <sys/privregs.h>
#include <sys/promif.h>

#define	FBT_ENTRY	"entry"
#define	FBT_RETURN	"return"
#define	FBT_ADDR2NDX(addr)	((((uintptr_t)(addr)) >> 4) & fbt_probetab_mask)
#define	FBT_PROBETAB_SIZE	0x8000		/* 32k entries -- 128K total */

#define FBT_PATCHVAL	0xd4200220	// brk #0x11
#define FBT_NOP		0xd503201f
#define FBT_RET		0xd65f03c0

typedef struct fbt_probe {
	struct fbt_probe *fbtp_hashnext;
	uint32_t	*fbtp_patchpoint;
	int		fbtp_rval;
	uint32_t	fbtp_patchval;
	uint32_t	fbtp_savedval;
	uintptr_t	fbtp_roffset;
	dtrace_id_t	fbtp_id;
	char		*fbtp_name;
	struct modctl	*fbtp_ctl;
	int		fbtp_loadcnt;
	int		fbtp_symndx;
	struct fbt_probe *fbtp_next;
} fbt_probe_t;

static dev_info_t		*fbt_devi;
static dtrace_provider_id_t	fbt_id;
static fbt_probe_t		**fbt_probetab;
static int			fbt_probetab_size;
static int			fbt_probetab_mask;
static int			fbt_verbose = 0;

static int
fbt_invop(uintptr_t addr, uintptr_t *stack, uintptr_t rval)
{
	fbt_probe_t *fbt = fbt_probetab[FBT_ADDR2NDX(addr)];
	struct regs *rp = (struct regs *)stack;

	for (; fbt != NULL; fbt = fbt->fbtp_hashnext) {
		if ((uintptr_t)fbt->fbtp_patchpoint == addr) {
			CPU->cpu_dtrace_caller = rp->r_x30;
			if (fbt->fbtp_roffset == 0) {
				dtrace_probe(fbt->fbtp_id, rp->r_x0, rp->r_x1, rp->r_x2, rp->r_x3, rp->r_x4);
			} else {
				dtrace_probe(fbt->fbtp_id, fbt->fbtp_roffset, rval, 0, 0, 0);
			}
			CPU->cpu_dtrace_caller = 0;

			return (fbt->fbtp_rval);
		}
	}

	return (0);
}

/*ARGSUSED*/
static void
fbt_provide_module(void *arg, struct modctl *ctl)
{
	struct module *mp = ctl->mod_mp;
	char *str = mp->strings;
	int nsyms = mp->nsyms;
	Shdr *symhdr = mp->symhdr;
	char *modname = ctl->mod_modname;
	char *name;
	fbt_probe_t *fbt, *retfbt;
	size_t symsize;
	int i, size;

	/*
	 * Employees of dtrace and their families are ineligible.  Void
	 * where prohibited.
	 */
	if (strcmp(modname, "dtrace") == 0)
		return;

	if (ctl->mod_requisites != NULL) {
		struct modctl_list *list;

		list = (struct modctl_list *)ctl->mod_requisites;

		for (; list != NULL; list = list->modl_next) {
			if (strcmp(list->modl_modp->mod_modname, "dtrace") == 0)
				return;
		}
	}

	/*
	 * KMDB is ineligible for instrumentation -- it may execute in
	 * any context, including probe context.
	 */
	if (strcmp(modname, "kmdbmod") == 0)
		return;

	if (str == NULL || symhdr == NULL || symhdr->sh_addr == 0) {
		/*
		 * If this module doesn't (yet) have its string or symbol
		 * table allocated, clear out.
		 */
		return;
	}

	symsize = symhdr->sh_entsize;

	if (mp->fbt_nentries) {
		/*
		 * This module has some FBT entries allocated; we're afraid
		 * to screw with it.
		 */
		return;
	}

	for (i = 1; i < nsyms; i++) {
		uint32_t *instr, *limit;
		Sym *sym = (Sym *)(symhdr->sh_addr + i * symsize);
		int j;

		if (ELF_ST_TYPE(sym->st_info) != STT_FUNC)
			continue;

		/*
		 * Weak symbols are not candidates.  This could be made to
		 * work (where weak functions and their underlying function
		 * appear as two disjoint probes), but it's not simple.
		 */
		if (ELF_ST_BIND(sym->st_info) == STB_WEAK)
			continue;

		name = str + sym->st_name;

		if (strstr(name, "dtrace_") == name &&
		    strstr(name, "dtrace_safe_") != name) {
			/*
			 * Anything beginning with "dtrace_" may be called
			 * from probe context unless it explitly indicates
			 * that it won't be called from probe context by
			 * using the prefix "dtrace_safe_".
			 */
			continue;
		}

		if (strstr(name, "kdi_") == name ||
		    strstr(name, "_kdi_") != NULL) {
			/*
			 * Any function name beginning with "kdi_" or
			 * containing the string "_kdi_" is a part of the
			 * kernel debugger interface and may be called in
			 * arbitrary context -- including probe context.
			 */
			continue;
		}

		/*
		 * Due to 4524008, _init and _fini may have a bloated st_size.
		 * While this bug was fixed quite some time ago, old drivers
		 * may be lurking.  We need to develop a better solution to
		 * this problem, such that correct _init and _fini functions
		 * (the vast majority) may be correctly traced.  One solution
		 * may be to scan through the entire symbol table to see if
		 * any symbol overlaps with _init.  If none does, set a bit in
		 * the module structure that this module has correct _init and
		 * _fini sizes.  This will cause some pain the first time a
		 * module is scanned, but at least it would be O(N) instead of
		 * O(N log N)...
		 */
		if (strcmp(name, "_init") == 0)
			continue;

		if (strcmp(name, "_fini") == 0)
			continue;

		instr = (uint32_t *)sym->st_value;
		limit = (uint32_t *)(st_value + sym->st_size);

		/* XXXAARCH64: we need to check that relocation offset has been applied */
		/* XXXAARCH64: we need to check the logic of where the NOP is inserted */
		/* XXXAARCH64: we need to check that -fpatchable-function-entry is required and add it if needed */
		// comiple with -fpatchable-function-entry
		if (instr[0] != FBT_NOP)
			continue;

		fbt = kmem_zalloc(sizeof (fbt_probe_t), KM_SLEEP);
		fbt->fbtp_patchpoint = instr;
		fbt->fbtp_rval = DTRACE_INVOP_NOP;
		fbt->fbtp_patchval = FBT_PATCHVAL;
		fbt->fbtp_savedval = *instr;
		fbt->fbtp_roffset = 0;
		fbt->fbtp_id = dtrace_probe_create(fbt_id, modname, name, FBT_ENTRY, 3, fbt);
		fbt->fbtp_name = name;
		fbt->fbtp_ctl = ctl;
		fbt->fbtp_loadcnt = ctl->mod_loadcnt;
		fbt->fbtp_symndx = i;
		fbt->fbtp_next = NULL;
		fbt->fbtp_hashnext = fbt_probetab[FBT_ADDR2NDX(instr)];
		fbt_probetab[FBT_ADDR2NDX(instr)] = fbt;

		mp->fbt_nentries++;

		retfbt = NULL;
again:
		if (instr >= limit)
			continue;

		/*
		 * We only instrument "ret" on aarch64
		 */
		if (*instr != FBT_RET) {
			instr++;
			goto again;
		}

		/*
		 * We have a winner!
		 */
		fbt = kmem_zalloc(sizeof (fbt_probe_t), KM_SLEEP);
		fbt->fbtp_patchpoint = instr;
		fbt->fbtp_rval = DTRACE_INVOP_RET;
		fbt->fbtp_patchval = FBT_PATCHVAL;
		fbt->fbtp_savedval = *instr;
		fbt->fbtp_roffset = (uintptr_t)instr - st_value;

		if (retfbt == NULL) {
			fbt->fbtp_id = dtrace_probe_create(fbt_id, modname, name, FBT_RETURN, 3, fbt);
		} else {
			retfbt->fbtp_next = fbt;
			fbt->fbtp_id = retfbt->fbtp_id;
		}
		fbt->fbtp_name = name;
		fbt->fbtp_ctl = ctl;
		fbt->fbtp_loadcnt = ctl->mod_loadcnt;
		fbt->fbtp_symndx = i;

		retfbt = fbt;

		fbt->fbtp_hashnext = fbt_probetab[FBT_ADDR2NDX(instr)];
		fbt_probetab[FBT_ADDR2NDX(instr)] = fbt;

		mp->fbt_nentries++;

		instr++;
		goto again;
	}
}

/*ARGSUSED*/
static void
fbt_destroy(void *arg, dtrace_id_t id, void *parg)
{
	fbt_probe_t *fbt = parg, *next, *hash, *last;
	struct modctl *ctl = fbt->fbtp_ctl;
	int ndx;

	do {
		if (ctl != NULL && ctl->mod_loadcnt == fbt->fbtp_loadcnt) {
			if ((ctl->mod_loadcnt == fbt->fbtp_loadcnt &&
			    ctl->mod_loaded)) {
				((struct module *)
				    (ctl->mod_mp))->fbt_nentries--;
			}
		}

		/*
		 * Now we need to remove this probe from the fbt_probetab.
		 */
		ndx = FBT_ADDR2NDX(fbt->fbtp_patchpoint);
		last = NULL;
		hash = fbt_probetab[ndx];

		while (hash != fbt) {
			ASSERT(hash != NULL);
			last = hash;
			hash = hash->fbtp_hashnext;
		}

		if (last != NULL) {
			last->fbtp_hashnext = fbt->fbtp_hashnext;
		} else {
			fbt_probetab[ndx] = fbt->fbtp_hashnext;
		}

		next = fbt->fbtp_next;
		kmem_free(fbt, sizeof (fbt_probe_t));

		fbt = next;
	} while (fbt != NULL);
}

static int
fbt_write_instruction(uint32_t *inst, uint32_t val)
{
	dtrace_icookie_t cookie = dtrace_interrupt_disable();
	write_s1e1r((uintptr_t)inst);
	isb();
	uint64_t par = read_par_el1();
	dtrace_interrupt_enable(cookie);
	if (par & PAR_F)
		return -1;

	pfn_t pfn = (par & PAR_PA_MASK) >> MMU_PAGESHIFT;

	caddr_t vaddr = hat_kpm_mapin_pfn(pfn);
	*(uint32_t* )((uintptr_t)vaddr + ((uintptr_t)inst & MMU_PAGEOFFSET)) = val;
	clean_data_cache_pou((uintptr_t)vaddr + ((uintptr_t)inst & MMU_PAGEOFFSET));
	dsb(ish);
	invalidate_instruction_cache((uintptr_t)inst);
	dsb(ish);
	hat_kpm_mapout_pfn(pfn);

	return 0;
}

/*ARGSUSED*/
static int
fbt_enable(void *arg, dtrace_id_t id, void *parg)
{
	fbt_probe_t *fbt = parg;
	struct modctl *ctl = fbt->fbtp_ctl;

	ctl->mod_nenabled++;

	if (!ctl->mod_loaded) {
		if (fbt_verbose) {
			cmn_err(CE_NOTE, "fbt is failing for probe %s "
			    "(module %s unloaded)",
			    fbt->fbtp_name, ctl->mod_modname);
		}

		return (0);
	}

	/*
	 * Now check that our modctl has the expected load count.  If it
	 * doesn't, this module must have been unloaded and reloaded -- and
	 * we're not going to touch it.
	 */
	if (ctl->mod_loadcnt != fbt->fbtp_loadcnt) {
		if (fbt_verbose) {
			cmn_err(CE_NOTE, "fbt is failing for probe %s "
			    "(module %s reloaded)",
			    fbt->fbtp_name, ctl->mod_modname);
		}

		return (0);
	}

	for (; fbt != NULL; fbt = fbt->fbtp_next) {
		if (fbt_write_instruction(fbt->fbtp_patchpoint, fbt->fbtp_patchval)) {
			cmn_err(CE_NOTE, "fbt is failing for probe %s "
			    "(%p is not readable in module %s)",
			    fbt->fbtp_name, fbt->fbtp_patchpoint, ctl->mod_modname);
		}
	}

	return (0);
}

/*ARGSUSED*/
static void
fbt_disable(void *arg, dtrace_id_t id, void *parg)
{
	fbt_probe_t *fbt = parg;
	struct modctl *ctl = fbt->fbtp_ctl;

	ASSERT(ctl->mod_nenabled > 0);
	ctl->mod_nenabled--;

	if (!ctl->mod_loaded || (ctl->mod_loadcnt != fbt->fbtp_loadcnt))
		return;

	for (; fbt != NULL; fbt = fbt->fbtp_next) {
		if (fbt_write_instruction(fbt->fbtp_patchpoint, fbt->fbtp_savedval)) {
			cmn_err(CE_NOTE, "fbt is failing for probe %s "
			    "(%p is not readable in module %s)",
			    fbt->fbtp_name, fbt->fbtp_patchpoint, ctl->mod_modname);
		}
	}
}

/*ARGSUSED*/
static void
fbt_suspend(void *arg, dtrace_id_t id, void *parg)
{
	fbt_probe_t *fbt = parg;
	struct modctl *ctl = fbt->fbtp_ctl;

	ASSERT(ctl->mod_nenabled > 0);

	if (!ctl->mod_loaded || (ctl->mod_loadcnt != fbt->fbtp_loadcnt))
		return;

	for (; fbt != NULL; fbt = fbt->fbtp_next)
		*fbt->fbtp_patchpoint = fbt->fbtp_savedval;
}

/*ARGSUSED*/
static void
fbt_resume(void *arg, dtrace_id_t id, void *parg)
{
	fbt_probe_t *fbt = parg;
	struct modctl *ctl = fbt->fbtp_ctl;

	ASSERT(ctl->mod_nenabled > 0);

	if (!ctl->mod_loaded || (ctl->mod_loadcnt != fbt->fbtp_loadcnt))
		return;

	for (; fbt != NULL; fbt = fbt->fbtp_next)
		*fbt->fbtp_patchpoint = fbt->fbtp_patchval;
}

/*ARGSUSED*/
static void
fbt_getargdesc(void *arg, dtrace_id_t id, void *parg, dtrace_argdesc_t *desc)
{
	fbt_probe_t *fbt = parg;
	struct modctl *ctl = fbt->fbtp_ctl;
	struct module *mp = ctl->mod_mp;
	ctf_file_t *fp = NULL, *pfp;
	ctf_funcinfo_t f;
	int error;
	ctf_id_t argv[32], type;
	int argc = sizeof (argv) / sizeof (ctf_id_t);
	const char *parent;

	if (!ctl->mod_loaded || (ctl->mod_loadcnt != fbt->fbtp_loadcnt))
		goto err;

	if (fbt->fbtp_roffset != 0 && desc->dtargd_ndx == 0) {
		(void) strcpy(desc->dtargd_native, "int");
		return;
	}

	if ((fp = ctf_modopen(mp, &error)) == NULL) {
		/*
		 * We have no CTF information for this module -- and therefore
		 * no args[] information.
		 */
		goto err;
	}

	/*
	 * If we have a parent container, we must manually import it.
	 */
	if ((parent = ctf_parent_name(fp)) != NULL) {
		struct modctl *mp = &modules;
		struct modctl *mod = NULL;

		/*
		 * We must iterate over all modules to find the module that
		 * is our parent.
		 */
		do {
			if (strcmp(mp->mod_modname, parent) == 0) {
				mod = mp;
				break;
			}
		} while ((mp = mp->mod_next) != &modules);

		if (mod == NULL)
			goto err;

		if ((pfp = ctf_modopen(mod->mod_mp, &error)) == NULL) {
			goto err;
		}

		if (ctf_import(fp, pfp) != 0) {
			ctf_close(pfp);
			goto err;
		}

		ctf_close(pfp);
	}

	if (ctf_func_info(fp, fbt->fbtp_symndx, &f) == CTF_ERR)
		goto err;

	if (fbt->fbtp_roffset != 0) {
		if (desc->dtargd_ndx > 1)
			goto err;

		ASSERT(desc->dtargd_ndx == 1);
		type = f.ctc_return;
	} else {
		if (desc->dtargd_ndx + 1 > f.ctc_argc)
			goto err;

		if (ctf_func_args(fp, fbt->fbtp_symndx, argc, argv) == CTF_ERR)
			goto err;

		type = argv[desc->dtargd_ndx];
	}

	if (ctf_type_name(fp, type, desc->dtargd_native,
	    DTRACE_ARGTYPELEN) != NULL) {
		ctf_close(fp);
		return;
	}
err:
	if (fp != NULL)
		ctf_close(fp);

	desc->dtargd_ndx = DTRACE_ARGNONE;
}

static dtrace_pattr_t fbt_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
};

static dtrace_pops_t fbt_pops = {
	NULL,
	fbt_provide_module,
	fbt_enable,
	fbt_disable,
	fbt_suspend,
	fbt_resume,
	fbt_getargdesc,
	NULL,
	NULL,
	fbt_destroy
};

static void
fbt_cleanup(dev_info_t *devi)
{
	dtrace_invop_remove(fbt_invop);
	ddi_remove_minor_node(devi, NULL);
	kmem_free(fbt_probetab, fbt_probetab_size * sizeof (fbt_probe_t *));
	fbt_probetab = NULL;
	fbt_probetab_mask = 0;
}

static int
fbt_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	if (fbt_probetab_size == 0)
		fbt_probetab_size = FBT_PROBETAB_SIZE;

	fbt_probetab_mask = fbt_probetab_size - 1;
	fbt_probetab =
	    kmem_zalloc(fbt_probetab_size * sizeof (fbt_probe_t *), KM_SLEEP);

	dtrace_invop_add(fbt_invop);

	if (ddi_create_minor_node(devi, "fbt", S_IFCHR, 0,
	    DDI_PSEUDO, 0) == DDI_FAILURE ||
	    dtrace_register("fbt", &fbt_attr, DTRACE_PRIV_KERNEL, NULL,
	    &fbt_pops, NULL, &fbt_id) != 0) {
		fbt_cleanup(devi);
		return (DDI_FAILURE);
	}

	ddi_report_dev(devi);
	fbt_devi = devi;

	return (DDI_SUCCESS);
}

static int
fbt_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	if (dtrace_unregister(fbt_id) != 0)
		return (DDI_FAILURE);

	fbt_cleanup(devi);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
fbt_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = (void *)fbt_devi;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}

/*ARGSUSED*/
static int
fbt_open(dev_t *devp, int flag, int otyp, cred_t *cred_p)
{
	return (0);
}

static struct cb_ops fbt_cb_ops = {
	fbt_open,		/* open */
	nodev,			/* close */
	nulldev,		/* strategy */
	nulldev,		/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	nodev,			/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	0,			/* streamtab  */
	D_NEW | D_MP		/* Driver compatibility flag */
};

static struct dev_ops fbt_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt */
	fbt_info,		/* get_dev_info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	fbt_attach,		/* attach */
	fbt_detach,		/* detach */
	nodev,			/* reset */
	&fbt_cb_ops,		/* driver operations */
	NULL,			/* bus operations */
	nodev,			/* dev power */
	ddi_quiesce_not_needed,		/* quiesce */
};

/*
 * Module linkage information for the kernel.
 */
static struct modldrv modldrv = {
	&mod_driverops,		/* module type (this is a pseudo driver) */
	"Function Boundary Tracing",	/* name of module */
	&fbt_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}
