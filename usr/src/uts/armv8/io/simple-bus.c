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
 * Copyright (c) 1992, 2011, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/autoconf.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/ddidmareq.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_subrdefs.h>
#include <sys/dma_engine.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/mach_intr.h>
#include <sys/note.h>
#include <sys/promif.h>
#include <sys/sysmacros.h>
#include <sys/obpdefs.h>

static int smpl_bus_map(dev_info_t *, dev_info_t *, ddi_map_req_t *, off_t,
    off_t, caddr_t *);
static int smpl_ctlops(dev_info_t *, dev_info_t *, ddi_ctl_enum_t,
    void *, void *);
static int smpl_intr_ops(dev_info_t *, dev_info_t *, ddi_intr_op_t,
    ddi_intr_handle_impl_t *, void *);

struct bus_ops smpl_bus_ops = {
	BUSO_REV,
	smpl_bus_map,
	NULL,
	NULL,
	NULL,
	i_ddi_map_fault,
	NULL,
	ddi_dma_allochdl,
	ddi_dma_freehdl,
	ddi_dma_bindhdl,
	ddi_dma_unbindhdl,
	ddi_dma_flush,
	ddi_dma_win,
	ddi_dma_mctl,
	smpl_ctlops,
	ddi_bus_prop_op,
	NULL,		/* (*bus_get_eventcookie)();	*/
	NULL,		/* (*bus_add_eventcall)();	*/
	NULL,		/* (*bus_remove_eventcall)();	*/
	NULL,		/* (*bus_post_event)();		*/
	NULL,		/* (*bus_intr_ctl)(); */
	NULL,		/* (*bus_config)(); */
	NULL,		/* (*bus_unconfig)(); */
	NULL,		/* (*bus_fm_init)(); */
	NULL,		/* (*bus_fm_fini)(); */
	NULL,		/* (*bus_fm_access_enter)(); */
	NULL,		/* (*bus_fm_access_exit)(); */
	NULL,		/* (*bus_power)(); */
	smpl_intr_ops	/* (*bus_intr_op)(); */
};


static int smpl_attach(dev_info_t *devi, ddi_attach_cmd_t cmd);

/*
 * Internal isa ctlops support routines
 */
struct dev_ops smpl_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	ddi_no_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	smpl_attach,	/* attach */
	nulldev,		/* detach */
	nodev,			/* reset */
	(struct cb_ops *)0,	/* driver operations */
	&smpl_bus_ops,	/* bus operations */
	NULL,			/* power */
	ddi_quiesce_not_needed,	/* quiesce */
};

/*
 * Module linkage information for the kernel.
 */

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module.  This is simple-bus bus driver */
	"simple-bus nexus driver",
	&smpl_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

int
_init(void)
{
	int	err;

	if ((err = mod_install(&modlinkage)) != 0)
		return (err);

	return (0);
}

int
_fini(void)
{
	int	err;

	if ((err = mod_remove(&modlinkage)) != 0)
		return (err);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*ARGSUSED*/
static int
smpl_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int rval;
	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	ddi_report_dev(devi);

	return (DDI_SUCCESS);
}

void
smpl_bus_cook_regs(uint32_t *regs, struct regspec64 *out, int addr_cells,
    int size_cells)
{
	uint64_t addr = 0;
	uint64_t size = 0;

	ASSERT(addr_cells == 1 || addr_cells == 2);
	ASSERT(size_cells == 1 || size_cells == 2);

	for (int i = 0; i < addr_cells; i++) {
		addr = (addr << 32) | regs[i];
	}

	for (int i = 0; i < size_cells; i++) {
		size = (size << 32) | regs[addr_cells + i];
	}

	out->regspec_addr = addr;
	out->regspec_size = size;
}

static inline int
smpl_bus_regno_to_offset(int regno, int addr_cells, int size_cells)
{
	return (regno * (addr_cells + size_cells));
}

/*
 * Apply our ranges property to the child's reg property and return addresses
 * in the parent bus's space
 *
 * We can't use `i_ddi_apply_range` since there are no ranges in
 * the parent data because we can't guarantee the address and size formats.
 *
 * XXXROOTNEX: We could arrange for that to be possible, instead, however.
 */
static int
smpl_bus_apply_range(dev_info_t *dip, struct regspec64 *out)
{
	dev_info_t *parent;
	uint32_t *rangep;
	uint_t rangelen;
	int parent_addr_cells, parent_size_cells;
	int child_addr_cells, child_size_cells;

	ASSERT3P(dip, !=, NULL);

	parent = ddi_get_parent(dip);
	ASSERT3P(parent, !=, NULL);

	child_addr_cells = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, OBP_ADDRESS_CELLS, 0);
	child_size_cells = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, OBP_SIZE_CELLS, 0);
	parent_addr_cells = ddi_prop_get_int(DDI_DEV_T_ANY, parent,
	    DDI_PROP_DONTPASS, OBP_ADDRESS_CELLS, 0);
	parent_size_cells = ddi_prop_get_int(DDI_DEV_T_ANY, parent,
	    DDI_PROP_DONTPASS, OBP_SIZE_CELLS, 0);

	VERIFY3S(parent_addr_cells, !=, 0);
	VERIFY3S(parent_size_cells, !=, 0);
	VERIFY3S(child_addr_cells, !=, 0);
	VERIFY3S(child_size_cells, !=, 0);

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    OBP_RANGES, (int **)&rangep, &rangelen) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "error reading ranges property");
		return (DDI_SUCCESS);
	} else if (rangelen == 0) {
		ddi_prop_free(rangep);
		dev_err(dip, CE_WARN, "0-length ranges property");
		return (DDI_SUCCESS);
	}

	int i;
	int ranges_cells = (child_addr_cells + parent_addr_cells +
	    child_size_cells);
	int n = rangelen / ranges_cells;

	for (i = 0; i < n; i++) {
		uint64_t base = 0;
		uint64_t target = 0;
		uint64_t rsize = 0;
		for (int j = 0; j < child_addr_cells; j++) {
			base <<= 32;
			base += rangep[ranges_cells * i + j];
		}
		for (int j = 0; j < parent_addr_cells; j++) {
			target <<= 32;
			target += rangep[ranges_cells * i +
			    child_addr_cells + j];
		}
		for (int j = 0; j < child_size_cells; j++) {
			rsize <<= 32;
			rsize += rangep[ranges_cells * i + child_addr_cells +
			    parent_addr_cells + j];
		}

		uint64_t rel_addr = out->regspec_addr;
		uint64_t rel_offset = out->regspec_addr - base;

		if (base <= rel_addr && rel_addr <= base + rsize - 1) {
			out->regspec_addr = rel_offset + target;
			out->regspec_size = MIN(out->regspec_size, (rsize -
			    rel_offset));
			break;
		}

		ddi_prop_free(rangep);

		/* Not found */
		if (i == n) {
			dev_err(dip, CE_WARN, "specified register bounds "
			    "are outside range");
			return (DDI_FAILURE);
		}
	}

	return (DDI_SUCCESS);
}

static int
smpl_bus_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp, off_t offset,
    off_t len, caddr_t *vaddrp)
{
	ddi_map_req_t mr;
	struct regspec64 reg = {0};
	int error, addr_cells, size_cells;
	uint32_t *cregs = NULL;

	if ((addr_cells = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, OBP_ADDRESS_CELLS, 0)) == 0) {
		dev_err(rdip, CE_WARN, "couldn't read #address-cells");
		return (DDI_ME_INVAL);
	}

	if ((size_cells = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, OBP_SIZE_CELLS, 0)) == 0) {
		dev_err(rdip, CE_WARN, "couldn't read #size-cells");
		return (DDI_ME_INVAL);
	}

	switch (mp->map_type) {
	case DDI_MT_REGSPEC:
		smpl_bus_cook_regs((uint32_t *)mp->map_obj.rp, &reg,
		    addr_cells, size_cells);
		break;
	case DDI_MT_RNUMBER: {
		uint_t n;
		int rnumber = mp->map_obj.rnumber;

		if ((ddi_prop_lookup_int_array(DDI_DEV_T_ANY, rdip,
		    DDI_PROP_DONTPASS, OBP_REG, (int **)&cregs, &n) !=
		    DDI_SUCCESS) || (n == 0)) {
			dev_err(rdip, CE_WARN,
			    "couldn't read reg property\n");
			return (DDI_ME_RNUMBER_RANGE);
		}

		ASSERT(n % (addr_cells + size_cells) == 0);

		if (rnumber < 0 || rnumber >= n) {
			ddi_prop_free(cregs);
			return (DDI_ME_RNUMBER_RANGE);
		}

		int off = smpl_bus_regno_to_offset(rnumber, addr_cells,
		    size_cells);
		smpl_bus_cook_regs(&cregs[off], &reg,
		    addr_cells, size_cells);

		break;
	}
	default:
		return (DDI_ME_INVAL);
	}

	if (cregs != NULL)
		ddi_prop_free(cregs);

	/* Adjust our reg property with offset and length */
	if (reg.regspec_addr + offset < MAX(reg.regspec_addr, offset))
		return (DDI_FAILURE);

	reg.regspec_addr += offset;
	if (len)
		reg.regspec_size = len;


#ifdef	DDI_MAP_DEBUG
	dev_err(dip, CE_CONT, "<%s,%s> <0x%lx, 0x%lx, %ld> "
	    "offset %ld len %ld handle 0x%p\n", ddi_get_name(dip),
	    ddi_get_name(rdip), reg.regspec_bustype, reg.regspec_addr,
	    reg.regspec_size, offset, len, mp->map_handlep);
#endif	/* DDI_MAP_DEBUG */

	if ((error = smpl_bus_apply_range(dip, &reg)) != DDI_SUCCESS)
		return (DDI_SUCCESS);

	mr = *mp;
	mr.map_type = DDI_MT_REGSPEC;
	mr.map_obj.rp = (struct regspec *)&reg;
	mr.map_flags |= DDI_MF_EXT_REGSPEC;
	mp = &mr;
#ifdef	DDI_MAP_DEBUG
	cmn_err(CE_CONT, "             <%s,%s> <0x%" PRIx64 ", 0x%" PRIx64
	    ", %" PRId64 "> offset %ld len %ld handle 0x%p\n",
	    ddi_get_name(dip), ddi_get_name(rdip), reg.regspec_bustype,
	    reg.regspec_addr, reg.regspec_size, offset, len, mp->map_handlep);
#endif	/* DDI_MAP_DEBUG */

	/* `offset` is already added in, above */
	return (ddi_map(dip, mp, 0, 0, vaddrp));
}

static int
smpl_ctlops(dev_info_t *dip, dev_info_t *rdip,
    ddi_ctl_enum_t ctlop, void *arg, void *result)
{
	uint_t reglen;
	int nreg;
	int ret;

	switch (ctlop) {
	case DDI_CTLOPS_INITCHILD:
		ret = impl_ddi_sunbus_initchild((dev_info_t *)arg);
		break;

	case DDI_CTLOPS_UNINITCHILD:
		impl_ddi_sunbus_removechild((dev_info_t *)arg);
		ret = DDI_SUCCESS;
		break;

	case DDI_CTLOPS_REPORTDEV:
		if (rdip == (dev_info_t *)0)
			return (DDI_FAILURE);
		cmn_err(CE_CONT, "?%s%d at %s%d\n",
		    ddi_driver_name(rdip), ddi_get_instance(rdip),
		    ddi_driver_name(dip), ddi_get_instance(dip));
		ret = DDI_SUCCESS;
		break;

	default:
		ret = ddi_ctlops(dip, rdip, ctlop, arg, result);
		break;
	}
	return (ret);
}

static int
smpl_intr_ops(dev_info_t *pdip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	return (i_ddi_intr_ops(pdip, rdip, intr_op, hdlp, result));
}
