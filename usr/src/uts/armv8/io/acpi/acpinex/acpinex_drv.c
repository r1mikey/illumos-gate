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
/*
 * Copyright (c) 2009-2010, Intel Corporation.
 * All rights reserved.
 */
/*
 * Copyright 2012 Garrett D'Amore <garrett@damore.org>.  All rights reserved.
 */
/*
 * This module implements a nexus driver for the ACPI virtual bus.
 * It does not handle any of the DDI functions passed up to it by the child
 * drivers, but instead allows them to bubble up to the root node.
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddifm.h>
#include <sys/note.h>
#include <sys/ndifm.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/acpidev.h>
#include <sys/acpidev_rsc.h>
#include <sys/acpinex.h>

#include <sys/promif.h>

/* Patchable through /etc/system. */
#ifdef	DEBUG
int acpinex_debug = 1;
#else
int acpinex_debug = 0;
#endif

/*
 * XXXARM: Maybe I should just give up this quixotic quest to defer to what the
 * firmware says and just do what the drivers say.
 *
 * Or maybe not. I just don't know.
 *
 * Or maybe make it a tweakable? Complexity abounds.
 */
typedef struct {
	/*
	 * The ddi_parent_private_data must be first, and must not be a pointer.
	 *
	 * By doing this we allow ranges and interrupts to be habdled using the
	 * normal functions, while we override register operations.
	 */
	struct ddi_parent_private_data	ppd_ppd;
	int				ppd_nreg;
	acpidev_regspec_t		*ppd_reg;
} acpinex_parent_private_data_t;

/*
 * Driver globals
 */
static kmutex_t acpinex_lock;
static void *acpinex_softstates;

static int acpinex_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int acpinex_attach(dev_info_t *, ddi_attach_cmd_t);
static int acpinex_detach(dev_info_t *, ddi_detach_cmd_t);
static int acpinex_open(dev_t *, int, int, cred_t *);
static int acpinex_close(dev_t, int, int, cred_t *);
static int acpinex_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int acpinex_bus_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
    off_t offset, off_t len, caddr_t *vaddrp);
static int acpinex_ctlops(dev_info_t *, dev_info_t *, ddi_ctl_enum_t, void *,
    void *);
static int acpinex_fm_init_child(dev_info_t *, dev_info_t *, int,
    ddi_iblock_cookie_t *);
static void acpinex_fm_init(acpinex_softstate_t *softsp);
static void acpinex_fm_fini(acpinex_softstate_t *softsp);

#if defined(__aarch64__)
static int acpinex_bus_config(dev_info_t *dip, uint_t flags,
    ddi_bus_config_op_t op, void *arg, dev_info_t **childp);
#endif

extern void make_ddi_ppd(dev_info_t *, struct ddi_parent_private_data **);

/*
 * Configuration data structures
 */
static struct bus_ops acpinex_bus_ops = {
	BUSO_REV,			/* busops_rev */
	acpinex_bus_map,		/* bus_map */
	NULL,				/* bus_get_intrspec */
	NULL,				/* bus_add_intrspec */
	NULL,				/* bus_remove_intrspec */
	i_ddi_map_fault,		/* bus_map_fault */
	NULL,				/* bus_dma_map */
	ddi_dma_allochdl,		/* bus_dma_allochdl */
	ddi_dma_freehdl,		/* bus_dma_freehdl */
	ddi_dma_bindhdl,		/* bus_dma_bindhdl */
	ddi_dma_unbindhdl,		/* bus_dma_unbindhdl */
	ddi_dma_flush,			/* bus_dma_flush */
	ddi_dma_win,			/* bus_dma_win */
	ddi_dma_mctl,			/* bus_dma_ctl */
	acpinex_ctlops,			/* bus_ctl */
	ddi_bus_prop_op,		/* bus_prop_op */
	ndi_busop_get_eventcookie,	/* bus_get_eventcookie */
	ndi_busop_add_eventcall,	/* bus_add_eventcall */
	ndi_busop_remove_eventcall,	/* bus_remove_eventcall */
	ndi_post_event,			/* bus_post_event */
	NULL,				/* bus_intr_ctl */
#if defined(__aarch64__)
	acpinex_bus_config,		/* bus_config */
#else
	NULL,				/* bus_config */
#endif
	NULL,				/* bus_unconfig */
	acpinex_fm_init_child,		/* bus_fm_init */
	NULL,				/* bus_fm_fini */
	NULL,				/* bus_fm_access_enter */
	NULL,				/* bus_fm_access_exit */
	NULL,				/* bus_power */
	i_ddi_intr_ops			/* bus_intr_op */
};

static struct cb_ops acpinex_cb_ops = {
	acpinex_open,			/* cb_open */
	acpinex_close,			/* cb_close */
	nodev,				/* cb_strategy */
	nodev,				/* cb_print */
	nodev,				/* cb_dump */
	nodev,				/* cb_read */
	nodev,				/* cb_write */
	acpinex_ioctl,			/* cb_ioctl */
	nodev,				/* cb_devmap */
	nodev,				/* cb_mmap */
	nodev,				/* cb_segmap */
	nochpoll,			/* cb_poll */
	ddi_prop_op,			/* cb_prop_op */
	NULL,				/* cb_str */
	D_NEW | D_MP | D_HOTPLUG,	/* Driver compatibility flag */
	CB_REV,				/* rev */
	nodev,				/* int (*cb_aread)() */
	nodev				/* int (*cb_awrite)() */
};

static struct dev_ops acpinex_ops = {
	DEVO_REV,			/* devo_rev, */
	0,				/* devo_refcnt */
	acpinex_info,			/* devo_getinfo */
	nulldev,			/* devo_identify */
	nulldev,			/* devo_probe */
	acpinex_attach,			/* devo_attach */
	acpinex_detach,			/* devo_detach */
	nulldev,			/* devo_reset */
	&acpinex_cb_ops,		/* devo_cb_ops */
	&acpinex_bus_ops,		/* devo_bus_ops */
	nulldev,			/* devo_power */
	ddi_quiesce_not_needed		/* devo_quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,			/* Type of module */
	"ACPI virtual bus driver",	/* name of module */
	&acpinex_ops,			/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,			/* rev */
	(void *)&modldrv,
	NULL
};

/*
 * Module initialization routines.
 */
int
_init(void)
{
	int error;

	/* Initialize soft state pointer. */
	if ((error = ddi_soft_state_init(&acpinex_softstates,
	    sizeof (acpinex_softstate_t), 8)) != 0) {
		cmn_err(CE_WARN,
		    "acpinex: failed to initialize soft state structure.");
		return (error);
	}

	/* Initialize event subsystem. */
	acpinex_event_init();

	/* Install the module. */
	if ((error = mod_install(&modlinkage)) != 0) {
		cmn_err(CE_WARN, "acpinex: failed to install module.");
		ddi_soft_state_fini(&acpinex_softstates);
		return (error);
	}

	mutex_init(&acpinex_lock, NULL, MUTEX_DRIVER, NULL);
	return (0);
}

int
_fini(void)
{
	int error;

	/* Remove the module. */
	if ((error = mod_remove(&modlinkage)) != 0) {
		return (error);
	}

	/* Shut down event subsystem. */
	acpinex_event_fini();

	/* Free the soft state info. */
	ddi_soft_state_fini(&acpinex_softstates);

	mutex_destroy(&acpinex_lock);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
acpinex_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	_NOTE(ARGUNUSED(dip));

	dev_t	dev;
	int	instance;

	if (infocmd == DDI_INFO_DEVT2INSTANCE) {
		dev = (dev_t)arg;
		instance = ACPINEX_GET_INSTANCE(getminor(dev));
		*result = (void *)(uintptr_t)instance;
		return (DDI_SUCCESS);
	}

	return (DDI_FAILURE);
}

#if defined(__aarch64__)
static int
acpinex_bus_config(dev_info_t *dip, uint_t flags, ddi_bus_config_op_t op,
    void *arg, dev_info_t **childp)
{
	return (ndi_busop_bus_config(dip, flags | NDI_ONLINE_ATTACH,
	    op, arg, childp, 0));
}
#endif

static int
acpinex_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int instance;
	acpinex_softstate_t *softsp;

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	/* Get and check instance number. */
	instance = ddi_get_instance(devi);
	if (instance >= ACPINEX_INSTANCE_MAX) {
		cmn_err(CE_WARN, "acpinex: instance number %d is out of range "
		    "in acpinex_attach(), max %d.",
		    instance, ACPINEX_INSTANCE_MAX - 1);
		return (DDI_FAILURE);
	}

	/* Get soft state structure. */
	if (ddi_soft_state_zalloc(acpinex_softstates, instance)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!acpinex: failed to allocate soft state "
		    "object in acpinex_attach().");
		return (DDI_FAILURE);
	}
	softsp = ddi_get_soft_state(acpinex_softstates, instance);

	/* Initialize soft state structure */
	softsp->ans_dip = devi;
	(void) ddi_pathname(devi, softsp->ans_path);
	if (ACPI_FAILURE(acpica_get_handle(devi, &softsp->ans_hdl))) {
		ACPINEX_DEBUG(CE_WARN,
		    "!acpinex: failed to get ACPI handle for %s.",
		    softsp->ans_path);
		ddi_soft_state_free(acpinex_softstates, instance);
		return (DDI_FAILURE);
	}
	mutex_init(&softsp->ans_lock, NULL, MUTEX_DRIVER, NULL);

	/* Install event handler for child/descendant objects. */
	if (acpinex_event_scan(softsp, B_TRUE) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!acpinex: failed to install event handler "
		    "for children of %s.", softsp->ans_path);
	}

	/* nothing to suspend/resume here */
	(void) ddi_prop_update_string(DDI_DEV_T_NONE, devi,
	    "pm-hardware-state", "no-suspend-resume");
	(void) ddi_prop_update_int(DDI_DEV_T_NONE, devi,
	    DDI_NO_AUTODETACH, 1);

	acpinex_fm_init(softsp);
	ddi_report_dev(devi);

	return (DDI_SUCCESS);
}

static int
acpinex_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int instance;
	acpinex_softstate_t *softsp;

	instance = ddi_get_instance(devi);
	if (instance >= ACPINEX_INSTANCE_MAX) {
		cmn_err(CE_WARN, "acpinex: instance number %d is out of range "
		    "in acpinex_detach(), max %d.",
		    instance, ACPINEX_INSTANCE_MAX - 1);
		return (DDI_FAILURE);
	}

	softsp = ddi_get_soft_state(acpinex_softstates, instance);
	if (softsp == NULL) {
		ACPINEX_DEBUG(CE_WARN, "!acpinex: failed to get soft state "
		    "object for instance %d in acpinex_detach()", instance);
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_DETACH:
		if (acpinex_event_scan(softsp, B_FALSE) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "!acpinex: failed to uninstall event "
			    "handler for children of %s.", softsp->ans_path);
			return (DDI_FAILURE);
		}
		ddi_remove_minor_node(devi, NULL);
		acpinex_fm_fini(softsp);
		mutex_destroy(&softsp->ans_lock);
		ddi_soft_state_free(acpinex_softstates, instance);
		(void) ddi_prop_update_int(DDI_DEV_T_NONE, devi,
		    DDI_NO_AUTODETACH, 0);
		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

#if defined(__aarch64__)
static int
acpinex_make_ddi_ppd(dev_info_t *child, acpinex_parent_private_data_t **ppd)
{
	struct ddi_parent_private_data *pdp;
	acpinex_parent_private_data_t *pdptr;
	int *reg_prop;
	uint_t reg_len;

	*ppd = pdptr = kmem_zalloc(sizeof (*pdptr), KM_SLEEP);
	make_ddi_ppd(child, &pdp);

	/*
	 * Free the registers from the standard property lookup, but save the
	 * IRQs and ranges, then free up the standard object.
	 */
	if (pdp->par_nreg != 0 && pdp->par_reg != NULL)
		ddi_prop_free((void *)pdp->par_reg);
	pdp->par_reg = NULL;
	pdp->par_nreg = 0;
	bcopy(pdp, &pdptr->ppd_ppd, sizeof (pdptr->ppd_ppd));
	kmem_free(pdp, sizeof (*pdp));	/* the rest has been stolen */

	/*
	 * Retrieve any registers definitions in acpidev_regspec_t format.
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
	    "reg", &reg_prop, &reg_len) == DDI_PROP_SUCCESS) {
		ASSERT(reg_len != 0);
		reg_len = CELLS_1275_TO_BYTES(reg_len);
		ASSERT((reg_len % sizeof (acpidev_regspec_t)) == 0);
		pdptr->ppd_nreg = (int)(reg_len / sizeof (acpidev_regspec_t));
		pdptr->ppd_reg = (acpidev_regspec_t *)reg_prop;
	}

	return (DDI_SUCCESS);
}

static void
acpinex_free_ddi_ppd(dev_info_t *dip)
{
	acpinex_parent_private_data_t *pdptr;
	size_t n;

	if ((pdptr = ddi_get_parent_data(dip)) == NULL)
		return;

	if ((n = (size_t)pdptr->ppd_ppd.par_nintr) != 0 &&
		pdptr->ppd_ppd.par_intr != NULL)
		kmem_free(pdptr->ppd_ppd.par_intr,
			n * sizeof (struct intrspec));

	if ((n = (size_t)pdptr->ppd_ppd.par_nrng) != 0 &&
		pdptr->ppd_ppd.par_rng != NULL)
		ddi_prop_free((void *)pdptr->ppd_ppd.par_rng);

	if ((n = pdptr->ppd_nreg) != 0 && pdptr->ppd_reg != NULL)
		ddi_prop_free((void *)pdptr->ppd_reg);

	kmem_free(pdptr, sizeof (*pdptr));
	ddi_set_parent_data(dip, NULL);
}
#endif

static void
acpinex_ddi_sunbus_removechild(dev_info_t *dip)
{
#if defined(__aarch64__)
	acpinex_free_ddi_ppd(dip);
#else
	impl_free_ddi_ppd(dip);
#endif
	ddi_set_name_addr(dip, NULL);
	impl_rem_dev_props(dip);
}

static int
acpinex_name_child(dev_info_t *child, char *name, int namelen)
{
	char *unitaddr;
#if defined(__aarch64__)
	acpinex_parent_private_data_t *pdptr = NULL;

	if (ddi_get_parent_data(child) == NULL)
		acpinex_make_ddi_ppd(child, &pdptr);

	ddi_set_parent_data(child, pdptr);
#else
	ddi_set_parent_data(child, NULL);
#endif

	name[0] = '\0';
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
	    ACPIDEV_PROP_NAME_UNIT_ADDR, &unitaddr) == DDI_SUCCESS) {
		(void) strlcpy(name, unitaddr, namelen);
		ddi_prop_free(unitaddr);
	} else {
		ACPINEX_DEBUG(CE_NOTE, "!acpinex: failed to lookup child "
		    "unit-address prop for %p.", (void *)child);
	}

	return (DDI_SUCCESS);
}

static int
acpinex_init_child(dev_info_t *child)
{
	char name[MAXNAMELEN];

	(void) acpinex_name_child(child, name, MAXNAMELEN);
	ddi_set_name_addr(child, name);
	if ((ndi_dev_is_persistent_node(child) == 0) &&
	    (ndi_merge_node(child, acpinex_name_child) == DDI_SUCCESS)) {
		acpinex_ddi_sunbus_removechild(child);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * Control ops entry point:
 *
 * Requests handled completely:
 *      DDI_CTLOPS_INITCHILD
 *      DDI_CTLOPS_UNINITCHILD
 * All others are passed to the parent.
 */
static int
acpinex_ctlops(dev_info_t *dip, dev_info_t *rdip, ddi_ctl_enum_t op, void *arg,
    void *result)
{
	int rval = DDI_SUCCESS;

	switch (op) {
	case DDI_CTLOPS_INITCHILD:
		rval = acpinex_init_child((dev_info_t *)arg);
		break;

	case DDI_CTLOPS_UNINITCHILD:
		acpinex_ddi_sunbus_removechild((dev_info_t *)arg);
		break;

	case DDI_CTLOPS_REPORTDEV: {
		if (rdip == (dev_info_t *)0)
			return (DDI_FAILURE);
		cmn_err(CE_CONT, "?acpinex: %s@%s, %s%d\n",
		    ddi_node_name(rdip), ddi_get_name_addr(rdip),
		    ddi_driver_name(rdip), ddi_get_instance(rdip));
		break;
	}

	default:
		rval = ddi_ctlops(dip, rdip, op, arg, result);
		break;
	}

	return (rval);
}

#if defined(__aarch64__)
/*
 * XXXARM: implement the whole beast here, use the metadata in the
 * ACPI-specific regs to map cleanly
 */
static int
acpinex_bus_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
    off_t offset, off_t len, caddr_t *vaddrp)
{
	struct regspec64 rp;
	dev_info_t *pdip;

	VERIFY3P(mp, !=, NULL);
	VERIFY3P(dip, !=, NULL);
	VERIFY3P(rdip, !=, NULL);
	VERIFY3P(mp, !=, NULL);
	VERIFY3P(vaddrp, !=, NULL);
	VERIFY3P(DEVI(rdip)->devi_parent_data, !=, NULL);

	pdip = ddi_get_parent(dip);
	VERIFY3P(pdip, !=, NULL);

	if (DEVI(pdip)->devi_ops == NULL ||
	    DEVI(pdip)->devi_ops->devo_bus_ops == NULL ||
	    DEVI(pdip)->devi_ops->devo_bus_ops->bus_map == NULL) {
		prom_printf("acpinex_bus_map: %s%d: parent has no bus_map\n",
		    ddi_node_name(dip), ddi_get_instance(dip));
		return (DDI_FAILURE);
	}

	switch (mp->map_op)  {
	case DDI_MO_MAP_LOCKED:	/* fallthrough */
	case DDI_MO_UNMAP:	/* fallthrough */
	case DDI_MO_MAP_HANDLE:
		if (mp->map_flags & DDI_MF_USER_MAPPING) {
			prom_printf("acpinex_bus_map: %s%d: user mapping unimplemented\n",
				ddi_node_name(dip), ddi_get_instance(dip));
			return (DDI_ME_UNIMPLEMENTED);
		}
		break;
	default:
		prom_printf("acpinex_bus_map: %s%d: unimplemented map_op %d\n",
		    ddi_node_name(dip), ddi_get_instance(dip), mp->map_op);
		return (DDI_ME_UNIMPLEMENTED);
	}

	/*
	 * Im the register-number case we convert our requested mapping to a
	 * regspec request, constructing the regspec from our ACPI regspec and
	 * propagating the ACPI-provided attributes into the mapping object,
	 * respecting the firmware-provided values.
	 */
	if (mp->map_type == DDI_MT_RNUMBER) {
		acpinex_parent_private_data_t *ppd;
		acpidev_regspec_t *rs;

		if (DEVI(rdip)->devi_parent_data == NULL) {
			prom_printf("acpinex_bus_map: %s%d: parent data is NULL\n",
				ddi_node_name(dip), ddi_get_instance(dip));
			return (DDI_FAILURE);
		}

		ppd = (acpinex_parent_private_data_t *)DEVI(rdip)
		    ->devi_parent_data;

		if (mp->map_obj.rnumber >= ppd->ppd_nreg) {
			prom_printf("acpinex_bus_map: %s%d: register number %d is out of range (%d)\n",
				ddi_node_name(dip), ddi_get_instance(dip), mp->map_obj.rnumber, ppd->ppd_nreg);
			return (DDI_ME_RNUMBER_RANGE);
		}

		rs = &ppd->ppd_reg[mp->map_obj.rnumber];

		rp.regspec_addr = ((uint64_t)rs->phys_mid) << 32;
		rp.regspec_addr |= (uint64_t)rs->phys_low;
		rp.regspec_size = ((uint64_t)rs->size_hi) << 32;
		rp.regspec_size |= (uint64_t)rs->size_low;

		/*
		 * XXXARM: are we missing subtleties here in the rest of the
		 * mapping pointer and access attributes? I suspect we are.
		 */
		switch (rs->phys_hi & ACPIDEV_REG_TYPE_M) {
		case ACPIDEV_REG_TYPE_MEMORY:
			rp.regspec_bustype = 0;
			break;
		case ACPIDEV_REG_TYPE_IO:
			rp.regspec_bustype = 1;
			break;
		default:
			prom_printf("acpinex_bus_map: %s%d: unknonwn ACPI register type %d\n",
				ddi_node_name(dip), ddi_get_instance(dip), rs->phys_hi & ACPIDEV_REG_TYPE_M);
			return (DDI_FAILURE);
		}

		// XXXARM: mash flags into the mapping request
		// mp is ddi_map_req_t
		// mp->map_handlep is ddi_acc_hdl_t, which is (AFAIK) what we need to populate
		// ddi_acc_hdl_t has ddi_device_acc_attr_t (ah_acc)
#if 0
#define DDI_STRICTORDER_ACC     0x00
#define DDI_UNORDERED_OK_ACC    0x01
#define DDI_MERGING_OK_ACC      0x02
#define DDI_LOADCACHING_OK_ACC  0x03
#define DDI_STORECACHING_OK_ACC 0x04
		mp->map_handlep;
#endif

		mp->map_type = DDI_MT_REGSPEC;
		mp->map_flags |= DDI_MF_EXT_REGSPEC;
		mp->map_obj.rp = (struct regspec *)&rp;
	}

	return ((DEVI(pdip)->devi_ops->devo_bus_ops->bus_map)(
	    pdip, rdip, mp, offset, len, vaddrp));
}
#else
/* ARGSUSED */
static int
acpinex_bus_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
    off_t offset, off_t len, caddr_t *vaddrp)
{
	ACPINEX_DEBUG(CE_WARN,
	    "!acpinex: acpinex_bus_map called and it's unimplemented.");
	return (DDI_ME_UNIMPLEMENTED);
}
#endif

/*
 * XXXARM: remind me why we need ioctls and device node glue?
 */

static int
acpinex_open(dev_t *devi, int flags, int otyp, cred_t *credp)
{
	_NOTE(ARGUNUSED(flags, otyp, credp));

	minor_t minor, instance;
	acpinex_softstate_t *softsp;

	minor = getminor(*devi);
	instance = ACPINEX_GET_INSTANCE(minor);
	if (instance >= ACPINEX_INSTANCE_MAX) {
		ACPINEX_DEBUG(CE_WARN, "!acpinex: instance number %d out of "
		    "range in acpinex_open, max %d.",
		    instance, ACPINEX_INSTANCE_MAX - 1);
		return (EINVAL);
	}

	softsp = ddi_get_soft_state(acpinex_softstates, instance);
	if (softsp == NULL) {
		ACPINEX_DEBUG(CE_WARN, "!acpinex: failed to get soft state "
		    "object for instance %d in acpinex_open().", instance);
		return (EINVAL);
	}

	if (ACPINEX_IS_DEVCTL(minor)) {
		return (0);
	} else {
		ACPINEX_DEBUG(CE_WARN,
		    "!acpinex: invalid minor number %d in acpinex_open().",
		    minor);
		return (EINVAL);
	}
}

static int
acpinex_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	_NOTE(ARGUNUSED(flags, otyp, credp));

	minor_t minor, instance;
	acpinex_softstate_t *softsp;

	minor = getminor(dev);
	instance = ACPINEX_GET_INSTANCE(minor);
	if (instance >= ACPINEX_INSTANCE_MAX) {
		ACPINEX_DEBUG(CE_WARN, "!acpinex: instance number %d out of "
		    "range in acpinex_close(), max %d.",
		    instance, ACPINEX_INSTANCE_MAX - 1);
		return (EINVAL);
	}

	softsp = ddi_get_soft_state(acpinex_softstates, instance);
	if (softsp == NULL) {
		ACPINEX_DEBUG(CE_WARN, "!acpinex: failed to get soft state "
		    "object for instance %d in acpinex_close().", instance);
		return (EINVAL);
	}

	if (ACPINEX_IS_DEVCTL(minor)) {
		return (0);
	} else {
		ACPINEX_DEBUG(CE_WARN,
		    "!acpinex: invalid minor number %d in acpinex_close().",
		    minor);
		return (EINVAL);
	}
}

static int
acpinex_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	_NOTE(ARGUNUSED(cmd, arg, mode, credp, rvalp));

	int rv = 0;
	minor_t minor, instance;
	acpinex_softstate_t *softsp;

	minor = getminor(dev);
	instance = ACPINEX_GET_INSTANCE(minor);
	if (instance >= ACPINEX_INSTANCE_MAX) {
		ACPINEX_DEBUG(CE_NOTE, "!acpinex: instance number %d out of "
		    "range in acpinex_ioctl(), max %d.",
		    instance, ACPINEX_INSTANCE_MAX - 1);
		return (EINVAL);
	}
	softsp = ddi_get_soft_state(acpinex_softstates, instance);
	if (softsp == NULL) {
		ACPINEX_DEBUG(CE_WARN, "!acpinex: failed to get soft state "
		    "object for instance %d in acpinex_ioctl().", instance);
		return (EINVAL);
	}

	rv = ENOTSUP;
	ACPINEX_DEBUG(CE_WARN,
	    "!acpinex: invalid minor number %d in acpinex_ioctl().", minor);

	return (rv);
}

/*
 * FMA error callback.
 * Register error handling callback with our parent. We will just call
 * our children's error callbacks and return their status.
 */
static int
acpinex_err_callback(dev_info_t *dip, ddi_fm_error_t *derr,
    const void *impl_data)
{
	_NOTE(ARGUNUSED(impl_data));

	/* Call our childrens error handlers */
	return (ndi_fm_handler_dispatch(dip, NULL, derr));
}

/*
 * Initialize our FMA resources
 */
static void
acpinex_fm_init(acpinex_softstate_t *softsp)
{
	softsp->ans_fm_cap = DDI_FM_EREPORT_CAPABLE | DDI_FM_ERRCB_CAPABLE |
	    DDI_FM_ACCCHK_CAPABLE | DDI_FM_DMACHK_CAPABLE;

	/*
	 * Request our capability level and get our parent's capability and ibc.
	 */
	ddi_fm_init(softsp->ans_dip, &softsp->ans_fm_cap, &softsp->ans_fm_ibc);
	if (softsp->ans_fm_cap & DDI_FM_ERRCB_CAPABLE) {
		/*
		 * Register error callback with our parent if supported.
		 */
		ddi_fm_handler_register(softsp->ans_dip, acpinex_err_callback,
		    softsp);
	}
}

/*
 * Breakdown our FMA resources
 */
static void
acpinex_fm_fini(acpinex_softstate_t *softsp)
{
	/* Clean up allocated fm structures */
	if (softsp->ans_fm_cap & DDI_FM_ERRCB_CAPABLE) {
		ddi_fm_handler_unregister(softsp->ans_dip);
	}
	ddi_fm_fini(softsp->ans_dip);
}

/*
 * Initialize FMA resources for child devices.
 * Called when child calls ddi_fm_init().
 */
static int
acpinex_fm_init_child(dev_info_t *dip, dev_info_t *tdip, int cap,
    ddi_iblock_cookie_t *ibc)
{
	_NOTE(ARGUNUSED(tdip, cap));

	acpinex_softstate_t *softsp = ddi_get_soft_state(acpinex_softstates,
	    ddi_get_instance(dip));

	*ibc = softsp->ans_fm_ibc;

	return (softsp->ans_fm_cap);
}
