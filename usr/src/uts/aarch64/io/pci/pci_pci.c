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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2012 Garrett D'Amore <garrett@damore.org>.  All rights reserved.
 * Copyright 2018 Joyent, Inc.
 * Copyright 2026 Michael van der Westhuizen
 */

/*
 * PCI to PCI bus bridge nexus driver for aarch64.
 *
 * Derived from the x86 pci_pci driver with the following changes:
 * - HyperTransport MSI mapping removed (x86-only hardware feature)
 * - npe parent driver checks replaced with parent_bus PCIe detection
 * - MSI capability through PCI bridges determined by the interrupt
 *   framework rather than HT capability scanning
 */

#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/modctl.h>
#include <sys/autoconf.h>
#include <sys/ddi_impldefs.h>
#include <sys/pci.h>
#include <sys/pci_impl.h>
#include <sys/pcie_impl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ddifm.h>
#include <sys/ndifm.h>
#include <sys/fm/protocol.h>
#include <sys/hotplug/pci/pcie_hp.h>
#include <sys/hotplug/pci/pcihp.h>

/*
 * The variable controls the default setting of the command register
 * for pci devices.  See ppb_initchild() for details.
 */
static ushort_t ppb_command_default = PCI_COMM_ME | PCI_COMM_MAE | PCI_COMM_IO;


static int	ppb_bus_map(dev_info_t *, dev_info_t *, ddi_map_req_t *,
		    off_t, off_t, caddr_t *);
static int	ppb_ctlops(dev_info_t *, dev_info_t *, ddi_ctl_enum_t,
		    void *, void *);
static int	ppb_fm_init(dev_info_t *, dev_info_t *, int,
		    ddi_iblock_cookie_t *);
static int	ppb_fm_callback(dev_info_t *, ddi_fm_error_t *, const void *);
static int	ppb_intr_ops(dev_info_t *, dev_info_t *, ddi_intr_op_t,
		    ddi_intr_handle_impl_t *, void *);

struct bus_ops ppb_bus_ops = {
	BUSO_REV,
	ppb_bus_map,
	0,
	0,
	0,
	i_ddi_map_fault,
	0,
	ddi_dma_allochdl,
	ddi_dma_freehdl,
	ddi_dma_bindhdl,
	ddi_dma_unbindhdl,
	ddi_dma_flush,
	ddi_dma_win,
	ddi_dma_mctl,
	ppb_ctlops,
	ddi_bus_prop_op,
	0,			/* (*bus_get_eventcookie)();	*/
	0,			/* (*bus_add_eventcall)();	*/
	0,			/* (*bus_remove_eventcall)();	*/
	0,			/* (*bus_post_event)();		*/
	0,			/* (*bus_intr_ctl)();		*/
	0,			/* (*bus_config)();		*/
	0,			/* (*bus_unconfig)();		*/
	ppb_fm_init,		/* (*bus_fm_init)();		*/
	NULL,			/* (*bus_fm_fini)();		*/
	NULL,			/* (*bus_fm_access_enter)();	*/
	NULL,			/* (*bus_fm_access_exit)();	*/
	NULL,			/* (*bus_power)();		*/
	ppb_intr_ops,		/* (*bus_intr_op)();		*/
	pcie_hp_common_ops	/* (*bus_hp_op)();		*/
};

/*
 * The goal here is to leverage off of the pcihp.c source without making
 * changes to it.  Call into its cb_ops directly if needed.
 */
static int	ppb_open(dev_t *, int, int, cred_t *);
static int	ppb_close(dev_t, int, int, cred_t *);
static int	ppb_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int	ppb_prop_op(dev_t, dev_info_t *, ddi_prop_op_t, int, char *,
		    caddr_t, int *);
static int	ppb_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static void	ppb_peekpoke_cb(dev_info_t *, ddi_fm_error_t *);

struct cb_ops ppb_cb_ops = {
	ppb_open,			/* open */
	ppb_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	ppb_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	ppb_prop_op,			/* cb_prop_op */
	NULL,				/* streamtab */
	D_NEW | D_MP | D_HOTPLUG,	/* Driver compatibility flag */
	CB_REV,				/* rev */
	nodev,				/* int (*cb_aread)() */
	nodev				/* int (*cb_awrite)() */
};


static int ppb_probe(dev_info_t *);
static int ppb_attach(dev_info_t *devi, ddi_attach_cmd_t cmd);
static int ppb_detach(dev_info_t *devi, ddi_detach_cmd_t cmd);

struct dev_ops ppb_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt  */
	ppb_info,		/* info */
	nulldev,		/* identify */
	ppb_probe,		/* probe */
	ppb_attach,		/* attach */
	ppb_detach,		/* detach */
	nulldev,		/* reset */
	&ppb_cb_ops,		/* driver operations */
	&ppb_bus_ops,		/* bus operations */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

/*
 * Module linkage information for the kernel.
 */

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module */
	"Standard PCI to PCI bridge nexus driver",
	&ppb_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

/*
 * soft state pointer and structure template:
 */
static void *ppb_state;

typedef struct {
	dev_info_t *dip;
	int ppb_fmcap;
	ddi_iblock_cookie_t ppb_fm_ibc;
	kmutex_t ppb_mutex;
	kmutex_t ppb_peek_poke_mutex;
	kmutex_t ppb_err_mutex;

	/*
	 * cpr support:
	 */
	uint_t config_state_index;
	struct {
		dev_info_t *dip;
		ushort_t command;
		uchar_t cache_line_size;
		uchar_t latency_timer;
		uchar_t header_type;
		uchar_t sec_latency_timer;
		ushort_t bridge_control;
	} config_state[PCI_MAX_CHILDREN];

	uint16_t parent_bus;
} ppb_devstate_t;


/*
 * forward function declarations:
 */
static void	ppb_removechild(dev_info_t *);
static int	ppb_initchild(dev_info_t *child);
static void	ppb_save_config_regs(ppb_devstate_t *ppb_p);
static void	ppb_restore_config_regs(ppb_devstate_t *ppb_p);


int
_init(void)
{
	int e;

	if ((e = ddi_soft_state_init(&ppb_state, sizeof (ppb_devstate_t),
	    1)) == 0 && (e = mod_install(&modlinkage)) != 0)
		ddi_soft_state_fini(&ppb_state);
	return (e);
}

int
_fini(void)
{
	int e;

	if ((e = mod_remove(&modlinkage)) == 0)
		ddi_soft_state_fini(&ppb_state);
	return (e);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*ARGSUSED*/
static int
ppb_probe(dev_info_t *devi)
{
	return (DDI_PROBE_SUCCESS);
}

/*ARGSUSED*/
static int
ppb_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	dev_info_t *root = ddi_root_node();
	int instance;
	ppb_devstate_t *ppb;
	dev_info_t *pdip;
	ddi_acc_handle_t config_handle;
	char *bus;
	int ret;

	switch (cmd) {
	case DDI_ATTACH:

		/*
		 * Make sure the "device_type" property exists.
		 */
		(void) ddi_prop_update_string(DDI_DEV_T_NONE, devi,
		    "device_type", "pci");

		/*
		 * Allocate and get soft state structure.
		 */
		instance = ddi_get_instance(devi);
		if (ddi_soft_state_zalloc(ppb_state, instance) != DDI_SUCCESS)
			return (DDI_FAILURE);
		ppb = ddi_get_soft_state(ppb_state, instance);
		ppb->dip = devi;

		/*
		 * Determine whether we sit under a PCIe hierarchy.
		 * Walk ancestors looking for device_type "pciex".
		 */
		ppb->parent_bus = PCIE_PCIECAP_DEV_TYPE_PCI_PSEUDO;
		for (pdip = ddi_get_parent(devi); pdip && (pdip != root) &&
		    (ppb->parent_bus != PCIE_PCIECAP_DEV_TYPE_PCIE_DEV);
		    pdip = ddi_get_parent(pdip)) {
			if (ddi_prop_lookup_string(DDI_DEV_T_ANY, pdip,
			    DDI_PROP_DONTPASS, "device_type", &bus) !=
			    DDI_PROP_SUCCESS)
				break;

			if (strcmp(bus, "pciex") == 0)
				ppb->parent_bus =
				    PCIE_PCIECAP_DEV_TYPE_PCIE_DEV;

			ddi_prop_free(bus);
		}

		/*
		 * When under a PCIe parent (e.g. pcieb, ecam), the PCIe
		 * fabric error handling framework manages ereports.
		 * Otherwise generate them ourselves.
		 */
		if (ppb->parent_bus == PCIE_PCIECAP_DEV_TYPE_PCIE_DEV)
			ppb->ppb_fmcap = DDI_FM_ERRCB_CAPABLE |
			    DDI_FM_ACCCHK_CAPABLE | DDI_FM_DMACHK_CAPABLE;
		else
			ppb->ppb_fmcap = DDI_FM_EREPORT_CAPABLE |
			    DDI_FM_ERRCB_CAPABLE | DDI_FM_ACCCHK_CAPABLE |
			    DDI_FM_DMACHK_CAPABLE;

		ddi_fm_init(devi, &ppb->ppb_fmcap, &ppb->ppb_fm_ibc);
		mutex_init(&ppb->ppb_mutex, NULL, MUTEX_DRIVER, NULL);
		mutex_init(&ppb->ppb_err_mutex, NULL, MUTEX_DRIVER,
		    (void *)ppb->ppb_fm_ibc);
		mutex_init(&ppb->ppb_peek_poke_mutex, NULL, MUTEX_DRIVER,
		    (void *)ppb->ppb_fm_ibc);

		if (ppb->ppb_fmcap & (DDI_FM_ERRCB_CAPABLE |
		    DDI_FM_EREPORT_CAPABLE))
			pci_ereport_setup(devi);
		if (ppb->ppb_fmcap & DDI_FM_ERRCB_CAPABLE)
			ddi_fm_handler_register(devi, ppb_fm_callback, NULL);

		if (pci_config_setup(devi, &config_handle) != DDI_SUCCESS) {
			if (ppb->ppb_fmcap & DDI_FM_ERRCB_CAPABLE)
				ddi_fm_handler_unregister(devi);
			if (ppb->ppb_fmcap & (DDI_FM_ERRCB_CAPABLE |
			    DDI_FM_EREPORT_CAPABLE))
				pci_ereport_teardown(devi);
			ddi_fm_fini(devi);
			ddi_soft_state_free(ppb_state, instance);
			return (DDI_FAILURE);
		}

		pci_config_teardown(&config_handle);

		/*
		 * Initialize hotplug support on this bus.
		 */
		if (ppb->parent_bus == PCIE_PCIECAP_DEV_TYPE_PCIE_DEV) {
			ret = pcie_init(devi, NULL);
		} else {
			ret = pcihp_init(devi);
		}

		if (ret != DDI_SUCCESS) {
			cmn_err(CE_WARN,
			    "pci: Failed to setup hotplug framework");
			(void) ppb_detach(devi, DDI_DETACH);
			return (ret);
		}

		ddi_report_dev(devi);
		return (DDI_SUCCESS);

	case DDI_RESUME:

		/*
		 * Get the soft state structure for the bridge.
		 */
		ppb = ddi_get_soft_state(ppb_state, ddi_get_instance(devi));
		ppb_restore_config_regs(ppb);
		return (DDI_SUCCESS);

	default:
		break;
	}
	return (DDI_FAILURE);
}

/*ARGSUSED*/
static int
ppb_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	ppb_devstate_t *ppb;
	int		ret;

	switch (cmd) {
	case DDI_DETACH:
		(void) ddi_prop_remove(DDI_DEV_T_NONE, devi, "device_type");

		ppb = ddi_get_soft_state(ppb_state, ddi_get_instance(devi));
		if (ppb->ppb_fmcap & DDI_FM_ERRCB_CAPABLE)
			ddi_fm_handler_unregister(devi);
		if (ppb->ppb_fmcap & (DDI_FM_ERRCB_CAPABLE |
		    DDI_FM_EREPORT_CAPABLE))
			pci_ereport_teardown(devi);

		/*
		 * Uninitialize hotplug support on this bus.
		 */
		ret = (ppb->parent_bus == PCIE_PCIECAP_DEV_TYPE_PCIE_DEV) ?
		    pcie_uninit(devi) : pcihp_uninit(devi);
		if (ret != DDI_SUCCESS)
			return (DDI_FAILURE);

		mutex_destroy(&ppb->ppb_peek_poke_mutex);
		mutex_destroy(&ppb->ppb_err_mutex);
		mutex_destroy(&ppb->ppb_mutex);
		ddi_fm_fini(devi);

		/*
		 * And finally free the per-pci soft state.
		 */
		ddi_soft_state_free(ppb_state, ddi_get_instance(devi));

		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		ppb = ddi_get_soft_state(ppb_state, ddi_get_instance(devi));
		ppb_save_config_regs(ppb);
		return (DDI_SUCCESS);

	default:
		break;
	}
	return (DDI_FAILURE);
}

/*ARGSUSED*/
static int
ppb_bus_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
    off_t offset, off_t len, caddr_t *vaddrp)
{
	dev_info_t *pdip;
	ppb_devstate_t *ppb = ddi_get_soft_state(ppb_state,
	    ddi_get_instance(dip));

	/*
	 * When under a PCIe parent, set up FM peek/poke hooks so that
	 * config space access errors are caught by the fabric error handler.
	 */
	if (ppb->parent_bus == PCIE_PCIECAP_DEV_TYPE_PCIE_DEV &&
	    mp->map_handlep != NULL) {
		ddi_acc_impl_t *hdlp =
		    (ddi_acc_impl_t *)(mp->map_handlep)->ah_platform_private;
		hdlp->ahi_err_mutexp = &ppb->ppb_err_mutex;
		hdlp->ahi_peekpoke_mutexp = &ppb->ppb_peek_poke_mutex;
		hdlp->ahi_scan_dip = dip;
		hdlp->ahi_scan = ppb_peekpoke_cb;
	}
	pdip = (dev_info_t *)DEVI(dip)->devi_parent;
	return ((DEVI(pdip)->devi_ops->devo_bus_ops->bus_map)(pdip,
	    rdip, mp, offset, len, vaddrp));
}

/*ARGSUSED*/
static int
ppb_ctlops(dev_info_t *dip, dev_info_t *rdip,
    ddi_ctl_enum_t ctlop, void *arg, void *result)
{
	pci_regspec_t *drv_regp;
	uint_t	reglen;
	int	rn;
	int	totreg;
	ppb_devstate_t *ppb = ddi_get_soft_state(ppb_state,
	    ddi_get_instance(dip));
	struct detachspec *dsp;
	struct attachspec *asp;

	switch (ctlop) {
	case DDI_CTLOPS_REPORTDEV:
		if (rdip == (dev_info_t *)0)
			return (DDI_FAILURE);
		cmn_err(CE_CONT, "?PCI-device: %s@%s, %s%d\n",
		    ddi_node_name(rdip), ddi_get_name_addr(rdip),
		    ddi_driver_name(rdip),
		    ddi_get_instance(rdip));
		return (DDI_SUCCESS);

	case DDI_CTLOPS_INITCHILD:
		return (ppb_initchild((dev_info_t *)arg));

	case DDI_CTLOPS_UNINITCHILD:
		ppb_removechild((dev_info_t *)arg);
		return (DDI_SUCCESS);

	case DDI_CTLOPS_SIDDEV:
		return (DDI_SUCCESS);

	case DDI_CTLOPS_REGSIZE:
	case DDI_CTLOPS_NREGS:
		if (rdip == (dev_info_t *)0)
			return (DDI_FAILURE);
		break;

	case DDI_CTLOPS_ATTACH:
		if (!pcie_is_child(dip, rdip)) {
			return (DDI_SUCCESS);
		}

		asp = (struct attachspec *)arg;
		if ((ppb->parent_bus == PCIE_PCIECAP_DEV_TYPE_PCIE_DEV) &&
		    (asp->when == DDI_POST) && (asp->result == DDI_SUCCESS))
			pf_init(rdip, (void *)ppb->ppb_fm_ibc, asp->cmd);

		if (asp->cmd == DDI_RESUME && asp->when == DDI_PRE)
			if (pci_pre_resume(rdip) != DDI_SUCCESS) {
				return (DDI_FAILURE);
			}

		return (DDI_SUCCESS);

	case DDI_CTLOPS_DETACH:
		if (!pcie_is_child(dip, rdip)) {
			return (DDI_SUCCESS);
		}

		dsp = (struct detachspec *)arg;
		if ((ppb->parent_bus == PCIE_PCIECAP_DEV_TYPE_PCIE_DEV) &&
		    (dsp->when == DDI_PRE))
			pf_fini(rdip, dsp->cmd);

		if (dsp->cmd == DDI_SUSPEND && dsp->when == DDI_POST)
			if (pci_post_suspend(rdip) != DDI_SUCCESS) {
				return (DDI_FAILURE);
			}

		return (DDI_SUCCESS);

	case DDI_CTLOPS_PEEK:
	case DDI_CTLOPS_POKE:
		if (ppb->parent_bus != PCIE_PCIECAP_DEV_TYPE_PCIE_DEV) {
			return (ddi_ctlops(dip, rdip, ctlop, arg, result));
		}
		return (pci_peekpoke_check(dip, rdip, ctlop, arg, result,
		    ddi_ctlops, &ppb->ppb_err_mutex,
		    &ppb->ppb_peek_poke_mutex, ppb_peekpoke_cb));

	default:
		return (ddi_ctlops(dip, rdip, ctlop, arg, result));
	}

	*(int *)result = 0;
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, rdip, DDI_PROP_DONTPASS,
	    "reg", (int **)&drv_regp, &reglen) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	totreg = CELLS_1275_TO_BYTES(reglen) / sizeof (pci_regspec_t);
	if (ctlop == DDI_CTLOPS_NREGS)
		*(int *)result = totreg;
	else if (ctlop == DDI_CTLOPS_REGSIZE) {
		uint64_t rs;

		rn = *(int *)arg;
		if (rn >= totreg) {
			ddi_prop_free(drv_regp);
			return (DDI_FAILURE);
		}

		rs = drv_regp[rn].pci_size_low |
		    ((uint64_t)drv_regp[rn].pci_size_hi << 32);
		if (rs > OFF_MAX) {
			ddi_prop_free(drv_regp);
			return (DDI_FAILURE);
		}
		*(off_t *)result = rs;
	}

	ddi_prop_free(drv_regp);
	return (DDI_SUCCESS);
}

static int
ppb_name_child(dev_info_t *child, char *name, int namelen)
{
	pci_regspec_t *pci_rp;
	uint_t slot, func;
	char **unit_addr;
	uint_t n;

	/*
	 * For .conf nodes, use unit-address property as name
	 */
	if (ndi_dev_is_persistent_node(child) == 0) {
		if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY, child,
		    DDI_PROP_DONTPASS, "unit-address", &unit_addr, &n) !=
		    DDI_PROP_SUCCESS) {
			cmn_err(CE_WARN,
			    "cannot find unit-address in %s.conf",
			    ddi_driver_name(child));
			return (DDI_FAILURE);
		}
		if (n != 1 || *unit_addr == NULL || **unit_addr == 0) {
			cmn_err(CE_WARN, "unit-address property in %s.conf"
			    " not well-formed", ddi_driver_name(child));
			ddi_prop_free(unit_addr);
			return (DDI_SUCCESS);
		}
		(void) snprintf(name, namelen, "%s", *unit_addr);
		ddi_prop_free(unit_addr);
		return (DDI_SUCCESS);
	}

	/* get child "reg" property */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, child,
	    DDI_PROP_DONTPASS, "reg", (int **)&pci_rp, &n) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/* copy the device identifications */
	slot = PCI_REG_DEV_G(pci_rp->pci_phys_hi);
	func = PCI_REG_FUNC_G(pci_rp->pci_phys_hi);

	if (func != 0)
		(void) snprintf(name, namelen, "%x,%x", slot, func);
	else
		(void) snprintf(name, namelen, "%x", slot);

	ddi_prop_free(pci_rp);
	return (DDI_SUCCESS);
}

static int
ppb_initchild(dev_info_t *child)
{
	struct ddi_parent_private_data *pdptr;
	ppb_devstate_t *ppb;
	char name[MAXNAMELEN];
	ddi_acc_handle_t config_handle;
	ushort_t command_preserve, command;

	ppb = (ppb_devstate_t *)ddi_get_soft_state(ppb_state,
	    ddi_get_instance(ddi_get_parent(child)));

	if (ppb_name_child(child, name, MAXNAMELEN) != DDI_SUCCESS)
		return (DDI_FAILURE);
	ddi_set_name_addr(child, name);

	/*
	 * Pseudo nodes indicate a prototype node with per-instance
	 * properties to be merged into the real h/w device node.
	 * The interpretation of the unit-address is DD[,F]
	 * where DD is the device id and F is the function.
	 */
	if (ndi_dev_is_persistent_node(child) == 0) {
		extern int pci_allow_pseudo_children;

		ddi_set_parent_data(child, NULL);

		/*
		 * Try to merge the properties from this prototype
		 * node into real h/w nodes.
		 */
		if (ndi_merge_node(child, ppb_name_child) == DDI_SUCCESS) {
			/*
			 * Merged ok - return failure to remove the node.
			 */
			ddi_set_name_addr(child, NULL);
			return (DDI_FAILURE);
		}

		/* workaround for ddivs to run under PCI */
		if (pci_allow_pseudo_children)
			return (DDI_SUCCESS);

		/*
		 * The child was not merged into a h/w node,
		 * but there's not much we can do with it other
		 * than return failure to cause the node to be removed.
		 */
		cmn_err(CE_WARN, "!%s@%s: %s.conf properties not merged",
		    ddi_driver_name(child), ddi_get_name_addr(child),
		    ddi_driver_name(child));
		ddi_set_name_addr(child, NULL);
		return (DDI_NOT_WELL_FORMED);
	}

	ddi_set_parent_data(child, NULL);

	/*
	 * PCIe FMA specific
	 *
	 * Note: parent_data for parent is created only if this is PCI-E
	 * platform, for which, SG take a different route to handle device
	 * errors.
	 */
	if (ppb->parent_bus == PCIE_PCIECAP_DEV_TYPE_PCIE_DEV) {
		if (pcie_init_cfghdl(child) != DDI_SUCCESS)
			return (DDI_FAILURE);
		pcie_init_dom(child);
	}

	/* transfer select properties from PROM to kernel */
	if (ddi_prop_get_int(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
	    "interrupts", -1) != -1) {
		pdptr = kmem_zalloc((sizeof (struct ddi_parent_private_data) +
		    sizeof (struct intrspec)), KM_SLEEP);
		pdptr->par_intr = (struct intrspec *)(pdptr + 1);
		pdptr->par_nintr = 1;
		ddi_set_parent_data(child, pdptr);
	} else
		ddi_set_parent_data(child, NULL);

	if (pci_config_setup(child, &config_handle) != DDI_SUCCESS) {
		pcie_fini_dom(child);
		return (DDI_FAILURE);
	}

	/*
	 * Support for the "command-preserve" property.
	 */
	command_preserve = ddi_prop_get_int(DDI_DEV_T_ANY, child,
	    DDI_PROP_DONTPASS, "command-preserve", 0);
	command = pci_config_get16(config_handle, PCI_CONF_COMM);
	command &= (command_preserve | PCI_COMM_BACK2BACK_ENAB);
	command |= (ppb_command_default & ~command_preserve);
	pci_config_put16(config_handle, PCI_CONF_COMM, command);

	pci_config_teardown(&config_handle);
	return (DDI_SUCCESS);
}

static void
ppb_removechild(dev_info_t *dip)
{
	struct ddi_parent_private_data *pdptr;
	ppb_devstate_t *ppb;

	ppb = (ppb_devstate_t *)ddi_get_soft_state(ppb_state,
	    ddi_get_instance(ddi_get_parent(dip)));

	if (ppb->parent_bus == PCIE_PCIECAP_DEV_TYPE_PCIE_DEV) {
		pcie_fini_dom(dip);
		pcie_fini_cfghdl(dip);
	} else if ((pdptr = ddi_get_parent_data(dip)) != NULL) {
		kmem_free(pdptr, (sizeof (*pdptr) + sizeof (struct intrspec)));
		ddi_set_parent_data(dip, NULL);
	}
	ddi_set_name_addr(dip, NULL);

	/*
	 * Strip the node to properly convert it back to prototype form
	 */
	ddi_remove_minor_node(dip, NULL);

	impl_rem_dev_props(dip);
}

/*
 * ppb_save_config_regs
 *
 * This routine saves the state of the configuration registers of all
 * the child nodes of each PBM.
 *
 * used by: ppb_detach() on suspends
 *
 * return value: none
 */
static void
ppb_save_config_regs(ppb_devstate_t *ppb_p)
{
	int i;
	dev_info_t *dip;
	ddi_acc_handle_t config_handle;

	for (i = 0, dip = ddi_get_child(ppb_p->dip); dip != NULL;
	    i++, dip = ddi_get_next_sibling(dip)) {

		if (pci_config_setup(dip, &config_handle) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s%d: can't config space for %s%d\n",
			    ddi_driver_name(ppb_p->dip),
			    ddi_get_instance(ppb_p->dip),
			    ddi_driver_name(dip),
			    ddi_get_instance(dip));
			continue;
		}

		ppb_p->config_state[i].dip = dip;
		ppb_p->config_state[i].command =
		    pci_config_get16(config_handle, PCI_CONF_COMM);
		pci_config_teardown(&config_handle);
	}
	ppb_p->config_state_index = i;
}


/*
 * ppb_restore_config_regs
 *
 * This routine restores the state of the configuration registers of all
 * the child nodes of each PBM.
 *
 * used by: ppb_attach() on resume
 *
 * return value: none
 */
static void
ppb_restore_config_regs(ppb_devstate_t *ppb_p)
{
	int i;
	dev_info_t *dip;
	ddi_acc_handle_t config_handle;

	for (i = 0; i < ppb_p->config_state_index; i++) {
		dip = ppb_p->config_state[i].dip;
		if (pci_config_setup(dip, &config_handle) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s%d: can't config space for %s%d\n",
			    ddi_driver_name(ppb_p->dip),
			    ddi_get_instance(ppb_p->dip),
			    ddi_driver_name(dip),
			    ddi_get_instance(dip));
			continue;
		}
		pci_config_put16(config_handle, PCI_CONF_COMM,
		    ppb_p->config_state[i].command);
		pci_config_teardown(&config_handle);
	}
}


/*
 * On aarch64, MSI through PCI bridges is determined by the interrupt
 * framework and the GIC MSI controller — there is no HyperTransport
 * MSI mapping to check.  Forward all interrupt operations, including
 * SUPPORTED_TYPES, to the framework.
 */
static int
ppb_intr_ops(dev_info_t *pdip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	return (i_ddi_intr_ops(pdip, rdip, intr_op, hdlp, result));
}

/* ARGSUSED */
static int
ppb_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	int		instance = PCI_MINOR_NUM_TO_INSTANCE(getminor(*devp));
	ppb_devstate_t	*ppb_p = ddi_get_soft_state(ppb_state, instance);
	int	rv;

	if (ppb_p == NULL)
		return (ENXIO);

	/*
	 * Ioctls will be handled by PCI Express framework for all
	 * PCIe platforms
	 */
	if (ppb_p->parent_bus == PCIE_PCIECAP_DEV_TYPE_PCIE_DEV) {
		mutex_enter(&ppb_p->ppb_mutex);
		rv = pcie_open(ppb_p->dip, devp, flags, otyp, credp);
		mutex_exit(&ppb_p->ppb_mutex);
		return (rv);
	}

	return ((pcihp_get_cb_ops())->cb_open(devp, flags, otyp, credp));
}

/* ARGSUSED */
static int
ppb_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	int		instance = PCI_MINOR_NUM_TO_INSTANCE(getminor(dev));
	ppb_devstate_t	*ppb_p = ddi_get_soft_state(ppb_state, instance);
	int	rv;

	if (ppb_p == NULL)
		return (ENXIO);

	mutex_enter(&ppb_p->ppb_mutex);
	/*
	 * Ioctls will be handled by PCI Express framework for all
	 * PCIe platforms
	 */
	if (ppb_p->parent_bus == PCIE_PCIECAP_DEV_TYPE_PCIE_DEV) {
		rv = pcie_close(ppb_p->dip, dev, flags, otyp, credp);
		mutex_exit(&ppb_p->ppb_mutex);
		return (rv);
	}

	mutex_exit(&ppb_p->ppb_mutex);
	return ((pcihp_get_cb_ops())->cb_close(dev, flags, otyp, credp));
}

/*
 * ppb_ioctl: devctl hotplug controls
 */
/* ARGSUSED */
static int
ppb_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	int		instance = PCI_MINOR_NUM_TO_INSTANCE(getminor(dev));
	ppb_devstate_t	*ppb_p = ddi_get_soft_state(ppb_state, instance);

	if (ppb_p == NULL)
		return (ENXIO);

	/*
	 * Ioctls will be handled by PCI Express framework for all
	 * PCIe platforms
	 */
	if (ppb_p->parent_bus == PCIE_PCIECAP_DEV_TYPE_PCIE_DEV)
		return (pcie_ioctl(ppb_p->dip, dev, cmd, arg, mode, credp,
		    rvalp));

	return ((pcihp_get_cb_ops())->cb_ioctl(dev, cmd, arg, mode, credp,
	    rvalp));
}

static int
ppb_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op, int flags,
    char *name, caddr_t valuep, int *lengthp)
{
	int		instance = PCI_MINOR_NUM_TO_INSTANCE(getminor(dev));
	ppb_devstate_t	*ppb_p = ddi_get_soft_state(ppb_state, instance);

	if (ppb_p == NULL)
		return (ENXIO);

	if (ppb_p->parent_bus == PCIE_PCIECAP_DEV_TYPE_PCIE_DEV)
		return (pcie_prop_op(dev, dip, prop_op, flags, name,
		    valuep, lengthp));

	return ((pcihp_get_cb_ops())->cb_prop_op(dev, dip, prop_op, flags,
	    name, valuep, lengthp));
}

static int
ppb_info(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	minor_t		minor = getminor((dev_t)arg);
	int		instance = PCI_MINOR_NUM_TO_INSTANCE(minor);
	ppb_devstate_t	*ppb_p = ddi_get_soft_state(ppb_state, instance);

	if (ppb_p == NULL)
		return (DDI_FAILURE);

	if (ppb_p->parent_bus != PCIE_PCIECAP_DEV_TYPE_PCIE_DEV)
		return (pcihp_info(dip, cmd, arg, result));

	switch (cmd) {
	default:
		return (DDI_FAILURE);

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)instance;
		return (DDI_SUCCESS);

	case DDI_INFO_DEVT2DEVINFO:
		if (ppb_p == NULL)
			return (DDI_FAILURE);
		*result = (void *)ppb_p->dip;
		return (DDI_SUCCESS);
	}
}

void
ppb_peekpoke_cb(dev_info_t *dip, ddi_fm_error_t *derr)
{
	(void) pci_ereport_post(dip, derr, NULL);
}

/*ARGSUSED*/
static int
ppb_fm_init(dev_info_t *dip, dev_info_t *tdip, int cap,
    ddi_iblock_cookie_t *ibc)
{
	ppb_devstate_t  *ppb = ddi_get_soft_state(ppb_state,
	    ddi_get_instance(dip));

	ASSERT(ibc != NULL);
	*ibc = ppb->ppb_fm_ibc;

	return (ppb->ppb_fmcap);
}

/*ARGSUSED*/
static int
ppb_fm_callback(dev_info_t *dip, ddi_fm_error_t *derr, const void *no_used)
{
	ppb_devstate_t  *ppb = ddi_get_soft_state(ppb_state,
	    ddi_get_instance(dip));

	mutex_enter(&ppb->ppb_err_mutex);
	pci_ereport_post(dip, derr, NULL);
	mutex_exit(&ppb->ppb_err_mutex);
	return (derr->fme_status);
}
