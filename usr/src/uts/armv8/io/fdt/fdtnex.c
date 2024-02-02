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
 * Copyright 2024 Michael van der Westhuizen
 */

/*
 * Flattened Device Tree Nexus Driver
 *
 * This nexus exists to separate FDT-specifics from the rootnex, allowing
 * rootnex to be more easily shared between ACPI and FDT-based machines.
 *
 * Specific knowledge of FDT should leak no further than this nexus (with very
 * few exceptions in rootnex and in machdep code).
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/devops.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/dditypes.h>
#include <sys/ddi_implfuncs.h>
#include <libfdt.h>
#include <sys/promif.h>	/* XXXARM: temporary */

typedef struct {
	dev_info_t	*dip;
	void		*fdtp;
	uint64_t	fdt_size;
	int		node_offset;
} fdtnex_state_t;

static void	*fdtnex_state;

static int fdtnex_bus_map(dev_info_t *dip, dev_info_t *rdip,
    ddi_map_req_t *mp, off_t offset, off_t len, caddr_t *vaddrp);
static int fdtnex_bus_ctl(dev_info_t *dip, dev_info_t *rdip,
    ddi_ctl_enum_t ctlop, void *arg, void *result);
static int fdtnex_bus_config(dev_info_t *parent, uint_t flags,
    ddi_bus_config_op_t op, void *arg, dev_info_t **childp);
static int fdtnex_bus_unconfig(dev_info_t *parent, uint_t flags,
    ddi_bus_config_op_t op, void *arg);
static int fdtnex_bus_intr_op(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_op_t op, ddi_intr_handle_impl_t *hdlp, void *result);
static int fdtnex_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int fdtnex_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

static struct bus_ops fdtnex_bus_ops = {
	.busops_rev		= BUSO_REV,
	.bus_map		= fdtnex_bus_map,
	.bus_map_fault		= i_ddi_map_fault,
	.bus_dma_allochdl	= ddi_dma_allochdl,
	.bus_dma_freehdl	= ddi_dma_freehdl,
	.bus_dma_bindhdl	= ddi_dma_bindhdl,
	.bus_dma_unbindhdl	= ddi_dma_unbindhdl,
	.bus_dma_flush		= ddi_dma_flush,
	.bus_dma_win		= ddi_dma_win,
	.bus_dma_ctl		= ddi_dma_mctl,
	.bus_ctl		= fdtnex_bus_ctl,
	.bus_prop_op		= ddi_bus_prop_op,
	.bus_config		= fdtnex_bus_config,
	.bus_unconfig		= fdtnex_bus_unconfig,
	.bus_intr_op		= fdtnex_bus_intr_op,
};

static struct dev_ops fdtnex_dev_ops = {
	.devo_rev		= DEVO_REV,
	.devo_getinfo		= ddi_no_info,
	.devo_identify		= nulldev,
	.devo_probe		= nulldev,
	.devo_attach		= fdtnex_attach,
	.devo_detach		= fdtnex_detach,
	.devo_reset		= nodev,
	.devo_bus_ops		= &fdtnex_bus_ops,
	.devo_quiesce		= ddi_quiesce_not_needed,
};

/*
 * Module linkage information for the kernel.
 */
static struct modldrv modldrv = {
	&mod_driverops,
	"FDT nexus driver",
	&fdtnex_dev_ops,
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

	if ((err = ddi_soft_state_init(
	    &fdtnex_state, sizeof (fdtnex_state_t), 1)) != 0)
		return (err);

	if ((err = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&fdtnex_state);
		return (err);
	}

	return (err);
}

int
_fini(void)
{
	int err;

	if ((err = mod_remove(&modlinkage)) != 0)
		return (err);

	ddi_soft_state_fini(&fdtnex_state);
	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
fdtnex_bus_map(dev_info_t *dip, dev_info_t *rdip,
    ddi_map_req_t *mp, off_t offset, off_t len, caddr_t *vaddrp)
{
	prom_printf("fdtnex_bus_map called\n");
	/*
	 * We do this is simple-bus, but take a look at
	 * usr/src/uts/sun4/io/ebus.c, which seems quite clean and seems to
	 * do much the same thing.
	 */
	return (DDI_FAILURE);
}

static int
fdtnex_bus_ctl(dev_info_t *dip, dev_info_t *rdip,
    ddi_ctl_enum_t ctlop, void *arg, void *result)
{
	prom_printf("fdtnex_bus_ctl called\n");
	/*
	 * Check out usr/src/uts/sun4/io/ebus.c
	 */
	int ret;

	switch (ctlop) {
	case DDI_CTLOPS_REPORTDEV:
		/*
		 * XXXARM: make rootnex deal with the parent not being the
		 * rootnex, then this can just be forwarded to ddi_ctlops.
		 */
		if (rdip == NULL)
			return (DDI_FAILURE);
		cmn_err(CE_CONT, "?%s%d at %s%d",
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

#define	FDTNEX_FAKE_COMPATIBLES	1
/*
 * This function should be shared - fdtutil_nexus_create_children
 *
 * Can look up /fdt to get property translation and type maps.
 *
 * For virtio-mmio children, see https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html
 * §4.2.2 MMIO Device Register Layout and §5 Device Types - use those
 * to set a suitable compatible string for attaching the right driver.
 *
 * For now we seem to only support virtio-net and virtio-block, though it looks
 * like Toomas is adding virtio-rng.
 */
static int
fdtnex_set_child_prop_u32(
    dev_info_t *dip, fdtnex_state_t *rsp, int nodeoff, const char *name)
{
	const struct fdt_property	*prop;
	int				len;

	if ((prop = fdt_get_property(rsp->fdtp, nodeoff, name, &len)) == NULL) {
		return (NDI_FAILURE);
	}

	VERIFY3S(len, ==, sizeof (uint32_t));
	memcpy(&len, prop->data, sizeof (uint32_t));
	len = ntohl(len);
	return (ndi_prop_update_int(DDI_DEV_T_NONE, dip, (char *)name, len));
}

#if 0
static int
fdtnex_set_child_prop_u64(
    dev_info_t *dip, fdtnex_state_t *rsp, int nodeoff, const char *name)
{
	const struct fdt_property	*prop;
	int				len;
	int64_t				val;

	if ((prop = fdt_get_property(rsp->fdtp, nodeoff, name, &len)) == NULL) {
		return (NDI_FAILURE);
	}

	VERIFY3S(len, ==, sizeof (uint64_t));
	memcpy(&val, prop->data, sizeof (uint64_t));
	val = ntohll(val);
	return (ndi_prop_update_int64(DDI_DEV_T_NONE, dip, (char *)name, val));
}
#endif

static int
fdtnex_set_child_prop_bool(
    dev_info_t *dip, fdtnex_state_t *rsp, int nodeoff, const char *name)
{
	if (fdt_get_property(rsp->fdtp, nodeoff, name, NULL) == NULL)
		return (ndi_prop_remove(DDI_DEV_T_NONE, dip, (char *)name));

	return (ndi_prop_create_boolean(DDI_DEV_T_NONE, dip, (char *)name));
}

static int
fdtnex_set_child_prop_string(
    dev_info_t *dip, fdtnex_state_t *rsp, int nodeoff, const char *name)
{
	const struct fdt_property	*prop;
	int				len;

	if ((prop = fdt_get_property(rsp->fdtp, nodeoff, name, &len)) == NULL) {
		return (NDI_FAILURE);
	}

	return (ndi_prop_update_string(
	    DDI_DEV_T_NONE, dip, (char *)name, (char *)prop->data));
}

static int
fdtnex_set_child_prop_stringlist(dev_info_t *dip, fdtnex_state_t *rsp,
    int nodeoff, const char *name, const char *override)
{
	int elems;
	int idx;
	int offset;
	int ret;
	char **propval;

	elems = fdt_stringlist_count(rsp->fdtp, nodeoff, name);
	if (override != NULL)
		++elems;
	propval = (char **) kmem_zalloc(
	    sizeof (char *) * elems, KM_SLEEP);

	offset = 0;
	if (override != NULL) {
		propval[0] = (char *)override;
		offset = 1;
	}

	for (idx = offset; idx < elems; ++idx) {
#if !defined(FDTNEX_FAKE_COMPATIBLES)
		propval[idx] = (char *)fdt_stringlist_get(rsp->fdtp,
		    nodeoff, name, idx - offset, NULL);
#else
		propval[idx] = kmem_asprintf("not-%s",
		    (char *)fdt_stringlist_get(
		    rsp->fdtp, nodeoff, name, idx - offset, NULL));
#endif
	}

	ret = ndi_prop_update_string_array(DDI_DEV_T_NONE, dip,
	    (char *)name, propval, elems);

#if defined(FDTNEX_FAKE_COMPATIBLES)
	for (idx = offset; idx < elems; ++idx)
		strfree(propval[idx]);
#endif

	kmem_free(propval, sizeof (char *) * elems);
	return (ret);
}

static int
fdtnex_set_child_prop(
    dev_info_t *dip, fdtnex_state_t *rsp, int nodeoff, int propoff)
{
	const char	*propname = NULL;

	if (fdt_getprop_by_offset(
	    rsp->fdtp, propoff, &propname, NULL) == NULL) {
		cmn_err(CE_WARN, "%s%d: failed to retrieve child property "
		    "name at offset \"%d\"",
		    ddi_get_name(rsp->dip), ddi_get_instance(rsp->dip),
		    propoff);
		return (NDI_FAILURE);
	}

	if (propname == NULL) {
		cmn_err(CE_WARN, "%s%d: no child property name at "
		    "offset \"%d\"",
		    ddi_get_name(rsp->dip), ddi_get_instance(rsp->dip),
		    propoff);
		return (NDI_FAILURE);
	}

	/*
	 * Translate and propagate the property.
	 *
	 * This is disgusting - we need a data-driven approach when this
	 * moves somewhere common.
	 */
	if (strcmp(propname, "phandle") == 0) {
		return (fdtnex_set_child_prop_u32(
		    dip, rsp, nodeoff, propname));
	} else if (strcmp(propname, "compatible") == 0) {
		return (fdtnex_set_child_prop_stringlist(
		    dip, rsp, nodeoff, propname, NULL));
	} else if (strcmp(propname, "reg") == 0) {
		/*
		 * We need to look up the #address-cells and #size-cells to get this right
		 */
	} else if (strcmp(propname, "interrupts") == 0) {
	} else if (strcmp(propname, "dma-coherent") == 0) {
		return (fdtnex_set_child_prop_bool(
		    dip, rsp, nodeoff, propname));
	} else if (strcmp(propname, "dma-noncoherent") == 0) {
		return (fdtnex_set_child_prop_bool(
		    dip, rsp, nodeoff, propname));
	} else if (strcmp(propname, "#address-cells") == 0) {
		return (fdtnex_set_child_prop_u32(
		    dip, rsp, nodeoff, propname));
	} else if (strcmp(propname, "#size-cells") == 0) {
		return (fdtnex_set_child_prop_u32(
		    dip, rsp, nodeoff, propname));
	} else if (strcmp(propname, "virtual-reg") == 0) {
		return (fdtnex_set_child_prop_u32(
		    dip, rsp, nodeoff, propname));
	} else if (strcmp(propname, "ranges") == 0) {
	} else if (strcmp(propname, "#interrupt-cells") == 0) {
		return (fdtnex_set_child_prop_u32(
		    dip, rsp, nodeoff, propname));
	} else if (strcmp(propname, "clock-names") == 0) {
		return (fdtnex_set_child_prop_stringlist(
		    dip, rsp, nodeoff, propname, NULL));
	} else if (strcmp(propname, "clocks") == 0) {
	} else if (strcmp(propname, "device_type") == 0) {
		return (fdtnex_set_child_prop_string(
		    dip, rsp, nodeoff, propname));
	} else if (strcmp(propname, "#clock-cells") == 0) {
		return (fdtnex_set_child_prop_u32(
		    dip, rsp, nodeoff, propname));
	} else if (strcmp(propname, "#gpio-cells") == 0) {
		return (fdtnex_set_child_prop_u32(
		    dip, rsp, nodeoff, propname));
	} else if (strcmp(propname, "#redistributor-regions") == 0) {
		return (fdtnex_set_child_prop_u32(
		    dip, rsp, nodeoff, propname));
	} else if (strcmp(propname, "always-on") == 0) {
		return (fdtnex_set_child_prop_bool(
		    dip, rsp, nodeoff, propname));
	} else if (strcmp(propname, "bank-width") == 0) {
	} else if (strcmp(propname, "bus-range") == 0) {
	} else if (strcmp(propname, "clock-frequency") == 0) {
	} else if (strcmp(propname, "clock-output-names") == 0) {
		return (fdtnex_set_child_prop_stringlist(
		    dip, rsp, nodeoff, propname, NULL));
	} else if (strcmp(propname, "cpu_off") == 0) {
	} else if (strcmp(propname, "cpu_on") == 0) {
	} else if (strcmp(propname, "cpu_suspend") == 0) {
	} else if (strcmp(propname, "gpio-controller") == 0) {
		return (fdtnex_set_child_prop_bool(
		    dip, rsp, nodeoff, propname));
	} else if (strcmp(propname, "interrupt-controller") == 0) {
		return (fdtnex_set_child_prop_bool(
		    dip, rsp, nodeoff, propname));
	} else if (strcmp(propname, "interrupt-map") == 0) {
	} else if (strcmp(propname, "interrupt-map-mask") == 0) {
	} else if (strcmp(propname, "interrupt-parent") == 0) {
		return (fdtnex_set_child_prop_u32(
		    dip, rsp, nodeoff, propname));
	} else if (strcmp(propname, "linux,pci-domain") == 0) {
	} else if (strcmp(propname, "status") == 0) {
		return (fdtnex_set_child_prop_string(
		    dip, rsp, nodeoff, propname));
	} else if (strcmp(propname, "model") == 0) {
		return (fdtnex_set_child_prop_string(
		    dip, rsp, nodeoff, propname));
	} else if (strcmp(propname, "method") == 0) {
		return (fdtnex_set_child_prop_string(
		    dip, rsp, nodeoff, propname));
	} else if (strcmp(propname, "migrate") == 0) {
	} else if (strcmp(propname, "msi-map") == 0) {
	} else if (strcmp(propname, "lba-access-ok") == 0) {
		return (fdtnex_set_child_prop_bool(
		    dip, rsp, nodeoff, propname));
	} else {
		cmn_err(CE_WARN, "%s%d: unknown child property name \"%s\"",
		    ddi_get_name(rsp->dip), ddi_get_instance(rsp->dip),
		    propname);
#if 0
		return (NDI_FAILURE);
#else
		return (NDI_SUCCESS);
#endif
	}

	return (NDI_SUCCESS);
}

static int
fdtnex_set_child_props(dev_info_t *dip, fdtnex_state_t *rsp, int nodeoff)
{
	int propoff;

	fdt_for_each_property_offset(propoff, rsp->fdtp, nodeoff) {
		if (fdtnex_set_child_prop(
		    dip, rsp, nodeoff, propoff) != NDI_SUCCESS) {
			const char *propname = NULL;
			if (fdt_getprop_by_offset(rsp->fdtp,
			    propoff, &propname, NULL) != NULL &&
			    propname != NULL) {
				cmn_err(CE_WARN, "%s%d: failed to set "
				    "child proprty \"%s\" on %s%d",
				    ddi_get_name(rsp->dip),
				    ddi_get_instance(rsp->dip),
				    propname,
				    ddi_get_name(dip), ddi_get_instance(dip));
			}

			return (NDI_FAILURE);
		}
	}

	return (NDI_SUCCESS);
}

static void
fdtnex_create_child(dev_info_t *parent, fdtnex_state_t *rsp, int nodeoff)
{
	dev_info_t	*dip;
	const char	*fdtnamep;
	char		*fdtname;
	int		fdtname_len;
	char		*nodename;
	char		*unitaddress;

	/*
	 * The rest of the system expects to have name and unit-address as
	 * properties, while FDT creates the node name as <name>@<unit-address>.
	 *
	 * Parse out the name and unit address into the format we expect, then
	 * synthesise any otherwise missing properties.
	 */
	if ((fdtnamep = fdt_get_name(rsp->fdtp, nodeoff, NULL)) == NULL)
		return;

	/*
	 * Skip well-known pseudo nodes
	 */
	if (strcmp(fdtnamep, "chosen") == 0)
		return;

	/* prom_printf("fdtnex: Child Node: %s\n", fdtnamep); */

	fdtname_len = strlen(fdtnamep) + 1;
	fdtname = kmem_zalloc(fdtname_len, KM_SLEEP);
	strcpy(fdtname, fdtnamep);
	fdtname[fdtname_len - 1] = '\0';

	i_ddi_parse_name((char *)fdtname, &nodename, &unitaddress, NULL);
	ASSERT(nodename != NULL);
	ndi_devi_alloc_sleep(parent, nodename, (pnode_t)DEVI_SID_NODEID, &dip);

	if (ndi_prop_update_string(
	    DDI_DEV_T_NONE, dip, "name", nodename) != NDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: failed to set child name "
		    "\"%s%d\" (\"%s\")",
		    ddi_get_name(parent), ddi_get_instance(parent),
		    ddi_get_name(dip), ddi_get_instance(dip),
		    fdtnamep);
		kmem_free(fdtname, fdtname_len);
		ddi_prop_remove_all(dip);
		(void) ndi_devi_free(dip);
		return;
	}

	if (unitaddress != NULL && *unitaddress) {
		if (ndi_prop_update_string(DDI_DEV_T_NONE, dip,
		    "unit-address", unitaddress) != NDI_SUCCESS) {
			cmn_err(CE_WARN, "%s%d: failed to set child nexus "
			    "unit address \"%s%d\" (\"%s\")",
			    ddi_get_name(parent), ddi_get_instance(parent),
			    ddi_get_name(dip), ddi_get_instance(dip),
			    fdtnamep);
			kmem_free(fdtname, fdtname_len);
			ddi_prop_remove_all(dip);
			(void) ndi_devi_free(dip);
			return;
		}
	}

	kmem_free(fdtname, fdtname_len);

	/*
	 * For nexus children we need to set the FDT offset to the node so
	 * that they can find their children.
	 *
	 * "nexus children" here means "anything that has child nodes".
	 */
	if (fdt_first_subnode(rsp->fdtp, nodeoff) >= 0) {
		if (ndi_prop_update_int(DDI_DEV_T_NONE, dip,
		    "illumos,fdt-node-offset", nodeoff) != NDI_SUCCESS) {
			cmn_err(CE_WARN, "%s%d: failed to set child nexus "
			    "FDT node offset \"%s%d\" (\"%s\")",
			    ddi_get_name(parent), ddi_get_instance(parent),
			    ddi_get_name(dip), ddi_get_instance(dip),
			    fdtnamep);
			ddi_prop_remove_all(dip);
			(void) ndi_devi_free(dip);
			return;
		}
	}

	if (fdtnex_set_child_props(dip, rsp, nodeoff) != NDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: failed to set child properties "
		    "\"%s%d\" (\"%s\")",
		    ddi_get_name(parent), ddi_get_instance(parent),
		    ddi_get_name(dip), ddi_get_instance(dip),
		    fdtnamep);
		ddi_prop_remove_all(dip);
		(void) ndi_devi_free(dip);
		return;
	}

	/* (void) ndi_devi_bind_driver(dip, 0); */
#if 0
	/* we might need to do this */
	if (ndi_devi_bind_driver(dip, 0) != NDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: failed to bind driver for child "
		    "\"%s%d\" (\"%s\")",
		    ddi_get_name(parent), ddi_get_instance(parent),
		    ddi_get_name(dip), ddi_get_instance(dip),
		    fdtnamep);
#if 0
		ddi_prop_remove_all(dip);
		(void) ndi_devi_free(dip);
#endif
		return;
	}

	if (ddi_initchild(parent, dip) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: failed to init child "
		    "\"%s%d\" (\"%s\")",
		    ddi_get_name(parent), ddi_get_instance(parent),
		    ddi_get_name(dip), ddi_get_instance(dip),
		    fdtnamep);
		ddi_prop_remove_all(dip);
		(void) ndi_devi_free(dip);
		return;
	}
#endif
}

static void
fdtnex_create_children(dev_info_t *parent, fdtnex_state_t *rsp)
{
	int		offset;

	/*
	 * Iterate the immediate children of this node, creating
	 * child nodes for those.
	 */
	fdt_for_each_subnode(offset, rsp->fdtp, rsp->node_offset) {
		fdtnex_create_child(parent, rsp, offset);
	}
}

static int
fdtnex_bus_config(dev_info_t *parent, uint_t flags,
    ddi_bus_config_op_t op, void *arg, dev_info_t **childp)
{
	int ret;
	fdtnex_state_t *rsp;

	rsp = ddi_get_soft_state(fdtnex_state, ddi_get_instance(parent));
	VERIFY(rsp != NULL);

	ndi_devi_enter(parent);
	if (DEVI(parent)->devi_child == NULL)
		fdtnex_create_children(parent, rsp);
	ret = ndi_busop_bus_config(parent, flags, op, arg, childp, 0);
	ndi_devi_exit(parent);

	return (ret);
}

static int
fdtnex_bus_unconfig(dev_info_t *parent, uint_t flags,
    ddi_bus_config_op_t op, void *arg)
{
	int ret;

	if (op == BUS_UNCONFIG_ALL)
		flags &= ~(NDI_DEVI_REMOVE | NDI_UNCONFIG);

	ndi_devi_enter(parent);
	ret = ndi_busop_bus_unconfig(parent, flags, op, arg);

	/*
	 * If previous step was successful and not part of modunload daemon,
	 * attempt to remove children.
	 */
	if ((op == BUS_UNCONFIG_ALL) && (ret == NDI_SUCCESS) &&
	    ((flags & NDI_AUTODETACH) == 0)) {
		flags |= NDI_DEVI_REMOVE;
		ret = ndi_busop_bus_unconfig(parent, flags, op, arg);
	}

	ndi_devi_exit(parent);
	return (ret);
}

static int fdtnex_bus_intr_op(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_op_t op, ddi_intr_handle_impl_t *hdlp, void *result)
{
	prom_printf("fdtnex_bus_intr_op called\n");
	/* see usr/src/uts/sun4/io/ebus.c */
	return (DDI_FAILURE);
}

static int
fdtnex_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int		instance;
	fdtnex_state_t	*rsp;
	uint64_t	fdt_addr;
	void		*fdtp;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);
	if (ddi_soft_state_zalloc(fdtnex_state, instance) != DDI_SUCCESS) {
		cmn_err(CE_CONT, "%s%d: can't allocate state\n",
		    ddi_get_name(dip), instance);
		return (DDI_FAILURE);
	}

	rsp = ddi_get_soft_state(fdtnex_state, instance);
	VERIFY(rsp != NULL);
	rsp->dip = dip;
	rsp->node_offset = 0;

	if ((fdt_addr = ddi_prop_get_int64(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "illumos,fdt-ptr", 0)) == 0) {
		cmn_err(CE_CONT, "%s%d: missing \"illumos,fdt-ptr\" property\n",
		    ddi_get_name(dip), instance);
		goto attach_failed;
	}

	fdtp = (void *)fdt_addr;

	if (fdt_check_header(fdtp) != 0) {
		cmn_err(CE_CONT, "%s%d: FDT header check failed\n",
		    ddi_get_name(dip), instance);
		goto attach_failed;
	}

	/*
	 * Allocate some private memory for a copy of the FDT that we can
	 * rely upon.
	 */
	rsp->fdt_size = roundup(fdt_totalsize(fdtp), PAGESIZE);
	rsp->fdtp = kmem_zalloc(rsp->fdt_size, KM_SLEEP);

	if (fdt_open_into(fdtp, rsp->fdtp, rsp->fdt_size) != 0) {
		cmn_err(CE_CONT, "%s%d: failed to open FDT into a buffer\n",
		    ddi_get_name(dip), instance);
		goto attach_failed;
	}

	if (fdt_pack(rsp->fdtp) != 0) {
		cmn_err(CE_CONT, "%s%d: failed to pack FDT\n",
		    ddi_get_name(dip), instance);
		goto attach_failed;
	}

#if 0
	/*
	 * I think we should create children here
	 */
	ndi_devi_enter(dip);
	if (DEVI(dip)->devi_child == NULL)
		fdtnex_create_children(dip, rsp);
	ndi_devi_exit(dip);
#endif

	ddi_report_dev(dip);
	return (DDI_SUCCESS);

attach_failed:
	(void) fdtnex_detach(dip, DDI_DETACH);
	return (DDI_FAILURE);
}

static int
fdtnex_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		instance;
	fdtnex_state_t	*rsp;

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:	/* fallthrough */
	case DDI_PM_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	/*
	 * I think we should remove children here
	 */

	/*
	 * Ownership of properties is a bit vague here, and
	 * deallocation may not be appropriate.
	 *
	 * ddi_prop_remove_all(dip);
	 */
	instance = ddi_get_instance(dip);
	if ((rsp = ddi_get_soft_state(fdtnex_state, instance)) != NULL) {
		if (rsp->fdt_size && rsp->fdtp)
			kmem_free(rsp->fdtp, rsp->fdt_size);
		rsp->fdtp = NULL;
		rsp->fdt_size = 0;
		rsp->dip = NULL;
		ddi_soft_state_free(fdtnex_state, instance);
	}

	return (DDI_SUCCESS);
}
