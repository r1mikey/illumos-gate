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
 * Bus-dependent probe for systems with flattened device tree firmware.
 */

#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/ddi_subrdefs.h>
#include <sys/sunndi.h>
#include <libfdt.h>

#define	FW_NODE_NAME	"fw"
#define	FDTNEX_NAME	"fdtnex"

extern void *fw_fdt_ptr;

static void fdt_enumerate(int);

static struct modlmisc modlmisc = {
	&mod_miscops, "FDT firmware interface"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

int
_init(void)
{
	int err;

	if ((err = mod_install(&modlinkage)) != 0)
		return (err);

	impl_bus_add_probe(fdt_enumerate);
	return (0);
}

int
_fini(void)
{
	int err;

	if ((err = mod_remove(&modlinkage)) != 0)
		return (err);

	impl_bus_delete_probe(fdt_enumerate);
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static void
fdt_create_nexus_dip(void)
{
	dev_info_t *dip;
	int len;
	const struct fdt_property *prop;
	char fdtnex_name[] = FDTNEX_NAME;

	ndi_devi_alloc_sleep(ddi_root_node(), FW_NODE_NAME,
	    (pnode_t)DEVI_SID_NODEID, &dip);

	/*
	 * Fix up the compatible string array to put us first. If there is no
	 * compatible (unlikely) then we create one.
	 */
	if ((prop = fdt_getprop(fw_fdt_ptr, 0, "compatible", NULL)) != NULL) {
		int elems;
		char **propval;
		int idx;

		elems = fdt_stringlist_count(fw_fdt_ptr, 0, "compatible");
		VERIFY3S(elems, >=, 0);

		++elems;	/* +1 for our fdtnex compat */

		propval = (char **) kmem_zalloc(
		    sizeof (char *) * elems, KM_SLEEP);
		propval[0] = fdtnex_name;

		for (idx = 1; idx < elems; ++idx) {
			propval[idx] = (char *)fdt_stringlist_get(
			    fw_fdt_ptr, 0, "compatible", idx - 1, NULL);
			VERIFY3P(propval[idx], !=, NULL);
		}

		(void) ndi_prop_update_string_array(DDI_DEV_T_NONE, dip,
		    "compatible", propval, elems);
		kmem_free(propval, sizeof (char *) * elems);
	} else {
		char *propval[] = {
			fdtnex_name,
		};
		(void) ndi_prop_update_string_array(DDI_DEV_T_NONE, dip,
		    "compatible", propval, 1);
	}

	/*
	 * Leave a pointer to the firmware-provided FDT pointer for the driver
	 */
	(void) ndi_prop_update_int64(DDI_DEV_T_NONE, dip,
	    "illumos,fdt-ptr", (int64_t)fw_fdt_ptr);

	/*
	 * Copy out the #address-cells property if present. If not, create it
	 * with the default value (2).
	 */
	if ((prop = fdt_get_property(fw_fdt_ptr, 0, "#address-cells", &len))) {
		ASSERT(len == sizeof (uint32_t));
		memcpy(&len, prop->data, sizeof (uint32_t));
		len = ntohl(len);
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
		    "#address-cells", len);
	} else {
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
		    "#address-cells", 2);
	}

	/*
	 * Copy out the #size-cells property if present. If not, create it
	 * with the default value (1).
	 */
	if ((prop = fdt_get_property(fw_fdt_ptr, 0, "#size-cells", &len))) {
		ASSERT(len == sizeof (uint32_t));
		memcpy(&len, prop->data, sizeof (uint32_t));
		len = ntohl(len);
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
		    "#size-cells", len);
	} else {
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
		    "#size-cells", 1);
	}

	/*
	 * Handling interrupt-parent is an open question for now, but we can
	 * probably punt for the platforms we're going to support
	 *
	 * SPARC doesn't do delegated interrupts via interrupt-parent, and
	 * we don't necessarily want to go down the rabbit hole of supporting
	 * exotic embedded platforms.
	 */

	/*
	 * Finally, bind instance 0 of the FDT (there can be only one).
	 */
	(void) ndi_devi_bind_driver(dip, 0);
}

static void
fdt_enumerate(int reprogram)
{
	dev_info_t *dip;
	paddr_t acpi_root;

	/*
	 * We should only be called once, with reprobe=0
	 */
	if (reprogram)
		return;

	/*
	 * If the system has ACPI we must skip FDT - the two don't mix.
	 */
	acpi_root = ddi_prop_get_int64(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, "acpi-root-tab", 0);
	if (acpi_root != 0)
		return;

	/*
	 * If there's no firmware-provided FDT we can't run.
	 */
	if (fw_fdt_ptr == NULL || fdt_check_header(fw_fdt_ptr) != 0)
		return;

	/*
	 * If the fdt node already exists we skip this run and warn.
	 */
	if ((dip = ddi_find_devinfo(FW_NODE_NAME, -1, 0)) != NULL) {
		cmn_err(CE_WARN, "!fdt_autoconfig: %s node already exists",
		    FW_NODE_NAME);
		ndi_rele_devi(dip);
		return;
	}

	/*
	 * The FDT nexus is responsible for creating the tree,
	 * which will happen via bus_config/bus_unconfig.
	 *
	 * See usr/src/uts/common/io/i8042.c for an example.
	 */
	fdt_create_nexus_dip();
}
