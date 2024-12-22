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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015 Joyent, Inc.
 */

/*
 *	Library file that has miscellaneous support for npe(4D)
 */

#include <sys/conf.h>
#include <sys/pci.h>
#include <sys/sunndi.h>
#include <sys/pci_cap.h>
#include <sys/pcie_impl.h>
#include <sys/cpuvar.h>
#include <sys/obpdefs.h>

/*
 * Prototype declaration
 */
int	npe_disable_empty_bridges_workaround(dev_info_t *child);
boolean_t npe_is_child_pci(dev_info_t *dip);

/*
 * If the bridge is empty, disable it
 */
int
npe_disable_empty_bridges_workaround(dev_info_t *child)
{
	pcie_bus_t *bus_p = PCIE_DIP2BUS(child);

	/*
	 * Do not bind drivers to empty bridges.
	 * Fail above, if the bridge is found to be hotplug capable
	 */
	if (ddi_driver_major(child) == ddi_name_to_major("pcieb") &&
	    ddi_get_child(child) == NULL && bus_p->bus_hp_sup_modes ==
	    PCIE_NONE_HP_MODE) {
		return (1);
	}

	return (0);
}

/*
 * Check's if this child is a PCI device.
 * Child is a PCI device if:
 * parent has a dev_type of "pci"
 * -and-
 * child does not have a dev_type of "pciex"
 *
 * If the parent is not of dev_type "pci", then assume it is "pciex" and all
 * children should support using PCIe style MMCFG access.
 *
 * If parent's dev_type is "pci" and child is "pciex", then also enable using
 * PCIe style MMCFG access.  This covers the case where NPE is "pci" and a PCIe
 * RP is beneath.
 */
boolean_t
npe_child_is_pci(dev_info_t *dip)
{
	char *dev_type;
	boolean_t parent_is_pci, child_is_pciex;

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, ddi_get_parent(dip),
	    DDI_PROP_DONTPASS, OBP_DEVICETYPE, &dev_type) ==
	    DDI_PROP_SUCCESS) {
		parent_is_pci = (strcmp(dev_type, "pci") == 0);
		ddi_prop_free(dev_type);
	} else {
		parent_is_pci = B_FALSE;
	}

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    OBP_DEVICETYPE, &dev_type) == DDI_PROP_SUCCESS) {
		child_is_pciex = (strcmp(dev_type, "pciex") == 0);
		ddi_prop_free(dev_type);
	} else {
		child_is_pciex = B_FALSE;
	}

	return (parent_is_pci && !child_is_pciex);
}
