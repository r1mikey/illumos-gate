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
 * Copyright 2026 Michael van der Westhuizen
 */

/*
 * PCIe _OSC dispatch for aarch64.
 *
 * On ACPI platforms, plat_pcie_osc (provided by sbbr.c) dispatches
 * through to the acpidev evaluator.  On DT platforms the weak symbol
 * is absent -- no firmware manages hotplug or AER, so grant all
 * requested control bits.
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/platmod.h>

int
pcie_osc(dev_info_t *dip, uint32_t support,
    uint32_t ctrl_req, uint32_t *ctrl_ret)
{
	if (&plat_pcie_osc != NULL) {
		return (plat_pcie_osc(dip, support, ctrl_req, ctrl_ret));
	}

	/* DT platform -- no firmware to negotiate with */
	*ctrl_ret = ctrl_req;
	return (DDI_SUCCESS);
}
