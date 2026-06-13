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
 * Devicetree PCIe hotplug mode selection.
 *
 * On DT platforms there is no firmware hotplug management (_OSC/ACPI)
 * to negotiate with.  Native PCIe hotplug is the only mode: the
 * common pciehpc code drives the slot controller hardware directly
 * via SLOTCAP/SLOTCTL/SLOTSTS registers, and slot-change interrupts
 * arrive through MSI.  Nothing platform-specific is needed here.
 */

#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/hotplug/pci/pciehpc.h>

void
pciehpc_update_ops(pcie_hp_ctrl_t *ctrl_p __unused)
{
	/* Native mode: common pciehpc ops are already correct. */
}
