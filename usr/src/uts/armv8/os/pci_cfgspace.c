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
 * Copyright 2019 Joyent, Inc.
 * Copyright 2024 Oxide Computer Company
 */

/*
 * PCI configuration space access routines
 */

#include <sys/systm.h>
#include <sys/psw.h>
#include <sys/bootconf.h>
#include <sys/reboot.h>
#include <sys/spl.h>
#include <sys/pci.h>
#include <sys/pci_impl.h>
#include <sys/pci_cfgspace.h>
#include <sys/pci_cfgspace_impl.h>
#include <sys/pci_cfgacc.h>

int pci_max_nbus = 0xFF;
int pci_bios_cfg_type = PCI_MECHANISM_UNKNOWN;
int pci_bios_maxbus;
int pci_bios_mech;
int pci_bios_vers;

/*
 * These two variables can be used to force a configuration mechanism or
 * to force which function is used to probe for the presence of the PCI bus.
 */
int	PCI_CFG_TYPE = 0;
int	PCI_PROBE_TYPE = 0;

/*
 * No valid mcfg_mem_base by default, and accessing pci config space
 * in mem-mapped way is disabled.
 */
uint64_t mcfg_mem_base = 0;
uint8_t mcfg_bus_start = 0;
uint8_t mcfg_bus_end = 0xff;

/*
 * Maximum offset in config space when not using MMIO
 */
uint_t pci_iocfg_max_offset = 0xff;

/*
 * These function pointers lead to the actual implementation routines
 * for configuration space access.  Normally they lead to either the
 * pci_mech1_* or pci_mech2_* routines, but they can also lead to
 * routines that work around chipset bugs.
 * These functions are accessing pci config space via I/O way.
 * Pci_cfgacc_get/put functions shoul be used as more common interfaces,
 * which also provide accessing pci config space via mem-mapped way.
 */
uint8_t (*pci_getb_func)(int bus, int dev, int func, int reg);
uint16_t (*pci_getw_func)(int bus, int dev, int func, int reg);
uint32_t (*pci_getl_func)(int bus, int dev, int func, int reg);
void (*pci_putb_func)(int bus, int dev, int func, int reg, uint8_t val);
void (*pci_putw_func)(int bus, int dev, int func, int reg, uint16_t val);
void (*pci_putl_func)(int bus, int dev, int func, int reg, uint32_t val);

extern void (*pci_cfgacc_acc_p)(pci_cfgacc_req_t *req);

/*
 * Internal routines
 */
static int pci_check(void);

/* for legacy io-based config space access */
kmutex_t pcicfg_mutex;

/* for mmio-based config space access */
kmutex_t pcicfg_mmio_mutex;

static uint8_t
pci_mech1_getb(int bus, int dev, int func, int reg)
{
	return (PCI_EINVAL8);
}

static uint16_t
pci_mech1_getw(int bus, int dev, int func, int reg)
{
	return (PCI_EINVAL16);
}

static uint32_t
pci_mech1_getl(int bus, int dev, int func, int reg)
{
	return (PCI_EINVAL32);
}

static void
pci_mech1_putb(int bus, int dev, int func, int reg, uint8_t val)
{

}

static void
pci_mech1_putw(int bus, int dev, int func, int reg, uint16_t val)
{

}

static void
pci_mech1_putl(int bus, int dev, int func, int reg, uint32_t val)
{

}

void
pci_cfgspace_init(void)
{
	mutex_init(&pcicfg_mutex, NULL, MUTEX_SPIN,
	    (ddi_iblock_cookie_t)ipltospl(15));
	mutex_init(&pcicfg_mmio_mutex, NULL, MUTEX_SPIN,
	    (ddi_iblock_cookie_t)ipltospl(DISP_LEVEL));
	if (!pci_check()) {
		mutex_destroy(&pcicfg_mutex);
		mutex_destroy(&pcicfg_mmio_mutex);
	}
}

/*
 * This code determines if this system supports PCI/PCIE and which
 * type of configuration access method is used
 */
static int
pci_check(void)
{
	uint64_t ecfginfo[4];

	/*
	 * Only do this once.  NB:  If this is not a PCI system, and we
	 * get called twice, we can't detect it and will probably die
	 * horribly when we try to ask the BIOS whether PCI is present.
	 * This code is safe *ONLY* during system startup when the
	 * BIOS is still available.
	 */
	if (pci_bios_cfg_type != PCI_MECHANISM_UNKNOWN)
		return (TRUE);

	/*
	 * only support PCI config mechanism 1 in armv8. This should be fine
	 * since the other ones are workarounds for old broken H/W which won't
	 * be supported in SBSA anyway.
	 */
	pci_bios_cfg_type = PCI_MECHANISM_1;
	pci_getb_func = pci_mech1_getb;
	pci_getw_func = pci_mech1_getw;
	pci_getl_func = pci_mech1_getl;
	pci_putb_func = pci_mech1_putb;
	pci_putw_func = pci_mech1_putw;
	pci_putl_func = pci_mech1_putl;

	/*
	 * Since we can't get the BIOS info in i86xpv, we will do an
	 * exhaustive search of all PCI buses. We have to do this until
	 * we start using the PCI information in ACPI.
	 */
	pci_bios_maxbus = pci_max_nbus;

	/*
	 * Try to get a valid mcfg_mem_base in early boot
	 * If failed, leave mem-mapped pci config space accessing disabled
	 * until pci boot code (pci_autoconfig) makes sure this is a PCIE
	 * platform.
	 */
	if (do_bsys_getprop(NULL, MCFG_PROPNAME, ecfginfo) != -1) {
		mcfg_mem_base = ecfginfo[0];
		mcfg_bus_start = ecfginfo[2];
		mcfg_bus_end = ecfginfo[3];
	}

	/* See pci_cfgacc.c */
	pci_cfgacc_acc_p = pci_cfgacc_acc;

	return (TRUE);
}
