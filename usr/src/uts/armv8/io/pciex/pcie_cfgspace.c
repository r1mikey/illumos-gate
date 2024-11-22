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
 * Copyright 2023 Oxide Computer Company
 */

/*
 * XXXPCI: On ARM we have basically two universes, SBSA and Not.  In the SBSA
 * world this can be ACPI based, and I think only ECAM is relevant
 *
 * In the non-BSA world this can be a lot.  We may have multiple PCIe root
 * complexes in the devicetree, each with its own space, and in theory at
 * least, its own configuration space access mechanism
 *
 * These devices may or may not (further) have been partially (or perhaps
 * fully) enumerated either by firmmware, or statically.
 *
 * The current PCI prototype makes a simplifying assumption:
 *
 * - There is only one PCIe root complex in the devicetree, it is at "/pcie"
 *   (this is generally false, but convenient to bootstrap)
 */

/* XXXPCI: This belongs in pcie_cfgspace_ecam.c */
/*
 * This file provides a means of accessing PCIe extended configuration space
 * over memory mapped I/O. Traditionally this was always accessed over the
 * various I/O ports; however, we instead opt to leverage facilities in the CPU
 * to set up memory-mapped I/O. To do this we basically do an initial mapping
 * that we use prior to VM in whatever VA space that we can get. After which,
 * we will unmap that and leverage addresses from the device arena once that has
 * been set up.
 *
 * Configuration space is accessed by constructing and addresss that has the
 * bits arranged in the following pattern to indicate what the bus, device,
 * function, and register is:
 *
 *	bus[7:0]	addr[27:20]
 *	dev[4:0]	addr[19:15]
 *	func[2:0]	addr[14:12]
 *	reg[11:0]	addr[11:0]
 *
 * The CPU does not generally support 64-bit accesses, which means that a 64-bit
 * access requires us to write the lower 32-bits followed by the uppwer 32-bits.
 */

#include <sys/ddi.h>
#include <sys/esunddi.h>
#include <sys/sunddi.h>
#include <sys/promif.h>
/* XXXPCI: for psm_map* */
#include <sys/smp_impldefs.h>

#include <sys/machparam.h>
#include <vm/as.h>
#include <vm/hat.h>
#include <sys/mman.h>
#include <sys/bootconf.h>
#include <sys/spl.h>
#include <sys/pci.h>
#include <sys/pcie.h>
#include <sys/pcie_impl.h>
#include <sys/pci_cfgacc.h>
#include <sys/machsystm.h>
#include <sys/sysmacros.h>

/*
 * These function pointers are entry points that the system has historically
 * assumed to exist. While we only have a single implementation, for now we need
 * to keep the indirect functions.
 *
 * XXX Can we go back and make the arguments for the bdfr unsigned?
 */
uint8_t (*pci_getb_func)(int bus, int dev, int func, int reg);
uint16_t (*pci_getw_func)(int bus, int dev, int func, int reg);
uint32_t (*pci_getl_func)(int bus, int dev, int func, int reg);
void (*pci_putb_func)(int bus, int dev, int func, int reg, uint8_t val);
void (*pci_putw_func)(int bus, int dev, int func, int reg, uint16_t val);
void (*pci_putl_func)(int bus, int dev, int func, int reg, uint32_t val);

/*
 * The pci_cfgacc_req
 */
extern void (*pci_cfgacc_acc_p)(pci_cfgacc_req_t *req);

/*
 * This contains the base virtual address for PCIe configuration space.
 *
 * XXXPCI: This doesn't actually work generally on ARM platforms, we may (in
 * theory at least) have a heterogenous collection of PCIe hardware, each with
 * its own base address.  This is the simplification we made for the
 * prototype alluded to above.
 */
uintptr_t pcie_cfgspace_ecam_vaddr;

kmutex_t pcicfg_mmio_mutex;

static boolean_t
pcie_access_check(int bus, int dev, int func, int reg, size_t len)
{
	if (bus < 0 || bus >= PCI_MAX_BUS_NUM) {
		return (B_FALSE);
	}

	if (dev < 0 || dev >= PCI_MAX_DEVICES) {
		return (B_FALSE);
	}

	/*
	 * Due to the advent of ARIs we want to make sure that we're not overly
	 * stringent here. ARIs retool how the bits are used for the device and
	 * function. This means that if dev == 0, allow func to be up to 0xff.
	 */
	if (func < 0 || (dev != 0 && func >= PCI_MAX_FUNCTIONS) ||
	    (dev == 0 && func >= PCIE_ARI_MAX_FUNCTIONS)) {
		return (B_FALSE);
	}

	/*
	 * Technically the maximum register is determined by the parent. At this
	 * point we have no way of knowing what is PCI or PCIe and will rely on
	 * mmio to solve this for us.
	 */
	if (reg < 0 || reg >= PCIE_CONF_HDR_SIZE) {
		return (B_FALSE);
	}

	if (!IS_P2ALIGNED(reg, len)) {
#ifdef	DEBUG
		/*
		 * While there are legitimate reasons we might try to access
		 * nonexistent devices and functions, misaligned accesses are at
		 * least strongly suggestive of kernel bugs.  Let's see what
		 * this finds.
		 */
		cmn_err(CE_WARN, "misaligned PCI config space access at "
		    "%x/%x/%x reg 0x%x len %lu\n", bus, dev, func, reg, len);
#endif
		return (B_FALSE);
	}

	return (B_TRUE);
}

static uintptr_t
pcie_bdfr_to_addr(int bus, int dev, int func, int reg)
{
	uintptr_t bdfr = PCIE_CADDR_ECAM(bus, dev, func, reg);

	return (bdfr + pcie_cfgspace_ecam_vaddr);
}

uint8_t
pcie_cfgspace_ecam_read_uint8(int bus, int dev, int func, int reg)
{
	volatile uint8_t *u8p;
	uint8_t rv;

	if (!pcie_access_check(bus, dev, func, reg, sizeof (rv))) {
		return (PCI_EINVAL8);
	}

	u8p = (uint8_t *)pcie_bdfr_to_addr(bus, dev, func, reg);
	return (*u8p);
}

void
pcie_cfgspace_ecam_write_uint8(int bus, int dev, int func, int reg, uint8_t val)
{
	volatile uint8_t *u8p;

	if (!pcie_access_check(bus, dev, func, reg, sizeof (val))) {
		return;
	}

	u8p = (uint8_t *)pcie_bdfr_to_addr(bus, dev, func, reg);
	*u8p = val;
}

uint16_t
pcie_cfgspace_ecam_read_uint16(int bus, int dev, int func, int reg)
{
	volatile uint16_t *u16p;
	uint16_t rv;

	if (!pcie_access_check(bus, dev, func, reg, sizeof (rv))) {
		return (PCI_EINVAL16);
	}

	u16p = (uint16_t *)pcie_bdfr_to_addr(bus, dev, func, reg);
	return (*u16p);
}

void
pcie_cfgspace_ecam_write_uint16(int bus, int dev, int func, int reg,
    uint16_t val)
{
	volatile uint16_t *u16p;

	if (!pcie_access_check(bus, dev, func, reg, sizeof (val))) {
		return;
	}

	u16p = (uint16_t *)pcie_bdfr_to_addr(bus, dev, func, reg);
	*u16p = val;
}

uint32_t
pcie_cfgspace_ecam_read_uint32(int bus, int dev, int func, int reg)
{
	volatile uint32_t *u32p;
	uint32_t rv;

	if (!pcie_access_check(bus, dev, func, reg, sizeof (rv))) {
		return (PCI_EINVAL32);
	}

	u32p = (uint32_t *)pcie_bdfr_to_addr(bus, dev, func, reg);
	return (*u32p);
}

void
pcie_cfgspace_ecam_write_uint32(int bus, int dev, int func, int reg,
    uint32_t val)
{
	volatile uint32_t *u32p;

	if (!pcie_access_check(bus, dev, func, reg, sizeof (val))) {
		return;
	}

	u32p = (uint32_t *)pcie_bdfr_to_addr(bus, dev, func, reg);
	*u32p = val;
}

/*
 * XXX Historically only 32-bit accesses were done to configuration space.
 */
uint64_t
pcie_cfgspace_ecam_read_uint64(int bus, int dev, int func, int reg)
{
	volatile uint64_t *u64p;
	uint64_t rv;

	if (!pcie_access_check(bus, dev, func, reg, sizeof (rv))) {
		return (PCI_EINVAL64);
	}

	u64p = (uint64_t *)pcie_bdfr_to_addr(bus, dev, func, reg);
	return (*u64p);
}

void
pcie_cfgspace_ecam_write_uint64(int bus, int dev, int func, int reg,
    uint64_t val)
{
	volatile uint64_t *u64p;

	if (!pcie_access_check(bus, dev, func, reg, sizeof (val))) {
		return;
	}

	u64p = (uint64_t *)pcie_bdfr_to_addr(bus, dev, func, reg);
	*u64p = val;
}

/*
 * This is an entry point that expects accesses in a different pattern from the
 * traditional function pointers used above.
 */
void
pcie_cfgspace_ecam_acc(pci_cfgacc_req_t *req)
{
	int bus, dev, func, reg;

	bus = PCI_CFGACC_BUS(req);
	dev = PCI_CFGACC_DEV(req);
	func = PCI_CFGACC_FUNC(req);
	reg = req->offset;

	switch (req->size) {
	case PCI_CFG_SIZE_BYTE:
		if (req->write) {
			pcie_cfgspace_ecam_write_uint8(bus, dev, func, reg,
			    VAL8(req));
		} else {
			VAL8(req) = pcie_cfgspace_ecam_read_uint8(bus, dev,
			    func, reg);
		}
		break;
	case PCI_CFG_SIZE_WORD:
		if (req->write) {
			pcie_cfgspace_ecam_write_uint16(bus, dev, func, reg,
			    VAL16(req));
		} else {
			VAL16(req) = pcie_cfgspace_ecam_read_uint16(bus, dev,
			    func, reg);
		}
		break;
	case PCI_CFG_SIZE_DWORD:
		if (req->write) {
			pcie_cfgspace_ecam_write_uint32(bus, dev, func, reg,
			    VAL32(req));
		} else {
			VAL32(req) = pcie_cfgspace_ecam_read_uint32(bus, dev,
			    func, reg);
		}
		break;
	case PCI_CFG_SIZE_QWORD:
		if (req->write) {
			pcie_cfgspace_ecam_write_uint64(bus, dev, func, reg,
			    VAL64(req));
		} else {
			VAL64(req) = pcie_cfgspace_ecam_read_uint64(bus, dev,
			    func, reg);
		}
		break;
	default:
		if (!req->write) {
			VAL64(req) = PCI_EINVAL64;
		}
		break;
	}
}

void
pcie_cfgspace_init(void)
{
	pnode_t node;

	/*
	 * XXXPCI: This is the other part of the prototype simplification, we
	 * use /pcie explicitly and assume it to be ECAM
	 */
	if ((node = prom_finddevice("/pcie")) == OBP_NONODE) {
#ifdef DEBUG
		cmn_err(CE_WARN, "system has no PCIe at /pcie");
#endif
		return;
	}

	if (prom_is_compatible(node, "pci-host-ecam-generic")) {
		uint64_t addr;
		uint64_t size;

#ifdef DEBUG
		cmn_err(CE_CONT, "?PCIe: System is ECAM\n");
#endif

		/* XXXPCI: pcie_cfgspace_ecam_init(addr, size?) */
		if (prom_get_reg_address(node, 0, &addr) != 0) {
			cmn_err(CE_WARN, "PCIe: Failed to get config "
			    "space address");
			return;
		}

		if (prom_get_reg_size(node, 0, &size) != 0) {
			cmn_err(CE_WARN, "PCIe: Failed to get config "
			    "space size");
			return;
		}

		cmn_err(CE_NOTE, "PCIe: Using /pcie@%lx-+%lx for config space",
		    addr, size);

		pcie_cfgspace_ecam_vaddr = (uintptr_t)psm_map_phys(addr,
		    size, PROT_READ|PROT_WRITE);
		if (pcie_cfgspace_ecam_vaddr == 0) {
			cmn_err(CE_WARN, "PCIe: Failed to map config space");
			return;
		}

		pci_getb_func = pcie_cfgspace_ecam_read_uint8;
		pci_getw_func = pcie_cfgspace_ecam_read_uint16;
		pci_getl_func = pcie_cfgspace_ecam_read_uint32;
		pci_putb_func = pcie_cfgspace_ecam_write_uint8;
		pci_putw_func = pcie_cfgspace_ecam_write_uint16;
		pci_putl_func = pcie_cfgspace_ecam_write_uint32;
		pci_cfgacc_acc_p = pcie_cfgspace_ecam_acc;
	}

	/*
	 * XXXPCI:
	 *
	 *  else if bcm2711? ....
	 *  else ...
	 *  else assume DEN0115
	 *
	 * Probably in reality just assume the world is either ecam, or
	 * DEN0115 works.
	 */
	mutex_init(&pcicfg_mmio_mutex, NULL, MUTEX_SPIN,
	    (ddi_iblock_cookie_t)ipltospl(DISP_LEVEL));
}

/*
 * This would be called once the device arena was up, to remap into it, except
 * we don't really have one, we just have primordial PSM maps that live
 * forever.
 */
void
pcie_cfgspace_remap(void)
{
}
