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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/systm.h>
#include <sys/pci_cfgacc.h>
#include <sys/pci_cfgspace.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include <sys/pci.h>
#include <sys/cmn_err.h>
#include <vm/seg_kmem.h>

#define	PCIE_CFG_SPACE_SIZE	(PCI_CONF_HDR_SIZE << 4)
#define	PCI_BDF_BUS(bdf)	((((uint16_t)bdf) & 0xff00) >> 8)
#define	PCI_BDF_DEV(bdf)	((((uint16_t)bdf) & 0xf8) >> 3)
#define	PCI_BDF_FUNC(bdf)	(((uint16_t)bdf) & 0x7)

void pci_cfgacc_acc(pci_cfgacc_req_t *);

extern uintptr_t pcie_cfgspace_ecam_vaddr;
extern kmutex_t pcicfg_mmio_mutex;

/*
 * IS_P2ALIGNED() is used to make sure offset is 'size'-aligned, so
 * it's guaranteed that the access will not cross 4k page boundary.
 * Thus only 1 page is allocated for all config space access, and the
 * virtual address of that page is cached in pci_cfgacc_virt_base.
 */
static caddr_t pci_cfgacc_virt_base = NULL;

static void
pci_cfgacc_mmio(pci_cfgacc_req_t *req)
{
	caddr_t vaddr;

	vaddr = (caddr_t)pcie_cfgspace_ecam_vaddr + req->offset +
	    (req->bdf << 12);

	mutex_enter(&pcicfg_mmio_mutex);

	switch (req->size) {
	case 1:
		if (req->write)
			*((uint8_t *)vaddr) = VAL8(req);
		else
			VAL8(req) = *((uint8_t *)vaddr);
		break;
	case 2:
		if (req->write)
			*((uint16_t *)vaddr) = VAL16(req);
		else
			VAL16(req) = *((uint16_t *)vaddr);
		break;
	case 4:
		if (req->write)
			*((uint32_t *)vaddr) = VAL32(req);
		else
			VAL32(req) = *((uint32_t *)vaddr);
		break;
	case 8:
		if (req->write)
			*((uint64_t *)vaddr) = VAL64(req);
		else
			VAL64(req) = *((uint64_t *)vaddr);
		break;
	}
	mutex_exit(&pcicfg_mmio_mutex);
}

static boolean_t
pci_cfgacc_valid(pci_cfgacc_req_t *req, uint16_t cfgspc_size)
{
	int sz = req->size;

	if (IS_P2ALIGNED(req->offset, sz) &&
	    (req->offset + sz - 1 < cfgspc_size) &&
	    ((sz & 0xf) && ISP2(sz)))
		return (B_TRUE);

	cmn_err(CE_WARN, "illegal PCI request: offset = %x, size = %d",
	    req->offset, sz);
	return (B_FALSE);
}

void
pci_cfgacc_acc(pci_cfgacc_req_t *req)
{
	if (!req->write)
		VAL64(req) = (uint64_t)-1;

	if (pci_cfgacc_valid(req, PCIE_CFG_SPACE_SIZE))
		pci_cfgacc_mmio(req);
}
