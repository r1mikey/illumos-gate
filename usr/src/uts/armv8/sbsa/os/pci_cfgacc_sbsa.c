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

#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/promif.h>
#include <sys/pci.h>
#include <sys/sysmacros.h>
#include <sys/pcie_impl.h>
#include <sys/machsystm.h>
#include <sys/byteorder.h>
#include <sys/pci_cfgacc.h>
#include <sys/pci_cfgspace_impl.h>
#include <vm/hat_aarch64.h>
#include <vm/seg_kmem.h>

#define	PCI_CFG_SPACE		(PCI_REG_ADDR_G(PCI_ADDR_CONFIG))
#define	PCIE_CFG_SPACE_SIZE	(PCI_CONF_HDR_SIZE << 4)

/* RC BDF Shift in a Phyiscal Address */
#define	RC_PA_BDF_SHIFT			12
#define	RC_BDF_TO_CFGADDR(bdf, offset) (((bdf) << RC_PA_BDF_SHIFT) + (offset))

/*
 * IS_P2ALIGNED() is used to make sure offset is 'size'-aligned, so
 * it's guaranteed that the access will not cross 4k page boundary.
 * Thus only 1 page is allocated for all config space access, and the
 * virtual address of that page is cached in pci_cfgacc_virt_base.
 */
static caddr_t pci_cfgacc_virt_base = NULL;

static caddr_t
pci_cfgacc_map(paddr_t phys_addr)
{
	pfn_t pfn;

	ASSERT(khat_running);

	if (pci_cfgacc_virt_base == NULL)
		pci_cfgacc_virt_base = vmem_alloc(heap_arena,
		    MMU_PAGESIZE, VM_SLEEP);

	pfn = mmu_btop(phys_addr);
	hat_devload(kas.a_hat, pci_cfgacc_virt_base,
	    MMU_PAGESIZE, pfn, PROT_READ | PROT_WRITE |
	    HAT_STRICTORDER, HAT_LOAD_LOCK);

	return (pci_cfgacc_virt_base + (phys_addr & MMU_PAGEOFFSET));
}

static void
pci_cfgacc_unmap(void)
{
	ASSERT(khat_running);
	ASSERT(pci_cfgacc_virt_base != NULL);
	hat_unload(kas.a_hat, pci_cfgacc_virt_base, MMU_PAGESIZE,
	    HAT_UNLOAD_UNLOCK);
}

static boolean_t
pci_cfgacc_valid(pci_cfgacc_req_t *req)
{
	int sz = req->size;

	if (IS_P2ALIGNED(req->offset, sz) &&
	    (req->offset + sz - 1 < PCIE_CFG_SPACE_SIZE) &&
	    ((sz & 0xf) && ISP2(sz)))
		return (B_TRUE);

	cmn_err(CE_WARN, "illegal PCI request: offset = %x, size = %d",
	    req->offset, sz);
	return (B_FALSE);
}

static void
pci_cfgacc_mmio_get_raw(pci_cfgacc_req_t *req)
{
	caddr_t vaddr;
	paddr_t paddr;

	paddr = (paddr_t)req->bdf << 12;
	paddr += mcfg_mem_base + req->offset;

	mutex_enter(&pcicfg_mmio_mutex);
	vaddr = pci_cfgacc_map(paddr);

	switch (req->size) {
	case 1:
		VAL8(req) = i_ddi_get8(NULL, (uint8_t *)(vaddr));
		break;
	case 2:
		VAL16(req) = i_ddi_get16(NULL, (uint16_t *)(vaddr));
		break;
	case 4:
		VAL32(req) = i_ddi_get32(NULL, (uint32_t *)(vaddr));
		break;
	case 8:
		VAL64(req) = i_ddi_get64(NULL, (uint64_t *)vaddr);
		break;
	}

	pci_cfgacc_unmap();
	mutex_exit(&pcicfg_mmio_mutex);
}

static void
pci_cfgacc_mmio_set_raw(pci_cfgacc_req_t *req)
{
	caddr_t vaddr;
	paddr_t paddr;

	paddr = (paddr_t)req->bdf << 12;
	paddr += mcfg_mem_base + req->offset;

	mutex_enter(&pcicfg_mmio_mutex);
	vaddr = pci_cfgacc_map(paddr);

	switch (req->size) {
	case 1:
		i_ddi_put8(NULL, (uint8_t *)(vaddr), VAL8(req));
		break;
	case 2:
		i_ddi_put16(NULL, (uint16_t *)(vaddr), VAL16(req));
		break;
	case 4:
		i_ddi_put32(NULL, (uint32_t *)(vaddr), VAL32(req));
		break;
	case 8:
		i_ddi_put64(NULL, (uint64_t *)(vaddr), VAL64(req));
		break;
	}

	pci_cfgacc_unmap();
	mutex_exit(&pcicfg_mmio_mutex);
}

/*
 * TODO: if we were passed a dip, and that dip has a valid bus_cfg_hdl, then
 * we should use that access handle.
 */
void
pci_cfgacc_acc(pci_cfgacc_req_t *req)
{
	if (!req->write)
		VAL64(req) = (uint64_t)-1;

	if (!pci_cfgacc_valid(req))
		return;

	if (req->write) {
		pci_cfgacc_mmio_set_raw(req);
	} else {
		pci_cfgacc_mmio_get_raw(req);
	}
}
