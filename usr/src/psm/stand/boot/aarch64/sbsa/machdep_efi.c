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
 * Copyright 2017 Hayashi Naoyuki
 */
#if 0
#include <libfdt.h>
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/boot.h>
#if 0
#include <sys/salib.h>
#endif
#include <sys/promif.h>
#include <sys/platform.h>
#include <sys/controlregs.h>
#include <sys/memlist.h>
#include <sys/memlist_impl.h>
#include <sys/sysmacros.h>
#include <sys/bootconf.h>
#include <sys/efi.h>
#if 0
#include <sys/psci.h>
#include "prom_dev.h"
#include "boot_plat.h"
#endif
#include "dbg2.h"
#include "shim.h"

#ifdef DEBUG
static int	debug = 1;
#else /* DEBUG */
extern int	debug;
#endif /* DEBUG */
#define	dprintf if (debug) prom_printf

int pagesize = MMU_PAGESIZE;

struct efi_map_header *efi_map_header = NULL;

extern uintptr_t pa_to_ttbr1(uintptr_t pa);

/*
 * Needs to see the UEFI memory map
 */
void
init_physmem(void)
{
	struct efi_map_header	*mhdr;
	size_t			efisz;
	EFI_MEMORY_DESCRIPTOR	*map;
	int			ndesc;
	EFI_MEMORY_DESCRIPTOR	*p;
	int			i;
	uint64_t		addr;
	uint64_t		size;
	uint64_t		ptot;
	uint64_t		stot;
	uint64_t		rtot;

	if (efi_map_header == NULL)
		prom_panic("init_physmem: no UEFI memory map header\n");

	ptot = stot = rtot = 0;
	mhdr = efi_map_header;
	efisz = (sizeof(struct efi_map_header) + 0xf) & ~0xf;
	map = (EFI_MEMORY_DESCRIPTOR *)((uint8_t *)mhdr + efisz);
	if (mhdr->descriptor_size == 0)
		prom_panic("init_physmem: invalid memory descriptor size\n");

	ndesc = mhdr->memory_size / mhdr->descriptor_size;

	for (i = 0, p = map; i < ndesc; i++, p = efi_mmap_next(p, mhdr->descriptor_size)) {
		switch (p->Type) {
		case EfiMemoryMappedIOPortSpace:
		case EfiMemoryMappedIO:
		case EfiRuntimeServicesCode:
		case EfiRuntimeServicesData:
			break;
		default:
			addr = RNDUP(p->PhysicalStart, MMU_PAGESIZE);
			size = RNDDN(p->PhysicalStart + (p->NumberOfPages * MMU_PAGESIZE), MMU_PAGESIZE) - addr;
			dprintf("phys memory add 0x%lx - 0x%lx\n", addr, addr + size - 1);
			memlist_add_span(addr, size, &pinstalledp);
			memlist_add_span(addr, size, &plinearlistp);
			memlist_add_span(addr, size, &pfreelistp);
			ptot += size;
			break;
		}
	}

	/*
	 * Now reserved memory
	 */
	for (i = 0, p = map; i < ndesc; i++, p = efi_mmap_next(p, mhdr->descriptor_size)) {
		switch (p->Type) {
		case EfiRuntimeServicesCode:
			addr = RNDDN(p->PhysicalStart, MMU_PAGESIZE);
			size = RNDUP(p->PhysicalStart + (p->NumberOfPages * MMU_PAGESIZE), MMU_PAGESIZE) - addr;
			rtot += size;
			dprintf("efirt code 0x%lx - 0x%lx\n", addr, addr + size - 1);
			if (memlist_find(pfreelistp, addr))
				 memlist_delete_span(addr, size, &pfreelistp);
			if (memlist_find(plinearlistp, addr))
				memlist_delete_span(addr, size, &plinearlistp);
			memlist_add_span(addr, size, &pfwcodelistp);
			p->VirtualStart = pa_to_ttbr1(addr);
			break;
		case EfiRuntimeServicesData:
			addr = RNDDN(p->PhysicalStart, MMU_PAGESIZE);
			size = RNDUP(p->PhysicalStart + (p->NumberOfPages * MMU_PAGESIZE), MMU_PAGESIZE) - addr;
			rtot += size;
			dprintf("efirt data 0x%lx - 0x%lx\n", addr, addr + size - 1);
			if (memlist_find(pfreelistp, addr))
				 memlist_delete_span(addr, size, &pfreelistp);
			if (memlist_find(plinearlistp, addr))
				memlist_delete_span(addr, size, &plinearlistp);
			memlist_add_span(addr, size, &pfwdatalistp);
			p->VirtualStart = pa_to_ttbr1(addr);
			break;
		case EfiReservedMemoryType:
		case EfiPalCode:
		case EfiUnusableMemory:
		case EfiACPIReclaimMemory:	/* ACPI tables? */
		case EfiACPIMemoryNVS:
			addr = RNDDN(p->PhysicalStart, MMU_PAGESIZE);
			size = RNDUP(p->PhysicalStart + (p->NumberOfPages * MMU_PAGESIZE), MMU_PAGESIZE) - addr;
			rtot += size;
			if (p->Type == EfiReservedMemoryType)
				dprintf("EfiReservedMemoryType: ");
			else if (p->Type == EfiPalCode)
				dprintf("EfiPalCode: ");
			else if (p->Type == EfiUnusableMemory)
				dprintf("EfiUnusableMemory: ");
			else if (p->Type == EfiACPIReclaimMemory)
				dprintf("EfiACPIReclaimMemory: ");
			else if (p->Type == EfiACPIMemoryNVS)
				dprintf("EfiACPIMemoryNVS: ");
			dprintf("memory resv 0x%lx - 0x%lx\n", addr, addr + size - 1);
			if (memlist_find(pfreelistp, addr))
				memlist_delete_span(addr, size, &pfreelistp);
#if 0
			if (memlist_find(plinearlistp, addr))
				memlist_delete_span(addr, size, &plinearlistp);
#endif
			break;
		default:
			break;
		}
	}

	/*
	 * Claim all scratch memory that the kernel can reclaim after bootstrap
	 */
	for (i = 0, p = map; i < ndesc; i++, p = efi_mmap_next(p, mhdr->descriptor_size)) {
		switch (p->Type) {
		case EfiLoaderCode:
		case EfiLoaderData:
		case EfiBootServicesCode:
		case EfiBootServicesData:
			addr = RNDDN(p->PhysicalStart, MMU_PAGESIZE);
			size = RNDUP(p->PhysicalStart + (p->NumberOfPages * MMU_PAGESIZE), MMU_PAGESIZE) - addr;
			stot += size;
			dprintf("memory scratch 0x%lx - 0x%lx\n", addr, addr + size - 1);
			if (memlist_find(pfreelistp, addr))
				memlist_delete_span(addr, size, &pfreelistp);
			memlist_add_span(addr, size, &pscratchlistp);
			break;
		default:
			break;
		}
	}

	dprintf("physical memory: 0x%lx bytes\n", ptot);
	dprintf("       reserved: 0x%lx bytes\n", rtot);
	dprintf("        scratch: 0x%lx bytes\n", stot);

#if 0
	/* used by device drivers, should not be necessary for us */
	if (BOOT_TMP_MAP_SIZE > 0)
		memlist_add_span(BOOT_TMP_MAP_BASE, BOOT_TMP_MAP_SIZE, &ptmplistp);
#endif
}


void
init_iolist(void)
{
	struct efi_map_header	*mhdr;
	size_t			efisz;
	EFI_MEMORY_DESCRIPTOR	*map;
	int			ndesc;
	EFI_MEMORY_DESCRIPTOR	*p;
	int			i;
	uint64_t		addr;
	uint64_t		size;

	if (efi_map_header == NULL)
		prom_panic("init_physmem: no UEFI memory map header\n");

	mhdr = efi_map_header;
	efisz = (sizeof(struct efi_map_header) + 0xf) & ~0xf;
	map = (EFI_MEMORY_DESCRIPTOR *)((uint8_t *)mhdr + efisz);
	if (mhdr->descriptor_size == 0)
		prom_panic("init_physmem: invalid memory descriptor size\n");

	ndesc = mhdr->memory_size / mhdr->descriptor_size;

	/*
	 * Record all device memory, ensuring that there are no overlaps with
	 * other memory types.
	 */
	for (i = 0, p = map; i < ndesc; i++, p = efi_mmap_next(p, mhdr->descriptor_size)) {
		switch (p->Type) {
		case EfiMemoryMappedIOPortSpace:
		case EfiMemoryMappedIO:
			addr = RNDDN(p->PhysicalStart, MMU_PAGESIZE);
			size = RNDUP(p->PhysicalStart + (p->NumberOfPages * MMU_PAGESIZE), MMU_PAGESIZE) - addr;
			dprintf("io 0x%lx - 0x%lx\n", addr, addr + size - 1);
			/*
			 * It'd be highly unusual to find the I/O memory in any of
			 * the other memlists, but handle those cases anyway.
			 */
			if (memlist_find(pfreelistp, addr))
				memlist_delete_span(addr, size, &pfreelistp);
			if (memlist_find(pscratchlistp, addr))
				memlist_delete_span(addr, size, &pscratchlistp);
			if (memlist_find(plinearlistp, addr))
				memlist_delete_span(addr, size, &plinearlistp);
			memlist_add_span(addr, size, &piolistp);
			break;
		default:
			break;
		}
	}

	/*
	 * FUDGE: It seems as if DBG2 memory is not necessarily added to the UEFI
	 * memory map, which is somewhat unexpected.
	 */
	extern struct xboot_info *bi;
	addr = bi->bi_bsvc_uart_mmio_base;
	size = 0x1000;

	if (addr && !memlist_find(piolistp, addr)) {
		dprintf("io 0x%lx - 0x%lx\n", addr, addr + size - 1);
		if (memlist_find(pfreelistp, addr))
			memlist_delete_span(addr, size, &pfreelistp);
		if (memlist_find(pscratchlistp, addr))
			memlist_delete_span(addr, size, &pscratchlistp);
		if (memlist_find(plinearlistp, addr))
			memlist_delete_span(addr, size, &plinearlistp);
		memlist_add_span(addr, size, &piolistp);
	}
}

void
reloc_efi_runtime_services(struct xboot_info *xbi)
{
	EFI_STATUS		status;
	size_t			efisz;
	struct efi_map_header	*mhdr;
	EFI_MEMORY_DESCRIPTOR	*map;
	EFI_SYSTEM_TABLE64	*systab;

	mhdr = efi_map_header;
	efisz = (sizeof(struct efi_map_header) + 0xf) & ~0xf;
	map = (EFI_MEMORY_DESCRIPTOR *)((uint8_t *)mhdr + efisz);
	systab = (EFI_SYSTEM_TABLE64 *)xbi->bi_uefi_systab;

	status = systab->RuntimeServices->SetVirtualAddressMap(
		mhdr->memory_size,		/* MemoryMapSize */
		mhdr->descriptor_size,		/* DescruptorSize */
		mhdr->descriptor_version,	/* DescriptorVersion */
		map);				/* *VirtualMap */

	if (status != EFI_SUCCESS)
		dbg2_panic("reloc_efi_runtime_services: failed to relocate runtime services (%d)\n", status);

	xbi->bi_uefi_systab = pa_to_ttbr1(xbi->bi_uefi_systab);
}
