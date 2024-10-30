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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/boot.h>
#include <sys/bootconf.h>
#include <sys/bootinfo.h>
#include <sys/controlregs.h>
#include <sys/cpu.h>
#include <sys/cpuid.h>
#include <sys/machparam.h>
#include <sys/memlist.h>
#include <sys/memlist_impl.h>
#include <sys/platform.h>
#include <sys/promif.h>
#include <sys/pte.h>
#include <sys/saio.h>
#include <sys/salib.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/efi.h>

#include <alloca.h>

#include "boot_plat.h"
#include "shim.h"
#include "early_dbg2.h"

#ifdef DEBUG
static int	debug = 1;
#else /* DEBUG */
extern int	debug;
#endif /* DEBUG */
#define	dprintf	if (debug) printf

extern caddr_t		memlistpage;
extern char _BootScratch[];
extern char _RamdiskStart[];
extern char _BootStart[];
extern char _BootEnd[];

extern void init_physmem(void);
extern void init_iolist(void);

static caddr_t scratch_used_top;
static pte_t *l1_ptbl0;
static pte_t *l1_ptbl1;

static void init_pt(void);
static void dump_tables(uint64_t tab, uint64_t va_offset);

extern struct efi_map_header *efi_map_header;

static inline int
l1_pteidx(caddr_t vaddr)
{
	return ((((uintptr_t)vaddr) >> (PAGESHIFT + 3 * NPTESHIFT)) &
	    ((1 << NPTESHIFT) - 1));
}

static inline int
l2_pteidx(caddr_t vaddr)
{
	return ((((uintptr_t)vaddr) >> (PAGESHIFT + 2 * NPTESHIFT)) &
	    ((1 << NPTESHIFT) - 1));
}

static inline int
l3_pteidx(caddr_t vaddr)
{
	return ((((uintptr_t)vaddr) >> (PAGESHIFT + 1 * NPTESHIFT)) &
	    ((1 << NPTESHIFT) - 1));
}

static inline int
l4_pteidx(caddr_t vaddr)
{
	return ((((uintptr_t)vaddr) >> (PAGESHIFT)) & ((1 << NPTESHIFT) - 1));
}


void
init_memory(void)
{
	kmem_init();
	init_iolist();
	init_pt();
}

void
init_memlists(void)
{
	scratch_used_top = _BootScratch;
	memlistpage = scratch_used_top;
	scratch_used_top += MMU_PAGESIZE;

	init_physmem();
}

/*
 * Maybe move this to machdep.efi
 */
static pte_t
efi_to_pte_attrs(uint64_t efi)
{
	pte_t	pte = (PTE_AF)|(PTE_NG)|(PTE_SH_INNER)|(PTE_AP_KRWUNA)|(PTE_UXN);

	if (efi & (EFI_MEMORY_WB))
		pte |= (PTE_ATTR_NORMEM);
	else if (efi & (EFI_MEMORY_WT))
		pte |= (PTE_ATTR_NORMEM_WT);
	else if (efi & (EFI_MEMORY_WC))
		pte |= (PTE_ATTR_NORMEM_UC);
	else if (efi & (EFI_MEMORY_UC))
		pte |= ((PTE_ATTR_DEVICE)|(PTE_PXN));
	else if (efi & (EFI_MEMORY_UCE))
		prom_panic("efi_to_pte_attrs: EFI_MEMORY_UCE undefined for "
			   "aarch64\n");

	if (efi & (EFI_MEMORY_WP))
		prom_panic("efi_to_pte_attrs: EFI_MEMORY_WP undefined for "
			   "aarch64\n");
	else if (efi & (EFI_MEMORY_RP))
		prom_panic("efi_to_pte_attrs: EFI_MEMORY_RP undefined for "
			   "aarch64\n");
	else if (efi & (EFI_MEMORY_XP))
		pte |= ((PTE_UXN)|(PTE_PXN));
	else if (efi & (EFI_MEMORY_RO))
		pte |= (PTE_AP_RO);

	/*
	 * Ignore EFI_MEMORY_NV and EFI_MEMORY_MORE_RELIABLE for now.
	 */

	return (pte);
}

/*
 * Maybe move this to machdep.efi
 */
void
map_efimem(uint64_t offset)
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
		prom_panic("map_efimem: no UEFI memory map header\n");

	mhdr = efi_map_header;
	efisz = (sizeof(struct efi_map_header) + 0xf) & ~0xf;
	map = (EFI_MEMORY_DESCRIPTOR *)((uint8_t *)mhdr + efisz);
	if (mhdr->descriptor_size == 0)
		prom_panic("map_efimem: invalid memory descriptor size\n");
        ndesc = mhdr->memory_size / mhdr->descriptor_size;

        for (i = 0, p = map; i < ndesc; i++, p = efi_mmap_next(p, mhdr->descriptor_size)) {
		map_phys(
			efi_to_pte_attrs(p->Attribute),
			(caddr_t)(offset + p->PhysicalStart),
			p->PhysicalStart,
			p->NumberOfPages * MMU_PAGESIZE);
	}

	/*
	 * Annoyingly, we don't always have the DBG2 memory covered.
	 */
	if (bi->bi_bsvc_uart_mmio_base) {
		addr = RNDDN(bi->bi_bsvc_uart_mmio_base, MMU_PAGESIZE);
		size = RNDUP(bi->bi_bsvc_uart_mmio_base + 0x1000, MMU_PAGESIZE) - addr;
		map_phys(
			efi_to_pte_attrs(EFI_MEMORY_UC)|PTE_UXN,
			(caddr_t)(offset + addr),
			addr,
			size);
	} else {
#if defined(_EARLY_DBG2) && _EARLY_DBG2 > 0
		addr = RNDDN(EARLY_DBG2_PA, MMU_PAGESIZE);
		size = RNDUP(EARLY_DBG2_PA + 0x1000, MMU_PAGESIZE) - addr;
		map_phys(
			efi_to_pte_attrs(EFI_MEMORY_UC)|PTE_UXN,
			(caddr_t)(offset + addr),
			addr,
			size);
#endif
	}
}

/* Page Table Initialization */
static void
init_pt(void)
{
	uintptr_t paddr;

	paddr = memlist_get(MMU_PAGESIZE, MMU_PAGESIZE, &pfreelistp);
	if (paddr == 0)
		prom_panic("phy alloc error for L1 PT\n");
	bzero((void *)paddr, MMU_PAGESIZE);
	l1_ptbl0 = (pte_t *)paddr;

	paddr = memlist_get(MMU_PAGESIZE, MMU_PAGESIZE, &pfreelistp);
	if (paddr == 0)
		prom_panic("phy alloc error for L1 PT\n");
	bzero((void *)paddr, MMU_PAGESIZE);
	l1_ptbl1 = (pte_t *)paddr;

	map_efimem(0);

	uint64_t mair = ((MAIR_ATTR_nGnRnE    << (MAIR_STRONG_ORDER * 8)) |
	    (MAIR_ATTR_nGnRE	<< (MAIR_DEVICE * 8)) |
	    (MAIR_ATTR_IWB_OWB	<< (MAIR_NORMAL_MEMORY * 8)) |
	    (MAIR_ATTR_IWT_OWT	<< (MAIR_NORMAL_MEMORY_WT * 8)) |
	    (MAIR_ATTR_INC_ONC	<< (MAIR_NORMAL_MEMORY_UC * 8)) |
	    (MAIR_ATTR_nGRE	<< (MAIR_UNORDERED * 8)));

	uint64_t tcr =
	    ((uint64_t)MMFR0_PARANGE(read_id_aa64mmfr0()) << TCR_IPS_SHIFT) |
	    TCR_TG1_4K | TCR_SH1_ISH | TCR_ORGN1_WBWA | TCR_IRGN1_WBWA |
	    TCR_T1SZ_256T | TCR_TG0_4K | TCR_SH0_ISH | TCR_ORGN0_WBWA |
	    TCR_IRGN0_WBWA | TCR_T0SZ_256T;

	uint64_t sctlr = SCTLR_EL1_RES1 | SCTLR_UCI | SCTLR_UCT | SCTLR_DZE |
	    SCTLR_I | SCTLR_C | SCTLR_M;

	write_mair(mair);
	write_tcr(tcr);
	write_ttbr0((uint64_t)l1_ptbl0);
	write_ttbr1((uint64_t)l1_ptbl1);
	isb();

	if (debug)
		dump_tables((uint64_t)l1_ptbl0, 0);

	tlbi_allis();
	dsb(ish);
	isb();

	dsb(ish);
	write_sctlr(sctlr);
	isb();
}


static void
map_pages(pte_t pte_attr, caddr_t vaddr, uint64_t paddr, size_t bytes)
{
	int l1_idx = l1_pteidx(vaddr);
	int l2_idx = l2_pteidx(vaddr);
	int l3_idx = l3_pteidx(vaddr);
	int l4_idx = l4_pteidx(vaddr);

	pte_t *l1_ptbl = (((uint64_t)vaddr) >> 63)? l1_ptbl1: l1_ptbl0;

	if ((l1_ptbl[l1_idx] & PTE_TYPE_MASK) == 0) {
		paddr_t pa = memlist_get(MMU_PAGESIZE, MMU_PAGESIZE,
		    &pfreelistp);
		if (pa == 0)
			prom_panic("phy alloc error for L2 PT\n");
		bzero((void *)(uintptr_t)pa, MMU_PAGESIZE);
		dsb(ish);
		l1_ptbl[l1_idx] = PTE_TABLE_APT_NOUSER | PTE_TABLE_UXNT | pa |
		    PTE_TABLE;
	}

	if ((l1_ptbl[l1_idx] & PTE_VALID) == 0) {
		prom_panic("invalid L1 PT\n");
	}

	pte_t *l2_ptbl = (pte_t *)(uintptr_t)(l1_ptbl[l1_idx] & PTE_PFN_MASK);

	if (bytes == MMU_PAGESIZE1G) {
		if ((uintptr_t)vaddr & (bytes - 1)) {
			prom_panic("invalid vaddr (1G)\n");
		}
		if (paddr & (bytes - 1)) {
			prom_panic("invalid paddr (1G)\n");
		}
		if (l2_ptbl[l2_idx] & PTE_VALID) {
			prom_panic("invalid L2 PT\n");
		}
		l2_ptbl[l2_idx] = paddr | pte_attr | PTE_BLOCK;
		dsb(ish);
		return;
	}

	if ((l2_ptbl[l2_idx] & PTE_TYPE_MASK) == 0) {
		paddr_t pa = memlist_get(MMU_PAGESIZE, MMU_PAGESIZE,
		    &pfreelistp);
		if (pa == 0)
			prom_panic("phy alloc error for L2 PT\n");
		bzero((void *)(uintptr_t)pa, MMU_PAGESIZE);
		dsb(ish);
		l2_ptbl[l2_idx] = PTE_TABLE_APT_NOUSER | PTE_TABLE_UXNT | pa |
		    PTE_TABLE;
	}

	if ((l2_ptbl[l2_idx] & PTE_TYPE_MASK) != PTE_TABLE) {
		prom_panic("invalid L2 PT\n");
	}

	pte_t *l3_ptbl = (pte_t *)(uintptr_t)(l2_ptbl[l2_idx] & PTE_PFN_MASK);

	if (bytes == MMU_PAGESIZE2M) {
		if ((uintptr_t)vaddr & (bytes - 1)) {
			prom_panic("invalid vaddr (2M)\n");
		}
		if (paddr & (bytes - 1)) {
			prom_panic("invalid paddr (2M)\n");
		}
		if (l3_ptbl[l3_idx] & PTE_VALID) {
			prom_panic("invalid L3 PT\n");
		}
		l3_ptbl[l3_idx] = paddr | pte_attr | PTE_BLOCK;
		dsb(ish);
		return;
	}

	if ((l3_ptbl[l3_idx] & PTE_TYPE_MASK) == 0) {
		paddr_t pa = memlist_get(MMU_PAGESIZE, MMU_PAGESIZE,
		    &pfreelistp);
		if (pa == 0)
			prom_panic("phy alloc error for L3 PT\n");
		bzero((void *)(uintptr_t)pa, MMU_PAGESIZE);
		dsb(ish);
		l3_ptbl[l3_idx] = PTE_TABLE_APT_NOUSER | PTE_TABLE_UXNT | pa |
		    PTE_TABLE;
	}

	if ((l3_ptbl[l3_idx] & PTE_TYPE_MASK) != PTE_TABLE) {
		prom_panic("invalid L3 PT\n");
	}

	pte_t *l4_ptbl = (pte_t *)(uintptr_t)(l3_ptbl[l3_idx] & PTE_PFN_MASK);
	if (bytes == MMU_PAGESIZE) {
		if ((uintptr_t)vaddr & (bytes - 1)) {
			prom_panic("invalid vaddr (4K)\n");
		}
		if (paddr & (bytes - 1)) {
			prom_panic("invalid paddr (4K)\n");
		}
		if (l4_ptbl[l4_idx] & PTE_VALID) {
			prom_panic("invalid L4 PT\n");
		}
		l4_ptbl[l4_idx] = paddr | pte_attr | PTE_PAGE;
		dsb(ish);
		return;
	}
	prom_panic("invalid size\n");
}

void
map_phys(pte_t pte_attr, caddr_t vaddr, uint64_t paddr, size_t bytes)
{
	if (((uintptr_t)vaddr % MMU_PAGESIZE) != 0) {
		prom_panic("map_phys invalid vaddr\n");
	}
	if ((paddr % MMU_PAGESIZE) != 0) {
		prom_panic("map_phys invalid paddr\n");
	}
	if ((bytes % MMU_PAGESIZE) != 0) {
		prom_panic("map_phys invalid size\n");
	}

	while (bytes) {
		uintptr_t va = (uintptr_t)vaddr;
		size_t maxalign = va & (-va);
		size_t mapsz;
		if (maxalign >= MMU_PAGESIZE1G && bytes >= MMU_PAGESIZE1G &&
		    paddr >= MMU_PAGESIZE1G) {
			mapsz = MMU_PAGESIZE1G;
		} else if (maxalign >= MMU_PAGESIZE2M &&
		    bytes >= MMU_PAGESIZE2M && paddr >= MMU_PAGESIZE2M) {
			mapsz = MMU_PAGESIZE2M;
		} else {
			mapsz = MMU_PAGESIZE;
		}
		map_pages(pte_attr, vaddr, paddr, mapsz);
		bytes -= mapsz;
		vaddr += mapsz;
		paddr += mapsz;
	}
}

static caddr_t
get_low_vpage(size_t bytes)
{
	caddr_t v;

	if ((scratch_used_top + bytes) <= _RamdiskStart) {
		v = scratch_used_top;
		scratch_used_top += bytes;
		return (v);
	}

	return (NULL);
}

caddr_t
resalloc(enum RESOURCES type, size_t bytes, caddr_t virthint, int align)
{
	caddr_t	vaddr = 0;
	uintptr_t paddr = 0;

	if (bytes != 0) {
		/* extend request to fill a page */
		bytes = roundup(bytes, MMU_PAGESIZE);
		dprintf("resalloc:  bytes = %lu\n", bytes);
		switch (type) {
		case RES_BOOTSCRATCH:
			vaddr = get_low_vpage(bytes);
			break;
		case RES_CHILDVIRT:
			vaddr = virthint;
			while (bytes) {
				uintptr_t va = (uintptr_t)virthint;
				size_t maxalign = va & (-va);
				size_t mapsz;
				if (maxalign >= MMU_PAGESIZE1G &&
				    bytes >= MMU_PAGESIZE1G) {
					mapsz = MMU_PAGESIZE1G;
				} else if (maxalign >= MMU_PAGESIZE2M &&
				    bytes >= MMU_PAGESIZE2M) {
					mapsz = MMU_PAGESIZE2M;
				} else {
					mapsz = MMU_PAGESIZE;
				}
				paddr = memlist_get(mapsz, mapsz, &pfreelistp);
				if (paddr == 0) {
					prom_panic("phys mem allocate error\n");
				}
				map_phys(PTE_AF | PTE_SH_INNER | PTE_AP_KRWUNA |
				    PTE_ATTR_NORMEM, virthint, paddr, mapsz);
				bytes -= mapsz;
				virthint += mapsz;
			}
			break;
		default:
			dprintf("Bad resurce type\n");
			break;
		}
	}

	return (vaddr);
}

void
reset_alloc(void)
{
}

void
resfree(enum RESOURCES type, caddr_t virtaddr, size_t size)
{
}

static void
dump_tables(uint64_t tab, uint64_t va_offset)
{
	uint_t shift_amt[] = {12, 21, 30, 39};
	uint_t save_index[4];   /* for recursion */
	char *save_table[4];    /* for recursion */
	uint_t top_level = 3;
	uint_t ptes_per_table = 512;
	uint_t  l;
	uint64_t va;
	uint64_t pgsize;
	int index;
	int i;
	pte_t pteval;
	char *table;
	static char *tablist = "\t\t\t";
	char *tabs = tablist + 3 - top_level;
	paddr_t pa, pa1;

	table = (char *)(uintptr_t)tab;
	l = top_level;
	va = va_offset;

	for (index = 0; index < ptes_per_table; ++index) {
		pgsize = 1ull << shift_amt[l];
		pteval = ((pte_t *)table)[index];
		if (!(pteval & PTE_VALID))
			goto next_entry;

		prom_printf("%s [L%u] 0x%p[%u] = 0x%" PRIx64 ", va=0x%" PRIx64,
		    tabs + l, l, (void *)table, index, (uint64_t)pteval, va);
		pa = pteval & PTE_PFN_MASK;
		if (l == 0 || (l != 0 && (pteval & PTE_TYPE_MASK) == PTE_BLOCK)) {
			prom_printf(" physaddr=0x%" PRIx64 "\n", pa);
		} else {
			prom_printf(" => 0x%" PRIx64 "\n", pa);
		}

		if (l > 0 && (pteval & PTE_TYPE_MASK) == PTE_TABLE) {
			save_table[l] = table;
			save_index[l] = index;
			--l;
			index = -1;
			table = (char *)(uintptr_t)(pteval & PTE_PFN_MASK);
			goto recursion;
		}

		/*
		 * shorten dump for consecutive mappings
		 */
		for (i = 1; index + i < ptes_per_table; ++i) {
			pteval = ((pte_t *)table)[index + i];
			if (!(pteval & PTE_TYPE_MASK))
				break;
			pa1 = (pteval & PTE_PFN_MASK);
			if (pa1 != pa + i * pgsize)
				break;
		}

		if (i > 2) {
			prom_printf("%s...\n", tabs + l);
			va += pgsize * (i - 2);
			index += i - 2;
		}
next_entry:
		va += pgsize;
recursion:
		;
	}

	if (l < top_level) {
		++l;
		index = save_index[l];
		table = save_table[l];
		goto recursion;
	}
}
