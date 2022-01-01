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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2018 Joyent, Inc.
 * Copyright 2022 Michael van der Westhuizen
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/archsystm.h>
#include <sys/debug.h>
#include <sys/bootconf.h>
#include <sys/bootsvcs.h>
#include <sys/bootinfo.h>
#include <sys/mman.h>
#include <sys/cmn_err.h>
#include <sys/param.h>
#include <sys/machparam.h>
#include <sys/machsystm.h>
#include <sys/promif.h>
#include <sys/kobj.h>
#include <vm/kboot_mmu.h>
#include <vm/hat_pte.h>
#include <vm/hat_aarch64.h>
#include <vm/seg_kmem.h>

#if 0
/*
 * Joe's debug printing
 */
#define	DBG(x)    \
	bop_printf(NULL, "kboot_mmu.c: %s is %" PRIx64 "\n", #x, (uint64_t)(x));
#else
#define	DBG(x)	/* naught */
#endif

/*
 * Page table and memory stuff.
 */
static aarch64pte_t *window;
static aarch64pte_t *pte_to_window;

/*
 * these are needed by mmu_init()
 */
int kbm_largepage_support = 0;
uint_t kbm_nucleus_size = 0;

#define	BOOT_SHIFT(l)	(shift_amt[l])
#define	BOOT_SZ(l)	((size_t)1 << BOOT_SHIFT(l))
#define	BOOT_OFFSET(l)	(BOOT_SZ(l) - 1)
#define	BOOT_MASK(l)	(~BOOT_OFFSET(l))

/*
 * Initialize memory management parameters for boot time page table management
 */
void
kbm_init(struct xboot_info *bi)
{
	/*
	 * configure mmu information
	 */
	kbm_nucleus_size = (uintptr_t)bi->bi_kseg_size;
	kbm_largepage_support = 1;
	window = (aarch64pte_t *)bi->bi_pt_window;
	DBG(window);
	pte_to_window = (aarch64pte_t *)bi->bi_pte_to_pt_window;
	DBG(pte_to_window);

	shift_amt = shift_amt_pae;	/* XXXAARCH64 */
	ptes_per_table = 512;
	pte_size = 8;
	lpagesize = TWO_MEG;
	top_level = 3;			/* XXXAARCH64 */

	ttbr1_top_table = bi->bi_top_ttbr1;
	DBG(ttbr1_top_table);
	ttbr0_top_table = bi->bi_top_ttbr0;
	DBG(ttbr0_top_table);
}

/*
 * Change the addressible page table window to point at a given page
 */
/*ARGSUSED*/
void *
kbm_remap_window(paddr_t physaddr, int writeable)
{
	aarch64pte_t tmpl = PT_NOCONSIST
	    | PT_ATTR_AF
	    | PT_ATTR_SH(PT_SH_OS)
	    | PT_ATTR_AP(PT_AP_PRW)
	    | PT_MATTR(MIDX_MEMORY_NC)
	    | PTE_PAGE;

	aarch64pte_t pt_bits = tmpl | PA_TO_PT_OA(physaddr);

	/*
	 * should we drain the write and flush of the existing entry is valid?
	 * also, invalidate regardless?
	 */
	*pte_to_window = pt_bits;
	tlbi_mva((uint64_t)window);
	dsb(ish);
	isb();
	return ((void *)window);
}

/*
 * Add a mapping for the physical page at the given virtual address.
 *
 * The level indicates the size, with 0 beibg 4KiB, 1 being 2MiB
 * and 2 being 1GiB. Level 3 can't do block mappings.
 *
 * This won't handle contiguous stuff very well.
 */
void
kbm_map(uintptr_t va, paddr_t pa, uint_t level, uint_t is_kernel)
{
	aarch64pte_t *ptep;
	paddr_t pte_physaddr;
	aarch64pte_t pteval;

	if (khat_running)
		panic("kbm_map() called too late");

	if (level == 3)
		panic("kbm_map() can't create mappings at page table level 3");

#if defined(KBM_DEBUG)
	bop_printf(NULL, "kbm_map: va 0x%lx, pa 0x%lx, level %u, "
	    "is_kernel %u\n", va, pa, level, is_kernel);
#endif

	/*
	 * If we're doing a L2 mapping we must be 1GiB aligned.
	 * If we're doing an L1 mapping we must be 2MiB aligned.
	 * If we're doing a L0 mapping we must be 4KiB aligned.
	 */

	pteval = PT_NOCONSIST | PA_TO_PT_OA(pa) | \
	    PT_ATTR_AP(PT_AP_PRW) | PT_ATTR_SH(PT_SH_OS) | \
	    PT_ATTR_AF | ((level == 0) ? PTE_PAGE : PTE_BLOCK);

	/* XXXAARCH64: I don't get it - it's all kernel at this point */
	if (!is_kernel)
		pteval |= PT_ATTR_NG;

	/*
	 * Find the pte that will map this address. This creates any
	 * missing intermediate level page tables.
	 */
	ptep = find_pte(va, &pte_physaddr, level, 0);
	if (ptep == NULL)
		bop_panic("kbm_map: find_pte returned NULL");

#if defined(KBM_DEBUG)
	bop_printf(NULL, "kbm_map: mapping 0x%lx to 0x%lx with PTE pointer "
	    "0x%p and value 0x%lx - pte physaddress is 0x%lx\n",
	    pa, va, ptep, pteval, pte_physaddr);
#endif
	DBG(ptep);
	DBG(*ptep);
	*ptep = pteval;
	DBG(*ptep);
	mmu_invlpg((caddr_t)ptep);
	mmu_invlpg((caddr_t)va);
}

/*
 * Probe the boot time page tables to find the first mapping
 * including va (or higher) and return non-zero if one is found.
 * va is updated to the starting address and len to the pagesize.
 * pp will be set to point to the 1st page_t of the mapped page(s).
 *
 * Note that if va is in the middle of a large page, the returned va
 * will be less than what was asked for.
 */
int
kbm_probe(uintptr_t *va, size_t *len, pfn_t *pfn, uint_t *prot)
{
	uintptr_t	probe_va;
	aarch64pte_t	*ptep;
	paddr_t		pte_physaddr;
	aarch64pte_t	pte_val;
	uint_t		l;	/* should be level_t */
	int		first = 1;

	if (khat_running)
		panic("kbm_probe() called too late");

	*len = 0;
	*pfn = PFN_INVALID;
	*prot = 0;
	probe_va = *va;
restart_new_va:
	l = top_level;
	for (;;) {
		if (!first && probe_va < *va)
			return (0);
		first = 0;

		if (IN_VA_HOLE(probe_va)) {
			probe_va = mmu.hole_end;
			if (probe_va <= *va)
				return (0);
			goto restart_new_va;
		}

		/*
		 * If we don't have a valid PTP/PTE at this level then we can
		 * bump VA by this level's block/page size and try again.
		 * When the probe_va wraps around, we are done.
		 */
		ptep = find_pte(probe_va, &pte_physaddr, l, 1);
		if (ptep == NULL)
			bop_panic("kbm_probe: find_pte returned NULL for "
			    "va 0x%lx", probe_va);
		pte_val = *ptep;

		if (!PTE_IS_VALID(pte_val, l)) {
			probe_va = (probe_va & BOOT_MASK(l)) + BOOT_SZ(l);
			if (probe_va <= *va)
				return (0);
			goto restart_new_va;
		}

		/*
		 * If this entry is a pointer to a lower level page table go
		 * down to it.
		 */
		if (PTE_IS_TABLE(pte_val, l)) {
			ASSERT(l > 0);
			--l;
			continue;
		}

		/*
		 * We are valid and we are either a block or a page.
		 */
#if 0
		bop_printf(NULL, "%s: for pte_val 0x%lx at level %u, PTE_IS_BLOCK: %u, PTE_ISPAGE %u\n",
		    __func__, pte_val, l, PTE_IS_BLOCK(pte_val, l), PTE_ISPAGE(pte_val, l));
		bop_printf(NULL, "%s: got an entry, level is %u, len is 0x%lx, *va is 0x%lx, pfn is 0x%lx\n",
		    __func__, l, BOOT_SZ(l), probe_va & ~((BOOT_SZ(l)) - 1), PTE2PFN(pte_val, l));
#endif
		*len = BOOT_SZ(l);		/* mapping size (bytes) */
		*va = probe_va & ~(*len - 1);	/* aligned mapping va */
		*pfn = PTE2PFN(pte_val, l);	/* mapping start pfn */

		*prot = PROT_READ | PROT_EXEC;
		if (PT_IS_WRITABLE(pte_val))
			*prot |= PROT_WRITE;

		if (PT_IS_EXECUTABLE(pte_val))
			*prot |= PROT_EXEC;
		else
			*prot &= ~PROT_EXEC;

		return (1);
	}
}

/*
 * Destroy a boot loader page table 4K mapping.
 */
void
kbm_unmap(uintptr_t va)
{
	if (khat_running)
		panic("kbm_unmap() called too late");
	else {
		aarch64pte_t *ptep;
		level_t	level = 0;
		uint_t  probe_only = 1;

		ptep = find_pte(va, NULL, level, probe_only);
		if (ptep == NULL)
			return;

		DBG(ptep);
		DBG(*ptep);
		*ptep = 0;
		DBG(*ptep);
		mmu_invlpg((caddr_t)va);
	}
}


/*
 * Change a boot loader page table 4K mapping.
 * Returns the pfn of the old mapping.
 */
pfn_t
kbm_remap(uintptr_t va, pfn_t pfn)
{
	aarch64pte_t *ptep;
	level_t	level = 0;
	uint_t  probe_only = 1;
	aarch64pte_t pte_val = PT_NOCONSIST | PA_TO_PT_OA(pfn_to_pa(pfn)) |
	    PT_ATTR_AP(PT_AP_PRW) | PT_ATTR_SH(PT_SH_OS) | \
	    PT_ATTR_AF | PT_ATTR_NG | PTE_PAGE;
	aarch64pte_t old_pte;

	if (khat_running)
		panic("kbm_remap() called too late");
	ptep = find_pte(va, NULL, level, probe_only);
	if (ptep == NULL)
		bop_panic("kbm_remap: find_pte returned NULL");

	old_pte = *ptep;
	DBG(ptep);
	DBG(old_pte);
	*((aarch64pte_t *)ptep) = pte_val;
	DBG(*ptep);
	mmu_invlpg((caddr_t)va);

	/* XXXAARCH64: this -1 check is bad */
	if (!(old_pte & PT_VALID) || old_pte == -1)
		return (PFN_INVALID);
	return (mmu_btop(old_pte));
}


/*
 * Change a boot loader page table 4K mapping to read only.
 */
void
kbm_read_only(uintptr_t va, paddr_t pa)
{
	aarch64pte_t pte_val = PT_NOCONSIST | PA_TO_PT_OA(pa) |
	    PT_ATTR_AP(PT_AP_PRO) | PT_ATTR_SH(PT_SH_OS) | \
	    PT_ATTR_AF | PT_ATTR_NG | PTE_PAGE;

	aarch64pte_t *ptep;
	level_t	level = 0;

	ptep = find_pte(va, NULL, level, 0);
	if (ptep == NULL)
		bop_panic("kbm_read_only: find_pte returned NULL");

	DBG(ptep);
	DBG(*ptep);
	*ptep = pte_val;
	DBG(*ptep);
	mmu_invlpg((caddr_t)va);
}

/*
 * interfaces for kernel debugger to access physical memory
 */
static aarch64pte_t save_pte;

void *
kbm_push(paddr_t pa)
{
	static int first_time = 1;

	if (first_time) {
		first_time = 0;
		return ((void *)window);
	}

	save_pte = *pte_to_window;
	return (kbm_remap_window(pa, 0));
}

void
kbm_pop(void)
{
	*pte_to_window = save_pte;
	mmu_invlpg((caddr_t)window);
}

/*
 * Returns the value of the PTE at the given index in the given table.
 *
 * This remaps the table into the temporary mapping window to accomplish this
 * magical feat. See map_pte for getting a pointer you can mutate.
 */
aarch64pte_t
get_pteval(paddr_t table, uint_t index)
{
	aarch64pte_t *table_ptr = kbm_remap_window(table, 0);
	return table_ptr[index];
}

/*
 * Sets a PTE value in a table to the passed value.
 *
 * Temporarily maps the table, then updates the entry at the provided index.
 */
void
set_pteval(paddr_t table, uint_t index, uint_t level, aarch64pte_t pteval)
{
	aarch64pte_t *table_ptr = kbm_remap_window(table, 0);
	DBG(table);
	DBG(table_ptr);
	DBG(index);
	table_ptr[index] = pteval;
	DBG(table_ptr[index]);
}

/*
 * Only called by find_pte, which has the rather straightforward job of finding
 * a pointer to a specific page table entry for a leaf page table.
 *
 * This routine is called to create the pages that are part of the page table
 * as they are found to be required.
 *
 * Creates a new table, temporarily maps is and zeroes it.
 * The PTE value for the parent is passed back in pteval.
 *
 * The level argument is not used in aarch64, since all intermediate levels have
 * the same format for table references.
 */
paddr_t
make_ptable(aarch64pte_t *pteval, uint_t level)
{
	paddr_t new_table;
	aarch64pte_t *table_ptr;

	new_table = do_bop_phys_alloc(MMU_PAGESIZE, MMU_PAGESIZE);
	table_ptr = kbm_remap_window(new_table, 1);
	bzero((void *)table_ptr, MMU_PAGESIZE);

	*pteval = PA_TO_PT_OA(new_table) | PTE_TABLE;
	return (new_table);
}

/*
 * Maps the provided table into the PT management window, then returns a pointer
 * to the page table entry at the provided index.
 */
aarch64pte_t *
map_pte(paddr_t table, uint_t index)
{
	aarch64pte_t *table_ptr = kbm_remap_window(table, 0);
	return (&table_ptr[index]);
}
