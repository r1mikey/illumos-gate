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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2018 Joyent, Inc.
 * Copyright 2022 Michael van der Westhuizen
 */

#include <sys/t_lock.h>
#include <sys/memlist.h>
#include <sys/cpuvar.h>
#include <sys/vmem.h>
#include <sys/mman.h>
#include <sys/vm.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/vm_machparam.h>
#include <sys/vnode.h>
#include <vm/hat.h>
#include <vm/anon.h>
#include <vm/as.h>
#include <vm/page.h>
#include <vm/seg.h>
#include <vm/seg_kmem.h>
#include <vm/seg_map.h>
#include <vm/hat_aarch64.h>
#include <vm/kboot_mmu.h>
#include <sys/promif.h>
#include <sys/systm.h>
#include <sys/archsystm.h>
#include <sys/sunddi.h>
#include <sys/ddidmareq.h>
#include <sys/controlregs.h>
#include <sys/pte.h>

extern caddr_t	kpm_vbase;
extern size_t	kpm_size;

/*
 * Flag is not set early in boot. Once it is set we are no longer
 * using boot's page tables.
 */
uint_t khat_running = 0;

/*
 * This procedure is callable only while the boot loader is in charge of the
 * MMU. It assumes that PA == VA for page table pointers.  It doesn't live in
 * kboot_mmu.c since it's used from common code.
 */
pfn_t
va_to_pfn(void *vaddr)
{
	uint64_t par;
	uint64_t pa;
	uintptr_t va;

	if (khat_running)
		panic("va_to_pfn(): called too late\n");

	va = ALIGN2PAGE(vaddr);
	write_s1e1r(va);
	isb();

	par = read_par_el1();
	if (par & PAR_F)
		return (PFN_INVALID);

	pa = (par & PAR_PA_MASK);

	return mmu_btop(pa);
}

/*
 * Initialize a special area in the kernel that always holds some PTEs for
 * faster performance. This always holds segmap's PTEs.
 * In the 32 bit kernel this maps the kernel heap too.
 *
 * XXXAARCH64: this needs a very careful read-through - I think indices may be funky.
 */
void
hat_kmap_init(uintptr_t base, size_t len)
{
	uintptr_t map_addr;	/* base rounded down to large page size */
	uintptr_t map_eaddr;	/* base + len rounded up */
	size_t map_len;
	caddr_t ptes;		/* mapping area in kernel for kmap ptes */
	size_t window_size;	/* size of mapping area for ptes */
	ulong_t htable_cnt;	/* # of page tables to cover map_len */
	ulong_t i;
	htable_t *ht;
	uintptr_t va;

	/*
	 * We have to map in an area that matches an entire page table.
	 * The PTEs are large page aligned to avoid spurious pagefaults
	 * on the hypervisor.
	 */
	map_addr = base & LEVEL_MASK(1);
	map_eaddr = (base + len + LEVEL_SIZE(1) - 1) & LEVEL_MASK(1);
	map_len = map_eaddr - map_addr;
	window_size = mmu_btop(map_len) * mmu.pte_size;
	window_size = (window_size + LEVEL_SIZE(1)) & LEVEL_MASK(1);
	htable_cnt = map_len >> LEVEL_SHIFT(1);

	/*
	 * allocate vmem for the kmap_ptes
	 */
	ptes = vmem_xalloc(heap_arena, window_size, LEVEL_SIZE(1), 0,
	    0, NULL, NULL, VM_SLEEP);
	mmu.kmap_htables =
	    kmem_alloc(htable_cnt * sizeof (htable_t *), KM_SLEEP);

	/*
	 * Map the page tables that cover kmap into the allocated range.
	 * Note we don't ever htable_release() the kmap page tables - they
	 * can't ever be stolen, freed, etc.
	 */
	for (va = map_addr, i = 0; i < htable_cnt; va += LEVEL_SIZE(1), ++i) {
		ht = htable_create(kas.a_hat, va, 0, NULL);
		if (ht == NULL)
			panic("hat_kmap_init: ht == NULL");
		mmu.kmap_htables[i] = ht;

		hat_devload(kas.a_hat, ptes + i * MMU_PAGESIZE,
		    MMU_PAGESIZE, ht->ht_pfn,
		    PROT_READ | PROT_WRITE | HAT_NOSYNC | HAT_UNORDERED_OK,
		    HAT_LOAD | HAT_LOAD_NOCONSIST);	/* XXXAARCH64: is devload right? */
	}

	/*
	 * set information in mmu to activate handling of kmap
	 */
	mmu.kmap_addr = map_addr;
	mmu.kmap_eaddr = map_eaddr;
	mmu.kmap_ptes = (aarch64pte_t *)ptes;
}

/*
 * Routine to pre-allocate data structures for hat_kern_setup(). It computes
 * how many pagetables it needs by walking the boot loader's page tables.
 *
 * If the kernel physical map (kpm) is to be used, sets up those mappings.
 */
void
hat_kern_alloc(
	caddr_t	segmap_base,
	size_t	segmap_size,
	caddr_t	ekernelheap)
{
	uintptr_t	last_va = (uintptr_t)-1;	/* catch 1st time */
	uintptr_t	va = 0;
	size_t		size;
	pfn_t		pfn;
	uint_t		prot;
	uint_t		table_cnt = 1;
	uint_t		mapping_cnt;
	level_t		start_level;
	level_t		l;
	struct memlist	*pmem;
	level_t		lpagel = mmu.max_page_level;
	uint64_t	paddr;
	int64_t		psize;

	ASSERT(kpm_size > 0);

	/*
	 * Create the kpm page tables.
	 */
	for (pmem = phys_install; pmem; pmem = pmem->ml_next) {
		paddr = pmem->ml_address;
		psize = pmem->ml_size;
		while (psize >= MMU_PAGESIZE) {
			/* find the largest page size */
			for (l = lpagel; l > 0; l--) {
				if ((paddr & LEVEL_OFFSET(l)) == 0 &&
				    psize > LEVEL_SIZE(l))
					break;
			}

			kbm_map((uintptr_t)kpm_vbase + paddr, paddr,
			    l, 1);
			paddr += LEVEL_SIZE(l);
			psize -= LEVEL_SIZE(l);
		}
	}

	/*
	 * Walk the boot loader's page tables and figure out
	 * how many tables and page mappings there will be.
	 */
	while (kbm_probe(&va, &size, &pfn, &prot) != 0) {
		/*
		 * At each level, if the last_va falls into a new htable,
		 * increment table_cnt. We can stop at the 1st level where
		 * they are in the same htable.
		 */
		start_level = 0;
		while (start_level <= mmu.max_page_level) {
			if (size == LEVEL_SIZE(start_level))
				break;
			start_level++;
		}

		for (l = start_level; l < mmu.max_level; ++l) {
			if (va >> LEVEL_SHIFT(l + 1) ==
			    last_va >> LEVEL_SHIFT(l + 1))
				break;
			++table_cnt;
		}
		last_va = va;
		l = (start_level == 0) ? 1 : start_level;
		va = (va & LEVEL_MASK(l)) + LEVEL_SIZE(l);
	}

	/*
	 * Besides the boot loader mappings, we're going to fill in
	 * the entire top level page table for the kernel. Make sure there's
	 * enough reserve for that too.
	 */
	table_cnt += mmu.top_level_count - ((kernelbase >>
	    LEVEL_SHIFT(mmu.max_level)) & (mmu.top_level_count - 1));

	/*
	 * Add 1/4 more into table_cnt for extra slop.  The unused
	 * slop is freed back when we htable_adjust_reserve() later.
	 */
	table_cnt += table_cnt >> 2;

	/*
	 * We only need mapping entries (hments) for shared pages.
	 * This should be far, far fewer than the total possible,
	 * We'll allocate enough for 1/16 of all possible PTEs.
	 */
	mapping_cnt = (table_cnt * mmu.ptes_per_table) >> 4;

	/*
	 * Now create the initial htable/hment reserves
	 */
	htable_initial_reserve(table_cnt);
	hment_reserve(mapping_cnt);
	/* XXXAARCH64: necessary? aarch64pte_cpu_init(CPU); */
}


/*
 * This routine handles the work of creating the kernel's initial mappings
 * by deciphering the mappings in the page tables created by the boot program.
 *
 * We maintain large page mappings, but only to a level 1 pagesize.
 * The boot loader can only add new mappings once this function starts.
 * In particular it can not change the pagesize used for any existing
 * mappings or this code breaks!
 */

void
hat_kern_setup(void)
{
	/*
	 * Attach htables to the existing pagetables
	 */
	htable_attach(kas.a_hat, KERNELBASE, mmu.max_level, NULL,
	    mmu_btop(read_ttbr1() & TTBR_BADDR48_MASK));	/* XXXAARCH64: only 48 bit PA */

	/*
	 * The kernel HAT is now officially open for business.
	 */
	khat_running = 1;

	/* XXXAARCH64: probably need this for user stuff... CPUSET_ATOMIC_ADD(kas.a_hat->hat_cpus, CPU->cpu_id); */
	CPUSET_ATOMIC_ADD(kas.a_hat->hat_cpus, CPU->cpu_id);
	CPU->cpu_current_hat = kas.a_hat;
}

/*
 * XXXAARCH64: invpcid (from i86pc) seems to map to our notion of ASID - need
 * to check if we need something like this.
 */

/*
 * Flush one kernel mapping.
 *
 * XXXAARCH64: we need to check what we really need here
 */
void
mmu_flush_tlb_kpage(uintptr_t va)
{
	ASSERT(va >= kernelbase);
	/* ASSERT(getasid() == KERNEL_ASID); */
	mmu_invlpg((caddr_t)va);
	/* tlbi va */
}

/*
 * Flush one mapping.
 *
 * XXXAARCH64: needs an ASID argument
 */
void
mmu_flush_tlb_page(uintptr_t va)
{
	ASSERT(va < mmu.hole_start);
	/* getasid() to get the ASID? We should allow the user to specify */
	mmu_invlpg((caddr_t)va);	/* XXXAARCH64: replace me */
	/* tlbi va + asid */
}

/* XXXAARCH64: mmu_flush_tlb_range - user or kernel? */
static void
mmu_flush_tlb_range(uintptr_t addr, size_t len, size_t pgsz)
{
	EQUIV(addr < kernelbase, (addr + len - 1) < kernelbase);
	ASSERT(len > 0);
	ASSERT(pgsz != 0);
	/* tlbi va + asid? unless asid is 0? */
}

/* XXXAARCH64: mmu_flush_tlb - user or kernel? differentiate by ASID? VA? */
/*
 * MMU TLB (and PT cache) flushing
 *
 * FLUSH_TLB_ALL: invalidate everything, all ASIDs, all global.
 * FLUSH_TLB_NONGLOBAL: invalidate all PCIDs, excluding PT_GLOBAL -- oof, no, can't do this
 * FLUSH_TLB_RANGE: invalidate the given range, including PCID_USER
 * mappings as appropriate.  If using invpcid, PT_GLOBAL mappings are not
 * invalidated.
 */
void
mmu_flush_tlb(flush_tlb_type_t type, tlb_range_t *range)
{
	/* ASSERT(getpcid() == PCID_KERNEL); */
	switch (type) {
	case FLUSH_TLB_ALL:
		ASSERT(range == NULL);
		/* invpcid(INVPCID_ALL_GLOBAL, 0, 0); */
		break;

	case FLUSH_TLB_NONGLOBAL:
		ASSERT(range == NULL);
		/* invpcid(INVPCID_ALL_NONGLOBAL, 0, 0); */
		break;

	case FLUSH_TLB_RANGE: {
		mmu_flush_tlb_range(range->tr_va, TLB_RANGE_LEN(range),
		    LEVEL_SIZE(range->tr_level));
		break;
	}

	default:
		break;
	}
}

/*
 * Everything below here is unique to the original port.  Need to check where
 * and how it's used and whether I can just delete it.
 */
static int
is_reserved_memory(paddr_t pa)
{
	pfn_t pfn = mmu_btop(pa);
	page_t *pp = page_numtopp_nolock(pfn);
	if (pp == NULL)
		return 0;
	if (!PAGE_EXCL(pp))
		return 0;
	if (pp->p_lckcnt != 1)
		return 0;
	return 1;
}

void boot_reserve(void)
{
	size_t count = 0;

	size_t pa_size_array[] = { (1ul << 32), (1ul << 36), (1ul << 40), (1ul << 42), (1ul << 44), (1ul << 48), (1ul << 52) };
	size_t pa_size = pa_size_array[read_id_aa64mmfr0() & 0xF];
	uintptr_t va = KERNELBASE;
	aarch64pte_t *ptbl[MMU_PAGE_LEVELS] = {0};
	ptbl[MMU_PAGE_LEVELS - 1] = (aarch64pte_t *)pa_to_kseg(read_ttbr1() & TTBR_BADDR48_MASK);

	ASSERT(is_reserved_memory(read_ttbr1() & TTBR_BADDR48_MASK));

	int l = 0;
	while (va != 0) {
		if (ptbl[l] == NULL) {
			l++;
			continue;
		}
		size_t page_size = LEVEL_SIZE(l);
		if (va == SEGKPM_BASE) {
			ASSERT(l == MMU_PAGE_LEVELS - 1);
			va += SEGKPM_SIZE;
			ptbl[l] += SEGKPM_SIZE / page_size;
			continue;
		}
		if ((*ptbl[l] & PTE_VALID) == 0) {
			va += page_size;
			++ptbl[l];
			if (((uintptr_t)ptbl[l] & MMU_PAGEOFFSET) == 0) {
				ptbl[l] = NULL;
			}
			continue;
		}

		if (l > 0 && (*ptbl[l] & PTE_TYPE_MASK) == PTE_TABLE) {
			ASSERT(ptbl[l - 1] == NULL);
			ptbl[l - 1] = (aarch64pte_t *)pa_to_kseg(PTE_TO_PA(*ptbl[l]));

			ASSERT(is_reserved_memory(PTE_TO_PA(*ptbl[l])));

			++ptbl[l];
			if (((uintptr_t)ptbl[l] & MMU_PAGEOFFSET) == 0) {
				ptbl[l] = NULL;
			}

			l--;
			continue;
		}

		*ptbl[l] |= PTE_NOCONSIST;
		uint64_t pa = (*ptbl[l] & ~(page_size - 1)) & (pa_size - 1);
		for (uint64_t x = 0; x < page_size / MMU_PAGESIZE; x++) {
			pfn_t pfn = mmu_btop(pa + MMU_PAGESIZE * x);
			page_t *pp = page_numtopp_nolock(pfn);
			if (pp) {
				ASSERT(PAGE_EXCL(pp));
				ASSERT(pp->p_lckcnt == 1);

				if (pp->p_vnode == NULL) {
					page_hashin(pp, &kvp, va + MMU_PAGESIZE * x, NULL);
				}
				count++;
			}
		}

		va += page_size;
		++ptbl[l];
		if (((uintptr_t)ptbl[l] & MMU_PAGEOFFSET) == 0) {
			ptbl[l] = NULL;
		}
	}

	if (page_resv(count, KM_NOSLEEP) == 0)
		panic("boot_reserve: page_resv failed");
}
