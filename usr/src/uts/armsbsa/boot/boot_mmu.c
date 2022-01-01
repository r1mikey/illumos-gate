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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2022 Michael van der Westhuizen
 */

/*
 * WARNING: This file is used by both eboot and the kernel.
 */

#include <sys/param.h>
#include <sys/machparam.h>
#include <sys/mach_mmu.h>
#include <sys/machsystm.h>

#ifdef _BOOT
#include <eboot/eboot_printf.h>
#define	bop_panic eboot_panic
#else
#include <sys/bootconf.h>
#endif

#if defined(_BOOT)
#undef	FIND_PTE_DEBUG
#else
#undef	FIND_PTE_DEBUG
#endif

#if defined(FIND_PTE_DEBUG)
#if defined(_BOOT)
extern int debug_get_pteval;
extern void eboot_printf(char *fmt, ...);
#define	DBG_P(...) { if (debug_get_pteval) eboot_printf(__VA_ARGS__); }
#else
#define	DBG_P(...) bop_printf(NULL, __VA_ARGS__)
#endif
#else
#define	DBG_P(...)	/* de nada */
#endif

/*
 * XXXAARCH64: this can go, but we want 52 bit VA support in the future too, so
 * the technique must stay.
 *
 * Note that levels in illumos are backwards compared to aarch64 levels, where
 * level 0 is the root in aarch64 but the leaf in illumos.  While this seems
 * like something that could/should be addressed, the illumos way is a bit
 * more flexible and will help us when we need to add level -1 mappings in the
 * future.
 */
uint_t shift_amt_nopae[] = {12, 22};
uint_t shift_amt_pae[] = {12, 21, 30, 39};
uint_t *shift_amt;
uint_t ptes_per_table;
uint_t pte_size;
uint32_t lpagesize;
paddr_t ttbr1_top_table;
paddr_t ttbr0_top_table;
uint_t top_level;

#ifdef _BOOT
extern uintptr_t hole_start;
extern uintptr_t hole_end;
#endif

/*
 * Return the index corresponding to a virt address at a given page table level.
 */
static uint_t
vatoindex(uint64_t va, uint_t level)
{
	return ((va >> shift_amt[level]) & (ptes_per_table - 1));
}

/*
 * Return a pointer to the page table entry that maps a virtual address.
 * If there is no page table and probe_only is not set, one is created.
 *
 * Level is the requested leaf level, where 0 is the ultimate leaf.
 *
 * If the requested level is non-zero, the created PTE should be set to
 * PTE_BLOCK for levels 1 and 2.  Level 3 (the top level) can only reference
 * other tables, so should be PTE_TABLE.  A leaf (level 0) entry can only
 * be marked as PTE_PAGE.  This is done via make_ptable for internal tables
 * needed to reach the returned PTE (which will always create a PTE_TABLE),
 * and is left to the caller for the requested leaf level (i.e PTE_BLOCK for
 * large mappings and PTE_PAGE for granule-sized mappings).
 */
aarch64pte_t *
find_pte(uint64_t va, paddr_t *pa, uint_t level, uint_t probe_only)
{
	uint_t l;
	uint_t index;
	paddr_t table;

	if (pa)
		*pa = 0;

	/*
	 * Select the appropriate root table based on the requested VA.
	 *
	 * If the requested VA falls into the VA hole we use the probe_only
	 * flag to decide whether to return NULL (in the probe case) or
	 * panic.
	 */
	if (va < hole_start) {
		table = ttbr0_top_table;
	} else if (va >= hole_end) {
		table = ttbr1_top_table;
	} else {
		if (probe_only)
			return (NULL);
		bop_panic("find_pte(): va in hole!\n");
	}

	/*
	 * Walk down the page tables creating any needed intermediate tables.
	 */
	for (l = top_level; l != level; --l) {
		uint64_t pteval;
		paddr_t new_table;

		index = vatoindex(va, l);
		pteval = get_pteval(table, index);

		/*
		 * Life is easy if we find the pagetable.  We just use it.
		 */
		if (PTE_IS_VALID(pteval, l)) {
			table = PT_TO_PA(pteval);
			continue;
		}

		if (probe_only)
			return (NULL);

		new_table = make_ptable(&pteval, l);
		set_pteval(table, index, l, pteval);
		table = new_table;
	}

	/*
	 * Return a pointer into the current pagetable.
	 */
	index = vatoindex(va, l);
	if (pa)
		*pa = table + index * pte_size;
	return (map_pte(table, index));
}
