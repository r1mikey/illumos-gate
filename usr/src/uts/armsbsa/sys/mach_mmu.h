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
 * Copyright 2022 Michael van der Westhuizen
 */

#ifndef _MACH_MMU_H
#define	_MACH_MMU_H

/*
 * Platform-dependent MMU routines and types.
 *
 * WARNING: this header file is used by both dboot and armsbsa, so don't go
 * using normal kernel headers.
 */

#ifndef _ASM

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/archmmu.h>
#include <sys/pte.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	pa_to_ma(pa)	(pa)

#if !defined(_BOOT)
extern void mmu_invlpg(caddr_t);
#endif

aarch64pte_t get_pteval(paddr_t, uint_t);
void set_pteval(paddr_t, uint_t, uint_t, aarch64pte_t);
paddr_t make_ptable(aarch64pte_t *, uint_t);
aarch64pte_t *find_pte(uint64_t, paddr_t *, uint_t, uint_t);
aarch64pte_t *map_pte(paddr_t, uint_t);

/* XXXAARCH64: we don't need a lot of this cruft */
extern uint_t *shift_amt;
extern uint_t ptes_per_table;
extern paddr_t ttbr1_top_table;
extern paddr_t ttbr0_top_table;
extern uint_t top_level;
extern uint_t pte_size;
extern uint_t shift_amt_nopae[];
extern uint_t shift_amt_pae[];
extern uint32_t lpagesize;

#ifdef __cplusplus
}
#endif

#endif	/* _ASM */

#endif	/* _MACH_MMU_H */
