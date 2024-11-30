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
 * Copyright 2024 Michael van der Westhuizen
 */

#ifndef _SYS_PSM_H
#define	_SYS_PSM_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	PSM_PROT_READ	0x0000
#define	PSM_PROT_WRITE	0x0001

extern caddr_t psm_map_phys(paddr_t addr, size_t len, int prot);
extern caddr_t psm_map_phys_new(paddr_t addr, size_t len, int prot);
extern void psm_unmap_phys(caddr_t addr, size_t len);

extern caddr_t psm_map(paddr_t addr, size_t len, int prot);
extern caddr_t psm_map_new(paddr_t addr, size_t len, int prot);
extern void psm_unmap(caddr_t addr, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_PSM_H */
