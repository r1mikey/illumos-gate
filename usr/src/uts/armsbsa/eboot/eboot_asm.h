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

#ifndef	_EBOOT_ASM_H
#define	_EBOOT_ASM_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern void iowrite32(uint64_t a, uint32_t c);
extern uint32_t ioread32(uint64_t a);

#ifdef	__cplusplus
}
#endif

#endif	/* _EBOOT_ASM_H */
