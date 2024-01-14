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

#ifndef _SYS_PSM_GIC_TYPES_H
#define	_SYS_PSM_GIC_TYPES_H

/*
 * PSM GIC types, mostly just configuration data.
 */

#include <sys/types.h>
#include <sys/ddi_impldefs.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	struct regspec64	pgc_gicc;
	struct regspec64	pgc_gicd;
} psm_gicv2_config_t;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_PSM_GIC_TYPES_H */
