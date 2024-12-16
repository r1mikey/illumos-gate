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

#ifndef _DDI_ARCH_INTR_H
#define	_DDI_ARCH_INTR_H

/*
 * DDI interrupt extensions for Arm BSA hardware
 *
 * Specifically, handle data needed for the Arm Generic Interrupt Controller.
 */

#include <sys/types.h>
#include <sys/ddi_impldefs.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ddi_arch_parent_private_data {
	/*
	 * `ppd' must come first, and must not be a pointer.
	 *
	 * This allows us to cast to/from ddi_parent_private_data.
	 */
	struct ddi_parent_private_data	ppd;
	int				*par_icfg;
};

extern dev_info_t * i_ddi_interrupt_parent(dev_info_t *);

#ifdef __cplusplus
}
#endif

#endif /* _DDI_ARCH_INTR_H */
