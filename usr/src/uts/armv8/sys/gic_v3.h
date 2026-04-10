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
 * Copyright 2026 Michael van der Westhuizen
 */

#ifndef _SYS_GIC_V3_H
#define	_SYS_GIC_V3_H

#include <sys/types.h>
#include <sys/sunddi.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * GICv3 LPI exports for ITS and MBI drivers.
 *
 * This is a private interface between the GIC and the subordinate ITS driver
 * or embedded MBI driver.
 */

/* LPI INTID allocation */
extern int	gicv3_alloc_lpi(dev_info_t *, uint32_t *);
extern int	gicv3_alloc_lpi_block(dev_info_t *, uint32_t, uint32_t,
		    uint32_t *);
extern void	gicv3_free_lpi(dev_info_t *, uint32_t);
extern void	gicv3_free_lpi_block(dev_info_t *, uint32_t, uint32_t);

/* LPI configuration (PROPBASER table access) */
extern void	gicv3_lpi_set_config(dev_info_t *, uint32_t, uint8_t,
		    boolean_t);
extern uint8_t	gicv3_lpi_get_config(dev_info_t *, uint32_t);

/* Redistributor info for ITS MAPC commands */
extern uint64_t	gicv3_redist_pa(dev_info_t *, processorid_t);
extern uint32_t	gicv3_redist_procnum(dev_info_t *, processorid_t);
extern uint32_t	gicv3_num_redists(dev_info_t *);
extern uint32_t	gicv3_lpi_idbits(dev_info_t *);

/* ITS instance registration (for DDI MSI framework discovery) */
extern void	gicv3_register_its(dev_info_t *, dev_info_t *);
extern void	gicv3_unregister_its(dev_info_t *, dev_info_t *);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_GIC_V3_H */
