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

#ifndef _SYS_GIC_V2M_H
#define	_SYS_GIC_V2M_H

#include <sys/types.h>
#include <sys/sunddi.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * GICv2m MSI frame registers
 *
 * ARM Server Base System Architecture (SBSA), Section 4.3.2
 * ARM GIC Architecture Specification, Section 9.9 (GICv2m)
 */
#define	V2M_MSI_TYPER		0x008
#define	V2M_MSI_SETSPI_NS	0x040
#define	V2M_MSI_IIDR		0xFCC

#define	V2M_MSI_TYPER_BASE(v)	(((v) >> 16) & 0x3FF)
#define	V2M_MSI_TYPER_COUNT(v)	((v) & 0x3FF)

/*
 * DT properties for SPI base/count override.
 *
 * Some GIC-400 implementations have incorrect MSI_TYPER values.
 * These properties, when present in the DT v2m node, override
 * the hardware register.  See: arm,gic.yaml in devicetree-source.
 */
#define	V2M_PROP_MSI_BASE_SPI	"arm,msi-base-spi"
#define	V2M_PROP_MSI_NUM_SPIS	"arm,msi-num-spis"

/*
 * Configure an SPI as edge-triggered or level-sensitive on the GICv2
 * distributor.  Takes the distributor lock internally.
 *
 * gic_dip: dev_info_t of the parent GICv2 instance
 * irq:     SPI INTID (32-1019)
 * is_edge: B_TRUE for edge-triggered, B_FALSE for level-sensitive
 *
 * This is a private interface, implemented by the GICv2 driver.
 */
extern void gicv2_configure_irq(dev_info_t *gic_dip, uint32_t irq,
    boolean_t is_edge);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_GIC_V2M_H */
