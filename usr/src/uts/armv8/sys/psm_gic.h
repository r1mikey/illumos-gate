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

#ifndef _SYS_PSM_GIC_H
#define	_SYS_PSM_GIC_H

/*
 * PSM GIC interface structure
 */

#ifdef __cplusplus
extern "C" {
#endif

struct psm_gic;
typedef struct psm_gic psm_gic_t;

/*
 * Types and data structure filled by GIC implementation modules
 */
typedef int (*pgo_init_t)(psm_gic_t *pg);
typedef int (*pgo_fini_t)(psm_gic_t *pg);
typedef void (*pgo_cpu_init_t)(void *ctx, cpu_t *cp);

typedef void (*pgo_config_irq_t)(void *ctx, uint32_t irq, boolean_t is_edge);
typedef int (*pgo_addspl_t)(void *ctx, int irq, int ipl);
typedef int (*pgo_delspl_t)(void *ctx, int irq, int ipl);
/* set priority mask from an IRQ */
typedef int (*pgo_setlvl_t)(void *ctx, int irq);
/* set priority mask from an IPL */
typedef void (*pgo_setlvlx_t)(void *ctx, int ipl);

typedef void (*pgo_send_ipi_t)(void *ctx, cpuset_t cpuset, int irq);

typedef uint64_t (*pgo_acknowledge_t)(void *ctx);
typedef uint32_t (*pgo_ack_to_vector_t)(void *ctx, uint64_t ack);
typedef void (*pgo_eoi_t)(void *ctx, uint64_t ack);
typedef void (*pgo_deactivate_t)(void *ctx, uint64_t ack);

typedef int (*pgo_is_spurious_t)(void *ctx, uint32_t intid);

typedef int (*pgo_get_intr_caps_t)(void *ctx, uint32_t intid);

typedef struct {
	pgo_init_t		pgo_init;
	pgo_fini_t		pgo_fini;
	pgo_cpu_init_t		pgo_cpu_init;

	pgo_config_irq_t	pgo_config_irq;
	pgo_addspl_t		pgo_addspl;
	pgo_delspl_t		pgo_delspl;
	pgo_setlvl_t		pgo_setlvl;
	pgo_setlvlx_t		pgo_setlvlx;

	pgo_send_ipi_t		pgo_send_ipi;

	pgo_acknowledge_t	pgo_acknowledge;
	pgo_ack_to_vector_t	pgo_ack_to_vector;
	pgo_eoi_t		pgo_eoi;
	pgo_deactivate_t	pgo_deactivate;

	pgo_is_spurious_t	pgo_is_spurious;
	pgo_get_intr_caps_t	pgo_get_intr_caps;
} psm_gic_ops_t;

typedef int (*psm_gic_initfunc_t)(psm_gic_t *pg);
typedef int (*psm_gic_finifunc_t)(psm_gic_t *pg);

typedef struct psm_gic {
	psm_gic_ops_t		pg_ops;
	psm_gic_initfunc_t	pg_init;
	psm_gic_finifunc_t	pg_fini;
	void			*pg_config;
	void			*pg_data;
} psm_gic_t;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_PSM_GIC_H */
