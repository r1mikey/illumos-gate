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

/*
 * FDT firmware configuration interfaces for interrupt controller
 * initialisation and finalisation.
 *
 * There are two public functions: armbsa_fdt_gic_probe and
 * armbsa_fdt_gic_init. The probe function takes no arguments and simply
 * return PSM_SUCCESS if the firmware tables indicate that a compatible
 * GIC is present. The init function initialises the probed hardware.
 *
 * The probe function is used by the PSM probe function to determine if this
 * PSM module is suitable for use.
 *
 * During initialisation, the pg_init and pg_fini of the passed psm_gic_t
 * object are set to functions that initialise and finalise the GIC
 * implementation. The initialiser is then called, while the finaliser is
 * called when the PSM module is bieng unloaded (or hit a later error while
 * initialising).
 *
 * The calls have the following responsibilities:
 * - fdt_gicv?_init: Allocate and fill an implementation-specific
 *   configuration object for the GIC implementation, then call the
 *   implementation-specific initialiser. Returns PSM_SUCCESS on success. Any
 *   other return value shoud be treated as a failure. There is no need to
 *   call the finaliser unless the initialiser returns PSM_SUCCESS.
 * - fdt_gicv?_fini: Call the implementation-specific finaliser function,
 *   then deallocate the configuration object. Returns PSM_SUCCESS on success.
 *
 * Firmware configuration GIC implementation initialisers must ensure that
 * they are being called in a reasonable state (this which are unallocated
 * must be NULL etc.) and finalisers must be tolerant of being called when in
 * a partially or completely uninitialised state.
 *
 * Implementations are expected to provide both an initialiser and finaliser.
 */

#include <sys/types.h>
#include <sys/cpuvar.h>
#include <sys/sunddi.h>
#include <sys/psm_gic.h>
#include <sys/psm_gic_types.h>
#include <sys/psm_types.h>
#include <sys/promif.h>

/*
 * Return the GIC PROM node, or OBP_NONODE if none was found.
 */
static pnode_t
find_gic(pnode_t nodeid, int depth, const char *compat)
{
	pnode_t node;
	pnode_t child;

	if (prom_is_compatible(nodeid, compat))
		return (nodeid);

	child = prom_childnode(nodeid);
	while (child > 0) {
		node = find_gic(child, depth + 1, compat);
		if (node > 0)
			return (node);
		child = prom_nextnode(child);
	}

	return (OBP_NONODE);
}

static int
fdt_gicv2_fini(psm_gic_t *pg)
{
	ASSERT(pg != NULL);

	if (pg->pg_ops.pgo_fini != NULL) {
		if (pg->pg_ops.pgo_fini(pg) != PSM_SUCCESS)
			return (PSM_FAILURE);
	}

	if (pg->pg_config != NULL) {
		kmem_free(pg->pg_config, sizeof (psm_gicv2_config_t));
		pg->pg_config = NULL;
	}

	memset(&pg->pg_ops, 0, sizeof(pg->pg_ops));
	pg->pg_init = NULL;
	pg->pg_fini = NULL;
	return (PSM_SUCCESS);
}

static int
fdt_gicv2_init(psm_gic_t *pg)
{
	pnode_t			node;
	uint64_t		gicd_base;
	uint64_t		gicd_size;
	uint64_t		gicc_base;
	uint64_t		gicc_size;
	psm_gicv2_config_t	*conf;

	extern int armbsa_gicv2_init(psm_gic_t *pg);

	ASSERT(pg != NULL);
	ASSERT(pg->pg_config == NULL);

	node = find_gic(prom_rootnode(), 0, "arm,gic-400");
	if (node == OBP_NONODE)
		node = find_gic(prom_rootnode(), 0, "arm,cortex-a15-gic");
	if (node == OBP_NONODE)
		return (PSM_FAILURE);

	if (prom_get_reg_address(node, 0, &gicd_base) != 0)
		return (PSM_FAILURE);

	if (prom_get_reg_size(node, 0, &gicd_size) != 0)
		return (PSM_FAILURE);

	if (prom_get_reg_address(node, 1, &gicc_base) != 0)
		return (PSM_FAILURE);

	if (prom_get_reg_size(node, 1, &gicc_size) != 0)
		return (PSM_FAILURE);

	conf = kmem_zalloc(sizeof (psm_gicv2_config_t), KM_SLEEP);
	conf->pgc_gicc.regspec_addr = gicc_base;
	conf->pgc_gicc.regspec_size = gicc_size;
	conf->pgc_gicd.regspec_addr = gicd_base;
	conf->pgc_gicd.regspec_size = gicd_size;
	pg->pg_config = conf;

	if (armbsa_gicv2_init(pg) != PSM_SUCCESS) {
		(void) fdt_gicv2_fini(pg);
		return (PSM_FAILURE);
	}

	ASSERT(pg->pg_ops.pgo_init != NULL);
	ASSERT(pg->pg_ops.pgo_fini != NULL);

	if (pg->pg_ops.pgo_init(pg) != PSM_SUCCESS) {
		(void) fdt_gicv2_fini(pg);
		return (PSM_FAILURE);
	}

	return (PSM_SUCCESS);
}

static int
fdt_gicv3_fini(psm_gic_t *pg)
{
	psm_gicv3_config_t *conf;

	ASSERT(pg != NULL);

	if (pg->pg_ops.pgo_fini != NULL) {
		if (pg->pg_ops.pgo_fini(pg) != PSM_SUCCESS)
			return (PSM_FAILURE);
	}

	if (pg->pg_config != NULL) {
		conf = (psm_gicv3_config_t *)pg->pg_config;
		if (conf->pgc_gicrr != NULL && conf->pgc_num_gicrr)
			kmem_free(conf->pgc_gicrr,
			    sizeof (*(conf->pgc_gicrr)) * conf->pgc_num_gicrr);
		kmem_free(pg->pg_config, sizeof (*conf));
		pg->pg_config = NULL;
	}

	memset(&pg->pg_ops, 0, sizeof(pg->pg_ops));
	pg->pg_init = NULL;
	pg->pg_fini = NULL;
	return (PSM_SUCCESS);
}

static int
fdt_gicv3_init(psm_gic_t *pg)
{
	pnode_t			node;
	uint32_t		i;
	uint64_t		gicd_base;
	uint64_t		gicd_size;
	uint64_t		gicrr_base;
	uint64_t		gicrr_size;
	struct regspec64	*gicrr;
	uint32_t		num_gicrr;
	uint64_t		gicr_stride;
	psm_gicv3_config_t	*conf;

	extern int armbsa_gicv3_init(psm_gic_t *pg);

	node = find_gic(prom_rootnode(), 0, "arm,gic-v3");
	if (node == OBP_NONODE)
		return (PSM_FAILURE);

	if (prom_get_reg_address(node, 0, &gicd_base) != 0)
		return (PSM_FAILURE);

	if (prom_get_reg_size(node, 0, &gicd_size) != 0)
		return (PSM_FAILURE);

	gicr_stride = prom_get_prop_u64(node, "redistributor-stride", 0);
	num_gicrr = prom_get_prop_u32(node, "#redistributor-regions", 1);

	gicrr = kmem_zalloc(sizeof (*gicrr) * num_gicrr, KM_SLEEP);

	for (i = 0; i < num_gicrr; ++i) {
		if (prom_get_reg_address(node, 1 + i, &gicrr_base) != 0 ||
		    prom_get_reg_size(node, 1 + i, &gicrr_size) != 0) {
			kmem_free(gicrr, sizeof (*gicrr) * num_gicrr);
			return (PSM_FAILURE);
		}

		gicrr[i].regspec_addr = gicrr_base;
		gicrr[i].regspec_size = gicrr_size;
	}

	conf = kmem_zalloc(sizeof (psm_gicv3_config_t), KM_SLEEP);
	conf->pgc_gicd.regspec_addr = gicd_base;
	conf->pgc_gicd.regspec_size = gicd_size;
	conf->pgc_gicrr = gicrr;
	conf->pgc_num_gicrr = num_gicrr;
	conf->pgc_gicr_stride = gicr_stride;
	pg->pg_config = conf;

	if (armbsa_gicv3_init(pg) != PSM_SUCCESS) {
		(void) pg->pg_fini(pg);
		return (PSM_FAILURE);
	}

	return (pg->pg_ops.pgo_init(pg));
}

/*
 * Check for a GIC module of some supported type.
 *
 * If a compatible GIC is found, set the init function in the passed psm_gic_t
 * structure and return PSM_SUCCESS.
 */
int
armbsa_fdt_gic_init(psm_gic_t *gic)
{
	if (prom_has_compatible("arm,gic-v3")) {
		gic->pg_init = fdt_gicv3_init;
		gic->pg_fini = fdt_gicv3_fini;
	} else if (prom_has_compatible("arm,gic-400") ||
	    prom_has_compatible("arm,cortex-a15-gic")) {
		gic->pg_init = fdt_gicv2_init;
		gic->pg_fini = fdt_gicv2_fini;
	} else {
		gic->pg_init = NULL;
		gic->pg_fini = NULL;
		return (PSM_FAILURE);
	}

	return (PSM_SUCCESS);
}

int
armbsa_fdt_gic_probe(void)
{
	if (prom_has_compatible("arm,gic-v3") ||
	    prom_has_compatible("arm,gic-400") ||
	    prom_has_compatible("arm,cortex-a15-gic"))
		return (PSM_SUCCESS);

	return (PSM_FAILURE);
}
