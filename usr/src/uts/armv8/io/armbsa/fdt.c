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
 * Legacy FDT-base firmware interfaces
 */

#include <sys/psm_gic.h>
#include <sys/psm_gic_types.h>
#include <sys/psm_types.h>

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
		node = find_gic(child, depth + 1);
		if (node > 0)
			return (node);
		child = prom_nextnode(child);
	}

	return (OBP_NONODE);
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
		(void) pg->pg_fini(pg);
		return (PSM_FAILURE);
	}

	/* consumes config, populates data */
	/* hereafter we only pass the data pointer */
	return (pg->pg_ops.pgo_init(pg));
}

static int
fdt_gicv2_fini(psm_gic_t *pg)
{
	/* call the GIC fini function */
	kmem_free(pg->pg_config, sizeof (psm_gicv2_config_t));
	return (PSM_SUCCESS);
}

static int
fdt_gicv3_init(psm_gic_t *pg)
{
	return (PSM_FAILURE);
}

static int
fdt_gicv3_fini(psm_gic_t *pg)
{
	return (PSM_FAILURE);
}


/*
 * Check for a GIC module of some supported type.
 *
 * If a compatible GIC is found, set the init function in the passed psm_gic_t
 * structure and return PSM_SUCCESS.
 */
int
armbsa_fdt_gic_probe(psm_gic_t *gic)
{
	if (prom_has_compatible("arm,gic-v3")) {
		gic.pg_init = fdt_gicv3_init;
		gic.pg_fini = fdt_gicv3_fini;
	} else if (prom_has_compatible("arm,gic-400") ||
	    prom_has_compatible("arm,cortex-a15-gic")) {
		gic.pg_init = fdt_gicv2_init;
		gic.pg_fini = fdt_gicv2_fini;
	} else {
		gic.pg_init = NULL;
		return (PSM_FAILURE);
	}

	return (PSM_SUCCESS);
}
