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
 * Locate a GIC root interrupt controller, then attach that controller
 * and any known child nodes.
 *
 * Supports orderly system startup by attaching the system interrupt
 * controller as early as reasonably possible.
 */

#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ddi_subrdefs.h>
#include <sys/ddi_impldefs.h>
#include <sys/ndi_impldefs.h>
#include <sys/ddi_implfuncs.h>
#include <sys/ddi_arch_intr.h>
#include <sys/modctl.h>
#include <sys/obpdefs.h>

typedef struct {
	dev_info_t	*gsr_dip;
	uint32_t	gsr_roots;
} gic_search_result_t;

static const char *compatible_gics[] = {
	"arm,gic-v3",
	"arm,gic-400",
	"arm,cortex-a15-gic"
};
static const uint_t num_compatible_gics =
    sizeof (compatible_gics) / sizeof (compatible_gics[0]);

static const char *compatible_children[] = {
	"arm,gic-v3-its",
	"arm,gic-v2m-frame",
};
static const uint_t num_compatible_children =
    sizeof (compatible_children) / sizeof (compatible_children[0]);

static void gic_probe(int);

static struct modlmisc modlmisc = {
	.misc_modops	= &mod_miscops,
	.misc_linkinfo	= "GIC Instantiation Helper"
};

static struct modlinkage modlinkage = {
	.ml_rev		= MODREV_1,
	.ml_linkage	= { &modlmisc, NULL }
};

int
_init(void)
{
	int err;

	if ((err = mod_install(&modlinkage)) != 0)
		return (err);

	impl_bus_add_probe(gic_probe);
	return (err);
}

int
_fini(void)
{
	int err;

	impl_bus_delete_probe(gic_probe);
	if ((err = mod_remove(&modlinkage)) != 0)
		return (err);

	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static boolean_t
gic_test_compatible(dev_info_t *dip, const char **compats, uint_t ncompats)
{
	char	**data;
	uint_t	nelements;
	uint_t	n;
	uint_t	i;

	if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    OBP_COMPATIBLE, &data, &nelements) != DDI_PROP_SUCCESS)
		return (B_FALSE);

	for (n = 0; n < nelements; ++n) {
		for (i = 0; i < ncompats; ++i) {
			if (strcmp(data[n], compats[i]) == 0) {
				ddi_prop_free(data);
				return (B_TRUE);
			}
		}
	}

	ddi_prop_free(data);
	return (B_FALSE);
}

static int
gic_online(dev_info_t *dip)
{
	dev_info_t	*pdip;
	int		rv;

	if (i_ddi_devi_attached(dip))
		return (DDI_SUCCESS);

	pdip = ddi_get_parent(dip);
	if (pdip == ddi_root_node() && !i_ddi_devi_attached(pdip))
		return (DDI_FAILURE);
	ASSERT3P(pdip, !=, NULL);

	if (gic_online(pdip) != DDI_SUCCESS)
		return (DDI_FAILURE);

	ndi_devi_enter(pdip);
	rv = i_ndi_config_node(dip, DS_READY, 0);
	ndi_devi_exit(pdip);
	return (rv);
}

static int
gic_searcher(dev_info_t *rdip, void *arg)
{
	gic_search_result_t	*gsr = arg;

	ASSERT3P(rdip, !=, NULL);
	ASSERT3P(gsr, !=, NULL);

	/*
	 * Filter out nodes that are not root interrupt controllers, which
	 * is defined as an interrupt controller without an interrupt parent.
	 */
	if (ddi_prop_exists(DDI_DEV_T_ANY, rdip,
	    DDI_PROP_DONTPASS, "interrupt-controller") == 0)
		return (DDI_WALK_CONTINUE);

	if (ddi_prop_exists(DDI_DEV_T_ANY, rdip,
	    DDI_PROP_DONTPASS, "interrupt-parent") == 1)
		return (DDI_WALK_CONTINUE);

	/*
	 * Track the number of discovered interrupt roots.
	 */
	gsr->gsr_roots++;

	/*
	 * We have what claims to be a root interrupt controller.
	 *
	 * If it's a compatible GIC and we have not yet recorded a compatible
	 * GIC, then record it.
	 */
	if (gic_test_compatible(rdip, compatible_gics, num_compatible_gics))
		if (gsr->gsr_dip == NULL)
			gsr->gsr_dip = rdip;

	return (DDI_WALK_CONTINUE);
}

static void
gic_probe(int reprogram)
{
	dev_info_t		*cdip;
	gic_search_result_t	search_results = {
		.gsr_dip	= NULL,
		.gsr_roots	= 0
	};

	if (reprogram == 0)
		return;

	/*
	 * Find a compatible GIC which is the root interrupt controller.
	 *
	 * We prefer a root interrupt controller that is referenced from
	 * the device tree root via an interrupt-parent property. Failing
	 * that, we trawl around in the device tree for a compatible GIC.
	 */
	if ((cdip = i_ddi_interrupt_parent(ddi_root_node())) != NULL) {
		if (gic_test_compatible(cdip,
		    compatible_gics, num_compatible_gics) == B_TRUE) {
			search_results.gsr_roots = 1;
			search_results.gsr_dip = cdip;
		}
	} else {
		ndi_devi_enter(ddi_root_node());
		ddi_walk_devs(ddi_get_child(ddi_root_node()),
		    gic_searcher, &search_results);
		ndi_devi_exit(ddi_root_node());

		ASSERT3U(search_results.gsr_roots, >=, 1);
		if (search_results.gsr_roots == 0)
			cmn_err(CE_PANIC, "gic_probe: failed to find any root "
			    "interrupt controllers");
	}

	/*
	 * Check that the discovered root controller is compatible.
	 */
	ASSERT3P(search_results.gsr_dip, !=, NULL);
	if (search_results.gsr_dip == NULL)
		cmn_err(CE_PANIC, "gic_probe: could not find a compatible "
		    "root interrupt controller");

	/*
	 * OK, we have a compatible root controller, attach it so that the
	 * rest of the tree can register interrupts.
	 */
	if (gic_online(search_results.gsr_dip) != DDI_SUCCESS)
		cmn_err(CE_PANIC, "Unable to attach GIC %s",
		    ddi_node_name(search_results.gsr_dip));

	/*
	 * Iterate through the root GIC child nodes and ensure that each
	 * known child node has come online. This enables, for example,
	 * MSI/MSI-X functionality.
	 */
	for (cdip = ddi_get_child(search_results.gsr_dip);
	    cdip != NULL;
	    cdip = ddi_get_next_sibling(cdip)) {
		if (gic_test_compatible(cdip, compatible_children,
		    num_compatible_children) == B_FALSE)
			continue;
		if (gic_online(cdip) != DDI_SUCCESS)
			cmn_err(CE_PANIC, "Unable to online root interrupt "
			    "controller child node %s", ddi_node_name(cdip));
	}
}
