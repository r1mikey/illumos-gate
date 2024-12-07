/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Garrett D'Amore <garrett@damore.org>
 * Copyright 2014 Pluribus Networks, Inc.
 * Copyright 2016 Nexenta Systems, Inc.
 * Copyright 2018 Joyent, Inc.
 */

/*
 * aarch64-specific DDI implementation, ACPI-based machine routines.
 */
#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/avintr.h>
#include <sys/pci_impl.h>

/*
 * Platform drivers on this platform
 */
char *platform_module_list[] = {
	"acpippm",
	"ppm",
	(char *)0
};

/* pci bus resource maps */
struct pci_bus_resource *pci_bus_res;

/* XXXARM: here temporarily */
int pci_irq_nroutes = 0;

/* XXXARM: also here temporarily */
int
pci_slot_names_prop(int bus __unused, char *buf __unused, int len __unused)
{
	return (0);
}

void
impl_late_hardware_probe(void)
{
	dev_info_t *dip;

	for (dip = ddi_get_child(ddi_root_node());
	    dip != NULL;
	    dip = ddi_get_next_sibling(dip)) {
		if (strcmp(ddi_node_name(dip), "fw") == 0) {
			ndi_devi_online(dip, 0);
			break;
		}
	}
}

/*
 * Configure the hardware on the system.
 * Called before the rootfs is mounted
 */
void
configure(void)
{
	extern void i_ddi_init_root();
	extern void impl_bus_reprobe(void);

	/*
	 * Initialize devices on the machine.
	 * Uses configuration tree built by the PROMs to determine what
	 * is present, and builds a tree of prototype dev_info nodes
	 * corresponding to the hardware which identified itself.
	 */

	/*
	 * Initialize root node.
	 */
	i_ddi_init_root();

	/*
	 * XXXARM: if we're going to do GIC as a proper device, this is a good
	 * place to do it.
	 */

	/* reprogram devices not set up by firmware (BIOS) */
	impl_bus_reprobe();

#if XXXARM
	/*
	 * Setup but don't startup the IOMMU
	 * Startup happens later via a direct call
	 * to IOMMU code by boot code.
	 * At this point, all PCI bus renumbering
	 * is done, so safe to init the IMMU
	 * AKA Intel IOMMU.
	 */
	immu_init();
#endif
}

static int
get_prop_int_array(dev_info_t *di, char *pname, int **pval, uint_t *plen)
{
	int ret;

	if ((ret = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, di,
	    DDI_PROP_DONTPASS, pname, pval, plen))
	    == DDI_PROP_SUCCESS) {
		*plen = (*plen) * (sizeof (int));
	}

	return (ret);
}

/*
 * Node Configuration
 */

struct prop_ispec {
	uint_t	pri, vec;
};

/*
 * For the x86, we're prepared to claim that the interrupt string
 * is in the form of a list of <ipl,vec> specifications.
 */

#define	VEC_MIN	1
#define	VEC_MAX	255

static int
impl_xlate_intrs(dev_info_t *child, int *in,
    struct ddi_parent_private_data *pdptr)
{
	size_t size;
	int n;
	struct intrspec *new;
	int *oinpri;
	int *inpri;
	uint_t got_len;

	/*
	 * We only supoprt the new-style "interrupts" property, which just
	 * contains the IRQ.
	 *
	 * If there's no matching "interrupt-priorities" property, we assign
	 * IPL 5.
	 */

	oinpri = inpri = NULL;

	/*
	 * XXXARM: What on earth is this about?
	 */
	if ((n = (*in++)) < 1) {
		return (DDI_FAILURE);
	}

	pdptr->par_nintr = n;
	size = n * sizeof (struct intrspec);
	new = pdptr->par_intr = kmem_zalloc(size, KM_SLEEP);

	/* XXX check for "interrupt-priorities" property... */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, child,
	    DDI_PROP_DONTPASS, "interrupt-priorities",
	    &oinpri, &got_len) == DDI_PROP_SUCCESS) {
		if (n != got_len) {
			cmn_err(CE_CONT,
			    "bad interrupt-priorities length"
			    " from %s%d: expected %d, got %d\n",
			    DEVI(child)->devi_name,
			    DEVI(child)->devi_instance, n, got_len);
			goto broken;
		}
	}

	inpri = oinpri;

	while (n--) {
		int level;
		int vec = *in++;

		if (inpri == NULL)
			level = 5;
		else
			level = *inpri++;

		if (level < 1 || level > MAXIPL ||
		    vec < VEC_MIN || vec > VEC_MAX) {
			cmn_err(CE_CONT, "bad interrupt spec from %s%d - "
			    "ipl %d, irq %d\n",
			    DEVI(child)->devi_name,
			    DEVI(child)->devi_instance, level, vec);
			goto broken;
		}

		new->intrspec_pri = level;
		new->intrspec_vec = vec;
		new++;
	}

	if (oinpri != NULL)
		ddi_prop_free(oinpri);

	return (DDI_SUCCESS);

broken:
	kmem_free(pdptr->par_intr, size);
	pdptr->par_intr = NULL;
	pdptr->par_nintr = 0;
	if (inpri != NULL)
		ddi_prop_free(inpri);

	return (DDI_FAILURE);
}

/*
 * Create a ddi_parent_private_data structure from the ddi properties of
 * the dev_info node.
 *
 * The "reg" and either an "intr" or "interrupts" properties are required
 * if the driver wishes to create mappings or field interrupts on behalf
 * of the device.
 *
 * The "reg" property is assumed to be a list of at least one triple
 *
 *	<bustype, address, size>*1
 *
 * The "intr" property is assumed to be a list of at least one duple
 *
 *	<SPARC ipl, vector#>*1
 *
 * The "interrupts" property is assumed to be a list of at least one
 * n-tuples that describes the interrupt capabilities of the bus the device
 * is connected to.  For SBus, this looks like
 *
 *	<SBus-level>*1
 *
 * (This property obsoletes the 'intr' property).
 *
 * The "ranges" property is optional.
 */
void
make_ddi_ppd(dev_info_t *child, struct ddi_parent_private_data **ppd)
{
	struct ddi_parent_private_data *pdptr;
	int n;
	int *reg_prop, *rng_prop, *intr_prop, *irupts_prop;
	uint_t reg_len, rng_len, irupts_len;

	*ppd = pdptr = kmem_zalloc(sizeof (*pdptr), KM_SLEEP);

	/*
	 * Handle the 'reg' property.
	 */
	if ((get_prop_int_array(child, "reg", &reg_prop, &reg_len) ==
	    DDI_PROP_SUCCESS) && (reg_len != 0)) {
		pdptr->par_nreg = reg_len / (int)sizeof (struct regspec);
		pdptr->par_reg = (struct regspec *)reg_prop;
	}

	/*
	 * See if I have a range (adding one where needed - this
	 * means to add one for sbus node in sun4c, when romvec > 0,
	 * if no range is already defined in the PROM node.
	 * (Currently no sun4c PROMS define range properties,
	 * but they should and may in the future.)  For the SBus
	 * node, the range is defined by the SBus reg property.
	 */
	if (get_prop_int_array(child, "ranges", &rng_prop, &rng_len)
	    == DDI_PROP_SUCCESS) {
		pdptr->par_nrng = rng_len / (int)(sizeof (struct rangespec));
		pdptr->par_rng = (struct rangespec *)rng_prop;
	}

	/*
	 * Handle the 'interrupts' property
	 */

	if (get_prop_int_array(child, "interrupts", &irupts_prop,
	    &irupts_len) != DDI_PROP_SUCCESS) {
		irupts_len = 0;
	}

	if ((n = irupts_len) != 0) {
		size_t size;
		int *out;

		/*
		 * Translate the 'interrupts' property into an array
		 * of intrspecs for the rest of the DDI framework to
		 * toy with.  Only our ancestors really know how to
		 * do this, so ask 'em.  We massage the 'interrupts'
		 * property so that it is pre-pended by a count of
		 * the number of integers in the argument.
		 */
		size = sizeof (int) + n;
		out = kmem_alloc(size, KM_SLEEP);
		*out = n / sizeof (int);
		bcopy(irupts_prop, out + 1, (size_t)n);
		ddi_prop_free((void *)irupts_prop);
		if (impl_xlate_intrs(child, out, pdptr) != DDI_SUCCESS) {
			cmn_err(CE_CONT,
			    "Unable to translate 'interrupts' for %s%d\n",
			    DEVI(child)->devi_binding_name,
			    DEVI(child)->devi_instance);
		}
		kmem_free(out, size);
	}
}

/*
 * Name a child
 */
int
impl_sunbus_name_child(dev_info_t *child, char *name, int namelen)
{
	/*
	 * Fill in parent-private data and this function returns to us
	 * an indication if it used "registers" to fill in the data.
	 */
	if (ddi_get_parent_data(child) == NULL) {
		struct ddi_parent_private_data *pdptr;
		make_ddi_ppd(child, &pdptr);
		ddi_set_parent_data(child, pdptr);
	}

	name[0] = '\0';
	if (sparc_pd_getnreg(child) > 0) {
		(void) snprintf(name, namelen, "%x,%x",
		    (uint_t)sparc_pd_getreg(child, 0)->regspec_bustype,
		    (uint_t)sparc_pd_getreg(child, 0)->regspec_addr);
	}

	return (DDI_SUCCESS);
}

/*
 * DDI Interrupt
 */

int
i_ddi_get_intx_nintrs(dev_info_t *dip)
{
	struct ddi_parent_private_data *pdp;

	if ((pdp = ddi_get_parent_data(dip)) == NULL)
		return (0);

	return (pdp->par_nintr);
}

int
i_ddi_convert_dma_attr(
    ddi_dma_attr_t *dst, dev_info_t *dip, const ddi_dma_attr_t *src)
{
	bcopy(src, dst, sizeof (*dst));
	return (DDI_SUCCESS);
}

int
i_ddi_update_dma_attr(dev_info_t *dip, ddi_dma_attr_t *attr)
{
	return (DDI_SUCCESS);
}

/*
 * XXXPCI: hackery
 */
uint32_t
i_ddi_get_inum(dev_info_t *dip, uint_t inumber)
{
	struct ddi_parent_private_data	*pdp;

	if ((pdp = ddi_get_parent_data(dip)) == NULL) {
		dev_err(dip, CE_PANIC, "missing parent private data");
		return (0);	/* Unreachable */
	}

	ASSERT(inumber < pdp->par_nintr);
	return (pdp->par_intr[inumber].intrspec_vec);
}

uint32_t
i_ddi_get_intr_pri(dev_info_t *dip, uint_t inumber)
{
	struct ddi_parent_private_data	*pdp;

	if ((pdp = ddi_get_parent_data(dip)) == NULL) {
		dev_err(dip, CE_PANIC, "missing parent private data");
		return (0);	/* Unreachable */
	}

	ASSERT(inumber < pdp->par_nintr);
	return (pdp->par_intr[inumber].intrspec_pri);
}

/*
 * BODGE: rootnex fills these in. We can't do it here, because it relies on
 * acpica.
 */
int (*i_ddi_priv_map_interrupt)(dev_info_t *dip,
    ddi_intr_handle_impl_t *hdlp) = NULL;

dev_info_t *
map_interrupt(dev_info_t *dip, ddi_intr_handle_impl_t *hdlp)
{
	VERIFY3P(i_ddi_priv_map_interrupt, !=, NULL);

	if (i_ddi_priv_map_interrupt(dip, hdlp) != DDI_SUCCESS)
		return (NULL);

	return (dip);	/* nobody looks at this, other than a NULL-check */
}
