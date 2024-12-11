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
 * PSM-compatible wrapper for implementing PSM interrupt operations.
 */

#include <sys/types.h>
#include <sys/debug.h>
#include <sys/processor.h>
#include <sys/cpuvar.h>
#include <sys/dditypes.h>
#include <sys/ddi_intr.h>
#include <sys/ddi_intr_impl.h>
#include <sys/sunddi.h>
#include <sys/mach_intr.h>
#include <sys/psm_types.h>

typedef struct {
	uint32_t	airq_share;
} mach_irq_t;

typedef struct {
	uint32_t	agi_whatever;
} mach_get_intr_t;

typedef struct {
	char		*avgi_type;	/*  platform type - from kernel */
	uint32_t	avgi_num_intr;	/*  max intr number - from kernel */
	uint32_t	avgi_num_cpu;	/*  max cpu number - from kernel */
} apic_get_type_t;

typedef struct {
	uint16_t	avgi_req_flags;	/* request flags - to kernel */
	uint8_t		avgi_num_devs;	/* # devs on this ino - from kernel */
	uint8_t		avgi_vector;	/* vector (too small) */
	uint32_t	avgi_cpu_id;	/* cpu of interrupt - from kernel */
	dev_info_t	**avgi_dip_list;/* kmem_alloc'ed list of dev_infos. */
					/* Contains num_devs elements. */
} apic_get_intr_t;

#define	APIC_MAX_VECTOR	256		/* for now, must get this from GIC */

/*
 * Allocate `count' MSI vector(s) for the given `dip', `pri' and `type'.
 */
static int
mach_intc_alloc_msi_vectors(dev_info_t *dip, int inum, int count, int pri,
    int behavior)
{
        return (0);
}

/*
 * Allocate `count' MSI-X vector(s) for the given `dip', `pri' and `type'.
 */
static int
mach_intc_alloc_msix_vectors(dev_info_t *dip, int inum, int count, int pri,
    int behavior)
{
        return (0);
}

static void
mach_intc_free_vectors(dev_info_t *dip, int inum, int count, int pri, int type)
{
        /* implement me */
}

static int
mach_intc_navail_vector(dev_info_t *dip, int pri)
{
        return (0);
}

/*
 * This gets very, very complicated and needs acpica and PCI, so it needs to
 * be a module.
 */
static int
mach_intc_introp_xlate(dev_info_t *dip, struct intrspec *ispec, int type)
{
        return (-1);
}

static mach_irq_t *
mach_intc_find_irq(dev_info_t *dip, struct intrspec *ispec, int type)
{
	return (NULL);
}

static int
mach_intc_get_pending(mach_irq_t *irqp, int type)
{
	return (0);
}

static void
mach_intc_clear_mask(mach_irq_t *irqp)
{
	//
}

static void
mach_intc_set_mask(mach_irq_t *irqp)
{
	//
}

/*
 * XXXARM: this is iffy
 */
static int
mach_intc_get_cap(ddi_intr_handle_impl_t *hdlp)
{
	int cap;

	cap = DDI_INTR_FLAG_PENDING;
	if (hdlp->ih_type == DDI_INTR_TYPE_FIXED)
		cap |= DDI_INTR_FLAG_MASKABLE;

	return (cap);
}

static boolean_t
mach_intc_cpu_in_range(int cpu)
{
	return (B_FALSE);
}

static int
mach_intc_set_cpu(int irqno, int cpu, int *result)
{
	return (PSM_FAILURE);
}

static int
mach_intc_grp_set_cpu(int irqno, int new_cpu, int *result)
{
	return (PSM_FAILURE);
}

static int
mach_intc_get_vector_intr_info(int vecirq, apic_get_intr_t *intr_params_p)
{
	return (PSM_FAILURE);
}

/* XXXARM: get this from the system GIC */
static char *
mach_intc_get_intc_type(void)
{
	static char _type[] = "gic";
	return (_type);
}

/* XXXARM: get this from the system GIC */
static uint16_t
mach_intc_get_intc_version()
{
	return (0x42);
}

int
mach_intc_intr_ops(dev_info_t *dip, ddi_intr_handle_impl_t *hdlp,
    psm_intr_op_t intr_op, int *result)
{
	int ret;
	mach_irq_t *irqp;
	struct intrspec *ispec;
	int new_cpu;
	apic_get_type_t *avgi;

	ret = PSM_FAILURE;
	switch (intr_op) {
	/* 0.  Allocate vectors */
	case PSM_INTR_OP_ALLOC_VECTORS:
		VERIFY(DDI_INTR_IS_MSI_OR_MSIX(hdlp->ih_type));
		if (hdlp->ih_type == DDI_INTR_TYPE_MSI) {
			*result = mach_intc_alloc_msi_vectors(dip,
			    hdlp->ih_inum, hdlp->ih_scratch1, hdlp->ih_pri,
			    (int)(uintptr_t)hdlp->ih_scratch2);
                        ret = PSM_SUCCESS;
		} else {
			*result = mach_intc_alloc_msix_vectors(dip,
			    hdlp->ih_inum, hdlp->ih_scratch1, hdlp->ih_pri,
			    (int)(uintptr_t)hdlp->ih_scratch2);
                        ret = PSM_SUCCESS;
		}

		break;
	/* 1.  Free vectors */
	case PSM_INTR_OP_FREE_VECTORS:
		VERIFY(DDI_INTR_IS_MSI_OR_MSIX(hdlp->ih_type));
		mach_intc_free_vectors(dip, hdlp->ih_inum, hdlp->ih_scratch1,
		    hdlp->ih_pri, hdlp->ih_type);
		ret = PSM_SUCCESS;
		break;
	/* 2.  Get # of available vectors */
	case PSM_INTR_OP_NAVAIL_VECTORS:
		/* XXXARM: nobody calls this */
		*result = mach_intc_navail_vector(dip, hdlp->ih_pri);
		ret = PSM_SUCCESS;
		break;
	/* 3.  Translate vector */
	case PSM_INTR_OP_XLATE_VECTOR:
		ispec = ((ihdl_plat_t *)hdlp->ih_private)->ip_ispecp;
		*result = mach_intc_introp_xlate(dip, ispec, hdlp->ih_type);
		if (*result == -1)
			return (PSM_FAILURE);
		break;
	/* 4.  Get pending information */
	case PSM_INTR_OP_GET_PENDING:
		if ((irqp = mach_intc_find_irq(
		    dip, ispec, hdlp->ih_type)) == NULL)
			return (PSM_FAILURE);
		*result = mach_intc_get_pending(irqp, hdlp->ih_type);
		break;
	/* 5.  Clear interrupt mask */
	case PSM_INTR_OP_CLEAR_MASK:
		if (hdlp->ih_type != DDI_INTR_TYPE_FIXED)
			return (PSM_FAILURE);
		if ((irqp = mach_intc_find_irq(
		    dip, ispec, hdlp->ih_type)) == NULL)
			return (PSM_FAILURE);
		mach_intc_clear_mask(irqp);
		break;
	/* 6.  Set interrupt mask */
	case PSM_INTR_OP_SET_MASK:
		if (hdlp->ih_type != DDI_INTR_TYPE_FIXED)
			return (PSM_FAILURE);
		if ((irqp = mach_intc_find_irq(
		    dip, ispec, hdlp->ih_type)) == NULL)
			return (PSM_FAILURE);
		mach_intc_set_mask(irqp);
		break;
	/* 7.  Get devices's capabilities */
	case PSM_INTR_OP_GET_CAP:
		*result = mach_intc_get_cap(hdlp);
		if (*result == -1)
			return (PSM_FAILURE);
		break;
	/* 8.  Set devices's capabilities */
	case PSM_INTR_OP_SET_CAP:
		break;	/* unsupported */
	/* 9.  Set the interrupt priority */
	case PSM_INTR_OP_SET_PRI:
		/* XXXARM: this works strangely */
		break;
	/* 10. Get the shared interrupt info */
	case PSM_INTR_OP_GET_SHARED:
		if (hdlp->ih_type != DDI_INTR_TYPE_FIXED)
			return (PSM_FAILURE);
		ispec = ((ihdl_plat_t *)hdlp->ih_private)->ip_ispecp;
		if ((irqp = mach_intc_find_irq(
		    dip, ispec, hdlp->ih_type)) == NULL)
			return (PSM_FAILURE);
		*result = (irqp->airq_share > 1) ? 1: 0;
		break;
	/* 11. Check if device supports MSI */
	case PSM_INTR_OP_CHECK_MSI:
		/* XXXARM: ask the hardware! */
		*result =
		    hdlp->ih_type & ~(DDI_INTR_TYPE_MSI | DDI_INTR_TYPE_MSIX);
		break;
	/* 12. Set vector's CPU */
	case PSM_INTR_OP_SET_CPU:
		/*
		 * The interrupt handle given here has been allocated
		 * specifically for this command, and ih_private carries
		 * a CPU value.
		 */
		new_cpu = (int)(intptr_t)hdlp->ih_private;
		if (!mach_intc_cpu_in_range(new_cpu)) {
			DDI_INTR_IMPLDBG((CE_CONT,
			    "set_cpu: cpu out of range: %d\n", new_cpu));
			*result = EINVAL;
			return (PSM_FAILURE);
		}
		if (hdlp->ih_vector > APIC_MAX_VECTOR) {
			DDI_INTR_IMPLDBG((CE_CONT,
			    "set_cpu: vector out of range: %d\n",
			    hdlp->ih_vector));
			*result = EINVAL;
			return (PSM_FAILURE);
		}
#if XXXARM
		if ((hdlp->ih_flags & PSMGI_INTRBY_FLAGS) == PSMGI_INTRBY_VEC)
			hdlp->ih_vector = apic_vector_to_irq[hdlp->ih_vector];
#endif
		if (mach_intc_set_cpu(hdlp->ih_vector, new_cpu, result) !=
		    PSM_SUCCESS)
			return (PSM_FAILURE);
		break;
	/* 13. Get vector's info */
	case PSM_INTR_OP_GET_INTR:
		/*
		 * The interrupt handle given here has been allocated
		 * specifically for this command, and ih_private carries
		 * a pointer to a apic_get_intr_t (mach_get_intr_t).
		 */
		if (mach_intc_get_vector_intr_info(
		    hdlp->ih_vector, hdlp->ih_private) != PSM_SUCCESS)
			return (PSM_FAILURE);
		break;
	/* 14. Set all device's vectors' CPU */
	case PSM_INTR_OP_GRP_SET_CPU:
		/*
		 * The interrupt handle given here has been allocated
		 * specifically for this command, and ih_private carries
		 * a CPU value.
		 */
		new_cpu = (int)(intptr_t)hdlp->ih_private;
		if (!mach_intc_cpu_in_range(new_cpu)) {
			DDI_INTR_IMPLDBG((CE_CONT,
			    "set_cpu: cpu out of range: %d\n", new_cpu));
			*result = EINVAL;
			return (PSM_FAILURE);
		}
		if (hdlp->ih_vector > APIC_MAX_VECTOR) {
			DDI_INTR_IMPLDBG((CE_CONT,
			    "set_cpu: vector out of range: %d\n",
			    hdlp->ih_vector));
			*result = EINVAL;
			return (PSM_FAILURE);
		}
#if XXXARM
		if ((hdlp->ih_flags & PSMGI_INTRBY_FLAGS) == PSMGI_INTRBY_VEC)
			hdlp->ih_vector = apic_vector_to_irq[hdlp->ih_vector];
#endif
		if (mach_intc_grp_set_cpu(hdlp->ih_vector, new_cpu, result) !=
		    PSM_SUCCESS)
			return (PSM_FAILURE);
		break;
	/* 15. Returns APIC type */
	case PSM_INTR_OP_APIC_TYPE:
		if ((avgi = (apic_get_type_t *)(hdlp->ih_private)) == NULL)
			return (PSM_FAILURE);
		avgi->avgi_type = mach_intc_get_intc_type();
		avgi->avgi_num_intr = APIC_MAX_VECTOR;
		avgi->avgi_num_cpu = boot_ncpus;
		hdlp->ih_ver = mach_intc_get_intc_version();
		break;
	default:
		break;
	}

	return (ret);
}
