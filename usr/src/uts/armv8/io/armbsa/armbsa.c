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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 * Copyright 2018 Joyent, Inc.
 * Copyright 2024 Michael van der Westhuizen
 */

/*
 * Processor-specific module for Arm Base System Architecture systems.
 *
 * Supports SBBR, ESBBR and EBBR firmware specifications.
 */

#define	PSMI_1_0

#include <sys/types.h>
#include <sys/processor.h>
#include <sys/dditypes.h>
#include <sys/ddi_intr.h>
#include <sys/ddi_intr_impl.h>
#include <sys/psm_types.h>
#include <sys/psm.h>

static int armbsa_probe(void);
static void armbsa_init(void);

static void armbsa_picinit(void);
static int armbsa_intr_enter(int ipl, int *vectorp);
static void armbsa_intr_exit(int ipl, int irqno);
static void armbsa_setspl(int ipl);
static int armbsa_addspl(int irqno, int ipl, int min_ipl, int max_ipl);
static int armbsa_delspl(int irqno, int ipl, int min_ipl, int max_ipl);
static int armbsa_disable_intr(processorid_t cpun);
static void armbsa_enable_intr(processorid_t cpun);
static int armbsa_softlvl_to_irq(int ipl);
static void armbsa_set_softintr(int ipl);

static void armbsa_set_idlecpu(processorid_t cpun);
static void armbsa_unset_idlecpu(processorid_t cpun);

static int armbsa_clkinit(int hertz);  /* >= PSMI_1_3 */
static int armbsa_get_clkirq(int ipl);
static void armbsa_hrtimeinit(void);
static hrtime_t armbsa_gethrtime(void);

static processorid_t armbsa_get_next_processorid(processorid_t cpu_id);
static int armbsa_cpu_start(processorid_t cpun, caddr_t ctxt);
static int armbsa_post_cpu_start(void);
static void armbsa_shutdown(int cmd, int fcn);

/* umm... */
static int armbsa_get_ipivect(int ipl, int type);
static void armbsa_send_ipi(processorid_t cpun, int ipl);

static int armbsa_translate_irq(dev_info_t *dip, int irqno);

static void armbsa_notify_error(int level, char *errmsg);
static void armbsa_notify_func(int msg);

static void armbsa_timer_reprogram(hrtime_t time);
static void armbsa_timer_enable(void);
static void armbsa_timer_disable(void);
static void armbsa_post_cyclic_setup(void *arg);

static void armbsa_preshutdown(int cmd, int fcn);

static int armbsa_intr_ops(dev_info_t *dip, ddi_intr_handle_impl_t *handle, psm_intr_op_t op, int *result);

static int armbsa_state(psm_state_request_t *request);

static int armbsa_cpu_ops(psm_cpu_request_t *reqp);

static struct psm_ops armbsa_ops = {
	armbsa_probe,

	armbsa_init,
	armbsa_picinit,
	armbsa_intr_enter,
	armbsa_intr_exit,
	armbsa_setspl,
	armbsa_addspl,
	armbsa_delspl,
	armbsa_disable_intr,
	armbsa_enable_intr,
	armbsa_softlvl_to_irq,	/* psm_softlvl_to_irq */
	armbsa_set_softintr,	/* psm_set_softintr */

	armbsa_set_idlecpu,
	armbsa_unset_idlecpu,

	armbsa_clkinit,
	armbsa_get_clkirq,
	armbsa_hrtimeinit,	/* psm_hrtimeinit */
	armbsa_gethrtime,

	armbsa_get_next_processorid,
	armbsa_cpu_start,
	armbsa_post_cpu_start,
	armbsa_shutdown,
	armbsa_get_ipivect,
	armbsa_send_ipi,

	armbsa_translate_irq,	/* psm_translate_irq */
	armbsa_notify_error,	/* psm_notify_error */
	armbsa_notify_func,	/* psm_notify_func */
	armbsa_timer_reprogram,
	armbsa_timer_enable,
	armbsa_timer_disable,
	armbsa_post_cyclic_setup,
	armbsa_preshutdown,
	armbsa_intr_ops,		/* Advanced DDI Interrupt framework */
	armbsa_state,		/* save, restore apic state for S3 */
	armbsa_cpu_ops,		/* CPU control interface. */
};

/* XXXARM: ytho */
/* struct psm_ops *psmops = &armbsa_ops; */

static struct psm_info armbsa_psm_info = {
	PSM_INFO_VER01_0,			/* version */
	PSM_OWN_EXCLUSIVE,			/* ownership */
	&armbsa_ops,				/* operation */
	"armbsa",				/* machine name */
	"Arm Base System Architecture",		/* machine descriptions */
};

static void *armbsa_hdlp;

static uint32_t armbsa_gic_version;		/* XXXARM: use an enum */
static uint32_t armbsa_firmware_interface;	/* XXXARM: use an enum */

/*
 * Loadable module wrapper
 */

int
_init(void)
{
	return (psm_mod_init(&armbsa_hdlp, &armbsa_psm_info));
}

int
_fini(void)
{
	return (psm_mod_fini(&armbsa_hdlp, &armbsa_psm_info));
}

int
_info(struct modinfo *modinfop)
{
	return (psm_mod_info(&armbsa_hdlp, &armbsa_psm_info, modinfop));
}

/*
 * Processor-specific Module Functions
 */

static int
armbsa_probe(void)
{
	/*
	 * The x86_64 code does an awful lot of changing state in probe.
	 *
	 * We might need to do something similar - to verify that we support
	 * the GIC etc. - also the firmware abstraction and (possibly) UEFI.
	 */
	return (PSM_SUCCESS);
}

static void
armbsa_init(void)
{

}

/*
 * Interrupt Handling
 */

static void
armbsa_picinit(void)
{
	/* XXXARM: we could do better here - function pointers (yay?) */
	/* XXXARM: use an enum */
	if (armbsa_gic_version == 2) {
		if (armbsa_firmware_interface == 1) {
			/* gicv2 via fdt */
		} else if (armbsa_firmware_interface == 2) {
			/* gicv2 via ACPI */
		} else {
		}
	} else if (armbsa_gic_version == 3) {
		if (armbsa_firmware_interface == 1) {
			/* gicv3 via fdt */
		} else if (armbsa_firmware_interface == 2) {
			/* gicv3 via ACPI */
		} else {
		}
	}

	/* call the init function, pass it the psm_gic_ops pointer to fill */
	/* actually do the initialisation */
}

static int
armbsa_intr_enter(int ipl, int *vectorp)
{
	return (-1);
}

static void
armbsa_intr_exit(int ipl, int irqno)
{

}

static void
armbsa_setspl(int ipl)
{

}

static int
armbsa_addspl(int irqno, int ipl, int min_ipl, int max_ipl)
{
	return (-1);
}

static int
armbsa_delspl(int irqno, int ipl, int min_ipl, int max_ipl)
{
	return (-1);
}

static int
armbsa_disable_intr(processorid_t cpun)
{
	return (-1);
}

static void
armbsa_enable_intr(processorid_t cpun)
{

}

static int
armbsa_softlvl_to_irq(int ipl)
{
	return (-1);
}

static void
armbsa_set_softintr(int ipl)
{

}

/*
 * Clocks and timers
 */

static int
armbsa_clkinit(int hertz)
{
	return (-1);
}

static int
armbsa_get_clkirq(int ipl)
{
	return (-1);
}

static void
armbsa_hrtimeinit(void)
{

}

static hrtime_t
armbsa_gethrtime(void)
{
	return ((hrtime_t)-1);
}

/*
 * CPU management
 */

static void
armbsa_set_idlecpu(processorid_t cpun)
{

}

static void
armbsa_unset_idlecpu(processorid_t cpun)
{

}

static processorid_t
armbsa_get_next_processorid(processorid_t cpu_id)
{
	return ((processorid_t)-1);
}

static int
armbsa_cpu_start(processorid_t cpun, caddr_t ctxt)
{
	return (-1);
}

static int
armbsa_post_cpu_start(void)
{
	return (-1);
}

static void
armbsa_shutdown(int cmd, int fcn)
{

}

static int
armbsa_get_ipivect(int ipl, int type)
{
	return (-1);
}

static void
armbsa_send_ipi(processorid_t cpun, int ipl)
{

}

/*
 * I *think* we can just return irqno here, since we're not remapping
 */
static int
armbsa_translate_irq(dev_info_t *dip __unused, int irqno)
{
	return (irqno);
}

static void
armbsa_notify_error(int level, char *errmsg)
{

}

static void
armbsa_notify_func(int msg)
{

}

/*
 * Timer functions - are we going to use these?
 */

static void
armbsa_timer_reprogram(hrtime_t time)
{

}

static void
armbsa_timer_enable(void)
{

}

static void
armbsa_timer_disable(void)
{

}

/*
 * I assume this is for IRQ balancing?
 */
static void
armbsa_post_cyclic_setup(void *arg)
{

}

static void
armbsa_preshutdown(int cmd, int fcn)
{

}

/*
 * Interrupt Operations Helpers
 */

/*
 * DDI_INTR_TYPE_FIXED case we should not be called
 * DDI_INTR_TYPE_MSI case: allocate the LPIs/MBIs
 * DDI_INTR_TYPE_MSIX case: allocate the LPIs/MBIs
 * 
 * Also has some utility in CPU binding, but I think we can just do that in the GIC itself.
 */
static int
armbsa_intr_op_alloc_vectors(dev_info_t *dip, ddi_intr_handle_impl_t *handle,
    int *result)
{
	return (PSM_FAILURE);
}

/*
 * See comment in armbsa_intr_op_alloc_vectors - this seems to be our MSI/X mapping stuff.
 */
static int
armbsa_intr_op_free_vectors(dev_info_t *dip, ddi_intr_handle_impl_t *handle,
    int *result)
{
	return (PSM_FAILURE);
}

/*
 * I *think* we can just return the original vector here, since we don't have
 * any sort of translation table (and we don't need one).
 */
static int
armbsa_intr_op_xlate_vector(dev_info_t *dip, ddi_intr_handle_impl_t *handle,
    int *result)
{
#if 0
	*result = hdlp->ih_vector;	/* what is ih_inum? */
	return (PSM_SUCCESS);
#else
	return (PSM_FAILURE);
#endif
}

/*
 * Retrieves whether _the hardware_ says there's an IRQ pending
 *
 * Use the GIC for this, TL;DR is ICC_HPPIR1_EL1, filtering out special INTIDs.
 *
 * In GICv2, GICC_HPPIR., filter out special INTIDs.
 *
 * Dances over to the bound CPU, which is... interesting.
 */
static int
armbsa_intr_op_get_pending(dev_info_t *dip, ddi_intr_handle_impl_t *handle,
    int *result)
{
	return (PSM_FAILURE);
}

/*
 * Unmask the interrupt on the GIC - i.e. enable it
 */
static int
armbsa_intr_op_clear_mask(dev_info_t *dip, ddi_intr_handle_impl_t *handle,
    int *result)
{
	return (PSM_FAILURE);
}

/*
 * Mask the interrupt on the GIC - i.e. disable it
 */
static int
armbsa_intr_op_set_mask(dev_info_t *dip, ddi_intr_handle_impl_t *handle,
    int *result)
{
	return (PSM_FAILURE);
}

static int
armbsa_intr_op_get_shared(dev_info_t *dip, ddi_intr_handle_impl_t *handle,
    int *result)
{
	/*
	 * XXXARM: Sets *result to 1 iff there's more than one handler for this vector, 0 otherwise.
	 */
	return (PSM_FAILURE);
}

/*
 * There's actually nothing for us to do here, as we don't shadow anything
 *
 * i86pc code stashes the priority in intrspec_pri after checking it, then that's passed into the irq subsystem via addisr.
 */
static int
armbsa_intr_op_set_pri(dev_info_t *dip, ddi_intr_handle_impl_t *handle,
    int *result)
{
#if 0
	/* XXXARM: perhaps there's nothing to do? Need to figure out more of the i86pc code */
	if (*(int *)result > LOCK_LEVEL)
		return (PSM_SUCCESS);

	handle->ih_pri = *(int *)result;
	return (PSM_SUCCESS);
#endif
	return (PSM_FAILURE);
}

/*
 * Private helper for armbsa_intr_op_set_cpu and armbsa_intr_op_grp_set_cpu.
 *
 * The interrupt handle given here has been allocated specifically for these
 * commands, and ih_private carries a CPU value.
 */
static int
set_cpu_common(ddi_intr_handle_impl_t *handle,
    processorid_t *new_cpu, int *result)
{
	ASSERT(handle != NULL);
	ASSERT(new_cpu != NULL);
	ASSERT(result != NULL);
#if 1
	*new_cpu = (processorid_t)(uintptr_t)handle->ih_private;

#if 0
	/* XXXARM: check if the IRQ can happen on the requested CPU */
	if (!apic_cpu_in_range(*new_cpu)) {
		DDI_INTR_IMPLDBG((CE_CONT,
		    "[grp_]set_cpu: cpu out of range: %d\n", *new_cpu));
		*result = EINVAL;
		return (PSM_FAILURE);
	}

	/* XXXARM: seems APIX specific, but yeah, the vector needs to be valid */
	if (handle->ih_vector > APIC_MAX_VECTOR) {
		DDI_INTR_IMPLDBG((CE_CONT,
		    "[grp_]set_cpu: vector out of range: %d\n",
		    handle->ih_vector));
		*result = EINVAL;
		return (PSM_FAILURE);
	}
#endif

#if 0
	/* XXXARM: this is translation stuff, no? */
	if ((handle->ih_flags & PSMGI_INTRBY_FLAGS) == PSMGI_INTRBY_VEC)
		handle->ih_vector = apic_vector_to_irq[handle->ih_vector];
#endif

	return (PSM_SUCCESS);
#else
	return (PSM_FAILURE);
#endif
}

static int
armbsa_intr_op_set_cpu(dev_info_t *dip, ddi_intr_handle_impl_t *handle,
    int *result)
{
#if 1
	processorid_t new_cpu;

	if (set_cpu_common(handle, &new_cpu, result) != PSM_SUCCESS)
		return (PSM_FAILURE);

	/* return (apic_set_cpu(handle->ih_vector, new_cpu, result)); */
	/* return (armbsa_intr_set_cpu(handle->ih_vector, new_cpu, result)); */
	/* XXXARM: could we just inline the func? */
	return (PSM_SUCCESS);
#else
	return (PSM_FAILURE);
#endif
}

static int
armbsa_intr_op_grp_set_cpu(dev_info_t *dip, ddi_intr_handle_impl_t *handle,
    int *result)
{
#if 1
	processorid_t new_cpu;

	if (set_cpu_common(handle, &new_cpu, result) != PSM_SUCCESS)
		return (PSM_FAILURE);

	/* return (armbsa_intr_grp_set_cpu(handle->ih_vector, new_cpu, result)); */
	/* return (apic_grp_set_cpu(handle->ih_vector, new_cpu, result)); */
	return (PSM_SUCCESS);
#else
	return (PSM_FAILURE);
#endif
}

/*
 * XXXARM: This has a fairly rich query interface
 */
static int
armbsa_intr_op_get_intr(dev_info_t *dip, ddi_intr_handle_impl_t *handle,
    int *result)
{
	return (PSM_FAILURE);
}

/*
 * Seems to be a simple qeury interface for MSI and MSIX capabilities.
 *
 * APIX code leaves ih_type alone if MSI/MSIX is supported.
 *
 * Doesn't look like we need to look at the specific vector here.
 */
static int
armbsa_intr_op_check_msi(dev_info_t *dip, ddi_intr_handle_impl_t *handle,
    int *result)
{
#if 0
	uint16_t caps = 0;

	if (gic_ops.go_msi_supported())
		caps |= DDI_INTR_TYPE_MSI;
	if (gic_ops.go_msix_supported())
		caps |= DDI_INTR_TYPE_MSIX;

	*result =
	    (handle->ih_type & ~(DDI_INTR_TYPE_MSI|DDI_INTR_TYPE_MSIX)) | caps;

	return (PSM_SUCCESS);
#endif
	return (PSM_FAILURE);
}

static int
armbsa_intr_op_get_cap(dev_info_t *dip, ddi_intr_handle_impl_t *handle,
    int *result)
{
	/*
	 * XXXARM: this is flat out wrong
	 *
	 * Call into the GIC
	 * SGI is always edge
	 * PPI, EPPI, SPI and ESPI can be both level and edge
	 * LPI is alwats edge (IIRC, must check)
	 */
#if 0
	if (gic_ops.get_intid_type == NULL)
		return (PSM_FAILURE);

	switch (gic_ops.get_intid_type(vecnum)) {
	case GIC_INTID_TYPE_SGI:
		*(int *)result = DDI_INTR_FLAG_EDGE;
		break;
	case GIC_INTID_TYPE_PPI:	/* fallthrough */
	case GIC_INTID_TYPE_SPI:	/* fallthrough */
	case GIC_INTID_TYPE_EPPI:	/* fallthrough */
	case GIC_INTID_TYPE_ESPI:
		*(int *)result = DDI_INTR_FLAG_EDGE|DDI_INTR_FLAG_LEVEL;
		break;
	case GIC_INTID_TYPE_LPI:
		*(int *)result = DDI_INTR_FLAG_EDGE;
		break;
	default:
		return (PSM_FAILURE);
	}

	return (PSM_SUCCESS);
#endif
	*(int *)result = DDI_INTR_FLAG_LEVEL;
	return (PSM_SUCCESS);
}

static int
armbsa_intr_op_set_cap(dev_info_t *dip, ddi_intr_handle_impl_t *handle,
    int *result)
{
	/*
	 * Always fail, just like i86pc.
	 */
	return (PSM_FAILURE);
}

static int
armbsa_intr_op_apic_type(dev_info_t *dip, ddi_intr_handle_impl_t *handle,
    int *result)
{
#if 0
	apic_get_type_t	*typ = (apic_get_type_t *)hdlp->ih_private;

	typ->avgi_type = apix_get_apic_type(); /* XXXARM: this is the name, get this from the GIC module */
	typ->avgi_num_intr = APIX_IPI_MIN; /* XXXARM: get this from the GIC, allow it to be sparse */
	typ->avgi_num_cpu = boot_max_ncpus; /* XXXARM: boot_max_ncpus, I guess */
	hdlp->ih_ver = apic_get_apic_version(); /* XXXARM: GIC version - get this from the GIC */
#endif
	return (PSM_FAILURE);
}

/*
 * This function provides external interface to the nexus for all
 * functionalities related to the new DDI interrupt framework.
 *
 * Input:
 * dip     - pointer to the dev_info structure of the requested device
 * hdlp    - pointer to the internal interrupt handle structure for the
 *           requested interrupt
 * intr_op - opcode for this call
 * result  - pointer to the integer that will hold the result to be
 *           passed back if return value is PSM_SUCCESS
 *
 * Output:
 * Return value is either PSM_SUCCESS or PSM_FAILURE. The result parameter
 * can only be considered valid when the return value is PSM_SUCCESS.
 */
static int
armbsa_intr_ops(dev_info_t *dip, ddi_intr_handle_impl_t *handle,
    psm_intr_op_t intr_op, int *result)
{
	switch (intr_op) {
	case PSM_INTR_OP_ALLOC_VECTORS:	/* DDI_INTROP_ALLOC */
		return (armbsa_intr_op_alloc_vectors(dip, handle, result));
	case PSM_INTR_OP_FREE_VECTORS:	/* DDI_INTROP_FREE */
		return (armbsa_intr_op_free_vectors(dip, handle, result));
	case PSM_INTR_OP_XLATE_VECTOR:	/* DDI_INTROP_ENABLE, DDI_INTROP_DISABLE */
		return (armbsa_intr_op_xlate_vector(dip, handle, result));
	case PSM_INTR_OP_GET_PENDING:	/* DDI_INTROP_GETPENDING */
		return (armbsa_intr_op_get_pending(dip, handle, result));
	case PSM_INTR_OP_CLEAR_MASK:	/* DDI_INTROP_CLRMASK */
		return (armbsa_intr_op_clear_mask(dip, handle, result));
	case PSM_INTR_OP_SET_MASK:	/* DDI_INTROP_SETMASK */
		return (armbsa_intr_op_set_mask(dip, handle, result));
	case PSM_INTR_OP_GET_SHARED:	/* IRM, PCI */
		return (armbsa_intr_op_get_shared(dip, handle, result));
	case PSM_INTR_OP_SET_PRI:	/* DDI_INTROP_SETPRI */
		return (armbsa_intr_op_set_pri(dip, handle, result));
	case PSM_INTR_OP_SET_CPU:	/* PCI (tools and common) */
		return (armbsa_intr_op_set_cpu(dip, handle, result));
	case PSM_INTR_OP_GRP_SET_CPU:	/* PCI (tools) */
		return (armbsa_intr_op_grp_set_cpu(dip, handle, result));
	case PSM_INTR_OP_GET_INTR:	/* PCI (tools, common, kstats) */
		return (armbsa_intr_op_get_intr(dip, handle, result));
	case PSM_INTR_OP_CHECK_MSI:	/* PCI (common) */
		return (armbsa_intr_op_check_msi(dip, handle, result));
	case PSM_INTR_OP_GET_CAP:	/* DDI_INTROP_GETCAP */
		return (armbsa_intr_op_get_cap(dip, handle, result));
	case PSM_INTR_OP_SET_CAP:	/* DDI_INTROP_SETCAP */
		return (armbsa_intr_op_set_cap(dip, handle, result));
	case PSM_INTR_OP_APIC_TYPE:	/* PCI-IDE, ISA, PCI (tools, common), rootnex */
		return (armbsa_intr_op_apic_type(dip, handle, result));
	default:
		return (PSM_FAILURE);
	}

	return (PSM_SUCCESS);
}

static int
armbsa_state(psm_state_request_t *request)
{
	return (-1);
}

static int
armbsa_cpu_ops(psm_cpu_request_t *reqp)
{
	return (-1);
}
