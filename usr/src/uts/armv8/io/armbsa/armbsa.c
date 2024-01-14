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
#include <sys/psm_gic.h>
#include <sys/archsystm.h>
#include <sys/cpuinfo.h>

static int armbsa_probe(void);
static void armbsa_init(void);

static void armbsa_picinit(void);
static int armbsa_intr_enter(int ipl, psm_intr_cookie_t *cookiep,
    psm_intr_vector_t *vectorp);
static void armbsa_intr_exit(int ipl, psm_intr_cookie_t cookie);
static void armbsa_setspl(int ipl);
static int armbsa_config_irq(uint32_t irqno, int flags);
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
static void armbsa_send_ipi(cpuset_t cpus, int ipl);

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
	armbsa_config_irq,
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
	PSM_OWN_SYS_DEFAULT,			/* ownership */
	&armbsa_ops,				/* operation */
	"armbsa",				/* machine name */
	"Arm Base System Architecture",		/* machine descriptions */
};

static void *armbsa_hdlp;

static psm_gic_t *pgic;

typedef enum {
	FWIF_FDT = 0,
	FWIF_ACPI = 1
} armbsa_firmware_interface_t;

static armbsa_firmware_interface_t armbsa_firmware_interface = FWIF_FDT;

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
	extern int armbsa_fdt_gic_probe(void);

	if (armbsa_fdt_gic_probe() == PSM_SUCCESS)
		return (PSM_SUCCESS);

	return (PSM_FAILURE);
}

static void
armbsa_init(void)
{
	/*
	 * XXXARM: this needs to be more intelligent
	 *
	 * If we have an ACPI pointer we *must* use it (per BBR)
	 *   ... but we can also have an FDT pointer, just not
	 *       for hardware stuff
	 * else we must have an FDT pointer.
	 *
	 * In both cases we may also have an EFI system table pointer,
	 * which we'll happily use for things like a TOD, reboots etc.
	 *
	 * Otherwise TOD is board specific and loaded as a driver, while 
	 * reset is via PSCI (which we absolutely need).
	 */
	armbsa_firmware_interface = FWIF_FDT;
}

/*
 * Interrupt Handling
 */

static void
armbsa_picinit(void)
{
	extern int armbsa_fdt_gic_init(psm_gic_t *gic);

	/* XXXARM: clean up once ACPI is implemented */
	ASSERT(armbsa_firmware_interface == FWIF_FDT);

	ASSERT(pgic == NULL);
	pgic = kmem_zalloc(sizeof (*pgic), KM_SLEEP);

	if (armbsa_firmware_interface == FWIF_FDT) {
		if (armbsa_fdt_gic_init(pgic) != PSM_SUCCESS) {
			kmem_free(pgic, sizeof (*pgic));
			panic("armbsa: failed to initialise GIC from FDT");
		}
	}

	if (pgic->pg_init(pgic) != PSM_SUCCESS) {
		kmem_free(pgic, sizeof (*pgic));
		panic("armbsa: failed to initialise GIC");
	}
}

/*
 * Enters IRQ Processing
 *
 * Must be called with interrupts disabled.
 *
 * Returns PSM_SPURIOUS_INTERRUPT if the interrupt was spurious or disabled
 * by the time the interrupt was delivered.
 *
 * When PSM_SUCCESS is returned:
 * - The cookiep argument is filled in with a cookie to pass to the
 *   psm_intr_exit function.
 * - The vectorp argument is filled in with the interrupt vector to be
 *   processed by the interrpt handler.
 * - The cpu_pri field of the current CPU is updated with the current priority.
 * - The called must pair this call with a call to the psm_intr_exit function,
 *   passing the returned cookie to that function.
 */
static int
armbsa_intr_enter(int ipl __unused, psm_intr_cookie_t *cookiep,
    psm_intr_vector_t *vectorp)
{
	uint64_t ack;
	uint32_t vector;
	int newipl;

	ASSERT(interrupts_disabled());

	if (pgic == NULL ||
	    pgic->pg_data == NULL ||
	    pgic->pg_ops.pgo_acknowledge == NULL ||
	    pgic->pg_ops.pgo_ack_to_vector == NULL ||
	    pgic->pg_ops.pgo_is_spurious == NULL ||
	    pgic->pg_ops.pgo_deactivate == NULL ||
	    pgic->pg_ops.pgo_setlvl == NULL ||
	    pgic->pg_ops.pgo_eoi == NULL)
		return (PSM_SPURIOUS_INTERRUPT);

	ack = pgic->pg_ops.pgo_acknowledge(pgic->pg_data);
	vector = pgic->pg_ops.pgo_ack_to_vector(pgic->pg_data, ack);

	if (pgic->pg_ops.pgo_is_spurious(pgic->pg_data, vector))
		return (PSM_SPURIOUS_INTERRUPT);

	newipl = pgic->pg_ops.pgo_setlvl(pgic->pg_data, vector);
	pgic->pg_ops.pgo_eoi(pgic->pg_data, ack);

	if (newipl == 0) {
		pgic->pg_ops.pgo_deactivate(pgic->pg_data, ack);
		return (PSM_SPURIOUS_INTERRUPT);
	}

	CPU->cpu_pri = newipl;
	*cookiep = ack;
	*vectorp = vector;
	return (PSM_SUCCESS);
}

/*
 * Leaves IRQ Processig
 *
 * In this implementation, the following actions are performed:
 * - The current CPUs recorded and running priorities are set to ipl
 * - The interrupt represented by cookie is deactivated.
 *
 * Interrupts must be disabled when this function is called.
 *
 * This interrupt must only be called after a successful call to the
 * psm_intr_enter function, passing the cookie value provided by that function.
 */
static void
armbsa_intr_exit(int ipl, psm_intr_cookie_t cookie)
{
	ASSERT(interrupts_disabled());

	ASSERT(pgic != NULL);
	ASSERT(pgic->pg_data != NULL);
	ASSERT(pgic->pg_ops.pgo_deactivate != NULL);
	ASSERT(pgic->pg_ops.pgo_setlvlx != NULL);

	CPU->cpu_m.mcpu_pri = ipl;
	pgic->pg_ops.pgo_deactivate(pgic->pg_data, cookie);
	pgic->pg_ops.pgo_setlvlx(pgic->pg_data, ipl);
}

/*
 * Mask all interrupts at or below the passed IPL.
 */
static void
armbsa_setspl(int ipl)
{
	ASSERT(pgic != NULL);
	ASSERT(pgic->pg_data != NULL);
	ASSERT(pgic->pg_ops.pgo_setlvlx != NULL);
	pgic->pg_ops.pgo_setlvlx(pgic->pg_data, ipl);
}

static int
armbsa_config_irq(uint32_t irqno, int flags)
{
	boolean_t is_edge = B_FALSE;

	ASSERT(pgic != NULL);
	ASSERT(pgic->pg_data != NULL);
	ASSERT(pgic->pg_ops.pgo_config_irq != NULL);

	if ((flags & DDI_INTR_FLAG_EDGE) && !((flags & DDI_INTR_FLAG_LEVEL)))
		is_edge = B_TRUE;

	pgic->pg_ops.pgo_config_irq(pgic->pg_data, irqno, is_edge);
	return (PSM_SUCCESS);
}

static int
armbsa_addspl(int irqno, int ipl, int min_ipl, int max_ipl)
{
	ASSERT(pgic != NULL);
	ASSERT(pgic->pg_data != NULL);
	ASSERT(pgic->pg_ops.pgo_addspl != NULL);

	if (pgic->pg_ops.pgo_addspl(pgic->pg_data, irqno, ipl) == 0)
		return (PSM_SUCCESS);

	return (PSM_FAILURE);
}

static int
armbsa_delspl(int irqno, int ipl, int min_ipl, int max_ipl)
{
	ASSERT(pgic != NULL);
	ASSERT(pgic->pg_data != NULL);
	ASSERT(pgic->pg_ops.pgo_delspl != NULL);

	if (pgic->pg_ops.pgo_delspl(pgic->pg_data, irqno, ipl) == 0)
		return (PSM_SUCCESS);

	return (PSM_FAILURE);
}

static int
armbsa_disable_intr(processorid_t cpun)
{
	panic("unimplemented");
	return (-1);
}

static void
armbsa_enable_intr(processorid_t cpun)
{
	panic("unimplemented");
}

/*
 * XXXARM: implement
 */
static int
armbsa_softlvl_to_irq(int ipl)
{
	panic("unimplemented");
	return (-1);
}

/*
 * XXXARM: implement
 */
static void
armbsa_set_softintr(int ipl)
{
	panic("unimplemented");
}

/*
 * Clocks and timers
 */

/*
 * XXXARM: implement
 */
static int
armbsa_clkinit(int hertz)
{
	panic("unimplemented");
	return (-1);
}

/*
 * XXXARM: implement
 */
static int
armbsa_get_clkirq(int ipl)
{
	panic("unimplemented");
	return (-1);
}

/*
 * XXXARM: implement?
 */
static void
armbsa_hrtimeinit(void)
{
	panic("unimplemented");
}

/*
 * XXXARM: implement
 */
static hrtime_t
armbsa_gethrtime(void)
{
	panic("unimplemented");
	return ((hrtime_t)-1);
}

/*
 * CPU management
 */

/*
 * XXXARM: implement
 */
static void
armbsa_set_idlecpu(processorid_t cpun)
{
	panic("unimplemented");
}

/*
 * XXXARM: implement
 */
static void
armbsa_unset_idlecpu(processorid_t cpun)
{
	panic("unimplemented");
}

/*
 * Returns the next enabled processor ID.
 *
 * To retrieve the first enabled processor, pass -1 as cpu_id. Thereafter,
 * pass the previously returned processor ID, until -1 is returned. At this
 * point you will have iterated through all enabled processors.
 */
static processorid_t
armbsa_get_next_processorid(processorid_t cpu_id)
{
	struct cpuinfo	*ci;
	boolean_t	take_next = B_FALSE;

	ci = cpuinfo_first_enabled();
	ASSERT(ci != NULL);

	if (cpu_id == (processorid_t)-1)
		return (ci->ci_id);

	for (; ci != cpuinfo_end(); ci = cpuinfo_next_enabled(ci)) {
		if (ci->ci_id == cpu_id) {
			take_next = B_TRUE;
			continue;
		}

		if (take_next)
			return (ci->ci_id);
	}

	return ((processorid_t)-1);
}

/*
 * XXXARM: implement
 *
 * This is the spin-table or PSCI wakeup.
 */
static int
armbsa_cpu_start(processorid_t cpun, caddr_t ctxt)
{
	panic("unimplemented");
	return (-1);
}

/*
 * Perform any remaining PSM actions for a CPU that has just started.
 *
 * In this case, initialises the GIC CPU interface.
 */
static int
armbsa_post_cpu_start(void)
{
	pgic->pg_ops.pgo_cpu_init(pgic->pg_data, CPU);
	return (PSM_SUCCESS);
}

/*
 * XXXARM: what does this do?
 */
static void
armbsa_shutdown(int cmd, int fcn)
{
	panic("unimplemented");
}

/*
 * XXXARM: implement
 */
static int
armbsa_get_ipivect(int ipl, int type)
{
	panic("unimplemented");
	return (-1);
}

static void
armbsa_send_ipi(cpuset_t cpus, int irq)
{
	ASSERT(pgic != NULL);
	ASSERT(pgic->pg_data != NULL);
	ASSERT(pgic->pg_ops.pgo_send_ipi != NULL);

	pgic->pg_ops.pgo_send_ipi(pgic->pg_data, cpus, irq);
}

/*
 * Translate an IRQ number to a vector.
 *
 * aarch64 systems do an identity mapping, so no translation.
 */
static int
armbsa_translate_irq(dev_info_t *dip __unused, int irqno)
{
	return (irqno);	/* no translation */
}

/*
 * XXXARM: what does this do?
 */
static void
armbsa_notify_error(int level, char *errmsg)
{
	panic("unimplemented");
}

/*
 * XXXARM: what does this do?
 */
static void
armbsa_notify_func(int msg)
{
	panic("unimplemented");
}

/*
 * Timer functions - are we going to use these?
 */

/*
 * XXXARM: what does this do?
 */
static void
armbsa_timer_reprogram(hrtime_t time)
{
	panic("unimplemented");
}

/*
 * XXXARM: what does this do?
 */
static void
armbsa_timer_enable(void)
{
	panic("unimplemented");
}

/*
 * XXXARM: what does this do?
 */
static void
armbsa_timer_disable(void)
{
	panic("unimplemented");
}

/*
 * XXXARM: I assume this is for IRQ balancing?
 */
static void
armbsa_post_cyclic_setup(void *arg)
{
	panic("unimplemented");
}

/*
 * XXXARM: what does this do?
 */
static void
armbsa_preshutdown(int cmd, int fcn)
{
	panic("unimplemented");
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
armbsa_intr_op_alloc_vectors_fixed(dev_info_t *dip,
    ddi_intr_handle_impl_t *hdlp, int *result)
{
	ASSERT(hdlp != NULL);
	ASSERT(hdlp->ih_type == DDI_INTR_TYPE_FIXED);
	*result = 1;
	return (PSM_SUCCESS);
}

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

static int
armbsa_intr_op_xlate_vector(dev_info_t *dip, ddi_intr_handle_impl_t *hdlp,
    int *result)
{
	*result = armbsa_translate_irq(dip, hdlp->ih_vector);
	return (PSM_SUCCESS);
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
armbsa_intr_op_check_msi(dev_info_t *dip, ddi_intr_handle_impl_t *hdlp,
    int *result)
{
#if 1
	*result = hdlp->ih_type & ~(DDI_INTR_TYPE_MSI | DDI_INTR_TYPE_MSIX);
	return (PSM_SUCCESS);
#else
	uint16_t caps = 0;

	if (gic_ops.go_msi_supported())
		caps |= DDI_INTR_TYPE_MSI;
	if (gic_ops.go_msix_supported())
		caps |= DDI_INTR_TYPE_MSIX;

	*result =
	    (handle->ih_type & ~(DDI_INTR_TYPE_MSI|DDI_INTR_TYPE_MSIX)) | caps;

	return (PSM_SUCCESS);
#endif
}

/*
 * Supports the ddi_intr_get_cap function via a nexus driver.
 */
static int
armbsa_intr_op_get_cap(dev_info_t *dip, ddi_intr_handle_impl_t *hdlp,
    int *result)
{
	int hwcap;

	if (pgic == NULL || pgic->pg_data == NULL ||
	    pgic->pg_ops.pgo_get_intr_caps == NULL)
		return (PSM_FAILURE);

	hwcap = pgic->pg_ops.pgo_get_intr_caps(pgic->pg_data, hdlp->ih_vector);
	if (hwcap == -1)
		return (PSM_FAILURE);

	*result = hwcap & (DDI_INTR_FLAG_PENDING|DDI_INTR_FLAG_MASKABLE|
	    DDI_INTR_FLAG_EDGE|DDI_INTR_FLAG_LEVEL);

	return (PSM_SUCCESS);
}

/*
 * Supports the ddi_intr_set_cap function via a nexus driver.
 *
 * Only DDI_INTR_FLAG_LEVEL and DDI_INTR_FLAG_EDGE flags can be set. Some
 * devices can support both level and edge capability and either can be set
 * by using the ddi_intr_set_cap() function.
 *
 * The requested capability is stored in the ih_flags field of the passed
 * intr handle and only applied when the interrupt is established.
 */
static int
armbsa_intr_op_set_cap(dev_info_t *dip, ddi_intr_handle_impl_t *hdlp,
    int *result)
{
	int hwcap;	/* hardware capabilities */
	int rcap;	/* requested capabilities */

	ASSERT(hdlp != NULL);
	ASSERT(result != NULL);
	rcap = *result;

	/*
	 * Only one of edge and level can be requested. No other capabilities
	 * can be set.
	 */
	if (rcap & (DDI_INTR_FLAG_EDGE|DDI_INTR_FLAG_LEVEL))
		return (PSM_FAILURE);
	if ((rcap & (DDI_INTR_FLAG_EDGE|DDI_INTR_FLAG_LEVEL)) ==
	    (DDI_INTR_FLAG_EDGE|DDI_INTR_FLAG_LEVEL))
		return (PSM_FAILURE);

	/*
	 * Get the capabilities of the interrupt line and check if the line
	 * supports the requested capability.
	 */
	if (armbsa_intr_op_get_cap(dip, hdlp, &hwcap) != PSM_SUCCESS)
		return (PSM_FAILURE);
	if (!(hwcap & rcap))
		return (PSM_FAILURE);

	/*
	 * The hardware supports our request, update flags to include only
	 * the requested capability (level or edge).
	 */
	hdlp->ih_flags &= ~(DDI_INTR_FLAG_EDGE|DDI_INTR_FLAG_LEVEL);
	hdlp->ih_flags &= rcap;
	return (PSM_SUCCESS);
}

static int
armbsa_intr_op_apic_type(dev_info_t *dip, ddi_intr_handle_impl_t *hdlp,
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
armbsa_intr_ops(dev_info_t *dip, ddi_intr_handle_impl_t *hdlp,
    psm_intr_op_t intr_op, int *result)
{
	panic("unimplemented");
	switch (intr_op) {
	case PSM_INTR_OP_ALLOC_VECTORS:	/* DDI_INTROP_ALLOC */
		if (hdlp->ih_type == DDI_INTR_TYPE_FIXED)
			return (armbsa_intr_op_alloc_vectors_fixed(
			    dip, hdlp, result));
		return (armbsa_intr_op_alloc_vectors(dip, hdlp, result));
	case PSM_INTR_OP_FREE_VECTORS:	/* DDI_INTROP_FREE */
		if (hdlp->ih_type == DDI_INTR_TYPE_FIXED)
			break;
		return (armbsa_intr_op_free_vectors(dip, hdlp, result));
	case PSM_INTR_OP_XLATE_VECTOR:	/* DDI_INTROP_ENABLE, DDI_INTROP_DISABLE */
		return (armbsa_intr_op_xlate_vector(dip, hdlp, result));
	case PSM_INTR_OP_GET_PENDING:	/* DDI_INTROP_GETPENDING */
		return (armbsa_intr_op_get_pending(dip, hdlp, result));
	case PSM_INTR_OP_CLEAR_MASK:	/* DDI_INTROP_CLRMASK */
		return (armbsa_intr_op_clear_mask(dip, hdlp, result));
	case PSM_INTR_OP_SET_MASK:	/* DDI_INTROP_SETMASK */
		return (armbsa_intr_op_set_mask(dip, hdlp, result));
	case PSM_INTR_OP_GET_SHARED:	/* IRM, PCI */
		return (armbsa_intr_op_get_shared(dip, hdlp, result));
	case PSM_INTR_OP_SET_PRI:	/* DDI_INTROP_SETPRI */
		return (armbsa_intr_op_set_pri(dip, hdlp, result));
	case PSM_INTR_OP_SET_CPU:	/* PCI (tools and common) */
		return (armbsa_intr_op_set_cpu(dip, hdlp, result));
	case PSM_INTR_OP_GRP_SET_CPU:	/* PCI (tools) */
		return (armbsa_intr_op_grp_set_cpu(dip, hdlp, result));
	case PSM_INTR_OP_GET_INTR:	/* PCI (tools, common, kstats) */
		return (armbsa_intr_op_get_intr(dip, hdlp, result));
	case PSM_INTR_OP_CHECK_MSI:	/* PCI (common) */
		return (armbsa_intr_op_check_msi(dip, hdlp, result));
	case PSM_INTR_OP_GET_CAP:	/* DDI_INTROP_GETCAP */
		return (armbsa_intr_op_get_cap(dip, hdlp, result));
	case PSM_INTR_OP_SET_CAP:	/* DDI_INTROP_SETCAP */
		return (armbsa_intr_op_set_cap(dip, hdlp, result));
	case PSM_INTR_OP_APIC_TYPE:	/* PCI-IDE, ISA, PCI (tools, common), rootnex */
		return (armbsa_intr_op_apic_type(dip, hdlp, result));
	default:
		return (PSM_FAILURE);
	}

	return (PSM_SUCCESS);
}

/*
 * XXXARM: what does this do?
 */
static int
armbsa_state(psm_state_request_t *request)
{
	panic("unimplemented");
	return (-1);
}

/*
 * XXXARM: Implement this.
 */
static int
armbsa_cpu_ops(psm_cpu_request_t *reqp)
{
	panic("unimplemented");
	return (-1);
}
