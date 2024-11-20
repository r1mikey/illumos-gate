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

#include <sys/avl.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/gic.h>
#include <sys/gic_reg.h>
#include <sys/modctl.h>
#include <sys/promif.h>
#include <sys/smp_impldefs.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/bootinfo.h>
#include <sys/acpi/platform/acsolaris.h>
#include <sys/acpi/actypes.h>
#include <sys/acpi/actbl.h>

extern struct xboot_info *xboot_info_p;

static void stub_not_config(void);
static void stub_setlvlx(int ipl);

/*
 * State we track for debugging, such as mdb's `::interrupts`
 *
 * We store an AVL keyed on vector (since our space is far too sparse for
 * tables).  `gic_intrs_lock` protects the tree and the entries in the tree.
 *
 * Effort is taken such that people consuming `gic_intrs_lock` receive a
 * consistent view (that is, `gic_intrs_lock` is held until the state changes
 * are in hardware).  This is a courtesy as long as the state is only observed
 * by a debugger, as intended.
 */
kmutex_t gic_intrs_lock;
avl_tree_t gic_intrs;

/*
 * Used by implementations to ensure that they only fill in gic_ops when
 * appropriate.
 */
char *gic_module_name = NULL;

gic_ops_t gic_ops = {
	.go_send_ipi		= (gic_send_ipi_t)stub_not_config,
	.go_init		= (gic_init_t)stub_not_config,
	.go_cpu_init		= (gic_cpu_init_t)stub_not_config,
	.go_config_irq		= (gic_config_irq_t)stub_not_config,
	.go_addspl		= (gic_addspl_t)stub_not_config,
	.go_delspl		= (gic_delspl_t)stub_not_config,
	.go_setlvl		= (gic_setlvl_t)stub_not_config,
	.go_setlvlx		= stub_setlvlx,
	.go_acknowledge		= (gic_acknowledge_t)stub_not_config,
	.go_ack_to_vector	= (gic_ack_to_vector_t)stub_not_config,
	.go_eoi			= (gic_eoi_t)stub_not_config,
	.go_deactivate		= (gic_deactivate_t)stub_not_config,
	.go_is_spurious		= (gic_is_spurious_t)NULL
};

static void
stub_not_config(void)
{
	prom_panic("GIC not configured\n");
}

static void
stub_setlvlx(int ipl __unused)
{
	/*
	 * Nothing to do here.
	 *
	 * setlvlx is called while locking and printing in the early kmem_init
	 * path (console_{enter,exit}, putq, cprintf) and in startup (cmn_err
	 * and mod_setup, reaching many of the same locks as in the kmem_init
	 * path).
	 *
	 * Adjusting the priority level this early is unnecessary, since
	 * interrupts are completely disabled. Locking is also unnecessary,
	 * since only one CPU is running. However, avoiding these calls in this
	 * case would overly complicate the general case of running the system,
	 * so we just allow the calls to be no-ops prior to loading a GIC
	 * implementation module.
	 */
}

static int
gic_intr_state_cmp(const void *l, const void *r)
{
	const gic_intr_state_t *li = l;
	const gic_intr_state_t *ri = r;

	if (li->gi_vector > ri->gi_vector)
		return (1);
	if (li->gi_vector < ri->gi_vector)
		return (-1);
	return (0);
}

gic_intr_state_t *
gic_get_state(int irq)
{
	gic_intr_state_t lookup, *new;
	avl_index_t where = 0;

	lookup.gi_vector = irq;

	mutex_enter(&gic_intrs_lock);

	if ((new = avl_find(&gic_intrs, &lookup, &where)) == NULL) {
		new = kmem_zalloc(sizeof (*new), KM_SLEEP);
		new->gi_vector = irq;
		avl_insert(&gic_intrs, new, where);
	} else {
		new->gi_vector = irq;
	}


	return (new);
}

void
gic_remove_state(int irq)
{
	gic_intr_state_t lookup, *st;

	lookup.gi_vector = irq;
	st = avl_find(&gic_intrs, &lookup, NULL);
	VERIFY3P(st, !=, NULL);

	avl_remove(&gic_intrs, st);
	kmem_free(st, sizeof (gic_intr_state_t));
}

void
gic_send_ipi(cpuset_t cpuset, int irq)
{
	gic_ops.go_send_ipi(cpuset, irq);
}

void
gic_cpu_init(cpu_t *cp)
{
	gic_ops.go_cpu_init(cp);
}

void
gic_config_irq(uint32_t irq, bool is_edge)
{
	gic_intr_state_t *state = gic_get_state(irq);
	VERIFY3P(state, !=, NULL);

	state->gi_edge_triggered = is_edge;

	gic_ops.go_config_irq(irq, is_edge);
	mutex_exit(&gic_intrs_lock);
}

static int
gic_addspl(int irq, int ipl, int min_ipl, int max_ipl)
{
	gic_intr_state_t *state = gic_get_state(irq);
	int ret;

	VERIFY3P(state, !=, NULL);

	state->gi_prio = ipl;
	ret = gic_ops.go_addspl(irq, ipl, min_ipl, max_ipl);
	mutex_exit(&gic_intrs_lock);
	return (ret);
}

/*
 * XXXARM: Comment taken verbatim from
 *         i86pc/io/mp_platform_misc.c:apic_delspl_common)
 *
 * Recompute mask bits for the given interrupt vector.
 * If there is no interrupt servicing routine for this
 * vector, this function should disable interrupt vector
 * from happening at all IPLs. If there are still
 * handlers using the given vector, this function should
 * disable the given vector from happening below the lowest
 * IPL of the remaining handlers.
 */
static int
gic_delspl(int irq, int ipl, int min_ipl, int max_ipl)
{
	ASSERT3S(irq, <, MAX_VECT);

	if (autovect[irq].avh_hi_pri == 0) {
		int ret = 0;
		mutex_enter(&gic_intrs_lock);
		gic_remove_state(irq);

		ret = gic_ops.go_delspl(irq, ipl, min_ipl, max_ipl);
		mutex_exit(&gic_intrs_lock);
		return (ret);
	}

	return (0);
}

int (*addspl)(int, int, int, int) = gic_addspl;
int (*delspl)(int, int, int, int) = gic_delspl;

int
setlvl(int irq)
{
	return (gic_ops.go_setlvl(irq));
}

void
setlvlx(int ipl)
{
	gic_ops.go_setlvlx(ipl);
}

uint64_t
gic_acknowledge(void)
{
	return (gic_ops.go_acknowledge());
}

uint32_t
gic_ack_to_vector(uint64_t ack)
{
	return (gic_ops.go_ack_to_vector(ack));
}

void
gic_eoi(uint64_t ack)
{
	gic_ops.go_eoi(ack);
}

void
gic_deactivate(uint64_t ack)
{
	gic_ops.go_deactivate(ack);
}

int
gic_is_spurious(uint32_t intid)
{
	if (gic_ops.go_is_spurious != NULL)
		return (gic_ops.go_is_spurious(intid));

	if (GIC_INTID_IS_SPECIAL(intid))
		return (1);

	return (0);
}

/*
 * GIC Initialisation
 */
static int
get_gic_version_acpi(void)
{
	ACPI_TABLE_XSDT *xsdt;
	ACPI_TABLE_HEADER *tab;
	ACPI_TABLE_MADT *madt;
	ACPI_SUBTABLE_HEADER *item;
	ACPI_SUBTABLE_HEADER *end;
	ACPI_MADT_GENERIC_DISTRIBUTOR *gicd;
	uint64_t *entry;
	uint32_t entries;
	size_t slen;
	uint32_t i;
	int vers = -1;

	xsdt = (ACPI_TABLE_XSDT *)xboot_info_p->bi_acpi_xsdt;
	entries = (xsdt->Header.Length -
	    sizeof (xsdt->Header)) / ACPI_XSDT_ENTRY_SIZE;
	entry = &xsdt->TableOffsetEntry[0];
	slen = strlen(ACPI_SIG_MADT);
	tab = NULL;

	for (i = 0; i < entries; ++i) {
		tab = (ACPI_TABLE_HEADER *)entry[i];
		if (tab == NULL)
			continue;
		if (strncmp(tab->Signature, ACPI_SIG_MADT, slen) == 0)
			break;
		tab = NULL;
	}

	if (tab == NULL)
		return (vers);

	madt = (ACPI_TABLE_MADT *)tab;
	end = (ACPI_SUBTABLE_HEADER *)
	    (madt->Header.Length + (uintptr_t)madt);
	item = (ACPI_SUBTABLE_HEADER *)
	    ((uintptr_t)madt + sizeof (*madt));

	while (item < end) {
		if (item->Type != ACPI_MADT_TYPE_GENERIC_DISTRIBUTOR) {
			item = (ACPI_SUBTABLE_HEADER *)
			    ((uintptr_t)item + item->Length);
			continue;
		}
		gicd = (ACPI_MADT_GENERIC_DISTRIBUTOR *)item;

		if (gicd->Version) {
			vers = gicd->Version;
			break;
		}

		/*
		 * We could probe the version from the distributor here, by
		 * by reading ICPIDR2 (GICv2) or GICD_PIDR2 (GICv3).  However,
		 * GICv2 and GICv3 have different register offsets for the
		 * IDR registers, and different distributor frame sizes.
		 *
		 * Since ACPI does not give us the size of the mapping for the
		 * GIC we can't even derive that a 4k mapping would be ICPIDR2
		 * and a 64k mapping would be GICD_PIDR2.
		 *
		 * So we just don't do anything here, trusting the firmware
		 * to supply us with a reasonable value.
		 */

		/*
		 * §5.2.12.15 GIC Distributor (GICD) Structue
		 *
		 * One, and only one, GIC distributor structure must be present
		 * in the MADT for an ARM based system.
		 */
		break;
	}

	return (vers);
}

static int
get_gic_version_fdt(void)
{
	if (prom_fdt_has_compatible("arm,gic-400") ||
	    prom_fdt_has_compatible("arm,cortex-a15-gic")) {
		return (2);
	}

	if (prom_fdt_has_compatible("arm,gic-v3")) {
		return (3);
	}

	return (-1);
}

static void
set_gic_module_name(void)
{
	int ver;

	if (gic_module_name)
		return;

	if (xboot_info_p && xboot_info_p->bi_fdt)
		ver = get_gic_version_fdt();
	else if (xboot_info_p && xboot_info_p->bi_acpi_xsdt)
		ver = get_gic_version_acpi();
	else
		prom_panic("Unknown firmware interface\n");

	switch (ver) {
	case -1:
		prom_panic("Unrecognised GIC version\n");
		break;
	case 2:
		gic_module_name = "gicv2";
		break;
	case 3:	/* fallthrough */
	case 4:
		gic_module_name = "gicv3";
		break;
	default:
		prom_panic("Unknown GIC version\n");
		break;
	}

	return;
}

int
gic_init(void)
{
	set_gic_module_name();
	if (gic_module_name == NULL)
		return (ENOTSUP);

	if (modload("drv", gic_module_name) == -1)
		return (ENOENT);

	if (gic_ops.go_init() != 0)
		return (-1);

	mutex_init(&gic_intrs_lock, NULL, MUTEX_DEFAULT, NULL);
	avl_create(&gic_intrs, gic_intr_state_cmp, sizeof (gic_intr_state_t),
	    offsetof(gic_intr_state_t, gi_node));

	return (0);
}
