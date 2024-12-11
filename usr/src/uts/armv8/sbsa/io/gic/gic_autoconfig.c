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
 * Create device tree nodes for the top-level interrupt controller (an Arm
 * Generic Interrupt Controller), then ensure that controller is attached
 * early, registering with the interrupt framework ahead of devices that
 * will consume interrupts.
 */

#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ddi_subrdefs.h>
#include <sys/ddi_impldefs.h>
#include <sys/modctl.h>

#include <sys/acpi/acpi.h>
#include <sys/acpica.h>

struct gicc_item;
struct gicd_item;
struct gv2m_item;
struct gicr_item;
struct gits_item;

struct gicc_item {
	ACPI_MADT_GENERIC_INTERRUPT	*gicc;
	struct gicc_item		*next;
};

struct gicd_item {
	ACPI_MADT_GENERIC_DISTRIBUTOR	*gicd;
	struct gicd_item		*next;
};

struct gv2m_item {
	ACPI_MADT_GENERIC_MSI_FRAME	*gv2m;
	struct gv2m_item		*next;
};

struct gicr_item {
	ACPI_MADT_GENERIC_REDISTRIBUTOR	*gicr;
	struct gicr_item		*next;
};

struct gits_item {
	ACPI_MADT_GENERIC_TRANSLATOR	*gits;
	struct gits_item		*next;
};

struct madt_gic {
	ACPI_TABLE_MADT			*mg_madt;

	struct gicc_item		*mg_gicc;
	struct gicd_item		*mg_gicd;
	struct gv2m_item		*mg_gv2m;
	struct gicr_item		*mg_gicr;
	struct gits_item		*mg_gits;

	uint32_t			mg_ngicc;
	uint32_t			mg_ngicd;
	uint32_t			mg_ngv2m;
	uint32_t			mg_ngicr;
	uint32_t			mg_ngits;
};

static void pic_probe(int);

static struct modlmisc modlmisc = {
	.misc_modops = &mod_miscops,
	.misc_linkinfo = "GIC MADT interface"
};

static struct modlinkage modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &modlmisc, NULL }
};

int
_init(void)
{
	int err = -1;

	if (acpica_init() != AE_OK)
		return (err);

	if ((err = mod_install(&modlinkage)) != 0)
		return (err);

	impl_bus_add_probe(pic_probe);
	return (err);
}

int
_fini(void)
{
	int err = -1;

	if ((err = mod_remove(&modlinkage)) != 0)
		return (err);

	impl_bus_delete_probe(pic_probe);
	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * See Documentation/devicetree/bindings/interrupt-controller/arm,gic.txt in
 * the Linux kernel tree, or on https://www.kernel.org/doc/.
 *
 * XXXARM: It's not clear how FDT support for GICv2 with virtualisation
 * extensions works.  Once we figure that out we can incorporate the
 * VGIC maintenance interrupt and the GIC virtual CPU interface and GIC
 * virtual interface control block registers. These are stored in the
 * ACPI_MADT_GENERIC_INTERRUPT structure as VgicInterrupt, GicvBaseAddress and
 * GichBaseAddress.
 */

static int
gic_setup_v2_device(dev_info_t *rdip, struct madt_gic *mg)
{
	int			rv;
	uint64_t		gicc_addr;
	uint64_t		gicd_addr;
	uint64_t		gich_addr;
	uint64_t		gicv_addr;
	uint64_t		gicc_size;
	uint64_t		gicd_size;
	uint64_t		gv2m_size;
	uint64_t		gich_size;
	uint64_t		gicv_size;
	uint64_t		lowest_reg;
	uint64_t		highest_reg;
	uint64_t		highest_reg_size;
	struct gicc_item	*gicc;
	struct gv2m_item	*gv2m;
	struct regspec		regspecs[4];
	uint32_t		vgic_intid;
	uint_t			nregs;
	char			*compatible[] = {"arm,gic-400"};

	vgic_intid = 0;
	gicc_addr = 0;
	gicd_addr = 0;
	gich_addr = 0;
	gicv_addr = 0;
	gicc_size = 0x2000;	/* always 8k */
	gicd_size = 0x1000;	/* always 4k */
	gich_size = 0x2000;	/* always 8k */
	gicv_size = 0x2000;	/* always 8k */
	gv2m_size = 0x1000;	/* always 4k */

	ASSERT3P(mg, !=, NULL);
	ASSERT3P(rdip, !=, NULL);
	ASSERT3P(mg->mg_gicc, !=, NULL);
	ASSERT3U(mg->mg_ngicc, >, 0);
	ASSERT3U(mg->mg_ngicc, <=, 8);
	ASSERT3P(mg->mg_gicd, !=, NULL);
	ASSERT3U(mg->mg_ngicd, ==, 1);
	ASSERT0(mg->mg_ngicr);
	ASSERT0(mg->mg_ngits);

	gicd_addr = mg->mg_gicd->gicd->BaseAddress;
	VERIFY3P(gicd_addr, !=, 0);
	lowest_reg = gicd_addr;
	highest_reg = gicd_addr;
	highest_reg_size = gicd_size;

	for (gicc = mg->mg_gicc; gicc != NULL; gicc = gicc->next) {
		if (gicc_addr == 0)
			gicc_addr = gicc->gicc->BaseAddress;

		if (gicc->gicc->BaseAddress != gicc_addr) {
			panic("Inconsitent GICC base address in MADT. Expected "
			    "0x%lx, got 0x%lx",
			    gicc_addr, gicc->gicc->BaseAddress);
		}

		if (gich_addr == 0)
			gich_addr = gicc->gicc->GichBaseAddress;

		if (gicc->gicc->GichBaseAddress != gich_addr) {
			panic("Inconsitent GICH base address in MADT. Expected "
			    "0x%lx, got 0x%lx",
			    gich_addr, gicc->gicc->GichBaseAddress);
		}

		if (gicv_addr == 0)
			gicv_addr = gicc->gicc->GicvBaseAddress;

		if (gicc->gicc->GicvBaseAddress != gicv_addr) {
			panic("Inconsitent GICV base address in MADT. Expected "
			    "0x%lx, got 0x%lx",
			    gicv_addr, gicc->gicc->GicvBaseAddress);
		}

		if (vgic_intid == 0)
			vgic_intid = gicc->gicc->VgicInterrupt;

		if (gicc->gicc->VgicInterrupt != vgic_intid) {
			panic("Inconsitent VGIC maintenance INTID in MADT. "
			    "Expected %u, got %u",
			    vgic_intid, gicc->gicc->VgicInterrupt);
		}
	}

	if ((gich_addr == 0 && gicv_addr != 0) ||
	    (gicv_addr == 0 && gich_addr !=0)) {
		panic("Incoherent GIC virtualisation base addresses. Either "
		    "both must be zero, or neither may be zero. "
		    "GICH is 0x%lx, GICV is 0x%lx.", gich_addr, gicv_addr);
	}

	if (gich_addr != 0 && vgic_intid == 0) {
		cmn_err(CE_WARN, "Virtualization base addresses are set while "
		    "the VGIC maintenance interrupt is not. VGIC functionality "
		    "will be disabled.");
	}

	if (gicc_addr < lowest_reg) {
		lowest_reg = gicc_addr;
	} else if (gicc_addr > highest_reg) {
		highest_reg = gicc_addr;
		highest_reg_size = gicc_size;
	}

	if (gich_addr < lowest_reg) {
		lowest_reg = gich_addr;
	} else if (gich_addr > highest_reg) {
		highest_reg = gich_addr;
		highest_reg_size = gich_size;
	}

	if (gicv_addr < lowest_reg) {
		lowest_reg = gicv_addr;
	} else if (gicv_addr > highest_reg) {
		highest_reg = gicv_addr;
		highest_reg_size = gicv_size;
	}

	for (gv2m = mg->mg_gv2m; gv2m != NULL; gv2m = gv2m->next) {
		if (gv2m->gv2m->BaseAddress < lowest_reg) {
			lowest_reg = gv2m->gv2m->BaseAddress;
		} else if (gv2m->gv2m->BaseAddress > highest_reg) {
			highest_reg = gv2m->gv2m->BaseAddress;
			highest_reg_size = gv2m_size;
		}
	}

	if ((rv = ndi_prop_update_string_array(DDI_DEV_T_NONE, rdip,
	    "compatible", compatible, 1)) != DDI_PROP_SUCCESS)
		goto out;

	if ((rv = e_ddi_prop_update_int(DDI_DEV_T_NONE, rdip,
	    DDI_NO_AUTODETACH, 1)) != DDI_PROP_SUCCESS)
		goto out;

	if ((rv = ndi_prop_update_int(DDI_DEV_T_NONE, rdip,
	    "#interrupt-cells", 1)) != DDI_PROP_SUCCESS)
		goto out;

	if ((rv = ndi_prop_update_int(DDI_DEV_T_NONE, rdip,
	    "#address-cells", 2)) != DDI_PROP_SUCCESS)
		goto out;

	if ((rv = ndi_prop_update_int(DDI_DEV_T_NONE, rdip,
	    "#size-cells", 1)) != DDI_PROP_SUCCESS)
		goto out;

	if ((rv = ddi_prop_create(DDI_DEV_T_NONE, rdip,
	    DDI_PROP_CANSLEEP|DDI_PROP_HW_DEF, "interrupt-controller",
	    NULL, 0)) != DDI_PROP_SUCCESS)
		goto out;

	/*
	 * For GICv2 the first register is the distributor and the second is
	 * the CPU interface. The distributor has one 4k frame and the CPU
	 * interface has two.
	 *
	 * Note that we're bodging regspecs here, which rootnex knows how
	 * to undo.
	 */
	regspecs[0].regspec_bustype = (gicd_addr >> 32) & 0x0fffffff;
	regspecs[0].regspec_addr = gicd_addr & 0xffffffff;
	regspecs[0].regspec_size = gicd_size & 0xffffffff;
	regspecs[1].regspec_bustype = (gicc_addr >> 32) & 0x0fffffff;
	regspecs[1].regspec_addr = gicc_addr & 0xffffffff;
	regspecs[1].regspec_size = gicc_size & 0xffffffff;
	nregs = 2;

	/*
	 * When we have virtualisation extensions we add two registers to
	 * the configuration (virtual interface control and virtual CPU
	 * interface) and add an interrupt to service the virtual GIC.
	 *
	 * Our only other reason to add an interrupts entry would be when
	 * the GIC is chained to another interrupt controller, which will
	 * not be the case for a system GIC.
	 */
	if (gich_addr != 0 && gicv_addr != 0 && vgic_intid != 0) {
		if ((rv = ndi_prop_update_int_array(DDI_DEV_T_NONE, rdip,
		    "interrupts", (int *)&vgic_intid, 1) != DDI_PROP_SUCCESS))
			goto out;

		regspecs[2].regspec_bustype = (gich_addr >> 32) & 0x0fffffff;
		regspecs[2].regspec_addr = gich_addr & 0xffffffff;
		regspecs[2].regspec_size = gich_addr & 0xffffffff;

		regspecs[3].regspec_bustype = (gicv_addr >> 32) & 0x0fffffff;
		regspecs[3].regspec_addr = gicv_addr & 0xffffffff;
		regspecs[3].regspec_size = gicv_addr & 0xffffffff;

		nregs += 2;
	}

	CTASSERT((sizeof (regspecs[0]) / sizeof (int)) == 3);
	if ((rv = ndi_prop_update_int_array(DDI_DEV_T_NONE, rdip, "reg",
	    (int *)regspecs, nregs * 3)) != DDI_PROP_SUCCESS)
		goto out;

	/*
	 * interrupt-parent - Used for chaining GICs, which is something we
	 * won't see for the system GIC and something we're extremely unlikely
	 * to ever see. The notion of chaining GICs is unsupported in GICv3,
	 * where the CPU interface is through system registers.
	 */

	/*
	 * ranges - when we have a v2m we need to manufacture a ranges property
	 * that covers our lowest register to our highest register + highest
	 * register size. This is a simple identity mapping, and makes for a
	 * nice clean integration.
	 */
	if (mg->mg_ngv2m > 0) {
		VERIFY3U(lowest_reg, !=, 0);
		VERIFY3U(highest_reg, !=, 0);
		VERIFY3U(highest_reg_size, !=, 0);
		highest_reg_size =
		    ((highest_reg + highest_reg_size) - lowest_reg);
#if XXXARM
		uint32_t ranges[6] = {
			0,
			0,
			(uint32_t)((lowest_reg >> 32) & 0xffffffff),
			(uint32_t)(lowest_reg & 0xffffffff),
			(uint32_t)((highest_reg_size >> 32) & 0xffffffff),
			(uint32_t)(highest_reg_size & 0xffffffff)
		};
		if ((rv = ndi_prop_update_int_array(DDI_DEV_T_NONE, rdip,
		    "ranges", (int *)ranges, 6)) != DDI_PROP_SUCCESS)
			goto out;
#endif
	}

out:
	return (rv);
}

static int
gic_setup_v2_child(dev_info_t *rdip, ACPI_MADT_GENERIC_MSI_FRAME *v2m)
{
	int		rv;
	uint64_t	gv2m_size;
	struct regspec	rs;
	char		*compatible[] = {"arm,gic-v2m-frame"};

	ASSERT3P(rdip, !=, NULL);
	ASSERT3P(v2m, !=, NULL);
	VERIFY3U(v2m->BaseAddress, !=, 0);

	gv2m_size = 0x1000;	/* always 4k */

	if ((rv = ndi_prop_update_string_array(DDI_DEV_T_NONE, rdip,
	    "compatible", compatible, 1)) != DDI_PROP_SUCCESS)
		goto out;

	if ((rv = e_ddi_prop_update_int(DDI_DEV_T_NONE, rdip,
	    DDI_NO_AUTODETACH, 1)) != DDI_PROP_SUCCESS)
		goto out;

	if ((rv = ddi_prop_create(DDI_DEV_T_NONE, rdip,
	    DDI_PROP_CANSLEEP|DDI_PROP_HW_DEF,
	    "msi-controller", NULL, 0)) != DDI_PROP_SUCCESS)
		goto out;

	rs.regspec_bustype = (v2m->BaseAddress >> 32) & 0x0fffffff;
	rs.regspec_addr = (v2m->BaseAddress & 0xffffffff);
	rs.regspec_size = gv2m_size & 0xffffffff;
	CTASSERT((sizeof (rs) / sizeof (int)) == 3);

	if ((rv = ndi_prop_update_int_array(DDI_DEV_T_NONE, rdip, "reg",
	    (int *)&rs, 3)) != DDI_PROP_SUCCESS)
		goto out;

	if (v2m->Flags & ACPI_MADT_OVERRIDE_SPI_VALUES) {
		if ((rv = ndi_prop_update_int(DDI_DEV_T_NONE, rdip,
		    "arm,msi-base-spi", v2m->SpiBase)) != DDI_PROP_SUCCESS)
			goto out;

		if ((rv = ndi_prop_update_int(DDI_DEV_T_NONE, rdip,
		    "arm,msi-num-spis", v2m->SpiCount)) != DDI_PROP_SUCCESS)
			goto out;
	}

out:
	return (rv);
}

static int
gic_setup_v2_node(dev_info_t *dip, struct madt_gic *mg, dev_info_t **xdip)
{
	int			rv;
	struct gv2m_item	*gv2m;
	dev_info_t		*rdip;
	dev_info_t		*gdip;
	dev_info_t		*tdip;

	VERIFY3P(dip, !=, NULL);
	VERIFY3P(mg, !=, NULL);
	VERIFY3P(xdip, !=, NULL);
	VERIFY3P(*xdip, ==, NULL);

	if (mg->mg_ngicc == 0 || mg->mg_ngicc > 8)
		panic("GICv2 only supports up eight CPU interfaces, and must "
		    "have at least one CPU interface. "
		    "Found %u CPU interface(s)",
		    mg->mg_ngicc);
	VERIFY3P(mg->mg_gicc, !=, NULL);

	if (mg->mg_ngicd != 1)
		panic("One, and only one, GIC Distributor Interface must exist "
		    "in the MADT. Found %u GIC Distributor Interfaces",
		    mg->mg_ngicd);
	VERIFY3P(mg->mg_gicd, !=, NULL);

	VERIFY0(mg->mg_ngicr);
	VERIFY0(mg->mg_ngits);

	ndi_devi_alloc_sleep(dip, "intc",
	    (pnode_t)DEVI_SID_NODEID, &rdip);

	if ((rv = gic_setup_v2_device(rdip, mg)) != DDI_SUCCESS)
		goto out;

	if ((rv = ndi_devi_bind_driver(rdip, 0)) != NDI_SUCCESS)
		goto out;

	/*
	 * Add any MSI frames that are exposed in the MADT.
	 */

	for (gv2m = mg->mg_gv2m; gv2m != NULL; gv2m = gv2m->next) {
		gdip = NULL;
		VERIFY3P(gv2m->gv2m, !=, NULL);

		ndi_devi_alloc_sleep(rdip, "v2m",
		    (pnode_t)DEVI_SID_NODEID, &gdip);

		if ((rv = gic_setup_v2_child(gdip, gv2m->gv2m)) != DDI_SUCCESS)
			goto out;

		if ((rv = ndi_devi_bind_driver(gdip, 0)) != NDI_SUCCESS)
			goto out;
	}

out:
	if (rv == DDI_SUCCESS) {
		*xdip = rdip;
	} else {
		if ((gdip = ddi_get_child(rdip)) != NULL) {
			while (gdip != NULL) {
				tdip = ddi_get_next_sibling(gdip);
				(void) ndi_devi_offline(gdip, NDI_DEVI_REMOVE);
				gdip = tdip;
			}
		}

		(void) ndi_devi_offline(rdip, NDI_DEVI_REMOVE);
	}

	return (rv);
}

/*
 * See Documentation/devicetree/bindings/interrupt-controller/arm,gic-v3.txt in
 * the Linux kernel tree, or on https://www.kernel.org/doc/.
 */

static int
gic_setup_v3_device(dev_info_t *rdip, struct madt_gic *mg)
{
	int			rv;
	uint64_t		gicd_addr;
	uint64_t		gicd_size;
	uint64_t		gicr_size;
	uint64_t		gits_size;
	uint64_t		lowest_reg;
	uint64_t		highest_reg;
	uint64_t		highest_reg_size;
	struct gicc_item	*gicc;
	struct gicr_item	*gicr;
	struct gits_item	*gits;
	struct regspec		*regspecs;
	char			*compatible[] = {"arm,gic-v3"};
	uint_t			nreg;
	uint32_t		nredist_regions;
	uint32_t		i;
	uint32_t		vgic_maintenance_interrupt;

	VERIFY3P(rdip, !=, NULL);
	VERIFY3P(mg, !=, NULL);
	VERIFY3P(mg->mg_gicd, !=, NULL);

	vgic_maintenance_interrupt = 0;
	nreg = 1;		/* we always have a distributor */
	gicd_addr = 0;
	gicd_size = 0x10000;	/* always 64k */
	/* 128k for GICv3, 256k for GICv4 */
	gicr_size = mg->mg_gicd->gicd->Version > 3 ? 0x40000 : 0x20000;
	gits_size = 0x20000;	/*128k, seems to add another 64k frame in 4.1 */
	nredist_regions = 0;


	if (mg->mg_ngicc == 0)
		panic("Must have at least one CPU interface.");
	VERIFY3P(mg->mg_gicc, !=, NULL);

	for (gicc = mg->mg_gicc; gicc != NULL; gicc = gicc->next) {
		if (gicc->gicc->BaseAddress != 0)
			panic("GICv3 and GICv4 must use the system "
			    "register interface.");

		if (vgic_maintenance_interrupt != 0 &&
		    gicc->gicc->VgicInterrupt != vgic_maintenance_interrupt) {
			panic("Inconsitent BGIC maintenance interrupt in MADT. "
			    "Expected %u, got %u.", vgic_maintenance_interrupt,
			    gicc->gicc->VgicInterrupt);
		}
	}

	if (mg->mg_ngicd != 1)
		panic("One, and only one, GIC Distributor Interface must exist "
		    "in the MADT. Found %u GIC Distributor Interfaces",
		    mg->mg_ngicd);
	VERIFY3P(mg->mg_gicd, !=, NULL);

	VERIFY0(mg->mg_ngv2m);
	VERIFY3P(mg->mg_gv2m, ==, NULL);

	/*
	 * Anchor our range calculations on the GICD base address, which
	 * will always exist.
	 */
	gicd_addr = mg->mg_gicd->gicd->BaseAddress;
	VERIFY3P(gicd_addr, !=, 0);
	lowest_reg = gicd_addr;
	highest_reg = gicd_addr;
	highest_reg_size = gicd_size;

	/*
	 * When all redistributors are in the always-on power domain we will
	 * have GICR structures, describing the base and length of redistributor
	 * regions (which contain redistributors, matched to CPUs by the GIC
	 * driver).
	 */
	for (gicr = mg->mg_gicr; gicr != NULL; gicr = gicr->next) {
		if (gicr->gicr->BaseAddress < lowest_reg) {
			lowest_reg = gicr->gicr->BaseAddress;
		} else if (gicr->gicr->BaseAddress > highest_reg) {
			highest_reg = gicr->gicr->BaseAddress;
			highest_reg_size = gicr->gicr->Length;
		}

		nredist_regions++;
	}

	/*
	 * However, if we do not have GICR structures the distributor base
	 * addresses are stored on the CPU interface objects on a per-CPU basis
	 * and are of a fixed length (128k for GICv3, 256k for GICv4).
	 */
	if (mg->mg_ngicr == 0) {
		for (gicc = mg->mg_gicc; gicc != NULL; gicc = gicc->next) {
			if (gicc->gicc->GicrBaseAddress < lowest_reg) {
				lowest_reg = gicc->gicc->GicrBaseAddress;
			} else if (gicc->gicc->GicrBaseAddress > highest_reg) {
				highest_reg = gicc->gicc->GicrBaseAddress;
				highest_reg_size = gicr_size;
			}
		}

		nredist_regions++;
	}

	nreg += nredist_regions;

	/*
	 * XXXARM: inspect the registers to figure out our precise GIC version
	 */

	for (gits = mg->mg_gits; gits != NULL; gits = gits->next) {
		if (gits->gits->BaseAddress < lowest_reg) {
			lowest_reg = gits->gits->BaseAddress;
		} else if (gits->gits->BaseAddress > highest_reg) {
			highest_reg = gits->gits->BaseAddress;
			highest_reg_size += gits_size;
		}
	}

	if ((rv = ndi_prop_update_string_array(DDI_DEV_T_NONE, rdip,
	    "compatible", compatible, 1)) != DDI_PROP_SUCCESS)
		goto out;

	if ((rv = e_ddi_prop_update_int(DDI_DEV_T_NONE, rdip,
	    DDI_NO_AUTODETACH, 1)) != DDI_PROP_SUCCESS)
		goto out;

	if ((rv = ndi_prop_update_int(DDI_DEV_T_NONE, rdip,
	    "#interrupt-cells", 1)) != DDI_PROP_SUCCESS)
		goto out;

	if ((rv = ndi_prop_update_int(DDI_DEV_T_NONE, rdip,
	    "#address-cells", 2)) != DDI_PROP_SUCCESS)
		goto out;

	if ((rv = ndi_prop_update_int(DDI_DEV_T_NONE, rdip,
	    "#size-cells", 1)) != DDI_PROP_SUCCESS)
		goto out;

	if ((rv = ddi_prop_create(DDI_DEV_T_NONE, rdip,
	    DDI_PROP_CANSLEEP|DDI_PROP_HW_DEF, "interrupt-controller",
	    NULL, 0)) != DDI_PROP_SUCCESS)
		goto out;

	if ((rv = ndi_prop_update_int(DDI_DEV_T_NONE, rdip,
	    "#redistributor-regions", nredist_regions)) != DDI_PROP_SUCCESS)
		goto out;

	/*
	 * redistributor-stride - Unnecessary in ACPI-based implementations, as
	 * there are no padding pages.
	 */

	if (vgic_maintenance_interrupt != 0) {
		if ((rv = ndi_prop_update_int_array(DDI_DEV_T_NONE, rdip,
		    "interrupts", (int *)&vgic_maintenance_interrupt, 1)) !=
		    DDI_PROP_SUCCESS) {
			goto out;
		}
	}

	/*
	 * msi-controller - iff Message Based Interrupt AND mbi-ranges present
	 * mbi-ranges - [start, size] of MBIs
	 * mbi-alias - not 100% sure, but used for hardware isolation
	 *
	 * XXXARM: We could fall back to MBI-based MSI when we have no ITS.
	 *
	 * ... but what would the ranges be?
	 */

	regspecs = kmem_zalloc(sizeof (struct regspec) * nreg, KM_SLEEP);
	i = 0;

	regspecs[0].regspec_bustype = (gicd_addr >> 32) & 0x0fffffff;
	regspecs[0].regspec_addr = gicd_addr & 0xffffffff;
	regspecs[0].regspec_size = gicd_size & 0xffffffff;

	for (gicr = mg->mg_gicr; gicr != NULL; gicr = gicr->next) {
		i += 1;
		VERIFY3U(i, <, nreg);
		regspecs[i].regspec_bustype =
		    (gicr->gicr->BaseAddress >> 32) & 0x0fffffff;
		regspecs[i].regspec_addr = gicr->gicr->BaseAddress & 0xffffffff;
		regspecs[i].regspec_size = gicr->gicr->Length;
	}

	if (mg->mg_ngicr == 0) {
		VERIFY3U(i, ==, 1);
		for (gicc = mg->mg_gicc; gicc != NULL; gicc = gicc->next) {
			i += 1;
			VERIFY3U(i, <, nreg);
			regspecs[i].regspec_bustype =
			    (gicc->gicc->GicrBaseAddress >> 32) & 0x0fffffff;
			regspecs[i].regspec_addr =
			    gicc->gicc->GicrBaseAddress & 0xffffffff;
			regspecs[i].regspec_size = gicr_size & 0xffffffff;
		}
	}

	if ((rv = ndi_prop_update_int_array(DDI_DEV_T_NONE, rdip,
	    "reg", (int *)regspecs,
	    (sizeof (struct regspec) * nreg) / sizeof (int))) !=
	    DDI_PROP_SUCCESS) {
		kmem_free(regspecs, sizeof (struct regspec) * nreg);
		goto out;
	}

	kmem_free(regspecs, sizeof (struct regspec) * nreg);

	/*
	 * ranges - when we have one or more ITS children we need to
	 * manufacture a ranges property that covers our lowest register to
	 * our highest register + highest register size. This is a simple
	 * identity mapping, and makes for a nice clean integration.
	 */
	if (mg->mg_ngits > 0) {
		VERIFY3U(lowest_reg, !=, 0);
		VERIFY3U(highest_reg, !=, 0);
		VERIFY3U(highest_reg_size, !=, 0);
		highest_reg_size =
		    ((highest_reg + highest_reg_size) - lowest_reg);
#if XXXARM
		uint32_t ranges[6] = {
			0,
			0,
			(uint32_t)((lowest_reg >> 32) & 0xffffffff),
			(uint32_t)(lowest_reg & 0xffffffff),
			(uint32_t)((highest_reg_size >> 32) & 0xffffffff),
			(uint32_t)(highest_reg_size & 0xffffffff)
		};
		if ((rv = ndi_prop_update_int_array(DDI_DEV_T_NONE, rdip,
		    "ranges", (int *)ranges, 6)) != DDI_PROP_SUCCESS)
			goto out;
#endif
	}

out:
	return (rv);
}

static int
gic_setup_v3_child(dev_info_t *rdip, ACPI_MADT_GENERIC_TRANSLATOR *gits)
{
	int		rv;
	uint64_t	gits_size;
	struct regspec	rs;
	char		*compatible[] = {"arm,gic-v3-its"};

	gits_size = 0x20000;	/*128k, seems to add another 64k frame in 4.1 */

	if ((rv = ndi_prop_update_string_array(DDI_DEV_T_NONE, rdip,
	    "compatible", compatible, 1)) != DDI_PROP_SUCCESS)
		goto out;

	if ((rv = e_ddi_prop_update_int(DDI_DEV_T_NONE, rdip,
	    DDI_NO_AUTODETACH, 1)) != DDI_PROP_SUCCESS)
		goto out;

	if ((rv = ddi_prop_create(DDI_DEV_T_NONE, rdip,
	    DDI_PROP_CANSLEEP|DDI_PROP_HW_DEF, "msi-controller",
	    NULL, 0)) != DDI_PROP_SUCCESS)
		goto out;

	if ((rv = ndi_prop_update_int(DDI_DEV_T_NONE, rdip,
	    "#msi-cells", 1)) != DDI_PROP_SUCCESS)
		goto out;

	if ((rv = ndi_prop_update_int(DDI_DEV_T_NONE, rdip,
	    "illumos,translation-id", gits->TranslationId)) != DDI_PROP_SUCCESS)
		goto out;

	rs.regspec_bustype = (gits->BaseAddress >> 32) & 0x0fffffff;
	rs.regspec_addr = gits->BaseAddress & 0xffffffff;
	rs.regspec_size = gits_size & 0xffffffff;
	CTASSERT(sizeof (rs) / sizeof (int) == 3);

	if ((rv = ndi_prop_update_int_array(DDI_DEV_T_NONE, rdip,
	    "reg", (int *)&rs, 3)) != DDI_PROP_SUCCESS)
		goto out;

out:
	return (rv);
}

static int
gic_setup_v3_node(dev_info_t *dip, struct madt_gic *mg, dev_info_t **xdip)
{
	int			rv;
	dev_info_t		*rdip;
	dev_info_t		*gdip;
	dev_info_t		*tdip;
	struct gicc_item	*gicc;
	struct gits_item	*gits;
	uint32_t		vgic_maintenance_interrupt;

	VERIFY3P(mg, !=, NULL);
	VERIFY3P(mg->mg_gicd, !=, NULL);

	vgic_maintenance_interrupt = 0;

	VERIFY3P(mg, !=, NULL);
	VERIFY3P(xdip, !=, NULL);
	VERIFY3P(*xdip, ==, NULL);

	if (mg->mg_ngicc == 0)
		panic("Must have at least one CPU interface.");
	VERIFY3P(mg->mg_gicc, !=, NULL);

	for (gicc = mg->mg_gicc; gicc != NULL; gicc = gicc->next) {
		if (gicc->gicc->BaseAddress != 0)
			panic("GICv3 and GICv4 must use the system "
			    "register interface.");

		if (vgic_maintenance_interrupt != 0 &&
		    gicc->gicc->VgicInterrupt != vgic_maintenance_interrupt) {
			panic("Inconsitent BGIC maintenance interrupt in MADT. "
			    "Expected %u, got %u.", vgic_maintenance_interrupt,
			    gicc->gicc->VgicInterrupt);
		}
	}

	if (mg->mg_ngicd != 1)
		panic("One, and only one, GIC Distributor Interface must exist "
		    "in the MADT. Found %u GIC Distributor Interfaces",
		    mg->mg_ngicd);
	VERIFY3P(mg->mg_gicd, !=, NULL);

	VERIFY0(mg->mg_ngv2m);
	VERIFY3P(mg->mg_gv2m, ==, NULL);
	/* XXXARM: rules around the ITS? */

	ndi_devi_alloc_sleep(dip, "intc",
	    (pnode_t)DEVI_SID_NODEID, &rdip);

	if ((rv = gic_setup_v3_device(rdip, mg)) != DDI_SUCCESS)
		goto out;

	if ((rv = ndi_devi_bind_driver(rdip, 0)) != NDI_SUCCESS)
		goto out;

	for (gits = mg->mg_gits; gits != NULL; gits = gits->next) {
		gdip = NULL;

		ndi_devi_alloc_sleep(rdip, "its",
		    (pnode_t)DEVI_SID_NODEID, &gdip);

		if ((rv = gic_setup_v3_child(gdip, gits->gits)) != DDI_SUCCESS)
			goto out;

		if ((rv = ndi_devi_bind_driver(gdip, 0)) != NDI_SUCCESS)
			goto out;
	}

out:
	if (rv == DDI_SUCCESS) {
		*xdip = rdip;
	} else {
		if ((gdip = ddi_get_child(rdip)) != NULL) {
			while (gdip != NULL) {
				tdip = ddi_get_next_sibling(gdip);
				(void) ndi_devi_offline(gdip, NDI_DEVI_REMOVE);
				gdip = tdip;
			}
		}

		(void) ndi_devi_offline(rdip, NDI_DEVI_REMOVE);
	}

	return (rv);
}

static int
gic_setup_device_node(dev_info_t **xdip)
{
	int				rv;
	ACPI_SUBTABLE_HEADER		*item;
	ACPI_SUBTABLE_HEADER		*end;

	struct madt_gic			mg;
	struct gicc_item		*gicc;
	struct gicd_item		*gicd;
	struct gv2m_item		*gv2m;
	struct gicr_item		*gicr;
	struct gits_item		*gits;

	VERIFY3P(xdip, !=, NULL);
	VERIFY3P(*xdip, ==, NULL);

	memset(&mg, 0, sizeof (mg));

	if (AcpiGetTable(ACPI_SIG_MADT, 1,
	    (ACPI_TABLE_HEADER **)&mg.mg_madt) != AE_OK)
		panic("Unable to get the MADT");

	end = (ACPI_SUBTABLE_HEADER *)
	    (mg.mg_madt->Header.Length + (uintptr_t)mg.mg_madt);
	item = (ACPI_SUBTABLE_HEADER *)
	    ((uintptr_t)mg.mg_madt + sizeof (*mg.mg_madt));

	while (item < end) {
		switch (item->Type) {
		case ACPI_MADT_TYPE_GENERIC_INTERRUPT:
			gicc = kmem_zalloc(sizeof (*gicc), KM_SLEEP);
			gicc->gicc = (ACPI_MADT_GENERIC_INTERRUPT *)item;
			if (mg.mg_gicc == NULL) {
				mg.mg_gicc = gicc;
			} else {
				struct gicc_item *t = mg.mg_gicc;
				while (t->next != NULL)
					t = t->next;
				t->next = gicc;
			}
			mg.mg_ngicc++;
			break;
		case ACPI_MADT_TYPE_GENERIC_DISTRIBUTOR:
			gicd = kmem_zalloc(sizeof (*gicd), KM_SLEEP);
			gicd->gicd = (ACPI_MADT_GENERIC_DISTRIBUTOR *)item;
			if (mg.mg_gicd == NULL) {
				mg.mg_gicd = gicd;
			} else {
				struct gicd_item *t = mg.mg_gicd;
				while (t->next != NULL)
					t = t->next;
				t->next = gicd;
			}
			mg.mg_ngicd++;
			break;
		case ACPI_MADT_TYPE_GENERIC_MSI_FRAME:
			gv2m = kmem_zalloc(sizeof (*gv2m), KM_SLEEP);
			gv2m->gv2m = (ACPI_MADT_GENERIC_MSI_FRAME *)item;
			if (mg.mg_gv2m == NULL) {
				mg.mg_gv2m = gv2m;
			} else {
				struct gv2m_item *t = mg.mg_gv2m;
				while (t->next != NULL)
					t = t->next;
				t->next = gv2m;
			}
			mg.mg_ngv2m++;
			break;
		case ACPI_MADT_TYPE_GENERIC_REDISTRIBUTOR:
			gicr = kmem_zalloc(sizeof (*gicr), KM_SLEEP);
			gicr->gicr =
			    (ACPI_MADT_GENERIC_REDISTRIBUTOR *)item;
			if (mg.mg_gicr == NULL) {
				mg.mg_gicr = gicr;
			} else {
				struct gicr_item *t = mg.mg_gicr;
				while (t->next != NULL)
					t = t->next;
				t->next = gicr;
			}
			mg.mg_ngicr++;
			break;
		case ACPI_MADT_TYPE_GENERIC_TRANSLATOR:
			gits = kmem_zalloc(sizeof (*gits), KM_SLEEP);
			gits->gits = (ACPI_MADT_GENERIC_TRANSLATOR *)item;
			if (mg.mg_gits == NULL) {
				mg.mg_gits = gits;
			} else {
				struct gits_item *t = mg.mg_gits;
				while (t->next != NULL)
					t = t->next;
				t->next = gits;
			}
			mg.mg_ngits++;
			break;
		default:
			cmn_err(CE_WARN, "gic_autoconfig: unhandled interrupt "
			    "controller structure type: %u", item->Type);
			break;
		}

		item = (ACPI_SUBTABLE_HEADER *)((uintptr_t)item + item->Length);
	}

	ASSERT(mg.mg_ngicd == 1);
	if (mg.mg_ngicd != 1)
		panic("Expected 1 GIC distributor, found %u", mg.mg_ngicd);

	VERIFY3P(mg.mg_gicd, !=, NULL);
	VERIFY3P(mg.mg_gicd->gicd, !=, NULL);
	ASSERT(mg.mg_gicd->gicd->Version >= 2);	/* GICv1 is unsupported */
	ASSERT(mg.mg_gicd->gicd->Version <= 4);	/* GICv5 is unreleased */
	if (mg.mg_gicd->gicd->Version == 0)
		panic("Retrieving GIC version from hardware is unsupported in "
		    "illumos, as there is no portable interface to divine "
		    "this information. Please fix your firmware to declare "
		    "the GIC version.");
	if (mg.mg_gicd->gicd->Version < 2 || mg.mg_gicd->gicd->Version > 4)
		panic("Unsupported GIC version %u", mg.mg_gicd->gicd->Version);

	switch (mg.mg_gicd->gicd->Version) {
	case 2:
		rv = gic_setup_v2_node(ddi_root_node(), &mg, xdip);
		break;
	case 3:	/* fallthrough */
	case 4:
		rv = gic_setup_v3_node(ddi_root_node(), &mg, xdip);
		break;
	default:
		panic("Unexpected GIC version %u", mg.mg_gicd->gicd->Version);
	}

	while (mg.mg_gicc != NULL) {
		gicc = mg.mg_gicc->next;
		kmem_free(mg.mg_gicc, sizeof (*mg.mg_gicc));
		mg.mg_gicc = gicc;
	}

	while (mg.mg_gicd != NULL) {
		gicd = mg.mg_gicd->next;
		kmem_free(mg.mg_gicd, sizeof (*mg.mg_gicd));
		mg.mg_gicd = gicd;
	}

	while (mg.mg_gv2m != NULL) {
		gv2m = mg.mg_gv2m->next;
		kmem_free(mg.mg_gv2m, sizeof (*mg.mg_gv2m));
		mg.mg_gv2m = gv2m;
	}

	while (mg.mg_gicr != NULL) {
		gicr = mg.mg_gicr->next;
		kmem_free(mg.mg_gicr, sizeof (*mg.mg_gicr));
		mg.mg_gicr = gicr;
	}

	while (mg.mg_gits != NULL) {
		gits = mg.mg_gits->next;
		kmem_free(mg.mg_gits, sizeof (*mg.mg_gits));
		mg.mg_gits = gits;
	}

	AcpiPutTable((ACPI_TABLE_HEADER *)mg.mg_madt);
	return (rv);
}

/*
 * This function is invoked twice: first time, with reprogram=0 to
 * set up the GIC portion of the device tree. The second time is
 * used to attach the GIC, since it's needed really early.
 *
 * The attached GIC will register itself with the interrupt frameworks
 * so that it is usable by the system.
 */
static void
pic_probe(int reprogram)
{
	static dev_info_t *rdip = NULL;
	dev_info_t *cdip;

	if (reprogram == 0) {
		VERIFY3P(rdip, ==, NULL);
		if (gic_setup_device_node(&rdip) != DDI_SUCCESS)
			panic("Unable to set up GIC device node");
		VERIFY3P(rdip, !=, NULL);
		return;
	}

	VERIFY3P(rdip, !=, NULL);
	if (ndi_devi_online(rdip, 0) != DDI_SUCCESS)
		panic("Unable to online the GIC device node");

	for (cdip = ddi_get_child(rdip);
	    cdip != NULL;
	    cdip = ddi_get_next_sibling(cdip)) {
		if (ndi_devi_online(cdip, 0) != DDI_SUCCESS)
			panic("Unable to online a GIC device child node");
	}
}
