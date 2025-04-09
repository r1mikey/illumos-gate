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
 * Copyright 2026 Michael van der Westhuizen
 */

/*
 * ACPI _OSC (Operating System Capabilities) Evaluation
 *
 * This module implements two levels of ACPI _OSC negotiation for the
 * aarch64 SBBR platform:
 *
 * 1. Platform-wide \_SB._OSC
 *
 *    Declares OS-level platform capabilities to the firmware.  Called
 *    once during acpidev root initialisation, before any PCIe bridge
 *    enumeration.  Uses the Platform-wide OSPM Capabilities UUID
 *    defined in ACPI 4.0+.
 *
 *    Currently we declare NO support for CPPC (Collaborative Processor
 *    Performance Control) or LPI (Low Power Idle) because the required
 *    frameworks do not exist on aarch64 yet.  The call is still valuable
 *    because it informs the firmware that an _OSC-aware OS is running.
 *
 * 2. Per-bridge PCIe Host Bridge _OSC
 *
 *    Negotiates control of PCIe hierarchy features (native hotplug, AER,
 *    PCIe capability structure) with the firmware on a per-host-bridge
 *    basis.  Called from pcierc_attach() via weak symbol.  Uses the PCI
 *    Host Bridge _OSC UUID from the PCI Firmware Specification 3.0.
 *
 *    The MCFG code tags each ecam dip with its ACPI companion handle
 *    (via acpica_tag_devinfo()), so acpica_get_handle() works from
 *    pcierc_attach context.
 *
 * Without _OSC evaluation, firmware retains control of PCIe error
 * handling, hotplug, and device management.  On some platforms (notably
 * Ampere Altra), this means firmware-initialised devices (e.g. xHCI
 * used for USB console) may not be properly quiesced when the OS takes
 * over, leading to rogue DMA after ExitBootServices.
 *
 * Future work:
 *   - CPPC support (bit 6 of \_SB._OSC) requires a cpupm/acpipm
 *     framework for aarch64, which does not yet exist.
 *   - LPI support (bit 7 of \_SB._OSC) requires processor idle state
 *     management for aarch64, which does not yet exist.
 *   - The entire cpupm/acpipm power management subsystem needs to be
 *     ported to aarch64 before either CPPC or LPI can be declared.
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/acpidev_osc.h>

/*
 * Platform-wide OSPM Capabilities UUID (ACPI 4.0+)
 * 0811b06e-4a27-44f9-8d60-3cbbc22e7b48
 */
static uint8_t acpidev_osc_plat_uuid[16] = {
	0x6e, 0xb0, 0x11, 0x08, 0x27, 0x4a, 0xf9, 0x44,
	0x8d, 0x60, 0x3c, 0xbb, 0xc2, 0x2e, 0x7b, 0x48
};

/*
 * PCI Host Bridge _OSC UUID (PCI Firmware Specification 3.0)
 * 33db4d5b-1ff7-401c-9657-7441c03dd766
 */
static uint8_t acpidev_osc_pcie_uuid[16] = {
	0x5b, 0x4d, 0xdb, 0x33, 0xf7, 0x1f, 0x1c, 0x40,
	0x96, 0x57, 0x74, 0x41, 0xc0, 0x3d, 0xd7, 0x66
};

/* _OSC Status DWORD bit definitions (common to both UUIDs) */
#define	OSC_STS_QUERY		0x01	/* Query Support Flag */
#define	OSC_STS_FAILED		0x02	/* _OSC failure */
#define	OSC_STS_INV_UUID	0x04	/* Unrecognised UUID */
#define	OSC_STS_INV_REV		0x08	/* Unrecognised revision */
#define	OSC_STS_CAPS_MASKED	0x10	/* Capabilities masked */

#define	OSC_STS_ERRORS	\
	(OSC_STS_FAILED | OSC_STS_INV_UUID | OSC_STS_INV_REV)

/*
 * Platform-wide \_SB._OSC Support Field (DWORD 2)
 *
 * Each bit requires framework support that does not yet exist on
 * aarch64.  Defined here for documentation; none are set today.
 */
#define	PLAT_OSC_PR_OST		0x0001	/* _PR._OST extensions */
#define	PLAT_OSC_PROC_AGG	0x0002	/* Processor aggregator */
#define	PLAT_OSC_APEI		0x0004	/* APEI support */
#define	PLAT_OSC_IDLE		0x0008	/* Platform-wide idle */
#define	PLAT_OSC_CORE_OFFLINE	0x0010	/* Core off-lining */
#define	PLAT_OSC_SYS_UPDATE	0x0020	/* System update */
#define	PLAT_OSC_CPPC		0x0040	/* CPPC (ACPI 5.0+) */
#define	PLAT_OSC_LPI		0x0080	/* LPI (ACPI 6.0+) */

/* PCI Host Bridge _OSC Support Field (DWORD 2) */
#define	PCIE_OSC_SUP_EXT_CFG	0x01	/* Extended PCI Config Ops */
#define	PCIE_OSC_SUP_ACT_PM	0x02	/* Active State PM */
#define	PCIE_OSC_SUP_CLK_PM	0x04	/* Clock PM Capability */
#define	PCIE_OSC_SUP_SEGS	0x08	/* PCI Segment Groups */
#define	PCIE_OSC_SUP_MSI	0x10	/* MSI */

/* PCI Host Bridge _OSC Control Field (DWORD 3) */
#define	PCIE_OSC_CTL_NAT_HP	0x01	/* Native Hot Plug */
#define	PCIE_OSC_CTL_SHPC_HP	0x02	/* SHPC Native Hot Plug */
#define	PCIE_OSC_CTL_NAT_PM	0x04	/* Native Power Mgmt */
#define	PCIE_OSC_CTL_AER	0x08	/* Adv Error Reporting */
#define	PCIE_OSC_CTL_CAPS	0x10	/* PCIe Cap Structure */

/* What we declare as supported (mirrors i86pc) */
#define	PCIE_OSC_SUPPORT_INIT	\
	(PCIE_OSC_SUP_EXT_CFG | PCIE_OSC_SUP_ACT_PM | \
	PCIE_OSC_SUP_CLK_PM | PCIE_OSC_SUP_MSI | PCIE_OSC_SUP_SEGS)

/*
 * What we request control of.
 *
 * TODO: Add PCIE_OSC_CTL_NAT_HP and PCIE_OSC_CTL_NAT_PM once native
 * PCIe hotplug is implemented on aarch64.  On i86pc these are
 * conditionally requested based on hotplug controller presence;
 * the callsite in acpidev_pcie_osc() below will need the same
 * conditional logic (see pcieb_x86.c / pcie_acpi_eval_osc()).
 */
#define	PCIE_OSC_CONTROL_INIT	\
	(PCIE_OSC_CTL_AER | PCIE_OSC_CTL_CAPS)

/* Property name for granted PCIe _OSC control bits */
#define	ACPIDEV_OSC_PROP	"pcie-osc-control"

/*
 * Evaluate an _OSC method.  Common helper for both platform-wide and
 * per-bridge calls.
 *
 * uuid:     16-byte UUID identifying the _OSC caller
 * osc_hdl:  ACPI handle of the _OSC method to evaluate
 * revision: _OSC revision ID (currently always 1)
 * ndwords:  number of capability DWORDs (excluding status DWORD)
 * caps:     capability DWORD array (ndwords entries); on successful
 *           return, contains the firmware's response
 *
 * Returns AE_OK on success, ACPI error otherwise.
 */
static ACPI_STATUS
acpidev_osc_eval(uint8_t *uuid, ACPI_HANDLE osc_hdl,
    uint32_t revision, uint32_t ndwords, uint32_t *caps)
{
	ACPI_OBJECT_LIST	arglist;
	ACPI_OBJECT		args[4];
	ACPI_BUFFER		rb;
	ACPI_STATUS		status;
	uint32_t		*rbuf;
	uint32_t		total_dw = ndwords + 1;
	uint32_t		buf_len = total_dw * sizeof (uint32_t);
	uint32_t		*buf;
	uint32_t		i;

	/*
	 * Build the capabilities buffer: DWORD 0 is the status/query
	 * word (0 = not a query), followed by ndwords capability
	 * DWORDs.
	 */
	buf = kmem_zalloc(buf_len, KM_SLEEP);
	buf[0] = 0;
	for (i = 0; i < ndwords; i++)
		buf[i + 1] = caps[i];

	/* arg0: UUID */
	args[0].Type = ACPI_TYPE_BUFFER;
	args[0].Buffer.Length = 16;
	args[0].Buffer.Pointer = uuid;

	/* arg1: Revision ID */
	args[1].Type = ACPI_TYPE_INTEGER;
	args[1].Integer.Value = revision;

	/* arg2: Count of DWORDs in capabilities buffer */
	args[2].Type = ACPI_TYPE_INTEGER;
	args[2].Integer.Value = total_dw;

	/* arg3: Capabilities Buffer */
	args[3].Type = ACPI_TYPE_BUFFER;
	args[3].Buffer.Length = buf_len;
	args[3].Buffer.Pointer = (void *)buf;

	arglist.Count = 4;
	arglist.Pointer = args;

	rb.Length = ACPI_ALLOCATE_BUFFER;
	rb.Pointer = NULL;

	status = AcpiEvaluateObjectTyped(osc_hdl, NULL, &arglist,
	    &rb, ACPI_TYPE_BUFFER);

	kmem_free(buf, buf_len);

	if (ACPI_FAILURE(status))
		return (status);

	/* LINTED pointer alignment */
	rbuf = (uint32_t *)
	    ((ACPI_OBJECT *)rb.Pointer)->Buffer.Pointer;

	/* Check the status DWORD for hard errors */
	if (rbuf[0] & OSC_STS_ERRORS) {
		if (rbuf[0] & OSC_STS_INV_UUID)
			cmn_err(CE_NOTE, "!acpidev: _OSC: firmware "
			    "does not recognise UUID");
		if (rbuf[0] & OSC_STS_INV_REV)
			cmn_err(CE_NOTE, "!acpidev: _OSC: firmware "
			    "does not support revision");
		if (rbuf[0] & OSC_STS_FAILED)
			cmn_err(CE_NOTE, "!acpidev: _OSC: "
			    "evaluation failed");
		AcpiOsFree(rb.Pointer);
		return (AE_ERROR);
	}

	if (rbuf[0] & OSC_STS_CAPS_MASKED) {
		cmn_err(CE_NOTE, "!acpidev: _OSC: some capabilities "
		    "were masked by firmware");
	}

	/* Copy back the response capability DWORDs */
	for (i = 0; i < ndwords; i++)
		caps[i] = rbuf[i + 1];

	AcpiOsFree(rb.Pointer);
	return (AE_OK);
}

/*
 * Evaluate \_SB._OSC -- platform-wide OS capability declaration.
 *
 * Called once during acpidev root initialisation, before any PCIe
 * bridge enumeration begins.  Tells the firmware what platform-level
 * features the OS supports.
 *
 * Currently we declare NO support for any platform capabilities
 * (CPPC, LPI, processor aggregator, etc.) because the required
 * frameworks do not exist on aarch64 yet.  The call is still
 * valuable because it informs the firmware that an _OSC-aware OS
 * is present.
 */
void
acpidev_osc_init(void)
{
	ACPI_HANDLE	sb_hdl;
	ACPI_HANDLE	osc_hdl;
	ACPI_STATUS	status;
	uint32_t	caps[1];

	/* Find \_SB */
	status = AcpiGetHandle(ACPI_ROOT_OBJECT, "\\_SB", &sb_hdl);
	if (ACPI_FAILURE(status)) {
		cmn_err(CE_NOTE,
		    "!acpidev: _OSC: \\_SB not found");
		return;
	}

	/* Check if _OSC exists under \_SB */
	status = AcpiGetHandle(sb_hdl, "_OSC", &osc_hdl);
	if (ACPI_FAILURE(status)) {
		/* No \_SB._OSC -- nothing to negotiate. */
		return;
	}

	/*
	 * Build capabilities:
	 *   Bit 6 (CPPC): 0 -- not supported
	 *   Bit 7 (LPI):  0 -- not supported
	 *
	 * TODO: Set PLAT_OSC_CPPC once cpupm/acpipm is ported
	 *       to aarch64.
	 * TODO: Set PLAT_OSC_LPI once processor idle management
	 *       is ported to aarch64.
	 */
	caps[0] = 0;

	status = acpidev_osc_eval(acpidev_osc_plat_uuid, osc_hdl,
	    1, 1, caps);
	if (ACPI_FAILURE(status)) {
		cmn_err(CE_NOTE, "!acpidev: \\_SB._OSC evaluation "
		    "failed (status 0x%x)", status);
		return;
	}

	cmn_err(CE_CONT, "?acpidev: \\_SB._OSC: platform "
	    "capabilities negotiated (granted 0x%x)\n", caps[0]);
}

/*
 * Evaluate _OSC on a PCIe host bridge.
 *
 * Called from pcierc_attach() via weak symbol for each PCIe root
 * complex.  Negotiates OS control of native hotplug, AER, and PCIe
 * capability structure access.  The granted control bits are stored
 * as an integer property on the bridge dip for later use.
 *
 * Returns DDI_SUCCESS if _OSC was successfully evaluated (even if
 * some capabilities were masked), DDI_FAILURE otherwise.
 */
int
acpidev_pcie_osc(dev_info_t *dip)
{
	ACPI_HANDLE	bridge_hdl;
	ACPI_HANDLE	cur_hdl;
	ACPI_HANDLE	parent_hdl;
	ACPI_HANDLE	osc_hdl;
	ACPI_STATUS	status;
	uint32_t	caps[2];
	int		prev;

	/*
	 * Get the ACPI handle for this bridge.  The MCFG code
	 * tags each ecam dip with its ACPI companion.
	 */
	status = acpica_get_handle(dip, &bridge_hdl);
	if (ACPI_FAILURE(status)) {
		/*
		 * No ACPI companion -- this bridge wasn't matched
		 * to a DSDT object.  Nothing to negotiate.
		 */
		/* XXXMICHAEL: prefix with ! */
		dev_err(dip, CE_NOTE,
		    "acpidev: No ACPI handle tag for this controller");
		return (DDI_FAILURE);
	}

	/*
	 * Walk up the ACPI tree looking for an _OSC method,
	 * following the i86pc pattern.  Some firmware places _OSC
	 * on a parent scope rather than directly on the bridge.
	 */
	osc_hdl = NULL;
	cur_hdl = bridge_hdl;
	do {
		if (AcpiGetHandle(cur_hdl, "_OSC",
		    &osc_hdl) == AE_OK)
			break;
		osc_hdl = NULL;
	} while (AcpiGetParent(cur_hdl, &parent_hdl) == AE_OK &&
	    (cur_hdl = parent_hdl) != NULL);

	if (osc_hdl == NULL) {
		/* XXXMICHAEL: prefix with ! */
		dev_err(dip, CE_NOTE,
		    "acpidev: No _OSC method found");
		/* No _OSC method found. */
		return (DDI_FAILURE);
	}

	/*
	 * DWORD 1 (caps[0]): Support Field
	 * DWORD 2 (caps[1]): Control Field
	 *
	 * TODO: When native PCIe hotplug is implemented, detect
	 * hotplug controller presence and conditionally OR in
	 * PCIE_OSC_CTL_NAT_HP | PCIE_OSC_CTL_NAT_PM here
	 * (see pcieb_x86.c for the i86pc equivalent).
	 */
	caps[0] = PCIE_OSC_SUPPORT_INIT;
	caps[1] = PCIE_OSC_CONTROL_INIT;

	/*
	 * Preserve any capabilities granted by a prior _OSC call
	 * (e.g. across detach/reattach).  Per the _OSC spec, not
	 * re-requesting a previously granted bit relinquishes it.
	 */
	prev = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, ACPIDEV_OSC_PROP, 0);
	if (prev >= 0)
		caps[1] |= (uint32_t)prev;

	status = acpidev_osc_eval(acpidev_osc_pcie_uuid, osc_hdl,
	    1, 2, caps);
	if (ACPI_FAILURE(status)) {
		/* XXXMICHAEL: prefix with ! */
		cmn_err(CE_NOTE, "acpidev: PCIe _OSC evaluation "
		    "failed for %s (status 0x%x)",
		    ddi_node_name(dip), status);
		return (DDI_FAILURE);
	}

	/* Store granted control bits as a property */
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    ACPIDEV_OSC_PROP, (int)caps[1]);

	cmn_err(CE_CONT, "?acpidev: PCIe _OSC for %s%d: "
	    "granted control 0x%x\n",
	    ddi_driver_name(dip), ddi_get_instance(dip),
	    caps[1]);

	return (DDI_SUCCESS);
}
