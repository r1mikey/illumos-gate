#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/bootinfo.h>
#include <sys/efi.h>
#include <sys/efifb.h>
#include <sys/framebuffer.h>
#include <sys/smbios.h>
#include <sys/acpi/platform/acsolaris.h>
#undef strtoul
#include <sys/acpi/actypes.h>
#include <sys/acpi/actbl.h>
#include <string.h>
#include <sys/cpuid.h>
#include <asm/controlregs.h>
#include "dbg2.h"
#include "preload.h"
#include "uefi.h"

static EFI_SYSTEM_TABLE64 *systab = NULL;
static  EFI_RUNTIME_SERVICES64 *efirt = NULL;

static efi_guid_t smbios3 = SMBIOS3_TABLE_GUID;
static efi_guid_t acpi2 = EFI_ACPI_TABLE_GUID;  /* EFI_ACPI_20_TABLE_GUID */

static inline uint64_t
read_icc_sre_el1(void)
{
	uint64_t reg;
	__asm__ __volatile__("mrs %0, icc_sre_el1":"=r"(reg)::"memory");
	return (reg);
}

static inline void
write_icc_sre_el1(uint64_t reg)
{
	__asm__ __volatile__("msr icc_sre_el1, %0":"=r"(reg)::"memory");
}

static int
same_guids(efi_guid_t *g1, efi_guid_t *g2)
{
	int i;

	if (g1->time_low != g2->time_low)
		return (0);
	if (g1->time_mid != g2->time_mid)
		return (0);
	if (g1->time_hi_and_version != g2->time_hi_and_version)
		return (0);
	if (g1->clock_seq_hi_and_reserved != g2->clock_seq_hi_and_reserved)
		return (0);
	if (g1->clock_seq_low != g2->clock_seq_low)
		return (0);

	for (i = 0; i < 6; i++)
		if (g1->node_addr[i] != g2->node_addr[i])
			return (0);

	return (1);
}

/*
 * Find an ACPI table by signature in the XSDT.
 *
 * Assumes that ingest_uefi_systab has already been called.
 */
static ACPI_TABLE_HEADER *
find_acpi_table(ACPI_TABLE_XSDT *xsdt, const char *sig)
{
	ACPI_TABLE_HEADER *tab;
	UINT64 *xsdt_entry;
	size_t slen;
	UINT32 xsdt_entries;
	UINT32 i;

	if (xsdt == NULL)
		return (NULL);

	slen = strlen(sig);
	xsdt_entries = (xsdt->Header.Length -
	    sizeof(xsdt->Header)) / ACPI_XSDT_ENTRY_SIZE;
	xsdt_entry = &xsdt->TableOffsetEntry[0];
	tab = NULL;

	for (i = 0; i < xsdt_entries; ++i) {
		tab = (ACPI_TABLE_HEADER *)xsdt_entry[i];
		if (tab == NULL)
			continue;
		if (tab->Signature == NULL) {
			tab = NULL;
			continue;
		}
		if (strncmp(tab->Signature, sig, slen) == 0)
			break;
		tab = NULL;
	}

	if (tab == NULL)
		return (NULL);

	/*
	 * XXXARM: check table CRC32
	 */
	return (tab);
}

static int
ingest_madt(struct xboot_info *xbi, ACPI_TABLE_MADT *madt)
{
	ACPI_SUBTABLE_HEADER		*item;
	ACPI_SUBTABLE_HEADER		*end;
	ACPI_MADT_GENERIC_DISTRIBUTOR	*distp;
	uint8_t				gic_version;

	if (madt == NULL || xbi == NULL)
		return (-1);

	if (!(PFR0_GIC(read_id_aa64pfr0()) & PFR0_FEAT_GIC))
		dbg2_panic("ingest_madt: ID_AA64PRF0 does not indicate the presence of GICv3+\n");

	if (!(read_icc_sre_el1() & 0x1)) {
		write_icc_sre_el1(read_icc_sre_el1() | 0x1);
		if (!(read_icc_sre_el1() & 0x1))
			dbg2_panic("ingest_madt: Failed to enable GIC system register access\n");
	}

	end = (ACPI_SUBTABLE_HEADER *)(madt->Header.Length + (uintptr_t)madt);
	item = (ACPI_SUBTABLE_HEADER *)((uintptr_t)madt + sizeof (*madt));
	distp = NULL;

	/*
	 * There's a lot more we could (and perhaps should) do here, but for now
	 * we won't.
	 */
	while (item < end) {
		switch (item->Type) {
		case ACPI_MADT_TYPE_GENERIC_DISTRIBUTOR:
			if (distp != NULL)
				dbg2_panic("ingest_madt: Only one GIC Distributor (GICD) Structure allowed in MADT\n");

			distp = (ACPI_MADT_GENERIC_DISTRIBUTOR *)item;
			if (distp->GlobalIrqBase != 0)
				dbg2_panic("ingest_madt: System Vector Base is reserved and must be zero\n");

			gic_version = distp->Version;
			/* XXXARM: I'm not sure this is right */
			if (gic_version == 0) {
				volatile uint64_t *reg = (volatile uint64_t *)(distp->BaseAddress);
				gic_version = (((*reg) >> 4) & 0xf);
			}

			if (gic_version < 3)
				dbg2_panic("ingest_madt: GIC version must be 3 or greater\n");

			if (gic_version > 4)
				dbg2_printf("ingest_madt: Detected unrecognised GICv%u, assuming compatability with GICv3\n", gic_version);

			xbi->bi_gic_dist_base = (uint64_t)distp->BaseAddress;
			xbi->bi_gic_dist_size = 0x10000; /* 64KiB */
			xbi->bi_gic_version = (uint64_t)gic_version;
			break;
		default:
			break;
		}

		item = (ACPI_SUBTABLE_HEADER *)((uintptr_t)item + item->Length);
	}

	if (xbi->bi_gic_dist_base == 0 || xbi->bi_gic_version == 0)
		return (-1);

	return (0);
}

static int
ingest_fadt(struct xboot_info *xbi, ACPI_TABLE_FADT *fadt)
{
	if (!(fadt->ArmBootFlags & ACPI_FADT_PSCI_COMPLIANT))
		dbg2_panic("ingest_fadt: illumos requires PSCI");

	xbi->bi_psci_use_hvc = 0;
	xbi->bi_use_psci =
		(fadt->ArmBootFlags & ACPI_FADT_PSCI_COMPLIANT) ? 1 : 0;
	if (xbi->bi_use_psci &&
	    (fadt->ArmBootFlags & ACPI_FADT_PSCI_USE_HVC))
		xbi->bi_psci_use_hvc = 1;

	return(0);
}

/*
 * Use the UEFI system table and provided environment to locate the RSDP, XSDT
 *  and SMBIOS3 tables.
 */
static int
ingest_uefi_systab(EFI_SYSTEM_TABLE64 *st, struct xboot_info *xbi)
{
	EFI_CONFIGURATION_TABLE64 *cf;
	UINT32 i;
	efi_guid_t vguid;
	smbios_entry_t *smbios_entry;
	ACPI_TABLE_RSDP *rsdp;
	ACPI_TABLE_XSDT *xsdt;

	if (st == NULL)
		return (-1);

	efirt = (EFI_RUNTIME_SERVICES64 *)systab->RuntimeServices;
	if (efirt == NULL)
		return (-1);

	/*
	 * DEN0044B Server Base Boot Requirements, issue B (8 March 2016)
	 * SBBR version 1.0
	 * 3.4.4 Configuration Tables
	 *
	 * A compliant implementation MUST provide the EFI_ACPI_20_TABLE_GUID
	 * and the SMBIOS3_TABLE_GUID configuration tables.
	 *
	 * The ACPI tables must be at version ACPI 6.0 or later with a
	 * HW-Reduced ACPI model.
	 *
	 * The SMBIOS v3.0 tables must conform to version 3.0.0 or later of the
	 * SMBIOS Specification
	 *
	 * An oddity here is that the ACPI 6.4 spec says:
	 * "The OS loader must retrieve the pointer to the RSDP structure from
	 * the EFI System Table before assuming platform control via the EFI
	 * ExitBootServices interface."
	 *
	 * The FreeBSD and illumos loaders pass this through to us via the
	 * hint.acpi.0.rsdp environment variable.  This helps to keep us
	 * compliant, but we'll dredge around in the UEFI system table if this
	 * is not passed to us.
	 */
	if (!prekern_getenv_uint64(xbi, "hint.acpi.0.rsdp", &xbi->bi_rsdp))
		xbi->bi_rsdp = 0;

	cf = (EFI_CONFIGURATION_TABLE64 *)st->ConfigurationTable;
	if (cf == NULL)
		return (-1);

	for (i = 0; i < st->NumberOfTableEntries; ++i) {
		memcpy(&vguid, &cf[i].VendorGuid, sizeof(vguid));

		if (xbi->bi_rsdp == 0 && same_guids(&vguid, &acpi2))
			xbi->bi_rsdp = (uint64_t)cf[i].VendorTable;
		else if (xbi->bi_smbios3 == 0 &&
		    same_guids(&vguid, &smbios3))
			xbi->bi_smbios3 = (uint64_t)cf[i].VendorTable;

		if (xbi->bi_rsdp != 0 && xbi->bi_smbios3 != 0)
			break;
	}

	if (xbi->bi_rsdp == 0)
		return (-1);

	if (xbi->bi_smbios3 == 0)
		return (-1);

	smbios_entry = (smbios_entry_t *)xbi->bi_smbios3;
	if (strncmp(smbios_entry->ep30.smbe_eanchor, SMB3_ENTRY_EANCHOR,
	    SMB3_ENTRY_EANCHORLEN) != 0)
		return (-1);

	rsdp = (ACPI_TABLE_RSDP *)xbi->bi_rsdp;
	if (strncmp(rsdp->Signature, ACPI_SIG_RSDP,
	    strlen(ACPI_SIG_RSDP)) != 0)
		return (-1);

	if (rsdp->Revision < 2)
		return (-1);

	/*
	 * XXXARM: Check the RSDP CRC32
	 */
	/*
	 * DEN0044B Server Base Boot Requirements, issue B (8 March 2016)
	 * SBBR version 1.0
	 * 4.2.1 Mandatory ACPI Tables
	 *
	 * The following tables are mandatory for all compliant systems:
	 * RSDP: RsdtAddress mus be NULL, XsdtAddresss must be valid.
	 * XSDT: The RSDP must contain a pointer to this table.
	 * FADT: Must have the HW_REDUCED_ACPI flag set.
	 *       It is recommended that a server profiles is selected.
	 *       The ARM_BOOT_ARCH flags describe the presence of PSCI.
	 * DSDT: Essential configuration information.
	 * SSDT: Seems optional.
	 * MADT: Describes the GIC interrupt controllers.
	 *       When no PSCI, describes the parked address for secondary CPUs.
	 * GTDT: Describes the generic timer and watchdog.
	 * DBG2: Provides a standard debug port.
	 *       Describes the ARM SBSA Generic UART.
	 * SPCR: Config needed for headless operation.
	 *       Serial port type, location, and interrupts.
	 *       Revision 2 of the SPCR table or higher is required.
	 *       Must contain correct interrupt routing information.
	 *       The SPCR console device must be included in the DSDT.
	 *
	 * Appendix E Recommended ACPI Tables
	 * MCFG: PCI memory-mapped configuration space base address description
	 *       table
	 * IORT: Support for SMMUv2, ITS, and system topology description
	 * BERT: Boot Error Record Table
	 * EINJ: Error Injection Table
	 * ERST: Error Record Serialization Table
	 * HEST: Hardware Error Source Table
	 * RASF: RAS Facilities
	 * SPMI: Server Platform Management Interface Table
	 * SLIT: System Locality Information Table
	 * SRAT: System Resource Affinity Table
	 * CSRT: Core System Resource Table
	 * ECDT: Embedded Controller Description Table
	 * MPST: Memory Power State Table
	 * PCCT: Platform Communications Channel Table
	 */

	/*
	 * Since we're here, pick up the XSDT from the RSDP.
	 *
	 * Since we're a mandatory 64 bit platform we expect to have an XSDT.
	 */
	xbi->bi_acpi_xsdt = rsdp->XsdtPhysicalAddress;
	xsdt = (ACPI_TABLE_XSDT *)xbi->bi_acpi_xsdt;
	if (xsdt == NULL)
		return (-1);
	if (strncmp(xsdt->Header.Signature, ACPI_SIG_XSDT,
	    strlen(ACPI_SIG_XSDT)) != 0)
		return (-1);
	/*
	 * XXXARM: Check the XSDT CRC32
	 */

	dbg2_config_acpi(xbi, (ACPI_TABLE_DBG2 *)find_acpi_table((ACPI_TABLE_XSDT *)xbi->bi_acpi_xsdt, ACPI_SIG_DBG2));

	if (ingest_fadt(xbi, (ACPI_TABLE_FADT *)find_acpi_table(
	    (ACPI_TABLE_XSDT *)xbi->bi_acpi_xsdt, ACPI_SIG_FADT)) < 0)
		return (-1);

	if (ingest_madt(xbi, (ACPI_TABLE_MADT *)find_acpi_table(
	    (ACPI_TABLE_XSDT *)xbi->bi_acpi_xsdt, ACPI_SIG_MADT)) < 0)
		return (-1);

	return (0);
}

int
init_uefi(struct xboot_info *xbi)
{
	systab = (EFI_SYSTEM_TABLE64 *)xbi->bi_uefi_systab;
	if (systab == NULL)
		return (-1);

	if (systab->Hdr.Signature != EFI_SYSTEM_TABLE_SIGNATURE)
		return (-1);

	if (systab->Hdr.Revision < EFI_REV(2, 5))
		return (-1);

	/*
	 * XXXARM: check the EFI System Table CRC32
	 */

	if (ingest_uefi_systab(systab, xbi) != 0)
		return (-1);

	return (0);
}

void
uefi_reset(void)
{
	if (efirt != NULL) {
		efirt->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
		dbg2_puts("uefi_reset: ResetSystem returned, spinning\r\n");
	} else {
		dbg2_puts("uefi_reset: runtime services is null\r\n");
	}

        for (;;) ;
}
