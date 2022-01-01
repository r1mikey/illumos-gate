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
 * Copyright 2022 Michael van der Westhuizen
 */

/*
 * Record information about processors, features, topology, caches and
 * workarounds.
 */

#include <sys/types.h>
#include <sys/debug.h>
#include <sys/bitmap.h>
#include <sys/cpuvar.h>
#include <sys/processor.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#if 0
#include <sys/promif.h>
#endif
#include <sys/aarch64_archext.h>
#include <asm/arm/aarch64_idregs.h>
#include <sys/bootconf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

struct cpuid_info {
	uint8_t		cpi_midr_implementer;
	uint8_t		cpi_midr_variant;
	uint8_t		cpi_midr_architecture;
	uint16_t	cpi_midr_partnum;
	uint8_t		cpi_midr_revision;

	uint64_t	cpi_mpidr;
	uint8_t		cpi_uniprocessor;
	uint8_t		cpi_smt;
	uint32_t	cpi_apicid;
	uint32_t	cpi_pass;

	uint64_t	id_aa64mmfr0_el1;
	uint64_t	id_aa64mmfr1_el1;
	uint64_t	id_aa64mmfr2_el1;
	uint64_t	id_aa64pfr0_el1;
	uint64_t	id_aa64pfr1_el1;
	uint64_t	id_aa64afr0_el1;
};

/*
 * CPU ID information for the boot processor.
 */
struct cpuid_info cpuid_info0;

/*
 * This is set to platform type we are running on.
 */
static int platform_type = -1;

/*
 * Variable to patch if hypervisor platform detection needs to be
 * disabled (e.g. platform_type will always be HW_NATIVE if this is 0).
 */
int enable_platform_detection = 1;

uchar_t aarch64_featureset[BT_SIZEOFMAP(NUM_AARCH64_FEATURES)];

static char *aarch64_feature_names[NUM_AARCH64_FEATURES] = {
	[FEAT_PMUv3]		= "PMUv3",
	[FEAT_TRACE]		= "TRACE",
	[FEAT_DEBUGv8]		= "DEBUGv8",
	[FEAT_CRC32]		= "CRC32",
	[FEAT_SHA256]		= "SHA256",
	[FEAT_SHA1]		= "SHA1",
	[FEAT_AES]		= "AES",
	[FEAT_PMULL]		= "PMULL",
	[FEAT_GICv3]		= "GICv3",
	[FEAT_AdvSIMD]		= "AdvSIMD",
	[FEAT_FP]		= "FP",
#if 0
	[FEAT_AA32BF16]		= "AA32BF16",
	[FEAT_AA32HPD]		= "AA32HPD",
	[FEAT_AA32I8MM]		= "AA32I8MM",
	[FEAT_AdvSIMD]		= "AdvSIMD",
	[FEAT_AES]		= "AES",
	[FEAT_AFP]		= "AFP",
	[FEAT_AMUv1]		= "AMUv1",
	[FEAT_AMUv1p1]		= "AMUv1p1",
	[FEAT_BBM]		= "BBM",
	[FEAT_BF16]		= "BF16",
	[FEAT_BRBE]		= "BRBE",
	[FEAT_BRBEv1p1]		= "BRBEv1p1",
	[FEAT_BTI]		= "BTI",
	[FEAT_CCIDX]		= "CCIDX",
	[FEAT_CMOW]		= "CMOW",
	[FEAT_CNTSC]		= "CNTSC",
	[FEAT_CONSTPACFIELD]	= "CONSTPACFIELD",
	[FEAT_CP15SDISABLE2]	= "CP15SDISABLE2",
	[FEAT_CRC32]		= "CRC32",
	[FEAT_CSV2]		= "CSV2",
	[FEAT_CSV2_2]		= "CSV2_2",
	[FEAT_CSV2_1p1]		= "CSV2_1p1",
	[FEAT_CSV2_1p2]		= "CSV2_1p2",
	[FEAT_CSV3]		= "CSV3",
	[FEAT_Debugv8p1]	= "Debugv8p1",
	[FEAT_Debugv8p2]	= "Debugv8p2",
	[FEAT_Debugv8p4]	= "Debugv8p4",
	[FEAT_Debugv8p8]	= "Debugv8p8",
	[FEAT_DGH]		= "DGH",
	[FEAT_DIT]		= "DIT",
	[FEAT_DoPD]		= "DoPD",
	[FEAT_DotProd2]		= "DotProd2",
	[FEAT_DoubleFault]	= "DoubleFault",
	[FEAT_DoubleLock]	= "DoubleLock",
	[FEAT_DPB]		= "DPB",
	[FEAT_DPB2]		= "DPB2",
	[FEAT_E0PD]		= "E0PD",
	[FEAT_ECV]		= "ECV",
	[FEAT_EPAC]		= "EPAC",
	[FEAT_ETE]		= "ETE",
	[FEAT_ETEv1p1]		= "ETEv1p1",
	[FEAT_ETMv4]		= "ETMv4",
	[FEAT_ETMv4p1]		= "ETMv4p1",
	[FEAT_ETMv4p2]		= "ETMv4p2",
	[FEAT_ETMv4p3]		= "ETMv4p3",
	[FEAT_ETMv4p4]		= "ETMv4p4",
	[FEAT_ETMv4p5]		= "ETMv4p5",
	[FEAT_ETMv4p6]		= "ETMv4p6",
	[FEAT_ETS]		= "ETS",
	[FEAT_EVT]		= "EVT",
	[FEAT_ExS]		= "ExS",
	[FEAT_F32MM]		= "F32MM",
	[FEAT_F64MM]		= "F64MM",
	[FEAT_FCMA]		= "FCMA",
	[FEAT_FGT]		= "FGT",
	[FEAT_FHM]		= "FHM",
	[FEAT_FlagM]		= "FlagM",
	[FEAT_FlagM2]		= "FlagM2",
	[FEAT_FP]		= "FP",
	[FEAT_FP16]		= "FP16",
	[FEAT_FPAC]		= "FPAC",
	[FEAT_FPACCOMBINE]	= "FPACCOMBINE",
	[FEAT_FRINTTS]		= "FRINTTS",
	[FEAT_GICv3]		= "GICv3",
	[FEAT_GICv3_NMI]	= "GICv3_NMI",
	[FEAT_GICv3_TDIR]	= "GICv3_TDIR",
	[FEAT_GICv3p1]		= "GICv3p1",
	[FEAT_GICv4]		= "GICv4",
	[FEAT_GICv4p1]		= "GICv4p1",
	[FEAT_GTG]		= "GTG",
	[FEAT_HAFDBS]		= "HAFDBS",
	[FEAT_HBC]		= "HBC",
	[FEAT_HCX]		= "HCX",
	[FEAT_HPDS]		= "HPDS",
	[FEAT_HPDS2]		= "HPDS2",
	[FEAT_HPMN0]		= "HPMN0",
	[FEAT_I8MM]		= "I8MM",
	[FEAT_IDST]		= "IDST",
	[FEAT_IESB]		= "IESB",
	[FEAT_IVIPT]		= "IVIPT",
	[FEAT_JSCVT]		= "JSCVT",
	[FEAT_LOR]		= "LOR",
	[FEAT_LPA]		= "LPA",
	[FEAT_LPA2]		= "LPA2",
	[FEAT_LRCPC]		= "LRCPC",
	[FEAT_LRCPC2]		= "LRCPC2",
	[FEAT_LS64]		= "LS64",
	[FEAT_LS64_ACCDATA]	= "LS64_ACCDATA",
	[FEAT_LS64_V]		= "LS64_V",
	[FEAT_LSE]		= "LSE",
	[FEAT_LSE2]		= "LSE2",
	[FEAT_LSMAOC]		= "LSMAOC",
	[FEAT_LVA]		= "LVA",
	[FEAT_MOPS]		= "MOPS",
	[FEAT_MPAM]		= "MPAM",
	[FEAT_MPAMv0p1]		= "MPAMv0p1",
	[FEAT_MPAMv1p1]		= "MPAMv1p1",
	[FEAT_MTE]		= "MTE",
	[FEAT_MTE2]		= "MTE2",
	[FEAT_MTE3]		= "MTE3",
	[FEAT_MTPMU]		= "MTPMU",
	[FEAT_NMI]		= "NMI",
	[FEAT_nTLBPA]		= "nTLBPA",
	[FEAT_NV]		= "NV",
	[FEAT_NV2]		= "NV2",
	[FEAT_PACIMP]		= "PACIMP",
	[FEAT_PACQARMA3]	= "PACQARMA3",
	[FEAT_PACQARMA5]	= "PACQARMA5",
	[FEAT_PAN]		= "PAN",
	[FEAT_PAN2]		= "PAN2",
	[FEAT_PAN3]		= "PAN3",
	[FEAT_PAuth]		= "PAuth",
	[FEAT_PAuth2]		= "PAuth2",
	[FEAT_PCSRv8]		= "PCSRv8",
	[FEAT_PCSRv8p2]		= "PCSRv8p2",
	[FEAT_PMULL]		= "PMULL",
	[FEAT_PMUv3]		= "PMUv3",
	[FEAT_PMUv3_TH]		= "PMUv3_TH",
	[FEAT_PMUv3p1]		= "PMUv3p1",
	[FEAT_PMUv3p4]		= "PMUv3p4",
	[FEAT_PMUv3p5]		= "PMUv3p5",
	[FEAT_PMUv3p7]		= "PMUv3p7",
	[FEAT_PMUv3p8]		= "PMUv3p8",
	[FEAT_RAS]		= "RAS",
	[FEAT_RASv1p1]		= "RASv1p1",
	[FEAT_RDM]		= "RDM",
	[FEAT_RME]		= "RME",
	[FEAT_RNG]		= "RNG",
	[FEAT_RNG_TRAP]		= "RNG_TRAP",
	[FEAT_RPRES]		= "RPRES",
	[FEAT_S2FWB]		= "S2FWB",
	[FEAT_SB]		= "SB",
	[FEAT_SEL2]		= "SEL2",
	[FEAT_SHA1]		= "SHA1",
	[FEAT_SHA256]		= "SHA256",
	[FEAT_SHA3]		= "SHA3",
	[FEAT_SHA512]		= "SHA512",
	[FEAT_SM3]		= "SM3",
	[FEAT_SM4]		= "SM4",
	[FEAT_SME]		= "SME",
	[FEAT_SPE]		= "SPE",
	[FEAT_SPECRES]		= "SPECRES",
	[FEAT_SPEv1p1]		= "SPEv1p1",
	[FEAT_SPEv1p2]		= "SPEv1p2",
	[FEAT_SPEv1p3]		= "SPEv1p3",
	[FEAT_SSBS]		= "SSBS",
	[FEAT_SSBS2]		= "SSBS2",
	[FEAT_SVE]		= "SVE",
	[FEAT_SVE_AES]		= "SVE_AES",
	[FEAT_SVE_BitPerm]	= "SVE_BitPerm",
	[FEAT_SVE_PMULL128]	= "SVE_PMULL128",
	[FEAT_SVE_SHA3]		= "SVE_SHA3",
	[FEAT_SVE_SM4]		= "SVE_SM4",
	[FEAT_SVE2]		= "SVE2",
	[FEAT_TIDCP1]		= "TIDCP1",
	[FEAT_TLBIOS]		= "TLBIOS",
	[FEAT_TLBIRANGE]	= "TLBIRANGE",
	[FEAT_TME]		= "TME",
	[FEAT_TRBE]		= "TRBE",
	[FEAT_TRF]		= "TRF",
	[FEAT_TTCNP]		= "TTCNP",
	[FEAT_TTL]		= "TTL",
	[FEAT_TTST]		= "TTST",
	[FEAT_TWED]		= "TWED",
	[FEAT_UAO]		= "UAO",
	[FEAT_VHE]		= "VHE",
	[FEAT_VMID16]		= "VMID16",
	[FEAT_VPIPT]		= "VPIPT",
	[FEAT_WFxT]		= "WFxT",
	[FEAT_WFxT2]		= "WFxT2",
	[FEAT_XNX]		= "XNX",
	[FEAT_XS]		= "XS",
#endif
};

boolean_t
is_aarch64_feature(void *featureset, uint_t feature)
{
	ASSERT(feature < NUM_AARCH64_FEATURES);
	return (BT_TEST((ulong_t *)featureset, feature));
}

void
add_aarch64_feature(void *featureset, uint_t feature)
{
	ASSERT(feature < NUM_AARCH64_FEATURES);
	BT_SET((ulong_t *)featureset, feature);
}

void
remove_aarch64_feature(void *featureset, uint_t feature)
{
	ASSERT(feature < NUM_AARCH64_FEATURES);
	BT_CLEAR((ulong_t *)featureset, feature);
}

boolean_t
compare_aarch64_featureset(void *setA, void *setB)
{
	/*
	 * We assume that the unused bits of the bitmap are always zero.
	 */
	if (memcmp(setA, setB, BT_SIZEOFMAP(NUM_AARCH64_FEATURES)) == 0)
		return (B_TRUE);

	return (B_FALSE);
}

void
print_aarch64_featureset(void *featureset)
{
	uint_t i;

	for (i = 0; i < NUM_AARCH64_FEATURES; i++) {
		if (is_aarch64_feature(featureset, i)) {
#if 1
			cmn_err(CE_CONT, "?aarch64_feature: %s\n",
			    aarch64_feature_names[i]);
#else
			prom_printf(" ?aarch64_feature: %s\n",
			    aarch64_feature_names[i]);
#endif
		}
	}
}

void
determine_platform(void)
{
	ASSERT(platform_type == -1);

	platform_type = HW_NATIVE;

	if (!enable_platform_detection)
		return;

	/*
	 * We can, in theory, poke around in ACPI data to find out of we're
	 * running on a hypervisor.
	 */
}

int
get_hwenv(void)
{
	ASSERT(platform_type != -1);
	return (platform_type);
}

void
cpuid_pass1(cpu_t *cpu, uchar_t *featureset)
{
	struct cpuid_info *cpi;
	uint64_t midr;
	uint64_t mpidr;
	uint64_t isar0;
	uint64_t isar1;
	uint64_t isar2;
	uint64_t dfr0;
	uint64_t dfr1;
	uint64_t pfr0;
	uint64_t pfr1;

	uint_t i;

	/*
	 * Space statically allocated for BSP, ensure pointer is set
	 */
	if (cpu->cpu_id == 0) {
		if (cpu->cpu_m.mcpu_cpi == NULL)
			cpu->cpu_m.mcpu_cpi = &cpuid_info0;
	}

	cpi = cpu->cpu_m.mcpu_cpi;
	ASSERT(cpi != NULL);

	for (i = 0; i < NUM_AARCH64_FEATURES; i++)
		remove_aarch64_feature(featureset, i);

	midr = read_midr_el1();
	mpidr = read_mpidr_el1();
	isar0 = read_id_aa64isar0_el1();
	/* isar1 = read_id_aa64isar1_el1(); */
	/* isar2 = read_id_aa64isar2_el1(); */
	dfr0 = read_id_aa64dfr0_el1();
	/* dfr1 = read_id_aa64dfr1_el1(); */
	pfr0 = read_id_aa64pfr0_el1();
	/* pfr1 = read_id_aa64pfr1_el1(); */

	cpi->cpi_midr_implementer =
	    (midr >> MIDR_EL1_IMPLEMENTER_SHIFT) & MIDR_EL1_IMPLEMENTER_MASK;
	cpi->cpi_midr_variant =
	    (midr >> MIDR_EL1_VARIANT_SHIFT) & MIDR_EL1_VARIANT_MASK;
	cpi->cpi_midr_architecture =
	    (midr >> MIDR_EL1_ARCHITECTURE_SHIFT) & MIDR_EL1_ARCHITECTURE_MASK;
	cpi->cpi_midr_partnum =
	    (midr >> MIDR_EL1_PARTNUM_SHIFT) & MIDR_EL1_PARTNUM_MASK;
	cpi->cpi_midr_revision =
	    (midr >> MIDR_EL1_REVISION_SHIFT) & MIDR_EL1_REVISION_MASK;

	/*
	 * Strip out non-affinity bits so that we can match the MPIDR field
	 * presented in the MADT GIC CPU Interface (GICC) Structure.  This will
	 * let us tie ACPI-provided information (GIC, topology) to this CPU.
	 */
	cpi->cpi_mpidr = mpidr & ((MPIDR_EL1_AFF3_MASK << MPIDR_EL1_AFF3_SHIFT) |
	    (MPIDR_EL1_AFF2_MASK << MPIDR_EL1_AFF2_SHIFT) |
	    (MPIDR_EL1_AFF1_MASK << MPIDR_EL1_AFF1_SHIFT) |
	    (MPIDR_EL1_AFF0_MASK << MPIDR_EL1_AFF0_SHIFT));
	cpi->cpi_uniprocessor = (mpidr >> MPIDR_EL1_U_SHIFT) & MPIDR_EL1_U_MASK;
	cpi->cpi_smt = (mpidr >> MPIDR_EL1_MT_SHIFT) & MPIDR_EL1_MT_MASK;

#define	EXTRACT_UFEAT(__v, __s)	((uint32_t)(((__v) >> (__s)) & 0xf))
#define	EXTRACT_SFEAT(__v, __s)	((int32_t)(((__v) >> ((__s)) & 0x7) | \
	((((__v) >> (__s)) & 0x8) ? (0xfffffff8) : 0x0)))

	/*
	 * Features from the original armv8.0-a featureset.
	 */
	if (EXTRACT_UFEAT(isar0, ID_AA64ISAR0_EL1_CRC32_SHIFT) == 0x1)
		add_aarch64_feature(featureset, FEAT_CRC32);

	if (EXTRACT_UFEAT(isar0, ID_AA64ISAR0_EL1_SHA2_SHIFT) >= 0x1)
		add_aarch64_feature(featureset, FEAT_SHA256);

	if (EXTRACT_UFEAT(isar0, ID_AA64ISAR0_EL1_SHA1_SHIFT) == 0x1)
		add_aarch64_feature(featureset, FEAT_SHA1);

	if (EXTRACT_UFEAT(isar0, ID_AA64ISAR0_EL1_AES_SHIFT) >= 0x1)
		add_aarch64_feature(featureset, FEAT_AES);

	if (EXTRACT_UFEAT(isar0, ID_AA64ISAR0_EL1_AES_SHIFT) >= 0x2)
		add_aarch64_feature(featureset, FEAT_PMULL);

	if (EXTRACT_SFEAT(dfr0, ID_AA64DFR0_EL1_PMUVER_SHIFT) >= 0x1)
		add_aarch64_feature(featureset, FEAT_PMUv3);

	if (EXTRACT_UFEAT(dfr0, ID_AA64DFR0_EL1_TRACEVER_SHIFT) >= 0x1)
		add_aarch64_feature(featureset, FEAT_TRACE);

	/* XXX: inclusive? */
	if (EXTRACT_UFEAT(dfr0, ID_AA64DFR0_EL1_DEBUGVER_SHIFT) == 0x6)
		add_aarch64_feature(featureset, FEAT_DEBUGv8);

	if (EXTRACT_UFEAT(pfr0, ID_AA64PFR0_EL1_GIC_SHIFT) >= 0x1)
		add_aarch64_feature(featureset, FEAT_GICv3);

	if (EXTRACT_SFEAT(pfr0, ID_AA64PFR0_EL1_ADVSIMD_SHIFT) >= 0x0)
		add_aarch64_feature(featureset, FEAT_AdvSIMD);

	if (EXTRACT_SFEAT(pfr0, ID_AA64PFR0_EL1_FP_SHIFT) >= 0x0)
		add_aarch64_feature(featureset, FEAT_FP);

	cpi->cpi_pass++;
}

/*
 * Use the ACPI ID and MPIDR recorded in boot properties to match this
 * CPU to an ACPI ID.
 *
 * This can only happen once the VM system is up.
 */
void
cpuid_pass2(cpu_t *cpu)
{
	uint_t i;
	uint_t n0;
	uint_t n1;
	int *apicid_array;
	long *mpidr_array;
	struct cpuid_info *cpi;

	cpi = cpu->cpu_m.mcpu_cpi;
	ASSERT(cpi != NULL);

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, ddi_root_node(), 0,
	    BP_CPU_APICID_ARRAY, &apicid_array, &n0) != DDI_SUCCESS) {
		panic("Failed to retrieve ACPI ID array.");
	}

	if (ddi_prop_lookup_int64_array(DDI_DEV_T_ANY, ddi_root_node(), 0,
	    BP_CPU_MPIDR_ARRAY, &mpidr_array, &n1) != DDI_SUCCESS) {
		panic("Failed to retrieve ACPI ID array.");
	}

	if (n0 != n1) {
		panic("Mismatched ACPI ID and MPIDR array lengths.");
	}

	for (i = 0; i < n0; ++i) {
		if ((uint64_t)mpidr_array[i] == cpi->cpi_mpidr) {
			cpi->cpi_apicid = (uint32_t)apicid_array[i];
			ddi_prop_free(mpidr_array);
			ddi_prop_free(apicid_array);
			cpi->cpi_pass++;
			return;
		}
	}

	panic("Failed to match MPIDR 0x%lx to an ACPI ID.", cpi->cpi_mpidr);
}


uint32_t
cpuid_get_apicid(cpu_t *cpu)
{
	ASSERT(cpuid_checkpass(cpu, 2));
	return (cpu->cpu_m.mcpu_cpi->cpi_apicid);
}

void
cpuid_get_addrsize(cpu_t *cpu, uint_t *pabits, uint_t *vabits)
{
	/* XXXAARCH64: fix this hackery */
#if 0
	struct cpuid_info *cpi;

	if (cpu == NULL)
                cpu = CPU;
	cpi = cpu->cpu_m.mcpu_cpi;

	ASSERT(cpuid_checkpass(cpu, 1));

	if (pabits)
		*pabits = cpi->cpi_pabits;
	if (vabits)
		*vabits = cpi->cpi_vabits;
#else
	if (pabits)
		*pabits = 48;
	if (vabits)
		*vabits = 48;
#endif
}

int
cpuid_checkpass(cpu_t *cpu, int pass)
{
	return (cpu != NULL && cpu->cpu_m.mcpu_cpi != NULL &&
	    cpu->cpu_m.mcpu_cpi->cpi_pass >= pass);
}
