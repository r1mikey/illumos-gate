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

#include <sys/types.h>
#include <sys/smcccinfo.h>
#include <sys/smccc.h>
#include <sys/psci.h>
#include <sys/systm.h>
#include <sys/obpdefs.h>
#include <sys/promif.h>

/*
 * SMCCC numeric versions
 *
 * These are 31 bits, laid out as follows in a 32 bit integer:
 * - [31]   : Must be zero
 * - [30:16]: Major version
 * - [15:0] : Minor version
 */
#define	SMCCC_VERS_1_0			0x10000u
#define	SMCCC_VERS_1_1			0x10001u
#define	SMCCC_VERS_1_2			0x10002u
#define	SMCCC_VERS_1_3			0x10003u
#define	SMCCC_VERS_1_4			0x10004u
#define	SMCCC_VERS_1_5			0x10005u

#define	PSCI_CONDUIT_PROPNAME		"method"
#define	PSCI_CONDUIT_PROPVAL_SMC	"smc"
#define	PSCI_CONDUIT_PROPVAL_HVC	"hvc"

#define	PSCI_CPU_SUSPEND_PROPNAME	"cpu_suspend"
#define	PSCI_CPU_CPU_OFF_PROPNAME	"cpu_off"
#define	PSCI_CPU_CPU_ON_PROPNAME	"cpu_on"
#define	PSCI_CPU_MIGRATE_PROPNAME	"migrate"

extern void i_smccc_smc_call32(smccc32_args_t *args);
extern void i_smccc_hvc_call32(smccc32_args_t *args);

static smcccinfo_t si_info = {
	.si_version			= SMCCC_NOT_IMPLEMENTED,
	.si_conduit			= SMCCC_CONDUIT_HVC,
};

static psciinfo_t pi_info = {
	.pi_version			= PSCI_NOT_IMPLEMENTED,
	.pi_cpu_suspend_id		= PSCI_CPU_SUSPEND_ID,
	.pi_cpu_off_id			= PSCI_CPU_OFF_ID,
	.pi_cpu_on_id			= PSCI_CPU_ON_ID,
	.pi_migrate_id			= PSCI_MIGRATE_ID,
};

struct psci_scan {
	const char			*compatible;
	psci_version_t			psci_version;
};

static struct psci_scan scan_data[] = {
	{ .compatible = "arm,psci-1.3", .psci_version = PSCI_VERSION_1_3, },
	{ .compatible = "arm,psci-1.2", .psci_version = PSCI_VERSION_1_2, },
	{ .compatible = "arm,psci-1.1", .psci_version = PSCI_VERSION_1_1, },
	{ .compatible = "arm,psci-1.0", .psci_version = PSCI_VERSION_1_0, },
	{ .compatible = "arm,psci-0.2", .psci_version = PSCI_VERSION_0_2, },
	{ .compatible = "arm,psci", .psci_version = PSCI_VERSION_0_1, },
	{ .compatible = NULL, .psci_version = PSCI_NOT_IMPLEMENTED, },
};

static void
smcccinfo_probe_versions(void)
{
	smccc32_args_t psci_args = {
		.w0	= PSCI_VERSION_ID
	};
	smccc32_args_t feat = {
		.w0	= PSCI_FEATURES_ID,
		.w1	= SMCCC_VERSION_ID
	};

	si_info.si_version = SMCCC_NOT_IMPLEMENTED;

	if (si_info.si_conduit == SMCCC_CONDUIT_HVC)
		i_smccc_hvc_call32(&psci_args);
	else
		i_smccc_smc_call32(&psci_args);

	if (pi_info.pi_version == PSCI_VERSION_DEFERRED) {
		switch ((psci_args.w0 & 0x7FFF0000) >> 16) {
		case 0:
			if ((psci_args.w0 & 0xFFFF) < 2)
				pi_info.pi_version = PSCI_VERSION_0_1;
			else
				pi_info.pi_version = PSCI_VERSION_0_2;
			break;
		case 1:
			switch (psci_args.w0 & 0xFFFF) {
			case 0:
				pi_info.pi_version = PSCI_VERSION_1_0;
				break;
			case 1:
				pi_info.pi_version = PSCI_VERSION_1_1;
				break;
			case 2:
				pi_info.pi_version = PSCI_VERSION_1_2;
				break;
			case 3:
				pi_info.pi_version = PSCI_VERSION_1_3;
				break;
			default:
				pi_info.pi_version =
				    PSCI_VERSION_1_HIGHEST_SUPPORTED;
				break;
			}
			break;
		default:
			pi_info.pi_version = PSCI_VERSION_HIGHEST_SUPPORTED;
			break;
		}
	}

	/*
	 * PSCI below 1.0 does not support querying SMCCC features.
	 */
	if (pi_info.pi_version < PSCI_VERSION_1_0)
		return;

	if (si_info.si_conduit == SMCCC_CONDUIT_HVC)
		i_smccc_hvc_call32(&feat);
	else
		i_smccc_smc_call32(&feat);

	/*
	 * Function is not supported, completely unambiguous.
	 */
	if (feat.w0 == SMCCC32_NOT_SUPPORTED)
		return;

	/*
	 * Malformed return value.
	 */
	if (!(feat.w0 & 0x80000000))
		return;

	/*
	 * Bad version code.
	 */
	if (feat.w0 < SMCCC_VERS_1_0)
		return;

	/*
	 * Interpret the version, capping at the latest version we support.
	 */
	if (feat.w0 >= SMCCC_VERS_1_0 && feat.w0 < SMCCC_VERS_1_1)
		si_info.si_version = SMCCC_VERSION_1_0;
	else if (feat.w0 >= SMCCC_VERS_1_1 && feat.w0 < SMCCC_VERS_1_2)
		si_info.si_version = SMCCC_VERSION_1_1;
	else if (feat.w0 >= SMCCC_VERS_1_2 && feat.w0 < SMCCC_VERS_1_3)
		si_info.si_version = SMCCC_VERSION_1_2;
	else if (feat.w0 >= SMCCC_VERS_1_3 && feat.w0 < SMCCC_VERS_1_4)
		si_info.si_version = SMCCC_VERSION_1_3;
	else if (feat.w0 >= SMCCC_VERS_1_4 && feat.w0 < SMCCC_VERS_1_5)
		si_info.si_version = SMCCC_VERSION_1_4;
	else if (feat.w0 >= SMCCC_VERS_1_5)
		si_info.si_version = SMCCC_VERSION_1_5;
	else
		si_info.si_version = SMCCC_VERSION_HIGHEST_SUPPORTED;
}

static void
smcccinfo_init_fdt(void)
{
	pnode_t			node;
	static struct psci_scan	*ps;
	boolean_t		exists;
	int			cv;
	char			prop[OBP_STANDARD_MAXPROPNAME];

	if (pi_info.pi_version != PSCI_NOT_IMPLEMENTED)
		return;

	for (ps = &scan_data[0]; ps->compatible != NULL; ++ps) {
		node = prom_find_compatible(prom_rootnode(), ps->compatible);
		if (node > 0)
			break;
	}

	/*
	 * While a machine can theoretically operate without PSCI, illumos
	 * will not do well without it.
	 */
	if (ps->compatible == NULL)
		return;

	exists = prom_node_has_property(node, PSCI_CONDUIT_PROPNAME);
	if (exists != B_TRUE)
		prom_panic("PSCI: no \"method\" property in PSCI node");

	cv = prom_bounded_getprop(node, PSCI_CONDUIT_PROPNAME,
	    prop, OBP_STANDARD_MAXPROPNAME - 1);
	if (cv < 0)
		prom_panic("PSCI: \"method\" property too long");

	if (strcmp(prop, PSCI_CONDUIT_PROPVAL_SMC) == 0)
		si_info.si_conduit = SMCCC_CONDUIT_SMC;
	else if (strcmp(prop, PSCI_CONDUIT_PROPVAL_HVC) == 0)
		si_info.si_conduit = SMCCC_CONDUIT_HVC;
	else
		prom_panic("PSCI: \"method\" property has unknown value");

	if (ps->psci_version == PSCI_VERSION_0_1) {
		/* XXXARM: use new u32 helpers */
		pi_info.pi_cpu_suspend_id = (uint32_t)prom_get_prop_int(node,
		    PSCI_CPU_SUSPEND_PROPNAME, (int)PSCI_CPU_SUSPEND_ID);
		pi_info.pi_cpu_off_id = (uint32_t)prom_get_prop_int(node,
		    PSCI_CPU_CPU_OFF_PROPNAME, (int)PSCI_CPU_OFF_ID);
		pi_info.pi_cpu_on_id = (uint32_t)prom_get_prop_int(node,
		    PSCI_CPU_CPU_ON_PROPNAME, (int)PSCI_CPU_ON_ID);
		pi_info.pi_migrate_id = (uint32_t)prom_get_prop_int(node,
		    PSCI_CPU_MIGRATE_PROPNAME, (int)PSCI_MIGRATE_ID);
	}

	pi_info.pi_version = ps->psci_version;
}

void
smcccinfo_init(void)
{
	smcccinfo_init_fdt();
	smcccinfo_probe_versions();
}

const smcccinfo_t *
smcccinfo_get(void)
{
	return (&si_info);
}

const psciinfo_t *
psciinfo_get(void)
{
	return (&pi_info);
}
