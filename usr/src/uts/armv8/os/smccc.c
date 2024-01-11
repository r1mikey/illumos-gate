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
 * Secure Monitor Call Calling Convention Implementation
 */

#include <sys/types.h>
#include <sys/smccc.h>
#include <sys/smcccinfo.h>
#include <sys/psci.h>
#include <sys/promif.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

/*
 * From usr/src/uts/armv8/ml/smccc_impl.S
 */
extern void i_smccc_smc_call32(smccc32_args_t *args);
extern void i_smccc_hvc_call32(smccc32_args_t *args);
extern void i_smccc_smc_call64(smccc64_args_t *args);
extern void i_smccc_hvc_call64(smccc64_args_t *args);

static boolean_t smccc_is_initialized = B_FALSE;
static boolean_t smccc_psci_only = B_FALSE;
static boolean_t smccc_conduit_is_hvc = B_FALSE;
static smccc_version_t smccc_version_number = SMCCC_NOT_IMPLEMENTED;

void
smccc_init(void)
{
	const smcccinfo_t *si;
	const psciinfo_t *pi;

	if (smccc_is_initialized)
		return;

	si = smcccinfo_get();
	VERIFY(si != NULL);
	smccc_version_number = si->si_version;

	pi = psciinfo_get();
	VERIFY(pi != NULL);

	switch (si->si_conduit) {
	case SMCCC_CONDUIT_SMC:
		smccc_conduit_is_hvc = B_FALSE;
		break;
	case SMCCC_CONDUIT_HVC:
		smccc_conduit_is_hvc = B_TRUE;
		break;
	}

	if (smccc_version_number == SMCCC_NOT_IMPLEMENTED) {
		if (pi->pi_version > PSCI_VERSION_DEFERRED)
			smccc_psci_only = B_TRUE;
		else
			smccc_psci_only = B_FALSE;
	}

	smccc_is_initialized = B_TRUE;
}

boolean_t
smccc_initialized(void)
{
	return (smccc_is_initialized);
}

boolean_t
smccc_available(void)
{
	if (smccc_is_initialized && !smccc_psci_only)
		return (B_TRUE);

	return (B_FALSE);
}

smccc_version_t
smccc_version(void)
{
	return (smccc_version_number);
}

static boolean_t
smccc_can_call(uint32_t func_id)
{
	/*
	 * Not initialized, we can't call it.
	 */
	if (!smccc_is_initialized)
		return (B_FALSE);

	if (smccc_version_number == SMCCC_NOT_IMPLEMENTED) {
		/*
		 * Not implemented and not in PSCI-only mode, we can't call it.
		 */
		if (!smccc_psci_only)
			return (B_FALSE);

		/*
		 * We're in PSCI-only mode, ensure we're calling a PSCI
		 * function ID.
		 */
		switch (func_id) {
		case PSCI_VERSION_ID:			/* fallthrough */
		case PSCI_CPU_SUSPEND_ID:		/* fallthrough */
		case PSCI_CPU_OFF_ID:			/* fallthrough */
		case PSCI_CPU_ON_ID:			/* fallthrough */
		case PSCI_AFFINITY_INFO_ID:		/* fallthrough */
		case PSCI_MIGRATE_ID:			/* fallthrough */
		case PSCI_MIGRATE_INFO_TYPE_ID:		/* fallthrough */
		case PSCI_MIGRATE_INFO_UP_CPU_ID:	/* fallthrough */
		case PSCI_SYSTEM_OFF_ID:		/* fallthrough */
		case PSCI_SYSTEM_RESET_ID:		/* fallthrough */
		case PSCI_SYSTEM_RESET2_ID:		/* fallthrough */
		case PSCI_MEM_PROTECT_ID:		/* fallthrough */
		case PSCI_MEM_PROTECT_CHECK_RANGE_ID:	/* fallthrough */
		case PSCI_FEATURES_ID:			/* fallthrough */
		case PSCI_CPU_FREEZE_ID:		/* fallthrough */
		case PSCI_CPU_DEFAULT_SUSPEND_ID:	/* fallthrough */
		case PSCI_NODE_HW_STATE_ID:		/* fallthrough */
		case PSCI_SYSTEM_SUSPEND_ID:		/* fallthrough */
		case PSCI_SET_SUSPEND_MODE_ID:		/* fallthrough */
		case PSCI_STAT_RESIDENCY_ID:		/* fallthrough */
		case PSCI_STAT_COUNT_ID:		/* fallthrough */
		case PSCI_CLEAN_INV_MEMREGION_ID:	/* fallthrough */
		case PSCI_CLEAN_INV_MEMREGION_ATTRIBUTES_ID:
			return (B_TRUE);
		default:
			return (B_FALSE);
		}
	}

	/*
	 * We're initialized and we have a version, we can call it.
	 */
	return (B_TRUE);
}

void
smccc32_call(smccc32_args_t *args)
{
	VERIFY(args != NULL);

	/*
	 * We may get here very early if panicking, attempt to be useful, and
	 * not panic recursively.
	 */
	if (!panicstr)
		VERIFY(smccc_can_call(args->w0));

	if (panicstr != NULL && !smccc_can_call(args->w0)) {
		prom_printf("ERROR: attempted SMCCC call when "
		    "it's unavailable\n");
		args->w0 = SMCCC32_NOT_INITIALIZED;
		return;
	}

	if (smccc_conduit_is_hvc)
		i_smccc_hvc_call32(args);
	else
		i_smccc_smc_call32(args);
}

void
smccc64_call(smccc64_args_t *args)
{
	VERIFY(args != NULL);

	/*
	 * We may get here very early if panicking, attempt to be useful, and
	 * not panic recursively.
	 */
	if (!panicstr)
		VERIFY(smccc_can_call(args->x0));

	if (panicstr != NULL && !smccc_can_call(args->x0)) {
		prom_printf("ERROR: attempted SMCCC call when "
		    "it's unavailable\n");
		args->x0 = SMCCC32_NOT_INITIALIZED;
		return;
	}

	if (smccc_conduit_is_hvc)
		i_smccc_hvc_call64(args);
	else
		i_smccc_smc_call64(args);
}
