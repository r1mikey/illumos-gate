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

#ifndef _SYS_SMCCCINFO_H
#define	_SYS_SMCCCINFO_H

#include <sys/types.h>

/*
 * Secure Monitor Call Calling Convention Information
 *
 * Document Reference: Arm DEN0028 SMC Calling Convention
 *
 * The SMCCC defines a calling convention for making secure monitor calls (SMC)
 * to access firmware services at runtime.  Depending on the system, these
 * secure monitor calls might be substituted with Hypervisor calls (HVC). These
 * trap types are called conduits in SMCCC-lingo.
 *
 * There are both 32bit and 64bit ABIs available for the calls, so we end up
 * with four flavours of call:
 * - 32bit Secure Monitor Call
 * - 32bit Hypervisor Call
 * - 64bit Secure Monitor Call
 * - 64bit Hypervisor Call
 *
 * 32bit calls accept eight parameters, the first of which is the function
 * identifier and the remaining are arguments.
 *
 * 64bit calls accept 18 parameters, the first of which is the function
 * identifier and the remaining are arguments.
 *
 * Return values are placed into the same registers as calls, with the
 * convention that the return code is in the first parameter and any additional
 * data is either colocated with the return code or is placed into additional
 * parameters.
 *
 * SMCCC itself appears to be an abstraction of the mechanism derived to carry
 * the PSCI API (DEN0022).  As such, one infers the presence of SMCCC by the
 * presence of PSCI.  Due to this historical accident, the SMCCC Information
 * interface also provides information about the PSCI implementation.
 *
 * SMCCC, as defined by DEN0028, defines a number of architectural functions
 * that can be used to learn about the SoC and implement workarounds for
 * hardware sidechannel bugs.
 *
 * There are a number of other useful firmware interfaces built on top of
 * SMCCC. Of particular interest is:
 *   DEN0115: Arm® PCI Configuration Space Access Firmware Interface
 * This specification provides a firmware interface to paper over the quirks
 * in half-baked SoCs so that operating systems reduce the number of quirks
 * they need to deal with when bringing up PCI/PCIe devices.
 *
 * The functions defined by the SMCCC Information interface exist to abstract
 * detection of the presence of SMCCC.  Individual API interfaces detect
 * the presence of their specific implementations using the call interface
 * defined by the SMCCC interface.
 *
 * This chicken-and-egg approach to identifying what functionality we can call
 * is a little infuriating.  It is entirely possibe that we end up with PSCI
 * but without general SMCCC functionality, in which case the SMCCC interface
 * moves into a PSCI-only mode.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	/*
	 * Used internally to indicate that the PSCI information has not
	 * been initialised or was not found (or explicitly marked as not
	 * implemented) in the firmware tables.
	 *
	 * In devicetree there would simply be no PSCI node if PSCI was not
	 * implemented, while in ACPI the Arm Boot Architecture Flags would
	 * not have the PSCI_COMPLIANT bit set.
	 */
	PSCI_NOT_IMPLEMENTED			= 0,
	/*
	 * In the ACPI world the PSCI version can only be determined at runtime
	 * by calling the PSCI_VERSION function.
	 */
	PSCI_VERSION_DEFERRED			= 1,
	/*
	 * PSCI 0.1 will contain function identifier values for the four
	 * supported functions.
	 *
	 * There is no support for overriding function identifier values in
	 * ACPI.
	 */
	PSCI_VERSION_0_1			= 2,
	PSCI_VERSION_0_2			= 3,
	PSCI_VERSION_1_0			= 4,
	PSCI_VERSION_1_1			= 5,
	PSCI_VERSION_1_2			= 6,
	/*
	 * PSCI 1.3 is still being standardized (as of 2023-12-18).
	 */
	PSCI_VERSION_1_3			= 7,
	PSCI_VERSION_1_HIGHEST_SUPPORTED	= PSCI_VERSION_1_3,
	PSCI_VERSION_HIGHEST_SUPPORTED		= PSCI_VERSION_1_3,
} psci_version_t;

typedef enum {
	SMCCC_NOT_IMPLEMENTED		= 0,
	SMCCC_VERSION_1_0		= 1,
	SMCCC_VERSION_1_1		= 2,
	SMCCC_VERSION_1_2		= 3,
	SMCCC_VERSION_1_3		= 4,
	SMCCC_VERSION_1_4		= 5,
	SMCCC_VERSION_1_5		= 6,
	SMCCC_VERSION_HIGHEST_SUPPORTED	= SMCCC_VERSION_1_5,
} smccc_version_t;

/*
 * The SMCCC conduit indicates the exception (trap) type that the SMCCC code
 * should use to access firmware ABI functions.
 *
 * These values are used to choose between Hypervisor calls (HVC) and Secure
 * Monitor calls (SMC).  The conduit is always provided by firmware, either
 * through the mandatory method property in the PSCI devicetree node or via the
 * PSCI_USE_HVC bit in the Arm Boot Architecture Flags (these are in the FADT
 * field called ARM_BOOT_ARCH).
 */
typedef enum {
	SMCCC_CONDUIT_HVC	= 0,	/* Use "hvc #0" */
	SMCCC_CONDUIT_SMC	= 1,	/* Use "smc #0" */
} smccc_conduit_t;

typedef struct {
	smccc_version_t		si_version;
	smccc_conduit_t		si_conduit;
} smcccinfo_t;

typedef struct {
	/*
	 * Populated from firmware if available, otherwise deferred.
	 */
	psci_version_t		pi_version;
	/*
	 * Only populated from firmware in the PSCI 0.1 case and only ever on
	 * devicetree machines.
	 */
	uint32_t		pi_cpu_suspend_id;
	uint32_t		pi_cpu_off_id;
	uint32_t		pi_cpu_on_id;
	uint32_t		pi_migrate_id;
} psciinfo_t;

extern void smcccinfo_init(void);
extern const smcccinfo_t *smcccinfo_get(void);
extern const psciinfo_t *psciinfo_get(void);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_SMCCCINFO_H */
