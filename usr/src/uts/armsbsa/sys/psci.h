/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2017 Hayashi Naoyuki
 */

#pragma once

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

enum {
	PSCI_SUCCESS		= 0,
	PSCI_NOT_SUPPORTED	= -1,
	PSCI_INVALID_PARAMETERS	= -2,
	PSCI_DENIED		= -3,
	PSCI_ALREADY_ON		= -4,
	PSCI_ON_PENDING		= -5,
	PSCI_INTERNAL_FAILURE	= -6,
	PSCI_NOT_PRESENT	= -7,
	PSCI_DISABLED		= -8,
	PSCI_INVALID_ADDRESS	= -9,
};

static inline uint64_t
psci_smc64(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3)
{
	register uint64_t x0 __asm__("x0") = a0;
	register uint64_t x1 __asm__("x1") = a1;
	register uint64_t x2 __asm__("x2") = a2;
	register uint64_t x3 __asm__("x3") = a3;

	__asm__ __volatile__ ("smc #0"
	    : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3)
	    :
	    :
	    "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
	    "x12", "x13", "x14", "x15", "x16", "x17", "x18", "memory", "cc");

	return x0;
}

static inline uint32_t
psci_version(void)
{
	return psci_smc64(0x84000000, 0, 0, 0);
}

static inline int32_t
psci_cpu_suspend(uint32_t power_state, uint64_t entry_point_address, uint64_t context_id)
{
	return psci_smc64(0xc4000001, power_state, entry_point_address, context_id);
}

static inline int32_t
psci_cpu_off(void)
{
	return psci_smc64(0x84000002, 0, 0, 0);
}

static inline int32_t
psci_cpu_on(uint64_t target_cpu, uint64_t entry_point_address, uint64_t context_id)
{
	return psci_smc64(0xc4000003, target_cpu, entry_point_address, context_id);
}

static inline int32_t
psci_affinity_info(uint64_t target_affinity, uint32_t lowest_affinity_level)
{
	return psci_smc64(0xc4000004, target_affinity, lowest_affinity_level, 0);
}

static inline int32_t
psci_migrate(uint64_t target_cpu)
{
	return psci_smc64(0xc4000005, target_cpu, 0, 0);
}

static inline int32_t
psci_migrate_info_type(void)
{
	return psci_smc64(0x84000006, 0, 0, 0);
}

static inline uint64_t
psci_migrate_info_up_cpu(void)
{
	return psci_smc64(0xc4000007, 0, 0, 0);
}

static inline void
psci_system_off(void)
{
	psci_smc64(0x84000008, 0, 0, 0);
}

static inline void
psci_system_reset(void)
{
	psci_smc64(0x84000009, 0, 0, 0);
}

static inline int32_t
psci_features(uint32_t psci_func_id)
{
	return psci_smc64(0x8400000a, psci_func_id, 0, 0);
}

static inline int32_t
psci_cpu_freeze(void)
{
	return psci_smc64(0x8400000b, 0, 0, 0);
}

static inline int32_t
psci_cpu_default_suspend(uint64_t entry_point_address, uint64_t context_id)
{
	return psci_smc64(0xc400000c, entry_point_address, context_id, 0);
}

static inline int32_t
psci_node_hw_state(uint64_t target_cpu, uint32_t power_level)
{
	return psci_smc64(0xc400000d, target_cpu, power_level, 0);
}

static inline int32_t
psci_system_suspend(uint64_t entry_point_address, uint64_t context_id)
{
	return psci_smc64(0xc400000e, entry_point_address, context_id, 0);
}

static inline int32_t
psci_set_suspend_mode(uint32_t mode)
{
	return psci_smc64(0x8400000f, mode, 0, 0);
}

static inline uint64_t
psci_stat_residency(uint64_t target_cpu, uint32_t power_state)
{
	return psci_smc64(0xc4000010, target_cpu, power_state, 0);
}

static inline uint64_t
psci_stat_count(uint64_t target_cpu, uint32_t power_state)
{
	return psci_smc64(0xc4000011, target_cpu, power_state, 0);
}

#ifdef	__cplusplus
}
#endif

