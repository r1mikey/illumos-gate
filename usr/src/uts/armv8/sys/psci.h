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
 * Copyright 2024 Michael van der Westhuizen
 * Copyright 2017 Hayashi Naoyuki
 */

#ifndef _SYS_PSCI_H
#define	_SYS_PSCI_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Default PSCI function identifiers.
 *
 * PSCI 0.1 can override the identifiers for:
 * - PSCI_CPU_SUSPEND_ID
 * - PSCI_CPU_OFF_ID
 * - PSCI_CPU_ON_ID
 * - PSCI_MIGRATE_ID
 *
 * Later versions of PSCI fixed that spec hole.
 *
 * The following two identifiers are used in SMCCC discovery, following
 * appendix B of the SMCCC spec (ARM DEN0028):
 * - PSCI_VERSION_ID
 * - PSCI_FEATURES_ID
 *
 * Functions with bit 30 clear (those that start with 0x8... below) are 32bit
 * calls. Those with bit 30 set (the ones that start with 0xC...) are 64bit
 * calls. Where there are both 32bit and 64bit versions of a function we use
 * the 64bit version.
 */
#define	PSCI_VERSION_ID				0x84000000
#define	PSCI_CPU_SUSPEND_ID			0xC4000001
#define	PSCI_CPU_OFF_ID				0x84000002
#define	PSCI_CPU_ON_ID				0xC4000003
#define	PSCI_AFFINITY_INFO_ID			0xC4000004
#define	PSCI_MIGRATE_ID				0xC4000005
#define	PSCI_MIGRATE_INFO_TYPE_ID		0x84000006
#define	PSCI_MIGRATE_INFO_UP_CPU_ID		0xC4000007
#define	PSCI_SYSTEM_OFF_ID			0x84000008
#define	PSCI_SYSTEM_RESET_ID			0x84000009
#define	PSCI_SYSTEM_RESET2_ID			0xC4000012
#define	PSCI_MEM_PROTECT_ID			0x84000013
#define	PSCI_MEM_PROTECT_CHECK_RANGE_ID		0xC4000014
#define	PSCI_FEATURES_ID			0x8400000A
#define	PSCI_CPU_FREEZE_ID			0x8400000B
#define	PSCI_CPU_DEFAULT_SUSPEND_ID		0xC400000C
#define	PSCI_NODE_HW_STATE_ID			0xC400000D
#define	PSCI_SYSTEM_SUSPEND_ID			0xC400000E
#define	PSCI_SET_SUSPEND_MODE_ID		0x8400000F
#define	PSCI_STAT_RESIDENCY_ID			0xC4000010
#define	PSCI_STAT_COUNT_ID			0xC4000011
#define	PSCI_CLEAN_INV_MEMREGION_ID		0xC4000015
#define	PSCI_CLEAN_INV_MEMREGION_ATTRIBUTES_ID	0x84000016

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

extern void psci_init(void);

extern uint32_t psci_version(void);
extern int64_t psci_cpu_suspend(uint32_t power_state,
	uint64_t entry_point_address, uint64_t context_id);
extern int32_t psci_cpu_off(void);
extern int64_t psci_cpu_on(uint64_t target_cpu,
	uint64_t entry_point_address, uint64_t context_id);
extern int64_t psci_affinity_info(uint64_t target_affinity,
	uint32_t lowest_affinity_level);
extern int64_t psci_migrate(uint64_t target_cpu);
extern int32_t psci_migrate_info_type(void);
extern uint64_t psci_migrate_info_up_cpu(void);
extern void psci_system_off(void);
extern void psci_system_reset(void);
extern void psci_system_reset2(uint32_t reset_type, uint64_t cookie);
extern int32_t psci_mem_protect(boolean_t enable);
extern int64_t psci_mem_protect_check_range(uint64_t base, uint64_t length);
extern int32_t psci_features(uint32_t psci_func_id);
extern int32_t psci_cpu_freeze(void);
extern int64_t psci_cpu_default_suspend(uint64_t entry_point_address,
	uint64_t context_id);
extern int64_t psci_node_hw_state(uint64_t target_cpu, uint32_t power_level);
extern int64_t psci_system_suspend(uint64_t entry_point_address,
	uint64_t context_id);
extern int32_t psci_set_suspend_mode(uint32_t mode);
extern uint64_t psci_stat_residency(uint64_t target_cpu, uint32_t power_state);
extern uint64_t psci_stat_count(uint64_t target_cpu, uint32_t power_state);
extern int64_t psci_clean_inv_memregion(uint64_t base, uint64_t length,
	uint64_t timeout, uint32_t flags);
extern int32_t psci_clean_inv_memregion_attributes(uint32_t flags);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PSCI_H */
