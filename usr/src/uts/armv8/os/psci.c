/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#include <sys/types.h>
#include <sys/psci.h>
#include <sys/promif.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/smcccinfo.h>
#include <sys/smccc.h>

static psci_version_t psci_version_number = PSCI_NOT_IMPLEMENTED;
static uint32_t psci_cpu_suspend_id = PSCI_CPU_SUSPEND_ID;
static uint32_t psci_cpu_off_id = PSCI_CPU_OFF_ID;
static uint32_t psci_cpu_on_id = PSCI_CPU_ON_ID;
static uint32_t psci_migrate_id = PSCI_MIGRATE_ID;

#define	PSCI32_CALL0(name, fid)			smccc32_args_t name = {	\
							.w0 = (fid),	\
						};			\
						smccc32_call(&name)
#define	PSCI32_CALL1(name, fid, a0)		smccc32_args_t name = {	\
							.w0 = (fid),	\
							.w1 = (a0),	\
						};			\
						smccc32_call(&name)
#define	PSCI32_RES_TO_INT32(name)		((int32_t)(name.w0))

#define	PSCI64_CALL0(name, fid)			smccc64_args_t name = {	\
							.x0 = (fid),	\
						};			\
						smccc64_call(&name)
#define	PSCI64_CALL1(name, fid, a0)		smccc64_args_t name = {	\
							.x0 = (fid),	\
							.x1 = (a0),	\
						};			\
						smccc64_call(&name)
#define	PSCI64_CALL2(name, fid, a0, a1)		smccc64_args_t name = {	\
							.x0 = (fid),	\
							.x1 = (a0),	\
							.x2 = (a1),	\
						};			\
						smccc64_call(&name)
#define	PSCI64_CALL3(name, fid, a0, a1, a2)	smccc64_args_t name = {	\
							.x0 = (fid),	\
							.x1 = (a0),	\
							.x2 = (a1),	\
							.x3 = (a2)	\
						};			\
						smccc64_call(&name)
#define	PSCI64_CALL4(name, fid, a0, a1, a2, a3)	smccc64_args_t name = {	\
							.x0 = (fid),	\
							.x1 = (a0),	\
							.x2 = (a1),	\
							.x3 = (a2),	\
							.x4 = (a3)	\
						};			\
						smccc64_call(&name)
#define	PSCI64_RES_TO_INT64(name)		((int32_t)((uint32_t)name.x0))

void
psci_init(void)
{
	const psciinfo_t *pi;

	pi = psciinfo_get();
	VERIFY(pi != NULL);

	psci_cpu_suspend_id = pi->pi_cpu_suspend_id;
	psci_cpu_off_id = pi->pi_cpu_off_id;
	psci_cpu_on_id = pi->pi_cpu_on_id;
	psci_migrate_id = pi->pi_migrate_id;
	psci_version_number = pi->pi_version;

	if (psci_version_number == PSCI_NOT_IMPLEMENTED) {
		prom_printf("WARNING: PSCI not implemented\n");
		return;
	}

	VERIFY(psci_version_number != PSCI_VERSION_DEFERRED);
}

uint32_t
psci_version(void)
{
	PSCI32_CALL0(res, PSCI_VERSION_ID);
	return (PSCI32_RES_TO_INT32(res));
}

int64_t
psci_cpu_suspend(uint32_t power_state, uint64_t entry_point_address,
    uint64_t context_id)
{
	PSCI64_CALL3(res, psci_cpu_suspend_id,
	    power_state, entry_point_address, context_id);
	return (PSCI64_RES_TO_INT64(res));
}

int32_t
psci_cpu_off(void)
{
	PSCI32_CALL0(res, psci_cpu_off_id);
	return (PSCI32_RES_TO_INT32(res));
}

int64_t
psci_cpu_on(uint64_t target_cpu, uint64_t entry_point_address,
    uint64_t context_id)
{
	PSCI64_CALL3(res, psci_cpu_on_id,
	    target_cpu, entry_point_address, context_id);
	return (PSCI64_RES_TO_INT64(res));
}

int64_t
psci_affinity_info(uint64_t target_affinity, uint32_t lowest_affinity_level)
{
	PSCI64_CALL2(res, PSCI_AFFINITY_INFO_ID,
	    target_affinity, lowest_affinity_level);
	return (PSCI64_RES_TO_INT64(res));
}

int64_t
psci_migrate(uint64_t target_cpu)
{
	PSCI64_CALL1(res, psci_migrate_id, target_cpu);
	return (PSCI64_RES_TO_INT64(res));
}

int32_t
psci_migrate_info_type(void)
{
	PSCI32_CALL0(res, PSCI_MIGRATE_INFO_TYPE_ID);
	return (PSCI32_RES_TO_INT32(res));
}

uint64_t
psci_migrate_info_up_cpu(void)
{
	PSCI64_CALL0(res, PSCI_MIGRATE_INFO_UP_CPU_ID);
	return (res.x0);
}

void
psci_system_off(void)
{
	PSCI32_CALL0(res, PSCI_SYSTEM_OFF_ID);

	/* If we've got here we were asked to power off and could not, spin. */
	for (;;)
		__asm__("wfi");
}

void
psci_system_reset(void)
{
	PSCI32_CALL0(res, PSCI_SYSTEM_RESET_ID);

	/* If we've got here we were asked to reset and could not, spin. */
	for (;;)
		__asm__("wfi");
}

void
psci_system_reset2(uint32_t reset_type, uint64_t cookie)
{
	PSCI64_CALL2(res, PSCI_SYSTEM_RESET2_ID, reset_type, cookie);

	/* If we've got here we were asked to reset and could not, spin. */
	for (;;)
		__asm__("wfi");
}

int32_t
psci_mem_protect(boolean_t enable)
{
	PSCI32_CALL1(res, PSCI_MEM_PROTECT_ID, enable ? 1 : 0);
	return (PSCI32_RES_TO_INT32(res));
}

int64_t
psci_mem_protect_check_range(uint64_t base, uint64_t length)
{
	PSCI64_CALL2(res, PSCI_MEM_PROTECT_CHECK_RANGE_ID, base, length);
	return (PSCI64_RES_TO_INT64(res));
}

int32_t
psci_features(uint32_t psci_func_id)
{
	PSCI32_CALL1(res, PSCI_FEATURES_ID, psci_func_id);
	return (PSCI32_RES_TO_INT32(res));
}

int32_t
psci_cpu_freeze(void)
{
	PSCI32_CALL0(res, PSCI_CPU_FREEZE_ID);
	return (PSCI32_RES_TO_INT32(res));
}

int64_t
psci_cpu_default_suspend(uint64_t entry_point_address, uint64_t context_id)
{
	PSCI64_CALL2(res, PSCI_CPU_DEFAULT_SUSPEND_ID,
	    entry_point_address, context_id);
	return (PSCI64_RES_TO_INT64(res));
}

int64_t
psci_node_hw_state(uint64_t target_cpu, uint32_t power_level)
{
	PSCI64_CALL2(res, PSCI_NODE_HW_STATE_ID, target_cpu, power_level);
	return (PSCI64_RES_TO_INT64(res));
}

int64_t
psci_system_suspend(uint64_t entry_point_address, uint64_t context_id)
{
	PSCI64_CALL2(res, PSCI_SYSTEM_SUSPEND_ID,
	    entry_point_address, context_id);
	return (PSCI64_RES_TO_INT64(res));
}

int32_t
psci_set_suspend_mode(uint32_t mode)
{
	PSCI32_CALL1(res, PSCI_SET_SUSPEND_MODE_ID, mode);
	return (PSCI32_RES_TO_INT32(res));
}

uint64_t
psci_stat_residency(uint64_t target_cpu, uint32_t power_state)
{
	PSCI64_CALL2(res, PSCI_STAT_RESIDENCY_ID, target_cpu, power_state);
	return (res.x0);
}

uint64_t
psci_stat_count(uint64_t target_cpu, uint32_t power_state)
{
	PSCI64_CALL2(res, PSCI_STAT_COUNT_ID, target_cpu, power_state);
	return (res.x0);
}

int64_t
psci_clean_inv_memregion(uint64_t base, uint64_t length,
    uint64_t timeout, uint32_t flags)
{
	PSCI64_CALL4(res, PSCI_CLEAN_INV_MEMREGION_ID,
	    base, length, timeout, flags);
	return (PSCI64_RES_TO_INT64(res));
}

int32_t
psci_clean_inv_memregion_attributes(uint32_t flags)
{
	PSCI32_CALL1(res, PSCI_CLEAN_INV_MEMREGION_ATTRIBUTES_ID, flags);
	return (PSCI32_RES_TO_INT32(res));
}
