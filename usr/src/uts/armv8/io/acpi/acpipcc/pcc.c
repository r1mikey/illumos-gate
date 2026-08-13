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
 * PCC (Platform Communications Channel) common code for illumos/aarch64.
 *
 * Implements ACPI 6.6 Chapter 14: PCCT parsing, channel management,
 * the public consumer API (pcc_chan_*), the common doorbell-protocol
 * send path, interrupt-driven completion, the doorbell/ack register
 * registry, timing enforcement, and module init/teardown.
 *
 * Type-specific logic (subtable parsing, register mapping, header
 * manipulation, completion polling, error checking) lives in
 * pcc_type12.c and pcc_type3.c behind the pcc_type_ops_t vector.
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/list.h>
#include <sys/cmn_err.h>
#include <sys/avintr.h>
#include <sys/atomic.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/syspic.h>
#include <sys/syspic_impl.h>
#include <sys/acpi/acpi.h>
#include <sys/acpipcc.h>
#include <sys/smp_impldefs.h>
#include <vm/hat.h>
#include <vm/page.h>
#include <vm/hat_aarch64.h>
#include "pcc_impl.h"

/*
 * Firmware signature tolerance.  See pcc_check_signature() below.
 * 0 = accept any PCC_SIGNATURE_BASE signature (log mismatches)
 * 1 = accept off-by-one subspace index (Ampere Altra firmware bug)
 * 2 = exact match only
 */
int pcc_strictness = 1;

/* Module globals (file-local static) */
static pcc_chan_t *pcc_channels;	/* channel array (kmem_zalloc'd) */
static uint_t pcc_nchan;			/* number of channels parsed */
volatile boolean_t pcc_initialised;	/* pcc_init completed */
static kmutex_t pcc_init_lock;		/* serializes pcc_init */
static list_t pcc_reg_list;		/* global register registry list */
static list_t pcc_irq_group_list;	/* global irq group list */
static kmutex_t pcc_reg_list_lock;	/* protects pcc_reg_list */
static kmutex_t pcc_irq_list_lock;	/* protects pcc_irq_group_list */

/*
 * Subspace type dispatch table.  Maps PCCT subtable type to the
 * minimum subtable length and the type's ops vector.
 */
static const struct {
	uint8_t		psd_type;	/* PCCT subspace type */
	size_t		psd_min_len;	/* minimum subtable length */
	const pcc_type_ops_t *psd_ops;
} pcc_subspace_dispatch[] = {
	{ ACPI_PCCT_TYPE_HW_REDUCED_SUBSPACE,
	    sizeof (ACPI_PCCT_HW_REDUCED), &pcc_type1_ops },
	{ ACPI_PCCT_TYPE_HW_REDUCED_SUBSPACE_TYPE2,
	    sizeof (ACPI_PCCT_HW_REDUCED_TYPE2), &pcc_type2_ops },
	{ ACPI_PCCT_TYPE_EXT_PCC_MASTER_SUBSPACE,
	    sizeof (ACPI_PCCT_EXT_PCC_MASTER), &pcc_type3_ops },
	/* Type 5 deferred: ACPICA 20180629 lacks the subtable struct */
};

/* Forward declarations for file-local helpers */
static uint_t pcc_irq_handler(caddr_t arg1, __unused caddr_t arg2);
static void pcc_irq_storm_stop(void *arg);
static int pcc_wait_irq(pcc_chan_t *pc, boolean_t *responded);
static int pcc_check_signature(pcc_chan_t *pc);
static void pcc_chan_cleanup(pcc_chan_t *pc);
static int pcc_parse_pcct(void);

/*
 * pcc_init: parse the PCCT and bring up all PCC channels.
 *
 * Called from the module's _init, which runs at load time via the
 * -N dependency of the first consumer (misc/acpicppc).  That load
 * happens during the driver attach walk, after the interrupt
 * subsystem is up.  Idempotent via double-checked locking:
 * concurrent callers are safe, the first does the work.
 *
 * Returns DDI_SUCCESS or DDI_FAILURE.
 */
int
pcc_init(void)
{
	int ret;

	if (pcc_initialised) {
		return (DDI_SUCCESS);
	}

	mutex_enter(&pcc_init_lock);
	if (pcc_initialised) {
		mutex_exit(&pcc_init_lock);
		return (DDI_SUCCESS);
	}

	ret = pcc_parse_pcct();
	if (ret == DDI_SUCCESS) {
		membar_producer();
		pcc_initialised = B_TRUE;
	}
	mutex_exit(&pcc_init_lock);
	return (ret);
}

/*
 * pcc_teardown: reverse-order cleanup of all PCC state.
 *
 * The module's _fini refuses unload (channels may be in use), so
 * this is not called in normal operation; it reverses pcc_init
 * for completeness.
 */
void
pcc_teardown(void)
{
	int i;
	pcc_reg_entry_t *reg;

	ASSERT(pcc_initialised);

	/*
	 * Tear down channels in reverse parse order.  pcc_chan_cleanup
	 * uses pc_init_state to release exactly the resources each
	 * channel acquired: callback drain under pc_lock, irq group
	 * unlink (rem_avintr + pig_active drain on 1->0), pto_unmap
	 * releasing registry entries, mutex/cv destroy.
	 */
	for (i = (int)pcc_nchan - 1; i >= 0; i--) {
		pcc_chan_cleanup(&pcc_channels[i]);
	}

	/* Final sweep of the irq group list; all should be gone. */
	pcc_irq_groups_destroy();

	/*
	 * The register registry must be empty: every entry was
	 * released by pto_unmap during channel cleanup.  Assert,
	 * do not bulk-free.
	 */
	mutex_enter(&pcc_reg_list_lock);
	reg = list_head(&pcc_reg_list);
	ASSERT(reg == NULL);
	mutex_exit(&pcc_reg_list_lock);

	/*
	 * Clear pcc_initialised before freeing the channel array: a
	 * racing pcc_chan_get checks pcc_initialised first, so it
	 * must observe B_FALSE before pcc_channels can become NULL.
	 * The array is NULL when there was no PCCT; kmem_free(NULL)
	 * is not allowed.
	 */
	pcc_initialised = B_FALSE;
	membar_producer();
	if (pcc_channels != NULL) {
		kmem_free(pcc_channels,
			PCC_MAX_CHANNELS * sizeof (pcc_chan_t));
		pcc_channels = NULL;
	}
	pcc_nchan = 0;
}

/*
 * pcc_chan_get: look up a channel by firmware subspace ID.
 *
 * The chan_id is the firmware subspace ID (PCCT subtable index
 * or CPC package value), NOT the array index.
 * Returns NULL if PCC is not initialised, the ID is unknown, or the
 * channel is not usable.
 *
 * On success, increments pc_refcnt under pc_lock.  The caller
 * must call pcc_chan_release when done.
 *
 * No locking of the channel array: PCC is initialised from acpidev
 * attach before any consumer loads, so pcc_channels/pcc_nchan are
 * stable by the time consumers call this (_fini runs only after
 * dependents unload).
 */
pcc_chan_t *
pcc_chan_get(uint_t chan_id)
{
	pcc_chan_t *pc;
	uint_t i;

	/*
	 * PCC is initialized from acpidev attach, after the acpica
	 * module has initialised.  By the time any consumer calls
	 * pcc_chan_get, initialization has completed.  If PCC failed
	 * to initialize (no PCCT, or firmware untrustworthy), this
	 * returns NULL.
	 */
	if (!pcc_initialised) {
		return (NULL);
	}
	/*
	 * Acquire barrier: pairs with the membar_producer() in
	 * pcc_teardown, so the pcc_channels/pcc_nchan reads below
	 * cannot be satisfied before the pcc_initialised load.
	 */
	membar_consumer();

	/* Lookup by firmware subspace ID, not array index */
	pc = NULL;
	for (i = 0; i < pcc_nchan; i++) {
		if (pcc_channels[i].pc_id == chan_id) {
			pc = &pcc_channels[i];
			break;
		}
	}
	if (pc == NULL) {
		return (NULL);
	}
	if (!pc->pc_usable) {
		return (NULL);
	}

	/*
	 * Increment pc_refcnt to mark the channel as in use by a
	 * consumer.  Note: multiple CPPC CPUs in the same _PSD
	 * performance domain MUST share a subspace (ACPI 6.6
	 * s8.4.6.1.9), so a refcount (not a boolean) is required.
	 */
	mutex_enter(&pc->pc_lock);
	pc->pc_refcnt++;
	mutex_exit(&pc->pc_lock);
	return (pc);
}

/*
 * pcc_chan_release: drop a consumer reference on a channel.
 */
void
pcc_chan_release(pcc_chan_t *pc)
{
	mutex_enter(&pc->pc_lock);
	ASSERT(pc->pc_refcnt > 0);
	pc->pc_refcnt--;
	mutex_exit(&pc->pc_lock);
}

/*
 * pcc_chan_lock / pcc_chan_unlock: channel mutex wrappers.
 */
void
pcc_chan_lock(pcc_chan_t *pc)
{
	mutex_enter(&pc->pc_lock);
}

void
pcc_chan_unlock(pcc_chan_t *pc)
{
	mutex_exit(&pc->pc_lock);
}

/*
 * Shared-memory accessors.  offset is relative to the start of the
 * Communication Space (after the type-specific header).  The caller
 * must hold pc_lock.  Returns DDI_FAILURE if out of bounds.
 */
int
pcc_chan_read32(pcc_chan_t *pc, uint32_t offset, uint32_t *val)
{
	uint64_t abs_off;
	volatile uint32_t *p;

	ASSERT(MUTEX_HELD(&pc->pc_lock));

	abs_off = (uint64_t)offset + pc->pc_hdr_len;

	if (abs_off + sizeof (uint32_t) > pc->pc_shmem_len) {
		return (DDI_FAILURE);
	}

	p = (volatile uint32_t *)(void *)(pc->pc_shmem_va + abs_off);
	*val = *p;
	return (DDI_SUCCESS);
}

int
pcc_chan_write32(pcc_chan_t *pc, uint32_t offset, uint32_t val)
{
	uint64_t abs_off;
	volatile uint32_t *p;

	ASSERT(MUTEX_HELD(&pc->pc_lock));

	abs_off = (uint64_t)offset + pc->pc_hdr_len;

	if (abs_off + sizeof (uint32_t) > pc->pc_shmem_len) {
		return (DDI_FAILURE);
	}

	p = (volatile uint32_t *)(void *)(pc->pc_shmem_va + abs_off);
	*p = val;
	return (DDI_SUCCESS);
}

int
pcc_chan_read64(pcc_chan_t *pc, uint32_t offset, uint64_t *val)
{
	uint64_t abs_off;
	volatile uint64_t *p;

	ASSERT(MUTEX_HELD(&pc->pc_lock));

	abs_off = (uint64_t)offset + pc->pc_hdr_len;

	if (abs_off + sizeof (uint64_t) > pc->pc_shmem_len) {
		return (DDI_FAILURE);
	}

	p = (volatile uint64_t *)(void *)(pc->pc_shmem_va + abs_off);
	*val = *p;
	return (DDI_SUCCESS);
}

int
pcc_chan_write64(pcc_chan_t *pc, uint32_t offset, uint64_t val)
{
	uint64_t abs_off;
	volatile uint64_t *p;

	ASSERT(MUTEX_HELD(&pc->pc_lock));

	abs_off = (uint64_t)offset + pc->pc_hdr_len;

	if (abs_off + sizeof (uint64_t) > pc->pc_shmem_len) {
		return (DDI_FAILURE);
	}

	p = (volatile uint64_t *)(void *)(pc->pc_shmem_va + abs_off);
	*p = val;
	return (DDI_SUCCESS);
}

/*
 * Register registry: deduplicates doorbell/ack/cmd-complete/error
 * registers by (address, space_id, width).  Multiple subspaces may
 * share a physical register, each owning different bits via masks.
 */

/*
 * pcc_reg_lookup_or_create: find or create a registry entry.
 *
 * Looks up by (addr, space_id, width).  If found, bumps refcnt and
 * returns it.  Otherwise allocates, maps (MMIO only), and links it.
 *
 * Returns NULL on failure: FFH (no spec-defined invocation
 * convention), System I/O (no port I/O on aarch64), or a mapping
 * failure.  The caller (pto_map) must unwind on NULL.
 */
pcc_reg_entry_t *
pcc_reg_lookup_or_create(uint64_t addr, uint8_t space_id, uint8_t width)
{
	pcc_reg_entry_t *reg;

	if (addr == 0) {
		return (NULL);
	}

	if (space_id == ACPI_ADR_SPACE_FIXED_HARDWARE) {
		cmn_err(CE_WARN, "acpipcc: FFH register at 0x%llx "
			"unsupported (no spec-defined PCC invocation "
			"convention)",
			(unsigned long long)addr);
		return (NULL);
	}

	if (space_id == ACPI_ADR_SPACE_SYSTEM_IO) {
		cmn_err(CE_WARN, "acpipcc: System I/O register at 0x%llx "
			"unsupported (no port I/O on aarch64)",
			(unsigned long long)addr);
		return (NULL);
	}

	if (space_id != ACPI_ADR_SPACE_SYSTEM_MEMORY) {
		cmn_err(CE_WARN, "acpipcc: register at 0x%llx has "
			"invalid address space %u", (unsigned long long)addr,
			space_id);
		return (NULL);
	}

	if (width != 32 && width != 64) {
		cmn_err(CE_WARN, "acpipcc: register at 0x%llx has "
			"invalid width %u", (unsigned long long)addr, width);
		return (NULL);
	}

	mutex_enter(&pcc_reg_list_lock);
	for (reg = list_head(&pcc_reg_list); reg != NULL;
		reg = list_next(&pcc_reg_list, reg)) {
		if (reg->pre_addr == addr &&
			reg->pre_space_id == space_id &&
			reg->pre_width == width) {
			reg->pre_refcnt++;
			mutex_exit(&pcc_reg_list_lock);
			return (reg);
		}
	}

	reg = kmem_zalloc(sizeof (*reg), KM_SLEEP);
	reg->pre_addr = addr;
	reg->pre_space_id = space_id;
	reg->pre_width = width;
	reg->pre_refcnt = 1;
	mutex_init(&reg->pre_lock, NULL, MUTEX_DEFAULT, NULL);

	reg->pre_va = psm_map_phys((paddr_t)addr, width / 8,
		PROT_READ | PROT_WRITE);
	if (reg->pre_va == NULL) {
		cmn_err(CE_WARN, "acpipcc: failed to map register at "
			"0x%llx", (unsigned long long)addr);
		mutex_destroy(&reg->pre_lock);
		kmem_free(reg, sizeof (*reg));
		mutex_exit(&pcc_reg_list_lock);
		return (NULL);
	}

	list_insert_tail(&pcc_reg_list, reg);
	mutex_exit(&pcc_reg_list_lock);
	return (reg);
}

/*
 * pcc_reg_release: drop a reference on a registry entry.
 *
 * Safe to call with a NULL pointer (no-op), so partial mapping
 * cleanup in pto_map works without special cases.  Takes a
 * pointer-to-pointer and NULLs the caller's pointer.
 */
void
pcc_reg_release(pcc_reg_entry_t **regp)
{
	pcc_reg_entry_t *reg;

	if (regp == NULL || *regp == NULL) {
		return;
	}

	reg = *regp;
	*regp = NULL;

	mutex_enter(&pcc_reg_list_lock);
	ASSERT(reg->pre_refcnt > 0);
	reg->pre_refcnt--;
	if (reg->pre_refcnt == 0) {
		list_remove(&pcc_reg_list, reg);
		mutex_exit(&pcc_reg_list_lock);
		if (reg->pre_space_id == ACPI_ADR_SPACE_SYSTEM_MEMORY) {
			psm_unmap_phys(reg->pre_va, reg->pre_width / 8);
		}
		mutex_destroy(&reg->pre_lock);
		kmem_free(reg, sizeof (*reg));
		return;
	}
	mutex_exit(&pcc_reg_list_lock);
}

/*
 * pcc_reg_read: read an MMIO register through the registry.
 * Infallible: a volatile device-memory load cannot fail.
 */
void
pcc_reg_read(pcc_reg_entry_t *reg, uint64_t *val)
{
	if (reg->pre_width == 32) {
		volatile uint32_t *r =
			(volatile uint32_t *)(void *)reg->pre_va;
		*val = (uint64_t)*r;
	} else {
		volatile uint64_t *r =
			(volatile uint64_t *)(void *)reg->pre_va;
		*val = *r;
	}
}

/*
 * pcc_reg_write: write an MMIO register through the registry.
 * Infallible.
 */
void
pcc_reg_write(pcc_reg_entry_t *reg, uint64_t val)
{
	if (reg->pre_width == 32) {
		volatile uint32_t *r =
			(volatile uint32_t *)(void *)reg->pre_va;
		*r = (uint32_t)val;
	} else {
		volatile uint64_t *r =
			(volatile uint64_t *)(void *)reg->pre_va;
		*r = val;
	}
}

/*
 * pcc_reg_rmw_locked: read-modify-write a register with
 * preserve/set masks.  The caller must hold the register's
 * pre_lock: the panic path acquires every register it needs up
 * front (holding the doorbell lock across the Command Complete
 * clear and the doorbell write), so the ownership transfer can
 * never strand the channel with the doorbell unrung.
 */
void
pcc_reg_rmw_locked(pcc_reg_entry_t *reg, uint64_t preserve, uint64_t set)
{
	uint64_t val;

	ASSERT(MUTEX_HELD(&reg->pre_lock));
	pcc_reg_read(reg, &val);
	val = (val & preserve) | set;
	pcc_reg_write(reg, val);
}

/*
 * pcc_reg_rmw: read-modify-write a register with preserve/set
 * masks.  Always holds pre_lock across the RMW, regardless of
 * refcnt: shared registers need serialization even for a single
 * channel, and the lock is cheap.
 */
void
pcc_reg_rmw(pcc_reg_entry_t *reg, uint64_t preserve, uint64_t set)
{
	mutex_enter(&reg->pre_lock);
	pcc_reg_rmw_locked(reg, preserve, set);
	mutex_exit(&reg->pre_lock);
}

/*
 * pcc_ring_doorbell: ring the channel's doorbell register.
 * Infallible.
 */
void
pcc_ring_doorbell(pcc_chan_t *pc)
{
	/*
	 * Initiators (Types 1-3) always have a doorbell; parse fails
	 * the firmware if the GAS address is zero.
	 */
	ASSERT(pc->pc_db_reg != NULL);

	pcc_reg_rmw(pc->pc_db_reg, pc->pc_db_preserve, pc->pc_db_set);
}

/*
 * pcc_write_ack: write the channel's platform-interrupt ack
 * register.  No-op if the channel has none (Type 1,
 * edge-triggered).  Infallible.
 */
void
pcc_write_ack(pcc_chan_t *pc)
{
	if (pc->pc_ack_reg == NULL) {
		return;
	}

	pcc_reg_rmw(pc->pc_ack_reg, pc->pc_ack_preserve,
		pc->pc_ack_set);
}

/*
 * Interrupt support: per-GSIV reference-counted groups.
 *
 * PCC has no dip, so the DDI interrupt path is unavailable.
 * Instead, add_avintr/rem_avintr are used directly with raw
 * INTIDs, plus syspic interfaces for trigger-mode configuration.
 */

/*
 * pcc_irq_group_add: link a channel into its GSIV's group.
 *
 * Finds or creates the group for gsiv, links the channel, bumps
 * refcnt.  Installs the interrupt handler on the 0->1 transition.
 *
 * Returns 0 on success, EBUSY if an edge-triggered channel tries
 * to share a populated GSIV (ACPI 6.6 s14.1.6 requires a unique
 * GSIV per edge subspace), or if a level-triggered channel shares
 * a GSIV with a channel using identical Platform Interrupt Ack
 * preserve/set masks (s14.1.6 requires unique masks per subspace
 * on a shared level GSIV).  Both are firmware contradictions.
 * Returns DDI_FAILURE on a pure OS-side installation failure.
 */
int
pcc_irq_group_add(uint32_t gsiv, uint8_t flags, pcc_chan_t *pc)
{
	pcc_irq_group_t *group;
	pcc_chan_t *member;
	boolean_t edge;
	uint_t ipl;
	syspic_intr_state_t *state;

	/* ACPI 6.6 Table 14.7: bit 1 is Interrupt Mode (0=level, 1=edge) */
	edge = (flags & ACPI_PCCT_INTERRUPT_MODE) != 0;
	ipl = DDI_IPL_5;

	if ((flags & ACPI_PCCT_INTERRUPT_POLARITY) != 0) {
		/*
		 * Active-low SPI: GICv3 SPIs are always active-high.
		 * Warn; the GIC will still be programmed active-high.
		 */
		cmn_err(CE_WARN, "acpipcc: GSIV %u reports active-low "
			"polarity; GICv3 SPIs are active-high", gsiv);
	}

	mutex_enter(&pcc_irq_list_lock);
	for (group = list_head(&pcc_irq_group_list); group != NULL;
		group = list_next(&pcc_irq_group_list, group)) {
		if (group->pig_gsiv == gsiv) {
			break;
		}
	}

	if (group == NULL) {
		group = kmem_zalloc(sizeof (*group), KM_SLEEP);
		group->pig_gsiv = gsiv;
		group->pig_edge = edge;
		group->pig_ipl = ipl;
		group->pig_refcnt = 0;
		group->pig_active = 0;
		group->pig_storm = 0;
		group->pig_storm_tripped = B_FALSE;
		group->pig_storm_tid = 0;
		list_create(&group->pig_channels,
			sizeof (pcc_chan_t),
			offsetof(pcc_chan_t, pc_irq_node));
		list_insert_tail(&pcc_irq_group_list, group);
	} else {
		/*
		 * Edge-triggered subspaces must each have a unique GSIV
		 * (ACPI 6.6 s14.1.6).  A second channel on this GSIV is
		 * a firmware contradiction.
		 */
		if (edge || group->pig_edge) {
			mutex_exit(&pcc_irq_list_lock);
			return (EBUSY);
		}
		/*
		 * Level-triggered subspaces may share a GSIV, but ACPI
		 * 6.6 s14.1.6 requires each to have unique Platform
		 * Interrupt Ack preserve and set masks, so the handler
		 * can attribute and acknowledge each subspace's
		 * interrupt.  Duplicate masks on the *same* ack
		 * register are a firmware contradiction:
		 * acknowledging one subspace would acknowledge (or
		 * misattribute) the other's interrupt.  Identical
		 * masks on *distinct* ack registers are fine: each
		 * subspace acknowledges its own register.
		 */
		for (member = list_head(&group->pig_channels);
			member != NULL;
			member = list_next(&group->pig_channels, member)) {
			if (member->pc_ack_reg->pre_addr ==
			    pc->pc_ack_reg->pre_addr &&
			    member->pc_ack_reg->pre_space_id ==
			    pc->pc_ack_reg->pre_space_id &&
			    member->pc_ack_preserve == pc->pc_ack_preserve &&
			    member->pc_ack_set == pc->pc_ack_set) {
				mutex_exit(&pcc_irq_list_lock);
				return (EBUSY);
			}
		}
	}

	list_insert_tail(&group->pig_channels, pc);
	group->pig_refcnt++;

	if (group->pig_refcnt > 1) {
		/* Handler already installed; just linked. */
		mutex_exit(&pcc_irq_list_lock);
		return (0);
	}

	/*
	 * 0->1 transition: install the handler.  Uses aarch64
	 * syspic internals: syspic_get_state takes syspic_intrs_lock
	 * and returns holding it, protecting the state table across
	 * the get_state/add_avintr sequence (add_avintr's addspl
	 * asserts the lock is held).  Do NOT take the lock here;
	 * it is not recursive.
	 */
	state = syspic_get_state((intr_intid_t)gsiv);
	state->si_edge_triggered = edge;
	state->si_prio = ipl;

	/*
	 * Program the GIC trigger mode before add_avintr enables the
	 * interrupt: changing Int_config on an enabled interrupt is
	 * UNPREDICTABLE.  If the GSIV is already active with a
	 * different trigger mode, fail rather than change it under
	 * a live user.
	 */
	if (syspic_config_irq((int)gsiv, edge) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "acpipcc: GSIV %u already active with a "
		    "different trigger mode; failing channel", gsiv);
		syspic_remove_state((intr_intid_t)gsiv);
		mutex_exit(&syspic_intrs_lock);
		list_remove(&group->pig_channels, pc);
		group->pig_refcnt--;
		list_destroy(&group->pig_channels);
		list_remove(&pcc_irq_group_list, group);
		kmem_free(group, sizeof (*group));
		mutex_exit(&pcc_irq_list_lock);
		return (DDI_FAILURE);
	}

	if (add_avintr(NULL, ipl, pcc_irq_handler, "pcc", (int)gsiv,
		(caddr_t)(void *)group, NULL, NULL, NULL) == 0) {
		/*
		 * add_avintr returns 0 on failure.  Undo the syspic
		 * state, unlink the channel, destroy the group, and
		 * return DDI_FAILURE (not EBUSY, so the caller
		 * can distinguish OS-side failure from firmware
		 * contradiction).
		 *
		 * PCC GSIVs are never shared with non-PCC drivers, so the
		 * syspic state installed above is ours; removing it here
		 * cannot disturb another driver's state.
		 */
		syspic_remove_state((intr_intid_t)gsiv);
		mutex_exit(&syspic_intrs_lock);
		list_remove(&group->pig_channels, pc);
		group->pig_refcnt--;
		list_destroy(&group->pig_channels);
		list_remove(&pcc_irq_group_list, group);
		kmem_free(group, sizeof (*group));
		mutex_exit(&pcc_irq_list_lock);
		return (DDI_FAILURE);
	}
	mutex_exit(&syspic_intrs_lock);
	mutex_exit(&pcc_irq_list_lock);
	return (0);
}

/*
 * pcc_irq_group_remove: unlink a channel from its irq group.
 *
 * On the 1->0 refcount transition, removes the handler with
 * rem_avintr (whose delspl removes the syspic state and disables
 * the SPI), drains in-flight handler invocations via pig_active,
 * cancels a pending storm fail-stop, and frees the group.
 */
void
pcc_irq_group_remove(pcc_chan_t *pc)
{
	pcc_irq_group_t *group;
	uint32_t gsiv;
	uint_t ipl;

	mutex_enter(&pcc_irq_list_lock);
	for (group = list_head(&pcc_irq_group_list); group != NULL;
		group = list_next(&pcc_irq_group_list, group)) {
		pcc_chan_t *c;
		for (c = list_head(&group->pig_channels); c != NULL;
			c = list_next(&group->pig_channels, c)) {
			if (c == pc) {
				break;
			}
		}
		if (c == pc) {
			break;
		}
	}
	if (group == NULL) {
		/* Not linked; nothing to do. */
		mutex_exit(&pcc_irq_list_lock);
		return;
	}

	list_remove(&group->pig_channels, pc);
	ASSERT(group->pig_refcnt > 0);
	group->pig_refcnt--;
	gsiv = group->pig_gsiv;
	ipl = group->pig_ipl;

	if (group->pig_refcnt > 0) {
		mutex_exit(&pcc_irq_list_lock);
		return;
	}

	/*
	 * 1->0 transition: remove the handler.  rem_avintr
	 * guarantees no new invocations after it returns, but not
	 * that in-flight handlers have completed (see avintr.c:
	 * "there is no guarantee that the handler is not currently
	 * still executing").  Drain via pig_active below.
	 */
	mutex_exit(&pcc_irq_list_lock);
	rem_avintr(NULL, ipl, pcc_irq_handler, (int)gsiv);

	/*
	 * Drain in-flight handler invocations.  No timeout:
	 * rem_avintr means no new invocations can start, and every
	 * in-flight invocation is bounded (the callback contract
	 * forbids blocking), so this clears immediately in practice.
	 *
	 * rem_avintr's delspl already removed the syspic state and
	 * disabled the SPI when the last handler on the vector was
	 * removed; there is no explicit syspic_remove_state here.
	 */
	while (atomic_add_32_nv(&group->pig_active, 0) != 0) {
		drv_usecwait(10);
	}

	/*
	 * Cancel a pending storm fail-stop for this GSIV; the group
	 * is going away.  rem_avintr above guarantees no new handler
	 * invocation can schedule one, and the pig_active drain
	 * guarantees none is in flight, so pig_storm_tripped is
	 * stable here.  If the timeout already fired (this may be
	 * running from it), untimeout is a no-op.
	 */
	if (group->pig_storm_tripped) {
		(void) untimeout(group->pig_storm_tid);
	}

	mutex_enter(&pcc_irq_list_lock);
	list_remove(&pcc_irq_group_list, group);
	mutex_exit(&pcc_irq_list_lock);
	list_destroy(&group->pig_channels);
	kmem_free(group, sizeof (*group));
}

/*
 * pcc_irq_storm_stop: deferred interrupt-storm fail-stop.
 *
 * Runs in timeout(9F) thread context: the handler cannot call
 * rem_avintr itself (it may block).  The GSIV, not the group
 * pointer, is passed in: the group may have been torn down since
 * the timeout was scheduled, and a stale pointer must never be
 * dereferenced.
 *
 * Marks every member channel polling-only (pc_has_irq = B_FALSE)
 * so later sends degrade to polling, then unlinks each member via
 * pcc_irq_group_remove; the last unlink removes the handler and
 * frees the group.  The group is re-found by GSIV after every
 * unlink, so a concurrent teardown racing this callback simply
 * makes the lookup fail and the callback returns.
 *
 * Any thread blocked in pcc_wait_irq is woken so it can fall back
 * to polling rather than sleep out the full timeout waiting for
 * an interrupt that can never arrive.
 */
static void
pcc_irq_storm_stop(void *arg)
{
	uint32_t gsiv = (uint32_t)(uintptr_t)arg;
	pcc_irq_group_t *group;
	pcc_chan_t *pc;

	mutex_enter(&pcc_irq_list_lock);
	for (;;) {
		for (group = list_head(&pcc_irq_group_list); group != NULL;
		    group = list_next(&pcc_irq_group_list, group)) {
			if (group->pig_gsiv == gsiv &&
			    group->pig_storm_tripped) {
				break;
			}
		}
		if (group == NULL) {
			break;
		}
		pc = list_head(&group->pig_channels);
		if (pc == NULL) {
			break;
		}

		mutex_enter(&pc->pc_state_lock);
		pc->pc_has_irq = B_FALSE;
		/*
		 * Wake any thread blocked in pcc_wait_irq: the handler
		 * is being unlinked, so no signal is coming.  The
		 * waiter observes pc_has_irq == B_FALSE and falls back
		 * to polling.
		 */
		cv_broadcast(&pc->pc_cv);
		mutex_exit(&pc->pc_state_lock);

		mutex_exit(&pcc_irq_list_lock);
		pcc_irq_group_remove(pc);
		mutex_enter(&pcc_irq_list_lock);
	}
	mutex_exit(&pcc_irq_list_lock);
}

/*
 * pcc_irq_groups_destroy: final sweep of the irq group list.
 *
 * All groups should already be gone (every linked channel was
 * unlinked during per-channel cleanup).  Any group found here is
 * a bug: warn, remove its handler, and free it rather than
 * leaking.
 */
void
pcc_irq_groups_destroy(void)
{
	pcc_irq_group_t *group;

	mutex_enter(&pcc_irq_list_lock);
	while ((group = list_head(&pcc_irq_group_list)) != NULL) {
		uint32_t gsiv = group->pig_gsiv;
		uint_t ipl = group->pig_ipl;

		cmn_err(CE_WARN, "acpipcc: irq group for GSIV %u still "
			"present at teardown; removing", gsiv);
		list_remove(&pcc_irq_group_list, group);
		mutex_exit(&pcc_irq_list_lock);

		rem_avintr(NULL, ipl, pcc_irq_handler, (int)gsiv);
		while (atomic_add_32_nv(&group->pig_active, 0) != 0) {
			drv_usecwait(10);
		}
		/*
		 * rem_avintr's delspl already removed the syspic state
		 * and disabled the SPI; cancel a pending storm
		 * fail-stop for this GSIV, if any.
		 */
		if (group->pig_storm_tripped) {
			(void) untimeout(group->pig_storm_tid);
		}
		list_destroy(&group->pig_channels);
		kmem_free(group, sizeof (*group));

		mutex_enter(&pcc_irq_list_lock);
	}
	mutex_exit(&pcc_irq_list_lock);
}

/*
 * pcc_irq_handler: per-GSIV interrupt handler.
 *
 * Runs in interrupt context with the pcc_irq_group_t as arg1.
 * Walks only the channels bound to that GSIV.  If it acquires a
 * contended mutex, the illumos interrupt framework transparently
 * converts the handler into an interrupt thread.
 *
 * ACK ordering follows ACPI 6.6 Figures 14-1, 14-2: the platform
 * interrupt is cleared (ACKed) BEFORE the handler acts on a
 * completion or notification.
 *
 * For a level-triggered GSIV shared by multiple channels, the
 * handler peeks at each channel's completion indicator (read-only)
 * to determine ownership before ACKing.  Sole-occupant GSIVs skip
 * the peek.
 */
/*
 * Clear the Type 1/2 Status field's Platform Interrupt bit (ACPI 6.6
 * Table 14.11).  The clear is interlocked, so no lock is needed;
 * Status is KPM normal memory.  Used by the interrupt handler and by
 * the send path's final hardware peek, which stands in for the
 * handler when the interrupt wait timed out.
 */
static void
pcc_clear_platform_irq(pcc_chan_t *pc)
{
	volatile uint16_t *status;

	status = (volatile uint16_t *)(void *)
	    (pc->pc_shmem_va + PCC_SHMEM_STATUS);
	atomic_and_16(status, (uint16_t)~PCC_STATUS_PLATFORM_IRQ);
}

static uint_t
pcc_irq_handler(caddr_t arg1, __unused caddr_t arg2)
{
	pcc_irq_group_t *group = (pcc_irq_group_t *)(void *)arg1;
	pcc_chan_t *pc;
	pcc_irq_result_t result;
	boolean_t claimed;
	int ret;

	claimed = B_FALSE;

	atomic_inc_32(&group->pig_active);

	/*
	 * Hold pcc_irq_list_lock across the channel walk: a channel
	 * can otherwise be unlinked from the group concurrently by
	 * init-failure teardown (a platform interrupt can arrive
	 * mid-parse, after the group's handler is installed).
	 * Lock ordering is pcc_irq_list_lock -> pc_lock; nothing
	 * takes them in the reverse order.  If the lock is
	 * contended, the interrupt framework runs the handler as
	 * an interrupt thread.
	 */
	mutex_enter(&pcc_irq_list_lock);
	for (pc = list_head(&group->pig_channels); pc != NULL;
		pc = list_next(&group->pig_channels, pc)) {
		result = PCC_IRQ_NONE;

		/*
		 * Shared level-triggered GSIV: peek at the completion
		 * indicator to determine ownership before ACKing.
		 * The peek is read-only and consumes nothing.
		 */
		if (group->pig_refcnt > 1) {
			ret = pc->pc_ops->pto_irq_check(pc, &result);
			if (ret != DDI_SUCCESS ||
				result == PCC_IRQ_NONE) {
				continue;
			}
			/*
			 * Types 1-2: the Platform Interrupt bit (Status
			 * bit 1) is the platform's own attribution signal
			 * for this interrupt (ACPI 6.6 s14.5 step 7: the
			 * platform sets it when generating the interrupt
			 * for this subspace).  The Command Complete bit
			 * alone cannot attribute a shared interrupt: it is
			 * set on every idle initiator channel.  Skip
			 * channels the platform did not signal instead of
			 * leaning on the software pc_cmd_outstanding gate
			 * below (kept as defence in depth).  Type 3 has no
			 * Status bit; its check register is clear while a
			 * command is in flight, so its peek already
			 * attributes precisely.
			 *
			 * A platform that raises the interrupt without
			 * setting bit 1 is untrustworthy: the channel is
			 * skipped, the waiter falls back to its timeout
			 * and final hardware peek, and repeated
			 * occurrences trip the storm fail-stop below,
			 * degrading the GSIV to polling.
			 */
			if ((pc->pc_type ==
			    ACPI_PCCT_TYPE_HW_REDUCED_SUBSPACE ||
			    pc->pc_type ==
			    ACPI_PCCT_TYPE_HW_REDUCED_SUBSPACE_TYPE2) &&
			    (result & PCC_IRQ_PLATFORM_IRQ) == 0) {
				continue;
			}
		}

		/*
		 * ACK the platform interrupt before acting on the
		 * result.  No-op for channels without an ack register
		 * (Type 1, edge-triggered).  Infallible.
		 */
		pcc_write_ack(pc);

		/*
		 * Determine what happened on this channel.  Shared
		 * groups reuse the ownership peek above; sole-occupant
		 * GSIVs check here.
		 */
		if (group->pig_refcnt <= 1) {
			ret = pc->pc_ops->pto_irq_check(pc, &result);
			if (ret != DDI_SUCCESS) {
				continue;
			}
		}

		if ((result & PCC_IRQ_CMD_COMPLETE) != 0) {
			/*
			 * The handoff takes only pc_state_lock: the
			 * waiter drops it in cv_reltimedwait, so the
			 * handler never blocks on pc_lock, which the
			 * waiter holds across the whole transaction.
			 */
			mutex_enter(&pc->pc_state_lock);
			/*
			 * Only a channel with a command outstanding can
			 * own a completion interrupt.  An idle initiator
			 * channel always has Command Complete set (ACPI
			 * 6.6 s14.5 step 1: set means OSPM owns the
			 * channel), so the bit alone cannot attribute a
			 * shared interrupt: without this gate every
			 * spurious invocation would be "claimed" and the
			 * storm fail-stop below could never trip.
			 */
			if (pc->pc_cmd_outstanding) {
				pc->pc_cmd_outstanding = B_FALSE;
				pc->pc_cmd_complete = B_TRUE;
				cv_signal(&pc->pc_cv);
			} else {
				result &= ~PCC_IRQ_CMD_COMPLETE;
			}
			mutex_exit(&pc->pc_state_lock);
		}

		/*
		 * Type 1/2 platform notifications (ACPI 6.6 s14.6.1)
		 * are deprecated and unsupported: discard the bits
		 * without dispatching.  Only Types 1/2 report
		 * PCC_IRQ_NOTIFY (Type 3 has no notification
		 * mechanism).  The clear is interlocked, so no lock
		 * is needed.
		 */
		if ((result & PCC_IRQ_NOTIFY) != 0) {
			pcc_type12_clear_notify(pc);
		}

		/*
		 * ACPI 6.6 Table 14.11: clear the Platform Interrupt
		 * bit whenever observed, even when set alone with no
		 * command completion or notification.  Types 1-2 only;
		 * Types 3-4 have no Status field bit (the Ack register
		 * write above already cleared the hardware interrupt
		 * source).
		 */
		if ((result & PCC_IRQ_PLATFORM_IRQ) != 0 &&
		    (pc->pc_type == ACPI_PCCT_TYPE_HW_REDUCED_SUBSPACE ||
		    pc->pc_type ==
		    ACPI_PCCT_TYPE_HW_REDUCED_SUBSPACE_TYPE2)) {
			pcc_clear_platform_irq(pc);
		}

		/*
		 * A Platform Interrupt bit set alone (no completion,
		 * no notification) is cleared above but not claimed:
		 * it made no forward progress, so it counts toward
		 * the storm fail-stop below.
		 */
		/*
		 * A completion made forward progress; a stray
		 * notification was discarded above.  Either way the
		 * interrupt was for this channel: claim it so it
		 * does not count toward the storm fail-stop.
		 */
		if ((result &
		    (PCC_IRQ_CMD_COMPLETE | PCC_IRQ_NOTIFY)) != 0) {
			claimed = B_TRUE;
		}
	}

	/*
	 * No channel claimed the interrupt.  On a shared
	 * level-triggered GSIV the level line is still asserted with
	 * no ack path taken above, so ACK every member (a benign
	 * preserve/set RMW on a non-asserted line, and the ACPI 6.6
	 * s14.1.6 unique-mask rule keeps attribution safe) and warn:
	 * without this the CPU re-takes the interrupt immediately,
	 * forever.  Sole-occupant GSIVs already ACKed unconditionally
	 * in the walk above.
	 */
	if (!claimed && !group->pig_edge && group->pig_refcnt > 1) {
		cmn_err(CE_WARN, "acpipcc: spurious interrupt on "
			"shared level-triggered GSIV %u", group->pig_gsiv);
		for (pc = list_head(&group->pig_channels); pc != NULL;
		    pc = list_next(&group->pig_channels, pc)) {
			pcc_write_ack(pc);
		}
	}

	/*
	 * Interrupt storm guard: count consecutive handler
	 * invocations with no forward progress.  Past the threshold,
	 * warn once and schedule a deferred fail-stop (rem_avintr
	 * cannot run in interrupt context): the timeout callback
	 * unlinks every member, which removes the handler, and marks
	 * the channels polling-only so later sends degrade to
	 * polling.
	 */
	if (claimed) {
		group->pig_storm = 0;
	} else if (!group->pig_storm_tripped &&
	    ++group->pig_storm >= PCC_STORM_THRESHOLD) {
		group->pig_storm_tripped = B_TRUE;
		cmn_err(CE_WARN, "acpipcc: interrupt storm on GSIV %u: "
			"%u consecutive unclaimed interrupts; disabling "
			"PCC interrupts on this GSIV", group->pig_gsiv,
			PCC_STORM_THRESHOLD);
		group->pig_storm_tid = timeout(pcc_irq_storm_stop,
		    (void *)(uintptr_t)group->pig_gsiv, 1);
	}
	mutex_exit(&pcc_irq_list_lock);

	atomic_dec_32(&group->pig_active);

	return (claimed ? DDI_INTR_CLAIMED : DDI_INTR_UNCLAIMED);
}

/*
 * pcc_enforce_timing: enforce Minimum Request Turnaround Time and
 * Maximum Periodic Access Rate.
 *
 * Called at the start of pcc_chan_send (with pc_lock held).  If
 * both are zero, returns immediately.  Otherwise computes
 * min_gap = max(turnaround, rate-derived interval) and waits for
 * the remainder if the last observed command completion was too
 * recent.  Turnaround is measured from completion per ACPI 6.6
 * s14.1.4/s14.1.6, not from the last send.
 *
 * Note: the rate limit is applied to every command, including
 * infrequent event-driven ones.  ACPI 6.6 s14.1 exempts
 * infrequent, event-driven commands from the Maximum Periodic
 * Access Rate, but the channel API has no periodic/event
 * distinction, so the conservative choice is to throttle all
 * commands.  This never violates the platform's limit; it may
 * only delay event-driven sends.
 */
void
pcc_enforce_timing(pcc_chan_t *pc)
{
	hrtime_t now, elapsed, min_gap;

	ASSERT(MUTEX_HELD(&pc->pc_lock));

	if (pc->pc_last_complete == 0) {
		return;
	}

	/* min_gap = max(turnaround, rate-derived interval) */
	min_gap = (hrtime_t)pc->pc_turnaround * NANOSEC / MICROSEC;
	if (pc->pc_max_rate > 0) {
		hrtime_t rate_gap = (hrtime_t)60 * NANOSEC / pc->pc_max_rate;
		if (rate_gap > min_gap) {
			min_gap = rate_gap;
		}
	}
	if (min_gap == 0) {
		return;
	}

	now = gethrtime();
	elapsed = now - pc->pc_last_complete;
	if (elapsed < min_gap) {
		drv_usecwait((clock_t)((min_gap - elapsed) /
			(NANOSEC / MICROSEC)));
	}
}

/*
 * pcc_wait_irq: wait for interrupt-driven command completion.
 *
 * Uses pc_cmd_complete as the predicate.  The handler sets it
 * before cv_signal; the send path clears it before ringing the
 * doorbell, so an instant completion cannot lose its wakeup.
 *
 * After waking, re-verifies against hardware with pto_irq_check
 * (the same predicate the handler uses) to close the race where
 * a delayed interrupt for a previous command arrives during the
 * next command's wait.  Sends are serialized by pc_lock, so if
 * hardware does not show complete, the signal was stale.
 *
 * If the interrupt storm fail-stop takes the channel's interrupt
 * away mid-wait (pc_has_irq cleared, pc_cv broadcast), bails out
 * with DDI_FAILURE so the caller can fall back to polling; the
 * unlinked handler can never signal us.
 *
 * The wait drops pc_state_lock, never pc_lock: pc_lock is the
 * transaction guard, held across the whole send, while
 * pc_state_lock guards only the handoff state above.
 */
static int
pcc_wait_irq(pcc_chan_t *pc, boolean_t *responded)
{
	hrtime_t timeout_ns;
	hrtime_t expire;
	hrtime_t remain;
	pcc_irq_result_t result;
	int ret;

	ASSERT(MUTEX_HELD(&pc->pc_lock));

	/* timeout = latency * PCC_TIMEOUT_MULTIPLIER, in nanosec */
	timeout_ns = (hrtime_t)pc->pc_nominal_lat * NANOSEC / MICROSEC;
	if (timeout_ns == 0) {
		timeout_ns = (hrtime_t)1000 * NANOSEC / MICROSEC;
	}
	timeout_ns *= PCC_TIMEOUT_MULTIPLIER;

	expire = gethrtime() + timeout_ns;
	*responded = B_FALSE;

	mutex_enter(&pc->pc_state_lock);
	for (;;) {
		while (!pc->pc_cmd_complete) {
			/*
			 * Storm fail-stop took our interrupt: bail out
			 * promptly for the caller's polling fallback.
			 */
			if (!pc->pc_has_irq) {
				mutex_exit(&pc->pc_state_lock);
				return (DDI_FAILURE);
			}
			remain = expire - gethrtime();

			if (remain <= 0) {
				mutex_exit(&pc->pc_state_lock);
				cmn_err(CE_WARN, "acpipcc: subspace %u: "
				    "command completion timeout", pc->pc_id);
				return (DDI_FAILURE);
			}

			(void) cv_reltimedwait(&pc->pc_cv,
			    &pc->pc_state_lock, remain, TR_NANOSEC);
		}

		ret = pc->pc_ops->pto_irq_check(pc, &result);
		if (ret == DDI_SUCCESS &&
			(result & PCC_IRQ_CMD_COMPLETE) != 0) {
			break;
		}
		pc->pc_cmd_complete = B_FALSE;
	}
	mutex_exit(&pc->pc_state_lock);

	*responded = B_TRUE;
	return (DDI_SUCCESS);
}

/*
 * pcc_chan_send: send a command and wait for completion.
 *
 * The caller must hold pc_lock and must have written the payload
 * into the Communication Space via the pcc_chan_write* accessors
 * before calling.  payload_len is the payload byte count; for
 * Types 1-2 it is ignored (the platform uses the PCCT Length).
 *
 * Returns DDI_SUCCESS, DDI_FAILURE (transport/protocol or
 * platform-reported error, or channel previously marked failed
 * after a completion timeout).
 */
int
pcc_chan_send(pcc_chan_t *pc, uint32_t cmd, uint32_t payload_len)
{
	boolean_t responded = B_FALSE;
	boolean_t irq;
	pcc_irq_result_t result;
	int ret;

	ASSERT(MUTEX_HELD(&pc->pc_lock));

	/*
	 * A previous command timed out: the platform is not
	 * responding.  Fail fast rather than stalling every send
	 * on a dead channel.
	 */
	if (pc->pc_broken) {
		return (DDI_FAILURE);
	}

	/* Enforce minimum inter-command interval */
	pcc_enforce_timing(pc);

	/*
	 * Clear the completion predicate before pto_prepare_send
	 * clears the hardware Command Complete bit.  If the platform
	 * completes instantly, the handler's signal must not be
	 * clobbered by a later clear (lost wakeup).
	 */
	mutex_enter(&pc->pc_state_lock);
	pc->pc_cmd_complete = B_FALSE;
	mutex_exit(&pc->pc_state_lock);

	/* Type-specific: check ownership, populate header, clear CmdComplete */
	ret = pc->pc_ops->pto_prepare_send(pc, cmd, payload_len, B_FALSE);
	if (ret != DDI_SUCCESS) {
		return (ret);
	}

	/*
	 * The command is issued: ownership transferred (Command
	 * Complete cleared) and any previous command known complete
	 * (prepare_send verified Command Complete set).  Record it
	 * outstanding so the interrupt handler can attribute a
	 * completion interrupt to this channel; the handler clears
	 * it when it consumes the completion.
	 */
	mutex_enter(&pc->pc_state_lock);
	pc->pc_cmd_outstanding = B_TRUE;
	mutex_exit(&pc->pc_state_lock);

	/* Ring doorbell (common for all sending types; infallible) */
	pcc_ring_doorbell(pc);

	mutex_enter(&pc->pc_state_lock);
	irq = pc->pc_has_irq;
	mutex_exit(&pc->pc_state_lock);

	/* Wait for completion (interrupt or poll) */
	if (irq) {
		ret = pcc_wait_irq(pc, &responded);
		mutex_enter(&pc->pc_state_lock);
		irq = pc->pc_has_irq;
		mutex_exit(&pc->pc_state_lock);
		if (ret != DDI_SUCCESS && !irq) {
			/*
			 * The interrupt storm fail-stop took the
			 * channel's interrupt away mid-wait.  The
			 * platform itself may still be responsive, so
			 * poll once for this command instead of marking
			 * the channel broken: a lost interrupt is not
			 * a dead platform.
			 */
			cmn_err(CE_NOTE, "acpipcc: subspace %u: interrupt "
			    "lost to storm fail-stop; falling back to "
			    "polling", pc->pc_id);
			ret = pc->pc_ops->pto_poll_complete(pc, &responded);
		}
	} else {
		ret = pc->pc_ops->pto_poll_complete(pc, &responded);
	}

	/*
	 * The wait is over: on success the command's completion was
	 * just observed, so stamp it for turnaround and rate
	 * enforcement (ACPI 6.6 s14.1.4/s14.1.6 measure Minimum
	 * Request Turnaround Time from completion, not from the
	 * send).  On failure stamp as late as possible; the channel
	 * is marked broken below, so no future send consults it.
	 */
	pc->pc_last_complete = gethrtime();

	/*
	 * The command's fate is known (completed, timed out, or its
	 * interrupt lost to the storm fail-stop): it is no longer
	 * outstanding.  The handler clears the flag itself when it
	 * consumes a completion, so this is idempotent.
	 */
	mutex_enter(&pc->pc_state_lock);
	pc->pc_cmd_outstanding = B_FALSE;
	mutex_exit(&pc->pc_state_lock);

	/*
	 * The platform's response data must be visible before it is
	 * read, either here by pto_check_error or by the caller via
	 * the pcc_chan_read accessors.  ARMv8 does not order
	 * load-load, so a read barrier is required between observing
	 * command completion and reading the response.
	 */
	membar_consumer();

	/*
	 * Check error status (type-specific).  The handler does not
	 * interpret errors; it only signals.  Error interpretation
	 * stays in the send path.
	 */
	mutex_enter(&pc->pc_state_lock);
	irq = pc->pc_has_irq;
	mutex_exit(&pc->pc_state_lock);
	if (ret != DDI_SUCCESS && irq) {
		/*
		 * The interrupt wait timed out, but the interrupt
		 * itself may have been lost, arrived before the
		 * Command Complete write was visible, or raced the
		 * timeout.  Take one final read-only peek at the
		 * hardware: if the completion indicator is set, the
		 * platform did respond, so treat the command as
		 * complete rather than bricking the channel over a
		 * lost interrupt.  Only the interrupt path needs
		 * this; a polled wait already reads the hardware
		 * directly.  (If the storm fail-stop fired mid-wait,
		 * pc_has_irq is false and the fallback poll above
		 * was the hardware verdict.)
		 */
		result = PCC_IRQ_NONE;
		if (pc->pc_ops->pto_irq_check(pc, &result) ==
		    DDI_SUCCESS &&
		    (result & PCC_IRQ_CMD_COMPLETE) != 0) {
			/*
			 * The handler never ran for this completion, so
			 * a level-triggered platform interrupt may still
			 * be asserted: write the ACK exactly as the
			 * handler would have, so the line does not keep
			 * firing and feeding the storm counter as
			 * unclaimed.  No-op for channels without an ack
			 * register (Type 1, edge-triggered).
			 */
			pcc_write_ack(pc);
			/*
			 * The handler never ran for this completion, so the
			 * Platform Interrupt status bit may still be set:
			 * clear it exactly as the handler would have, so it
			 * does not linger until the next interrupt.  Types
			 * 1-2 only; Type 3 has no Status field bit.
			 */
			if ((result & PCC_IRQ_PLATFORM_IRQ) != 0 &&
			    (pc->pc_type ==
			    ACPI_PCCT_TYPE_HW_REDUCED_SUBSPACE ||
			    pc->pc_type ==
			    ACPI_PCCT_TYPE_HW_REDUCED_SUBSPACE_TYPE2)) {
				pcc_clear_platform_irq(pc);
			}
			ret = DDI_SUCCESS;
		}
	}

	if (ret == DDI_SUCCESS) {
		ret = pc->pc_ops->pto_check_error(pc);
	} else {
		/*
		 * Completion timed out: the platform did not respond
		 * within 500x nominal latency, and the final hardware
		 * peek above found no completion either.  Mark the
		 * channel failed so future sends fail fast instead of
		 * stalling on a dead platform.  A platform-reported
		 * error is not a timeout: the platform responded, so
		 * the channel stays usable.
		 */
		pc->pc_broken = B_TRUE;
		cmn_err(CE_WARN, "acpipcc: subspace %u: channel marked "
			"failed after command completion timeout", pc->pc_id);
	}

	/*
	 * No ACK on the polled path.  ACPI 6.6 s14.5 step 9 clears
	 * the platform interrupt only if the interrupt was requested
	 * via Notify on completion, and Notify on completion is set
	 * only when pc_has_irq (see pto_prepare_send).  A polled
	 * command therefore never raises an interrupt, so there is
	 * nothing to clear.
	 */

	return (ret);
}

/*
 * pcc_chan_send_nowait: fire-and-forget send for PDTT-like use.
 *
 * This is the ONLY panic-safe PCC call, for debug triggers that
 * fire during fatal crash / panic paths (ACPI 6.6 s5.2.30), where
 * interrupts may be disabled and the dump must not wait for the
 * platform.  Do NOT use for normal command/response traffic.
 *
 * Panic detection via panicstr.  In the panic path another CPU
 * may be stopped while holding pc_lock or a register's pre_lock,
 * so nothing here may block: pc_lock is try-entered, and the
 * type's prepare_send performs the register sequence (error
 * clear, Command Complete clear, doorbell ring) with try-locks,
 * holding the doorbell lock across the ownership transfer so
 * the channel can never be left wedged.  Any contention returns
 * EBUSY: a best-effort skip, retryable while we still own the
 * channel (EBUSY is only returned before ownership moves).
 *
 * No timing enforcement, no completion wait, no error check, no
 * ACK.  The platform may still be processing when we return.
 * Returns DDI_FAILURE if the channel was previously marked
 * failed after a completion timeout.
 */
int
pcc_chan_send_nowait(pcc_chan_t *pc, uint32_t cmd, uint32_t payload_len)
{
	boolean_t in_panic = (panicstr != NULL);
	int ret;

	if (in_panic) {
		if (!mutex_tryenter(&pc->pc_lock)) {
			return (EBUSY);
		}
	} else {
		mutex_enter(&pc->pc_lock);
	}

	/*
	 * A previous command timed out: the platform is not
	 * responding.  Fail fast (best effort, nothing to retry).
	 */
	if (pc->pc_broken) {
		mutex_exit(&pc->pc_lock);
		return (DDI_FAILURE);
	}

	mutex_enter(&pc->pc_state_lock);
	pc->pc_cmd_complete = B_FALSE;
	mutex_exit(&pc->pc_state_lock);

	/*
	 * On the panic path the type's prepare_send performs the
	 * full register sequence without blocking and rings the
	 * doorbell itself, so the doorbell must not be rung again
	 * here.
	 */
	ret = pc->pc_ops->pto_prepare_send(pc, cmd, payload_len, in_panic);
	if (ret != DDI_SUCCESS) {
		mutex_exit(&pc->pc_lock);
		return (ret);
	}

	/*
	 * As in pcc_chan_send: the command is issued, so mark it
	 * outstanding for interrupt attribution.  It stays marked
	 * until the next send's prepare_send observes its completion
	 * (or the handler consumes it).
	 */
	mutex_enter(&pc->pc_state_lock);
	pc->pc_cmd_outstanding = B_TRUE;
	mutex_exit(&pc->pc_state_lock);

	if (!in_panic) {
		pcc_ring_doorbell(pc);
	}

	/*
	 * No completion is observed on this path, so stamp the send
	 * time as a lower bound for the completion: enforcement may
	 * under-wait by up to this command's latency, but the
	 * ownership protocol still serializes sends.
	 */
	pc->pc_last_complete = gethrtime();

	mutex_exit(&pc->pc_lock);
	return (DDI_SUCCESS);
}

/*
 * pcc_map_shmem: map a PCC shared-memory region via KPM.
 *
 * Shared memory is normal RAM, not MMIO.  KPM provides the
 * existing cacheable kernel VA (Normal Inner Shareable on
 * aarch64).  No explicit cache maintenance: the platform is in
 * the coherency domain (as in Linux's arm64 PCC driver).
 *
 * Validates that every page in [pa, pa+len) is backed by physical
 * memory.  Returns NULL on failure.  No unmap is needed; KPM
 * mappings are permanent.
 */
caddr_t
pcc_map_shmem(uint64_t pa, uint64_t len)
{
	pfn_t pfn;
	pfn_t last_pfn;
	pfn_t p;
	uint_t pgoffset;

	if (len == 0) {
		return (NULL);
	}

	/*
	 * Guard against pa + len overflowing: the last byte of the
	 * range is pa + len - 1, which must not wrap.
	 */
	if (pa + len < pa) {
		cmn_err(CE_WARN, "acpipcc: shared memory PA "
			"0x%llx+0x%llx overflows",
			(unsigned long long)pa,
			(unsigned long long)len);
		return (NULL);
	}

	pfn = btop(pa);
	last_pfn = btop(pa + len - 1);
	pgoffset = (uint_t)(pa & MMU_PAGEOFFSET);

	/*
	 * Validate that every page in the range is backed by
	 * physical memory and covered by KPM.  page_numtopp_nolock
	 * returns NULL for PFNs outside the physical memory map.
	 * The loop breaks at last_pfn rather than testing
	 * p <= last_pfn so it cannot wrap if last_pfn is the
	 * maximum pfn_t value.
	 */
	for (p = pfn; ; ) {
		if (page_numtopp_nolock(p) == NULL) {
			cmn_err(CE_WARN, "acpipcc: shared memory PA "
				"0x%llx+0x%llx: PFN 0x%lx not in "
				"physical memory",
				(unsigned long long)pa,
				(unsigned long long)len,
				(unsigned long)p);
			return (NULL);
		}
		if (p == last_pfn) {
			break;
		}
		p++;
	}

	return (hat_kpm_pfn2va(pfn) + pgoffset);
}

/*
 * pcc_check_signature: validate the shared-memory signature.
 *
 * The PCC signature is PCC_SIGNATURE_BASE | subspace_id, except
 * RASF which uses the spec-defined ASCII "RASF" (0x52415346).
 * pcc_strictness controls tolerance for firmware bugs:
 *   0 = accept any PCC_SIGNATURE_BASE signature
 *   1 = accept off-by-one index (Ampere Altra subspaces 12-14)
 *   2 = exact match only
 */
static int
pcc_check_signature(pcc_chan_t *pc)
{
	uint32_t expected_sig;
	uint32_t sig;
	uint32_t sig_base;
	uint32_t sig_idx;
	int32_t idx_delta;

	expected_sig = PCC_SIGNATURE_BASE | pc->pc_id;
	sig = *(volatile uint32_t *)(void *)pc->pc_shmem_va;

	if (sig == expected_sig) {
		return (DDI_SUCCESS);
	}

	/*
	 * RASF uses a spec-defined ASCII signature, not the PCC
	 * formula (ACPI 6.6 Table 5.87).  Accept it at all
	 * strictness levels.
	 */
	if (sig == PCC_SIGNATURE_RASF) {
		return (DDI_SUCCESS);
	}

	sig_base = sig & ~0xffU;
	sig_idx = sig & 0xffU;
	idx_delta = (int32_t)sig_idx - (int32_t)pc->pc_id;

	if (sig_base != PCC_SIGNATURE_BASE) {
		cmn_err(CE_WARN, "acpipcc: subspace %u signature "
			"mismatch (0x%x, expected 0x%x)", pc->pc_id, sig,
			expected_sig);
		return (DDI_FAILURE);
	}

	if (pcc_strictness >= 2) {
		cmn_err(CE_WARN, "acpipcc: subspace %u signature "
			"mismatch (0x%x, expected 0x%x)", pc->pc_id, sig,
			expected_sig);
		return (DDI_FAILURE);
	}

	if (pcc_strictness >= 1 && (idx_delta < -1 || idx_delta > 1)) {
		cmn_err(CE_WARN, "acpipcc: subspace %u signature "
			"index too far (0x%x, expected 0x%x)", pc->pc_id,
			sig, expected_sig);
		return (DDI_FAILURE);
	}

	/*
	 * Strictness 0 accepts any index with the right base;
	 * strictness 1 accepts an off-by-one index (Ampere Altra
	 * firmware bug for subspaces 12-14).
	 */
	cmn_err(CE_NOTE, "acpipcc: subspace %u signature index "
		"mismatch (0x%x, expected 0x%x)", pc->pc_id, sig,
		expected_sig);
	return (DDI_SUCCESS);
}

/*
 * pcc_chan_cleanup: reverse-order per-channel teardown.
 *
 * Uses pc_init_state to release exactly the resources the
 * channel acquired.  Called from the parse loop's fail_chan path
 * and from pcc_teardown.
 */
static void
pcc_chan_cleanup(pcc_chan_t *pc)
{
	if (pc->pc_init_state & PCC_INIT_IRQ_LINKED) {
		/*
		 * Unlink from the irq group.  If this was the last
		 * channel on the GSIV (refcount 1->0), the handler is
		 * removed and the group freed here.
		 */
		pcc_irq_group_remove(pc);
	}
	/* PCC_INIT_TYPE: no resources to release (state is in shmem) */
	/* PCC_INIT_SIG_OK: no resources to release */
	if (pc->pc_init_state & PCC_INIT_MAPPED) {
		pc->pc_ops->pto_unmap(pc);
	}
	if (pc->pc_init_state & PCC_INIT_SHMEM) {
		/* KPM mapping: no explicit unmap needed */
		pc->pc_shmem_va = NULL;
	}
	/* PCC_INIT_PARSED: no resources to release */

	if (pc->pc_init_state & PCC_INIT_SYNCH) {
		cv_destroy(&pc->pc_cv);
		mutex_destroy(&pc->pc_lock);
		mutex_destroy(&pc->pc_state_lock);
	}

	/*
	 * Clear init_state only.  pc_valid and pc_usable are owned by
	 * the init loop, not by cleanup: firmware-validation failures
	 * clear pc_valid before jumping to fail_chan, while OS-side
	 * failures leave pc_valid set (from parse) and pc_usable
	 * clear (from zeroing).  The fail_all and _fini sweeps do not
	 * consult either flag.
	 */
	pc->pc_init_state = 0;
}

/*
 * pcc_parse_pcct: walk the PCCT, validate, and bring up channels.
 *
 * The PCCT is a flat array of variable-length subtables following
 * a fixed header.  Walk with manual pointer arithmetic, validating
 * length at every step.
 *
 * Trust boundary: firmware-description failures (corrupt table,
 * short subtable, bad signature, inconsistent interrupts) fail
 * ALL of PCC/CPPC.  Pure OS-side bring-up failures (register or
 * shmem mapping, interrupt installation) mark only that channel
 * unusable; the rest continue.
 *
 * Returns DDI_SUCCESS or DDI_FAILURE.
 */
static int
pcc_parse_pcct(void)
{
	ACPI_STATUS status;
	ACPI_TABLE_HEADER *hdr;
	ACPI_TABLE_PCCT *pcct;
	ACPI_SUBTABLE_HEADER *sub_hdr;
	uint8_t *tbl, *end, *pos;
	uint_t idx = 0;
	uint_t d;
	boolean_t tbl_irq_capable;
	const pcc_type_ops_t *ops;
	size_t min_len;
	pcc_chan_t *pc;
	int ret;
	uint_t i;

	status = AcpiGetTable(ACPI_SIG_PCCT, 1, &hdr);
	if (ACPI_FAILURE(status)) {
		/* No PCCT: not an error, just no PCC subspaces */
		pcc_nchan = 0;
		return (DDI_SUCCESS);
	}
	if (hdr->Length < sizeof (ACPI_TABLE_PCCT)) {
		cmn_err(CE_WARN, "acpipcc: PCCT too short (%u)",
			hdr->Length);
		return (DDI_FAILURE);
	}

	pcct = (ACPI_TABLE_PCCT *)(void *)hdr;

	/*
	 * ACPI 6.6 Table 14.1: PCCT Revision must be 2.  A different
	 * revision indicates a firmware/spec mismatch; fail all
	 * PCC/CPPC rather than misinterpreting the table.
	 */
	if (pcct->Header.Revision != 2) {
		cmn_err(CE_WARN, "acpipcc: PCCT revision %u unsupported "
			"(expected 2); failing all PCC/CPPC",
			pcct->Header.Revision);
		return (DDI_FAILURE);
	}

	/*
	 * ACPI 6.6 Table 14.2: Global Flags bits 1-31 are reserved
	 * and must be zero.  Non-zero reserved bits indicate
	 * firmware using a newer spec or corrupt data; fail all.
	 */
	if ((pcct->Flags & ~ACPI_PCCT_DOORBELL) != 0) {
		cmn_err(CE_WARN, "acpipcc: PCCT global flags reserved bits "
			"set (0x%x); failing all PCC/CPPC", pcct->Flags);
		return (DDI_FAILURE);
	}

	/*
	 * Allocate the channel array.  Zeroed, so pc_valid and
	 * pc_usable start B_FALSE for all entries.
	 */
	pcc_channels = kmem_zalloc(PCC_MAX_CHANNELS *
		sizeof (pcc_chan_t), KM_SLEEP);
	pcc_nchan = 0;

	tbl = (uint8_t *)(void *)hdr;
	end = tbl + hdr->Length;
	pos = tbl + sizeof (ACPI_TABLE_PCCT);

	/* Read table-level Platform Interrupt flag once */
	tbl_irq_capable = (pcct->Flags & ACPI_PCCT_DOORBELL) != 0;

	while (pos + sizeof (ACPI_SUBTABLE_HEADER) <= end &&
		idx < PCC_MAX_CHANNELS) {
		sub_hdr = (ACPI_SUBTABLE_HEADER *)(void *)pos;
		if (sub_hdr->Length == 0 || pos + sub_hdr->Length > end) {
			/*
			 * Corrupt PCCT: a zero-length or overrunning
			 * subtable means the table cannot be trusted.
			 * Fail all of PCC/CPPC rather than silently
			 * initializing a truncated subset of subspaces.
			 */
			cmn_err(CE_WARN, "acpipcc: corrupt PCCT subtable %u "
				"(length %u); failing all PCC/CPPC", idx,
				sub_hdr->Length);
			/*
			 * Channel idx has not been touched yet (the
			 * corruption check runs before its mutex/cv
			 * init), so fail_all's teardown covers channels
			 * 0..idx-1.
			 */
			pcc_nchan = idx;
			goto fail_all;
		}

		/* Allocate/zero channel, init mutex/cv */
		pc = &pcc_channels[idx];
		mutex_init(&pc->pc_lock, NULL, MUTEX_DEFAULT, NULL);
		mutex_init(&pc->pc_state_lock, NULL, MUTEX_DEFAULT, NULL);
		cv_init(&pc->pc_cv, NULL, CV_DEFAULT, NULL);
		pc->pc_init_state = PCC_INIT_SYNCH;
		pc->pc_idx = idx;
		/*
		 * pc_id (firmware subspace ID) is set by pto_parse from
		 * the subtable.  Per ACPI 6.6 s14.1.2, the subspace ID
		 * is the subtable's index in the PCCT list; pto_parse
		 * records idx as pc_id.
		 */
		pc->pc_type = sub_hdr->Type;

		/* Look up type in dispatch table */
		ops = NULL;
		min_len = 0;
		for (d = 0; d < ARRAY_SIZE(pcc_subspace_dispatch); d++) {
			if (pcc_subspace_dispatch[d].psd_type ==
				sub_hdr->Type) {
				ops = pcc_subspace_dispatch[d].psd_ops;
				min_len = pcc_subspace_dispatch[d].psd_min_len;
				break;
			}
		}

		if (ops == NULL) {
			/*
			 * Types 0 (generic), 4 (responder) and 5 (HW
			 * register) are defined by the spec but not
			 * implemented by this driver; types 6 and up are
			 * reserved.  Log-only (! prefix with CE_NOTE):
			 * neither is an error, just something this driver
			 * does not handle.  Keep the index aligned.
			 */
			cmn_err(CE_NOTE, "!acpipcc: subspace %u: %s type %u; "
				"ignoring", idx,
				(sub_hdr->Type == 0 || sub_hdr->Type == 4 ||
				sub_hdr->Type == 5) ?
				"unsupported" : "unknown", sub_hdr->Type);
			pc->pc_valid = B_FALSE;
			goto next;
		}

		/*
		 * Record the ops before the length check so the
		 * post-loop check sees a recognized-but-short subtable
		 * as a supported channel that failed validation (fail
		 * all), rather than an unsupported type (ignored).
		 */
		pc->pc_ops = ops;
		pc->pc_type = sub_hdr->Type;

		/* Validate subtable length before casting */
		if (sub_hdr->Length < min_len) {
			cmn_err(CE_WARN, "acpipcc: subspace %u type %u "
				"too short (%u < %lu)", idx, sub_hdr->Type,
				sub_hdr->Length, (ulong_t)min_len);
			pc->pc_valid = B_FALSE;
			goto next;
		}

		/* Type-specific parse: extract fields from ACPICA struct */
		if (pc->pc_ops->pto_parse(sub_hdr, pc) != DDI_SUCCESS) {
			pc->pc_valid = B_FALSE;
			goto next;
		}
		pc->pc_init_state |= PCC_INIT_PARSED;
		/*
		 * Firmware description accepted; see below for which
		 * later failures clear pc_valid (fail all) vs leave the
		 * channel merely unusable.
		 */
		pc->pc_valid = B_TRUE;

		/* Set pc_has_irq from table-level flag + per-channel GSIV */
		pc->pc_has_irq = tbl_irq_capable && (pc->pc_gsiv != 0);

		/*
		 * ACPI 6.6 s14.1.4: "Type 1 subspaces do not support a
		 * level triggered platform interrupt as no method is
		 * provided to clear the interrupt."  Fall back to
		 * polling-only mode: command completion still works by
		 * polling the Status field.  Platform notifications
		 * are unsupported regardless (ACPI 6.6 s14.6.1
		 * deprecates the mechanism).
		 */
		if (pc->pc_has_irq && pc->pc_ops->pto_edge_only_irq &&
			(pc->pc_irq_flags & ACPI_PCCT_INTERRUPT_MODE) == 0) {
			cmn_err(CE_WARN, "acpipcc: chan %u: Type 1 subspace "
				"with level-triggered platform interrupt; "
				"using polling-only mode", idx);
			pc->pc_has_irq = B_FALSE;
		}

	/*
	 * ACPI 6.6 Table 14.7: for Type 2/3/4 subspaces, "if the
	 * subspace does support interrupts, and these are level,
	 * [the Platform Interrupt Ack register] must be supplied".
	 * Without it the handler cannot clear the interrupt, so the
	 * line would stay asserted and the handler would spin at
	 * IPL 5 forever.  A present ack register with a zero
	 * AckWriteMask is the same contradiction: the ack RMW could
	 * never set anything, so the interrupt could never be
	 * cleared.  The firmware description cannot be trusted:
	 * fail all.  (Type 1 has no ack register and falls back to
	 * polling above.)  pc_has_irq already accounts for the PCCT
	 * global Platform Interrupt flag: when the flag is clear the
	 * GSI is ignored (Table 14.7) and no ack is needed.
	 */
	if (pc->pc_has_irq &&
		(pc->pc_type == ACPI_PCCT_TYPE_HW_REDUCED_SUBSPACE_TYPE2 ||
		pc->pc_type == ACPI_PCCT_TYPE_EXT_PCC_MASTER_SUBSPACE) &&
		(pc->pc_irq_flags & ACPI_PCCT_INTERRUPT_MODE) == 0 &&
		(pc->pc_ack_gas.addr == 0 || pc->pc_ack_set == 0)) {
		cmn_err(CE_WARN, "acpipcc: chan %u: level-triggered "
			"platform interrupt without usable ack register; "
			"failing all PCC/CPPC", idx);
		pc->pc_valid = B_FALSE;
		goto fail_chan;
	}

		/* Type-specific register mapping */
		if (pc->pc_ops->pto_map(pc) != DDI_SUCCESS) {
			/*
			 * OS-side failure (psm_map_phys or registry
			 * allocation).  The firmware description validated
			 * fine, so contain the damage: mark the channel
			 * unusable and continue with the rest.
			 */
			goto fail_chan;
		}
		pc->pc_init_state |= PCC_INIT_MAPPED;

		/* Map shared memory via KPM */
		pc->pc_shmem_va = pcc_map_shmem(pc->pc_shmem_pa,
			pc->pc_shmem_len);
		if (pc->pc_shmem_va == NULL) {
			/* OS-side failure: channel unusable, rest continues. */
			goto fail_chan;
		}
		pc->pc_init_state |= PCC_INIT_SHMEM;

		/* Signature validation */
		if (pcc_check_signature(pc) != DDI_SUCCESS) {
			pc->pc_valid = B_FALSE;
			goto fail_chan;
		}
		pc->pc_init_state |= PCC_INIT_SIG_OK;

		/* Post-map initialisation (optional per type) */
		if (pc->pc_ops->pto_init != NULL) {
			ret = pc->pc_ops->pto_init(pc);
			if (ret == PCC_INIT_UNUSABLE) {
				/*
				 * Firmware description valid, but the
				 * channel cannot be driven (e.g. Command
				 * Complete stuck clear after timeout).
				 * Preserve pc_valid; the channel is merely
				 * unusable.  The post-loop !pc_valid check
				 * does not fire.
				 */
				goto fail_chan;
			}
			if (ret != DDI_SUCCESS) {
				/*
				 * Firmware-side failure: pto_init validates
				 * firmware-provided data, so a failure means
				 * the firmware description cannot be trusted.
				 * Clear pc_valid; the post-loop check fails
				 * all PCC/CPPC.
				 */
				pc->pc_valid = B_FALSE;
				goto fail_chan;
			}
		}
		pc->pc_init_state |= PCC_INIT_TYPE;

		/* Link into interrupt group if applicable */
		if (pc->pc_has_irq) {
			ret = pcc_irq_group_add(pc->pc_gsiv,
				pc->pc_irq_flags, pc);
			if (ret == EBUSY) {
				/*
				 * Firmware contradicted itself about this
				 * GSIV: either an edge-triggered channel tried
				 * to share a populated GSIV (ACPI 6.6 s14.1.6
				 * requires a unique GSIV per edge subspace),
				 * or a level-triggered channel shares it with
				 * duplicate Platform Interrupt Ack masks
				 * (s14.1.6 requires unique masks).  The
				 * interrupt description cannot be trusted:
				 * fail the channel, and the post-loop check
				 * fails all of PCC/CPPC.
				 */
				cmn_err(CE_WARN, "acpipcc: chan %u: "
				    "inconsistent interrupt description for "
				    "GSIV %u; failing all PCC/CPPC",
				    idx, pc->pc_gsiv);
				pc->pc_valid = B_FALSE;
				goto fail_chan;
			}
			if (ret != 0) {
				/*
				 * Pure OS-side installation failure
				 * (add_avintr or syspic setup).  The firmware
				 * description was fine, so contain the damage
				 * to this channel.  Types 1-3 are
				 * OSPM-initiated, so completion can always
				 * be polled from shared memory.  Degrade to
				 * polling-only mode rather than failing.
				 */
				cmn_err(CE_WARN, "acpipcc: chan %u: interrupt "
				    "installation failed; using "
				    "polling-only mode", idx);
				pc->pc_has_irq = B_FALSE;
			} else {
				pc->pc_init_state |= PCC_INIT_IRQ_LINKED;
			}
		}

		pc->pc_usable = B_TRUE;
		goto next;

fail_chan:
		/*
		 * Reverse-order cleanup using pc_init_state flags.
		 * Each phase tears down only if its flag is set.
		 */
		pcc_chan_cleanup(pc);

next:
		pos += sub_hdr->Length;
		idx++;
	}

	pcc_nchan = idx;

	/*
	 * The loop above exits when pos reaches end, when fewer than
	 * sizeof (ACPI_SUBTABLE_HEADER) bytes remain, or when
	 * PCC_MAX_CHANNELS is reached.  Neither of the latter two may
	 * be silent.
	 */
	if (pos != end) {
		if (idx >= PCC_MAX_CHANNELS) {
			/*
			 * Firmware describes more subspaces than we
			 * support.  Not a firmware bug, just an OS limit.
			 * Log prominently and continue with the subspaces
			 * we parsed; the remainder are unavailable
			 * (pcc_chan_get returns NULL for them).
			 */
			cmn_err(CE_WARN, "acpipcc: PCCT describes more than %u "
				"subspaces; ignoring the remainder",
				PCC_MAX_CHANNELS);
		} else {
			/*
			 * Trailing bytes too short for a subtable header:
			 * the table Length does not match its content.
			 * Firmware bug; fail all of PCC/CPPC.
			 */
			cmn_err(CE_WARN, "acpipcc: PCCT has %lu trailing "
				"bytes; failing all PCC/CPPC",
				(ulong_t)(end - pos));
			goto fail_all;
		}
	}

	/*
	 * Post-loop check: if any supported channel (one with pc_ops
	 * set and a recognized type) failed firmware validation
	 * (!pc_valid), the firmware description cannot be trusted:
	 * fail the entire PCC/CPPC initialization.  Channels that
	 * are valid but unusable (!pc_usable, OS-side bring-up
	 * failure) do not trigger this; their consumers get NULL
	 * from pcc_chan_get.  Unsupported types (pc_ops == NULL) are
	 * ignored; they were never expected to work.
	 */
	for (i = 0; i < pcc_nchan; i++) {
		pc = &pcc_channels[i];

		if (pc->pc_ops != NULL && !pc->pc_valid) {
			cmn_err(CE_WARN, "acpipcc: supported subspace %u "
				"(type %u) failed to initialise; "
				"failing all PCC/CPPC", i, pc->pc_type);
			goto fail_all;
		}
	}

	/*
	 * Interrupt handlers are installed during the parse loop by
	 * pcc_irq_group_add on each GSIV's 0->1 refcount transition,
	 * so there is no separate post-loop installation step.
	 *
	 * A PCCT with zero subspaces (or zero supported subspaces)
	 * is not an error: pcc_init succeeds with pcc_nchan == 0,
	 * and pcc_chan_get returns NULL for all ids.  This is
	 * unusual but valid; the platform simply has no PCC
	 * channels.
	 */
	return (DDI_SUCCESS);

fail_all:
	/*
	 * Reverse-order teardown of all channels.  pcc_chan_cleanup
	 * checks pc_init_state to determine which resources were
	 * acquired.  Unlinking a channel from its irq group
	 * decrements that group's refcount; the group (and its
	 * installed handler) is destroyed when the last channel
	 * using the GSIV is unlinked.
	 */
	for (i = pcc_nchan; i-- > 0; ) {
		pcc_chan_cleanup(&pcc_channels[i]);
	}
	/*
	 * Final sweep of the global irq group list.  All groups
	 * should already be gone (every linked channel was unlinked
	 * above), so any group found here is a bug: warn, remove
	 * its handler, and free it rather than leaking.
	 */
	pcc_irq_groups_destroy();
	kmem_free(pcc_channels, PCC_MAX_CHANNELS * sizeof (pcc_chan_t));
	pcc_channels = NULL;
	pcc_nchan = 0;
	return (DDI_FAILURE);
}

static struct modlmisc modlmisc = {
	.misc_modops	= &mod_miscops,
	.misc_linkinfo	= "ACPI PCC channel driver"
};

static struct modlinkage modlinkage = {
	.ml_rev		= MODREV_1,
	.ml_linkage	= { &modlmisc, NULL }
};

int
_init(void)
{
	int err;

	err = mod_install(&modlinkage);
	if (err != 0) {
		return (err);
	}

	/*
	 * Initialise module-global locks and lists before any
	 * channel bring-up can touch them.
	 */
	mutex_init(&pcc_init_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&pcc_reg_list_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&pcc_irq_list_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&pcc_reg_list, sizeof (pcc_reg_entry_t),
		offsetof(pcc_reg_entry_t, pre_node));
	list_create(&pcc_irq_group_list, sizeof (pcc_irq_group_t),
		offsetof(pcc_irq_group_t, pig_node));

	/*
	 * Bring up the PCC channels now, at module load.  The module
	 * loads via the -N dependency of its first consumer
	 * (misc/acpicppc), which happens during the driver attach
	 * walk - after the interrupt subsystem is up.  Channel
	 * bring-up programs interrupt trigger modes and installs
	 * handlers, so it must not run from acpidev's boot probe:
	 * the syspic backend is not registered yet at that point.
	 */
	if (pcc_init() != DDI_SUCCESS) {
		list_destroy(&pcc_irq_group_list);
		list_destroy(&pcc_reg_list);
		mutex_destroy(&pcc_irq_list_lock);
		mutex_destroy(&pcc_reg_list_lock);
		mutex_destroy(&pcc_init_lock);
		(void) mod_remove(&modlinkage);
		return (-1);
	}

	return (0);
}

int
_fini(void)
{
	int err;

	if ((err = mod_remove(&modlinkage)) != 0) {
		return (err);
	}

	/*
	 * mod_remove succeeding only unlinks the module: its text
	 * stays mapped until _fini returns, and mod_remove fails
	 * with EBUSY while any module with an explicit -N
	 * dependency on misc/acpipcc (acpicppc) is loaded,
	 * so no new consumers can arrive from here on.  Tear down
	 * the channels and interrupt handlers now, before the text
	 * is unmapped on return; an interrupt arriving after that
	 * point would jump to unloaded text.
	 */
	if (pcc_initialised) {
		pcc_teardown();
	}

	list_destroy(&pcc_irq_group_list);
	list_destroy(&pcc_reg_list);
	mutex_destroy(&pcc_irq_list_lock);
	mutex_destroy(&pcc_reg_list_lock);
	mutex_destroy(&pcc_init_lock);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
