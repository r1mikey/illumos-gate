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
 * PCC Types 3 and 4: Extended PCC Master and Slave subspaces.
 *
 * Type 3 is the initiator (OSPM drives commands, platform responds).
 * Type 4 is the responder (platform drives notifications, OSPM
 * responds).  Both share the 16-byte extended shared memory header
 * and the external Command Complete / Error Status register model
 * (ACPI 6.6 s14.1.6, s14.1.7, Table 14.7, Table 14.8).
 */

#include "pcc_impl.h"

/*
 * Validate a GAS register descriptor at parse time.  A zero Address
 * means the register is absent (not an error for optional registers;
 * the caller decides).  BitOffset must be 0: the driver cannot address
 * sub-register bit fields.  AccessSize must be consistent with
 * BitWidth: for 32-bit width, 0 (undefined) through 3 (dword); for
 * 64-bit width, 0 through 4 (qword).  Returns DDI_SUCCESS if the
 * descriptor is usable or absent, DDI_FAILURE if it is malformed.
 */
static int
pcc_type34_validate_gas(ACPI_GENERIC_ADDRESS *gas)
{
	if (gas->Address == 0) {
		return (DDI_SUCCESS);
	}
	/*
	 * ACPI 6.6 s14.1.4/s14.1.5: only System I/O, System Memory,
	 * and Functional Fixed Hardware spaces are valid for PCC
	 * register GAS Address_Space_ID values.  Anything else is
	 * a firmware description failure: fail all PCC/CPPC, the
	 * same as the type 1/2 parse path.
	 */
	if (gas->SpaceId != ACPI_ADR_SPACE_SYSTEM_MEMORY &&
		gas->SpaceId != ACPI_ADR_SPACE_SYSTEM_IO &&
		gas->SpaceId != ACPI_ADR_SPACE_FIXED_HARDWARE) {
		cmn_err(CE_WARN, "acpipcc: PCC register has invalid "
			"Address_Space_ID 0x%x; failing all PCC/CPPC",
			gas->SpaceId);
		return (DDI_FAILURE);
	}
	if (gas->BitOffset != 0) {
		cmn_err(CE_WARN, "acpipcc: PCC register has non-zero "
			"BitOffset (%u); failing all PCC/CPPC", gas->BitOffset);
		return (DDI_FAILURE);
	}
	if (gas->BitWidth == 32) {
		if (gas->AccessWidth > 3) {
			cmn_err(CE_WARN, "acpipcc: PCC register has invalid "
				"AccessWidth (%u) for 32-bit width; failing all "
				"PCC/CPPC", gas->AccessWidth);
			return (DDI_FAILURE);
		}
	} else if (gas->BitWidth == 64) {
		if (gas->AccessWidth > 4) {
			cmn_err(CE_WARN, "acpipcc: PCC register has invalid "
				"AccessWidth (%u) for 64-bit width; failing all "
				"PCC/CPPC", gas->AccessWidth);
			return (DDI_FAILURE);
		}
	} else {
		cmn_err(CE_WARN, "acpipcc: PCC register has invalid "
			"BitWidth (%u); failing all PCC/CPPC", gas->BitWidth);
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

/*
 * Copy the raw GAS fields into the channel's storage.  Does not
 * create registry entries or map anything; that happens in
 * pto_map.
 */
#define PCC_STORE_GAS(dst, src) \
	do { \
		(dst).addr = (src)->Address; \
		(dst).space_id = (src)->SpaceId; \
		(dst).width = (src)->BitWidth; \
		(dst).bit_offset = (src)->BitOffset; \
		(dst).access_size = (src)->AccessWidth; \
	} while (0)

/*
 * pcc_type34_parse: extract Type 3/4 fields from the ACPICA subtable
 * into the channel.  Type 3 (ACPI_PCCT_EXT_PCC_MASTER) and Type 4
 * (ACPI_PCCT_EXT_PCC_SLAVE) share the same struct layout.  Stores
 * raw GAS fields; registry entries are created in pto_map.
 */
static int
pcc_type34_parse(void *subtable, pcc_chan_t *pc)
{
	ACPI_PCCT_EXT_PCC_MASTER *sub = subtable;

	/*
	 * ACPI 6.6 s14.1.2: the firmware subspace ID is the
	 * subtable's index in the PCCT list; there is no explicit
	 * ID field in the subtable.
	 */
	pc->pc_id = pc->pc_idx;

	if (pcc_type34_validate_gas(&sub->DoorbellRegister) !=
		DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	if (pcc_type34_validate_gas(&sub->PlatformAckRegister) !=
		DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	if (pcc_type34_validate_gas(&sub->CmdCompleteRegister) !=
		DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	if (pcc_type34_validate_gas(&sub->CmdUpdateRegister) !=
		DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	if (pcc_type34_validate_gas(&sub->ErrorStatusRegister) !=
		DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/*
	 * ACPI 6.6 Table 14.7: the shared memory Length "Must be >= 16".
	 * The driver unconditionally writes the 16-byte extended header
	 * (Flags, Length, Command), so a shorter region would put those
	 * writes past the firmware-described range and underflow the
	 * payload bound arithmetic.  A bad Length is a firmware
	 * description failure.
	 */
	if (sub->Length < PCC_EXT_SHMEM_HDR_LEN) {
		cmn_err(CE_WARN, "acpipcc: Type 3/4 subspace %u has invalid "
			"shared memory length %u; failing all PCC/CPPC",
			pc->pc_id, sub->Length);
		return (DDI_FAILURE);
	}

	/*
	 * The doorbell is required for the initiator (ACPI 6.6
	 * Table 14.7: optional only for responders).  A zero address
	 * on Type 3 is a firmware validation failure.
	 */
	if (pc->pc_type == ACPI_PCCT_TYPE_EXT_PCC_MASTER_SUBSPACE &&
		sub->DoorbellRegister.Address == 0) {
		cmn_err(CE_WARN, "acpipcc: Type 3 subspace %u has no "
			"doorbell register; failing all PCC/CPPC", pc->pc_id);
		return (DDI_FAILURE);
	}

	/*
	 * The Command Complete check and update registers are the
	 * core of the Type 3/4 protocol; both are required.
	 */
	if (sub->CmdCompleteRegister.Address == 0) {
		cmn_err(CE_WARN, "acpipcc: subspace %u has no Command "
			"Complete check register; failing all PCC/CPPC",
			pc->pc_id);
		return (DDI_FAILURE);
	}
	if (sub->CmdUpdateRegister.Address == 0) {
		cmn_err(CE_WARN, "acpipcc: subspace %u has no Command "
			"Complete update register; failing all PCC/CPPC",
			pc->pc_id);
		return (DDI_FAILURE);
	}

	pc->pc_shmem_pa = sub->BaseAddress;
	pc->pc_shmem_len = sub->Length;
	PCC_STORE_GAS(pc->pc_db_gas, &sub->DoorbellRegister);
	pc->pc_db_preserve = sub->PreserveMask;
	pc->pc_db_set = sub->WriteMask;
	pc->pc_nominal_lat = sub->Latency;
	pc->pc_max_rate = sub->MaxAccessRate;
	pc->pc_turnaround = sub->MinTurnaroundTime;
	PCC_STORE_GAS(pc->pc_ack_gas, &sub->PlatformAckRegister);
	pc->pc_ack_preserve = sub->AckPreserveMask;
	pc->pc_ack_set = sub->AckSetMask;
	PCC_STORE_GAS(pc->pc_cc_check_gas, &sub->CmdCompleteRegister);
	pc->pc_cc_check_mask = sub->CmdCompleteMask;
	PCC_STORE_GAS(pc->pc_cc_update_gas, &sub->CmdUpdateRegister);
	pc->pc_cc_update_preserve = sub->CmdUpdatePreserveMask;
	pc->pc_cc_update_set = sub->CmdUpdateSetMask;
	PCC_STORE_GAS(pc->pc_err_gas, &sub->ErrorStatusRegister);
	pc->pc_err_mask = sub->ErrorStatusMask;
	pc->pc_gsiv = sub->PlatformInterrupt;
	pc->pc_irq_flags = sub->Flags;
	pc->pc_has_doorbell = (sub->DoorbellRegister.Address != 0);
	pc->pc_hdr_len = PCC_EXT_SHMEM_HDR_LEN;
	pc->pc_signature = PCC_SIGNATURE_BASE | pc->pc_id;

	return (DDI_SUCCESS);
}

/*
 * Create a registry entry for one GAS field if the register is
 * present (addr != 0).  On failure, the caller unwinds.
 */
static int
pcc_type34_map_one(uint64_t addr, uint8_t space_id, uint8_t width,
	pcc_reg_entry_t **regp)
{
	if (addr == 0) {
		*regp = NULL;
		return (DDI_SUCCESS);
	}
	*regp = pcc_reg_lookup_or_create(addr, space_id, width);
	if (*regp == NULL) {
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

/*
 * pcc_type34_map: create register registry entries for all
 * Type 3/4 registers.  On any failure, unwind entries already
 * created and return DDI_FAILURE (channel unusable, valid
 * firmware description).
 */
static int
pcc_type34_map(pcc_chan_t *pc)
{
	if (pcc_type34_map_one(pc->pc_db_gas.addr,
		pc->pc_db_gas.space_id, pc->pc_db_gas.width,
		&pc->pc_db_reg) != DDI_SUCCESS) {
		goto fail;
	}
	if (pcc_type34_map_one(pc->pc_ack_gas.addr,
		pc->pc_ack_gas.space_id, pc->pc_ack_gas.width,
		&pc->pc_ack_reg) != DDI_SUCCESS) {
		goto fail;
	}
	if (pcc_type34_map_one(pc->pc_cc_check_gas.addr,
		pc->pc_cc_check_gas.space_id, pc->pc_cc_check_gas.width,
		&pc->pc_cc_check_reg) != DDI_SUCCESS) {
		goto fail;
	}
	if (pcc_type34_map_one(pc->pc_cc_update_gas.addr,
		pc->pc_cc_update_gas.space_id, pc->pc_cc_update_gas.width,
		&pc->pc_cc_update_reg) != DDI_SUCCESS) {
		goto fail;
	}
	if (pcc_type34_map_one(pc->pc_err_gas.addr,
		pc->pc_err_gas.space_id, pc->pc_err_gas.width,
		&pc->pc_err_reg) != DDI_SUCCESS) {
		goto fail;
	}
	return (DDI_SUCCESS);

fail:
	pcc_reg_release(&pc->pc_err_reg);
	pcc_reg_release(&pc->pc_cc_update_reg);
	pcc_reg_release(&pc->pc_cc_check_reg);
	pcc_reg_release(&pc->pc_ack_reg);
	pcc_reg_release(&pc->pc_db_reg);
	return (DDI_FAILURE);
}

/*
 * pcc_type34_unmap: release all registry entries for the channel.
 * Safe to call with NULL entries (pcc_reg_release handles NULL).
 */
static void
pcc_type34_unmap(pcc_chan_t *pc)
{
	pcc_reg_release(&pc->pc_err_reg);
	pcc_reg_release(&pc->pc_cc_update_reg);
	pcc_reg_release(&pc->pc_cc_check_reg);
	pcc_reg_release(&pc->pc_ack_reg);
	pcc_reg_release(&pc->pc_db_reg);
}

/*
 * pcc_type3_init: establish the idle state for a Type 3 initiator.
 * Read the Command Complete check register (AND with the mask).
 * Unlike Types 0-2, OSPM cannot set the idle state itself: for
 * initiator subspaces the Command Complete update set mask
 * *clears* Command Complete (ACPI 6.6 Table 14.7), so the
 * update-register RMW cannot set it; only the platform sets
 * Command Complete on an initiator (ACPI 6.6 s14.5 step 7).
 *
 * If Command Complete is set, the channel is idle and OSPM owns
 * the shared memory; nothing further is required (Flags is
 * rewritten on every send, so no stale state can persist).  If
 * it is clear, OSPM must not modify shared memory (ACPI 6.6
 * s14.2.2); poll bounded for the platform to release the
 * channel, else return PCC_INIT_UNUSABLE (valid description,
 * channel cannot be driven).
 */
static int
pcc_type3_init(pcc_chan_t *pc)
{
	uint64_t ccval;
	hrtime_t timeout_ns;
	hrtime_t expire;

	pcc_reg_read(pc->pc_cc_check_reg, &ccval);

	if ((ccval & pc->pc_cc_check_mask) == 0) {
		/*
		 * Platform still owns the channel.  Do not touch
		 * shared memory or the update register (the latter
		 * would clear Command Complete on an initiator).
		 * Wait a bounded time for the platform to release it.
		 */
		timeout_ns = (hrtime_t)pc->pc_nominal_lat *
			NANOSEC / MICROSEC;
		if (timeout_ns == 0) {
			timeout_ns = (hrtime_t)1000 * NANOSEC / MICROSEC;
		}
		timeout_ns *= PCC_TIMEOUT_MULTIPLIER;
		expire = gethrtime() + timeout_ns;
		for (;;) {
			pcc_reg_read(pc->pc_cc_check_reg, &ccval);
			if ((ccval & pc->pc_cc_check_mask) != 0) {
				break;
			}
			if (gethrtime() >= expire) {
				cmn_err(CE_WARN, "acpipcc: chan %u: Command "
					"Complete still clear after init timeout; "
					"channel unusable", pc->pc_id);
				return (PCC_INIT_UNUSABLE);
			}
			drv_usecwait(PCC_POLL_INTERVAL_US);
		}
	}

	return (DDI_SUCCESS);
}

/*
 * pcc_type4_init: advertise readiness for a Type 4 responder.
 * Set Command Complete via the Command Complete update register
 * (RMW with update preserve/set masks).  ACPI 6.6 s14.6.2:
 * "OSPM must set the Command Complete bit when it is ready to
 * receive notifications from the platform."  For responder
 * subspaces the update set mask *sets* Command Complete
 * (ACPI 6.6 Table 14.7), so this RMW establishes the idle state;
 * until it is done the platform sees "notification pending" and
 * will not send.
 */
static int
pcc_type4_init(pcc_chan_t *pc)
{
	pcc_reg_rmw(pc->pc_cc_update_reg,
		pc->pc_cc_update_preserve, pc->pc_cc_update_set);

	return (DDI_SUCCESS);
}

/*
 * pcc_type3_send_regs_try: non-blocking register sequence for a
 * Type 3 send on the panic path.  Clears Error Status, clears
 * Command Complete (transferring ownership to the platform),
 * and rings the doorbell.  Called with pc_lock held.
 *
 * The doorbell register lock is acquired first and held across
 * the Command Complete clear and the doorbell write: once
 * ownership is transferred the doorbell write cannot fail, so
 * the channel is never left wedged.  Every acquisition is a
 * try-lock; EBUSY is returned only before Command Complete is
 * cleared, so the caller still owns the channel and may retry.
 *
 * The registry dedupes entries by address/space/width, so
 * channel registers that describe the same GAS resolve to the
 * same entry: pointer equality detects the aliasing, and a lock
 * already held is not acquired again (kmutex is not recursive).
 */
static int
pcc_type3_send_regs_try(pcc_chan_t *pc)
{
	pcc_reg_entry_t *db = pc->pc_db_reg;
	pcc_reg_entry_t *err = pc->pc_err_reg;
	pcc_reg_entry_t *ccu = pc->pc_cc_update_reg;
	boolean_t err_held = B_FALSE;
	boolean_t ccu_held = B_FALSE;
	int ret;

	ASSERT(db != NULL);
	ASSERT(ccu != NULL);

	if (!mutex_tryenter(&db->pre_lock)) {
		return (EBUSY);
	}
	if (err != NULL && err != db) {
		if (!mutex_tryenter(&err->pre_lock)) {
			ret = EBUSY;
			goto out;
		}
		err_held = B_TRUE;
	}
	if (ccu != db && ccu != err) {
		if (!mutex_tryenter(&ccu->pre_lock)) {
			ret = EBUSY;
			goto out;
		}
		ccu_held = B_TRUE;
	}

	/* Clear stale error bits; we own the channel. */
	if (err != NULL) {
		pcc_reg_rmw_locked(err, ~pc->pc_err_mask, 0);
	}

	/*
	 * Clear Command Complete, transferring ownership to the
	 * platform.  The doorbell lock is held, so the ring below
	 * cannot fail.
	 */
	pcc_reg_rmw_locked(ccu, pc->pc_cc_update_preserve,
		pc->pc_cc_update_set);

	/* Ring the doorbell. */
	pcc_reg_rmw_locked(db, pc->pc_db_preserve, pc->pc_db_set);

	ret = DDI_SUCCESS;

out:
	if (ccu_held) {
		mutex_exit(&ccu->pre_lock);
	}
	if (err_held) {
		mutex_exit(&err->pre_lock);
	}
	mutex_exit(&db->pre_lock);
	return (ret);
}

/*
 * pcc_type3_prepare_send: set up a Type 3 transaction.  Called
 * with pc_lock held.  The consumer payload is already in the
 * Communication Space (offset 16+); this function writes the
 * 16-byte header and transfers ownership to the platform (the
 * doorbell ring is done by common code after this returns, or
 * in the trylock path below on the panic path).
 */
static int
pcc_type3_prepare_send(pcc_chan_t *pc, uint32_t cmd,
	uint32_t payload_len, boolean_t trylock)
{
	uint64_t ccval;
	volatile uint32_t *flagsp;
	volatile uint32_t *lenp;
	volatile uint32_t *cmdp;

	/* 1. Payload must fit in the Communication Space. */
	if (payload_len > pc->pc_shmem_len - pc->pc_hdr_len) {
		return (DDI_FAILURE);
	}

	/* 2. We must own the channel (Command Complete set). */
	pcc_reg_read(pc->pc_cc_check_reg, &ccval);
	if ((ccval & pc->pc_cc_check_mask) == 0) {
		return (DDI_FAILURE);
	}

	/*
	 * 3. Clear stale error bits.  The platform does not clear
	 * the Error Status register; a previous failed command
	 * (e.g. one that timed out before pto_check_error ran)
	 * would otherwise cause a false error report on this
	 * command.  Safe: we own the channel, so the platform is
	 * not touching it.
	 *
	 * Skipped on the panic path: pcc_reg_rmw may block on a
	 * register lock held by a stopped CPU, and
	 * pcc_type3_send_regs_try performs this same clear with
	 * try-locks.
	 */
	if (!trylock && pc->pc_err_reg != NULL) {
		pcc_reg_rmw(pc->pc_err_reg, ~pc->pc_err_mask, 0);
	}

	/* 4. Write 32-bit Flags (Notify on completion iff IRQ). */
	flagsp = (volatile uint32_t *)(void *)
		(pc->pc_shmem_va + PCC_EXT_SHMEM_FLAGS);
	if (pc->pc_has_irq) {
		*flagsp = PCC_EXT_FLAG_NOTIFY_ON_COMPLETE;
	} else {
		*flagsp = 0;
	}

	/*
	 * 5. Write 32-bit Length: size of Command field plus
	 * payload (ACPI 6.6 Table 14.12).
	 */
	lenp = (volatile uint32_t *)(void *)
		(pc->pc_shmem_va + PCC_EXT_SHMEM_LENGTH);
	*lenp = (uint32_t)sizeof (uint32_t) + payload_len;

	/* 6. Write 32-bit Command. */
	cmdp = (volatile uint32_t *)(void *)
		(pc->pc_shmem_va + PCC_EXT_SHMEM_CMD);
	*cmdp = cmd;

	/*
	 * 7. Ensure all shared-memory writes are observable by the
	 * platform before ownership is transferred (ACPI 6.6 s14.5).
	 */
	membar_producer();

	if (trylock) {
		/*
		 * Panic path: the register sequence (error clear,
		 * Command Complete clear, doorbell ring) must not
		 * block.  The helper acquires the doorbell lock first
		 * and holds it across the ownership transfer, so the
		 * channel can never be left wedged; EBUSY is only
		 * returned before ownership moves.
		 */
		return (pcc_type3_send_regs_try(pc));
	}

	/*
	 * 8. Clear Command Complete via the CmdUpdate register RMW,
	 * transferring ownership to the platform.
	 */
	pcc_reg_rmw(pc->pc_cc_update_reg,
		pc->pc_cc_update_preserve, pc->pc_cc_update_set);

	return (DDI_SUCCESS);
}

/*
 * pcc_type34_poll_complete: poll for command completion.  Sample
 * the Command Complete check register, AND with the mask.  Sets
 * *done = B_TRUE and returns DDI_SUCCESS when Command Complete
 * is set; returns DDI_FAILURE on timeout.  Does not check errors;
 * that is done afterwards by pto_check_error in the common
 * send path.
 */
static int
pcc_type34_poll_complete(pcc_chan_t *pc, boolean_t *done)
{
	uint64_t ccval;
	hrtime_t deadline;
	hrtime_t timeout;

	/*
	 * Nominal latency is in microseconds; give the platform a
	 * multiple of that before declaring the command lost.
	 */
	timeout = (hrtime_t)pc->pc_nominal_lat * PCC_TIMEOUT_MULTIPLIER *
		(NANOSEC / MICROSEC);
	if (timeout == 0) {
		timeout = (hrtime_t)1000 * PCC_TIMEOUT_MULTIPLIER *
			(NANOSEC / MICROSEC);
	}
	deadline = gethrtime() + timeout;

	*done = B_FALSE;
	for (;;) {
		pcc_reg_read(pc->pc_cc_check_reg, &ccval);
		if ((ccval & pc->pc_cc_check_mask) != 0) {
			*done = B_TRUE;
			return (DDI_SUCCESS);
		}
		if (gethrtime() >= deadline) {
			cmn_err(CE_WARN, "acpipcc: subspace %u: command "
				"completion timeout", pc->pc_id);
			return (DDI_FAILURE);
		}
		drv_usecwait(PCC_POLL_INTERVAL_US);
	}
}

/*
 * pcc_type34_check_error: check Error Status after command
 * completion.  ACPI 6.6 Table 14.7: "Error Status needs to be
 * checked after completion status indicates issued command has
 * been completed."  Read the Error Status register, AND with
 * the Error Status mask.  If the mask is 0, the Error Status
 * register is ignored (return DDI_SUCCESS).  If the masked
 * value is 0, the command succeeded.
 *
 * Note: The Error Status register may alias the Command Complete
 * check register (same address).  This function only reads; it
 * does not clear.  Clearing happens in pto_prepare_send via the
 * Command Complete update register, which handles the aliasing
 * correctly through the preserve/set masks.
 */
static int
pcc_type34_check_error(pcc_chan_t *pc)
{
	uint64_t val;

	if (pc->pc_err_mask == 0) {
		return (DDI_SUCCESS);
	}
	if (pc->pc_err_reg == NULL) {
		return (DDI_SUCCESS);
	}
	pcc_reg_read(pc->pc_err_reg, &val);
	if ((val & pc->pc_err_mask) != 0) {
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

/*
 * pcc_type34_irq_check: read-only peek at the Command Complete
 * check register to determine interrupt ownership.  For Type 3,
 * returns PCC_IRQ_CMD_COMPLETE if the Command Complete bit is
 * set.  For Type 4, returns PCC_IRQ_NOTIFY if the Command Complete
 * bit is clear: per ACPI 6.6 section 14.6.2 the platform clears
 * Command Complete when posting a notification, transferring
 * ownership to OSPM, so a clear bit on a shared interrupt means
 * the interrupt targeted this subspace.  Does NOT clear anything;
 * the Ack register is written by the handler via pcc_write_ack.
 */
static int
pcc_type34_irq_check(pcc_chan_t *pc, pcc_irq_result_t *result)
{
	uint64_t val;

	pcc_reg_read(pc->pc_cc_check_reg, &val);

	*result = PCC_IRQ_NONE;
	if (pc->pc_type == ACPI_PCCT_TYPE_EXT_PCC_SLAVE_SUBSPACE) {
		if ((val & pc->pc_cc_check_mask) == 0) {
			*result |= PCC_IRQ_NOTIFY;
		}
	} else {
		if ((val & pc->pc_cc_check_mask) != 0) {
			*result |= PCC_IRQ_CMD_COMPLETE;
		}
	}
	return (DDI_SUCCESS);
}

/*
 * pcc_type4_respond: complete the ACPI 6.6 s14.6.2 responder
 * protocol after the notification callback returns.  Called
 * from pcc_notify_channel with pc_lock held.
 */
void
pcc_type4_respond(pcc_chan_t *pc)
{
	volatile uint32_t *flagsp;

	/*
	 * ACPI 6.6 s14.6.2: "the OSPM must ensure that any writes in
	 * step 7 are observable by the platform before step 8
	 * completes."  Step 7 was the notification callback (which
	 * may have written response data to shared memory); step 8
	 * is setting Command Complete below.
	 */
	membar_producer();

	/* Set Command Complete via the CmdUpdate register. */
	pcc_reg_rmw(pc->pc_cc_update_reg,
		pc->pc_cc_update_preserve, pc->pc_cc_update_set);

	/*
	 * Ring the doorbell back if the platform asked for it via
	 * Notify on completion (Flags bit 0) and this subspace has
	 * a doorbell (optional for Type 4).
	 */
	flagsp = (volatile uint32_t *)(void *)
		(pc->pc_shmem_va + PCC_EXT_SHMEM_FLAGS);
	if (((*flagsp & PCC_EXT_FLAG_NOTIFY_ON_COMPLETE) != 0) &&
		pc->pc_has_doorbell) {
		pcc_ring_doorbell(pc);
	}
}

const pcc_type_ops_t pcc_type3_ops = {
	.pto_parse = pcc_type34_parse,
	.pto_map = pcc_type34_map,
	.pto_init = pcc_type3_init,
	.pto_unmap = pcc_type34_unmap,
	.pto_prepare_send = pcc_type3_prepare_send,
	.pto_poll_complete = pcc_type34_poll_complete,
	.pto_check_error = pcc_type34_check_error,
	.pto_irq_check = pcc_type34_irq_check,
	.pto_edge_only_irq = B_FALSE,
	.pto_irq_required = B_FALSE,
};

const pcc_type_ops_t pcc_type4_ops = {
	.pto_parse = pcc_type34_parse,
	.pto_map = pcc_type34_map,
	.pto_init = pcc_type4_init,
	.pto_unmap = pcc_type34_unmap,
	.pto_prepare_send = NULL,  /* Type 4 is responder-only */
	.pto_poll_complete = pcc_type34_poll_complete,
	.pto_check_error = pcc_type34_check_error,
	.pto_irq_check = pcc_type34_irq_check,
	.pto_edge_only_irq = B_FALSE,
	.pto_irq_required = B_TRUE,  /* Type 4 needs its interrupt */
};
