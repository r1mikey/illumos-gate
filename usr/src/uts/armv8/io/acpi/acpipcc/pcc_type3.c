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
 * PCC Type 3: Extended PCC Master subspace.
 *
 * Type 3 is the initiator (OSPM drives commands, platform responds).
 * It uses the 16-byte extended shared memory header and the external
 * Command Complete / Error Status register model (ACPI 6.6 s14.1.6,
 * s14.1.7, Table 14.7, Table 14.8).
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
pcc_type3_validate_gas(ACPI_GENERIC_ADDRESS *gas)
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
				"AccessWidth (%u) for 32-bit width; "
				"failing all PCC/CPPC", gas->AccessWidth);
			return (DDI_FAILURE);
		}
	} else if (gas->BitWidth == 64) {
		if (gas->AccessWidth > 4) {
			cmn_err(CE_WARN, "acpipcc: PCC register has invalid "
				"AccessWidth (%u) for 64-bit width; "
				"failing all PCC/CPPC", gas->AccessWidth);
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
#define	PCC_STORE_GAS(dst, src) \
	do { \
		(dst).addr = (src)->Address; \
		(dst).space_id = (src)->SpaceId; \
		(dst).width = (src)->BitWidth; \
		(dst).bit_offset = (src)->BitOffset; \
		(dst).access_size = (src)->AccessWidth; \
	} while (0)

/*
 * Physical register identity is (addr, space_id, width): the
 * registry dedupes entries by all three, and the send path uses
 * pointer equality to detect aliasing.  Two descriptors naming
 * the same address/space at different widths would be distinct
 * entries sharing one physical register, defeating both - and
 * Table 14.7's sanctioned aliasing ("the same register")
 * implies a single width.
 */
#define	PCC_GAS_WIDTH_MISMATCH(a, b) \
	((a).addr != 0 && (b).addr != 0 && \
	(a).addr == (b).addr && (a).space_id == (b).space_id && \
	(a).width != (b).width)

/*
 * Unsanctioned register aliasing: two descriptors naming the same
 * physical register (address and space).  Table 14.7 sanctions
 * aliasing only for the Command Complete update and Error Status
 * registers against the check register; the doorbell and ack
 * registers must be distinct physical registers.
 */
#define	PCC_GAS_ALIASES(a, b) \
	((a).addr != 0 && (b).addr != 0 && \
	(a).addr == (b).addr && (a).space_id == (b).space_id)

/*
 * pcc_type3_parse: extract Type 3 fields from the ACPICA subtable
 * (ACPI_PCCT_EXT_PCC_MASTER) into the channel.  Stores raw GAS
 * fields; registry entries are created in pto_map.
 */
static int
pcc_type3_parse(void *subtable, pcc_chan_t *pc)
{
	ACPI_PCCT_EXT_PCC_MASTER *sub = subtable;

	/*
	 * ACPI 6.6 s14.1.2: the firmware subspace ID is the
	 * subtable's index in the PCCT list; there is no explicit
	 * ID field in the subtable.
	 */
	pc->pc_id = pc->pc_idx;

	if (pcc_type3_validate_gas(&sub->DoorbellRegister) !=
		DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	if (pcc_type3_validate_gas(&sub->PlatformAckRegister) !=
		DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	if (pcc_type3_validate_gas(&sub->CmdCompleteRegister) !=
		DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	if (pcc_type3_validate_gas(&sub->CmdUpdateRegister) !=
		DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	if (pcc_type3_validate_gas(&sub->ErrorStatusRegister) !=
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
		cmn_err(CE_WARN, "acpipcc: Type 3 subspace %u has invalid "
			"shared memory length %u; failing all PCC/CPPC",
			pc->pc_id, sub->Length);
		return (DDI_FAILURE);
	}

	/*
	 * The doorbell is required for the initiator (ACPI 6.6
	 * Table 14.7: optional only for responders, which this
	 * driver does not implement).  A zero address is a firmware
	 * validation failure.
	 */
	if (sub->DoorbellRegister.Address == 0) {
		cmn_err(CE_WARN, "acpipcc: Type 3 subspace %u has no "
			"doorbell register; failing all PCC/CPPC", pc->pc_id);
		return (DDI_FAILURE);
	}

	/*
	 * The Command Complete check and update registers are the
	 * core of the Type 3 protocol; both are required.
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
	/*
	 * A zero Command Complete check mask makes the ownership
	 * protocol impossible: (reg & 0) != 0 is never true, so the
	 * channel could never be used.  The firmware description
	 * cannot be trusted: fail all.
	 */
	if (pc->pc_cc_check_mask == 0) {
		cmn_err(CE_WARN, "acpipcc: subspace %u: zero Command "
			"Complete check mask; failing all PCC/CPPC",
			pc->pc_id);
		return (DDI_FAILURE);
	}
	PCC_STORE_GAS(pc->pc_cc_update_gas, &sub->CmdUpdateRegister);
	pc->pc_cc_update_preserve = sub->CmdUpdatePreserveMask;
	pc->pc_cc_update_set = sub->CmdUpdateSetMask;
	PCC_STORE_GAS(pc->pc_err_gas, &sub->ErrorStatusRegister);
	pc->pc_err_mask = sub->ErrorStatusMask;
	/*
	 * A width mismatch on the same physical register is a
	 * malformed firmware description: the alias checks below
	 * compare (addr, space_id) and the mask math assumes one
	 * width.  The firmware description cannot be trusted:
	 * fail all.
	 */
	if (PCC_GAS_WIDTH_MISMATCH(pc->pc_cc_check_gas,
	    pc->pc_cc_update_gas) ||
	    PCC_GAS_WIDTH_MISMATCH(pc->pc_err_gas, pc->pc_cc_check_gas) ||
	    PCC_GAS_WIDTH_MISMATCH(pc->pc_err_gas, pc->pc_cc_update_gas) ||
	    PCC_GAS_WIDTH_MISMATCH(pc->pc_db_gas, pc->pc_cc_check_gas) ||
	    PCC_GAS_WIDTH_MISMATCH(pc->pc_db_gas, pc->pc_cc_update_gas) ||
	    PCC_GAS_WIDTH_MISMATCH(pc->pc_db_gas, pc->pc_err_gas) ||
	    PCC_GAS_WIDTH_MISMATCH(pc->pc_db_gas, pc->pc_ack_gas) ||
	    PCC_GAS_WIDTH_MISMATCH(pc->pc_ack_gas, pc->pc_cc_check_gas) ||
	    PCC_GAS_WIDTH_MISMATCH(pc->pc_ack_gas, pc->pc_cc_update_gas) ||
	    PCC_GAS_WIDTH_MISMATCH(pc->pc_ack_gas, pc->pc_err_gas)) {
		cmn_err(CE_WARN, "acpipcc: subspace %u: same physical "
		    "register described at different widths; failing "
		    "all PCC/CPPC", pc->pc_id);
		return (DDI_FAILURE);
	}
	/*
	 * ACPI 6.6 Table 14.7 permits the Error Status register to be
	 * the same register as the Command Complete check register,
	 * but the two masks must not overlap: the stale-error clear
	 * in pto_prepare_send (an RMW with ~ErrorStatusMask) would
	 * otherwise wipe Command Complete immediately after the
	 * ownership check verified it set, handing the platform a
	 * torn command.  The firmware description cannot be trusted:
	 * fail all.
	 */
	if (pc->pc_err_gas.addr != 0 &&
	    pc->pc_err_gas.addr == pc->pc_cc_check_gas.addr &&
	    pc->pc_err_gas.space_id == pc->pc_cc_check_gas.space_id &&
	    (pc->pc_err_mask & pc->pc_cc_check_mask) != 0) {
		cmn_err(CE_WARN, "acpipcc: subspace %u: Error Status "
			"mask overlaps Command Complete check mask on "
			"the same register; failing all PCC/CPPC",
			pc->pc_id);
		return (DDI_FAILURE);
	}
	/*
	 * Table 14.7 sanctions exactly one register aliasing for
	 * Error Status: the Command Complete check register (with
	 * non-overlapping masks, checked above).  It does not
	 * sanction aliasing the Command Complete *update* register:
	 * the stale-error clear in pto_prepare_send (an RMW with
	 * ~ErrorStatusMask) would then write the update register,
	 * which the platform interprets as a Command Complete
	 * update, transferring ownership before the header is
	 * written.  The firmware description cannot be trusted:
	 * fail all.  (When the update register is the same
	 * physical register as the check register, err == update
	 * implies err == check, which the overlap check above
	 * already validated.)
	 */
	if (pc->pc_err_gas.addr != 0 &&
	    pc->pc_err_gas.addr == pc->pc_cc_update_gas.addr &&
	    pc->pc_err_gas.space_id == pc->pc_cc_update_gas.space_id &&
	    (pc->pc_cc_update_gas.addr != pc->pc_cc_check_gas.addr ||
	    pc->pc_cc_update_gas.space_id != pc->pc_cc_check_gas.space_id)) {
		cmn_err(CE_WARN, "acpipcc: subspace %u: Error Status "
			"register aliases the Command Complete update "
			"register; failing all PCC/CPPC", pc->pc_id);
		return (DDI_FAILURE);
	}
	/*
	 * Table 14.7 sanctions no aliasing for the doorbell or ack
	 * registers: the only sanctioned aliasings are the Command
	 * Complete update register and the Error Status register
	 * against the check register (validated above).  A doorbell
	 * or ack register sharing a physical register with any other
	 * PCC register would make the RMW sequences incoherent.
	 * The firmware description cannot be trusted: fail all.
	 */
	if (PCC_GAS_ALIASES(pc->pc_db_gas, pc->pc_cc_check_gas) ||
	    PCC_GAS_ALIASES(pc->pc_db_gas, pc->pc_cc_update_gas) ||
	    PCC_GAS_ALIASES(pc->pc_db_gas, pc->pc_err_gas) ||
	    PCC_GAS_ALIASES(pc->pc_db_gas, pc->pc_ack_gas) ||
	    PCC_GAS_ALIASES(pc->pc_ack_gas, pc->pc_cc_check_gas) ||
	    PCC_GAS_ALIASES(pc->pc_ack_gas, pc->pc_cc_update_gas) ||
	    PCC_GAS_ALIASES(pc->pc_ack_gas, pc->pc_err_gas)) {
		cmn_err(CE_WARN, "acpipcc: subspace %u: doorbell or ack "
			"register aliases another PCC register; failing "
			"all PCC/CPPC", pc->pc_id);
		return (DDI_FAILURE);
	}
	pc->pc_gsiv = sub->PlatformInterrupt;
	pc->pc_irq_flags = sub->Flags;
	pc->pc_hdr_len = PCC_EXT_SHMEM_HDR_LEN;
	pc->pc_signature = PCC_SIGNATURE_BASE | pc->pc_id;

	return (DDI_SUCCESS);
}

/*
 * Create a registry entry for one GAS field if the register is
 * present (addr != 0).  On failure, the caller unwinds.
 */
static int
pcc_type3_map_one(uint64_t addr, uint8_t space_id, uint8_t width,
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
 * pcc_type3_map: create register registry entries for all
 * Type 3 registers.  On any failure, unwind entries already
 * created and return DDI_FAILURE (channel unusable, valid
 * firmware description).
 */
static int
pcc_type3_map(pcc_chan_t *pc)
{
	if (pcc_type3_map_one(pc->pc_db_gas.addr,
		pc->pc_db_gas.space_id, pc->pc_db_gas.width,
		&pc->pc_db_reg) != DDI_SUCCESS) {
		goto fail;
	}
	if (pcc_type3_map_one(pc->pc_ack_gas.addr,
		pc->pc_ack_gas.space_id, pc->pc_ack_gas.width,
		&pc->pc_ack_reg) != DDI_SUCCESS) {
		goto fail;
	}
	if (pcc_type3_map_one(pc->pc_cc_check_gas.addr,
		pc->pc_cc_check_gas.space_id, pc->pc_cc_check_gas.width,
		&pc->pc_cc_check_reg) != DDI_SUCCESS) {
		goto fail;
	}
	if (pcc_type3_map_one(pc->pc_cc_update_gas.addr,
		pc->pc_cc_update_gas.space_id, pc->pc_cc_update_gas.width,
		&pc->pc_cc_update_reg) != DDI_SUCCESS) {
		goto fail;
	}
	if (pcc_type3_map_one(pc->pc_err_gas.addr,
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
 * pcc_type3_unmap: release all registry entries for the channel.
 * Safe to call with NULL entries (pcc_reg_release handles NULL).
 */
static void
pcc_type3_unmap(pcc_chan_t *pc)
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
				    "Complete still clear after init "
				    "timeout; channel unusable", pc->pc_id);
				return (PCC_INIT_UNUSABLE);
			}
			drv_usecwait(PCC_POLL_INTERVAL_US);
		}
	}

	return (DDI_SUCCESS);
}

/*
 * pcc_type3_prepare_send: set up a Type 3 transaction.  Called
 * with pc_lock held.  The consumer payload is already in the
 * Communication Space (offset 16+); this function writes the
 * 16-byte header and transfers ownership to the platform (the
 * doorbell ring is done by common code after this returns).
 */
static int
pcc_type3_prepare_send(pcc_chan_t *pc, uint32_t cmd,
	uint32_t payload_len)
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
	 */
	if (pc->pc_err_reg != NULL) {
		pcc_reg_rmw(pc->pc_err_reg, ~pc->pc_err_mask, 0);
	}

	/*
	 * 4. Write 32-bit Flags: Notify on completion iff we have
	 * an interrupt.
	 */
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

	/*
	 * 8. Clear Command Complete via the CmdUpdate register RMW,
	 * transferring ownership to the platform.
	 */
	pcc_reg_rmw(pc->pc_cc_update_reg,
		pc->pc_cc_update_preserve, pc->pc_cc_update_set);

	return (DDI_SUCCESS);
}

/*
 * pcc_type3_poll_complete: poll for command completion.  Sample
 * the Command Complete check register, AND with the mask.  Sets
 * *done = B_TRUE and returns DDI_SUCCESS when Command Complete
 * is set; returns DDI_FAILURE on timeout.  Does not check errors;
 * that is done afterwards by pto_check_error in the common
 * send path.
 */
static int
pcc_type3_poll_complete(pcc_chan_t *pc, boolean_t *done)
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
 * pcc_type3_check_error: check Error Status after command
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
pcc_type3_check_error(pcc_chan_t *pc)
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
 * pcc_type3_irq_check: read-only peek at the Command Complete
 * check register to determine interrupt ownership.  Returns
 * PCC_IRQ_CMD_COMPLETE if the Command Complete bit is set.
 * Does NOT clear anything; the Ack register is written by the
 * handler via pcc_write_ack.
 */
static int
pcc_type3_irq_check(pcc_chan_t *pc, pcc_irq_result_t *result)
{
	uint64_t val;

	pcc_reg_read(pc->pc_cc_check_reg, &val);

	*result = PCC_IRQ_NONE;
	if ((val & pc->pc_cc_check_mask) != 0) {
		*result |= PCC_IRQ_CMD_COMPLETE;
	}
	return (DDI_SUCCESS);
}

const pcc_type_ops_t pcc_type3_ops = {
	.pto_parse = pcc_type3_parse,
	.pto_map = pcc_type3_map,
	.pto_init = pcc_type3_init,
	.pto_unmap = pcc_type3_unmap,
	.pto_prepare_send = pcc_type3_prepare_send,
	.pto_poll_complete = pcc_type3_poll_complete,
	.pto_check_error = pcc_type3_check_error,
	.pto_irq_check = pcc_type3_irq_check,
	.pto_edge_only_irq = B_FALSE,
};
