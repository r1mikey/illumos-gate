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
 * PCC Types 1 and 2 (HW-Reduced Communications Subspaces).
 *
 * ACPI 6.6 s14.1.4 (Type 1) and s14.1.5 (Type 2).  Both use the
 * 8-byte generic shared memory header (Signature, 16-bit Command,
 * 16-bit Status) described in s14.2, and both ring the platform
 * via a doorbell register.  Type 2 adds the Platform Interrupt
 * Ack register so that level-triggered interrupts can be cleared;
 * Type 1 has no ACK register and therefore only supports
 * edge-triggered interrupts (s14.1.4: "Type 1 subspaces do not
 * support a level triggered platform interrupt as no method is
 * provided to clear the interrupt"), so its ops set
 * pto_edge_only_irq = B_TRUE and common code falls back to
 * polling-only mode when a level interrupt is described.
 */

#include "pcc_impl.h"

/*
 * Validate a PCC register GAS field and copy it into the channel's
 * raw GAS storage.  Called by pto_parse only; performs no mapping.
 *
 * A zero Address means the register is absent (not an error); the
 * raw fields are zeroed and pto_map leaves the registry pointer
 * NULL.  All other validation failures are firmware validation
 * failures: the firmware description cannot be trusted, so parse
 * fails and the caller fails all PCC/CPPC.
 *
 * Returns DDI_SUCCESS or DDI_FAILURE.
 */
static int
pcc_type12_parse_gas(pcc_chan_t *pc, ACPI_GENERIC_ADDRESS *gas,
	uint64_t *addrp, uint8_t *space_idp, uint8_t *widthp,
	uint8_t *bit_offsetp, uint8_t *access_sizep, const char *name)
{
	if (gas->Address == 0) {
		*addrp = 0;
		*space_idp = 0;
		*widthp = 0;
		*bit_offsetp = 0;
		*access_sizep = 0;
		return (DDI_SUCCESS);
	}

	/*
	 * ACPI 6.6 s14.1.4/s14.1.5: only System I/O, System Memory,
	 * and Functional Fixed Hardware spaces are valid for PCC
	 * register GAS Address_Space_ID values.
	 */
	if (gas->SpaceId != ACPI_ADR_SPACE_SYSTEM_MEMORY &&
		gas->SpaceId != ACPI_ADR_SPACE_SYSTEM_IO &&
		gas->SpaceId != ACPI_ADR_SPACE_FIXED_HARDWARE) {
		cmn_err(CE_WARN, "acpipcc: subspace %u %s: invalid "
			"Address_Space_ID 0x%x; failing all PCC/CPPC",
			pc->pc_id, name, gas->SpaceId);
		return (DDI_FAILURE);
	}

	if (gas->BitWidth != 32 && gas->BitWidth != 64) {
		cmn_err(CE_WARN, "acpipcc: subspace %u %s: invalid "
			"BitWidth %u; failing all PCC/CPPC",
			pc->pc_id, name, gas->BitWidth);
		return (DDI_FAILURE);
	}

	/*
	 * The driver cannot address sub-register bit fields; a
	 * non-zero BitOffset is not representable in the register
	 * registry identity of (addr, space_id, width).
	 */
	if (gas->BitOffset != 0) {
		cmn_err(CE_WARN, "acpipcc: subspace %u %s: non-zero "
			"BitOffset %u unsupported; failing all PCC/CPPC",
			pc->pc_id, name, gas->BitOffset);
		return (DDI_FAILURE);
	}

	/*
	 * AccessSize (AccessWidth) must be consistent with BitWidth:
	 * 0 means undefined (any access), otherwise the access size
	 * must not exceed the register width.
	 */
	if (gas->BitWidth == 32) {
		if (gas->AccessWidth > 3) {
			cmn_err(CE_WARN, "acpipcc: subspace %u %s: "
				"AccessWidth %u inconsistent with 32-bit "
				"BitWidth; failing all PCC/CPPC",
				pc->pc_id, name, gas->AccessWidth);
			return (DDI_FAILURE);
		}
	} else {
		if (gas->AccessWidth > 4) {
			cmn_err(CE_WARN, "acpipcc: subspace %u %s: "
				"AccessWidth %u inconsistent with 64-bit "
				"BitWidth; failing all PCC/CPPC",
				pc->pc_id, name, gas->AccessWidth);
			return (DDI_FAILURE);
		}
	}

	*addrp = gas->Address;
	*space_idp = gas->SpaceId;
	*widthp = gas->BitWidth;
	*bit_offsetp = gas->BitOffset;
	*access_sizep = gas->AccessWidth;
	return (DDI_SUCCESS);
}

/*
 * Interlocked read of the Type 1/2 Status field.  ACPI 6.6 s14.5
 * requires interlocked access for all Status field accesses: the
 * platform sets bits concurrently with OSPM, so every read goes
 * through the same exclusive-access mechanism as the
 * read-modify-writes (atomic_and_16), rather than a plain
 * volatile load.  Status lives in KPM normal memory, so
 * exclusive accesses are safe here (never use atomics on
 * psm_map_phys device mappings).
 */
static uint16_t
pcc_type12_read_status(pcc_chan_t *pc)
{
	volatile uint16_t *status;

	status = (volatile uint16_t *)(void *)
		(pc->pc_shmem_va + PCC_SHMEM_STATUS);
	return (atomic_add_16_nv(status, 0));
}

/*
 * Extract the Type 1 / Type 2 subtable fields into the channel.
 * No mapping is done here; pto_map consumes the raw GAS fields.
 *
 * pc->pc_type and pc->pc_idx are set by the common parse loop
 * before this is called.  The firmware subspace ID is the
 * subtable's index in the PCCT list (ACPI 6.6 s14.1.2: "the
 * subspace ID is the index of the subspace in the PCCT"); there
 * is no ID field in the subtable itself.
 *
 * Returns DDI_SUCCESS or DDI_FAILURE (firmware validation
 * failure; caller fails all PCC/CPPC).
 */
int
pcc_type12_parse(void *subtable, pcc_chan_t *pc)
{
	ACPI_PCCT_HW_REDUCED *sub1;
	ACPI_PCCT_HW_REDUCED_TYPE2 *sub2;
	ACPI_GENERIC_ADDRESS *dbg;
	ACPI_GENERIC_ADDRESS *ackg;
	uint64_t base;
	uint64_t len;
	uint64_t preserve;
	uint64_t set;
	uint32_t latency;
	uint32_t max_rate;
	uint16_t turnaround;
	int ret;

	pc->pc_id = pc->pc_idx;

	if (pc->pc_type == ACPI_PCCT_TYPE_HW_REDUCED_SUBSPACE_TYPE2) {
		sub2 = (ACPI_PCCT_HW_REDUCED_TYPE2 *)subtable;
		base = sub2->BaseAddress;
		len = sub2->Length;
		dbg = &sub2->DoorbellRegister;
		preserve = sub2->PreserveMask;
		set = sub2->WriteMask;
		latency = sub2->Latency;
		max_rate = sub2->MaxAccessRate;
		turnaround = sub2->MinTurnaroundTime;
		ackg = &sub2->PlatformAckRegister;
		pc->pc_gsiv = sub2->PlatformInterrupt;
		pc->pc_irq_flags = sub2->Flags;
	} else {
		sub1 = (ACPI_PCCT_HW_REDUCED *)subtable;
		base = sub1->BaseAddress;
		len = sub1->Length;
		dbg = &sub1->DoorbellRegister;
		preserve = sub1->PreserveMask;
		set = sub1->WriteMask;
		latency = sub1->Latency;
		max_rate = sub1->MaxAccessRate;
		turnaround = sub1->MinTurnaroundTime;
		ackg = NULL;
		pc->pc_gsiv = sub1->PlatformInterrupt;
		pc->pc_irq_flags = sub1->Flags;
	}

	/*
	 * ACPI 6.6 Tables 14.4/14.5/14.6: Memory Length "Must be > 8".
	 * The 8-byte header leaves no Communication Space otherwise,
	 * so there is nowhere for a consumer payload to live.
	 */
	if (len <= PCC_SHMEM_HDR_LEN) {
		cmn_err(CE_WARN, "acpipcc: subspace %u: shared memory "
			"length %llu too short (must be > %u); failing all "
			"PCC/CPPC", pc->pc_id, (unsigned long long)len,
			PCC_SHMEM_HDR_LEN);
		return (DDI_FAILURE);
	}

	/*
	 * The doorbell is required for initiator subspaces (ACPI 6.6
	 * Table 14.7: it is optional only for responders).  Types 1
	 * and 2 are initiators; a zero doorbell address is a
	 * firmware validation failure.
	 */
	if (dbg->Address == 0) {
		cmn_err(CE_WARN, "acpipcc: subspace %u: doorbell register "
			"absent; failing all PCC/CPPC", pc->pc_id);
		return (DDI_FAILURE);
	}

	ret = pcc_type12_parse_gas(pc, dbg,
		&pc->pc_db_gas.addr, &pc->pc_db_gas.space_id,
		&pc->pc_db_gas.width, &pc->pc_db_gas.bit_offset,
		&pc->pc_db_gas.access_size, "doorbell");
	if (ret != DDI_SUCCESS) {
		return (ret);
	}

	if (ackg != NULL) {
		ret = pcc_type12_parse_gas(pc, ackg,
			&pc->pc_ack_gas.addr, &pc->pc_ack_gas.space_id,
			&pc->pc_ack_gas.width, &pc->pc_ack_gas.bit_offset,
			&pc->pc_ack_gas.access_size, "ack");
		if (ret != DDI_SUCCESS) {
			return (ret);
		}
		/*
		 * The ack masks ride along in the raw fields above.  The
		 * level-triggered-without-ack validation lives in common
		 * code, which also accounts for the PCCT global Platform
		 * Interrupt flag (Table 14.7: the GSI is ignored when the
		 * flag is clear).
		 */
		pc->pc_ack_preserve = sub2->AckPreserveMask;
		pc->pc_ack_set = sub2->AckWriteMask;
	} else {
		pc->pc_ack_gas.addr = 0;
		pc->pc_ack_gas.space_id = 0;
		pc->pc_ack_gas.width = 0;
		pc->pc_ack_gas.bit_offset = 0;
		pc->pc_ack_gas.access_size = 0;
		pc->pc_ack_preserve = 0;
		pc->pc_ack_set = 0;
	}

	/*
	 * ACPI 6.6 Table 14.7 sanctions no register aliasing for
	 * Types 1/2: the doorbell and ack registers must be distinct
	 * physical registers (the Status field lives in shared
	 * memory, not in a GAS register).  The firmware description
	 * cannot be trusted: fail all.
	 */
	if (pc->pc_ack_gas.addr != 0 &&
	    pc->pc_ack_gas.addr == pc->pc_db_gas.addr &&
	    pc->pc_ack_gas.space_id == pc->pc_db_gas.space_id) {
		cmn_err(CE_WARN, "acpipcc: subspace %u: ack register "
			"aliases doorbell register; failing all PCC/CPPC",
			pc->pc_id);
		return (DDI_FAILURE);
	}

	/*
	 * A zero doorbell WriteMask means the doorbell can never be
	 * rung: pcc_ring_doorbell's (val & preserve) | set would never
	 * set anything, so every send would time out.  The firmware
	 * description cannot be trusted: fail all.
	 */
	if (set == 0) {
		cmn_err(CE_WARN, "acpipcc: subspace %u: doorbell "
			"WriteMask is zero; failing all PCC/CPPC",
			pc->pc_id);
		return (DDI_FAILURE);
	}

	/*
	 * Set-mask bits above the register width are silently dropped
	 * by the width truncation in pcc_reg_write: the firmware asks
	 * to set a bit that can never be set.  The firmware
	 * description cannot be trusted: fail all.
	 */
	if (pc->pc_db_gas.width == 32 && set > UINT32_MAX) {
		cmn_err(CE_WARN, "acpipcc: subspace %u: doorbell "
			"WriteMask 0x%llx exceeds 32-bit register width; "
			"failing all PCC/CPPC", pc->pc_id,
			(unsigned long long)set);
		return (DDI_FAILURE);
	}
	if (pc->pc_ack_gas.addr != 0 && pc->pc_ack_gas.width == 32 &&
	    pc->pc_ack_set > UINT32_MAX) {
		cmn_err(CE_WARN, "acpipcc: subspace %u: ack WriteMask "
			"0x%llx exceeds 32-bit register width; failing all "
			"PCC/CPPC", pc->pc_id,
			(unsigned long long)pc->pc_ack_set);
		return (DDI_FAILURE);
	}

	pc->pc_shmem_pa = base;
	pc->pc_shmem_len = len;
	pc->pc_db_preserve = preserve;
	pc->pc_db_set = set;
	pc->pc_nominal_lat = latency;
	pc->pc_max_rate = max_rate;
	pc->pc_turnaround = turnaround;
	pc->pc_hdr_len = PCC_SHMEM_HDR_LEN;
	pc->pc_signature = PCC_SIGNATURE_BASE | pc->pc_id;
	pc->pc_valid = B_TRUE;
	return (DDI_SUCCESS);
}

/*
 * Create register registry entries for the doorbell (and, for
 * Type 2, the ack register).  On failure, unwind any entries
 * already created and return DDI_FAILURE with nothing
 * outstanding; the caller marks the channel unusable.
 */
int
pcc_type12_map(pcc_chan_t *pc)
{
	pc->pc_db_reg = pcc_reg_lookup_or_create(
		pc->pc_db_gas.addr, pc->pc_db_gas.space_id,
		pc->pc_db_gas.width);
	if (pc->pc_db_reg == NULL) {
		return (DDI_FAILURE);
	}

	if (pc->pc_type == ACPI_PCCT_TYPE_HW_REDUCED_SUBSPACE_TYPE2 &&
		pc->pc_ack_gas.addr != 0) {
		pc->pc_ack_reg = pcc_reg_lookup_or_create(
			pc->pc_ack_gas.addr, pc->pc_ack_gas.space_id,
			pc->pc_ack_gas.width);
		if (pc->pc_ack_reg == NULL) {
			pcc_reg_release(&pc->pc_db_reg);
			return (DDI_FAILURE);
		}
	}
	return (DDI_SUCCESS);
}

/*
 * Release every registry entry created by pcc_type12_map.
 * pcc_reg_release is NULL-safe, so partial mapping cleanup
 * needs no special cases.
 */
void
pcc_type12_unmap(pcc_chan_t *pc)
{
	pcc_reg_release(&pc->pc_ack_reg);
	pcc_reg_release(&pc->pc_db_reg);
}

/*
 * Prepare a Type 1/2 send.  Called with pc_lock held, after
 * timing enforcement.  The consumer payload is already in the
 * shared Communication Space (written via pcc_chan_write32/64).
 *
 * Returns DDI_SUCCESS or DDI_FAILURE.
 */
int
pcc_type12_prepare_send(pcc_chan_t *pc, uint32_t cmd,
	uint32_t __unused payload_len)
{
	volatile uint16_t *status;
	volatile uint16_t *cmdfield;
	uint16_t val;

	status = (volatile uint16_t *)(void *)
		(pc->pc_shmem_va + PCC_SHMEM_STATUS);
	cmdfield = (volatile uint16_t *)(void *)
		(pc->pc_shmem_va + PCC_SHMEM_CMD);

	/*
	 * ACPI 6.6 s14.5 step 1: OSPM must only proceed when Command
	 * Complete is set; otherwise the platform still owns the
	 * channel and has not released it.
	 */
	val = pcc_type12_read_status(pc);
	if ((val & PCC_STATUS_CMD_COMPLETE) == 0) {
		cmn_err(CE_WARN, "acpipcc: subspace %u: send with "
			"Command Complete clear (platform owns channel)",
			pc->pc_id);
		return (DDI_FAILURE);
	}

	/*
	 * ACPI 6.6 Table 14.10: the Command field is 16 bits wide;
	 * bits 0-7 are the command, bits 8-14 are reserved, bit 15
	 * is Notify on Completion.  The caller passes the command
	 * code only; reserved bits and bit 15 are not theirs to set.
	 */
	if (cmd > UINT8_MAX) {
		cmn_err(CE_WARN, "acpipcc: subspace %u: command 0x%x "
			"exceeds 8-bit command field", pc->pc_id, cmd);
		return (DDI_FAILURE);
	}

	/*
	 * Write the 16-bit Command field, setting Notify on
	 * Completion (bit 15) iff we have an interrupt.  The
	 * platform generates the completion interrupt only if this
	 * bit is set; without it, interrupt-driven completion would
	 * never fire and every send would time out.  When polling
	 * (pc_has_irq false) the bit stays clear so the platform
	 * does not raise an interrupt nobody handles.  pc_has_irq
	 * is false when the PCCT global Platform Interrupt flag is
	 * off, which satisfies Table 14.10's "must be cleared"
	 * rule.
	 *
	 * payload_len is ignored: the Type 0-2 header has no Length
	 * field; the platform determines the data extent from the
	 * subspace's fixed Length in the PCCT.
	 */
	*cmdfield = (uint16_t)cmd |
		(pc->pc_has_irq ? PCC_CMD_NOTIFY_ON_COMPLETE : 0);

	/*
	 * ACPI 6.6 s14.5 step 2: OSPM must ensure all shared memory
	 * writes are observable by the platform before the doorbell
	 * (step 4, rung by common code after this returns).
	 */
	membar_producer();

	/*
	 * Clear Command Complete (bit 0) to transfer ownership to the
	 * platform (s14.5 step 3), and clear a stale Error (bit 2)
	 * from the previous command: the Error bit reports on the
	 * "last command" and must not leak into this one.  Do NOT
	 * clear bits 1 (Platform Interrupt) or 3 (Platform
	 * Notification): they are platform-initiated events.  The
	 * Platform Interrupt bit is cleared by the interrupt handler
	 * (Table 14.11 note); the Platform Notification bit is
	 * cleared by pcc_type12_clear_notify.  Clearing them here
	 * would discard a concurrent platform notification.
	 *
	 * Interlocked access is required by ACPI 6.6 s14.5 for all
	 * Status field accesses: the platform can set the Platform
	 * Interrupt / Platform Notification bits concurrently, and a
	 * plain volatile read-modify-write under the channel mutex
	 * would lose them.  The mutex still serializes OSPM threads;
	 * the atomicity is for the platform race.  Safe: Status lives
	 * in KPM normal memory, not a device-memory mapping.
	 */
	atomic_and_16(status, (uint16_t)~(PCC_STATUS_CMD_COMPLETE |
		PCC_STATUS_ERROR));

	return (DDI_SUCCESS);
}

/*
 * Poll for command completion.  Checks only the completion
 * condition; error checking is done afterwards by
 * pto_check_error in the common send path.
 *
 * Sets *responded = B_TRUE and returns DDI_SUCCESS when Command
 * Complete is set; returns DDI_FAILURE on timeout.
 */
int
pcc_type12_poll_complete(pcc_chan_t *pc, boolean_t *responded)
{
	hrtime_t deadline;
	hrtime_t timeout;

	/*
	 * Nominal latency is in microseconds; give the platform a
	 * multiple of that before declaring the command lost.  A zero
	 * nominal latency gets the same 1000us floor used elsewhere.
	 */
	timeout = (hrtime_t)pc->pc_nominal_lat * PCC_TIMEOUT_MULTIPLIER *
		(NANOSEC / MICROSEC);
	if (timeout == 0) {
		timeout = (hrtime_t)1000 * PCC_TIMEOUT_MULTIPLIER *
			(NANOSEC / MICROSEC);
	}
	deadline = gethrtime() + timeout;

	*responded = B_FALSE;
	for (;;) {
		if ((pcc_type12_read_status(pc) &
		    PCC_STATUS_CMD_COMPLETE) != 0) {
			*responded = B_TRUE;
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
 * Check the platform-reported error status after completion.
 * Returns DDI_SUCCESS when the platform reports no error,
 * DDI_FAILURE when the Error bit is set.  A platform error is
 * reported to the caller distinctly from a transport failure:
 * common code keeps the response visible to the consumer and
 * returns success to the transport, per the plan's error
 * semantics.
 */
int
pcc_type12_check_error(pcc_chan_t *pc)
{
	uint16_t val;

	val = pcc_type12_read_status(pc);

	if ((val & PCC_STATUS_ERROR) != 0) {
		cmn_err(CE_WARN, "acpipcc: subspace %u: platform "
			"reported command error (status 0x%x)",
			pc->pc_id, val);
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

/*
 * Read-only ownership peek at the Status field for the
 * interrupt handler.  Sets *result to PCC_IRQ_CMD_COMPLETE if
 * bit 0 (Command Complete) is set, PCC_IRQ_NOTIFY if bit 3
 * (Platform Notification) is set.  Bit 1 (Platform Interrupt)
 * merely indicates the platform raised an interrupt to this
 * subspace (ACPI 6.6 Table 14.11); it is set for both command
 * completions and notifications, so it cannot distinguish
 * them.  Report it separately via PCC_IRQ_PLATFORM_IRQ so the
 * handler can clear it even when set alone.  Does NOT clear
 * anything; the handler clears bit 1, and bits 1 and 3 via
 * pcc_type12_clear_notify.  Notifications are deprecated
 * (ACPI 6.6 s14.6.1) and unsupported: the handler discards them
 * without dispatching.
 */
static int
pcc_type12_irq_check(pcc_chan_t *pc, pcc_irq_result_t *result)
{
	uint16_t val;

	val = pcc_type12_read_status(pc);

	*result = PCC_IRQ_NONE;
	if ((val & PCC_STATUS_CMD_COMPLETE) != 0) {
		*result |= PCC_IRQ_CMD_COMPLETE;
	}
	if ((val & PCC_STATUS_PLATFORM_NOTIFY) != 0) {
		*result |= PCC_IRQ_NOTIFY;
	}
	if ((val & PCC_STATUS_PLATFORM_IRQ) != 0) {
		*result |= PCC_IRQ_PLATFORM_IRQ;
	}
	return (DDI_SUCCESS);
}

/*
 * Clear stray platform notification bits (1 and 3) in the Status
 * field.  Notifications are deprecated (ACPI 6.6 s14.6.1) and
 * unsupported; the interrupt handler discards them here without
 * dispatching.  Called without pc_lock held; uses an interlocked
 * clear for the same platform race described in
 * pcc_type12_prepare_send.  Status is KPM normal memory.
 */
void
pcc_type12_clear_notify(pcc_chan_t *pc)
{
	volatile uint16_t *status;

	status = (volatile uint16_t *)(void *)
		(pc->pc_shmem_va + PCC_SHMEM_STATUS);
	atomic_and_16(status, (uint16_t)~(PCC_STATUS_PLATFORM_IRQ |
		PCC_STATUS_PLATFORM_NOTIFY));
}

/*
 * pcc_type12_init: wait for the platform to release the channel.
 * Unlike Type 3, Types 1-2 have no separate check register: the
 * Command Complete bit lives in the shared-memory Status field.
 * If it is clear at init, the platform still owns the channel and
 * OSPM must not touch shared memory; poll bounded (like
 * pcc_type3_init) for the platform to release it, else return
 * PCC_INIT_UNUSABLE (valid description, channel cannot be
 * driven).  Read-only: never modifies shared memory.
 */
static int
pcc_type12_init(pcc_chan_t *pc)
{
	hrtime_t timeout_ns;
	hrtime_t expire;

	if ((pcc_type12_read_status(pc) & PCC_STATUS_CMD_COMPLETE) != 0) {
		return (DDI_SUCCESS);
	}

	/*
	 * Platform still owns the channel.  Wait a bounded time
	 * for it to be released.
	 */
	timeout_ns = (hrtime_t)pc->pc_nominal_lat * NANOSEC / MICROSEC;
	if (timeout_ns == 0) {
		timeout_ns = (hrtime_t)1000 * NANOSEC / MICROSEC;
	}
	timeout_ns *= PCC_TIMEOUT_MULTIPLIER;
	expire = gethrtime() + timeout_ns;
	for (;;) {
		if ((pcc_type12_read_status(pc) &
		    PCC_STATUS_CMD_COMPLETE) != 0) {
			break;
		}
		if (gethrtime() >= expire) {
			cmn_err(CE_WARN, "acpipcc: subspace %u: Command "
				"Complete still clear after init timeout; "
				"channel unusable", pc->pc_id);
			return (PCC_INIT_UNUSABLE);
		}
		drv_usecwait(PCC_POLL_INTERVAL_US);
	}

	return (DDI_SUCCESS);
}

const pcc_type_ops_t pcc_type1_ops = {
	.pto_parse = pcc_type12_parse,
	.pto_map = pcc_type12_map,
	.pto_init = pcc_type12_init,
	.pto_unmap = pcc_type12_unmap,
	.pto_prepare_send = pcc_type12_prepare_send,
	.pto_poll_complete = pcc_type12_poll_complete,
	.pto_check_error = pcc_type12_check_error,
	.pto_irq_check = pcc_type12_irq_check,
	.pto_edge_only_irq = B_TRUE,    /* Type 1: no level IRQ clear */
};

const pcc_type_ops_t pcc_type2_ops = {
	.pto_parse = pcc_type12_parse,
	.pto_map = pcc_type12_map,
	.pto_init = pcc_type12_init,
	.pto_unmap = pcc_type12_unmap,
	.pto_prepare_send = pcc_type12_prepare_send,
	.pto_poll_complete = pcc_type12_poll_complete,
	.pto_check_error = pcc_type12_check_error,
	.pto_irq_check = pcc_type12_irq_check,
	.pto_edge_only_irq = B_FALSE,   /* Type 2 has Ack register */
};
