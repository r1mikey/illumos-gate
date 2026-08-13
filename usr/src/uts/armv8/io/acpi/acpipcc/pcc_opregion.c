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
 * PCC OperationRegion handler for illumos/aarch64.
 *
 * Implements the PCC address space handler (ACPI 6.6 section 5.5.2.4.8)
 * for AML OperationRegion(name, PCC, subspace-id, Length) declarations.
 * Address space ID is ACPI_ADR_SPACE_PLATFORM_COMM (0x0A).
 *
 * Only Type 3 (Extended PCC Master Subspace) is supported:
 * - Type 4 is forbidden for OpRegions by ACPI 6.6 section 5.5.2.4.8.1.
 * - Types 0-2 are rejected because ACPICA buffers their writes without
 *   ever invoking the OS handler to trigger transmission.
 *
 * The handler triggers transmission on writes to the CMD field
 * (OpRegion offset 8, 32-bit).  All other field accesses read or write
 * the channel's shared memory directly.
 */

#include <sys/types.h>
#include <sys/mutex.h>
#include <sys/atomic.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/acpi/acpi.h>

#include "pcc_impl.h"

/*
 * Protects the shared ACPI_PCC_INFO HandlerContext across concurrent
 * Setup calls.  AcpiEvAddressSpaceDispatch exits the interpreter before
 * calling Setup, so concurrent region activations are possible.
 */
static kmutex_t pcc_opregion_lock;

/*
 * Tracks whether the handler is installed.  pcc_opregion_unregister
 * is a no-op when the handler was never installed (e.g. the
 * pcc_init unwind path after a failed register).
 */
static boolean_t pcc_opregion_registered = B_FALSE;

/*
 * Forward declarations.
 */
static ACPI_STATUS pcc_opregion_setup(ACPI_HANDLE, UINT32, void *,
	void **);
static ACPI_STATUS pcc_opregion_handler(UINT32, ACPI_PHYSICAL_ADDRESS,
	UINT32, UINT64 *, void *, void *);
static int pcc_opregion_transmit(pcc_chan_t *, uint32_t);

int
pcc_opregion_register(void)
{
	ACPI_STATUS status;
	static ACPI_PCC_INFO pcc_opregion_ctx;

	/*
	 * Idempotent: a second call is a no-op.  Without this, a
	 * repeat call would re-init the live pcc_opregion_lock and,
	 * when AcpiInstallAddressSpaceHandler fails, destroy the
	 * mutex guarding the installed handler.
	 */
	if (pcc_opregion_registered) {
		return (DDI_SUCCESS);
	}

	mutex_init(&pcc_opregion_lock, NULL, MUTEX_DEFAULT, NULL);

	status = AcpiInstallAddressSpaceHandler(ACPI_ROOT_OBJECT,
		ACPI_ADR_SPACE_PLATFORM_COMM,
		pcc_opregion_handler, pcc_opregion_setup, &pcc_opregion_ctx);
	if (ACPI_FAILURE(status)) {
		cmn_err(CE_WARN, "acpipcc: failed to install PCC OpRegion "
			"handler: %s", AcpiFormatException(status));
		mutex_destroy(&pcc_opregion_lock);
		return (DDI_FAILURE);
	}
	pcc_opregion_registered = B_TRUE;
	return (DDI_SUCCESS);
}

void
pcc_opregion_unregister(void)
{
	if (!pcc_opregion_registered) {
		return;
	}
	pcc_opregion_registered = B_FALSE;
	(void) AcpiRemoveAddressSpaceHandler(ACPI_ROOT_OBJECT,
		ACPI_ADR_SPACE_PLATFORM_COMM, pcc_opregion_handler);
	mutex_destroy(&pcc_opregion_lock);
}

/*
 * Setup function for PCC OperationRegions.
 *
 * On ACTIVATE: validates the subspace, checks exclusivity, and stores
 * the channel pointer in *RegionContext for the handler to use.
 * On DEACTIVATE: clears pc_opregion and NULLs the RegionContext.
 *
 * The HandlerContext is the shared ACPI_PCC_INFO populated by ACPICA
 * per-region before Setup runs.  Copy out the SubspaceId under
 * pcc_opregion_lock; do not retain a pointer to the shared info.
 */
static ACPI_STATUS
pcc_opregion_setup(ACPI_HANDLE RegionHandle, UINT32 Function,
	void *HandlerContext, void **RegionContext)
{
	ACPI_PCC_INFO *info = (ACPI_PCC_INFO *)HandlerContext;
	pcc_chan_t *pc;
	uint32_t subspace_id;

	(void) RegionHandle;

	/*
	 * Copy the SubspaceId under the opregion lock.  The ACPI_PCC_INFO
	 * is shared across all PCC regions, and Setup can run concurrently
	 * (ACPICA exits the interpreter before calling Setup).
	 */
	mutex_enter(&pcc_opregion_lock);
	subspace_id = info->SubspaceId;
	mutex_exit(&pcc_opregion_lock);

	if (Function == ACPI_REGION_DEACTIVATE) {
		/*
		 * Read and clear the RegionContext under the opregion
		 * lock: a concurrent ACTIVATE on this region writes the
		 * same pointer.  The channel flag is cleared afterwards
		 * under pc_lock; the two locks are never nested.
		 */
		mutex_enter(&pcc_opregion_lock);
		pc = (pcc_chan_t *)(*RegionContext);
		*RegionContext = NULL;
		mutex_exit(&pcc_opregion_lock);
		if (pc != NULL) {
			mutex_enter(&pc->pc_lock);
			pc->pc_opregion = B_FALSE;
			mutex_exit(&pc->pc_lock);
		}
		return (AE_OK);
	}

	/* ACPI_REGION_ACTIVATE */

	/*
	 * Only Type 3 is supported.  Types 0-2 would buffer silently
	 * without ever triggering transmission, and Type 4 is forbidden
	 * for OpRegions by ACPI 6.6 section 5.5.2.4.8.1.
	 *
	 * Use internal lookup by firmware subspace ID, not pcc_chan_get:
	 * Setup is not a consumer, and must distinguish "already in use"
	 * from "does not exist".
	 */
	if (!pcc_initialised) {
		return (AE_NOT_EXIST);
	}
	pc = pcc_chan_lookup(subspace_id);
	if (pc == NULL) {
		return (AE_NOT_EXIST);
	}
	if (pc->pc_type != ACPI_PCCT_TYPE_EXT_PCC_MASTER_SUBSPACE) {
		return (AE_BAD_PARAMETER);
	}

	mutex_enter(&pc->pc_lock);
	if (!pc->pc_usable) {
		mutex_exit(&pc->pc_lock);
		return (AE_NOT_EXIST);
	}
	if (pc->pc_opregion) {
		mutex_exit(&pc->pc_lock);
		return (AE_ALREADY_EXISTS);
	}
	if (pc->pc_refcnt > 0) {
		/*
		 * Firmware bug: the same subspace is assigned to both an
		 * OpRegion and a PCC consumer (CPPC/RASF/PDTT/MPST),
		 * violating ACPI 6.6 section 5.5.2.4.8.1.  Fail the region
		 * activation; do not share the channel.
		 */
		cmn_err(CE_WARN, "acpipcc: PCC subspace %u used by both "
			"OpRegion and consumer (firmware bug)", subspace_id);
		mutex_exit(&pc->pc_lock);
		return (AE_ALREADY_EXISTS);
	}
	pc->pc_opregion = B_TRUE;
	mutex_exit(&pc->pc_lock);

	/*
	 * Store the RegionContext under the opregion lock, paired
	 * with the DEACTIVATE path above.
	 */
	mutex_enter(&pcc_opregion_lock);
	*RegionContext = pc;
	mutex_exit(&pcc_opregion_lock);
	return (AE_OK);
}

/*
 * Handler function for PCC OperationRegions.
 *
 * ACPICA passes Address = Region.Address (subspace ID) + field offset.
 * The OpRegion covers shared memory after the 4-byte signature, so the
 * absolute shared memory offset is 4 + field_offset.
 *
 * Writes to the CMD field (OpRegion offset 8, 32-bit) trigger a full
 * transmit sequence.  All other accesses read or write shared memory
 * directly.  Per section 5.5.2.4.8.5, AML must check the Error Status
 * before processing response data; the handler does not interpret
 * status on read.
 */
static ACPI_STATUS
pcc_opregion_handler(UINT32 Function, ACPI_PHYSICAL_ADDRESS Address,
	UINT32 BitWidth, UINT64 *Value, void *HandlerContext, void *RegionContext)
{
	pcc_chan_t *pc = (pcc_chan_t *)RegionContext;
	uint64_t field_offset64;
	uint32_t field_offset;
	uint32_t shmem_offset;
	uint32_t byte_len;
	int ret;

	(void) HandlerContext;

	if (pc == NULL) {
		return (AE_NOT_EXIST);
	}
	if (!pc->pc_usable) {
		return (AE_NOT_EXIST);
	}

	/*
	 * Compute the field offset with 64-bit arithmetic to avoid
	 * wraparound.  Address is attacker-controlled via AML; it must
	 * not be less than the subspace ID.
	 */
	if (Address < (ACPI_PHYSICAL_ADDRESS)pc->pc_id) {
		return (AE_BAD_PARAMETER);
	}
	field_offset64 = (uint64_t)Address - (uint64_t)pc->pc_id;
	if (field_offset64 > UINT32_MAX) {
		return (AE_BAD_PARAMETER);
	}
	field_offset = (uint32_t)field_offset64;

	/*
	 * BitWidth must be a whole number of bytes.
	 */
	if ((BitWidth % 8) != 0) {
		return (AE_BAD_PARAMETER);
	}
	byte_len = BitWidth / 8;

	/*
	 * Bounds check: 4 (signature) + field_offset + byte_len must not
	 * exceed the shared memory length and must not overflow.
	 */
	if (field_offset64 + 4 + byte_len > pc->pc_shmem_len) {
		return (AE_BAD_PARAMETER);
	}
	shmem_offset = 4 + field_offset;

	mutex_enter(&pc->pc_lock);

	if (Function == ACPI_READ) {
		switch (byte_len) {
		case 1:
			*Value = *(volatile uint8_t *)(void *)
				(pc->pc_shmem_va + shmem_offset);
			break;
		case 2:
			*Value = *(volatile uint16_t *)(void *)
				(pc->pc_shmem_va + shmem_offset);
			break;
		case 4:
			*Value = *(volatile uint32_t *)(void *)
				(pc->pc_shmem_va + shmem_offset);
			break;
		case 8:
			*Value = *(volatile uint64_t *)(void *)
				(pc->pc_shmem_va + shmem_offset);
			break;
		default:
			mutex_exit(&pc->pc_lock);
			return (AE_BAD_PARAMETER);
		}
		mutex_exit(&pc->pc_lock);
		return (AE_OK);
	}

	/* ACPI_WRITE */

	/*
	 * Check for the CMD field: OpRegion offset 8, 32-bit.  With the
	 * backported ACPICA, the handler is only invoked on COMD writes,
	 * but verify anyway for safety.
	 */
	if (field_offset == PCC_OPREGION_CMD_OFFSET) {
		if (BitWidth != 32) {
			mutex_exit(&pc->pc_lock);
			return (AE_BAD_PARAMETER);
		}
		ret = pcc_opregion_transmit(pc, (uint32_t)*Value);
		mutex_exit(&pc->pc_lock);
		if (ret != 0) {
			/*
			 * Protocol failure (timeout, lost ownership): report
			 * AE_ERROR.  Platform-reported errors are left in the
			 * Error Status register for AML to check per section
			 * 5.5.2.4.8.5; transmit returns 0 in that case and we
			 * return AE_OK below.
			 */
			return (AE_ERROR);
		}
		return (AE_OK);
	}

	/* Non-CMD field: write the value to shared memory. */
	switch (byte_len) {
	case 1:
		*(volatile uint8_t *)(void *)(pc->pc_shmem_va + shmem_offset) =
			(uint8_t)*Value;
		break;
	case 2:
		*(volatile uint16_t *)(void *)(pc->pc_shmem_va + shmem_offset) =
			(uint16_t)*Value;
		break;
	case 4:
		*(volatile uint32_t *)(void *)(pc->pc_shmem_va + shmem_offset) =
			(uint32_t)*Value;
		break;
	case 8:
		*(volatile uint64_t *)(void *)(pc->pc_shmem_va + shmem_offset) =
			*Value;
		break;
	default:
		mutex_exit(&pc->pc_lock);
		return (AE_BAD_PARAMETER);
	}
	mutex_exit(&pc->pc_lock);
	return (AE_OK);
}

/*
 * Transmit a command on behalf of an OpRegion CMD field write.
 *
 * Called with pc_lock held.  The FLGS, LEN, and DATA fields are already
 * in shared memory from prior AML field writes; only the CMD value is
 * passed in.  Uses polling only; the OpRegion path never uses
 * interrupts, so pc_cmd_complete is not involved.
 *
 * Sequence:
 * 1. Clear stale Error Status (a previous failed command must not
 *    cause a false error report on this one).
 * 2. Write the CMD value to shared memory.
 * 3. membar_producer() to ensure visibility before the doorbell.
 * 4. Clear Command Complete via the CC update register, transferring
 *    ownership to the platform (ACPI 6.6 section 14.5, step 3).
 * 5. Ring the doorbell.
 * 6. Poll for completion via pto_poll_complete.
 * 7. membar to ensure response data is visible before returning.
 *
 * Platform-reported errors are NOT cleared and NOT converted to
 * AE_ERROR.  The Error Status remains visible in the Error Status
 * register for AML to check per section 5.5.2.4.8.5; the handler
 * returns AE_OK.  Only protocol failures (timeout, lost ownership)
 * or a previously failed channel return non-zero, which the
 * handler maps to AE_ERROR.  A timeout marks the channel failed;
 * later transmits fail fast with EIO.
 *
 * Returns 0 on success (including platform-reported errors), or an
 * errno on protocol failure.
 */
static int
pcc_opregion_transmit(pcc_chan_t *pc, uint32_t cmd_value)
{
	uint64_t ccval;
	volatile uint32_t *cmdp;
	volatile uint32_t *flagsp;
	boolean_t responded = B_FALSE;
	int ret;

	ASSERT(MUTEX_HELD(&pc->pc_lock));

	/*
	 * A previous command timed out: the platform is not
	 * responding.  Fail fast rather than stalling on a dead
	 * channel.
	 */
	if (pc->pc_broken) {
		return (EIO);
	}

	/* Enforce minimum inter-command interval (before the send) */
	pcc_enforce_timing(pc);

	/*
	 * Verify ownership: Command Complete must be set, meaning the
	 * platform has finished the previous command and the channel
	 * is ours.  A previous transmit that timed out leaves Command
	 * Complete clear (the platform still owns the channel); writing
	 * a new command and ringing the doorbell would corrupt the
	 * in-flight transaction (ACPI 6.6 section 14.5, step 1).
	 */
	pcc_reg_read(pc->pc_cc_check_reg, &ccval);
	if ((ccval & pc->pc_cc_check_mask) == 0) {
		return (EBUSY);
	}

	/*
	 * Clear stale error bits before the send.  The platform does not
	 * clear the Error Status register; a previous failed command would
	 * otherwise cause a false error report on this command.  We own
	 * the channel (pc_lock held, OpRegion exclusivity), so the platform
	 * is not touching the register.
	 *
	 * Note: we do NOT check or clear the error after completion.
	 * A platform-reported error stays in the register for AML to read;
	 * pto_check_error would clear it, hiding it from AML.
	 *
	 * The Error Status register is optional; skip the clear for
	 * subspaces that do not describe one.
	 */
	if (pc->pc_err_reg != NULL) {
		pcc_reg_rmw(pc->pc_err_reg, ~pc->pc_err_mask, 0);
	}

	/*
	 * Write the command value to the CMD field in shared memory.
	 * The OpRegion covers shared memory after the 4-byte signature,
	 * so the absolute shared memory offset is 4 + 8 = 12, which
	 * matches PCC_EXT_SHMEM_CMD.  FLGS, LEN, and DATA were populated
	 * by prior AML field writes; do not touch them.
	 */
	cmdp = (volatile uint32_t *)(void *)
		(pc->pc_shmem_va + PCC_EXT_SHMEM_CMD);
	*cmdp = cmd_value;

	/*
	 * Ensure the command write (and any prior field writes) are
	 * visible to the platform before ringing the doorbell.
	 */
	membar_producer();

	/*
	 * Clear Command Complete via the CC update register RMW,
	 * transferring ownership to the platform (ACPI 6.6 section
	 * 14.5, step 3).  Without this, the poll below would observe
	 * the still-set bit from the ownership check above and report
	 * completion before the platform has processed the command.
	 */
	pcc_reg_rmw(pc->pc_cc_update_reg,
		pc->pc_cc_update_preserve, pc->pc_cc_update_set);

	/* Ring the doorbell. */
	pcc_ring_doorbell(pc);

	/*
	 * Wait for completion via polling.  Reuse the type's
	 * pto_poll_complete; do not duplicate the poll loop.
	 */
	ret = pc->pc_ops->pto_poll_complete(pc, &responded);
	if (ret != DDI_SUCCESS) {
		/*
		 * Completion timed out: the platform did not respond
		 * within 500x nominal latency.  Mark the channel
		 * failed so future transmits fail fast instead of
		 * stalling on a dead platform.
		 */
		pc->pc_broken = B_TRUE;
		cmn_err(CE_WARN, "acpipcc: subspace %u: channel marked "
			"failed after command completion timeout", pc->pc_id);
		return (ETIMEDOUT);
	}

	/*
	 * Ensure the response data written by the platform is visible
	 * before AML reads it from shared memory.
	 */
	membar_consumer();

	/*
	 * ACPI 6.6 s14.5 step 9: clear the platform interrupt only if
	 * the platform raised one for this command.  All three must
	 * hold: AML requested the interrupt via Notify on completion
	 * in FLGS, the interrupt is level-triggered, and an ack
	 * register is present (pcc_write_ack no-ops without one).
	 * This path always polls, so a raised level interrupt would
	 * otherwise stay asserted with no handler to clear it.
	 */
	flagsp = (volatile uint32_t *)(void *)
		(pc->pc_shmem_va + PCC_EXT_SHMEM_FLAGS);
	if (responded &&
		(*flagsp & PCC_EXT_FLAG_NOTIFY_ON_COMPLETE) != 0 &&
		(pc->pc_irq_flags & ACPI_PCCT_INTERRUPT_MODE) == 0 &&
		pc->pc_ack_reg != NULL) {
		pcc_write_ack(pc);
	}

	/* Record send time for rate/turnaround enforcement */
	pc->pc_last_send = gethrtime();

	return (0);
}
