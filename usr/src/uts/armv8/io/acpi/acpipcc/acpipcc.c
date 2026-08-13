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
 * Platform Communications Channel (PCC) driver.
 *
 * Parses the ACPI PCCT (Platform Communications Channel Table) and
 * provides shared-memory channel access with doorbell/acknowledge
 * transport for higher-level protocols such as CPPC.
 *
 * Each PCCT subspace describes a communication channel between the OS
 * and platform firmware, consisting of:
 * - A shared memory region at a fixed physical address
 * - A doorbell register the OS writes to notify the platform
 * - An acknowledge register the OS writes to clear completion state
 * - Timing parameters (command latency, turnaround time)
 *
 * Two shared memory layouts are supported:
 *
 * Type 0-2 (ACPI 6.6 Table 14.9): 8-byte header containing a
 * 2-byte Command, 2-byte Status (with Command Complete and Error
 * bits), then Communication Space at offset 8.
 *
 * Type 3 (ACPI 6.6 Table 14.12): 16-byte extended header containing
 * a 4-byte Flags, 4-byte Length, 4-byte Command, then Communication
 * Space at offset 16.  Completion and errors are reported through
 * separate MMIO registers (CmdComplete, CmdUpdate, ErrorStatus)
 * described in the PCCT, not through shared memory.
 *
 * Supported subspace types:
 *   Type 2 - HW-Reduced Communications Subspace (ACPI 6.1)
 *   Type 3 - Extended PCC Master Subspace (ACPI 6.2)
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/mutex.h>
#include <sys/smp_impldefs.h>
#include <sys/acpipcc.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>

/*
 * Internal representation of a parsed PCC channel.
 */
typedef struct pcc_chan {
	boolean_t	pc_valid;	/* channel was parsed successfully */
	uint8_t		pc_type;	/* PCCT subspace type (2 or 3) */
	uint8_t		pc_hdr_len;	/* shared memory header length */
	kmutex_t	pc_lock;	/* serializes channel access */

	/*
	 * Platform interrupt (parsed, not yet used; we poll today).
	 * pc_plat_irq and pc_irq_flags come from the subspace
	 * descriptor; pc_irq_capable is the PCCT table-level
	 * Platform Interrupt flag (Flags bit 0).
	 */
	uint32_t	pc_plat_irq;	/* GSIV */
	uint8_t		pc_irq_flags;	/* polarity and trigger mode */
	boolean_t	pc_irq_capable;	/* platform can signal completion */

	/* Shared memory region */
	uint64_t	pc_base_pa;	/* physical address */
	uint64_t	pc_length;	/* region size in bytes */
	caddr_t		pc_base_va;	/* mapped virtual address */

	/* Doorbell register */
	uint64_t	pc_db_pa;	/* doorbell physical address */
	uint8_t		pc_db_width;	/* doorbell register bit width */
	caddr_t		pc_db_va;	/* mapped doorbell VA */
	uint64_t	pc_db_preserve;	/* doorbell preserve mask */
	uint64_t	pc_db_write;	/* doorbell write mask */

	/* Platform ACK register (Type 2 and Type 3) */
	uint64_t	pc_ack_pa;	/* ack register physical address */
	uint8_t		pc_ack_width;	/* ack register bit width */
	caddr_t		pc_ack_va;	/* mapped ack VA */
	uint64_t	pc_ack_preserve; /* ack preserve mask */
	uint64_t	pc_ack_write;	/* ack write mask */
	boolean_t	pc_has_ack;	/* ack register is present */

	/* Type 3 command complete check register */
	uint64_t	pc_cc_pa;	/* cmd complete physical address */
	uint8_t		pc_cc_width;	/* cmd complete register width */
	caddr_t		pc_cc_va;	/* mapped cmd complete VA */
	uint64_t	pc_cc_mask;	/* cmd complete check mask */

	/* Type 3 command complete update register */
	uint64_t	pc_cu_pa;	/* cmd update physical address */
	uint8_t		pc_cu_width;	/* cmd update register width */
	caddr_t		pc_cu_va;	/* mapped cmd update VA */
	uint64_t	pc_cu_preserve;	/* cmd update preserve mask */
	uint64_t	pc_cu_set;	/* cmd update set mask */

	/* Type 3 error status register */
	uint64_t	pc_err_pa;	/* error status physical address */
	uint8_t		pc_err_width;	/* error status register width */
	caddr_t		pc_err_va;	/* mapped error status VA */
	uint64_t	pc_err_mask;	/* error status mask */

	/* Timing */
	uint32_t	pc_latency;	/* command latency in microseconds */
	uint32_t	pc_max_rate;	/* max access rate */
	uint32_t	pc_turnaround;	/* min turnaround time */
} pcc_chan_t;

static pcc_chan_t pcc_channels[PCC_MAX_CHANNELS];
static uint_t pcc_nchan;
static volatile boolean_t pcc_initialized;
static int pcc_init_result = DDI_FAILURE;
static kmutex_t pcc_init_lock;

/*
 * Global lock for register read-modify-write operations.
 *
 * Multiple PCC channels can share the same physical doorbell or ACK
 * register, using different bits in the same register.  The
 * per-channel pc_lock does not serialize cross-channel access, so a
 * global lock is needed to prevent lost updates when two channels
 * perform concurrent RMW operations on a shared register.
 */
static kmutex_t pcc_rmw_lock;

/*
 * Signature verification strictness (settable via /etc/system).
 *
 * 0 - verify the PCC base signature only (0x504343xx); warn if
 *     the index portion does not match but continue.
 * 1 - allow an off-by-one index (firmware is known to use
 *     1-based indexing on some platforms); warn but continue.
 * 2 - require an exact match (ACPI 6.6 Tables 14.9, 14.12).
 *
 * Default is 1 because several shipping firmware images compute
 * the index portion incorrectly.
 */
int pcc_strictness = 1;

/*
 * Polling interval for command completion, in microseconds.
 * We use a 10us granularity to balance responsiveness and CPU cost.
 */
#define	PCC_POLL_INTERVAL_US	10

/*
 * Safety multiplier for the command latency timeout.  The ACPI spec
 * says the latency value is the "expected" time to process a command,
 * but firmware can be significantly slower under sustained load
 * (e.g. 128 sequential CPPC reads at boot).  We allow 10x the
 * stated latency before declaring a timeout.
 */
#define	PCC_TIMEOUT_MULTIPLIER	10

/*
 * PCC subspace signature base value (ACPI 6.6 Tables 14.9, 14.12).
 * The expected signature for subspace N is PCC_SIGNATURE_BASE | N.
 */
#define	PCC_SIGNATURE_BASE	0x50434300

/*
 * Map a physical MMIO register.  Returns the mapped virtual address,
 * or NULL on failure.  The mapping covers the minimum size needed for
 * the register width.
 */
static caddr_t
pcc_map_register(uint64_t pa, uint8_t bit_width)
{
	size_t len;

	if (pa == 0) {
		return (NULL);
	}

	len = (bit_width + 7) / 8;

	return (psm_map_phys((paddr_t)pa, len, PROT_READ | PROT_WRITE));
}

/*
 * Validate a GAS (Generic Address Structure) for a PCC register.
 * Registers with a zero address are considered absent and always
 * pass.  Otherwise, the address space must be SystemMemory and the
 * access width must be 32-bit or 64-bit.
 */
static boolean_t
pcc_gas_valid(ACPI_GENERIC_ADDRESS *gas, const char *name)
{
	if (gas->Address == 0) {
		return (B_TRUE);
	}

	if (gas->SpaceId != ACPI_ADR_SPACE_SYSTEM_MEMORY) {
		cmn_err(CE_WARN, "!pcc: %s uses unsupported "
		    "address space %u", name, gas->SpaceId);
		return (B_FALSE);
	}

	if (gas->BitWidth != 32 && gas->BitWidth != 64) {
		cmn_err(CE_WARN, "!pcc: %s has unsupported "
		    "bit width %u", name, gas->BitWidth);
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Parse a single Type 2 (HW-Reduced) PCCT subspace and populate the
 * channel structure.
 */
static int
pcc_parse_type2(ACPI_PCCT_HW_REDUCED_TYPE2 *sub, pcc_chan_t *pc)
{
	ASSERT3P(sub, !=, NULL);
	ASSERT3P(pc, !=, NULL);

	if (!pcc_gas_valid(&sub->DoorbellRegister, "doorbell") ||
	    !pcc_gas_valid(&sub->PlatformAckRegister, "ack")) {
		return (DDI_FAILURE);
	}

	pc->pc_type = ACPI_PCCT_TYPE_HW_REDUCED_SUBSPACE_TYPE2;
	pc->pc_hdr_len = PCC_SHMEM_HDR_LEN;
	pc->pc_base_pa = sub->BaseAddress;
	pc->pc_length = sub->Length;
	pc->pc_latency = sub->Latency;
	pc->pc_max_rate = sub->MaxAccessRate;
	pc->pc_turnaround = sub->MinTurnaroundTime;

	/* Doorbell register */
	pc->pc_db_pa = sub->DoorbellRegister.Address;
	pc->pc_db_width = sub->DoorbellRegister.BitWidth;
	pc->pc_db_preserve = sub->PreserveMask;
	pc->pc_db_write = sub->WriteMask;

	/* Platform ACK register */
	pc->pc_ack_pa = sub->PlatformAckRegister.Address;
	pc->pc_ack_width = sub->PlatformAckRegister.BitWidth;
	pc->pc_ack_preserve = sub->AckPreserveMask;
	pc->pc_ack_write = sub->AckWriteMask;
	pc->pc_has_ack = (sub->PlatformAckRegister.Address != 0);

	/* Platform interrupt (not yet used; we poll for completion) */
	pc->pc_plat_irq = sub->PlatformInterrupt;
	pc->pc_irq_flags = sub->Flags;

	return (DDI_SUCCESS);
}

/*
 * Parse a single Type 3 (Extended PCC Master) PCCT subspace and
 * populate the channel structure.
 *
 * Type 3 uses a 16-byte extended shared memory header (Signature,
 * Flags, Length, Command) and external MMIO registers for command
 * completion checking, completion clearing, and error status.
 */
static int
pcc_parse_type3(ACPI_PCCT_EXT_PCC_MASTER *sub, pcc_chan_t *pc)
{
	ASSERT3P(sub, !=, NULL);
	ASSERT3P(pc, !=, NULL);

	if (!pcc_gas_valid(&sub->DoorbellRegister, "doorbell") ||
	    !pcc_gas_valid(&sub->PlatformAckRegister, "ack") ||
	    !pcc_gas_valid(&sub->CmdCompleteRegister,
	    "cmd complete") ||
	    !pcc_gas_valid(&sub->CmdUpdateRegister,
	    "cmd update") ||
	    !pcc_gas_valid(&sub->ErrorStatusRegister,
	    "error status")) {
		return (DDI_FAILURE);
	}

	pc->pc_type = ACPI_PCCT_TYPE_EXT_PCC_MASTER_SUBSPACE;
	pc->pc_hdr_len = PCC_EXT_SHMEM_HDR_LEN;
	pc->pc_base_pa = sub->BaseAddress;
	pc->pc_length = (uint64_t)sub->Length;
	pc->pc_latency = sub->Latency;
	pc->pc_max_rate = sub->MaxAccessRate;
	pc->pc_turnaround = sub->MinTurnaroundTime;

	/* Doorbell register */
	pc->pc_db_pa = sub->DoorbellRegister.Address;
	pc->pc_db_width = sub->DoorbellRegister.BitWidth;
	pc->pc_db_preserve = sub->PreserveMask;
	pc->pc_db_write = sub->WriteMask;

	/* Platform ACK register */
	pc->pc_ack_pa = sub->PlatformAckRegister.Address;
	pc->pc_ack_width = sub->PlatformAckRegister.BitWidth;
	pc->pc_ack_preserve = sub->AckPreserveMask;
	pc->pc_ack_write = sub->AckSetMask;
	pc->pc_has_ack = (sub->PlatformAckRegister.Address != 0);

	/* Command complete check register */
	pc->pc_cc_pa = sub->CmdCompleteRegister.Address;
	pc->pc_cc_width = sub->CmdCompleteRegister.BitWidth;
	pc->pc_cc_mask = sub->CmdCompleteMask;

	/* Command complete update register */
	pc->pc_cu_pa = sub->CmdUpdateRegister.Address;
	pc->pc_cu_width = sub->CmdUpdateRegister.BitWidth;
	pc->pc_cu_preserve = sub->CmdUpdatePreserveMask;
	pc->pc_cu_set = sub->CmdUpdateSetMask;

	/* Error status register */
	pc->pc_err_pa = sub->ErrorStatusRegister.Address;
	pc->pc_err_width = sub->ErrorStatusRegister.BitWidth;
	pc->pc_err_mask = sub->ErrorStatusMask;

	/* Platform interrupt (not yet used; we poll for completion) */
	pc->pc_plat_irq = sub->PlatformInterrupt;
	pc->pc_irq_flags = sub->Flags;

	return (DDI_SUCCESS);
}

/*
 * Unmap all MMIO registers and shared memory for a channel.
 * Safe to call on a partially mapped or unmapped channel.
 */
static void
pcc_unmap_channel(pcc_chan_t *pc)
{
	if (pc->pc_err_va != NULL) {
		psm_unmap_phys(pc->pc_err_va,
		    (size_t)((pc->pc_err_width + 7) / 8));
		pc->pc_err_va = NULL;
	}
	if (pc->pc_cu_va != NULL) {
		psm_unmap_phys(pc->pc_cu_va,
		    (size_t)((pc->pc_cu_width + 7) / 8));
		pc->pc_cu_va = NULL;
	}
	if (pc->pc_cc_va != NULL) {
		psm_unmap_phys(pc->pc_cc_va,
		    (size_t)((pc->pc_cc_width + 7) / 8));
		pc->pc_cc_va = NULL;
	}
	if (pc->pc_ack_va != NULL) {
		psm_unmap_phys(pc->pc_ack_va,
		    (size_t)((pc->pc_ack_width + 7) / 8));
		pc->pc_ack_va = NULL;
	}
	if (pc->pc_db_va != NULL) {
		psm_unmap_phys(pc->pc_db_va,
		    (size_t)((pc->pc_db_width + 7) / 8));
		pc->pc_db_va = NULL;
	}
	if (pc->pc_base_va != NULL) {
		psm_unmap_phys(pc->pc_base_va,
		    (size_t)pc->pc_length);
		pc->pc_base_va = NULL;
	}
	pc->pc_valid = B_FALSE;
}

/*
 * Map the shared memory and MMIO registers for a parsed channel.
 */
static int
pcc_map_channel(pcc_chan_t *pc)
{
	ASSERT3P(pc, !=, NULL);

	/*
	 * Minimum shared memory size check.  ACPI 6.6 requires
	 * "must be > 8" for Types 0-2 (Tables 14.4, 14.5, 14.6)
	 * and "must be >= 16" for Type 3 (Table 14.7).
	 */
	if (pc->pc_type == ACPI_PCCT_TYPE_EXT_PCC_MASTER_SUBSPACE) {
		if (pc->pc_length < pc->pc_hdr_len) {
			cmn_err(CE_WARN, "!pcc: shared memory "
			    "too short (%llu bytes, need %u)",
			    (unsigned long long)pc->pc_length,
			    pc->pc_hdr_len);
			return (DDI_FAILURE);
		}
	} else {
		if (pc->pc_length <= pc->pc_hdr_len) {
			cmn_err(CE_WARN, "!pcc: shared memory "
			    "too short "
			    "(%llu bytes, need > %u)",
			    (unsigned long long)pc->pc_length,
			    pc->pc_hdr_len);
			return (DDI_FAILURE);
		}
	}

	/* Map the shared memory region */
	if (pc->pc_base_pa == 0 || pc->pc_length == 0) {
		cmn_err(CE_WARN, "!pcc: channel has no shared memory");
		return (DDI_FAILURE);
	}

	pc->pc_base_va = psm_map_phys((paddr_t)pc->pc_base_pa,
	    (size_t)pc->pc_length, PROT_READ | PROT_WRITE);
	if (pc->pc_base_va == NULL) {
		cmn_err(CE_WARN, "!pcc: failed to map shared memory "
		    "at 0x%llx", (unsigned long long)pc->pc_base_pa);
		return (DDI_FAILURE);
	}

	/* Map the doorbell register */
	pc->pc_db_va = pcc_map_register(pc->pc_db_pa, pc->pc_db_width);
	if (pc->pc_db_va == NULL) {
		cmn_err(CE_WARN, "!pcc: failed to map doorbell "
		    "register at 0x%llx",
		    (unsigned long long)pc->pc_db_pa);
		goto fail;
	}

	/* Map the ack register, if present */
	if (pc->pc_has_ack) {
		pc->pc_ack_va = pcc_map_register(pc->pc_ack_pa,
		    pc->pc_ack_width);
		if (pc->pc_ack_va == NULL) {
			cmn_err(CE_WARN, "!pcc: failed to map "
			    "ack register at 0x%llx",
			    (unsigned long long)pc->pc_ack_pa);
			goto fail;
		}
	}

	/* Map Type 3 extended registers */
	if (pc->pc_type == ACPI_PCCT_TYPE_EXT_PCC_MASTER_SUBSPACE) {
		pc->pc_cc_va = pcc_map_register(pc->pc_cc_pa,
		    pc->pc_cc_width);
		if (pc->pc_cc_va == NULL) {
			cmn_err(CE_WARN, "!pcc: failed to map cmd "
			    "complete register at 0x%llx",
			    (unsigned long long)pc->pc_cc_pa);
			goto fail;
		}

		pc->pc_cu_va = pcc_map_register(pc->pc_cu_pa,
		    pc->pc_cu_width);
		if (pc->pc_cu_va == NULL) {
			cmn_err(CE_WARN, "!pcc: failed to map cmd "
			    "update register at 0x%llx",
			    (unsigned long long)pc->pc_cu_pa);
			goto fail;
		}

		pc->pc_err_va = pcc_map_register(pc->pc_err_pa,
		    pc->pc_err_width);
		if (pc->pc_err_va == NULL) {
			cmn_err(CE_WARN, "!pcc: failed to map error "
			    "status register at 0x%llx",
			    (unsigned long long)pc->pc_err_pa);
			goto fail;
		}
	}

	return (DDI_SUCCESS);

fail:
	pcc_unmap_channel(pc);
	return (DDI_FAILURE);
}

/*
 * Perform a read-modify-write on a mapped MMIO register.  Reads the
 * current value, applies the preserve mask (AND), sets the write mask
 * bits (OR), and writes back.  Supports 32-bit and 64-bit access
 * widths.
 *
 * A global lock serializes all RMW operations because multiple PCC
 * channels can share the same physical doorbell or ACK register
 * (using different bit positions).  The per-channel pc_lock does
 * not cover cross-channel access, so without this lock a concurrent
 * RMW from another channel could lose a bit update.
 */
static void
pcc_rmw_register(caddr_t va, uint8_t width, uint64_t preserve, uint64_t set)
{
	ASSERT3P(va, !=, NULL);
	ASSERT(width == 32 || width == 64);

	mutex_enter(&pcc_rmw_lock);

	if (width == 32) {
		volatile uint32_t *r =
		    (volatile uint32_t *)(void *)va;
		*r = (uint32_t)((*r & preserve) | set);
	} else {
		volatile uint64_t *r =
		    (volatile uint64_t *)(void *)va;
		*r = (*r & preserve) | set;
	}

	mutex_exit(&pcc_rmw_lock);
}

/*
 * Read a mapped MMIO register at the width described by its GAS entry.
 * Returns the register value zero-extended to 64 bits.
 */
static uint64_t
pcc_read_register(caddr_t va, uint8_t width)
{
	ASSERT3P(va, !=, NULL);
	ASSERT(width == 32 || width == 64);

	if (width == 32) {
		volatile uint32_t *r =
		    (volatile uint32_t *)(void *)va;
		return ((uint64_t)*r);
	} else {
		volatile uint64_t *r =
		    (volatile uint64_t *)(void *)va;
		return (*r);
	}
}

/*
 * Ring the doorbell register.
 */
static void
pcc_ring_doorbell(pcc_chan_t *pc)
{
	ASSERT3P(pc, !=, NULL);
	ASSERT3P(pc->pc_db_va, !=, NULL);

	pcc_rmw_register(pc->pc_db_va, pc->pc_db_width,
	    pc->pc_db_preserve, pc->pc_db_write);
}

/*
 * Write the ACK register to acknowledge command completion.
 */
static void
pcc_write_ack(pcc_chan_t *pc)
{
	ASSERT3P(pc, !=, NULL);

	if (!pc->pc_has_ack || pc->pc_ack_va == NULL) {
		return;
	}

	pcc_rmw_register(pc->pc_ack_va, pc->pc_ack_width,
	    pc->pc_ack_preserve, pc->pc_ack_write);
}

/*
 * Poll for command completion with timeout.
 *
 * For Type 0-2: polls the shared memory Status field for Command
 * Complete (bit 0).  When set, checks the Error bit (bit 2).
 *
 * For Type 3: polls the CmdComplete register against the
 * CmdComplete mask.  When set, checks the ErrorStatus register
 * and clears any error (ACPI 6.6 Table 14.7).
 *
 * Returns DDI_SUCCESS when command completion is observed, or
 * DDI_FAILURE on timeout or platform error.
 *
 * *responded is set to B_TRUE when the platform responds (success or
 * error) and left B_FALSE on timeout.  The caller uses this to decide
 * whether to write the ACK register.
 */
static int
pcc_poll_complete(pcc_chan_t *pc, boolean_t *responded)
{
	uint64_t timeout_us;
	uint64_t elapsed;
	uint64_t val;
	volatile uint16_t *statusp;
	uint16_t status;

	ASSERT3P(pc, !=, NULL);
	ASSERT3P(pc->pc_base_va, !=, NULL);

	*responded = B_FALSE;

	/*
	 * Use the channel's command latency with a safety multiplier
	 * as the timeout.  A latency of 0 means "no expected latency",
	 * in which case we use a generous default.
	 */
	timeout_us = pc->pc_latency;
	if (timeout_us == 0) {
		timeout_us = 1000;
	}
	timeout_us *= PCC_TIMEOUT_MULTIPLIER;

	for (elapsed = 0; elapsed < timeout_us;
	    elapsed += PCC_POLL_INTERVAL_US) {
		if (pc->pc_type ==
		    ACPI_PCCT_TYPE_EXT_PCC_MASTER_SUBSPACE) {

			/* Check command complete */
			val = pcc_read_register(pc->pc_cc_va,
			    pc->pc_cc_width);
			if (val & pc->pc_cc_mask) {
				/*
				 * Check error after completion
				 * (ACPI 6.6 s14.5).
				 */
				val = pcc_read_register(
				    pc->pc_err_va,
				    pc->pc_err_width);
				if (val & pc->pc_err_mask) {
					cmn_err(CE_WARN,
					    "!pcc: platform "
					    "reported error "
					    "(error status "
					    "0x%llx)",
					    (unsigned long long)
					    val);
					/*
					 * Clear the error
					 * (ACPI 6.6 Table
					 * 14.7).
					 */
					pcc_rmw_register(
					    pc->pc_err_va,
					    pc->pc_err_width,
					    ~pc->pc_err_mask,
					    0);
					*responded = B_TRUE;
					return (DDI_FAILURE);
				}
				membar_consumer();
				*responded = B_TRUE;
				return (DDI_SUCCESS);
			}
		} else {

			statusp = (volatile uint16_t *)(void *)
			    (pc->pc_base_va + PCC_SHMEM_STATUS);
			status = *statusp;

			if (status & PCC_STATUS_CMD_COMPLETE) {
				if (status & PCC_STATUS_ERROR) {
					cmn_err(CE_WARN,
					    "!pcc: platform "
					    "reported error "
					    "(status 0x%x)",
					    status);
					*responded = B_TRUE;
					return (DDI_FAILURE);
				}
				membar_consumer();
				*responded = B_TRUE;
				return (DDI_SUCCESS);
			}
		}

		drv_usecwait(PCC_POLL_INTERVAL_US);
	}

	cmn_err(CE_WARN, "!pcc: command timed out after %llu us "
	    "(latency %u us)", (unsigned long long)elapsed,
	    pc->pc_latency);
	return (DDI_FAILURE);
}

/*
 * Validate a channel ID and return the channel pointer, or NULL if
 * the channel is invalid or not initialized.
 */
static pcc_chan_t *
pcc_get_chan(uint_t chan_id)
{
	pcc_chan_t *pc;

	if (!pcc_initialized) {
		return (NULL);
	}
	membar_consumer();

	if (chan_id >= pcc_nchan) {
		return (NULL);
	}

	pc = &pcc_channels[chan_id];
	if (!pc->pc_valid) {
		return (NULL);
	}

	return (pc);
}

static int
pcc_init_impl(void)
{
	ACPI_TABLE_HEADER *hdr;
	ACPI_SUBTABLE_HEADER *sub_hdr;
	ACPI_STATUS status;
	pcc_chan_t *pc;
	uint8_t *tbl;
	uint8_t *end;
	uint8_t *pos;
	uint_t idx;
	uint_t nvalid;
	uint_t i;
	uint32_t sig;
	uint32_t expected_sig;
	boolean_t supported;
	boolean_t tbl_irq_capable;
	int ret;

	status = AcpiGetTable(ACPI_SIG_PCCT, 1, &hdr);
	if (ACPI_FAILURE(status)) {
		cmn_err(CE_NOTE, "!pcc: PCCT table not found");
		return (DDI_FAILURE);
	}

	if (hdr->Length < sizeof (ACPI_TABLE_PCCT)) {
		cmn_err(CE_WARN, "!pcc: PCCT too short "
		    "(%u bytes)", hdr->Length);
		return (DDI_FAILURE);
	}

	tbl = (uint8_t *)hdr;
	end = tbl + hdr->Length;
	pos = tbl + sizeof (ACPI_TABLE_PCCT);
	idx = 0;

	/*
	 * PCCT table-level Flags bit 0 (Platform Interrupt): set when
	 * the platform can raise an interrupt to signal command
	 * completion.  Stored per-channel for future use.
	 */
	tbl_irq_capable = (((ACPI_TABLE_PCCT *)(void *)tbl)->Flags &
	    ACPI_PCCT_DOORBELL) != 0;

	while (pos + sizeof (ACPI_SUBTABLE_HEADER) <= end &&
	    idx < PCC_MAX_CHANNELS) {
		sub_hdr = (ACPI_SUBTABLE_HEADER *)(void *)pos;
		if (sub_hdr->Length == 0 ||
		    pos + sub_hdr->Length > end) {
			break;
		}

		pc = &pcc_channels[idx];
		memset(pc, 0, sizeof (*pc));
		mutex_init(&pc->pc_lock, NULL, MUTEX_DEFAULT,
		    NULL);

		ret = DDI_FAILURE;
		supported = B_FALSE;

		switch (sub_hdr->Type) {
		case ACPI_PCCT_TYPE_HW_REDUCED_SUBSPACE_TYPE2:
			supported = B_TRUE;
			if (sub_hdr->Length <
			    sizeof (ACPI_PCCT_HW_REDUCED_TYPE2)) {
				cmn_err(CE_WARN, "!pcc: subspace "
				    "%u type 2 too short "
				    "(%u bytes)", idx,
				    sub_hdr->Length);
				break;
			}
			ret = pcc_parse_type2(
			    (ACPI_PCCT_HW_REDUCED_TYPE2 *)
			    (void *)pos, pc);
			break;

		case ACPI_PCCT_TYPE_EXT_PCC_MASTER_SUBSPACE:
			supported = B_TRUE;
			if (sub_hdr->Length <
			    sizeof (ACPI_PCCT_EXT_PCC_MASTER)) {
				cmn_err(CE_WARN, "!pcc: subspace "
				    "%u type 3 too short "
				    "(%u bytes)", idx,
				    sub_hdr->Length);
				break;
			}
			ret = pcc_parse_type3(
			    (ACPI_PCCT_EXT_PCC_MASTER *)
			    (void *)pos, pc);
			break;

		default:
			/*
			 * Types 0, 1, 4+ are not used by CPPC on
			 * arm64.  Record them as invalid so channel
			 * indices stay aligned with the PCCT
			 * subspace order.
			 */
			break;
		}

		if (ret == DDI_SUCCESS) {
			ret = pcc_map_channel(pc);
		}

		/*
		 * Verify the subspace signature in shared
		 * memory (ACPI 6.6 Tables 14.9, 14.12).
		 * Strictness is controlled by pcc_strictness.
		 */
		if (ret == DDI_SUCCESS) {
			expected_sig = PCC_SIGNATURE_BASE | idx;
			sig = *(volatile uint32_t *)(void *)
			    pc->pc_base_va;

			if (sig != expected_sig) {
				uint32_t sig_base =
				    sig & ~0xffU;
				uint32_t sig_idx =
				    sig & 0xffU;
				int32_t idx_delta =
				    (int32_t)sig_idx -
				    (int32_t)idx;

				if (sig_base !=
				    PCC_SIGNATURE_BASE) {
					cmn_err(CE_WARN,
					    "!pcc: subspace "
					    "%u signature "
					    "mismatch (0x%x, "
					    "expected 0x%x)",
					    idx, sig,
					    expected_sig);
					ret = DDI_FAILURE;
				} else if (pcc_strictness >= 2) {
					cmn_err(CE_WARN,
					    "!pcc: subspace "
					    "%u signature "
					    "mismatch (0x%x, "
					    "expected 0x%x)",
					    idx, sig,
					    expected_sig);
					ret = DDI_FAILURE;
				} else if (pcc_strictness >= 1 &&
				    (idx_delta < -1 ||
				    idx_delta > 1)) {
					cmn_err(CE_WARN,
					    "!pcc: subspace "
					    "%u signature "
					    "index too far "
					    "(0x%x, expected "
					    "0x%x)",
					    idx, sig,
					    expected_sig);
					ret = DDI_FAILURE;
				} else {
					cmn_err(CE_NOTE,
					    "!pcc: subspace "
					    "%u signature "
					    "index mismatch "
					    "(0x%x, expected "
					    "0x%x)",
					    idx, sig,
					    expected_sig);
				}
			}
		}

		if (ret == DDI_SUCCESS) {
			pc->pc_valid = B_TRUE;
			pc->pc_irq_capable = tbl_irq_capable;
		} else if (supported) {
			cmn_err(CE_WARN, "!pcc: subspace %u "
			    "failed to initialize", idx);
			for (i = 0; i <= idx; i++) {
				pcc_unmap_channel(
				    &pcc_channels[i]);
				mutex_destroy(
				    &pcc_channels[i].pc_lock);
			}
			return (DDI_FAILURE);
		}

		pos += sub_hdr->Length;
		idx++;
	}

	pcc_nchan = idx;

	nvalid = 0;
	for (i = 0; i < idx; i++) {
		if (pcc_channels[i].pc_valid) {
			nvalid++;
		}
	}

	if (nvalid == 0) {
		cmn_err(CE_NOTE, "!pcc: no usable subspaces "
		    "in PCCT (%u found)", idx);
		for (i = 0; i < idx; i++) {
			pcc_unmap_channel(&pcc_channels[i]);
			mutex_destroy(
			    &pcc_channels[i].pc_lock);
		}
		return (DDI_FAILURE);
	}

	cmn_err(CE_CONT, "!pcc: %u of %u PCCT subspace(s) "
	    "usable\n", nvalid, idx);
	return (DDI_SUCCESS);
}

int
pcc_init(void)
{
	int ret;

	if (pcc_initialized) {
		membar_consumer();
		return (pcc_init_result);
	}

	mutex_enter(&pcc_init_lock);
	if (pcc_initialized) {
		mutex_exit(&pcc_init_lock);
		return (pcc_init_result);
	}

	ret = pcc_init_impl();

	pcc_init_result = ret;
	membar_producer();
	pcc_initialized = B_TRUE;
	mutex_exit(&pcc_init_lock);
	return (ret);
}

int
pcc_chan_info(uint_t chan_id, pcc_chan_info_t *info)
{
	pcc_chan_t *pc;

	ASSERT3P(info, !=, NULL);

	pc = pcc_get_chan(chan_id);
	if (pc == NULL) {
		return (DDI_FAILURE);
	}

	info->pci_type = pc->pc_type;
	info->pci_base = pc->pc_base_pa;
	info->pci_length = pc->pc_length;
	info->pci_latency = pc->pc_latency;

	return (DDI_SUCCESS);
}

int
pcc_chan_lock(uint_t chan_id)
{
	pcc_chan_t *pc;

	pc = pcc_get_chan(chan_id);
	if (pc == NULL) {
		return (DDI_FAILURE);
	}

	mutex_enter(&pc->pc_lock);
	return (DDI_SUCCESS);
}

void
pcc_chan_unlock(uint_t chan_id)
{
	pcc_chan_t *pc;

	pc = pcc_get_chan(chan_id);
	if (pc == NULL) {
		return;
	}

	mutex_exit(&pc->pc_lock);
}

int
pcc_chan_read32(uint_t chan_id, uint32_t offset, uint32_t *val)
{
	pcc_chan_t *pc;
	uint64_t abs_off;
	volatile uint32_t *addr;

	ASSERT3P(val, !=, NULL);

	pc = pcc_get_chan(chan_id);
	if (pc == NULL) {
		return (DDI_FAILURE);
	}

	ASSERT(MUTEX_HELD(&pc->pc_lock));

	/* Offsets from callers are relative to the Communication Space */
	abs_off = (uint64_t)offset + pc->pc_hdr_len;
	if (abs_off + sizeof (uint32_t) > pc->pc_length) {
		return (DDI_FAILURE);
	}

	addr = (volatile uint32_t *)(void *)(pc->pc_base_va + abs_off);
	*val = *addr;

	return (DDI_SUCCESS);
}

int
pcc_chan_write32(uint_t chan_id, uint32_t offset, uint32_t val)
{
	pcc_chan_t *pc;
	uint64_t abs_off;
	volatile uint32_t *addr;

	pc = pcc_get_chan(chan_id);
	if (pc == NULL) {
		return (DDI_FAILURE);
	}

	ASSERT(MUTEX_HELD(&pc->pc_lock));

	abs_off = (uint64_t)offset + pc->pc_hdr_len;
	if (abs_off + sizeof (uint32_t) > pc->pc_length) {
		return (DDI_FAILURE);
	}

	addr = (volatile uint32_t *)(void *)(pc->pc_base_va + abs_off);
	*addr = val;

	return (DDI_SUCCESS);
}

int
pcc_chan_read64(uint_t chan_id, uint32_t offset, uint64_t *val)
{
	pcc_chan_t *pc;
	uint64_t abs_off;
	volatile uint64_t *addr;

	ASSERT3P(val, !=, NULL);

	pc = pcc_get_chan(chan_id);
	if (pc == NULL) {
		return (DDI_FAILURE);
	}

	ASSERT(MUTEX_HELD(&pc->pc_lock));

	abs_off = (uint64_t)offset + pc->pc_hdr_len;
	if (abs_off + sizeof (uint64_t) > pc->pc_length) {
		return (DDI_FAILURE);
	}

	addr = (volatile uint64_t *)(void *)(pc->pc_base_va + abs_off);
	*val = *addr;

	return (DDI_SUCCESS);
}

int
pcc_chan_send(uint_t chan_id, uint32_t cmd, uint32_t payload_len)
{
	pcc_chan_t *pc;
	boolean_t responded;
	volatile uint32_t *cmd32p;
	volatile uint32_t *flagsp;
	volatile uint32_t *lenp;
	volatile uint16_t *cmd16p;
	volatile uint16_t *statusp;
	uint64_t val;
	uint16_t status;
	int ret;

	pc = pcc_get_chan(chan_id);
	if (pc == NULL) {
		return (DDI_FAILURE);
	}

	ASSERT(MUTEX_HELD(&pc->pc_lock));

	if (pc->pc_type == ACPI_PCCT_TYPE_EXT_PCC_MASTER_SUBSPACE) {
		/*
		 * Type 3: verify the channel is free, populate
		 * the extended header, and clear Command
		 * Complete to transfer ownership to the
		 * platform (ACPI 6.6 s14.5 steps 1-3).
		 */
		val = pcc_read_register(pc->pc_cc_va,
		    pc->pc_cc_width);
		if (!(val & pc->pc_cc_mask)) {
			cmn_err(CE_WARN, "!pcc: channel %u "
			    "not free (command complete "
			    "not set)", chan_id);
			return (DDI_FAILURE);
		}

		flagsp = (volatile uint32_t *)(void *)
		    (pc->pc_base_va + PCC_EXT_SHMEM_FLAGS);
		lenp = (volatile uint32_t *)(void *)
		    (pc->pc_base_va + PCC_EXT_SHMEM_LENGTH);
		cmd32p = (volatile uint32_t *)(void *)
		    (pc->pc_base_va + PCC_EXT_SHMEM_CMD);

		/*
		 * Flags: Notify on Completion (bit 0) is not
		 * set because we poll for completion rather
		 * than requesting a platform interrupt.
		 */
		*flagsp = 0;
		*lenp = sizeof (uint32_t) + payload_len;
		*cmd32p = cmd;

		/*
		 * Command data must be observable before we
		 * clear Command Complete (ACPI 6.6 s14.5).
		 */
		membar_producer();

		pcc_rmw_register(pc->pc_cu_va, pc->pc_cu_width,
		    pc->pc_cu_preserve, pc->pc_cu_set);
	} else {
		/*
		 * Type 0-2: verify the channel is free,
		 * write the 16-bit command, and clear Command
		 * Complete to transfer ownership to the
		 * platform (ACPI 6.6 s14.5 steps 1-3).
		 */
		cmd16p = (volatile uint16_t *)(void *)
		    (pc->pc_base_va + PCC_SHMEM_CMD);
		statusp = (volatile uint16_t *)(void *)
		    (pc->pc_base_va + PCC_SHMEM_STATUS);

		status = *statusp;
		if (!(status & PCC_STATUS_CMD_COMPLETE)) {
			cmn_err(CE_WARN, "!pcc: channel %u "
			    "not free (command complete "
			    "not set)", chan_id);
			return (DDI_FAILURE);
		}

		*cmd16p = (uint16_t)cmd;

		/*
		 * Command data must be observable before we
		 * clear Command Complete (ACPI 6.6 s14.5).
		 */
		membar_producer();

		/*
		 * Clear Command Complete to transfer
		 * ownership to the platform.  The channel
		 * mutex serializes OS access (ACPI 6.6
		 * §14.2.2).
		 */
		*statusp &= ~PCC_STATUS_CMD_COMPLETE;
	}

	/*
	 * Command Complete clear must be observable before
	 * the doorbell (ACPI 6.6 s14.5 step 4).
	 */
	membar_producer();

	/* Ring the doorbell */
	pcc_ring_doorbell(pc);

	/* Poll for completion */
	ret = pcc_poll_complete(pc, &responded);

	/*
	 * Acknowledge the platform's response.  On timeout, we never
	 * observed completion, so ACKing would falsely claim the
	 * response was consumed and may race with firmware still
	 * writing shared memory.
	 */
	if (responded) {
		pcc_write_ack(pc);
	}

	/*
	 * Honour the Minimum Turnaround Time from the PCCT.  The
	 * platform needs this much idle time between successive
	 * commands on the same channel.
	 */
	if (pc->pc_turnaround > 0) {
		drv_usecwait(pc->pc_turnaround);
	}

	return (ret);
}

/*
 * Module infrastructure
 */

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

	mutex_init(&pcc_init_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&pcc_rmw_lock, NULL, MUTEX_DEFAULT, NULL);

	err = mod_install(&modlinkage);
	if (err != 0) {
		mutex_destroy(&pcc_rmw_lock);
		mutex_destroy(&pcc_init_lock);
	}
	return (err);
}

int
_fini(void)
{
	/* Do not allow unload; channels may be in use */
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
