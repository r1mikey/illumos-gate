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
 *   - A shared memory region at a fixed physical address
 *   - A doorbell register the OS writes to notify the platform
 *   - An acknowledge register the OS writes to clear completion state
 *   - Timing parameters (command latency, turnaround time)
 *
 * The shared memory region begins with a standard 8-byte header
 * (Signature, Command, Status) followed by protocol-specific data.
 * The PCC transport protocol is:
 *   1. Write protocol data to shared memory (caller's responsibility)
 *   2. Write command to the Command field (offset 4)
 *   3. Clear the Status field (offset 6)
 *   4. Ring the doorbell (read-modify-write with preserve/write masks)
 *   5. Poll Status for Command Complete (bit 0), with timeout
 *   6. Check Status Error bit (bit 2)
 *   7. Write ACK register to acknowledge completion (Type 2/3)
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
#include <sys/pcc.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>

/*
 * Internal representation of a parsed PCC channel.
 */
typedef struct pcc_chan {
	boolean_t	pc_valid;	/* channel was parsed successfully */
	uint8_t		pc_type;	/* PCCT subspace type (2 or 3) */
	kmutex_t	pc_lock;	/* serializes channel access */

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

	/* Timing */
	uint32_t	pc_latency;	/* command latency in microseconds */
	uint32_t	pc_max_rate;	/* max access rate */
	uint16_t	pc_turnaround;	/* min turnaround time */
} pcc_chan_t;

static pcc_chan_t pcc_channels[PCC_MAX_CHANNELS];
static uint_t pcc_nchan;
static boolean_t pcc_initialized;

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
	if (len == 0) {
		len = 4;
	}

	return (psm_map_phys((paddr_t)pa, len, PROT_READ | PROT_WRITE));
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

	pc->pc_type = ACPI_PCCT_TYPE_HW_REDUCED_SUBSPACE_TYPE2;
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

	return (DDI_SUCCESS);
}

/*
 * Parse a single Type 3 (Extended PCC Master) PCCT subspace and
 * populate the channel structure.
 *
 * Type 3 extends Type 2 with additional command complete, command
 * update, and error status registers.  For the basic PCC transport
 * protocol we only use the doorbell and ack mechanism, which is
 * identical to Type 2.  The extended registers are available for
 * future use if needed.
 */
static int
pcc_parse_type3(ACPI_PCCT_EXT_PCC_MASTER *sub, pcc_chan_t *pc)
{
	ASSERT3P(sub, !=, NULL);
	ASSERT3P(pc, !=, NULL);

	pc->pc_type = ACPI_PCCT_TYPE_EXT_PCC_MASTER_SUBSPACE;
	pc->pc_base_pa = sub->BaseAddress;
	pc->pc_length = (uint64_t)sub->Length;
	pc->pc_latency = sub->Latency;
	pc->pc_max_rate = sub->MaxAccessRate;
	pc->pc_turnaround = (uint16_t)sub->MinTurnaroundTime;

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

	return (DDI_SUCCESS);
}

/*
 * Map the shared memory and MMIO registers for a parsed channel.
 */
static int
pcc_map_channel(pcc_chan_t *pc)
{
	ASSERT3P(pc, !=, NULL);

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
		cmn_err(CE_WARN, "!pcc: failed to map doorbell register "
		    "at 0x%llx", (unsigned long long)pc->pc_db_pa);
		psm_unmap_phys(pc->pc_base_va, (size_t)pc->pc_length);
		pc->pc_base_va = NULL;
		return (DDI_FAILURE);
	}

	/* Map the ack register, if present */
	if (pc->pc_has_ack) {
		pc->pc_ack_va = pcc_map_register(pc->pc_ack_pa,
		    pc->pc_ack_width);
		if (pc->pc_ack_va == NULL) {
			cmn_err(CE_WARN, "!pcc: failed to map ack register "
			    "at 0x%llx",
			    (unsigned long long)pc->pc_ack_pa);
			psm_unmap_phys(pc->pc_db_va,
			    (size_t)((pc->pc_db_width + 7) / 8));
			psm_unmap_phys(pc->pc_base_va,
			    (size_t)pc->pc_length);
			pc->pc_db_va = NULL;
			pc->pc_base_va = NULL;
			return (DDI_FAILURE);
		}
	}

	return (DDI_SUCCESS);
}

/*
 * Ring the doorbell register.
 *
 * Performs a read-modify-write: reads the current value, applies the
 * preserve mask (AND), sets the write mask bits (OR), and writes back.
 */
static void
pcc_ring_doorbell(pcc_chan_t *pc)
{
	volatile uint32_t *db32;
	uint32_t val;

	ASSERT3P(pc, !=, NULL);
	ASSERT3P(pc->pc_db_va, !=, NULL);

	/*
	 * All doorbell registers observed on arm64 platforms are 32-bit
	 * SystemMemory-addressed MMIO.
	 */
	db32 = (volatile uint32_t *)(void *)pc->pc_db_va;
	val = *db32;
	val = (uint32_t)((val & pc->pc_db_preserve) | pc->pc_db_write);
	*db32 = val;
}

/*
 * Write the ACK register to acknowledge command completion.
 */
static void
pcc_write_ack(pcc_chan_t *pc)
{
	volatile uint32_t *ack32;
	uint32_t val;

	ASSERT3P(pc, !=, NULL);

	if (!pc->pc_has_ack || pc->pc_ack_va == NULL) {
		return;
	}

	ack32 = (volatile uint32_t *)(void *)pc->pc_ack_va;
	val = *ack32;
	val = (uint32_t)((val & pc->pc_ack_preserve) | pc->pc_ack_write);
	*ack32 = val;
}

/*
 * Poll the shared memory Status field for command completion.
 *
 * Returns DDI_SUCCESS when Command Complete (bit 0) is set, or
 * DDI_FAILURE on timeout or platform error.
 */
static int
pcc_poll_status(pcc_chan_t *pc)
{
	volatile uint16_t *statusp;
	uint16_t status;
	uint32_t timeout_us;
	uint32_t elapsed;

	ASSERT3P(pc, !=, NULL);
	ASSERT3P(pc->pc_base_va, !=, NULL);

	statusp = (volatile uint16_t *)(void *)(pc->pc_base_va +
	    PCC_SHMEM_STATUS);

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
		status = *statusp;

		if (status & PCC_STATUS_ERROR) {
			cmn_err(CE_WARN, "!pcc: platform reported error "
			    "(status 0x%x)", status);
			return (DDI_FAILURE);
		}

		if (status & PCC_STATUS_CMD_COMPLETE) {
			return (DDI_SUCCESS);
		}

		drv_usecwait(PCC_POLL_INTERVAL_US);
	}

	cmn_err(CE_WARN, "!pcc: command timed out after %u us "
	    "(latency %u us)", elapsed, pc->pc_latency);
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

	if (!pcc_initialized || chan_id >= pcc_nchan) {
		return (NULL);
	}

	pc = &pcc_channels[chan_id];
	if (!pc->pc_valid) {
		return (NULL);
	}

	return (pc);
}

int
pcc_init(void)
{
	ACPI_TABLE_HEADER *hdr;
	ACPI_STATUS status;
	uint8_t *tbl;
	uint8_t *end;
	uint8_t *pos;
	uint_t idx;
	int ret;

	if (pcc_initialized) {
		return (DDI_SUCCESS);
	}

	status = AcpiGetTable(ACPI_SIG_PCCT, 1, &hdr);
	if (ACPI_FAILURE(status)) {
		cmn_err(CE_NOTE, "!pcc: PCCT table not found");
		return (DDI_FAILURE);
	}

	tbl = (uint8_t *)hdr;
	end = tbl + hdr->Length;
	pos = tbl + sizeof (ACPI_TABLE_PCCT);
	idx = 0;

	while (pos < end && idx < PCC_MAX_CHANNELS) {
		ACPI_SUBTABLE_HEADER *sub_hdr;
		pcc_chan_t *pc;

		sub_hdr = (ACPI_SUBTABLE_HEADER *)(void *)pos;
		if (sub_hdr->Length == 0 || pos + sub_hdr->Length > end) {
			break;
		}

		pc = &pcc_channels[idx];
		memset(pc, 0, sizeof (*pc));
		mutex_init(&pc->pc_lock, NULL, MUTEX_DEFAULT, NULL);

		ret = DDI_FAILURE;

		switch (sub_hdr->Type) {
		case ACPI_PCCT_TYPE_HW_REDUCED_SUBSPACE_TYPE2:
			if (sub_hdr->Length <
			    sizeof (ACPI_PCCT_HW_REDUCED_TYPE2)) {
				cmn_err(CE_WARN, "!pcc: subspace %u type 2 "
				    "too short (%u bytes)", idx,
				    sub_hdr->Length);
				break;
			}
			ret = pcc_parse_type2(
			    (ACPI_PCCT_HW_REDUCED_TYPE2 *)(void *)pos, pc);
			break;

		case ACPI_PCCT_TYPE_EXT_PCC_MASTER_SUBSPACE:
			if (sub_hdr->Length <
			    sizeof (ACPI_PCCT_EXT_PCC_MASTER)) {
				cmn_err(CE_WARN, "!pcc: subspace %u type 3 "
				    "too short (%u bytes)", idx,
				    sub_hdr->Length);
				break;
			}
			ret = pcc_parse_type3(
			    (ACPI_PCCT_EXT_PCC_MASTER *)(void *)pos, pc);
			break;

		default:
			/*
			 * Types 0, 1, 4+ are not used by CPPC on arm64.
			 * Record them as invalid so channel indices stay
			 * aligned with the PCCT subspace order.
			 */
			break;
		}

		if (ret == DDI_SUCCESS) {
			ret = pcc_map_channel(pc);
		}

		if (ret == DDI_SUCCESS) {
			pc->pc_valid = B_TRUE;
		}

		pos += sub_hdr->Length;
		idx++;
	}

	pcc_nchan = idx;
	pcc_initialized = B_TRUE;

	if (idx == 0) {
		cmn_err(CE_NOTE, "!pcc: no subspaces found in PCCT");
		return (DDI_FAILURE);
	}

	cmn_err(CE_CONT, "!pcc: parsed %u PCCT subspace(s)\n", idx);
	return (DDI_SUCCESS);
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

	/* Offsets from callers are relative to the Communication Space */
	abs_off = (uint64_t)offset + PCC_SHMEM_HDR_LEN;
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

	abs_off = (uint64_t)offset + PCC_SHMEM_HDR_LEN;
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

	abs_off = (uint64_t)offset + PCC_SHMEM_HDR_LEN;
	if (abs_off + sizeof (uint64_t) > pc->pc_length) {
		return (DDI_FAILURE);
	}

	addr = (volatile uint64_t *)(void *)(pc->pc_base_va + abs_off);
	*val = *addr;

	return (DDI_SUCCESS);
}

int
pcc_chan_send(uint_t chan_id, uint16_t cmd)
{
	pcc_chan_t *pc;
	volatile uint16_t *cmdp;
	volatile uint16_t *statusp;
	int ret;

	pc = pcc_get_chan(chan_id);
	if (pc == NULL) {
		return (DDI_FAILURE);
	}

	cmdp = (volatile uint16_t *)(void *)(pc->pc_base_va + PCC_SHMEM_CMD);
	statusp = (volatile uint16_t *)(void *)(pc->pc_base_va +
	    PCC_SHMEM_STATUS);

	/* Clear status before issuing the command */
	*statusp = 0;

	/* Write the command */
	*cmdp = cmd;

	/* Ensure writes are visible before ringing the doorbell */
	membar_producer();

	/* Ring the doorbell */
	pcc_ring_doorbell(pc);

	/* Poll for completion */
	ret = pcc_poll_status(pc);

	/* Acknowledge completion regardless of success/failure */
	pcc_write_ack(pc);

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
	return (mod_install(&modlinkage));
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
