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

#ifndef _SYS_ACPIPCC_H
#define	_SYS_ACPIPCC_H

/*
 * Platform Communications Channel (PCC) - ACPI PCCT table driver.
 *
 * Parses the PCCT (Platform Communications Channel Table) and provides
 * access to PCC subspace shared memory regions and the associated
 * doorbell/acknowledge transport protocol.
 *
 * Supported subspace types:
 *   Type 2 - HW-Reduced Communications Subspace (ACPI 6.1)
 *   Type 3 - Extended PCC Master Subspace (ACPI 6.2)
 *
 * Type 0-2 shared memory layout (ACPI 6.6 Table 14.9):
 *   Offset 0: Signature  (4 bytes)
 *   Offset 4: Command    (2 bytes) - written by OS before doorbell
 *   Offset 6: Status     (2 bytes) - set by platform on completion
 *   Offset 8: Communication Space
 *
 * Type 3 extended shared memory layout (ACPI 6.6 Table 14.12):
 *   Offset 0:  Signature  (4 bytes)
 *   Offset 4:  Flags      (4 bytes)
 *   Offset 8:  Length     (4 bytes)
 *   Offset 12: Command    (4 bytes) - written by OS before doorbell
 *   Offset 16: Communication Space
 *
 * Type 3 does not carry completion or error status in shared memory.
 * Instead, separate MMIO registers described in the PCCT provide
 * command-complete checking, command-complete clearing, and error
 * status.
 *
 * Higher-level protocols (e.g. CPPC) place their register data at
 * offsets within the Communication Space, as specified by the _CPC
 * ACPI method.
 */

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Type 0-2 shared memory header offsets (ACPI 6.6 Table 14.9).
 */
#define	PCC_SHMEM_SIGNATURE	0
#define	PCC_SHMEM_CMD		4
#define	PCC_SHMEM_STATUS	6
#define	PCC_SHMEM_HDR_LEN	8

/*
 * Type 3 extended shared memory header offsets (ACPI 6.6 Table 14.12).
 */
#define	PCC_EXT_SHMEM_SIGNATURE	0
#define	PCC_EXT_SHMEM_FLAGS	4
#define	PCC_EXT_SHMEM_LENGTH	8
#define	PCC_EXT_SHMEM_CMD	12
#define	PCC_EXT_SHMEM_HDR_LEN	16

/*
 * PCC command values written to the Command field.
 */
#define	PCC_CMD_READ		0
#define	PCC_CMD_WRITE		1

/*
 * PCC status bits for the Type 0-2 Status field at offset 6.
 */
#define	PCC_STATUS_CMD_COMPLETE	(1U << 0)
#define	PCC_STATUS_SCI_DOORBELL	(1U << 1)
#define	PCC_STATUS_ERROR	(1U << 2)
#define	PCC_STATUS_NOTIFY	(1U << 3)

/*
 * Maximum number of PCC channels (ACPI allows up to 256 subspaces).
 */
#define	PCC_MAX_CHANNELS	256

/*
 * Information about a parsed PCC channel, returned by pcc_chan_info().
 */
typedef struct pcc_chan_info {
	uint8_t		pci_type;	/* PCCT subspace type (2 or 3) */
	uint64_t	pci_base;	/* shared memory physical address */
	uint64_t	pci_length;	/* shared memory region size */
	uint32_t	pci_latency;	/* command latency in microseconds */
} pcc_chan_info_t;

/*
 * Initialize the PCC subsystem by parsing the PCCT ACPI table.
 *
 * Must be called once before any other pcc_chan_*() function.
 * Returns DDI_SUCCESS if the PCCT was found and parsed, or
 * DDI_FAILURE if the PCCT is absent or contains no supported
 * subspaces.
 */
extern int pcc_init(void);

/*
 * Retrieve information about a PCC channel.
 *
 * Returns DDI_SUCCESS if the channel exists and is valid, or
 * DDI_FAILURE if chan_id is out of range or the channel was not
 * parsed.
 */
extern int pcc_chan_info(uint_t chan_id, pcc_chan_info_t *info);

/*
 * Acquire and release the per-channel mutex.
 *
 * Callers must hold the channel lock across a full PCC transaction
 * (write registers, send command, read results).  pcc_chan_lock()
 * returns DDI_SUCCESS if the channel exists or DDI_FAILURE otherwise.
 */
extern int pcc_chan_lock(uint_t chan_id);
extern void pcc_chan_unlock(uint_t chan_id);

/*
 * Read/write the shared memory region of a PCC channel.
 *
 * These perform raw memory access to the mapped shared memory at the
 * given byte offset.  No PCC doorbell or command protocol is involved;
 * the caller is responsible for bracketing these with pcc_chan_send()
 * as required by the higher-level protocol.
 *
 * Offsets are relative to the start of the Communication Space, which
 * follows the channel's type-specific header (8 bytes for Type 0-2,
 * 16 bytes for Type 3).  The offset translation is handled
 * internally.
 *
 * The channel lock must be held by the caller.
 */
extern int pcc_chan_read32(uint_t chan_id, uint32_t offset, uint32_t *val);
extern int pcc_chan_write32(uint_t chan_id, uint32_t offset, uint32_t val);
extern int pcc_chan_read64(uint_t chan_id, uint32_t offset, uint64_t *val);

/*
 * Execute the PCC doorbell/ack protocol.
 *
 * Verifies that the channel is free (Command Complete is set),
 * then populates the shared memory header and transfers ownership
 * to the platform (ACPI 6.6 s14.5 steps 1-4):
 *
 * For Type 0-2: writes the 16-bit command, clears Command
 * Complete in the Status field using an interlocked operation,
 * and rings the doorbell.  Polls the Status field for
 * completion, then checks the Error bit.
 *
 * For Type 3: writes Flags (0, no completion interrupt),
 * Length (command + payload_len), and the 32-bit command.
 * Clears Command Complete via the CmdUpdate register and
 * rings the doorbell.  Polls the CmdComplete register for
 * completion, then checks and clears ErrorStatus.
 *
 * For both types, writes the ACK register when the platform
 * responds (success or error) and honours the minimum
 * turnaround time.  The ACK is skipped on timeout since no
 * response was observed.
 *
 * payload_len is the number of bytes the caller wrote into
 * the Communication Space before calling pcc_chan_send.
 * For read commands this is 0.  The value is used only by
 * Type 3 channels for the Length header field; Type 0-2
 * channels ignore it.
 *
 * Returns DDI_SUCCESS on successful completion, DDI_FAILURE on
 * timeout or platform error.
 *
 * The channel lock must be held by the caller.
 */
extern int pcc_chan_send(uint_t chan_id, uint32_t cmd,
    uint32_t payload_len);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_ACPIPCC_H */
