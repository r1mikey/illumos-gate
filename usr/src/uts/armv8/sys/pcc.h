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

#ifndef _SYS_PCC_H
#define	_SYS_PCC_H

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
 * The shared memory region for each channel starts with a standard
 * PCC header (ACPI 6.5 Table 14-350):
 *   Offset 0: Signature  (4 bytes)
 *   Offset 4: Command    (2 bytes) - written by OS before doorbell
 *   Offset 6: Status     (2 bytes) - set by platform on completion
 *
 * Higher-level protocols (e.g. CPPC) place their register data at
 * offsets within this same shared memory region, as specified by the
 * _CPC ACPI method.
 */

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * PCC shared memory header offsets and sizes.
 */
#define	PCC_SHMEM_SIGNATURE	0
#define	PCC_SHMEM_CMD		4
#define	PCC_SHMEM_STATUS	6
#define	PCC_SHMEM_HDR_LEN	8

/*
 * PCC command values written to the Command field at offset 4.
 */
#define	PCC_CMD_READ		0
#define	PCC_CMD_WRITE		1

/*
 * PCC status bits read from the Status field at offset 6.
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
 * The channel lock must be held by the caller.
 */
extern int pcc_chan_read32(uint_t chan_id, uint32_t offset, uint32_t *val);
extern int pcc_chan_write32(uint_t chan_id, uint32_t offset, uint32_t val);
extern int pcc_chan_read64(uint_t chan_id, uint32_t offset, uint64_t *val);

/*
 * Execute the PCC doorbell/ack protocol.
 *
 * Writes the given command to the shared memory Command field,
 * clears the Status field, rings the doorbell register, and polls
 * for command completion with a timeout derived from the channel's
 * command latency.  For Type 2/3 channels, writes the ACK register
 * on completion.
 *
 * Returns DDI_SUCCESS on successful completion, DDI_FAILURE on
 * timeout or platform error.
 *
 * The channel lock must be held by the caller.
 */
extern int pcc_chan_send(uint_t chan_id, uint16_t cmd);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_PCC_H */
