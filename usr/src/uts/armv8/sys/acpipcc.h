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
 * Public interface to the ACPI Platform Communications Channel (PCC)
 * driver, which is the acpipcc module.  PCC implements the
 * subspace types defined in ACPI 6.6 Chapter 14 and provides channel
 * handles to consumers such as CPPC, RASF, PDTT and MPST.
 *
 * Channel handles are opaque.  The full struct pcc_chan definition
 * lives in the driver's private header; consumers must not cast the
 * handle to void * or inspect its contents.
 */

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pcc_chan pcc_chan_t;

/*
 * Shared memory header layout.  Offsets are relative to the start of
 * the channel's shared memory region.  Access is always via volatile
 * casts.  Consumers may read the Status and Command fields directly
 * using these offsets.
 */

/* Type 0-2 generic communications channel header (8 bytes). */
#define	PCC_SHMEM_SIGNATURE	0	/* UINT32 */
#define	PCC_SHMEM_CMD		4	/* UINT16 */
#define	PCC_SHMEM_STATUS	6	/* UINT16 */
#define	PCC_SHMEM_HDR_LEN	8

/* Type 3 extended PCC header (16 bytes). */
#define	PCC_EXT_SHMEM_SIGNATURE	0	/* UINT32 */
#define	PCC_EXT_SHMEM_FLAGS	4	/* UINT32 */
#define	PCC_EXT_SHMEM_LENGTH	8	/* UINT32 */
#define	PCC_EXT_SHMEM_CMD	12	/* UINT32 */
#define	PCC_EXT_SHMEM_HDR_LEN	16

/*
 * Generic shared memory Status field (UINT16 at PCC_SHMEM_STATUS).
 * Used by Types 0, 1 and 2.  Not provided by ACPICA.
 */
#define	PCC_STATUS_CMD_COMPLETE		(1u << 0)
#define	PCC_STATUS_PLATFORM_IRQ		(1u << 1) /* SCI(T0)/doorbell(T1-2) */
#define	PCC_STATUS_ERROR		(1u << 2)
#define	PCC_STATUS_PLATFORM_NOTIFY	(1u << 3) /* deprecated notification */

/*
 * Generic shared memory Command field (UINT16 at PCC_SHMEM_CMD).
 * Used by Types 0, 1 and 2.  ACPI 6.6 Table 14.10: bits 0-7 are the
 * command code, bits 8-14 are reserved, bit 15 is Notify on
 * Completion.
 */
#define	PCC_CMD_NOTIFY_ON_COMPLETE	(1u << 15)

/*
 * Extended shared memory Flags field (UINT32 at PCC_EXT_SHMEM_FLAGS).
 * Used by Type 3.
 */
#define	PCC_EXT_FLAG_NOTIFY_ON_COMPLETE	(1u << 0)

/*
 * Signature base value.  The per-subspace signature is
 * PCC_SIGNATURE_BASE | subspace_id, where subspace_id is the
 * firmware subspace ID (the PCCT subtable index).  Some consumers
 * (e.g. RASF) define their own signatures instead.
 */
#define	PCC_SIGNATURE_BASE		0x50434300u

/*
 * Initialise PCC: parse the PCCT, validate subspace descriptions and
 * bring up usable channels.  Called from acpidev attach, after the
 * acpica module has initialised.  Consumers must not call this;
 * pcc_chan_get works once PCC has initialised.
 * Returns DDI_SUCCESS or DDI_FAILURE.
 */
int pcc_init(void);

/*
 * Tear down PCC: release interrupts, unmap registers and shared
 * memory, and free channels.  The module's _fini refuses unload
 * (channels may be in use), so this is not called in normal
 * operation; it exists to reverse pcc_init for completeness.
 */
void pcc_teardown(void);

/*
 * Look up a channel by firmware subspace ID (the PCCT subtable index,
 * also used in CPPC _CPC packages).  This is NOT the channel's index
 * in the driver's channel array.
 *
 * Returns a handle, or NULL if the ID does not exist, the channel is
 * not usable (OS-side bring-up failed), or PCC did not initialise.
 * A successful get increments the channel's consumer reference count;
 * every successful get must be paired with pcc_chan_release.
 * The caller must not hold the channel mutex.
 */
pcc_chan_t *pcc_chan_get(uint_t chan_id);

/*
 * Release a channel handle obtained from pcc_chan_get.  Decrements
 * the consumer reference count.  The caller must not hold the
 * channel mutex.
 */
void pcc_chan_release(pcc_chan_t *pc);

/*
 * Acquire or release the channel mutex.  The mutex serialises
 * transactions on the channel between all of its consumers.
 */
void pcc_chan_lock(pcc_chan_t *pc);
void pcc_chan_unlock(pcc_chan_t *pc);

/*
 * Read or write the channel's Communication Space (the payload area
 * after the type-specific header).  offset is relative to the start
 * of the Communication Space.  The caller must hold the channel mutex.
 * Returns DDI_SUCCESS, or DDI_FAILURE if the access is out of bounds.
 */
int pcc_chan_read32(pcc_chan_t *pc, uint32_t offset, uint32_t *val);
int pcc_chan_write32(pcc_chan_t *pc, uint32_t offset, uint32_t val);
int pcc_chan_read64(pcc_chan_t *pc, uint32_t offset, uint64_t *val);
int pcc_chan_write64(pcc_chan_t *pc, uint32_t offset, uint64_t val);

/*
 * Send a command on the channel.  The caller writes the payload with
 * the pcc_chan_write accessors, then calls pcc_chan_send; the driver
 * writes the header, rings the doorbell and waits for completion
 * (interrupt-driven when the channel has an interrupt, polled
 * otherwise).  payload_len is the number of payload bytes the caller
 * wrote (0 for a header-only command).  For Types 0-2 it is ignored:
 * the platform derives the extent from the subspace Length.
 *
 * The caller must hold the channel mutex.  Returns DDI_SUCCESS or
 * DDI_FAILURE (transport or protocol error).
 */
int pcc_chan_send(pcc_chan_t *pc, uint32_t cmd, uint32_t payload_len);

/*
 * Fire-and-forget send for use where waiting is impossible, such as
 * the panic path (PDTT-style debug triggers).  Writes the header and
 * payload, rings the doorbell and returns without waiting for
 * completion.  Acquires the channel mutex itself; in the panic path
 * (panicstr != NULL) it uses mutex_tryenter and returns EBUSY if the
 * channel is busy.  This is the only panic-safe call in this API.
 * Returns DDI_SUCCESS, DDI_FAILURE or EBUSY.
 */
int pcc_chan_send_nowait(pcc_chan_t *pc, uint32_t cmd, uint32_t payload_len);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_ACPIPCC_H */
