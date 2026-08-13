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

#ifndef	_SYS_ACPIPCC_H
#define	_SYS_ACPIPCC_H

/*
 * Public interface to the ACPI Platform Communications Channel (PCC) driver,
 * which is the acpipcc module.  PCC implements the subspace types defined in
 * ACPI 6.6 Chapter 14 and provides channel handles to consumers such as CPPC,
 * RASF, PDTT and MPST.
 */

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pcc_chan pcc_chan_t;

/*
 * Acquire or release a channel.
 */
extern pcc_chan_t *pcc_chan_get(uint_t chan_id);
extern void pcc_chan_put(pcc_chan_t *pc);

/*
 * Acquire or release the channel mutex.
 */
extern void pcc_chan_lock(pcc_chan_t *pc);
extern void pcc_chan_unlock(pcc_chan_t *pc);

/*
 * Communication space access.
 */
extern int pcc_chan_read32(pcc_chan_t *pc, uint32_t offset, uint32_t *val);
extern int pcc_chan_write32(pcc_chan_t *pc, uint32_t offset, uint32_t val);
extern int pcc_chan_read64(pcc_chan_t *pc, uint32_t offset, uint64_t *val);
extern int pcc_chan_write64(pcc_chan_t *pc, uint32_t offset, uint64_t val);

/*
 * Initiate platform communication.
 */
extern int pcc_chan_send(pcc_chan_t *pc, uint32_t cmd, uint32_t payload_len);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_ACPIPCC_H */
