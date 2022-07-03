/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2022 Michael van der Westhuizen
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_ASM_SUNDDI_H
#define	_ASM_SUNDDI_H

#include <sys/types.h>
#include <sys/controlregs.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if !defined(__lint) && defined(__GNUC__)

#if defined(_BOOT)

/*
 * XXXAARCH64: dodgy: we should not be messing with EL0
 *
 * Is this even needed with new booting?
 */
static inline void
sync_instruction_memory(caddr_t addr, size_t len)
{
	uint64_t inst_line_size, data_line_size;
	uintptr_t v;

	inst_line_size = CTR_TO_INST_LINESIZE(read_ctr_el0());
	data_line_size = CTR_TO_DATA_LINESIZE(read_ctr_el0());

	for (v = (uintptr_t)addr;
	    v < (uintptr_t)addr + len;
	    v += data_line_size) {
		flush_data_cache(v);
	}
	dsb(ish);
	for (v = (uintptr_t)addr;
	    v < (uintptr_t)addr + len;
	    v += inst_line_size) {
		invalidate_instruction_cache(v);
	}
	dsb(ish);
	isb();
}

#endif /* _BOOT */

#endif /* !__lint && __GNUC__ */

#ifdef __cplusplus
}
#endif

#endif	/* _ASM_SUNDDI_H */
