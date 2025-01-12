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
 * Copyright 2025 Michael van der Westhuizen
 */

#ifndef _SYS_EFIFB_H
#define	_SYS_EFIFB_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct efi_fb {
	uint64_t	fb_addr;
	uint64_t	fb_size;
	uint32_t	fb_height;
	uint32_t	fb_width;
	uint32_t	fb_stride;
	uint32_t	fb_mask_red;
	uint32_t	fb_mask_green;
	uint32_t	fb_mask_blue;
	uint32_t	fb_mask_reserved;
};

#ifdef __cplusplus
}
#endif

#endif /* _SYS_EFIFB_H */
