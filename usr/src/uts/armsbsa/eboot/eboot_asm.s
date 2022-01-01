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
 * Copyright 2022 Michael van der Westhuizen
 */

	.file   "eboot_asm.s"

/*
 * Helper routines for bootstrapping in an EFI environment.
 */

#include <sys/asm_linkage.h>
/* #include <sys/asm_misc.h> */

#if defined(__aarch64__)

	ENTRY_NP(iowrite32)
	str	w1, [x0]
	ret
	SET_SIZE(iowrite32)

	ENTRY_NP(ioread32)
	ldr	w0, [x0]
	ret
	SET_SIZE(ioread32)

#endif	/* __aarch64__ */
