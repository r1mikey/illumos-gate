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
 * Copyright 2023 Michael van der Westhuizen
 */

	.file	"osl_ml.S"

/*
 * The Global Lock is not a part of the hardware reduced profile, so it does
 * not apply to aarch64.
 */

#include <sys/asm_linkage.h>

	ENTRY(__acpi_acquire_global_lock)
	ret
	SET_SIZE(__acpi_acquire_global_lock)

	ENTRY(__acpi_release_global_lock)
	ret
	SET_SIZE(__acpi_release_global_lock)

	ENTRY(__acpi_wbinvd)
	ret
	SET_SIZE(__acpi_wbinvd)
