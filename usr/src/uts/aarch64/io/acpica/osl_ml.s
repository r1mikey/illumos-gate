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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

#include <sys/asm_linkage.h>

/*
 * Implementation as specific by ACPI 3.0 specification
 * section 5.2.10.1
 *
 * Global Lock Structure within the FACS 
 *
 * |-----------------------------------------------------------------------| 
 * |  Field  | Bit Length | Bit Offset |           Description             |
 * |---------|------------|------------|-----------------------------------| 
 * | Pending |     1      |     0      | Non-zero indicates that a request |
 * |         |            |            | for ownership of the global lock  |
 * |         |            |            | is pending.                       |
 * |---------|------------|------------|-----------------------------------| 
 * | Owned   |     1      |     1      | Non-zero indicates that the Global|
 * |         |            |            | lock is owned.                    |
 * |---------|------------|------------|-----------------------------------| 
 * | Reserved|     30     |     2      | Reserved for future use           |
 * |---------|------------|------------|-----------------------------------| 
 */

/*
 * The Global Lock is not a part of the hardware reduced profile, so it does
 * not apply to aarch64.
 */

/* Offset of GlobalLock element in FACS structure */
#define	GlobalLock	0x10

	ENTRY(__acpi_acquire_global_lock)
	ret
	SET_SIZE(__acpi_acquire_global_lock)


	ENTRY(__acpi_release_global_lock)
	ret
	SET_SIZE(__acpi_release_global_lock)


/*
 * execute WBINVD instruction
 */

	ENTRY(__acpi_wbinvd)
	/* wbinvd */
	ret
	SET_SIZE(__acpi_wbinvd)

