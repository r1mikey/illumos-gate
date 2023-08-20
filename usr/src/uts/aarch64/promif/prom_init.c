/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2023 Michael van der Westhuizen
 * Copyright 2017 Hayashi Naoyuki
 */

#include <sys/promif.h>
#include <sys/promimpl.h>
#include <sys/prom_emul.h>
#include <sys/bootconf.h>
#include <sys/obpdefs.h>
#include <sys/kmem.h>
#include <libfdt.h>

int	promif_debug = 0;	/* debug */
int	emul_1275 = 0;

extern int	prom_is_acpi;

/*
 * prom_init() lives in prom_node.c in this implementation.
 */

#ifndef _KMDB
/*
 * This is for compatibility only. Somewhere between Solaris 2.6
 * and 10, we had a prom tree constructed by a bootloader with
 * realmode drivers. That is now gone, but we are left with some
 * applications depending on /dev/openprom. We fake a prom tree
 * based on hardware properties in the kernel device tree.
 */
void
prom_setup()
{
	if (prom_is_acpi)
		promif_create_device_tree();
}
#endif
