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

#include <sys/systm.h>

/*
 * All platmod functions are weak and are only present when required.
 * The function calls have been converted to use methods
 *	if (&plat_func)
 *		plat_func(args);
 */

/*
 * Platform power management drivers list - empty by default
 */
char *platform_module_list[] = {
	NULL
};

void
plat_tod_fault(enum tod_fault_type tod_bad __unused)
{
}
