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
 * Copyright 2024 Michael van der Westhuizen
 */

#ifndef _SYS_ACPIDEV_DEVPROP_H
#define	_SYS_ACPIDEV_DEVPROP_H

#include <sys/acpidev.h>

#ifdef __cplusplus
extern "C" {
#endif

ACPI_STATUS acpidev_devprop_process(acpidev_walk_info_t *infop);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_ACPIDEV_DEVPROP_H */
