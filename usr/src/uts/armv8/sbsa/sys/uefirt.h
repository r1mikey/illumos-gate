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

#ifndef _SYS_UEFIRT_H
#define	_SYS_UEFIRT_H

#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int uefirt_get_time(timestruc_t *ts);
extern int uefirt_set_time(timestruc_t ts);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_UEFIRT_H */
