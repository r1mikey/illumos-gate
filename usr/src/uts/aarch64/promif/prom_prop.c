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

#include <sys/promif.h>
#include <sys/promimpl.h>
#include <sys/systm.h>
#include <sys/sunddi.h>

#include "prom_ops.h"

extern const prom_ops_t *prom_ops;

/*
 * Dispatch functions for PROM properties.
 */
int
prom_getproplen(pnode_t nodeid, const char *name)
{
	return (prom_ops->po_getproplen(nodeid, name));
}

int
prom_getprop(pnode_t nodeid, const char *name, caddr_t value)
{
	return (prom_ops->po_getprop(nodeid, name, value));
}

caddr_t
prom_nextprop(pnode_t nodeid, caddr_t previous, caddr_t next)
{
	return (prom_ops->po_nextprop(nodeid, previous, next));
}

char *
prom_decode_composite_string(void *buf, size_t buflen, char *prev)
{
	return (prom_ops->po_decode_composite_string(buf, buflen, prev));
}

int
prom_bounded_getprop(pnode_t nodeid, const char *name, caddr_t value, int len)
{
	return (prom_ops->po_bounded_getprop(nodeid, name, value, len));
}
