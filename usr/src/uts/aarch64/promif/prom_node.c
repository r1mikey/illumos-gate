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
 * Dispatch functions for PROM nodes.
 */

pnode_t
prom_rootnode(void)
{
	return (prom_ops->po_rootnode());
}

pnode_t
prom_nextnode(pnode_t nodeid)
{
	return (prom_ops->po_nextnode(nodeid));
}

pnode_t
prom_childnode(pnode_t nodeid)
{
	return (prom_ops->po_childnode(nodeid));
}

pnode_t
prom_findnode_byname(pnode_t n, char *name)
{
	return (prom_ops->po_findnode_byname(n, name));
}

pnode_t
prom_chosennode(void)
{
	return (prom_ops->po_chosennode());
}

pnode_t
prom_optionsnode(void)
{
	return (prom_ops->po_optionsnode());
}

pnode_t
prom_finddevice(const char *path)
{
	return (prom_ops->po_finddevice(path));
}

pnode_t
prom_alias_node(void)
{
	return (prom_ops->po_alias_node());
}

void
prom_pathname(char *buf)
{
	return (prom_ops->po_pathname(buf));
}
