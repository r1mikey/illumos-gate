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

#ifndef _PROM_OPS_H
#define	_PROM_OPS_H

/*
 * PROM operations functions for unifying FDT and generic PROM.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	/* initialisation */
	void	(*po_setup)(void);

	/* utility operations */
	void	(*po_create_device_tree)(void);

	/* node operations */
	pnode_t	(*po_rootnode)(void);
	pnode_t	(*po_nextnode)(pnode_t nodeid);
	pnode_t	(*po_childnode)(pnode_t nodeid);
	pnode_t	(*po_findnode_byname)(pnode_t n, char *name);
	pnode_t	(*po_chosennode)(void);
	pnode_t	(*po_optionsnode)(void);
	pnode_t	(*po_finddevice)(const char *path);
	pnode_t	(*po_alias_node)(void);
	void	(*po_pathname)(char *buf);

	/* property operations */
	int	(*po_getproplen)(pnode_t nodeid, const char *name);
	int	(*po_getprop)(pnode_t nodeid, const char *name, caddr_t value);
	caddr_t	(*po_nextprop)(pnode_t nodeid, caddr_t previous, caddr_t next);
	char	*(*po_decode_composite_string)(
	    void *buf, size_t buflen, char *prev);
	int	(*po_bounded_getprop)(
	    pnode_t nodeid, const char *name, caddr_t value, int len);
} prom_ops_t;

#ifdef __cplusplus
}
#endif

#endif /* _PROM_OPS_H */
