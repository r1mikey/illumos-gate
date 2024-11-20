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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2024 Michael van der Westhuizen
 */

#include <libfdt.h>
#include <sys/promif.h>
#include <sys/promimpl.h>
#include <sys/systm.h>
#include <sys/sunddi.h>

#include "prom_ops.h"

/*
 * XXXARM:
 *
 * The rest of the system expects the "PROM" to provide device name and
 * unit-address as properties, however the devicetree specification gives
 * nodes true names, formed <name>@<unit-address>.
 *
 * We synthesize these properties at runtime, rather unfortunately.  An
 * alternative is to stuff them as actual properties into the devicetree, but
 * depending on platform this runs us out of string space in the FDT.
 *
 * It's possible in future it would be better to:
 * 1) Just resize the FDT to be big enough in prom_init (though this
 *    would move it, and leave the old one dangling).
 * 2) Specify a larger FDT in u-boot or other boot firmware
 * 3) Copy the whole FDT into a data structure of our own,
 *    rather than manipulating the actual FDT.
 */

static struct fdt_header	*prom_fdtp;

/*
 * This exists to keep us from trying to check for over-long property names
 * before the system can support us doing it.
 *
 * Can be tuned _to 0_ to prevent any warnings.  Tuning to 1 is absolutely
 * fatal.
 */
#ifdef DEBUG
static int prom_propname_warn = -1;
#else
static int prom_propname_warn = 0;
#endif

static phandle_t
get_phandle(int offset)
{
	int len;
	const void *prop = fdt_getprop(prom_fdtp, offset, "phandle", &len);

	/*
	 * XXXARM: It is not obvious to me, based on the specification, how we
	 * could ever not have a phandle
	 */
	if (prop == NULL || len != sizeof (uint32_t)) {
		uint32_t phandle = fdt_get_max_phandle(prom_fdtp) + 1;
		uint32_t v = ntohl(phandle);
		int r = fdt_setprop(prom_fdtp, offset, "phandle", &v,
		    sizeof (uint32_t));
		if (r != 0)
			return (-1);
		return (phandle);
	}

	uint32_t v;
	memcpy(&v, prop, sizeof (uint32_t));
	return (ntohl(v));
}

static void
prom_check_overlong_property(pnode_t nodeid, const char *name)
{
	/*
	 * We are called very early in boot, in limited circumstances.  So
	 * early we can't actually tell anyone we've failed.  Bail out if
	 * we're unready, or have been tuned off.
	 */
	if (prom_propname_warn <= 0)
		return;

	if ((strlen(name) + 1) > OBP_STANDARD_MAXPROPNAME) {
		int offset = fdt_node_offset_by_phandle(prom_fdtp, nodeid);
		const char *nodename = NULL;
		int len;

		if (offset < 0)
			goto no_name;

		nodename = fdt_get_name(prom_fdtp, offset, &len);
		if ((nodename == NULL) || nodename[0] == '\0')
			goto no_name;

		cmn_err(CE_WARN,
		    "PROM node '%s' request for over long property '%s'",
		    nodename, name);
		return;

no_name:
		cmn_err(CE_WARN,
		    "PROM node %u request for over long property '%s'",
		    nodeid, name);
	}
}

static int
prom_fdt_getprop(pnode_t nodeid, const char *name, caddr_t value)
{
	int offset = fdt_node_offset_by_phandle(prom_fdtp, nodeid);

	prom_check_overlong_property(nodeid, name);

	if (offset < 0)
		return (-1);

	int len;
	const void *prop = fdt_getprop(prom_fdtp, offset, name, &len);

	if (prop == NULL) {
		if (strcmp(name, "name") == 0) {
			const char *name_ptr = fdt_get_name(prom_fdtp, offset, &len);
			const char *p = strchr(name_ptr, '@');

			if (!name_ptr)
				return (-1);

			if (p) {
				len = p - name_ptr;
			} else {
				len = strlen(name_ptr);
			}
			memcpy(value, name_ptr, len);
			value[len] = '\0';

			return (len + 1);
		}
		if (strcmp(name, "unit-address") == 0) {
			const char *name_ptr = fdt_get_name(prom_fdtp, offset, &len);
			const char *p = strchr(name_ptr, '@');
			if (p) {
				p++;
				len = strlen(p);
			} else {
				return (-1);
			}
			if (len == 0)
				return (-1);

			memcpy(value, p, len);
			value[len] = '\0';
			return (len + 1);
		}

		return (-1);
	}

	memcpy(value, prop, len);
	return (len);
}

static int
prom_fdt_getproplen(pnode_t nodeid, const char *name)
{
	int offset = fdt_node_offset_by_phandle(prom_fdtp, (pnode_t)nodeid);

	if (offset < 0)
		return (-1);

	prom_check_overlong_property(nodeid, name);

	int len;
	const struct fdt_property *prop = fdt_get_property(prom_fdtp, offset, name,
	    &len);

	if (prop == NULL) {
		if (strcmp(name, "name") == 0) {
			const char *name_ptr = fdt_get_name(prom_fdtp, offset, &len);
			if (!name_ptr)
				return (-1);
			const char *p = strchr(name_ptr, '@');
			if (p) {
				len = p - name_ptr;
			} else {
				len = strlen(name_ptr);
			}

			return (len + 1);
		}
		if (strcmp(name, "unit-address") == 0) {
			const char *name_ptr = fdt_get_name(prom_fdtp, offset, &len);
			if (!name_ptr)
				return (-1);
			const char *p = strchr(name_ptr, '@');
			if (p) {
				p++;
				len = strlen(p);
			} else {
				return (-1);
			}
			if (len == 0)
				return (-1);
			return (len + 1);
		}

		return (-1);
	}

	return (len);
}

static pnode_t
prom_fdt_finddevice(const char *device)
{
	int offset = fdt_path_offset(prom_fdtp, device);
	if (offset < 0)
		return (OBP_BADNODE);

	phandle_t phandle = get_phandle(offset);
	if (phandle < 0)
		return (OBP_BADNODE);

	return ((pnode_t)phandle);
}

static pnode_t
prom_fdt_rootnode(void)
{
	pnode_t root = prom_fdt_finddevice("/");
	if (root < 0) {
		return (OBP_NONODE);
	}
	return (root);
}

static pnode_t
prom_fdt_chosennode(void)
{
	pnode_t node = prom_fdt_finddevice("/chosen");
	if (node != OBP_BADNODE)
		return (node);
	return (OBP_NONODE);
}

static pnode_t
prom_fdt_optionsnode(void)
{
	pnode_t node = prom_fdt_finddevice("/options");
	if (node != OBP_BADNODE)
		return (node);
	return (OBP_NONODE);
}

/*
 * Returning NULL means something went wrong, returning '\0' means no more
 * properties.
 */
static char *
prom_fdt_nextprop(pnode_t nodeid, char *name, char *next)
{
	int offset = fdt_node_offset_by_phandle(prom_fdtp, (pnode_t)nodeid);
	if (offset < 0)
		return (NULL);

	/*
	 * The first time we're called, present the "name" pseudo-property
	 */
	if (name[0] == '\0') {
		strlcpy(next, "name", OBP_MAXPROPNAME);
		return (next);
	}

	/*
	 * The second time we're called, present the "unit-address"
	 * pseudo-property, if appropriate
	 */
	if (strcmp(name, "name") == 0) {
		int len;
		const char *fullname = fdt_get_name(prom_fdtp, offset, &len);

		if (strchr(fullname, '@') != NULL) {
			strlcpy(next, "unit-address", OBP_MAXPROPNAME);
			return (next);
		}

		/* Fall through to get real properties */
	}

	*next = '\0';
	offset = fdt_first_property_offset(prom_fdtp, offset);
	if (offset < 0) {
		return (next);
	}

	const struct fdt_property *data;
	for (;;) {
		data = fdt_get_property_by_offset(prom_fdtp, offset, NULL);
		const char *name0 = fdt_string(prom_fdtp,
		    fdt32_to_cpu(data->nameoff));
		if (name0) {
			/*
			 * If we reach here with name equal to one of our
			 * pseudo-properties, give the first real property.
			 */
			if ((strcmp(name, "name") == 0) ||
			    (strcmp(name, "unit-address") == 0)) {
				strlcpy(next, name0, OBP_MAXPROPNAME);
				return (next);
			}
			if (strcmp(name, name0) == 0)
				break;
		}
		offset = fdt_next_property_offset(prom_fdtp, offset);
		if (offset < 0) {
			return (next);
		}
	}
	offset = fdt_next_property_offset(prom_fdtp, offset);
	if (offset < 0) {
		return (next);
	}
	data = fdt_get_property_by_offset(prom_fdtp, offset, NULL);
	strlcpy(next, (char *)fdt_string(prom_fdtp, fdt32_to_cpu(data->nameoff)),
	    OBP_MAXPROPNAME);
	return (next);
}

static pnode_t
prom_fdt_nextnode(pnode_t nodeid)
{
	if (nodeid == OBP_NONODE)
		return (prom_fdt_rootnode());

	int offset = fdt_node_offset_by_phandle(prom_fdtp, (phandle_t)nodeid);
	if (offset < 0)
		return (OBP_BADNODE);

	int depth = 1;
	for (;;) {
		offset = fdt_next_node(prom_fdtp, offset, &depth);
		if (offset < 0)
			return (OBP_NONODE);
		if (depth == 1)
			break;
	}

	phandle_t phandle = get_phandle(offset);
	if (phandle < 0)
		return (OBP_NONODE);
	return ((pnode_t)phandle);
}

static pnode_t
prom_fdt_childnode(pnode_t nodeid)
{
	if (nodeid == OBP_NONODE)
		return (prom_fdt_rootnode());

	int offset = fdt_node_offset_by_phandle(prom_fdtp, (phandle_t)nodeid);
	if (offset < 0)
		return (OBP_NONODE);

	int depth = 0;
	for (;;) {
		offset = fdt_next_node(prom_fdtp, offset, &depth);
		if (offset < 0)
			return (OBP_NONODE);
		if (depth == 0)
			return (OBP_NONODE);
		if (depth == 1)
			break;
	}
	phandle_t phandle = get_phandle(offset);
	if (phandle < 0)
		return (OBP_NONODE);
	return ((pnode_t)phandle);
}

static char *
prom_fdt_decode_composite_string(void *buf, size_t buflen, char *prev)
{
	if ((buf == 0) || (buflen == 0) || ((int)buflen == -1))
		return (NULL);

	if (prev == 0)
		return (buf);

	prev += strlen(prev) + 1;
	if (prev >= ((char *)buf + buflen))
		return (NULL);
	return (prev);
}

static int
prom_fdt_bounded_getprop(pnode_t nodeid, const char *name, caddr_t value, int len)
{
	int prop_len = prom_fdt_getproplen(nodeid, name);
	if (prop_len < 0 || len < prop_len) {
		return (-1);
	}

	return (prom_fdt_getprop(nodeid, name, value));
}

static pnode_t
prom_fdt_alias_node(void)
{
	return (OBP_BADNODE);
}

/*ARGSUSED*/
static void
prom_fdt_pathname(char *buf)
{
	/* nothing, just to get consconfig_dacf to compile */
}

/* XXX must go */
static pnode_t
prom_fdt_findnode_byname(pnode_t n, char *name)
{
	return (OBP_NONODE);
}

static void
prom_fdt_setup(void)
{
	if (prom_propname_warn == -1)
		prom_propname_warn = 1;
}

/*
 * External interface
 */

const prom_ops_t prom_fdt_ops = {
	/* utility operations */
	.po_setup			= prom_fdt_setup,

	/* node operations */
	.po_rootnode			= prom_fdt_rootnode,
	.po_nextnode			= prom_fdt_nextnode,
	.po_childnode			= prom_fdt_childnode,
	.po_findnode_byname		= prom_fdt_findnode_byname,
	.po_chosennode			= prom_fdt_chosennode,
	.po_optionsnode			= prom_fdt_optionsnode,
	.po_finddevice			= prom_fdt_finddevice,
	.po_alias_node			= prom_fdt_alias_node,
	.po_pathname			= prom_fdt_pathname,

	/* property operations */
	.po_getproplen			= prom_fdt_getproplen,
	.po_getprop			= prom_fdt_getprop,
	.po_nextprop			= prom_fdt_nextprop,
	.po_decode_composite_string	= prom_fdt_decode_composite_string,
	.po_bounded_getprop		= prom_fdt_bounded_getprop,
};

extern const prom_ops_t *prom_ops;

void
prom_init_fdt(void *cookie)
{
	if (cookie && fdt_check_header(cookie) == 0) {
		prom_fdtp = (struct fdt_header *)cookie;
		prom_ops = &prom_fdt_ops;
	}
}

boolean_t
prom_fw_is_fdt(void)
{
	return (prom_fdtp ? B_TRUE : B_FALSE);
}

void *
prom_fdt_get_fdtp(void)
{
	return (prom_fdtp);
}

int
prom_fdt_set_fdtp(void *fdtp)
{
	if (!fdtp) {
		prom_fdtp = NULL;
		return (0);
	}

	if (fdt_check_header(fdtp) != 0)
		return (-1);

	prom_fdtp = (struct fdt_header *)fdtp;
	return (0);
}

/*
 * Externally callable FDT supporting functions.
 *
 * Use of these functions is discouraged.
 */

pnode_t
prom_fdt_findnode_by_phandle(phandle_t phandle)
{
	int offset = fdt_node_offset_by_phandle(prom_fdtp, phandle);
	if (offset < 0)
		return (-1);
	return ((pnode_t)phandle);
}

pnode_t
prom_fdt_parentnode(pnode_t nodeid)
{
	int offset = fdt_node_offset_by_phandle(prom_fdtp, (pnode_t)nodeid);
	if (offset < 0)
		return (OBP_NONODE);

	int parent_offset = fdt_parent_offset(prom_fdtp, offset);
	if (parent_offset < 0)
		return (OBP_NONODE);
	phandle_t phandle = get_phandle(parent_offset);
	if (phandle < 0)
		return (OBP_NONODE);
	return ((pnode_t)phandle);
}

static void
prom_walk_dev(pnode_t nodeid, void(*func)(pnode_t, void*), void *arg)
{
	func(nodeid, arg);

	pnode_t child = prom_fdt_childnode(nodeid);
	while (child > 0) {
		prom_walk_dev(child, func, arg);
		child = prom_fdt_nextnode(child);
	}
}

void
prom_fdt_walk(void(*func)(pnode_t, void*), void *arg)
{
	prom_walk_dev(prom_fdt_rootnode(), func, arg);
}

boolean_t
prom_fdt_node_has_property(pnode_t nodeid, const char *name)
{
	int offset;
	int len;
	const struct fdt_property *prop;

	offset = fdt_node_offset_by_phandle(prom_fdtp, nodeid);
	if (offset < 0)
		return (B_FALSE);

	prop = fdt_get_property(prom_fdtp, offset, name, &len);
	if (prop == NULL)
		return (B_FALSE);

	return (B_TRUE);
}

#if 0
/* XXX: rename to prom_fdt_setprop */
int
prom_fdt_setprop(pnode_t nodeid, const char *name, const caddr_t value, int len)
{
	int offset = fdt_node_offset_by_phandle(prom_fdtp, (pnode_t)nodeid);
	if (offset < 0)
		return (-1);

	/*
	 * The name and unit-address properties are special,
	 * and should never be altered.
	 */
	ASSERT3U(strcmp(name, "name"), !=, 0);
	ASSERT3U(strcmp(name, "unit-address"), !=, 0);

	prom_check_overlong_property(nodeid, name);

	int r = fdt_setprop(prom_fdtp, offset, name, value, len);

	return (r == 0 ? len : -1);
}
#endif

/*
 * So-called PROM utilities, only called from FDT-based code.
 *
 * These shouldn't really be a part of the PROM at all.
 */

static int
prom_fdt_get_prop_index(pnode_t node, const char *prop_name, const char *name)
{
	int len;
	len = prom_getproplen(node, prop_name);
	if (len > 0) {
		char *prop = __builtin_alloca(len);
		prom_getprop(node, prop_name, prop);
		int offset = 0;
		int index = 0;
		while (offset < len) {
			if (strcmp(name, prop + offset) == 0)
				return (index);
			offset += strlen(prop + offset) + 1;
			index++;
		}
	}
	return (-1);
}

int
prom_fdt_get_prop_int(pnode_t node, const char *name, int def)
{
	int value = def;

	while (node > 0) {
		int len = prom_getproplen(node, name);
		if (len == sizeof (int)) {
			int prop;
			prom_getprop(node, name, (caddr_t)&prop);
			value = ntohl(prop);
			break;
		}
		if (len > 0) {
			break;
		}
		node = prom_fdt_parentnode(node);
	}
	return (value);
}

uint64_t
prom_fdt_get_prop_u64(pnode_t node, const char *name, uint64_t def)
{
	uint64_t prop;
	uint64_t value = def;

	if (node > 0 && prom_getproplen(node, name) == sizeof (uint64_t)) {
		prom_getprop(node, name, (caddr_t)&prop);
		value = ntohll(prop);
	}

	return (value);
}

uint32_t
prom_fdt_get_prop_u32(pnode_t node, const char *name, uint32_t def)
{
	uint32_t prop;
	uint32_t value = def;

	if (node > 0 && prom_getproplen(node, name) == sizeof (uint32_t)) {
		prom_getprop(node, name, (caddr_t)&prop);
		value = ntohl(prop);
	}

	return (value);
}

int
prom_fdt_get_clock(pnode_t node, int index, struct prom_hwclock *clock)
{
	int len = prom_getproplen(node, "clocks");
	if (len <= 0)
		return (-1);

	uint32_t *clocks = __builtin_alloca(len);
	prom_getprop(node, "clocks", (caddr_t)clocks);

	pnode_t clock_node;
	clock_node = prom_fdt_findnode_by_phandle(ntohl(clocks[0]));
	if (clock_node < 0)
		return (-1);

	int clock_cells = prom_fdt_get_prop_int(clock_node, "#clock-cells", 1);
	if (clock_cells != 0 && clock_cells != 1)
		return (-1);

	if (len % (CELLS_1275_TO_BYTES(clock_cells + 1)) != 0)
		return (-1);
	if (len <= index * CELLS_1275_TO_BYTES(clock_cells + 1))
		return (-1);

	clock_node =
	    prom_fdt_findnode_by_phandle(ntohl(clocks[index * (clock_cells + 1)]));
	if (clock_node < 0)
		return (-1);
	clock->node = clock_node;
	clock->id = (clock_cells == 0 ? 0:
	    ntohl(clocks[index * (clock_cells + 1) + 1]));

	return (0);
}

int
prom_fdt_get_clock_by_name(pnode_t node,
    const char *name, struct prom_hwclock *clock)
{
	int index = prom_fdt_get_prop_index(node, "clock-names", name);
	if (index >= 0)
		return (prom_fdt_get_clock(node, index, clock));
	return (-1);
}

int
prom_fdt_get_address_cells(pnode_t node)
{
	return (prom_fdt_get_prop_int(prom_fdt_parentnode(node), "#address-cells", 2));
}

int
prom_fdt_get_size_cells(pnode_t node)
{
	return (prom_fdt_get_prop_int(prom_fdt_parentnode(node), "#size-cells", 2));
}

static int
prom_fdt_get_reg_bounds(pnode_t node, int index, uint64_t *base, uint64_t *size)
{
	size_t off;
	int len = prom_getproplen(node, "reg");
	if (len <= 0)
		return (-1);

	uint32_t *regs = __builtin_alloca(len);
	prom_getprop(node, "reg", (caddr_t)regs);

	int address_cells = prom_fdt_get_address_cells(node);
	int size_cells = prom_fdt_get_size_cells(node);

	if (CELLS_1275_TO_BYTES((address_cells + size_cells) *
	    index + address_cells + size_cells) > len) {
		return (-1);
	}

	if (address_cells < 1 || address_cells > 2 ||
	    size_cells < 1 || size_cells > 2)
		return (-1);

	off = (address_cells + size_cells) * index;
	switch (address_cells) {
	case 1:
		*base = ntohl(regs[off]);
		break;
	case 2:
		*base = ntohl(regs[off]);
		*base <<= 32;
		*base |= ntohl(regs[off + 1]);
		break;
	default:
		return (-1);
	}

	off += address_cells;
	switch (size_cells) {
	case 1:
		*size = ntohl(regs[off]);
		break;
	case 2:
		*size = ntohl(regs[off]);
		*size <<= 32;
		*size |= ntohl(regs[off + 1]);
		break;
	default:
		return (-1);
	}

	return (0);
}

int
prom_fdt_get_reg(pnode_t node, int index, uint64_t *base)
{
	uint64_t size;
	return (prom_fdt_get_reg_bounds(node, index, base, &size));
}

int
prom_fdt_get_reg_size(pnode_t node, int index, uint64_t *size)
{
	uint64_t base;
	return (prom_fdt_get_reg_bounds(node, index, &base, size));
}

int
prom_fdt_get_reg_address(pnode_t node, int index, uint64_t *reg)
{
	uint64_t addr;
	if (prom_fdt_get_reg(node, index, &addr) != 0)
		return (-1);

	pnode_t parent = prom_fdt_parentnode(node);
	while (parent > 0) {
		if (!prom_fdt_is_compatible(parent, "simple-bus")) {
			parent = prom_fdt_parentnode(parent);
			continue;
		}

		int len = prom_getproplen(parent, "ranges");
		if (len <= 0) {
			parent = prom_fdt_parentnode(parent);
			continue;
		}

		int address_cells =
		    prom_fdt_get_prop_int(parent, "#address-cells", 2);
		int size_cells = prom_fdt_get_prop_int(parent, "#size-cells", 2);
		int parent_address_cells = prom_fdt_get_prop_int(
		    prom_fdt_parentnode(parent), "#address-cells", 2);

		if ((len % CELLS_1275_TO_BYTES(address_cells +
		    parent_address_cells + size_cells)) != 0) {
			parent = prom_fdt_parentnode(parent);
			continue;
		}

		uint32_t *ranges = __builtin_alloca(len);
		prom_getprop(parent, "ranges", (caddr_t)ranges);
		int ranges_cells =
		    (address_cells + parent_address_cells + size_cells);

		for (int i = 0;
		    i < len / CELLS_1275_TO_BYTES(ranges_cells); i++) {
			uint64_t base = 0;
			uint64_t target = 0;
			uint64_t size = 0;
			for (int j = 0; j < address_cells; j++) {
				base <<= 32;
				base += ntohl(ranges[ranges_cells * i + j]);
			}
			for (int j = 0; j < parent_address_cells; j++) {
				target <<= 32;
				target += ntohl(ranges[
				    ranges_cells * i + address_cells + j]);
			}
			for (int j = 0; j < size_cells; j++) {
				size <<= 32;
				size += ntohl(ranges[
				    ranges_cells * i + address_cells +
				    parent_address_cells + j]);
			}

			if (base <= addr && addr <= base + size - 1) {
				addr = (addr - base) + target;
				break;
			}
		}

		parent = prom_fdt_parentnode(parent);
	}

	*reg = addr;
	return (0);
}

boolean_t
prom_fdt_is_compatible(pnode_t node, const char *name)
{
	int len;
	char *prop_name = "compatible";
	len = prom_getproplen(node, prop_name);
	if (len <= 0)
		return (B_FALSE);

	char *prop = __builtin_alloca(len);
	prom_getprop(node, prop_name, prop);

	int offset = 0;
	while (offset < len) {
		if (strcmp(name, prop + offset) == 0)
			return (B_TRUE);
		offset += strlen(prop + offset) + 1;
	}
	return (B_FALSE);
}

pnode_t
prom_fdt_find_compatible(pnode_t node, const char *compatible)
{
	pnode_t child;

	if (prom_fdt_is_compatible(node, compatible))
		return (node);

	child = prom_childnode(node);

	while (child > 0) {
		node = prom_fdt_find_compatible(child, compatible);
		if (node > 0)
			return (node);

		child = prom_nextnode(child);
	}

	return (OBP_NONODE);
}

boolean_t
prom_fdt_has_compatible(const char *compatible)
{
	pnode_t node;

	node = prom_fdt_find_compatible(prom_rootnode(), compatible);

	if (node == OBP_NONODE)
		return (B_FALSE);

	return (B_TRUE);
}
