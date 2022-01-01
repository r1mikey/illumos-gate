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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2017 Hayashi Naoyuki
 */

#include <sys/sysmacros.h>
#include <sys/byteorder.h>
#include <sys/of_utils.h>
#include <sys/systm.h>

static int
of_get_prop_index(pnode_t node, const char *prop_name, const char *name)
{
	int len;
	len = prom_getproplen(node, prop_name);
	if (len > 0) {
		char *prop = __builtin_alloca(len);
		prom_getprop(node, prop_name, prop);
		int offeset = 0;
		int index = 0;
		while (offeset < len) {
			if (strcmp(name, prop + offeset) == 0)
				return index;
			offeset += strlen(prop + offeset) + 1;
			index++;
		}
	}
	return -1;
}

int
of_get_prop_int(pnode_t node, const char *name, int def)
{
	int value = def;

	while (node > 0) {
		int len = prom_getproplen(node, name);
		if (len == sizeof(int)) {
			int prop;
			prom_getprop(node, name, (caddr_t)&prop);
			value = ntohl(prop);
			break;
		}
		if (len > 0) {
			break;
		}
		node = prom_parentnode(node);
	}
	return value;
}

int of_get_reset(pnode_t node, int index, struct of_reset *reset)
{
	int len = prom_getproplen(node, "resets");
	if (len <= 0)
		return -1;

	uint32_t *resets = __builtin_alloca(len);
	prom_getprop(node, "resets", (caddr_t)resets);

	pnode_t reset_node;
	reset_node = prom_findnode_by_phandle(htonl(resets[0]));
	if (reset_node < 0)
		return -1;

	int reset_cells = of_get_prop_int(reset_node, "#reset-cells", 1);
	if (reset_cells != 1)
		return -1;

	if ((len % (sizeof(uint32_t) * (reset_cells + 1))) != 0)
		return -1;
	if (len >= index * (sizeof(uint32_t) * (reset_cells + 1)))
		return -1;

	reset_node = prom_findnode_by_phandle(htonl(resets[index * (reset_cells + 1)]));
	if (reset_node < 0)
		return -1;
	reset->node = reset_node;
	reset->id = htonl(resets[index * (reset_cells + 1) + 1]);

	return 0;
}

int of_get_reset_by_name(pnode_t node, const char *name, struct of_reset *reset)
{
	int index = of_get_prop_index(node, "reset-names", name);
	if (index >= 0)
		return of_get_reset(node, index, reset);
	return -1;
}

int of_get_clock(pnode_t node, int index, struct of_clock *clock)
{
	int len = prom_getproplen(node, "clocks");
	if (len <= 0)
		return -1;

	uint32_t *clocks = __builtin_alloca(len);
	prom_getprop(node, "clocks", (caddr_t)clocks);

	pnode_t clock_node;
	clock_node = prom_findnode_by_phandle(htonl(clocks[0]));
	if (clock_node < 0)
		return -1;

	int clock_cells = of_get_prop_int(clock_node, "#clock-cells", 1);
	if (clock_cells != 1)
		return -1;

	if ((len % (sizeof(uint32_t) * (clock_cells + 1))) != 0)
		return -1;
	if (len >= index * (sizeof(uint32_t) * (clock_cells + 1)))
		return -1;

	clock_node = prom_findnode_by_phandle(htonl(clocks[index * (clock_cells + 1)]));
	if (clock_node < 0)
		return -1;
	clock->node = clock_node;
	clock->id = htonl(clocks[index * (clock_cells + 1) + 1]);

	return 0;
}

int of_get_clock_by_name(pnode_t node, const char *name, struct of_clock *clock)
{
	int index = of_get_prop_index(node, "clock-names", name);
	if (index >= 0)
		return of_get_clock(node, index, clock);
	return -1;
}

int of_get_address_cells(pnode_t node)
{
	return of_get_prop_int(prom_parentnode(node), "#address-cells", 2);
}

int of_get_size_cells(pnode_t node)
{
	return of_get_prop_int(prom_parentnode(node), "#size-cells", 2);
}

int of_get_reg(pnode_t node, int index, uint64_t *base)
{
	int len = prom_getproplen(node, "reg");
	if (len <= 0)
		return -1;

	uint32_t *regs = __builtin_alloca(len);
	prom_getprop(node, "reg", (caddr_t)regs);

	int address_cells = of_get_address_cells(node);
	int size_cells = of_get_size_cells(node);

	if (((address_cells + size_cells) * index + address_cells) * sizeof(uint32_t) > len)
		return -1;

	switch (address_cells) {
	case 1:
		*base = htonl(regs[(address_cells + size_cells) * index]);
		break;
	case 2:
		*base = htonl(regs[(address_cells + size_cells) * index]);
		*base <<= 32;
		*base |= htonl(regs[(address_cells + size_cells) * index + 1]);
		break;
	default:
		return -1;
	}

	return 0;
}

int of_get_reg_by_name(pnode_t node, const char *name, uint64_t *base)
{
	int index = of_get_prop_index(node, "reg-names", name);

	if (index >= 0)
		return of_get_reg(node, index, base);
	return -1;
}

bool of_is_compatible(pnode_t node, const char *name)
{
	int len;
	char *prop_name = "compatible";
	len = prom_getproplen(node, prop_name);
	if (len <= 0)
		return false;

	char *prop = __builtin_alloca(len);
	prom_getprop(node, prop_name, prop);

	int offeset = 0;
	while (offeset < len) {
		if (strcmp(name, prop + offeset) == 0)
			return true;
		offeset += strlen(prop + offeset) + 1;
	}
	return false;
}

static void
of_register_child(pnode_t node, const struct of_compat *data)
{
	const struct of_compat *tmp = data;
	while (tmp->compatible) {
		if (of_is_compatible(node, tmp->compatible)) {
			tmp->init(node);
		}
		tmp++;
	}

	pnode_t child = prom_childnode(node);
	while (child > 0) {
		of_register_child(child, data);
		child = prom_nextnode(child);
	}
}

void
of_register(const struct of_compat *data)
{
	of_register_child(prom_rootnode(), data);
}

