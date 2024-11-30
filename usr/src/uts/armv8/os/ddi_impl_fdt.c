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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2012 Garrett D'Amore <garrett@damore.org>
 * Copyright 2014 Pluribus Networks, Inc.
 * Copyright 2016 Nexenta Systems, Inc.
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2018 Joyent, Inc.
 * Copyright 2024 Michael van der Westhuizen
 */

/*
 * aarch64-specific DDI implementation, FDT-based machine routines.
 */
#include <sys/types.h>
#include <sys/null.h>
#include <sys/sunddi.h>
#include <sys/promif.h>

/*
 * Platform drivers on this platform
 */
char *platform_module_list[] = { NULL };

int
i_ddi_get_intx_nintrs(dev_info_t *dip)
{
	uint_t intrlen;
	int intr_sz;
	int *ip;
	int ret = 0;

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS |
	    DDI_PROP_CANSLEEP,
	    "interrupts", &ip, &intrlen) == DDI_SUCCESS) {
		intr_sz = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		    0, "#interrupt-cells", 1);

		intr_sz = CELLS_1275_TO_BYTES(intr_sz);
		ret = intrlen / intr_sz;

		ddi_prop_free(ip);
	}

	return (ret);
}

void
make_ddi_ppd(dev_info_t *child __unused, struct ddi_parent_private_data **ppd)
{
	struct ddi_parent_private_data *pdptr;
	pdptr = kmem_zalloc(sizeof (*pdptr), KM_SLEEP);
	*ppd = pdptr;
}

int
impl_sunbus_name_child(dev_info_t *child, char *name, int namelen)
{
	/*
	 * Fill in parent-private data and this function returns to us
	 * an indication if it used "registers" to fill in the data.
	 */
	if (ddi_get_parent_data(child) == NULL) {
		struct ddi_parent_private_data *pdptr;
		make_ddi_ppd(child, &pdptr);
		ddi_set_parent_data(child, pdptr);
	}

	name[0] = '\0';
	pnode_t node = ddi_get_nodeid(child);
	if (node > 0) {
		char buf[MAXNAMELEN] = {0};
		int len = prom_getproplen(node, "unit-address");
		if (0 < len && len < MAXNAMELEN) {
			prom_getprop(node, "unit-address", buf);
			if (strlen(buf) < namelen)
				strcpy(name, buf);
		}
	}

	return (DDI_SUCCESS);
}

static int
get_address_cells(pnode_t node)
{
	int address_cells = 0;

	while (node > 0) {
		int len = prom_getproplen(node, "#address-cells");
		if (len > 0) {
			ASSERT(len == sizeof (int));
			int prop;
			prom_getprop(node, "#address-cells", (caddr_t)&prop);
			address_cells = ntohl(prop);
			break;
		}
		node = prom_fdt_parentnode(node);
	}
	return (address_cells);
}

static int
get_size_cells(pnode_t node)
{
	int size_cells = 0;

	while (node > 0) {
		int len = prom_getproplen(node, "#size-cells");
		if (len > 0) {
			ASSERT(len == sizeof (int));
			int prop;
			prom_getprop(node, "#size-cells", (caddr_t)&prop);
			size_cells = ntohl(prop);
			break;
		}
		node = prom_fdt_parentnode(node);
	}
	return (size_cells);
}

struct dma_range
{
	uint64_t cpu_addr;
	uint64_t bus_addr;
	size_t size;
};

static int
get_dma_ranges(dev_info_t *dip, struct dma_range **range, int *nrange)
{
	int dma_range_num = 0;
	struct dma_range *dma_ranges = NULL;
	boolean_t *update = NULL;
	int ret = DDI_SUCCESS;

	if (dip == NULL)
		goto err_exit;

	for (;;) {
		dip = ddi_get_parent(dip);
		if (dip == NULL)
			break;
		pnode_t node = ddi_get_nodeid(dip);
		if (node <= 0)
			break;
		if (prom_getproplen(node, "dma-ranges") <= 0)
			continue;

		int bus_address_cells;
		int bus_size_cells;
		int parent_address_cells;
		pnode_t parent;

		parent = prom_fdt_parentnode(node);
		if (parent <= 0) {
			cmn_err(CE_WARN,
			    "%s: root node has a dma-ranges property.",
			    __func__);
			goto err_exit;
		}

		bus_address_cells = get_address_cells(node);
		bus_size_cells = get_size_cells(node);
		parent_address_cells = get_address_cells(parent);

		int len = prom_getproplen(node, "dma-ranges");
		if (len % CELLS_1275_TO_BYTES(bus_address_cells +
		    parent_address_cells + bus_size_cells) != 0) {
			cmn_err(CE_WARN,
			    "%s: dma-ranges property length is invalid\n"
			    "bus_address_cells %d\n"
			    "parent_address_cells %d\n"
			    "bus_size_cells %d\n"
			    "len %d\n",
			    __func__, bus_address_cells, parent_address_cells,
			    bus_size_cells, len);
			ret = DDI_FAILURE;
			goto err_exit;
		}
		int num = len / CELLS_1275_TO_BYTES(bus_address_cells +
		    parent_address_cells + bus_size_cells);
		uint32_t *cells = __builtin_alloca(len);
		prom_getprop(node, "dma-ranges", (caddr_t)cells);

		boolean_t first = (dma_ranges == NULL);
		if (first) {
			dma_range_num = num;
			dma_ranges = kmem_zalloc(
			    sizeof (struct dma_range) * dma_range_num,
			    KM_SLEEP);
			update = kmem_zalloc(
			    sizeof (boolean_t) * dma_range_num, KM_SLEEP);
		} else {
			memset(update, 0, sizeof (boolean_t) * dma_range_num);
		}

		for (int i = 0; i < num; i++) {
			uint64_t bus_address = 0;
			uint64_t parent_address = 0;
			uint64_t bus_size = 0;
			for (int j = 0; j < bus_address_cells; j++) {
				bus_address <<= 32;
				bus_address += ntohl(cells[(
				    bus_address_cells + parent_address_cells +
				    bus_size_cells) * i + j]);
			}
			for (int j = 0; j < parent_address_cells; j++) {
				parent_address <<= 32;
				parent_address += ntohl(
				    cells[(bus_address_cells +
				    parent_address_cells + bus_size_cells) *
				    i + bus_address_cells + j]);
			}
			for (int j = 0; j < bus_size_cells; j++) {
				bus_size <<= 32;
				bus_size += ntohl(cells[(bus_address_cells +
				    parent_address_cells + bus_size_cells) *
				    i + bus_address_cells +
				    parent_address_cells + j]);
			}

			if (first) {
				dma_ranges[i].cpu_addr = parent_address;
				dma_ranges[i].bus_addr = bus_address;
				dma_ranges[i].size = bus_size;
				update[i] = B_TRUE;
			} else {
				for (int j = 0; j < dma_range_num; j++) {
					if (bus_address <=
					    dma_ranges[j].cpu_addr &&
					    dma_ranges[j].cpu_addr +
					    dma_ranges[j].size - 1 <=
					    bus_address + bus_size - 1) {
						dma_ranges[j].cpu_addr +=
						    (parent_address -
						    bus_address);
						update[j] = B_TRUE;
						break;
					}
				}
			}
		}
		for (int i = 0; i < dma_range_num; i++) {
			if (!update[i]) {
				cmn_err(CE_WARN,
				    "%s: dma-ranges property is invalid",
				    __func__);
				ret = DDI_FAILURE;
				goto err_exit;
			}
		}
	}

	*nrange = dma_range_num;
	*range = dma_ranges;
err_exit:
	if (ret != DDI_SUCCESS && dma_ranges) {
		kmem_free(
		    dma_ranges, sizeof (struct dma_range) * dma_range_num);
	}
	if (update) {
		kmem_free(update, sizeof (boolean_t) * dma_range_num);
	}
	return (ret);
}

int
i_ddi_convert_dma_attr(
    ddi_dma_attr_t *dst, dev_info_t *dip, const ddi_dma_attr_t *src)
{
	*dst = *src;

	int dma_range_num = 0;
	struct dma_range *dma_ranges = NULL;
	int ret = get_dma_ranges(dip, &dma_ranges, &dma_range_num);
	if (ret != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (dma_range_num > 0) {
		int i;
		for (i = 0; i < dma_range_num; i++) {
			if (dma_ranges[i].bus_addr <= dst->dma_attr_addr_lo &&
			    dst->dma_attr_addr_hi <=
			    dma_ranges[i].bus_addr + dma_ranges[i].size - 1) {
				dst->dma_attr_addr_lo +=
				    (dma_ranges[i].cpu_addr -
				    dma_ranges[i].bus_addr);
				dst->dma_attr_addr_hi +=
				    (dma_ranges[i].cpu_addr -
				    dma_ranges[i].bus_addr);
				break;
			}
		}
		if (i == dma_range_num) {
			cmn_err(CE_WARN,
			    "%s: ddi_dma_attr_t is invalid range", __func__);
			ret = DDI_FAILURE;
		}
	}

	if (dma_ranges) {
		kmem_free(
		    dma_ranges, sizeof (struct dma_range) * dma_range_num);
	}
	return (ret);
}

int
i_ddi_update_dma_attr(dev_info_t *dip, ddi_dma_attr_t *attr)
{
	int dma_range_num = 0;
	struct dma_range *dma_ranges = NULL;
	int ret = get_dma_ranges(dip, &dma_ranges, &dma_range_num);
	if (ret != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (dma_range_num > 0) {
		int dma_range_index = 0;
		for (int i = 0; i < dma_range_num; i++) {
			if (dma_ranges[i].cpu_addr <
			    dma_ranges[dma_range_index].cpu_addr) {
				dma_range_index = i;
			}
		}

		attr->dma_attr_addr_lo = dma_ranges[dma_range_index].bus_addr;
		attr->dma_attr_addr_hi =
		    dma_ranges[dma_range_index].bus_addr +
		    dma_ranges[dma_range_index].size - 1;
	} else {
		ret = DDI_FAILURE;
	}

	if (dma_ranges) {
		kmem_free(
		    dma_ranges, sizeof (struct dma_range) * dma_range_num);
	}

	return (ret);
}

void
configure(void)
{
	extern void i_ddi_init_root();

	i_ddi_init_root();
	i_ddi_attach_hw_nodes("dld");
}
