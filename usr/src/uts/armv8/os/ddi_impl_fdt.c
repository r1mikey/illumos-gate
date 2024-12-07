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
#include <sys/esunddi.h>
#include <sys/mach_intr.h>
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

/*
 * XXXPCI: Hackery
 */

/*
 * Return the device node that claims ownership of this interrupt domain
 * following "interrupt-parent" as necessary.
 *
 * In practical terms, this is the node with the "#interrupt-cells" which
 * applies to `pdip`.  This may be `pdip` itself.
 *
 * As I read the 1275 PCI bindings, I believe we don't need to handle
 * "interrupt-map" here, because we should always have an "#interrupt-cells"
 * on that same node.
 */
dev_info_t *
i_ddi_interrupt_domain(dev_info_t *pdip)
{
	dev_info_t *ret = NULL;
	dev_info_t *p = pdip;

	while (p != NULL) {
		phandle_t phandle;

		/* If we have "#interrupt-cells", we're what we want */
		if (ddi_prop_exists(DDI_DEV_T_ANY, p, DDI_PROP_DONTPASS,
		    "#interrupt-cells") != 0) {
			ret = p;
			break;
		}

		/* If not, if there's an interrupt-parent follow it */
		if ((phandle = ddi_prop_get_int(DDI_DEV_T_ANY, p,
		    DDI_PROP_DONTPASS, "interrupt-parent", -1)) != -1) {
			p = e_ddi_nodeid_to_dip(phandle);
			VERIFY3P(p, !=, NULL);
			continue;
		}

		/* If that didn't work, follow the tree itself */
		p = ddi_get_parent(p);
	}

	return (ret);
}

/*
 * i_ddi_get_interrupt - Get the interrupt property from the specified device
 * for a given interrupt. Note that this function is called only for the FIXED
 * interrupt type.
 *
 * NB: i_ddi_get_inum returns a single uint32_t, which is insufficient to
 * fully describe an interrupt.  We are returning the full interrupt
 * descriptor, plus the length of the vector (for the purpose of freeing it).
 */
size_t
i_ddi_get_interrupt(dev_info_t *dip, uint_t inumber, int **ret)
{
	int32_t		max_intrs;
	int		*ip;
	uint_t		ip_sz;
	uint32_t	intr = 0;

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "interrupts", &ip, &ip_sz) == DDI_SUCCESS) {
		dev_info_t *id = i_ddi_interrupt_domain(dip);

		VERIFY3P(id, !=, NULL);

		int intr_cells = ddi_prop_get_int(DDI_DEV_T_ANY, id, 0,
		    "#interrupt-cells", 1);

		if (inumber >= ip_sz / intr_cells) {
			return (0);	/* failure */
		}

		int *intrp = ip + (inumber * intr_cells);

		*ret = kmem_zalloc(CELLS_1275_TO_BYTES(intr_cells),
		    KM_SLEEP);
		memcpy(*ret, intrp, CELLS_1275_TO_BYTES(intr_cells));

		ddi_prop_free(ip);
		return (intr_cells);
	}

	return (0);
}


/*
 * i_ddi_get_inum - Get the interrupt number property from the
 * specified device. Note that this function is called only for
 * the FIXED interrupt type.
 */
uint32_t
i_ddi_get_inum(dev_info_t *dip, uint_t inumber)
{
	int32_t		max_intrs;
	int		*ip;
	uint_t		ip_sz;
	uint32_t	intr = 0;
	size_t		intr_cells;

	intr_cells = i_ddi_get_interrupt(dip, inumber, &ip);

	switch (intr_cells) {
	case 0:
		intr = 0;
		break;
	case 1:
		intr = *ip;
		break;
	case 3:
		intr = *(ip + 1);
		break;
	default:
		dev_err(dip, CE_PANIC, "unknown #interrupt-cells: %zd",
		    intr_cells);
		return (0);	/* Unreachable */
	}

	/*
	 * XXXPCI: I hate this, it's weird now we have to handle 0.  We should
	 * stop handling 0 and fix the virtio nodes.
	 */
	if (intr_cells > 0)
		kmem_free(ip, CELLS_1275_TO_BYTES(intr_cells));
	return (intr);
}

/*
 * i_ddi_get_intr_pri - Get the interrupt-priorities property from
 * the specified device. Note that this function is called only for
 * the FIXED interrupt type.
 */
uint32_t
i_ddi_get_intr_pri(dev_info_t *dip, uint_t inumber)
{
	int		*intr_prio_p;
	uint_t		intr_prio_num;
	uint32_t	pri = 0;

	/*
	 * Use the "interrupt-priorities" property to determine the
	 * the pil/ipl for the interrupt handler.
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "interrupt-priorities", &intr_prio_p,
	    &intr_prio_num) == DDI_SUCCESS) {
		if (inumber < intr_prio_num)
			pri = intr_prio_p[inumber];
		ddi_prop_free(intr_prio_p);
	}

	return (pri);	/* XXXARM: should be 5 when not found? */
}

/*
 * Pull a unitaddress for dip from reg[0], and put it in *out.
 * Returns the actual number of address cells, or -1 on failure.
 */
static int
i_ddi_unitaddr(dev_info_t *dip, uint_t *out, size_t out_cells)
{
	int *reg;
	uint_t reg_cells;

	int addr_cells = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "#address-cells", 2);

	if (addr_cells == 0)
		return (0);

	if (addr_cells > out_cells)
		return (-1);

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", &reg, &reg_cells) != DDI_SUCCESS) {
		dev_err(dip, CE_PANIC,
		    "Mapping interrupts on device with no registers");
		return (-1);	/* Unreachable */
	}

	memcpy(out, reg, CELLS_1275_TO_BYTES(out_cells));
	ddi_prop_free(reg);
	return (addr_cells);
}

typedef struct {
	size_t		ui_nelems;	/* Number of elements in ui_v */
	uint32_t	ui_v[];	/* unit/interrupt descriptor */
} unit_intr_t;

static unit_intr_t *
i_ddi_unitintr(dev_info_t *dip, uint_t inum)
{
	unit_intr_t *ui;
	int addr_cells = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "#address-cells", 2);

	int *intrs = NULL;
	int intr_cells = i_ddi_get_interrupt(dip, inum, &intrs);

	if (intr_cells == 0) {
		dev_err(dip, CE_PANIC,
		    "Mapping interrupts on device with no interrupts?");
		return (NULL);
	}

	ui = kmem_zalloc(sizeof (*ui) +
	    CELLS_1275_TO_BYTES(addr_cells + intr_cells), KM_SLEEP);
	ui->ui_nelems = addr_cells + intr_cells;

	if (i_ddi_unitaddr(dip, ui->ui_v, addr_cells) != addr_cells) {
		dev_err(dip, CE_PANIC, "couldn't interpret unit address");
		return (NULL);	/* Unreachable */
	}

	memcpy(ui->ui_v + addr_cells, intrs, CELLS_1275_TO_BYTES(intr_cells));
	kmem_free(intrs, CELLS_1275_TO_BYTES(intr_cells));

	return (ui);
}

static dev_info_t *
map_interrupt_core(dev_info_t *dip, unit_intr_t **ui)
{
	if (ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "interrupt-controller") != 0) {
		phandle_t ip = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "interrupt-parent", -1);

		/*
		 * In the algorithm presented in the spec we would
		 * build a unitintr based on our "reg"[0] and
		 * "interrupts"[intr] and continue our search to the
		 * top.  We stop at every interrupt controller to
		 * allow for their programming and allow them to then
		 * pass things on up the tree as appropriate.
		 *
		 * XXXPCI: In theory, anyway.  I don't have an
		 * environment with cascaded controllers.
		 */
		if (ip != -1) {
			return (e_ddi_nodeid_to_dip(ip));
		} else {
			/* interrupt-controller with no parent, done */
			return (dip);
		}
	} else {
		int *intr_map, *intr_mask;
		uint_t intr_map_sz, intr_mask_sz;

		/* Not an interrupt controller, check the interrupt-map */
		if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "interrupt-map", &intr_map,
		    &intr_map_sz) == DDI_SUCCESS) {
			if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
			    DDI_PROP_DONTPASS, "interrupt-map-mask", &intr_mask,
			    &intr_mask_sz) != DDI_SUCCESS) {
				intr_mask_sz = 0;
			}

			/*
			 * By definition, if we have an interrupt-map we're the
			 * interrupt domain
			 */
			ASSERT3P(i_ddi_interrupt_domain(dip), ==, dip);

			int intr_cells = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
			    DDI_PROP_DONTPASS, "#interrupt-cells", 1);

			VERIFY((intr_mask_sz == (*ui)->ui_nelems) ||
			    (intr_mask_sz == 0));

			/* Apply the mask if we have one */
			for (int i = 0; i < intr_mask_sz; i++) {
				(*ui)->ui_v[i] &= intr_mask[i];
			}

			int unitintr_cells = (*ui)->ui_nelems;

			/*
			 * The effective stride through the table, the width
			 * of the row we're reading as we're reading it.
			 */
			int effective_stride = 0;
			for (int *scan = intr_map;
			    scan < intr_map + intr_map_sz;
			    scan += effective_stride) {
				dev_info_t *parent;

				/*
				 * Our stride is at least as far as our own
				 * unit-interrupt specifier plus the parent
				 * phandle.
				 */
				effective_stride = unitintr_cells + 1;

				parent = e_ddi_nodeid_to_dip(scan[effective_stride - 1]);
				VERIFY3P(parent, !=, NULL);

				int par_addr_cells = ddi_prop_get_int(
				    DDI_DEV_T_ANY, parent, 0,
				    "#address-cells", 2);
				int par_intr_cells = ddi_prop_get_int(
				    DDI_DEV_T_ANY, parent, 0,
				    "#interrupt-cells", 1);

				if (memcmp((*ui)->ui_v, scan,
				    CELLS_1275_TO_BYTES((*ui)->ui_nelems)) ==
				    0) {
					int nelems =
					    par_addr_cells + par_intr_cells;

					kmem_free(*ui, sizeof (**ui) +
					    CELLS_1275_TO_BYTES(
					    (*ui)->ui_nelems));
					*ui = kmem_zalloc(sizeof (**ui) +
					    CELLS_1275_TO_BYTES(nelems),
					    KM_SLEEP);
					(*ui)->ui_nelems = nelems;
					memcpy((*ui)->ui_v,
					    scan + effective_stride,
					    CELLS_1275_TO_BYTES(
					    (*ui)->ui_nelems));

					ddi_prop_free(intr_map);
					if (intr_mask != NULL)
						ddi_prop_free(intr_mask);
					return (parent);
				}

				effective_stride += par_addr_cells + par_intr_cells;
			}

			ddi_prop_free(intr_map);
			if (intr_mask != NULL)
				ddi_prop_free(intr_mask);
		}

		/*
		 * It may feel like the size here could not possibly change,
		 * because if it did then this would require an
		 * "interrupt-map", but that's not true, it's entirely
		 * possible for "#address-cells" to change.
		 */
		int intr_cells = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
		    "#interrupt-cells", 1);
		int addr_cells = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
		    "#address-cells", 2);

		if ((intr_cells + addr_cells) == (*ui)->ui_nelems) {
			/* Same size, just overwrite the unit address */
			if (i_ddi_unitaddr(dip, (*ui)->ui_v, addr_cells) !=
			    addr_cells) {
				dev_err(dip, CE_PANIC,
				    "couldn't interpret unit address");
				return (NULL);	/* Unreachable */
			}
		} else {
			/* Different size, we need a replacement */
			unit_intr_t *nu = kmem_zalloc(sizeof (*nu) +
			    CELLS_1275_TO_BYTES(intr_cells + addr_cells),
			    KM_SLEEP);

			if (i_ddi_unitaddr(dip, nu->ui_v, addr_cells) !=
			    addr_cells) {
				dev_err(dip, CE_PANIC,
				    "couldn't interpret unit address");
				return (NULL);	/* Unreachable */
			}

			/*
			 * Use the same interrupt specifier as before.  Note
			 * that we're careful not to use "addr_cells", as that
			 * refers to the wrong node.
			 */
			memcpy(nu->ui_v + addr_cells, (*ui)->ui_v +
			    ((*ui)->ui_nelems - intr_cells), intr_cells);
			kmem_free(*ui, CELLS_1275_TO_BYTES((*ui)->ui_nelems));
			*ui = nu;
		}

		phandle_t ip = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "interrupt-parent", -1);
		if (ip != -1) {
			return (map_interrupt_core(
			    e_ddi_nodeid_to_dip(ip), ui));
		}

		return (map_interrupt_core(ddi_get_parent(dip), ui));
	}

	ASSERT(0 && "Unreachable!");
	return ((dev_info_t *)-1);	/* That dip is PoOOiiiSoooOOOoon */
}

dev_info_t *
map_interrupt(dev_info_t *dip, ddi_intr_handle_impl_t *hdlp)
{
	unit_intr_t *ui = i_ddi_unitintr(dip, hdlp->ih_inum);

	VERIFY3P(ui, !=, NULL);

	dev_info_t *par = map_interrupt_core(dip, &ui);

	/*
	 * XXXPCI: Doing this via the private data in the hdl, v. just
	 * returning it, is bullshit.
	 */
	ihdl_plat_t *priv = (ihdl_plat_t *)hdlp->ih_private;
	VERIFY3P(priv, !=, NULL);

	int addr_cells = ddi_prop_get_int(DDI_DEV_T_ANY, par, 0,
	    "#address-cells", 2);	/* XXXPCI: default? */
	int intr_cells = ddi_prop_get_int(DDI_DEV_T_ANY, par, 0,
	    "#interrupt-cells", 1);	/* XXXPCI: default? */

	VERIFY3S(ui->ui_nelems, ==, addr_cells + intr_cells);

	/*
	 * XXXPCI: What would a non-0 unit address at the top of the tree
	 * _mean_?
	 *
	 * This should let us catch one if we find one in the wild, and
	 * actively choose whether to ignore it or what.
	 */
	for (int i = 0; i < addr_cells; i++) {
		VERIFY3S(ui->ui_v[i], ==, 0);
	}

	/*
	 * XXXPCI: Actually, this is specific to the device in `par`, we just
	 * assume we know what to do.  Another case where we should check
	 * "compatible" or, ideally, architect interrupts properly.
	 */
	VERIFY3S(intr_cells, ==, 3);

	priv->ip_gic_cfg = ui->ui_v[addr_cells + 0];
	priv->ip_gic_sense = ui->ui_v[addr_cells + 2];
	hdlp->ih_vector = ui->ui_v[addr_cells + 1];

	kmem_free(ui, sizeof (*ui) +
	    CELLS_1275_TO_BYTES(ui->ui_nelems));

	return (par);
}
