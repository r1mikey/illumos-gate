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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2019 Joyent, Inc.
 * Copyright 2019 Western Digital Corporation
 * Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
 * Copyright 2024 Oxide Computer Company
 */

/*
 * PCI bus enumeration and device programming are done in several passes. The
 * following is a high level overview of this process.
 *
 * pci_enumerate()
 *				The main entry point to PCI bus enumeration.
 *   pci_setup_tree()
 *	enumerate_bus_devs(CONFIG_INFO)		[recursive]
 *	    <foreach dev/func on bus>
 *	        process_devfunc(CONFIG_INFO)
 *	            <set up most device properties>
 *				Enumerate the bus and set up the bulk of the
 *				properties for each device.
 *		    <if PPB device>
 *			add_ppb_props()
 *				For a PCI-to-PCI bridge (ppb) device, firmware
 *				memory ranges for IO, memory or pre-fetchable
 *				memory are retrieved and recorded for the
 *				initial 'ranges' property.  These are
 *				informational only -- all bridges are
 *				reprogrammed from scratch.
 *			enumerate_bus_devs(CONFIG_INFO)	[recurse into secbus]
 *		    <add to list of devices for the bus>
 *		    add_reg_props(CONFIG_INFO)
 *				Record BAR sizes in mem_size/io_size/pmem_size.
 *	    <accumulate bus requirements on unwind>
 *				Bottom-up: compute per-bus mem_required,
 *				io_required, pmem_required, num_hp_bridges
 *				from local BAR sizes + child bridge needs.
 *
 *   pci_reprogram()
 *	<foreach ROOT bus>
 *	    populate_bus_res()
 *				Seed RC busra resource maps from
 *				the RC's "ranges" and "bus-range" properties.
 *	    allocate_all_bridges()
 *				Compute global per-hotplug-bridge spare, then
 *				recursively allocate bridge windows and
 *				reprogram device BARs in a single pass.
 *				For each bus (root or behind a bridge):
 *		    reprogram_bus_devs()
 *				Drain the devlist, assigning device BARs via
 *				ndi_ra_alloc() from the bus dip's busra map.
 *		    allocate_bridge_resources()	[recurse into children]
 *				Program bridge window, seed child busra,
 *				then reprogram + recurse on the child bus.
 *
 *  The busra framework maintains the "available" property on each dip
 *  automatically as resources are allocated and freed -- no separate
 *  add_bus_available_prop() pass is needed.  The pci_resource_setup()
 *  call in HPC drivers becomes a no-op since maps are pre-seeded.
 */

#include <sys/ddi.h>
#include <sys/obpdefs.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/sysmacros.h>

#include <sys/pci.h>
#include <sys/pci_cfgacc.h>
#include <sys/pci_impl.h>
#include <sys/pci_props.h>
#include <sys/pcie_impl.h>
#include <sys/plat/pci_prd.h>
#include <sys/pci_bar_relocate.h>

#define	ddev_err	if (pci_boot_debug != 0) dev_err
#define	bus_debug(bus)	(pci_boot_debug != 0 && pci_debug_bus_start != -1 && \
	    pci_debug_bus_end != -1 && (bus) >= pci_debug_bus_start && \
	    (bus) <= pci_debug_bus_end)
#define	MSGHDR		"pci_boot: %s[%02x/%02x/%x]: "

typedef enum {
	CONFIG_INFO,
	CONFIG_NEW,
} config_phase_t;

/*
 * Minimum bridge window alignments per the PCIe spec (Type 1 header
 * base/limit register encoding).  These are also the smallest useful
 * allocation units, so we use them as the low-address exclusion size
 * (to keep address 0 out of the allocator) and as the bound base for
 * 32-bit non-prefetchable MEM allocations.
 */
#define	PPB_IO_ALIGNMENT	0x1000		/* 4K aligned */
#define	PPB_MEM_ALIGNMENT	0x100000	/* 1M aligned */

/*
 * Determining the size of a PCI BAR is done by writing all 1s to the base
 * register and then reading the value back. The retrieved value will either
 * be zero, indicating that the BAR is unimplemented, or a mask in which
 * the significant bits for the required memory space are 0.
 * For example, a 32-bit BAR could return 0xfff00000 which equates to a
 * length of 0x100000 (1MiB). The following macro does that conversion.
 * The input value must have already had the lower encoding bits cleared.
 */
#define	BARMASKTOLEN(value) ((((value) ^ ((value) - 1)) + 1) >> 1)

typedef enum {
	RES_IO,
	RES_MEM,
	RES_PMEM
} mem_res_t;

/*
 * In order to disable an IO or memory range on a bridge, the range's base must
 * be set to a value greater than its limit. The following values are used for
 * this purpose.
 */
#define	PPB_DISABLE_IORANGE_BASE	0x9fff
#define	PPB_DISABLE_IORANGE_LIMIT	0x1000
#define	PPB_DISABLE_MEMRANGE_BASE	0x9ff00000
#define	PPB_DISABLE_MEMRANGE_LIMIT	0x100fffff

/*
 * Value used to indicate that a bus hasn't yet been set.
 *
 * It being the maximum valid bus number seems like a problem but is not,
 * because we're caring about the parent side of bridges.  If the parent is
 * bus 255, there's no room for a child.
 */
#define	NO_PAR_BUS	(uchar_t)-1

struct pci_devfunc {
	struct pci_devfunc *next;
	dev_info_t *dip;
	uchar_t dev;
	uchar_t func;
};

static uchar_t max_dev_pci = PCI_MAX_DEVICES;
int pci_boot_maxbus;

/*
 * Debugging aid: set pci_boot_debug to non-zero to enable debug messages, and
 * optionally set pci_debug_bus_start and pci_debug_bus_end to restrict messages
 * to a specific bus or bus range.
 *
 * Do this using /etc/system, adding or modifying lines like the following:
 *   set pcierc:pci_boot_debug=1
 *   set pcierc:pci_debug_bus_start=42
 *   set pcierc:pci_debug_bus_end=84
 */
int pci_boot_debug = 0;
int pci_debug_bus_start = 0;
int pci_debug_bus_end = PCI_MAX_BUS_NUM - 1;

extern dev_info_t *pcie_get_rc_dip(dev_info_t *);

/*
 * Module prototypes
 */
static void enumerate_bus_devs(dev_info_t *, uchar_t,
    struct pci_bus_resource *);
static void reprogram_bus_devs(dev_info_t *, uchar_t,
    struct pci_bus_resource *);
static int process_devfunc(dev_info_t *, struct pci_bus_resource *,
    uchar_t, uchar_t, uchar_t, config_phase_t);
static void add_reg_props(dev_info_t *, dev_info_t *,
    struct pci_bus_resource *, uchar_t, uchar_t, uchar_t, config_phase_t);
static void add_ppb_props(dev_info_t *, dev_info_t *, struct pci_bus_resource *,
    uchar_t, uchar_t, uchar_t, boolean_t, boolean_t);
static void add_bus_range_prop(struct pci_bus_resource *, int);
static void add_ranges_prop(dev_info_t *, struct pci_bus_resource *, int);
static void alloc_res_array(struct pci_bus_resource **, size_t);

static void populate_bus_res(dev_info_t *, struct pci_bus_resource *,
    uchar_t);
static void pci_reprogram(dev_info_t *, struct pci_bus_resource *);
static void dip_bus_range(dev_info_t *, int *);

/*
 * Enumerate all PCI devices
 */
static void
pci_setup_tree(dev_info_t *dip, struct pci_bus_resource *pci_bus_res)
{
	for (uint_t i = 0; i <= pci_boot_maxbus; i++) {
		pci_bus_res[i].par_bus = NO_PAR_BUS;
		pci_bus_res[i].sub_bus = i;
	}

	int busrng[2];

	dip_bus_range(dip, busrng);

	VERIFY3P(pci_bus_res[busrng[0]].dip, ==, NULL);

	/*
	 * The first bus is _our_ bus, others in the range
	 * are available to subordinate bridges.
	 */
	pci_bus_res[busrng[0]].dip = dip;

	enumerate_bus_devs(dip, busrng[0], pci_bus_res);
}

void
pci_enumerate(dev_info_t *dip)
{
	struct pci_bus_resource *pci_bus_res;

	pci_boot_maxbus = pci_prd_max_bus();

	alloc_res_array(&pci_bus_res, pci_boot_maxbus);
	pci_setup_tree(dip, pci_bus_res);
	pci_reprogram(dip, pci_bus_res);
	kmem_free(pci_bus_res, (pci_boot_maxbus + 1) *
	    sizeof (struct pci_bus_resource));
}

/*
 * Retrieve, or default, the "bus-range" property.
 */
static void
dip_bus_range(dev_info_t *dip, int *busrng)
{
	int *bus_prop;
	uint_t bus_prop_sz;

	busrng[0] = 0;
	busrng[1] = pci_prd_max_bus();

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, OBP_BUS_RANGE,
	    &bus_prop, &bus_prop_sz) == DDI_SUCCESS) {
		VERIFY3U(bus_prop_sz, ==, 2);
		busrng[0] = bus_prop[0];
		busrng[1] = bus_prop[1];
		ddi_prop_free(bus_prop);
	}
}

/*
 * given a cap_id, return its cap_id location in config space
 */
static int
get_pci_cap(dev_info_t *rcdip, uchar_t bus, uchar_t dev, uchar_t func,
    uint8_t cap_id)
{
	uint8_t curcap, cap_id_loc;
	uint16_t status;
	int location = -1;
	int attempts = 48;

	/*
	 * Need to check the Status register for ECP support first.
	 * Also please note that for type 1 devices, the
	 * offset could change. Should support type 1 next.
	 */
	status = pci_cfgacc_get16(rcdip, PCI_GETBDF(bus, dev, func),
	    PCI_CONF_STAT);
	if (!(status & PCI_STAT_CAP)) {
		return (-1);
	}
	cap_id_loc = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
	    PCI_CONF_CAP_PTR);

	/* Walk the list of capabilities, with a safety limit */
	while (cap_id_loc && cap_id_loc != (uint8_t)-1 && attempts-- > 0) {
		curcap = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
		    cap_id_loc);

		if (curcap == cap_id) {
			location = cap_id_loc;
			break;
		}
		cap_id_loc = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
		    cap_id_loc + 1);
	}
	return (location);
}

/*
 * Determine whether a PCIe bridge has hot-plug capability by reading the
 * Slot Capabilities register directly from config space.  We cannot rely
 * on the devinfo "hotplug-capable" property because pcie_init_bus() has
 * not yet run at pci_boot enumeration time.  Conventional PCI bridges
 * (no PCIe capability) are never hot-plug capable.
 */
static boolean_t
bridge_is_hotplug_capable(dev_info_t *rcdip, uchar_t bus, uchar_t dev,
    uchar_t func)
{
	int cap_ptr;
	uint16_t pciecap;
	uint32_t slotcap;

	cap_ptr = get_pci_cap(rcdip, bus, dev, func, PCI_CAP_ID_PCI_E);
	if (cap_ptr == -1)
		return (B_FALSE);

	pciecap = pci_cfgacc_get16(rcdip, PCI_GETBDF(bus, dev, func),
	    (uint16_t)cap_ptr + PCIE_PCIECAP);
	if ((pciecap & PCIE_PCIECAP_SLOT_IMPL) == 0)
		return (B_FALSE);

	slotcap = pci_cfgacc_get32(rcdip, PCI_GETBDF(bus, dev, func),
	    (uint16_t)cap_ptr + PCIE_SLOTCAP);
	return ((slotcap & PCIE_SLOTCAP_HP_CAPABLE) != 0);
}

static void
set_ppb_res(dev_info_t *rcdip, dev_info_t *dip, uchar_t bus, uchar_t dev,
    uchar_t func, mem_res_t type, uint64_t base, uint64_t limit)
{
	char *tag;

	switch (type) {
	case RES_IO: {
		VERIFY0(base >> 32);
		VERIFY0(limit >> 32);

		pci_cfgacc_put8(rcdip, PCI_GETBDF(bus, dev, func),
		    PCI_BCNF_IO_BASE_LOW,
		    (uint8_t)((base >> PCI_BCNF_IO_SHIFT) & PCI_BCNF_IO_MASK));
		pci_cfgacc_put8(rcdip, PCI_GETBDF(bus, dev, func),
		    PCI_BCNF_IO_LIMIT_LOW,
		    (uint8_t)((limit >> PCI_BCNF_IO_SHIFT) & PCI_BCNF_IO_MASK));

		uint8_t val = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
		    PCI_BCNF_IO_BASE_LOW);
		if ((val & PCI_BCNF_ADDR_MASK) == PCI_BCNF_IO_32BIT) {
			pci_cfgacc_put16(rcdip, PCI_GETBDF(bus, dev, func),
			    PCI_BCNF_IO_BASE_HI, base >> 16);
			pci_cfgacc_put16(rcdip, PCI_GETBDF(bus, dev, func),
			    PCI_BCNF_IO_LIMIT_HI, limit >> 16);
		} else {
			VERIFY0(base >> 16);
			VERIFY0(limit >> 16);
		}

		tag = "I/O";
		break;
	}

	case RES_MEM:
		VERIFY0(base >> 32);
		VERIFY0(limit >> 32);

		pci_cfgacc_put16(rcdip, PCI_GETBDF(bus, dev, func),
		    PCI_BCNF_MEM_BASE, (uint16_t)((base >> PCI_BCNF_MEM_SHIFT) &
		    PCI_BCNF_MEM_MASK));
		pci_cfgacc_put16(rcdip, PCI_GETBDF(bus, dev, func),
		    PCI_BCNF_MEM_LIMIT,
		    (uint16_t)((limit >> PCI_BCNF_MEM_SHIFT) &
		    PCI_BCNF_MEM_MASK));

		tag = "MEM";
		break;

	case RES_PMEM: {
		pci_cfgacc_put16(rcdip, PCI_GETBDF(bus, dev, func),
		    PCI_BCNF_PF_BASE_LOW,
		    (uint16_t)((base >> PCI_BCNF_MEM_SHIFT) &
		    PCI_BCNF_MEM_MASK));
		pci_cfgacc_put16(rcdip, PCI_GETBDF(bus, dev, func),
		    PCI_BCNF_PF_LIMIT_LOW,
		    (uint16_t)((limit >> PCI_BCNF_MEM_SHIFT) &
		    PCI_BCNF_MEM_MASK));

		uint16_t val = pci_cfgacc_get16(rcdip,
		    PCI_GETBDF(bus, dev, func), PCI_BCNF_PF_BASE_LOW);
		if ((val & PCI_BCNF_ADDR_MASK) == PCI_BCNF_PF_MEM_64BIT) {
			pci_cfgacc_put32(rcdip, PCI_GETBDF(bus, dev, func),
			    PCI_BCNF_PF_BASE_HIGH, base >> 32);
			pci_cfgacc_put32(rcdip, PCI_GETBDF(bus, dev, func),
			    PCI_BCNF_PF_LIMIT_HIGH, limit >> 32);
		} else {
			VERIFY0(base >> 32);
			VERIFY0(limit >> 32);
		}

		tag = "PMEM";
		break;
	}

	default:
		panic("Invalid resource type %d", type);
	}

	if (base > limit) {
		ddev_err(rcdip, CE_NOTE, MSGHDR "DISABLE %4s range",
		    ddi_node_name(dip), bus, dev, func, tag);
	} else {
		ddev_err(rcdip, CE_NOTE,
		    MSGHDR "PROGRAM %4s range 0x%lx ~ 0x%lx",
		    ddi_node_name(dip), bus, dev, func, tag, base, limit);
	}
}

static void
fetch_ppb_res(dev_info_t *rcdip, uchar_t bus, uchar_t dev, uchar_t func,
    mem_res_t type, uint64_t *basep, uint64_t *limitp)
{
	uint64_t val, base, limit;

	switch (type) {
	case RES_IO:
		val = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
		    PCI_BCNF_IO_LIMIT_LOW);
		limit = ((val & PCI_BCNF_IO_MASK) << PCI_BCNF_IO_SHIFT) |
		    PCI_BCNF_IO_LIMIT_BITS;
		val = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
		    PCI_BCNF_IO_BASE_LOW);
		base = ((val & PCI_BCNF_IO_MASK) << PCI_BCNF_IO_SHIFT);

		if ((val & PCI_BCNF_ADDR_MASK) == PCI_BCNF_IO_32BIT) {
			val = pci_cfgacc_get16(rcdip,
			    PCI_GETBDF(bus, dev, func), PCI_BCNF_IO_BASE_HI);
			base |= val << 16;
			val = pci_cfgacc_get16(rcdip,
			    PCI_GETBDF(bus, dev, func), PCI_BCNF_IO_LIMIT_HI);
			limit |= val << 16;
		}
		VERIFY0(base >> 32);
		break;

	case RES_MEM:
		val = pci_cfgacc_get16(rcdip, PCI_GETBDF(bus, dev, func),
		    PCI_BCNF_MEM_LIMIT);
		limit = ((val & PCI_BCNF_MEM_MASK) << PCI_BCNF_MEM_SHIFT) |
		    PCI_BCNF_MEM_LIMIT_BITS;
		val = pci_cfgacc_get16(rcdip, PCI_GETBDF(bus, dev, func),
		    PCI_BCNF_MEM_BASE);
		base = ((val & PCI_BCNF_MEM_MASK) << PCI_BCNF_MEM_SHIFT);
		VERIFY0(base >> 32);
		break;

	case RES_PMEM:
		val = pci_cfgacc_get16(rcdip, PCI_GETBDF(bus, dev, func),
		    PCI_BCNF_PF_LIMIT_LOW);
		limit = ((val & PCI_BCNF_MEM_MASK) << PCI_BCNF_MEM_SHIFT) |
		    PCI_BCNF_MEM_LIMIT_BITS;
		val = pci_cfgacc_get16(rcdip, PCI_GETBDF(bus, dev, func),
		    PCI_BCNF_PF_BASE_LOW);
		base = ((val & PCI_BCNF_MEM_MASK) << PCI_BCNF_MEM_SHIFT);

		if ((val & PCI_BCNF_ADDR_MASK) == PCI_BCNF_PF_MEM_64BIT) {
			val = pci_cfgacc_get32(rcdip,
			    PCI_GETBDF(bus, dev, func), PCI_BCNF_PF_BASE_HIGH);
			base |= val << 32;
			val = pci_cfgacc_get32(rcdip,
			    PCI_GETBDF(bus, dev, func), PCI_BCNF_PF_LIMIT_HIGH);
			limit |= val << 32;
		}
		break;
	default:
		panic("Invalid resource type %d", type);
	}

	*basep = base;
	*limitp = limit;
}


/*
 * Allocate a single resource type for a bridge window from the parent's
 * busra map, seed the bridge's own busra map, and program the bridge
 * window registers.  Returns B_TRUE on success, B_FALSE if allocation
 * failed entirely (bridge window will be disabled).
 *
 * If allocp is non-NULL, the actual allocated window size is stored
 * there on success (0 on failure).
 */
static boolean_t
alloc_bridge_res_type(dev_info_t *rcdip, dev_info_t *parent_dip,
    dev_info_t *bridge_dip, struct pci_bus_resource *pci_bus_res,
    uchar_t bus, uchar_t dev, uchar_t func, uchar_t secbus,
    mem_res_t type, uint64_t mandatory, uint64_t hp_spare,
    char *ra_type, uint64_t *allocp)
{
	uint64_t window, base, len;
	ndi_ra_request_t req = {0};
	uint64_t align;
	int rv;
	uint64_t disable_base, disable_limit;

	if (allocp != NULL)
		*allocp = 0;

	if (type == RES_IO) {
		align = PPB_IO_ALIGNMENT;
		disable_base = PPB_DISABLE_IORANGE_BASE;
		disable_limit = PPB_DISABLE_IORANGE_LIMIT;
	} else {
		align = PPB_MEM_ALIGNMENT;
		disable_base = PPB_DISABLE_MEMRANGE_BASE;
		disable_limit = PPB_DISABLE_MEMRANGE_LIMIT;
	}

	window = P2ROUNDUP(mandatory + hp_spare, align);
	if (window == 0)
		window = align;  /* minimum 1 unit even if nothing needed */

	if (mandatory == 0 && hp_spare == 0) {
		/* No resources needed at all; disable the window */
		set_ppb_res(rcdip, bridge_dip, bus, dev, func, type,
		    disable_base, disable_limit);
		return (B_TRUE);
	}

	req.ra_len = window;
	req.ra_align_mask = align - 1;

	/*
	 * Non-prefetchable MEM must be in the 32-bit address space.
	 */
	if (type == RES_MEM) {
		req.ra_flags = NDI_RA_ALLOC_BOUNDED;
		req.ra_boundbase = PPB_MEM_ALIGNMENT;
		req.ra_boundlen = (uint64_t)UINT32_MAX -
		    PPB_MEM_ALIGNMENT + 1;
	}

	rv = ndi_ra_alloc(parent_dip, &req, &base, &len, ra_type, 0);

	/*
	 * If the full window (mandatory + spare) fails, retry with just
	 * mandatory.  This sheds hotplug spare first.
	 */
	if (rv != NDI_SUCCESS && hp_spare > 0) {
		window = P2ROUNDUP(mandatory, align);
		if (window == 0)
			window = align;
		req.ra_len = window;
		req.ra_align_mask = align - 1;
		rv = ndi_ra_alloc(parent_dip, &req, &base, &len,
		    ra_type, 0);
	}

	if (rv != NDI_SUCCESS) {
		dev_err(rcdip, CE_WARN,
		    MSGHDR "failed to allocate %s window (need 0x%lx)",
		    ddi_node_name(bridge_dip), bus, dev, func,
		    type == RES_IO ? "I/O" :
		    type == RES_MEM ? "MEM" : "PMEM", mandatory);
		set_ppb_res(rcdip, bridge_dip, bus, dev, func, type,
		    disable_base, disable_limit);
		return (B_FALSE);
	}

	/* Seed this bridge's busra map */
	(void) ndi_ra_free(bridge_dip, base, len, ra_type, 0);

	/* Program bridge window registers */
	set_ppb_res(rcdip, bridge_dip, bus, dev, func, type,
	    base, base + len - 1);

	ddev_err(rcdip, CE_NOTE,
	    MSGHDR "allocated %s "
	    "window 0x%lx ~ 0x%lx (req 0x%lx + spare 0x%lx)",
	    ddi_node_name(bridge_dip), bus, dev, func,
	    type == RES_IO ? "I/O" : type == RES_MEM ? "MEM" : "PMEM",
	    base, base + len - 1, mandatory, hp_spare);

	if (allocp != NULL)
		*allocp = len;

	return (B_TRUE);
}

/*
 * Recursive top-down bridge resource allocation via busra.
 *
 * For each bridge (identified by its secondary bus number), allocate
 * IO/MEM/PMEM windows from the parent's busra map, seed the bridge's
 * own map, program bridge registers, then recurse into child bridges.
 *
 * per_hp_mem/per_hp_io/per_hp_pmem are the per-hotplug-bridge spare
 * amounts, computed by the caller from the parent's actual available
 * resources.  Each level recomputes these for its children based on
 * the actual allocated window size minus descendant requirements.
 */
static void
allocate_bridge_resources(dev_info_t *rcdip,
    struct pci_bus_resource *pci_bus_res, uchar_t secbus,
    uint64_t per_hp_mem, uint64_t per_hp_io, uint64_t per_hp_pmem)
{
	struct pci_bus_resource *pbr = &pci_bus_res[secbus];
	uchar_t parbus, bus, dev, func;
	dev_info_t *parent_dip, *bridge_dip;
	int *regp;
	uint_t reglen;
	int rv, cap_ptr, i;
	uint16_t cmd_reg;
	boolean_t has_io, has_mem, has_pmem;
	uint64_t mem_spare, io_spare, pmem_spare;
	uint64_t alloc_mem = 0, alloc_io = 0, alloc_pmem = 0;
	uint64_t child_per_hp_mem = 0, child_per_hp_io = 0;
	uint64_t child_per_hp_pmem = 0;
	uint64_t child_mem_mandatory = 0, child_io_mandatory = 0;
	uint64_t child_pmem_mandatory = 0, child_hp = 0;

	/* skip root (peer) PCI buses */
	if (pbr->par_bus == NO_PAR_BUS)
		return;

	/* some entries may be empty due to discontiguous bus numbering */
	bridge_dip = pbr->dip;
	if (bridge_dip == NULL)
		return;

	parbus = pbr->par_bus;
	parent_dip = pci_bus_res[parbus].dip;
	ASSERT(parent_dip != NULL);

	rv = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, bridge_dip,
	    DDI_PROP_DONTPASS, OBP_REG, &regp, &reglen);
	if (rv != DDI_PROP_SUCCESS || reglen == 0)
		return;
	func = (uchar_t)PCI_REG_FUNC_G(regp[0]);
	dev = (uchar_t)PCI_REG_DEV_G(regp[0]);
	bus = (uchar_t)PCI_REG_BUS_G(regp[0]);
	ddi_prop_free(regp);

	ASSERT(bus == parbus);

	/*
	 * If PCIe bridge, check to see if link is disabled.
	 */
	cap_ptr = get_pci_cap(rcdip, bus, dev, func, PCI_CAP_ID_PCI_E);
	if (cap_ptr != -1) {
		uint16_t reg = pci_cfgacc_get16(rcdip,
		    PCI_GETBDF(bus, dev, func),
		    (uint16_t)cap_ptr + PCIE_LINKCTL);
		if ((reg & PCIE_LINKCTL_LINK_DISABLE) != 0) {
			ddev_err(rcdip, CE_NOTE,
			    MSGHDR "link disabled, skipping",
			    ddi_node_name(bridge_dip),
			    bus, dev, func);
			return;
		}
	}

	/* Set up busra maps for this bridge */
	(void) ndi_ra_map_setup(bridge_dip, NDI_RA_TYPE_MEM);
	(void) ndi_ra_map_setup(bridge_dip, NDI_RA_TYPE_IO);
	(void) ndi_ra_map_setup(bridge_dip, NDI_RA_TYPE_PCI_PREFETCH_MEM);
	(void) ndi_ra_map_setup(bridge_dip, NDI_RA_TYPE_PCI_BUSNUM);

	/*
	 * Allocate this bridge's bus number range [secbus..sub_bus] from
	 * the parent's BUSNUM map, then seed our own map with the free
	 * subordinate numbers (excluding secbus itself, which is our
	 * secondary bus and not available for further allocation).
	 */
	{
		ndi_ra_request_t bus_req = {0};
		uint64_t bus_base, bus_len;

		bus_req.ra_flags = NDI_RA_ALLOC_SPECIFIED;
		bus_req.ra_addr = (uint64_t)secbus;
		bus_req.ra_len = (uint64_t)(pbr->sub_bus - secbus + 1);
		rv = ndi_ra_alloc(parent_dip, &bus_req, &bus_base,
		    &bus_len, NDI_RA_TYPE_PCI_BUSNUM, 0);
		if (rv != NDI_SUCCESS) {
			dev_err(rcdip, CE_WARN,
			    MSGHDR "failed to allocate BUSNUM range "
			    "[0x%02x..0x%02x]",
			    ddi_node_name(bridge_dip), bus, dev, func,
			    secbus, pbr->sub_bus);
		}

		if (pbr->sub_bus > secbus) {
			(void) ndi_ra_free(bridge_dip,
			    (uint64_t)(secbus + 1),
			    (uint64_t)(pbr->sub_bus - secbus),
			    NDI_RA_TYPE_PCI_BUSNUM, 0);
		}
	}

	/*
	 * Calculate hotplug spare for this bridge's subtree.
	 * The bridge gets spare proportional to its num_hp_bridges count,
	 * using the per-hp values computed by our parent.
	 */
	mem_spare = pbr->num_hp_bridges * per_hp_mem;
	io_spare = pbr->num_hp_bridges * per_hp_io;
	pmem_spare = pbr->num_hp_bridges * per_hp_pmem;

	cmd_reg = pci_cfgacc_get16(rcdip, PCI_GETBDF(bus, dev, func),
	    PCI_CONF_COMM);

	/*
	 * Subtractive bridges get a nominal window for busra bookkeeping.
	 * They forward everything not claimed by siblings, so the window
	 * size is somewhat arbitrary.
	 */
	if (pbr->subtractive) {
		uint64_t sub_mem = P2ROUNDUP(
		    MAX(pbr->mem_required, PPB_MEM_ALIGNMENT),
		    PPB_MEM_ALIGNMENT);
		uint64_t sub_io = P2ROUNDUP(
		    MAX(pbr->io_required, PPB_IO_ALIGNMENT),
		    PPB_IO_ALIGNMENT);

		(void) alloc_bridge_res_type(rcdip, parent_dip, bridge_dip,
		    pci_bus_res, bus, dev, func, secbus,
		    RES_MEM, sub_mem, 0, NDI_RA_TYPE_MEM, NULL);
		(void) alloc_bridge_res_type(rcdip, parent_dip, bridge_dip,
		    pci_bus_res, bus, dev, func, secbus,
		    RES_IO, sub_io, 0, NDI_RA_TYPE_IO, NULL);

		add_ranges_prop(rcdip, pci_bus_res, secbus);
		goto recurse;
	}

	/*
	 * Normal (non-subtractive) bridge: allocate IO, MEM, and PMEM.
	 * Capture the actual allocated window sizes for child spare
	 * computation below.
	 */
	has_io = alloc_bridge_res_type(rcdip, parent_dip, bridge_dip,
	    pci_bus_res, bus, dev, func, secbus,
	    RES_IO, pbr->io_required, io_spare, NDI_RA_TYPE_IO,
	    &alloc_io);

	has_mem = alloc_bridge_res_type(rcdip, parent_dip, bridge_dip,
	    pci_bus_res, bus, dev, func, secbus,
	    RES_MEM, pbr->mem_required, mem_spare, NDI_RA_TYPE_MEM,
	    &alloc_mem);

	has_pmem = alloc_bridge_res_type(rcdip, parent_dip, bridge_dip,
	    pci_bus_res, bus, dev, func, secbus,
	    RES_PMEM, pbr->pmem_required, pmem_spare,
	    NDI_RA_TYPE_PCI_PREFETCH_MEM, &alloc_pmem);

	add_ranges_prop(rcdip, pci_bus_res, secbus);

	/* Enable IO/MEM access as appropriate */
	if (has_io)
		cmd_reg |= PCI_COMM_IO | PCI_COMM_ME;
	if (has_mem || has_pmem)
		cmd_reg |= PCI_COMM_MAE | PCI_COMM_ME;
	pci_cfgacc_put16(rcdip, PCI_GETBDF(bus, dev, func),
	    PCI_CONF_COMM, cmd_reg);

recurse:
	/*
	 * Reprogram device BARs on this bus.  The bridge window has
	 * been established and busra is seeded, so devices can allocate
	 * resources immediately.
	 */
	reprogram_bus_devs(rcdip, secbus, pci_bus_res);

	/*
	 * Compute local per-hp spare for child bridges.
	 *
	 * The spare available at this level is the difference between
	 * what we actually got allocated and what our descendants
	 * require (mem_required already includes all descendant needs).
	 * Dividing that among the hotplug-capable bridges in our
	 * subtree gives a right-sized spare that naturally decreases
	 * at deeper levels where less resource is available.
	 */
	for (i = 0; i <= pci_boot_maxbus; i++) {
		if (pci_bus_res[i].par_bus != secbus ||
		    pci_bus_res[i].dip == NULL)
			continue;
		child_mem_mandatory += P2ROUNDUP(
		    pci_bus_res[i].mem_required, PPB_MEM_ALIGNMENT);
		child_io_mandatory += P2ROUNDUP(
		    pci_bus_res[i].io_required, PPB_IO_ALIGNMENT);
		child_pmem_mandatory += P2ROUNDUP(
		    pci_bus_res[i].pmem_required, PPB_MEM_ALIGNMENT);
		child_hp += pci_bus_res[i].num_hp_bridges;
	}

	if (child_hp > 0) {
		uint64_t mem_free, io_free, pmem_free;

		mem_free = alloc_mem > pbr->mem_required ?
		    alloc_mem - pbr->mem_required : 0;
		io_free = alloc_io > pbr->io_required ?
		    alloc_io - pbr->io_required : 0;
		pmem_free = alloc_pmem > pbr->pmem_required ?
		    alloc_pmem - pbr->pmem_required : 0;

		child_per_hp_mem = mem_free / child_hp;
		child_per_hp_io = io_free / child_hp;
		child_per_hp_pmem = pmem_free / child_hp;

		/*
		 * Floor at one alignment unit and round down
		 * to one alignment unit to avoid over-fitting
		 * and subsequent resource starvation.
		 */
		if (child_per_hp_mem < PPB_MEM_ALIGNMENT)
			child_per_hp_mem = PPB_MEM_ALIGNMENT;
		child_per_hp_mem = P2ALIGN(child_per_hp_mem,
		    PPB_MEM_ALIGNMENT);
		if (child_per_hp_mem * child_hp > mem_free)
			child_per_hp_mem = 0;

		if (child_per_hp_io < PPB_IO_ALIGNMENT)
			child_per_hp_io = PPB_IO_ALIGNMENT;
		child_per_hp_io = P2ALIGN(child_per_hp_io,
		    PPB_IO_ALIGNMENT);
		if (child_per_hp_io * child_hp > io_free)
			child_per_hp_io = 0;

		if (child_per_hp_pmem < PPB_MEM_ALIGNMENT)
			child_per_hp_pmem = PPB_MEM_ALIGNMENT;
		child_per_hp_pmem = P2ALIGN(child_per_hp_pmem,
		    PPB_MEM_ALIGNMENT);
		if (child_per_hp_pmem * child_hp > pmem_free)
			child_per_hp_pmem = 0;
	}

	/* Recurse into child bridges with locally-computed spare */
	for (i = 0; i <= pci_boot_maxbus; i++) {
		if (pci_bus_res[i].par_bus == secbus &&
		    pci_bus_res[i].dip != NULL) {
			allocate_bridge_resources(rcdip, pci_bus_res, i,
			    child_per_hp_mem, child_per_hp_io,
			    child_per_hp_pmem);
		}
	}
}

/*
 * Allocate bridge windows and reprogram device BARs in a single
 * recursive pass.  For each root bus, compute per-hotplug-bridge spare
 * from that bus's own available resources and accumulated requirements,
 * reprogram root bus device BARs, then recursively allocate child
 * bridge windows -- reprogramming each bus's device BARs immediately
 * after its busra map is seeded.
 *
 * Spare is computed per root bus, not globally, so that multi-segment
 * systems with independent resource pools get correctly scoped spare.
 * No maximum clamp is applied -- the available pool itself is the
 * natural upper bound.  Each level of the recursion recomputes spare
 * locally from its actual allocated window, so deep bridges get
 * proportionally less spare without needing artificial limits.
 */
static void
allocate_all_bridges(dev_info_t *rcdip,
    struct pci_bus_resource *pci_bus_res)
{
	int bus, i;

	for (bus = 0; bus <= pci_boot_maxbus; bus++) {
		pci_ranges_t *rngs;
		uint_t rnglen, nranges, ri;
		uint64_t mem_avail = 0, io_avail = 0, pmem_avail = 0;
		uint64_t per_hp_mem = 0, per_hp_io = 0, per_hp_pmem = 0;
		uint64_t mem_free, io_free, pmem_free;
		uint64_t hp;

		if (pci_bus_res[bus].par_bus != NO_PAR_BUS)
			continue;
		if (pci_bus_res[bus].dip == NULL)
			continue;

		/*
		 * Compute available resources for this root bus from the
		 * RC's ranges property.  Each root bus gets its own spare
		 * computation so that multi-segment systems with separate
		 * resource pools are handled correctly.
		 */
		if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, rcdip,
		    DDI_PROP_DONTPASS, OBP_RANGES,
		    (int **)&rngs, &rnglen) == DDI_PROP_SUCCESS) {
			nranges = CELLS_1275_TO_BYTES(rnglen) /
			    sizeof (pci_ranges_t);

			for (ri = 0; ri < nranges; ri++) {
				uint32_t addr_type =
				    rngs[ri].child_high & PCI_ADDR_MASK;
				uint64_t base =
				    ((uint64_t)rngs[ri].child_mid << 32) |
				    rngs[ri].child_low;
				uint64_t size =
				    ((uint64_t)rngs[ri].size_high << 32) |
				    rngs[ri].size_low;

				switch (addr_type) {
				case PCI_ADDR_IO:
					io_avail += size;
					break;
				case PCI_ADDR_MEM32:
				case PCI_ADDR_MEM64:
					if (rngs[ri].child_high &
					    PCI_PREFETCH_B) {
						pmem_avail += size;
					} else if (base < UINT32_MAX) {
						/*
						 * Non-prefetchable MEM bridge
						 * windows are limited to 32-bit
						 * addresses by PPB hardware.
						 *
						 * Only count sub-4G ranges for
						 * spare computation.
						 */
						mem_avail += size;
					}
					break;
				default:
					break;
				}
			}

			ddi_prop_free(rngs);
		}

		/*
		 * Compute per-hotplug-bridge spare for this root bus.
		 * Use the root bus's accumulated requirements directly:
		 * mem_required = mem_size (RC integrated device BARs) +
		 * sum of P2ROUNDUP(child.mem_required), which accounts
		 * for all descendants and root-complex integrated devices.
		 *
		 * Only a minimum floor is applied; no maximum clamp.  The
		 * recursive allocator recomputes spare at each level from
		 * the actual allocated window, so over-reservation at the
		 * root naturally attenuates at depth.
		 */
		hp = pci_bus_res[bus].num_hp_bridges;
		if (hp > 0) {
			mem_free = mem_avail >
			    pci_bus_res[bus].mem_required ?
			    mem_avail - pci_bus_res[bus].mem_required : 0;
			io_free = io_avail >
			    pci_bus_res[bus].io_required ?
			    io_avail - pci_bus_res[bus].io_required : 0;
			pmem_free = pmem_avail >
			    pci_bus_res[bus].pmem_required ?
			    pmem_avail - pci_bus_res[bus].pmem_required : 0;

			per_hp_mem = mem_free / hp;
			per_hp_io = io_free / hp;
			per_hp_pmem = pmem_free / hp;

			/*
			 * Floor at one alignment unit, round down to
			 * alignment to reduce resource exhaustion risk,
			 * and disable spare if it would exceed available.
			 */
			if (per_hp_mem < PPB_MEM_ALIGNMENT)
				per_hp_mem = PPB_MEM_ALIGNMENT;
			per_hp_mem = P2ALIGN(per_hp_mem,
			    PPB_MEM_ALIGNMENT);
			if (per_hp_mem * hp > mem_free)
				per_hp_mem = 0;

			if (per_hp_io < PPB_IO_ALIGNMENT)
				per_hp_io = PPB_IO_ALIGNMENT;
			per_hp_io = P2ALIGN(per_hp_io,
			    PPB_IO_ALIGNMENT);
			if (per_hp_io * hp > io_free)
				per_hp_io = 0;

			if (per_hp_pmem < PPB_MEM_ALIGNMENT)
				per_hp_pmem = PPB_MEM_ALIGNMENT;
			per_hp_pmem = P2ALIGN(per_hp_pmem,
			    PPB_MEM_ALIGNMENT);
			if (per_hp_pmem * hp > pmem_free)
				per_hp_pmem = 0;

			ddev_err(rcdip, CE_NOTE,
			    "pci_boot: bus 0x%02x hp_bridges %lu, "
			    "per_hp: mem 0x%lx, io 0x%lx, pmem 0x%lx",
			    bus, hp, per_hp_mem, per_hp_io,
			    per_hp_pmem);
		}

		/*
		 * Reprogram root bus device BARs, then allocate and
		 * reprogram child bridges recursively.  Non-subtractive
		 * bridges are processed before subtractive ones.
		 */
		reprogram_bus_devs(rcdip, (uchar_t)bus, pci_bus_res);

		for (i = 0; i <= pci_boot_maxbus; i++) {
			if (pci_bus_res[i].par_bus == bus &&
			    pci_bus_res[i].dip != NULL &&
			    !pci_bus_res[i].subtractive) {
				allocate_bridge_resources(rcdip, pci_bus_res,
				    i, per_hp_mem, per_hp_io,
				    per_hp_pmem);
			}
		}
		for (i = 0; i <= pci_boot_maxbus; i++) {
			if (pci_bus_res[i].par_bus == bus &&
			    pci_bus_res[i].dip != NULL &&
			    pci_bus_res[i].subtractive) {
				allocate_bridge_resources(rcdip, pci_bus_res,
				    i, per_hp_mem, per_hp_io,
				    per_hp_pmem);
			}
		}
	}
}

static void
pci_reprogram(dev_info_t *rcdip, struct pci_bus_resource *pci_bus_res)
{
	int bus;

	/*
	 * Root-bus resource discovery: seed busra maps, exclude low
	 * addresses, and set bus-range properties.
	 */
	for (bus = 0; bus <= pci_boot_maxbus; bus++) {
		if (pci_bus_res[bus].par_bus != NO_PAR_BUS)
			continue;
		if (pci_bus_res[bus].dip == NULL)
			continue;

		populate_bus_res(rcdip, pci_bus_res, bus);

		/*
		 * Exclude the low address range from the busra maps.
		 * Reserve one minimum allocation unit (one alignment
		 * quantum) at address zero for each resource type.
		 * The PCI codebase assumes address 0 is invalid.
		 */
		{
			ndi_ra_request_t req = {0};
			uint64_t ra_base, ra_len;

			req.ra_flags = NDI_RA_ALLOC_SPECIFIED;
			req.ra_addr = 0x0;
			req.ra_len = PPB_MEM_ALIGNMENT;
			(void) ndi_ra_alloc(rcdip, &req, &ra_base, &ra_len,
			    NDI_RA_TYPE_MEM, 0);
			(void) ndi_ra_alloc(rcdip, &req, &ra_base, &ra_len,
			    NDI_RA_TYPE_PCI_PREFETCH_MEM, 0);

			req.ra_len = PPB_IO_ALIGNMENT;
			(void) ndi_ra_alloc(rcdip, &req, &ra_base, &ra_len,
			    NDI_RA_TYPE_IO, 0);
		}

		add_bus_range_prop(pci_bus_res, bus);
	}

	/*
	 * Allocate bridge windows, reprogram device BARs, and assign
	 * bus number ranges -- all in a single recursive pass.
	 * allocate_all_bridges() reprograms root bus devices first,
	 * then recurses into child bridges; each child bus's devices
	 * are reprogrammed immediately after the bridge window is
	 * established.
	 */
	allocate_all_bridges(rcdip, pci_bus_res);
}

/*
 * populate bus resources
 */
static void
populate_bus_res(dev_info_t *rcdip, struct pci_bus_resource *pci_bus_res,
    uchar_t bus)
{
	pci_ranges_t *rngs;
	uint_t rnglen, nranges, i;
	int busrng[2];

	/*
	 * Seed busra resource maps on the RC dip.  The busra framework
	 * (ndi_ra_alloc/ndi_ra_free) is the authoritative allocator for
	 * bridge window and device BAR resources.  We create maps for
	 * each resource type and populate them from the RC's "ranges"
	 * and "bus-range" properties.
	 */
	(void) ndi_ra_map_setup(rcdip, NDI_RA_TYPE_MEM);
	(void) ndi_ra_map_setup(rcdip, NDI_RA_TYPE_IO);
	(void) ndi_ra_map_setup(rcdip, NDI_RA_TYPE_PCI_PREFETCH_MEM);
	(void) ndi_ra_map_setup(rcdip, NDI_RA_TYPE_PCI_BUSNUM);

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, rcdip,
	    DDI_PROP_DONTPASS, OBP_RANGES,
	    (int **)&rngs, &rnglen) != DDI_PROP_SUCCESS) {
		dev_err(rcdip, CE_PANIC, "No ranges property");
		return;
	}

	nranges = CELLS_1275_TO_BYTES(rnglen) / sizeof (pci_ranges_t);

	for (i = 0; i < nranges; i++) {
		uint32_t addr_type = rngs[i].child_high & PCI_ADDR_MASK;
		uint64_t base = ((uint64_t)rngs[i].child_mid << 32) |
		    rngs[i].child_low;
		uint64_t size = ((uint64_t)rngs[i].size_high << 32) |
		    rngs[i].size_low;

		switch (addr_type) {
		case PCI_ADDR_IO:
			(void) ndi_ra_free(rcdip, base, size,
			    NDI_RA_TYPE_IO, 0);
			break;
		case PCI_ADDR_MEM32:
		case PCI_ADDR_MEM64:
			if (rngs[i].child_high & PCI_PREFETCH_B) {
				(void) ndi_ra_free(rcdip, base, size,
				    NDI_RA_TYPE_PCI_PREFETCH_MEM, 0);
			} else {
				(void) ndi_ra_free(rcdip, base, size,
				    NDI_RA_TYPE_MEM, 0);
			}
			break;
		default:
			break;
		}
	}

	ddi_prop_free(rngs);

	/*
	 * Seed bus number resources.  Read bus-range directly —
	 * the property gives us exactly [first_bus, last_bus].
	 * Exclude the root bus itself (already assigned) and seed
	 * the remaining subordinate range into busra for bridge
	 * allocation.
	 */
	dip_bus_range(rcdip, busrng);
	pci_bus_res[bus].sub_bus = busrng[1];

	if (busrng[1] > busrng[0]) {
		(void) ndi_ra_free(rcdip, (uint64_t)(busrng[0] + 1),
		    (uint64_t)(busrng[1] - busrng[0]),
		    NDI_RA_TYPE_PCI_BUSNUM, 0);
	}
}

/*
 * Reprogram device BARs for a single bus.  Drain the devlist built
 * during CONFIG_INFO enumeration, calling add_reg_props(CONFIG_NEW) for
 * each device.  Called from allocate_all_bridges() for root buses and
 * from allocate_bridge_resources() for non-root buses, immediately
 * after the bus's busra map is seeded.
 */
static void
reprogram_bus_devs(dev_info_t *rcdip, uchar_t bus,
    struct pci_bus_resource *pci_bus_res)
{
	struct pci_devfunc *devlist, *entry;

	if (bus_debug(bus))
		ddev_err(rcdip, CE_NOTE, "pci_boot: configuring pci bus 0x%x", bus);

	devlist = (struct pci_devfunc *)pci_bus_res[bus].privdata;
	while (devlist) {
		entry = devlist;
		devlist = entry->next;
		add_reg_props(rcdip, entry->dip,
		    pci_bus_res, bus, entry->dev, entry->func,
		    CONFIG_NEW);
		kmem_free(entry, sizeof (*entry));
	}
	pci_bus_res[bus].privdata = NULL;
}

/*
 * Recursively enumerate all PCI devices on and below the given bus.
 * For each bridge discovered, recurse into its secondary bus.  On
 * unwind, accumulate resource requirements (BAR sizes + child bridge
 * needs) and count hotplug-capable bridges.
 */
static void
enumerate_bus_devs(dev_info_t *rcdip, uchar_t bus,
    struct pci_bus_resource *pci_bus_res)
{
	uchar_t dev, func, nfunc, header;

	if (bus_debug(bus))
		ddev_err(rcdip, CE_NOTE, "pci_boot: enumerating pci bus 0x%x", bus);

	for (dev = 0; dev < max_dev_pci; dev++) {
		nfunc = 1;
		for (func = 0; func < nfunc; func++) {
			ushort_t venid = pci_cfgacc_get16(rcdip,
			    PCI_GETBDF(bus, dev, func), PCI_CONF_VENID);
			ushort_t devid = pci_cfgacc_get16(rcdip,
			    PCI_GETBDF(bus, dev, func), PCI_CONF_DEVID);
			if ((venid != 0xffff) && (venid != 0x0))
				ddev_err(rcdip, CE_NOTE, "pci_boot: pci%x,%x at %x:%x:%x",
				    venid, devid, bus, dev, func);
			if ((venid == 0xffff) || (venid == 0)) {
				/* no function at this address */
				continue;
			}

			header = pci_cfgacc_get8(rcdip,
			    PCI_GETBDF(bus, dev, func), PCI_CONF_HEADER);
			if (header == 0xff) {
				ddev_err(rcdip, CE_NOTE, "pci_boot: %x:%x:%x has no header",
				    bus, dev, func);
				continue; /* illegal value */
			}

			/*
			 * according to some mail from Microsoft posted
			 * to the pci-drivers alias, their only requirement
			 * for a multifunction device is for the 1st
			 * function to have to PCI_HEADER_MULTI bit set.
			 */
			if ((func == 0) && (header & PCI_HEADER_MULTI)) {
				nfunc = 8;
			}

			{
				int secbus;

				/*
				 * Create the node.  It may still need
				 * resource assignment, which will be
				 * done by reprogram_bus_devs().
				 */
				secbus = process_devfunc(rcdip, pci_bus_res,
				    bus, dev, func, CONFIG_INFO);

				/*
				 * If this device is a bridge, recurse into
				 * the secondary bus immediately.  By the time
				 * process_devfunc returns, add_ppb_props has
				 * already set up pci_bus_res[secbus].
				 */
				if (secbus >= 0 &&
				    (uchar_t)secbus <= pci_boot_maxbus) {
					enumerate_bus_devs(rcdip,
					    (uchar_t)secbus, pci_bus_res);
				}

			}
		}
	}

	/*
	 * All devices on this bus and all child bridge subtrees have
	 * now been enumerated.  Accumulate the resource requirements
	 * for this bus: start with the BAR sizes gathered during
	 * CONFIG_INFO, then add each child bridge's requirements
	 * (rounded up to bridge window alignment), and count
	 * hotplug-capable bridges.
	 *
	 * Because we recurse depth-first, child buses have already
	 * completed their accumulation by the time we reach this
	 * point -- leaves-first ordering is guaranteed by the
	 * call stack.
	 */
	{
		struct pci_bus_resource *pbr = &pci_bus_res[bus];
		int i;

		pbr->mem_required = pbr->mem_size;
		pbr->io_required = pbr->io_size;
		pbr->pmem_required = pbr->pmem_size;
		pbr->num_hp_bridges = 0;

		for (i = 0; i <= pci_boot_maxbus; i++) {
			if (pci_bus_res[i].par_bus != bus)
				continue;
			if (pci_bus_res[i].dip == NULL)
				continue;

			pbr->mem_required += P2ROUNDUP(
			    pci_bus_res[i].mem_required, PPB_MEM_ALIGNMENT);
			pbr->io_required += P2ROUNDUP(
			    pci_bus_res[i].io_required, PPB_IO_ALIGNMENT);
			pbr->pmem_required += P2ROUNDUP(
			    pci_bus_res[i].pmem_required, PPB_MEM_ALIGNMENT);
			pbr->num_hp_bridges += pci_bus_res[i].num_hp_bridges;
		}

		/*
		 * Check whether this bus's bridge is hotplug-capable.
		 * Only bridges (not root buses) can be hotplug-capable.
		 */
		if (pbr->par_bus != NO_PAR_BUS) {
			int *regp;
			uint_t reglen;
			uchar_t bbus, bdev, bfunc;
			int rv;

			rv = ddi_prop_lookup_int_array(DDI_DEV_T_ANY,
			    pbr->dip, DDI_PROP_DONTPASS, OBP_REG,
			    &regp, &reglen);
			if (rv == DDI_PROP_SUCCESS && reglen > 0) {
				bfunc = (uchar_t)PCI_REG_FUNC_G(regp[0]);
				bdev = (uchar_t)PCI_REG_DEV_G(regp[0]);
				bbus = (uchar_t)PCI_REG_BUS_G(regp[0]);
				ddi_prop_free(regp);

				if (bridge_is_hotplug_capable(rcdip, bbus,
				    bdev, bfunc)) {
					pbr->num_hp_bridges++;
					ddev_err(rcdip, CE_NOTE,
					    MSGHDR "hotplug-capable",
					    ddi_node_name(pbr->dip),
					    bbus, bdev, bfunc);
				}
			} else if (rv == DDI_PROP_SUCCESS) {
				ddi_prop_free(regp);
			}
		}

		ddev_err(rcdip, CE_NOTE,
		    "pci_boot: bus 0x%02x requirements: "
		    "mem 0x%lx, io 0x%lx, pmem 0x%lx, hp_bridges %u",
		    bus, pbr->mem_required, pbr->io_required,
		    pbr->pmem_required, pbr->num_hp_bridges);
	}
}

static void
set_devpm_d0(dev_info_t *rcdip, uchar_t bus, uchar_t dev, uchar_t func)
{
	uint16_t status;
	uint8_t header;
	uint8_t cap_ptr;
	uint8_t cap_id;
	uint16_t pmcsr;

	status = pci_cfgacc_get16(rcdip, PCI_GETBDF(bus, dev, func),
	    PCI_CONF_STAT);
	if (!(status & PCI_STAT_CAP))
		return;	/* No capabilities list */

	header = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
	    PCI_CONF_HEADER) & PCI_HEADER_TYPE_M;
	if (header == PCI_HEADER_CARDBUS) {
		cap_ptr = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
		    PCI_CBUS_CAP_PTR);
	} else {
		cap_ptr = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
		    PCI_CONF_CAP_PTR);
	}
	/*
	 * Walk the capabilities list searching for a PM entry.
	 */
	while (cap_ptr != PCI_CAP_NEXT_PTR_NULL && cap_ptr >= PCI_CAP_PTR_OFF) {
		cap_ptr &= PCI_CAP_PTR_MASK;
		cap_id = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
		    cap_ptr + PCI_CAP_ID);
		if (cap_id == PCI_CAP_ID_PM) {
			pmcsr = pci_cfgacc_get16(rcdip,
			    PCI_GETBDF(bus, dev, func), cap_ptr + PCI_PMCSR);
			pmcsr &= ~(PCI_PMCSR_STATE_MASK);
			pmcsr |= PCI_PMCSR_D0; /* D0 state */
			pci_cfgacc_put16(rcdip, PCI_GETBDF(bus, dev, func),
			    cap_ptr + PCI_PMCSR, pmcsr);
			break;
		}
		cap_ptr = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
		    cap_ptr + PCI_CAP_NEXT_PTR);
	}

}

static int
process_devfunc(dev_info_t *rcdip, struct pci_bus_resource *pci_bus_res,
    uchar_t bus, uchar_t dev, uchar_t func, config_phase_t config_op)
{
	pci_prop_data_t prop_data;
	pci_prop_failure_t prop_ret;
	dev_info_t *dip = NULL;
	struct pci_devfunc *devlist = NULL, *entry = NULL;
	int secbus = -1;
	int power[2] = {1, 1};
	pcie_req_id_t bdf;

	prop_ret = pci_prop_data_fill(rcdip, NULL, bus, dev, func, &prop_data);
	if (prop_ret != PCI_PROP_OK) {
		dev_err(rcdip, CE_WARN, MSGHDR "failed to get basic PCI data: 0x%x",
		    ddi_node_name(rcdip), bus, dev, func, prop_ret);
		return (-1);
	}

	VERIFY3P(pci_bus_res[bus].dip, !=, NULL);

	/*
	 * There may be be nodes below the root complex in the device tree
	 * already, passed to us from firmware.  However, these nodes are not
	 * necessarily complete, we are expected to merge information from the
	 * bus with the information from firmware.
	 *
	 * We do this matching based on PCI unit address, matching device and
	 * function (we search below the parent dip, so we know bus must
	 * match).
	 */
	ndi_devi_enter(pci_bus_res[bus].dip);
	for (dev_info_t *firmdip = ddi_get_child(pci_bus_res[bus].dip);
	    firmdip != NULL;
	    firmdip = ddi_get_next_sibling(firmdip)) {
		pci_regspec_t *regs;
		uint_t regsz;
		uint16_t child_dev = 0;
		uint16_t child_func = 0;

		if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, firmdip,
		    DDI_PROP_DONTPASS, OBP_REG,
		    (int **)&regs, &regsz) == DDI_SUCCESS) {
			child_dev = (regs->pci_phys_hi & PCI_REG_DEV_M) >>
			    PCI_REG_DEV_SHIFT;
			child_func = (regs->pci_phys_hi & PCI_REG_FUNC_M) >>
			    PCI_REG_FUNC_SHIFT;

			ddi_prop_free(regs);
		}

		if ((child_dev == dev) && (child_func == func)) {
			dip = firmdip;
		}
	}
	ndi_devi_exit(pci_bus_res[bus].dip);

	if (dip == NULL) {
		ndi_devi_alloc_sleep(pci_bus_res[bus].dip, DEVI_PSEUDO_NEXNAME,
		    DEVI_SID_NODEID, &dip);
		prop_ret = pci_prop_name_node(dip, &prop_data);
		if (prop_ret != PCI_PROP_OK) {
			dev_err(rcdip, CE_WARN, MSGHDR "failed to set node "
			    "name: 0x%x; devinfo node not created",
			    ddi_node_name(rcdip), bus, dev, func, prop_ret);
			(void) ndi_devi_free(dip);
			return (-1);
		}
	}

	bdf = PCI_GETBDF(bus, dev, func);

	/*
	 * Only populate bus_t if this device is sitting under a PCIE root
	 * complex.  Some particular machines have both a PCIE root complex and
	 * a PCI hostbridge, in which case only devices under the PCIE root
	 * complex will have their bus_t populated.
	 */
	if (pcie_get_rc_dip(dip) != NULL) {
		(void) pcie_init_bus(dip, bdf, PCIE_BUS_INITIAL);
	}

	/*
	 * Go through and set all of the devinfo proprties on this function.
	 */
	prop_ret = pci_prop_set_common_props(dip, &prop_data);
	if (prop_ret != PCI_PROP_OK) {
		dev_err(rcdip, CE_WARN, MSGHDR "failed to set properties: 0x%x; "
		    "devinfo node not created", ddi_node_name(rcdip), bus, dev,
		    func, prop_ret);
		if (pcie_get_rc_dip(dip) != NULL) {
			pcie_fini_bus(dip, PCIE_BUS_FINAL);
		}
		(void) ndi_devi_free(dip);
		return (-1);
	}

	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip,
	    "power-consumption", power, 2);

	/* Set the device PM state to D0 */
	set_devpm_d0(rcdip, bus, dev, func);

	if (pci_prop_class_is_pcibridge(&prop_data)) {
		boolean_t pciex = (prop_data.ppd_flags & PCI_PROP_F_PCIE) != 0;
		boolean_t is_pci_bridge = pciex &&
		    prop_data.ppd_pcie_type == PCIE_PCIECAP_DEV_TYPE_PCIE2PCI;
		add_ppb_props(rcdip, dip, pci_bus_res, bus, dev, func, pciex,
		    is_pci_bridge);
		secbus = (int)pci_cfgacc_get8(rcdip,
		    PCI_GETBDF(bus, dev, func), PCI_BCNF_SECBUS);
	}

	/*
	 * Record all devices on the bus for BAR reprogramming at the
	 * 2nd (CONFIG_NEW) bus enumeration pass.  Bridge forwarding
	 * windows are programmed separately in allocate_bridge_resources(),
	 * but bridge device BARs (Type 1 header BAR0/BAR1) are parent-bus
	 * resources and must be reprogrammed from the bus's busra pool
	 * alongside leaf device BARs.  add_reg_props() handles the
	 * Type 1 header correctly (PCI_BCNF_BASE_NUM limits probing to
	 * BAR0/BAR1 only).
	 */
	devlist = (struct pci_devfunc *)pci_bus_res[bus].privdata;
	entry = kmem_zalloc(sizeof (*entry), KM_SLEEP);
	entry->dip = dip;
	entry->dev = dev;
	entry->func = func;
	entry->next = devlist;
	pci_bus_res[bus].privdata = entry;

	prop_ret = pci_prop_set_compatible(dip, &prop_data);
	if (prop_ret != PCI_PROP_OK) {
		dev_err(rcdip, CE_WARN, MSGHDR "failed to set compatible property: "
		    "0x%x;  device may not bind to a driver",
		    ddi_node_name(rcdip), bus, dev, func, prop_ret);
	}

	DEVI_SET_PCI(dip);
	add_reg_props(rcdip, dip, pci_bus_res, bus, dev, func,
	    config_op);
	(void) ndi_devi_bind_driver(dip, 0);

	return (secbus);
}

/*
 * Where op is one of:
 *   CONFIG_INFO	- first pass, gather what is there.
 *   CONFIG_NEW		- second pass, allocate regions.
 * Returns:
 *	-1	Skip this BAR (BAR does not exist / size is 0)
 *	 0	BAR exists but allocation failed; reg entry populated,
 *		assigned-addresses entry skipped, BAR disabled in hardware
 *	 1	Properties have been assigned, reprogramming required
 */
static int
add_bar_reg_props(dev_info_t *rcdip, struct pci_bus_resource *pci_bus_res,
    config_phase_t op, uchar_t bus, uchar_t dev, uchar_t func, uint_t bar,
    ushort_t offset, pci_regspec_t *regs, pci_regspec_t *assigned,
    ushort_t *bar_sz)
{
	uint8_t baseclass;
	uint32_t base, devloc;
	uint16_t command = 0;
	uint64_t value;

	devloc = PCI_REG_MAKE_BDFR(bus, dev, func, 0);
	baseclass = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
	    PCI_CONF_BASCLASS);

	/*
	 * Determine the size of the BAR by writing 0xffffffff to the base
	 * register and reading the value back before restoring the original.
	 *
	 * For non-bridges, disable I/O and Memory access while doing this to
	 * avoid difficulty with USB emulation (see OHCI spec1.0a appendix B
	 * "Host Controller Mapping"). Doing this for bridges would have the
	 * side-effect of making the bridge transparent to secondary-bus
	 * activity (see sections 4.1-4.3 of the PCI-PCI Bridge Spec V1.2).
	 */
	base = pci_cfgacc_get32(rcdip, PCI_GETBDF(bus, dev, func), offset);

	if (baseclass != PCI_CLASS_BRIDGE) {
		command = pci_cfgacc_get16(rcdip, PCI_GETBDF(bus, dev, func),
		    PCI_CONF_COMM);
		pci_cfgacc_put16(rcdip, PCI_GETBDF(bus, dev, func),
		    PCI_CONF_COMM, command & ~(PCI_COMM_MAE | PCI_COMM_IO));
	}

	pci_cfgacc_put32(rcdip, PCI_GETBDF(bus, dev, func), offset, 0xffffffff);
	value = pci_cfgacc_get32(rcdip, PCI_GETBDF(bus, dev, func), offset);
	pci_cfgacc_put32(rcdip, PCI_GETBDF(bus, dev, func), offset, base);

	if (baseclass != PCI_CLASS_BRIDGE) {
		pci_cfgacc_put16(rcdip, PCI_GETBDF(bus, dev, func),
		    PCI_CONF_COMM, command);
	}

	/* I/O Space */
	if ((base & PCI_BASE_SPACE_IO) != 0) {
		uint_t type, len;

		*bar_sz = PCI_BAR_SZ_32;
		value &= PCI_BASE_IO_ADDR_M;
		len = BARMASKTOLEN(value);

		if (value == 0) {
			/* skip base regs with size of 0 */
			return (-1);
		}

		regs->pci_phys_hi = PCI_ADDR_IO | devloc;
		regs->pci_phys_hi |= offset;
		regs->pci_phys_low = 0;
		assigned->pci_phys_hi = PCI_RELOCAT_B | regs->pci_phys_hi;
		regs->pci_size_low = assigned->pci_size_low = len;

		/*
		 * 'type' holds the non-address part of the base to be re-added
		 * to any new address in the programming step below.
		 */
		type = base & ~PCI_BASE_IO_ADDR_M;
		base &= PCI_BASE_IO_ADDR_M;

		if (op == CONFIG_INFO) {	/* first pass */
			ddev_err(rcdip, CE_NOTE,
			    MSGHDR "BAR%u I/O FWINIT 0x%x ~ 0x%x "
			    "(ignored)", ddi_node_name(rcdip),
			    bus, dev, func, bar, base, len);
			pci_bus_res[bus].io_size += len;
		} else {
			/*
			 * Allocate IO from the bus dip's busra map.
			 */
			ndi_ra_request_t ra_req = {0};
			uint64_t ra_base, ra_len;

			ra_req.ra_len = len;
			ra_req.ra_align_mask = len - 1;
			if (ndi_ra_alloc(pci_bus_res[bus].dip,
			    &ra_req, &ra_base, &ra_len,
			    NDI_RA_TYPE_IO, 0) == NDI_SUCCESS) {
				base = (uint32_t)ra_base;
			} else {
				base = 0;
			}
			if (base == 0) {
				dev_err(rcdip, CE_WARN, MSGHDR "BAR%u I/O "
				    "failed to find length 0x%x",
				    ddi_node_name(rcdip), bus, dev, func, bar,
				    len);
				/*
				 * Disable the BAR and skip the
				 * assigned-addresses entry so drivers
				 * that do not need this BAR can still
				 * attach.
				 */
				pci_cfgacc_put32(rcdip,
				    PCI_GETBDF(bus, dev, func),
				    offset, 0);
				return (0);
			} else {
				uint32_t nbase;

				ddev_err(rcdip, CE_NOTE, MSGHDR "BAR%u  "
				    "I/O REPROG 0x%x ~ 0x%x",
				    ddi_node_name(rcdip), bus, dev, func,
				    bar, base, len);
				pci_cfgacc_put32(rcdip,
				    PCI_GETBDF(bus, dev, func),
				    offset, base | type);
				nbase = pci_cfgacc_get32(rcdip,
				    PCI_GETBDF(bus, dev, func), offset);
				nbase &= PCI_BASE_IO_ADDR_M;

				if (base != nbase) {
					dev_err(rcdip, CE_NOTE, MSGHDR "BAR%u  "
					    "I/O REPROG 0x%x ~ 0x%x "
					    "FAILED READBACK 0x%x",
					    ddi_node_name(rcdip), bus, dev,
					    func, bar, base, len, nbase);
					pci_cfgacc_put32(rcdip,
					    PCI_GETBDF(bus, dev, func),
					    offset, 0);
					if (baseclass != PCI_CLASS_BRIDGE) {
						/* Disable PCI_COMM_IO bit */
						command =
						    pci_cfgacc_get16(rcdip,
						    PCI_GETBDF(bus, dev, func),
						    PCI_CONF_COMM);
						command &= ~PCI_COMM_IO;
						pci_cfgacc_put16(rcdip,
						    PCI_GETBDF(bus, dev, func),
						    PCI_CONF_COMM, command);
					}
					/*
					 * Return failed alloc to busra.
					 */
					(void) ndi_ra_free(
					    pci_bus_res[bus].dip,
					    base, len,
					    NDI_RA_TYPE_IO, 0);
					return (0);
				}
			}
		}
		assigned->pci_phys_low = base;

	} else {	/* Memory space */
		uint_t type, base_hi, phys_hi;
		uint64_t len, fbase;

		if ((base & PCI_BASE_TYPE_M) == PCI_BASE_TYPE_ALL) {
			*bar_sz = PCI_BAR_SZ_64;
			base_hi = pci_cfgacc_get32(rcdip,
			    PCI_GETBDF(bus, dev, func), offset + 4);
			pci_cfgacc_put32(rcdip, PCI_GETBDF(bus, dev, func),
			    offset + 4, 0xffffffff);
			value |= (uint64_t)pci_cfgacc_get32(rcdip,
			    PCI_GETBDF(bus, dev, func), offset + 4) << 32;
			pci_cfgacc_put32(rcdip, PCI_GETBDF(bus, dev, func),
			    offset + 4, base_hi);
			phys_hi = PCI_ADDR_MEM64;
			value &= PCI_BASE_M_ADDR64_M;
		} else {
			*bar_sz = PCI_BAR_SZ_32;
			base_hi = 0;
			phys_hi = PCI_ADDR_MEM32;
			value &= PCI_BASE_M_ADDR_M;
		}

		/* skip base regs with size of 0 */
		if (value == 0)
			return (-1);

		len = BARMASKTOLEN(value);
		regs->pci_size_low = assigned->pci_size_low = len & 0xffffffff;
		regs->pci_size_hi = assigned->pci_size_hi = len >> 32;

		phys_hi |= devloc | offset;
		if (base & PCI_BASE_PREF_M)
			phys_hi |= PCI_PREFETCH_B;

		regs->pci_phys_hi = assigned->pci_phys_hi = phys_hi;
		assigned->pci_phys_hi |= PCI_RELOCAT_B;

		/*
		 * 'type' holds the non-address part of the base to be re-added
		 * to any new address in the programming step below.
		 */
		type = base & ~PCI_BASE_M_ADDR_M;
		base &= PCI_BASE_M_ADDR_M;

		fbase = (((uint64_t)base_hi) << 32) | base;
		if (op == CONFIG_INFO) {
			ddev_err(rcdip, CE_NOTE,
			    MSGHDR "BAR%u %sMEM FWINIT 0x%lx ~ 0x%lx%s "
			    "(ignored)",
			    ddi_node_name(rcdip), bus, dev, func, bar,
			    (phys_hi & PCI_PREFETCH_B) ? "P" : " ",
			    fbase, len,
			    *bar_sz == PCI_BAR_SZ_64 ? " (64-bit)" : "");

			if (phys_hi & PCI_PREFETCH_B)
				pci_bus_res[bus].pmem_size += len;
			else
				pci_bus_res[bus].mem_size += len;

			pci_bar_relocate_match(fbase, len,
			    bus, dev, func, bar);
			pci_bar_relocate_notify(
			    PCI_BAR_PRE_RELOCATE,
			    bus, dev, func, bar,
			    fbase, 0, len);
		} else {
			boolean_t pf = B_FALSE;
			uint64_t fbase_fw = fbase;
			fbase = 0;

			/*
			 * Allocate MEM from the bus dip's busra map.
			 * Try prefetchable first if requested.
			 */
			ndi_ra_request_t ra_req = {0};
			uint64_t ra_base, ra_len;

			ra_req.ra_len = len;
			ra_req.ra_align_mask = len - 1;

			if ((phys_hi & PCI_PREFETCH_B) != 0) {
				if (ndi_ra_alloc(pci_bus_res[bus].dip,
				    &ra_req, &ra_base, &ra_len,
				    NDI_RA_TYPE_PCI_PREFETCH_MEM,
				    0) == NDI_SUCCESS) {
					fbase = ra_base;
					pf = B_TRUE;
				}
			}
			/*
			 * If prefetchable allocation was not desired, or
			 * failed, attempt ordinary memory allocation.
			 * Bound to 32-bit address space for non-PF.
			 */
			if (fbase == 0) {
				ra_req.ra_flags = NDI_RA_ALLOC_BOUNDED;
				ra_req.ra_boundbase = PPB_MEM_ALIGNMENT;
				ra_req.ra_boundlen =
				    (uint64_t)UINT32_MAX -
				    PPB_MEM_ALIGNMENT + 1;
				if (ndi_ra_alloc(pci_bus_res[bus].dip,
				    &ra_req, &ra_base, &ra_len,
				    NDI_RA_TYPE_MEM,
				    0) == NDI_SUCCESS) {
					fbase = ra_base;
				}
			}

			base_hi = fbase >> 32;
			base = fbase & 0xffffffff;

			if (fbase == 0) {
				dev_err(rcdip, CE_WARN, MSGHDR "BAR%u MEM "
				    "failed to find length 0x%lx",
				    ddi_node_name(rcdip), bus, dev, func,
				    bar, len);
				/*
				 * Disable the BAR and skip the
				 * assigned-addresses entry so drivers
				 * that do not need this BAR can still
				 * attach.
				 */
				pci_cfgacc_put32(rcdip,
				    PCI_GETBDF(bus, dev, func),
				    offset, 0);
				if (*bar_sz == PCI_BAR_SZ_64) {
					pci_cfgacc_put32(rcdip,
					    PCI_GETBDF(bus, dev, func),
					    offset + 4, 0);
				}
				pci_bar_relocate_notify(
				    PCI_BAR_POST_RELOCATE,
				    bus, dev, func, bar,
				    fbase_fw, 0, len);
				return (0);
			} else {
				uint64_t nbase, nbase_hi = 0;

				ddev_err(rcdip, CE_NOTE, MSGHDR "BAR%u "
				    "%s%s REPROG 0x%lx ~ 0x%lx",
				    ddi_node_name(rcdip), bus, dev, func, bar,
				    pf ? "PMEM" : "MEM",
				    *bar_sz == PCI_BAR_SZ_64 ? "64" : "",
				    fbase, len);
				pci_cfgacc_put32(rcdip,
				    PCI_GETBDF(bus, dev, func),
				    offset, base | type);
				nbase = pci_cfgacc_get32(rcdip,
				    PCI_GETBDF(bus, dev, func), offset);

				if (*bar_sz == PCI_BAR_SZ_64) {
					pci_cfgacc_put32(rcdip,
					    PCI_GETBDF(bus, dev, func),
					    offset + 4, base_hi);
					nbase_hi = pci_cfgacc_get32(rcdip,
					    PCI_GETBDF(bus, dev, func),
					    offset + 4);
				}

				nbase &= PCI_BASE_M_ADDR_M;

				if (base != nbase || base_hi != nbase_hi) {
					pci_bar_relocate_notify(
					    PCI_BAR_POST_RELOCATE,
					    bus, dev, func, bar,
					    fbase_fw, 0, len);
					dev_err(rcdip, CE_NOTE, MSGHDR "BAR%u "
					    "%s%s REPROG 0x%lx ~ 0x%lx "
					    "FAILED READBACK 0x%lx",
					    ddi_node_name(rcdip), bus, dev,
					    func, bar, pf ? "PMEM" : "MEM",
					    *bar_sz == PCI_BAR_SZ_64 ?
					    "64" : "",
					    fbase, len,
					    nbase_hi << 32 | nbase);

					pci_cfgacc_put32(rcdip,
					    PCI_GETBDF(bus, dev, func),
					    offset, 0);
					if (*bar_sz == PCI_BAR_SZ_64) {
						pci_cfgacc_put32(rcdip,
						    PCI_GETBDF(bus, dev, func),
						    offset + 4, 0);
					}

					if (baseclass != PCI_CLASS_BRIDGE) {
						/* Disable PCI_COMM_MAE bit */
						command =
						    pci_cfgacc_get16(rcdip,
						    PCI_GETBDF(bus, dev,
						    func), PCI_CONF_COMM);
						command &= ~PCI_COMM_MAE;
						pci_cfgacc_put16(rcdip,
						    PCI_GETBDF(bus, dev, func),
						    PCI_CONF_COMM, command);
					}

					/*
					 * Return failed alloc to busra.
					 */
					(void) ndi_ra_free(
					    pci_bus_res[bus].dip,
					    fbase, len,
					    pf ? NDI_RA_TYPE_PCI_PREFETCH_MEM :
					    NDI_RA_TYPE_MEM, 0);
					return (0);
				}

				pci_bar_relocate_notify(
				    PCI_BAR_POST_RELOCATE,
				    bus, dev, func, bar,
				    fbase_fw, fbase, len);
			}
		}

		assigned->pci_phys_mid = base_hi;
		assigned->pci_phys_low = base;
	}

	ddev_err(rcdip, CE_NOTE, MSGHDR "BAR%u ---- %08x.%x.%x.%x.%x",
	    ddi_node_name(rcdip), bus, dev, func, bar,
	    assigned->pci_phys_hi,
	    assigned->pci_phys_mid,
	    assigned->pci_phys_low,
	    assigned->pci_size_hi,
	    assigned->pci_size_low);

	return (1);
}

/*
 * Add the "reg" and "assigned-addresses" property
 */
static void
add_reg_props(dev_info_t *rcdip, dev_info_t *dip,
    struct pci_bus_resource *pci_bus_res, uchar_t bus, uchar_t dev,
    uchar_t func, config_phase_t op)
{
	uchar_t baseclass, subclass, progclass, header;
	uint_t bar, value, devloc, base;
	ushort_t bar_sz, offset, end;
	int max_basereg;

	pci_regspec_t regs[16] = {{0}};
	pci_regspec_t assigned[15] = {{0}};
	int nreg, nasgn;

	devloc = PCI_REG_MAKE_BDFR(bus, dev, func, 0);
	regs[0].pci_phys_hi = devloc;
	nreg = 1;	/* rest of regs[0] is all zero */
	nasgn = 0;

	baseclass = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
	    PCI_CONF_BASCLASS);
	subclass = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
	    PCI_CONF_SUBCLASS);
	progclass = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
	    PCI_CONF_PROGCLASS);
	header = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
	    PCI_CONF_HEADER) & PCI_HEADER_TYPE_M;

	switch (header) {
	case PCI_HEADER_ZERO:
		max_basereg = PCI_BASE_NUM;
		break;
	case PCI_HEADER_PPB:
		max_basereg = PCI_BCNF_BASE_NUM;
		break;
	default:
		max_basereg = 0;
		break;
	}

	end = PCI_CONF_BASE0 + max_basereg * sizeof (uint_t);
	for (bar = 0, offset = PCI_CONF_BASE0; offset < end;
	    bar++, offset += bar_sz) {
		int ret;

		ret = add_bar_reg_props(rcdip, pci_bus_res, op, bus, dev, func,
		    bar, offset, &regs[nreg], &assigned[nasgn], &bar_sz);

		if (bar_sz == PCI_BAR_SZ_64)
			bar++;

		if (ret == -1)		/* Skip BAR */
			continue;

		nreg++;
		if (ret > 0)	/* allocation succeeded */
			nasgn++;
	}

	switch (header) {
	case PCI_HEADER_ZERO:
		offset = PCI_CONF_ROM;
		break;
	case PCI_HEADER_PPB:
		offset = PCI_BCNF_ROM;
		break;
	default: /* including PCI_HEADER_CARDBUS */
		goto done;
	}

	/*
	 * Expansion ROM BAR.
	 *
	 * Size the ROM by writing the address mask and reading back.
	 * Bit 0 of the read-back indicates the device has a ROM.
	 */
	base = pci_cfgacc_get32(rcdip, PCI_GETBDF(bus, dev, func), offset);
	pci_cfgacc_put32(rcdip, PCI_GETBDF(bus, dev, func),
	    offset, PCI_BASE_ROM_ADDR_M);
	value = pci_cfgacc_get32(rcdip, PCI_GETBDF(bus, dev, func), offset);
	pci_cfgacc_put32(rcdip, PCI_GETBDF(bus, dev, func), offset, base);
	if (value & PCI_BASE_ROM_ENABLE)
		value &= PCI_BASE_ROM_ADDR_M;
	else
		value = 0;

	if (value != 0) {
		uint_t len = BARMASKTOLEN(value);

		regs[nreg].pci_phys_hi = (PCI_ADDR_MEM32 | devloc) + offset;
		regs[nreg].pci_size_low = len;
		nreg++;

		if (op == CONFIG_INFO) {
			/*
			 * First pass: just account for the ROM size so
			 * bridge windows are sized to include it.
			 */
			pci_bus_res[bus].mem_size += len;
		} else {
			/*
			 * Second pass: allocate ROM space from the bus's
			 * MEM pool via busra.  ROM BARs are always
			 * non-prefetchable MEM32.
			 */
			ndi_ra_request_t ra_req = {0};
			uint64_t ra_base, ra_len;

			ra_req.ra_len = len;
			ra_req.ra_align_mask = len - 1;
			ra_req.ra_flags = NDI_RA_ALLOC_BOUNDED;
			ra_req.ra_boundbase = PPB_MEM_ALIGNMENT;
			ra_req.ra_boundlen =
			    (uint64_t)UINT32_MAX - PPB_MEM_ALIGNMENT + 1;

			if (ndi_ra_alloc(pci_bus_res[bus].dip,
			    &ra_req, &ra_base, &ra_len,
			    NDI_RA_TYPE_MEM, 0) == NDI_SUCCESS) {
				uint32_t rom_val;

				rom_val = (uint32_t)ra_base &
				    PCI_BASE_ROM_ADDR_M;
				/*
				 * Preserve the firmware ROM enable
				 * bit; if firmware had decode off,
				 * the driver can enable it later.
				 */
				if (base & PCI_BASE_ROM_ENABLE)
					rom_val |= PCI_BASE_ROM_ENABLE;
				pci_cfgacc_put32(rcdip,
				    PCI_GETBDF(bus, dev, func),
				    offset, rom_val);

				ddev_err(rcdip, CE_NOTE,
				    MSGHDR "ROM REPROG 0x%lx ~ 0x%x",
				    ddi_node_name(rcdip),
				    bus, dev, func,
				    ra_base, len);

				assigned[nasgn].pci_phys_hi =
				    (PCI_RELOCAT_B | PCI_ADDR_MEM32 |
				    devloc) + offset;
				assigned[nasgn].pci_phys_low =
				    (uint32_t)ra_base;
				assigned[nasgn].pci_size_low = len;
				nasgn++;
			} else {
				dev_err(rcdip, CE_WARN,
				    MSGHDR "ROM failed to allocate "
				    "0x%x bytes",
				    ddi_node_name(rcdip),
				    bus, dev, func, len);
				/*
				 * Disable ROM decode.
				 */
				pci_cfgacc_put32(rcdip,
				    PCI_GETBDF(bus, dev, func),
				    offset, 0);
			}
		}
	}

	/*
	 * Legacy VGA alias resources (IO 0x3b0-0x3bb, 0x3c0-0x3df, MEM
	 * 0xa0000-0xbffff) and 8514/A ranges are x86 ISA hard-decodes.
	 * These do not exist on Arm - no device responds to these fixed
	 * addresses. We must not add them as reg properties.  Just note
	 * the device class for diagnostic purposes.
	 */
	if ((baseclass == PCI_CLASS_DISPLAY && subclass == PCI_DISPLAY_VGA) ||
	    (baseclass == PCI_CLASS_NONE && subclass == PCI_NONE_VGA)) {
		ddev_err(rcdip, CE_NOTE, MSGHDR "VGA class device: legacy alias "
		    "ranges are not applicable on Arm",
		    ddi_node_name(dip), bus, dev, func);
	}

	if ((baseclass == PCI_CLASS_DISPLAY) &&
	    (subclass == PCI_DISPLAY_VGA) &&
	    (progclass & PCI_DISPLAY_IF_8514)) {
		ddev_err(rcdip, CE_NOTE, MSGHDR "8514/A compat: legacy alias "
		    "ranges are not applicable on Arm",
		    ddi_node_name(dip), bus, dev, func);
	}

done:
	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip, OBP_REG,
	    (int *)regs, nreg * sizeof (pci_regspec_t) / sizeof (int));
	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip,
	    "assigned-addresses",
	    (int *)assigned, nasgn * sizeof (pci_regspec_t) / sizeof (int));
}

static void
add_ppb_props(dev_info_t *rcdip, dev_info_t *dip,
    struct pci_bus_resource *pci_bus_res, uchar_t bus, uchar_t dev,
    uchar_t func, boolean_t pciex, boolean_t is_pci_bridge)
{
	char *dev_type;
	int i;
	uint_t cmd_reg;
	uint16_t bcntrl;
	struct {
		uint64_t base;
		uint64_t limit;
	} io, mem, pmem;
	uchar_t secbus, subbus;
	uchar_t progclass;

	secbus = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
	    PCI_BCNF_SECBUS);
	subbus = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
	    PCI_BCNF_SUBBUS);

	ASSERT3U(secbus, <=, subbus);
	ASSERT3P(pci_bus_res[secbus].dip, ==, NULL);
	pci_bus_res[secbus].dip = dip;
	pci_bus_res[secbus].par_bus = bus;

	/*
	 * Check if it's a subtractive PPB.
	 */
	progclass = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
	    PCI_CONF_PROGCLASS);
	if (progclass == PCI_BRIDGE_PCI_IF_SUBDECODE)
		pci_bus_res[secbus].subtractive = B_TRUE;

	dev_type = (pciex && !is_pci_bridge) ? "pciex" : "pci";

	/* set up bus number hierarchy */
	pci_bus_res[secbus].sub_bus = subbus;
	/*
	 * Keep track of the largest subordinate bus number (this is essential
	 * for peer buses because there is no other way of determining its
	 * subordinate bus number).
	 */
	if (subbus > pci_bus_res[bus].sub_bus)
		pci_bus_res[bus].sub_bus = subbus;
	/*
	 * Loop through subordinate buses, initializing their parent bus
	 * field to this bridge's parent.  The subordinate buses' parent
	 * fields may very well be further refined later, as child bridges
	 * are enumerated.  (The value is to note that the subordinate buses
	 * are not peer buses by changing their par_bus fields to anything
	 * other than -1.)
	 */
	for (i = secbus + 1; i <= subbus; i++)
		pci_bus_res[i].par_bus = bus;

	/*
	 * Update the number of bridges on the bus.
	 */
	if (!is_pci_bridge)
		pci_bus_res[bus].num_bridge++;

	(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip,
	    OBP_DEVICETYPE, dev_type);
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    OBP_ADDRESS_CELLS, 3);
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    OBP_SIZE_CELLS, 2);

	/*
	 * Read firmware's bridge window state.  The FWINIT diagnostic
	 * lines log the initial values for comparison against what
	 * allocate_bridge_resources() programs later.
	 *
	 * Windows that firmware left unconfigured (command register
	 * decode bits clear, or zero base) are explicitly disabled
	 * here (base > limit) so they do not shadow addresses that
	 * busra may allocate for other devices.  They will only be
	 * re-enabled if allocate_bridge_resources() assigns real
	 * resources to them.
	 *
	 * Per the PPB spec, programming the base register to a value
	 * larger than the limit register disables the window.
	 */

	cmd_reg = pci_cfgacc_get16(rcdip, PCI_GETBDF(bus, dev, func),
	    PCI_CONF_COMM);
	fetch_ppb_res(rcdip, bus, dev, func, RES_IO, &io.base, &io.limit);
	fetch_ppb_res(rcdip, bus, dev, func, RES_MEM, &mem.base, &mem.limit);
	fetch_ppb_res(rcdip, bus, dev, func, RES_PMEM, &pmem.base, &pmem.limit);

	ddev_err(rcdip, CE_NOTE, MSGHDR " I/O FWINIT 0x%lx ~ 0x%lx%s",
	    ddi_node_name(dip), bus, dev, func, io.base, io.limit,
	    io.base > io.limit ? " (disabled)" : "");
	ddev_err(rcdip, CE_NOTE, MSGHDR " MEM FWINIT 0x%lx ~ 0x%lx%s",
	    ddi_node_name(dip), bus, dev, func, mem.base, mem.limit,
	    mem.base > mem.limit ? " (disabled)" : "");
	ddev_err(rcdip, CE_NOTE, MSGHDR "PMEM FWINIT 0x%lx ~ 0x%lx%s",
	    ddi_node_name(dip), bus, dev, func, pmem.base, pmem.limit,
	    pmem.base > pmem.limit ? " (disabled)" : "");

	/*
	 * I/O range
	 *
	 * If I/O space is not enabled in the command register, we assume
	 * the window was left unconfigured by firmware.  Disable it
	 * explicitly so the allocator will reconfigure it later.
	 */
	if ((cmd_reg & PCI_COMM_IO) == 0) {
		io.base = PPB_DISABLE_IORANGE_BASE;
		io.limit = PPB_DISABLE_IORANGE_LIMIT;
		set_ppb_res(rcdip, dip, bus, dev, func, RES_IO,
		    io.base, io.limit);
	}

	/*
	 * Memory range
	 *
	 * As for I/O, check Memory Access Enable and also reject a zero
	 * base address (still at PCIe defaults, technically valid but
	 * unlikely on real firmware).
	 */
	if ((cmd_reg & PCI_COMM_MAE) == 0 || mem.base == 0) {
		mem.base = PPB_DISABLE_MEMRANGE_BASE;
		mem.limit = PPB_DISABLE_MEMRANGE_LIMIT;
		set_ppb_res(rcdip, dip, bus, dev, func, RES_MEM,
		    mem.base, mem.limit);
	}

	/*
	 * Prefetchable memory range -- same checks as MEM above.
	 */
	if ((cmd_reg & PCI_COMM_MAE) == 0 || pmem.base == 0) {
		pmem.base = PPB_DISABLE_MEMRANGE_BASE;
		pmem.limit = PPB_DISABLE_MEMRANGE_LIMIT;
		set_ppb_res(rcdip, dip, bus, dev, func, RES_PMEM,
		    pmem.base, pmem.limit);
	}

	/*
	 * Clear VGA_ENABLE (bit 3) and VGA 16-bit decode (bit 4) in the
	 * bridge control register if set by firmware.  These bits make
	 * the bridge unconditionally forward legacy VGA IO (0x3b0-0x3bb,
	 * 0x3c0-0x3df) and MEM (0xa0000-0xbffff) to the secondary bus,
	 * bypassing the normal IO/MEM windows.  On ARM there are no ISA
	 * legacy decodes, so leaving these set would silently swallow
	 * transactions if busra happened to allocate in those ranges.
	 */
	bcntrl = pci_cfgacc_get16(rcdip,
	    PCI_GETBDF(bus, dev, func), PCI_BCNF_BCNTRL);
	if (bcntrl & (PCI_BCNF_BCNTRL_VGA_ENABLE |
	    PCI_BCNF_BCNTRL_VGA_16BIT_DECODE)) {
		ddev_err(rcdip, CE_NOTE,
		    MSGHDR "clearing VGA_ENABLE on bridge",
		    ddi_node_name(dip), bus, dev, func);
		bcntrl &= ~(PCI_BCNF_BCNTRL_VGA_ENABLE |
		    PCI_BCNF_BCNTRL_VGA_16BIT_DECODE);
		pci_cfgacc_put16(rcdip,
		    PCI_GETBDF(bus, dev, func),
		    PCI_BCNF_BCNTRL, bcntrl);
	}

	add_bus_range_prop(pci_bus_res, secbus);
}

/*
 *
 * Insert the "bus-range" property, indicating the buses this node is
 * responsible for.
 */
static void
add_bus_range_prop(struct pci_bus_resource *pci_bus_res, int bus)
{
	int bus_range[2];

	if (pci_bus_res[bus].dip == NULL)
		return;
	bus_range[0] = bus;
	bus_range[1] = pci_bus_res[bus].sub_bus;
	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, pci_bus_res[bus].dip,
	    OBP_BUS_RANGE, (int *)bus_range, 2);
}

/*
 * Handle both PCI root and PCI-PCI bridge range properties;
 * the 'ppb' argument selects PCI-PCI bridges versus root.
 */
static void
add_ranges_prop(dev_info_t *rcdip, struct pci_bus_resource *pci_bus_res,
    int bus)
{
	ppb_ranges_t ranges[3];
	int nranges = 0;
	int *regp;
	uint_t reglen;
	uchar_t parbus, bdev, bfunc;
	uint64_t base, limit;
	int rv;

	/* no devinfo node - unused bus, return */
	if (pci_bus_res[bus].dip == NULL)
		return;

	/*
	 * Read the programmed bridge window registers directly.
	 * After allocate_bridge_resources() programs the windows,
	 * the config registers are the authoritative source.
	 */
	rv = ddi_prop_lookup_int_array(DDI_DEV_T_ANY,
	    pci_bus_res[bus].dip, DDI_PROP_DONTPASS,
	    OBP_REG, &regp, &reglen);
	if (rv != DDI_PROP_SUCCESS || reglen == 0)
		return;
	bfunc = (uchar_t)PCI_REG_FUNC_G(regp[0]);
	bdev = (uchar_t)PCI_REG_DEV_G(regp[0]);
	parbus = (uchar_t)PCI_REG_BUS_G(regp[0]);
	ddi_prop_free(regp);

	/* IO window */
	fetch_ppb_res(rcdip, parbus, bdev, bfunc,
	    RES_IO, &base, &limit);
	if (base <= limit) {
		uint64_t size = limit - base + 1;
		ppb_ranges_t *rp = &ranges[nranges++];

		rp->child_high = rp->parent_high =
		    PCI_ADDR_IO | PCI_RELOCAT_B;
		rp->child_mid = rp->parent_mid =
		    (uint32_t)(base >> 32);
		rp->child_low = rp->parent_low =
		    (uint32_t)base;
		rp->size_high = (uint32_t)(size >> 32);
		rp->size_low = (uint32_t)size;
	}

	/* MEM window */
	fetch_ppb_res(rcdip, parbus, bdev, bfunc,
	    RES_MEM, &base, &limit);
	if (base <= limit) {
		uint64_t size = limit - base + 1;
		ppb_ranges_t *rp = &ranges[nranges++];

		rp->child_high = rp->parent_high =
		    PCI_ADDR_MEM32 | PCI_RELOCAT_B;
		rp->child_mid = rp->parent_mid =
		    (uint32_t)(base >> 32);
		rp->child_low = rp->parent_low =
		    (uint32_t)base;
		rp->size_high = (uint32_t)(size >> 32);
		rp->size_low = (uint32_t)size;
	}

	/* PMEM window */
	fetch_ppb_res(rcdip, parbus, bdev, bfunc,
	    RES_PMEM, &base, &limit);
	if (base <= limit) {
		uint64_t size = limit - base + 1;
		uint32_t type = PCI_ADDR_MEM32 | PCI_RELOCAT_B |
		    PCI_PREFETCH_B;
		ppb_ranges_t *rp = &ranges[nranges++];

		if (base + size - 1 > UINT32_MAX) {
			type &= ~PCI_ADDR_MASK;
			type |= PCI_ADDR_MEM64;
		}
		rp->child_high = rp->parent_high = type;
		rp->child_mid = rp->parent_mid =
		    (uint32_t)(base >> 32);
		rp->child_low = rp->parent_low =
		    (uint32_t)base;
		rp->size_high = (uint32_t)(size >> 32);
		rp->size_low = (uint32_t)size;
	}

	if (nranges == 0)
		return;

	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE,
	    pci_bus_res[bus].dip, OBP_RANGES, (int *)ranges,
	    nranges * sizeof (ppb_ranges_t) / sizeof (int));
}

static void
alloc_res_array(struct pci_bus_resource **pci_bus_res, size_t maxbus)
{
	*pci_bus_res = kmem_zalloc((maxbus + 1) *
	    sizeof (struct pci_bus_resource), KM_SLEEP);
}
