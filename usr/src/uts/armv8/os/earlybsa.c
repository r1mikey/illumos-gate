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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2020 Oxide Computer Company
 * Copyright 2024 Michael van der Westhuizen
 */

/*
 * Routines used by pre-rootnex Base System Architecture hardware support.
 */

#include <sys/types.h>
#include <sys/null.h>
#include <sys/machparam.h>
#include <sys/param.h>
#include <sys/vmem.h>
#include <vm/hat.h>
#include <vm/seg_kmem.h>
#include <sys/smp_impldefs.h>
#if defined(_AARCH64_ACPI)
#include <sys/psm.h>
#include <sys/psm_types.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#endif

#if defined(_AARCH64_ACPI)
static int mach_cpu_create_devinfo(cpu_t *cp, dev_info_t **dipp);

int (*psm_cpu_create_devinfo)(cpu_t *, dev_info_t **) = mach_cpu_create_devinfo;
int (*psm_cpu_get_devinfo)(cpu_t *, dev_info_t **) = NULL;
#endif

/*
 * from startup.c - kernel VA range allocator for device mappings
 */
extern void *device_arena_alloc(size_t size, int vm_flag);
extern void device_arena_free(void * vaddr, size_t size);

caddr_t
psm_map_phys(paddr_t addr, size_t len, int prot)
{
	uint_t pgoffset;
	paddr_t base;
	pgcnt_t npages;
	caddr_t cvaddr;

	if (len == 0)
		return (NULL);

	pgoffset = addr & MMU_PAGEOFFSET;
	base = addr;

	npages = mmu_btopr(len + pgoffset);
	cvaddr = device_arena_alloc(ptob(npages), VM_NOSLEEP);
	if (cvaddr == NULL)
		return (NULL);
	hat_devload(kas.a_hat, cvaddr, mmu_ptob(npages), mmu_btop(base),
	    prot, HAT_LOAD_LOCK);
	return (cvaddr + pgoffset);
}

#if defined(_AARCH64_ACPI)
caddr_t
psm_map_phys_new(paddr_t addr, size_t len, int prot)
{
	return (psm_map_phys(addr, len, prot));
}

caddr_t
psm_map(paddr_t addr, size_t len, int prot)
{
	int phys_prot = PROT_READ;

	ASSERT(prot == (prot & (PSM_PROT_WRITE | PSM_PROT_READ)));
	if (prot & PSM_PROT_WRITE)
		phys_prot |= PROT_WRITE;

        return (psm_map_phys(addr, len, phys_prot));
}

caddr_t
psm_map_new(paddr_t addr, size_t len, int prot)
{
	return (psm_map(addr, len, prot));
}
#endif

void
psm_unmap_phys(caddr_t addr, size_t len)
{
	uint_t pgoffset;
	caddr_t base;
	pgcnt_t npages;

	if (len == 0)
		return;

	pgoffset = (uintptr_t)addr & MMU_PAGEOFFSET;
	base = addr - pgoffset;
	npages = mmu_btopr(len + pgoffset);
	hat_unload(kas.a_hat, base, ptob(npages), HAT_UNLOAD_UNLOCK);
	device_arena_free(base, ptob(npages));
}

#if defined(_AARCH64_ACPI)
void
psm_unmap(caddr_t addr, size_t len)
{
	psm_unmap_phys(addr, len);
}

/*
 * Default handler to create device node for CPU.
 * One reference count will be held on created device node.
 */
static int
mach_cpu_create_devinfo(cpu_t *cp, dev_info_t **dipp)
{
	int rv;
	dev_info_t *dip;
	static kmutex_t cpu_node_lock;
	static dev_info_t *cpu_nex_devi = NULL;

	ASSERT(cp != NULL);
	ASSERT(dipp != NULL);
	*dipp = NULL;

	if (cpu_nex_devi == NULL) {
		mutex_enter(&cpu_node_lock);
		/* First check whether cpus exists. */
		cpu_nex_devi = ddi_find_devinfo("cpus", -1, 0);
		/* Create cpus if it doesn't exist. */
		if (cpu_nex_devi == NULL) {
			ndi_devi_enter(ddi_root_node());
			rv = ndi_devi_alloc(ddi_root_node(), "cpus",
			    (pnode_t)DEVI_SID_NODEID, &dip);
			if (rv != NDI_SUCCESS) {
				mutex_exit(&cpu_node_lock);
				cmn_err(CE_CONT,
				    "?failed to create cpu nexus device.\n");
				return (PSM_FAILURE);
			}
			ASSERT(dip != NULL);
			(void) ndi_devi_online(dip, 0);
			ndi_devi_exit(ddi_root_node());
			cpu_nex_devi = dip;
		}
		mutex_exit(&cpu_node_lock);
	}

	/*
	 * create a child node for cpu identified as 'cpu_id'
	 */
	ndi_devi_enter(cpu_nex_devi);
	dip = ddi_add_child(cpu_nex_devi, "cpu", DEVI_SID_NODEID, -1);
	if (dip == NULL) {
		cmn_err(CE_CONT,
		    "?failed to create device node for cpu%d.\n", cp->cpu_id);
		rv = PSM_FAILURE;
	} else {
		*dipp = dip;
		(void) ndi_hold_devi(dip);
		rv = PSM_SUCCESS;
	}
	ndi_devi_exit(cpu_nex_devi);

	return (rv);
}

/*
 * The dipp contains one of following values on return:
 * - NULL if no device node found
 * - pointer to device node if found
 */
int
mach_cpu_get_device_node(struct cpu *cp, dev_info_t **dipp)
{
	*dipp = NULL;
	if (psm_cpu_get_devinfo != NULL) {
		if (psm_cpu_get_devinfo(cp, dipp) == PSM_SUCCESS) {
			return (PSM_SUCCESS);
		}
	}

	return (PSM_FAILURE);
}
#endif
