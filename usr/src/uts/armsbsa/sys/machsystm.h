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
 * Copyright (c) 1993, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 */

#ifndef _SYS_MACHSYSTM_H
#define	_SYS_MACHSYSTM_H

/*
 * Numerous platform-dependent interfaces that don't seem to belong
 * in any other header file.
 *
 * This file should not be included by code that purports to be
 * platform-independent.
 *
 * XXXAARCH64: this whole file should be closer to Intel.
 */

#include <sys/machparam.h>
#include <sys/varargs.h>
#include <sys/thread.h>
#include <sys/cpuvar.h>
#include <sys/privregs.h>
#include <sys/systm.h>
#include <vm/page.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _KERNEL

/* Dynamic Reconfiguration capability interface. */
#define	PLAT_DR_OPTIONS_NAME		"plat-dr-options"
#define	PLAT_DR_PHYSMAX_NAME		"plat-dr-physmax"
#define	PLAT_MAX_NCPUS_NAME		"plat-max-ncpus"
#define	BOOT_MAX_NCPUS_NAME		"boot-max-ncpus"
#define	BOOT_NCPUS_NAME			"boot-ncpus"

#define	PLAT_DR_FEATURE_CPU		0x1
#define	PLAT_DR_FEATURE_MEMORY		0x2
#define	PLAT_DR_FEATURE_ENABLED		0x1000000

#define plat_dr_enabled()		\
	plat_dr_check_capability(PLAT_DR_FEATURE_ENABLED)

extern boolean_t plat_dr_support_cpu(void);
extern boolean_t plat_dr_support_memory(void);
extern boolean_t plat_dr_check_capability(uint64_t features);
extern void plat_dr_enable_capability(uint64_t features);
extern void plat_dr_disable_capability(uint64_t features);

#pragma weak plat_dr_support_cpu
#pragma weak plat_dr_support_memory

struct panic_trap_info {
	struct regs *trap_regs;
	uint_t trap_type;
	caddr_t trap_addr;
};

struct memconf {
	pfn_t	mcf_spfn;	/* begin page frame number */
	pfn_t	mcf_epfn;	/* end page frame number */
};

struct system_hardware {
	int		hd_nodes;		/* number of nodes */
	int		hd_cpus_per_node;	/* max cpus in a node */
	struct memconf	hd_mem[MAXNODES];
						/*
						 * memory layout for each
						 * node.
						 */
};
extern struct system_hardware system_hardware;

extern uint64_t plat_dr_physmax;

extern struct cpu	*cpu[];		/* pointer to all cpus */
extern unsigned int microdata;
extern uintptr_t hole_start, hole_end;

#define	INVALID_VADDR(a)	\
	(((a) >= (caddr_t)hole_start && (a) < (caddr_t)hole_end))

/* kpm mapping window */
extern size_t   kpm_size;
extern uchar_t  kpm_size_shift;
extern caddr_t  kpm_vbase;
extern void get_system_configuration(void);
extern page_t *page_get_physical(uintptr_t seed);
extern void *mach_cpucontext_alloc(struct cpu *);
extern int trap(uint32_t ec, uint32_t iss, caddr_t addr, struct regs *rp);
extern void mmu_init(void);
extern void boot_reserve(void);
extern void kcpc_hw_init(cpu_t *cp);
extern int mach_cpu_create_device_node(cpu_t *, dev_info_t **);
extern void send_dirint(int, int);
extern int mach_cpu_start(cpu_t *, void *);
extern int mach_cpucontext_init(void);
extern void mach_cpucontext_fini(void);
extern void *mach_cpucontext_alloc(struct cpu *);
extern void mach_cpucontext_free(struct cpu *, void *, int);
extern void *mach_cpucontext_xalloc(struct cpu *, int);
extern void mach_cpucontext_xfree(struct cpu *, void *, int, int);
extern void kcpc_hw_fini(cpu_t *cp);
extern void siron(void);

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_MACHSYSTM_H */
