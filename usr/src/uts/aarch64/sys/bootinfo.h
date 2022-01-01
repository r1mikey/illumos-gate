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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_BOOTINFO_H
#define	_SYS_BOOTINFO_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	MAX_BOOT_MODULES	99

#if defined(_BOOT_TARGET_aarch64)
typedef uint64_t native_ptr_t;
#elif defined(_KERNEL)
typedef void *native_ptr_t;
#endif

struct boot_memlist {
	uint64_t	addr;
	uint64_t	size;	/* bytes */
	native_ptr_t	next;
	native_ptr_t	prev;
};

typedef enum boot_module_type {
	BMT_ROOTFS,
	BMT_ENV,
	BMT_FONT
} boot_module_type_t;

/*
 * The kernel needs to know how to find its modules.
 */
struct boot_modules {
	native_ptr_t		bm_addr;
	native_ptr_t		bm_name;
	uint64_t		bm_size;
	boot_module_type_t	bm_type;
};

/*
 * We're on aarch64, so keep this very strictly aligned.
 */
struct xboot_info {
	uint64_t	bi_va_pa_delta;	/* nucleus VA/PA delta */
	uint64_t	bi_physload;	/* nucleus PA load address */
	uint64_t	bi_dbg2_pa;	/* DBG2 port base PA (or 0) */
	uint64_t	bi_dbg2_va;	/* DBG2 port base VA (or 0) */
	uint64_t	bi_dbg2_type;	/* DBG2 UART port subtype (iff va) */
#if 1
	uint64_t	bi_fdt;			/* I'll be removing this... */
#endif
	uint64_t	bi_next_paddr;		/* next physical address fakebop */
	native_ptr_t	bi_next_vaddr;		/* next virtual address fakebop */
	native_ptr_t	bi_cmdline;		/* points to arbitrary memory, fakebop, boot */
	native_ptr_t	bi_phys_install;	/* pointer into eboot, fakebop -> bm */
	native_ptr_t	bi_rsvdmem;		/* pointer into eboot, fakebop -> bm  */
	native_ptr_t	bi_pcimem;		/* pointer into eboot, fakebop -> bm  */
	native_ptr_t	bi_pt_window;		/* a page for the kernel to work with page tables - needs investigation */
	native_ptr_t	bi_pte_to_pt_window;	/* vm/kboot_mmu.c - needs investigation - is this the PT to the window? */
	uint64_t	bi_kseg_size;		/* mapping size for the nucleus - i86pc is... special */
	uint64_t	bi_top_ttbr0;		/* physical or virtual? */
	uint64_t	bi_top_ttbr1;		/* physical or virtual? */
	native_ptr_t	bi_uefi_systab;		/* physical pointer? */
	native_ptr_t	bi_rsdp;		/* physical pointer? */
	native_ptr_t	bi_smbios3;		/* physical pointer? */
	native_ptr_t	bi_acpi_xsdt;		/* physical pointer? */
#if 0
	uefi_arch_type_t	bi_uefi_arch;
#endif
	native_ptr_t	bi_framebuffer;		/* pointer to physical memory, AFAICT, points to our fb_info */

	/*
	 * MMU setup registers, primarily used by eboot ASM code.
	 */
	uint64_t	bi_mair;		/* memory attribute indirection settings */
	uint64_t	bi_tcr;			/* translation control */
	uint64_t	bi_sctlr;		/* system control register */

	uint64_t	bi_physmin;		/* lowest page number in the system */
	uint64_t	bi_physmax;		/* highest page number in the system */
	native_ptr_t	bi_modules;		/* pointer into eboot */
	uint32_t	bi_module_cnt;		/* number of boot modules (rootfs etc.) */
	uint32_t	bi__pad;
#if 0
	uint32_t	bi_use_largepage;       /* MMU uses large pages */
	uint32_t	bi_use_pae;     /* MMU uses PAE mode (8 byte PTES) */
	uint32_t	bi_use_nx;      /* MMU uses NX bit in PTEs */
	uint32_t	bi_use_pge;     /* MMU uses Page Global Enable */
	uint32_t	bi__pad;
#endif
};

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_BOOTINFO_H */
