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

#if defined(_EFI)
typedef enum boot_module_type {
	BMT_ROOTFS,
	BMT_ENV,
	BMT_FONT
} boot_module_type_t;
#endif

/*
 * The kernel needs to know how to find its modules.
 */
struct boot_modules {
	uint64_t		bm_addr;
#if defined(_EFI)
	uint64_t		bm_name;
#endif
	uint64_t		bm_size;
#if defined(_EFI)
	boot_module_type_t	bm_type;
#endif
};

/*
 *
 */
struct xboot_info {
	uint64_t	bi_fdt;
#if defined(_EFI)
	/* XXXARM: These three must evolve */
	uint64_t	bi_dbg2_pa;
	uint64_t	bi_dbg2_sz;	/* in bytes */
	uint64_t	bi_dbg2_va;
	uint64_t	bi_dbg2_type;
	/* XXXARM: Kernel arguments */
	uint64_t	bi_boothowto;
	uint64_t	bi_args;
	/* XXXARM: System tables */
	uint64_t	bi_uefi_systab;
	uint64_t	bi_rsdp;
	uint64_t	bi_smbios3;
	uint64_t	bi_acpi_xsdt;
	/* XXXARM: UEFI framebuffer */
	uint64_t	bi_framebuffer;
	uint64_t	bi_cmdline;
	uint64_t	bi_modules;	/* pointer into the boot shim */
	uint32_t	bi_module_cnt;
	uint32_t	bi__pad;
	uint64_t	bi_boot_sysp;
	uint64_t	bi_gic_dist_base;
	uint64_t	bi_gic_dist_size;
	uint64_t	bi_gic_version;
	/* PSCI bootstrap */
	uint32_t	bi_use_psci;
	uint32_t	bi_psci_use_hvc;
	/* XXXARM: Boot memory, I don't like this, but maybe I'm dumb */
	uint64_t	bi_phys_avail;
	uint64_t	bi_phys_installed;
	uint64_t	bi_boot_scratch;
#endif
};

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_BOOTINFO_H */
