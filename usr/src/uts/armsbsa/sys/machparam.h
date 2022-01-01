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
 * Copyright 2022 Michael van der Westhuizen
 * Copyright 2017 Hayashi Naoyuki
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#ifndef	_SYS_MACHPARAM_H
#define	_SYS_MACHPARAM_H

#ifndef	_ASM
#include <sys/types.h>
#include <sys/int_const.h>
#endif	/* !_ASM */

#ifdef	__cplusplus
extern "C" {
#endif

#if !defined(_ASM)
#define	ADDRESS_C(c)	UINT64_C(c)
#else
#define	ADDRESS_C(c)	(c)
#endif

/*
 * Machine dependent parameters and limits.
 */

/*
 * Maximum number of CPUs we can support.
 *
 * From i86pc (and relevant when we do a comm page):
 * If NCPU grows beyond 256, sizing for the x86 comm page will require
 * adjustment.
 */
#define	NCPU		64
#define	NCPU_LOG2	6
#define	NCPU_P2		(1 << NCPU_LOG2)

/*
 * The value defined below could grow to 16. hat structure and
 * page_t have room for 16 nodes.
 */
#define	MAXNODES	4
#define	NUMA_NODEMASK	0x0f

/*
 * Supported page sizes
 *
 * XXXAARCH64: Future QoI changes here.
 *
 * These are block and page based sizes (4KiB, 2MiB, 1GiB).  If we choose to
 * support contiguous ranges (64KiB, 32MiB, 16GiB) we'll want to update this.
 *
 * Used in physical page list management.
 */
#define	MMU_PAGE_SIZES	3
/*
 * Levels in the page table hierarchy
 *
 * XXXAARCH64: Future QoI changes here.
 *
 * For 52 bit output addresses with a 4KiB granule this is actually 5, as
 * aarch64 introduces a "level -1" as the top-level page.
 */
#define	MMU_PAGE_LEVELS	4

/*
 * MMU_PAGES* describes the physical page size used by the mapping hardware.
 * PAGES* describes the logical page size used by the system.
 *
 * Ensure that the MMU_PAGESHIFT definition here is consistent with the one in
 * param.h
 */

#define	MMU_PAGESHIFT		12
#define	MMU_PAGESIZE		(ADDRESS_C(1) << MMU_PAGESHIFT)
#if !defined(_ASM)
#define	MMU_PAGEOFFSET		(MMU_PAGESIZE - 1)
#else
#define MMU_PAGEOFFSET		_CONST(MMU_PAGESIZE-1)
#endif
#define	MMU_PAGEMASK		(~MMU_PAGEOFFSET)

#define	MMU_PAGESHIFT2M		21
#define	MMU_PAGESIZE2M		(ADDRESS_C(1) << MMU_PAGESHIFT2M)
#define	MMU_PAGEOFFSET2M	(MMU_PAGESIZE2M - 1)
#define	MMU_PAGEMASK2M		(~MMU_PAGEOFFSET2M)

#define	MMU_PAGESHIFT1G		30
#define	MMU_PAGESIZE1G		(ADDRESS_C(1) << MMU_PAGESHIFT1G)
#define	MMU_PAGEOFFSET1G	(MMU_PAGESIZE1G - 1)
#define	MMU_PAGEMASK1G		(~MMU_PAGEOFFSET1G)

#define	PAGESHIFT		MMU_PAGESHIFT
#define	PAGESIZE		MMU_PAGESIZE
#define	PAGEOFFSET		MMU_PAGEOFFSET
#define	PAGEMASK		MMU_PAGEMASK

/*
 * DATA_ALIGN is used to define the alignment of the Unix data segment.
 *
 * XXXAARCH64: This is only true for sun4, it's not true for amd64, where it's
 * not used at all.  I doubt this will be true for aarch64 either.
 */
#define	DATA_ALIGN	PAGESIZE

/*
 * DEFAULT KERNEL THREAD stack size (in pages).
 */
#define	DEFAULTSTKSZ_NPGS	5

/*
 * DEFAULT KERNEL THREAD stack size.
 */
/* #if !defined(_ASM) */
#define	DEFAULTSTKSZ	(DEFAULTSTKSZ_NPGS * PAGESIZE)
/* #else */
/* #define	DEFAULTSTKSZ	_MUL(DEFAULTSTKSZ_NPGS, PAGESIZE) */
/* #endif */

/*
 * Use a slightly larger thread stack size for interrupt threads rather than
 * the default. This is useful for cases where the networking stack may do an
 * rx and a tx in the context of a single interrupt and when combined with
 * various promisc hooks that need memory, can cause us to get dangerously
 * close to the edge of the traditional stack sizes. This is only a few pages
 * more than a traditional stack and given that we don't have that many
 * interrupt threads, the memory costs end up being more than worthwhile.
 */
#define LL_INTR_STKSZ_NPGS	8
#define LL_INTR_STKSZ		(LL_INTR_STKSZ_NPGS * PAGESIZE)

/*
 * DEFAULT initial thread stack size.
 *
 * XXXAARCH64: I'm not sure why we need this to be different.
 */
#if !defined(_ASM)
#define	T0STKSZ		(2 * DEFAULTSTKSZ)
#else
#define	T0STKSZ		_MUL(2 * DEFAULTSTKSZ)
#endif

/*
 * ARGSBASE is used to set up _argsbase in param.c (in common kernel code), but
 * after that neither is referenced anywhere in the kernel, other than in setup
 * code for memory maps.
 *
 * We keep this around for now, but it could probably just go quietly into the
 * night.
 *
 * This is set up to point to the start of a chunk of VA we use for things
 * passed to the kernel-proper by the EFI kernel bootstrap.
 *
 * The original documentation is:
 * ARGSBASE is the base virtual address of the range which
 * the kernel uses to map the arguments for exec.
 */
#define	ARGSBASE	ADDRESS_C(0xffffffffffc00000)

/*
 * Virtual address range available to the debugger
 */
#define	SEGDEBUGBASE	ADDRESS_C(0xffffffffff800000)
#define	SEGDEBUGSIZE	ADDRESS_C(0x400000)

/*
 * Highest VA the kernel can use for dynamic allocation during startup
 *
 * Used as a check in fakebop.c.  This is the end of the unused chunk of
 * VA above the kernel nucleus.
 */
#define	MAX_DYNAMIC_VA		(SEGDEBUGBASE)


/*
 * Keep the mapfiles up to date if you change this:
 * armsbsa/conf/Mapfile.armsbsa.aarch64
 * armsbsa/unix/eboot/Mapfile.eboot
 */
#define	KERNEL_TEXT	ADDRESS_C(0xffffffffbf800000)
#define	EBOOT_TEXT	ADDRESS_C(0xffffffffbf600000)

/*
 * DEBUG_INFO_VA is the VA at which we leave a page of data for external
 * debuggers to attach to and discover information about the running kernel.
 *
 * This starts 64KiB below KERNEL_TEXT (to allow a 64KiB granule) and is
 * logically a part of the core heap.
 */
#define	DEBUG_INFO_VA	ADDRESS_C(0xffffffffbf7f0000)
/*
 * YAGNI in aarch64
 */
#define	MISC_VA_BASE	DEBUG_INFO_VA
#define	MISC_VA_SIZE	MMU_PAGESIZE


/*
 * The kernel can address text and data within a 2GiB range of the program
 * counter.  To that end, we keep a core heap region covering a range that
 * starts 2GiB below the end of the kernel data and extends to KERNEL_BASE,
 * excluding DEBUG_INFO_VA.
 *
 * This layout allows for PC-relative addressing in the kernel and all loaded
 * modules.
 *
 * COREHEAP_MAX_SIZE is the space available between COREHEAP_BASE and the base
 * of the DEBUG_INFO_VA address (2GiB - 4MiB - 4MiB - 64KiB).
 */
#define	COREHEAP_BASE		ADDRESS_C(0xffffffff40000000)
#define	COREHEAP_MAX_SIZE	ADDRESS_C(0x7f7f0000)

/*
 * The heap has a region allocated from it of HEAPTEXT_SIZE bytes specifically
 * for module text.
 *
 * This space is allocated in the last HEAPTEXT_SIZE bytes of the kmem area.
 * (XXXAARCH64: is this core_base->KERNEL_TEXT? - if so, this could be a lot
 * bigger)
 *
 * XXX: this breaks my assumptions (again)
 * XXX: ??? difference here between coreheap and heaptext?  Is that the text
 * portion of coreheap?  Either way, needs updating - probably the top 1GiB
 * of coreheap?
 */
#define	HEAPTEXT_SIZE	(64 * 1024 * 1024)	/* bytes */


/*
 * The next "known quantity" is SEGKPM_BASE, which is 512GiB above KERNELBASE.
 * We make some guesses about others.
 *
 * kernelheap
 * segmap_start
 * toxic_addr
 * segzio_base
 * segkvmm_base
 * segkp_base
 * valloc_base
 * SEGKPM_BASE
 * uefi_runtime_base
 * framebuffer_base
 * shadowfb_base
 * KERNELBASE
 */

/*
 * kernel heap here
 */

/*
 * segmap here
 */

/*
 * Device mappings here - should we say 2TiB max?
 */

/*
 * minimum size for segzio
 */
#define	SEGZIOMINSIZE	(512L * 1024 * 1024L)		/* 512MiB */
#define	SEGZIOMAXSIZE	(512L * 1024L * 1024L * 1024L)	/* 512GiB */

/*
 * segkvmm here, which is 4*PHYSMEM (128TiB max)
 */
#define	SEGVMMMINSIZE	(4096L * 1024 * 1024L)		/* 4GiB */

/*
 * default and boundary sizes for segkp
 *
 * These are up for revision, and should be based on a 2TiB physical address
 * space.
 */
#define	SEGKPDEFSIZE	(2L * 1024L * 1024L * 1024L)		/*   2G */
#define	SEGKPMAXSIZE	(8L * 1024L * 1024L * 1024L)		/*   8G */
#define	SEGKPMINSIZE	(200L * 1024 * 1024L)			/* 200M */


/*
 * This is valloc_base, above seg_kpm, but below everything else.
 *
 * Since seg_kpm is variable sized, this is a floating value and the rest of the
 * kernel should use valloc_base to refer to the values calculated by
 * os/startup.c.
 *
 * The constant here represents the base used when 32TiB of physical address
 * space is present.
 *
 * This area contains data structures describing physical memory on the machine
 * and is of a variable size, extending upwards to segkp_base, and ultimately
 * up to segkvmm_base.
 */
#define	VALLOC_BASE		ADDRESS_C(0xffff208000000000)


/*
 * SEGKPM_BASE starts immediately after the redzone and extends upwards based
 * on the amount of physical address space (RAM, IO space, holes) installed in
 * the machine.  This area is used to map all physical memory into the kernel
 * virtual address space at a known offset to the kernel virtual address space.
 *
 * This memory area is known as segkpm (kernel physical map segment).
 *
 * The maximum size of the PA is dictated by the maximum amount of VA we set
 * aside for segkpm, which is 32TiB when we have a 48 bit VA.
 *
 * Note that this area is a 1:1 map to physical address space, which may contain
 * enormous holes, such as on qemu-sbsaref, which has a huge hole at the start
 * of physical address space.
 */
#define	SEGKPM_BASE		ADDRESS_C(0xffff008000000000)
/* this is from the original port, and needs to be removed */
#define	SEGKPM_SIZE		ADDRESS_C(0x200000000000)

/*
 * VA for remapping the UEFI Runtime Services
 *
 * We set aside 256GiB of VA for this, which is rather excessive.
 *
 * This contains different kinds of mappings, including device mappings.  The
 * precise nature of the mappings is based on UEFI 2.6 aarch64 specifications.
 *
 * The contents of this are "everything that had the relocatable flag set" in
 * the UEFI memory map.  The reason we include absolutely everything here is
 * that it is possible that runtime code needs to access hardware, and therefore
 * it needs to have a valid mapping for that hardware (think of the RTC).  I'd
 * expect this to not really matter when the UEFI lives in HYP mode and we're
 * in supervisor, but let's play along.
 */
#define	UEFI_RUNTIME_BASE	ADDRESS_C(0xffff004000000000)
#define	UEFI_RUNTIME_MAX_SIZE	ADDRESS_C(0x4000000000)

/*
 * Framebuffer
 *
 * We set aside a generous 8GiB of VA for mapping the hardware FB.
 *
 * This is a write-combining mapping.
 */
#define	FRAMEBUFFER_BASE	ADDRESS_C(0xffff003e00000000)
#define	FRAMEBUFFER_MAX_SIZE	ADDRESS_C(0x200000000)

/*
 * Shadow FB
 *
 * As with the hardware framebuffer, we set aside a generous 8GiB of shadow
 * framebuffer VA.
 *
 * This is normal memory.
 */
#define	SHADOWFB_BASE		ADDRESS_C(0xffff003c00000000)
#define	SHADOWFB_MAX_SIZE	ADDRESS_C(0x200000000)

/*
 * The VA window the early kernel will use for pagetable manipulation.
 *
 * PT_WINDOW_VA is a VA that page table pages will be temporarily mapped to for
 * manipulation.  PTE_WINDOW_PTE_VA is a mapping of the page table page that
 * manages the mapping for PT_WINDOW_VA - this is an L0 (leaf) 4KiB mapping.
 */
#define	PT_WINDOW_VA		ADDRESS_C(0xffff003bffe00000)
#define	PTE_WINDOW_PTE_VA	ADDRESS_C(0xffff003bffc00000)

/*
 * DBG2_BASE is the VA at which the dbg2 port is mapped if one is present.
 *
 * This is a 2MiB mapping, aligned to 2MiB, below the PT window VA.  This maps
 * device memory.
 */
#define	DBG2_BASE	ADDRESS_C(0xffff003bffa00000)
#define	DBG2_SIZE	(2 * 1024 * 1024)

/*
 * BOOT_VEC_BASE is used for the secondary CPU spin tables, and needs to
 * be both allocated and communicated to secondary CPUs (when PSCI is not
 * involved).
 *
 * This is unused right now, and will probably just go away when we figure this
 * out properly (and segkpm is up).
 *
 * For now, this lives below DBG2 base, with 1GiB allocated on a 1GiB boundary.
 */
#define	BOOT_VEC_BASE		ADDRESS_C(0xffff003b80000000)
#define	BOOT_VEC_SIZE		(1 * 1024 * 1024 * 1024)

/*
 * eboot maps all data references it passes to the kernel up into the lower part
 * of the redzone.  This makes it really easy to reclaim boot pages: just clear
 * off all of TTBR0 and scrub this region from TTBR1.
 *
 * We set aside 127GiB of space for this boot-time data, which includes the
 * bootarchive.
 */
#define	BOOTLOADER_DATA_BASE	ADDRESS_C(0xffff000040000000)
#define	BOOTLOADER_DATA_SIZE	(127ul * 1024 * 1024 * 1024)

/*
 * KERNELBASE is the virtual address at which the kernel segments start in
 * all contexts.
 *
 * On aarch64 this value is the lower limit of the TTBR1 space (the top half
 * of the virtual address space).
 *
 * We stash the UEFI Runtime Services mappings, framebuffer and shadow
 * framebuffer in the 512GiB of VA that starts here, but those are in the top
 * part of the VA.  The bottom part forms a red zone.  The red zone is not
 * strictly needed in aarch64 - both for architectural reasons and because we
 * have a huge hole between TTBR1 (kernel) and TTBR0 (user) mappings already.
 */
#define	KERNELBASE	ADDRESS_C(0xffff000000000000)

/*
 * The size of the "red zone" (as above, not so red!) - used when verifying
 * address space layout in startup.
 *
 * Note that we stash a few things *in the redzone* that are not for general:
 * kernel use:
 * - the PT manipulation window VA (allocated in eboot)
 * - the shadow framebuffer mapped VA space (allocated in startup for now)
 * - the mapped framebuffer VA space (write-combining)
 * - the UEFI runtime services remapped mappings, which includes device I/O
 * - the VA for accessing the DBG2 port
 * - - used until a full driver takes over
 * - - ... or not, in which case this is simply used
 *
 * Need to tweak the unmapping logic in startup (or the verification logic) so
 * that this continues to work and is not terribly inefficient.
 */
#define	KERNEL_REDZONE_SIZE	(ADDRESS_C(1) << 39)

/*
 * aarch64 has an architected hole in the middle of the virtual address space.
 *
 * On each end of the hole we have 48 bits of VA.  These are differentiated by
 * the top 16 bits being all zeroes (bottom half addresses, translated by the
 * tables configured in the TTBR0_EL1 register) or all ones (top half addresses,
 * translated by the tables configured in the TTBR1_EL1 register).
 *
 * If and when we add support for 52 bit addressing these holes will move (as
 * will the user limit and kernel nucleus).  Note that 52 bit VA support can
 * be configured independently for the top and bottom halves, so our hole
 * definitions will need to be completely dynamic.
 */
#define	HOLE_END	ADDRESS_C(0xffff000000000000)	/* exclusive */
#define	HOLE_START	ADDRESS_C(0x0001000000000000)	/* inclusive */

/*
 * Define upper limit on user address space
 *
 * For 64 bit processes, we define the upper limit as one large page (2MiB)
 * below the top the the addressable user VA (the bottom 48 bits of the full
 * 64 bit address space).
 *
 * If we choose to support a 52 bit VA for the bottom half address space then
 * we'll need to adjust this appropriately.
 *
 * For 32 bit processes (aarch64_p32), we define the upper limit as one large
 * page (2MiB) below the 4GiB 32 bit addressing limit. On amd64 this is only
 * 4KiB (one page), but let's keep things consistent on aarch64, since 32 bit
 * is only a crutch to get the OS up and running while we sort out a 64 bit-only
 * build system.
 */
#define	USERLIMIT		ADDRESS_C(0x0000ffffffe00000)
#define	USERLIMIT32		ADDRESS_C(0x00000000ffe00000)

#if !defined(_ASM) && !defined(_KMDB)
extern uintptr_t kernelbase, segmap_start, segmapsize;
#endif

/*
 * MODTEXT and MODDATA are used to carve out space in the leftover nucleus space
 * for loaded modules, prior to spilling over into the core_base area.
 *
 * Reserve space for modules
 *
 * XXXAARCH64: I can't help but feel that we should be a bit more dynamic about
 * this.  I will fix this, because it annoys me.  We should just use all of the
 * remaining space, until the point where we change protections on the kernel
 * text.
 */
#define	MODTEXT	(1024 * 1024 * 2)
#define	MODDATA	(1024 * 300)

/*
 * Below bits from the original port - remove these.
 *
 * Virtual Address Spaces
 */
#define	PTE_BITS	3
#define	VA_BITS		(MMU_PAGESHIFT + (MMU_PAGESHIFT - PTE_BITS) * MMU_PAGE_LEVELS + 1)
#define	VIRT_BITS	48

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MACHPARAM_H */
