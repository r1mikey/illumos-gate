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

	.file	"eboot_entry.s"

/*
 * EFI boot entry point.
 *
 * The eboot binary is static and location independent and is prepended to unix
 * so that there's a small stub that can bootstrap virtual memory mappings and
 * normalise the bootloader information that the kernel needs to process.
 */

#include <sys/asm_linkage.h>
#include <sys/machparam.h>

#if 0
#include <sys/segments.h>
#include <sys/controlregs.h>

#include "dboot_xboot.h"
#endif

#include <sys/archmmu.h>

#include "assym.h"

#define	ATTR_AF			(1 << 10)
#define	ATTR_SH_IS		3	/* Inner-shareable */
#define	ATTR_SH(x)		((x) << 8)
#define	ATTR_DEFAULT		(ATTR_AF | ATTR_SH(ATTR_SH_IS))

#define	ATTR_S1_IDX(x)		((x) << 2)
#define ATTR_S1_UXN             (1UL << 54)
#define ATTR_S1_nG              (1 << 11)

/* Level 0 table, 512GiB per entry */
#define L0_SHIFT        39
#define L0_SIZE         (1ul << L0_SHIFT)
#define L0_OFFSET       (L0_SIZE - 1ul)
#define L0_INVAL        0x0 /* An invalid address */
        /* 0x1 Level 0 doesn't support block translation */
        /* 0x2 also marks an invalid address */
#define L0_TABLE        0x3 /* A next-level table */

/* Level 1 table, 1GiB per entry */
#define L1_SHIFT        30
#define L1_SIZE         (1 << L1_SHIFT)
#define L1_OFFSET       (L1_SIZE - 1)
#define L1_INVAL        L0_INVAL
#define L1_BLOCK        0x1
#define L1_TABLE        L0_TABLE

/* Level 2 table, 2MiB per entry */
#define L2_SHIFT        21
#define L2_SIZE         (1 << L2_SHIFT)
#define L2_OFFSET       (L2_SIZE - 1)
#define L2_INVAL        L1_INVAL
#define L2_BLOCK        L1_BLOCK
#define L2_TABLE        L1_TABLE

#define L2_BLOCK_MASK   0xffffffffffe00000ULL

/* Level 3 table, 4KiB per entry */
#define L3_SHIFT        12
#define L3_SIZE         (1 << L3_SHIFT)
#define L3_OFFSET       (L3_SIZE - 1)
#define L3_INVAL        0x0
        /* 0x1 is reserved */
        /* 0x2 also marks an invalid address */
#define L3_PAGE         0x3

#define L0_ENTRIES_SHIFT 9
#define L0_ENTRIES      (1 << L0_ENTRIES_SHIFT)
#define L0_ADDR_MASK    (L0_ENTRIES - 1)

#define Ln_ENTRIES_SHIFT 9
#define Ln_ENTRIES      (1 << Ln_ENTRIES_SHIFT)
#define Ln_ADDR_MASK    (Ln_ENTRIES - 1)
#define Ln_TABLE_MASK   ((1 << 12) - 1)

#define PAGE_SHIFT_4K   12
#define PAGE_SIZE_4K    (1 << PAGE_SHIFT_4K)
#define PAGE_MASK_4K    (PAGE_SIZE_4K - 1)

#define PAGE_SHIFT_16K  14
#define PAGE_SIZE_16K   (1 << PAGE_SHIFT_16K)
#define PAGE_MASK_16K   (PAGE_SIZE_16K - 1)

#define PAGE_SHIFT_64K  16
#define PAGE_SIZE_64K   (1 << PAGE_SHIFT_64K)
#define PAGE_MASK_64K   (PAGE_SIZE_64K - 1)

#define PAGE_SHIFT      PAGE_SHIFT_4K
#define PAGE_SIZE       PAGE_SIZE_4K
#define PAGE_MASK       PAGE_MASK_4K

#define TATTR_UXN_TABLE         (1UL << 60)
#define TATTR_AP_TABLE_NO_EL0   (1UL << 61)

#define	TCR_HD_SHIFT		40
#define	TCR_HD			(1UL << TCR_HD_SHIFT)
#define	TCR_HA_SHIFT		39
#define	TCR_HA			(1UL << TCR_HA_SHIFT)
#define	TCR_ASID_SHIFT		36
#define	TCR_ASID_WIDTH		1
#define	TCR_IPS_SHIFT		32
#define	TCR_IPS_WIDTH		3
#define	TCR_TG1_SHIFT		30
#define TCR_TG1_4K		(2UL << TCR_TG1_SHIFT)
#define	TCR_SH1_SHIFT		28
#define	TCR_SH1_IS		(3UL << TCR_SH1_SHIFT)
#define	TCR_ORGN1_SHIFT		26
#define	TCR_ORGN1_WBWA		(1UL << TCR_ORGN1_SHIFT)
#define	TCR_IRGN1_SHIFT		24
#define	TCR_IRGN1_WBWA		(1UL << TCR_IRGN1_SHIFT)
#define	TCR_T1SZ_SHIFT		16
#define	TCR_T1SZ(x)		((x) << TCR_T1SZ_SHIFT)
#define	TCR_TG0_SHIFT		14
#define	TCR_TG0_4K		(0 << TCR_TG0_SHIFT)
#define	TCR_SH0_SHIFT		12
#define	TCR_SH0_IS		(3UL << TCR_SH0_SHIFT)
#define	TCR_ORGN0_SHIFT		10
#define	TCR_ORGN0_WBWA		(1UL << TCR_ORGN0_SHIFT)
#define	TCR_IRGN0_SHIFT		8
#define	TCR_IRGN0_WBWA		(1UL << TCR_IRGN0_SHIFT)
#define	TCR_T0SZ_SHIFT		0
#define	TCR_T0SZ(x)		((x) << TCR_T0SZ_SHIFT)

#define	TCR_TxSZ(x)		(TCR_T1SZ(x) | TCR_T0SZ(x))
#define	TCR_CACHE_ATTRS		((TCR_IRGN0_WBWA | TCR_IRGN1_WBWA) | (TCR_ORGN0_WBWA | TCR_ORGN1_WBWA))
#define	TCR_SMP_ATTRS		(TCR_SH0_IS | TCR_SH1_IS)

#define	ID_AA64MMFR0_ASIDBits_SHIFT	4
#define	ID_AA64MMFR0_ASIDBits_MASK	(0xfUL << ID_AA64MMFR0_ASIDBits_SHIFT)
#define	ID_AA64MMFR0_ASIDBits_16	(0x2UL << ID_AA64MMFR0_ASIDBits_SHIFT)

#define	ID_AA64MMFR1_HAFDBS_SHIFT	0
#define	ID_AA64MMFR1_HAFDBS_MASK	(0xfUL << ID_AA64MMFR1_HAFDBS_SHIFT)

#define	SCTLR_LSMAOE			(0x1UL << 29)
#define	SCTLR_nTLSMD			(0x1UL << 28)
#define	SCTLR_UCI			(0x1UL << 26)
#define	SCTLR_EE			(0x1UL << 25)
#define	SCTLR_E0E			(0x1UL << 24)
#define	SCTLR_SPAN			(0x1UL << 23)
#define	SCTLR_IESB			(0x1UL << 21)
#define	SCTLR_WXN			(0x1UL << 19)
#define	SCTLR_nTWE			(0x1UL << 18)
#define	SCTLR_nTWI			(0x1UL << 16)
#define	SCTLR_UCT			(0x1UL << 15)
#define	SCTLR_DZE			(0x1UL << 14)
#define	SCTLR_I				(0x1UL << 12)
#define	SCTLR_UMA			(0x1UL << 9)
#define	SCTLR_SED			(0x1UL << 8)
#define	SCTLR_ITD			(0x1UL << 7)
#define	SCTLR_CP15BEN			(0x1UL << 5)
#define	SCTLR_SA0			(0x1UL << 4)
#define	SCTLR_SA			(0x1UL << 3)
#define	SCTLR_C				(0x1UL << 2)
#define	SCTLR_A				(0x1UL << 1)
#define	SCTLR_M				(0x1UL << 0)

#define	SCTLR_SET			(SCTLR_LSMAOE | SCTLR_nTLSMD | \
	SCTLR_UCI | SCTLR_SPAN | SCTLR_nTWE | SCTLR_nTWI | SCTLR_UCT | \
	SCTLR_DZE | SCTLR_I | SCTLR_SED | SCTLR_SA0 | SCTLR_SA | SCTLR_C | \
	SCTLR_M | SCTLR_CP15BEN)

#define	SCTLR_CLEAR			(SCTLR_EE | SCTLR_E0E | SCTLR_IESB | \
	SCTLR_WXN | SCTLR_UMA | SCTLR_ITD | SCTLR_A)

/*
 * VMSAv8-64 address translation
 *
 * In AArch64 state, the VA has a maximum address width of one of the following:
 * * 48 bits
 * * 52 bits when FEAT_LVA is implemented and the 64KB translation granule is
 *   used.
 * * 52 bits when all of the following are true:
 *   * FEAT_LPA2 is implemented.
 *   * TCR_ELx.DS==1 for the translation regime controlled by that register.
 *   * The 4KB or 16KB translation granule is used.
 *
 * For simplicity and portability we stick to 48 bits for now.
 *
 * We'll do two VA ranges (TTBR0, TTBR1).
 * 256TiB of VA space for userspace (TTBR0) 0x0-0xFFFFFFFFFFFF
 * 256TiB of VA for the kernel (TTBR1) 0xFFFF000000000000-0xFFFFFFFFFFFFFFFF
 *
 * Let't move the kernel itself down to 0xffffffe000000000 ($TOP-128GiB).
 *
 * Kernel at 0xffffffe0ff800000
 * core_base at 0xffffffe000000000
 * ^^ puts us in the 4GiB range we want, and leaves 124GiB of VA above the kernel
 *
 * During boot:
 *
 * L0 -> L1[TOP-512GiB] -> L2[0..510 as block, 511 as table] -> L3[top stuff]
 *
 *              64-bit Kernel's Virtual memory layout. (assuming 64 bit app)
 *                      +-----------------------+
 * 0xffffffff.fffc0000  |---      DBG2       ---|- DBG2_BASE (dtrace_toxic_ranges!)
 *                      |                       |
 * 0xffffffff.ffc00000  |-----------------------|- ARGSBASE
 *                      |       debugger (?)    |
 * 0xffffffff.ff800000  |-----------------------|- SEGDEBUGBASE
 *                      |      unused           |
 * 0xffffffff.c0000000  +-----------------------+
 *                      |      Kernel Data      |
 * 0xffffffff.bfc00000  |-----------------------|
 *                      |      Kernel Text      |
 * 0xffffffff.bf800000  |-----------------------|- KERNEL_TEXT
 * 0xffffffff.bf7f0000  |---    debug info   ---|- debug info (DEBUG_INFO_VA)
 *                      |                       |
 *                      |                       |
 *                      |                       |
 *                      |                       |
 *                      |      Core heap        | (used for loadable modules)
 * 0xffffffff.40000000  |-----------------------|- core_base / ekernelheap
 *                      |        Kernel         |
 *                      |         heap          |
 *                      |                       |
 *                      |                       |
 * 0xffffXXXX.XXX00000  |-----------------------|- kernelheap (floating)
 *                      |        segmap         |
 * 0xffffXXXX.XXX00000  |-----------------------|- segmap_start (floating) (toxic_end?)
 *                      |    device mappings    |
 * 0xffffXXXX.XXX00000  |-----------------------|- toxic_addr (floating, maybe unallocated below here?) (dtrace_toxic_ranges!)
 *                      |        segzio         |
 * 0xffffXXXX.XXX00000  |-----------------------|- segzio_base (floating)
 *                      |        segkvmm        |
 *                      |                       |
 *                      |                       |
 *                      |                       |
 * 0xffffXXXX.XXX00000  |-----------------------|- segkvmm_base (floating)
 *                      |        segkp          |
 *                      |-----------------------|- segkp_base (floating)
 *                      |   page_t structures   |  valloc_base + valloc_sz
 *                      |   memsegs, memlists,  |
 *                      |   page hash, etc.     |
 * 0xffff2080.00000000  |-----------------------|- valloc_base (32TiB maximum)
 *                      |        segkpm         |
 *                      |                       |
 * 0xffff0080.00000000  |-----------------------|- SEGKPM_BASE
 * 0xffff0040.00000000  |-- UEFI Runtime Data --|- uefi_runtime_base (dtrace_toxic_ranges!)
 * 0xffff003e.00000000  |--    Framebuffer    --|- framebuffer_base (dtrace_toxic_ranges!)
 * 0xffff003c.00000000  |--     Shadow FB     --|- shadowfb_base (dtrace_toxic_ranges!)
 * 0xffff0000.00000000  |-----------------------|- KERNELBASE
 *                      :       VA Hole         :
 * 0x0000ffff.ffffffff  |-----------------------|- USERLIMIT
 *                      |     User stack        |- User space memory
 *                      |                       |
 *                      | shared objects, etc   |       (grows downwards)
 *                      :                       :
 *                      |                       |
 * 0x00008000.00000000  |-----------------------|
 *                      |                       |
 *                      | VA Hole / unused      | (make this a red zone at 128TiB for 512GiB)
 *                      |                       |
 * 0x00008000.00000000  |-----------------------|
 *                      |                       |
 *                      |                       |
 *                      :                       :
 *                      |       user heap       |       (grows upwards)
 *                      |                       |
 *                      |       user data       |
 *                      |-----------------------|
 *                      |       user text       |
 * 0x00000000.04000000  |-----------------------| (make this 2MiB)
 *                      |       invalid         |
 * 0x00000000.00000000  +-----------------------+

 * NEWEST LAYOUT
 *       4MiB @ ($TOP -       4MiB) (0xffffffffffc00000): kernel arguments, environment (ARGSBASE), temp mappings - 0xfffffffffffc0000 (256k) to end maps DBG2, if present
 *       4MiB @ ($TOP -       8MiB) (0xffffffffff800000): debugger (SEGDEBUGBASE)
 *    1016MiB @ ($TOP -       1GiB) (0xffffffffc0000000): unused (rootfs etc. during boot, but that *should* be physical)
 *       4MiB @ ($TOP -    1028MiB) (0xffffffffbfc00000): kernel data segment - only 4MiB after bootup, has modules appended during bootup
 *       4MiB @ ($TOP -    1032MiB) (0xffffffffbf800000): kernel text segment (KERNEL_TEXT)
 *    2040MiB @ ($TOP -       3GiB) (0xffffffff40000000): core_base (pc-relative range limit of kernel) - toxic ends here
 *       1TiB @ ($TOP -       2TiB) (0xffffff0000000000): kernelheap (lower bound, sticky to higher region, make up the 1TiB of VA?)
 *
 *
 *
 *
 *       1GiB @ ($TOP -       4GiB) (0xffffffff00000000): efi_runtime_base
 *       2MiB @ ($TOP -    4098MiB) (0xfffffffeffe00000): fb_hi_redzone
 *    1020MiB @ ($TOP -    5118MiB) (0xfffffffec0200000): Framebuffer (252.875MiB for an 8KiB buffer with 32bpp)
 *       2MiB @ ($TOP -       5GiB) (0xfffffffec0000000): fb_lo_redzone
 *       2MiB @ ($TOP -    5122MiB) (0xfffffffebfe00000): shadowfb_hi_redzone
 *    1020MiB @ ($TOP -    6112MiB) (0xfffffffe80200000): Shadow Framebuffer (252.875MiB for an 8KiB buffer with 32bpp)
 *       2MiB @ ($TOP -       6GiB) (0xfffffffe80000000): shadowfb_lo_redzone (ekernelheap)
 *    1019GiB @ ($TOP -       1TiB) (0xffffff0000000000): devmem_va_start / toxic_addr
 *       1TiB @ ($TOP -       2TiB) (0xffffff0000000000): kernelheap (lower bound, sticky to higher region, make up the 1TiB of VA?)
 *       1TiB @ ($TOP -       3TiB) (0xfffffe0000000000): segmap_start (64MiB on 64bit machines, up this a little?  Unchecked upper bound in i86pc!)
 *                                                        segzio_base (1.5x physmem - 48TiB max)
 *                                                        segkvmm_base (4x physmem - 128TiB max)
 *                                                        segkp_base (sized how?)
 * (variable) @ ($TOP -  228864GiB) (0xffff208000000000): VALLOC_BASE / valloc_base (page_t structures etc. - max size ~6TiB?)
 *      32TiB @ ($TOP -  261632GiB) (0xffff008000000000): SEGKPM_BASE (map of all physical address space - up to 32TiB supported, 1x physical memory)
 *     512GiB @ ($TOP -     256TiB) (0xffff000000000000): KERNELBASE (space is one top level page table entry of red zone)
 *
 * -  segkpm: 1x physmem allocated (but 1Tb room, below VALLOC_BASE) - 64
 * -  segzio: 1.5x physmem 64*1.5
 * -  segkvmm: 4x physmem - 64*4
 * -  heap: whatever's left up to COREHEAP_BASE, at least 1.5x physmem
 *
 * NEW LAYOUT
 *    8MiB @ ($TOP -       8MiB) (0xffffffffff800000): kernel arguments, environment (ARGSBASE), temp mappings - 0xfffffffffffc0000 (256k) to end maps DBG2, if present
 *    8MiB @ ($TOP -      16MiB) (0xffffffffff000000): debugger (SEGDEBUGBASE)
 *  112MiB @ ($TOP -     128MiB) (0xfffffffff8000000): UEFI runtime code and data
 *  896MiB @ ($TOP -    1024MiB) (0xffffffffc0000000): Unallocated
 * 1024MiB @ ($TOP -    2048MiB) (0xffffffff80000000): Framebuffer
 * 1024MiB @ ($TOP -    3072MiB) (0xffffffff40000000): Shadow Framebuffer
 *                                                     <<$TOP-124GiB>> -- map out 124GiB here during boot L0 [512x512GiB] points to L1 [512*1GiB] -> L2 [512*2MiB]
 *    4MiB @ ($TOP -  126980MiB) (0xffffffe0ffc00000): kernel data segment - only 4MiB after bootup, has modules appended during bootup
 *    4MiB @ ($TOP -  126984MiB) (0xffffffe0ff800000): kernel text segment (KERNEL_TEXT)
 * 4088MiB @ ($TOP -     128GiB) (0xffffffe000000000): core_base / ekernelheap (also debug info, GDT, IDT, LDT) -- this base to top of kernel text must be within PC-relative range (perf)
 *                                                     kernelheap (floating, snuggles up to core_base via ekernelheap - starts at )
 *                                                     segmap_start (floating)
 *                                                     toxic_addr (floating?)
 *                                                     segzio_base (floating)
 *                                                     segkvmm_base (floating)
 *                                                     segkp_base (floating, valloc_base + valloc_sz)
 *  XXXXXX @ ($TOP -  XXXXXXXXX) (0xffff208000000000): VALLOC_BASE / valloc_base (page_t structures etc. - max size?)
 *   32TiB @ ($TOP -  261632GiB) (0xffff008000000000): SEGKPM_BASE (map of all physical address space - up to 32TiB accounted for)
 *  512GiB @ ($TOP -     256TiB) (0xffff000000000000): KERNELBASE (space is one top level page table entry of red zone)
 *
 * -  segkpm: 1x physmem allocated (but 1Tb room, below VALLOC_BASE) - 64
 * -  segzio: 1.5x physmem 64*1.5
 * -  segkvmm: 4x physmem - 64*4
 * -  heap: whatever's left up to COREHEAP_BASE, at least 1.5x physmem
 *
 *    4MiB @ ($TOP -    4MiB) (0xffffffffffc00000): kernel arguments, environment (ARGSBASE), temp mappings - 0xfffffffffffc0000 (256k) to end maps DBG2, if present
 *    4MiB @ ($TOP -    8MiB) (0xffffffffff800000): debugger (SEGDEBUGBASE)
 *   24MiB @ ($TOP -   32MiB) (0xfffffffffe000000): UEFI runtime code and data << we will map these on 2MiB in the loader, then remap them properly in the OS
 *   36MiB @ ($TOP -   68MiB) (0xfffffffffbc00000): kernel data segment - only 4MiB after bootup
 *    4MiB @ ($TOP -   72MiB) (0xfffffffffb800000): kernel text segment (KERNEL_TEXT)
 * 4024MiB @ ($TOP -    4GiB) (0xffffffff00000000): core_base / ekernelheap (also debug info, GDT, IDT, LDT) -- this base to top of kernel text must be within PC-relative range (perf)
 *
 * ~~~ everything below here could be dynamically sized based on total memory ~~~
 *  10TiB @ ($TOP - XXXXXXX): kernelheap << excessive?
 * segmap_start
 * toxic_addr (device mappings base?)
 * segzio_base
 * segkvmm_base
 * segkp_base
 * valloc_base
 * SEGKPM_BASE << direct map
 * KERNELBASE
 *
 * Maybe a 1:3 split is a good idea? 64TiB kernel, 192TiB user.
 * Or maybe a 1:7 split: 32TiB kernel and 224TiB user. <<< let's do this and
 * allow for adjusting to a 1:3 split later.
 *
 * XXX: seems we can do 256TiB/256TiB! This would be 49 bit addresses and a
 * four level page table.
 */

/*
 * Sizing Assumptions:
 *  sizeof(page_t) == 80 bytes
 *  Granule size: 4KiB
 *  Maximum 256TiB of RAM
 *
 * page_t storage will be 5TiB to manage 256TiB of RAM, so we allow that much
 * VA space up-front.
 *
 * (((256.*1024.*1024.*1024.*1024.)/4096.)*80.)/1024./1024./1024./1024.
 *
 * + space for memsegs, memlists, page hash etc. - so we can safely
 * assume another 5TiB of VA should be enough?
 *
 * kernelbase: On a 32-bit kernel the default value of 0xd4000000 will be
 * decreased by 2X the size required for page_t.  This allows the kernel
 * heap to grow in size with physical memory.  With sizeof(page_t) == 80
 * bytes, the following shows the values of kernelbase and kernel heap
 * sizes for different memory configurations (assuming default segmap and
 * segkp sizes).
 *
 *      mem     size for        kernelbase      kernel heap
 *      size    page_t's                        size
 *      ----    ---------       ----------      -----------
 *      1gb     0x01400000      0xd1800000      684MB
 *      2gb     0x02800000      0xcf000000      704MB
 *      4gb     0x05000000      0xca000000      744MB
 *      6gb     0x07800000      0xc5000000      784MB
 *      8gb     0x0a000000      0xc0000000      824MB
 *      16gb    0x14000000      0xac000000      984MB
 *      32gb    0x28000000      0x84000000      1304MB
 *      64gb    0x50000000      0x34000000      1944MB (*)
 */

/*
 *              64-bit Kernel's Virtual memory layout. (assuming 64 bit app)
 *                      +-----------------------+
 *                      |                       |
 * 0xFFFFFFFF.FFC00000  |-----------------------|- ARGSBASE
 *                      |       debugger (?)    |
 * 0xFFFFFFFF.FF800000  |-----------------------|- SEGDEBUGBASE
 *                      |      unused           |
 *                      +-----------------------+
 *                      |      Kernel Data      |
 * 0xFFFFFFFF.FBC00000  |-----------------------|
 *                      |      Kernel Text      |
 * 0xFFFFFFFF.FB800000  |-----------------------|- KERNEL_TEXT
 *                      |---    debug info   ---|- debug info (DEBUG_INFO_VA)
 *                      |---       GDT       ---|- GDT page (GDT_VA)
 *                      |---       IDT       ---|- IDT page (IDT_VA)
 *                      |---       LDT       ---|- LDT pages (LDT_VA)
 *                      |                       |
 *                      |      Core heap        | (used for loadable modules)
 * 0xFFFFFFFF.C0000000  |-----------------------|- core_base / ekernelheap
 *                      |        Kernel         |
 *                      |         heap          |
 *                      |                       |
 *                      |                       |
 * 0xFFFFFXXX.XXX00000  |-----------------------|- kernelheap (floating)
 *                      |        segmap         |
 * 0xFFFFFXXX.XXX00000  |-----------------------|- segmap_start (floating)
 *                      |    device mappings    |
 * 0xFFFFFXXX.XXX00000  |-----------------------|- toxic_addr (floating)
 *                      |        segzio         |
 * 0xFFFFFXXX.XXX00000  |-----------------------|- segzio_base (floating)
 *                      |        segkvmm        |
 *                      |                       |
 *                      |                       |
 *                      |                       |
 * 0xFFFFFXXX.XXX00000  |-----------------------|- segkvmm_base (floating)
 *                      |        segkp          |
 *                      |-----------------------|- segkp_base (floating)
 *                      |   page_t structures   |  valloc_base + valloc_sz
 *                      |   memsegs, memlists,  |
 *                      |   page hash, etc.     |
 * 0xFFFFFE00.00000000  |-----------------------|- valloc_base (lower if >256GB)
 *                      |        segkpm         |
 *                      |                       |
 * 0xFFFFFD00.00000000  |-----------------------|- SEGKPM_BASE (lower if >256GB)
 *                      |       Red Zone        |
 * 0xFFFFFC80.00000000  |-----------------------|- KERNELBASE (lower if >256GB)
 * 0xFFFFFC7F.FFE00000  |-----------------------|- USERLIMIT (lower if >256GB)
 *                      |     User stack        |- User space memory
 *                      |                       |
 *                      | shared objects, etc   |       (grows downwards)
 *                      :                       :
 *                      |                       |
 * 0xFFFF8000.00000000  |-----------------------|
 *                      |                       |
 *                      | VA Hole / unused      |
 *                      |                       |
 * 0x00008000.00000000  |-----------------------|
 *                      |                       |
 *                      |                       |
 *                      :                       :
 *                      |       user heap       |       (grows upwards)
 *                      |                       |
 *                      |       user data       |
 *                      |-----------------------|
 *                      |       user text       |
 * 0x00000000.04000000  |-----------------------|
 *                      |       invalid         |
 * 0x00000000.00000000  +-----------------------+
 */
	/*
	 * The Memory Attribute Indirection Register (MAIR) allows us to provide
	 * (in poge table entries) a simple index value that indexes into eight
	 * memory attribute definitions in the MAIR.
	 *
	 * The indices we define are common to all aarch64 ports, but need to be
	 * placed into the MAIR in early bootup, prior to turning on the MMU.
	 *
	 * The values themselves are a combination of those found in the
	 * original port and those found in FreeBSD.
	 *
	 * Document Reference:
	 * MAIR_EL1, Memory Attribute Indirection Register (EL1)
	 * DDI0487G (B) ARMv8 ARM, D13.2.95.
	 *
	 * The goal of all of this is to support advisory odering flags on
	 * device memory, where appropriate.  The HAT layer passes the following
	 * to arch/mach code (see uts/common/vm/hat.h for documentation).
	 * - HAT_STRICTORDER
	 * - HAT_UNORDERED_OK
	 * - HAT_MERGING_OK
	 * - HAT_LOADCACHING_OK
	 * - HAT_STORECACHING_OK
	 *
	 * MAIR entries have the following layout:
	 * Bits [7:4]
	 * 0b0000: Device Memory
	 * 0b00RW: RW not 00, Normal Memory, Outer Write-through transient.
	 * 0b0100: Normal Memory, Outer Non-Cacheable.
	 * 0b01RW: RW not 00, Normal Memory, Outer Write-back transient.
	 * 0b10RW: Normal Memory, Outer Write-through non-transient.
	 * 0b11RW: Normal Memory, Outer Write-back non-transient.
	 *
	 * In the Device Memory case ([7:4] == 0b0000), bits [3:0] are:
	 * 0b0000: Device-nGnRnE memory
	 * 0b0100: Device-nGnRE memory
	 * 0b1000: Device-nGRE memory
	 * 0b1100: Device-GRE memory
	 *
	 * In the non-device case ([7:4] != 0b0000), bits [3:0] are:
	 * 0b00RW: RW not 00, Normal Memory, Inner Write-through transient.
	 * 0b0100: Normal memory, Inner Non-Cacheable.
	 * 0b01RW: RW not 00, Normal Memory, Inner Write-back transient.
	 * 0b1000: Normal Memory, Inner Write-through non-transient (RW=00)
	 * 0b10RW: RW not 00, Normal Memory, Inner Write-through non-transient
	 * 0b1100: Normal Memory, Inner Write-back non-transient (RW=00)
	 * 0b11RW: RW not 00, Normal Memory, Inner Write-back non-transient
	 *
	 * The RW bits represent the outer read and write allocate policy
	 * respectively, and have the following meanings:
	 * 0: Do not allocate
	 * 1: Allocate
	 */

	/*
	 * At entry we are in a64 state.  We are either running under an
	 * identity mapping or have the MMU disabled.  Interrupts ought to be
	 * disabled.
	 *
	 * The module dictionary pointer is in x0, in KVA.
	 */
	ENTRY_NP(_start)
	/*
	 * Stash our physical entry address into x28 and the VA/PA delta for
	 * unix into x29.  Adjust the passed module pointer (which is provided
	 * as a kernel VA based on the main unix VMA) to point to physical
	 * space and stash it in x27 so that it survives cache flush.
	 */
	bl	1f
	sub	x28, lr, #0x4
	b	2f
1:	ret
2:	ldr	x29, =(EBOOT_TEXT)
	sub	x29, x29, x28
	sub	x27, x0, x29

	/*
	 * Before we (possibly) leave HYP mode we ensure that all data has been
	 * written out to main memory and there are no stake entries in the TLB.
	 *
	 * Note that we should be using vmalle1os, but it's not available on all
	 * revisions of the architecture.
	 *
	 * The flush_data_cache_all routine trashes registers up to x17, which
	 * is why we stash things into higher registers above.
	 *
	 * TODO: use vmalle1os where available.
	 */
	bl	flush_data_cache_all
	dsb	ish
	ic	iallu
	dmb	ish
	isb
	dsb	ish
	tlbi	vmalle1is
	dsb	ish
	isb

	/*
	 * If we were loaded to EL2 we leave a few stub exception handlers in
	 * place and drop down to EL1.
	 *
	 * The drop_to_el1 trashes registers x2 and x23.
	 */
	bl	drop_to_el1

	/*
	 * We're now definitely in supervisor mode (EL1).
	 *
	 * Disable the MMU.
	 *
	 * We've either entered the kernel with an identity mapping, or with no
	 * address translation.  Switch off address translation here while we
	 * set up our own view of the world.
	 */
	dsb	sy
	mrs	x2, sctlr_el1
	bic	x2, x2, SCTLR_M
	msr	sctlr_el1, x2
	isb

	/* Set the context id */
	msr	contextidr_el1, xzr

	/*
	 * Clear the initial stack
	 */
	adrp	x6, initstack
	add	x6, x6, :lo12:initstack
	adrp	x7, initstack_end
	add	x7, x7, :lo12:initstack_end
1:	stp	xzr, xzr, [x6], #16
	stp	xzr, xzr, [x6], #16
	stp	xzr, xzr, [x6], #16
	stp	xzr, xzr, [x6], #16
	cmp	x6, x7
	b.lo	1b

	/*
	 * Set up our stack pointer.  This is our loaded address, so it's still
	 * valid once we process relocations.
	 */
	bic	sp, x7, #0x7

	/*
	 * Before anything else, reserve some nice clean space for the bootinfo
	 * structure.  Doing this early prevents an C calls we make dirtying
	 * the (presently zeroed) memory.
	 */
	mov	x1, sp
	sub	x1, x1, #(XBI_SIZE)
	bic	x1, x1, #0x7
	mov	sp, x1

	str	x29, [x1, #XBI_VA_PA_DELTA]
	str	x28, [x1, #XBI_PHYSLOAD]

	/*
	 * Since we now have a stack, and we're about to call C code, stash
	 * anything we've computed to date onto our stack so that we don't lose
	 * it.
	 */
	stp	x27, x1, [sp, #-16]!	/* modulep, xbi */
	stp	x28, x29, [sp, #-16]!	/* physload, delta */

	/*
	 * Relocate eboot to the loaded address.
	 *
	 * The self_reloc function takes two arguments:
	 * - The address we were loaded at (in x28 at this point)
	 * - The relative address of the ELF dynamic relocs
	 */
	mov	x0, x28
	adrp	x1, _DYNAMIC
	add	x1, x1, :lo12:_DYNAMIC
	bl	self_reloc

	/*
	 * We've processed any outstanding relocations (which should all be
	 * relative relocs), so we're nearly ready to call the C code.
	 *
	 * Clear the BSS.
	 */
	ldr	x15, =__bss_start
	ldr	x14, =__bss_end
	b	1f
2:	str	xzr, [x15], #8
1:	cmp	x15, x14
	b.lo	2b

	adrp	x14, eboot_vectors
	add	x14, x14, :lo12:eboot_vectors
	msr	vbar_el1, x14

	/*
	 * We call the C code with the MMU off.
	 *
	 * This is a bit of an odd choice, but it solves the chicken-and-egg
	 * problem of identity mapping all valid memory when you don't yet know
	 * enough about the installed memory.
	 *
	 * The C code is pretty short, so this should not be a performance
	 * concern.
	 *
	 * Pop the variables we stashed onto the stack, then set up the bootinfo
	 * structure.
	 *
	 * The module pointer, passed to us by loader, is passed to
	 * startup_kernel as the first argument.  The bootinfo we create here
	 * is passed to startup_kernel as the second argument, and later to
	 * the kernel as the first argument.
	 *
	 * startup_kernel returns the entry point, in KVA, of unix itself.
	 */
	ldp	x28, x29, [sp], #16
	ldp	x0, x1, [sp], #16
	stp	x1, xzr, [sp, #-16]!	/* preserve bootinfo */

	mov	fp, #0
	bl	startup_kernel
	ldp	x1, xzr, [sp], #16
	stp	x0, x1, [sp, #-16]!	/* unix _start, bootinfo, for later */

	/*
	 * The C code has updated the bootinfo structure and has returned the
	 * kernel entry point (in VA space) to us.
	 *
	 * Our contract with the C code is that it will never return an invalid
	 * set of data to us (it will panic instead), so plough on.
	 *
	 * We now load up the TTBR0 and TTBR1 registers with the values stored
	 * in the bootinfo structure by the C code, then turn on the MMU.
	 *
	 * All of memory is identity mapped (in TTBR0), which lets us survive
	 * the transition.  To complete our move to VA we need to jump to a
	 * virtual address, which is the kernel entry point in our case.
	 */
	bl	flush_data_cache_all
	dsb	ish
	ic	iallu
	dmb	ish
	isb
	dsb	ish
	tlbi	vmalle1is
	dsb	ish
	isb

	ldp	x1, x0, [sp], #16	/* retrieve unix _start, bootinfo */
	ldr	x29, [x0, #XBI_TTBR0]
	ldr	x28, [x0, #XBI_TTBR1]
	ldr	x27, [x0, #XBI_MAIR]
	ldr	x26, [x0, #XBI_TCR]
	ldr	x25, [x0, #XBI_SCTLR]

	dsb	sy
	msr	ttbr0_el1, x29		/* set bottom-half translation tables */
	msr	ttbr1_el1, x28		/* set top-half translation tables */
	isb

	msr	mdscr_el1, xzr		/* clear monitor debug register */

	tlbi	vmalle1is		/* invalidate the TLB */
	dsb	ish
	isb

	msr	mair_el1, x27		/* memory attribute indirection */
	msr	tcr_el1, x26		/* translation control */
	msr	sctlr_el1, x25		/* system control */
	isb

	/*
	 * The MMU is now on, but our PC is still in physical space.
	 *
	 * To complete our move to VA we need to jump to a virtual address, and
	 * the kernel entry point just happens to be conveniently in x1...
	 */
	blr	x1			/* and... jump */
	b	eboot_halt
1:	b	1b
	SET_SIZE(_start)

	ENTRY_P(drop_to_el1)
	mrs	x23, CurrentEL		/* grab the current EL */
	lsr	x23, x23, #2		/* shift into place */
	and	x23, x23, #3		/* clean it up */
	cmp	x23, #0x2		/* check if we're in EL2 */
	b.eq	1f			/* yep, proceed to drop to EL1 */
	ret				/* already out of EL2, we're done */

1:	/* Configure the Hypervisor */
	mov	x2, #(HCR_RW)
	msr	hcr_el2, x2

	/* Load the Virtualization Process ID Register */
	mrs	x2, midr_el1
	msr	vpidr_el2, x2

	/* Load the Virtualization Multiprocess ID Register */
	mrs	x2, mpidr_el1
	msr	vmpidr_el2, x2

	/* Set the bits that need to be 1 in sctlr_el1 */
	ldr	x2, .Lsctlr_res1
	msr	sctlr_el1, x2

	/* Don't trap to EL2 for exceptions */
	mov	x2, #CPTR_RES1
	msr	cptr_el2, x2

	/* Don't trap to EL2 for CP15 traps */
	msr	hstr_el2, xzr

	/* Enable access to the physical timers at EL1 */
	mrs	x2, cnthctl_el2
	orr	x2, x2, #(CNTHCTL_EL1PCTEN | CNTHCTL_EL1PCEN)
	msr	cnthctl_el2, x2

	/* Set the counter offset to a known value */
	msr	cntvoff_el2, xzr

	/* Hypervisor trap functions */
	adrp	x2, hyp_vectors
	add	x2, x2, :lo12:hyp_vectors
	msr	vbar_el2, x2

	/* SPSR setup: no FIQ, no IRQ, no alignment faults, D? M? */
	mov	x2, #(PSR_F | PSR_I | PSR_A | PSR_D | PSR_M_EL1h)
	msr	spsr_el2, x2

	/* Configure GICv3 CPU interface */
	mrs	x2, id_aa64pfr0_el1
	/* Extract GIC bits from the register */
	ubfx	x2, x2, #ID_AA64PFR0_GIC_SHIFT, #ID_AA64PFR0_GIC_BITS
	/* GIC[3:0] == 0001 - GIC CPU interface via special regs. supported */
	cmp	x2, #(ID_AA64PFR0_GIC_CPUIF_EN >> ID_AA64PFR0_GIC_SHIFT)
	b.ne	2f	/* if not supported, skip setup */

	mrs	x2, icc_sre_el2
	orr	x2, x2, #ICC_SRE_EL2_EN	/* Enable access from insecure EL1 */
	orr	x2, x2, #ICC_SRE_EL2_SRE	/* Enable system registers */
	msr	icc_sre_el2, x2
2:

	/* Set the address to return to our return address */
	msr	elr_el2, x30
	isb

	eret

	.align	3
.Lsctlr_res1:
	.quad SCTLR_RES1
	SET_SIZE(drop_to_el1)

	ENTRY_NP(read_sctlr_el1)
	mrs	x0, sctlr_el1
	ret
	SET_SIZE(read_sctlr_el1)

	ENTRY_NP(read_id_aa64mmfr0_el1)
	mrs	x0, id_aa64mmfr0_el1
	ret
	SET_SIZE(read_id_aa64mmfr0_el1)

	ENTRY_NP(read_id_aa64mmfr1_el1)
	mrs	x0, id_aa64mmfr1_el1
	ret
	SET_SIZE(read_id_aa64mmfr1_el1)

	ENTRY_NP(eboot_halt)
	msr	daifset, #15
1:	wfe
	b	1b
	SET_SIZE(eboot_halt)

#define	VECT_EMPTY	\
	.align 7;	\
	1:	b	1b

	.align	11
	.type	hyp_vectors, @object
hyp_vectors:
	VECT_EMPTY	/* Synchronous EL2t */
	VECT_EMPTY	/* IRQ EL2t */
	VECT_EMPTY	/* FIQ EL2t */
	VECT_EMPTY	/* Error EL2t */

	VECT_EMPTY	/* Synchronous EL2h */
	VECT_EMPTY	/* IRQ EL2h */
	VECT_EMPTY	/* FIQ EL2h */
	VECT_EMPTY	/* Error EL2h */

	VECT_EMPTY	/* Synchronous 64-bit EL1 */
	VECT_EMPTY	/* IRQ 64-bit EL1 */
	VECT_EMPTY	/* FIQ 64-bit EL1 */
	VECT_EMPTY	/* Error 64-bit EL1 */

	VECT_EMPTY	/* Synchronous 32-bit EL1 */
	VECT_EMPTY	/* IRQ 32-bit EL1 */
	VECT_EMPTY	/* FIQ 32-bit EL1 */
	VECT_EMPTY	/* Error 32-bit EL1 */
	SET_SIZE(hyp_vectors)

#define	VECT_EMPTY_N(n)	\
	ENTRY_NP(n)	\
	.align 7;	\
	1:	b	1b;	\
	SET_SIZE(n)

	.align	11
	.type	eboot_vectors, @object
eboot_vectors:
	VECT_EMPTY	/* Synchronous EL1t */
	VECT_EMPTY	/* IRQ EL1t */
	VECT_EMPTY	/* FIQ EL1t */
	VECT_EMPTY	/* Error EL1t */

	VECT_EMPTY_N(eboot_cur_el_with_spx_sync)
	VECT_EMPTY_N(eboot_cur_el_with_spx_irq)
	VECT_EMPTY_N(eboot_cur_el_with_spx_fiq)
	VECT_EMPTY_N(eboot_cur_el_with_spx_serr)

	VECT_EMPTY	/* Synchronous 64-bit EL1 */
	VECT_EMPTY	/* IRQ 64-bit EL1 */
	VECT_EMPTY	/* FIQ 64-bit EL1 */
	VECT_EMPTY	/* Error 64-bit EL1 */

	VECT_EMPTY	/* Synchronous 32-bit EL1 */
	VECT_EMPTY	/* IRQ 32-bit EL1 */
	VECT_EMPTY	/* FIQ 32-bit EL1 */
	VECT_EMPTY	/* Error 32-bit EL1 */
	SET_SIZE(eboot_vectors)

	.data
	.align	4
	.type	eboot_cur_el_with_spx_irq_panicstr, @object
eboot_cur_el_with_spx_irq_panicstr:
	.asciz  "eboot: synchronous exception ESR 0x%lx FAR 0x%lx\n"
	SET_SIZE(eboot_cur_el_with_spx_irq_panicstr)

	.data
	.align	4
	.type	initstack, @object
initstack:
	.space	0x2000
initstack_end:
	SET_SIZE(initstack)
