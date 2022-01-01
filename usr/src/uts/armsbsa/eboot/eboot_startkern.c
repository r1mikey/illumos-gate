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
 *
 * Copyright 2020 Joyent, Inc.
 */


#include <sys/ctype.h>
#include <sys/types.h>
#include <sys/inttypes.h>
#include <sys/machparam.h>
#include <sys/archmmu.h>
#include <sys/systm.h>
#if 1
#include <sys/mach_mmu.h>
#endif
#include <sys/sysmacros.h>
#include <sys/framebuffer.h>
#include <sys/sha1.h>
#include <util/string.h>
#include <util/strtolctype.h>
#include <sys/efi.h>
#include <sys/smbios.h>
#include <sys/acpi/platform/acsolaris.h>
#include <sys/acpi/actypes.h>
#include <sys/acpi/actbl.h>

#include <sys/inttypes.h>
#include <sys/bootinfo.h>
#include <sys/boot_console.h>
#include <sys/elf.h>
/* #include "eboot_asm.h" */
#include "eboot_printf.h"
#include "eboot_xboot.h"

struct efi_map_header {
	size_t		memory_size;
	size_t		descriptor_size;
	uint32_t	descriptor_version;
};

extern uint64_t read_id_aa64mmfr0_el1(void);
extern uint64_t read_id_aa64mmfr1_el1(void);
extern uint64_t read_sctlr_el1(void);

static int relocated = 1;

uintptr_t hole_start = HOLE_START;
uintptr_t hole_end = HOLE_END;

uint64_t physmax = 0;
uint64_t physmin = -(uint64_t)1;

extern uint64_t _sbsa_dbg2_addr;
extern uint64_t _sbsa_dbg2_type;

extern paddr_t ttbr1_top_table;
extern paddr_t ttbr0_top_table;

#define	MAYBE_VTOP(__x)	((__x) >= hole_end ? VTOP((__x)) : (__x))

/*
 * Define EARLY_DBG2_PA to the value of the first Generic Address Structure for
 * a DBG2 ARM SBSA Generic UART compatible UART as presented by your board. This
 * is a PL011-compatible UART subset, and we only use the DR and FR registers
 * this early in the game.  The UART should be pre-configured by the firmware.
 *
 * The above address cannot be 0x0 and really ought to be 4KiB aligned.
 *
 * The early bootstrap code blindly maps 256KiB of device VA onto this address
 * in 4KiB chunks.
 *
 * This is only used until the DBG2 port can be found in ACPI tables and
 * properly hooked up.
 *
 * For now, you should use 0x000e (ARM SBSA Generic UART), 0x0003 (ARM PL011
 * UART) or 0x0010 (BCM2835) as the value of EARLY_DBG2_TYPE.  As support is
 * added for other UART types this list should be updated.
 */
#define	EARLY_DBG2_PA	0x60000000ULL
#define	EARLY_DBG2_TYPE	0x000e

#define	VTOP(x)		((x) - bi->bi_va_pa_delta)
#define	PTOV(x)		((x) + bi->bi_va_pa_delta)

/*
 * Module information subtypes
 *
 * XXXAARCH64: we won't need a lot of these
 */
#define MODINFO_END             0x0000          /* End of list */
#define MODINFO_NAME            0x0001          /* Name of module (string) */
#define MODINFO_TYPE            0x0002          /* Type of module (string) */
#define MODINFO_ADDR            0x0003          /* Loaded address */
#define MODINFO_SIZE            0x0004          /* Size of module */
#define MODINFO_EMPTY           0x0005          /* Has been deleted */
#define MODINFO_ARGS            0x0006          /* Parameters string */
#define MODINFO_METADATA        0x8000          /* Module-specfic */

#define MODINFOMD_AOUTEXEC      0x0001          /* a.out exec header */
#define MODINFOMD_ELFHDR        0x0002          /* ELF header */
#define MODINFOMD_SSYM          0x0003          /* start of symbols */
#define MODINFOMD_ESYM          0x0004          /* end of symbols */
#define MODINFOMD_DYNAMIC       0x0005          /* _DYNAMIC pointer */
#define MODINFOMD_MB2HDR        0x0006          /* MB2 header info */
/* These values are MD on PowerPC */
#if !defined(__powerpc__)
#define MODINFOMD_ENVP          0x0006          /* envp[] */
#define MODINFOMD_HOWTO         0x0007          /* boothowto */
#define MODINFOMD_KERNEND       0x0008          /* kernend */
#endif
#define MODINFOMD_SHDR          0x0009          /* section header table */
#define MODINFOMD_CTORS_ADDR    0x000a          /* address of .ctors */
#define MODINFOMD_CTORS_SIZE    0x000b          /* size of .ctors */
#define MODINFOMD_FW_HANDLE     0x000c          /* Firmware dependent handle */
#define MODINFOMD_KEYBUF        0x000d          /* Crypto key intake buffer */
#define MODINFOMD_FONT          0x000e          /* Console font */
#define MODINFOMD_NOCOPY        0x8000          /* don't copy this metadata to the kernel */

#define MODINFOMD_DEPLIST       (0x4001 | MODINFOMD_NOCOPY)     /* depends on */

#define MODINFOMD_EFI_MAP       0x1001
#define MODINFOMD_DTBP          0x1002
#define MODINFOMD_EFI_FB        0x1003

#define efi_mmap_next(ptr, size) \
	((EFI_MEMORY_DESCRIPTOR *)(((uint8_t *)(ptr)) + (size)))


/*
 * Compile time debug knob. We do not have any early mechanism to control it
 * as the boot is the earliest mechanism we have, and we do not want to have
 * it being switched on by default.
 */
int eboot_debug = 0;
struct xboot_info *bi = NULL;
void *fmodulep = NULL;
void *kmdp = NULL;
const char *envp = NULL;
caddr_t mod_ssym = NULL;
caddr_t mod_esym = NULL;
EFI_SYSTEM_TABLE64 *efi = NULL;
ACPI_TABLE_RSDP *rsdp = NULL;
ACPI_TABLE_XSDT *xsdt = NULL;
uint64_t *ttbr1tab = NULL;
uint64_t *toptab = NULL;
uint64_t *toptop = NULL;
uint64_t next_avail_addr = 0;
uint64_t memavail = 0;
uint64_t kernel_start_addr = 0;
uint64_t kernel_load_start = 0;
uint64_t kernel_load_end = 0;
uint64_t md_end = 0;

/* Updated to the value of the eboot_image in the loaded kernel */
static uint64_t target_kernel_text = KERNEL_TEXT;

uint64_t nucleus_paddr = 0;	/* done */
uint64_t nucleus_size = 0;	/* done */
uint64_t rootfs_paddr = 0;	/* done */
uint64_t rootfs_size = 0;	/* done */
uint64_t font_paddr = 0;
uint64_t font_size = 0;
uint64_t env_paddr = 0;		/* done */
uint64_t env_size = 0;		/* done */
uint64_t cmdline_paddr = 0;
uint64_t cmdline_size = 0;

uint64_t relocated_uefi_systab;

struct efi_map_header *uefi_map_hdr = NULL;

/* can not be automatic variables because of alignment */
static efi_guid_t smbios3 = SMBIOS3_TABLE_GUID;
static efi_guid_t smbios = SMBIOS_TABLE_GUID;
static efi_guid_t acpi2 = EFI_ACPI_TABLE_GUID;	/* EFI_ACPI_20_TABLE_GUID */
static efi_guid_t acpi1 = ACPI_10_TABLE_GUID;
static efi_guid_t efi_global_var = EFI_GLOBAL_VARIABLE;
static efi_guid_t mps = MPS_TABLE_GUID;
static efi_guid_t sal = SAL_SYSTEM_TABLE_GUID;
static efi_guid_t fdt = FDT_TABLE_GUID;
static efi_guid_t dxe = DXE_SERVICES_TABLE_GUID;
static efi_guid_t hob = HOB_LIST_TABLE_GUID;
static efi_guid_t mti = MEMORY_TYPE_INFORMATION_TABLE_GUID;
static efi_guid_t dii = DEBUG_IMAGE_INFO_TABLE_GUID;
static efi_guid_t ept = EFI_PROPERTIES_TABLE_GUID;

struct dbg2_memlist {
	uint64_t va;
	uint64_t pa;
	uint64_t size;
};
#define	MAX_DBG_MEMLIST	(64)
struct dbg2_memlist dbg2memlist[MAX_DBG_MEMLIST] = { { 0, 0, 0 } };
uint_t dbg2memlist_used = 0;

/*
 * Memlists for the kernel. We shouldn't need a lot of these.
 */
#define	MAX_MEMLIST (50)
struct boot_memlist memlists[MAX_MEMLIST] = {
	{ 0, 0, 0, 0 }
};
uint_t memlists_used = 0;
struct boot_memlist ememlists[MAX_MEMLIST] = {
	{ 0, 0, 0, 0 }
};
uint_t ememlists_used = 0;
struct boot_memlist pcimemlists[MAX_MEMLIST] = {
	{ 0, 0, 0, 0 }
};
uint_t pcimemlists_used = 0;
struct boot_memlist rsvdmemlists[MAX_MEMLIST] = {
	{ 0, 0, 0, 0 }
};
uint_t rsvdmemlists_used = 0;
/*
 * We need two lists here.  One with va assignments and the original index,
 * the second with MMU stuff
 */
struct uefi_runtime_orig {
	uint64_t	va;
	uint32_t	idx;
	uint32_t	nidx;
};
struct uefi_runtime_orig rtomemlist[MAX_MEMLIST] = {
	{ 0, 0 }
};
uint_t rtomemlist_used = 0;
struct uefi_runtime_memlist {
	uint64_t	pa;
	uint64_t	va;
	uint64_t	size;
	uint64_t	attr;
	uint32_t	type;
};
struct uefi_runtime_memlist rtsmemlist[MAX_MEMLIST] = {
	{ 0, 0, 0, 0 }
};
uint_t rtsmemlist_used = 0;


/*
 * XXXAARCH64: need to pass FB bits from the loader through here to the kernel
 */
static boot_framebuffer_t framebuffer __aligned(16) = {
	0,				/* framebuffer - efi_fb */
	/* origin.x, origin.y, pos.y, pos.y, visible */
	{ { 0, 0 }, { 0, 0 }, 0 }
};
static boot_framebuffer_t *fb = NULL;

/*
 * Standard bits used in page table entries (both leaf and block entries) and
 * in intermediate page tables.  Set up a template for contiguous entries too.
 *
 * In aarch64 the upper and lower attributes of page and block entries are
 * identical, which is very convenient.
 *
 * Device memory is slightly different (uncached would mean write-combining,
 * which we only want for the framebuffer).
 */
aarch64pte_t pte_memory = PT_NOCONSIST
    | PT_ATTR_AF		/* page has been accessed */
    | PT_ATTR_SH(PT_SH_OS)	/* outer sharable */
    | PT_ATTR_AP(PT_AP_PRW)	/* privileged read/write */
    | PT_MATTR(MIDX_MEMORY_WB);	/* normal memory, writeback cacheable */

aarch64pte_t pte_write_combining = PT_NOCONSIST
    | PT_ATTR_AF		/* page has been accessed */
    | PT_ATTR_SH(PT_SH_OS)	/* outer sharable */
    | PT_ATTR_AP(PT_AP_PRW)	/* privileged read/write */
    | PT_MATTR(MIDX_MEMORY_NC);	/* normal memory, non-cacheable */

aarch64pte_t pte_device = PT_NOCONSIST
    | PT_ATTR_AF		/* page has been accessed */
    | PT_ATTR_UXN		/* user execute never */
    | PT_ATTR_PXN		/* privileged execute never */
    | PT_ATTR_AP(PT_AP_PRW)	/* privileged read/write */
    | PT_MATTR(MIDX_DEVICE);	/* device nGnRnE */

/*
 * This should match what's in the bootloader.  It's arbitrary, but GRUB
 * in particular has limitations on how much space it can use before it
 * stops working properly.  This should be enough.
 */
struct boot_modules modules[MAX_BOOT_MODULES] = { { 0, 0, 0, 0 } };
uint_t modules_used = 0;

static int
eboot_same_guids(efi_guid_t *g1, efi_guid_t *g2)
{
	int i;

	if (g1->time_low != g2->time_low)
		return (0);
	if (g1->time_mid != g2->time_mid)
		return (0);
	if (g1->time_hi_and_version != g2->time_hi_and_version)
		return (0);
	if (g1->clock_seq_hi_and_reserved != g2->clock_seq_hi_and_reserved)
		return (0);
	if (g1->clock_seq_low != g2->clock_seq_low)
		return (0);

	for (i = 0; i < 6; i++) {
		if (g1->node_addr[i] != g2->node_addr[i])
			return (0);
	}
	return (1);
}


#if 0
/*
 * Page table and memory stuff.
 */
static paddr_t max_mem;			/* maximum memory address */
static char noname[2] = "-";
#endif

uint_t prom_debug = 0;
uint_t map_debug = 0;

static const char *
rtsmem_code_or_data(uint32_t t)
{
	switch (t) {
	case EfiRuntimeServicesCode:
		return "code";
	case EfiRuntimeServicesData:
		return "data";
	case EfiMemoryMappedIO:
		return "mmio";
	default:
		eboot_panic("Unexpected runtime services mapping %u\n", t);
	}
}

/*
 * This is as terrible as it seems.
 */
static EFI_MEMORY_DESCRIPTOR *
eboot_find_efi_memory_descriptor(uint32_t idx)
{
	EFI_MEMORY_DESCRIPTOR	*p;
	EFI_MEMORY_DESCRIPTOR	*map;
	size_t			efisz;
	uint32_t		ndesc;
	uint32_t		i;

	if (uefi_map_hdr == NULL)
		eboot_panic("No UEFI memory map header set\n");
	if (uefi_map_hdr->descriptor_size == 0)
		eboot_panic("Invalid memory descriptor size\n");

	efisz = (sizeof(struct efi_map_header) + 0xf) & ~0xf;
	map = (EFI_MEMORY_DESCRIPTOR *)((uint8_t *)uefi_map_hdr + efisz);
	ndesc = uefi_map_hdr->memory_size / uefi_map_hdr->descriptor_size;

	for (i = 0, p = map; i < ndesc;
	    i++, p = efi_mmap_next(p, uefi_map_hdr->descriptor_size)) {
		if (i == idx)
			return p;
	}

	eboot_panic("No UEFI memory map entry at index %u\n", idx);
}

static int
eboot_relocate_efi_pointer(uint64_t *ptr)
{
	uint32_t i;

	for (i = 0; i < rtsmemlist_used; ++i) {
		if (*ptr >= rtsmemlist[i].pa &&
		    *ptr < rtsmemlist[i].pa + rtsmemlist[i].size) {
			*ptr += rtsmemlist[i].va - rtsmemlist[i].pa;
			return (1);
		}
	}

	return (0);
}

static void
sort_rtsmem(void)
{
	struct uefi_runtime_memlist tmp;
	struct uefi_runtime_orig tmp2;
	EFI_MEMORY_DESCRIPTOR *dst;
	EFI_MEMORY_DESCRIPTOR *src;
	uint64_t cur_va;
	int i;
	int j;

	if (rtsmemlist_used != rtomemlist_used)
		eboot_panic("Runtime services memlists are mismatched\n");

	/*
	 * Start by sorting both lists by the PA of the MMU list.
	 */
	DBG_MSG("Sorting UEFI runtime services memlists\n");
	for (j = rtsmemlist_used - 1; j > 0; --j) {
		for (i = 0; i < j; ++i) {
			if (rtsmemlist[i].pa < rtsmemlist[i + 1].pa)
				continue;
			tmp = rtsmemlist[i];
			tmp2 = rtomemlist[i];
			rtsmemlist[i] = rtsmemlist[i + 1];
			rtomemlist[i] = rtomemlist[i + 1];
			rtsmemlist[i + 1] = tmp;
			rtomemlist[i + 1] = tmp2;
		}
	}

	/*
	 * Assign virtual addresses - this defragments the virtual view of the
	 * runtime services.
	 *
	 * The assigned VA is recorded twice: once in the MMU view of the
	 * remapping and the second in the UEFI view of the remapping.
	 */
	cur_va = UEFI_RUNTIME_BASE;

	DBG_MSG("Assigning virtual addresses for runtime services\n");
	for (j = 0; j < rtsmemlist_used; ++j) {
		rtsmemlist[j].va = cur_va;
		rtomemlist[j].va = cur_va;
		cur_va += rtsmemlist[j].size;

		DBG_P((" %s: 0x%lx -> 0x%lx\n",
		    rtsmem_code_or_data(rtsmemlist[j].type),
		    rtsmemlist[j].pa, rtsmemlist[j].va));
		if (cur_va >= (UEFI_RUNTIME_BASE + UEFI_RUNTIME_MAX_SIZE))
			eboot_panic("No more VA for UEFI runtime services\n");
	}

	/*
	 * Sort the original list by indices again.
	 *
	 * This list is used to drive repacking the UEFI memory map prior to
	 * handing it back to UEFI runtime services to relocate the runtime
	 * memory regions.
	 */
	DBG_MSG("Resorting original list by index position\n");
	for (j = rtomemlist_used - 1; j > 0; --j) {
		for (i = 0; i < j; ++i) {
			if (rtomemlist[i].idx < rtomemlist[i + 1].idx)
				continue;
			tmp2 = rtomemlist[i];
			rtomemlist[i] = rtomemlist[i + 1];
			rtomemlist[i + 1] = tmp2;
		}
	}

	/*
	 * Assign final indices for the UEFI view of the remapping.  This data
	 * is used when we munge the UEFI-provided data.
	 */
	DBG_MSG("Assigning final indices in the UEFI remapping list\n");
	for (j = 0; j < rtomemlist_used; ++j) {
		rtomemlist[j].nidx = j;
	}

	/*
	 * Merge the MMU view of the runtime services allocations.  Adjacent
	 * memory regions *of the same type with the same attributes* are
	 * merged.
	 *
	 * Merging is driven on the PA, since adjacent PA sections will have
	 * adjacent VA sections (but the opposite is not true).
	 */
	for (i = 0; i <= rtsmemlist_used - 1; ++i) {
		if (rtsmemlist[i].pa + rtsmemlist[i].size !=
		    rtsmemlist[i + 1].pa)
			continue;
		if (rtsmemlist[i].type != rtsmemlist[i + 1].type)
			continue;
		if (rtsmemlist[i].attr != rtsmemlist[i + 1].attr)
			continue;

		if (prom_debug)
			eboot_printf(
			    "merging rts segs %" PRIx64 "...%" PRIx64
			    " w/ %" PRIx64 "...%" PRIx64 "\n",
			    rtsmemlist[i].va,
			    rtsmemlist[i].va + rtsmemlist[i].size,
			    rtsmemlist[i + 1].va,
			    rtsmemlist[i + 1].va + rtsmemlist[i + 1].size);

		rtsmemlist[i].size += rtsmemlist[i + 1].size;
		for (j = i + 1; j < rtsmemlist_used - 1; ++j)
			rtsmemlist[j] = rtsmemlist[j + 1];
		--rtsmemlist_used;
		DBG(rtsmemlist_used);
		--i;	/* after merging we need to reexamine, so do this */
	}

	/*
	 * XXXSHUFFLE
	 */
	/*
	 * I'm really unsure of how right this is.
	 *
	 * FreeBSD does a 1:1 relocation automatically (can be disabled via
	 * setting efi_disable_vmap=YES in EFI/FreeBSD/loader.env), which gets
	 * in the way of us relocating things (you can only call
	 * SetVirtualAddressMap once per boot).
	 *
	 * The other interesting thing FreeBSD does is to simply set the
	 * identity mapping values on all descriptors that need to be remapped,
	 * then call SetVirtualAddressMap with the size of the memory of
	 * the mapped descriptors as the first argument.  This is weird
	 * behaviour, and I don't entirely understand it.
	 *
	 * Anyway, this is all subject to change due to this mess.
	 *
	 * I think I need to spelunk through the Tianocore sources to get a
	 * better idea of what is expected (yes, the documentation is this
	 * unclear).
	 */
	DBG_P(("Shuffling UEFI memory entries...\n"));
	for (i = 0; i < rtomemlist_used; ++i) {
		src = eboot_find_efi_memory_descriptor(rtomemlist[i].idx);
		src->VirtualStart = rtomemlist[i].va;

		if (rtomemlist[i].idx == rtomemlist[i].nidx)
			continue;

		DBG_P(("Moving index %u to %u\n", rtomemlist[i].idx,
		    rtomemlist[i].nidx));
		dst = eboot_find_efi_memory_descriptor(rtomemlist[i].nidx);
		memcpy(dst, src, uefi_map_hdr->descriptor_size);
	}

	relocated_uefi_systab = bi->bi_uefi_systab;
	if (!eboot_relocate_efi_pointer(&relocated_uefi_systab))
		eboot_panic("Failed to relocate systab pointer\n");

	if (prom_debug) {
		eboot_printf("\nFinal rts memlist:\n");
		for (i = 0; i < rtsmemlist_used; ++i) {
			eboot_printf("\t%d: va=0x%" PRIx64 " pa=0x%" PRIx64
			    " size=0x%" PRIx64 " type=%s\n",
			    i, rtsmemlist[i].va, rtsmemlist[i].pa,
			    rtsmemlist[i].size,
			    rtsmem_code_or_data(rtsmemlist[i].type));
		}

		eboot_printf("\nFinal original RTS mappings by index:\n");
		for (i = 0; i < rtomemlist_used; ++i) {
			eboot_printf("\t%d: va=0x%" PRIx64 " idx=%u\n",
			    i, rtomemlist[i].va, rtomemlist[i].idx);
		}
	}
}

static void
sort_dbg2mem(void)
{
	int i;
	int j;
	struct dbg2_memlist tmp;
	/* memlists */

	/*
	 * Now sort the dbg2 memlists, in case they weren't in order.
	 * Yeah, this is a bubble sort; small, simple and easy to get right.
	 */
	DBG_MSG("Sorting dbg2 memlist\n");
	for (j = dbg2memlist_used - 1; j > 0; --j) {
		for (i = 0; i < j; ++i) {
			if (dbg2memlist[i].va < dbg2memlist[i + 1].va)
				continue;
			tmp = dbg2memlist[i];
			dbg2memlist[i] = dbg2memlist[i + 1];
			dbg2memlist[i + 1] = tmp;
		}
	}

	/*
	 * Merge any dbg2 memlists that don't have holes between them.
	 */
	for (i = 0; i <= dbg2memlist_used - 1; ++i) {
		if (dbg2memlist[i].va + dbg2memlist[i].size !=
		    dbg2memlist[i + 1].va)
			continue;
		if (dbg2memlist[i].pa + dbg2memlist[i].size !=
		    dbg2memlist[i + 1].pa)
			continue;

		if (prom_debug)
			eboot_printf(
			    "merging dbg2 segs %" PRIx64 "...%" PRIx64
			    " w/ %" PRIx64 "...%" PRIx64 "\n",
			    dbg2memlist[i].va,
			    dbg2memlist[i].va + dbg2memlist[i].size,
			    dbg2memlist[i + 1].va,
			    dbg2memlist[i + 1].va + dbg2memlist[i + 1].size);

		dbg2memlist[i].size += dbg2memlist[i + 1].size;
		for (j = i + 1; j < dbg2memlist_used - 1; ++j)
			dbg2memlist[j] = dbg2memlist[j + 1];
		--dbg2memlist_used;
		DBG(dbg2memlist_used);
		--i;	/* after merging we need to reexamine, so do this */
	}

	if (prom_debug) {
		eboot_printf("\nFinal dbg2 memlist:\n");
		for (i = 0; i < dbg2memlist_used; ++i) {
			eboot_printf("\t%d: va=0x%" PRIx64 " pa=0x%" PRIx64
			    " size=0x%" PRIx64 "\n",
			    i, dbg2memlist[i].va, dbg2memlist[i].pa,
			    dbg2memlist[i].size);
		}
	}
}

/*
 * Either hypervisor-specific or grub-specific code builds the initial
 * memlists. This code does the sort/merge/link for final use.
 */
static void
sort_physinstall(void)
{
	int i;
	int j;
	struct boot_memlist tmp;

	/*
	 * Now sort the memlists, in case they weren't in order.
	 * Yeah, this is a bubble sort; small, simple and easy to get right.
	 */
	DBG_MSG("Sorting phys-installed list\n");
	for (j = memlists_used - 1; j > 0; --j) {
		for (i = 0; i < j; ++i) {
			if (memlists[i].addr < memlists[i + 1].addr)
				continue;
			tmp = memlists[i];
			memlists[i] = memlists[i + 1];
			memlists[i + 1] = tmp;
		}
	}

	/*
	 * Merge any memlists that don't have holes between them.
	 */
	for (i = 0; i <= memlists_used - 1; ++i) {
		if (memlists[i].addr + memlists[i].size != memlists[i + 1].addr)
			continue;

		if (prom_debug)
			eboot_printf(
			    "merging mem segs %" PRIx64 "...%" PRIx64
			    " w/ %" PRIx64 "...%" PRIx64 "\n",
			    memlists[i].addr,
			    memlists[i].addr + memlists[i].size,
			    memlists[i + 1].addr,
			    memlists[i + 1].addr + memlists[i + 1].size);

		memlists[i].size += memlists[i + 1].size;
		for (j = i + 1; j < memlists_used - 1; ++j)
			memlists[j] = memlists[j + 1];
		--memlists_used;
		DBG(memlists_used);
		--i;	/* after merging we need to reexamine, so do this */
	}

	if (prom_debug) {
		eboot_printf("\nFinal memlists:\n");
		for (i = 0; i < memlists_used; ++i) {
			eboot_printf("\t%d: addr=%" PRIx64 " size=%"
			    PRIx64 "\n", i, memlists[i].addr, memlists[i].size);
		}
	}

	/*
	 * link together the memlists with native size pointers
	 */
	memlists[0].next = 0;
	memlists[0].prev = 0;
	for (i = 1; i < memlists_used; ++i) {
		memlists[i].prev = (native_ptr_t)(uintptr_t)(memlists + i - 1);
		memlists[i].next = 0;
		memlists[i - 1].next = (native_ptr_t)(uintptr_t)(memlists + i);
	}
	bi->bi_phys_install = (uint64_t)memlists;
	DBG(bi->bi_phys_install);
}

static void
sort_ebootmem(void)
{
	int i;
	int j;
	struct boot_memlist tmp;

	DBG_MSG("Sorting eboot phys-installed list\n");
	for (j = ememlists_used - 1; j > 0; --j) {
		for (i = 0; i < j; ++i) {
			if (ememlists[i].addr < ememlists[i + 1].addr)
				continue;
			tmp = ememlists[i];
			ememlists[i] = ememlists[i + 1];
			ememlists[i + 1] = tmp;
		}
	}

	/*
	 * Merge any memlists that don't have holes between them.
	 */
	for (i = 0; i <= ememlists_used - 1; ++i) {
		if (ememlists[i].addr + ememlists[i].size !=
		    ememlists[i + 1].addr)
			continue;

		if (prom_debug)
			eboot_printf(
			    "merging eboot mem segs %" PRIx64 "...%" PRIx64
			    " w/ %" PRIx64 "...%" PRIx64 "\n",
			    ememlists[i].addr,
			    ememlists[i].addr + ememlists[i].size,
			    ememlists[i + 1].addr,
			    ememlists[i + 1].addr + ememlists[i + 1].size);

		ememlists[i].size += ememlists[i + 1].size;
		for (j = i + 1; j < ememlists_used - 1; ++j)
			ememlists[j] = ememlists[j + 1];
		--ememlists_used;
		DBG(ememlists_used);
		--i;	/* after merging we need to reexamine, so do this */
	}

	if (prom_debug) {
		eboot_printf("\nFinal eboot memlists:\n");
		for (i = 0; i < ememlists_used; ++i) {
			eboot_printf("\t%d: addr=%" PRIx64 " size=%"
			    PRIx64 "\n",
			    i, ememlists[i].addr, ememlists[i].size);
		}
	}
}

/*
 * This could do a nice sort and merge like the physical memory list code
 * does.
 */
static void
build_rsvdmemlists(void)
{
	int i;

	rsvdmemlists[0].next = 0;
	rsvdmemlists[0].prev = 0;
	for (i = 1; i < rsvdmemlists_used; ++i) {
		rsvdmemlists[i].prev =
		    (native_ptr_t)(uintptr_t)(rsvdmemlists + i - 1);
		rsvdmemlists[i].next = 0;
		rsvdmemlists[i - 1].next =
		    (native_ptr_t)(uintptr_t)(rsvdmemlists + i);
	}
	bi->bi_rsvdmem = (uint64_t)rsvdmemlists;
	DBG(bi->bi_rsvdmem);
}


aarch64pte_t
get_pteval(paddr_t table, uint_t index)
{
	return (((aarch64pte_t *)(uintptr_t)table)[index]);
}

/*ARGSUSED*/
void
set_pteval(paddr_t table, uint_t index, uint_t level, aarch64pte_t pteval)
{
	uintptr_t tab_addr = (uintptr_t)table;
	((aarch64pte_t *)tab_addr)[index] = pteval;
}

paddr_t
make_ptable(aarch64pte_t *pteval, uint_t level)
{
	paddr_t new_table;

	new_table = (paddr_t)(uintptr_t)mem_alloc(MMU_PAGESIZE);
	/* mem_alloc has cleared the memory for us */
	*pteval = PA_TO_PT_OA(pa_to_ma(new_table)) | PTE_TABLE;

	if (map_debug)
		eboot_printf("new page table lvl=%d paddr=0x%lx ptp=0x%"
		    PRIx64 "\n", level, (ulong_t)new_table, *pteval);
	return (new_table);
}

aarch64pte_t *
map_pte(paddr_t table, uint_t index)
{
	return ((aarch64pte_t *)(uintptr_t)(table + index * pte_size));
}

#if 1
/*
 * Dump out the contents of page tables
 *
 * This is based on, but a little different to, the i86pc version.  Aside from
 * the obvious differences in pagetable format, aarch64 has two root tables, one
 * for the top-half memory and the other for the bottom half, so we need to know
 * which one we're dumping and apply a VA offset to properly visualise the top
 * table.
 */
static void
dump_tables(uint64_t tab, const char *name, uint64_t va_offset)
{
	uint_t save_index[4];	/* for recursion */
	char *save_table[4];	/* for recursion */
	uint_t	l;
	uint64_t va;
	uint64_t pgsize;
	int index;
	int i;
	aarch64pte_t pteval;
	char *table;
	static char *tablist = "\t\t\t";
	char *tabs = tablist + 3 - top_level;
	paddr_t pa, pa1;

	eboot_printf("Finished %s pagetables:\n", name);
#if 0
extern paddr_t ttbr1_top_table;
extern paddr_t ttbr0_top_table;
#endif
#if 0
	table = (char *)(uintptr_t)top_page_table;
#else
	table = (char *)(uintptr_t)tab;
#endif
	l = top_level;
	va = va_offset;
	for (index = 0; index < ptes_per_table; ++index) {
		pgsize = 1ull << shift_amt[l];
		pteval = ((aarch64pte_t *)table)[index];
		if (!(PTE_IS_VALID(pteval, l)))
			goto next_entry;

		eboot_printf("%s [L%u] 0x%p[%u] = 0x%" PRIx64 ", va=0x%" PRIx64,
		    tabs + l, l, (void *)table, index, (uint64_t)pteval, va);
		pa = PT_TO_PA(pteval);
		if (l == 0 || (l != 0 && (pteval & PTE_VALID_MASK) == PTE_BLOCK)) {
			eboot_printf(" physaddr=0x%" PRIx64 "\n", pa);
		} else {
			eboot_printf(" => 0x%" PRIx64 "\n", pa);
		}

#if 1
		/*
		 * Don't try to walk hypervisor private pagetables
		 */
#if 0
		if ((l > 1 || (l == 1 && (pteval & PT_PAGESIZE) == 0))) {
#endif
		if (l > 0 && PTE_IS_VALID(pteval, l) && (pteval & PTE_VALID_MASK) == PTE_TABLE) {
			save_table[l] = table;
			save_index[l] = index;
			--l;
			index = -1;
			table = (char *)(uintptr_t)
			    PT_TO_PA(pteval);
			goto recursion;
		}
#endif

		/*
		 * shorten dump for consecutive mappings
		 */
		for (i = 1; index + i < ptes_per_table; ++i) {
			pteval = ((aarch64pte_t *)table)[index + i];
			if (!(PTE_IS_VALID(pteval, l)))
				break;
			pa1 = PT_TO_PA(pteval);
			if (pa1 != pa + i * pgsize)
				break;
		}
		if (i > 2) {
			eboot_printf("%s...\n", tabs + l);
			va += pgsize * (i - 2);
			index += i - 2;
		}
next_entry:
		va += pgsize;
#if 0
		if (l == 3 && index == 256)	/* BAD: VA hole */
			va = 0xffff800000000000ull;
#endif
recursion:
		;
	}
	if (l < top_level) {
		++l;
		index = save_index[l];
		table = save_table[l];
		goto recursion;
	}
}
#endif

#if 0
/*
 * This is called to remove start..end from the
 * possible range of PCI addresses.
 */
const uint64_t pci_lo_limit = 0x00100000ul;
const uint64_t pci_hi_limit = 0xfff00000ul;
static void
exclude_from_pci(uint64_t start, uint64_t end)
{
	int i;
	int j;
	struct boot_memlist *ml;

	for (i = 0; i < pcimemlists_used; ++i) {
		ml = &pcimemlists[i];

		/* delete the entire range? */
		if (start <= ml->addr && ml->addr + ml->size <= end) {
			--pcimemlists_used;
			for (j = i; j < pcimemlists_used; ++j)
				pcimemlists[j] = pcimemlists[j + 1];
			--i;	/* to revisit the new one at this index */
		}

		/* split a range? */
		else if (ml->addr < start && end < ml->addr + ml->size) {

			++pcimemlists_used;
			if (pcimemlists_used > MAX_MEMLIST)
				eboot_panic("too many pcimemlists\n");

			for (j = pcimemlists_used - 1; j > i; --j)
				pcimemlists[j] = pcimemlists[j - 1];
			ml->size = start - ml->addr;

			++ml;
			ml->size = (ml->addr + ml->size) - end;
			ml->addr = end;
			++i;	/* skip on to next one */
		}

		/* cut memory off the start? */
		else if (ml->addr < end && end < ml->addr + ml->size) {
			ml->size -= end - ml->addr;
			ml->addr = end;
		}

		/* cut memory off the end? */
		else if (ml->addr <= start && start < ml->addr + ml->size) {
			ml->size = start - ml->addr;
		}
	}
}
#endif

/*
 * During memory allocation, find the highest address not used yet.
 */
static void
check_higher(uint64_t a)
{
	if (a < next_avail_addr)
		return;
	DBG_P(("check_higher: moving from 0x%lx to ", next_avail_addr));
	next_avail_addr = RNDUP(a + 1, MMU_PAGESIZE);
	DBG_P(("0x%lx\n", next_avail_addr));
}

#if 0
static void
build_pcimemlists(void)
{
	uint64_t page_offset = MMU_PAGEOFFSET;	/* needs to be 64 bits */
	uint64_t start;
	uint64_t end;
	int i, num;

	/*
	 * initialize
	 */
	pcimemlists[0].addr = pci_lo_limit;
	pcimemlists[0].size = pci_hi_limit - pci_lo_limit;
	pcimemlists_used = 1;

	num = dboot_loader_mmap_entries();
	/*
	 * Fill in PCI memlists.
	 */
	for (i = 0; i < num; ++i) {
		start = dboot_loader_mmap_get_base(i);
		end = start + dboot_loader_mmap_get_length(i);

		if (prom_debug)
			eboot_printf("\ttype: %d %" PRIx64 "..%"
			    PRIx64 "\n", dboot_loader_mmap_get_type(i),
			    start, end);

		/*
		 * page align start and end
		 */
		start = (start + page_offset) & ~page_offset;
		end &= ~page_offset;
		if (end <= start)
			continue;

		exclude_from_pci(start, end);
	}

	/*
	 * Finish off the pcimemlist
	 */
	if (prom_debug) {
		for (i = 0; i < pcimemlists_used; ++i) {
			eboot_printf("pcimemlist entry 0x%" PRIx64 "..0x%"
			    PRIx64 "\n", pcimemlists[i].addr,
			    pcimemlists[i].addr + pcimemlists[i].size);
		}
	}
	pcimemlists[0].next = 0;
	pcimemlists[0].prev = 0;
	for (i = 1; i < pcimemlists_used; ++i) {
		pcimemlists[i].prev =
		    (native_ptr_t)(uintptr_t)(pcimemlists + i - 1);
		pcimemlists[i].next = 0;
		pcimemlists[i - 1].next =
		    (native_ptr_t)(uintptr_t)(pcimemlists + i);
	}
	bi->bi_pcimem = (uint64_t)pcimemlists;
	DBG(bi->bi_pcimem);
}
#endif

static const char *
type_to_str(boot_module_type_t type)
{
	switch (type) {
	case BMT_ROOTFS:
		return ("rootfs");
	case BMT_ENV:
		return ("environment");
	case BMT_FONT:
		return ("console-font");
	default:
		return ("unknown");
	}
}

#define	MOD_UINT64(x)	(*((uint64_t *)(&(x)[2])))

static void
eboot_process_module_record(uint32_t *mr)
{
#if 0
#define	MOD_SIZE(x)	((x)[1])
#define	MOD_STRING(x)	((const char *)(&(x)[2]))
#define	MOD_UINT32(x)	(*((uint32_t *)(&(x)[2])))
#define	P_MOD_STRING(n, x)	eboot_printf("MODINFO_%s: <%s> (%u bytes)\n", \
	(n), MOD_STRING((x)), MOD_SIZE((x)));
#define	P_MOD_UINT32(n, x)	eboot_printf("MODINFO_%s: <0x%x> (%u bytes)\n", \
	(n), MOD_UINT32((x)), MOD_SIZE((x)));
#define	P_MOD_UINT64(n, x)	eboot_printf("MODINFO_%s: <0x%lx> (%u bytes)\n", \
	(n), MOD_UINT64((x)), MOD_SIZE((x)));
#define	P_MDMOD_STRING(n, x)	eboot_printf("MODINFOMD_%s: <%s> (%u bytes)\n", \
	(n), MOD_STRING((x)), MOD_SIZE((x)));
#define	P_MDMOD_UINT32(n, x)	eboot_printf("MODINFOMD_%s: <0x%x> (%u bytes)\n", \
	(n), MOD_UINT32((x)), MOD_SIZE((x)));
#define	P_MDMOD_UINT64(n, x)	eboot_printf("MODINFOMD_%s: <0x%lx> (%u bytes)\n", \
	(n), MOD_UINT64((x)), MOD_SIZE((x)));

	if ((mr[0] & MODINFO_METADATA) == 0) {
		switch (mr[0]) {
		case MODINFO_NAME:
			P_MOD_STRING("NAME", mr);
			break;
		case MODINFO_TYPE:
			P_MOD_STRING("TYPE", mr);
			break;
		case MODINFO_ADDR:
			P_MOD_UINT64("ADDR", mr);
			break;
		case MODINFO_SIZE:
			P_MOD_UINT64("SIZE", mr);
			break;
		case MODINFO_ARGS:
			/* kernel/module command-line arguments, as a flat string */
			/* not provided if there were no arguments */
			/* should we be prepending the name? */
			P_MOD_STRING("ARGS", mr);
			break;
		case MODINFO_END:
			eboot_printf("MODINFO_END\n");
			break;
		case MODINFO_EMPTY:
			eboot_printf("MODINFO_EMPTY\n");
			break;
		default:
			eboot_printf("Unhandled record %u\n", mr[0]);
			break;
		}
	} else {
		switch (mr[0] & ~MODINFO_METADATA) {
		case MODINFOMD_AOUTEXEC:
			P_MDMOD_UINT64("AOUTEXEC", mr);
			break;
		case MODINFOMD_ELFHDR:
			P_MDMOD_UINT64("ELFHDR", mr);
			break;
		case MODINFOMD_SSYM:
			P_MDMOD_UINT64("SSYM", mr);
			break;
		case MODINFOMD_ESYM:
			P_MDMOD_UINT64("ESYM", mr);
			break;
		case MODINFOMD_DYNAMIC:
			P_MDMOD_UINT64("DYNAMIC", mr);
			break;
#if !defined(MODINFOMD_ENVP)
		case MODINFOMD_MB2HDR:
			P_MDMOD_UINT64("MB2HDR", mr);
			break;
#endif
#if defined(MODINFOMD_ENVP)
		case MODINFOMD_ENVP:
			P_MDMOD_UINT64("ENVP", mr);
			preload_dump_env((const char *)MAYBE_VTOP(MOD_UINT64(mr)));
			break;
#endif
#if defined(MODINFOMD_HOWTO)
		case MODINFOMD_HOWTO:
			P_MDMOD_UINT64("HOWTO", mr);
			break;
#endif
#if defined(MODINFOMD_KERNEND)
		case MODINFOMD_KERNEND:
			P_MDMOD_UINT64("KERNEND", mr);
			break;
#endif
		case MODINFOMD_SHDR:
			P_MDMOD_UINT64("SHDR", mr);
			break;
		case MODINFOMD_CTORS_ADDR:
			P_MDMOD_UINT64("CTORS_ADDR", mr);
			break;
		case MODINFOMD_CTORS_SIZE:
			P_MDMOD_UINT64("CTORS_SIZE", mr);
			break;
		case MODINFOMD_FW_HANDLE:
			P_MDMOD_UINT64("FW_HANDLE", mr);
			break;
		case MODINFOMD_KEYBUF:
			P_MDMOD_UINT64("KEYBUF", mr);
			break;
		case MODINFOMD_FONT:
			P_MDMOD_UINT64("FONT", mr);
			break;
		case MODINFOMD_DEPLIST:
			P_MDMOD_UINT64("DEPLIST", mr);
			break;
		case MODINFOMD_EFI_MAP:
#if 1
			eboot_printf("Found UEFI Memory Map\n");
			eboot_printf("  Map size: %u\n", MOD_SIZE((mr)));
#endif
			/* XXXX */
			P_MDMOD_UINT64("EFI_MAP", mr);
			break;
		case MODINFOMD_DTBP:
			P_MDMOD_UINT64("DTBP", mr);
			break;
		case MODINFOMD_EFI_FB:
			P_MDMOD_UINT64("EFI_FB", mr);
			break;
		default:
			eboot_printf("Unhandled metadata record %x\n", mr[0]);
			break;
		}
	}
#endif
}

static uint64_t
eboot_find_kernel_sym(Elf64_Sym *symtab, size_t nsym,
    const char *kstrtab, size_t strsz, const char *symname, uint8_t type)
{
	size_t i;
	Elf64_Sym *sym;
	const char *symn;

	for (i = 0; i < nsym; ++i) {
		sym = &symtab[i];

		if (sym->st_name >= strsz)
			continue;

		if (ELF64_ST_BIND(sym->st_info) != STB_GLOBAL)
			continue;

		if (ELF64_ST_TYPE(sym->st_info) != type)
			continue;

		if (ELF64_ST_VISIBILITY(sym->st_other) != STV_DEFAULT &&
		    ELF64_ST_VISIBILITY(sym->st_other) != STV_EXPORTED)
			continue;

		if (strcmp(kstrtab + sym->st_name, symname) != 0)
			continue;

		return ((uint64_t)sym->st_value);
	}

	return (0);
}

static int
eboot_process_symtab(caddr_t s, caddr_t e, uint64_t *ks, uint64_t *kl,
    uint64_t *ks_text, uint64_t *ke_text,
    uint64_t *ks_data, uint64_t *ke_data,
    uint64_t *k_end)
{
	uint64_t ksymtab;
	uint64_t kstrtab;
	uint64_t ksymtab_size;
	uint64_t strsz;

	if (e <= s || s == 0)
		eboot_panic("No kernel symbols from loader\n");

	ksymtab = (uint64_t)s;
	ksymtab_size = *(Elf64_Xword*)ksymtab;
	ksymtab += sizeof(Elf64_Xword);
	kstrtab = ksymtab + ksymtab_size;
	strsz = *(Elf64_Xword*)kstrtab;
	kstrtab += sizeof(Elf64_Xword);

	if (kstrtab + strsz > (uint64_t)e)
		eboot_panic("Corrupted symbol table\n");

	if (ksymtab_size % sizeof(Elf64_Sym) != 0)
		eboot_panic("Corrupted symbol table size\n");

	*ks = eboot_find_kernel_sym(
	    (Elf64_Sym *)ksymtab, (size_t)(ksymtab_size / sizeof(Elf64_Sym)),
	    (const char *)kstrtab, (size_t)strsz, "_start", STT_FUNC);
	if (*ks == 0) {
		eboot_printf("Unable to locate kernel _start symbol\n");
		return (0);
	}

	*kl = eboot_find_kernel_sym(
	    (Elf64_Sym *)ksymtab, (size_t)(ksymtab_size / sizeof(Elf64_Sym)),
	    (const char *)kstrtab, (size_t)strsz, "eboot_image", STT_OBJECT);
	if (*kl == 0) {
		eboot_printf("Unable to locate kernel eboot_image symbol\n");
		return (0);
	}

	*ks_text = eboot_find_kernel_sym(
	    (Elf64_Sym *)ksymtab, (size_t)(ksymtab_size / sizeof(Elf64_Sym)),
	    (const char *)kstrtab, (size_t)strsz, "s_text", STT_OBJECT);
	if (*ks_text == 0) {
		eboot_printf("Unable to locate kernel s_text symbol\n");
		return (0);
	}

	*ke_text = eboot_find_kernel_sym(
	    (Elf64_Sym *)ksymtab, (size_t)(ksymtab_size / sizeof(Elf64_Sym)),
	    (const char *)kstrtab, (size_t)strsz, "e_text", STT_OBJECT);
	if (*ke_text == 0) {
		eboot_printf("Unable to locate kernel e_text symbol\n");
		return (0);
	}

	*ks_data = eboot_find_kernel_sym(
	    (Elf64_Sym *)ksymtab, (size_t)(ksymtab_size / sizeof(Elf64_Sym)),
	    (const char *)kstrtab, (size_t)strsz, "s_data", STT_OBJECT);
	if (*ks_data == 0) {
		eboot_printf("Unable to locate kernel s_data symbol\n");
		return (0);
	}

	*ke_data = eboot_find_kernel_sym(
	    (Elf64_Sym *)ksymtab, (size_t)(ksymtab_size / sizeof(Elf64_Sym)),
	    (const char *)kstrtab, (size_t)strsz, "e_data", STT_OBJECT);
	if (*ke_data == 0) {
		eboot_printf("Unable to locate kernel e_data symbol\n");
		return (0);
	}

	*k_end = eboot_find_kernel_sym(
	    (Elf64_Sym *)ksymtab, (size_t)(ksymtab_size / sizeof(Elf64_Sym)),
	    (const char *)kstrtab, (size_t)strsz, "_end", STT_OBJECT);
	if (*k_end == 0) {
		eboot_printf("Unable to locate kernel _end symbol\n");
		return (0);
	}

	return (1);
}

static const char env_module_name[] = "environment";

static uint64_t
eboot_process_module_env(const char *menv)
{
	char c;
	char lastc;
	uint64_t ep;

	if (menv == NULL)
		eboot_panic("NULL module environment\n");

	modules[modules_used].bm_addr = (uint64_t)menv;
	modules[modules_used].bm_name = (uint64_t)&env_module_name[0];
	modules[modules_used].bm_type = BMT_ENV;

	for (c = *menv, lastc = 0xff; ; c = *++menv) {
		if (c == '\0' && lastc == '\0')
			break;
		lastc = c;
	}

	ep = roundup((uint64_t)menv, sizeof(uint64_t));
	modules[modules_used].bm_size = ep - modules[modules_used].bm_addr;
	modules_used++;

	return (ep);
}

static int
process_efi_memory_map_for_eboot(
    EFI_MEMORY_DESCRIPTOR *map, int ndesc, int descsz)
{
	EFI_MEMORY_DESCRIPTOR *p;
	int i;

	for (i = 0, p = map; i < ndesc; i++, p = efi_mmap_next(p, descsz)) {
		switch (p->Type) {
			case EfiLoaderCode:
			case EfiLoaderData:
			case EfiConventionalMemory:
				/* add to memlists */
				/* this is all normal memory */
				ememlists[ememlists_used].addr =
				    RNDUP(p->PhysicalStart, 0x1000);
				ememlists[ememlists_used].size =
				    RNDDN(p->PhysicalStart +
				        (p->NumberOfPages * 0x1000), 0x1000) -
				    RNDUP(p->PhysicalStart, 0x1000);
				ememlists_used++;
				break;
			case EfiBootServicesCode:
			case EfiBootServicesData:
			case EfiReservedMemoryType:
			case EfiRuntimeServicesCode:
			case EfiRuntimeServicesData:
			case EfiMemoryMappedIO:
			case EfiMemoryMappedIOPortSpace:
			case EfiPalCode:
			case EfiUnusableMemory:
			case EfiACPIReclaimMemory:
			case EfiACPIMemoryNVS:
				break;
			default:
				eboot_printf("Unhandled memory type %u\n",
				    p->Type);
				break;
		}
	}

	sort_ebootmem();
	return (1);
}

/*
 * eboot gets its own, more conservative, view of available memory.
 *
 * This allows us to avoid boot services code and data that might be needed
 * for runtime services relocation.  The relocation is pretty much the last
 * thing we do, so we don't pass these exclusions on to the kernel.
 */
static int
eboot_process_efi_map_for_eboot(struct efi_map_header *mhdr)
{
	size_t			efisz;
	EFI_MEMORY_DESCRIPTOR	*map;
	int			ndesc;

	if (mhdr == NULL)
		return (0);

	uefi_map_hdr = mhdr;

	efisz = (sizeof(struct efi_map_header) + 0xf) & ~0xf;
	map = (EFI_MEMORY_DESCRIPTOR *)((uint8_t *)mhdr + efisz);
	if (mhdr->descriptor_size == 0)
		eboot_panic("Invalid memory descriptor size.\n");

	ndesc = mhdr->memory_size / mhdr->descriptor_size;
	DBG_P(("%u memory descriptors present\n", ndesc));
	DBG_P(("descriptor size is %lu\n", mhdr->descriptor_size));
	return (process_efi_memory_map_for_eboot(
	    map, ndesc, mhdr->descriptor_size));
}

static int
process_efi_memory_map(EFI_MEMORY_DESCRIPTOR *map, int ndesc, int descsz)
{
	EFI_MEMORY_DESCRIPTOR *p;
	int i;

	/*
	 * Here's an approach:
	 * Fill out out memory map we'll pass to the OS, sort it etc.
	 * ^^ includes reserved bits, pci etc.
	 * steal the pages we need from the available physical memory
	 * map the runtime services nice and high, tell the OS to skip these?
	 * XX
	 */
	for (i = 0, p = map; i < ndesc; i++, p = efi_mmap_next(p, descsz)) {
		switch (p->Type) {
			case EfiLoaderCode:
			case EfiLoaderData:		/* loader code and data are pages allocated by UEFI for the staging area and loader heap from what I can tell */
			case EfiBootServicesCode:
			case EfiBootServicesData:
			case EfiConventionalMemory:
				/* add to memlists */
				/* this is all normal memory */
				memlists[memlists_used].addr =
				    RNDUP(p->PhysicalStart, 0x1000);
				memlists[memlists_used].size =
				    RNDDN(p->PhysicalStart +
				        (p->NumberOfPages * 0x1000), 0x1000) -
				    RNDUP(p->PhysicalStart, 0x1000);
				if (memlists[memlists_used].addr + memlists[memlists_used].size - 1 > physmax)
					physmax = memlists[memlists_used].addr + memlists[memlists_used].size - 1;
				if (physmin > memlists[memlists_used].addr)
					physmin = memlists[memlists_used].addr;
				memlists_used++;
				break;
			case EfiReservedMemoryType:
			case EfiRuntimeServicesCode:
			case EfiRuntimeServicesData:
			case EfiMemoryMappedIO:
			case EfiMemoryMappedIOPortSpace:
			case EfiPalCode:
			case EfiUnusableMemory:
			case EfiACPIReclaimMemory:
			case EfiACPIMemoryNVS:
				/*
				 * Add to reserved memlists
				 * Includes device memory, which will be ignored
				 * by the memory management subsystem and mapped
				 * in response to the contents of ACPI tables.
				 */
				rsvdmemlists[rsvdmemlists_used].addr =
				    RNDDN(p->PhysicalStart, 0x1000);
				rsvdmemlists[rsvdmemlists_used].size =
				    RNDUP(p->PhysicalStart +
				        (p->NumberOfPages * 0x1000), 0x1000) -
				    RNDDN(p->PhysicalStart, 0x1000);
				rsvdmemlists_used++;
				break;
			default:
				eboot_printf("Unhandled memory type %u\n",
				    p->Type);
				break;
		}

		if (p->Type != EfiRuntimeServicesCode &&
		    p->Type != EfiRuntimeServicesData &&
		    p->Type != EfiMemoryMappedIO)
			continue;

		if ((p->Attribute & EFI_MEMORY_RUNTIME) == 0)
			continue;

		if (p->VirtualStart != 0 &&
		    p->VirtualStart != p->PhysicalStart) {
			eboot_printf("EFI runtime services memory (entry %d) "
			    "is already mapped.\n", i);
			eboot_printf("VA = 0x%lx, VA = 0x%lx, count = %lu\n",
			    p->VirtualStart, p->PhysicalStart,
			    p->NumberOfPages);
			eboot_panic("Unexpected memory map state.\n");
		}

		if ((p->PhysicalStart & 0xfff) != 0)
			eboot_panic("EFI runtime services memory (entry %d) "
			    "is not aligned.\n", i);

		/*
		 * TODO: collect the relocations so that we can remap them later
		 */
		if (p->Type == EfiRuntimeServicesCode) {
			DBG_P(("UEFI EfiRuntimeServicesCode %lu pages @ "
			    "0x%lx\n", p->NumberOfPages, p->PhysicalStart));
		} else if (p->Type == EfiRuntimeServicesData) {
			DBG_P(("UEFI EfiRuntimeServicesData %lu pages @ "
			    "0x%lx\n", p->NumberOfPages, p->PhysicalStart));
		}
		rtsmemlist[rtsmemlist_used].attr = p->Attribute;
		rtsmemlist[rtsmemlist_used].pa = p->PhysicalStart;
		rtsmemlist[rtsmemlist_used].va = 0;
		rtomemlist[rtomemlist_used].va = 0;
		rtsmemlist[rtsmemlist_used].size = p->NumberOfPages << 12;
		rtsmemlist[rtsmemlist_used].type = p->Type;
		rtomemlist[rtomemlist_used].idx = i;
		rtsmemlist_used++;
		rtomemlist_used++;
	}

	if (physmax <= physmin)
		eboot_panic("Failed to determine phys limits\n");
	physmax >>= MMU_PAGESHIFT;
	physmin >>= MMU_PAGESHIFT;

	bi->bi_physmin = physmin;
	bi->bi_physmax = physmax;

	sort_physinstall();
	build_rsvdmemlists();
	sort_rtsmem();
	return (1);
}

static void
eboot_process_efi_map(struct efi_map_header *mhdr)
{
	size_t			efisz;
	EFI_MEMORY_DESCRIPTOR	*map;
	int			ndesc;

	if (mhdr == NULL)
		eboot_panic("NULL UEFI memory map from loader.\n");

	uefi_map_hdr = mhdr;

	efisz = (sizeof(struct efi_map_header) + 0xf) & ~0xf;
	map = (EFI_MEMORY_DESCRIPTOR *)((uint8_t *)mhdr + efisz);
	if (mhdr->descriptor_size == 0)
		eboot_panic("Invalid memory descriptor size.\n");

	ndesc = mhdr->memory_size / mhdr->descriptor_size;
	DBG_P(("%u memory descriptors present\n", ndesc));
	DBG_P(("descriptor size is %lu\n", mhdr->descriptor_size));
	if (!process_efi_memory_map(map, ndesc, mhdr->descriptor_size))
		eboot_panic("Cannot process UEFI memory map\n");
}

static void
eboot_process_module_info(caddr_t mi)
{
	caddr_t		curp;
	uint32_t	*hdr;
	uint32_t	type = 0;
	int		next;
	uint64_t	maddr;
	uint64_t	msize;
	const char	*mtype;
	const char	*mname;
	const char	*margs;

	if (mi == NULL)
		eboot_panic("NULL module info\n");

	curp = mi;
	maddr = 0;
	msize = 0;
	mtype = NULL;
	mname = NULL;
	margs = NULL;
	for (;;) {
		hdr = (uint32_t *)curp;
		/* end of module data? let the caller deal with it */
		if (hdr[0] == 0 && hdr[1] == 0)
			break;

		/*
		 * We give up once we've looped back to what we were looking at
		 * first - this is a MODINFO_NAME field.
		 */
		if (type == 0) {
			if (hdr[0] != MODINFO_NAME)
				eboot_panic("Module info processing without a "
				    "module name?\n");
			type = hdr[0];
		} else {
			if (hdr[0] == type)
				break;
		}

		if (hdr[0] == MODINFO_NAME) {
			mname = (const char *)&hdr[2];
			DBG(mname);
		} else if (hdr[0] == MODINFO_TYPE) {
			mtype = (const char *)&hdr[2];
			DBG(mtype);
		} else if (hdr[0] == MODINFO_ARGS) {
			/*
			 * This is, frankly, not very useful in the form
			 * provided by the FreeBSD loader.
			 */
			margs = (const char *)&hdr[2];
			DBG(margs);
		} else if (hdr[0] == MODINFO_ADDR) {
			maddr = MAYBE_VTOP(MOD_UINT64(hdr));
			DBG(maddr);
		} else if (hdr[0] == MODINFO_SIZE) {
			msize = MOD_UINT64(hdr);
			DBG(msize);
		} else if (hdr[0] & MODINFO_METADATA) {
			switch (hdr[0] & ~MODINFO_METADATA) {
			case MODINFOMD_ENVP:
				/* XXX clean up the envp name */
				env_paddr = MAYBE_VTOP(MOD_UINT64(hdr));
				env_size =
				    eboot_process_module_env(envp) - env_paddr;
				envp = (const char *)env_paddr;
				check_higher(env_paddr + env_size);
				break;
			case MODINFOMD_SSYM:
				mod_ssym = (caddr_t)MAYBE_VTOP(MOD_UINT64(hdr));
				break;
			case MODINFOMD_ESYM:
				mod_esym = (caddr_t)MAYBE_VTOP(MOD_UINT64(hdr));
				break;
			case MODINFOMD_EFI_MAP:
				eboot_process_efi_map(
				    (struct efi_map_header *)&hdr[2]);
				break;	/* already done */
			case MODINFOMD_FONT:
				/*
				 * This should just be a pointer to the font
				 * structure, but we might need to grok that
				 * enough to relocate it.
				 */
				eboot_printf("XXX: need to handle the font\n");
				break;
			default:
				break;
			}
		}

		/* skip to next field */
		next = sizeof(uint32_t) * 2 + hdr[1];
		next = roundup(next, sizeof(u_long));
		curp += next;
	}

	if (type == 0)
		return;

	if (mtype == NULL || mname == NULL || maddr == 0 || msize == 0)
		eboot_panic("Missing module type, name, address or size\n");

	DBG_P(("Module Type   : %s\n", mtype));
	DBG_P(("Module Name   : %s\n", mname));
	DBG_P(("Module Address: 0x%lx\n", maddr));
	DBG_P(("Module Size   : 0x%lx\n", msize));

	/*
	 * TODO:
	 * 1. Add the font module when we figure that out
	 * 2. Check that we're not adding a duplicate module
	 */
	if (strcmp(mtype, "rootfs") == 0) {
		/* XXX: check if we have one already */
		rootfs_paddr = maddr;
		rootfs_size = msize;
		modules[modules_used].bm_addr = rootfs_paddr;
		modules[modules_used].bm_name = (uint64_t)mname;
		modules[modules_used].bm_size = rootfs_size;
		modules[modules_used].bm_type = BMT_ROOTFS;
		modules_used++;
	} else if (strcmp(mtype, "elf kernel") == 0 ||
	    strcmp(mtype, "elf64 kernel")) {
		if (margs) {
			cmdline_paddr = (uint64_t)margs;
			cmdline_size = strlen(margs);
		}

		kernel_load_start = maddr;
		kernel_load_end = maddr + msize;
	}

	check_higher(roundup(maddr + msize, sizeof(uint64_t)));
}

/*
 * Walk through the module information finding the last used address.
 * The first available address will become the top level page table.
 */
static void
eboot_process_modules(void)
{
	/*
	 * Walk the modules, finding the higest address of the module
	 * metadata.  For modules and metadata that have external pointers,
	 * (kernel, rootfs, fonts, framebuffer, environment?), check the
	 * end of the external data.
	 */
	caddr_t		curp;
	uint32_t	*hdr;
	int		next;
	uint32_t	i;
	uint64_t	start;
	uint64_t	end;
	uint64_t	reloc_delta;
	uint64_t	reloc_dst;
	uint64_t	reloc_size;
	int		reloc_memcheck_ok;
	int		rootfs_found;
	int		env_found;
	uint64_t	ks_text;
	uint64_t	ke_text;
	uint64_t	ks_data;
	uint64_t	ke_data;
	uint64_t	k_end;

	if (fmodulep == NULL)
		eboot_panic("No FreeBSD-style module pointer\n");

	curp = fmodulep;

	for (;;) {
		hdr = (uint32_t *)curp;

		/*
		 * MODINFO_END signals the end of the TLV module list, so we
		 * use this as an additional input when calculating the last
		 * used address.
		 */
		if (hdr[0] == 0 && hdr[1] == 0) {
			check_higher(
			    roundup((uint64_t)&hdr[1], sizeof(uint64_t)));
			break;
		}

		if (hdr[0] == MODINFO_NAME)
			eboot_process_module_info(curp);

		next = sizeof(uint32_t) * 2 + hdr[1];
		next = roundup(next, sizeof(u_long));
		curp += next;
	}

	if (envp == NULL)
		eboot_panic("No environment passed by loader\n");

	if (memlists_used == 0 || rsvdmemlists_used == 0)
		eboot_panic("No (or unparseable) UEFI memory map\n");

	if (kernel_load_start == 0)
		eboot_panic("Unable to determine kernel load area address\n");

	if (kernel_load_end == 0)
		eboot_panic("Unable to determine kernel load end address\n");

	if (mod_ssym == NULL || mod_esym == NULL)
		eboot_panic("No symbols presented by the loader\n");

	if (!eboot_process_symtab(mod_ssym, mod_esym,
	    &kernel_start_addr, &target_kernel_text, &ks_text, &ke_text,
	    &ks_data, &ke_data, &k_end))
		eboot_panic("Failed to resolve kernel start or end address\n");

	if (kernel_start_addr < hole_end) {
		eboot_panic("Kernel start address (0x%lx) must be in TTBR1 "
		    "space (>= 0x%lx).\n", kernel_start_addr, hole_end);
	}

	check_higher(
	    roundup((uint64_t)(mod_esym - mod_ssym), sizeof(uint64_t)));
	check_higher(roundup(kernel_load_end, sizeof(uint64_t)));

	DBG_P(("Kernel s_text 0x%lx, e_text 0x%lx\n", ks_text, ke_text));
	DBG_P(("Kernel s_data 0x%lx, e_data 0x%lx\n", ks_data, ke_data));
	DBG_P(("Kernel _end 0x%lx\n", k_end));
	DBG_P(("Kernel Load Start Address: 0x%lx\n", kernel_load_start));
	DBG_P(("Kernel Load End Address: 0x%lx\n", kernel_load_end));
	DBG_P(("Kernel Text Load VA: 0x%lx\n", target_kernel_text));
	DBG_P(("Kernel _start Address: 0x%lx\n", kernel_start_addr));
	DBG_P(("Environment Pointer: 0x%p\n", envp));

	/*
	 * XXXAARCH64: Assert that target_kernel_text is 2MiB aligned (this is
	 * EBOOT_TEXT) and that kernel_start_addr starts 2MiB higher (this is
	 * KERNEL_TEXT).  May as well assert that these match the defines as
	 * well, because things will get weird quickly if they don't.
	 */
	if (target_kernel_text != EBOOT_TEXT)
		eboot_panic("Unexpected target VA for eboot\n");

	if (kernel_start_addr != KERNEL_TEXT)
		eboot_panic("Unexpected kernel entry VA\n");

	/*
	 * Check that we have a rootfs and environment.
	 *
	 * Font is optional.
	 */
	rootfs_found = env_found = 0;

	for (i = 0; i < modules_used; ++i) {
		switch (modules[i].bm_type) {
		case BMT_ROOTFS:
			rootfs_found = 1;
			break;
		case BMT_ENV:
			env_found = 1;
			break;
		default:
			break;
		}
	}

	if (rootfs_found == 0)
		eboot_panic("No rootfs provided by the bootloader\n");

	if (env_found == 0)
		eboot_panic("No environment provided by the bootloader\n");

	bi->bi_module_cnt = modules_used;
	DBG(bi->bi_modules);
	DBG(bi->bi_module_cnt);

	/*
	 * Work out how much we need to move the module data up, if we need to
	 * do so, to leave the proper hole for the nucleus.  It feels wrong to
	 * do this here, buts lets us boot with the FreeBSD loader for now.
	 *
	 * The idea is to take the address of the first non-kernel module and
	 * figure out if that's below our nucleus limit.  If it is, we take the
	 * end of the metadata (kernend) less that address, and that's the data
	 * we need to move.
	 *
	 * Work out the move delta (we'll always be moving up), then memmove
	 * the data upwards and update our module pointers.
	 *
	 * Once we have the new end, we can start allocating page tables.
	 *
	 * For reference, the loader packs the data in like this:
	 * +-------------+ kernend
	 * + module data |
	 * +-------------+ rootfs::addr + rootfs::size
	 * + rootfs      |
	 * +-------------+ rootfs::addr (kernel data + .data size + .bss size)
	 * + data        | (actual .data + .bss size)
	 * +-------------+ (kernel .data)
	 * + text        | (4MiB)
	 * +-------------+ KERNEL_TEXT
	 * + eboot       | (2MiB)
	 * +-------------+ EBOOT_TEXT
	 *
	 * We want this picture:
	 * +-------------+ kernend
	 * + module data |
	 * +-------------+ rootfs::addr + rootfs::size
	 * + rootfs      |
	 * +-------------+ rootfs::addr (kernel .data + 4MiB)
	 * + data        | (4MiB)
	 * +-------------+ (kernel data)
	 * + text        | (4MiB)
	 * +-------------+ KERNEL_TEXT
	 * + eboot       | (2MiB)
	 * +-------------+ EBOOT_TEXT
	 *
	 * MODINFOMD_KERNEND points to the end of the modules
	 * BMT_ROOTFS->addr _should_ point to the first address we need to move.
	 */
	DBG(kernel_load_start);
	DBG(kernel_load_end);
	if (kernel_load_start == 0 || kernel_load_end == 0 ||
	    kernel_load_end < kernel_load_start)
		eboot_panic("Nonsensical kernel load data: 0x%lx, 0x%lx\n",
		    kernel_load_start, kernel_load_end);

	if (kernel_load_end - kernel_load_start > (12 * 1024 * 1024))
		eboot_panic("Kernel too large\n");

	/*
	 * reloc_delta is the difference between where the kernel ends at the
	 * moment, and where we want it to end, which is reloc_dst.
	 *
	 * reloc_dst is kernel_load_start + 12MiB.
	 *
	 * We need to update our rootfs, env and font modules with the delta
	 * information.
	 *
	 * We then need to adjust any pointers in the bootinfo structure as
	 * needed.
	 */
	reloc_dst = kernel_load_start + (12 * 1024 * 1024);
	DBG(reloc_dst);
	if (reloc_dst < kernel_load_end)
		eboot_panic("Relocation destination is before kernel end\n");

	reloc_delta = reloc_dst - kernel_load_end;
	DBG(reloc_delta);
	if (md_end < kernel_load_end)
		eboot_panic("Suspect md_end value 0x%lx\n", md_end);

	/*
	 * We need to blindly relocate anything past where the loader thinks
	 * the kernel ends to the end of the data provided by the loader.
	 */
	reloc_size = md_end - kernel_load_end;
	DBG(md_end);
	DBG(reloc_size);

	DBG_P(("Will reloc module data away from the kernel area "
	    "by delta %lu, target address 0x%lx, source address 0x%lx, size "
	    "0x%lx\n", reloc_delta, reloc_dst, kernel_load_end, reloc_size));

	/*
	 * Find the memory region we're loaded into and ensure that our
	 * relocation operation won't overflow that region.
	 */
	reloc_memcheck_ok = 0;

	for (i = 0; i < memlists_used; ++i) {
		start = RNDUP(memlists[i].addr, MMU_PAGESIZE);
		end = RNDDN(memlists[i].addr + memlists[i].size,
		    MMU_PAGESIZE);
		if (!(kernel_load_start >= start && kernel_load_start < end))
			continue;

		/* we've found our region, check that we fit as it is */
		if (md_end > end)
			eboot_panic("We've already overflowed our physical "
			    "memory region\n");

		if (reloc_dst + reloc_size > end)
			eboot_panic("Data relocation would overflow our "
			    "physical region\n");

		reloc_memcheck_ok = 1;
		break;
	}

	if (reloc_memcheck_ok == 0)
		eboot_panic("Data relocation physical memory check failed\n");

	/*
	 * If we're actually relocating, do the data move and pointer updates
	 * now.  If not, we've at least checked that we haven't trashed any
	 * memory we're not supposed to be touching.
	 */
	if (reloc_delta != 0) {
		DBG_P(("memmove(dst=0x%lx, src=0x%lx, sz=0x%lx)\n",
		    reloc_dst, kernel_load_end, reloc_size));
		memmove((void *)reloc_dst, (const void *)kernel_load_end,
		    (size_t)reloc_size);

		cmdline_paddr += reloc_delta;
		bi->bi_cmdline = cmdline_paddr;
		uefi_map_hdr =
		    (struct efi_map_header *)(((uint64_t)uefi_map_hdr) +
		    reloc_delta);

		if (fb->framebuffer != 0) {
			fb->framebuffer += reloc_delta;
			DBG_P(("Relocated fb->framebuffer from 0x%lx to "
			    "0x%lx\n", fb->framebuffer - reloc_delta,
			    fb->framebuffer));
		}

		/*
		 * Now relocate our modules
		 */
		for (i = 0; i < modules_used; ++i) {
			modules[i].bm_addr += reloc_delta;
			if (modules[i].bm_name && modules[i].bm_type != BMT_ENV)
				modules[i].bm_name += reloc_delta;
			/* XXXAARCH64: ^^ we can do better than this */
		}
	}

	/*
	 * Clear the BSS, all trailing data and any holes in the kernel
	 * area.
	 *
	 * The layout is as follows:
	 * +--------------+ < to here
	 * \    space     /
	 * /              \
	 * +--------------+ < and from here...
	 * |    (bss)     | < and some here, then...
	 * |    (data)    |
	 * +--------------+ < to here...
	 * \    space     /
	 * /              \ 
	 * +--------------+ < clear from here...
	 * |    (text)    |
	 * +--------------+
	 */
	if (k_end - ke_data)
		memset((void *)(ke_data - bi->bi_va_pa_delta),
		    0, (k_end - ke_data));
	if (ks_data - ke_text)
		memset((void *)(ke_text - bi->bi_va_pa_delta),
		    0, (ks_data - ke_text));
	if (ks_data - ke_text)
		memset((void *)(ke_text - bi->bi_va_pa_delta),
		    0, (ks_data - ke_text));
	if ((KERNEL_TEXT + (8 * 1024 * 1024)) - k_end)
		memset((void *)(k_end - bi->bi_va_pa_delta), 0,
		    (KERNEL_TEXT + (8 * 1024 * 1024)) - k_end);

	next_avail_addr = RNDUP(reloc_dst + reloc_size, MMU_PAGESIZE);
	DBG(next_avail_addr);

	DBG_P(("Should already be set:\n"));
	DBG(bi->bi_va_pa_delta);
	DBG(bi->bi_physload);
	DBG(bi->bi_physmin);
	DBG(bi->bi_physmax);
	DBG_P(("Might be set:\n"));
	DBG(bi->bi_dbg2_pa);
	DBG(bi->bi_dbg2_va);
	DBG(bi->bi_dbg2_type);
	DBG_P(("Points into eboot:\n"));
	DBG(bi->bi_phys_install);	/* needs to be a PA */
	DBG(bi->bi_rsvdmem);		/* needs to be a PA */
	DBG(bi->bi_pcimem);		/* needs to be a PA (or delete) */
	DBG(bi->bi_modules);		/* not set yet, needs to be a PA */
	DBG(bi->bi_module_cnt);		/* not set yet */
	DBG_P(("UEFI systab:\n"));
	DBG(bi->bi_uefi_systab);
	DBG_P(("ACPI at fixed addresses:\n"));
	DBG(bi->bi_rsdp);
	DBG(bi->bi_smbios3);
	DBG(bi->bi_acpi_xsdt);
	DBG_P(("Stuff wot needed relocation\n"));
	DBG(bi->bi_cmdline);
	DBG(bi->bi_framebuffer);	/* points to eboot, but the member needs reloc */
	DBG_P(("Stuff to do later\n"));
	DBG(bi->bi_next_paddr);
	DBG(bi->bi_next_vaddr);
	DBG(bi->bi_pt_window);
	DBG(bi->bi_pte_to_pt_window);
	DBG(bi->bi_kseg_size);
	DBG(bi->bi_top_ttbr0);
	DBG(bi->bi_top_ttbr1);

	DBG_P(("bi->bi_cmdline: '%s'\n", (char *)bi->bi_cmdline));
	for (i = 0; i < modules_used; ++i) {
		DBG_P(("Boot module %u:\n", i));
		DBG_P(("  Address: 0x%lx\n", modules[i].bm_addr));
		DBG_P(("     Name: 0x%lx (%s)\n", modules[i].bm_name,
		    modules[i].bm_name ?
		    (char *)modules[i].bm_name : "(null)"));
		DBG_P(("     Size: %lu\n", modules[i].bm_size));
		DBG_P(("     Type: 0x%x (%s)\n", modules[i].bm_type,
		    type_to_str(modules[i].bm_type)));
	}

	DBG(kernel_load_start);
	DBG(kernel_load_end);
	DBG(kernel_load_end - kernel_load_start);

	DBG_P(("Next available physical address is 0x%lx\n", next_avail_addr));
}

/* XXXAARCH64: move this around when the dust settles */
static int prekern_getenv_uint32(
    const char *envp, const char *name, uint32_t *data);

static void
eboot_update_fb_info(void)
{
	uint32_t r, c;

	if (prekern_getenv_uint32(envp, "tem.cursor.row", &r) &&
	    prekern_getenv_uint32(envp, "tem.cursor.col", &c)) {
		if (r <= 0xffff && c <= 0xffff) {
			fb->cursor.pos.x = c;
			fb->cursor.pos.y = r;
		}
	}
}

static uint64_t
eboot_alloc_page(void)
{
	return ((uint64_t)mem_alloc(MMU_PAGESIZE));
}

#define	L0IDX(__va)	(((__va) >> 39) & 0x1ff)
#define	L0_TABLE_MASK	(((1UL << 48) - 1) & ~0xfff)
#define	L0_TABLE	0x3UL
#define	L1IDX(__va)	(((__va) >> 30) & 0x1ff)
#define	L1_BLOCK_MASK	L0_TABLE_MASK
#define	L1_TABLE_MASK	L0_TABLE_MASK
#define	L1_BLOCK	0x1UL
#define	L1_TABLE	0x3UL
#define	L2IDX(__va)	(((__va) >> 21) & 0x1ff)
#define	L2_TABLE_MASK	L1_TABLE_MASK
#define	L2_BLOCK_MASK	L1_BLOCK_MASK
#define	L2_BLOCK	0x1UL
#define	L2_TABLE	0x3UL
#define	L3IDX(__va)	(((__va) >> 12) & 0x1ff)
#define	L3_PAGE_MASK	L2_BLOCK_MASK
#define	L3_PAGE		0x3UL

#define	IS_P2_X_ALIGNED(__addr, __a)		(((__addr) & ((__a) - 1)) == 0)
#define	BOTH_P2_X_ALIGNED(__va, __pa, __a)	(IS_P2_X_ALIGNED((__va), (__a)) && IS_P2_X_ALIGNED((__pa), (__a)))
#define	USE_P2_MAPPING(__rem, __va, __pa, __a)	(((__rem) >= (__a)) && BOTH_P2_X_ALIGNED((__va), (__pa), (__a)))

#define	M_512G				(1UL << 39)
#define	M_16G				(1UL << 34)
#define	M_1G				(1UL << 30)
#define	M_32M				(1UL << 25)
#define	M_2M				(1UL << 21)
#define	M_64K				(1UL << 16)
#define	M_4K				(1UL << 12)

#define	USE_MAPPING(__m, __rem, __pa, __va)	USE_P2_MAPPING((__rem), (__va), (__pa), (__m))

#define	USE_512G_MAPPING(__rem, __pa, __va)	USE_MAPPING(M_512G, (__rem), (__pa), (__va))
#define	USE_16G_MAPPING(__rem, __pa, __va)	USE_MAPPING(M_16G, (__rem), (__pa), (__va))
#define	USE_1G_MAPPING(__rem, __pa, __va)	USE_MAPPING(M_1G, (__rem), (__pa), (__va))
#define	USE_32M_MAPPING(__rem, __pa, __va)	USE_MAPPING(M_32M, (__rem), (__pa), (__va))
#define	USE_2M_MAPPING(__rem, __pa, __va)	USE_MAPPING(M_2M, (__rem), (__pa), (__va))
#define	USE_64K_MAPPING(__rem, __pa, __va)	USE_MAPPING(M_64K, (__rem), (__pa), (__va))
#define	USE_4K_MAPPING(__rem, __pa, __va)	USE_MAPPING(M_4K, (__rem), (__pa), (__va))

/*
 * Walk the boot loader provided information and find the highest free address.
 */
static void
init_mem_alloc(void)
{
	DBG_MSG("Entered init_mem_alloc()\n");
	/* TODO: do we need to do anything here?  I don't think so. */
}

/* print out EFI version string with newline */
static void
eboot_print_efi_version(uint32_t ver)
{
	int rev;

	eboot_printf("%d.", EFI_REV_MAJOR(ver));

	rev = EFI_REV_MINOR(ver);
	if ((rev % 10) != 0) {
		eboot_printf("%d.%d\n", rev / 10, rev % 10);
	} else {
		eboot_printf("%d\n", rev / 10);
	}
}

static void
print_efi64(EFI_SYSTEM_TABLE64 *efi)
{
	uint16_t *data;
	EFI_CONFIGURATION_TABLE64 *conf;
	int i;

	eboot_printf("EFI64 signature: %llx\n",
	    (unsigned long long)efi->Hdr.Signature);
	eboot_printf("EFI system version: ");
	eboot_print_efi_version(efi->Hdr.Revision);
	eboot_printf("EFI system vendor: ");
	data = (uint16_t *)(uintptr_t)efi->FirmwareVendor;
	for (i = 0; data[i] != 0; i++)
		eboot_printf("%c", (char)data[i]);
	eboot_printf("\nEFI firmware revision: ");
	eboot_print_efi_version(efi->FirmwareRevision);
	eboot_printf("EFI system table number of entries: %" PRIu64 "\n",
	    efi->NumberOfTableEntries);
	conf = (EFI_CONFIGURATION_TABLE64 *)(uintptr_t)
	    efi->ConfigurationTable;
	for (i = 0; i < (int)efi->NumberOfTableEntries; i++) {
		eboot_printf("%d: 0x%x 0x%x 0x%x 0x%x 0x%x", i,
		    conf[i].VendorGuid.time_low,
		    conf[i].VendorGuid.time_mid,
		    conf[i].VendorGuid.time_hi_and_version,
		    conf[i].VendorGuid.clock_seq_hi_and_reserved,
		    conf[i].VendorGuid.clock_seq_low);
		eboot_printf(" 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x",
		    conf[i].VendorGuid.node_addr[0],
		    conf[i].VendorGuid.node_addr[1],
		    conf[i].VendorGuid.node_addr[2],
		    conf[i].VendorGuid.node_addr[3],
		    conf[i].VendorGuid.node_addr[4],
		    conf[i].VendorGuid.node_addr[5]);
		eboot_printf(" => 0x%lx\n", (uint64_t)conf[i].VendorTable);
	}
}

/*
 * Simple memory allocator, allocates aligned physical memory.
 * Note that startup_kernel() only allocates memory, never frees.
 * Memory usage just grows in an upward direction.
 */
static int
region_in_use(uint64_t addr, uint32_t size)
{
	uint32_t i;
	uint64_t aend;
	uint64_t start;
	uint64_t end;

	aend = addr + size;
	if (aend < addr)
		return (1);	/* XXX: rough overflow check */

	for (i = 0; i < rsvdmemlists_used; ++i) {
		start = rsvdmemlists[i].addr;
		end = start + rsvdmemlists[i].size;

		if (addr > end)
			continue;

		if (addr >= start && addr < end) {
			eboot_printf("addr 0x%lu falls within reserved region "
			    "%u (0x%lu - 0x%lu)\n", addr, i, start, end);
			return (1);
		}

		if (aend >= start && aend < end) {
			eboot_printf("aend 0x%lu falls within reserved region "
			    "%u (0x%lu - 0x%lu)\n", aend, i, start, end);
			return (1);
		}

		if (addr < start && aend >= end) {
			eboot_printf("addr range 0x%lu encompases within "
			    "reserved region %u (0x%lu - 0x%lu)\n",
			    addr, i, start, end);
			return (1);
		}
	}

	/* TODO: check memory allocated for the kernel */
	/* TODO: check env, font, rootfs */
	return (0);
}

static void *
do_mem_alloc(uint32_t size, uint32_t align)
{
	uint_t i;
	uint64_t best;
	uint64_t start;
	uint64_t end;
	int found;

	DBG_P(("do_mem_alloc with size %u, align %u, next_avail_addr 0x%lx\n",
	    size, align, next_avail_addr));

	/*
	 * make sure size is a multiple of pagesize
	 */
	size = RNDUP(size, MMU_PAGESIZE);
	next_avail_addr = RNDUP(next_avail_addr, align);

	DBG_P(("Adjusted size %u, next_avail_addr 0x%lx\n",
	    size, next_avail_addr));

	/*
	 * XXPV fixme joe
	 *
	 * a really large bootarchive that causes you to run out of memory
	 * may cause this to blow up
	 */
	/* LINTED E_UNEXPECTED_UINT_PROMOTION */
	best = (uint64_t)-size;
	found = 0;
	for (i = 0; i < memlists_used; ++i) {
		DBG_P(("Looking for 0x%lx in memlist %u\n",
		    next_avail_addr, i));
		start = memlists[i].addr;
		end = start + memlists[i].size;

		/*
		 * did we find the desired address?
		 */
		if (start <= next_avail_addr && next_avail_addr + size <= end) {
			if (!region_in_use(next_avail_addr, size)) {
				DBG_P(("Found 0x%lx in memlist %u. start "
				    "is 0x%lx, end is 0x%lx\n",
				    next_avail_addr, i, start, end));
				best = next_avail_addr;
				goto done;
			}
		}

		/*
		 * if not is this address the best so far?
		 */
		if (start > next_avail_addr && start < best &&
		    RNDUP(start, align) + size <= end) {
			if (!region_in_use(RNDUP(start, align), size)) {
				best = RNDUP(start, align);
				found = 1;
			}
		}
	}

	/*
	 * We didn't find exactly the address we wanted, due to going off the
	 * end of a memory region. Return the best found memory address.
	 */
	if (found == 0)
		eboot_panic("No suitable memory region for allocation\n");

	DBG_P(("Could not find our best region, falling back to "
	    "another suitable one\n"));
done:
	DBG_P(("Old next_avail_addr: 0x%lx, requested size %u, best 0x%lx "
	    "- new next_avail_addr 0x%lx\n",
	    next_avail_addr, size, best, best + size));
	next_avail_addr = RNDUP(best + size, MMU_PAGESIZE);
	(void) memset((void *)(uintptr_t)best, 0, size);
	return ((void *)(uintptr_t)best);
}

void *
mem_alloc(uint32_t size)
{
	return (do_mem_alloc(size, MMU_PAGESIZE));
}

static void *
page_alloc(void)
{
	return (do_mem_alloc(MMU_PAGESIZE, MMU_PAGESIZE));
}

static void *
alloc_pages(uint32_t n)
{
	return (do_mem_alloc(n * MMU_PAGESIZE, MMU_PAGESIZE));
}

#define MD_FETCH_RAW(mdp, info, type) ({ \
	type *__p; \
	__p = (type *)preload_search_info((mdp), MODINFO_METADATA | (info)); \
	__p ? *__p : 0; \
})

#define MD_FETCH(mdp, info, type) ({ \
	type *__p; \
	__p = (type *)preload_search_info((mdp), MODINFO_METADATA | (info)); \
	__p ? ((*__p >= (type)hole_end) ? VTOP(*__p) : *__p) : 0; \
})

static const char *
prekern_env_next(const char *cp)
{
	if (cp != NULL) {
		while (*cp != 0)
			++cp;
		cp++;
		if (*cp == 0)
			cp = NULL;
	}

	return (cp);
}

static const char *
prekern_getenv_from(const char *envp, const char *name)
{
	const char *cp, *ep;
	size_t len;

	for (cp = envp; cp != NULL; cp = prekern_env_next(cp)) {
		for (ep = cp; (*ep != '=') && (*ep != 0); ep++)
			;
		if (*ep != '=')
			continue;
		len = ep - cp;
		ep++;
		if (!strncmp(name, cp, len) && name[len] == 0)
			return (ep);
	}

	return (NULL);
}

/*
 * A mishmash of the Solaris and BSD strtoul code.
 */
static int
prekern_str_to_ulnum(const char *s, uint64_t *data)
{
	uint64_t multmax, val = 0;
	int c, base = 10;

	if (s == NULL)
		return (0);

	do {
		c = *s++;
	} while (c == ' ' || c == '\t');

	switch (c) {
	case '-':
		return (0);
	case '+':
		c = *s++;
		/* fallthrough */
	default:
		break;
	}

	if (c == '0' && (*s == 'x' || *s == 'X')) {
		c = s[1];
		s += 2;
		base = 16;
	} else if (c == '0') {
		base = 8;
	}

	multmax = UINT64_MAX / (uint64_t)base;
	val = 0;

	for (; ; c = *s++) {
		if (val > multmax)
			return (0);
		if (c >= '0' && c <= '9')
			c -= '0';
		else if (c >= 'A' && c <= 'Z')
			c -= 'A' - 10;
		else if (c >= 'a' && c <= 'z')
			c -= 'a' - 10;
		else
			break;
		if (c >= base)
			break;
		val *= base;
		if (UINT64_MAX - val < (uint64_t)c)
			return 0;
		val += c;
	}

	while (c != '\0') {
		if (c != ' ' && c != '\t')
			return (0);
		c = *s++;
	}

	*data = val;
	return (1);
}

static int
prekern_str_to_unum(const char *s, uint32_t *data)
{
	uint64_t x;

	if (!prekern_str_to_ulnum(s, &x))
		return (0);
	if (x > UINT32_MAX)
		return (0);

	*data = (uint32_t)x;
	return 1;
}

static int
prekern_getenv_uint64(const char *envp, const char *name, uint64_t *data)
{
	return prekern_str_to_ulnum(prekern_getenv_from(envp, name), data);
}

static int
prekern_getenv_uint32(const char *envp, const char *name, uint32_t *data)
{
	return prekern_str_to_unum(prekern_getenv_from(envp, name), data);
}

static int
prekern_has_env(const char *envp, const char *name)
{
	return (prekern_getenv_from(envp, name) != NULL);
}

static int
eboot_getenv_uint64(const char *name, uint64_t *data)
{
	return prekern_getenv_uint64(envp, name, data);
}

#if defined(MODINFOMD_ENVP)
static void
preload_dump_env(const char *cp)
{
	for (; cp != NULL; cp = prekern_env_next(cp))
		eboot_printf("  %s\n", cp);
}
#endif

static void
preload_dump_shdr(caddr_t v)
{
	DBG_P(("%s: section header at 0x%p\n", __func__, v));
}

/*
 * A string is:
 * four bytes: type
 * four bytes: size
 * X bytes, rounded up to 4: data
 *
 * A 64 bit value (address etc.) is:
 * four bytes: type
 * four bytes: size
 * eight bytes: data
 */
static void
preload_dump_record(uint32_t *hdr)
{
#define	MOD_SIZE(x)	((x)[1])
#define	MOD_STRING(x)	((const char *)(&(x)[2]))
#define	MOD_UINT32(x)	(*((uint32_t *)(&(x)[2])))
#define	MOD_UINT64(x)	(*((uint64_t *)(&(x)[2])))
#define	P_MOD_STRING(n, x)	eboot_printf("MODINFO_%s: <%s> (%u bytes)\n", \
	(n), MOD_STRING((x)), MOD_SIZE((x)));
#define	P_MOD_UINT32(n, x)	eboot_printf("MODINFO_%s: <0x%x> (%u bytes)\n", \
	(n), MOD_UINT32((x)), MOD_SIZE((x)));
#define	P_MOD_UINT64(n, x)	eboot_printf("MODINFO_%s: <0x%lx> (%u bytes)\n", \
	(n), MOD_UINT64((x)), MOD_SIZE((x)));
#define	P_MDMOD_STRING(n, x)	eboot_printf("MODINFOMD_%s: <%s> (%u bytes)\n", \
	(n), MOD_STRING((x)), MOD_SIZE((x)));
#define	P_MDMOD_UINT32(n, x)	eboot_printf("MODINFOMD_%s: <0x%x> (%u bytes)\n", \
	(n), MOD_UINT32((x)), MOD_SIZE((x)));
#define	P_MDMOD_UINT64(n, x)	eboot_printf("MODINFOMD_%s: <0x%lx> (%u bytes)\n", \
	(n), MOD_UINT64((x)), MOD_SIZE((x)));

	if ((hdr[0] & MODINFO_METADATA) == 0) {
		switch (hdr[0]) {
		case MODINFO_NAME:
			P_MOD_STRING("NAME", hdr);
			break;
		case MODINFO_TYPE:
			P_MOD_STRING("TYPE", hdr);
			break;
		case MODINFO_ADDR:
			P_MOD_UINT64("ADDR", hdr);
			break;
		case MODINFO_SIZE:
			P_MOD_UINT64("SIZE", hdr);
			break;
		case MODINFO_ARGS:
			/* kernel/module command-line arguments, as a flat string */
			/* not provided if there were no arguments */
			/* should we be prepending the name? */
			P_MOD_STRING("ARGS", hdr);
			break;
		case MODINFO_END:
			eboot_printf("MODINFO_END\n");
			break;
		case MODINFO_EMPTY:
			eboot_printf("MODINFO_EMPTY\n");
			break;
		default:
			eboot_printf("Unhandled record %u\n", hdr[0]);
			break;
		}
	} else {
		switch (hdr[0] & ~MODINFO_METADATA) {
		case MODINFOMD_AOUTEXEC:
			P_MDMOD_UINT64("AOUTEXEC", hdr);
			break;
		case MODINFOMD_ELFHDR:
			P_MDMOD_UINT64("ELFHDR", hdr);
			break;
		case MODINFOMD_SSYM:
			P_MDMOD_UINT64("SSYM", hdr);
			break;
		case MODINFOMD_ESYM:
			P_MDMOD_UINT64("ESYM", hdr);
			break;
		case MODINFOMD_DYNAMIC:
			P_MDMOD_UINT64("DYNAMIC", hdr);
			break;
#if !defined(MODINFOMD_ENVP)
		case MODINFOMD_MB2HDR:
			P_MDMOD_UINT64("MB2HDR", hdr);
			break;
#endif
#if defined(MODINFOMD_ENVP)
		case MODINFOMD_ENVP:
			P_MDMOD_UINT64("ENVP", hdr);
			preload_dump_env((const char *)MAYBE_VTOP(MOD_UINT64(hdr)));
			break;
#endif
#if defined(MODINFOMD_HOWTO)
		case MODINFOMD_HOWTO:
			P_MDMOD_UINT64("HOWTO", hdr);
			break;
#endif
#if defined(MODINFOMD_KERNEND)
		case MODINFOMD_KERNEND:
			P_MDMOD_UINT64("KERNEND", hdr);
			break;
#endif
		case MODINFOMD_SHDR:
			P_MDMOD_UINT64("SHDR", hdr);
			preload_dump_shdr((caddr_t)&hdr[2]);
			break;
		case MODINFOMD_CTORS_ADDR:
			P_MDMOD_UINT64("CTORS_ADDR", hdr);
			break;
		case MODINFOMD_CTORS_SIZE:
			P_MDMOD_UINT64("CTORS_SIZE", hdr);
			break;
		case MODINFOMD_FW_HANDLE:
			P_MDMOD_UINT64("FW_HANDLE", hdr);
			break;
		case MODINFOMD_KEYBUF:
			P_MDMOD_UINT64("KEYBUF", hdr);
			break;
		case MODINFOMD_FONT:
			P_MDMOD_UINT64("FONT", hdr);
			break;
		case MODINFOMD_DEPLIST:
			P_MDMOD_UINT64("DEPLIST", hdr);
			break;
		case MODINFOMD_EFI_MAP:
#if 1
			eboot_printf("Found UEFI Memory Map\n");
			eboot_printf("  Map size: %u\n", MOD_SIZE((hdr)));
#endif
			/* XXXX */
			P_MDMOD_UINT64("EFI_MAP", hdr);
			break;
		case MODINFOMD_DTBP:
			P_MDMOD_UINT64("DTBP", hdr);
			break;
		case MODINFOMD_EFI_FB:
			P_MDMOD_UINT64("EFI_FB", hdr);
			break;
		default:
			eboot_printf("Unhandled metadata record %x\n", hdr[0]);
			break;
		}
	}
}

static void
preload_dump_info(caddr_t mod)
{
	caddr_t		curp;
	uint32_t	*hdr;
	uint32_t	type = 0;
	int		next;

	if (mod == NULL)
		return;

	curp = mod;
	for (;;) {
		hdr = (uint32_t *)curp;
		/* end of module data? */
		if (hdr[0] == 0 && hdr[1] == 0) {
			preload_dump_record(hdr);
			eboot_printf("preload_dump_info: end of module data\n");
			break;
		}

		/*
		 * We give up once we've looped back to what we were looking at
		 * first - this should normally be a MODINFO_NAME field.
		 */
		if (type == 0) {
			type = hdr[0];
		} else {
			if (hdr[0] == type) {
				eboot_printf("preload_dump_info: wrapped around, breaking out\n");
				break;
			}
		}

		/*
		 * Attribute match? Return pointer to data.
		 * Consumer may safely assume that size value precedes data.
		 */
		preload_dump_record(hdr);
		/* eboot_printf("preload_dump_info: module info record %u\n", hdr[0]); */

		/* skip to next field */
		next = sizeof(uint32_t) * 2 + hdr[1];
		next = roundup(next, sizeof(u_long));
		curp += next;
	}
}

static void
preload_dump(caddr_t md)
{
	caddr_t		curp /*, lname */;
	uint32_t	*hdr;
	int		next;

	if (md != NULL) {
		curp = md;
		/* lname = NULL; */

		for (;;) {
			hdr = (uint32_t *)curp;

			if (hdr[0] == 0 && hdr[1] == 0) {
				eboot_printf("preload_dump: end of preloaded module list\n");
				break;
			}

			if (hdr[0] == MODINFO_NAME) {
				eboot_printf("preload_dump: start of record\n");
				/* lname = curp; */
				preload_dump_info(curp);
			}

			next = sizeof(uint32_t) * 2 + hdr[1];
			next = roundup(next, sizeof(u_long));
			curp += next;
		}

		eboot_printf("preload_dump: end of modules\n");
	}
}

static caddr_t
preload_find_end(caddr_t md)
{
	caddr_t		curp;
	uint32_t	*hdr;
	int		next;

	/* MODINFO_END */
	if (md == NULL)
		return (NULL);

	curp = md;

	for (;;) {
		hdr = (uint32_t *)curp;
		if (hdr[0] == MODINFO_END && hdr[1] == 0)
			return ((caddr_t)&hdr[1]);

		next = sizeof(uint32_t) * 2 + hdr[1];
		next = roundup(next, sizeof(u_long));
		curp += next;
	}
}

/*
 * Search for the first preloaded module of (type)
 */
static caddr_t
preload_search_by_type(caddr_t md, const char *type)
{
	caddr_t		curp, lname;
	uint32_t	*hdr;
	int		next;

	DBG_P(("Looking for '%s' in 0x%p\n", type, md));
	if (md != NULL) {
		curp = md;
		lname = NULL;

		for (;;) {
			hdr = (uint32_t *)curp;
			if (hdr[0] == 0 && hdr[1] == 0)
				break;

			/* remember the start of each record */
			if (hdr[0] == MODINFO_NAME) {
				DBG_P(("hdr[0] == MODINFO_NAME\n"));
				lname = curp;
			}

			if (hdr[0] == MODINFO_TYPE) {
				DBG_P(("hdr[0] == MODINFO_TYPE\n"));
				DBG_P(("compare '%s' to '%s'\n", curp + sizeof(uint32_t) * 2, type));
			}
			/* Search for a MODINFO_TYPE field */
			if ((hdr[0] == MODINFO_TYPE) &&
			    !strcmp(type, curp + sizeof(uint32_t) * 2))
				return (lname);

			// DBG_P(("No match, skip to next\n"));
			/* skip to next field */
			next = sizeof(uint32_t) * 2 + hdr[1];
			next = roundup(next, sizeof(u_long));
			curp += next;
		}
	}

	return (NULL);
}

/*
 * Given a preloaded module handle (mod), return a pointer
 * to the data for the attribute (inf).
 */
static caddr_t
preload_search_info(caddr_t mod, int inf)
{
	caddr_t		curp;
	uint32_t	*hdr;
	uint32_t	type = 0;
	int		next;

	if (mod == NULL)
		return (NULL);

	curp = mod;
	for (;;) {
		hdr = (uint32_t *)curp;
		/* end of module data? */
		if (hdr[0] == 0 && hdr[1] == 0)
			break;
		/*
		 * We give up once we've looped back to what we were looking at
		 * first - this should normally be a MODINFO_NAME field.
		 */
		if (type == 0) {
			type = hdr[0];
		} else {
			if (hdr[0] == type)
				break;
		}

		/*
		 * Attribute match? Return pointer to data.
		 * Consumer may safely assume that size value precedes data.
		 */
		if (hdr[0] == inf)
			return (curp + (sizeof(uint32_t) * 2));

		/* skip to next field */
		next = sizeof(uint32_t) * 2 + hdr[1];
		next = roundup(next, sizeof(u_long));
		curp += next;
	}

	return (NULL);
}

static int	boothowto;

static uint64_t
parse_boot_params(caddr_t md)
{
	uint64_t	lastaddr;
	char 		*loader_envp;
	char		*p;
	int		lastnul, thisnul;

	loader_envp = MD_FETCH(kmdp, MODINFOMD_ENVP, char *);
	eboot_printf("parse_boot_params: loader envp is %p\n", loader_envp);
	eboot_printf("parse_boot_params: loader env start is %s\n", loader_envp);

	lastnul = thisnul = 0;

	for (p = loader_envp; ; ++p) {
		if (*p == '\0' && lastnul)
			break;
		/*
		 * If last was NUL and this is NUL, we're done.
		 */
	}
#if 0
	boothowto = MD_FETCH(kmdp, MODINFOMD_HOWTO, int);
	init_static_kenv(loader_envp, 0);
#endif
	lastaddr = MD_FETCH(kmdp, MODINFOMD_KERNEND, uint64_t);
	/* XXX: adjust by va/pa offset */

	return (lastaddr);
}


/*
 * We just need enough from the boot modules to map/remap our memory regions and
 * and boot the kernel.
 *
 * Returns the last used address (physical?)
 */
static uint64_t
parse_modulep(caddr_t modulep, struct xboot_info *xbi)
{
	uint64_t	lastaddr;

	lastaddr = parse_boot_params(modulep);
	return (lastaddr);
}

static void *
prekern_get_kernel_module(caddr_t modulep)
{
	void *kmdp;

	kmdp = preload_search_by_type(modulep, "elf kernel");
	if (kmdp == NULL)
		kmdp = preload_search_by_type(modulep, "elf64 kernel");

	return (kmdp);
}

static uint64_t
eboot_efi_memattr_to_aarch64(uint64_t attr)
{
	uint64_t a;

	a = PT_ATTR_UXN			/* always user execute-never */
	    | PT_ATTR_NG		/* always non-global (ASID is 0) */
	    | PT_ATTR_AF		/* never take access exceptions */
	    | PT_ATTR_SH(PT_SH_OS)	/* outer shareable */
	    | PT_ATTR_NS;		/* non-secure */

	/*
	 * As per the mapping table in UEFI spec 2.6
	 * 2.3.6.1 Memory types
	 *
	 * We evaluate the bits set in the order we'd most prefer for
	 * performance reasons.
	 */
	if ((attr & EFI_MEMORY_WB) == EFI_MEMORY_WB)
		a |= PT_MATTR(MIDX_MEMORY_WB);	/* writeback */
	else if ((attr & EFI_MEMORY_WT) == EFI_MEMORY_WT)
		a |= PT_MATTR(MIDX_MEMORY_WT);	/* write-through */
	else if ((attr & EFI_MEMORY_WC) == EFI_MEMORY_WC)
		a |= PT_MATTR(MIDX_MEMORY_NC);	/* write-combining */
	else if ((attr & EFI_MEMORY_UC) == EFI_MEMORY_UC)
		a |= PT_MATTR(MIDX_DEVICE);	/* device nGnRnE */
	else
		eboot_panic("Unsupported memory attribute 0x%lx\n", attr);

	/*
	 * The following are not used or defined, so we ignore them:
	 * EFI_MEMORY_XP
	 * EFI_MEMORY_WP
	 * EFI_MEMORY_RP
	 * EFI_MEMORY_UCE
	 */

	/*
	 * EFI_MEMORY_RP is read-protect, so just leave it unmapped?
	 * EFI_MEMORY_NV persistent memory, which we ignore for now.
	 * EFI_MEMORY_MORE_RELIABLE unclear how we'd use this, so ignore.
	 * EFI_MEMORY_RUNTIME is how we got here to begin with.
	 */

	/*
	 * The UEFI runtime is for use by the privileged world, so make it
	 * user-execute-never.
	 */

	if ((attr & EFI_MEMORY_XP) == EFI_MEMORY_XP)
		a |= PT_ATTR_PXN;	/* privileged execute-never */

	if ((attr & EFI_MEMORY_RO) == EFI_MEMORY_RO)
		a |= PT_ATTR_AP(PT_AP_PRO);	/* privileged read-only */
	else
		a |= PT_ATTR_AP(PT_AP_PRW);	/* privileged read/write */

	return (a);
}

/*
 * There are three parts to remapping the UEFI runtime:
 * 1) Update the MMU page tables (already done)
 * 2) Relocate the runtime code and data (SetVirtualAddressMap)
 * 2a) This involves repacking the UEFI memory map passed by the loader
 * 3) Locating the various system table pointers in the remapped area and
 *    updating what we pass to the kernel.
 */
static void ingest_uefi_systab(void);

/*
 * Map sz pages at pa to va using tmpl as the PTE template.
 */
static void
eboot_map_pa_to_va(paddr_t pa, uint64_t va, size_t sz, aarch64pte_t tmpl)
{
	uint32_t n;
	paddr_t opa;
	aarch64pte_t *ptep;

	sz <<= MMU_PAGESHIFT;
	tmpl |= PT_ATTR_AF;

	while (sz) {
		if (USE_512G_MAPPING(sz, pa, va)) {
			/*
			 * A single 512GiB block
			 */
			DBG_P(("%s: Mapping 512GiB at 0x%lx to 0x%lx\n",
			    __func__, pa, va));
			*(find_pte(va, &opa, 3, 0)) =
			    tmpl | PA_TO_PT_OA(pa) | PTE_BLOCK;
			sz -= M_512G;
			pa += M_512G;
			va += M_512G;
		} else if (USE_16G_MAPPING(sz, pa, va)) {
			/*
			 * Sixteen contiguous 1GiB blocks aligned to a 16GiB
			 * boundary.
			 */
			DBG_P(("%s: Mapping 16GiB at 0x%lx to 0x%lx\n",
			    __func__, pa, va));
			ptep = find_pte(va, &opa, 2, 0);

			for (n = 0; n < 16; ++n, pa += M_1G)
				*ptep++ = tmpl | PA_TO_PT_OA(pa) |
				    PT_ATTR_CONTIG | PTE_BLOCK;

			sz -= M_16G;
			va += M_16G;
		} else if (USE_1G_MAPPING(sz, pa, va)) {
			/*
			 * A single 1GiB block
			 */
			DBG_P(("%s: Mapping 1GiB at 0x%lx to 0x%lx\n",
			    __func__, pa, va));
			*(find_pte(va, &opa, 2, 0)) =
			    tmpl | PA_TO_PT_OA(pa) | PTE_BLOCK;
			sz -= M_1G;
			pa += M_1G;
			va += M_1G;
		} else if (USE_32M_MAPPING(sz, pa, va)) {
			/*
			 * Sixteen contiguous 2MiB blocks aligned to a 32MiB
			 * boundary.
			 */
			DBG_P(("%s: Mapping 32MiB at 0x%lx to 0x%lx\n",
			    __func__, pa, va));
			ptep = find_pte(va, &opa, 1, 0);

			for (n = 0; n < 16; ++n, pa += M_2M)
				*ptep++ = tmpl | PA_TO_PT_OA(pa) |
				    PT_ATTR_CONTIG | PTE_BLOCK;

			sz -= M_32M;
			va += M_32M;
		} else if (USE_2M_MAPPING(sz, pa, va)) {
			/*
			 * A single 2MiB block
			 */
			DBG_P(("%s: Mapping 2MiB at 0x%lx to 0x%lx\n",
			    __func__, pa, va));
			*(find_pte(va, &opa, 1, 0)) =
			    tmpl | PA_TO_PT_OA(pa) | PTE_BLOCK;
			sz -= M_2M;
			pa += M_2M;
			va += M_2M;
		} else if (USE_64K_MAPPING(sz, pa, va)) {
			/*
			 * Sixteen contiguous 4KiB pages aligned to a 64KiB
			 * boundary.
			 */
			DBG_P(("%s: Mapping 64KiB at 0x%lx to 0x%lx\n",
			    __func__, pa, va));
			ptep = find_pte(va, &opa, 0, 0);

			for (n = 0; n < 16; ++n, pa += M_4K)
				*ptep++ = tmpl | PA_TO_PT_OA(pa) |
				    PT_ATTR_CONTIG | PTE_PAGE;

			sz -= M_64K;
			va += M_64K;
		} else if (USE_4K_MAPPING(sz, pa, va)) {
			/*
			 * A single 4KiB pages
			 */
#if 0
			DBG_P(("%s: Mapping 4KiB at 0x%lx to 0x%lx\n",
			    __func__, pa, va));
#endif
			ptep = find_pte(va, &opa, 0, 0);
			*ptep = tmpl | PA_TO_PT_OA(pa) | PTE_PAGE;
			sz -= M_4K;
			pa += M_4K;
			va += M_4K;
		} else {
			eboot_panic("Invalid mapping size\n");
		}
	}
}

/*
 * Create an empty top-level page table
 * Map the nucleus using the new top-level page table (creates intermediates)
 * Map the DBG2 VA if present
 * Relocate and map the environment
 * Relocate and map the font
 * Relocate the module name strings
 * Relocate the kernel command-line (this is still to be worked out)
 * Trawl through xbi and see what else needs to be relocated
 *   Relocate and update as needed
 *   We probably need some generic area to stash strings
 * Check the alignment of the rootfs and relocate if necessary.
 * Map in the framebuffer to our new VA, update pointers (really? we don't have this information, do we?)
 * Apparently the kernel needs a 1MiB window to work with page tables (not sure what this is supposed to mean)
 *
 * That _should_ be everything.  Update anything the ASM code will look at, then return to that code.
 * This _should_ be the kernel entry point and the XBI pointer.
 *
 * DBG2
 * ----
 * modules, environment, string tables etc.
 * ...
 * EFI runtime services
 * ...
 * Nucleus
 * ...
 */
static void
eboot_build_page_table()
{
	paddr_t window_pte_pte_pa;
	uint64_t tmp;
	uint64_t off;
	uint64_t sz;
	uint64_t ksz;
	uint32_t i;

	DBG_P(("eboot_build_page_table: let's get mooooooooving!\n"));

	/*
	 * Quick calc for the identity mapping needed in low space
	 */
	next_avail_addr =
	    RNDUP(next_avail_addr + MMU_PAGESIZE + 1, MMU_PAGESIZE);
	tmp = RNDDN(bi->bi_physload, MMU_PAGESIZE);
	sz = next_avail_addr - tmp;

	/*
	 * Allocate TTBR0, then identity map the following:
	 * - all physical memory that is not reserved
	 * - DBG2 device memory (if present)
	 * - the framebuffer (if present)
	 * - UEFI runtime services and device memory
	 *
	 * Set up a PTE pointer to the highest legal lower half address for use
	 * as the kernel PTE remapping window.
	 */
	ttbr0_top_table = (uint64_t)mem_alloc(MMU_PAGESIZE);
	if (ttbr0_top_table == 0)
		eboot_panic("Failed to allocate TTBR0 page table root\n");
	DBG(ttbr0_top_table);
	bi->bi_top_ttbr0 = (uint64_t)ttbr0_top_table;
	eboot_map_pa_to_va(tmp, tmp,
	    (2 * 1024 * 1024) >> MMU_PAGESHIFT, pte_memory);

	/*
	 * Allocate TTBR1, then map the following (from lowest to highest):
	 * - spintable mappings, if we end up needing these
	 * - the DBG2 port
	 * - a PTE for working with pagetables
	 * - the framebuffer, if present
	 * - the UEFI runtime
	 * - the kernel nucleus
	 *
	 * The kernel can and should, after relocation and module loading, write
	 * protect the text.
	 */
	ttbr1_top_table = (uint64_t)mem_alloc(MMU_PAGESIZE);
	if (ttbr1_top_table == 0)
		eboot_panic("Failed to allocate TTBR1 page table root\n");
	DBG(ttbr1_top_table);
	bi->bi_top_ttbr1 = (uint64_t)ttbr1_top_table;

	/*
	 * The kernel needs to run completely in TTBR1 (higher-half) space,
	 * including any references to bootloader data.  To make this possible
	 * we reflect our full bootloader region into higher-half memory.
	 *
	 * XXXMICHAEL: leave out the nucleus when doing this
	 */
	eboot_map_pa_to_va(tmp, BOOTLOADER_DATA_BASE,
	    (2 * 1024 * 1024) >> MMU_PAGESHIFT, pte_memory);
	tmp += (12 * 1024 * 1024);
	eboot_map_pa_to_va(tmp, BOOTLOADER_DATA_BASE + (12 * 1024 * 1024),
	    (sz - (12 * 1024 * 1024)) >> MMU_PAGESHIFT, pte_memory);

	/*
	 * TODO: spin table VA, if needed
	 */

	/*
	 * DBG2
	 */
	if (dbg2memlist_used != 0)
		DBG_P(("Mapping DBG2 to KVA\n"));

	for (i = 0; i < dbg2memlist_used; ++i) {
		DBG_P(("Mapping DBG2 region %u to KVA\n", i));
		eboot_map_pa_to_va(dbg2memlist[i].pa, dbg2memlist[i].va,
		    dbg2memlist[i].size >> MMU_PAGESHIFT, pte_device);
	}

	/*
	 * PT manipulation window
	 */
	bi->bi_pt_window = PT_WINDOW_VA;
	DBG_P(("Creating the PT manipulation window at KVA 0x%lx\n",
	    bi->bi_pt_window));
	bi->bi_pte_to_pt_window =
	    (uint64_t)find_pte(bi->bi_pt_window, &window_pte_pte_pa, 0, 0);
	window_pte_pte_pa &= ~0xfffUL;
	DBG(window_pte_pte_pa);
	DBG(bi->bi_pte_to_pt_window);
	eboot_map_pa_to_va(window_pte_pte_pa, PTE_WINDOW_PTE_VA, 1, pte_memory);
	DBG(PTE_WINDOW_PTE_VA);
	DBG(bi->bi_pte_to_pt_window & 0xfff);
	DBG(bi->bi_pte_to_pt_window);
	bi->bi_pte_to_pt_window =
	     PTE_WINDOW_PTE_VA | (bi->bi_pte_to_pt_window & 0xfffUL);
	DBG(bi->bi_pte_to_pt_window);

	/*
	 * Shadow FB space, leave this unallocated for now, as the kernel can
	 * fill it in as needed.
	 *
	 * ... or we could steal some RAM here... I dunno...
	 */

	/*
	 * Framebuffer space
	 */
	if (fb != NULL && fb->framebuffer) {
		struct efi_fb *efifb = (struct efi_fb *)fb->framebuffer;
		sz = (RNDUP(efifb->fb_addr + efifb->fb_size, MMU_PAGESIZE) -
		    RNDDN(efifb->fb_addr, MMU_PAGESIZE)) >> MMU_PAGESHIFT;

		if (sz != 0) {
			DBG_P(("Mapping UEFI Framebuffer to KVA\n"));
			eboot_map_pa_to_va(
			    RNDDN(efifb->fb_addr, MMU_PAGESIZE),
			    FRAMEBUFFER_BASE,
			    sz, pte_write_combining);
			efifb->fb_addr = FRAMEBUFFER_BASE;
		}
	}

	/*
	 * UEFI Runtime Services
	 *
	 * We simply set up the mappings here, the call to UEFI to relocate
	 * happens immediately before we return to ASM code.
	 */
	if (rtsmemlist_used == 0)
		eboot_panic("No UEFI memory map collected\n");

	for (i = 0; i < rtsmemlist_used; ++i) {
		if (rtsmemlist[i].type == EfiMemoryMappedIO) {
			DBG_P(("Mapping UEFI Runtime Services device region %u "
			    "to KVA\n", i));
			eboot_map_pa_to_va(rtsmemlist[i].pa, rtsmemlist[i].va,
			    rtsmemlist[i].size >> MMU_PAGESHIFT, pte_device);
			continue;
		}
		DBG_P(("Mapping UEFI Runtime Services region %u to KVA\n", i));
		eboot_map_pa_to_va(rtsmemlist[i].pa, rtsmemlist[i].va,
		    rtsmemlist[i].size >> MMU_PAGESHIFT,
		    eboot_efi_memattr_to_aarch64(rtsmemlist[i].attr));
	}

	/*
	 * Kernel nucleus
	 */
	DBG_P(("Mapping nucleus to KVA\n"));
	/*
	 * We need the actual kernel text start, which is 2MiB after the start
	 * of the eboot text.  We then map out 8MiB of kernel, which is what
	 * we build.  This is all terribly brittle.
	 */
	eboot_map_pa_to_va(bi->bi_physload + (2 * 1024 * 1024),
	    target_kernel_text + (2 * 1024 * 1024),
	    (8 * 1024 * 1024) >> MMU_PAGESHIFT, pte_memory);

	/* XXX: this should not be necessary */
	DBG(next_avail_addr);
	next_avail_addr =
	    RNDUP(next_avail_addr + MMU_PAGESIZE + 1, MMU_PAGESIZE);
	DBG(next_avail_addr);

	DBG_P(("Final TTBR0 L0 address is 0x%lx\n", bi->bi_top_ttbr0));
	DBG_P(("Final TTBR0 L1 address is 0x%lx\n", bi->bi_top_ttbr1));
}

/*
 * Find an ACPI table by signature in the XSDT.
 *
 * Assumes that ingest_uefi_systab has already been called.
 */
static ACPI_TABLE_HEADER *
find_acpi_table(const char *sig)
{
	ACPI_TABLE_HEADER *tab;
	UINT64 *xsdt_entry;
	size_t slen;
	UINT32 xsdt_entries;
	UINT32 i;
	UINT32 j;

	if (xsdt == NULL)
		return (NULL);

	DBG_P(("sig is %s\n", sig));
	slen = strlen(sig);
	DBG(slen);
	xsdt_entries = (xsdt->Header.Length -
	    sizeof(xsdt->Header)) / ACPI_XSDT_ENTRY_SIZE;
	xsdt_entry = &xsdt->TableOffsetEntry[0];

	DBG(xsdt_entries);
	DBG(xsdt_entry);
	tab = NULL;

	for (i = 0; i < xsdt_entries; ++i) {
		DBG(i);
		tab = (ACPI_TABLE_HEADER *)xsdt_entry[i];
		DBG(tab);
		if (tab == NULL)
			continue;
		DBG(tab->Signature);
		if (tab->Signature == NULL) {
			tab = NULL;
			continue;
		}
		DBG(sig);
		if (strncmp(tab->Signature, sig, slen) == 0) {
			DBG_P(("Found '%s' at index %u\n", sig, i));
			break;
		}
		DBG_P(("'"));
		for (j = 0; j < slen; ++j)
			DBG_P(("%c", tab->Signature[j]));
		DBG_P(("' does NOT match\n"));
		tab = NULL;
	}

	DBG(tab);
	if (tab == NULL) {
		DBG_P(("Could not find '%s'\n", sig));
		return (NULL);
	}

	/*
	 * TODO: check table CRC32
	 */

	return (tab);
}

#define	MMFR0_ECV_SHIFT		60
#define	MMFR0_ECV_MASK		0xfUL
#define	MMFR0_ECV_NOT_IMPL	0x0UL
#define	MMFR0_ECV_IMPL		0x1UL
#define	MMFR0_ECV_EXTENDED1	0x2UL

#define	MMFR0_FGT_SHIFT		56
#define	MMFR0_FGT_MASK		0xfUL
#define	MMFR0_FGT_NOT_IMPL	0x0UL
#define	MMFR0_FGT_IMPL		0x1UL

#define	MMFR0_EXS_SHIFT		44
#define	MMFR0_EXS_MASK		0xfUL

#define	MMFR0_TGRAN4_2_SHIFT	40
#define	MMFR0_TGRAN4_2_MASK	0xfUL

#define	MMFR0_TGRAN64_2_SHIFT	36
#define	MMFR0_TGRAN64_2_MASK	0xfUL

#define	MMFR0_TGRAN16_2_SHIFT	32
#define	MMFR0_TGRAN16_2_MASK	0xfUL

#define	MMFR0_TGRAN4_SHIFT	28
#define	MMFR0_TGRAN4_MASK	0xfUL

#define	MMFR0_TGRAN64_SHIFT	24
#define	MMFR0_TGRAN64_MASK	0xfUL

#define	MMFR0_TGRAN16_SHIFT	20
#define	MMFR0_TGRAN16_MASK	0xfUL

#define	MMFR0_BIGENDEL0_SHIFT	16
#define	MMFR0_BIGENDEL0_MASK	0xfUL

#define MMFR0_SNSMEM_SHIFT	12
#define	MMFR0_SNSMEM_MASK	0xfUL

#define MMFR0_BIGEND_SHIFT	8
#define	MMFR0_BIGEND_MASK	0xfUL

#define	MMFR0_ASIDBITS_SHIFT	4
#define MMFR0_ASIDBITS_MASK	0xfUL
#define	MMFR0_ASIDBITS_8	0x0UL
#define	MMFR0_ASIDBITS_16	0x2UL

#define	MMFR0_PARANGE_SHIFT	0
#define	MMFR0_PARANGE_MASK	0xfUL
#define	MMFR0_PARANGE_4G	0x0UL
#define	MMFR0_PARANGE_64G	0x1UL
#define	MMFR0_PARANGE_1T	0x2UL
#define	MMFR0_PARANGE_4T	0x3UL
#define	MMFR0_PARANGE_16T	0x4UL
#define	MMFR0_PARANGE_256T	0x5UL
#define	MMFR0_PARANGE_4P	0x6UL

#define	MMFR1_NTLBPA_SHIFT	48
#define	MMFR1_NTLBPA_MASK	0xfUL

#define	MMFR1_AFP_SHIFT		44
#define	MMFR1_AFP_MASK		0xfUL

#define	MMFR1_HCX_SHIFT		40
#define	MMFR1_HCX_MASK		0xfUL

#define	MMFR1_ETS_SHIFT		36
#define	MMFR1_ETS_MASK		0xfUL

#define	MMFR1_TWED_SHIFT	32
#define	MMFR1_TWED_MASK		0xfUL

#define	MMFR1_XNX_SHIFT		28
#define	MMFR1_XNX_MASK		0xfUL

#define	MMFR1_SPECSEI_SHIFT	24
#define	MMFR1_SPECSEI_MASK	0xfUL

#define	MMFR1_PAN_SHIFT		20
#define	MMFR1_PAN_MASK		0xfUL

#define	MMFR1_LO_SHIFT		16
#define	MMFR1_LO_MASK		0xfUL

#define	MMFR1_HPDS_SHIFT	12
#define	MMFR1_HPDS_MASK		0xfUL

#define	MMFR1_VH_SHIFT		8
#define	MMFR1_VH_MASK		0xfUL

#define	MMFR1_VMIDBITS_SHIFT	4
#define	MMFR1_VMIDBITS_MASK	0xfUL

#define	MMFR1_HAFDBS_SHIFT	0
#define	MMFR1_HAFDBS_MASK	0xfUL
#define	MMFR1_HAFDBS_NOTSUPP	0x0UL
#define	MMFR1_HAFDBS_AF_ONLY	0x1UL
#define	MMFR1_HAFDBS_BOTH	0x2UL

#define	TCR_IPS_SHIFT		32
#define	TCR_IPS_MASK		0x7UL
#define	TCR_IPS_WIDTH		3

#define	TCR_ASID_SHIFT		36
#define	TCR_ASID_MASK		0x1UL
#define	TCR_ASID_WIDTH		1
#define	TCR_ASID_8BIT		0x0UL
#define	TCR_ASID_16BIT		0x1UL

#define	TCR_HD_SHIFT		40
#define	TCR_HD_MASK		0x1UL
#define	TCR_HD			(1UL << TCR_HD_SHIFT)
#define	TCR_HA_SHIFT		39
#define	TCR_HA_MASK		0x1UL
#define	TCR_HA			(1UL << TCR_HA_SHIFT)

#define	TCR_T0SZ_SHIFT		0
#define	TCR_T1SZ_SHIFT		16

#define	TCR_T0SZ(x)		((x) << TCR_T0SZ_SHIFT)
#define	TCR_T1SZ(x)		((x) << TCR_T1SZ_SHIFT)
#define	TCR_TxSZ(x)		(TCR_T1SZ(x) | TCR_T0SZ(x))

#define	TCR_TG1_SHIFT		30
#define	TCR_TG1_4K		(2UL << TCR_TG1_SHIFT)

#define	TCR_TG0_SHIFT		14
#define	TCR_TG0_4K		(0 << TCR_TG0_SHIFT)

#define	TCR_SH1_SHIFT		28
#define	TCR_SH1_NS		(0UL << TCR_SH1_SHIFT)
#define	TCR_SH1_OS		(2UL << TCR_SH1_SHIFT)
#define	TCR_SH1_IS		(3UL << TCR_SH1_SHIFT)

#define	TCR_ORGN1_SHIFT		26
#define	TCR_ORGN1_WBWA		(1UL << TCR_ORGN1_SHIFT)

#define	TCR_IRGN1_SHIFT		24
#define	TCR_IRGN1_WBWA		(1UL << TCR_IRGN1_SHIFT)

#define	TCR_SH0_SHIFT		12
#define	TCR_SH0_NS		(0UL << TCR_SH0_SHIFT)
#define	TCR_SH0_OS		(2UL << TCR_SH0_SHIFT)
#define	TCR_SH0_IS		(3UL << TCR_SH0_SHIFT)

#define	TCR_ORGN0_SHIFT		10
#define	TCR_ORGN0_WBWA		(1UL << TCR_ORGN0_SHIFT)

#define	TCR_IRGN0_SHIFT		8
#define	TCR_IRGN0_WBWA		(1UL << TCR_IRGN0_SHIFT)

#define	TCR_CACHE_ATTRS		((TCR_IRGN0_WBWA | TCR_IRGN1_WBWA) | (TCR_ORGN0_WBWA | TCR_ORGN1_WBWA))

#define	TCR_SMP_ATTRS		(TCR_SH0_IS | TCR_SH1_IS)

#define SCTLR_LSMAOE                    (0x1UL << 29)
#define SCTLR_nTLSMD                    (0x1UL << 28)
#define SCTLR_UCI                       (0x1UL << 26)
#define SCTLR_EE                        (0x1UL << 25)
#define SCTLR_E0E                       (0x1UL << 24)
#define SCTLR_SPAN                      (0x1UL << 23)
#define SCTLR_IESB                      (0x1UL << 21)
#define SCTLR_WXN                       (0x1UL << 19)
#define SCTLR_nTWE                      (0x1UL << 18)
#define SCTLR_nTWI                      (0x1UL << 16)
#define SCTLR_UCT                       (0x1UL << 15)
#define SCTLR_DZE                       (0x1UL << 14)
#define SCTLR_I                         (0x1UL << 12)
#define SCTLR_UMA                       (0x1UL << 9)
#define SCTLR_SED                       (0x1UL << 8)
#define SCTLR_ITD                       (0x1UL << 7)
#define SCTLR_CP15BEN                   (0x1UL << 5)
#define SCTLR_SA0                       (0x1UL << 4)
#define SCTLR_SA                        (0x1UL << 3)
#define SCTLR_C                         (0x1UL << 2)
#define SCTLR_A                         (0x1UL << 1)
#define SCTLR_M                         (0x1UL << 0)

#define SCTLR_SET                       (SCTLR_LSMAOE | SCTLR_nTLSMD | \
        SCTLR_UCI | SCTLR_SPAN | SCTLR_nTWE | SCTLR_nTWI | SCTLR_UCT | \
        SCTLR_DZE | SCTLR_I | SCTLR_SED | SCTLR_SA0 | SCTLR_SA | SCTLR_C | \
        SCTLR_M | SCTLR_CP15BEN)

#define SCTLR_CLEAR                     (SCTLR_EE | SCTLR_E0E | SCTLR_IESB | \
        SCTLR_WXN | SCTLR_UMA | SCTLR_ITD | SCTLR_A)




static void
eboot_mmu_setup(void)
{
	uint64_t mmfr0;
	uint64_t mmfr1;

	bi->bi_mair = MAIR_EL1_CONTENTS;

	/*
	 * XXXAARCH64: we should be a lot more dynamic about these things,
	 * especially when we support more than a 48 bit VA.
	 */
	bi->bi_tcr = TCR_TxSZ(64 - VIRT_BITS)
	    | TCR_TG0_4K
	    | TCR_TG1_4K
	    | TCR_CACHE_ATTRS
	    | TCR_SMP_ATTRS;

	mmfr0 = read_id_aa64mmfr0_el1();
	mmfr1 = read_id_aa64mmfr1_el1();

	/*
	 * Intermediate physical address size.
	 *
	 * This is the supported size of addresses output by stage one address
	 * translation (i.e. what we do, which gets fed to the hypervisor if
	 * present).
	 *
	 * If 52 bit IPS is supported we log a note to debug output and
	 * configure for 48 bit physical addresses.
	 */
	/* XXXAARCH64: constants for TCR.IPS would be nice */
	switch ((mmfr0 >> MMFR0_PARANGE_SHIFT) & MMFR0_PARANGE_MASK) {
	case MMFR0_PARANGE_4G:
		DBG_P(("NOTE: Supported PA range is 4GiB\n"));
		bi->bi_tcr |=
		    ((((mmfr0 >> MMFR0_PARANGE_SHIFT) & MMFR0_PARANGE_MASK)
		    & TCR_IPS_MASK) << TCR_IPS_SHIFT);
		break;
	case MMFR0_PARANGE_64G:
		DBG_P(("NOTE: Supported PA range is 64GiB\n"));
		bi->bi_tcr |=
		    ((((mmfr0 >> MMFR0_PARANGE_SHIFT) & MMFR0_PARANGE_MASK)
		    & TCR_IPS_MASK) << TCR_IPS_SHIFT);
		break;
	case MMFR0_PARANGE_1T:
		DBG_P(("NOTE: Supported PA range is 1TiB\n"));
		bi->bi_tcr |=
		    ((((mmfr0 >> MMFR0_PARANGE_SHIFT) & MMFR0_PARANGE_MASK)
		    & TCR_IPS_MASK) << TCR_IPS_SHIFT);
		break;
	case MMFR0_PARANGE_4T:
		DBG_P(("NOTE: Supported PA range is 4TiB\n"));
		bi->bi_tcr |=
		    ((((mmfr0 >> MMFR0_PARANGE_SHIFT) & MMFR0_PARANGE_MASK)
		    & TCR_IPS_MASK) << TCR_IPS_SHIFT);
		break;
	case MMFR0_PARANGE_16T:
		DBG_P(("NOTE: Supported PA range is 16TiB\n"));
		bi->bi_tcr |=
		    ((((mmfr0 >> MMFR0_PARANGE_SHIFT) & MMFR0_PARANGE_MASK)
		    & TCR_IPS_MASK) << TCR_IPS_SHIFT);
		break;
	case MMFR0_PARANGE_256T:
		DBG_P(("NOTE: Supported PA range is 256TiB\n"));
		bi->bi_tcr |=
		    ((((mmfr0 >> MMFR0_PARANGE_SHIFT) & MMFR0_PARANGE_MASK)
		    & TCR_IPS_MASK) << TCR_IPS_SHIFT);
		break;
	case MMFR0_PARANGE_4P:
		DBG_P(("NOTE: 52 bit Physical Addresses are unimplemented, "
		    "using 48 bit addressing.\n"));
		bi->bi_tcr |= (0x5UL << TCR_IPS_SHIFT);
		break;
	default:
		eboot_printf("WARNING: Unrecognized physical address range "
		    "value 0x%lx.  Using 48 bit physical addressing.\n",
		    (mmfr0 >> MMFR0_PARANGE_SHIFT) & MMFR0_PARANGE_MASK);
		bi->bi_tcr |= (0x5UL << TCR_IPS_SHIFT);
		break;
	}

	/*
	 * Address-space identifier width (eight or sixteen bits).
	 */
	bi->bi_tcr &= ~(TCR_ASID_MASK << TCR_ASID_SHIFT);
	switch ((mmfr0 >> MMFR0_ASIDBITS_SHIFT) & MMFR0_ASIDBITS_MASK) {
	case MMFR0_ASIDBITS_8:
		DBG_P(("NOTE: This machine only supports 8 bit ASIDs.\n"));
		bi->bi_tcr |= (TCR_ASID_8BIT << TCR_ASID_SHIFT);
		break;
	case MMFR0_ASIDBITS_16:
		bi->bi_tcr |= (TCR_ASID_16BIT << TCR_ASID_SHIFT);
		break;
	default:
		DBG_P(("NOTE: Unrecognized MMFR0.ASIDBITS 0x%lx.  Assuming 16 "
		    "bit ASID support.\n",
		    (mmfr0 >> MMFR0_ASIDBITS_SHIFT) & MMFR0_ASIDBITS_MASK));
		bi->bi_tcr |= (TCR_ASID_16BIT << TCR_ASID_SHIFT);
		break;
	}

	/*
	 * Hardware managed access flag and dirty state
	 */
	/* mmfr1 */
	bi->bi_tcr &= ~(TCR_HD | TCR_HA);
	switch ((mmfr1 >> MMFR1_HAFDBS_SHIFT) & MMFR1_HAFDBS_MASK) {
	case MMFR1_HAFDBS_NOTSUPP:
		break;
	case MMFR1_HAFDBS_AF_ONLY:
		bi->bi_tcr |= TCR_HA;
		break;
	case MMFR1_HAFDBS_BOTH:
		bi->bi_tcr |= (TCR_HA | TCR_HD);
		break;
	default:
		DBG_P(("NOTE: Unrecognized MMFR1.HAFDBS 0x%lx.  Assuming no "
		    "support for hardware updates.\n",
		    (mmfr1 >> MMFR1_HAFDBS_SHIFT) & MMFR1_HAFDBS_MASK));
		break;
	}

	bi->bi_sctlr = read_sctlr_el1() & ~(SCTLR_CLEAR);
	bi->bi_sctlr |= SCTLR_SET;

	/*
	 * XXXAARCH64: This is hardcoded for now, but we definitely need to be
	 * more intelligent about things.  This is also replicated in unix, so
	 * a bit of sharing might be nice.
	 */
	shift_amt = shift_amt_pae;
	ptes_per_table = 512;
	pte_size = 8;
	lpagesize = TWO_MEG;
	top_level = 3;
}

/*
 * Routines to set up a DBG2 port.
 *
 * The only supported DBG2 port type is a UART, and specific support is needed
 * for different UART types (though SBSA mandates a PL011 compatible register
 * subset).
 *
 * The next two routines provide functionality to locate the XSDT via a walk
 * from the UEFI System Table, then use the XSDT to locate the DBG2 table.
 *
 * Once we have a DBG2 table we walk the Device Information structures within
 * that table and (attempt to) hook up the first compatible device that we see.
 * No fallback is attempted if hookup fails.
 *
 * This is all a bit of a manual effort as we want to get UART output in a
 * board-independent was really early on, allowing us to see further bootstrap
 * errors.
 *
 * To debug this code, define the following two values (up near the top of this
 * file) and set prom_debug.
 *
 * EARLY_DBG2_PA   : The DBG2 UART physical address
 * EARLY_DBG2_TYPE : The DBG2 UART subtype
 *
 * There's a comment block near the start of this file that describes what
 * values are legal.
 */

/*
 * Configures the debug UART from the chosen DBG2 Device Information structure.
 *
 * Only one structure is chosen.  This routine is responsible for mapping the
 * described UART into VA and saving information about the virtual mapping to
 * the boot information structure.
 */
static void
configure_dbg2_ddi(ACPI_DBG2_DEVICE *ddi)
{
	ACPI_GENERIC_ADDRESS *gas;
	uint64_t va_base;
	uint64_t base_prev;
	UINT32 *asz;
	uint32_t i;
	uint32_t j;
	uint32_t idx;
	uint32_t maxpg;
	uint32_t delta;

	/*
	 * This dance is theoretically unnecessary, the DBG2 specification is
	 * not abundantly clear on whether the namespace path is NUL terminated
	 * or not.
	 */
	DBG_P(("Processing device: "));
	for (i = 0; i < ddi->NamepathLength; ++i) {
		DBG_P(("%c", ((char *)ddi)[ddi->NamepathOffset + i]));
	}
	DBG_P(("\n"));

	gas = (ACPI_GENERIC_ADDRESS *)(((char *)ddi) + ddi->BaseAddressOffset);
	asz = (UINT32 *)(((char *)ddi) + ddi->AddressSizeOffset);
	maxpg = 0;

	for (i = 0; i < ddi->RegisterCount; ++i) {
		DBG_P(("Generic Address %u:\n", i));
		DBG_P(("  SpaceId: 0x%x\n", gas[i].SpaceId));
		DBG_P(("  BitWidth: %u\n", gas[i].BitWidth));
		DBG_P(("  BitOffset: %u\n", gas[i].BitOffset));
		DBG_P(("  AccessWidth: %u\n", gas[i].AccessWidth));
		DBG_P(("  Address: 0x%lx\n", gas[i].Address));
		DBG_P(("AddressSize[%u] == 0x%x\n", i, asz[i]));

		if (gas[i].SpaceId != 0 || gas[i].BitOffset != 0) {
			eboot_printf("Noncompliant Address Space ID (%u) or "
			    "Register Bit Offset (%u).\n",
			    gas[i].SpaceId, gas[i].BitOffset);
			return;
		}

		/*
		 * We could be more spec compliant here, but for now we just
		 * insist on Register Bit Width being 32 and Access Size being
		 * DWORD.
		 */
		if (gas[i].BitWidth != 32 || gas[i].AccessWidth != 3) {
			eboot_printf("Unsupported Register Bit Width (%u) or "
			    "Access Size (%u)\n",
			    gas[i].BitWidth,
			    gas[i].AccessWidth);
			return;
		}

		if (i != 0) {
			if (gas[i].Address <= base_prev) {
				eboot_printf("Non-ascending register layout\n");
				return;
			}

			maxpg += ((gas[i].Address - base_prev) >> 12);
		}

		if (asz[i] & 0xfff) {
			eboot_printf("Misaligned DBG2 address size\n");
			return;
		}

		if (i == ddi->RegisterCount - 1)
			maxpg += (asz[i] >> 12);

		base_prev = gas[i].Address;
	}

	/*
	 * It's not fatal if we can't map DBG2 for kernel use, but we should
	 * let people know anyway.  This isn't going to show up anywhere since
	 * DBG2 is how we'd tell people.
	 *
	 * XXXAARCH64: leave a marker so we can tell the user about the DBG2
	 * port once the console is up.
	 */
	if ((maxpg << 12) > DBG2_SIZE) {
		eboot_printf(
		    "ERROR: DBG2 is too big to fit into allocated KVA\n");
		return;
	}

	DBG_P(("DBG2 mapping will take %u page(s) of VA\n", maxpg));

	va_base = DBG2_BASE;
	gas = (ACPI_GENERIC_ADDRESS *)(((char *)ddi) + ddi->BaseAddressOffset);
	asz = (UINT32 *)(((char *)ddi) + ddi->AddressSizeOffset);

	for (i = 0; i < ddi->RegisterCount; ++i) {
		DBG_P(("Generic Address mapping %u\n", i));
		delta = ((gas[i].Address - gas[0].Address) >> 12);
		maxpg = asz[i] >> 12;
		DBG_P(("  Page delta for start is: %u\n", delta));
		DBG_P(("  Number of pages is: %u\n", maxpg));

		dbg2memlist[dbg2memlist_used].pa = (gas[i].Address >> 12) << 12;
		dbg2memlist[dbg2memlist_used].va =
		    ((va_base + (delta << 12)) >> 12) << 12;
		dbg2memlist[dbg2memlist_used].size = maxpg << 12;
		dbg2memlist_used++;

		DBG_P(("  0x%lx -> 0x%lx [%u pages]\n",
		    gas[i].Address,
		    va_base + (delta << 12),
		    maxpg));

		for (j = 0; j < maxpg; ++j) {
			DBG_P(("    [%lu] 0x%lx -> 0x%lx\n",
			    ((va_base + (delta << 12)) >> 12) & 0x1ff,
			    ((gas[i].Address + (0x1000 * j)) >> 12) << 12,
			    va_base + (delta << 12) + (0x1000 * j)));
		}
	}

	bi->bi_dbg2_pa = (gas[0].Address & ~0xfff);
	bi->bi_dbg2_va = DBG2_BASE + (gas[0].Address & 0xfff);
	bi->bi_dbg2_type = ddi->PortSubtype;

	sort_dbg2mem();

	DBG_P(("DBG2 device '"));
	for (i = 0; i < ddi->NamepathLength; ++i) {
		DBG_P(("%c", ((char *)ddi)[ddi->NamepathOffset + i]));
	}
	DBG_P(("' configured.\n"));
}

/*
 * https://docs.microsoft.com/en-us/windows-hardware/drivers/bringup/acpi-debug-port-table
 *
 * Walk the xsdt to the dbg2 table, then pick up the BAR and port type
 * from there.  This will have been initialised by the firmware, and
 * should have a type of Serial and a subtype of ARM SBSA Generic UART,
 * which is 0x000E (could add support for others in time).  There are
 * 1394 and USB options available, but those are not specified by the
 * BSA, so we'll ignore them (there's also Net, which we're not going
 * to be taking on).
 */
static void
configure_dbg2(void)
{
	ACPI_TABLE_DBG2 *dbg2;
	ACPI_DBG2_DEVICE *ddi;
	UINT32 i;

	dbg2 = (ACPI_TABLE_DBG2 *)find_acpi_table(ACPI_SIG_DBG2);
	if (dbg2 == NULL) {
		DBG_P(("No DBG2 ACPI table present.\n"));
		return;
	}

	DBG_P(("DBG2 table length: %u\n", dbg2->Header.Length));
	DBG_P(("DBG2 info offset: %u\n", dbg2->InfoOffset));
	DBG_P(("DBG2 info count: %u\n", dbg2->InfoCount));

	ddi = (ACPI_DBG2_DEVICE *)(((char *)dbg2) + dbg2->InfoOffset);

	for (i = 0; i < dbg2->InfoCount; ++i) {
		DBG_P(("Debug Device Information %u has length %u\n",
		    i, ddi->Length));
		DBG_P(("  Revision: %u\n", ddi->Revision));
		DBG_P(("  NumberofGenericAddressRegisters: %u\n",
		    ddi->RegisterCount));
		DBG_P(("  NameSpaceStringLength: %u\n", ddi->NamepathLength));
		DBG_P(("  NameSpaceStringOffset: %u\n", ddi->NamepathOffset));
		DBG_P(("  OemDataLength: %u\n", ddi->OemDataLength));
		DBG_P(("  OemDataOffset: %u\n", ddi->OemDataOffset));
		DBG_P(("  PortType: %u\n", ddi->PortType));
		DBG_P(("  PortSubtype: %u\n", ddi->PortSubtype));
		DBG_P(("  BaseAddressRegisterOffset: %u\n",
		    ddi->BaseAddressOffset));
		DBG_P(("  AddressSizeOffset: %u\n", ddi->AddressSizeOffset));

		if (ddi->PortType == ACPI_DBG2_SERIAL_PORT &&
		    (ddi->PortSubtype == ACPI_DBG2_ARM_PL011 ||
		    ddi->PortSubtype == ACPI_DBG2_ARM_SBSA_GENERIC)) {
			configure_dbg2_ddi(ddi);
			return;
		}

		ddi = (ACPI_DBG2_DEVICE *)(((char *)ddi) + ddi->Length);
	}
}

/*
 * Use the UEFI system table and provided environment to locate the RSDP, XSDT
 * and SMBIOS3 tables.
 */
static void
ingest_uefi_systab(void)
{
	efi_guid_t vguid;
	EFI_CONFIGURATION_TABLE64 *cf;
	smbios_entry_t *smbios_entry;
	UINT32 i;

	efi = (EFI_SYSTEM_TABLE64 *)bi->bi_uefi_systab;
	if (efi == NULL)
		eboot_panic("No EFI system table set\n");

	if (efi->Hdr.Signature != EFI_SYSTEM_TABLE_SIGNATURE)
		eboot_panic("Invalid EFI_SYSTEM_TABLE signature 0x%lx "
		    "(expected 0x%lx)\n", efi->Hdr.Signature,
		    EFI_SYSTEM_TABLE_SIGNATURE);

	/*
	 * DEN0044B Server Base Boot Requirements, issue B (8 March 2016)
	 * SBBR version 1.0
	 * 3.1 UEFI Version
	 * "Boot and system firmware for 64-bit ARM servers is based on the
	 * UEFI specification[4], version 2.5 or later, incorporating the
	 * AArch64 bindings."
	 */
	if (efi->Hdr.Revision < EFI_REV(2, 5))
		eboot_panic("Unsupported UEFI version %u.%u.%u\n",
			EFI_REV_MAJOR(efi->Hdr.Revision),
			EFI_REV_MINOR(efi->Hdr.Revision) / 10,
			EFI_REV_MINOR(efi->Hdr.Revision) % 10);

	DBG_P(("UEFI version: %u.%u.%u\n",
		EFI_REV_MAJOR(efi->Hdr.Revision),
		EFI_REV_MINOR(efi->Hdr.Revision) / 10,
		EFI_REV_MINOR(efi->Hdr.Revision) % 10));

	/*
	 * TODO: check the EFI System Table CRC32
	 */

	/*
	 * DEN0044B Server Base Boot Requirements, issue B (8 March 2016)
	 * SBBR version 1.0
	 * 3.4.4 Configuration Tables
	 *
	 * A compliant implementation MUST provide the EFI_ACPI_20_TABLE_GUID
	 * and the SMBIOS3_TABLE_GUID configuration tables.
	 *
	 * The ACPI tables must be at version ACPI 6.0 or later with a
	 * HW-Reduced ACPI model.
	 *
	 * The SMBIOS v3.0 tables must conform to version 3.0.0 or later of the
	 * SMBIOS Specification
	 *
	 * An oddity here is that the ACPI 6.4 spec says:
	 * "The OS loader must retrieve the pointer to the RSDP structure from
	 * the EFI System Table before assuming platform control via the EFI
	 * ExitBootServices interface."
	 *
	 * The FreeBSD and illumos loaders pass this through to us via the
	 * hint.acpi.0.rsdp environment variable.  This helps to keep us
	 * compliant, but we'll dredge around in the UEFI system table if this
	 * is not passed to us.
	 */

	if (!eboot_getenv_uint64("hint.acpi.0.rsdp", &bi->bi_rsdp)) {
		eboot_printf("WARNING: No RSDP hint passed by the loader.\n");
		bi->bi_rsdp = 0;
	} else {
		DBG_P(("RSDP from the environment: 0x%lx\n", bi->bi_rsdp));
	}

	cf = (EFI_CONFIGURATION_TABLE64 *)efi->ConfigurationTable;

	for (i = 0; i < efi->NumberOfTableEntries; ++i) {
		memcpy(&vguid, &cf[i].VendorGuid, sizeof(vguid));

		if (bi->bi_rsdp == 0 && eboot_same_guids(&vguid, &acpi2))
			bi->bi_rsdp = (uint64_t)cf[i].VendorTable;
		else if (bi->bi_smbios3 == 0 &&
		    eboot_same_guids(&vguid, &smbios3))
			bi->bi_smbios3 = (uint64_t)cf[i].VendorTable;

		if (bi->bi_rsdp != 0 && bi->bi_smbios3 != 0)
			break;
	}

	if (bi->bi_rsdp == 0)
		eboot_panic("Missing mandatory RSDP configuration table.\n");
	if (bi->bi_smbios3 == 0)
		eboot_panic("Missing mandatory SMBIOS3 configuration table.\n");

	rsdp = (ACPI_TABLE_RSDP *)bi->bi_rsdp;
	smbios_entry = (smbios_entry_t *)bi->bi_smbios3;

	if (strncmp(smbios_entry->ep30.smbe_eanchor, SMB3_ENTRY_EANCHOR,
	    SMB3_ENTRY_EANCHORLEN) != 0)
		eboot_panic("Invalid SMBIOS3 entry anchor signature\n");

	DBG_P(("SMBIOS version: %u.%u.%u\n",
		smbios_entry->ep30.smbe_major,
		smbios_entry->ep30.smbe_minor,
		smbios_entry->ep30.smbe_docrev));

	if (strncmp(rsdp->Signature, ACPI_SIG_RSDP,
	    strlen(ACPI_SIG_RSDP)) != 0)
		eboot_panic("Invalid RSDP signature\n");

	if (rsdp->Revision < 2)
		eboot_panic("Invalid RSDP revision.  Expected >= 2, got %u\n",
		    rsdp->Revision);

	/*
	 * TODO: Check the RSDP CRC32
	 */
	DBG_P(("RSDP Revision: %u\n", rsdp->Revision));
	DBG_P(("RSDP Length: %u\n", rsdp->Length));

	/*
	 * DEN0044B Server Base Boot Requirements, issue B (8 March 2016)
	 * SBBR version 1.0
	 * 4.2.1 Mandatory ACPI Tables
	 *
	 * The following tables are mandatory for all compliant systems:
	 * RSDP: RsdtAddress mus be NULL, XsdtAddresss must be valid.
	 * XSDT: The RSDP must contain a pointer to this table.
	 * FADT: Must have the HW_REDUCED_ACPI flag set.
	 *       It is recommended that a server profiles is selected.
	 *       The ARM_BOOT_ARCH flags describe the presence of PSCI.
	 * DSDT: Essential configuration information.
	 * SSDT: Seems optional.
	 * MADT: Describes the GIC interrupt controllers.
	 *       When no PSCI, describes the parked address for secondary CPUs.
	 * GTDT: Describes the generic timer and watchdog.
	 * DBG2: Provides a standard debug port.
	 *       Describes the ARM SBSA Generic UART.
	 * SPCR: Config needed for headless operation.
	 *       Serial port type, location, and interrupts.
	 *       Revision 2 of the SPCR table or higher is required.
	 *       Must contain correct interrupt routing information.
	 *       The SPCR console device must be included in the DSDT.
	 *
	 * Appendix E Recommended ACPI Tables
	 * MCFG: PCI memory-mapped configuration space base address description
	 *       table
	 * IORT: Support for SMMUv2, ITS, and system topology description
	 * BERT: Boot Error Record Table
	 * EINJ: Error Injection Table
	 * ERST: Error Record Serialization Table
	 * HEST: Hardware Error Source Table
	 * RASF: RAS Facilities
	 * SPMI: Server Platform Management Interface Table
	 * SLIT: System Locality Information Table
	 * SRAT: System Resource Affinity Table
	 * CSRT: Core System Resource Table
	 * ECDT: Embedded Controller Description Table
	 * MPST: Memory Power State Table
	 * PCCT: Platform Communications Channel Table
	 */

	/*
	 * Since we're here, pick up the XSDT from the RSDP.
	 *
	 * Since we're a mandatory 64 bit platform we expect to have an XSDT.
	 */
	bi->bi_acpi_xsdt = rsdp->XsdtPhysicalAddress;
	xsdt = (ACPI_TABLE_XSDT *)bi->bi_acpi_xsdt;

	if (xsdt == NULL)
		eboot_panic("No XSDT provided in RSDP\n");

	if (strncmp(xsdt->Header.Signature, ACPI_SIG_XSDT,
	    strlen(ACPI_SIG_XSDT)) != 0)
		eboot_panic("Invalid XSDT signature\n");

	DBG_P(("XSDT Revision: %u\n", xsdt->Header.Revision));
	DBG_P(("XSDT Length: %u\n", xsdt->Header.Length));

	/*
	 * TODO: Check the XSDT CRC32
	 */
}

/*
 * DEN0044B Server Base Boot Requirements, issue B (8 March 2016)
 * SBBR version 1.0
 * 4.2.1 Mandatory ACPI Tables
 *
 * The following tables are mandatory for all compliant systems:
 * RSDP: RsdtAddress mus be NULL, XsdtAddresss must be valid.
 * XSDT: The RSDP must contain a pointer to this table.
 * FADT: Must have the HW_REDUCED_ACPI flag set.
 *       It is recommended that a server profiles is selected.
 *       The ARM_BOOT_ARCH flags describe the presence of PSCI.
 * DSDT: Essential configuration information.
 * SSDT: Seems optional.
 * MADT: Describes the GIC interrupt controllers.
 *       When no PSCI, describes the parked address for secondary CPUs.
 * GTDT: Describes the generic timer and watchdog.
 * DBG2: Provides a standard debug port.
 *       Describes the ARM SBSA Generic UART.
 * SPCR: Config needed for headless operation.
 *       Serial port type, location, and interrupts.
 *       Revision 2 of the SPCR table or higher is required.
 *       Must contain correct interrupt routing information.
 *       The SPCR console device must be included in the DSDT.
 */
static void
find_mandatory_acpi_tables(void)
{
	ACPI_TABLE_FADT *fadt;
	ACPI_TABLE_HEADER *dsdt;
	ACPI_TABLE_HEADER *ssdt;
	ACPI_TABLE_MADT *madt;
	ACPI_TABLE_GTDT *gtdt;
	ACPI_TABLE_DBG2 *dbg2;
	ACPI_TABLE_SPCR *spcr;

	DBG_MSG("Scanning for FADT...\n");
	fadt = (ACPI_TABLE_FADT *)find_acpi_table(ACPI_SIG_FADT);
	if (fadt == NULL)
		eboot_panic("No FADT ACPI table presented\n");

	/*
	 * FADT hold the pointer to the DSDT, apparently
	 */

#if 0
	DBG_MSG("Scanning for DSDT...\n");
	dsdt = (ACPI_TABLE_HEADER *)find_acpi_table(ACPI_SIG_DSDT);
	if (dsdt == NULL)
		eboot_panic("No DSDT ACPI table presented\n");
#endif
	DBG_MSG("Scanning for SSDT...\n");
	ssdt = (ACPI_TABLE_HEADER *)find_acpi_table(ACPI_SIG_SSDT);
	if (ssdt == NULL)
		eboot_panic("No SSDT ACPI table presented\n");

	DBG_MSG("Scanning for MADT...\n");
	madt = (ACPI_TABLE_MADT *)find_acpi_table(ACPI_SIG_MADT);
	if (madt == NULL)
		eboot_panic("No MADT ACPI table presented\n");

	DBG_MSG("Scanning for GTDT...\n");
	gtdt = (ACPI_TABLE_GTDT *)find_acpi_table(ACPI_SIG_GTDT);
	if (gtdt == NULL)
		eboot_panic("No GTDT ACPI table presented\n");

	DBG_MSG("Scanning for DBG2...\n");
	dbg2 = (ACPI_TABLE_DBG2 *)find_acpi_table(ACPI_SIG_DBG2);
	if (dbg2 == NULL)
		eboot_panic("No DBG2 ACPI table presented\n");

	DBG_MSG("Scanning for SPCR...\n");
	spcr = (ACPI_TABLE_SPCR *)find_acpi_table(ACPI_SIG_SPCR);
	if (spcr == NULL)
		eboot_panic("No SPCR ACPI table presented\n");

	DBG_MSG("Scanning complete\n");
}

/*
 * Grab the passed environment pointer, get the xsdp value, map that over to a
 * temporary address, walk the table looking for DBG2, map the DBG2, scan that
 * for a supported debug port, map the debug port to a known address, profit.
 */

/*
 * UNNECESSARY: dboot_loader_name
 * HOW DOES THIS WORK: dboot_loader_cmdline
 * dboot_init_xboot_consinfo
 * bcons_init
 *   - sets boot_line (command-line), environment pointer, initial fb_info, etc.
 *   - there's quite a lot here
 * DONE prom_debug = (find_boot_prop("prom_debug") != NULL);
 * DONE map_debug = (find_boot_prop("map_debug") != NULL);
 * DONE dboot_multiboot_get_fwtables
 * DONE bi->bi_uefi_systab && prom_debug
 * DONE   print_efi64
 * CPU-specific setup (MMX etc.)
 * init_mem_alloc
 * MMU config (do we need this?)
 * ktext_phys = FOUR_MEG -- nah, any 2MiB boundary is OK
 * copy kernel and dboot_elfload64 it - do we need to do this?
 * build_page_tables
 * return to assembly code to switch to running kernel
 * bi_next_paddr and bi_next_vaddr
 * multiboot info pointer - why?
 * bi_mb_info
 * bi_top_page_table (phys or virt?)
 * bi_kseg_size - 4MiB
 * dump_tables (iff map_debug)
 * Update FB info (origin, position, cursor visible) 
 */

/*
 * We require a platform that complies to the following document:
 * Document Reference: DEN0044
 * Document Name     : Arm Base Boot Requirements
 * Document Version  : 1.0
 *
 * We support booting on systems that are compliant to the SBBR and ESBBR
 * recipes (mostly since there's no boot requirements difference between the
 * two).
 */

/*
 * FreeBSD modules are presented to us in virtual space, which is nice and all,
 * but doesn't properly align to where we need it.
 *
 * Strategy:
 * Transform FreeBSD-style modules into Illumos modules, pick up only the types
 * we are interested in (BMT_ROOTFS, BMT_FILE [not consumed], BMT_HASH [no],
 * BMT_ENV, BMT_FONT).  Relocate those into safe(r) physical and virtual
 * locations and update what we pass to the kernel.
 *
 * This leaves us with: BMT_ROOTFS, BMT_ENV and BMT_FONT, which seems
 * manageable.
 *
 * So, suck in what we need from the existing modules, migrate out what we want
 * from our reduced list, relocate those, then forget about the existing
 * modules.
 *
 * MODINFO_NAME: /platform/armsbsa/kernel/aarch64/unix
 * MODINFO_TYPE: elf kernel
 * MODINFO_ARGS: (this is our command-line - do we mash our name into it?)
 * MODINFO_ADDR: where we were loaded, a VA
 * MODINFO_SIZE: how much data was loaded
 *
 * Under the kernel we have:
 * MODINFOMD_EFI_MAP: the memory map, we need to ingest this, relocate runtime data
 * MODINFOMD_EFI_FB : Framebuffer configuration data - passed in via a pointer in boot info.
 * MODINFOMD_FW_HANDLE: The EFI System Table.  We need to grab and relocate the runtime services to VA, then pass _that_ in via the boot info
 * MODINFOMD_KERNEND: This is the size of the kernel area, after module data has been appended.  We can use addresses past this as free (of metadata).
 * MODINFOMD_ENVP: Our environment (we want this)
 * MODINFOMD_HOWTO: FreeBSD's boothowto
 * MODINFOMD_ELFHDR: The kernel's ELF header (the data).
 * MODINFOMD_DYNAMIC: A pointer to the ELF DYNAMIC data
 * MODINFOMD_ESYM: A pointer to the end of the symbol table.
 * MODINFOMD_SSYM: A pointer to the start of the symbol table (string table too)
 * MODINFOMD_SHDR: A pointer to the ELF section headers.
 * 
 * For the rootfs, we get the following:
 * MODINFO_NAME: </platform/armsbsa/aarch64/boot_archive> (39 bytes)
 * MODINFO_TYPE: <rootfs> (7 bytes)
 * MODINFO_ADDR: <0xfffffffffbc89c50> (8 bytes)
 * MODINFO_SIZE: <0x9e9400> (8 bytes)
 *
 * VA-wise, that's bringing us close to the edge of the space we have, so we really need to rethink things a bit. Time to shrink the VA we use by the top bit.
 *  
 */

static void
maybe_relocate(caddr_t modulep, struct xboot_info *xbi)
{
	uint64_t reloc_size;
	uint64_t start;
	uint64_t end;
	uint64_t offset;
	uint_t i;
	void (*relocated_start)(uint64_t) = NULL;

	if (md_end < xbi->bi_physload)
		return;	/* something strange in the neighborhood */

	reloc_size = RNDUP((md_end - xbi->bi_physload) + 4, MMU_PAGESIZE2M);
	offset = (MMU_PAGESIZE2M * 4);	/* we want the kernel to be below us */

	DBG(xbi->bi_physload);
	DBG(xbi->bi_va_pa_delta);
	DBG(reloc_size);

	for (i = 0; i < ememlists_used; ++i) {
                start = RNDUP(ememlists[i].addr, MMU_PAGESIZE2M) + offset;
                end = RNDDN(ememlists[i].addr + ememlists[i].size,
		    MMU_PAGESIZE2M);
		DBG(start);
		DBG(end);
		DBG(start >= end);
		if (start >= end)
			continue;
		/*
		 * If we live below this entry already we're done (no reloc).
		 */
		DBG(xbi->bi_physload <= start);
		if (xbi->bi_physload <= start)
			return;
		DBG(end - start < reloc_size);
		if (end - start < reloc_size)
			continue;	/* we won't fit */
		DBG(xbi->bi_physload + reloc_size >= end);
		if (xbi->bi_physload + reloc_size >= end)
			continue;
		DBG(start + reloc_size < xbi->bi_physload);
		if (start + reloc_size < xbi->bi_physload)
			break;		/* we can fit here */
	}

	DBG(i >= ememlists_used);
	if (i >= ememlists_used)
		return;	/* nothing suitable */

	for (i = 0; i < ememlists_used; ++i) {
		ememlists[i].addr =
		    ememlists[i].size =
		    ememlists[i].next =
		    ememlists[i].prev = 0;
	}
	ememlists_used = 0;

	DBG_P(("Will relocate 0x%lx bytes at 0x%lx to 0x%lx\n",
	    reloc_size, xbi->bi_physload, start));
	memcpy((void *)start, (const void *)xbi->bi_physload, reloc_size);
	relocated_start = (void *)start;
	DBG_P(("Jumping to 0x%lx with arg 0x%lx here\n",
	    start, ((uint64_t)modulep) + xbi->bi_va_pa_delta));
	(relocated_start)(((uint64_t)modulep) + xbi->bi_va_pa_delta);
	eboot_panic("Relocated execution returned!\n");
}

/*
 * For when we bring in the boot stuff properly
 */
extern void dbg2_preinit(uint64_t pa, uint64_t type);

/*ARGSUSED*/
uint64_t
startup_kernel(caddr_t modulep, struct xboot_info *xbi)
{
	EFI_STATUS64 status;
	uint64_t va_offset;
	uint32_t i;

#if defined(EARLY_DBG2_PA)
#if EARLY_DBG2_PA
	dbg2_preinit(EARLY_DBG2_PA & ~0xfff, EARLY_DBG2_TYPE);
	xbi->bi_dbg2_pa = _sbsa_dbg2_addr;
	xbi->bi_dbg2_type = _sbsa_dbg2_type;
	eboot_debug = 1;
#else
	dbg2_preinit(0, 0);
#endif
#else
	dbg2_preinit(0, 0);
#endif
	if (eboot_debug) {
		eboot_printf("Early DBG2 usage configured\n");
		/* prom_debug = 1; */
		/* map_debug = 1; */
	}

	bi = xbi;

	fmodulep = modulep;
	fb = &framebuffer;
	bi->bi_kseg_size = M_2M + M_2M;
	bi->bi_modules = (uint64_t)&modules[0];

	/*
	 * Find the DBG2 port and set it up
	 * Set up the EFI framebuffer console as per dboot
	 *
	 * Relocate module data to make space for the nucleus
	 * Create page tables for the nucleus (higher half)
	 * Create page tables for all of physical memory
	 * We need to pass through the UEFI memory map bits for runtime
	 * services remapping.
	 *
	 * _everything_ is passed to the kernel in physical space.
	 *
	 * We should use the kernel page tables stuff like dboot does.
	 */

	DBG_P(("modulep is 0x%p\n", modulep));
	kmdp = prekern_get_kernel_module(modulep);
	if (kmdp == NULL)
		eboot_panic("No kernel module from boot loader.\n");
	envp = MD_FETCH(kmdp, MODINFOMD_ENVP, const char *);
	eboot_debug = prekern_has_env(envp, "eboot_debug");
	prom_debug = prekern_has_env(envp, "prom_debug");
	map_debug = prekern_has_env(envp, "map_debug");
	DBG(kmdp);
	DBG(envp);
	DBG(prom_debug);
	DBG(map_debug);

	fb->framebuffer = (uint64_t)preload_search_info(
	    kmdp, MODINFO_METADATA|MODINFOMD_EFI_FB);
	if (fb->framebuffer != 0)
		bi->bi_framebuffer = (uint64_t)fb;
	DBG(fb->framebuffer);
	DBG(bi->bi_framebuffer);
	if (prom_debug) {
		struct efi_fb *efifb;
		efifb = (struct efi_fb *)fb->framebuffer;
		if (efifb != NULL) {
			DBG_P(("UEFI Framebuffer Information: 0x%p\n", efifb));
			DBG_P(("       Address: 0x%lx\n", efifb->fb_addr));
			DBG_P(("          Size: 0x%lx\n", efifb->fb_size));
			DBG_P(("        Height: 0x%x\n", efifb->fb_height));
			DBG_P(("         Width: 0x%x\n", efifb->fb_width));
			DBG_P(("        Stride: 0x%x\n", efifb->fb_stride));
			DBG_P(("      Red Mask: 0x%x\n", efifb->fb_mask_red));
			DBG_P(("    Green Mask: 0x%x\n", efifb->fb_mask_green));
			DBG_P(("     Blue Mask: 0x%x\n", efifb->fb_mask_blue));
			DBG_P((" Reserved Mask: 0x%x\n",
			    efifb->fb_mask_reserved));
		}
	}

	DBG(hole_start);
	DBG(hole_end);
	bi->bi_uefi_systab = MD_FETCH_RAW(kmdp, MODINFOMD_FW_HANDLE, uint64_t);
	if (bi->bi_uefi_systab == 0)
		eboot_panic("No UEFI System Table\n");
	DBG(bi->bi_uefi_systab);

	ingest_uefi_systab();
	DBG(bi->bi_rsdp);
	DBG(bi->bi_smbios3);
	DBG(bi->bi_acpi_xsdt);

	configure_dbg2();
	DBG(bi->bi_dbg2_pa);
	DBG(bi->bi_dbg2_va);
	DBG(bi->bi_dbg2_type);
	bcons_init(bi);
	/* framebuffer console should be up now, having fonts would be nice */

	/*
	 * We want to move ourselves down into the lowest reasonable memory
	 * address that's not reserved.  To do so, we need to ensure that
	 * there's sufficient non-overlapping space below where we are right
	 * now and, if there is, copy ourselves down there before jumping to
	 * our entry point again.
	 *
	 * We do this little dance to give the kernel the best chance at finding
	 * large contiguous memory chunks above our load area, which it seems
	 * to like (a lot!).
	 */
	if (!eboot_process_efi_map_for_eboot(
	    (struct efi_map_header *)preload_search_info(
	    kmdp, MODINFO_METADATA|MODINFOMD_EFI_MAP))) {
		eboot_panic("Could not create a memory map for eboot\n");
	}

	md_end = (uint64_t)preload_find_end(modulep);
	DBG(md_end);
	if (md_end == 0)
		eboot_panic("No 'end of metadata' module found\n");

	/*
	 * Figure out if we can relocate and do so if appropriate
	 */
	if (relocated < 2) {
		relocated = 2;
		maybe_relocate(modulep, xbi);
	} else {
		DBG_MSG("Already relocated\n");
	}


	/*
	 * Now that we (probably) have a console up we can do checks for
	 * mandatory and optional things.
	 */
	DBG_MSG("About to find ACPI tables...\n");
	find_mandatory_acpi_tables();
	DBG_MSG("Found mandatory ACPI tables\n");

	DBG_MSG("illumos/aarch64 SBBR/ESBBR bootstrap\n");
	DBG_P(("  VA/PA delta: 0x%lx\n", xbi->bi_va_pa_delta));
	DBG_P(("  PA load address: 0x%lx\n", xbi->bi_physload));
	DBG_P(("  Module pointer is %p\n", modulep));

	if (prom_debug) {
		if (bi->bi_uefi_systab)
			print_efi64((EFI_SYSTEM_TABLE64 *)bi->bi_uefi_systab);
		preload_dump(modulep);
	}

	eboot_process_modules();
	eboot_mmu_setup();
	eboot_build_page_table();

	/*
	 * Set these now for debugging purposes, but we'll set them again as
	 * the very last thing we do before returning to ASM.
	 */
	bi->bi_next_paddr = next_avail_addr;
	bi->bi_next_vaddr = next_avail_addr;

	/*
	 * Remap the UEFI runtime here (mappings must already be set up and the
	 * data structures must be set up.  Collect the relocated destination
	 * of the pointer to somewhere temporary, remap the structures, then
	 * switch the global data over and update the value we pass to unix.
	 *
	 * This dance is needed so that we can still panic and reboot if we hit
	 * an error.
	 */
	DBG_P(("Relocating UEFI Runtime Services (%u entries)...\n",
	    rtomemlist_used));
	status = efi->RuntimeServices->SetVirtualAddressMap(
	    rtomemlist_used * uefi_map_hdr->descriptor_size,
	    uefi_map_hdr->descriptor_size,
	    uefi_map_hdr->descriptor_version,
	    eboot_find_efi_memory_descriptor(0));
	if (status != EFI_SUCCESS)
		eboot_panic("Failed to relocate UEFI Runtime Services, error "
		    "0x%lx\n", status);
	DBG_P(("UEFI Runtime Services relocated\n"));
	bi->bi_uefi_systab = relocated_uefi_systab;
	/* XXXAARCH64: clear our local config */

	bi->bi_pcimem = (uint64_t)pcimemlists;

	/*
	 * One of the last things we need to do is adjust the pointers we're
	 * going to pass to the kernel to point to into TTBR1 space.
	 */
	va_offset = BOOTLOADER_DATA_BASE - bi->bi_physload;
	bi->bi_physload += (2 * 1024 * 1024);
	bi->bi_cmdline += va_offset;
	bi->bi_phys_install += va_offset;
	bi->bi_rsvdmem += va_offset;
	bi->bi_pcimem += va_offset;
	bi->bi_framebuffer += va_offset;
	fb->framebuffer += va_offset;
	bi->bi_modules += va_offset;

	/*
	 * Now relocate our modules
	 */
	for (i = 0; i < modules_used; ++i) {
		modules[i].bm_addr += va_offset;
		if (modules[i].bm_name && modules[i].bm_type != BMT_ENV)
			modules[i].bm_name += va_offset;
	}

	/*
	 * No more memory allocation past this point
	 */
	bi->bi_next_paddr = RNDUP((next_avail_addr) + 1, MMU_PAGESIZE2M);
	bi->bi_next_vaddr = bi->bi_next_paddr + va_offset;

	if (prom_debug) {
		eboot_printf("Boot Information Structure:\n");
		eboot_printf(" bi_physload: 0x%lx\n", bi->bi_physload);
		eboot_printf(" bi_physmin: 0x%lx\n", bi->bi_physmin);
		eboot_printf(" bi_physmax: 0x%lx\n", bi->bi_physmax);
		eboot_printf(" bi_dbg2_pa: 0x%lx\n", bi->bi_dbg2_pa);
		eboot_printf(" bi_dbg2_va: 0x%lx\n", bi->bi_dbg2_va);
		eboot_printf(" bi_dbg2_type: 0x%lx\n", bi->bi_dbg2_type);
		eboot_printf(" bi_fdt: 0x%lx\n", bi->bi_fdt);
		eboot_printf(" bi_next_paddr: 0x%lx\n", bi->bi_next_paddr);
		eboot_printf(" bi_next_vaddr: 0x%lx\n", bi->bi_next_vaddr);
		eboot_printf(" bi_cmdline: 0x%lx\n", bi->bi_cmdline);
		eboot_printf(" bi_phys_install: 0x%lx\n", bi->bi_phys_install);
		eboot_printf(" bi_rsvdmem: 0x%lx\n", bi->bi_rsvdmem);
		eboot_printf(" bi_pcimem: 0x%lx\n", bi->bi_pcimem);
		eboot_printf(" bi_pt_window: 0x%lx\n", bi->bi_pt_window);
		eboot_printf(" bi_pte_to_pt_window: 0x%lx\n", bi->bi_pte_to_pt_window);
		eboot_printf(" bi_kseg_size: 0x%lx\n", bi->bi_kseg_size);
		eboot_printf(" bi_top_ttbr0: 0x%lx\n", bi->bi_top_ttbr0);
		eboot_printf(" bi_top_ttbr1: 0x%lx\n", bi->bi_top_ttbr1);
		eboot_printf(" bi_uefi_systab: 0x%lx\n", bi->bi_uefi_systab);
		eboot_printf(" bi_rsdp: 0x%lx\n", bi->bi_rsdp);
		eboot_printf(" bi_smbios3: 0x%lx\n", bi->bi_smbios3);
		eboot_printf(" bi_acpi_xsdt: 0x%lx\n", bi->bi_acpi_xsdt);
		eboot_printf(" bi_framebuffer: 0x%lx\n", bi->bi_framebuffer);
		eboot_printf(" bi_mair: 0x%lx\n", bi->bi_mair);
		eboot_printf(" bi_tcr: 0x%lx\n", bi->bi_tcr);
		eboot_printf(" bi_sctlr: 0x%lx\n", bi->bi_sctlr);
		eboot_printf(" bi_modules: 0x%lx\n", bi->bi_modules);
		eboot_printf(" bi_module_cnt: %u\n", bi->bi_module_cnt);
	}

	if (map_debug) {
		dump_tables(bi->bi_top_ttbr0, "TTBR0", 0x0);
		dump_tables(bi->bi_top_ttbr1, "TTBR1", hole_end);
	}

	/*
	 * Once we've populated the bootinfo and setup up the page tables we
	 * return the unix entry point to the ASM code so that we can enable
	 * the MMU and execute unix.
	 *
	 * Immediately prior to returning, once no more console output is
	 * expected, we update the cursor location for the framebuffer so that
	 * the transition into the kernel is seamless.
	 */

	DBG_P(("\n\n*** EBOOT DONE -- back to asm to jump to unix at VA "
	    "0x%lx\n\n", kernel_start_addr));

	if (fb) {
		/* Update boot info with FB data */
		fb->cursor.origin.x = fb_info.cursor.origin.x;
		fb->cursor.origin.y = fb_info.cursor.origin.y;
		fb->cursor.pos.x = fb_info.cursor.pos.x;
		fb->cursor.pos.y = fb_info.cursor.pos.y;
		fb->cursor.visible = fb_info.cursor.visible;
	}

	return (kernel_start_addr);
}
