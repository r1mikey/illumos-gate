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
 * Copyright 2012 DEY Storage Systems, Inc.  All rights reserved.
 * Copyright (c) 2015 by Delphix. All rights reserved.
 * Copyright 2017 Nexenta Systems, Inc.
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2020 Joyent, Inc.
 * Copyright 2020 Oxide Computer Company
 * Copyright (c) 2020 Carlos Neira <cneirabustos@gmail.com>
 * Copyright 2022 Michael van der Westhuizen
 */
/*
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 */

/*
 * XXXAARCH64: a lot of these headers are unnecessary
 */
#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/signal.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/vm.h>
#include <sys/conf.h>
#include <sys/avintr.h>
#include <sys/autoconf.h>
#include <sys/disp.h>
#include <sys/class.h>
#include <sys/bitmap.h>

#include <sys/privregs.h>

#include <sys/proc.h>
#include <sys/buf.h>
#include <sys/kmem.h>
#include <sys/mem.h>
#include <sys/kstat.h>

#include <sys/reboot.h>

#include <sys/cred.h>
#include <sys/vnode.h>
#include <sys/file.h>

#include <sys/procfs.h>

#include <sys/vfs.h>
#include <sys/cmn_err.h>
#include <sys/utsname.h>
#include <sys/debug.h>
#include <sys/kdi.h>

#include <sys/dumphdr.h>
#include <sys/bootconf.h>
#include <sys/memlist_plat.h>
#include <sys/varargs.h>
#include <sys/promif.h>
#include <sys/prom_debug.h>
#include <sys/modctl.h>

#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ndi_impldefs.h>
#include <sys/ddidmareq.h>
#include <sys/psw.h>
#include <sys/regset.h>
#include <sys/clock.h>
#include <sys/pte.h>
/* #include <sys/tss.h> Intel task state segment */
#include <sys/stack.h>
#include <sys/trap.h>
#include <sys/fp.h>
#include <vm/kboot_mmu.h>
#include <vm/anon.h>
#include <vm/as.h>
#include <vm/page.h>
#include <vm/seg.h>
#include <vm/seg_dev.h>
#include <vm/seg_kmem.h>
#include <vm/seg_kpm.h>
#include <vm/seg_map.h>
#include <vm/seg_vn.h>
#include <vm/seg_kp.h>
#include <sys/memnode.h>
#include <vm/vm_dep.h>
#include <sys/thread.h>
#include <sys/sysconf.h>
#include <sys/vm_machparam.h>
#include <sys/archsystm.h>
#include <sys/machsystm.h>
#include <vm/hat.h>
#include <vm/hat_aarch64.h>
/*
 * XXXAARCH64: directly mapping physical pages to userland, useful
 * #include <sys/pmem.h>
 */
#include <sys/smp_impldefs.h>
#include <sys/aarch64_archext.h>
#include <sys/cpuvar.h>
/* #include <sys/segments.h> - x86 segmentation stuff */
#include <sys/clconf.h>
#include <sys/kobj.h>
#include <sys/kobj_lex.h>
#include <sys/cpc_impl.h>
/*
 * XXXAARCH64: CPU module interface, useful
 * Exists in sun4* systems and Intel, no reason not to have this
 * in the future, but not needed right now
 *
 * #include <sys/cpu_module.h>
 */
#include <sys/smbios.h>
/*
 * XXXAARCH64: x86 specific? Well know location for external debuggers
 * Used with kvm etc. Might be useful.
 * 
 * #include <sys/debug_info.h>
 */
#include <sys/bootinfo.h>
#include <sys/ddi_periodic.h>
#include <sys/systeminfo.h>
/* #include <sys/multiboot.h> */
#include <sys/ramdisk.h>
/* #include <sys/tsc.h> */
#include <sys/clock.h>	/* again, for luck */

/*
 * From the original port, and needed
 */
#include <sys/memlist_impl.h>
#include <sys/gic.h>

#if 0
/*
 * XXXAARCH6: in the original port
 */
#include <sys/cpu.h>
#include <sys/note.h>
#include <sys/asm_linkage.h>
#include <sys/x_call.h>
#include <sys/var.h>
#include <sys/vtrace.h>
#include <sys/pg.h>
#include <sys/cmt.h>
#include <sys/dtrace.h>
#include <sys/kdi_machimpl.h>
#include <sys/ontrap.h>
#include <sys/rtc.h>
#endif

extern void mem_config_init(void);
extern void brand_init(void);
extern void pcf_init(void);
extern void pg_init(void);
extern void ssp_init(void);
extern void mach_init(void);
extern void set_platform_defaults(void);
extern time_t process_rtc_config_file(void);

static int32_t set_soft_hostid(void);
static char hostid_file[] = "/etc/hostid";

/*
 * For now we can handle memory with physical addresses up to about
 * 32 Terabytes.  This allows for vmm in the KVA, which might not end up being
 * necessary.
 */
#define	TERABYTE		(1ul << 40)
#define	PHYSMEM_MAX64		mmu_btop(32 * TERABYTE)
#define	PHYSMEM			PHYSMEM_MAX64
#define	AARCH64_VA_HOLE_END	0xffff000000000000ul	/* HOLE_END */

extern int segkp_fromheap;

caddr_t econtig;		/* end of first block of contiguous kernel */

struct bootops		*bootops = 0;	/* passed in from boot */
struct bootops		**bootopsp;
struct boot_syscalls	*sysp;		/* passed in from boot */

pgcnt_t physmem = PHYSMEM;
pgcnt_t obp_pages;	/* Memory used by PROM for its text and data */
char bootblock_fstype[16];
int segzio_fromheap = 0;

char kern_bootargs[OBP_MAXPATHLEN];
char kern_bootfile[OBP_MAXPATHLEN];

/*
 * Enable some debugging messages concerning memory usage...
 */
static void
print_memlist(char *title, struct memlist *mp)
{
	prom_printf("memlist for '%s' has pointer 0x%p\n", title, mp);
	prom_printf("MEMLIST: %s:\n", title);
	while (mp != NULL) {
		prom_printf("\tAddress 0x%" PRIx64 ", size 0x%" PRIx64 "\n",
		    mp->ml_address, mp->ml_size);
		mp = mp->ml_next;
	}
}

int	l2cache_sz = 0x80000;
int	l2cache_linesz = 0x40;
int	l2cache_assoc = 1;
static size_t	textrepl_min_gb = 10;

vmem_t		*device_arena;
uintptr_t	toxic_addr = (uintptr_t)NULL;
size_t		toxic_size = 1024 * 1024 * 1024; /* Sparc uses 1 gig too */

uintptr_t	hole_start = HOLE_START;
uintptr_t	hole_end = HOLE_END;
caddr_t kpm_vbase;
size_t  kpm_size;
static int kpm_desired;
static uintptr_t segkpm_base = (uintptr_t)SEGKPM_BASE;
static page_t *rd_pages;

struct system_hardware system_hardware;

uintptr_t	kernelbase;
size_t		segmapsize;
uintptr_t	segmap_start;
int		segmapfreelists;
pgcnt_t		npages;
size_t		core_size;		/* size of "core" heap */
uintptr_t	core_base;		/* base address of "core" heap */

/*
 * new memory fragmentations are possible in startup() due to BOP_ALLOCs. this
 * depends on number of BOP_ALLOC calls made and requested size, memory size
 * combination and whether boot.bin memory needs to be freed.
 */
#define	POSS_NEW_FRAGMENTS	12

long page_hashsz;		/* Size of page hash table (power of two) */
unsigned int page_hashsz_shift;	/* log2(page_hashsz) */
struct page *pp_base;		/* Base of initial system page struct array */
struct page **page_hash;	/* Page hash table */
pad_mutex_t *pse_mutex;		/* Locks protecting pp->p_selock */
size_t pse_table_size;		/* Number of mutexes in pse_mutex[] */
int pse_shift;			/* log2(pse_table_size) */

struct seg ktextseg;		/* Segment used for kernel executable image */
struct seg kvalloc;		/* Segment used for "valloc" mapping */
struct seg kpseg;		/* Segment used for pageable kernel virt mem */
struct seg kmapseg;		/* Segment used for generic kernel mappings */
struct seg kdebugseg;		/* Segment used for the kernel debugger */

struct seg *segkmap = &kmapseg;	/* Kernel generic mapping segment */
static struct seg *segmap = &kmapseg;	/* easier to use name for in here */
struct seg *segkp = &kpseg;	/* Pageable kernel virtual memory segment */

struct seg kpmseg;		/* Segment used for physical mapping */
struct seg *segkpm = &kpmseg;	/* 64bit kernel physical mapping segment */

caddr_t segkp_base;		/* Base address of segkp */
caddr_t segzio_base;		/* Base address of segzio */
pgcnt_t segkpsize;		/* size of segkp segment in pages */
caddr_t segkvmm_base;
pgcnt_t segkvmmsize;
pgcnt_t segziosize = 0;		/* size of zio segment in pages */

/*
 * A static DR page_t VA map is reserved that can map the page structures
 * for a domain's entire RA space. The pages that back this space are
 * dynamically allocated and need not be physically contiguous.  The DR
 * map size is derived from KPM size.
 * This mechanism isn't used by aarch64 yet, so just stubs here.
 */
int ppvm_enable = 0;		/* Static virtual map for page structs */
page_t *ppvm_base = NULL;	/* Base of page struct map */
pgcnt_t ppvm_size = 0;		/* Size of page struct map */

/*
 * VA range available to the debugger
 */
const caddr_t kdi_segdebugbase = (const caddr_t)SEGDEBUGBASE;
const size_t kdi_segdebugsize = SEGDEBUGSIZE;

struct memseg *memseg_base;

static page_t *bootpages;

struct memlist *memlist;

caddr_t s_text;		/* start of kernel text segment */
caddr_t e_text;		/* end of kernel text segment */
caddr_t s_data;		/* start of kernel data segment */
caddr_t e_data;		/* end of kernel data segment */
caddr_t modtext;	/* start of loadable module text reserved */
caddr_t e_modtext;	/* end of loadable module text reserved */
caddr_t moddata;	/* start of loadable module data reserved */
caddr_t e_moddata;	/* end of loadable module data reserved */

struct memlist *phys_install;	/* Total installed physical memory */
struct memlist *phys_avail;	/* Total available physical memory */
struct memlist *bios_rsvd;	/* Bios reserved memory */

int physMemInit = 0;
struct memlist *boot_scratch;

uintptr_t	postbootkernelbase;	/* not set till boot loader is gone */
uintptr_t	eprom_kernelbase;
pgcnt_t		orig_npages;

/*
 * Simple boot time debug facilities
 */
static char *prm_dbg_str[] = {
	"%s:%d: '%s' is 0x%x\n",
	"%s:%d: '%s' is 0x%llx\n"
};

int prom_debug;

#define	ROUND_UP_PAGE(x)	\
	((uintptr_t)P2ROUNDUP((uintptr_t)(x), (uintptr_t)MMU_PAGESIZE))
#define	ROUND_UP_2MEG(x)	\
	((uintptr_t)P2ROUNDUP((uintptr_t)(x), (uintptr_t)(1 << 21)))
#define	ROUND_UP_LPAGE(x)	ROUND_UP_2MEG(x)

extern int size_pse_array(pgcnt_t, int);

/*
 * This structure is used to keep track of the intial allocations
 * done in startup_memlist(). The value of NUM_ALLOCATIONS needs to
 * be >= the number of ADD_TO_ALLOCATIONS() executed in the code.
 */
#define	NUM_ALLOCATIONS 8
int num_allocations = 0;
struct {
	void **al_ptr;
	size_t al_size;
} allocations[NUM_ALLOCATIONS];
size_t valloc_sz = 0;
uintptr_t valloc_base;

#define	ADD_TO_ALLOCATIONS(ptr, size) {					\
		size = ROUND_UP_PAGE(size);		 		\
		if (num_allocations == NUM_ALLOCATIONS)			\
			panic("too many ADD_TO_ALLOCATIONS()");		\
		allocations[num_allocations].al_ptr = (void**)&ptr;	\
		allocations[num_allocations].al_size = size;		\
		valloc_sz += size;					\
		++num_allocations;				 	\
	}
/*
 * Allocate all the initial memory needed by the page allocator.
 */
static void
perform_allocations(void)
{
	caddr_t mem;
	int i;
	int valloc_align;

	PRM_DEBUG(valloc_base);
	PRM_DEBUG(valloc_sz);
	valloc_align = MMU_PAGESIZE;
	mem = BOP_ALLOC(bootops, (caddr_t)valloc_base, valloc_sz, valloc_align);
	if (mem != (caddr_t)valloc_base)
		panic("BOP_ALLOC() failed");
	bzero(mem, valloc_sz);
	for (i = 0; i < num_allocations; ++i) {
		*allocations[i].al_ptr = (void *)mem;
		mem += allocations[i].al_size;
	}
}
static void startup_init(void);
static void startup_memlist(void);
static void startup_kmem(void);
static void startup_modules(void);
static void startup_vm(void);
static void startup_end(void);
static void layout_kernel_va(void);

static void
getl2cacheinfo(struct cpu *cpu, int *csz, int *lsz, int *assoc)
{
	write_csselr_el1((1u << 1) | 0);
	uint64_t ccsidr = read_ccsidr_el1();

	size_t num_set = ((ccsidr >> 13) & ((1u << 15) - 1)) + 1;

	l2cache_linesz = (1u << (4 + (ccsidr & 0x7)));
	l2cache_assoc = ((ccsidr >> 3) & ((1u << 10) - 1)) + 1;
	l2cache_sz = l2cache_linesz * l2cache_assoc * num_set;
}

void
kobj_vmem_init(vmem_t **text_arena, vmem_t **data_arena)
{
	size_t tsize = e_modtext - modtext;
	size_t dsize = e_moddata - moddata;

	*text_arena = vmem_create("module_text", tsize ? modtext : NULL, tsize,
	    1, segkmem_alloc, segkmem_free, heaptext_arena, 0, VM_SLEEP);
	*data_arena = vmem_create("module_data", dsize ? moddata : NULL, dsize,
	    1, segkmem_alloc, segkmem_free, heap32_arena, 0, VM_SLEEP);
}

caddr_t
kobj_text_alloc(vmem_t *arena, size_t size)
{
	return (vmem_alloc(arena, size, VM_SLEEP | VM_BESTFIT));
}

/*ARGSUSED*/
caddr_t
kobj_texthole_alloc(caddr_t addr, size_t size)
{
	panic("unexpected call to kobj_texthole_alloc()");
	/*NOTREACHED*/
	return (0);
}

/*ARGSUSED*/
void
kobj_texthole_free(caddr_t addr, size_t size)
{
	panic("unexpected call to kobj_texthole_free()");
}

/*
 * claim a "setaside" boot page for use in the kernel
 */
page_t *
boot_claim_page(pfn_t pfn)
{
	page_t *pp;

	pp = page_numtopp_nolock(pfn);
	ASSERT(pp != NULL);

	if (PP_ISBOOTPAGES(pp)) {
		if (pp->p_next != NULL)
			pp->p_next->p_prev = pp->p_prev;
		if (pp->p_prev == NULL)
			bootpages = pp->p_next;
		else
			pp->p_prev->p_next = pp->p_next;
	} else {
		/*
		 * htable_attach() expects a base pagesize page
		 */
		if (pp->p_szc != 0)
			page_boot_demote(pp);
		pp = page_numtopp(pfn, SE_EXCL);
	}
	return (pp);
}

/*
 * Walk through the pagetables looking for pages mapped in by boot.  If the
 * setaside flag is set the pages are expected to be returned to the
 * kernel later in boot, so we add them to the bootpages list.
 */
static void
protect_boot_range(uintptr_t low, uintptr_t high, int setaside)
{
	uintptr_t va = low;
	size_t len;
	uint_t prot;
	pfn_t pfn;
	page_t *pp;
	pgcnt_t boot_protect_cnt = 0;

	while (kbm_probe(&va, &len, &pfn, &prot) != 0 && va < high) {
		if (va + len > high)
			panic("0x%lx byte mapping at 0x%p exceeds boot's "
			    "legal range of 0x%lx -> 0x%lx.", len, (void *)va,
			    low, high);

		while (len > 0) {
			pp = page_numtopp_alloc(pfn);
			if (pp != NULL) {
				if (setaside == 0)
					panic("Unexpected mapping by boot.  "
					    "addr=%p pfn=%lx\n",
					    (void *)va, pfn);

				pp->p_next = bootpages;
				pp->p_prev = NULL;
				PP_SETBOOTPAGES(pp);
				if (bootpages != NULL) {
					bootpages->p_prev = pp;
				}
				bootpages = pp;
				++boot_protect_cnt;
			}

			++pfn;
			len -= MMU_PAGESIZE;
			va += MMU_PAGESIZE;
		}
	}
	PRM_DEBUG(boot_protect_cnt);
}

void
startup(void)
{
	extern cpuset_t cpu_ready_set;

	/*
	 * Make sure that nobody tries to use sekpm until we have
	 * initialized it properly.
	 */
	kpm_desired = 1;
	kpm_enable = 0;
	CPUSET_ONLY(cpu_ready_set, 0);	/* cpu 0 is boot cpu */
	PRM_POINT("startup() starting...");

	ssp_init();
	/* XXXAARCH64: could be cool: progressbar_init(); */
	startup_init();
	startup_memlist();
	startup_kmem();
	startup_vm();
	/* startup_tsc(); */
	/* startup_pci_bios(); */
	/* startup_smap(); */
	startup_modules();
	panic("<<<you shall not pass>>>");
	/* XXXMICHAEL: audit continues here */
	panic("stop here for now");
	startup_end();
	PRM_POINT("startup() done");
}

void
get_system_configuration(void)
{
	char	prop[32];
	u_longlong_t nodes_ll, cpus_pernode_ll, lvalue;

#if 0
	if (BOP_GETPROPLEN(bootops, "nodes") > sizeof (prop) ||
	    BOP_GETPROP(bootops, "nodes", prop) < 0 ||
	    kobj_getvalue(prop, &nodes_ll) == -1 ||
	    nodes_ll > MAXNODES ||
	    BOP_GETPROPLEN(bootops, "cpus_pernode") > sizeof (prop) ||
	    BOP_GETPROP(bootops, "cpus_pernode", prop) < 0 ||
	    kobj_getvalue(prop, &cpus_pernode_ll) == -1) {
		system_hardware.hd_nodes = 1;
		system_hardware.hd_cpus_per_node = 0;
	} else {
		system_hardware.hd_nodes = (int)nodes_ll;
		system_hardware.hd_cpus_per_node = (int)cpus_pernode_ll;
	}
#endif

	if (BOP_GETPROPLEN(bootops, "kernelbase") > sizeof (prop) ||
	    BOP_GETPROP(bootops, "kernelbase", prop) < 0 ||
	    kobj_getvalue(prop, &lvalue) == -1)
		eprom_kernelbase = 0;
	else
		eprom_kernelbase = (uintptr_t)lvalue;

	if (BOP_GETPROPLEN(bootops, "segmapsize") > sizeof (prop) ||
	    BOP_GETPROP(bootops, "segmapsize", prop) < 0 ||
	    kobj_getvalue(prop, &lvalue) == -1)
		segmapsize = SEGMAPDEFAULT;
	else
		segmapsize = (uintptr_t)lvalue;

	if (BOP_GETPROPLEN(bootops, "segmapfreelists") > sizeof (prop) ||
	    BOP_GETPROP(bootops, "segmapfreelists", prop) < 0 ||
	    kobj_getvalue(prop, &lvalue) == -1)
		segmapfreelists = 0;	/* use segmap driver default */
	else
		segmapfreelists = (int)lvalue;

	if (BOP_GETPROPLEN(bootops, "segkpsize") > sizeof (prop) ||
	    BOP_GETPROP(bootops, "segkpsize", prop) < 0 ||
	    kobj_getvalue(prop, &lvalue) == -1)
		segkpsize = mmu_btop(SEGKPDEFSIZE);
	else
		segkpsize = mmu_btop((size_t)lvalue);

	/* physmem used to be here, but moved much earlier to fakebop.c */
}

static void
startup_init(void)
{
	PRM_POINT("startup_init() starting...");

	/*
	 * Complete the extraction of cpuid data
	 */
	/* cpuid_pass2(CPU); */

	(void) check_boot_version(BOP_GETVERSION(bootops));

	/*
	 * Check for prom_debug in boot environment
	 */
	if (BOP_GETPROPLEN(bootops, "prom_debug") >= 0) {
		++prom_debug;
		PRM_POINT("prom_debug found in boot enviroment");
	}

	/*
	 * Collect node, cpu and memory configuration information.
	 */
	get_system_configuration();

#if 0
	/*
	 * XXXAARCH64: This is where we could detect required processor
	 * features,if we end up needing to do so.
	 */
	/*
	 * Halt if this is an unsupported processor.
	 */
	if (x86_type == X86_TYPE_486 || x86_type == X86_TYPE_CYRIX_486) {
		printf("\n486 processor (\"%s\") detected.\n",
		    CPU->cpu_brandstr);
		halt("This processor is not supported by this release "
		    "of illumos.");
	}
#endif

	/*
	 * In the i86pc world, this (and more) are done via the
	 * picinitf funciton pointer, which is set by mach_init and
	 * called in startup_end().  It's pretty late in the show,
	 * just before soft interrupts are wired up.
	 *
	 * That code is hosted in mp_machdep.c, which seems weird, but
	 * is inconsequential.  The mp_machdep.c used in the original
	 * port needs to be slewed over to what i86pc does.
	 */
	/*
	 * GIC is needed by SPL/IPL, but I really don't have a clue
	 * what the right thing to do here is... we *should* have register
	 * access to the GIC, which is banked by CPU, so we could use that at
	 * this point.  We still need ACPI tables for the rest of the GIC -
	 * need to give this a lot of thought.
	 * XXXAARCH64: fix the GIC!
	 */
	/* gic_init(); */

	PRM_POINT("startup_init() done");
}

/*
 * Callback for copy_memlist_filter() to filter nucleus, kadb/kmdb, (ie.
 * everything mapped above KERNEL_TEXT) pages from phys_avail.
 * There is some reliance on the boot loader allocating only a few contiguous
 * physical memory chunks.
 */
static void
avail_filter(uint64_t *addr, uint64_t *size)
{
	uintptr_t va;
	uintptr_t next_va;
	pfn_t pfn;
	uint64_t pfn_addr;
	uint64_t pfn_eaddr;
	uint_t prot;
	size_t len;
	uint_t change;

	if (prom_debug)
		prom_printf("\tFilter: in: a=%" PRIx64 ", s=%" PRIx64 "\n",
		    *addr, *size);

	/*
	 * First we trim from the front of the range. Since kbm_probe()
	 * walks ranges in virtual order, but addr/size are physical, we need
	 * to the list until no changes are seen.  This deals with the case
	 * where page "p" is mapped at v, page "p + PAGESIZE" is mapped at w
	 * but w < v.
	 */
	do {
		change = 0;
		for (va = KERNEL_TEXT;
		    *size > 0 && kbm_probe(&va, &len, &pfn, &prot) != 0;
		    va = next_va) {

			next_va = va + len;
			pfn_addr = pfn_to_pa(pfn);
			pfn_eaddr = pfn_addr + len;

			if (pfn_addr <= *addr && pfn_eaddr > *addr) {
				change = 1;
				while (*size > 0 && len > 0) {
					*addr += MMU_PAGESIZE;
					*size -= MMU_PAGESIZE;
					len -= MMU_PAGESIZE;
				}
			}
		}
		if (change && prom_debug)
			prom_printf("\t\ttrim: a=%" PRIx64 ", s=%" PRIx64 "\n",
			    *addr, *size);
	} while (change);

	/*
	 * Trim pages from the end of the range.
	 */
	for (va = KERNEL_TEXT;
	    *size > 0 && kbm_probe(&va, &len, &pfn, &prot) != 0;
	    va = next_va) {

		next_va = va + len;
		pfn_addr = pfn_to_pa(pfn);

		if (pfn_addr >= *addr && pfn_addr < *addr + *size)
			*size = pfn_addr - *addr;
	}

	if (prom_debug)
		prom_printf("\tFilter out: a=%" PRIx64 ", s=%" PRIx64 "\n",
		    *addr, *size);
}

static void
kpm_init(void)
{
	struct segkpm_crargs b;

	/*
	 * These variables were all designed for sfmmu in which segkpm is
	 * mapped using a single pagesize - either 8KB or 4MB.  On aarch64,
	 * we might use 2+ page sizes on a single machine, so none of these
	 * variables have a single correct value.  They are set up as if we
	 * always use a 4KB pagesize, which should do no harm.  In the long
	 * run, we should get rid of KPM's assumption that only a single
	 * pagesize is used.
	 */
	kpm_pgshft = MMU_PAGESHIFT;
	kpm_pgsz =  MMU_PAGESIZE;
	kpm_pgoff = MMU_PAGEOFFSET;
	kpmp2pshft = 0;
	kpmpnpgs = 1;
	ASSERT(((uintptr_t)kpm_vbase & (kpm_pgsz - 1)) == 0);

	PRM_POINT("about to create segkpm");
	rw_enter(&kas.a_lock, RW_WRITER);

	if (seg_attach(&kas, kpm_vbase, kpm_size, segkpm) < 0)
		panic("cannot attach segkpm");

	b.prot = PROT_READ | PROT_WRITE;
	b.nvcolors = 1;

	if (segkpm_create(segkpm, (caddr_t)&b) != 0)
		panic("segkpm_create segkpm");

	rw_exit(&kas.a_lock);

	kpm_enable = 1;
#if 0
	/*
	 * As the KPM was disabled while setting up the system, go back and fix
	 * CPU zero's access to its user page table. This is a bit gross, but
	 * we have a chicken and egg problem otherwise.
	 */
	ASSERT(CPU->cpu_hat_info->hci_user_l3ptes == NULL);
	CPU->cpu_hat_info->hci_user_l3ptes =
	    (aarch64pte_t *)hat_kpm_mapin_pfn(CPU->cpu_hat_info->hci_user_l3pfn);
#endif
}

void
add_physmem_cb(page_t *pp, pfn_t pnum)
{
	pp->p_pagenum = pnum;
	pp->p_mapping = NULL;
	pp->p_embed = 0;
	pp->p_share = 0;
	pp->p_mlentry = 0;
}

static void
diff_memlists(struct memlist *proto, struct memlist *diff, void (*func)())
{
	uint64_t p_base, p_end, d_base, d_end;

	while (proto != NULL) {
		/*
		 * find diff item which may overlap with proto item
		 * if none, apply func to all of proto item
		 */
		while (diff != NULL &&
		    proto->ml_address >= diff->ml_address + diff->ml_size)
			diff = diff->ml_next;
		if (diff == NULL) {
			(*func)(proto->ml_address, proto->ml_size);
			proto = proto->ml_next;
			continue;
		}
		if (proto->ml_address == diff->ml_address &&
		    proto->ml_size == diff->ml_size) {
			proto = proto->ml_next;
			diff = diff->ml_next;
			continue;
		}

		p_base = proto->ml_address;
		p_end = p_base + proto->ml_size;
		d_base = diff->ml_address;
		d_end = d_base + diff->ml_size;
		/*
		 * here p_base < d_end
		 * there are 5 cases
		 */

		/*
		 *	d_end
		 *	d_base
		 *  p_end
		 *  p_base
		 *
		 * apply func to all of proto item
		 */
		if (p_end <= d_base) {
			(*func)(p_base, proto->ml_size);
			proto = proto->ml_next;
			continue;
		}

		/*
		 * ...
		 *	d_base
		 *  p_base
		 *
		 * normalize by applying func from p_base to d_base
		 */
		if (p_base < d_base)
			(*func)(p_base, d_base - p_base);

		if (p_end <= d_end) {
			/*
			 *	d_end
			 *  p_end
			 *	d_base
			 *  p_base
			 *
			 *	-or-
			 *
			 *	d_end
			 *  p_end
			 *  p_base
			 *	d_base
			 *
			 * any non-overlapping ranges applied above,
			 * so just continue
			 */
			proto = proto->ml_next;
			continue;
		}

		/*
		 *  p_end
		 *	d_end
		 *	d_base
		 *  p_base
		 *
		 *	-or-
		 *
		 *  p_end
		 *	d_end
		 *  p_base
		 *	d_base
		 *
		 * Find overlapping d_base..d_end ranges, and apply func
		 * where no overlap occurs.  Stop when d_base is above
		 * p_end
		 */
		for (p_base = d_end, diff = diff->ml_next; diff != NULL;
		    p_base = d_end, diff = diff->ml_next) {
			d_base = diff->ml_address;
			d_end = d_base + diff->ml_size;
			if (p_end <= d_base) {
				(*func)(p_base, p_end - p_base);
				break;
			} else
				(*func)(p_base, d_base - p_base);
		}
		if (diff == NULL)
			(*func)(p_base, p_end - p_base);
		proto = proto->ml_next;
	}
}

static struct memseg *
memseg_find(pfn_t base, pfn_t *next)
{
	struct memseg *seg;

	if (next != NULL)
		*next = LONG_MAX;
	for (seg = memsegs; seg != NULL; seg = seg->next) {
		if (base >= seg->pages_base && base < seg->pages_end)
			return (seg);
		if (next != NULL && seg->pages_base > base &&
		    seg->pages_base < *next)
			*next = seg->pages_base;
	}
	return (NULL);
}

static void
kphysm_erase(uint64_t addr, uint64_t len)
{
	pfn_t pfn = btop(addr);
	pgcnt_t num = btop(len);
	page_t *pp;
	while (num--) {
		int locked;

#ifdef DEBUG
		pp = page_numtopp_nolock(pfn);
		ASSERT(pp != NULL);
		ASSERT(PP_ISFREE(pp));
#endif
		pp = page_numtopp(pfn, SE_EXCL);
		ASSERT(pp != NULL);
		page_pp_lock(pp, 0, 1);
		ASSERT(pp != NULL);
		ASSERT(!PP_ISFREE(pp));
		ASSERT(pp->p_lckcnt == 1);
		ASSERT(PAGE_EXCL(pp));
		pfn++;
		availrmem_initial--;
		availrmem--;
	}
}

static void
kphysm_add(uint64_t addr, uint64_t len, int reclaim)
{
	struct page *pp;
	struct memseg *seg;
	pfn_t base = btop(addr);
	pgcnt_t num = btop(len);

	seg = memseg_find(base, NULL);
	ASSERT(seg != NULL);
	pp = seg->pages + (base - seg->pages_base);

	if (reclaim) {
		struct page *rpp = pp;
		struct page *lpp = pp + num;

		/*
		 * page should be locked on prom_ppages
		 * unhash and unlock it
		 */
		while (rpp < lpp) {
			ASSERT(PP_ISNORELOC(rpp));
			PP_CLRNORELOC(rpp);
			page_pp_unlock(rpp, 0, 1);
			page_hashout(rpp, NULL);
			page_unlock(rpp);
			rpp++;
		}
	}

	add_physmem(pp, num, base);
	availrmem_initial += num;
	availrmem += num;
}

/*
 * kphysm_init() initializes physical memory.
 */
static pgcnt_t
kphysm_init(page_t *pp, pgcnt_t npages)
{
	struct memlist	*pmem;
	struct memseg	*cur_memseg;
	pfn_t		base_pfn;
	pfn_t		end_pfn;
	pgcnt_t		num;
	pgcnt_t		pages_done = 0;
	uint64_t	addr;
	uint64_t	size;
	extern int	mnode_xwa;
	int		ms = 0, me = 0;

	ASSERT(page_hash != NULL && page_hashsz != 0);

	cur_memseg = memseg_base;
	for (pmem = phys_avail; pmem && npages; pmem = pmem->ml_next) {
		/*
		 * In a 32 bit kernel can't use higher memory if we're
		 * not booting in PAE mode. This check takes care of that.
		 */
		addr = pmem->ml_address;
		size = pmem->ml_size;
		if (btop(addr) > physmax)
			continue;

		/*
		 * align addr and size - they may not be at page boundaries
		 */
		if ((addr & MMU_PAGEOFFSET) != 0) {
			addr += MMU_PAGEOFFSET;
			addr &= ~(uint64_t)MMU_PAGEOFFSET;
			size -= addr - pmem->ml_address;
		}

		/* only process pages below or equal to physmax */
		if ((btop(addr + size) - 1) > physmax)
			size = ptob(physmax - btop(addr) + 1);

		num = btop(size);
		if (num == 0)
			continue;

		if (num > npages)
			num = npages;

		npages -= num;
		pages_done += num;
		base_pfn = btop(addr);

		if (prom_debug)
			prom_printf("MEMSEG addr=0x%" PRIx64
			    " pgs=0x%lx pfn 0x%lx-0x%lx\n",
			    addr, num, base_pfn, base_pfn + num);

		/*
		 * mnode_xwa is greater than 1 when large pages regions can
		 * cross memory node boundaries. To prevent the formation
		 * of these large pages, configure the memsegs based on the
		 * memory node ranges which had been made non-contiguous.
		 */
		end_pfn = base_pfn + num - 1;
		if (mnode_xwa > 1) {
			ms = PFN_2_MEM_NODE(base_pfn);
			me = PFN_2_MEM_NODE(end_pfn);

			if (ms != me) {
				/*
				 * current range spans more than 1 memory node.
				 * Set num to only the pfn range in the start
				 * memory node.
				 */
				num = mem_node_config[ms].physmax - base_pfn
				    + 1;
				ASSERT(end_pfn > mem_node_config[ms].physmax);
			}
		}

		for (;;) {
			/*
			 * Build the memsegs entry
			 */
			cur_memseg->pages = pp;
			cur_memseg->epages = pp + num;
			cur_memseg->pages_base = base_pfn;
			cur_memseg->pages_end = base_pfn + num;

			/*
			 * Insert into memseg list in decreasing pfn range
			 * order. Low memory is typically more fragmented such
			 * that this ordering keeps the larger ranges at the
			 * front of the list for code that searches memseg.
			 * This ASSERTS that the memsegs coming in from boot
			 * are in increasing physical address order and not
			 * contiguous.
			 */
			if (memsegs != NULL) {
				ASSERT(cur_memseg->pages_base >=
				    memsegs->pages_end);
				cur_memseg->next = memsegs;
			}
			memsegs = cur_memseg;

			/*
			 * add_physmem() initializes the PSM part of the page
			 * struct by calling the PSM back with add_physmem_cb().
			 * In addition it coalesces pages into larger pages as
			 * it initializes them.
			 */
			add_physmem(pp, num, base_pfn);
			cur_memseg++;
			availrmem_initial += num;
			availrmem += num;

			pp += num;
			if (ms >= me)
				break;

			/* process next memory node range */
			ms++;
			base_pfn = mem_node_config[ms].physbase;

			if (mnode_xwa > 1) {
				num = MIN(mem_node_config[ms].physmax,
				    end_pfn) - base_pfn + 1;
			} else {
				num = mem_node_config[ms].physmax -
				    base_pfn + 1;
			}
		}
	}

	PRM_DEBUG(availrmem_initial);
	PRM_DEBUG(availrmem);
	PRM_DEBUG(freemem);
	build_pfn_hash();
	PRM_DEBUG(pages_done);
	return (pages_done);
}

/*
 * The debug info page provides enough information to allow external
 * inspectors (e.g. when running under a hypervisor) to bootstrap
 * themselves into allowing full-blown kernel debugging.
 */
static void
init_debug_info(void)
{
	/*
	 * XXXAARCH64: hook up the debug info page
	 */
#if 0
	caddr_t mem;
	debug_info_t *di;

	ASSERT(sizeof (debug_info_t) < MMU_PAGESIZE);

	mem = BOP_ALLOC(bootops, (caddr_t)DEBUG_INFO_VA, MMU_PAGESIZE,
	    MMU_PAGESIZE);

	if (mem != (caddr_t)DEBUG_INFO_VA)
		panic("BOP_ALLOC() failed");	/* huh? */
	bzero(mem, MMU_PAGESIZE);

	di = (debug_info_t *)mem;

	di->di_magic = DEBUG_INFO_MAGIC;
	di->di_version = DEBUG_INFO_VERSION;
	di->di_modules = (uintptr_t)&modules;
	di->di_s_text = (uintptr_t)s_text;
	di->di_e_text = (uintptr_t)e_text;
	di->di_s_data = (uintptr_t)s_data;
	di->di_e_data = (uintptr_t)e_data;
	di->di_hat_htable_off = offsetof(hat_t, hat_htable);
	di->di_ht_pfn_off = offsetof(htable_t, ht_pfn);
#endif
}

/*
 * Build the memlists and other kernel essential memory system data structures.
 * This is everything at valloc_base.
 */
static void
startup_memlist(void)
{
	size_t memlist_sz;
	size_t memseg_sz;
	size_t pagehash_sz;
	size_t pp_sz;
	uintptr_t va;
	size_t len;
	uint_t prot;
	pfn_t pfn;
	int memblocks;
	pfn_t rsvd_high_pfn;
	pfn_t rsvd_low_pfn;
	pgcnt_t rsvd_pgcnt;
	size_t rsvdmemlist_sz;
	int rsvdmemblocks;
	caddr_t pagecolor_mem;
	size_t pagecolor_memsz;
	caddr_t page_ctrs_mem;
	size_t page_ctrs_size;
	size_t pse_table_alloc_size;
	struct memlist *current;
	extern void startup_build_mem_nodes(struct memlist *);

	/* XX64 fix these - they should be in include files */
	extern size_t page_coloring_init(uint_t, int, int);
	extern void page_coloring_setup(caddr_t);

	PRM_POINT("startup_memlist() starting...");

	/*
	 * Use leftover large page nucleus text/data space for loadable modules.
	 * Use at most MODTEXT/MODDATA (why?)
	 */
	len = kbm_nucleus_size;
	ASSERT(len > MMU_PAGESIZE);

	moddata = (caddr_t)ROUND_UP_PAGE(e_data);
	e_moddata = (caddr_t)P2ROUNDUP((uintptr_t)e_data, (uintptr_t)len);
	if (e_moddata - moddata > MODDATA)
		e_moddata = moddata + MODDATA;

	modtext = (caddr_t)ROUND_UP_PAGE(e_text);
	e_modtext = (caddr_t)P2ROUNDUP((uintptr_t)e_text, (uintptr_t)len);
	if (e_modtext - modtext > MODTEXT)
		e_modtext = modtext + MODTEXT;

	econtig = e_moddata;

	PRM_DEBUG(modtext);
	PRM_DEBUG(e_modtext);
	PRM_DEBUG(moddata);
	PRM_DEBUG(e_moddata);
	PRM_DEBUG(econtig);

	/*
	 * Examine the boot loader physical memory map to find out:
	 * - total memory in system - physinstalled
	 * - the lowest physical address - physmin
	 * - the highest physical address - physmax
	 * - the number of discontiguous segments of memory.
	 */
	if (prom_debug)
		print_memlist("boot physinstalled",
		    bootops->boot_mem->physinstalled);
	installed_top_size_ex(bootops->boot_mem->physinstalled, &physmax,
	    &physmin, &physinstalled, &memblocks);
	PRM_DEBUG(physmin);
	PRM_DEBUG(physmax);
	PRM_DEBUG(physinstalled);
	PRM_DEBUG(memblocks);

	/*
	 * We no longer support any form of memory DR.
	 */
	plat_dr_physmax = 0;

	/*
	 * Examine the system reserved memory to find out:
	 * - the number of discontiguous segments of memory.
	 */
	if (prom_debug)
		print_memlist("boot reserved mem",
		    bootops->boot_mem->rsvdmem);
	installed_top_size_ex(bootops->boot_mem->rsvdmem, &rsvd_high_pfn,
	    &rsvd_low_pfn, &rsvd_pgcnt, &rsvdmemblocks);
	PRM_DEBUG(rsvd_low_pfn);
	PRM_DEBUG(rsvd_high_pfn);
	PRM_DEBUG(rsvd_pgcnt);
	PRM_DEBUG(rsvdmemblocks);

	/*
	 * Initialize hat's mmu parameters.
	 * Check for enforce-prot-exec in boot environment. It's used to
	 * enable/disable support for the page table entry NX bit.
	 * The default is to enforce PROT_EXEC on processors that support NX.
	 * Boot seems to round up the "len", but 8 seems to be big enough.
	 */
	mmu_init();


	startup_build_mem_nodes(bootops->boot_mem->physinstalled);
#if 0
	/* XXXAARCH64: do we want this? why? */
	if (BOP_GETPROPLEN(bootops, "enforce-prot-exec") >= 0) {
		int len = BOP_GETPROPLEN(bootops, "enforce-prot-exec");
		char value[8];

		if (len < 8)
			(void) BOP_GETPROP(bootops, "enforce-prot-exec", value);
		else
			(void) strcpy(value, "");
		if (strcmp(value, "off") == 0)
			mmu.pt_nx = 0;
	}
	PRM_DEBUG(mmu.pt_nx);
#endif

	/*
	 * We will need page_t's for every page in the system, except for
	 * memory mapped at or above above the start of the kernel text segment.
	 *
	 * pages above e_modtext are attributed to kernel debugger (obp_pages)
	 * (this feels bad - why not e_contig or e_moddata?)
	 *
	 * XXXAARCH64: A few things here...
	 * - The 'avail_filter() skips page 0' does not apply on ARM
	 * - Is this looking a physical pages? If so, we've shoved a lot of
	 *   data in above the kernel, so how do we relaim it?
	 *
	 * This is *incredibly* slow and dubious at best. It'd be interesting
	 * to see if it's thrown by the framebuffer mappings and device stuff
	 * that lives up here. There must be a better way.
	 *
	 * This stuff is used in dump and kstat - I need to better understand
	 * what's going on here.
	 */
	npages = physinstalled; /* - 1; */ /* avail_filter() skips page 0, so "- 1" */
	obp_pages = 0;
	va = KERNEL_TEXT;
	while (kbm_probe(&va, &len, &pfn, &prot) != 0) {
		npages -= len >> MMU_PAGESHIFT;
		if (va >= (uintptr_t)e_moddata)
			obp_pages += len >> MMU_PAGESHIFT;
		va += len;
		if (va < KERNEL_TEXT)	/* XXXAARCH64: do we really need this? */
			break;
	}
	PRM_DEBUG(npages);
	PRM_DEBUG(obp_pages);

	/*
	 * If physmem is patched to be non-zero, use it instead of the computed
	 * value unless it is larger than the actual amount of memory on hand.
	 */
	if (physmem == 0 || physmem > npages) {
		physmem = npages;
	} else if (physmem < npages) {
		orig_npages = npages;
		npages = physmem;
	}
	PRM_DEBUG(physmem);

	/*
	 * We now compute the sizes of all the  initial allocations for
	 * structures the kernel needs in order do kmem_alloc(). These
	 * include:
	 *	memsegs
	 *	memlists
	 *	page hash table
	 *	page_t's
	 *	page coloring data structs
	 */
	memseg_sz = sizeof (struct memseg) * (memblocks + POSS_NEW_FRAGMENTS);
	ADD_TO_ALLOCATIONS(memseg_base, memseg_sz);
	PRM_DEBUG(memseg_sz);

	/*
	 * Reserve space for memlists. There's no real good way to know exactly
	 * how much room we'll need, but this should be a good upper bound.
	 */
	memlist_sz = ROUND_UP_PAGE(2 * sizeof (struct memlist) *
	    (memblocks + POSS_NEW_FRAGMENTS));
	ADD_TO_ALLOCATIONS(memlist, memlist_sz);
	PRM_DEBUG(memlist_sz);

	/*
	 * Reserve space for system reserved memlists.
	 */
	rsvdmemlist_sz = ROUND_UP_PAGE(2 * sizeof (struct memlist) *
	    (rsvdmemblocks + POSS_NEW_FRAGMENTS));
	ADD_TO_ALLOCATIONS(bios_rsvd, rsvdmemlist_sz);
	PRM_DEBUG(rsvdmemlist_sz);

	/* LINTED */
	ASSERT(P2SAMEHIGHBIT((1 << PP_SHIFT), sizeof (struct page)));
	/*
	 * The page structure hash table size is a power of 2
	 * such that the average hash chain length is PAGE_HASHAVELEN.
	 */
	page_hashsz = npages / PAGE_HASHAVELEN;
	page_hashsz_shift = highbit(page_hashsz);
	page_hashsz = 1 << page_hashsz_shift;
	pagehash_sz = sizeof (struct page *) * page_hashsz;
	ADD_TO_ALLOCATIONS(page_hash, pagehash_sz);
	PRM_DEBUG(pagehash_sz);

	/*
	 * Set aside room for the page structures themselves.
	 */
	PRM_DEBUG(npages);
	pp_sz = sizeof (struct page) * npages;
	ADD_TO_ALLOCATIONS(pp_base, pp_sz);
	PRM_DEBUG(pp_sz);

	/*
	 * determine l2 cache info and memory size for page coloring
	 */
	(void) getl2cacheinfo(CPU,
	    &l2cache_sz, &l2cache_linesz, &l2cache_assoc);
	pagecolor_memsz =
	    page_coloring_init(l2cache_sz, l2cache_linesz, l2cache_assoc);
	ADD_TO_ALLOCATIONS(pagecolor_mem, pagecolor_memsz);
	PRM_DEBUG(pagecolor_memsz);

	page_ctrs_size = page_ctrs_sz();
	ADD_TO_ALLOCATIONS(page_ctrs_mem, page_ctrs_size);
	PRM_DEBUG(page_ctrs_size);

	/*
	 * Allocate the array that protects pp->p_selock.
	 */
	pse_shift = size_pse_array(physmem, max_ncpus);
	pse_table_size = 1 << pse_shift;
	pse_table_alloc_size = pse_table_size * sizeof (pad_mutex_t);
	ADD_TO_ALLOCATIONS(pse_mutex, pse_table_alloc_size);

	valloc_sz = ROUND_UP_LPAGE(valloc_sz);
	valloc_base = VALLOC_BASE;

	/*
	 * The signicant memory-sized regions are roughly sized as follows in
	 * the default layout with max physmem:
	 *  segkpm: 1x physmem allocated (but 1Tb room, below VALLOC_BASE)
	 *  segzio: 1.5x physmem
	 *  segkvmm: 4x physmem
	 *  heap: whatever's left up to COREHEAP_BASE, at least 1.5x physmem
	 *
	 * The idea is that we leave enough room to avoid fragmentation issues,
	 * so we would like the VA arenas to have some extra.
	 *
	 * Ignoring the loose change of segkp, valloc, and such, this means that
	 * as COREHEAP_BASE-VALLOC_BASE=2Tb, we can accommodate a physmem up to
	 * about (2Tb / 7.0), rounded down to 256Gb in the check below.
	 *
	 * Note that KPM lives below VALLOC_BASE, but we want to include it in
	 * adjustments, hence the 8 below.
	 *
	 * Beyond 256Gb, we push segkpm_base (and hence kernelbase and
	 * _userlimit) down to accommodate the VA requirements above.
	 *
	 * XXXAARCH64: recalculate all of this given the VA space we have
	 * available (assume 48 bit VA).  This is a bit suspicious, and comes
	 * from a world where we don't have TTBR0/TTBR1 (and only had a much
	 * smaller VA when this was written).
	 *
	 * This makes a huge assumption, which is that memory starts at 0,
	 * which it absolutely doesn't.
	 */
	PRM_DEBUG(physmax);
	PRM_DEBUG(mmu_btop(TERABYTE / 4));
	PRM_DEBUG(segkpm_base);
	PRM_DEBUG(valloc_base);
#if 0
	if (physmax + 1 > mmu_btop(TERABYTE / 4)) {
		uint64_t physmem_bytes = mmu_ptob(physmax + 1);
		uint64_t adjustment = 8 * (physmem_bytes - (TERABYTE / 4));

		PRM_DEBUG(adjustment);

		/*
		 * segkpm_base is always aligned on a L3 PTE boundary.
		 */
		segkpm_base -= P2ROUNDUP(adjustment, KERNEL_REDZONE_SIZE);

		/*
		 * But make sure we leave some space for user apps above hole.
		 * XXXAARCH64: this is plain old wrong for us
		 */
		segkpm_base = MAX(segkpm_base, AARCH64_VA_HOLE_END + (TERABYTE / 2));

		ASSERT(segkpm_base <= SEGKPM_BASE);

		valloc_base = segkpm_base + P2ROUNDUP(physmem_bytes, ONE_GIG);
		if (valloc_base < segkpm_base)
			panic("not enough kernel VA to support memory size");
	}
#endif
	PRM_DEBUG(segkpm_base);
	PRM_DEBUG(valloc_base);

	/*
	 * do all the initial allocations
	 */
	perform_allocations();
	PRM_DEBUG(memseg_base);
	PRM_DEBUG(memlist);
	PRM_DEBUG(bios_rsvd);
	PRM_DEBUG(page_hash);
	PRM_DEBUG(pp_base);
	PRM_DEBUG(pagecolor_mem);
	PRM_DEBUG(page_ctrs_mem);
	PRM_DEBUG(pse_mutex);

	/*
	 * Build phys_install and phys_avail in kernel memspace.
	 * - phys_install should be all memory in the system.
	 * - phys_avail is phys_install minus any memory mapped before this
	 *    point above KERNEL_TEXT.
	 */
	current = phys_install = memlist;
	copy_memlist_filter(bootops->boot_mem->physinstalled, &current, NULL);
	if ((caddr_t)current > (caddr_t)memlist + memlist_sz)
		panic("physinstalled was too big!");
	if (prom_debug)
		print_memlist("phys_install", phys_install);

	phys_avail = current;
	PRM_POINT("Building phys_avail:\n");
	copy_memlist_filter(bootops->boot_mem->physinstalled, &current,
	    avail_filter);
	if ((caddr_t)current > (caddr_t)memlist + memlist_sz)
		panic("physavail was too big!");
	if (prom_debug)
		print_memlist("phys_avail", phys_avail);

	/*
	 * Free unused memlist items, which may be used by memory DR driver
	 * at runtime.
	 */
	if ((caddr_t)current < (caddr_t)memlist + memlist_sz) {
		memlist_free_block((caddr_t)current,
		    (caddr_t)memlist + memlist_sz - (caddr_t)current);
	}

	/*
	 * Build system reserved memspace
	 */
	current = bios_rsvd;
	copy_memlist_filter(bootops->boot_mem->rsvdmem, &current, NULL);
	if ((caddr_t)current > (caddr_t)bios_rsvd + rsvdmemlist_sz)
		panic("bios_rsvd was too big!");
	if (prom_debug)
		print_memlist("bios_rsvd", bios_rsvd);

	/*
	 * Free unused memlist items, which may be used by memory DR driver
	 * at runtime.
	 */
	if ((caddr_t)current < (caddr_t)bios_rsvd + rsvdmemlist_sz) {
		memlist_free_block((caddr_t)current,
		    (caddr_t)bios_rsvd + rsvdmemlist_sz - (caddr_t)current);
	}

	/*
	 * setup page coloring
	 */
	page_coloring_setup(pagecolor_mem);
	page_lock_init();	/* currently a no-op */

	/*
	 * free page list counters
	 */
	(void) page_ctrs_alloc(page_ctrs_mem);

	/*
	 * Size the pcf array based on the number of cpus in the box at
	 * boot time.
	 */

	pcf_init();

	/*
	 * Initialize the page structures from the memory lists.
	 */
	availrmem_initial = availrmem = freemem = 0;
	PRM_POINT("Calling kphysm_init()...");
	npages = kphysm_init(pp_base, npages);
	PRM_POINT("kphysm_init() done");
	PRM_DEBUG(npages);

	init_debug_info();

	/*
	 * Now that page_t's have been initialized, remove all the
	 * initial allocation pages from the kernel free page lists.
	 */
	boot_mapin((caddr_t)valloc_base, valloc_sz);
	boot_mapin((caddr_t)MISC_VA_BASE, MISC_VA_SIZE);
	PRM_POINT("startup_memlist() done");

	PRM_DEBUG(valloc_sz);

	if ((availrmem >> (30 - MMU_PAGESHIFT)) >=
	    textrepl_min_gb && l2cache_sz <= 2 << 20) {
		extern size_t textrepl_size_thresh;
		textrepl_size_thresh = (16 << 20) - 1;
	}
}

static void
load_tod_module(char *todmod)
{
	if (modload("tod", todmod) == -1)
		halt("Can't load TOD module");
}

extern void exception_vector(void);
static inline void
enable_irq()
{
	__asm__ __volatile__("msr DAIFClr, #0xF":::"memory");
}
static void
startup_end(void)
{
	int i;
	extern void cpu_event_init(void);

	PRM_POINT("startup_end() starting...");

	write_vbar((uintptr_t)exception_vector);

	/*
	 * Perform tasks that get done after most of the VM
	 * initialization has been done but before the clock
	 * and other devices get started.
	 */
	kern_setup1();

	/*
	 * Perform CPC initialization for this CPU.
	 */
	kcpc_hw_init(CPU);

	/*
	 * Initialize cpu event framework.
	 */
	cpu_event_init();

	/*
	 * If needed, load TOD module now so that ddi_get_time(9F) etc. work
	 * (For now, "needed" is defined as set tod_module_name in /etc/system)
	 */
	if (tod_module_name != NULL) {
		PRM_POINT("load_tod_module()");
		load_tod_module(tod_module_name);
	}

	/*
	 * Configure the system.
	 */
	PRM_POINT("Calling configure()...");
	configure();		/* set up devices */
	PRM_POINT("configure() done");

	/*
	 * Set the isa_list string to the defined instruction sets we
	 * support.
	 */
	/* setx86isalist(); */
	PRM_POINT("cpu_intr_alloc()");
	cpu_intr_alloc(CPU, NINTR_THREADS);
	PRM_POINT("psm_install()");
	psm_install();

	/*
	 * We're done with bootops.  We don't unmap the bootstrap yet because
	 * we're still using bootsvcs.
	 */
	PRM_POINT("NULLing out bootops");
	bootops = (struct bootops *)NULL;

	PRM_POINT("Enabling interrupts");
#if 0
	(*picinitf)();
	sti();
#endif
	set_base_spl();
	enable_irq();

	(void) add_avsoftintr((void *)&softlevel1_hdl, 1, softlevel1,
	    "softlevel1", NULL, NULL); /* XXX to be moved later */

	/*
	 * Register these software interrupts for ddi timer.
	 * Software interrupts up to the level 10 are supported.
	 */
	for (i = DDI_IPL_1; i <= DDI_IPL_10; i++) {
		(void) add_avsoftintr((void *)&softlevel_hdl[i-1], i,
		    (avfunc)ddi_periodic_softintr, "ddi_periodic",
		    (caddr_t)(uintptr_t)i, NULL);
	}
	PRM_POINT("startup_end() done");
}

/*
 * Layout the kernel's part of address space and initialize kmem allocator.
 */
static void
startup_kmem(void)
{
	extern void page_set_colorequiv_arr(void);

	PRM_POINT("startup_kmem() starting...");

	if (eprom_kernelbase && eprom_kernelbase != KERNELBASE)
		cmn_err(CE_NOTE, "!kernelbase cannot be changed on 64-bit "
		    "systems.");
	kernelbase = segkpm_base - KERNEL_REDZONE_SIZE;	/* this is actually fixed */
	core_base = (uintptr_t)COREHEAP_BASE;
	core_size = (size_t)COREHEAP_MAX_SIZE;

	PRM_DEBUG(core_base);
	PRM_DEBUG(core_size);
	PRM_DEBUG(kernelbase);

	ekernelheap = (char *)core_base;
	PRM_DEBUG(ekernelheap);

	/*
	 * Now that we know the real value of kernelbase,
	 * update variables that were initialized with a value of
	 * KERNELBASE (in common/conf/param.c).
	 *
	 * XXX	The problem with this sort of hackery is that the
	 *	compiler just may feel like putting the const declarations
	 *	(in param.c) into the .text section.  Perhaps they should
	 *	just be declared as variables there?
	 */

	*(uintptr_t *)&_kernelbase = kernelbase;
	*(uintptr_t *)&_userlimit = USERLIMIT;
	PRM_DEBUG(_kernelbase);
	PRM_DEBUG(_userlimit);
	PRM_DEBUG(_userlimit32);

	layout_kernel_va();

	/*
	 * Initialize the kernel heap. Note 3rd argument must be > 1st.
	 */
	kernelheap_init(kernelheap, ekernelheap,
	    kernelheap + MMU_PAGESIZE,
	    (void *)core_base, (void *)(core_base + core_size));

	/*
	 * Initialize kernel memory allocator.
	 */
	kmem_init();

	/*
	 * Factor in colorequiv to check additional 'equivalent' bins
	 */
	page_set_colorequiv_arr();

	/*
	 * Initialize bp_mapin().
	 */
	bp_init(MMU_PAGESIZE, HAT_STORECACHING_OK);

	/*
	 * orig_npages is non-zero if physmem has been configured for less
	 * than the available memory.
	 */
	if (orig_npages) {
		cmn_err(CE_WARN, "!%slimiting physmem to 0x%lx of 0x%lx pages",
		    (npages == PHYSMEM ? "Due to virtual address space " : ""),
		    npages, orig_npages);
	}

	if (plat_dr_support_memory()) {
		mem_config_init();
	}

	PRM_POINT("startup_kmem() done");
}

#if defined(_SOFT_HOSTID)
/*
 * On platforms that do not have a hardware serial number, attempt
 * to set one based on the contents of /etc/hostid.  If this file does
 * not exist, assume that we are to generate a new hostid and set
 * it in the kernel, for subsequent saving by a userland process
 * once the system is up and the root filesystem is mounted r/w.
 *
 * In order to gracefully support upgrade on OpenSolaris, if
 * /etc/hostid does not exist, we will attempt to get a serial number
 * using the legacy method (/kernel/misc/sysinit).
 *
 * If that isn't present, we attempt to use an SMBIOS UUID, which is
 * a hardware serial number.  Note that we don't automatically trust
 * all SMBIOS UUIDs (some older platforms are defective and ship duplicate
 * UUIDs in violation of the standard), we check against a blocklist.
 *
 * In an attempt to make the hostid less prone to abuse
 * (for license circumvention, etc), we store it in /etc/hostid
 * in rot47 format.
 */
static int atoi(char *);

/*
 * Set this to non-zero in /etc/system if you think your SMBIOS returns a
 * UUID that is not unique. (Also report it so that the smbios_uuid_blocklist
 * array can be updated.)
 */
int smbios_broken_uuid = 0;

/*
 * List of known bad UUIDs.  This is just the lower 32-bit values, since
 * that's what we use for the host id.  If your hostid falls here, you need
 * to contact your hardware OEM for a fix for your BIOS.
 */
static unsigned char
smbios_uuid_blocklist[][16] = {

	{	/* Reported bad UUID (Google search) */
		0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05,
		0x00, 0x06, 0x00, 0x07, 0x00, 0x08, 0x00, 0x09,
	},
	{	/* Known bad DELL UUID */
		0x4C, 0x4C, 0x45, 0x44, 0x00, 0x00, 0x20, 0x10,
		0x80, 0x20, 0x80, 0xC0, 0x4F, 0x20, 0x20, 0x20,
	},
	{	/* Uninitialized flash */
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	},
	{	/* All zeros */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	},
};

static int32_t
uuid_to_hostid(const uint8_t *uuid)
{
	/*
	 * Although the UUIDs are 128-bits, they may not distribute entropy
	 * evenly.  We would like to use SHA or MD5, but those are located
	 * in loadable modules and not available this early in boot.  As we
	 * don't need the values to be cryptographically strong, we just
	 * generate 32-bit vaue by xor'ing the various sequences together,
	 * which ensures that the entire UUID contributes to the hostid.
	 */
	uint32_t	id = 0;

	/* first check against the blocklist */
	for (int i = 0; i < (sizeof (smbios_uuid_blocklist) / 16); i++) {
		if (bcmp(smbios_uuid_blocklist[0], uuid, 16) == 0) {
			cmn_err(CE_CONT, "?Broken SMBIOS UUID. "
			    "Contact BIOS manufacturer for repair.\n");
			return ((int32_t)HW_INVALID_HOSTID);
		}
	}

	for (int i = 0; i < 16; i++)
		id ^= ((uuid[i]) << (8 * (i % sizeof (id))));

	/* Make sure return value is positive */
	return (id & 0x7fffffff);
}

static int32_t
set_soft_hostid(void)
{
	struct _buf *file;
	char tokbuf[MAXNAMELEN];
	token_t token;
	int done = 0;
	u_longlong_t tmp;
	int i;
	int32_t hostid = (int32_t)HW_INVALID_HOSTID;
	unsigned char *c;
	smbios_system_t smsys;

	/*
	 * If /etc/hostid file not found, we'd like to get a pseudo
	 * random number to use at the hostid.  A nice way to do this
	 * is to read the real time clock.
	 */

	if ((file = kobj_open_file(hostid_file)) == (struct _buf *)-1) {
		/*
		 * hostid file not found - try to load sysinit module
		 * and see if it has a nonzero hostid value...use that
		 * instead of generating a new hostid here if so.
		 */
		if ((i = modload("misc", "sysinit")) != -1) {
			if (strlen(hw_serial) > 0)
				hostid = (int32_t)atoi(hw_serial);
			(void) modunload(i);
		}

		/*
		 * We try to use the SMBIOS UUID. But not if it is blocklisted
		 * in /etc/system.
		 */
		if ((hostid == HW_INVALID_HOSTID) &&
		    (smbios_broken_uuid == 0) &&
		    (ksmbios != NULL) &&
		    (smbios_info_system(ksmbios, &smsys) != SMB_ERR) &&
		    (smsys.smbs_uuidlen >= 16)) {
			hostid = uuid_to_hostid(smsys.smbs_uuid);
		}

		/*
		 * Generate a "random" hostid using the clock.  These
		 * hostids will change on each boot if the value is not
		 * saved to a persistent /etc/hostid file.
		 */
		if (hostid == HW_INVALID_HOSTID) {
			hostid = (int32_t)(read_cntpct() & 0x0CFFFFF);
		}
	} else {
		/* hostid file found */
		while (!done) {
			token = kobj_lex(file, tokbuf, sizeof (tokbuf));

			switch (token) {
			case POUND:
				/*
				 * skip comments
				 */
				kobj_find_eol(file);
				break;
			case STRING:
				/*
				 * un-rot47 - obviously this
				 * nonsense is ascii-specific
				 */
				for (c = (unsigned char *)tokbuf;
				    *c != '\0'; c++) {
					*c += 47;
					if (*c > '~')
						*c -= 94;
					else if (*c < '!')
						*c += 94;
				}
				/*
				 * now we should have a real number
				 */

				if (kobj_getvalue(tokbuf, &tmp) != 0)
					kobj_file_err(CE_WARN, file,
					    "Bad value %s for hostid",
					    tokbuf);
				else
					hostid = (int32_t)tmp;

				break;
			case EOF:
				done = 1;
				/* FALLTHROUGH */
			case NEWLINE:
				kobj_newline(file);
				break;
			default:
				break;

			}
		}
		if (hostid == HW_INVALID_HOSTID) /* didn't find a hostid */
			kobj_file_err(CE_WARN, file,
			    "hostid missing or corrupt");

		kobj_close_file(file);
	}
	/*
	 * hostid is now the value read from /etc/hostid, or the
	 * new hostid we generated in this routine or HW_INVALID_HOSTID if not
	 * set.
	 */
	return (hostid);
}

static int
atoi(char *p)
{
	int i = 0;

	while (*p != '\0')
		i = 10 * i + (*p++ - '0');

	return (i);
}

#endif	/* _SOFT_HOSTID */

#define	TORTURE_BLKSIZE 100
static void
simple_torture(void)
{
#if 0
#if 0
	int i;
	mblk_t *blocks[TORTURE_BLKSIZE] = { NULL };

	for (i = 0; i < 100000; ++i) {
		if (blocks[i % TORTURE_BLKSIZE] != NULL)
			freeb(blocks[i % TORTURE_BLKSIZE]);
		blocks[i % TORTURE_BLKSIZE] = allocb(33 * (i % 300), 0);
		ASSERT(blocks[i % TORTURE_BLKSIZE]);
	}

	for (i = 0; i < TORTURE_BLKSIZE; ++i) {
		freeb(blocks[i]);
	}
#else
	int i;

	for (i = 0; i < 100000; ++i) {
		cmn_err(CE_NOTE, "torture test iteration %d", i);
	}
#endif
#endif
}

/*
 * XXXAARCH64: pretty much all of this need auditing
 *
 * There's some delta between this and i86pc, which seems a touch gratuitous.
 */
static void
startup_modules(void)
{
	int cnt;
	extern void prom_setup(void);
	int32_t v, h;
	char d[11];
	char *cp;
	/* cmi_hdl_t hdl; */

	PRM_POINT("startup_modules() starting...");

	PRM_POINT("simple_torture() starting...");
	simple_torture();
	PRM_POINT("simple_torture() done");

	/*
	 * this is not in i86pc, and is in platmod, which is not loaded yet?!
	 *
	 * There's a bit of a sparc-like thing going on here, where is sparc
	 * one would set things like the default tod module name.
	 */
	PRM_POINT("set_platform_defaults() starting...");
	set_platform_defaults();
	PRM_POINT("set_platform_defaults() done");

	/*
	 * Read the GMT lag from /etc/rtc_config.
	 */
	PRM_POINT("sgmtl(process_rtc_config_file()) starting...");
	sgmtl(process_rtc_config_file());
	PRM_POINT("sgmtl(process_rtc_config_file()) done");

	/*
	 * Calculate default settings of system parameters based upon
	 * maxusers, yet allow to be overridden via the /etc/system file.
	 */
	PRM_POINT("param_calc() starting...");
	param_calc(0);
	PRM_POINT("param_calc() done");

	PRM_POINT("mod_setup() starting...");
	mod_setup();
	PRM_POINT("mod_setup() done");

	/*
	 * Initialize system parameters.
	 */
	PRM_POINT("param_init() starting...");
	param_init();
	PRM_POINT("param_init() done");

	/*
	 * Initialize the default brands
	 */
	PRM_POINT("brand_init() starting...");
	brand_init();
	PRM_POINT("brand_init() done");

	/*
	 * maxmem is the amount of physical memory we're playing with.
	 */
	maxmem = physmem;

	/*
	 * Initialize segment management stuff.
	 */
	PRM_POINT("seg_init() starting...");
	seg_init();
	PRM_POINT("seg_init() done");

	PRM_POINT("modload[specfs]() starting...");
	if (modload("fs", "specfs") == -1)
		halt("Can't load specfs");
	PRM_POINT("modload[specfs]() done");

	PRM_POINT("modload[devfs]() starting...");
	if (modload("fs", "devfs") == -1)
		halt("Can't load devfs");
	PRM_POINT("modload[devfs]() done");

#if 1
	/*
	 * XXXAARCH64: this heinous hack is needed for now due to loading of
	 * depended-upon modules not working quite right yet.
	 */
	PRM_POINT("modload[mac]() starting...");
	if (modload("misc", "mac") == -1)
		halt("Can't load mac");
	PRM_POINT("modload[mac]() done");

	PRM_POINT("modload[dls]() starting...");
	if (modload("misc", "dls") == -1)
		halt("Can't load dls");
	PRM_POINT("modload[dls]() done");
#endif

	PRM_POINT("modload[dev]() starting...");
	if (modload("fs", "dev") == -1)
		halt("Can't load dev");
	PRM_POINT("modload[dev]() done");

	PRM_POINT("modload[procfs]() starting...");
	if (modload("fs", "procfs") == -1)
		halt("Can't load procfs");
	PRM_POINT("modload[procfs]() done");

	PRM_POINT("modloadonly() starting...");
	(void) modloadonly("sys", "lbl_edition");
	PRM_POINT("modloadonly() done");

	PRM_POINT("dispinit() starting...");
	dispinit();
	PRM_POINT("dispinit() done");

	/* Read cluster configuration data. */
	PRM_POINT("clconf_init() starting...");
	clconf_init();
	PRM_POINT("clconf_init() done");

	/*
	 * Create a kernel device tree. First, create rootnex and
	 * then invoke bus specific code to probe devices.
	 */
	PRM_POINT("setup_ddi() starting...");
	setup_ddi();
	PRM_POINT("setup_ddi() done");

	/*
	 * The moment DDI is up we need to stitch our MPIDR information
	 * gathered in CPUID pass1 to ACPI IDs.
	 */
	PRM_POINT("cpuid_pass2() starting...");
	cpuid_pass2(CPU);
	PRM_POINT("cpuid_pass2() done");

	{
		id_t smid;
		smbios_system_t smsys;
		smbios_info_t sminfo;
		char *mfg;
		/*
		 * Load the System Management BIOS into the global ksmbios
		 * handle, if an SMBIOS is present on this system.
		 * Also set "si-hw-provider" property, if not already set.
		 */
		ksmbios = smbios_open(NULL, SMB_VERSION, ksmbios_flags, NULL);
		if (ksmbios != NULL &&
		    ((smid = smbios_info_system(ksmbios, &smsys)) != SMB_ERR) &&
		    (smbios_info_common(ksmbios, smid, &sminfo)) != SMB_ERR) {
			mfg = (char *)sminfo.smbi_manufacturer;
			if (BOP_GETPROPLEN(bootops, "si-hw-provider") < 0) {
				extern char hw_provider[];
				int i;
				for (i = 0; i < SYS_NMLN; i++) {
					if (isprint(mfg[i]))
						hw_provider[i] = mfg[i];
					else {
						hw_provider[i] = '\0';
						break;
					}
				}
				hw_provider[SYS_NMLN - 1] = '\0';
			}
		}
	}

	/*
	 * Originally clconf_init() apparently needed the hostid.  But
	 * this no longer appears to be true - it uses its own nodeid.
	 * By placing the hostid logic here, we are able to make use of
	 * the SMBIOS UUID.
	 */
	if ((h = set_soft_hostid()) == HW_INVALID_HOSTID) {
		cmn_err(CE_WARN, "Unable to set hostid");
	} else {
		for (v = h, cnt = 0; cnt < 10; cnt++) {
			d[cnt] = (char)(v % 10);
			v /= 10;
			if (v == 0)
				break;
		}
		for (cp = hw_serial; cnt >= 0; cnt--)
			*cp++ = d[cnt] + '0';
		*cp = 0;
	}

#if 1
	PRM_POINT("modload[acpica]() starting...");
	if (modload("misc", "acpica") == -1)
		halt("Can't load acpica");
	PRM_POINT("modload[acpica]() done");
#endif

	/*
	 * Set up the CPU module subsystem for the boot cpu in the native
	 * case, and all physical cpu resource in the xpv dom0 case.
	 * Modifies the device tree, so this must be done after
	 * setup_ddi().
	 */
	/*
	 * Initialize a handle for the boot cpu - others will initialize
	 * as they startup.
	 *
	 * XXXAARCH64: We need to pick up topology from the ACPI PPTT
	 *
	 * XXXAARCH64: This is an interesting subsystem - needs some
	 * thought.
	 */
#if 0
	if ((hdl = cmi_init(CMI_HDL_NATIVE, cmi_ntv_hwchipid(CPU),
	    cmi_ntv_hwcoreid(CPU), cmi_ntv_hwstrandid(CPU))) != NULL) {
		if (is_x86_feature(x86_featureset, X86FSET_MCA))
			cmi_mca_init(hdl);
		CPU->cpu_m.mcpu_cmi_hdl = hdl;
	}
#endif

	/*
	 * Fake a prom tree such that /dev/openprom continues to work
	 */
	PRM_POINT("startup_modules: calling prom_setup...");
	prom_setup();

	//if (modload("misc", "platmod") == -1)
	//	halt("Can't load platmod");

	/*
	 * Load all platform specific modules
	 */
	PRM_POINT("startup_modules: calling psm_modload...");
	psm_modload();

	PRM_POINT("startup_modules() done");

}

/*
 * Establish the final size of the kernel's heap, size of segmap, segkp, etc.
 */
static void
layout_kernel_va(void)
{
	const size_t physmem_size = mmu_ptob(physmem);
	size_t size;

	PRM_POINT("layout_kernel_va() starting...");

	kpm_vbase = (caddr_t)segkpm_base;
	kpm_size = ROUND_UP_LPAGE(mmu_ptob(physmax + 1));
	if ((uintptr_t)kpm_vbase + kpm_size > (uintptr_t)valloc_base)
		panic("not enough room for kpm!");
	PRM_DEBUG(kpm_size);
	PRM_DEBUG(kpm_vbase);

	segkp_base = (caddr_t)valloc_base + valloc_sz;
	if (!segkp_fromheap) {
		size = mmu_ptob(segkpsize);
		/*
		 * Determine size of segkp
		 * Users can change segkpsize through eeprom.
		 */
		if (size < SEGKPMINSIZE || size > SEGKPMAXSIZE) {
			size = SEGKPDEFSIZE;
			cmn_err(CE_WARN, "!Illegal value for segkpsize. "
			    "segkpsize has been reset to %ld pages",
			    mmu_btop(size));
		}
		size = MIN(size, MAX(SEGKPMINSIZE, physmem_size));
		segkpsize = mmu_btop(ROUND_UP_LPAGE(size));
	}
	PRM_DEBUG(segkp_base);
	PRM_DEBUG(segkpsize);

	/*
	 * segkvmm: backing for vmm guest memory. Like segzio, we have a
	 * separate segment for two reasons: it makes it easy to skip our pages
	 * on kernel crash dumps, and it helps avoid fragmentation.  With this
	 * segment, we're expecting significantly-sized allocations only; we'll
	 * default to 4x the size of physmem.
	 */
	segkvmm_base = segkp_base + mmu_ptob(segkpsize);
	size = segkvmmsize != 0 ? mmu_ptob(segkvmmsize) : (physmem_size * 4);

	size = MAX(size, SEGVMMMINSIZE);
	segkvmmsize = mmu_btop(ROUND_UP_LPAGE(size));

	PRM_DEBUG(segkvmmsize);
	PRM_DEBUG(segkvmm_base);

	/*
	 * segzio is used for ZFS cached data.  For segzio, we use 1.5x physmem.
	 */
	segzio_base = segkvmm_base + mmu_ptob(segkvmmsize);
	if (segzio_fromheap) {
		segziosize = 0;
	} else {
		size = (segziosize != 0) ? mmu_ptob(segziosize) :
		    (physmem_size * 3) / 2;

		size = MAX(size, SEGZIOMINSIZE);
		segziosize = mmu_btop(ROUND_UP_LPAGE(size));
	}
	PRM_DEBUG(segziosize);
	PRM_DEBUG(segzio_base);

	/*
	 * Put the range of VA for device mappings next, kmdb knows to not
	 * grep in this range of addresses.
	 */
	toxic_addr =
	    ROUND_UP_LPAGE((uintptr_t)segzio_base + mmu_ptob(segziosize));
	PRM_DEBUG(toxic_addr);
	segmap_start = ROUND_UP_LPAGE(toxic_addr + toxic_size);

	/*
	 * Users can change segmapsize through eeprom. If the variable
	 * is tuned through eeprom, there is no upper bound on the
	 * size of segmap.
	 */
	segmapsize = MAX(ROUND_UP_LPAGE(segmapsize), SEGMAPDEFAULT);

	PRM_DEBUG(segmap_start);
	PRM_DEBUG(segmapsize);
	kernelheap = (caddr_t)ROUND_UP_LPAGE(segmap_start + segmapsize);
	PRM_DEBUG(kernelheap);
	PRM_POINT("layout_kernel_va() done...");
}

static void
kvm_init(void)
{
	ASSERT((((uintptr_t)s_text) & MMU_PAGEOFFSET) == 0);
	ASSERT((((uintptr_t)s_text) & MMU_PAGEOFFSET) == 0);

	/*
	 * Put the kernel segments in kernel address space.
	 */
	rw_enter(&kas.a_lock, RW_WRITER);
	as_avlinit(&kas);

	caddr_t _text = (caddr_t)P2ALIGN((uintptr_t)s_text, (uintptr_t)MMU_PAGESIZE);
	caddr_t _etext = (caddr_t)P2ROUNDUP((uintptr_t)e_text, (uintptr_t)MMU_PAGESIZE);
	caddr_t _data = (caddr_t)P2ALIGN((uintptr_t)s_data, (uintptr_t)MMU_PAGESIZE);
	caddr_t _edata = (caddr_t)P2ROUNDUP((uintptr_t)e_data, (uintptr_t)MMU_PAGESIZE);
	PRM_DEBUG(_text);
	PRM_DEBUG(_etext);
	PRM_DEBUG(_data);
	PRM_DEBUG(_edata);

	(void) seg_attach(&kas, _text, _edata - _text, &ktextseg);
	(void) segkmem_create(&ktextseg);

	(void) seg_attach(&kas, (caddr_t)valloc_base, valloc_sz, &kvalloc);
	(void) segkmem_create(&kvalloc);

	(void) seg_attach(&kas, kernelheap,
	    ekernelheap - kernelheap, &kvseg);
	(void) segkmem_create(&kvseg);

	if (segziosize > 0) {
		PRM_POINT("attaching segzio");
		(void) seg_attach(&kas, segzio_base, mmu_ptob(segziosize),
		    &kzioseg);
		(void) segkmem_create(&kzioseg);

		/* create zio area covering new segment */
		segkmem_zio_init(segzio_base, mmu_ptob(segziosize));
	}

	(void) seg_attach(&kas, kdi_segdebugbase, kdi_segdebugsize, &kdebugseg);
	(void) segkmem_create(&kdebugseg);

	rw_exit(&kas.a_lock);

	/*
	 * XXXAARCH64: does this handle our large pages?
	 */
	(void) as_setprot(&kas, _text, _etext - _text, PROT_READ | PROT_EXEC);
	(void) as_setprot(&kas, _data, _edata - _data, PROT_READ | PROT_WRITE);
}

/*
 * Finish initializing the VM system, now that we are no longer
 * relying on the boot time memory allocators.
 */
static void
startup_vm(void)
{
	struct segmap_crargs a;

	extern int use_brk_lpg, use_stk_lpg;

	PRM_POINT("startup_vm() starting...");

	/*
	 * Initialize the hat layer.
	 */
	hat_init();

	/*
	 * Do final allocations of HAT data structures that need to
	 * be allocated before quiescing the boot loader.
	 */
	PRM_POINT("Calling hat_kern_alloc()...");
	hat_kern_alloc((caddr_t)segmap_start, segmapsize, ekernelheap);
	PRM_POINT("hat_kern_alloc() done");

	/*
	 * The next two loops are done in distinct steps in order
	 * to be sure that any page that is doubly mapped (both above
	 * KERNEL_TEXT and below kernelbase) is dealt with correctly.
	 * Note this may never happen, but it might someday.
	 */
	bootpages = NULL;
	PRM_POINT("Protecting boot pages");

	/*
	 * Protect pages mapped in KVA by eboot, but below SEGKPM_BASE
	 */
	protect_boot_range(BOOTLOADER_DATA_BASE,
	    BOOTLOADER_DATA_BASE + (2 * 1024 * 1024), 1);
	protect_boot_range(BOOTLOADER_DATA_BASE + (12 * 1024 * 1024),
	    BOOTLOADER_DATA_BASE + BOOTLOADER_DATA_SIZE, 1);
	protect_boot_range(BOOT_VEC_BASE, BOOT_VEC_BASE + BOOT_VEC_SIZE, 0);
	protect_boot_range(DBG2_BASE, DBG2_BASE + DBG2_SIZE, 0);
	protect_boot_range(PT_WINDOW_VA, PT_WINDOW_VA + (64 * 1024), 1);
	protect_boot_range(PTE_WINDOW_PTE_VA,
	    PTE_WINDOW_PTE_VA + (64 * 1024), 1);
	/*
	 * ShadowFB is allocated by kernel bootstrap
	 */
#if 0
	protect_boot_range(SHADOWFB_BASE,
	    SHADOWFB_BASE + SHADOWFB_MAX_SIZE, 0);
#endif
	protect_boot_range(FRAMEBUFFER_BASE,
	    FRAMEBUFFER_BASE + FRAMEBUFFER_MAX_SIZE, 0);
	protect_boot_range(UEFI_RUNTIME_BASE,
	    UEFI_RUNTIME_BASE + UEFI_RUNTIME_MAX_SIZE, 0);

	/*
	 * Protect any pages mapped above KERNEL_TEXT that somehow have
	 * page_t's. This can only happen if something weird allocated
	 * in this range (like kadb/kmdb).
	 */
	protect_boot_range(KERNEL_TEXT, (uintptr_t)-1, 0);

#if 0
	/*
	 * Before we can take over memory allocation/mapping from the boot
	 * loader we must remove from our free page lists any boot allocated
	 * pages that stay mapped until release_bootstrap().
	 */
	protect_boot_range(0, mmu.hole_start, 1);
#endif

	/*
	 * Switch to running on regular HAT (not boot_mmu)
	 */
	PRM_POINT("Calling hat_kern_setup()...");
	hat_kern_setup();

	/*
	 * It is no longer safe to call BOP_ALLOC(), so make sure we don't.
	 */
	bop_no_more_mem();

	PRM_POINT("hat_kern_setup() done");

	/* XXXAARCH64: hat_cpu_online(CPU); */

	/*
	 * Initialize VM system
	 */
	PRM_POINT("Calling kvm_init()...");
	kvm_init();
	PRM_POINT("kvm_init() done");
#if 0
	/*
	 * Tell kmdb that the VM system is now working
	 */
	if (boothowto & RB_DEBUG)
		kdi_dvec_vmready();
#endif
	/*
	 * Create the device arena for toxic (to dtrace/kmdb) mappings.
	 */
	device_arena = vmem_create("device", (void *)toxic_addr,
	    toxic_size, MMU_PAGESIZE, NULL, NULL, NULL, 0, VM_SLEEP);
#if 0
	/*
	 * Now that we've got more VA, as well as the ability to allocate from
	 * it, tell the debugger.
	 */
	if (boothowto & RB_DEBUG)
		kdi_dvec_memavail();
#endif

	cmn_err(CE_CONT, "?mem = %luK (0x%lx)\n",
	    physinstalled << (MMU_PAGESHIFT - 10), ptob(physinstalled));

	/*
	 * disable automatic large pages for small memory systems or
	 * when the disable flag is set.
	 *
	 * Do not yet consider page sizes larger than 2m/4m.
	 *
	 * XXXAARCH64: this needs to be more like i86pc
	 */
	use_brk_lpg = 0;
	use_stk_lpg = 0;

	PRM_POINT("Calling hat_init_finish()...");
	hat_init_finish();
	PRM_POINT("hat_init_finish() done");

	/*
	 * Initialize the segkp segment type.
	 */
	rw_enter(&kas.a_lock, RW_WRITER);
	PRM_POINT("Attaching segkp");
	if (segkp_fromheap) {
		segkp->s_as = &kas;
	} else if (seg_attach(&kas, (caddr_t)segkp_base, mmu_ptob(segkpsize),
	    segkp) < 0) {
		panic("startup: cannot attach segkp");
		/*NOTREACHED*/
	}
	PRM_POINT("Doing segkp_create()");
	if (segkp_create(segkp) != 0) {
		panic("startup: segkp_create failed");
		/*NOTREACHED*/
	}
	PRM_DEBUG(segkp);
	rw_exit(&kas.a_lock);

	/*
	 * kpm segment
	 */
	segmap_kpm = 0;
	if (kpm_desired)
		kpm_init();

	/*
	 * Now create segmap segment.
	 */
	rw_enter(&kas.a_lock, RW_WRITER);
	if (seg_attach(&kas, (caddr_t)segmap_start, segmapsize, segmap) < 0) {
		panic("cannot attach segmap");
		/*NOTREACHED*/
	}
	PRM_DEBUG(segmap);

	a.prot = PROT_READ | PROT_WRITE;
	a.shmsize = 0;
	a.nfreelist = segmapfreelists;

	if (segmap_create(segmap, (caddr_t)&a) != 0)
		panic("segmap_create segmap");
	rw_exit(&kas.a_lock);

	setup_vaddr_for_ppcopy(CPU);

	segdev_init();

	/* pmem_init(); */

	PRM_POINT("startup_vm() done");
}

void
post_startup(void)
{
	extern void cpu_event_init_cpu(cpu_t *);

	/*
	 * Complete CPU module initialization
	 */
	//cmi_post_startup();

	/*
	 * Perform forceloading tasks for /etc/system.
	 */
	(void) mod_sysctl(SYS_FORCELOAD, NULL);

	/*
	 * ON4.0: Force /proc module in until clock interrupt handle fixed
	 * ON4.0: This must be fixed or restated in /etc/systems.
	 */
	(void) modload("fs", "procfs");

	maxmem = freemem;

	cpu_event_init_cpu(CPU);

	pg_init();
}


static int
pp_in_range(page_t *pp, uint64_t low_addr, uint64_t high_addr)
{
	return ((SEGKPM_BASE <= low_addr) && (low_addr < (SEGKPM_BASE + SEGKPM_SIZE)) &&
	    (SEGKPM_BASE <= high_addr) && (high_addr < (SEGKPM_BASE + SEGKPM_SIZE)) &&
	    (pp->p_pagenum >= btop(low_addr - SEGKPM_BASE)) &&
	    (pp->p_pagenum < btopr(high_addr - SEGKPM_BASE)));
}

void
release_bootstrap(void)
{
	int root_is_ramdisk;
	page_t *pp;
	extern void kobj_boot_unmountroot(void);
	extern dev_t rootdev;
	pfn_t	pfn;

	/* unmount boot ramdisk and release kmem usage */
	kobj_boot_unmountroot();

	/*
	 * We're finished using the boot loader so free its pages.
	 */
	PRM_POINT("Unmapping lower boot pages");

	clear_boot_mappings(0, _userlimit);

	/*
	 * If root isn't on ramdisk, destroy the hardcoded
	 * ramdisk node now and release the memory. Else,
	 * ramdisk memory is kept in rd_pages.
	 */
	root_is_ramdisk = (getmajor(rootdev) == ddi_name_to_major("ramdisk"));
	if (!root_is_ramdisk) {
		dev_info_t *dip = ddi_find_devinfo("ramdisk", -1, 0);
		ASSERT(dip && ddi_get_parent(dip) == ddi_root_node());
		ndi_rele_devi(dip);	/* held from ddi_find_devinfo */
		(void) ddi_remove_child(dip, 0);
	}

	PRM_POINT("Releasing boot pages");

	for (struct memlist *scratch = boot_scratch; scratch != NULL; scratch = scratch->ml_next) {
		uintptr_t pa = scratch->ml_address;
		uintptr_t sz = scratch->ml_size;
		uintptr_t pfn = mmu_btop(pa);

		for (uintptr_t i = 0; i < mmu_btop(sz); i++) {
			extern uint64_t ramdisk_start, ramdisk_end;
			page_t *pp = page_numtopp_nolock(pfn + i);
			ASSERT(pp);
			ASSERT(PAGE_LOCKED(pp));
			ASSERT(!PP_ISFREE(pp));
			if (root_is_ramdisk && pp_in_range(pp, ramdisk_start, ramdisk_end)) {
				pp->p_next = rd_pages;
				rd_pages = pp;
				continue;
			}
			pp->p_next = (struct page *)0;
			pp->p_prev = (struct page *)0;
			PP_CLRBOOTPAGES(pp);
			page_pp_unlock(pp, 0, 1);
			page_free(pp, 1);
			mutex_enter(&freemem_lock);
			availrmem_initial++;
			availrmem++;
			mutex_exit(&freemem_lock);
		}
	}

	PRM_POINT("Boot pages released");
}


void *
device_arena_alloc(size_t size, int vm_flag)
{
	return (vmem_alloc(device_arena, size, vm_flag));
}

void
device_arena_free(void *vaddr, size_t size)
{
	vmem_free(device_arena, vaddr, size);
}
