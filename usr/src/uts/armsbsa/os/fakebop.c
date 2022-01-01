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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 *
 * Copyright 2020 Joyent, Inc.
 */

/*
 * This file contains the functionality that mimics the boot operations
 * on SPARC systems or the old boot.bin/multiboot programs on x86 systems.
 * The x86 kernel now does everything on its own.
 */

#include <sys/types.h>
#include <sys/bootconf.h>
#include <sys/bootsvcs.h>
#include <sys/bootinfo.h>
#include <sys/multiboot.h>
#include <sys/bootvfs.h>
#include <sys/bootprops.h>
#include <sys/varargs.h>
#include <sys/param.h>
#include <sys/machparam.h>
#include <sys/machsystm.h>
#include <sys/archsystm.h>
#include <sys/boot_console.h>
#include <sys/framebuffer.h>
#include <sys/cmn_err.h>
#include <sys/systm.h>
#include <sys/promif.h>
#include <sys/archsystm.h>
#if !defined(__aarch64__)
#include <sys/x86_archext.h>
#endif
#include <sys/kobj.h>
#include <sys/privregs.h>
#include <sys/sysmacros.h>
#include <sys/ctype.h>
#if !defined(__aarch64__)
#include <sys/fastboot.h>
#endif
#ifdef __xpv
#include <sys/hypervisor.h>
#include <net/if.h>
#endif
#include <vm/kboot_mmu.h>
#include <vm/hat_pte.h>
#include <sys/kobj.h>
#include <sys/kobj_lex.h>
#include <sys/pci_cfgspace_impl.h>
#if !defined(__aarch64__)
#include <sys/fastboot_impl.h>
#endif
#include <sys/acpi/acpi.h>
#include <sys/acpi/acconfig.h>
#include <sys/ddipropdefs.h>	/* For DDI prop types */
#include <sys/efi.h>
#include <sys/kobj_impl.h>	/* for kobj_debug */

static int have_console = 0;	/* set once primitive console is initialized */
static char *boot_args = "";

/*
 * Debugging macros
 */
static uint_t kbm_debug = 0;
#define	DBG_P(...)	{ if (kbm_debug) bop_printf(NULL, __VA_ARGS__); }
#define	DBG_MSG(s)	{ if (kbm_debug) bop_printf(NULL, "%s", s); }
#define	DBG(x)		{ if (kbm_debug)			\
	bop_printf(NULL, "%s is %" PRIx64 "\n", #x, (uint64_t)(x));	\
	}

#define	PUT_STRING(s) {				\
	char *cp;				\
	for (cp = (s); *cp; ++cp)		\
		bcons_putchar(*cp);		\
	}

/* callback to boot_fb to set shadow frame buffer */
extern void boot_fb_shadow_init(bootops_t *);

bootops_t bootop;	/* simple bootops we'll pass on to kernel */
struct bsys_mem bm;
extern EFI_RUNTIME_SERVICES64 *efirt;	/* used for RTC, reset, etc. */

/*
 * Boot info from "glue" code in low memory. xbootp is used by:
 *	do_bop_phys_alloc(), do_bsys_alloc() and read_bootenvrc().
 */
static struct xboot_info *xbootp;
static uintptr_t next_virt;	/* next available virtual address */
static paddr_t next_phys;	/* next available physical address from dboot */
static paddr_t high_phys = -(paddr_t)1;	/* last used physical address */

/*
 * buffer for vsnprintf for console I/O
 */
#define	BUFFERSIZE	512
static char buffer[BUFFERSIZE];

/*
 * stuff to store/report/manipulate boot property settings.
 */
typedef struct bootprop {
	struct bootprop *bp_next;
	char *bp_name;
	int bp_flags;			/* DDI prop type */
	uint_t bp_vlen;			/* 0 for boolean */
	char *bp_value;
} bootprop_t;

static bootprop_t *bprops = NULL;
static char *curr_page = NULL;		/* ptr to avail bprop memory */
static int curr_space = 0;		/* amount of memory at curr_page */

#ifdef __xpv
extern start_info_t *xen_info;
extern shared_info_t *HYPERVISOR_shared_info;
#endif

/*
 * some allocator statistics
 */
static ulong_t total_bop_alloc_scratch = 0;
static ulong_t total_bop_alloc_kernel = 0;

static void build_firmware_properties(struct xboot_info *);

static int early_allocation = 1;

int force_fastreboot = 0;
volatile int fastreboot_onpanic = 0;
int post_fastreboot = 0;
#ifdef	__xpv
volatile int fastreboot_capable = 0;
#else
volatile int fastreboot_capable = 1;
#endif

#if !defined(__aarch64__)
/*
 * Information saved from current boot for fast reboot.
 * If the information size exceeds what we have allocated, fast reboot
 * will not be supported.
 */
multiboot_info_t saved_mbi;
mb_memory_map_t saved_mmap[FASTBOOT_SAVED_MMAP_COUNT];
uint8_t saved_drives[FASTBOOT_SAVED_DRIVES_SIZE];
char saved_cmdline[FASTBOOT_SAVED_CMDLINE_LEN];
int saved_cmdline_len = 0;
size_t saved_file_size[FASTBOOT_MAX_FILES_MAP];

/*
 * Turn off fastreboot_onpanic to avoid panic loop.
 */
char fastreboot_onpanic_cmdline[FASTBOOT_SAVED_CMDLINE_LEN];
static const char fastreboot_onpanic_args[] = " -B fastreboot_onpanic=0";
#endif

/*
 * Pointers to where System Resource Affinity Table (SRAT), System Locality
 * Information Table (SLIT) and Maximum System Capability Table (MSCT)
 * are mapped into virtual memory
 */
ACPI_TABLE_SRAT	*srat_ptr = NULL;
ACPI_TABLE_SLIT	*slit_ptr = NULL;
ACPI_TABLE_MSCT	*msct_ptr = NULL;

/*
 * Arbitrary limit on number of localities we handle; if
 * this limit is raised to more than UINT16_MAX, make sure
 * process_slit() knows how to handle it.
 */
#define	SLIT_LOCALITIES_MAX	(4096)

#define	SLIT_NUM_PROPNAME	"acpi-slit-localities"
#define	SLIT_PROPNAME		"acpi-slit"

/*
 * Allocate aligned physical memory at boot time. This allocator allocates
 * from the highest possible addresses. This avoids exhausting memory that
 * would be useful for DMA buffers.
 */
paddr_t
do_bop_phys_alloc(uint64_t size, uint64_t align)
{
	paddr_t	pa = 0;
	paddr_t	start;
	paddr_t	end;
	struct memlist	*ml = (struct memlist *)xbootp->bi_phys_install;

	/*
	 * Be careful if high memory usage is limited in startup.c
	 * Since there are holes in the low part of the physical address
	 * space we can treat physmem as a pfn (not just a pgcnt) and
	 * get a conservative upper limit.
	 */
	if (physmem != 0 && high_phys > pfn_to_pa(bm.physmin + physmem))
		high_phys = pfn_to_pa(bm.physmin + physmem);

	/*
	 * find the highest available memory in physinstalled
	 */
	size = P2ROUNDUP(size, align);
	for (; ml; ml = ml->ml_next) {
		start = P2ROUNDUP(ml->ml_address, align);
		end = P2ALIGN(ml->ml_address + ml->ml_size, align);
		if (start < next_phys)
			start = P2ROUNDUP(next_phys, align);
		if (end > high_phys)
			end = P2ALIGN(high_phys, align);

		if (end <= start)
			continue;
		if (end - start < size)
			continue;

		/*
		 * Early allocations need to use low memory, since
		 * physmem might be further limited by bootenv.rc
		 */
		if (early_allocation) {
			if (pa == 0 || start < pa)
				pa = start;
		} else {
			if (end - size > pa)
				pa = end - size;
		}
	}
	if (pa != 0) {
		if (early_allocation)
			next_phys = pa + size;
		else
			high_phys = pa;
		return (pa);
	}
	bop_panic("do_bop_phys_alloc(0x%" PRIx64 ", 0x%" PRIx64
	    ") Out of memory\n", size, align);
	/*NOTREACHED*/
}

uintptr_t
alloc_vaddr(size_t size, paddr_t align)
{
	uintptr_t rv;

	next_virt = P2ROUNDUP(next_virt, (uintptr_t)align);
	if (next_virt >= MAX_DYNAMIC_VA)
		bop_panic("alloc_vaddr: out of boot VA space\n");
	rv = (uintptr_t)next_virt;
	next_virt += size;
	return (rv);
}

/*
 * Allocate virtual memory. The size is always rounded up to a multiple
 * of base pagesize.
 */

/*ARGSUSED*/
static caddr_t
do_bsys_alloc(bootops_t *bop, caddr_t virthint, size_t size, int align)
{
	paddr_t a = align;	/* same type as pa for masking */
	uint_t pgsize;
	paddr_t pa;
	uintptr_t va;
	ssize_t s;		/* the aligned size */
	uint_t level;
	uint_t is_kernel = (virthint != 0);	/* XXXAARCH64: interesting... */

	if (a < MMU_PAGESIZE)
		a = MMU_PAGESIZE;
	else if (!ISP2(a))
		prom_panic("do_bsys_alloc() incorrect alignment");
	size = P2ROUNDUP(size, MMU_PAGESIZE);

	/*
	 * Use the next aligned virtual address if we weren't given one.
	 */
	if (virthint == NULL) {
		virthint = (caddr_t)alloc_vaddr(size, a);
		total_bop_alloc_scratch += size;
	} else {
		total_bop_alloc_kernel += size;
	}

	/*
	 * allocate the physical memory
	 */
	pa = do_bop_phys_alloc(size, a);

	/*
	 * Add the mappings to the page tables, try large pages first.
	 * XXXAARCH64: 2MiB is not P2 aligned.
	 * XXXAARCH64: Add 1GiB large pages
	 * XXXAARCH64: Add 64KiB contiguous
	 * XXXAARCH64: Add 32MiB contiguous
	 * XXXAARCH64: Add 16GiB contiguous
	 * XXXAARCH64: Large page stuff should happen in a loop
	 */
	va = (uintptr_t)virthint;
	s = size;
	level = 1;
	pgsize = TWO_MEG;
	if (a == pgsize) {
		while (IS_P2ALIGNED(pa, pgsize) && IS_P2ALIGNED(va, pgsize) &&
		    s >= pgsize) {
#if 0
			DBG_MSG("Requesting 2MiB kbm_map: ");
			DBG(va);
			DBG(pa);
			DBG(level);
			DBG(is_kernel);
			bop_printf(NULL, "do_bsys_alloc: calling kbm_map with "
			    "va 0x%lx, pa 0x%lx, level %d, is_kernel %d\n",
			    va, pa, level, is_kernel);
#endif
			kbm_map(va, pa, level, is_kernel);
			va += pgsize;
			pa += pgsize;
			s -= pgsize;
		}
	}

	/*
	 * Map remaining pages use small mappings
	 */
	level = 0;
	pgsize = MMU_PAGESIZE;
	while (s > 0) {
#if 0
		DBG_MSG("Requesting 4KiB kbm_map: ");
		DBG(va);
		DBG(pa);
		DBG(level);
		DBG(is_kernel);
		bop_printf(NULL, "do_bsys_alloc: calling kbm_map with va "
		    "0x%lx, pa 0x%lx, level %d, is_kernel %d\n",
		    va, pa, level, is_kernel);
#endif
		kbm_map(va, pa, level, is_kernel);
		va += pgsize;
		pa += pgsize;
		s -= pgsize;
	}
#if 0
	DBG(virthint);
#endif
	return (virthint);
}

/*
 * Free virtual memory - we'll just ignore these.
 */
/*ARGSUSED*/
static void
do_bsys_free(bootops_t *bop, caddr_t virt, size_t size)
{
	bop_printf(NULL, "do_bsys_free(virt=0x%p, size=0x%lx) ignored\n",
	    (void *)virt, size);
}

/*
 * Old interface
 */
/*ARGSUSED*/
static caddr_t
do_bsys_ealloc(bootops_t *bop, caddr_t virthint, size_t size,
    int align, int flags)
{
	prom_panic("unsupported call to BOP_EALLOC()\n");
	return (0);
}


static void
bsetprop(int flags, char *name, int nlen, void *value, int vlen)
{
	uint_t size;
	uint_t need_size;
	bootprop_t *b;

	/*
	 * align the size to 16 byte boundary
	 */
	size = sizeof (bootprop_t) + nlen + 1 + vlen;
	size = (size + 0xf) & ~0xf;
	if (size > curr_space) {
		need_size = (size + (MMU_PAGEOFFSET)) & MMU_PAGEMASK;
		curr_page = do_bsys_alloc(NULL, 0, need_size, MMU_PAGESIZE);
		curr_space = need_size;
	}

	/*
	 * use a bootprop_t at curr_page and link into list
	 */
	b = (bootprop_t *)curr_page;
	curr_page += sizeof (bootprop_t);
	curr_space -=  sizeof (bootprop_t);
	b->bp_next = bprops;
	bprops = b;

	/*
	 * follow by name and ending zero byte
	 */
	b->bp_name = curr_page;
	bcopy(name, curr_page, nlen);
	curr_page += nlen;
	*curr_page++ = 0;
	curr_space -= nlen + 1;

	/*
	 * set the property type
	 */
	b->bp_flags = flags & DDI_PROP_TYPE_MASK;

	/*
	 * copy in value, but no ending zero byte
	 */
	b->bp_value = curr_page;
	b->bp_vlen = vlen;
	if (vlen > 0) {
		bcopy(value, curr_page, vlen);
		curr_page += vlen;
		curr_space -= vlen;
	}

	/*
	 * align new values of curr_page, curr_space
	 */
	while (curr_space & 0xf) {
		++curr_page;
		--curr_space;
	}
}

static void
bsetprops(char *name, char *value)
{
	bsetprop(DDI_PROP_TYPE_STRING, name, strlen(name),
	    value, strlen(value) + 1);
}

static void
bsetprop32(char *name, uint32_t value)
{
	bsetprop(DDI_PROP_TYPE_INT, name, strlen(name),
	    (void *)&value, sizeof (value));
}

static void
bsetprop64(char *name, uint64_t value)
{
	bsetprop(DDI_PROP_TYPE_INT64, name, strlen(name),
	    (void *)&value, sizeof (value));
}

static void
bsetpropsi(char *name, int value)
{
	char prop_val[32];

	(void) snprintf(prop_val, sizeof (prop_val), "%d", value);
	bsetprops(name, prop_val);
}

/*
 * to find the type of the value associated with this name
 */
/*ARGSUSED*/
int
do_bsys_getproptype(bootops_t *bop, const char *name)
{
	bootprop_t *b;

	for (b = bprops; b != NULL; b = b->bp_next) {
		if (strcmp(name, b->bp_name) != 0)
			continue;
		return (b->bp_flags);
	}
	return (-1);
}

/*
 * to find the size of the buffer to allocate
 */
/*ARGSUSED*/
int
do_bsys_getproplen(bootops_t *bop, const char *name)
{
	bootprop_t *b;

	for (b = bprops; b; b = b->bp_next) {
		if (strcmp(name, b->bp_name) != 0)
			continue;
		return (b->bp_vlen);
	}
	return (-1);
}

/*
 * get the value associated with this name
 */
/*ARGSUSED*/
int
do_bsys_getprop(bootops_t *bop, const char *name, void *value)
{
	bootprop_t *b;

	for (b = bprops; b; b = b->bp_next) {
		if (strcmp(name, b->bp_name) != 0)
			continue;
		bcopy(b->bp_value, value, b->bp_vlen);
		return (0);
	}
	return (-1);
}

/*
 * get the name of the next property in succession from the standalone
 */
/*ARGSUSED*/
static char *
do_bsys_nextprop(bootops_t *bop, char *name)
{
	bootprop_t *b;

	/*
	 * A null name is a special signal for the 1st boot property
	 */
	if (name == NULL || strlen(name) == 0) {
		if (bprops == NULL)
			return (NULL);
		return (bprops->bp_name);
	}

	for (b = bprops; b; b = b->bp_next) {
		if (name != b->bp_name)
			continue;
		b = b->bp_next;
		if (b == NULL)
			return (NULL);
		return (b->bp_name);
	}
	return (NULL);
}

/*
 * Parse numeric value from a string. Understands decimal, hex, octal, - and ~
 */
static int
parse_value(char *p, uint64_t *retval)
{
	int adjust = 0;
	uint64_t tmp = 0;
	int digit;
	int radix = 10;

	*retval = 0;
	if (*p == '-' || *p == '~')
		adjust = *p++;

	if (*p == '0') {
		++p;
		if (*p == 0)
			return (0);
		if (*p == 'x' || *p == 'X') {
			radix = 16;
			++p;
		} else {
			radix = 8;
			++p;
		}
	}
	while (*p) {
		if ('0' <= *p && *p <= '9')
			digit = *p - '0';
		else if ('a' <= *p && *p <= 'f')
			digit = 10 + *p - 'a';
		else if ('A' <= *p && *p <= 'F')
			digit = 10 + *p - 'A';
		else
			return (-1);
		if (digit >= radix)
			return (-1);
		tmp = tmp * radix + digit;
		++p;
	}
	if (adjust == '-')
		tmp = -tmp;
	else if (adjust == '~')
		tmp = ~tmp;
	*retval = tmp;
	return (0);
}

static boolean_t
unprintable(char *value, int size)
{
	int i;

	if (size <= 0 || value[0] == '\0')
		return (B_TRUE);

	for (i = 0; i < size; i++) {
		if (value[i] == '\0')
			return (i != (size - 1));

		if (!isprint(value[i]))
			return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * Print out information about all boot properties.
 * buffer is pointer to pre-allocated space to be used as temporary
 * space for property values.
 */
static void
boot_prop_display(char *buffer)
{
	char *name = "";
	int i, len, flags, *buf32;
	int64_t *buf64;

	bop_printf(NULL, "\nBoot properties:\n");

	while ((name = do_bsys_nextprop(NULL, name)) != NULL) {
		bop_printf(NULL, "\t0x%p %s = ", (void *)name, name);
		(void) do_bsys_getprop(NULL, name, buffer);
		len = do_bsys_getproplen(NULL, name);
		flags = do_bsys_getproptype(NULL, name);
		bop_printf(NULL, "len=%d ", len);

		switch (flags) {
		case DDI_PROP_TYPE_INT:
			len = len / sizeof (int);
			buf32 = (int *)buffer;
			for (i = 0; i < len; i++) {
				bop_printf(NULL, "%08x", buf32[i]);
				if (i < len - 1)
					bop_printf(NULL, ".");
			}
			break;
		case DDI_PROP_TYPE_STRING:
			bop_printf(NULL, "%s", buffer);
			break;
		case DDI_PROP_TYPE_INT64:
			len = len / sizeof (int64_t);
			buf64 = (int64_t *)buffer;
			for (i = 0; i < len; i++) {
				bop_printf(NULL, "%016" PRIx64, buf64[i]);
				if (i < len - 1)
					bop_printf(NULL, ".");
			}
			break;
		default:
			if (!unprintable(buffer, len)) {
				buffer[len] = 0;
				bop_printf(NULL, "%s", buffer);
				break;
			}
			for (i = 0; i < len; i++) {
				bop_printf(NULL, "%02x", buffer[i] & 0xff);
				if (i < len - 1)
					bop_printf(NULL, ".");
			}
			break;
		}
		bop_printf(NULL, "\n");
	}
}

/*
 * 2nd part of building the table of boot properties. This includes:
 * - values from /boot/solaris/bootenv.rc (ie. eeprom(1m) values)
 *
 * lines look like one of:
 * ^$
 * ^# comment till end of line
 * setprop name 'value'
 * setprop name value
 * setprop name "value"
 *
 * we do single character I/O since this is really just looking at memory
 */
void
read_bootenvrc(void)
{
	int fd;
	char *line;
	int c;
	int bytes_read;
	char *name;
	int n_len;
	char *value;
	int v_len;
	char *inputdev;	/* these override the command line if serial ports */
	char *outputdev;
	char *consoledev;
	uint64_t lvalue;
	int use_xencons = 0;
	extern int bootrd_debug;

#ifdef __xpv
	if (!DOMAIN_IS_INITDOMAIN(xen_info))
		use_xencons = 1;
#endif /* __xpv */

	DBG_MSG("Opening /boot/solaris/bootenv.rc\n");
	fd = BRD_OPEN(bfs_ops, "/boot/solaris/bootenv.rc", 0);
	DBG(fd);

	line = do_bsys_alloc(NULL, NULL, MMU_PAGESIZE, MMU_PAGESIZE);
	while (fd >= 0) {

		/*
		 * get a line
		 */
		for (c = 0; ; ++c) {
			bytes_read = BRD_READ(bfs_ops, fd, line + c, 1);
			if (bytes_read == 0) {
				if (c == 0)
					goto done;
				break;
			}
			if (line[c] == '\n')
				break;
		}
		line[c] = 0;

		/*
		 * ignore comment lines
		 */
		c = 0;
		while (ISSPACE(line[c]))
			++c;
		if (line[c] == '#' || line[c] == 0)
			continue;

		/*
		 * must have "setprop " or "setprop\t"
		 */
		if (strncmp(line + c, "setprop ", 8) != 0 &&
		    strncmp(line + c, "setprop\t", 8) != 0)
			continue;
		c += 8;
		while (ISSPACE(line[c]))
			++c;
		if (line[c] == 0)
			continue;

		/*
		 * gather up the property name
		 */
		name = line + c;
		n_len = 0;
		while (line[c] && !ISSPACE(line[c]))
			++n_len, ++c;

		/*
		 * gather up the value, if any
		 */
		value = "";
		v_len = 0;
		while (ISSPACE(line[c]))
			++c;
		if (line[c] != 0) {
			value = line + c;
			while (line[c] && !ISSPACE(line[c]))
				++v_len, ++c;
		}

		if (v_len >= 2 && value[0] == value[v_len - 1] &&
		    (value[0] == '\'' || value[0] == '"')) {
			++value;
			v_len -= 2;
		}
		name[n_len] = 0;
		if (v_len > 0)
			value[v_len] = 0;
		else
			continue;

		/*
		 * ignore "boot-file" property, it's now meaningless
		 */
		if (strcmp(name, "boot-file") == 0)
			continue;
		if (strcmp(name, "boot-args") == 0 &&
		    strlen(boot_args) > 0)
			continue;

		/*
		 * If a property was explicitly set on the command line
		 * it will override a setting in bootenv.rc. We make an
		 * exception for a property from the bootloader such as:
		 *
		 * console="text,ttya,ttyb,ttyc,ttyd"
		 *
		 * In such a case, picking the first value here (as
		 * lookup_console_devices() does) is at best a guess; if
		 * bootenv.rc has a value, it's probably better.
		 */
		if (strcmp(name, "console") == 0) {
			char propval[BP_MAX_STRLEN] = "";

			if (do_bsys_getprop(NULL, name, propval) == -1 ||
			    strchr(propval, ',') != NULL)
				bsetprops(name, value);
			continue;
		}

		if (do_bsys_getproplen(NULL, name) == -1)
			bsetprops(name, value);
	}
done:
	if (fd >= 0)
		(void) BRD_CLOSE(bfs_ops, fd);


	/*
	 * Check if we have to limit the boot time allocator
	 */
	if (do_bsys_getproplen(NULL, "physmem") != -1 &&
	    do_bsys_getprop(NULL, "physmem", line) >= 0 &&
	    parse_value(line, &lvalue) != -1) {
		if (0 < lvalue && (lvalue < physmem || physmem == 0)) {
			physmem = (pgcnt_t)lvalue;
			DBG(physmem);
		}
	}

	early_allocation = 1;	/* XXXAARCH64: odd logic for ARM */

	/*
	 * Check for bootrd_debug.
	 */
	if (find_boot_prop("bootrd_debug"))
		bootrd_debug = 1;

	/*
	 * check to see if we have to override the default value of the console
	 */
	if (!use_xencons) {
		inputdev = line;
		v_len = do_bsys_getproplen(NULL, "input-device");
		if (v_len > 0)
			(void) do_bsys_getprop(NULL, "input-device", inputdev);
		else
			v_len = 0;
		inputdev[v_len] = 0;

		outputdev = inputdev + v_len + 1;
		v_len = do_bsys_getproplen(NULL, "output-device");
		if (v_len > 0)
			(void) do_bsys_getprop(NULL, "output-device",
			    outputdev);
		else
			v_len = 0;
		outputdev[v_len] = 0;

		consoledev = outputdev + v_len + 1;
		v_len = do_bsys_getproplen(NULL, "console");
		if (v_len > 0) {
			(void) do_bsys_getprop(NULL, "console", consoledev);
			if (post_fastreboot &&
			    strcmp(consoledev, "graphics") == 0) {
				bsetprops("console", "text");
				v_len = strlen("text");
				bcopy("text", consoledev, v_len);
			}
		} else {
			v_len = 0;
		}
		consoledev[v_len] = 0;
		bcons_post_bootenvrc(inputdev, outputdev, consoledev);
	} else {
		/*
		 * Ensure console property exists
		 * If not create it as "hypervisor"
		 */
		v_len = do_bsys_getproplen(NULL, "console");
		if (v_len < 0)
			bsetprops("console", "hypervisor");
		inputdev = outputdev = consoledev = "hypervisor";
		bcons_post_bootenvrc(inputdev, outputdev, consoledev);
	}

	if (find_boot_prop("prom_debug") || kbm_debug)
		boot_prop_display(line);
}

/*
 * print formatted output
 */
/*ARGSUSED*/
void
vbop_printf(void *ptr, const char *fmt, va_list ap)
{
	if (have_console == 0)
		return;

	(void) vsnprintf(buffer, BUFFERSIZE, fmt, ap);
	PUT_STRING(buffer);
}

/*PRINTFLIKE2*/
void
bop_printf(void *bop, const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	vbop_printf(bop, fmt, ap);
	va_end(ap);
}

/*
 * Another panic() variant; this one can be used even earlier during boot than
 * prom_panic().
 */
/*PRINTFLIKE1*/
void
bop_panic(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vbop_printf(NULL, fmt, ap);
	va_end(ap);

	bop_printf(NULL, "\nPress any key to reboot.\n");
	(void) bcons_getchar();
	bop_printf(NULL, "Resetting...\n");
	reset();
	bop_printf(NULL, "Reset failed, spinning...\n");
	for (;;) {}	/* XXXAARCH64: do this in ASM */
}

/*
 * Do a real mode interrupt BIOS call
 */
typedef struct bios_regs {
	unsigned short ax, bx, cx, dx, si, di, bp, es, ds;
} bios_regs_t;
typedef int (*bios_func_t)(int, bios_regs_t *);

#if defined(__aarch64__)
struct bop_regs;
#endif
/*ARGSUSED*/
static void
do_bsys_doint(bootops_t *bop, int intnum, struct bop_regs *rp)
{
#if defined(__xpv) || defined(__aarch64__)
	prom_panic("unsupported call to BOP_DOINT()\n");
#else	/* __xpv */
	static int firsttime = 1;
	bios_func_t bios_func = (bios_func_t)(void *)(uintptr_t)0x5000;
	bios_regs_t br;

	/*
	 * We're about to disable paging; we shouldn't be PCID enabled.
	 */
	if (getcr4() & CR4_PCIDE)
		prom_panic("do_bsys_doint() with PCID enabled\n");

	/*
	 * The first time we do this, we have to copy the pre-packaged
	 * low memory bios call code image into place.
	 */
	if (firsttime) {
		extern char bios_image[];
		extern uint32_t bios_size;

		bcopy(bios_image, (void *)bios_func, bios_size);
		firsttime = 0;
	}

	br.ax = rp->eax.word.ax;
	br.bx = rp->ebx.word.bx;
	br.cx = rp->ecx.word.cx;
	br.dx = rp->edx.word.dx;
	br.bp = rp->ebp.word.bp;
	br.si = rp->esi.word.si;
	br.di = rp->edi.word.di;
	br.ds = rp->ds;
	br.es = rp->es;

	DBG_MSG("Doing BIOS call...");
	DBG(br.ax);
	DBG(br.bx);
	DBG(br.dx);
	rp->eflags = bios_func(intnum, &br);
	DBG_MSG("done\n");

	rp->eax.word.ax = br.ax;
	rp->ebx.word.bx = br.bx;
	rp->ecx.word.cx = br.cx;
	rp->edx.word.dx = br.dx;
	rp->ebp.word.bp = br.bp;
	rp->esi.word.si = br.si;
	rp->edi.word.di = br.di;
	rp->ds = br.ds;
	rp->es = br.es;
#endif /* __xpv */
}

static struct boot_syscalls bop_sysp = {
	bcons_getchar,
	bcons_putchar,
	bcons_ischar,
};

static char *whoami;

#define	BUFLEN	64

#if defined(__xpv)

static char namebuf[32];

static void
xen_parse_props(char *s, char *prop_map[], int n_prop)
{
	char **prop_name = prop_map;
	char *cp = s, *scp;

	do {
		scp = cp;
		while ((*cp != '\0') && (*cp != ':'))
			cp++;

		if ((scp != cp) && (*prop_name != NULL)) {
			*cp = '\0';
			bsetprops(*prop_name, scp);
		}

		cp++;
		prop_name++;
		n_prop--;
	} while (n_prop > 0);
}

#define	VBDPATHLEN	64

/*
 * parse the 'xpv-root' property to create properties used by
 * ufs_mountroot.
 */
static void
xen_vbdroot_props(char *s)
{
	char vbdpath[VBDPATHLEN] = "/xpvd/xdf@";
	const char lnamefix[] = "/dev/dsk/c0d";
	char *pnp;
	char *prop_p;
	char mi;
	short minor;
	long addr = 0;

	mi = '\0';
	pnp = vbdpath + strlen(vbdpath);
	prop_p = s + strlen(lnamefix);
	while ((*prop_p != '\0') && (*prop_p != 's') && (*prop_p != 'p'))
		addr = addr * 10 + *prop_p++ - '0';
	(void) snprintf(pnp, VBDPATHLEN, "%lx", addr);
	pnp = vbdpath + strlen(vbdpath);
	if (*prop_p == 's')
		mi = 'a';
	else if (*prop_p == 'p')
		mi = 'q';
	else
		ASSERT(0); /* shouldn't be here */
	prop_p++;
	ASSERT(*prop_p != '\0');
	if (ISDIGIT(*prop_p)) {
		minor = *prop_p - '0';
		prop_p++;
		if (ISDIGIT(*prop_p)) {
			minor = minor * 10 + *prop_p - '0';
		}
	} else {
		/* malformed root path, use 0 as default */
		minor = 0;
	}
	ASSERT(minor < 16); /* at most 16 partitions */
	mi += minor;
	*pnp++ = ':';
	*pnp++ = mi;
	*pnp++ = '\0';
	bsetprops("fstype", "ufs");
	bsetprops("bootpath", vbdpath);

	DBG_MSG("VBD bootpath set to ");
	DBG_MSG(vbdpath);
	DBG_MSG("\n");
}

/*
 * parse the xpv-nfsroot property to create properties used by
 * nfs_mountroot.
 */
static void
xen_nfsroot_props(char *s)
{
	char *prop_map[] = {
		BP_SERVER_IP,	/* server IP address */
		BP_SERVER_NAME,	/* server hostname */
		BP_SERVER_PATH,	/* root path */
	};
	int n_prop = sizeof (prop_map) / sizeof (prop_map[0]);

	bsetprops("fstype", "nfs");

	xen_parse_props(s, prop_map, n_prop);

	/*
	 * If a server name wasn't specified, use a default.
	 */
	if (do_bsys_getproplen(NULL, BP_SERVER_NAME) == -1)
		bsetprops(BP_SERVER_NAME, "unknown");
}

/*
 * Extract our IP address, etc. from the "xpv-ip" property.
 */
static void
xen_ip_props(char *s)
{
	char *prop_map[] = {
		BP_HOST_IP,		/* IP address */
		NULL,			/* NFS server IP address (ignored in */
					/* favour of xpv-nfsroot) */
		BP_ROUTER_IP,		/* IP gateway */
		BP_SUBNET_MASK,		/* IP subnet mask */
		"xpv-hostname",		/* hostname (ignored) */
		BP_NETWORK_INTERFACE,	/* interface name */
		"xpv-hcp",		/* host configuration protocol */
	};
	int n_prop = sizeof (prop_map) / sizeof (prop_map[0]);
	char ifname[IFNAMSIZ];

	xen_parse_props(s, prop_map, n_prop);

	/*
	 * A Linux dom0 administrator expects all interfaces to be
	 * called "ethX", which is not the case here.
	 *
	 * If the interface name specified is "eth0", presume that
	 * this is really intended to be "xnf0" (the first domU ->
	 * dom0 interface for this domain).
	 */
	if ((do_bsys_getprop(NULL, BP_NETWORK_INTERFACE, ifname) == 0) &&
	    (strcmp("eth0", ifname) == 0)) {
		bsetprops(BP_NETWORK_INTERFACE, "xnf0");
		bop_printf(NULL,
		    "network interface name 'eth0' replaced with 'xnf0'\n");
	}
}

#else	/* __xpv */

static void
setup_rarp_props(struct sol_netinfo *sip)
{
	char buf[BUFLEN];	/* to hold ip/mac addrs */
	uint8_t *val;

	val = (uint8_t *)&sip->sn_ciaddr;
	(void) snprintf(buf, BUFLEN, "%d.%d.%d.%d",
	    val[0], val[1], val[2], val[3]);
	bsetprops(BP_HOST_IP, buf);

	val = (uint8_t *)&sip->sn_siaddr;
	(void) snprintf(buf, BUFLEN, "%d.%d.%d.%d",
	    val[0], val[1], val[2], val[3]);
	bsetprops(BP_SERVER_IP, buf);

	if (sip->sn_giaddr != 0) {
		val = (uint8_t *)&sip->sn_giaddr;
		(void) snprintf(buf, BUFLEN, "%d.%d.%d.%d",
		    val[0], val[1], val[2], val[3]);
		bsetprops(BP_ROUTER_IP, buf);
	}

	if (sip->sn_netmask != 0) {
		val = (uint8_t *)&sip->sn_netmask;
		(void) snprintf(buf, BUFLEN, "%d.%d.%d.%d",
		    val[0], val[1], val[2], val[3]);
		bsetprops(BP_SUBNET_MASK, buf);
	}

	if (sip->sn_mactype != 4 || sip->sn_maclen != 6) {
		bop_printf(NULL, "unsupported mac type %d, mac len %d\n",
		    sip->sn_mactype, sip->sn_maclen);
	} else {
		val = sip->sn_macaddr;
		(void) snprintf(buf, BUFLEN, "%x:%x:%x:%x:%x:%x",
		    val[0], val[1], val[2], val[3], val[4], val[5]);
		bsetprops(BP_BOOT_MAC, buf);
	}
}

#endif	/* __xpv */

#if !defined(__aarch64__)
static void
build_panic_cmdline(const char *cmd, int cmdlen)
{
	int proplen;
	size_t arglen;

	arglen = sizeof (fastreboot_onpanic_args);
	/*
	 * If we allready have fastreboot-onpanic set to zero,
	 * don't add them again.
	 */
	if ((proplen = do_bsys_getproplen(NULL, FASTREBOOT_ONPANIC)) > 0 &&
	    proplen <=  sizeof (fastreboot_onpanic_cmdline)) {
		(void) do_bsys_getprop(NULL, FASTREBOOT_ONPANIC,
		    fastreboot_onpanic_cmdline);
		if (FASTREBOOT_ONPANIC_NOTSET(fastreboot_onpanic_cmdline))
			arglen = 1;
	}

	/*
	 * construct fastreboot_onpanic_cmdline
	 */
	if (cmdlen + arglen > sizeof (fastreboot_onpanic_cmdline)) {
		DBG_MSG("Command line too long: clearing "
		    FASTREBOOT_ONPANIC "\n");
		fastreboot_onpanic = 0;
	} else {
		bcopy(cmd, fastreboot_onpanic_cmdline, cmdlen);
		if (arglen != 1)
			bcopy(fastreboot_onpanic_args,
			    fastreboot_onpanic_cmdline + cmdlen, arglen);
		else
			fastreboot_onpanic_cmdline[cmdlen] = 0;
	}
}
#endif


#if !defined(__xpv) && !defined(__aarch64__)
/*
 * Construct boot command line for Fast Reboot. The saved_cmdline
 * is also reported by "eeprom bootcmd".
 */
static void
build_fastboot_cmdline(struct xboot_info *xbp)
{
	saved_cmdline_len =  strlen(xbp->bi_cmdline) + 1;
	if (saved_cmdline_len > FASTBOOT_SAVED_CMDLINE_LEN) {
		DBG(saved_cmdline_len);
		DBG_MSG("Command line too long: clearing fastreboot_capable\n");
		fastreboot_capable = 0;
	} else {
		bcopy((void *)(xbp->bi_cmdline), (void *)saved_cmdline,
		    saved_cmdline_len);
		saved_cmdline[saved_cmdline_len - 1] = '\0';
		build_panic_cmdline(saved_cmdline, saved_cmdline_len - 1);
	}
}

/*
 * Save memory layout, disk drive information, unix and boot archive sizes for
 * Fast Reboot.
 */
static void
save_boot_info(struct xboot_info *xbi)
{
	multiboot_info_t *mbi = xbi->bi_mb_info;
	struct boot_modules *modp;
	int i;

	bcopy(mbi, &saved_mbi, sizeof (multiboot_info_t));
	if (mbi->mmap_length > sizeof (saved_mmap)) {
		DBG_MSG("mbi->mmap_length too big: clearing "
		    "fastreboot_capable\n");
		fastreboot_capable = 0;
	} else {
		bcopy((void *)(uintptr_t)mbi->mmap_addr, (void *)saved_mmap,
		    mbi->mmap_length);
	}

	if ((mbi->flags & MB_INFO_DRIVE_INFO) != 0) {
		if (mbi->drives_length > sizeof (saved_drives)) {
			DBG(mbi->drives_length);
			DBG_MSG("mbi->drives_length too big: clearing "
			    "fastreboot_capable\n");
			fastreboot_capable = 0;
		} else {
			bcopy((void *)(uintptr_t)mbi->drives_addr,
			    (void *)saved_drives, mbi->drives_length);
		}
	} else {
		saved_mbi.drives_length = 0;
		saved_mbi.drives_addr = 0;
	}

	/*
	 * Current file sizes.  Used by fastboot.c to figure out how much
	 * memory to reserve for panic reboot.
	 * Use the module list from the dboot-constructed xboot_info
	 * instead of the list referenced by the multiboot structure
	 * because that structure may not be addressable now.
	 */
	saved_file_size[FASTBOOT_NAME_UNIX] = FOUR_MEG - PAGESIZE;
	for (i = 0, modp = (struct boot_modules *)(uintptr_t)xbi->bi_modules;
	    i < xbi->bi_module_cnt; i++, modp++) {
		saved_file_size[FASTBOOT_NAME_BOOTARCHIVE] += modp->bm_size;
	}
}
#endif	/* __xpv */

/*
 * Import boot environment module variables as properties, applying
 * blacklist filter for variables we know we will not use.
 *
 * Since the environment can be relatively large, containing many variables
 * used only for boot loader purposes, we will use a blacklist based filter.
 * To keep the blacklist from growing too large, we use prefix based filtering.
 * This is possible because in many cases, the loader variable names are
 * using a structured layout.
 *
 * We will not overwrite already set properties.
 *
 * Note that the menu items in particular can contain characters not
 * well-handled as bootparams, such as spaces, brackets, and the like, so that's
 * another reason.
 */
static struct bop_blacklist {
	const char *bl_name;
	int bl_name_len;
} bop_prop_blacklist[] = {
	{ "ISADIR", sizeof ("ISADIR") },
	{ "acpi", sizeof ("acpi") },
	{ "autoboot_delay", sizeof ("autoboot_delay") },
	{ "beansi_", sizeof ("beansi_") },
	{ "beastie", sizeof ("beastie") },
	{ "bemenu", sizeof ("bemenu") },
	{ "boot.", sizeof ("boot.") },
	{ "bootenv", sizeof ("bootenv") },
	{ "currdev", sizeof ("currdev") },
	{ "dhcp.", sizeof ("dhcp.") },
	{ "interpret", sizeof ("interpret") },
	{ "kernel", sizeof ("kernel") },
	{ "loaddev", sizeof ("loaddev") },
	{ "loader_", sizeof ("loader_") },
	{ "mainansi_", sizeof ("mainansi_") },
	{ "mainmenu_", sizeof ("mainmenu_") },
	{ "maintoggled_", sizeof ("maintoggled_") },
	{ "menu_timeout_command", sizeof ("menu_timeout_command") },
	{ "menuset_", sizeof ("menuset_") },
	{ "module_path", sizeof ("module_path") },
	{ "nfs.", sizeof ("nfs.") },
	{ "optionsansi_", sizeof ("optionsansi_") },
	{ "optionsmenu_", sizeof ("optionsmenu_") },
	{ "optionstoggled_", sizeof ("optionstoggled_") },
	{ "pcibios", sizeof ("pcibios") },
	{ "prompt", sizeof ("prompt") },
	{ "smbios", sizeof ("smbios") },
	{ "tem", sizeof ("tem") },
	{ "twiddle_divisor", sizeof ("twiddle_divisor") },
	{ "zfs_be", sizeof ("zfs_be") },
};

/*
 * Match the name against prefixes in above blacklist. If the match was
 * found, this name is blacklisted.
 */
static boolean_t
name_is_blacklisted(const char *name)
{
	int i, n;

	n = sizeof (bop_prop_blacklist) / sizeof (bop_prop_blacklist[0]);
	for (i = 0; i < n; i++) {
		if (strncmp(bop_prop_blacklist[i].bl_name, name,
		    bop_prop_blacklist[i].bl_name_len - 1) == 0) {
			return (B_TRUE);
		}
	}
	return (B_FALSE);
}

static void
process_boot_environment(struct boot_modules *benv)
{
	char *env, *ptr, *name, *value;
	uint32_t size, name_len, value_len;

	if (benv == NULL || benv->bm_type != BMT_ENV)
		return;
	ptr = env = benv->bm_addr;
	size = benv->bm_size;
	do {
		name = ptr;
		/* find '=' */
		while (*ptr != '=') {
			ptr++;
			if (ptr > env + size) /* Something is very wrong. */
				return;
		}
		name_len = ptr - name;
		if (sizeof (buffer) <= name_len)
			continue;

		(void) strncpy(buffer, name, sizeof (buffer));
		buffer[name_len] = '\0';
		name = buffer;

		value_len = 0;
		value = ++ptr;
		while ((uintptr_t)ptr - (uintptr_t)env < size) {
			if (*ptr == '\0') {
				ptr++;
				value_len = (uintptr_t)ptr - (uintptr_t)env;
				break;
			}
			ptr++;
		}

		/* Did we reach the end of the module? */
		if (value_len == 0)
			return;

		if (*value == '\0')
			continue;

		/* Is this property already set? */
		if (do_bsys_getproplen(NULL, name) >= 0)
			continue;

		/* Translate netboot variables */
		if (strcmp(name, "boot.netif.gateway") == 0) {
			bsetprops(BP_ROUTER_IP, value);
			continue;
		}
		if (strcmp(name, "boot.netif.hwaddr") == 0) {
			bsetprops(BP_BOOT_MAC, value);
			continue;
		}
		if (strcmp(name, "boot.netif.ip") == 0) {
			bsetprops(BP_HOST_IP, value);
			continue;
		}
		if (strcmp(name, "boot.netif.netmask") == 0) {
			bsetprops(BP_SUBNET_MASK, value);
			continue;
		}
		if (strcmp(name, "boot.netif.server") == 0) {
			bsetprops(BP_SERVER_IP, value);
			continue;
		}
		if (strcmp(name, "boot.netif.server") == 0) {
			if (do_bsys_getproplen(NULL, BP_SERVER_IP) < 0)
				bsetprops(BP_SERVER_IP, value);
			continue;
		}
		if (strcmp(name, "boot.nfsroot.server") == 0) {
			if (do_bsys_getproplen(NULL, BP_SERVER_IP) < 0)
				bsetprops(BP_SERVER_IP, value);
			continue;
		}
		if (strcmp(name, "boot.nfsroot.path") == 0) {
			bsetprops(BP_SERVER_PATH, value);
			continue;
		}

		if (name_is_blacklisted(name) == B_TRUE)
			continue;

		/* Create new property. */
		bsetprops(name, value);

		/* Avoid reading past the module end. */
		if (size <= (uintptr_t)ptr - (uintptr_t)env)
			return;
	} while (*ptr != '\0');
}

/*
 * 1st pass at building the table of boot properties. This includes:
 * - values set on the command line: -B a=x,b=y,c=z ....
 * - known values we just compute (ie. from xbp)
 * - values from /boot/solaris/bootenv.rc (ie. eeprom(1m) values)
 *
 * the grub command line looked like:
 * kernel boot-file [-B prop=value[,prop=value]...] [boot-args]
 *
 * whoami is the same as boot-file
 */
static void
build_boot_properties(struct xboot_info *xbp)
{
	char *name;
	int name_len;
	char *value;
	int value_len;
	struct boot_modules *bm, *rdbm, *benv = NULL;
	char *propbuf;
	int quoted = 0;
	int boot_arg_len;
	uint_t i, midx;
	char modid[32];
#if !defined(__xpv) && !defined(__aarch64__)
	static int stdout_val = 0;
	uchar_t boot_device;
	char str[3];
#endif

	/*
	 * These have to be done first, so that kobj_mount_root() works
	 */
	DBG_MSG("Building boot properties\n");
	propbuf = do_bsys_alloc(NULL, NULL, MMU_PAGESIZE, 0);
	if (xbp->bi_module_cnt > 0) {
		bm = xbp->bi_modules;
		rdbm = NULL;
		for (midx = i = 0; i < xbp->bi_module_cnt; i++) {
			if (bm[i].bm_type == BMT_ROOTFS) {
				rdbm = &bm[i];
				continue;
			}
			if (bm[i].bm_type == BMT_FONT ||
			    bm[i].bm_name == NULL)
				continue;

			if (bm[i].bm_type == BMT_ENV) {
				if (benv == NULL)
					benv = &bm[i];
				else
					continue;
			}

			(void) snprintf(modid, sizeof (modid),
			    "module-name-%u", midx);
			bsetprops(modid, (char *)bm[i].bm_name);
			(void) snprintf(modid, sizeof (modid),
			    "module-addr-%u", midx);
			bsetprop64(modid, (uint64_t)(uintptr_t)bm[i].bm_addr);
			(void) snprintf(modid, sizeof (modid),
			    "module-size-%u", midx);
			bsetprop64(modid, (uint64_t)bm[i].bm_size);
			++midx;
		}
		if (rdbm != NULL) {
			bsetprop64("ramdisk_start",
			    (uint64_t)(uintptr_t)rdbm->bm_addr);
			bsetprop64("ramdisk_end",
			    (uint64_t)(uintptr_t)rdbm->bm_addr + rdbm->bm_size);
		}
	}

	DBG_MSG("Parsing command line for boot properties\n");
	value = xbp->bi_cmdline;

	/*
	 * allocate memory to collect boot_args into
	 */
	boot_arg_len = strlen(xbp->bi_cmdline) + 1;
	boot_args = do_bsys_alloc(NULL, NULL, boot_arg_len, MMU_PAGESIZE);
	boot_args[0] = 0;
	boot_arg_len = 0;

	while (ISSPACE(*value))
		++value;
	/*
	 * value now points at the boot-file
	 */
	value_len = 0;
	while (value[value_len] && !ISSPACE(value[value_len]))
		++value_len;
	if (value_len > 0) {
		whoami = propbuf;
		bcopy(value, whoami, value_len);
		whoami[value_len] = 0;
		bsetprops("boot-file", whoami);
		/*
		 * strip leading path stuff from whoami, so running from
		 * PXE/miniroot makes sense.
		 */
		if (strstr(whoami, "/platform/") != NULL)
			whoami = strstr(whoami, "/platform/");
		bsetprops("whoami", whoami);
	}

	/*
	 * Values forcibly set boot properties on the command line via -B.
	 * Allow use of quotes in values. Other stuff goes on kernel
	 * command line.
	 */
	name = value + value_len;
	while (*name != 0) {
		/*
		 * anything not " -B" is copied to the command line
		 */
		if (!ISSPACE(name[0]) || name[1] != '-' || name[2] != 'B') {
			boot_args[boot_arg_len++] = *name;
			boot_args[boot_arg_len] = 0;
			++name;
			continue;
		}

		/*
		 * skip the " -B" and following white space
		 */
		name += 3;
		while (ISSPACE(*name))
			++name;
		while (*name && !ISSPACE(*name)) {
			value = strstr(name, "=");
			if (value == NULL)
				break;
			name_len = value - name;
			++value;
			value_len = 0;
			quoted = 0;
			for (; ; ++value_len) {
				if (!value[value_len])
					break;

				/*
				 * is this value quoted?
				 */
				if (value_len == 0 &&
				    (value[0] == '\'' || value[0] == '"')) {
					quoted = value[0];
					++value_len;
				}

				/*
				 * In the quote accept any character,
				 * but look for ending quote.
				 */
				if (quoted) {
					if (value[value_len] == quoted)
						quoted = 0;
					continue;
				}

				/*
				 * a comma or white space ends the value
				 */
				if (value[value_len] == ',' ||
				    ISSPACE(value[value_len]))
					break;
			}

			if (value_len == 0) {
				bsetprop(DDI_PROP_TYPE_ANY, name, name_len,
				    NULL, 0);
			} else {
				char *v = value;
				int l = value_len;
				if (v[0] == v[l - 1] &&
				    (v[0] == '\'' || v[0] == '"')) {
					++v;
					l -= 2;
				}
				bcopy(v, propbuf, l);
				propbuf[l] = '\0';
				bsetprop(DDI_PROP_TYPE_STRING, name, name_len,
				    propbuf, l + 1);
			}
			name = value + value_len;
			while (*name == ',')
				++name;
		}
	}

	/*
	 * set boot-args property
	 * 1275 name is bootargs, so set
	 * that too
	 */
	bsetprops("boot-args", boot_args);
	bsetprops("bootargs", boot_args);

	process_boot_environment(benv);

#if 0
	/*
	 * XXXAARCH64: we don't have a trivial notion of default console
	 */
	bsetprop32("stdout", stdout_val);
#endif

	/*
	 * more conjured up values for made up things....
	 */
#if defined(__aarch64__)
	bsetprops("mfg-name", "armsbsa");
	bsetprops("impl-arch-name", "armsbsa");
#endif

	/*
	 * Build firmware-provided system properties
	 */
	build_firmware_properties(xbp);

	/*
	 * XXPV
	 *
	 * Find out what these are:
	 * - cpuid_feature_ecx_include
	 * - cpuid_feature_ecx_exclude
	 * - cpuid_feature_edx_include
	 * - cpuid_feature_edx_exclude
	 *
	 * Find out what these are in multiboot:
	 * - netdev-path
	 * - fstype
	 */
}

#ifdef __xpv
/*
 * Under the Hypervisor, memory usable for DMA may be scarce. One
 * very likely large pool of DMA friendly memory is occupied by
 * the boot_archive, as it was loaded by grub into low MFNs.
 *
 * Here we free up that memory by copying the boot archive to what are
 * likely higher MFN pages and then swapping the mfn/pfn mappings.
 */
#define	PFN_2GIG	0x80000
static void
relocate_boot_archive(struct xboot_info *xbp)
{
	mfn_t max_mfn = HYPERVISOR_memory_op(XENMEM_maximum_ram_page, NULL);
	struct boot_modules *bm = xbp->bi_modules;
	uintptr_t va;
	pfn_t va_pfn;
	mfn_t va_mfn;
	caddr_t copy;
	pfn_t copy_pfn;
	mfn_t copy_mfn;
	size_t	len;
	int slop;
	int total = 0;
	int relocated = 0;
	int mmu_update_return;
	mmu_update_t t[2];
	aarch64pte_t pte;

	/*
	 * If all MFN's are below 2Gig, don't bother doing this.
	 */
	if (max_mfn < PFN_2GIG)
		return;
	if (xbp->bi_module_cnt < 1) {
		DBG_MSG("no boot_archive!");
		return;
	}

	DBG_MSG("moving boot_archive to high MFN memory\n");
	va = (uintptr_t)bm->bm_addr;
	len = bm->bm_size;
	slop = va & MMU_PAGEOFFSET;
	if (slop) {
		va += MMU_PAGESIZE - slop;
		len -= MMU_PAGESIZE - slop;
	}
	len = P2ALIGN(len, MMU_PAGESIZE);

	/*
	 * Go through all boot_archive pages, swapping any low MFN pages
	 * with memory at next_phys.
	 */
	while (len != 0) {
		++total;
		va_pfn = mmu_btop(va - ONE_GIG);
		va_mfn = mfn_list[va_pfn];
		if (mfn_list[va_pfn] < PFN_2GIG) {
			copy = kbm_remap_window(next_phys, 1);
			bcopy((void *)va, copy, MMU_PAGESIZE);
			copy_pfn = mmu_btop(next_phys);
			copy_mfn = mfn_list[copy_pfn];

			pte = mfn_to_ma(copy_mfn) | PT_NOCONSIST | PT_VALID;
			if (HYPERVISOR_update_va_mapping(va, pte,
			    UVMF_INVLPG | UVMF_LOCAL))
				bop_panic("relocate_boot_archive():  "
				    "HYPERVISOR_update_va_mapping() failed");

			mfn_list[va_pfn] = copy_mfn;
			mfn_list[copy_pfn] = va_mfn;

			t[0].ptr = mfn_to_ma(copy_mfn) | MMU_MACHPHYS_UPDATE;
			t[0].val = va_pfn;
			t[1].ptr = mfn_to_ma(va_mfn) | MMU_MACHPHYS_UPDATE;
			t[1].val = copy_pfn;
			if (HYPERVISOR_mmu_update(t, 2, &mmu_update_return,
			    DOMID_SELF) != 0 || mmu_update_return != 2)
				bop_panic("relocate_boot_archive():  "
				    "HYPERVISOR_mmu_update() failed");

			next_phys += MMU_PAGESIZE;
			++relocated;
		}
		len -= MMU_PAGESIZE;
		va += MMU_PAGESIZE;
	}
	DBG_MSG("Relocated pages:\n");
	DBG(relocated);
	DBG_MSG("Out of total pages:\n");
	DBG(total);
}
#endif /* __xpv */

#if !defined(__xpv) && !defined(__aarch64__)
/*
 * simple description of a stack frame (args are 32 bit only currently)
 */
typedef struct bop_frame {
	struct bop_frame *old_frame;
	pc_t retaddr;
	long arg[1];
} bop_frame_t;

void
bop_traceback(bop_frame_t *frame)
{
	pc_t pc;
	int cnt;
	char *ksym;
	ulong_t off;

	bop_printf(NULL, "Stack traceback:\n");
	for (cnt = 0; cnt < 30; ++cnt) {	/* up to 30 frames */
		pc = frame->retaddr;
		if (pc == 0)
			break;
		ksym = kobj_getsymname(pc, &off);
		if (ksym)
			bop_printf(NULL, "  %s+%lx", ksym, off);
		else
			bop_printf(NULL, "  0x%lx", pc);

		frame = frame->old_frame;
		if (frame == 0) {
			bop_printf(NULL, "\n");
			break;
		}
		bop_printf(NULL, "\n");
	}
}

struct trapframe {
	ulong_t error_code;	/* optional */
	ulong_t inst_ptr;
	ulong_t code_seg;
	ulong_t flags_reg;
	ulong_t stk_ptr;
	ulong_t stk_seg;
};

void
bop_trap(ulong_t *tfp)
{
	struct trapframe *tf = (struct trapframe *)tfp;
	bop_frame_t fakeframe;
	static int depth = 0;

	/*
	 * Check for an infinite loop of traps.
	 */
	if (++depth > 2)
		bop_panic("Nested trap");

	bop_printf(NULL, "Unexpected trap\n");

	/*
	 * adjust the tf for optional error_code by detecting the code selector
	 */
	if (tf->code_seg != B64CODE_SEL)
		tf = (struct trapframe *)(tfp - 1);
	else
		bop_printf(NULL, "error code           0x%lx\n",
		    tf->error_code & 0xffffffff);

	bop_printf(NULL, "instruction pointer  0x%lx\n", tf->inst_ptr);
	bop_printf(NULL, "code segment         0x%lx\n", tf->code_seg & 0xffff);
	bop_printf(NULL, "flags register       0x%lx\n", tf->flags_reg);
	bop_printf(NULL, "return %%rsp          0x%lx\n", tf->stk_ptr);
	bop_printf(NULL, "return %%ss           0x%lx\n", tf->stk_seg & 0xffff);
	bop_printf(NULL, "%%cr2			0x%lx\n", getcr2());

	/* grab %[er]bp pushed by our code from the stack */
	fakeframe.old_frame = (bop_frame_t *)*(tfp - 3);
	fakeframe.retaddr = (pc_t)tf->inst_ptr;
	bop_printf(NULL, "Attempting stack backtrace:\n");
	bop_traceback(&fakeframe);
	bop_panic("unexpected trap in early boot");
}

extern void bop_trap_handler(void);

static gate_desc_t *bop_idt;

static desctbr_t bop_idt_info;

/*
 * Install a temporary IDT that lets us catch errors in the boot time code.
 * We shouldn't get any faults at all while this is installed, so we'll
 * just generate a traceback and exit.
 */
static void
bop_idt_init(void)
{
	int t;

	bop_idt = (gate_desc_t *)
	    do_bsys_alloc(NULL, NULL, MMU_PAGESIZE, MMU_PAGESIZE);
	bzero(bop_idt, MMU_PAGESIZE);
	for (t = 0; t < NIDT; ++t) {
		/*
		 * Note that since boot runs without a TSS, the
		 * double fault handler cannot use an alternate stack (64-bit).
		 */
		set_gatesegd(&bop_idt[t], &bop_trap_handler, B64CODE_SEL,
		    SDT_SYSIGT, TRP_KPL, 0);
	}
	bop_idt_info.dtr_limit = (NIDT * sizeof (gate_desc_t)) - 1;
	bop_idt_info.dtr_base = (uintptr_t)bop_idt;
	wr_idtr(&bop_idt_info);
}
#endif	/* !defined(__xpv) */

/*
 * This is where, after setting up a stack and neatening up the C environment,
 * we enter the kernel.  It dummies up the boot_ops and boot_syscalls vectors
 * and jumps off to _kobj_boot().
 */
void
fakebop_start(struct xboot_info *xbp)
{
	bootops_t *bops = &bootop;
	extern void _kobj_boot();

	/*
	 * First up, set the runtime services pointer so that we can panic in
	 * a reasonable way, then set up the console so that we can tell people
	 * why we're panicking in the first place!
	 */

	if (xbp && xbp->bi_uefi_systab)
		efirt = ((EFI_SYSTEM_TABLE64 *)xbp->bi_uefi_systab)
		    ->RuntimeServices;

	xbootp = xbp;
	bcons_init(xbp);
	have_console = 1;

	/*
	 * enable debugging
	 */
	if (find_boot_prop("kbm_debug") != NULL)
		kbm_debug = 1;

	kobj_debug = find_boot_prop_int("kobj_debug", 0);

	DBG_MSG("\n\n*** Entered illumos in _start() cmdline is: ");
	DBG_MSG((char *)xbp->bi_cmdline);
	DBG_MSG("\n\n\n");

	/*
	 * physavail is no longer used by startup
	 */
	bm.physinstalled = xbp->bi_phys_install;
	bm.pcimem = xbp->bi_pcimem;
	bm.rsvdmem = xbp->bi_rsvdmem;
	bm.physavail = NULL;
	bm.physmin = xbp->bi_physmin;
	bm.physmax = xbp->bi_physmax;
	DBG(bm.physmin);
	DBG(bm.physmax);

	/*
	 * initialize the boot time allocator
	 */
	high_phys = pfn_to_pa(bm.physmax);	/* might be further constrained */
	DBG(high_phys);
	next_phys = xbp->bi_next_paddr;
	DBG(next_phys);
	next_virt = (uintptr_t)xbp->bi_next_vaddr;
	DBG(next_virt);
	DBG_MSG("Initializing boot time memory management...\n");
	kbm_init(xbp);
	DBG_MSG("Boot time memory management initialized\n");

	DBG(fb_info.paddr);
	DBG(fb_info.fb_size);

	/*
	 * Fill in the bootops vector
	 */
	bops->bsys_version = BO_VERSION;
	bops->boot_mem = &bm;
	bops->bsys_alloc = do_bsys_alloc;
	bops->bsys_free = do_bsys_free;
	bops->bsys_getproplen = do_bsys_getproplen;
	bops->bsys_getprop = do_bsys_getprop;
	bops->bsys_nextprop = do_bsys_nextprop;
	bops->bsys_printf = bop_printf;
	bops->bsys_doint = do_bsys_doint;

	/*
	 * BOP_EALLOC() is no longer needed
	 */
	bops->bsys_ealloc = do_bsys_ealloc;

#if !defined(__xpv) && !defined(__aarch64__)
	/*
	 * Install an IDT to catch early pagefaults (shouldn't have any).
	 * Also needed for kmdb.
	 *
	 * XXXAARCH64: set up the vector and hook it up as per i86pc
	 */
	bop_idt_init();
#endif

	/* Set up the shadow fb for framebuffer console */
	DBG_MSG("Init shadow fb\n");
	boot_fb_shadow_init(bops);

	/*
	 * Start building the boot properties from the command line
	 */
	DBG_MSG("Initializing boot properties:\n");
	build_boot_properties(xbp);

	if (find_boot_prop("prom_debug") || kbm_debug) {
		char *value;

		value = do_bsys_alloc(NULL, NULL, MMU_PAGESIZE, MMU_PAGESIZE);
		boot_prop_display(value);
	}

	/*
	 * jump into krtld...
	 */
	_kobj_boot(&bop_sysp, NULL, bops, NULL);
}


/*ARGSUSED*/
static caddr_t
no_more_alloc(bootops_t *bop, caddr_t virthint, size_t size, int align)
{
	panic("Attempt to bsys_alloc() too late\n");
	return (NULL);
}

/*ARGSUSED*/
static void
no_more_free(bootops_t *bop, caddr_t virt, size_t size)
{
	panic("Attempt to bsys_free() too late\n");
}

void
bop_no_more_mem(void)
{
	DBG(total_bop_alloc_scratch);
	DBG(total_bop_alloc_kernel);
	bootops->bsys_alloc = no_more_alloc;
	bootops->bsys_free = no_more_free;
}


/*
 * Set ACPI firmware properties
 */

static caddr_t
vmap_phys(size_t length, paddr_t pa)
{
	paddr_t	start, end;
	caddr_t	va;
	size_t	len, page;

	start = P2ALIGN(pa, MMU_PAGESIZE);
	end = P2ROUNDUP(pa + length, MMU_PAGESIZE);
	len = end - start;
	va = (caddr_t)alloc_vaddr(len, MMU_PAGESIZE);
	for (page = 0; page < len; page += MMU_PAGESIZE) {
		kbm_map((uintptr_t)va + page, start + page, 0, 0);
	}
	return (va + (pa & MMU_PAGEOFFSET));
}

static uint8_t
checksum_table(uint8_t *tp, size_t len)
{
	uint8_t sum = 0;

	while (len-- > 0)
		sum += *tp++;

	return (sum);
}

static int
valid_rsdp(ACPI_TABLE_RSDP *rp)
{

	/* validate the V1.x checksum */
	if (checksum_table((uint8_t *)rp, ACPI_RSDP_CHECKSUM_LENGTH) != 0)
		return (0);

	/* If pre-ACPI 2.0, this is a valid RSDP */
	if (rp->Revision < 2)
		return (1);

	/* validate the V2.x checksum */
	if (checksum_table((uint8_t *)rp, ACPI_RSDP_XCHECKSUM_LENGTH) != 0)
		return (0);

	return (1);
}

/*
 * Scan memory range for an RSDP;
 * see ACPI 3.0 Spec, 5.2.5.1
 */
static ACPI_TABLE_RSDP *
scan_rsdp(paddr_t *paddrp, size_t len)
{
	paddr_t paddr = *paddrp;
	caddr_t ptr;

	ptr = vmap_phys(len, paddr);

	while (len > 0) {
		if (strncmp(ptr, ACPI_SIG_RSDP, strlen(ACPI_SIG_RSDP)) == 0 &&
		    valid_rsdp((ACPI_TABLE_RSDP *)ptr)) {
			*paddrp = paddr;
			return ((ACPI_TABLE_RSDP *)ptr);
		}

		ptr += ACPI_RSDP_SCAN_STEP;
		paddr += ACPI_RSDP_SCAN_STEP;
		len -= ACPI_RSDP_SCAN_STEP;
	}

	return (NULL);
}

/*
 * Locate the ACPI RSDP.  We search in a particular order:
 *
 * - If the bootloader told us the location of the RSDP (via the EFI system
 *   table), try that first.
 * - Otherwise, look in the EBDA and BIOS memory as per ACPI 5.2.5.1 (legacy
 *   case).
 * - Finally, our bootloader may have a copy of the RSDP in its info: this might
 *   get freed after boot, so we always prefer to find the original RSDP first.
 *
 * Once found, we set acpi-root-tab property (a physical address) for the
 * benefit of acpica, acpidump etc.
 */

static ACPI_TABLE_RSDP *
find_rsdp(struct xboot_info *xbp)
{
	ACPI_TABLE_RSDP *rsdp = NULL;
	paddr_t paddr = 0;

	if (do_bsys_getproplen(NULL, "acpi-root-tab") == sizeof (uint64_t)) {
		(void) do_bsys_getprop(NULL, "acpi-root-tab", &paddr);
		rsdp = scan_rsdp(&paddr, sizeof (*rsdp));
	}

	if (rsdp == NULL && xbp->bi_rsdp != NULL) {
		paddr = (uintptr_t)xbp->bi_rsdp;
		rsdp = scan_rsdp(&paddr, sizeof (*rsdp));
	}

	if (rsdp == NULL)
		return (NULL);

	DBG_P("RSDP found at physical 0x%lx\n", paddr);

	if (do_bsys_getproplen(NULL, "acpi-root-tab") != sizeof (uint64_t))
		bsetprop64("acpi-root-tab", paddr);

	return (rsdp);
}

static ACPI_TABLE_HEADER *
map_fw_table(paddr_t table_addr)
{
	ACPI_TABLE_HEADER *tp;
	size_t len = MAX(sizeof (*tp), MMU_PAGESIZE);

	/*
	 * Map at least a page; if the table is larger than this, remap it
	 */
	tp = (ACPI_TABLE_HEADER *)vmap_phys(len, table_addr);
	if (tp->Length < sizeof(*tp))
		bop_panic("Invalid ACPI table length\n");
	if (tp->Length > len)
		tp = (ACPI_TABLE_HEADER *)vmap_phys(tp->Length, table_addr);
	return (tp);
}

static ACPI_TABLE_XSDT *
check_xsdt(ACPI_TABLE_RSDP *rsdp)
{
	ACPI_TABLE_XSDT *xsdt;
	paddr_t xsdt_addr;

	xsdt_addr = rsdp->XsdtPhysicalAddress;
	if (xsdt_addr == 0)
		return (NULL);

	xsdt = (ACPI_TABLE_XSDT *)map_fw_table(xsdt_addr);

	if (checksum_table((uint8_t *)xsdt, xsdt->Header.Length) != 0)
		bop_printf(NULL, "XSDT fails checksum validation\n");

	if (kbm_debug) {
		ACPI_TABLE_HEADER *tp;
		paddr_t table_addr;
		int n;
		int i;
		int len = (xsdt->Header.Length - sizeof (xsdt->Header))
		    / sizeof (uint64_t);
		for (n = 0; n < len; n++) {
			table_addr = xsdt->TableOffsetEntry[n];
			if (table_addr == 0)
				continue;
			tp = map_fw_table(table_addr);
			DBG_P("Table \"");
			for (i = 0; i < ACPI_NAME_SIZE; ++i)
				DBG_P("%c", tp->Signature[i]);
			DBG_P("\" found at address 0x%lx, checksum ",
			    table_addr);
			if (checksum_table((uint8_t *)tp, tp->Length) != 0) {
				DBG_P("FAILED!\n");
			} else {
				DBG_P("OK\n");
			}
		}
	}

	return (xsdt);
}

static ACPI_TABLE_HEADER *
find_fw_table(ACPI_TABLE_XSDT *xsdt, const char *sig)
{
	int len;
	ACPI_TABLE_HEADER *tp;
	paddr_t table_addr;
	size_t sigsz;
	size_t n;

	if (xsdt == NULL)
		return (NULL);

	sigsz = strlen(sig);
	len = (xsdt->Header.Length - sizeof (xsdt->Header)) / sizeof (uint64_t);

	/*
	 * Scan the table headers looking for a signature match
	 */
	for (n = 0; n < len; n++) {
		table_addr = xsdt->TableOffsetEntry[n];
		if (table_addr == 0)
			continue;

		tp = map_fw_table(table_addr);
		if (strncmp(tp->Signature, sig, sigsz) == 0) {
			if (checksum_table((uint8_t *)tp, tp->Length) != 0) {
				bop_printf(NULL, "ACPI table '%s' fails "
				    "checksum validation\n", sig);
				return (NULL);
			}

			return (tp);
		}
	}

	return (NULL);
}

/*
 * This is truly interesting.  Do we not handle multiple root complexes?
 */
static void
process_mcfg(ACPI_TABLE_MCFG *tp)
{
	ACPI_MCFG_ALLOCATION *cfg_baap;
	char *cfg_baa_endp;
	int64_t ecfginfo[4];	/* only int64 due to DDI type limitations */

	cfg_baap = (ACPI_MCFG_ALLOCATION *)((uintptr_t)tp + sizeof (*tp));
	cfg_baa_endp = ((char *)tp) + tp->Header.Length;
	while ((char *)cfg_baap < cfg_baa_endp) {
		if (cfg_baap->Address != 0 && cfg_baap->PciSegment == 0) {
			ecfginfo[0] = cfg_baap->Address;
			ecfginfo[1] = cfg_baap->PciSegment;
			ecfginfo[2] = cfg_baap->StartBusNumber;
			ecfginfo[3] = cfg_baap->EndBusNumber;
			bsetprop(DDI_PROP_TYPE_INT64,
			    MCFG_PROPNAME, strlen(MCFG_PROPNAME),
			    ecfginfo, sizeof (ecfginfo));
			break;
		}
		cfg_baap++;
	}
}

static void
process_madt_entries(ACPI_TABLE_MADT *tp, uint32_t *cpu_countp,
    uint32_t *cpu_possible_countp,
    uint32_t *cpu_apicid_array, uint64_t *cpu_mpidr_array)
{
	ACPI_SUBTABLE_HEADER *item, *end;
	uint32_t cpu_count = 0;
	uint32_t cpu_possible_count = 0;

	if (cpu_apicid_array != NULL) {
		if (cpu_mpidr_array == NULL)
			panic("MPIDR array must be passed with "
			    "APIC ID array\n");
	}

	if (cpu_apicid_array != NULL) {
		DBG_P("ACPI MADT\n");
		DBG_P("  Address: 0x%x\n", tp->Address);
		DBG_P("  Flags: 0x%x\n", tp->Flags);
	}

	/*
	 * Determine number of CPUs and keep track of "final" APIC ID
	 * for each CPU by walking through ACPI MADT processor list
	 */
	end = (ACPI_SUBTABLE_HEADER *)(tp->Header.Length + (uintptr_t)tp);
	item = (ACPI_SUBTABLE_HEADER *)((uintptr_t)tp + sizeof (*tp));

	while (item < end) {
		switch (item->Type) {
		case ACPI_MADT_TYPE_GENERIC_INTERRUPT:
			if (cpu_apicid_array != NULL)
				DBG_MSG("MADT GIC CPU Interface (GICC)\n");
			ACPI_MADT_GENERIC_INTERRUPT *cpu =
			    (ACPI_MADT_GENERIC_INTERRUPT *) item;

			if (cpu->Flags & ACPI_MADT_ENABLED) {
				if (cpu_apicid_array != NULL)
					cpu_apicid_array[cpu_count] = cpu->Uid;
				if (cpu_mpidr_array != NULL)
					cpu_mpidr_array[cpu_count] =
					    cpu->ArmMpidr;
				if (kbm_debug && cpu_apicid_array != NULL) {
					bop_printf(NULL, "  CPU %u MIDR "
					    "Aff3 0x%lx Aff2 0x%lx "
					    "Aff1 0x%lx Aff0 0x%lx\n",
					    cpu_count,
					    (cpu->ArmMpidr >> 32) & 0xff,
					    (cpu->ArmMpidr >> 16) & 0xff,
					    (cpu->ArmMpidr >>  8) & 0xff,
					    (cpu->ArmMpidr >>  0) & 0xff);

					bop_printf(NULL,
					    "  CpuInterfaceNumber: 0x%x\n",
					    cpu->CpuInterfaceNumber);
					bop_printf(NULL,
					    "  Uid: 0x%x\n", cpu->Uid);
					bop_printf(NULL,
					    "  Flags: 0x%x\n", cpu->Flags);
					bop_printf(NULL,
					    "  ParkingVersion: 0x%x\n",
					    cpu->ParkingVersion);
					bop_printf(NULL,
					    "  PerformanceInterrupt: 0x%x\n",
					    cpu->PerformanceInterrupt);
					bop_printf(NULL,
					    "  ParkedAddress: 0x%lx\n",
					    cpu->ParkedAddress);
					bop_printf(NULL,
					    "  BaseAddress: 0x%lx\n",
					    cpu->BaseAddress);
					bop_printf(NULL,
					    "  GicvBaseAddress: 0x%lx\n",
					    cpu->GicvBaseAddress);
					bop_printf(NULL,
					    "  GichBaseAddress: 0x%lx\n",
					    cpu->GichBaseAddress);
					bop_printf(NULL,
					    "  VgicInterrupt: 0x%x\n",
					    cpu->VgicInterrupt);
					bop_printf(NULL,
					    "  GicrBaseAddress: 0x%lx\n",
					    cpu->GicrBaseAddress);
					bop_printf(NULL, "  ArmMpidr: 0x%lx\n",
					    cpu->ArmMpidr);
					bop_printf(NULL,
					    "  EfficiencyClass: 0x%x\n",
					    cpu->EfficiencyClass);
				}
				cpu_count++;
			}
			cpu_possible_count++;
			break;
		case ACPI_MADT_TYPE_GENERIC_DISTRIBUTOR:
			if (cpu_apicid_array != NULL) {
				ACPI_MADT_GENERIC_DISTRIBUTOR *dis =
				    (ACPI_MADT_GENERIC_DISTRIBUTOR *) item;
				DBG_MSG(
				    "MADT GIC Distributor Interface (GICD)\n");
				DBG_P("  GicId: 0x%x\n", dis->GicId);
				DBG_P("  BaseAddress: 0x%lx\n",
				    dis->BaseAddress);
				DBG_P("  GlobalIrqBase: %u\n",
				    dis->GlobalIrqBase);
				DBG_P("  Version: 0x%x\n", dis->Version);
				if (dis->Version < 3)
					bop_panic(
					    "GIVv3 or GICv4 is required");
				if (dis->Version > 4)
					bop_panic("No support for GICv%u yet",
					    dis->Version);
			}
			break;
		case ACPI_MADT_TYPE_GENERIC_MSI_FRAME:
			if (cpu_apicid_array != NULL) {
				ACPI_MADT_GENERIC_MSI_FRAME *msi =
				    (ACPI_MADT_GENERIC_MSI_FRAME *) item;
				DBG_MSG("MADT GIC MSI Frame\n");
				DBG_P("  MsiFrameId: 0x%x\n", msi->MsiFrameId);
				DBG_P("  BaseAddress: 0x%lx\n",
				    msi->BaseAddress);
				DBG_P("  Flags: 0x%x\n", msi->Flags);
				DBG_P("  SpiCount: 0x%x\n", msi->SpiCount);
				DBG_P("  SpiBase: 0x%x\n", msi->SpiBase);
			}
			break;
		case ACPI_MADT_TYPE_GENERIC_REDISTRIBUTOR:
			if (cpu_apicid_array != NULL) {
				ACPI_MADT_GENERIC_REDISTRIBUTOR *rds =
				    (ACPI_MADT_GENERIC_REDISTRIBUTOR *) item;
				DBG_MSG("MADT GIC Redistributor "
				    "Interface (GICR)\n");
				DBG_P("  BaseAddress: 0x%lx\n",
				    rds->BaseAddress);
				DBG_P("  Length: 0x%x\n", rds->Length);
			}
			break;
		case ACPI_MADT_TYPE_GENERIC_TRANSLATOR:
			if (cpu_apicid_array != NULL) {
				ACPI_MADT_GENERIC_TRANSLATOR *its =
				    (ACPI_MADT_GENERIC_TRANSLATOR *) item;
				DBG_MSG("MADT GIC Interrupt "
				    "Translation Service\n");
				DBG_P("  TranslationId: 0x%x\n",
				    its->TranslationId);
				DBG_P("  BaseAddress: 0x%lx\n",
				    its->BaseAddress);
			}
			break;
		default:
			if (kbm_debug)
				bop_printf(NULL, "MADT type %d\n", item->Type);
			break;
		}

		item = (ACPI_SUBTABLE_HEADER *)((uintptr_t)item + item->Length);
	}
	if (cpu_countp)
		*cpu_countp = cpu_count;
	if (cpu_possible_countp)
		*cpu_possible_countp = cpu_possible_count;
}

static void
process_madt(ACPI_TABLE_MADT *tp)
{
	uint32_t cpu_count = 0;
	uint32_t cpu_possible_count = 0;
	uint32_t *cpu_apicid_array; /* x2APIC ID is 32bit! */
	uint64_t *cpu_mpidr_array;

	if (tp != NULL) {
		/* count cpus */
		process_madt_entries(tp, &cpu_count, &cpu_possible_count,
		    NULL, NULL);

		cpu_apicid_array = (uint32_t *)do_bsys_alloc(NULL, NULL,
		    cpu_count * sizeof (*cpu_apicid_array), MMU_PAGESIZE);
		/*
		 * The following check should trigger on having more than
		 * 1024 CPUs.  That's not entirely unthinkable nowadays.
		 */
		if (cpu_apicid_array == NULL)
			bop_panic("Not enough memory for APIC ID array\n");

		cpu_mpidr_array = (uint64_t *)do_bsys_alloc(NULL, NULL,
		    cpu_count * sizeof (*cpu_mpidr_array), MMU_PAGESIZE);
		/*
		 * ... only 512 CPUs... might need to rethink things...
		 */
		if (cpu_mpidr_array == NULL)
			bop_panic("Not enough memory for APIC MPIDR array\n");

		/* copy IDs */
		process_madt_entries(tp, NULL, NULL,
		    cpu_apicid_array, cpu_mpidr_array);

		/*
		 * Make boot property for array of "final" APIC IDs for each
		 * CPU
		 */
		bsetprop(DDI_PROP_TYPE_INT,
		    BP_CPU_APICID_ARRAY, strlen(BP_CPU_APICID_ARRAY),
		    cpu_apicid_array, cpu_count * sizeof (*cpu_apicid_array));

		bsetprop(DDI_PROP_TYPE_INT64,
		    BP_CPU_MPIDR_ARRAY, strlen(BP_CPU_MPIDR_ARRAY),
		    cpu_mpidr_array, cpu_count * sizeof (*cpu_mpidr_array));
	}

	/*
	 * Check whether property plat-max-ncpus is already set.
	 */
	if (do_bsys_getproplen(NULL, PLAT_MAX_NCPUS_NAME) < 0) {
		/*
		 * Set plat-max-ncpus to number of maximum possible CPUs given
		 * in MADT if it hasn't been set.
		 * There's no formal way to detect max possible CPUs supported
		 * by platform according to ACPI spec3.0b. So current CPU
		 * hotplug implementation expects that all possible CPUs will
		 * have an entry in MADT table and set plat-max-ncpus to number
		 * of entries in MADT.
		 * With introducing of ACPI4.0, Maximum System Capability Table
		 * (MSCT) provides maximum number of CPUs supported by platform.
		 * If MSCT is unavailable, fall back to old way.
		 *
		 * For aarch64, MSCT is not mentioned in SBBR, but could be
		 * presented under section 4.2.3 Optional Tables.
		 */
		if (tp != NULL)
			bsetpropsi(PLAT_MAX_NCPUS_NAME, cpu_possible_count);
	}

	/*
	 * Set boot property boot-max-ncpus to number of CPUs existing at
	 * boot time. boot-max-ncpus is mainly used for optimization.
	 */
	if (tp != NULL)
		bsetpropsi(BOOT_MAX_NCPUS_NAME, cpu_count);

	/*
	 * User-set boot-ncpus overrides firmware count
	 */
	if (do_bsys_getproplen(NULL, BOOT_NCPUS_NAME) >= 0)
		return;

	/*
	 * Set boot property boot-ncpus to number of active CPUs given in MADT
	 * if it hasn't been set yet.
	 */
	if (tp != NULL)
		bsetpropsi(BOOT_NCPUS_NAME, cpu_count);
}

/*
 * XXXAARCH64: needs porting
 */
static void
process_srat(ACPI_TABLE_SRAT *tp)
{
	ACPI_SUBTABLE_HEADER *item, *end;
	int i;
	int proc_num, mem_num;
#pragma pack(1)
	struct {
		uint32_t domain;
		uint32_t apic_id;
		uint32_t sapic_id;
	} processor;
	struct {
		uint32_t domain;
		uint32_t x2apic_id;
	} x2apic;
	struct {
		uint32_t domain;
		uint64_t addr;
		uint64_t length;
		uint32_t flags;
	} memory;
#pragma pack()
	char prop_name[30];
	uint64_t maxmem = 0;

	if (tp == NULL)
		return;

	proc_num = mem_num = 0;
	end = (ACPI_SUBTABLE_HEADER *)(tp->Header.Length + (uintptr_t)tp);
	item = (ACPI_SUBTABLE_HEADER *)((uintptr_t)tp + sizeof (*tp));
	while (item < end) {
		switch (item->Type) {
		case ACPI_SRAT_TYPE_CPU_AFFINITY: {
			ACPI_SRAT_CPU_AFFINITY *cpu =
			    (ACPI_SRAT_CPU_AFFINITY *) item;

			if (!(cpu->Flags & ACPI_SRAT_CPU_ENABLED))
				break;
			processor.domain = cpu->ProximityDomainLo;
			for (i = 0; i < 3; i++)
				processor.domain +=
				    cpu->ProximityDomainHi[i] << ((i + 1) * 8);
			processor.apic_id = cpu->ApicId;
			processor.sapic_id = cpu->LocalSapicEid;
			(void) snprintf(prop_name, 30, "acpi-srat-processor-%d",
			    proc_num);
			bsetprop(DDI_PROP_TYPE_INT,
			    prop_name, strlen(prop_name), &processor,
			    sizeof (processor));
			proc_num++;
			break;
		}
		case ACPI_SRAT_TYPE_MEMORY_AFFINITY: {
			ACPI_SRAT_MEM_AFFINITY *mem =
			    (ACPI_SRAT_MEM_AFFINITY *)item;

			if (!(mem->Flags & ACPI_SRAT_MEM_ENABLED))
				break;
			memory.domain = mem->ProximityDomain;
			memory.addr = mem->BaseAddress;
			memory.length = mem->Length;
			memory.flags = mem->Flags;
			(void) snprintf(prop_name, 30, "acpi-srat-memory-%d",
			    mem_num);
			bsetprop(DDI_PROP_TYPE_INT,
			    prop_name, strlen(prop_name), &memory,
			    sizeof (memory));
			if ((mem->Flags & ACPI_SRAT_MEM_HOT_PLUGGABLE) &&
			    (memory.addr + memory.length > maxmem)) {
				maxmem = memory.addr + memory.length;
			}
			mem_num++;
			break;
		}
		case ACPI_SRAT_TYPE_X2APIC_CPU_AFFINITY: {
			ACPI_SRAT_X2APIC_CPU_AFFINITY *x2cpu =
			    (ACPI_SRAT_X2APIC_CPU_AFFINITY *) item;

			if (!(x2cpu->Flags & ACPI_SRAT_CPU_ENABLED))
				break;
			x2apic.domain = x2cpu->ProximityDomain;
			x2apic.x2apic_id = x2cpu->ApicId;
			(void) snprintf(prop_name, 30, "acpi-srat-processor-%d",
			    proc_num);
			bsetprop(DDI_PROP_TYPE_INT,
			    prop_name, strlen(prop_name), &x2apic,
			    sizeof (x2apic));
			proc_num++;
			break;
		}
		default:
			if (kbm_debug)
				bop_printf(NULL, "SRAT type %d\n", item->Type);
			break;
		}

		item = (ACPI_SUBTABLE_HEADER *)
		    (item->Length + (uintptr_t)item);
	}

	/*
	 * The maximum physical address calculated from the SRAT table is more
	 * accurate than that calculated from the MSCT table.
	 */
	if (maxmem != 0) {
		plat_dr_physmax = btop(maxmem);
	}
}

static void
process_slit(ACPI_TABLE_SLIT *tp)
{

	/*
	 * Check the number of localities; if it's too huge, we just
	 * return and locality enumeration code will handle this later,
	 * if possible.
	 *
	 * Note that the size of the table is the square of the
	 * number of localities; if the number of localities exceeds
	 * UINT16_MAX, the table size may overflow an int when being
	 * passed to bsetprop() below.
	 */
	if (tp->LocalityCount >= SLIT_LOCALITIES_MAX)
		return;

	bsetprop64(SLIT_NUM_PROPNAME, tp->LocalityCount);
	bsetprop(DDI_PROP_TYPE_BYTE,
	    SLIT_PROPNAME, strlen(SLIT_PROPNAME), &tp->Entry,
	    tp->LocalityCount * tp->LocalityCount);
}

static ACPI_TABLE_MSCT *
process_msct(ACPI_TABLE_MSCT *tp)
{
	int last_seen = 0;
	int proc_num = 0;
	ACPI_MSCT_PROXIMITY *item, *end;
	extern uint64_t plat_dr_options;

	ASSERT(tp != NULL);

	end = (ACPI_MSCT_PROXIMITY *)(tp->Header.Length + (uintptr_t)tp);
	for (item = (void *)((uintptr_t)tp + tp->ProximityOffset);
	    item < end;
	    item = (void *)(item->Length + (uintptr_t)item)) {
		/*
		 * Sanity check according to section 5.2.19.1 of ACPI 4.0.
		 * Revision	1
		 * Length	22
		 */
		if (item->Revision != 1 || item->Length != 22) {
			cmn_err(CE_CONT,
			    "?boot: unknown proximity domain structure in MSCT "
			    "with Revision(%d), Length(%d).\n",
			    (int)item->Revision, (int)item->Length);
			return (NULL);
		} else if (item->RangeStart > item->RangeEnd) {
			cmn_err(CE_CONT,
			    "?boot: invalid proximity domain structure in MSCT "
			    "with RangeStart(%u), RangeEnd(%u).\n",
			    item->RangeStart, item->RangeEnd);
			return (NULL);
		} else if (item->RangeStart != last_seen) {
			/*
			 * Items must be organized in ascending order of the
			 * proximity domain enumerations.
			 */
			cmn_err(CE_CONT,
			    "?boot: invalid proximity domain structure in MSCT,"
			    " items are not orginized in ascending order.\n");
			return (NULL);
		}

		/*
		 * If ProcessorCapacity is 0 then there would be no CPUs in this
		 * domain.
		 */
		if (item->ProcessorCapacity != 0) {
			proc_num += (item->RangeEnd - item->RangeStart + 1) *
			    item->ProcessorCapacity;
		}

		last_seen = item->RangeEnd - item->RangeStart + 1;
		/*
		 * Break out if all proximity domains have been processed.
		 * Some BIOSes may have unused items at the end of MSCT table.
		 */
		if (last_seen > tp->MaxProximityDomains) {
			break;
		}
	}
	if (last_seen != tp->MaxProximityDomains + 1) {
		cmn_err(CE_CONT,
		    "?boot: invalid proximity domain structure in MSCT, "
		    "proximity domain count doesn't match.\n");
		return (NULL);
	}

	/*
	 * Set plat-max-ncpus property if it hasn't been set yet.
	 */
	if (do_bsys_getproplen(NULL, PLAT_MAX_NCPUS_NAME) < 0) {
		if (proc_num != 0) {
			bsetpropsi(PLAT_MAX_NCPUS_NAME, proc_num);
		}
	}

	/*
	 * Use Maximum Physical Address from the MSCT table as upper limit for
	 * memory hot-adding by default. It may be overridden by value from
	 * the SRAT table or the "plat-dr-physmax" boot option.
	 */
	plat_dr_physmax = btop(tp->MaxAddress + 1);

	/*
	 * Existence of MSCT implies CPU/memory hotplug-capability for the
	 * platform.
	 */
	plat_dr_options |= PLAT_DR_FEATURE_CPU;
	plat_dr_options |= PLAT_DR_FEATURE_MEMORY;

	return (tp);
}

/*ARGSUSED*/
static void
build_firmware_properties(struct xboot_info *xbp)
{
	ACPI_TABLE_HEADER *tp = NULL;
	ACPI_TABLE_RSDP *rsdp;
	ACPI_TABLE_XSDT *xsdt;

	bsetprops("efi-systype", "64");
	bsetprop64("efi-systab",
	    (uint64_t)(uintptr_t)xbp->bi_uefi_systab);
	if (kbm_debug)
		bop_printf(NULL, "64-bit UEFI assumed.\n");

	if (xbp->bi_smbios3 != NULL) {
		bsetprop64("smbios-address",
		    (uint64_t)(uintptr_t)xbp->bi_smbios3);
	}

	/*
	 * XXXAARCH64: check for mandatory tables here
	 *
	 * DEN0044 ARM Base Boot Requirements 1.0
	 * 8.3.1 Mandatory ACPI tables
	 * OK RSDP (RsdtAddress must be NULL, XsdtAddress must be valid)
	 * OK XSDT
	 * OK FADT (must have the HW_REDUCED_ACPI flag, ARM_BOOT_ARCH for PSCI)
	 * DSDT (via FADT)
	 * OK SSDT (optional, 0..* of these)
	 * OK MADT
	 * OK GTDT
	 * OK DBG2 (should be exclusive for the debugger)
	 * OK SPCR (must be in DSDT)
	 * OK MCFG
	 * OK PPTT
	 * BGRT (boot graphics resource)
	 */

	rsdp = find_rsdp(xbp);
	if (rsdp == NULL)
		bop_panic("No RSDP found.\n");
	if (rsdp->Revision != 2)
		bop_panic("RSDP %u found, >=2 is required by SBBR\n",
		    rsdp->Revision);

	xsdt = check_xsdt(rsdp);
	if (xsdt == NULL)
		bop_panic("No XSDT found.\n");

	/*
	 * Let's check for the mandatory tables, including transiting the FADT
	 * to get the DSDT.
	 */

	/*
	 * The Maximum System Characteristics Table is not explicitly mentioned
	 * in the ARM SBBR 1.0, but we'll take a look at it if it's been
	 * presented to us, since it's covered by the optional tables section.
	 */
	msct_ptr = (ACPI_TABLE_MSCT *)find_fw_table(xsdt, ACPI_SIG_MSCT);
	if (msct_ptr != NULL)
		msct_ptr = process_msct(msct_ptr);

	/*
	 * The Multiple APIC Description Table is a mandatory table in the ARM
	 * SBBR, so we panic if it's not present.
	 */
	if ((tp = find_fw_table(xsdt, ACPI_SIG_MADT)) != NULL)
		process_madt((ACPI_TABLE_MADT *)tp);
	else
		bop_panic("No MADT found.\n");

	/*
	 * The System Resource Affinity and System Locality Information Tables
	 * are optional, but mandatory if on a system that implements NUMA for
	 * memory.
	 */
	if ((srat_ptr = (ACPI_TABLE_SRAT *)
	    find_fw_table(xsdt, ACPI_SIG_SRAT)) != NULL)
		process_srat(srat_ptr);

	if ((slit_ptr = (ACPI_TABLE_SLIT *)
	    find_fw_table(xsdt, ACPI_SIG_SLIT)) != NULL)
		process_slit(slit_ptr);

	/*
	 * The PCI Express Memory-mapped Configuration Space base address
	 * description table is a recommended table in the ARM SBBR.
	 */
	tp = find_fw_table(xsdt, ACPI_SIG_MCFG);
	if (tp != NULL)
		process_mcfg((ACPI_TABLE_MCFG *)tp);

	/*
	 * Map the first GTDT table (if it exists) and save the address.
	 * XXXAARCH64: this is done for TSC calibration - do we need it?
	 */
	if ((tp = find_fw_table(xsdt, ACPI_SIG_GTDT)) != NULL)
		bsetprop64("gtdt-table", (uint64_t)(uintptr_t)tp);
	else
		bop_panic("No GTDT found.\n");
}

/*
 * fake up a boot property for deferred early console output
 * this is used by both graphical boot and the (developer only)
 * USB serial console
 */
void *
defcons_init(size_t size)
{
	static char *p = NULL;

	p = do_bsys_alloc(NULL, NULL, size, MMU_PAGESIZE);
	*p = 0;
	bsetprop32("deferred-console-buf", (uint32_t)((uintptr_t)&p));
	return (p);
}

/*ARGSUSED*/
int
boot_compinfo(int fd, struct compinfo *cbp)
{
	cbp->iscmp = 0;
	cbp->blksize = MAXBSIZE;
	return (0);
}

/*
 * Get an integer value for given boot property
 */
int
bootprop_getval(const char *prop_name, u_longlong_t *prop_value)
{
	int		boot_prop_len;
	char		str[BP_MAX_STRLEN];
	u_longlong_t	value;

	boot_prop_len = BOP_GETPROPLEN(bootops, prop_name);
	if (boot_prop_len < 0 || boot_prop_len >= sizeof (str) ||
	    BOP_GETPROP(bootops, prop_name, str) < 0 ||
	    kobj_getvalue(str, &value) == -1)
		return (-1);

	if (prop_value)
		*prop_value = value;

	return (0);
}

int
bootprop_getstr(const char *prop_name, char *buf, size_t buflen)
{
	int boot_prop_len = BOP_GETPROPLEN(bootops, prop_name);

	if (boot_prop_len < 0 || boot_prop_len >= buflen ||
	    BOP_GETPROP(bootops, prop_name, buf) < 0)
		return (-1);

	return (0);
}
