#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/bootinfo.h>
#include <sys/bootsvcs.h>
#include <sys/efi.h>
#include <sys/efifb.h>
#include <sys/framebuffer.h>
#include <sys/smbios.h>
#include <sys/acpi/platform/acsolaris.h>
#undef strtoul
#include <sys/acpi/actypes.h>
#include <sys/acpi/actbl.h>
#include <sys/promif.h>
#include <sys/platform.h>
#include <asm/controlregs.h>
#include <string.h>
#include "dbg2.h"
#include "preload.h"
#include "uefi.h"
#include "shim.h"
#include "boot_plat.h"

/* #include "console.h" */

int debug = 1;
int verbosemode = 1;
int boothowto = 0;

extern void init_memlists(void);
extern void bootflags(char *args, size_t argsz);

uint64_t boot_args[6];
static struct xboot_info xboot_info;
struct xboot_info *bi = &xboot_info;

static boot_framebuffer_t framebuffer __aligned(16) = {
	0,                              /* framebuffer - efi_fb */
	/* origin.x, origin.y, pos.y, pos.y, visible */
	{ { 0, 0 }, { 0, 0 }, 0 }
};
static boot_framebuffer_t *fb = NULL;

static struct boot_modules boot_modules[MAX_BOOT_MODULES] = {
	{ 0, 0, 0, BMT_ROOTFS },
};

extern struct efi_map_header *efi_map_header;

struct memlist *pfreelistp;
struct memlist *pscratchlistp;
struct memlist *pinstalledp;
struct memlist *piolistp;
struct memlist *ptmplistp;
struct memlist *plinearlistp;
struct memlist *pfwcodelistp;
struct memlist *pfwdatalistp;

typedef int     (*func_t)();
extern func_t load_elf_payload(caddr_t payload, size_t payload_size, int print);
extern void exitto(int (*entrypoint)());

void
_reset(void)
{
	uefi_reset();
}

int
main(uint64_t args[6])
{
	uint64_t uefi_memmap;
	uint64_t uefi_fb;
	uint64_t payload;
	uint64_t payload_size;
	int has_boot_archive;
	uint64_t i;
	func_t entry;

	uefi_memmap = 0;
	uefi_fb = 0;
	payload = 0;
	payload_size = 0;
	has_boot_archive = 0;
	bi->bi_modules = (uint64_t)&boot_modules[0];
	bi->bi_module_cnt = 0;
	fb = &framebuffer;

	dbg2_preinit();

	if (prekern_process_modules(
	    (caddr_t)args[0], bi, &uefi_memmap, &uefi_fb,
	    &payload, &payload_size) != 0)
		return (-1);

	efi_map_header = (struct efi_map_header *)uefi_memmap;
	if (efi_map_header == NULL)
		return (-1);

	fb->framebuffer = uefi_fb;
	if (fb->framebuffer != 0)
		bi->bi_framebuffer = (uint64_t)fb;

	if (init_uefi(bi) != 0)
		return (-1);

	if (bi->bi_cmdline != 0) {
		bootflags(
		    (char *)bi->bi_cmdline, strlen((char *)bi->bi_cmdline));
	}
	bi->bi_boothowto = (uint64_t)boothowto;

	if (payload == 0 || payload_size == 0) {
		dbg2_puts("shim: No payload (UNIX) passed.\n");
		return (-1);
	}

	for (i = 0; i < bi->bi_module_cnt; ++i) {
		if (boot_modules[i].bm_type == BMT_ROOTFS) {
			has_boot_archive = 1;
			break;
		}
	}

	if (!has_boot_archive) {
		dbg2_puts("shim: No boot archive passed.\n");
		return (-1);
	}

	fiximp();
	init_memlists();
	init_memory();

	dbg2_puts("booya - let's go!\n");
	/*
	 * As a bodge, we have the kernel to boot in memory already (thanks loader!)
	 * Grab phdrs etc. from that and hoist it up into memory, set up mapping
	 * and boot it.
	 *
	 * What could we do? We could pick up the kernel from the boot archive, but
	 * that means a loss of control for folks using the system.
	 */

	entry = load_elf_payload((caddr_t)payload, (size_t)payload_size, 0);
	if (entry == ((func_t)-1))
		dbg2_panic("Unable to load ELF payload\n");
	exitto(entry);
	dbg2_printf("Kernel returned to us\n");
	for (;;) ;
	return (0);
}
