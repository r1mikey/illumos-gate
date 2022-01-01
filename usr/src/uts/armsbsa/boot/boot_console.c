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
 * Copyright (c) 2012 Gary Mills
 * Copyright 2020 Joyent, Inc.
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Boot console support.  Most of the file is shared between dboot, and the
 * early kernel / fakebop.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/archsystm.h>
#include <sys/framebuffer.h>
#include <sys/boot_console.h>
#include <sys/panic.h>
#include <sys/ctype.h>
#include <sys/ascii.h>
#include <sys/vgareg.h>

#include "boot_console_impl.h"
#include "boot_serial.h"

#if defined(_BOOT)
/* #include <dboot/dboot_asm.h> */
#include <eboot/eboot_xboot.h>
#else /* _BOOT */
#include <sys/bootconf.h>
static char *defcons_buf;
static char *defcons_cur;
#endif /* _BOOT */

fb_info_t fb_info;
static bcons_dev_t bcons_dev;				/* Device callbacks */
static int console = CONS_SCREEN_TEXT;
static int diag = CONS_INVALID;
static int tty_num = 0;
static int tty_addr[] = {0x3f8, 0x2f8, 0x3e8, 0x2e8};
static char *boot_line;
static struct boot_env {
	char	*be_env;	/* ends with double ascii nul */
	size_t	be_size;	/* size of the environment, including nul */
} boot_env;
uint64_t _sbsa_dbg2_addr = 0;
uint64_t _sbsa_dbg2_type = 0;

#define	DBG2_IS_PL011()	(_sbsa_dbg2_type == 0x0003 || _sbsa_dbg2_type == 0x000e)
#define	DBG2_IS_USABLE()	(_sbsa_dbg2_addr != 0 && DBG2_IS_PL011())

/*
 * Simple console terminal emulator for early boot.
 * We need this to support kmdb, all other console output is supposed
 * to be simple text output.
 */
typedef enum btem_state_type {
	A_STATE_START,
	A_STATE_ESC,
	A_STATE_CSI,
	A_STATE_CSI_QMARK,
	A_STATE_CSI_EQUAL
} btem_state_type_t;

#define	BTEM_MAXPARAMS	5
typedef struct btem_state {
	btem_state_type_t btem_state;
	boolean_t btem_gotparam;
	int btem_curparam;
	int btem_paramval;
	int btem_params[BTEM_MAXPARAMS];
} btem_state_t;

static btem_state_t boot_tem;

static void dbg2_init(void);
static int dbg2_ischar(void);
static int dbg2_getchar(void);
static void dbg2_putchar(int);

static int serial_ischar(void);
static int serial_getchar(void);
static void serial_putchar(int);
static void serial_adjust_prop(void);

static void defcons_putchar(int);

#if !defined(_BOOT)
static boolean_t bootprop_set_tty_mode;
#endif

static int port;

static void
serial_init(void)
{
	if (console == CONS_DBG2)
		return;

#if 0
	port = tty_addr[tty_num];

	outb(port + ISR, 0x20);
	if (inb(port + ISR) & 0x20) {
		/*
		 * 82510 chip is present
		 */
		outb(port + DAT+7, 0x04);	/* clear status */
		outb(port + ISR, 0x40);  /* set to bank 2 */
		outb(port + MCR, 0x08);  /* IMD */
		outb(port + DAT, 0x21);  /* FMD */
		outb(port + ISR, 0x00);  /* set to bank 0 */
	} else {
		/*
		 * set the UART in FIFO mode if it has FIFO buffers.
		 * use 16550 fifo reset sequence specified in NS
		 * application note. disable fifos until chip is
		 * initialized.
		 */
		outb(port + FIFOR, 0x00);		/* clear */
		outb(port + FIFOR, FIFO_ON);		/* enable */
		outb(port + FIFOR, FIFO_ON|FIFORXFLSH);  /* reset */
		outb(port + FIFOR,
		    FIFO_ON|FIFODMA|FIFOTXFLSH|FIFORXFLSH|0x80);
		if ((inb(port + ISR) & 0xc0) != 0xc0) {
			/*
			 * no fifo buffers so disable fifos.
			 * this is true for 8250's
			 */
			outb(port + FIFOR, 0x00);
		}
	}

	/* disable interrupts */
	outb(port + ICR, 0);

#if !defined(_BOOT)
	if (IN_XPV_PANIC())
		return;
#endif

	/* adjust setting based on tty properties */
	serial_adjust_prop();
#endif
}

/* Advance str pointer past white space */
#define	EAT_WHITE_SPACE(str)	{			\
	while ((*str != '\0') && ISSPACE(*str))		\
		str++;					\
}

/*
 * boot_line is set when we call here.  Search it for the argument name,
 * and if found, return a pointer to it.
 */
static char *
find_boot_line_prop(const char *name)
{
	char *ptr;
	char *ret = NULL;
	char end_char;
	size_t len;

	if (boot_line == NULL)
		return (NULL);

	len = strlen(name);

	/*
	 * We have two nested loops here: the outer loop discards all options
	 * except -B, and the inner loop parses the -B options looking for
	 * the one we're interested in.
	 */
	for (ptr = boot_line; *ptr != '\0'; ptr++) {
		EAT_WHITE_SPACE(ptr);

		if (*ptr == '-') {
			ptr++;
			while ((*ptr != '\0') && (*ptr != 'B') &&
			    !ISSPACE(*ptr))
				ptr++;
			if (*ptr == '\0')
				goto out;
			else if (*ptr != 'B')
				continue;
		} else {
			while ((*ptr != '\0') && !ISSPACE(*ptr))
				ptr++;
			if (*ptr == '\0')
				goto out;
			continue;
		}

		do {
			ptr++;
			EAT_WHITE_SPACE(ptr);

			if ((strncmp(ptr, name, len) == 0) &&
			    (ptr[len] == '=')) {
				ptr += len + 1;
				if ((*ptr == '\'') || (*ptr == '"')) {
					ret = ptr + 1;
					end_char = *ptr;
					ptr++;
				} else {
					ret = ptr;
					end_char = ',';
				}
				goto consume_property;
			}

			/*
			 * We have a property, and it's not the one we're
			 * interested in.  Skip the property name.  A name
			 * can end with '=', a comma, or white space.
			 */
			while ((*ptr != '\0') && (*ptr != '=') &&
			    (*ptr != ',') && (!ISSPACE(*ptr)))
				ptr++;

			/*
			 * We only want to go through the rest of the inner
			 * loop if we have a comma.  If we have a property
			 * name without a value, either continue or break.
			 */
			if (*ptr == '\0')
				goto out;
			else if (*ptr == ',')
				continue;
			else if (ISSPACE(*ptr))
				break;
			ptr++;

			/*
			 * Is the property quoted?
			 */
			if ((*ptr == '\'') || (*ptr == '"')) {
				end_char = *ptr;
				ptr++;
			} else {
				/*
				 * Not quoted, so the string ends at a comma
				 * or at white space.  Deal with white space
				 * later.
				 */
				end_char = ',';
			}

			/*
			 * Now, we can ignore any characters until we find
			 * end_char.
			 */
consume_property:
			for (; (*ptr != '\0') && (*ptr != end_char); ptr++) {
				if ((end_char == ',') && ISSPACE(*ptr))
					break;
			}
			if (*ptr && (*ptr != ',') && !ISSPACE(*ptr))
				ptr++;
		} while (*ptr == ',');
	}
out:
	return (ret);
}

/*
 * Find prop from boot env module. The data in module is list of C strings
 * name=value, the list is terminated by double nul.
 */
static const char *
find_boot_env_prop(const char *name)
{
	char *ptr;
	size_t len;
	uintptr_t size;

	if (boot_env.be_env == NULL)
		return (NULL);

	ptr = boot_env.be_env;
	len = strlen(name);

	/*
	 * Make sure we have at least len + 2 bytes in the environment.
	 * We are looking for name=value\0 constructs, and the environment
	 * itself is terminated by '\0'.
	 */
	if (boot_env.be_size < len + 2)
		return (NULL);

	do {
		if ((strncmp(ptr, name, len) == 0) && (ptr[len] == '=')) {
			ptr += len + 1;
			return (ptr);
		}
		/* find the first '\0' */
		while (*ptr != '\0') {
			ptr++;
			size = (uintptr_t)ptr - (uintptr_t)boot_env.be_env;
			if (size > boot_env.be_size)
				return (NULL);
		}
		ptr++;

		/* If the remainder is shorter than name + 2, get out. */
		size = (uintptr_t)ptr - (uintptr_t)boot_env.be_env;
		if (boot_env.be_size - size < len + 2)
			return (NULL);
	} while (*ptr != '\0');
	return (NULL);
}

/*
 * Get prop value from either command line or boot environment.
 * We always check kernel command line first, as this will keep the
 * functionality and will allow user to override the values in environment.
 */
const char *
find_boot_prop(const char *name)
{
	const char *value = find_boot_line_prop(name);

	if (value == NULL)
		value = find_boot_env_prop(name);
	return (value);
}

#define	MATCHES(p, pat)	\
	(strncmp(p, pat, strlen(pat)) == 0 ? (p += strlen(pat), 1) : 0)

#define	SKIP(p, c)				\
	while (*(p) != 0 && *p != (c))		\
		++(p);				\
	if (*(p) == (c))			\
		++(p);

/*
 * find a tty mode property either from cmdline or from boot properties
 */
static const char *
get_mode_value(char *name)
{
	/*
	 * when specified on boot line it looks like "name" "="....
	 */
	if (boot_line != NULL) {
		return (find_boot_prop(name));
	}

#if defined(_BOOT)
	return (NULL);
#else
	/*
	 * if we're running in the full kernel we check the bootenv.rc settings
	 */
	{
		static char propval[20];

		propval[0] = 0;
		if (do_bsys_getproplen(NULL, name) <= 0)
			return (NULL);
		(void) do_bsys_getprop(NULL, name, propval);
		return (propval);
	}
#endif
}

/*
 * adjust serial port based on properties
 * These come either from the cmdline or from boot properties.
 */
static void
serial_adjust_prop(void)
{
#if 0
	char propname[20];
	const char *propval;
	const char *p;
	ulong_t baud;
	uchar_t lcr = 0;
	uchar_t mcr = DTR | RTS;

	(void) strcpy(propname, "ttyX-mode");
	propname[3] = 'a' + tty_num;
	propval = get_mode_value(propname);
#if !defined(_BOOT)
	if (propval != NULL)
		bootprop_set_tty_mode = B_TRUE;
#endif
	if (propval == NULL)
		propval = "9600,8,n,1,-";

	/* property is of the form: "9600,8,n,1,-" */
	p = propval;
	if (MATCHES(p, "110,"))
		baud = ASY110;
	else if (MATCHES(p, "150,"))
		baud = ASY150;
	else if (MATCHES(p, "300,"))
		baud = ASY300;
	else if (MATCHES(p, "600,"))
		baud = ASY600;
	else if (MATCHES(p, "1200,"))
		baud = ASY1200;
	else if (MATCHES(p, "2400,"))
		baud = ASY2400;
	else if (MATCHES(p, "4800,"))
		baud = ASY4800;
	else if (MATCHES(p, "19200,"))
		baud = ASY19200;
	else if (MATCHES(p, "38400,"))
		baud = ASY38400;
	else if (MATCHES(p, "57600,"))
		baud = ASY57600;
	else if (MATCHES(p, "115200,"))
		baud = ASY115200;
	else {
		baud = ASY9600;
		SKIP(p, ',');
	}
	outb(port + LCR, DLAB);
	outb(port + DAT + DLL, baud & 0xff);
	outb(port + DAT + DLH, (baud >> 8) & 0xff);

	switch (*p) {
	case '5':
		lcr |= BITS5;
		++p;
		break;
	case '6':
		lcr |= BITS6;
		++p;
		break;
	case '7':
		lcr |= BITS7;
		++p;
		break;
	case '8':
		++p;
		/* FALLTHROUGH */
	default:
		lcr |= BITS8;
		break;
	}

	SKIP(p, ',');

	switch (*p) {
	case 'n':
		lcr |= PARITY_NONE;
		++p;
		break;
	case 'o':
		lcr |= PARITY_ODD;
		++p;
		break;
	case 'e':
		++p;
		/* FALLTHROUGH */
	default:
		lcr |= PARITY_EVEN;
		break;
	}


	SKIP(p, ',');

	switch (*p) {
	case '1':
		/* STOP1 is 0 */
		++p;
		break;
	default:
		lcr |= STOP2;
		break;
	}
	/* set parity bits */
	outb(port + LCR, lcr);

	(void) strcpy(propname, "ttyX-rts-dtr-off");
	propname[3] = 'a' + tty_num;
	propval = get_mode_value(propname);
	if (propval == NULL)
		propval = "false";
	if (propval[0] != 'f' && propval[0] != 'F')
		mcr = 0;
	/* set modem control bits */
	outb(port + MCR, mcr | OUT2);
#endif
}

/* Obtain the console type */
int
boot_console_type(int *tnum)
{
	if (tnum != NULL)
		*tnum = tty_num;
	return (console);
}

/*
 * A structure to map console names to values.
 */
typedef struct {
	char *name;
	int value;
} console_value_t;

console_value_t console_devices[] = {
	{ "ttya", CONS_TTY },	/* 0 */
	{ "ttyb", CONS_TTY },	/* 1 */
	{ "ttyc", CONS_TTY },	/* 2 */
	{ "ttyd", CONS_TTY },	/* 3 */
	{ "dbg2", CONS_DBG2 },
	{ "text", CONS_SCREEN_TEXT },
	{ "efi", CONS_SCREEN_TEXT },
	{ "graphics", CONS_SCREEN_GRAPHICS },
#if !defined(_BOOT)
	{ "usb-serial", CONS_USBSER },
#endif
	{ NULL, CONS_INVALID }
};

static void
bcons_init_env(struct xboot_info *xbi)
{
	uint32_t i;
	struct boot_modules *modules;

	modules = (struct boot_modules *)(uintptr_t)xbi->bi_modules;
	for (i = 0; i < xbi->bi_module_cnt; i++) {
		if (modules[i].bm_type == BMT_ENV)
			break;
	}
	if (i == xbi->bi_module_cnt)
		return;

	boot_env.be_env = (char *)(uintptr_t)modules[i].bm_addr;
	boot_env.be_size = modules[i].bm_size;
}

int
boot_fb(struct xboot_info *xbi, int console)
{
	if (xbi_fb_init(xbi, &bcons_dev) == B_FALSE)
		return (console);

	/* FB address is not set, fall back to the debug port. */
	if (fb_info.paddr == 0)
		return (CONS_DBG2);

	/* XXXAARCH64: we have environment variables for this... */
	fb_info.terminal.x = VGA_TEXT_COLS;
	fb_info.terminal.y = VGA_TEXT_ROWS;
	boot_fb_init(CONS_FRAMEBUFFER);

	if (console == CONS_SCREEN_TEXT)
		return (CONS_FRAMEBUFFER);
	return (console);
}

/*
 * TODO.
 * quick and dirty local atoi. Perhaps should build with strtol, but
 * dboot & early boot mix does overcomplicate things much.
 * Stolen from libc anyhow.
 */
static int
atoi(const char *p)
{
	int n, c, neg = 0;
	unsigned char *up = (unsigned char *)p;

	if (!isdigit(c = *up)) {
		while (isspace(c))
			c = *++up;
		switch (c) {
		case '-':
			neg++;
			/* FALLTHROUGH */
		case '+':
			c = *++up;
		}
		if (!isdigit(c))
			return (0);
	}
	for (n = '0' - c; isdigit(c = *++up); ) {
		n *= 10; /* two steps to avoid unnecessary overflow */
		n += '0' - c; /* accum neg to avoid surprises at MAX */
	}
	return (neg ? n : -n);
}

/*
 * Get prop value from either command line or boot environment.
 * We always check kernel command line first, as this will keep the
 * functionality and will allow user to override the values in environment.
 */
int
find_boot_prop_int(const char *name, int defval)
{
	const char *value = find_boot_line_prop(name);

	if (value == NULL)
		value = find_boot_env_prop(name);

	if (value == NULL)
		return (defval);

	return (atoi(value));
}


static void
bcons_init_fb(void)
{
	const char *propval;
	int intval;

	/* initialize with explicit default values */
	fb_info.fg_color = CONS_COLOR;
	fb_info.bg_color = 0;
	fb_info.inverse = B_FALSE;
	fb_info.inverse_screen = B_FALSE;

	/* color values are 0 - 255 */
	propval = find_boot_prop("tem.fg_color");
	if (propval != NULL) {
		intval = atoi(propval);
		if (intval >= 0 && intval <= 255)
			fb_info.fg_color = intval;
	}

	/* color values are 0 - 255 */
	propval = find_boot_prop("tem.bg_color");
	if (propval != NULL && ISDIGIT(*propval)) {
		intval = atoi(propval);
		if (intval >= 0 && intval <= 255)
			fb_info.bg_color = intval;
	}

	/* get inverses. allow 0, 1, true, false */
	propval = find_boot_prop("tem.inverse");
	if (propval != NULL) {
		if (*propval == '1' || MATCHES(propval, "true"))
			fb_info.inverse = B_TRUE;
	}

	propval = find_boot_prop("tem.inverse-screen");
	if (propval != NULL) {
		if (*propval == '1' || MATCHES(propval, "true"))
			fb_info.inverse_screen = B_TRUE;
	}

#if defined(_BOOT)
	/*
	 * Load cursor position from bootloader only in dboot,
	 * dboot will pass cursor position to kernel via xboot info.
	 */
	propval = find_boot_prop("tem.cursor.row");
	if (propval != NULL) {
		intval = atoi(propval);
		if (intval >= 0 && intval <= 0xFFFF)
			fb_info.cursor.pos.y = intval;
	}

	propval = find_boot_prop("tem.cursor.col");
	if (propval != NULL) {
		intval = atoi(propval);
		if (intval >= 0 && intval <= 0xFFFF)
			fb_info.cursor.pos.x = intval;
	}
#endif
}

/*
 * Go through the known console device names trying to match the string we were
 * given.  The string on the command line must end with a comma or white space.
 *
 * For convenience, we provide the caller with an integer index for the CONS_TTY
 * case.
 */
static int
lookup_console_device(const char *cons_str, int *indexp)
{
	int n, cons;
	size_t len, cons_len;
	console_value_t *consolep;

	cons = CONS_INVALID;
	if (cons_str != NULL) {

		cons_len = strlen(cons_str);
		for (n = 0; console_devices[n].name != NULL; n++) {
			consolep = &console_devices[n];
			len = strlen(consolep->name);
			if ((len <= cons_len) && ((cons_str[len] == '\0') ||
			    (cons_str[len] == ',') || (cons_str[len] == '\'') ||
			    (cons_str[len] == '"') || ISSPACE(cons_str[len])) &&
			    (strncmp(cons_str, consolep->name, len) == 0)) {
				cons = consolep->value;
				if (cons == CONS_TTY)
					*indexp = n;
				break;
			}
		}
	}
	return (cons);
}

void
bcons_init(struct xboot_info *xbi)
{
	const char *cons_str;

	if (xbi == NULL) {
		console = CONS_INVALID;
#if !defined(_BOOT)
		diag = CONS_INVALID;
#else
		/* This is very early eboot console, set up dbg2. */
		diag = CONS_DBG2;
		dbg2_init();
#endif
		return;
	}

#if defined(_BOOT)
	_sbsa_dbg2_addr = xbi->bi_dbg2_pa;
#else
	_sbsa_dbg2_addr = xbi->bi_dbg2_va;
#endif
	_sbsa_dbg2_type = xbi->bi_dbg2_type;

	/* Set up data to fetch properties from the command line and boot env */
	boot_line = (char *)(uintptr_t)xbi->bi_cmdline;
	bcons_init_env(xbi);
	console = CONS_INVALID;

	/* set up initial fb_info */
	bcons_init_fb();

	/*
	 * First check for diag-device.
	 */
	cons_str = find_boot_prop("diag-device");
	if (cons_str != NULL)
		diag = lookup_console_device(cons_str, &tty_num);

	cons_str = find_boot_prop("console");
	if (cons_str == NULL)
		cons_str = find_boot_prop("output-device");

	if (cons_str != NULL)
		console = lookup_console_device(cons_str, &tty_num);

	if (console == CONS_INVALID)
		console = CONS_SCREEN_TEXT;

	/* make sure the FB is set up if present */
	console = boot_fb(xbi, console);

	switch (console) {
	case CONS_DBG2:
		/*
		 * The DBG2 interface has been set up by the firmware already,
		 * so there's nothing more for us to do.
		 */
		break;
	case CONS_TTY:
		serial_init();
		break;

	case CONS_HYPERVISOR:
		break;

#if !defined(_BOOT)
	case CONS_USBSER:
		/*
		 * We can't do anything with the usb serial
		 * until we have memory management.
		 */
		break;
#endif
#if !defined(__aarch64__)
	case CONS_SCREEN_GRAPHICS:
		kb_init();
		break;
#endif
#if !defined(__aarch64__)
	case CONS_SCREEN_TEXT:
		boot_vga_init(&bcons_dev);
		/* Fall through */
#endif
	default:
#if !defined(__aarch64__)
		kb_init();
#endif
		break;
	}

	/*
	 * Initialize diag device unless already done.
	 */
	switch (diag) {
	case CONS_DBG2:
		/* DBG2 already initialised by the firmware */
		break;
	case CONS_TTY:
		if (console != CONS_TTY)
			serial_init();
		break;
	case CONS_SCREEN_GRAPHICS:
	case CONS_SCREEN_TEXT:
		if (console != CONS_SCREEN_GRAPHICS &&
		    console != CONS_SCREEN_TEXT)
#if !defined(__aarch64__)
			kb_init();
#else
			;
#endif
		break;
	default:
		break;
	}
}

static uint32_t
dbg2_ioread32(uint64_t addr)
{
	volatile uint32_t *a;
	a = (volatile uint32_t *)addr;
	return *a;
}

static void
dbg2_iowrite32(uint64_t addr, uint32_t v)
{
	volatile uint32_t *a;
	a = (volatile uint32_t *)addr;
	*a = v;
}

#if defined(_BOOT)
/* XXXAARCH64: this must go */
void
dbg2_preinit(uint64_t pa, uint64_t type)
{
	int checks = 10000;
	console = CONS_INVALID;
	diag = CONS_DBG2;
	_sbsa_dbg2_addr = pa;
	_sbsa_dbg2_type = type;
	uint32_t cr;

	cr = dbg2_ioread32(_sbsa_dbg2_addr + 0x30);
	cr |= 0x300;
	dbg2_iowrite32(_sbsa_dbg2_addr + 0x30, cr);

	while (dbg2_ischar() && checks--)
		(void) dbg2_getchar();
}
#endif

static void
dbg2_init(void)
{
	int checks = 10000;

	if (!(DBG2_IS_USABLE()))
		return;

	if (DBG2_IS_PL011())
		dbg2_iowrite32(_sbsa_dbg2_addr + 0x30,
		    dbg2_ioread32(_sbsa_dbg2_addr + 0x30) | 0x301);

	while (dbg2_ischar() && checks--)
		(void) dbg2_getchar();
}

static int
dbg2_ischar(void)
{
	if (!DBG2_IS_USABLE() || !DBG2_IS_PL011())
		return (0);

	return ((dbg2_ioread32(_sbsa_dbg2_addr + 0x18) & (1U << 4)) == 0);
}

static int
dbg2_getchar(void)
{
	uint32_t dr;

	if (!DBG2_IS_USABLE() || !DBG2_IS_PL011())
		return (0);

	while (dbg2_ischar() == 0)
		;

	dr = dbg2_ioread32(_sbsa_dbg2_addr);
	if (dr & 0x700) /* FE, PE, BE */
		return (0);

	return (dr & 0xff);
}

static void
dbg2_putchar(int c)
{
	int checks = 10000;

	if (!DBG2_IS_USABLE() || !DBG2_IS_PL011())
		return;

	while (dbg2_ioread32(_sbsa_dbg2_addr + 0x18) & (1UL << 7) == 0 &&
	    checks--)
		;
	dbg2_iowrite32(_sbsa_dbg2_addr, c);
}

static void
serial_putchar(int c)
{
#if !defined(__aarch64__)
	int checks = 10000;

	while (((inb(port + LSR) & XHRE) == 0) && checks--)
		;
	outb(port + DAT, (char)c);
#else
	dbg2_putchar(c);
#endif
}

static int
serial_getchar(void)
{
#if !defined(__aarch64__)
	uchar_t lsr;

	while (serial_ischar() == 0)
		;

	lsr = inb(port + LSR);
	if (lsr & (SERIAL_BREAK | SERIAL_FRAME |
	    SERIAL_PARITY | SERIAL_OVERRUN)) {
		if (lsr & SERIAL_OVERRUN) {
			return (inb(port + DAT));
		} else {
			/* Toss the garbage */
			(void) inb(port + DAT);
			return (0);
		}
	}
	return (inb(port + DAT));
#else
	return (dbg2_getchar());
#endif
}

static int
serial_ischar(void)
{
#if !defined(__aarch64__)
	return (inb(port + LSR) & RCA);
#else
	return (dbg2_ischar());
#endif
}

static void
btem_control(btem_state_t *btem, int c)
{
	int y, rows, cols;

	rows = fb_info.cursor.pos.y;
	cols = fb_info.cursor.pos.x;

	btem->btem_state = A_STATE_START;
	switch (c) {
	case A_BS:
		bcons_dev.bd_setpos(rows, cols - 1);
		break;

	case A_HT:
		cols += 8 - (cols % 8);
		if (cols >= fb_info.terminal.x)
			cols = fb_info.terminal.x - 1;
		bcons_dev.bd_setpos(rows, cols);
		break;

	case A_CR:
		bcons_dev.bd_setpos(rows, 0);
		break;

	case A_FF:
		for (y = 0; y < fb_info.terminal.y; y++) {
			bcons_dev.bd_setpos(y, 0);
			bcons_dev.bd_eraseline();
		}
		bcons_dev.bd_setpos(0, 0);
		break;

	case A_ESC:
		btem->btem_state = A_STATE_ESC;
		break;

	default:
		bcons_dev.bd_putchar(c);
		break;
	}
}

/*
 * if parameters [0..count - 1] are not set, set them to the value
 * of newparam.
 */
static void
btem_setparam(btem_state_t *btem, int count, int newparam)
{
	int i;

	for (i = 0; i < count; i++) {
		if (btem->btem_params[i] == -1)
			btem->btem_params[i] = newparam;
	}
}

static void
btem_chkparam(btem_state_t *btem, int c)
{
	int rows, cols;

	rows = fb_info.cursor.pos.y;
	cols = fb_info.cursor.pos.x;
	switch (c) {
	case '@':			/* insert char */
		btem_setparam(btem, 1, 1);
		bcons_dev.bd_shift(btem->btem_params[0]);
		break;

	case 'A':			/* cursor up */
		btem_setparam(btem, 1, 1);
		bcons_dev.bd_setpos(rows - btem->btem_params[0], cols);
		break;

	case 'B':			/* cursor down */
		btem_setparam(btem, 1, 1);
		bcons_dev.bd_setpos(rows + btem->btem_params[0], cols);
		break;

	case 'C':			/* cursor right */
		btem_setparam(btem, 1, 1);
		bcons_dev.bd_setpos(rows, cols + btem->btem_params[0]);
		break;

	case 'D':			/* cursor left */
		btem_setparam(btem, 1, 1);
		bcons_dev.bd_setpos(rows, cols - btem->btem_params[0]);
		break;

	case 'K':
		bcons_dev.bd_eraseline();
		break;
	default:
		/* bcons_dev.bd_putchar(c); */
		break;
	}
	btem->btem_state = A_STATE_START;
}

static void
btem_getparams(btem_state_t *btem, int c)
{
	if (isdigit(c)) {
		btem->btem_paramval = btem->btem_paramval * 10 + c - '0';
		btem->btem_gotparam = B_TRUE;
		return;
	}

	if (btem->btem_curparam < BTEM_MAXPARAMS) {
		if (btem->btem_gotparam == B_TRUE) {
			btem->btem_params[btem->btem_curparam] =
			    btem->btem_paramval;
		}
		btem->btem_curparam++;
	}

	if (c == ';') {
		/* Restart parameter search */
		btem->btem_gotparam = B_FALSE;
		btem->btem_paramval = 0;
	} else {
		btem_chkparam(btem, c);
	}
}

/* Simple boot terminal parser. */
static void
btem_parse(btem_state_t *btem, int c)
{
	int i;

	/* Normal state? */
	if (btem->btem_state == A_STATE_START) {
		if (c == A_CSI || c < ' ')
			btem_control(btem, c);
		else
			bcons_dev.bd_putchar(c);
		return;
	}

	/* In <ESC> sequence */
	if (btem->btem_state != A_STATE_ESC) {
		btem_getparams(btem, c);
		return;
	}

	/* Previous char was <ESC> */
	switch (c) {
	case '[':
		btem->btem_curparam = 0;
		btem->btem_paramval = 0;
		btem->btem_gotparam = B_FALSE;
		/* clear the parameters */
		for (i = 0; i < BTEM_MAXPARAMS; i++)
			btem->btem_params[i] = -1;
		btem->btem_state = A_STATE_CSI;
		return;

	case 'Q':	/* <ESC>Q */
	case 'C':	/* <ESC>C */
		btem->btem_state = A_STATE_START;
		return;

	default:
		btem->btem_state = A_STATE_START;
		break;
	}

	if (c < ' ')
		btem_control(btem, c);
	else
		bcons_dev.bd_putchar(c);
}

static void
_doputchar(int device, int c)
{
	switch (device) {
	case CONS_DBG2:
		dbg2_putchar(c);
		return;
	case CONS_TTY:
		serial_putchar(c);
		return;
	case CONS_SCREEN_TEXT:
	case CONS_FRAMEBUFFER:
		bcons_dev.bd_cursor(B_FALSE);
		btem_parse(&boot_tem, c);
		bcons_dev.bd_cursor(B_TRUE);
		return;
	case CONS_SCREEN_GRAPHICS:
#if !defined(_BOOT)
	case CONS_USBSER:
		defcons_putchar(c);
#endif /* _BOOT */
	default:
		return;
	}
}

void
bcons_putchar(int c)
{
	if (c == '\n') {
		_doputchar(console, '\r');
		if (diag != console)
			_doputchar(diag, '\r');
	}

	_doputchar(console, c);
	if (diag != console)
		_doputchar(diag, c);
}

/*
 * kernel character input functions
 */
int
bcons_getchar(void)
{
	for (;;) {
		if (console == CONS_DBG2 || diag == CONS_DBG2) {
			if (dbg2_ischar())
				return (dbg2_getchar());
		}
		if (console == CONS_TTY || diag == CONS_TTY) {
			if (serial_ischar())
				return (serial_getchar());
		}
		if (console != CONS_INVALID || diag != CONS_INVALID) {
			if (kb_ischar())
				return (kb_getchar());
		}
	}
}

/*
 * Nothing below is used by [de]boot.
 */
#if !defined(_BOOT)

int
bcons_ischar(void)
{
	int c = 0;

	switch (console) {
	case CONS_DBG2:
		c = dbg2_ischar();
		break;

	case CONS_TTY:
		c = serial_ischar();
		break;

	case CONS_INVALID:
		break;

	default:
		c = kb_ischar();
	}
	if (c != 0)
		return (c);

	switch (diag) {
	case CONS_DBG2:
		c = dbg2_ischar();
		break;

	case CONS_TTY:
		c = serial_ischar();
		break;

	case CONS_INVALID:
		break;

	default:
		c = kb_ischar();
	}

	return (c);
}

/*
 * 2nd part of console initialization: we've now processed bootenv.rc; update
 * console settings as appropriate. This only really processes serial console
 * modifications.
 */
void
bcons_post_bootenvrc(char *inputdev, char *outputdev, char *consoledev)
{
	int cons = CONS_INVALID;
	int ttyn;
	char *devnames[] = { consoledev, outputdev, inputdev, NULL };
	console_value_t *consolep;
	int i;

	ttyn = 0;
	/* XXXAARCH64: was also protected by post_fastreboot */
	if (console == CONS_SCREEN_GRAPHICS)
		console = CONS_SCREEN_TEXT;

	/*
	 * USB serial and GRAPHICS console: we just collect data into a buffer.
	 */
	if (console == CONS_USBSER || console == CONS_SCREEN_GRAPHICS) {
		extern void *defcons_init(size_t);
		defcons_buf = defcons_cur = defcons_init(MMU_PAGESIZE);
		return;
	}

	for (i = 0; devnames[i] != NULL; i++) {
		cons = lookup_console_device(devnames[i], &ttyn);
		if (cons != CONS_INVALID)
			break;
	}

	if (cons == CONS_INVALID) {
		/*
		 * No console change, but let's see if bootenv.rc had a mode
		 * setting we should apply.
		 */
		if (console == CONS_TTY && !bootprop_set_tty_mode)
			serial_init();
		return;
	}

	console = cons;

	if (console == CONS_TTY) {
		tty_num = ttyn;
		serial_init();
	}
}

static void
defcons_putchar(int c)
{
	if (defcons_buf != NULL &&
	    defcons_cur + 1 - defcons_buf < MMU_PAGESIZE) {
		*defcons_cur++ = c;
		*defcons_cur = 0;
	}
}

#endif /* _BOOT */
