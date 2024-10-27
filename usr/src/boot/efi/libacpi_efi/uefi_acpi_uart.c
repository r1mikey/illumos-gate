/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2024 Michael van der Westhuizen
 */

/*
 * UEFI/ACPI UART implementation.
 *
 * This file is responsible for discovering compatible UARTs, then capturing
 * necessary information about them. The UARts are then turned into consoles
 * for consumption by the loader.
 */

#include <acpi.h>
#include <aclocal.h>
#include <acobject.h>
#include <acstruct.h>
#include <acnamesp.h>
#include <acutils.h>
#include <acmacros.h>
#include <acevents.h>

#include <bootstrap.h>

#include <stdio.h>

#include "pl011.h"
#include "uefi_acpi_uart.h"

/* XXXARM these defines don't make sense here */

#ifndef	COMSPEED
#define	COMSPEED	9600
#endif

#define	STOP1		0x00
#define	STOP2		0x04

#define	PARODD		0x00
#define	PAREN		0x08
#define	PAREVN		0x10
#define	PARMARK		0x20

#define	BITS5		0x00	/* 5 bits per char */
#define	BITS6		0x01	/* 6 bits per char */
#define	BITS7		0x02	/* 7 bits per char */
#define	BITS8		0x03	/* 8 bits per char */

#define	MAX_UARTS	8

typedef ACPI_STATUS (*uart_processor_t)(ACPI_HANDLE, ACPI_DEVICE_INFO *, void *, void **);

typedef struct known_uart {
	const char		hid[32];
	size_t			hid_len;
	uart_processor_t	processor;
} known_uart_t;

static ACPI_STATUS process_armh0011(ACPI_HANDLE handle, ACPI_DEVICE_INFO *obj, void *context, void **b);

static known_uart_t known_uarts[] = {
	{ .hid = "ARMH0011", .hid_len = 9, .processor = process_armh0011 }
};
static size_t num_known_uarts = sizeof (known_uarts) / sizeof (known_uarts[0]);

#define	ARMH0011_VALID_ADDR	0x1
#define	ARMH0011_VALID_ADDR_LEN	0x2
#define	ARMH0011_VALID_IRQ	0x4

static pl011_info_t armh0011_info[MAX_UARTS] = { { .addr = 0 } };
static size_t num_armh0011_info = 0;

static acpi_uart_t acpi_uart[MAX_UARTS] = { { .info = NULL } };
static size_t num_acpi_uart = 0;

static ACPI_STATUS
add_uart(const char *acpi_name, const char *acpi_hid, const char *acpi_uid, const uefi_acpi_uart_ops_t *ops, void *info)
{
	if (num_acpi_uart >= MAX_UARTS)
		return (AE_LIMIT);

	acpi_uart[num_acpi_uart].name[0] = 't';
	acpi_uart[num_acpi_uart].name[1] = 't';
	acpi_uart[num_acpi_uart].name[2] = 'y';
	acpi_uart[num_acpi_uart].name[3] = 'a' + num_acpi_uart;
	acpi_uart[num_acpi_uart].name[4] = '\0';
	acpi_uart[num_acpi_uart].info = info;

	strncpy(acpi_uart[num_acpi_uart].acpi_hid, acpi_hid, sizeof (acpi_uart[num_acpi_uart].acpi_hid));
	acpi_uart[num_acpi_uart].acpi_hid[sizeof (acpi_uart[num_acpi_uart].acpi_hid) - 1] = '\0';

	strncpy(acpi_uart[num_acpi_uart].acpi_name, acpi_name, sizeof (acpi_uart[num_acpi_uart].acpi_name));
	acpi_uart[num_acpi_uart].acpi_name[sizeof (acpi_uart[num_acpi_uart].acpi_name) - 1] = '\0';

	strncpy(acpi_uart[num_acpi_uart].acpi_uid, acpi_uid, sizeof (acpi_uart[num_acpi_uart].acpi_uid));
	acpi_uart[num_acpi_uart].acpi_uid[sizeof (acpi_uart[num_acpi_uart].acpi_uid) - 1] = '\0';

	acpi_uart[num_acpi_uart].ops = ops;

	++num_acpi_uart;
	return (AE_OK);
}

static ACPI_STATUS
armh0011_crs_cb(ACPI_RESOURCE *rp, void *context)
{
	ACPI_STATUS status = AE_OK;
	pl011_info_t *uart = context;

	switch (rp->Type) {
	case ACPI_RESOURCE_TYPE_IRQ:
		if (rp->Data.Irq.InterruptCount != 1) {
			status = AE_SUPPORT;
		} else if ((uart->valid & ARMH0011_VALID_IRQ) != 0) {
			uart->valid &= (~ARMH0011_VALID_IRQ);
			status = AE_SUPPORT;
		} else {
			uart->irq = rp->Data.Irq.Interrupts[0];
			uart->valid |= ARMH0011_VALID_IRQ;
		}

		break;
	case ACPI_RESOURCE_TYPE_EXTENDED_IRQ:
		if (rp->Data.ExtendedIrq.InterruptCount != 1) {
			status = AE_SUPPORT;
		} else if ((uart->valid & ARMH0011_VALID_IRQ) != 0) {
			uart->valid &= (~ARMH0011_VALID_IRQ);
			status = AE_SUPPORT;
		} else {
			uart->irq = rp->Data.ExtendedIrq.Interrupts[0];
			uart->valid |= ARMH0011_VALID_IRQ;
		}

		break;
	case ACPI_RESOURCE_TYPE_FIXED_MEMORY32:
		if ((uart->valid & (ARMH0011_VALID_ADDR|ARMH0011_VALID_ADDR_LEN)) != 0) {
			uart->valid &= (~(ARMH0011_VALID_ADDR|ARMH0011_VALID_ADDR_LEN));
			status = AE_SUPPORT;
		} else if (rp->Data.FixedMemory32.AddressLength != 0 && rp->Data.FixedMemory32.WriteProtect) {
			uart->addr = rp->Data.FixedMemory32.Address;
			uart->addr_len = rp->Data.FixedMemory32.AddressLength;
			uart->valid |= (ARMH0011_VALID_ADDR|ARMH0011_VALID_ADDR_LEN);
		}

		break;
	case ACPI_RESOURCE_TYPE_END_TAG:
		break;
	default:
		status = AE_NOT_IMPLEMENTED;
		break;
	}

	return (status);
}

static ACPI_STATUS
process_armh0011(ACPI_HANDLE handle, ACPI_DEVICE_INFO *obj, void *context, void **b)
{
	ACPI_STATUS status;
	pl011_info_t *uart;
	ACPI_BUFFER buf;
	char devname[128] = {0};
	buf.Pointer = devname;
	buf.Length = sizeof (devname) - 1;

	uart = &armh0011_info[num_armh0011_info];

	if (obj->Type != ACPI_TYPE_DEVICE) {
		return (AE_OK);
	}

	/*
	 * TODO: a list of supported pl011 types
	 */
	if (strcmp(obj->HardwareId.String, "ARMH0011") != 0) {
		return (AE_OK);
	}

	status = AcpiGetName(handle, ACPI_FULL_PATHNAME, &buf);
        if (ACPI_FAILURE(status))
                return status;

	devname[buf.Length] = '\0';

	status = AcpiWalkResources(handle, "_CRS", armh0011_crs_cb, uart);
	if (ACPI_FAILURE(status)) {
		return (status);
	}

	if ((uart->valid & (ARMH0011_VALID_ADDR|ARMH0011_VALID_ADDR_LEN)) !=
	    (ARMH0011_VALID_ADDR|ARMH0011_VALID_ADDR_LEN)) {
		return (AE_SUPPORT); /* a better error might be nice */
	}

	status = add_uart(devname, obj->HardwareId.String, (obj->Valid & ACPI_VALID_UID) ? obj->UniqueId.String : "0", &uefi_acpi_pl011_ops, uart);
	if (status == AE_LIMIT)
		status = AE_CTRL_TERMINATE;
	if (ACPI_FAILURE(status)) {
		return (status);
	}

	++num_armh0011_info;
	return (status);
}

static ACPI_STATUS
uefi_acpi_uart_device_callback(ACPI_HANDLE handle, UINT32 level, void *context, void **b)
{
	ACPI_STATUS status;
	size_t i;
	ACPI_DEVICE_INFO *obj;

	status = AcpiGetObjectInfo(handle, &obj);
        if (ACPI_FAILURE(status))
                return status;

	if (obj->Type != ACPI_TYPE_DEVICE) {
		AcpiOsFree(obj);
		return (AE_OK);
	}

	if ((obj->Valid & ACPI_VALID_HID) == 0) {
		AcpiOsFree(obj);
		return (AE_OK);
	}

	for (i = 0; i < num_known_uarts; ++i) {
		if (obj->HardwareId.Length == known_uarts[i].hid_len && strcmp(obj->HardwareId.String, known_uarts[i].hid) == 0) {
			status = known_uarts[i].processor(handle, obj, context, b);
			AcpiOsFree(obj);
			return (status);
		}
	}

	AcpiOsFree(obj);
        return (AE_OK);
}

static ACPI_STATUS
uefi_acpi_uart_probe(void)
{
        ACPI_STATUS status;
        ACPI_TABLE_HEADER *dsdt_table;
	ACPI_HANDLE sysbus_hdl;

	status = AcpiInitializeSubsystem();
	if (ACPI_FAILURE(status))
                return (status);

        status = AcpiInitializeTables(NULL, 16, TRUE);
        if (ACPI_FAILURE(status))
                return (status);

	status = AcpiGetTable(ACPI_SIG_DSDT, 1, &dsdt_table);
        if (ACPI_FAILURE(status))
                return (status);

	status = AcpiLoadTables();
        if (ACPI_FAILURE(status))
                return (status);

	status = AcpiEnableSubsystem(ACPI_FULL_INITIALIZATION);
        if (ACPI_FAILURE(status))
                return (status);

	status = AcpiInitializeObjects(ACPI_FULL_INITIALIZATION);
        if (ACPI_FAILURE(status))
                return (status);

	status = AcpiGetHandle(NULL, "\\_SB_", &sysbus_hdl);
	if (ACPI_FAILURE(status))
		return (status);

	status = AcpiWalkNamespace(ACPI_TYPE_DEVICE, sysbus_hdl, UINT32_MAX, uefi_acpi_uart_device_callback, NULL, NULL, NULL);
        if (ACPI_FAILURE(status))
                return (status);

	return (AE_OK);
}

static void	comc_probe(struct console *);
static int	comc_init(struct console *, int);
static bool	comc_setup(struct console *);
static void	comc_putchar(struct console *, int);
static int	comc_getchar(struct console *);
static int	comc_getspeed(struct console *);
static int	comc_ischar(struct console *);
static int	comc_ioctl(struct console *, int, void *);
static void	comc_devinfo(struct console *);

static char *
comc_asprint_mode(acpi_uart_t *uart)
{
	char par, *buf;

	if (uart == NULL)
		return (NULL);

	if ((uart->lcr & (PAREN|PAREVN)) == (PAREN|PAREVN))
		par = 'e';
	else if ((uart->lcr & PAREN) == PAREN)
		par = 'o';
	else
		par = 'n';

	asprintf(&buf, "%d,%d,%c,%d,-", uart->speed,
		(uart->lcr & BITS8) == BITS8? 8:7,
		par, (uart->lcr & STOP2) == STOP2? 2:1);
	return (buf);
}

static int
comc_parse_mode(acpi_uart_t *uart, const char *value)
{
	unsigned long n;
	int speed;
	int lcr;
	char *ep;

	if (value == NULL || *value == '\0')
		return (CMD_ERROR);

	errno = 0;
	n = strtoul(value, &ep, 10);
	if (errno != 0 || *ep != ',')
		return (CMD_ERROR);
	speed = n;

	ep++;
	errno = 0;
	n = strtoul(ep, &ep, 10);
	if (errno != 0 || *ep != ',')
		return (CMD_ERROR);

	switch (n) {
	case 7: lcr = BITS7;
		break;
	case 8: lcr = BITS8;
		break;
	default:
		return (CMD_ERROR);
	}

	ep++;
	switch (*ep++) {
	case 'n':
		break;
	case 'e': lcr |= PAREN|PAREVN;
		break;
	case 'o': lcr |= PAREN|PARODD;
		break;
	default:
		return (CMD_ERROR);
	}

	if (*ep == ',')
		ep++;
	else
		return (CMD_ERROR);

	switch (*ep++) {
	case '1':
		break;
	case '2': lcr |= STOP2;
		break;
	default:
		return (CMD_ERROR);
	}

	/* handshake is ignored, but we check syntax anyhow */
	if (*ep == ',')
		ep++;
	else
		return (CMD_ERROR);

	switch (*ep++) {
	case '-':
	case 'h':
	case 's':
		break;
	default:
		return (CMD_ERROR);
	}

	if (*ep != '\0')
		return (CMD_ERROR);

	uart->speed = speed;
	uart->lcr = lcr;
	return (CMD_OK);
}

/*
 * CMD_ERROR will cause set/setenv/setprop command to fail,
 * when used in loader scripts (forth), this will cause processing
 * of boot scripts to fail, rendering bootloading impossible.
 * To prevent such unfortunate situation, we return CMD_OK when
 * there is no such port, or there is invalid value in mode line.
 */
static int
comc_mode_set(struct env_var *ev, int flags, const void *value)
{
	struct console *cp;
	char name[15];

	if (value == NULL)
		return (CMD_ERROR);

	if ((cp = cons_get_console(ev->ev_name)) == NULL)
		return (CMD_OK);

	/* Do not override serial setup from SPCR */
	snprintf(name, sizeof (name), "%s-spcr-mode", cp->c_name);
	if (getenv(name) == NULL) {
		if (comc_parse_mode(cp->c_private, value) == CMD_ERROR) {
			printf("%s: invalid mode: %s\n", ev->ev_name,
			    (char *)value);
			return (CMD_OK);
		}
		(void) comc_setup(cp);
		env_setenv(ev->ev_name, flags | EV_NOHOOK, value, NULL, NULL);
	}

	return (CMD_OK);
}

/*
 * CMD_ERROR will cause set/setenv/setprop command to fail,
 * when used in loader scripts (forth), this will cause processing
 * of boot scripts to fail, rendering bootloading impossible.
 * To prevent such unfortunate situation, we return CMD_OK when
 * there is no such port or invalid value was used.
 */
static int
comc_cd_set(struct env_var *ev, int flags, const void *value)
{
	struct console *cp;
	acpi_uart_t *uart;

	if (value == NULL)
		return (CMD_OK);

	if ((cp = cons_get_console(ev->ev_name)) == NULL)
		return (CMD_OK);

	uart = cp->c_private;
	if (strcmp(value, "true") == 0) {
		uart->ignore_cd = 1;
	} else if (strcmp(value, "false") == 0) {
		uart->ignore_cd = 0;
	} else {
		printf("%s: invalid value: %s\n", ev->ev_name,
		    (char *)value);
		return (CMD_OK);
	}

	(void) comc_setup(cp);

	env_setenv(ev->ev_name, flags | EV_NOHOOK, value, NULL, NULL);

	return (CMD_OK);
}

/*
 * CMD_ERROR will cause set/setenv/setprop command to fail,
 * when used in loader scripts (forth), this will cause processing
 * of boot scripts to fail, rendering bootloading impossible.
 * To prevent such unfortunate situation, we return CMD_OK when
 * there is no such port, or invalid value was used.
 */
static int
comc_rtsdtr_set(struct env_var *ev, int flags, const void *value)
{
	struct console *cp;
	acpi_uart_t *uart;

	if (value == NULL)
		return (CMD_OK);

	if ((cp = cons_get_console(ev->ev_name)) == NULL)
		return (CMD_OK);

	uart = cp->c_private;
	if (strcmp(value, "true") == 0) {
		uart->rtsdtr_off = 1;
	} else if (strcmp(value, "false") == 0) {
		uart->rtsdtr_off = 0;
	} else {
		printf("%s: invalid value: %s\n", ev->ev_name,
		    (char *)value);
		return (CMD_OK);
	}

	(void) comc_setup(cp);

	env_setenv(ev->ev_name, flags | EV_NOHOOK, value, NULL, NULL);

	return (CMD_OK);
}

/*
 * Set up list of possible serial consoles.
 * This function is run very early, so we do not expect to
 * run out of memory, and on error, we can not print output.
 */
void
efi_acpi_comc_ini(void)
{
	ACPI_STATUS	status;
	size_t		c;
	size_t		n;
	size_t		i;
	struct console	**tmp;
	struct console	*tty;

	status = uefi_acpi_uart_probe();
        if (ACPI_FAILURE(status))
                return;

	if (num_acpi_uart == 0)
		return;

	n = num_acpi_uart;
	c = cons_array_size();
	if (c == 0)
		n++;

	tmp = realloc(consoles, (c + n) * sizeof (*consoles));
	if (tmp == NULL)
		return;
	consoles = tmp;
	if (c > 0)
		c--;

	for (i = 0; i < num_acpi_uart; i++) {
		/*
		 * If it's within num_acpi_uart then it's valid
		 */
		acpi_uart_t *uart = &acpi_uart[i];

		/*
		 * Allocate a new TTY object, set the name and description
		 * Set up flags and function pointers
		 */
		tty = malloc(sizeof (*tty));
		if (tty == NULL) {
			consoles[c] = tty;
			return;
		}

		if (asprintf(&tty->c_name, "tty%c", (int)('a' + i)) < 0) {
			free(tty);
			consoles[c] = NULL;
			return;
		}

		if (asprintf(&tty->c_desc, "serial port %c", (int)('a' + i)) < 0) {
			free(tty->c_name);
			free(tty);
			consoles[c] = NULL;
			return;
		}

		tty->c_flags = 0;
		tty->c_probe = comc_probe;
		tty->c_init = comc_init;
		tty->c_out = comc_putchar;
		tty->c_in = comc_getchar;
		tty->c_ready = comc_ischar;
		tty->c_ioctl = comc_ioctl;
		tty->c_devinfo = comc_devinfo;
		uart->lcr = BITS8;	/* 8,n,1 */
		uart->ignore_cd = 1;	/* ignore cd */
		uart->rtsdtr_off = 0;	/* rts-dtr is on */

		tty->c_private = uart;
		uart->speed = comc_getspeed(tty);
		consoles[c++] = tty;

		/* Reset terminal to initial normal settings with ESC [ 0 m */
		comc_putchar(tty, 0x1b);
		comc_putchar(tty, '[');
		comc_putchar(tty, '0');
		comc_putchar(tty, 'm');

		/* drain input from random data */
		while (comc_getchar(tty) != -1)
			;
	}

	consoles[c] = NULL;
}

static void
comc_probe(struct console *cp)
{
	acpi_uart_t	*uart;
	char		name[20];
	char		value[20];
	char		*env;

	uart = cp->c_private;
	if (uart->speed != 0)
		return;

	uart->speed = COMSPEED;

	/*
	 * If we have an environment variable for the speed, leave it alone
	 */
	snprintf(name, sizeof (name), "%s-mode", cp->c_name);
	env = getenv(name);
	if (env != NULL)
		uart->speed = comc_getspeed(cp);
	env = comc_asprint_mode(uart);

	if (env != NULL) {
		unsetenv(name);
		env_setenv(name, EV_VOLATILE, env, comc_mode_set, env_nounset);
		free(env);
	}

	snprintf(name, sizeof (name), "%s-ignore-cd", cp->c_name);
	env = getenv(name);
	if (env != NULL) {
		if (strcmp(env, "true") == 0)
			uart->ignore_cd = 1;
		else if (strcmp(env, "false") == 0)
			uart->ignore_cd = 0;
	}

	snprintf(value, sizeof (value), "%s", uart->ignore_cd ? "true" : "false");
	unsetenv(name);
	env_setenv(name, EV_VOLATILE, value, comc_cd_set, env_nounset);

	snprintf(name, sizeof (name), "%s-rts-dtr-off", cp->c_name);
	env = getenv(name);
	if (env != NULL) {
		if (strcmp(env, "true") == 0)
			uart->rtsdtr_off = 1;
		else if (strcmp(env, "false") == 0)
			uart->rtsdtr_off = 0;
	}

	snprintf(value, sizeof (value), "%s", uart->rtsdtr_off ? "true" : "false");
	unsetenv(name);
	env_setenv(name, EV_VOLATILE, value, comc_rtsdtr_set, env_nounset);

	cp->c_flags = 0;
	if (comc_setup(cp))
		cp->c_flags = C_PRESENTIN | C_PRESENTOUT;
}

static bool
comc_setup(struct console *cp)
{
	acpi_uart_t *uart = cp->c_private;

	if (uart->ops->op_setup(uart)) {
		/* Mark this port usable. */
		cp->c_flags |= (C_PRESENTIN | C_PRESENTOUT);
		return (true);
	}

	return (false);
}

static int
comc_init(struct console *cp, int arg __attribute((unused)))
{
	if (comc_setup(cp))
		return (CMD_OK);

	cp->c_flags = 0;
	return (CMD_ERROR);
}

static void
comc_putchar(struct console *cp, int c)
{
	acpi_uart_t *uart = cp->c_private;
	uart->ops->op_putchar(uart, c);
}

static int
comc_getchar(struct console *cp)
{
	acpi_uart_t *uart = cp->c_private;
	return (uart->ops->op_getchar(uart));
}

static int
comc_ischar(struct console *cp)
{
	acpi_uart_t *uart = cp->c_private;
	return (uart->ops->op_ischar(uart));
	return (0);
}

static int
comc_getspeed(struct console *cp)
{
	acpi_uart_t *uart = cp->c_private;
	return (uart->ops->op_getspeed(uart));
}

static int
comc_ioctl(struct console *cp __attribute((unused)), int n __attribute((unused)), void *arg __attribute((unused)))
{
	return (ENOTTY);
}

static void
comc_devinfo(struct console *cp __attribute((unused)))
{
	acpi_uart_t *uart = cp->c_private;
	uart->ops->op_devinfo(uart);
}
