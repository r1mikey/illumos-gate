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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/machparam.h>
#include <sys/archsystm.h>
#include <sys/boot_console.h>
#include <sys/varargs.h>
#include "eboot_asm.h"
#include "eboot_printf.h"
#include "eboot_xboot.h"

#ifdef __xpv
#include <sys/hypervisor.h>
#endif

/*
 * This file provides simple output formatting via eboot_printf()
 */

static uint64_t dbg2_va = 0;
static uint64_t dbg2_type = 0;

#define	UART_USABLE()	(dbg2_va != 0 &&	\
	(dbg2_type == 0x0003 || dbg2_type == 0x000e || dbg2_type == 0x0010))
#define	UART_ADDRESS	(dbg2_va)

static void do_eboot_printf(char *fmt, va_list args);

static char digits[] = "0123456789abcdef";

void
eboot_dbg2_init(uint64_t va, uint64_t type)
{
	dbg2_va = va;
	dbg2_type = type;
}

#if 0
static void
eboot_putchar(char c)
{
	if (c == '\n')
		eboot_putchar('\r');

	if (UART_USABLE()) {
		while (ioread32(UART_ADDRESS + 0x18) & (1UL << 5))
			;
		iowrite32(UART_ADDRESS, c);
	}
}
#endif

/*
 * Primitive version of panic, prints a message then resets the system
 */
void
eboot_panic(char *fmt, ...)
{
	va_list	args;

	va_start(args, fmt);
	do_eboot_printf(fmt, args);
	va_end(args);

#if 0
	if (boot_console_type(NULL) == CONS_SCREEN_TEXT) {
		eboot_printf("Press any key to reboot\n");
		(void) bcons_getchar();
	}
	outb(0x64, 0xfe);	/* this resets the system, see pc_reset() */
	eboot_halt();		/* just in case */
#else
	/* TODO: if we have runtime services, call them */
	eboot_halt();
#endif
}

/*
 * printf for boot code
 */
void
eboot_printf(char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	do_eboot_printf(fmt, args);
	va_end(args);
}


/*
 * output a string
 */
static void
eboot_puts(char *s)
{
	while (*s != 0) {
		// eboot_putchar(*s);
		bcons_putchar(*s);
		++s;
	}
}

static void
eboot_putnum(uint64_t x, boolean_t is_signed, uint8_t base)
{
	char buffer[64];	/* digits in reverse order */
	int i;

	if (is_signed && (int64_t)x < 0) {
		// eboot_putchar('-');
		bcons_putchar('-');
		x = -x;
	}

	for (i  = -1; x != 0 && i <= 63; x /= base)
		buffer[++i] = digits[x - ((x / base) * base)];

	if (i < 0)
		buffer[++i] = '0';

	while (i >= 0)
		// eboot_putchar(buffer[i--]);
		bcons_putchar(buffer[i--]);
}

/*
 * Very primitive printf - only does a subset of the standard format characters.
 */
static void
do_eboot_printf(char *fmt, va_list args)
{
	char *s;
	uint64_t x;
	uint8_t base;
	uint8_t size;

	if (fmt == NULL) {
		eboot_puts("eboot_printf(): 1st arg is NULL\n");
		return;
	}
	for (; *fmt; ++fmt) {
		if (*fmt != '%') {
			// eboot_putchar(*fmt);
			bcons_putchar(*fmt);
			continue;
		}

		size = 0;
again:
		++fmt;
		switch (*fmt) {

		case '%':
			// eboot_putchar(*fmt);
			bcons_putchar(*fmt);
			break;

		case 'c':
			x = va_arg(args, int);
			// eboot_putchar(x);
			bcons_putchar(x);
			break;

		case 's':
			s = va_arg(args, char *);
			if (s == NULL)
				eboot_puts("*NULL*");
			else
				eboot_puts(s);
			break;

		case 'p':
			x = va_arg(args, ulong_t);
			eboot_putnum(x, B_FALSE, 16);
			break;

		case 'l':
			if (size == 0)
				size = sizeof (long);
			else if (size == sizeof (long))
				size = sizeof (long long);
			goto again;

		case 'd':
			if (size == 0)
				x = va_arg(args, int);
			else if (size == sizeof (long))
				x = va_arg(args, long);
			else
				x = va_arg(args, long long);
			eboot_putnum(x, B_TRUE, 10);
			break;

		case 'u':
			base = 10;
			goto unsigned_num;

		case 'b':
			base = 2;
			goto unsigned_num;

		case 'o':
			base = 8;
			goto unsigned_num;

		case 'x':
			base = 16;
unsigned_num:
			if (size == 0)
				x = va_arg(args, uint_t);
			else if (size == sizeof (ulong_t))
				x = va_arg(args, ulong_t);
			else
				x = va_arg(args, unsigned long long);
			eboot_putnum(x, B_FALSE, base);
			break;

		default:
			eboot_puts("eboot_printf(): unknown % escape\n");
		}
	}
}
