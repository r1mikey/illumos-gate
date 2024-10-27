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
 * UEFI/ACPI UART implementation for Arm PL011 compatible UARTs.
 */
#include "pl011.h"
#include "uefi_acpi_uart.h"

#include <stddef.h>
#include <stdio.h>

#define UARTDR_REG	0x00
#define	UARTFR_REG	0x18

#define	UARTFR_TXFE	(1 << 7)
#define	UARTFR_TXFF	(1 << 5)
#define	UARTFR_RXFE	(1 << 4)

static bool pl011_setup(void *ctx);
static void pl011_putchar(void *ctx, int c);
static int pl011_getchar(void *ctx);
static int pl011_ischar(void *ctx);
static int pl011_getspeed(void *ctx);
static void pl011_devinfo(void *ctx);

const uefi_acpi_uart_ops_t uefi_acpi_pl011_ops = {
	.op_setup = pl011_setup,
	.op_putchar = pl011_putchar,
	.op_getchar = pl011_getchar,
	.op_ischar = pl011_ischar,
	.op_getspeed = pl011_getspeed,
	.op_devinfo = pl011_devinfo,
};

static uint32_t
pl011_readreg(pl011_info_t *pl011, uint16_t reg)
{
	return (*(volatile uint32_t *)(pl011->addr + reg));
}

static void
pl011_writereg(pl011_info_t *pl011, uint16_t reg, uint32_t val)
{
	(*(volatile uint32_t *)(pl011->addr + reg)) = val;
}

static bool
pl011_setup(void *ctx)
{
	acpi_uart_t	*uart = ctx;
	pl011_info_t	*pl011 = uart->info;

#if 0
	struct serial *sp = cp->c_private;
	static int TRY_COUNT = 1000000;
	int tries;

	outb(sp->ioaddr + com_cfcr, CFCR_DLAB | sp->lcr);
	outb(sp->ioaddr + com_dlbl, COMC_BPS(sp->speed) & 0xff);
	outb(sp->ioaddr + com_dlbh, COMC_BPS(sp->speed) >> 8);
	outb(sp->ioaddr + com_cfcr, sp->lcr);
	outb(sp->ioaddr + com_mcr,
	    sp->rtsdtr_off? ~(MCR_RTS | MCR_DTR) : MCR_RTS | MCR_DTR);

	tries = 0;
	do {
		inb(sp->ioaddr + com_data);
	} while (inb(sp->ioaddr + com_lsr) & LSR_RXRDY && ++tries < TRY_COUNT);

	if (tries == TRY_COUNT)
		return (false);
#endif
	return (true);
}

static void
pl011_putchar(void *ctx, int c)
{
	acpi_uart_t	*uart = ctx;
	pl011_info_t	*pl011 = uart->info;

	while(pl011_readreg(pl011, UARTFR_REG) & UARTFR_TXFF)
		;
	pl011_writereg(pl011, UARTDR_REG, c);
}

static int
pl011_getchar(void *ctx)
{
	acpi_uart_t	*uart = ctx;
	pl011_info_t	*pl011 = uart->info;

	if (pl011_ischar(ctx) == 0)
		return (-1);

	return (pl011_readreg(pl011, UARTDR_REG) & 0xff);
}

static int
pl011_ischar(void *ctx)
{
	acpi_uart_t	*uart = ctx;
	pl011_info_t	*pl011 = uart->info;

	if (pl011_readreg(pl011, UARTFR_REG) & UARTFR_RXFE)
		return (0);

	return (1);
}

static int
pl011_getspeed(void *ctx)
{
	acpi_uart_t	*uart = ctx;
	pl011_info_t	*pl011 = uart->info;
	return (115200);	/* ugh */
}

static void
pl011_devinfo(void *ctx)
{
	acpi_uart_t	*uart = ctx;
	pl011_info_t	*pl011 = uart->info;

	printf("\tmmio %#lx", pl011->addr);
}
