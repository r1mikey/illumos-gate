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
 * Boot "syscalls" for platform bringup
 */

#include <sys/types.h>
#include <sys/bootsvcs.h>
#include <sys/bootinfo.h>
#include <sys/psci.h>
#include <sys/machparam.h>

#define	SBSA_UARTDR			0x00
#define	SBSA_UARTFR			0x18
#define	SBSA_UARTFR_TXFE		(1 << 7)
#define	SBSA_UARTFR_TXFF		(1 << 5)
#define	SBSA_UARTFR_RXFE		(1 << 4)

static caddr_t _bsvc_uart_mmio_base = 0x0;
extern boolean_t psci_initialized;

static void
bsvc_uart_writereg32(uint32_t reg, uint32_t val)
{
	*((volatile uint32_t *)(_bsvc_uart_mmio_base + reg)) = val;
}

static uint32_t
bsvc_uart_readreg32(uint32_t reg)
{
	return (*((volatile uint32_t *)(_bsvc_uart_mmio_base + reg)));
}

static void
bsvc_yield(void)
{
	__asm__ volatile("yield":::"memory");
}

/*
 * No-op implementation.
 *
 * This is the default when bsvc has not been initialized.
 */
static int
bsvc_ischar_none(void)
{
	return (0);
}

static int
bsvc_getchar_none(void)
{
	return (-1);
}

static void
bsvc_putchar_none(int c __unused)
{
	/* de nada */
}

static void __NORETURN
bsvc_reset_none(bool poff __unused)
{
	for (;;) {
		__asm__ volatile("wfe":::"memory");
	}
}

static struct boot_syscalls _sysp = {
	.bsvc_getchar	= bsvc_getchar_none,
	.bsvc_putchar	= bsvc_putchar_none,
	.bsvc_ischar	= bsvc_ischar_none,
	.bsvc_reset	= bsvc_reset_none,
};

struct boot_syscalls *sysp = &_sysp;

/*
 * PSCI implementation.
 *
 * illumos has a hard dependency on PSCI.
 */

static void __NORETURN
bsvc_reset_psci(bool poff)
{
	if (poff)
		psci_system_off();
	else
		psci_system_reset();

	for (;;) {
		__asm__ volatile("wfe":::"memory");
	}
}

/*
 * SBSA UART implementation.
 *
 * Arm's SystemReady insists that an SBSA UART is implemented.
 */

static int
bsvc_ischar_sbsa(void)
{
	return (!(bsvc_uart_readreg32(SBSA_UARTFR) & SBSA_UARTFR_RXFE));
}

static int
bsvc_getchar_sbsa(void)
{
	while (!bsvc_ischar_sbsa())
		bsvc_yield();

	return (bsvc_uart_readreg32(SBSA_UARTDR) & 0xff);
}

static void
bsvc_putchar_sbsa(int c)
{
	while (bsvc_uart_readreg32(SBSA_UARTFR) & SBSA_UARTFR_TXFF)
		bsvc_yield();

	if ((c & 0xff) == '\n')
		bsvc_putchar_sbsa('\r');

	bsvc_uart_writereg32(SBSA_UARTDR, c & 0xff);
	while (!(bsvc_uart_readreg32(SBSA_UARTFR) & SBSA_UARTFR_TXFE))
		bsvc_yield();
}

/*
 * Boot services initialisation
 */
void
bsvc_init(struct xboot_info *xbp)
{
	const char no_psci_str[] = "BSVC: Unable to initialize PSCI";
	const char *no_psci = no_psci_str;

	if (xbp->bi_bsvc_uart_mmio_base == 0)
		return;

	_bsvc_uart_mmio_base =
	    (caddr_t)(xbp->bi_bsvc_uart_mmio_base + SEGKPM_BASE);

	switch (xbp->bi_bsvc_uart_type) {
	case XBI_BSVC_UART_PL011:	/* fallthrough */
	case XBI_BSVC_UART_SBSA2X:	/* fallthrough */
	case XBI_BSVC_UART_SBSA:	/* fallthrough */
	case XBI_BSVC_UART_BCM2835:
		_sysp.bsvc_getchar = bsvc_getchar_sbsa;
		_sysp.bsvc_putchar = bsvc_putchar_sbsa;
		_sysp.bsvc_ischar = bsvc_ischar_sbsa;
		break;
	default:
		break;
	}

	psci_init(xbp);

	/*
	 * If PSCI init fails we end up calling the PROM when we try to call
	 * PSCI, which is not what we want in bsvc, so do an early check to
	 * catch problems.
	 */
	if (!psci_initialized) {
		do {
			_sysp.bsvc_putchar(*no_psci);
		} while (*no_psci++);
		_sysp.bsvc_putchar('\n');
		bsvc_reset_none(true);
	}

	_sysp.bsvc_reset = bsvc_reset_psci;
}

void __NORETURN
_reset(bool poff)
{
	_sysp.bsvc_reset(poff);
}
