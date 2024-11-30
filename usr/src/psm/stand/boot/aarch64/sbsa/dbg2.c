#include <sys/types.h>
#include <sys/bootinfo.h>
#include <sys/bootsvcs.h>
#include "dbg2.h"
#include "early_dbg2.h"

#define	DBG2_IS_PL011()	(_sbsa_dbg2_type == 0x0003 || _sbsa_dbg2_type == 0x000d || _sbsa_dbg2_type == 0x000e || _sbsa_dbg2_type == 0x0010)
#define	DBG2_IS_USABLE()	(_sbsa_dbg2_addr != 0 && DBG2_IS_PL011())

static uint64_t _sbsa_dbg2_addr = 0;
static uint64_t _sbsa_dbg2_type = 0;

extern void _reset(void) __NORETURN;

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

int
dbg2_ischar(void)
{
        if (!DBG2_IS_USABLE() || !DBG2_IS_PL011())
                return (0);

        return ((dbg2_ioread32(_sbsa_dbg2_addr + 0x18) & (1U << 4)) == 0);
}

int
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
_dbg2_init(void)
{
        int checks = 10000;
        uint32_t cr;

	if (!DBG2_IS_USABLE() || !DBG2_IS_PL011())
		return;

        cr = dbg2_ioread32(_sbsa_dbg2_addr + 0x30);
        cr |= 0x300;
        dbg2_iowrite32(_sbsa_dbg2_addr + 0x30, cr);

        while (dbg2_ischar() && checks--)
                (void) dbg2_getchar();
}

void
dbg2_init(struct xboot_info *xbi)
{
#if defined(_EARLY_DBG2) && _EARLY_DBG2 > 0
	int reinit = 0;
#endif
	if (xbi == NULL)
		return;

#if defined(_EARLY_DBG2) && _EARLY_DBG2 > 0
	reinit = 1;
#endif
	_sbsa_dbg2_addr = xbi->bi_bsvc_uart_mmio_base;
	_sbsa_dbg2_type = xbi->bi_bsvc_uart_type;
	_dbg2_init();
#if defined(DEBUG)
	dbg2_puts("dbg2_init: DBG2 initialised from loader environment\n");
#endif
#if defined(_EARLY_DBG2) && _EARLY_DBG2 > 0
	if (reinit) {
#if defined(DEBUG)
		dbg2_puts("dbg2_init: DBG2 reinitialised from loader environment\n");
#endif
	}
#endif
}

void
dbg2_preinit(void)
{
#if defined(_EARLY_DBG2) && _EARLY_DBG2 > 0
        _sbsa_dbg2_addr = EARLY_DBG2_PA;
        _sbsa_dbg2_type = EARLY_DBG2_TYPE;

	_dbg2_init();
#endif
}

void
dbg2_putchar(int c)
{
        int checks = 10000;

        if (!DBG2_IS_USABLE() || !DBG2_IS_PL011())
                return;

        while (dbg2_ioread32(_sbsa_dbg2_addr + 0x18) & (1UL << 7) == 0 &&
            checks--)
                ;
        dbg2_iowrite32(_sbsa_dbg2_addr, c);
	/* XXXARM: wait for TXFE */
}

void
dbg2_puts(const char *s)
{
	while (s && *s)
		dbg2_putchar(*s++);
}

static char digits[] = "0123456789abcdef";

void
dbg2_putnum(uint64_t x, boolean_t is_signed, uint8_t base)
{
        char buffer[64];        /* digits in reverse order */
        int i;

        if (is_signed && (int64_t)x < 0) {
                dbg2_putchar('-');
                x = -x;
        }

        for (i  = -1; x != 0 && i <= 63; x /= base)
                buffer[++i] = digits[x - ((x / base) * base)];

        if (i < 0)
                buffer[++i] = '0';

        while (i >= 0)
                dbg2_putchar(buffer[i--]);
}

/*
 * Very primitive printf - only does a subset of the standard format characters.
 */
void
dbg2_vprintf(const char *fmt, va_list args)
{
	char *s;
	uint64_t x;
	uint8_t base;
	uint8_t size;

	if (fmt == NULL)
		return;

	for (; *fmt; ++fmt) {
		if (*fmt != '%') {
			dbg2_putchar(*fmt);
			continue;
		}

		size = 0;
again:
		++fmt;
		switch (*fmt) {

		case '%':
			dbg2_putchar(*fmt);
			break;

		case 'c':
			x = va_arg(args, int);
			dbg2_putchar(x);
			break;

		case 's':
			s = va_arg(args, char *);
			if (s == NULL)
				dbg2_puts("(null)");
			else
				dbg2_puts(s);
			break;

		case 'p':
			x = va_arg(args, ulong_t);
			dbg2_putnum(x, B_FALSE, 16);
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
			dbg2_putnum(x, B_TRUE, 10);
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
			dbg2_putnum(x, B_FALSE, base);
			break;

		default:
			dbg2_puts("dbg2_printf: unknown % escape\n");
		}
	}
}

void prom_vprintf(const char *fmt, va_list adx) __attribute__((alias("dbg2_vprintf")));

void
dbg2_printf(const char *fmt, ...)
{
	va_list	args;

	va_start(args, fmt);
	dbg2_vprintf(fmt, args);
	va_end(args);
}

void prom_printf(const char *fmt, ...) __attribute__((alias("dbg2_printf")));

void
dbg2_panic(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	dbg2_vprintf(fmt, args);
	va_end(args);

	dbg2_puts("Press any key to reboot\n");
	(void)dbg2_getchar();
	_reset();
}

void prom_panic(const char *fmt, ...) __attribute__((alias("dbg2_panic")));

void
prom_writestr(const char *buf, size_t len)
{
	size_t written = 0;
	ssize_t i;

	while (written < len)  {
		dbg2_putchar(buf[written]);
		++written;
	}
}

void
dbg2_dump_info(void)
{
	dbg2_printf("dbg2_dump_info: _sbsa_dbg2_addr is 0x%lx\n", _sbsa_dbg2_addr);
	dbg2_printf("dbg2_dump_info: _sbsa_dbg2_type is 0x%lx\n", _sbsa_dbg2_type);
}

static void bsvc_reset(bool x) __NORETURN;

static void
bsvc_reset(bool x)
{
	_reset();
}

static boot_syscalls_t boot_syscalls = {
	.bsvc_getchar = dbg2_getchar,
	.bsvc_putchar = dbg2_putchar,
	.bsvc_ischar = dbg2_ischar,
	.bsvc_reset = bsvc_reset,
};
boot_syscalls_t	*sysp = &boot_syscalls;
