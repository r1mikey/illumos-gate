#ifndef	_SBSA_DBG2_H
#define	_SBSA_DBG2_H

#include <sys/types.h>
#include <sys/bootinfo.h>
#include <sys/acpi/platform/acsolaris.h>
#undef strtoul
#include <sys/acpi/actypes.h>
#include <sys/acpi/actbl.h>

extern void dbg2_init(struct xboot_info *xbi);

extern void dbg2_preinit(void);

extern int dbg2_ischar(void);
extern int dbg2_getchar(void);
extern void dbg2_putchar(int c);
extern void dbg2_puts(const char *s);

extern void dbg2_printf(const char *fmt, ...);
extern void dbg2_panic(const char *fmt, ...);

#endif
