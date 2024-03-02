#include <sys/types.h>
#include <sys/bootsvcs.h>
#include <sys/machclock.h>

/*
 * XXXARM: Implement me
 */
uint64_t
plat_get_cpu_clock(int cpu_no)
{
	return 1500000000;
}

/*
 * XXXARM: This is just plain wrong
 */
static int
_getchar()
{
	return (0);
}

static void
_putchar(int c)
{
}

static int
_ischar()
{
	return (0);
}

void _reset(bool poff) __NORETURN;
void _reset(bool poff)
{
#if 0
	if (poff)
		psci_system_off();
	else
		psci_system_reset();
#endif
	for (;;) {
		__asm__ volatile("wfe":::"memory");
	}
}

void
set_platform_defaults(void)
{
	tod_module_name = "todefirt";
}

static struct boot_syscalls _sysp =
{
	.bsvc_getchar = _getchar,
	.bsvc_putchar = _putchar,
	.bsvc_ischar = _ischar,
	.bsvc_reset = _reset,
};
struct boot_syscalls *sysp = &_sysp;
