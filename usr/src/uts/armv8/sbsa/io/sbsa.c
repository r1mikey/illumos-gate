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

void
set_platform_defaults(void)
{
	tod_module_name = "todefirt";
}
