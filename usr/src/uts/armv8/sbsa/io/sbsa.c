#include <sys/types.h>
#include <sys/bootsvcs.h>
#include <sys/machclock.h>
#include <sys/promif.h>

/*
 * XXXARM: Implement me
 */
uint64_t
plat_get_cpu_clock(int cpu_no)
{
	return 1500000000;
}

/*
 * Stub to get drivers up
 */
int
plat_hwclock_get_rate(struct prom_hwclock *clk __unused)
{
        return -1;
}

void
set_platform_defaults(void)
{
	/* tod_module_name = "todefirt"; */
}
