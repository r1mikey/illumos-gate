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
 * Copyright 2025 Michael van der Westhuizen
 */

/*
 * Platform implementation dispatch.
 */

#include <sys/types.h>
#include <sys/platimpl.h>
#include <sys/bootinfo.h>
#include <sys/obpdefs.h>
#include <libfdt.h>
#if defined(DEBUG)
#include <sys/promif.h>
#endif

extern const platimpl_t rpi4_fdt_platimpl;
extern const platimpl_t virt_fdt_platimpl;

static const platimpl_t *impl;

typedef struct {
	const char		*ps_compat;
	const platimpl_t	*ps_impl;
} fdt_platsel_t;

static const fdt_platsel_t fdt_platsel[] = {
	{
		"raspberrypi,4-model-b",
		&rpi4_fdt_platimpl,
	},
	{
		"linux,dummy-virt",
		&virt_fdt_platimpl,
	},
};
static size_t num_fdt_platsel = sizeof (fdt_platsel) / sizeof (fdt_platsel[0]);

static void
plat_select_fdt(void *fdtp)
{
	const fdt_platsel_t *ps;
	size_t n;
#if defined(DEBUG)
	int i;
	int c;
	const char *cval;
#endif

	if (fdt_check_header(fdtp) != 0) {
		cmn_err(CE_WARN,
		    "Bad FDT header. Platform selection impossible.");
		return;
	}

#if defined(DEBUG)
	if ((c = fdt_stringlist_count(fdtp, 0, OBP_COMPATIBLE)) > 0) {
		prom_printf("plat_select_fdt: compatible entries:\n");
		for (i = 0; i < c; ++i) {
			if ((cval = fdt_stringlist_get(
			    fdtp, 0, OBP_COMPATIBLE, i, NULL)) != NULL) {
				prom_printf("  %d: \"%s\"\n", i, cval);
			}
		}
	}
#endif

	for (n = 0; n < num_fdt_platsel; ++n) {
		ps = &fdt_platsel[n];

		if (fdt_node_check_compatible(fdtp, 0, ps->ps_compat) == 0) {
#if defined(DEBUG)
			prom_printf("plat_select_fdt: matched \"%s\"\n",
			    ps->ps_compat);
#endif
			impl = ps->ps_impl;
			break;
		}
	}

	if (impl == NULL) {
		cmn_err(CE_WARN, "No compatible FDT selected. "
		    "Platform selection impossible.");
	}
}

void
plat_select(struct xboot_info *xbp)
{
	if (xbp == NULL) {
		cmn_err(CE_WARN,
		    "No boot info. Platform selection impossible.");
		return;
	}

	if (xbp->bi_fdt != 0) {
		plat_select_fdt((void *)xbp->bi_fdt);
		return;
	}

	cmn_err(CE_WARN, "No FDT for platform implementation selection");
}

void
set_platform_defaults(void)
{
	if (impl == NULL || impl->pi_set_platform_defaults == NULL)
		return;

	impl->pi_set_platform_defaults();
}

uint64_t
plat_get_cpu_clock(int cpu_no)
{
	if (impl == NULL || impl->pi_get_cpu_clock == NULL)
		return (1000 * 1000 * 1000);

	return (impl->pi_get_cpu_clock(cpu_no));
}

int
plat_gpio_get(struct gpio_ctrl *gpio)
{
	if (gpio == NULL || impl == NULL || impl->pi_gpio_get == NULL)
		return (-1);

	return (impl->pi_gpio_get(gpio));
}

int
plat_gpio_set(struct gpio_ctrl *gpio, int value)
{
	if (gpio == NULL || impl == NULL || impl->pi_gpio_set == NULL)
		return (-1);

	return (impl->pi_gpio_set(gpio, value));
}

int
plat_hwclock_get_rate(struct prom_hwclock *clk)
{
	if (clk == NULL || impl == NULL || impl->pi_hwclock_get_rate == NULL)
		return (-1);

	return (impl->pi_hwclock_get_rate(clk));
}
