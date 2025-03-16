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

#include <sys/types.h>
#include <sys/machclock.h>
#include <sys/platmod.h>
#include <sys/systm.h>

static plat_pcierc_takeover_func_t plat_pcierc_takeover_func;

/*
 * Platform power management drivers list - empty by default
 */
char *platform_module_list[] = {
	NULL,
};

void
plat_tod_fault(enum tod_fault_type tod_bad __unused)
{
}

typedef int (*plat_pcierc_takeover_func_t)(dev_info_t *);

void
plat_pcierc_set_takeover(plat_pcierc_takeover_func_t f)
{
	plat_pcierc_takeover_func = f;
}

int
plat_pcierc_takeover(dev_info_t *rdip)
{
	if (plat_pcierc_takeover_func == NULL)
		return (0);

	if (rdip == NULL)
		return (-1);

	return ((*plat_pcierc_takeover_func)(rdip));
}
