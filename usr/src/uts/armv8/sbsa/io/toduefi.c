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
 * Copyright 2023 Michael van der Westhuizen
 */

#include <sys/param.h>
#include <sys/time.h>
#include <sys/uefirt.h>
#include <sys/clock.h>
#include <sys/rtc.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/promif.h>
#include <sys/platmod.h>

static void
toduefi_set(timestruc_t ts)
{
	ASSERT(MUTEX_HELD(&tod_lock));

	(void)uefirt_set_time(ts);
}

static timestruc_t
toduefi_get(void)
{
	timestruc_t ts = {0};
	ASSERT(MUTEX_HELD(&tod_lock));

	if (uefirt_get_time(&ts) != 0) {
		ts.tv_sec = 0;
		ts.tv_nsec = 0;
	}

	return ts;
}

static struct modlmisc modlmisc = {
	&mod_miscops, "toduefi"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

int
_init(void)
{
	extern tod_ops_t tod_ops;
	if (strcmp(tod_module_name, "toduefi") == 0) {
		tod_ops.tod_get = toduefi_get;
		tod_ops.tod_set = toduefi_set;
		tod_ops.tod_set_watchdog_timer = NULL;
		tod_ops.tod_clear_watchdog_timer = NULL;
		tod_ops.tod_set_power_alarm = NULL;
		tod_ops.tod_clear_power_alarm = NULL;
	}

	return mod_install(&modlinkage);
}

int
_fini(void)
{
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
