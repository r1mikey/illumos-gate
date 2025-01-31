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

#ifndef _SYS_PLATFORM_MODULE_H
#define	_SYS_PLATFORM_MODULE_H

/*
 * Platform interfaces for the armv8 platform.
 *
 * These interfaces are incredibly volatile and should be expected to
 * churn for the foreseeable future.
 */

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct gpio_ctrl;
struct prom_hwclock;

#pragma	weak	plat_get_cpu_clock
#pragma	weak	plat_gpio_get
#pragma	weak	plat_gpio_set
#pragma	weak	plat_hwclock_get_rate

/*
 * Called in mp_startup.c from init_cpu_info (twice).
 */
extern uint64_t plat_get_cpu_clock(int cpu_no);

/*
 * Called in bcm2711-emmc2.c to drive the GPIO regulator when switching to 1v8.
 */
struct gpio_ctrl;
extern int plat_gpio_get(struct gpio_ctrl *);
extern int plat_gpio_set(struct gpio_ctrl *, int);

/*
 * Called in ns16550a.c to get the clock frequency driving the UART.
 */
extern int plat_hwclock_get_rate(struct prom_hwclock *);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_PLATFORM_MODULE_H */
