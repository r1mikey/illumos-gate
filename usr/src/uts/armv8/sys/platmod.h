/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2026 Michael van der Westhuizen
 */

#ifndef _SYS_PLATMOD_H
#define	_SYS_PLATMOD_H

/*
 * Platform interfaces for the armv8 platform.
 *
 * These interfaces are incredibly volatile and should be expected to
 * churn for the foreseeable future.
 *
 * See also: uts/aarch64/sys/platform_module.h
 */

#include <sys/types.h>
#include <sys/cpuvar.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(_KERNEL)

struct gpio_ctrl;
struct prom_hwclock;

#pragma weak	plat_get_cpu_clock
#pragma weak	plat_set_max_cpu_clock
#pragma weak	plat_set_cpu_supp_freqs
#pragma weak	plat_gpio_get
#pragma weak	plat_gpio_set
#pragma weak	plat_hwclock_get_rate
#pragma weak	plat_pcierc_set_takeover
#pragma weak	plat_pcierc_takeover

/*
 * Called in mp_startup.c from init_cpu_info (twice).
 */
extern uint64_t plat_get_cpu_clock(int cpu_no);
extern void plat_set_max_cpu_clock(int cpu_no);
extern void plat_set_cpu_supp_freqs(cpu_t *cp);

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

/*
 * Hooks to allow PCIe root complex drivers to negotiate device takeover
 * from firmware.
 *
 * The firmware implementation uses `plat_pcierc_set_takeover' to install
 * a takeover function, which receives a dev_info_t pointer and returns
 * an integer (a standard DDI return code).
 *
 * The PCIe root complex uses `plat_pcierc_takeover' at attach time, passing
 * its dev_info_t pointer. An integer is returned, which is the DDI return
 * code from the implementation pointer.
 *
 * Platform-specific code (in particular, ACPI) implements the firmware
 * interaction as apropriate.
 *
 * These are weak functions, so should be tested for presence prior to
 * being called.
 */
typedef int (*plat_pcierc_takeover_func_t)(dev_info_t *);

extern void plat_pcierc_set_takeover(plat_pcierc_takeover_func_t);
extern int plat_pcierc_takeover(dev_info_t *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PLATMOD_H */
