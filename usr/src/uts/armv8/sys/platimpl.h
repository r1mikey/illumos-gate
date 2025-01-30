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

#ifndef _SYS_PLATIMPL_H
#define	_SYS_PLATIMPL_H

/*
 * Platform-specific implementation types.
 */

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct xboot_info;
struct gpio_ctrl;
struct prom_hwclock;

typedef struct {
	void		(*pi_set_platform_defaults)(void);
	uint64_t	(*pi_get_cpu_clock)(int);
	int		(*pi_gpio_get)(struct gpio_ctrl *);
	int		(*pi_gpio_set)(struct gpio_ctrl *, int);
	int		(*pi_hwclock_get_rate)(struct prom_hwclock *);
} platimpl_t;

extern void plat_select(struct xboot_info *);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_PLATIMPL_H */
