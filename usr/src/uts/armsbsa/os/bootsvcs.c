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
 */

#include <sys/bootsvcs.h>

#if 0
static int _getchar()
{
	for (;;) { __asm__ __volatile__("wfe":::"memory"); }
	return 0;
}

static void _putchar(int c)
{
}

static int _ischar()
{
	return 0;
}

static void _reset(bool poff) __NORETURN;
static void _reset(bool poff)
{
	for (;;) { __asm__ __volatile__("wfe":::"memory"); }
}

static struct boot_syscalls _sysp =
{
	.bsvc_getchar = _getchar,
	.bsvc_putchar = _putchar,
	.bsvc_ischar = _ischar,
	.bsvc_reset = _reset,
};

struct boot_syscalls *sysp = &_sysp;
#endif
