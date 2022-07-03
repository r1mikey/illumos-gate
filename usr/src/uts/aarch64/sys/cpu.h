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
 * Copyright 2022 Michael van der Westhuizen
 * Copyright 2017 Hayashi Naoyuki
 */

#ifndef	_SYS_CPU_H
#define	_SYS_CPU_H

#include <sys/types.h>
#include <asm/cpu.h>
#ifdef __cplusplus
extern "C" {
#endif

#if defined(_KERNEL) && !defined(_ASM)

/* XXXAARCH64: check this in other architectures */
#define	SMT_PAUSE()	\
    __asm__ __volatile__("yield":::"memory")

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CPU_H */
