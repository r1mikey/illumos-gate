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

#include <sys/types.h>
#include <sys/machclock.h>
#include <sys/platform.h>
#include <sys/modctl.h>
#include <sys/platmod.h>
#include <sys/promif.h>
#include <sys/errno.h>
#include <sys/byteorder.h>

void
set_platform_defaults(void)
{
	tod_module_name = "todmeson";
}

#define	HHI_SYS_CPU_CLK_CNTL0	(*(volatile uint32_t *)	\
	(0xc883c000 + (0x67 << 2) + SEGKPM_BASE))
#define	HHI_SYS_PLL_CNTL	(*(volatile uint32_t *)	\
	(0xc883c000 + (0xc0 << 2) + SEGKPM_BASE))

union hhi_sys_cpu_clk_cntl0 {
	uint32_t dw;
	struct {
		uint32_t	mux		:	2;
		uint32_t			:	30;
	};
};

union hhi_sys_pll_cntl {
	uint32_t dw;
	struct {
		uint32_t	m		:	9;
		uint32_t	n		:	5;
		uint32_t			:	2;
		uint32_t	od		:	2;
		uint32_t			:	14;
	};
};

uint64_t
plat_get_cpu_clock(int cpu_no)
{
	uint32_t clk = 24 * 1000000;

	union hhi_sys_pll_cntl pll_cntl;
	pll_cntl.dw = HHI_SYS_PLL_CNTL;

	union hhi_sys_cpu_clk_cntl0 sys_cpu_clk_cntl0;
	sys_cpu_clk_cntl0.dw = HHI_SYS_CPU_CLK_CNTL0;

	clk *= pll_cntl.m / pll_cntl.n;
	clk >>= pll_cntl.od;
	clk /= (sys_cpu_clk_cntl0.mux + 1);

	return (clk);
}
