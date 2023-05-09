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
#if 0
#include <libfdt.h>
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/boot.h>
#include <sys/bootsvcs.h>
#if 0
#include <sys/salib.h>
#endif
#include <sys/promif.h>
#include <sys/platform.h>
#include <sys/controlregs.h>
#include <sys/memlist.h>
#include <sys/memlist_impl.h>
#include <sys/sysmacros.h>
#include <sys/bootconf.h>
#include <sys/pte.h>
#if 0
#include <sys/psci.h>
#include "prom_dev.h"
#include "boot_plat.h"
#endif
#include "dbg2.h"
#include "shim.h"

#ifndef rounddown
#define	rounddown(x, y)	(((x)/(y))*(y))
#endif

char *default_name = "armv8";
char *default_path = "/platform/armv8/kernel";
extern void exception_vector(void);
extern uint64_t boot_args[];
extern char _BootStart[];
extern char _BootEnd[];

extern void _reset(void);

extern void map_phys(pte_t pte_attr, caddr_t vaddr, uint64_t paddr, size_t bytes);
extern void reloc_efi_runtime_services(struct xboot_info *xbi);

extern struct xboot_info *bi;
extern boot_syscalls_t *sysp;

struct boot_fs_ops *boot_fsw[1];
int boot_nfsw = 0;

void
fiximp(void)
{
	write_vbar((uint64_t)&exception_vector);

	if ((4u << ((read_ctr_el0() >> 16) & 0xF)) != DCACHE_LINE) {
		prom_printf("CTR_EL0=%08x DCACHE_LINE=%ld\n", (uint32_t)read_ctr_el0(), DCACHE_LINE);
		_reset();
	}

}

extern void dbg2_putnum(uint64_t x, boolean_t is_signed, uint8_t base);

void
dump_exception(uint64_t *regs)
{
	uint64_t pc;
	uint64_t esr;
	uint64_t far;
	__asm__ volatile ("mrs %0, elr_el1":"=r"(pc));
	__asm__ volatile ("mrs %0, esr_el1":"=r"(esr));
	__asm__ volatile ("mrs %0, far_el1":"=r"(far));
	prom_printf("%s\n", __func__);
	prom_printf("pc  = %lx\n",  pc);
	prom_printf("esr = %lx\n",  esr);
	prom_printf("far = %lx\n",  far);
	for (int i = 0; i < 31; i++)
		prom_printf("x%d%s = %lx\n", i, ((i >= 10)?" ":""),regs[i]);
	_reset();
}

uintptr_t
pa_to_ttbr1(uintptr_t pa)
{
	return (SEGKPM_BASE + pa);
}

void
exitto(int (*entrypoint)())
{
	uintptr_t pa;
	uintptr_t sz;

	map_efimem(SEGKPM_BASE);
#if 0
	for (struct memlist *ml = plinearlistp; ml != NULL; ml = ml->ml_next) {
		pa = ml->ml_address;
		sz = ml->ml_size;
		map_phys(PTE_UXN | PTE_PXN | PTE_AF | PTE_SH_INNER | PTE_AP_KRWUNA | PTE_ATTR_NORMEM, (caddr_t)pa_to_ttbr1(pa), pa, sz);
	}
	for (struct memlist *ml = pfwcodelistp; ml != NULL; ml = ml->ml_next) {
		pa = ml->ml_address;
		sz = ml->ml_size;
		map_phys(PTE_UXN | PTE_AF | PTE_SH_INNER | PTE_AP_KRWUNA | PTE_ATTR_NORMEM, (caddr_t)pa_to_ttbr1(pa), pa, sz);
	}
	for (struct memlist *ml = pfwdatalistp; ml != NULL; ml = ml->ml_next) {
		pa = ml->ml_address;
		sz = ml->ml_size;
		map_phys(PTE_UXN | PTE_PXN | PTE_AF | PTE_SH_INNER | PTE_AP_KRWUNA | PTE_ATTR_NORMEM, (caddr_t)pa_to_ttbr1(pa), pa, sz);
	}
	for (struct memlist *ml = piolistp; ml != NULL; ml = ml->ml_next) {
		pa = ml->ml_address;
		sz = ml->ml_size;
		map_phys(PTE_UXN | PTE_PXN | PTE_AF | PTE_SH_INNER | PTE_AP_KRWUNA | PTE_ATTR_DEVICE, (caddr_t)pa_to_ttbr1(pa), pa, sz);
        }
#endif
	reloc_efi_runtime_services(bi);

	bi->bi_boot_sysp = (uint64_t)sysp;
	dbg2_printf("exitto: bi->bi_boot_sysp is 0x%lx\n", bi->bi_boot_sysp);

	bi->bi_phys_avail = (uint64_t)pfreelistp;
	bi->bi_phys_installed = (uint64_t)pinstalledp;
	bi->bi_boot_scratch = (uint64_t)pscratchlistp;

	/*
	 * Rebase pointers in xboot_info
	 * There's some other housekeeping crap we need.
	 */

	dbg2_printf("exitto: jumping to kernel at 0x%p with xboot_info 0x%p\n", entrypoint, bi);
	entrypoint(bi);
}
