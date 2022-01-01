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
 * Copyright (c) 2012 Gary Mills
 *
 * Copyright (c) 1993, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2011 by Delphix. All rights reserved.
 * Copyright 2019 Joyent, Inc.
 * Copyright 2020 Oxide Computer Company
 */
/*
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/disp.h>
#include <sys/promif.h>
#include <sys/clock.h>
#include <sys/cpuvar.h>
#include <sys/stack.h>
#include <vm/as.h>
#include <vm/hat.h>
#include <sys/reboot.h>
#include <sys/avintr.h>
#include <sys/vtrace.h>
#include <sys/proc.h>
#include <sys/thread.h>
#include <sys/cpupart.h>
#include <sys/pset.h>
#include <sys/copyops.h>
#include <sys/pg.h>
#include <sys/disp.h>
#include <sys/debug.h>
#include <sys/sunddi.h>
#include <sys/aarch64_archext.h>
#include <sys/privregs.h>
#include <sys/machsystm.h>
#include <sys/ontrap.h>
#include <sys/bootconf.h>
/* #include <sys/boot_console.h> */
#include <sys/kdi_machimpl.h>
#include <sys/archsystm.h>
#include <sys/promif.h>
#include <sys/pci_cfgspace.h>
/* #include <sys/apic.h> */
/* #include <sys/apic_common.h> */
#include <sys/bootvfs.h>
/* #include <sys/tsc.h> */
/* #include <sys/smt.h> */
#if 0
#include <sys/xpv_support.h>
#endif
#include <asm/controlregs.h>
#include <sys/efi.h>
#include <sys/modctl.h>

extern int dacfdebug;
extern EFI_RUNTIME_SERVICES64 *efirt;

#if 0

/*
 * Set console mode
 */
static void
set_console_mode(uint8_t val)
{
	struct bop_regs rp = {0};

	rp.eax.byte.ah = 0x0;
	rp.eax.byte.al = val;
	rp.ebx.word.bx = 0x0;

	BOP_DOINT(bootops, 0x10, &rp);
}
#endif

/*
 * Setup routine called right before main(). Interposing this function
 * before main() allows us to call it in a machine-independent fashion.
 */
void
mlsetup(struct regs *rp)
{
	extern char t0stack[];
	extern disp_t cpu0_disp;
	extern struct classfuncs sys_classfuncs;
	extern uint64_t plat_dr_options;
	u_longlong_t prop_value;
#if 0
	char prop_str[BP_MAX_STRLEN];
#endif
	ASSERT_STACK_ALIGNED();

	if (bootprop_getval("efi-systab", &prop_value) == 0)
		efirt = ((EFI_SYSTEM_TABLE64 *)prop_value)->RuntimeServices;

	if (bootprop_getval("moddebug", &prop_value) == 0)
		moddebug = (int)prop_value;

	if (bootprop_getval("dacfdebug", &prop_value) == 0)
		dacfdebug = (int)prop_value;

	/*
	 * initialize cpu_self
	 */
	cpu[0]->cpu_self = cpu[0];

	/*
	 * XXXAARCH64: i86pc sets up the NMI action here
	 */

	/*
	 * XXXAARCH64: i86pc sets up KPTI flags here
	 */

#if 0
	/*
	 * XXXAARCH64: SMT handling - this needs to be plumbed in
	 * While we don't need to check this until later, we might as well do it
	 * here.
	 */
	if (bootprop_getstr("smt_enabled", prop_str, sizeof (prop_str)) == 0) {
		if (strcasecmp(prop_str, "false") == 0 ||
		    strcmp(prop_str, "0") == 0)
			smt_boot_disable = 1;
	}
#endif

	/*
	 * XXXAARCH64: more vectors - check which ones these are (maybe
	 * the final ones?)
	 * We should install vecs in locore.s (that's IDT)
	 */
#if 0
	init_desctbls();
#endif

	/*
	 * lgrp_init() needs PCI config space access
	 *
	 * XXXAARCH64: Is this true?
	 */
	pci_cfgspace_init();

	/*
	 * Initialize the platform type from CPU 0 to ensure that
	 * determine_platform() is only ever called once.
	 */
	determine_platform();

	/*
	 * The first lightweight pass (pass0) through the cpuid data
	 * was done in locore before mlsetup was called.  Do the next
	 * pass in C code.
	 *
	 * The aarch64_featureset is initialized here based on the capabilities
	 * of the boot CPU.  Note that if we choose to support CPUs that have
	 * different feature sets (at which point we would almost certainly
	 * want to set the feature bits to correspond to the feature
	 * minimum) this value may be altered.
	 *
	 * XXXAARCH64: It is very likely that a big.LITTLE system will require
	 * us to take the feature minimum described above.
	 */
	cpuid_pass1(cpu[0], aarch64_featureset);

	/*
	 * i86pc does TSC workarounds here and patches out memops based on the
	 * boot CPU (cache ops? I'd want this very early).
	 *
	 * Also, open up permissions for EL0 to read the virtual timer?
	 */

	/*
	 * initialize t0
	 */
	t0.t_stk = (caddr_t)rp - MINFRAME;
	t0.t_stkbase = t0stack;
	t0.t_pri = maxclsyspri - 3;
	t0.t_schedflag = TS_LOAD | TS_DONT_SWAP;
	t0.t_procp = &p0;
	t0.t_plockp = &p0lock.pl_lock;
	t0.t_lwp = &lwp0;
	t0.t_forw = &t0;
	t0.t_back = &t0;
	t0.t_next = &t0;
	t0.t_prev = &t0;
	t0.t_cpu = cpu[0];
	t0.t_disp_queue = &cpu0_disp;
	t0.t_bind_cpu = PBIND_NONE;
	t0.t_bind_pset = PS_NONE;
	t0.t_bindflag = (uchar_t)default_binding_mode;
	t0.t_cpupart = &cp_default;
	t0.t_clfuncs = &sys_classfuncs.thread;
	t0.t_copyops = NULL;
	THREAD_ONPROC(&t0, CPU);

	lwp0.lwp_thread = &t0;
	lwp0.lwp_regs = (void *)rp;
	lwp0.lwp_procp = &p0;
	t0.t_tid = p0.p_lwpcnt = p0.p_lwprcnt = p0.p_lwpid = 1;

	p0.p_exec = NULL;
	p0.p_stat = SRUN;
	p0.p_flag = SSYS;
	p0.p_tlist = &t0;
	p0.p_stksize = 2*PAGESIZE;
	p0.p_stkpageszc = 0;
	p0.p_as = &kas;
	p0.p_lockp = &p0lock;
	p0.p_brkpageszc = 0;
	p0.p_t1_lgrpid = LGRP_NONE;
	p0.p_tr_lgrpid = LGRP_NONE;
	psecflags_default(&p0.p_secflags);

	sigorset(&p0.p_ignore, &ignoredefault);

	CPU->cpu_thread = &t0;
	bzero(&cpu0_disp, sizeof (disp_t));
	CPU->cpu_disp = &cpu0_disp;
	CPU->cpu_disp->disp_cpu = CPU;
	CPU->cpu_dispthread = &t0;
	CPU->cpu_idle_thread = &t0;
	CPU->cpu_flags = CPU_READY | CPU_RUNNING | CPU_EXISTS | CPU_ENABLE;
	CPU->cpu_dispatch_pri = t0.t_pri;

	CPU->cpu_id = 0;

	CPU->cpu_pri = 12;		/* initial PIL for the boot CPU */

	/*
	 * Initialize thread/cpu microstate accounting
	 *
	 * XXXAARCH64: Needs access to timers, must check that this is all set
	 * up correctly per DDI0487G page 4216.  Both of the following need
	 * the timers.
	 */
	init_mstate(&t0, LMS_SYSTEM);
	init_cpu_mstate(CPU, CMS_SYSTEM);

	/*
	 * Initialize lists of available and active CPUs.
	 */
	cpu_list_init(CPU);

	pg_cpu_bootstrap(CPU);

#if 0
	/*
	 * XXXAARCH64: kmdb... we need this, later.
	 */
	/*
	 * Now that we have taken over the GDT, IDT and have initialized
	 * active CPU list it's time to inform kmdb if present.
	 */
	if (boothowto & RB_DEBUG)
		kdi_idt_sync();

	/*
	 * If requested (boot -d) drop into kmdb.
	 *
	 * This must be done after cpu_list_init() on the 64-bit kernel
	 * since taking a trap requires that we re-compute gsbase based
	 * on the cpu list.
	 */
	if (boothowto & RB_DEBUGENTER)
		kmdb_enter();
#endif

	cpu_vm_data_init(CPU);

	rp->r_fp = 0;	/* terminate kernel stack traces! */

	prom_init("kernel", (void *)NULL);

	/* User-set option overrides firmware value. */
	if (bootprop_getval(PLAT_DR_OPTIONS_NAME, &prop_value) == 0) {
		plat_dr_options = (uint64_t)prop_value;
	}
	/* Flag PLAT_DR_FEATURE_ENABLED should only be set by DR driver. */
	plat_dr_options &= ~PLAT_DR_FEATURE_ENABLED;

	/*
	 * Get value of "plat_dr_physmax" boot option.
	 * It overrides values calculated from MSCT or SRAT table.
	 */
	if (bootprop_getval(PLAT_DR_PHYSMAX_NAME, &prop_value) == 0) {
		plat_dr_physmax = ((uint64_t)prop_value) >> PAGESHIFT;
	}

	/* Get value of boot_ncpus. */
	if (bootprop_getval(BOOT_NCPUS_NAME, &prop_value) != 0) {
		boot_ncpus = NCPU;
	} else {
		boot_ncpus = (int)prop_value;
		if (boot_ncpus <= 0 || boot_ncpus > NCPU)
			boot_ncpus = NCPU;
	}

	/*
	 * Set max_ncpus and boot_max_ncpus to boot_ncpus if platform doesn't
	 * support CPU DR operations.
	 */
	if (plat_dr_support_cpu() == 0) {
		max_ncpus = boot_max_ncpus = boot_ncpus;
	} else {
		if (bootprop_getval(PLAT_MAX_NCPUS_NAME, &prop_value) != 0) {
			max_ncpus = NCPU;
		} else {
			max_ncpus = (int)prop_value;
			if (max_ncpus <= 0 || max_ncpus > NCPU) {
				max_ncpus = NCPU;
			}
			if (boot_ncpus > max_ncpus) {
				boot_ncpus = max_ncpus;
			}
		}

		if (bootprop_getval(BOOT_MAX_NCPUS_NAME, &prop_value) != 0) {
			boot_max_ncpus = boot_ncpus;
		} else {
			boot_max_ncpus = (int)prop_value;
			if (boot_max_ncpus <= 0 || boot_max_ncpus > NCPU) {
				boot_max_ncpus = boot_ncpus;
			} else if (boot_max_ncpus > max_ncpus) {
				boot_max_ncpus = max_ncpus;
			}
		}
	}

	/*
	 * Initialize the lgrp framework
	 *
	 * XXXAARCH64: this is hardwired to 1 lgroup at the moment, which is
	 * unnecessary.  Must port over i86pc ACPI init and platform bits as
	 * necessary.
	 */
	lgrp_init(LGRP_INIT_STAGE1);

	if (boothowto & RB_HALT) {
		prom_printf("unix: kernel halted by -h flag\n");
		prom_enter_mon();
	}

	/*  we're on aarch64 - we'd have exploded if this was not the case */
	ASSERT_STACK_ALIGNED();

#if 0
	/*
	 * Fill out cpu_ucode_info.  Update microcode if necessary.
	 */
	ucode_check(CPU);
	cpuid_pass_ucode(CPU, x86_featureset);

	if (workaround_errata(CPU) != 0)
		panic("critical workaround(s) missing for boot cpu");
#endif
}


void
mach_modpath(char *path, const char *filename)
{
	/*
	 * Construct the directory path from the filename.
	 */

	int len;
	char *p;
	const char isastr[] = "/aarch64";
	size_t isalen = strlen(isastr);

	len = strlen(SYSTEM_BOOT_PATH "/kernel");
	(void) strcpy(path, SYSTEM_BOOT_PATH "/kernel ");
	path += len + 1;

	if ((p = strrchr(filename, '/')) == NULL)
		return;

	while (p > filename && *(p - 1) == '/')
		p--;	/* remove trailing '/' characters */
	if (p == filename)
		p++;	/* so "/" -is- the modpath in this case */

	/*
	 * Remove optional isa-dependent directory name - the module
	 * subsystem will put this back again (!)
	 */
	len = p - filename;
	if (len > isalen &&
	    strncmp(&filename[len - isalen], isastr, isalen) == 0)
		p -= isalen;

	/*
	 * "/platform/mumblefrotz" + " " + MOD_DEFPATH
	 */
	len += (p - filename) + 1 + strlen(MOD_DEFPATH) + 1;
	(void) strncpy(path, filename, p - filename);
}
