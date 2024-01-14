
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
 * Copyright 2024 Michael van der Westhuizen
 * Copyright 2017 Hayashi Naoyuki
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright (c) 2009-2010, Intel Corporation.
 * All rights reserved.
 */

#define	PSMI_1_7
#include <sys/smp_impldefs.h>
#include <sys/cmn_err.h>
#include <sys/strlog.h>
#include <sys/clock.h>
#include <sys/debug.h>
#include <sys/rtc.h>
#include <sys/cpupart.h>
#include <sys/cpuvar.h>
#include <sys/cpu_event.h>
#include <sys/cmt.h>
#include <sys/cpu.h>
#include <sys/disp.h>
#include <sys/archsystm.h>
#include <sys/machsystm.h>
#include <sys/sysmacros.h>
#include <sys/memlist.h>
#include <sys/param.h>
#include <sys/promif.h>
#include <sys/cpu_pm.h>
#include <sys/gic.h>
#include <sys/controlregs.h>
#include <sys/irq.h>
#include <sys/cpuinfo.h>
#include <sys/psm_modctl.h>
#include <sys/prom_debug.h>
#include <sys/xc_levels.h>
#include <sys/x_call.h>

#define	OFFSETOF(s, m)		(size_t)(&(((s *)0)->m))

extern void return_instr(void);

uint_t cp_haltset_fanout = 0;

/*
 * Local Static Data
 */
static struct psm_ops mach_ops;
static struct psm_ops *mach_set[4] = {&mach_ops, NULL, NULL, NULL};
static ushort_t mach_ver[4] = {0, 0, 0, 0};

static void explode(void);

static void mach_init(void);

static int mach_intr_enter(int ipl, uint64_t *cookiep, uint32_t *vectorp);

static int mach_translate_irq(dev_info_t *dip, int irqno);
static int mach_intr_ops(dev_info_t *dip, ddi_intr_handle_impl_t *hdlp,
    psm_intr_op_t intr_op, int *result);
static int mp_disable_intr(int cpun);
static void mp_enable_intr(int cpun);

/*
 * PSM functions initialization
 */
int (*ap_mlsetup)(void)		= (int (*)(void))explode;
void (*send_dirintf)(cpuset_t, int)	= (void (*)(cpuset_t, int))explode;
void (*setspl)(int)             = (void (*)(int))explode;
int (*addspl)(int, int, int, int) = (int (*)(int, int, int, int))explode;
int (*delspl)(int, int, int, int) = (int (*)(int, int, int, int))explode;
int (*psm_config_irq)(uint32_t, int) = (int (*)(uint32_t, int))explode;
void (*psm_shutdownf)(int, int) = (void (*)(int, int))explode;
void (*psm_preshutdownf)(int, int) = (void (*)(int, int))explode;
void (*psm_notifyf)(int)        = (void (*)(int))explode;
void (*psm_set_idle_cpuf)(int)  = (void (*)(int))explode;
void (*psm_unset_idle_cpuf)(int) = (void (*)(int))explode;
void (*psminitf)()		= mach_init;

int (*psm_disable_intr)(int)    = mp_disable_intr;
void (*psm_enable_intr)(int)    = mp_enable_intr;

int (*psm_get_ipivect)(int, int) = NULL;

void (*picinitf)()              = explode;
int (*clkinitf)(int, int *)     = (int (*)(int, int *))explode;

int (*psm_get_clockirq)(int) = NULL;
int (*psm_translate_irq)(dev_info_t *, int) = mach_translate_irq;

/* xx */
int (*psm_clkinit)(int) = NULL;
void (*psm_timer_reprogram)(hrtime_t) = NULL;
void (*psm_timer_enable)(void) = NULL;
void (*psm_timer_disable)(void) = NULL;
void (*psm_post_cyclic_setup)(void *arg) = NULL;
/* xx */
int (*psm_state)(psm_state_request_t *) = (int (*)(psm_state_request_t *))
    explode;
int (*psm_intr_ops)(dev_info_t *, ddi_intr_handle_impl_t *, psm_intr_op_t,
    int *) = mach_intr_ops;
/* xx */

void (*psm_notify_error)(int, char *) = (void (*)(int, char *))NULL;
void (*notify_error)(int, char *) = (void (*)(int, char *))explode;

int (*addintr)(void *, int, avfunc, char *, int, caddr_t, caddr_t, uint64_t *,
    dev_info_t *) = NULL;
void (*remintr)(void *, int, avfunc, int) = NULL;
void (*setsoftint)(int, struct av_softinfo *) =
	(void (*)(int, struct av_softinfo *))explode;
void (*kdisetsoftint)(int, struct av_softinfo *) =
	(void (*)(int, struct av_softinfo *))explode;
int (*slvltovect)(int) = (int (*)(int))explode;

int (*psm_intr_enter)(int, uint64_t *, uint32_t *) = mach_intr_enter;
void (*psm_intr_exit)(int, uint64_t) = (void (*)(int, uint64_t))explode;

static int
mach_softlvl_to_vect(int ipl)
{
	setsoftint = av_set_softint_pending;
	kdisetsoftint = kdi_av_set_softint_pending;

	return (-1);
}

int
pg_plat_hw_shared(cpu_t *cp, pghw_type_t hw)
{
	switch (hw) {
	case PGHW_CHIP:
		return (1);
	case PGHW_CACHE:
		return (1);
	default:
		return (0);
	}
}

/*
 * Compare two CPUs and see if they have a pghw_type_t sharing relationship
 * If pghw_type_t is an unsupported hardware type, then return -1
 */
int
pg_plat_cpus_share(cpu_t *cpu_a, cpu_t *cpu_b, pghw_type_t hw)
{
	id_t pgp_a, pgp_b;

	pgp_a = pg_plat_hw_instance_id(cpu_a, hw);
	pgp_b = pg_plat_hw_instance_id(cpu_b, hw);

	if (pgp_a == -1 || pgp_b == -1)
		return (-1);

	return (pgp_a == pgp_b);
}


/*
 * Return a physical instance identifier for known hardware sharing
 * relationships
 */
id_t
pg_plat_hw_instance_id(cpu_t *cpu, pghw_type_t hw)
{
	switch (hw) {
	case PGHW_CACHE:
		return (read_mpidr() & 0xFF);
	case PGHW_CHIP:
		return (((read_mpidr() >> 16) |
		    (read_mpidr() >> 8)) & 0xFFFFFF);
	default:
		return (-1);
	}
}

/*
 * Override the default CMT dispatcher policy for the specified
 * hardware sharing relationship
 */
pg_cmt_policy_t
pg_plat_cmt_policy(pghw_type_t hw)
{
	switch (hw) {
	case PGHW_CACHE:
		return (CMT_BALANCE|CMT_AFFINITY);
	default:
		return (CMT_NO_POLICY);
	}
}

id_t
pg_plat_get_core_id(cpu_t *cpu)
{
	return (read_mpidr() & 0xFF);
}

pghw_type_t
pg_plat_hw_rank(pghw_type_t hw1, pghw_type_t hw2)
{
	int i, rank1, rank2;

	static pghw_type_t hw_hier[] = {
		PGHW_CACHE,
		PGHW_CHIP,
		PGHW_NUM_COMPONENTS
	};

	for (i = 0; hw_hier[i] != PGHW_NUM_COMPONENTS; i++) {
		if (hw_hier[i] == hw1)
			rank1 = i;
		if (hw_hier[i] == hw2)
			rank2 = i;
	}

	if (rank1 > rank2)
		return (hw1);
	else
		return (hw2);
}

void
cmp_set_nosteal_interval(void)
{
	/* Set the nosteal interval (used by disp_getbest()) to 100us */
	nosteal_nsec = 100000UL;
}

int
cu_plat_cpc_init(cpu_t *cp, kcpc_request_list_t *reqs, int nreqs)
{
	return (-1);
}

void
mach_cpu_pause(volatile char *safe)
{
	/*
	 * This cpu is now safe.
	 */
	*safe = PAUSE_WAIT;
	membar_enter(); /* make sure stores are flushed */

	/*
	 * Now we wait.  When we are allowed to continue, safe
	 * will be set to PAUSE_IDLE.
	 */
	while (*safe != PAUSE_IDLE)
		SMT_PAUSE();
}

void
cpu_halt(void)
{
	cpu_t *cpup = CPU;
	processorid_t cpu_sid = cpup->cpu_seqid;
	cpupart_t *cp = cpup->cpu_part;
	int hset_update = 1;
	volatile int *p = &cpup->cpu_disp->disp_nrunnable;
	uint_t s;

	/*
	 * If this CPU is online then we should note our halting
	 * by adding ourselves to the partition's halted CPU
	 * bitset. This allows other CPUs to find/awaken us when
	 * work becomes available.
	 */
	if (CPU->cpu_flags & CPU_OFFLINE)
		hset_update = 0;

	/*
	 * Add ourselves to the partition's halted CPUs bitset
	 * and set our HALTED flag, if necessary.
	 *
	 * When a thread becomes runnable, it is placed on the queue
	 * and then the halted cpu bitset is checked to determine who
	 * (if anyone) should be awoken. We therefore need to first
	 * add ourselves to the halted bitset, and then check if there
	 * is any work available.  The order is important to prevent a race
	 * that can lead to work languishing on a run queue somewhere while
	 * this CPU remains halted.
	 *
	 * Either the producing CPU will see we're halted and will awaken us,
	 * or this CPU will see the work available in disp_anywork()
	 */
	if (hset_update) {
		cpup->cpu_disp_flags |= CPU_DISP_HALTED;
		membar_producer();
		bitset_atomic_add(&cp->cp_haltset, cpu_sid);
	}

	/*
	 * Check to make sure there's really nothing to do.
	 * Work destined for this CPU may become available after
	 * this check. We'll be notified through the clearing of our
	 * bit in the halted CPU bitset, and a poke.
	 */
	if (disp_anywork()) {
		if (hset_update) {
			cpup->cpu_disp_flags &= ~CPU_DISP_HALTED;
			bitset_atomic_del(&cp->cp_haltset, cpu_sid);
		}
		return;
	}

	/*
	 * We're on our way to being halted.  Wait until something becomes
	 * runnable locally or we are awakened (i.e. removed from the halt
	 * set).  Note that the call to hv_cpu_yield() can return even if we
	 * have nothing to do.
	 *
	 * Disable interrupts now, so that we'll awaken immediately
	 * after halting if someone tries to poke us between now and
	 * the time we actually halt.
	 *
	 * We check for the presence of our bit after disabling interrupts.
	 * If it's cleared, we'll return. If the bit is cleared after
	 * we check then the poke will pop us out of the halted state.
	 * Also, if the offlined CPU has been brought back on-line, then
	 * we return as well.
	 *
	 * The ordering of the poke and the clearing of the bit by cpu_wakeup
	 * is important.
	 * cpu_wakeup() must clear, then poke.
	 * cpu_halt() must disable interrupts, then check for the bit.
	 *
	 * The check for anything locally runnable is here for performance
	 * and isn't needed for correctness. disp_nrunnable ought to be
	 * in our cache still, so it's inexpensive to check, and if there
	 * is anything runnable we won't have to wait for the poke.
	 *
	 * Any interrupt will awaken the cpu from halt. Looping here
	 * will filter spurious interrupts that wake us up, but don't
	 * represent a need for us to head back out to idle().  This
	 * will enable the idle loop to be more efficient and sleep in
	 * the processor pipeline for a larger percent of the time,
	 * which returns useful cycles to the peer hardware strand
	 * that shares the pipeline.
	 */
	s = disable_interrupts();
	while (*p == 0 &&
	    ((hset_update && bitset_in_set(&cp->cp_haltset, cpu_sid)) ||
	    (!hset_update && (CPU->cpu_flags & CPU_OFFLINE)))) {
		__asm__ volatile("wfi");
		restore_interrupts(s);
		s = disable_interrupts();
	}

	/*
	 * We're no longer halted
	 */
	restore_interrupts(s);
	if (hset_update) {
		cpup->cpu_disp_flags &= ~CPU_DISP_HALTED;
		bitset_atomic_del(&cp->cp_haltset, cpu_sid);
	}
}

static void
cpu_wakeup(cpu_t *cpu, int bound)
{
	uint_t		cpu_found;
	processorid_t	cpu_sid;
	cpupart_t	*cp;

	cp = cpu->cpu_part;
	cpu_sid = cpu->cpu_seqid;
	if (bitset_in_set(&cp->cp_haltset, cpu_sid)) {
		/*
		 * Clear the halted bit for that CPU since it will be
		 * poked in a moment.
		 */
		bitset_atomic_del(&cp->cp_haltset, cpu_sid);
		/*
		 * We may find the current CPU present in the halted cpu bitset
		 * if we're in the context of an interrupt that occurred
		 * before we had a chance to clear our bit in cpu_halt().
		 * Poking ourself is obviously unnecessary, since if
		 * we're here, we're not halted.
		 */
		if (cpu != CPU)
			poke_cpu(cpu->cpu_id);
		return;
	} else {
		/*
		 * This cpu isn't halted, but it's idle or undergoing a
		 * context switch. No need to awaken anyone else.
		 */
		if (cpu->cpu_thread == cpu->cpu_idle_thread ||
		    cpu->cpu_disp_flags & CPU_DISP_DONTSTEAL)
			return;
	}

	/*
	 * No need to wake up other CPUs if this is for a bound thread.
	 */
	if (bound)
		return;

	/*
	 * The CPU specified for wakeup isn't currently halted, so check
	 * to see if there are any other halted CPUs in the partition,
	 * and if there are then awaken one.
	 *
	 * If possible, try to select a CPU close to the target, since this
	 * will likely trigger a migration.
	 */
	do {
		cpu_found = bitset_find(&cp->cp_haltset);
		if (cpu_found == (uint_t)-1)
			return;
	} while (bitset_atomic_test_and_del(&cp->cp_haltset, cpu_found) < 0);

	if (cpu_found != CPU->cpu_seqid)
		poke_cpu(cpu_seq[cpu_found]->cpu_id);
}

static int
mp_disable_intr(int cpun)
{
	panic("unimplemented");
#if XXXARM
	/*
	 * switch to the offline CPU
	 */
	affinity_set(cpun);
	/*
	 * raise ipl to just below cross call
	 */
	splx(XC_SYS_PIL - 1);
	/*
	 * set base spl to prevent the next swtch to idle from
	 * lowering back to ipl 0
	 */
	CPU->cpu_intr_actv |= (1 << (XC_SYS_PIL - 1));
	set_base_spl();
	affinity_clear();
#endif
	return (DDI_SUCCESS);
}

static void
mp_enable_intr(int cpun)
{
	panic("unimplemented");
#if XXXARM
	/*
	 * switch to the online cpu
	 */
	affinity_set(cpun);
	/*
	 * clear the interrupt active mask
	 */
	CPU->cpu_intr_actv &= ~(1 << (XC_SYS_PIL - 1));
	set_base_spl();
	(void) spl0();
	affinity_clear();
#endif
}

static void
mach_get_platform(int owner)
{
	void	**srv_opsp;
	void	**clt_opsp;
	int	i;
	int	total_ops;

	/* fix up psm ops */
	srv_opsp = (void **)mach_set[0];
	clt_opsp = (void **)mach_set[owner];

	if (mach_ver[owner] == (ushort_t)PSM_INFO_VER01_0) {
		total_ops = OFFSETOF(struct psm_ops, psm_cpu_ops) /
		    sizeof (void (*)(void));
	} else {
		total_ops = sizeof (struct psm_ops) / sizeof (void (*)(void));
	}

	/*
	 * Save the version of the PSM module, in case we need to
	 * behave differently based on version.
	 */
	mach_ver[0] = mach_ver[owner];

	for (i = 0; i < total_ops; i++) {
		if (clt_opsp[i] != NULL)
			srv_opsp[i] = clt_opsp[i];
	}
}

static void
mach_construct_info(void)
{
	struct psm_sw	*swp;
	int		mach_cnt[PSM_OWN_OVERRIDE+1] = {0};
	int		conflict_owner = 0;

	if (psmsw->psw_forw == psmsw)
		panic("No valid PSM modules found");

	mutex_enter(&psmsw_lock);
	for (swp = psmsw->psw_forw; swp != psmsw; swp = swp->psw_forw) {
		if (!(swp->psw_flag & PSM_MOD_IDENTIFY))
			continue;
		mach_set[swp->psw_infop->p_owner] = swp->psw_infop->p_ops;
		mach_ver[swp->psw_infop->p_owner] = swp->psw_infop->p_version;
		mach_cnt[swp->psw_infop->p_owner]++;
	}
	mutex_exit(&psmsw_lock);

	mach_get_platform(PSM_OWN_SYS_DEFAULT);

	/* check to see are there any conflicts */
	if (mach_cnt[PSM_OWN_EXCLUSIVE] > 1)
		conflict_owner = PSM_OWN_EXCLUSIVE;
	if (mach_cnt[PSM_OWN_OVERRIDE] > 1)
		conflict_owner = PSM_OWN_OVERRIDE;
	if (conflict_owner) {
		/* remove all psm modules except armbsa */
		cmn_err(CE_WARN,
		    "Conflicts detected on the following PSM modules:");
		mutex_enter(&psmsw_lock);
		for (swp = psmsw->psw_forw; swp != psmsw; swp = swp->psw_forw) {
			if (swp->psw_infop->p_owner == conflict_owner)
				cmn_err(CE_WARN, "%s ",
				    swp->psw_infop->p_mach_idstring);
		}
		mutex_exit(&psmsw_lock);
		cmn_err(CE_WARN,
		    "Setting the system back to ARM BSA mode!");
		cmn_err(CE_WARN,
		    "Please edit /etc/mach to remove the invalid PSM module.");
		return;
	}

	if (mach_set[PSM_OWN_EXCLUSIVE])
		mach_get_platform(PSM_OWN_EXCLUSIVE);

	if (mach_set[PSM_OWN_OVERRIDE])
		mach_get_platform(PSM_OWN_OVERRIDE);
}

static void
mach_picinit(void)
{
	struct psm_ops	*pops;

	PRM_POINT("mach_picinit()");
	pops = mach_set[0];

	/* register the interrupt handlers */
	psm_intr_enter = pops->psm_intr_enter;
	psm_intr_exit = pops->psm_intr_exit;

	PRM_POINT("pops->psm_picinit()");
	/* initialize the interrupt hardware */
	(*pops->psm_picinit)();

	/* set interrupt mask for current ipl */
	setspl = pops->psm_setspl;
	psm_config_irq = pops->psm_config_irq;
	(void) disable_interrupts();
	PRM_POINT("about to setspl");
	PRM_DEBUG(CPU->cpu_pri);
	setspl(CPU->cpu_pri);

	/*
	 * XXXARM: fix this properly
	 *
	 * Set up CPU cross-calls.
	 * In xc_init() at the moment, must extract to here or otherwise
	 * pass in the psm_get_ipivect stuff.
	 *
	 * xc_init((*pops->psm_get_ipivect)(XC_HI_PIL, PSM_INTR_IPI_HI),
	 *     (*pops->psm_get_ipivect)(XC_CPUPOKE_PIL, PSM_INTR_POKE));
	 *
	 * ... or just call psm_get_ipivect from xc_init (better, I think)
	 *
	 * ... though we really don't need that function _at the moment_.
	 */
	PRM_POINT("xc_init()");
	xc_init();
	PRM_POINT("mach_picinit() done");
}

/* XXXARM: do we need/want this? */
static int
mach_clkinit(int preferred_mode, int *set_mode)
{
	return (0);
}

/* XXXARM: we want a vector type */
static int
mach_translate_irq(dev_info_t *dip, int irqno)
{
	return (irqno);	/* default to NO translation */
}

static void
mach_notify_error(int level, char *errmsg)
{
	/*
	 * SL_FATAL is pass in once panicstr is set, deliver it
	 * as CE_PANIC.  Also, translate SL_ codes back to CE_
	 * codes for the psmi handler.
	 */
	if (level & SL_FATAL)
		(*notify_error)(CE_PANIC, errmsg);
	else if (level & SL_WARN)
		(*notify_error)(CE_WARN, errmsg);
	else if (level & SL_NOTE)
		(*notify_error)(CE_NOTE, errmsg);
	else if (level & SL_CONSOLE)
		(*notify_error)(CE_CONT, errmsg);
}

/*
 * Provides the default basic intr_ops interface for the DDI
 * interrupt framework if the PSM doesn't have one.
 *
 * Input:
 * dip     - pointer to the dev_info structure of the requested device
 * hdlp    - pointer to the internal interrupt handle structure for the
 *           requested interrupt
 * intr_op - opcode for this call
 * result  - pointer to the integer that will hold the result to be
 *           passed back if return value is PSM_SUCCESS
 *
 * Output:
 * Return value is either PSM_SUCCESS or PSM_FAILURE.
 */
static int
mach_intr_ops(dev_info_t *dip, ddi_intr_handle_impl_t *hdlp,
    psm_intr_op_t intr_op, int *result)
{
	switch (intr_op) {
	case PSM_INTR_OP_CHECK_MSI:
		*result = hdlp->ih_type & ~(DDI_INTR_TYPE_MSI |
		    DDI_INTR_TYPE_MSIX);
		break;
	case PSM_INTR_OP_ALLOC_VECTORS:
		if (hdlp->ih_type == DDI_INTR_TYPE_FIXED)
			*result = 1;
		else
			*result = 0;
		break;
	case PSM_INTR_OP_FREE_VECTORS:
		break;
	case PSM_INTR_OP_NAVAIL_VECTORS:
		if (hdlp->ih_type == DDI_INTR_TYPE_FIXED)
			*result = 1;
		else
			*result = 0;
		break;
	case PSM_INTR_OP_XLATE_VECTOR:
		*result = psm_translate_irq(dip, hdlp->ih_vector);
		break;
	case PSM_INTR_OP_GET_CAP:
		*result = 0;
		break;
	case PSM_INTR_OP_GET_PENDING:	/* fallthrough */
	case PSM_INTR_OP_CLEAR_MASK:	/* fallthrough */
	case PSM_INTR_OP_SET_MASK:	/* fallthrough */
	case PSM_INTR_OP_GET_SHARED:	/* fallthrough */
	case PSM_INTR_OP_SET_PRI:	/* fallthrough */
	case PSM_INTR_OP_SET_CAP:	/* fallthrough */
	case PSM_INTR_OP_SET_CPU:	/* fallthrough */
	case PSM_INTR_OP_GET_INTR:	/* fallthrough */
	default:
		return (PSM_FAILURE);
	}

	return (PSM_SUCCESS);
}

static void
mach_smpinit(void)
{
	struct psm_ops	*pops;
	processorid_t	cpu_id;
	int		cnt;
	cpuset_t	cpumask;

	pops = mach_set[0];
	CPUSET_ZERO(cpumask);

	cpu_id = -1;
	cpu_id = (*pops->psm_get_next_processorid)(cpu_id);
	/*
	 * Only add boot_ncpus CPUs to mp_cpus. Other CPUs will be handled
	 * by CPU DR driver at runtime.
	 */
	for (cnt = 0; cpu_id != -1 && cnt < boot_ncpus; cnt++) {
		PRM_DEBUG(cpu_id);
		CPUSET_ADD(cpumask, cpu_id);
		cpu_id = (*pops->psm_get_next_processorid)(cpu_id);
	}

	PRM_DEBUG(cnt);
	mp_cpus = cpumask;

	/* MP related routines */
	ap_mlsetup = pops->psm_post_cpu_start;
	send_dirintf = pops->psm_send_ipi;

	/* optional MP related routines */
	if (pops->psm_shutdown)
		psm_shutdownf = pops->psm_shutdown;
	if (pops->psm_preshutdown)
		psm_preshutdownf = pops->psm_preshutdown;
	if (pops->psm_notify_func)
		psm_notifyf = pops->psm_notify_func;
	if (pops->psm_set_idlecpu)
		psm_set_idle_cpuf = pops->psm_set_idlecpu;
	if (pops->psm_unset_idlecpu)
		psm_unset_idle_cpuf = pops->psm_unset_idlecpu;

	psm_clkinit = pops->psm_clkinit;

	if (pops->psm_timer_reprogram)
		psm_timer_reprogram = pops->psm_timer_reprogram;

	if (pops->psm_timer_enable)
		psm_timer_enable = pops->psm_timer_enable;

	if (pops->psm_timer_disable)
		psm_timer_disable = pops->psm_timer_disable;

	if (pops->psm_post_cyclic_setup)
		psm_post_cyclic_setup = pops->psm_post_cyclic_setup;

	if (pops->psm_state)
		psm_state = pops->psm_state;

	/*
	 * Set these vectors here so they can be used by Suspend/Resume
	 * on UP machines.
	 */
	if (pops->psm_disable_intr)
		psm_disable_intr = pops->psm_disable_intr;
	if (pops->psm_enable_intr)
		psm_enable_intr  = pops->psm_enable_intr;

	/*
	 * Set this vector so it can be used by vmbus (for Hyper-V)
	 * Need this even for single-CPU systems.  This works for
	 * "pcplusmp" and "apix" platforms, but not "uppc" (because
	 * "Uni-processor PC" does not provide a _get_ipivect).
	 */
	psm_get_ipivect = pops->psm_get_ipivect;

	/* check for multiple CPUs - XXXARM: plat_dr_support_cpu, see i96pc */
	if (cnt < 2)
		return;

	PRM_DEBUG(pops->psm_cpu_start);
	/* check for MP platforms */
	if (pops->psm_cpu_start == NULL)
		return;

	PRM_POINT("mach_smpinit() done");
}

static int
mach_intr_enter(int ipl, uint64_t *cookiep, uint32_t *vectorp)
{
	return (-1);
}

static void
mach_init(void)
{
	struct psm_ops	*pops;

	PRM_POINT("mach_construct_info()");
	mach_construct_info();

	pops = mach_set[0];

#if 0
	/* XXXARM: seems dodgy */
	CPU->cpu_pri = 0xFF;
#endif

	/* register the interrupt and clock initialization rotuines */
	picinitf = mach_picinit;
	clkinitf = mach_clkinit;
	psm_get_clockirq = pops->psm_get_clockirq;

	/* register the interrupt setup code */
	slvltovect = mach_softlvl_to_vect;
	addspl	= pops->psm_addspl;
	delspl	= pops->psm_delspl;

	if (pops->psm_translate_irq)
		psm_translate_irq = pops->psm_translate_irq;
	if (pops->psm_intr_ops)
		psm_intr_ops = pops->psm_intr_ops;

	if (pops->psm_notify_error) {
		psm_notify_error = mach_notify_error;
		notify_error = pops->psm_notify_error;
	}

	PRM_POINT("psm_softinit()");
	(*pops->psm_softinit)();

	/*
	 * Initialize the dispatcher's function hooks to enable CPU halting
	 * when idle.
	 *
	 * XXXARM: this is much more basic than i86pc, and could be closer
	 * to Intel platforms, especially in the ACPI case.
	 */
	idle_cpu = cpu_halt;
	disp_enq_thread = cpu_wakeup;

	PRM_POINT("mach_smpinit()");
	mach_smpinit();
	PRM_POINT("mach_init() done");
}

static void
explode(void)
{
	panic("explode: function called far too early");
}
