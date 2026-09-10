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
 * Copyright 2026 Michael van der Westhuizen
 */

/*
 * DEN0098 TRNG pseudo-driver: probe, attach, detach, suspend/resume.
 * All KCF provider logic lives in trng_smccc_kcf.c; entropy retrieval
 * and FIPS post-processing live in trng_smccc_provider.c.
 */

#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#include <sys/byteorder.h>
#include <sys/sysmacros.h>
#include <sys/smccc.h>
#include <sys/trng_smccc.h>

static int trng_probe(dev_info_t *);
static int trng_attach(dev_info_t *, ddi_attach_cmd_t);
static int trng_detach(dev_info_t *, ddi_detach_cmd_t);

/*
 * No cb_ops: this driver exposes no device nodes.
 * All access is through KCF.
 */
static struct dev_ops trng_devops = {
	.devo_rev       = DEVO_REV,
	.devo_refcnt    = 0,
	.devo_getinfo   = nodev,
	.devo_identify  = nulldev,
	.devo_probe     = trng_probe,
	.devo_attach    = trng_attach,
	.devo_detach    = trng_detach,
	.devo_reset     = nodev,
	.devo_cb_ops    = NULL,
	.devo_bus_ops   = NULL,
	.devo_power     = ddi_power,
	.devo_quiesce   = ddi_quiesce_not_needed,
};

static struct modldrv modldrv = {
	.drv_modops     = &mod_driverops,
	.drv_linkinfo   = "DEN0098 TRNG Driver",
	.drv_dev_ops    = &trng_devops,
};

static struct modlinkage modlinkage = {
	.ml_rev         = MODREV_1,
	.ml_linkage     = { &modldrv, NULL },
};

void *trng_softstate = NULL;

int
_init(void)
{
	int rv;

	rv = ddi_soft_state_init(&trng_softstate, sizeof (trng_t), 1);
	if (rv != 0) {
		return (rv);
	}

	rv = mod_install(&modlinkage);
	if (rv != 0) {
		ddi_soft_state_fini(&trng_softstate);
	}

	return (rv);
}

int
_fini(void)
{
	int rv;

	rv = mod_remove(&modlinkage);
	if (rv == 0) {
		ddi_soft_state_fini(&trng_softstate);
	}

	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * Functions we require from the TRNG implementation.
 */
static const uint32_t trng_required_fids[] = {
	TRNG_GET_UUID,
};

static int
trng_check_feature(uint32_t fid)
{
	smccc32_args_t args = {
		.w = { [0] = TRNG_FEATURES, [1] = fid }
	};
	int rv;

	rv = smccc32_call(&args);
	if (rv != 0 || (int32_t)args.w[0] < 0) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
trng_probe(dev_info_t *dip __unused)
{
	int rv;
	int i;
	smccc32_args_t args = {
		.w = { [0] = TRNG_VERSION }
	};

	/* DEN0098 §2.1.3: SMCCC >= 1.1 required before calling TRNG_VERSION */
	if (smccc_version() < 0x10001) {
		return (DDI_PROBE_FAILURE);
	}

	/*
	 * Confirm the TRNG interface exists
	 *
	 * DEN0098 §2.1.1: W0 >= 0 on success
	 */
	rv = smccc32_call(&args);
	if (rv != 0 || (int32_t)args.w[0] < 0) {
		return (DDI_PROBE_FAILURE);
	}

	/* Require at least v1.0 */
	if ((uint32_t)args.w[0] < 0x10000) {
		return (DDI_PROBE_FAILURE);
	}

	/* Check every function we need */
	for (i = 0; i < ARRAY_SIZE(trng_required_fids); i++) {
		if (trng_check_feature(trng_required_fids[i]) != DDI_SUCCESS) {
			return (DDI_PROBE_FAILURE);
		}
	}

	/* Need at least one of RND64 or RND32 */
	if (trng_check_feature(TRNG_RND64) != DDI_SUCCESS &&
		trng_check_feature(TRNG_RND32) != DDI_SUCCESS) {
		return (DDI_PROBE_FAILURE);
	}

	return (DDI_PROBE_SUCCESS);
}

static int
trng_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	trng_t *trng;
	smccc32_args_t args;
	int instance;
	int rv;
	int val;

	instance = ddi_get_instance(dip);

	switch (cmd) {
	case DDI_RESUME:
		trng = ddi_get_soft_state(trng_softstate, instance);
		if (trng == NULL) {
			return (DDI_FAILURE);
		}
		/* Re-init FIPS, kstats, re-register with KCF */
		return (trng_init(trng) == DDI_SUCCESS ?
			DDI_SUCCESS : DDI_FAILURE);

	case DDI_ATTACH:
		break;
	default:
		return (DDI_FAILURE);
	}

	/* Only instance 0 */
	if (instance != 0) {
		return (DDI_FAILURE);
	}

	rv = ddi_soft_state_zalloc(trng_softstate, instance);
	if (rv != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	trng = ddi_get_soft_state(trng_softstate, instance);
	trng->t_dip = dip;
	mutex_init(&trng->t_lock, NULL, MUTEX_DRIVER, NULL);

	/*
	 * Read DEN0098 version.  DEN0098 §2.1.1:
	 *   W0 >= 0 on success; W0[31] MBZ.
	 *   W0[30:16] = major version (15 bits)
	 *   W0[15:0]  = minor version (16 bits)
	 *   W1-W3 are reserved MBZ.
	 * Probe already confirmed a successful VERSION call.
	 */
	args = (smccc32_args_t){
		.w = { [0] = TRNG_VERSION }
	};
	rv = smccc32_call(&args);
	if (rv != 0 || (int32_t)args.w[0] < 0) {
		goto fail;
	}
	trng->t_version = (uint32_t)args.w[0];

	/* Require at least v1.0; all four functions are mandatory from v1.0 */
	if (trng->t_version < 0x10000) {
		goto fail;
	}

	/* Determine RND call: prefer RND64 */
	if (trng_check_feature(TRNG_RND64) == DDI_SUCCESS) {
		trng_set(trng, TRNG_F_RND64);
	}

	/*
	 * Fetch UUID for ext_info.  DEN0098 §2.3.1: the UUID
	 * occupies all four return registers (w0-w3) with no
	 * separate status word.  The only error indicator is
	 * w0 == NOT_SUPPORTED (0xFFFFFFFF); the spec requires
	 * UUID[31:0] != 0xFFFFFFFF so the two are
	 * distinguishable.
	 *
	 * NOT_SUPPORTED is tolerable (firmware may not
	 * implement GET_UUID even though FEATURES claimed it).
	 * Any other error (transport failure) fails attach.
	 *
	 * Store each word in LE byte order via LE_32().
	 */
	args = (smccc32_args_t){
		.w = { [0] = TRNG_GET_UUID }
	};
	rv = smccc32_call(&args);
	if (rv != 0) {
		goto fail;
	}
	if (args.w[0] != (uint32_t)TRNG_NOT_SUPPORTED) {
		uint32_t u[4] = {
			[0] = LE_32(args.w[0]),
			[1] = LE_32(args.w[1]),
			[2] = LE_32(args.w[2]),
			[3] = LE_32(args.w[3]),
		};
		bcopy(u, trng->t_uuid, sizeof (trng->t_uuid));
	}

	/*
	 * Read attempt tunables from driver properties.
	 * Each value is the total number of SMCCC calls per phase.
	 * A value of 0 selects the compiled default; negative
	 * values are rejected (logged to the message log only
	 * via the ! prefix) and fall back to the default.
	 */
	val = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		DDI_PROP_DONTPASS, "trng-busywait-attempts",
		TRNG_DEF_BUSYWAIT_ATTEMPTS);
	if (val < 0) {
		cmn_err(CE_NOTE,
			"!trng_smccc: trng-busywait-attempts %d "
			"negative, using default %d",
			val, TRNG_DEF_BUSYWAIT_ATTEMPTS);
		val = TRNG_DEF_BUSYWAIT_ATTEMPTS;
	} else if (val == 0) {
		val = TRNG_DEF_BUSYWAIT_ATTEMPTS;
	}
	trng->t_busywait_attempts = val;

	val = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		DDI_PROP_DONTPASS, "trng-retry-delay-us",
		TRNG_DEF_RETRY_DELAY_US);
	if (val < 0) {
		cmn_err(CE_NOTE,
			"!trng_smccc: trng-retry-delay-us %d "
			"negative, using default %d",
			val, TRNG_DEF_RETRY_DELAY_US);
		val = TRNG_DEF_RETRY_DELAY_US;
	} else if (val == 0) {
		val = TRNG_DEF_RETRY_DELAY_US;
	}
	trng->t_retry_delay_us = val;

	val = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		DDI_PROP_DONTPASS, "trng-sleep-attempts",
		TRNG_DEF_SLEEP_ATTEMPTS);
	if (val < 0) {
		cmn_err(CE_NOTE,
			"!trng_smccc: trng-sleep-attempts %d "
			"negative, using default %d",
			val, TRNG_DEF_SLEEP_ATTEMPTS);
		val = TRNG_DEF_SLEEP_ATTEMPTS;
	} else if (val == 0) {
		val = TRNG_DEF_SLEEP_ATTEMPTS;
	}
	trng->t_sleep_attempts = val;

	/* Create taskq for async unregister on failure */
	trng->t_taskq = ddi_taskq_create(dip, "trng_taskq", 1,
		TASKQ_DEFAULTPRI, 0);
	if (trng->t_taskq == NULL) {
		goto fail;
	}

	/* Initialize FIPS state, kstats, and register with KCF */
	if (trng_init(trng) != DDI_SUCCESS) {
		goto fail;
	}

	return (DDI_SUCCESS);

fail:
	if (trng->t_taskq != NULL) {
		ddi_taskq_destroy(trng->t_taskq);
		trng->t_taskq = NULL;
	}
	mutex_destroy(&trng->t_lock);
	ddi_soft_state_free(trng_softstate, instance);
	return (DDI_FAILURE);
}

static int
trng_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance;
	trng_t *trng;
	timeout_id_t tid;

	instance = ddi_get_instance(dip);
	trng = ddi_get_soft_state(trng_softstate, instance);
	if (trng == NULL) {
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_SUSPEND:
		/*
		 * Signal any in-flight recovery to bail out, then
		 * cancel the timeout and drain the taskq.  Resume
		 * assumes a working RNG and re-inits from scratch;
		 * if the firmware is still starved, normal starvation
		 * detection kicks in again.
		 */
		mutex_enter(&trng->t_lock);
		trng_set(trng, TRNG_F_ABANDON);
		tid = trng->t_retry_id;
		trng->t_retry_id = 0;
		mutex_exit(&trng->t_lock);
		if (tid != 0) {
			(void) untimeout(tid);
		}
		ddi_taskq_wait(trng->t_taskq);

		mutex_enter(&trng->t_lock);
		trng_clr(trng, TRNG_F_STARVED);
		trng_clr(trng, TRNG_F_ABANDON);
		mutex_exit(&trng->t_lock);

		/* Unregister from KCF, tear down FIPS state */
		return (trng_uninit(trng) == DDI_SUCCESS ?
			DDI_SUCCESS : DDI_FAILURE);

	case DDI_DETACH:
		break;
	default:
		return (DDI_FAILURE);
	}

	/* Signal recovery to abandon, cancel timeout, drain taskq */
	mutex_enter(&trng->t_lock);
	trng_set(trng, TRNG_F_ABANDON);
	tid = trng->t_retry_id;
	trng->t_retry_id = 0;
	mutex_exit(&trng->t_lock);
	if (tid != 0) {
		(void) untimeout(tid);
	}

	/* Drain taskq before teardown */
	if (trng->t_taskq != NULL) {
		ddi_taskq_destroy(trng->t_taskq);
		trng->t_taskq = NULL;
	}

	/* Unregister from KCF, tear down FIPS and kstats */
	if (trng_uninit(trng) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	mutex_destroy(&trng->t_lock);
	ddi_soft_state_free(trng_softstate, instance);

	return (DDI_SUCCESS);
}
