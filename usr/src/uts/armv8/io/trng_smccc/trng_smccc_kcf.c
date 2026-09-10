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
 * DEN0098 TRNG KCF provider: registration/unregistration, the
 * generate_random entry point, ext_info, FIPS state init/fini,
 * kstats, and the starvation/failure recovery machinery.
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#include <sys/atomic.h>
#include <sys/crypto/common.h>
#include <sys/crypto/spi.h>
#include <sys/smccc.h>
#include <sys/trng_smccc.h>

static void trng_provider_status(crypto_provider_handle_t, uint_t *);
static int trng_random_number(crypto_provider_handle_t,
	crypto_session_id_t, uchar_t *, size_t, crypto_req_handle_t);
static int trng_ext_info(crypto_provider_handle_t,
	crypto_provider_ext_info_t *, crypto_req_handle_t);

static int fips_init(trng_t *);
static void fips_fini(trng_t *);

/*
 * Provider description string, file-scoped by design.
 * KCF copies this during registration.
 */
static char trng_prov_desc[64];

static crypto_control_ops_t trng_control_ops = {
	.provider_status = trng_provider_status,
};

static crypto_random_number_ops_t trng_rng_ops = {
	.seed_random = NULL,
	.generate_random = trng_random_number,
};

static crypto_provider_management_ops_t trng_mgmt_ops = {
	.ext_info   = trng_ext_info,
	.init_token = NULL,
	.init_pin   = NULL,
	.set_pin    = NULL,
};

static crypto_ops_t trng_crypto_ops = {
	.co_control_ops     = &trng_control_ops,
	.co_digest_ops      = NULL,
	.co_cipher_ops      = NULL,
	.co_mac_ops         = NULL,
	.co_sign_ops        = NULL,
	.co_verify_ops      = NULL,
	.co_dual_ops        = NULL,
	.co_dual_cipher_mac_ops = NULL,
	.co_random_ops      = &trng_rng_ops,
	.co_session_ops     = NULL,
	.co_object_ops      = NULL,
	.co_key_ops         = NULL,
	.co_provider_ops    = &trng_mgmt_ops,
	.co_ctx_ops         = NULL,
};

/*
 * Positional initialization is used here as an explicit exception
 * to the designated-initializer preference: the spi.h macros route
 * v1 fields through piu.piu_v1 and pi_flags through piu.piu_v2,
 * so mixing them in a designated initializer would initialize
 * different union members.  Initializing positionally targets
 * piu.piu_v2 (v1_info followed by pi_flags) directly.
 */
static crypto_provider_info_t trng_prov_info = {
	CRYPTO_SPI_VERSION_2,
	NULL,				/* pi_provider_description */
	CRYPTO_HW_PROVIDER,
	NULL,				/* pi_provider_dev */
	NULL,				/* pi_provider_handle */
	&trng_crypto_ops,
	0,					/* number of mechanisms */
	NULL,				/* mechanism table */
	0,					/* pi_logical_provider_count */
	NULL,				/* pi_logical_providers */
	CRYPTO_SYNCHRONOUS			/* pi_flags */
};

static void
trng_provider_status(crypto_provider_handle_t provider __unused,
	uint_t *status)
{
	*status = CRYPTO_PROVIDER_READY;
}

/*
 * KCF generate_random entry point.
 *
 * Calls trng_fips_random() which internally fetches
 * entropy and post-processes through SHA1.
 *
 * This blocks synchronously like n2rng.  The provider advertises
 * CRYPTO_SYNCHRONOUS, so it must never return CRYPTO_QUEUED.
 */
static int
trng_random_number(crypto_provider_handle_t provider,
	crypto_session_id_t sess __unused, uchar_t *buf, size_t buflen,
	crypto_req_handle_t cfreq __unused)
{
	trng_t *trng = (trng_t *)provider;
	int rv;

	rv = trng_fips_random(trng, buf, buflen);

	/*
	 * Jobs count every request.  Bytes count only after
	 * complete success.
	 */
	atomic_inc_64(&trng->t_stats[TRNG_STAT_JOBS]);
	if (rv == CRYPTO_SUCCESS) {
		atomic_add_64(&trng->t_stats[TRNG_STAT_BYTES], buflen);
	}

	return (rv);
}

static void
strncpy_spacepad(uchar_t *s1, const char *s2, int n)
{
	int len = strlen(s2);

	(void) strncpy((char *)s1, s2, n);
	if (len < n) {
		(void) memset(s1 + len, ' ', n - len);
	}
}

static int
trng_ext_info(crypto_provider_handle_t provider,
	crypto_provider_ext_info_t *ext_info,
	crypto_req_handle_t cfreq __unused)
{
#define	BUFSZ	64
	trng_t *trng = (trng_t *)provider;
	char buf[BUFSZ];

	/* Manufacturer ID */
	strncpy_spacepad(ext_info->ei_manufacturerID,
		TRNG_SMCCC_MANUFACTURER, CRYPTO_EXT_SIZE_MANUF);

	/* Model */
	strncpy_spacepad(ext_info->ei_model, "SMCCC",
		CRYPTO_EXT_SIZE_MODEL);

	/* Token flags */
	ext_info->ei_flags = CRYPTO_EXTF_RNG |
		CRYPTO_EXTF_SO_PIN_LOCKED | CRYPTO_EXTF_WRITE_PROTECTED;

	ext_info->ei_max_session_count = CRYPTO_EFFECTIVELY_INFINITE;
	ext_info->ei_max_pin_len = 0;
	ext_info->ei_min_pin_len = 0;
	ext_info->ei_total_public_memory = CRYPTO_UNAVAILABLE_INFO;
	ext_info->ei_free_public_memory = CRYPTO_UNAVAILABLE_INFO;
	ext_info->ei_total_private_memory = CRYPTO_UNAVAILABLE_INFO;
	ext_info->ei_free_private_memory = CRYPTO_UNAVAILABLE_INFO;
	ext_info->ei_time[0] = '\0';

	/* Token label */
	(void) snprintf(buf, BUFSZ, "%s/%d %s",
		ddi_driver_name(trng->t_dip),
		ddi_get_instance(trng->t_dip),
		TRNG_SMCCC_IDENT);
	strncpy_spacepad(ext_info->ei_label, buf, CRYPTO_EXT_SIZE_LABEL);

	/*
	 * Serial number: use the DEN0098 version string.
	 * The UUID from TRNG_GET_UUID is a firmware
	 * implementation identifier for detecting vulnerable
	 * RNG implementations (DEN0098 §2.3), not a device
	 * serial number.
	 */
	(void) snprintf(buf, BUFSZ, "%u.%u",
		(trng->t_version >> 16) & 0x7fff,
		trng->t_version & 0xffff);
	strncpy_spacepad(ext_info->ei_serial_number,
		buf, CRYPTO_EXT_SIZE_SERIAL);

	/*
	 * DEN0098 §2.1.1 TRNG_VERSION format:
	 *   W0[31]    MBZ
	 *   W0[30:16] = major version (15 bits)
	 *   W0[15:0]  = minor version (16 bits)
	 *
	 * The KCF version fields are uchar_t, so versions beyond 255.255
	 * are truncated here; the full version is always available in the
	 * serial number string.
	 */
	ext_info->ei_hardware_version.cv_major =
		(uchar_t)((trng->t_version >> 16) & 0xff);
	ext_info->ei_hardware_version.cv_minor =
		(uchar_t)(trng->t_version & 0xff);
	ext_info->ei_firmware_version.cv_major = 0;
	ext_info->ei_firmware_version.cv_minor = 0;

	return (CRYPTO_SUCCESS);
#undef	BUFSZ
}

int
trng_register_provider(trng_t *trng)
{
	int ret;

	if (trng_is(trng, TRNG_F_REGISTERED)) {
		return (DDI_SUCCESS);
	}

	ret = crypto_register_provider(&trng_prov_info, &trng->t_prov);
	if (ret != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN,
			"trng_smccc: crypto_register_provider() failed (%d)",
			ret);
		trng->t_prov = 0;
		return (DDI_FAILURE);
	}

	trng_set(trng, TRNG_F_REGISTERED);
	crypto_provider_notification(trng->t_prov, CRYPTO_PROVIDER_READY);

	return (DDI_SUCCESS);
}

int
trng_unregister_provider(trng_t *trng)
{
	if (!trng_is(trng, TRNG_F_REGISTERED)) {
		return (DDI_SUCCESS);
	}

	if (crypto_unregister_provider(trng->t_prov) != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN,
			"trng_smccc: unable to unregister from KCF");
		return (DDI_FAILURE);
	}

	trng->t_prov = 0;
	trng_clr(trng, TRNG_F_REGISTERED);

	return (DDI_SUCCESS);
}

static void
trng_unregister_task(void *arg)
{
	trng_t *trng = (trng_t *)arg;

	if (trng_unregister_provider(trng) != DDI_SUCCESS) {
		trng_failure(trng);
	}
}

/*
 * Permanent failure: set TRNG_F_FAILED, dispatch async KCF
 * unregistration via the taskq.  swrand takes over as the
 * kernel RNG source.
 *
 * Used for SMCCC transport failures (EPERM from trng_smccc_rnd)
 * and for failed starvation recovery.  Unlike trng_starvation(),
 * this is terminal: no retry is attempted.
 *
 * TRNG_F_FAILED is never cleared, including across DDI_SUSPEND and
 * DDI_RESUME.  On resume the driver re-initializes and re-registers
 * normally; if the firmware is still broken the resume-time FIPS
 * initialization fails and resume returns DDI_FAILURE, and if the
 * firmware has recovered the driver generates data again but the
 * FAILED flag (and the kstat failure indication) remain set.
 *
 * t_lock is held across the flag check and dispatch so that
 * a concurrent detach cannot destroy the taskq between them.
 */
void
trng_failure(trng_t *trng)
{
	mutex_enter(&trng->t_lock);
	if (trng_is(trng, TRNG_F_FAILED) ||
		trng_is(trng, TRNG_F_ABANDON)) {
		mutex_exit(&trng->t_lock);
		return;
	}

	cmn_err(CE_WARN, "trng_smccc: hardware failure detected");
	trng_set(trng, TRNG_F_FAILED);

	if (ddi_taskq_dispatch(trng->t_taskq, trng_unregister_task,
		trng, DDI_NOSLEEP) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
			"trng_smccc: ddi_taskq_dispatch() failed");
	}
	mutex_exit(&trng->t_lock);
}

/*
 * Starvation recovery: taskq callback dispatched from
 * trng_recovery_timeout after TRNG_STARVATION_RETRY_SECS.
 *
 * Re-probes TRNG_VERSION (must succeed with W0 >= 0), then
 * requests an 8-byte entropy sample via trng_getentropy.
 * If both pass, sleeps TRNG_REREGISTER_DELAY_SECS to avoid
 * immediate re-starvation, resets all FIPS instance hunger
 * counters, and re-registers with KCF.
 *
 * Any failure, including crypto_unregister_provider or
 * trng_register_provider returning an error, is treated as
 * permanent (trng_failure).  No second attempt.
 *
 * Checks TRNG_F_ABANDON under t_lock before each major step
 * so detach/suspend can cleanly terminate recovery.
 *
 * Runs in taskq thread context, so delay() and mutex ops
 * are safe.
 */
static void
trng_recovery_task(void *arg)
{
	trng_t *trng = (trng_t *)arg;
	smccc32_args_t args;
	uint8_t sample[8];
	int rv;
	int i;

	mutex_enter(&trng->t_lock);
	if (trng_is(trng, TRNG_F_FAILED) ||
		trng_is(trng, TRNG_F_ABANDON)) {
		mutex_exit(&trng->t_lock);
		return;
	}
	mutex_exit(&trng->t_lock);

	/* Re-probe TRNG_VERSION */
	args = (smccc32_args_t){
		.w = { [0] = TRNG_VERSION }
	};
	rv = smccc32_call(&args);
	if (rv != 0 || (int32_t)args.w[0] < 0 ||
		(uint32_t)args.w[0] < 0x10000) {
		cmn_err(CE_WARN,
			"trng_smccc: starvation recovery failed "
			"(TRNG_VERSION not available)");
		trng_failure(trng);
		return;
	}

	/* Try to get a small entropy sample */
	rv = trng_getentropy(trng, sample, sizeof (sample));
	bzero(sample, sizeof (sample));
	if (rv != 0) {
		cmn_err(CE_WARN,
			"trng_smccc: starvation recovery failed "
			"(no entropy available)");
		trng_failure(trng);
		return;
	}

	/*
	 * Firmware looks healthy.  Wait before re-registering
	 * to reduce the chance of immediate re-starvation.
	 */
	delay(drv_usectohz(TRNG_REREGISTER_DELAY_SECS * 1000000));

	/* Check again after the long sleep */
	mutex_enter(&trng->t_lock);
	if (trng_is(trng, TRNG_F_ABANDON)) {
		mutex_exit(&trng->t_lock);
		return;
	}
	mutex_exit(&trng->t_lock);

	/* Reset starvation counters before re-registering */
	for (i = 0; i < TRNG_FIPS_INSTANCES; i++) {
		mutex_enter(&trng->t_frs.fipsarray[i].mtx);
		trng->t_frs.fipsarray[i].entropyhunger = 0;
		mutex_exit(&trng->t_frs.fipsarray[i].mtx);
	}

	if (trng_register_provider(trng) != DDI_SUCCESS) {
		trng_failure(trng);
		return;
	}

	mutex_enter(&trng->t_lock);
	trng_clr(trng, TRNG_F_STARVED);
	mutex_exit(&trng->t_lock);

	cmn_err(CE_NOTE,
		"trng_smccc: firmware entropy recovered, "
		"provider re-registered");
}

/*
 * Timeout callback: dispatches recovery work to the taskq
 * so it runs in thread context (delay is legal, unlike a
 * timeout callback which may run at elevated PIL).
 *
 * Checks TRNG_F_ABANDON under t_lock before dispatching:
 * if detach or suspend set ABANDON after arming this timeout,
 * the dispatch is skipped rather than hitting a destroyed taskq.
 */
static void
trng_recovery_timeout(void *arg)
{
	trng_t *trng = (trng_t *)arg;

	mutex_enter(&trng->t_lock);
	trng->t_retry_id = 0;
	if (trng_is(trng, TRNG_F_ABANDON)) {
		mutex_exit(&trng->t_lock);
		return;
	}
	mutex_exit(&trng->t_lock);

	if (ddi_taskq_dispatch(trng->t_taskq, trng_recovery_task,
		trng, DDI_NOSLEEP) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
			"trng_smccc: recovery dispatch failed");
		trng_failure(trng);
	}
}

/*
 * Sustained entropy starvation: unregister from KCF and
 * schedule a recovery probe after TRNG_STARVATION_RETRY_SECS.
 *
 * Unlike trng_failure(), this is not permanent.  The firmware
 * entropy source may recover.  swrand serves as the kernel
 * RNG while recovery is pending.
 *
 * The unregister runs via the taskq (same as trng_failure) to
 * avoid calling crypto_unregister_provider from the KCF
 * callback context.  The 60-second timeout then dispatches
 * the recovery probe to the same single-threaded taskq, so
 * the probe is serialized after the unregister.
 *
 * t_lock is held across the flag check, dispatch, and timeout
 * arm so that a concurrent detach cannot destroy the taskq or
 * miss the armed timeout between those steps.
 */
void
trng_starvation(trng_t *trng)
{
	mutex_enter(&trng->t_lock);
	if (trng_is(trng, TRNG_F_STARVED) ||
		trng_is(trng, TRNG_F_FAILED) ||
		trng_is(trng, TRNG_F_ABANDON)) {
		mutex_exit(&trng->t_lock);
		return;
	}

	cmn_err(CE_WARN,
		"trng_smccc: entropy starvation detected, "
		"unregistering provider");
	trng_set(trng, TRNG_F_STARVED);

	if (ddi_taskq_dispatch(trng->t_taskq, trng_unregister_task,
		trng, DDI_NOSLEEP) != DDI_SUCCESS) {
		mutex_exit(&trng->t_lock);
		cmn_err(CE_WARN,
			"trng_smccc: ddi_taskq_dispatch() failed");
		trng_failure(trng);
		return;
	}

	trng->t_retry_id = timeout(trng_recovery_timeout, trng,
		drv_usectohz(TRNG_STARVATION_RETRY_SECS * 1000000));
	mutex_exit(&trng->t_lock);
}

/*
 * Initialize kstats, FIPS state, and register with KCF.
 * Called from attach and resume.
 */
int
trng_init(trng_t *trng)
{
	int ret;

	if (!trng_is(trng, TRNG_F_INITIALIZED)) {
		trng_ksinit(trng);

		ret = fips_init(trng);
		if (ret != 0) {
			trng_ksdeinit(trng);
			return (DDI_FAILURE);
		}
	}

	(void) snprintf(trng_prov_desc, sizeof (trng_prov_desc),
		"%s/%d %s",
		ddi_driver_name(trng->t_dip),
		ddi_get_instance(trng->t_dip),
		TRNG_SMCCC_IDENT);
	trng_prov_info.pi_provider_description = trng_prov_desc;
	trng_prov_info.pi_provider_dev.pd_hw = trng->t_dip;
	trng_prov_info.pi_provider_handle = trng;

	trng_set(trng, TRNG_F_INITIALIZED);

	ret = trng_register_provider(trng);
	if (ret != DDI_SUCCESS) {
		fips_fini(trng);
		trng_ksdeinit(trng);
		trng_clr(trng, TRNG_F_INITIALIZED);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * Unregister from KCF, tear down FIPS state and kstats.
 * Called from detach and suspend.
 */
int
trng_uninit(trng_t *trng)
{
	if (!trng_is(trng, TRNG_F_INITIALIZED)) {
		return (DDI_SUCCESS);
	}

	if (trng_unregister_provider(trng) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	fips_fini(trng);
	trng_ksdeinit(trng);
	trng_clr(trng, TRNG_F_INITIALIZED);

	return (DDI_SUCCESS);
}

static int
fips_init(trng_t *trng)
{
	int i;
	int rv;

	trng->t_frs.fips_round_robin_j = 0;
	for (i = 0; i < TRNG_FIPS_INSTANCES; i++) {
		rv = trng_fips_random_init(trng,
			&trng->t_frs.fipsarray[i]);
		if (rv != 0) {
			for (--i; i >= 0; --i) {
				trng_fips_random_fini(
					&trng->t_frs.fipsarray[i]);
			}
			return (rv);
		}
	}

	return (0);
}

static void
fips_fini(trng_t *trng)
{
	int i;

	for (i = 0; i < TRNG_FIPS_INSTANCES; i++) {
		trng_fips_random_fini(&trng->t_frs.fipsarray[i]);
	}
}

static int trng_ksupdate(kstat_t *, int);

void
trng_ksinit(trng_t *trng)
{
	trng_stat_t *tsp;
	int instance;

	if (ddi_prop_exists(DDI_DEV_T_ANY, trng->t_dip,
	    DDI_PROP_DONTPASS, "nostats")) {
		return;
	}

	instance = ddi_get_instance(trng->t_dip);

	trng->t_ksp = kstat_create("trng_smccc", instance, NULL, "misc",
		KSTAT_TYPE_NAMED,
		sizeof (trng_stat_t) / sizeof (kstat_named_t),
		0);
	if (trng->t_ksp == NULL) {
		cmn_err(CE_WARN, "trng_smccc: unable to create kstats");
		return;
	}

	tsp = (trng_stat_t *)trng->t_ksp->ks_data;

	kstat_named_init(&tsp->ts_status, "status",
		KSTAT_DATA_CHAR);
	kstat_named_init(&tsp->ts_algs[TRNG_STAT_BYTES],
		"rngbytes", KSTAT_DATA_ULONGLONG);
	kstat_named_init(&tsp->ts_algs[TRNG_STAT_JOBS],
		"rngjobs", KSTAT_DATA_ULONGLONG);
	kstat_named_init(&tsp->ts_algs[TRNG_STAT_RETRIES],
		"rngretries", KSTAT_DATA_ULONGLONG);
	kstat_named_init(&tsp->ts_algs[TRNG_STAT_CALL_RETRIES],
		"rngcallretries", KSTAT_DATA_ULONGLONG);

	trng->t_ksp->ks_update = trng_ksupdate;
	trng->t_ksp->ks_private = trng;
	kstat_install(trng->t_ksp);
}

void
trng_ksdeinit(trng_t *trng)
{
	if (trng->t_ksp != NULL) {
		kstat_delete(trng->t_ksp);
		trng->t_ksp = NULL;
	}
}

static int
trng_ksupdate(kstat_t *ksp, int rw)
{
	trng_t *trng = (trng_t *)ksp->ks_private;
	trng_stat_t *tsp = (trng_stat_t *)ksp->ks_data;
	int i;

	if (rw == KSTAT_WRITE) {
		return (EACCES);
	}

	if (trng_is(trng, TRNG_F_FAILED)) {
		(void) strcpy(tsp->ts_status.value.c, "failed");
	} else if (trng_is(trng, TRNG_F_REGISTERED)) {
		(void) strcpy(tsp->ts_status.value.c, "online");
	} else {
		(void) strcpy(tsp->ts_status.value.c, "offline");
	}

	for (i = 0; i < TRNG_MAX_STATS; i++) {
		tsp->ts_algs[i].value.ull = trng->t_stats[i];
	}

	return (0);
}
