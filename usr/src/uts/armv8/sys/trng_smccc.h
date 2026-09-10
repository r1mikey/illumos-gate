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

#ifndef	_SYS_TRNG_SMCCC_H
#define	_SYS_TRNG_SMCCC_H

#include <sys/types.h>
#include <sys/mutex.h>
#include <sys/kstat.h>
#include <sys/taskq.h>
#include <sys/crypto/common.h>
#include <sys/crypto/spi.h>
#include <rng/fips_random.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * DEN0098 TRNG function IDs.
 */
/* SMC32 - Standard Secure Service (owner 4, fast call) */
#define	TRNG_VERSION		0x84000050
#define	TRNG_FEATURES		0x84000051
#define	TRNG_GET_UUID		0x84000052
#define	TRNG_RND32		0x84000053

/* SMC64 */
#define	TRNG_RND64		0xC4000053

/* Return codes (signed) */
#define	TRNG_SUCCESS		0
#define	TRNG_NOT_SUPPORTED	(-1)
#define	TRNG_INVALID_PARAMETERS	(-2)
#define	TRNG_NO_ENTROPY		(-3)

/*
 * FIPS 186-2 post-processing state, one per round-robin slot.
 * Mirrors the n2rng fipsrandomstruct_t layout; defined here
 * rather than importing the sun4v header.
 */
typedef struct trng_fips_state trng_fips_state_t;
struct trng_fips_state {
	kmutex_t	mtx;
	uint64_t	entropyhunger;	/* consecutive outputs w/o entropy */
	uint32_t	XKEY[6];	/* SHA1 seed: P2ROUNDUP(SHA1BYTES,8)/4 */
	uint32_t	x_jminus1[SHA1WORDS]; /* previous output for cont. test */
};

#define	TRNG_SMCCC_IDENT	"DEN0098_ARM_TRNG"
#define	TRNG_SMCCC_MANUFACTURER	"ARM"

/*
 * Number of FIPS post-processing instances for round-robin
 * selection.  Must be a power of 2 so the modulo in fips_random
 * is a cheap mask.  16 keeps contention low even on large machines
 * (e.g. 128-core Altra: 8 CPUs per slot on average).
 * boot_max_ncpus is available this early if we ever want to
 * scale dynamically.
 */
#define	TRNG_FIPS_INSTANCES	16

/*
 * Default attempt counts for TRNG_NO_ENTROPY.
 * Each value is the total number of SMCCC calls per phase,
 * not retries after a first call.
 * Phase 1: busy-wait with drv_usecwait.
 * Phase 2: sleeping with delay(1).
 * A property value of 0 selects the default.
 */
#define	TRNG_DEF_BUSYWAIT_ATTEMPTS	5
#define	TRNG_DEF_RETRY_DELAY_US		100
#define	TRNG_DEF_SLEEP_ATTEMPTS		10

/*
 * Maximum number of consecutive fips_random calls per FIPS instance
 * without fresh entropy before we declare starvation and unregister.
 * Same threshold as n2rng (see FIPS 186-2 change 1 rationale in
 * n2rng_provider.c).
 */
#define	TRNG_ENTROPY_STARVATION		10000ULL

/*
 * Starvation recovery timing.
 */
#define	TRNG_STARVATION_RETRY_SECS	60
#define	TRNG_REREGISTER_DELAY_SECS	5

/* kstat indices */
#define	TRNG_STAT_BYTES		0	/* bytes generated */
#define	TRNG_STAT_JOBS		1	/* generate_random calls */
#define	TRNG_STAT_RETRIES	2	/* requests needing any retry */
#define	TRNG_STAT_CALL_RETRIES	3	/* NO_ENTROPY SMCCC responses */
#define	TRNG_MAX_STATS		4

/* t_flags */
#define	TRNG_F_INITIALIZED	0x01
#define	TRNG_F_REGISTERED	0x02
#define	TRNG_F_FAILED		0x04
#define	TRNG_F_RND64		0x08	/* firmware supports TRNG_RND64 */
#define	TRNG_F_STARVED		0x10	/* starvation recovery pending */
#define	TRNG_F_ABANDON		0x20	/* detach/suspend abandoning recovery */

typedef struct trng {
	dev_info_t		*t_dip;
	uint32_t		t_version;	/* DEN0098 version: major<<16|minor */
	uint32_t		t_flags;
	crypto_kcf_provider_handle_t t_prov;
	ddi_taskq_t		*t_taskq;
	timeout_id_t		t_retry_id;	/* starvation recovery timeout */
	kmutex_t		t_lock;

	/* UUID from TRNG_GET_UUID (RFC 4122 format, 16 bytes) */
	uint8_t			t_uuid[16];

	/* Retry tunables, read from driver properties at attach */
	int			t_busywait_attempts;
	int			t_retry_delay_us;
	int			t_sleep_attempts;

	/* FIPS state */
	struct {
		volatile uint32_t fips_round_robin_j;
		trng_fips_state_t fipsarray[TRNG_FIPS_INSTANCES];
	} t_frs;

	/* kstats */
	uint64_t		t_stats[TRNG_MAX_STATS];
	kstat_t			*t_ksp;
} trng_t;

/*
 * Kstat structure for named kstats.
 */
typedef struct trng_stat {
	kstat_named_t	ts_status;
	kstat_named_t	ts_algs[TRNG_MAX_STATS];
} trng_stat_t;

/* Flag accessors (under t_lock or atomic context) */
#define	trng_is(t, f)		(((t)->t_flags & (f)) != 0)
#define	trng_set(t, f)		((t)->t_flags |= (f))
#define	trng_clr(t, f)		((t)->t_flags &= ~(f))

/* trng_smccc.c */
extern void *trng_softstate;

/* trng_smccc_kcf.c */
extern int trng_init(trng_t *);
extern int trng_uninit(trng_t *);
extern int trng_register_provider(trng_t *);
extern int trng_unregister_provider(trng_t *);
extern void trng_failure(trng_t *);
extern void trng_starvation(trng_t *);
extern void trng_ksinit(trng_t *);
extern void trng_ksdeinit(trng_t *);

/* trng_smccc_provider.c */
extern int trng_getentropy(trng_t *, uint8_t *, size_t);
extern int trng_fips_random_init(trng_t *, trng_fips_state_t *);
extern void trng_fips_random_fini(trng_fips_state_t *);
extern int trng_fips_random(trng_t *, uint8_t *, size_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_TRNG_SMCCC_H */
