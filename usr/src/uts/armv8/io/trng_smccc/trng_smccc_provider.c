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
 * DEN0098 TRNG entropy retrieval via TRNG_RND32/TRNG_RND64 SMCCC
 * calls, with FIPS 186-2 post-processing (mirrors n2rng_provider.c).
 */

#include <sys/types.h>
#include <sys/stdbool.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#include <sys/atomic.h>
#include <sys/sysmacros.h>
#include <sys/smccc.h>
#include <sys/trng_smccc.h>
#include <rng/fips_random.h>

/*
 * Issue one TRNG_RND64 or TRNG_RND32 call and copy the result
 * into buf.
 *
 * Returns:
 *   0      success, chunk bytes written to buf
 *   EAGAIN TRNG_NO_ENTROPY (transient, caller should retry)
 *   EPERM  SMCCC call failure or unexpected firmware error
 *          (permanent, caller should trigger failure path)
 */
static int
trng_smccc_rnd(trng_t *trng, bool use64, size_t nbits,
	uint8_t *buf, size_t chunk)
{
	if (use64) {
		smccc64_args_t args = {
			.x = { [0] = TRNG_RND64, [1] = nbits }
		};

		if (smccc64_call(&args) != 0) {
			return (EPERM);
		}

		if ((int64_t)args.x[0] == TRNG_SUCCESS) {
			/*
			 * Entropy packed: x3 (LSB), x2, x1 (MSB).
			 * Copy x3 first, then x2, then x1, up to
			 * chunk bytes total.
			 */
			uint8_t tmp[24];
			size_t off = 0;

			bcopy(&args.x[3], &tmp[off], sizeof (uint64_t));
			off += sizeof (uint64_t);
			bcopy(&args.x[2], &tmp[off], sizeof (uint64_t));
			off += sizeof (uint64_t);
			bcopy(&args.x[1], &tmp[off], sizeof (uint64_t));

			bcopy(tmp, buf, chunk);
			bzero(tmp, sizeof (tmp));
			bzero(&args, sizeof (args));
			return (0);
		}

		if ((int64_t)args.x[0] == TRNG_NO_ENTROPY) {
			atomic_inc_64(
				&trng->t_stats[TRNG_STAT_CALL_RETRIES]);
			bzero(&args, sizeof (args));
			return (EAGAIN);
		}

		bzero(&args, sizeof (args));
		return (EPERM);
	} else {
		smccc32_args_t args = {
			.w = { [0] = TRNG_RND32, [1] = (uint32_t)nbits }
		};

		if (smccc32_call(&args) != 0) {
			return (EPERM);
		}

		if ((int32_t)args.w[0] == TRNG_SUCCESS) {
			uint8_t tmp[12];
			size_t off = 0;

			bcopy(&args.w[3], &tmp[off], sizeof (uint32_t));
			off += sizeof (uint32_t);
			bcopy(&args.w[2], &tmp[off], sizeof (uint32_t));
			off += sizeof (uint32_t);
			bcopy(&args.w[1], &tmp[off], sizeof (uint32_t));

			bcopy(tmp, buf, chunk);
			bzero(tmp, sizeof (tmp));
			bzero(&args, sizeof (args));
			return (0);
		}

		if ((int32_t)args.w[0] == TRNG_NO_ENTROPY) {
			atomic_inc_64(
				&trng->t_stats[TRNG_STAT_CALL_RETRIES]);
			bzero(&args, sizeof (args));
			return (EAGAIN);
		}

		bzero(&args, sizeof (args));
		return (EPERM);
	}
}

/*
 * Pull entropy via TRNG_RND64 (192 bits max per call) or TRNG_RND32
 * (96 bits max per call) depending on what the firmware supports.
 *
 * Fills buf with exactly len bytes, looping over SMCCC calls as
 * needed.  Returns 0 on success, EPERM on firmware error (caller
 * should treat as permanent), EAGAIN on transient entropy exhaustion
 * (caller tracks starvation).
 *
 * On TRNG_NO_ENTROPY, uses a two-phase attempt scheme per chunk:
 *   Phase 1: up to t_busywait_attempts (default 5) SMCCC calls
 *            at t_retry_delay_us (default 100us) apart.
 *   Phase 2: up to t_sleep_attempts (default 10) SMCCC calls
 *            at delay(1) (one tick) apart.
 * Each value is the total number of calls in that phase.  No delay
 * follows the final call of a phase.  If both phases are exhausted,
 * returns EAGAIN for this chunk.  The FIPS layer's starvation counter
 * handles sustained drought.
 *
 * Statistics: TRNG_STAT_RETRIES counts each trng_getentropy() request
 * that needed more than one SMCCC call (per-request);
 * TRNG_STAT_CALL_RETRIES counts every NO_ENTROPY response
 * (per SMCCC call, in trng_smccc_rnd).
 *
 * No mutexes are held by the caller (trng_fips_random acquires the
 * FIPS instance mutex after this returns), so both drv_usecwait
 * and delay are safe here.
 */
int
trng_getentropy(trng_t *trng, uint8_t *buf, size_t len)
{
	bool use64 = trng_is(trng, TRNG_F_RND64);
	size_t maxbytes = use64 ? 24 : 12;  /* 192 or 96 bits */
	bool any_retried = false;
	int rv;

	while (len > 0) {
		size_t chunk = MIN(len, maxbytes);
		size_t nbits = chunk * 8;
		int attempt;
		bool retried = false;

		/* Phase 1: busy-wait attempts */
		for (attempt = 0; attempt < trng->t_busywait_attempts;
			attempt++) {
			rv = trng_smccc_rnd(trng, use64, nbits, buf, chunk);
			if (rv == 0) {
				goto next;
			}
			if (rv != EAGAIN) {
				goto done;
			}
			retried = true;
			if (attempt + 1 < trng->t_busywait_attempts) {
				drv_usecwait(trng->t_retry_delay_us);
			}
		}

		/* Phase 2: sleeping attempts */
		for (attempt = 0; attempt < trng->t_sleep_attempts;
			attempt++) {
			rv = trng_smccc_rnd(trng, use64, nbits, buf, chunk);
			if (rv == 0) {
				goto next;
			}
			if (rv != EAGAIN) {
				goto done;
			}
			retried = true;
			if (attempt + 1 < trng->t_sleep_attempts) {
				delay(1);
			}
		}

		/* Exhausted attempts on this chunk */
		rv = EAGAIN;
		goto done;
next:
		if (retried) {
			any_retried = true;
		}
		buf += chunk;
		len -= chunk;
	}

	rv = 0;
done:
	if (any_retried) {
		atomic_inc_64(&trng->t_stats[TRNG_STAT_RETRIES]);
	}
	return (rv);
}

/*
 * Seed one FIPS instance with entropy from the firmware and
 * compute the initial (compare-only) random value.
 */
int
trng_fips_random_init(trng_t *trng, trng_fips_state_t *frsp)
{
	int rv;
	static uint32_t FIPS_RNG_NO_USER_INPUT[] = {0, 0, 0, 0, 0};

	/*
	 * Seed XKEY with P2ROUNDUP(SHA1BYTES, 8) = 24 bytes of
	 * fresh entropy.
	 */
	rv = trng_getentropy(trng, (void *)frsp->XKEY,
		P2ROUNDUP(SHA1BYTES, 8));
	if (rv != 0) {
		return (rv);
	}

	frsp->entropyhunger = 0;
	mutex_init(&frsp->mtx, NULL, MUTEX_DRIVER, NULL);

	/* Compute the first (compare only) random value */
	fips_random_inner(frsp->XKEY, frsp->x_jminus1, FIPS_RNG_NO_USER_INPUT);

	return (0);
}

void
trng_fips_random_fini(trng_fips_state_t *frsp)
{
	mutex_destroy(&frsp->mtx);
	bzero(frsp, sizeof (trng_fips_state_t));
}

/*
 * FIPS post-processed random number generation.
 *
 * Mirrors n2rng's fips_random(): selects a FIPS instance
 * round-robin, fetches 8 bytes of entropy per SHA1-block-sized
 * output, runs fips_random_inner(), and tracks starvation.
 *
 * Unlike n2rng, tracks entropy failure via the EAGAIN return
 * from trng_getentropy rather than a zero-sentinel comparison,
 * eliminating the 2^-64 false positive.
 *
 * Implements the FIPS 140-2 continuous random number generator
 * test: each output block is compared against the previous
 * output (x_jminus1) for that FIPS instance.  A match indicates
 * a catastrophic RNG failure.
 *
 * On EPERM from getentropy (permanent firmware failure),
 * dispatches trng_failure() and returns CRYPTO_DEVICE_ERROR.
 *
 * On sustained starvation (TRNG_ENTROPY_STARVATION consecutive
 * calls without fresh entropy on a single instance), dispatches
 * trng_starvation() which unregisters and schedules a recovery
 * probe.  Returns CRYPTO_DEVICE_ERROR for this call.
 */
int
trng_fips_random(trng_t *trng, uint8_t *out, size_t nbytes)
{
	int i;
	trng_fips_state_t *frsp;
	int rv;
	int ret = CRYPTO_SUCCESS;
	bool got_entropy;
	union {
		uint32_t as32[SHA1WORDS];
		uint64_t as64[P2ROUNDUP(SHA1WORDS, 2) >> 1];
	} entropy = { .as64 = { 0 } };
	uint32_t tempout[SHA1WORDS];

	for (i = 0; i < (int)nbytes; i += SHA1BYTES) {
		/*
		 * Select a FIPS instance round-robin.
		 * The atomic increment avoids a global mutex.
		 */
		frsp = &trng->t_frs.fipsarray[
			atomic_inc_32_nv(&trng->t_frs.fips_round_robin_j) %
			TRNG_FIPS_INSTANCES];

		/*
		 * Fetch 8 bytes of entropy (one uint64_t) per output
		 * block.  Done before acquiring the FIPS mutex to
		 * avoid holding it during the SMCCC call and any
		 * retry delays.
		 */
		got_entropy = true;
		rv = trng_getentropy(trng,
			(void *)&entropy.as64[1], sizeof (uint64_t));
		if (rv != 0) {
			if (rv == EPERM) {
				trng_failure(trng);
				ret = CRYPTO_DEVICE_ERROR;
				goto cleanup;
			}
			/* EAGAIN: no entropy this round */
			got_entropy = false;
			entropy.as64[1] = 0;
		}

		mutex_enter(&frsp->mtx);

		if (!got_entropy) {
			if (++frsp->entropyhunger >=
				TRNG_ENTROPY_STARVATION) {
				mutex_exit(&frsp->mtx);
				trng_starvation(trng);
				ret = CRYPTO_DEVICE_ERROR;
				goto cleanup;
			}
		} else {
			frsp->entropyhunger = 0;
		}

		fips_random_inner(frsp->XKEY, tempout, entropy.as32);

		/*
		 * FIPS 140-2 continuous random number generator test:
		 * compare this block with the previous output from
		 * this instance.  A match is a catastrophic failure.
		 */
		if (bcmp(tempout, frsp->x_jminus1,
			sizeof (frsp->x_jminus1)) == 0) {
			mutex_exit(&frsp->mtx);
			cmn_err(CE_WARN,
				"trng_smccc: FIPS continuous test failure");
			trng_failure(trng);
			ret = CRYPTO_DEVICE_ERROR;
			goto cleanup;
		}
		bcopy(tempout, frsp->x_jminus1,
			sizeof (frsp->x_jminus1));

		bcopy(tempout, &out[i], MIN(nbytes - i, SHA1BYTES));

		mutex_exit(&frsp->mtx);
	}

cleanup:
	/* Zeroize sensitive temporaries on every exit path */
	bzero(&entropy, sizeof (entropy));
	bzero(tempout, sizeof (tempout));

	return (ret);
}
