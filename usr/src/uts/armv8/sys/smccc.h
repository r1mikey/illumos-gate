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
 * Copyright 2024 Michael van der Westhuizen
 */

#ifndef _SYS_SMCCC_H
#define	_SYS_SMCCC_H

/*
 * DEN0028: SMC Calling Convention
 */

#include <sys/types.h>
#include <sys/smcccinfo.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	SMCCC_VERSION_ID			0x80000000
#define	SMCCC_ARCH_FEATURES_ID			0x80000001
#define	SMCCC_ARCH_SOC_ID_ID			0x80000002
#define	SMCCC_ARCH_FEATURE_AVAILABILITY_ID	0x80000003
#define	SMCCC_ARCH_WORKAROUND_1_ID		0x80008000
#define	SMCCC_ARCH_WORKAROUND_2_ID		0x80007FFF
#define	SMCCC_ARCH_WORKAROUND_3_ID		0x80003FFF

#define	SMCCC32_SUCCESS				0u
#define	SMCCC32_NOT_SUPPORTED			0xFFFFFFFFu
#define	SMCCC32_NOT_REQUIRED			0xFFFFFFFEu
#define	SMCCC32_INVALID_PARAMETER		0xFFFFFFFDu
#define	SMCCC32_NOT_INITIALIZED			0xFFFFFFd6u

#define	SMCCC64_SUCCESS				0ul
#define	SMCCC64_NOT_SUPPORTED			0xFFFFFFFFFFFFFFFFul
#define	SMCCC64_NOT_REQUIRED			0xFFFFFFFFFFFFFFFEul
#define	SMCCC64_INVALID_PARAMETER		0xFFFFFFFFFFFFFFFDul
#define	SMCCC64_NOT_INITIALIZED			0xFFFFFFFFFFFFFFd6ul

typedef struct {
	uint32_t w0;	/* function identifier */
	uint32_t w1;
	uint32_t w2;
	uint32_t w3;
	uint32_t w4;
	uint32_t w5;
	uint32_t w6;
	uint32_t w7;
} smccc32_args_t;

typedef struct {
	uint64_t x0;	/* function identifier, actually w0 on the way in */
	uint64_t x1;
	uint64_t x2;
	uint64_t x3;
	uint64_t x4;
	uint64_t x5;
	uint64_t x6;
	uint64_t x7;
	uint64_t x8;
	uint64_t x9;
	uint64_t x10;
	uint64_t x11;
	uint64_t x12;
	uint64_t x13;
	uint64_t x14;
	uint64_t x15;
	uint64_t x16;
	uint64_t x17;
} smccc64_args_t;

extern boolean_t smccc_initialized(void);
extern boolean_t smccc_available(void);
extern smccc_version_t smccc_version(void);
extern void smccc_init(void);
extern void smccc32_call(smccc32_args_t *args);
extern void smccc64_call(smccc64_args_t *args);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_SMCCC_H */
