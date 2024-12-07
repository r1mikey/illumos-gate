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
 * Copyright (c) 1993, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2018 Joyent, Inc.
 * Copyright (c) 2017 by Delphix. All rights reserved.
 */
/*
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 */

#ifndef _SYS_APIC_APIC_H
#define	_SYS_APIC_APIC_H

#include <sys/psm_types.h>
#include <sys/avintr.h>
#include <sys/pci.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* #include <sys/psm_common.h> */

#define	APIC_PCPLUSMP_NAME	"pcplusmp"
#define	APIC_APIX_NAME		"apix"
#define APIC_GIC_NAME		"gic"

#define	VENID_AMD		0x1022
#define	DEVID_8131_IOAPIC	0x7451
#define	DEVID_8132_IOAPIC	0x7459

#define	IOAPICS_NODE_NAME	"ioapics"
#define	IOAPICS_CHILD_NAME	"ioapic"
#define	IOAPICS_DEV_TYPE	"ioapic"
#define	IOAPICS_PROP_VENID	"vendor-id"
#define	IOAPICS_PROP_DEVID	"device-id"

#define	MAX_IO_APIC		32	/* maximum # of IOAPICs supported */

#if 0
/* Used by PSM_INTR_OP_GET_INTR to return device information. */
typedef struct {
	uint16_t	avgi_req_flags;	/* request flags - to kernel */
	uint8_t		avgi_num_devs;	/* # devs on this ino - from kernel */
	uint8_t		avgi_vector;	/* vector */
	uint32_t	avgi_cpu_id;	/* cpu of interrupt - from kernel */
	dev_info_t	**avgi_dip_list; /* kmem_alloc'ed list of dev_infos. */
					/* Contains num_devs elements. */
} apic_get_intr_t;
#endif

/* Used by PSM_INTR_OP_GET_TYPE to return platform information. */
typedef struct {
	char		*avgi_type;	/*  platform type - from kernel */
	uint32_t	avgi_num_intr;	/*  max intr number - from kernel */
	uint32_t	avgi_num_cpu;	/*  max cpu number - from kernel */
} apic_get_type_t;

#if 0
/* Masks for avgi_req_flags. */
#define	PSMGI_REQ_CPUID		0x1	/* Request CPU ID */
#define	PSMGI_REQ_NUM_DEVS	0x2	/* Request num of devices on vector */
#define	PSMGI_REQ_VECTOR	0x4
#define	PSMGI_REQ_GET_DEVS	0x8	/* Request device list */
#define	PSMGI_REQ_ALL		0xf	/* Request everything */

/* Other flags */
#define	PSMGI_INTRBY_VEC	0	/* Vec passed.  xlate to IRQ needed */
#define	PSMGI_INTRBY_IRQ	0x8000	/* IRQ passed.  no xlate needed */
#define	PSMGI_INTRBY_DEFAULT	0x4000	/* PSM specific default value */
#define	PSMGI_INTRBY_FLAGS	0xc000	/* Mask for this flag */
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_APIC_APIC_H */
