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

#ifndef _SYS_PSM_TYPES_H
#define	_SYS_PSM_TYPES_H

#define	PSM_SUCCESS		DDI_SUCCESS
#define	PSM_FAILURE		DDI_FAILURE

#ifdef __cplusplus
extern "C" {
#endif

/*
 * PSM_OPS definitions
 */
typedef enum {
	PSM_INTR_OP_ALLOC_VECTORS = 0,	/* 0.  Allocate vectors */
	PSM_INTR_OP_FREE_VECTORS,	/* 1.  Free vectors */
	PSM_INTR_OP_NAVAIL_VECTORS,	/* 2.  Get # of available vectors */
	PSM_INTR_OP_XLATE_VECTOR,	/* 3.  Translate vector */
	PSM_INTR_OP_GET_PENDING,	/* 4.  Get pending information */
	PSM_INTR_OP_CLEAR_MASK,		/* 5.  Clear interrupt mask */
	PSM_INTR_OP_SET_MASK,		/* 6.  Set interrupt mask */
	PSM_INTR_OP_GET_CAP,		/* 7.  Get devices's capabilities */
	PSM_INTR_OP_SET_CAP,		/* 8.  Set devices's capabilities */
	PSM_INTR_OP_SET_PRI,		/* 9.  Set the interrupt priority */
	PSM_INTR_OP_GET_SHARED,		/* 10. Get the shared intr info */
	PSM_INTR_OP_CHECK_MSI,		/* 11. Chk if device supports MSI */
	PSM_INTR_OP_SET_CPU,		/* 12. Set vector's CPU */
	PSM_INTR_OP_GET_INTR,		/* 13. Get vector's info */
	PSM_INTR_OP_GRP_SET_CPU,	/* 14. Set all device's vectors' CPU */
	PSM_INTR_OP_APIC_TYPE		/* 15. Returns APIC type */
} psm_intr_op_t;

/*
 *      Get INTR flags
 */
#define	PSMGI_CPU_USER_BOUND	0x80000000	/* user requested bind if set */
#define	PSMGI_CPU_FLAGS		0x80000000	/* all possible flags */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_PSM_TYPES_H */
