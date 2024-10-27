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

#ifndef _ACPI_EFI_PL011_H
#define	_ACPI_EFI_PL011_H

#include "uefi_acpi_uart.h"

/*
 * UEFI/ACPI UART declarations for Arm PL011 compatible UARTs.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	uint64_t	addr;
	uint64_t	addr_len;
	uint64_t	irq;
	uint64_t	valid;
} pl011_info_t;

extern const uefi_acpi_uart_ops_t uefi_acpi_pl011_ops;

#ifdef __cplusplus
}
#endif

#endif /* _ACPI_EFI_PL011_H */
