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

#ifndef _ACPI_EFI_UART_H
#define	_ACPI_EFI_UART_H

#include <stdbool.h>

/*
 * UEFI/ACPI UART declarations.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	bool	(*op_setup)(void *);
	void	(*op_putchar)(void *, int);
	int	(*op_getchar)(void *);
	int	(*op_getspeed)(void *);
	int	(*op_ischar)(void *);
	void	(*op_devinfo)(void *);
	void	(*op_fillenv)(void *, const char *, const char *);
} uefi_acpi_uart_ops_t;

typedef struct {
	uint64_t			addr;
	uint32_t			addr_size;
	uint32_t			baud;
	uint32_t			frequency;      /* <= rev 2, 0, else 0 is indeterminate and !0 is Hz */
	uint16_t			interface_type;
	uint8_t				parity; // 0 is no parity, else reserved
	uint8_t				stop_bits; // 1 = 1 stop bit, else reserved
	uint8_t				flow_control; // b0: DCD on, b1: RTS/CTS hw, b2: XON/XOFF sw, other res0 */
	uint8_t				pad;
	char				acpi_name[128];
} spcr_data_t;

typedef struct {
	uint64_t			addr;
	uint32_t			addr_size;
	uint16_t			interface_type;
	uint16_t			pad;
	char				acpi_name[128];
} dbg2_data_t;

typedef struct {
	char				name[8];
	char				acpi_name[128];
	char				acpi_uid[64];
	char				acpi_hid[32];
	const uefi_acpi_uart_ops_t	*ops;
	void				*info;
	uint32_t			speed;  /* baud rate */
	uint8_t				lcr;    /* line control */
	uint8_t				ignore_cd;
	uint8_t				rtsdtr_off;
} acpi_uart_t;

#ifdef __cplusplus
}
#endif

#endif /* _ACPI_EFI_UART_H */
