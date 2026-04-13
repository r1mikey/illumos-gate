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

#ifndef _SYS_EFIIO_H
#define	_SYS_EFIIO_H

/*
 * ioctl definitions for the efidev pseudo-device driver, providing
 * the /dev/efi character device.
 *
 * Provides userland access to UEFI Runtime Services variable
 * operations: GetVariable, SetVariable, GetNextVariableName.
 */

#include <sys/types.h>
#include <sys/ioccom.h>
#include <sys/efi.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ioctl data structure for UEFI variable operations.
 *
 * vi_name and vi_data are userland pointers to buffers owned by
 * the caller.  vi_name points to a UCS-2 (16-bit) encoded,
 * NUL-terminated variable name.  vi_name_size and vi_data_size
 * are in/out: on entry they describe the buffer sizes in bytes,
 * on return they reflect the actual sizes.
 *
 * For EFIIOC_VAR_GET:
 *   in:  vi_name, vi_name_size, vi_vendor, vi_data, vi_data_size
 *   out: vi_data (filled), vi_data_size (actual), vi_attrib
 *
 * For EFIIOC_VAR_SET:
 *   in:  vi_name, vi_name_size, vi_vendor, vi_attrib,
 *        vi_data, vi_data_size
 *   Setting vi_data_size to 0 deletes the variable.
 *
 * For EFIIOC_VAR_NEXT:
 *   in:  vi_name (previous or empty), vi_name_size, vi_vendor
 *   out: vi_name (next name), vi_name_size (actual), vi_vendor
 */
typedef struct efi_var_ioc {
	uint16_t	*vi_name;	/* UCS-2 variable name */
	size_t		vi_name_size;	/* name buffer size (bytes) */
	efi_guid_t	vi_vendor;	/* vendor GUID */
	uint32_t	vi_attrib;	/* EFI variable attributes */
	void		*vi_data;	/* data buffer */
	size_t		vi_data_size;	/* data buffer size (bytes) */
} efi_var_ioc_t;

#define	EFIIOC_VAR_GET	_IOWR('E', 1, efi_var_ioc_t)
#define	EFIIOC_VAR_SET	_IOW('E', 2, efi_var_ioc_t)
#define	EFIIOC_VAR_NEXT	_IOWR('E', 3, efi_var_ioc_t)

#ifdef __cplusplus
}
#endif

#endif /* _SYS_EFIIO_H */
