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
 * Copyright 2025 Michael van der Westhuizen
 */

/*
 * Obtain the FDT pointer when it is usable.
 */

#include <efi.h>
#include <efilib.h>
#include <Guid/Acpi.h>
#include <Guid/Fdt.h>

/*
 * This is a forward declaration as EFI and FDT don't play well, which is
 * due to the standalone library conflicting with the FreeBSD C library
 * headers in the boot tree.
 */
extern int fdt_check_header(const void *fdt);

const void *
efi_get_fdtp(void)
{
	const void	*fdtp;

	/*
	 * Examine the system table. If we have an FDT and no RSDP then we
	 * are safe to use the FDT.
	 *
	 * If we have an RSDP (so, ACPI), then we claim there is no FDT, as
	 * ACPI is the preferred configuration table. EBBR states that we can
	 * have one or the other, but never both, so this extra safety check
	 * should be redundant.
	 */

	if ((fdtp = efi_get_table(&gFdtTableGuid)) == NULL)
		return (NULL);

	if (efi_get_table(&gEfiAcpi20TableGuid) != NULL)
		return (NULL);

	if (fdt_check_header(fdtp) != 0)
		return (NULL);

	return (fdtp);
}
