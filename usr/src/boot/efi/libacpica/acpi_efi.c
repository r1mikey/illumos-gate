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
 * ACPICA initialisation for UEFI in the illumos loader
 */

#include <acpi.h>
#include <aclocal.h>
#include <acobject.h>
#include <acstruct.h>
#include <acnamesp.h>
#include <acutils.h>
#include <acmacros.h>
#include <acevents.h>
#include <actbl.h>
#include <actbl1.h>
#include <actbl3.h>

#include "acpi_efi.h"

bool
acpi_efi_init(void)
{
	ACPI_STATUS status;
	static int init_status = 0;

	switch (init_status) {
	case 0:
		break;
	case 1:
		return (false);
	case 2:
		return (true);
	}

	init_status = 1;

	status = AcpiInitializeSubsystem();
	if (ACPI_FAILURE(status))
                return (false);

        status = AcpiInitializeTables(NULL, 16, TRUE);
        if (ACPI_FAILURE(status))
                return (false);

	status = AcpiLoadTables();
        if (ACPI_FAILURE(status))
                return (false);

	status = AcpiEnableSubsystem(ACPI_FULL_INITIALIZATION);
        if (ACPI_FAILURE(status))
                return (false);

	status = AcpiInitializeObjects(ACPI_FULL_INITIALIZATION);
        if (ACPI_FAILURE(status))
                return (false);

	init_status = 2;
	return (true);
}
