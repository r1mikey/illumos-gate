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
 * Board information support for FDT systems.
 */

#include <stand.h>
#include <libfdt.h>
#include <fdt.h>

typedef struct {
	const char *bi_compat;
	const char *bi_impl_name;
	const char *bi_mfg_name;
	const char *bi_hw_provider;
} board_info_t;

static const board_info_t board_info[] = {
	{
		.bi_compat = "raspberrypi,4-model-b",
		.bi_impl_name = "RaspberryPi,4",
		.bi_mfg_name = "RaspberryPi,4",
		.bi_hw_provider = "Raspberry Pi Foundation"
	},
	{
		.bi_compat = "linux,dummy-virt",
		.bi_impl_name = "QEMU,virt",
		.bi_mfg_name = "QEMU,virt",
		.bi_hw_provider = "QEMU"
	},
	{
		.bi_compat = NULL
	}
};

static const char *
get_board_compatible(const void *fdtp)
{
	const char *n;
	int len;

	if (fdt_getprop(fdtp, 0, "compatible", NULL) == NULL)
		return (NULL);
	if (fdt_stringlist_count(fdtp, 0, "compatible") < 1)
		return (NULL);
	if ((n = fdt_stringlist_get(fdtp, 0, "compatible", 0, &len)) == NULL)
		return (NULL);
	if (len <= 0)
		return (NULL);

	return (n);
}

const board_info_t *
get_board_info(const void *fdtp, const char **compat)
{
	const board_info_t *bi;
	*compat = get_board_compatible(fdtp);

	if (*compat == NULL)
		return (NULL);

	for (bi = &board_info[0]; bi->bi_compat != NULL; ++bi) {
		if (strcmp(*compat, bi->bi_compat) == 0)
			return (bi);
	}

	return (NULL);
}

void
bi_platform_fdt(const void *fdtp)
{
	const board_info_t *bi;
	const char *compat;
	int rc;
	bool update_compat;
	int clen;
	int plen;
	const struct fdt_property *prop;
	char *compatible;

	update_compat = false;
	compat = NULL;
	bi = get_board_info(fdtp, &compat);
	if (bi == NULL && compat == NULL) {
		if ((rc = setenv("PLATFORM", "", 1)) != 0) {
			printf("Warning: failed to set PLATFORM environment "
			    "variable: %d\n", rc);
		}

		return;
	}

	if (bi != NULL && bi->bi_impl_name != NULL) {
		compat = bi->bi_impl_name;
		update_compat = true;
	}

	if (compat == NULL) {
		if ((rc = setenv("PLATFORM", "", 1)) != 0) {
			printf("Warning: failed to set PLATFORM environment "
			    "variable: %d\n", rc);
		}
	} else {
		if ((rc = setenv("PLATFORM", compat, 1)) != 0) {
			printf("Warning: failed to set PLATFORM environment "
			    "variable: %d\n", rc);
		}
	}

	if (!update_compat)
		return;

	plen = 0;
	if ((prop = fdt_get_property(fdtp, 0, "compatible", &plen)) == NULL || plen < 1)
		return;
	clen = strlen(compat) + 1 + plen + 1;
	if ((compatible = malloc(clen)) == NULL)
		return;
	memset(compatible, 0, clen);
	strcpy(compatible, compat);
	memcpy(compatible + strlen(compat) + 1, prop->data, plen);
	(void) fdt_setprop((void *)fdtp, 0, "compatible", compatible, clen);
	free(compatible);
}
