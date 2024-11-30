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
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * isa-specific console configuration routines
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/cmn_err.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/esunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/promif.h>
#include <sys/modctl.h>
#include <sys/termios.h>

/*
 * In our port, look through consoles or stdout and
 * then look at the loader-defined properties to pick
 * up the ACPI namepsace, then grab that from acpica
 * and get the dip, then return that dip.
 */
char *
impl_plat_ttypath(void)
{
	dev_info_t *dip;
	static char path[MAXPATHLEN];
	char *bp;
	major_t major;
	int inum = 0;

	/* ns16550a0 */
	if ((major = ddi_name_to_major("ns16550a")) == (major_t)-1) {
		return (NULL);
	}

	if ((dip = devnamesp[major].dn_head) == NULL) {
		return (NULL);
	}

	for (; dip != NULL; dip = ddi_get_next(dip)) {
		if (i_ddi_attach_node_hierarchy(dip) != DDI_SUCCESS) {
			return (NULL);
		}

		if (DEVI(dip)->devi_minor->ddm_name[0] == ('a' + (char)inum)) {
			break;
		}
	}

	if (dip == NULL) {
		return (NULL);
	}

	(void) ddi_pathname(dip, path);
	bp = path + strlen(path);
	(void) snprintf(bp, 3, ":%s", DEVI(dip)->devi_minor->ddm_name);
	prom_printf("plat_ttypath: console pathname: '%s'\n", path);

	return (path);
}
