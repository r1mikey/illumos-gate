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

char *
impl_plat_ttypath(void)
{
	int len;
	static char *ttypath = NULL;
	char buf[MAXPATHLEN];

	if (ttypath != NULL)
		return (ttypath);

	len = prom_getproplen(prom_chosennode(), "stdout-path");
	if (len <= 0)
		return (NULL);


	prom_getprop(prom_chosennode(), "stdout-path", buf);
	buf[len] = '\0';

	char *p = strchr(buf, ':');
	if (p != NULL)
		*p = '\0';

	/* If the path appears relative, it refers to an alias */
	if (buf[0] != '/') {
		pnode_t node = prom_finddevice("/aliases");
		if (node <= 0) {
			return (NULL);
		}

		int nlen = prom_getproplen(node, buf);
		if (nlen <= 0) {
			return (NULL);
		}

		char b[MAXPATHLEN];
		prom_getprop(node, buf, b);
		bcopy(b, buf, MAXPATHLEN);
		len = nlen;
	}

	ttypath = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	if (i_ddi_prompath_to_devfspath(buf, ttypath) != DDI_SUCCESS) {
		kmem_free(ttypath, MAXPATHLEN);
		return (NULL);
	}

	return (ttypath);
}
