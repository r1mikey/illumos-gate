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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include	<sys/types.h>
#include	"reloc.h"

/*
 * This is a 'stub' of the orignal version defined in liblddbg.so.  This stub
 * returns the 'int string' of the relocation in question instead of converting
 * the relocation to it's full syntax.
 */
const char *
conv_reloc_aarch64_type(Word type)
{
	static char 	strbuf[32];
	int		ndx = 31;

	switch (type) {
	case R_AARCH64_ABS64:
		return "R_AARCH64_ABS64";
	case R_AARCH64_ABS32:
		return "R_AARCH64_ABS32";
	case R_AARCH64_ABS16:
		return "R_AARCH64_ABS16";
	case R_AARCH64_ADD_ABS_LO12_NC:
		return "R_AARCH64_ADD_ABS_LO12_NC";
	case R_AARCH64_ADR_PREL_PG_HI21:
		return "R_AARCH64_ADR_PREL_PG_HI21";
	case R_AARCH64_CALL26:
		return "R_AARCH64_CALL26";
	case R_AARCH64_GLOB_DAT:
		return "R_AARCH64_GLOB_DAT";
	case R_AARCH64_JUMP_SLOT:
		return "R_AARCH64_JUMP_SLOT";
	case R_AARCH64_JUMP26:
		return "R_AARCH64_JUMP26";
	case R_AARCH64_LDST8_ABS_LO12_NC:
		return "R_AARCH64_LDST8_ABS_LO12_NC";
	case R_AARCH64_LDST32_ABS_LO12_NC:
		return "R_AARCH64_LDST32_ABS_LO12_NC";
	case R_AARCH64_LDST64_ABS_LO12_NC:
		return "R_AARCH64_LDST64_ABS_LO12_NC";
	case R_AARCH64_RELATIVE:
		return "R_AARCH64_RELATIVE";
	}

	strbuf[ndx--] = '\0';
	do {
		strbuf[ndx--] = '0' + (type % 10);
		type = type / 10;
	} while ((ndx >= (int)0) && (type > (Word)0));

	return (&strbuf[ndx + 1]);
}
