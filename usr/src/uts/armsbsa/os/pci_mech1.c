/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2021 Oxide Computer Company
 */

/*
 * PCI Mechanism 1 low-level routines
 */

#include <sys/types.h>
#include <sys/pci.h>
#include <sys/pci_impl.h>
#include <sys/sunddi.h>
#include <sys/pci_cfgspace_impl.h>
#include <sys/pci_cfgacc.h>

extern void (*pci_cfgacc_acc_p)(pci_cfgacc_req_t *req);

/*
 * Per PCI 2.1 section 3.7.4.1 and PCI-PCI Bridge Architecture 1.0 section
 * 5.3.1.2:  dev=31 func=7 reg=0 means a special cycle.  We don't want to
 * trigger that by accident, so we pretend that dev 31, func 7 doesn't
 * exist.  If we ever want special cycle support, we'll add explicit
 * special cycle support.
 */
#define	BAD_CHECK(d, f, r, rv)	if (((d) == PCI_MECH1_SPEC_CYCLE_DEV &&	\
    (f) == PCI_MECH1_SPEC_CYCLE_FUNC) || (r) > pci_iocfg_max_offset)	\
	return ((rv))
#define	BAD_CHECK_NRV(d, f, r)	if (((d) == PCI_MECH1_SPEC_CYCLE_DEV &&	\
    (f) == PCI_MECH1_SPEC_CYCLE_FUNC) || (r) > pci_iocfg_max_offset)	\
	return

#define	MECH1_CFGACC_FILLREQ(r, b, o, s, w, v)				\
	{(r).bdf = (b); (r).offset = (o); (r).size = (s);		\
	(r).write = w; (r).ioacc = B_FALSE; VAL64(&(r)) = (v); }

uint8_t
pci_mech1_getb(int bus, int device, int function, int reg)
{
	pci_cfgacc_req_t req;

	BAD_CHECK(device, function, reg, PCI_EINVAL8);
	MECH1_CFGACC_FILLREQ(req, PCI_GETBDF(bus, device, function), reg,
	    PCI_CFG_SIZE_BYTE, B_FALSE, 0);
	(*pci_cfgacc_acc_p)(&req);
	return (VAL8(&req));
}

uint16_t
pci_mech1_getw(int bus, int device, int function, int reg)
{
	pci_cfgacc_req_t req;

	BAD_CHECK(device, function, reg, PCI_EINVAL16);
	MECH1_CFGACC_FILLREQ(req, PCI_GETBDF(bus, device, function), reg,
	    PCI_CFG_SIZE_WORD, B_FALSE, 0);
	(*pci_cfgacc_acc_p)(&req);
	return (VAL16(&req));
}

uint32_t
pci_mech1_getl(int bus, int device, int function, int reg)
{
	pci_cfgacc_req_t req;

	BAD_CHECK(device, function, reg, PCI_EINVAL32);
	MECH1_CFGACC_FILLREQ(req, PCI_GETBDF(bus, device, function), reg,
	    PCI_CFG_SIZE_DWORD, B_FALSE, 0);
	(*pci_cfgacc_acc_p)(&req);
	return (VAL32(&req));
}

void
pci_mech1_putb(int bus, int device, int function, int reg, uint8_t val)
{
	pci_cfgacc_req_t req;

	BAD_CHECK_NRV(device, function, reg);
	MECH1_CFGACC_FILLREQ(req, PCI_GETBDF(bus, device, function), reg,
	    PCI_CFG_SIZE_BYTE, B_TRUE, val);
	(*pci_cfgacc_acc_p)(&req);
}

void
pci_mech1_putw(int bus, int device, int function, int reg, uint16_t val)
{
	pci_cfgacc_req_t req;

	BAD_CHECK_NRV(device, function, reg);
	MECH1_CFGACC_FILLREQ(req, PCI_GETBDF(bus, device, function), reg,
	    PCI_CFG_SIZE_WORD, B_TRUE, val);
	(*pci_cfgacc_acc_p)(&req);
}

void
pci_mech1_putl(int bus, int device, int function, int reg, uint32_t val)
{
	pci_cfgacc_req_t req;

	BAD_CHECK_NRV(device, function, reg);
	MECH1_CFGACC_FILLREQ(req, PCI_GETBDF(bus, device, function), reg,
	    PCI_CFG_SIZE_DWORD, B_TRUE, val);
	(*pci_cfgacc_acc_p)(&req);
}
