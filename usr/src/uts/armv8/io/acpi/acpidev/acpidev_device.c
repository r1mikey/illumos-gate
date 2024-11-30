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
 * Copyright (c) 2009-2010, Intel Corporation.
 * All rights reserved.
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/ctype.h>
#include <sys/atomic.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/acpidev.h>
#include <sys/acpidev_impl.h>
#if defined(__aarch64__)
#include <sys/acpidev_devprop.h>
#endif
#include <sys/pci.h>

#if defined(__aarch64__)
static char *acpidev_device_well_known_hids[] = {
	ACPIDEV_HID_ARM_PL011,
	ACPIDEV_HID_VIRTIO_MMIO
};
static int num_acpidev_device_well_known_hids =
    sizeof (acpidev_device_well_known_hids) /
    sizeof (acpidev_device_well_known_hids[0]);

static const intptr_t acpidev_device_known_consumer = 0x7ffefdfcfbcafe42;
#endif	/* __aarch64__ */

static ACPI_STATUS acpidev_device_probe(acpidev_walk_info_t *infop);
static acpidev_filter_result_t acpidev_device_filter(acpidev_walk_info_t *infop,
    char *devname, int maxlen);
static acpidev_filter_result_t acpidev_device_filter_usb(acpidev_walk_info_t *,
    ACPI_HANDLE, acpidev_filter_rule_t *, char *, int);
#if defined(__aarch64__)
static acpidev_filter_result_t acpidev_device_filter_known_leaves(
    acpidev_walk_info_t *, ACPI_HANDLE, acpidev_filter_rule_t *, char *, int);
#endif	/* __aarch64__ */
static ACPI_STATUS acpidev_device_init(acpidev_walk_info_t *infop);

static uint32_t acpidev_device_unitaddr = 0;

/*
 * Default class driver for ACPI DEVICE objects.
 * The default policy for DEVICE objects is to scan child objects without
 * creating device nodes. But some special DEVICE objects will have device
 * nodes created for them.
 */
acpidev_class_t acpidev_class_device = {
	0,				/* adc_refcnt */
	ACPIDEV_CLASS_REV1,		/* adc_version */
	ACPIDEV_CLASS_ID_DEVICE,	/* adc_class_id */
	"ACPI Device",			/* adc_class_name */
	ACPIDEV_TYPE_DEVICE,		/* adc_dev_type */
	NULL,				/* adc_private */
	NULL,				/* adc_pre_probe */
	NULL,				/* adc_post_probe */
	acpidev_device_probe,		/* adc_probe */
	acpidev_device_filter,		/* adc_filter */
	acpidev_device_init,		/* adc_init */
	NULL,				/* adc_fini */
};

/*
 * List of class drivers which will be called in order when handling
 * children of ACPI DEVICE objects.
 */
acpidev_class_list_t *acpidev_class_list_device = NULL;

/* Filter rule table for boot. */
static acpidev_filter_rule_t acpidev_device_filters[] = {
	{	/* _SB_ object type is hardcoded to DEVICE by acpica */
		NULL,
		0,
		ACPIDEV_FILTER_DEFAULT,
		&acpidev_class_list_device,
		1,
		1,
		ACPIDEV_OBJECT_NAME_SB,
		ACPIDEV_NODE_NAME_MODULE_SBD,
	},
	{	/* Ignore other device objects under ACPI root object */
		NULL,
		0,
		ACPIDEV_FILTER_SKIP,
		NULL,
		1,
		1,
		NULL,
		NULL,
	},
	{	/* Scan a device attempting to find a USB node */
		acpidev_device_filter_usb,
		0,
		ACPIDEV_FILTER_SCAN,
		&acpidev_class_list_usbport,
		2,
		INT_MAX,
		NULL,
		NULL
	},
#if defined(__aarch64__)
	{	/* Create known device objects not directly under ACPI root */
		acpidev_device_filter_known_leaves,
		0,
		ACPIDEV_FILTER_DEFAULT,	/* XXXARM: ACPIDEV_FILTER_CREATE? */
		&acpidev_class_list_device,
		2,
		INT_MAX,
		NULL,
		NULL,
	},
#endif	/* __aarch64__ */
	{	/* Scan other device objects not directly under ACPI root */
		NULL,
		0,
		ACPIDEV_FILTER_SCAN,
		&acpidev_class_list_device,
		2,
		INT_MAX,
		NULL,
		NULL,
	}
};

static ACPI_STATUS
acpidev_device_probe(acpidev_walk_info_t *infop)
{
	ACPI_STATUS rc = AE_OK;
	int flags;

	ASSERT(infop != NULL);
	ASSERT(infop->awi_hdl != NULL);
	ASSERT(infop->awi_info != NULL);

	if (infop->awi_info->Type != ACPI_TYPE_DEVICE) {
		return (AE_OK);
	}

	flags = ACPIDEV_PROCESS_FLAG_SCAN;
	switch (infop->awi_op_type) {
	case ACPIDEV_OP_BOOT_PROBE:
		flags |= ACPIDEV_PROCESS_FLAG_CREATE;
		break;

	case ACPIDEV_OP_BOOT_REPROBE:
		break;

	case ACPIDEV_OP_HOTPLUG_PROBE:
		flags |= ACPIDEV_PROCESS_FLAG_CREATE |
		    ACPIDEV_PROCESS_FLAG_SYNCSTATUS |
		    ACPIDEV_PROCESS_FLAG_HOLDBRANCH;
		break;

	default:
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: unknown operation type %u in "
		    "acpi_device_probe().", infop->awi_op_type);
		rc = AE_BAD_PARAMETER;
		break;
	}

	if (rc == AE_OK) {
		rc = acpidev_process_object(infop, flags);
	}
	if (ACPI_FAILURE(rc) && rc != AE_NOT_EXIST && rc != AE_ALREADY_EXISTS) {
		cmn_err(CE_WARN,
		    "!acpidev: failed to process device object %s.",
		    infop->awi_name);
#if defined(__aarch64__)
	} else if (infop->awi_op_type == ACPIDEV_OP_BOOT_REPROBE) {
		/*
		 * XXXARM: unit address processing should be here too
		 */
		if (infop->awi_scratchpad[AWI_SCRATCH_KNOWN_DEV] ==
		    acpidev_device_known_consumer) {
			rc = acpidev_resource_process(infop, B_TRUE);
			if (ACPI_FAILURE(rc)) {
				cmn_err(CE_WARN, "!acpidev: failed to process "
				    "resources of known ACPI device %s.",
				    infop->awi_name);
			} else {
				rc = acpidev_devprop_process(infop);
				if (ACPI_FAILURE(rc)) {
					cmn_err(CE_WARN, "!acpidev: failed to "
					    "process properties of known "
					    "ACPI device %s.",
					    infop->awi_name);
					rc = AE_OK;	/* XXXARM */
				}
			}
		}
#endif	/* __aarch64__ */
	} else {
		rc = AE_OK;
	}

	return (rc);
}

/*
 * Attempt to determine which devices here correspond to an HCI for a USB
 * controller.
 */
static acpidev_filter_result_t
acpidev_device_filter_usb(acpidev_walk_info_t *infop, ACPI_HANDLE hdl,
    acpidev_filter_rule_t *afrp, char *devname, int len)
{
	dev_info_t *dip;
	char **compat;
	uint_t ncompat, i;

	if (infop->awi_op_type != ACPIDEV_OP_BOOT_REPROBE)
		return (ACPIDEV_FILTER_SKIP);

	/*
	 * If we don't find a dip that matches this one, then let's not worry
	 * about it. This means that it may not be a device we care about in any
	 * way.
	 */
	if (ACPI_FAILURE(acpica_get_devinfo(hdl, &dip))) {
		return (ACPIDEV_FILTER_SKIP);
	}

	/*
	 * To determine if this is a PCI USB class controller, we grab its
	 * compatible array and look for an instance of pciclass,0c03 or
	 * pciexclass,0c03. The class code 0c03 is used to indicate a USB
	 * controller.
	 */
	if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "compatible", &compat, &ncompat) != DDI_SUCCESS) {
		return (ACPIDEV_FILTER_SKIP);
	}

	for (i = 0; i < ncompat; i++) {
		if (strcmp(compat[i], "pciclass,0c03") == 0 ||
		    strcmp(compat[i], "pciexclass,0c03") == 0) {
			ddi_prop_free(compat);
			/*
			 * We've found a PCI based USB controller. Switch to the
			 * USB specific parser.
			 */
			return (ACPIDEV_FILTER_SCAN);
		}
	}

	ddi_prop_free(compat);
	return (ACPIDEV_FILTER_SKIP);
}

#if defined(__aarch64__)
/*
 * Clean up the ACPI device node name ahead of node creation.
 *
 * Some (most?) ACPI systems generate names that have the UID appended
 * (providing unique names in the ACPI tree). In some cases, notably Qemu,
 * the UID that is appended is also left-padded with zeroes.
 *
 * Clean this up, leaving a cleaner node name. The UID will later be used to
 * create the instance when the UID can be parsed as an integer, so we're not
 * losing this information, just presenting it a little better.
 */
static void
acpidev_device_trim_devname(acpidev_walk_info_t *infop, char *devname)
{
	size_t i;
	size_t uidlen;
	const char *uid;
	char *np;
	char *dnp;
	char *tnp;

	/*
	 * If we don't have a valid UID there's nothing to trim.
	 */
	if (!(infop->awi_info->Valid & ACPI_VALID_UID))
		return;

	/*
	 * We'll only trim when the UID represents an integer.
	 */
	uid = infop->awi_info->UniqueId.String;
	uidlen = strlen(uid);
	for (i = 0; i < uidlen; ++i)
		if (!isdigit(uid[i]))
			return;

	/*
	 * If the UID is not appended to the device name we have nothing to do.
	 */
	dnp = &devname[strlen(devname) - uidlen];
	if (strcmp(dnp, uid) != 0)
		return;

	/*
	 * Find the start of the trailing digits of devname.
	 */
	np = &devname[strlen(devname) - 1];
	while (np != devname && isdigit(*np))
		--np;
	/* if it's all numbers we can't do anything sensible */
	if (np == devname)
		return;
	np++;	/* point np to the first of the trailing digits */

	if (np == dnp) {
		*dnp = '\0';
		return;
	}

	/*
	 * If there are non-0 characters between the first trailing digit and
	 * the appended UID we can only cut the appended UID.
	 */
	tnp = np;
	while (tnp != (dnp - 1)) {
		if (*tnp++ != '0') {
			*dnp = '\0';
			return;
		}
	}

	/*
	 * The appended UID is zero-padded, so cut the padding in addition to
	 * the UID itself.
	 */
	*np = '\0';
}

static acpidev_filter_result_t
acpidev_device_filter_known_leaves(acpidev_walk_info_t *infop, ACPI_HANDLE hdl,
    acpidev_filter_rule_t *afrp, char *devname, int len)
{
	ASSERT(infop->awi_info != NULL);

	if (acpidev_match_device_id(infop->awi_info,
	    acpidev_device_well_known_hids, num_acpidev_device_well_known_hids))
		infop->awi_scratchpad[AWI_SCRATCH_KNOWN_DEV]
		    = acpidev_device_known_consumer;
	else
		return (ACPIDEV_FILTER_CONTINUE);

	if (infop->awi_scratchpad[AWI_SCRATCH_KNOWN_DEV] ==
	    acpidev_device_known_consumer && devname != NULL) {
		/* ACPI systems create really ugly names, fix them */
		acpidev_device_trim_devname(infop, devname);
	}

	return (ACPIDEV_FILTER_DEFAULT);
}
#endif	/* __aarch64__ */

static acpidev_filter_result_t
acpidev_device_filter(acpidev_walk_info_t *infop, char *devname, int maxlen)
{
	acpidev_filter_result_t res;

	ASSERT(infop != NULL);
	if (infop->awi_op_type == ACPIDEV_OP_BOOT_PROBE ||
	    infop->awi_op_type == ACPIDEV_OP_BOOT_REPROBE ||
	    infop->awi_op_type == ACPIDEV_OP_HOTPLUG_PROBE) {
		res = acpidev_filter_device(infop, infop->awi_hdl,
		    ACPIDEV_ARRAY_PARAM(acpidev_device_filters),
		    devname, maxlen);
	} else {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: unknown operation type %u "
		    "in acpidev_device_filter().", infop->awi_op_type);
		res = ACPIDEV_FILTER_FAILED;
	}

	return (res);
}

static ACPI_STATUS
acpidev_device_init(acpidev_walk_info_t *infop)
{
	char unitaddr[32];
	char *compatible[] = {
		ACPIDEV_TYPE_DEVICE,
		ACPIDEV_HID_VIRTNEX,
		ACPIDEV_TYPE_VIRTNEX,
	};

	if (ACPI_FAILURE(acpidev_set_compatible(infop,
	    ACPIDEV_ARRAY_PARAM(compatible)))) {
		return (AE_ERROR);
	}
	/* XXXARM: this is wrong, needs to be per-instance */
	(void) snprintf(unitaddr, sizeof (unitaddr), "%u",
	    atomic_inc_32_nv(&acpidev_device_unitaddr) - 1);
	if (ACPI_FAILURE(acpidev_set_unitaddr(infop, NULL, 0, unitaddr))) {
		return (AE_ERROR);
	}

	return (AE_OK);
}
