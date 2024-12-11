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

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/acpi/acpi.h>
#include <sys/acpi/aclocal.h>
#include <sys/acpi/acobject.h>
#include <sys/acpi/acstruct.h>
#include <sys/acpi/acnamesp.h>
#include <sys/acpica.h>
#include <sys/acpidev.h>
#include <sys/acpidev_devprop.h>
#include <sys/acpidev_impl.h>
#include <sys/uuid.h>

/*
 * Propagate ACPI Device Specific Data (_DSD) information to properties.
 */

/*
 * daffd814-6eba-4d8c-8a91-bc9bbf4aa301
 */
static const struct uuid devprops_uuid = {
	.time_low			= 0xdaffd814,
	.time_mid			= 0x6eba,
	.time_hi_and_version		= 0x4d8c,
	.clock_seq_hi_and_reserved	= 0x8a,
	.clock_seq_low			= 0x91,
	.node_addr			= {0xbc, 0x9b, 0xbf, 0x4a, 0xa3, 0x01}
};

/*
 * Return true if an integer DSD entry should be propagated as a 32bit integer.
 *
 * The default is to propagate as a 64bit integer.
 */
static boolean_t
acpidev_devprop_downgrade_int_width(
    acpidev_walk_info_t *infop __unused, const char *name)
{
	if (strcmp(name, "clock-frequency") == 0)
		return (B_TRUE);

	return (B_FALSE);
}

static char *
adcpidev_dsd_key_name(acpidev_walk_info_t *infop __unused, char *name)
{
	ASSERT(name != NULL);

	if (strcmp(name, "phy-channel") == 0)
		return "acpi-phy-channel";
	else if (strcmp(name, "phy-mode") == 0)
		return "acpi-phy-mode";
	else if (strcmp(name, "mac-address") == 0)
		return "acpi-mac-address";
	else if (strcmp(name, "max-transfer-unit") == 0)
		return "acpi-max-transfer-unit";
	else if (strcmp(name, "max-speed") == 0)
		return "acpi-max-speed";

	return (name);
}

static ACPI_STATUS
acpidev_devprop_process_integer(acpidev_walk_info_t *infop,
    const ACPI_OBJECT *name, const ACPI_OBJECT *val)
{
	dev_t dev;
	int rc;
	char *key_name;

	ASSERT(infop != NULL);
	ASSERT(infop->awi_dip != NULL);
	ASSERT(name != NULL);
	ASSERT(val != NULL);
	ASSERT(name->Type == ACPI_TYPE_STRING);
	ASSERT(val->Type == ACPI_TYPE_INTEGER);

	key_name = adcpidev_dsd_key_name(infop, name->String.Pointer);
	ASSERT(key_name != NULL);
	dev = makedevice(DDI_MAJOR_T_UNKNOWN, ddi_get_instance(infop->awi_dip));

	if (acpidev_devprop_downgrade_int_width(infop, name->String.Pointer)) {
		uint32_t v;
		v = (uint32_t)val->Integer.Value;
		rc = ndi_prop_update_int(dev, infop->awi_dip, key_name, v);
	} else {
		rc = ndi_prop_update_int64(dev, infop->awi_dip, key_name,
		    val->Integer.Value);
	}

	if (rc != DDI_SUCCESS)
		return (AE_ERROR);

	return (AE_OK);
}

static ACPI_STATUS
acpidev_devprop_process_string(acpidev_walk_info_t *infop,
    const ACPI_OBJECT *name, const ACPI_OBJECT *val)
{
	dev_t dev;
	char *key_name;

	ASSERT(infop != NULL);
	ASSERT(infop->awi_dip != NULL);
	ASSERT(name != NULL);
	ASSERT(val != NULL);
	ASSERT(name->Type == ACPI_TYPE_STRING);
	ASSERT(val->Type == ACPI_TYPE_STRING);

	key_name = adcpidev_dsd_key_name(infop, name->String.Pointer);
	ASSERT(key_name != NULL);
	dev = makedevice(DDI_MAJOR_T_UNKNOWN, ddi_get_instance(infop->awi_dip));

	if (ndi_prop_update_string(dev, infop->awi_dip, key_name,
	    val->String.Pointer) != DDI_SUCCESS)
		return (AE_ERROR);

	return (AE_OK);
}

/*
 * MAC Address is a special case of integer list, where we know the packages
 * will be 6 integers, representing the 6 octets of a MAC address.
 *
 * We add this property as a simple byte array rather than an integer list.
 */
static ACPI_STATUS
acpidev_devprop_process_mac_address(acpidev_walk_info_t *infop,
    const ACPI_OBJECT *name, const ACPI_OBJECT *val)
{
	/* XXX: is this really a package? Should it not be a buffer? */
	return (AE_OK);
}

static ACPI_STATUS
acpidev_devprop_process_integer_list(acpidev_walk_info_t *infop,
    const ACPI_OBJECT *name, const ACPI_OBJECT *val)
{
	int rc;
	UINT32 n;
	dev_t dev;
	char *key_name;

	ASSERT(infop != NULL);
	ASSERT(infop->awi_dip != NULL);
	ASSERT(name != NULL);
	ASSERT(val != NULL);
	ASSERT(name->Type == ACPI_TYPE_STRING);
	ASSERT(val->Type == ACPI_TYPE_PACKAGE);

	key_name = adcpidev_dsd_key_name(infop, name->String.Pointer);
	ASSERT(key_name != NULL);
	if (strcmp(key_name, "acpi-mac-address") == 0)
		return (acpidev_devprop_process_mac_address(infop, name, val));

	dev = makedevice(DDI_MAJOR_T_UNKNOWN, ddi_get_instance(infop->awi_dip));

	if (acpidev_devprop_downgrade_int_width(infop, name->String.Pointer)) {
		int32_t *ints;
		uint_t nints;
		size_t sz;

		nints = val->Package.Count;
		sz = sizeof (int32_t) * nints;
		ints = kmem_alloc(sz, KM_SLEEP);
		for (n = 0; n < val->Package.Count; ++n) {
			uint32_t v;
			v = val->Package.Elements[n].Integer.Value;
			ints[n] = v;
		}

		rc = ndi_prop_update_int_array(dev, infop->awi_dip, key_name,
		    ints, nints);

		kmem_free(ints, sz);
	} else {
		int64_t *ints;
		uint_t nints;
		size_t sz;

		nints = val->Package.Count;
		sz = sizeof (int64_t) * nints;
		ints = kmem_alloc(sz, KM_SLEEP);
		for (n = 0; n < val->Package.Count; ++n)
			ints[n] = val->Package.Elements[n].Integer.Value;

		rc = ndi_prop_update_int64_array(dev, infop->awi_dip, key_name,
		    ints, nints);

		kmem_free(ints, sz);
	}

	if (rc != DDI_SUCCESS)
		return (AE_ERROR);

	return (AE_OK);
}

static ACPI_STATUS
acpidev_devprop_process_string_list(acpidev_walk_info_t *infop,
    const ACPI_OBJECT *name, const ACPI_OBJECT *val)
{
	UINT32 n;
	char **vals;
	uint_t nvals;
	size_t sz;
	dev_t dev;
	int rc;
	char *key_name;

	ASSERT(infop != NULL);
	ASSERT(infop->awi_dip != NULL);
	ASSERT(name != NULL);
	ASSERT(val != NULL);
	ASSERT(name->Type == ACPI_TYPE_STRING);
	ASSERT(val->Type == ACPI_TYPE_PACKAGE);

	key_name = adcpidev_dsd_key_name(infop, name->String.Pointer);
	ASSERT(key_name != NULL);
	dev = makedevice(DDI_MAJOR_T_UNKNOWN, ddi_get_instance(infop->awi_dip));

	nvals = val->Package.Count;
	sz = sizeof (char *) * nvals;
	vals = kmem_zalloc(sz, KM_SLEEP);

	for (n = 0; n < val->Package.Count; ++n)
		vals[n] = ddi_strdup(
		    val->Package.Elements[n].String.Pointer, KM_SLEEP);

	rc = ndi_prop_update_string_array(dev, infop->awi_dip, key_name,
	    vals, nvals);

	for (n = 0; n < val->Package.Count; ++n)
		strfree(vals[n]);
	kmem_free(vals, sz);

	if (rc != DDI_SUCCESS)
		return (AE_ERROR);

	return (AE_OK);
}

/*
 * Checks that the value is a package (list of values) and that the package
 * contents are homogenous, then calls the appropriate typed list function.
 */
static ACPI_STATUS
acpidev_devprop_process_list(acpidev_walk_info_t *infop,
    const ACPI_OBJECT *name, const ACPI_OBJECT *val)
{
	UINT32 n;
	ACPI_OBJECT_TYPE t;

	ASSERT(infop != NULL);
	ASSERT(infop->awi_dip != NULL);
	ASSERT(name != NULL);
	ASSERT(val != NULL);
	ASSERT(name->Type == ACPI_TYPE_STRING);
	ASSERT(val->Type == ACPI_TYPE_PACKAGE);

	if (val->Package.Count < 1)
		return (AE_BAD_DATA);

	t = val->Package.Elements[0].Type;
	for (n = 1; n < val->Package.Count; ++n)
		if (val->Package.Elements[0].Type != t)
			return (AE_BAD_DATA);

	switch (t) {
	case ACPI_TYPE_INTEGER:
		return (acpidev_devprop_process_integer_list(infop, name, val));
	case ACPI_TYPE_STRING:
		return (acpidev_devprop_process_string_list(infop, name, val));
	/*
	 * We could handle reference here
	 */
	default:
		/* XXXARM: warn? */
		break;
	}

	return (AE_ERROR);
}

static ACPI_STATUS
acpidev_devprop_walker(acpidev_walk_info_t *infop, ACPI_OBJECT *dsd)
{
	UINT32			i;
	ACPI_STATUS		rc;
	const ACPI_OBJECT	*guid;
	const ACPI_OBJECT	*dsd_pkg;

	rc = AE_OK;

	ASSERT(infop != NULL);
	ASSERT(dsd != NULL);
	ASSERT(dsd->Type == ACPI_TYPE_PACKAGE);
	if (infop == NULL || dsd == NULL || dsd->Type != ACPI_TYPE_PACKAGE)
		return (AE_BAD_PARAMETER);

	/*
	 * The _DSD is described as a package consisting of UUID/package pairs,
	 * where the UUID describes the contents of the associated package.
	 *
	 * Therefore there must be an even number of entries.
	 */
	if ((dsd->Package.Count & 0x1) == 0x1)
		return (AE_BAD_DATA);

	/*
	 * Now we iterate through the UUID/package pairs under the _DSD, looking
	 * for the device properties UUID.
	 */
	for (i = 0; i < dsd->Package.Count; i += 2) {
		guid = &dsd->Package.Elements[i];

		if (guid->Type != ACPI_TYPE_BUFFER ||
		    guid->Buffer.Length != sizeof (devprops_uuid))
			continue;

		if (memcmp(guid->Buffer.Pointer, &devprops_uuid,
		    sizeof (devprops_uuid)) != 0)
			continue;

		/*
		 * We have the entry for the device properties GUID, now check
		 * that the payload is a package and that it looks reasonable,
		 * which simply means that it is itself a package.
		 */
		dsd_pkg = &dsd->Package.Elements[i + 1];

		if (dsd_pkg->Type != ACPI_TYPE_PACKAGE)
			continue;

		/*
		 * Seems reasonable so far. Now we iterate through the package
		 * pairs, checking that they are packages, that they are pairs
		 * and that the first element is a string (the property name).
		 */
		for (i = 0; i < dsd_pkg->Package.Count; i ++) {
			ACPI_OBJECT *pkg;
			ACPI_OBJECT *name;
			ACPI_OBJECT *val;

			pkg = &dsd_pkg->Package.Elements[i];
			if (pkg->Type != ACPI_TYPE_PACKAGE ||
			    pkg->Package.Count != 2)
				continue;	/* XXXARM: warn? */

			name = &pkg->Package.Elements[0];
			if (name->Type != ACPI_TYPE_STRING ||
			    name->String.Length < 1)
				continue;	/* XXXARM: warn? */

			val = &pkg->Package.Elements[1];
			switch (val->Type) {
			case ACPI_TYPE_INTEGER:
				acpidev_devprop_process_integer(
				    infop, name, val);
				break;
			case ACPI_TYPE_STRING:
				acpidev_devprop_process_string(
				    infop, name, val);
				break;
			/*
			 * We could handle reference objects here
			 */
			case ACPI_TYPE_PACKAGE:
				acpidev_devprop_process_list(infop, name, val);
				break;
			default:
				/* XXXARM: warn? */
				break;
			}
		}
	}

	return (rc);
}

static ACPI_STATUS
acpidev_devprop_walk(acpidev_walk_info_t *infop, ACPI_HANDLE hdl)
{
	ACPI_STATUS rc = AE_OK;
	ACPI_HANDLE mhdl = NULL;
	ACPI_BUFFER dsd_buf;

	ASSERT(hdl != NULL);
	ASSERT(infop != NULL);
	if (hdl == NULL) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: hdl is NULL in acpidev_devprop_walk().");
		return (AE_BAD_PARAMETER);
	}
	if (infop == NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: walk info "
		    "ptr is NULL in acpidev_devprop_walk().");
		return (AE_BAD_PARAMETER);
	}

	/* Check whether method exists under object. */
	if (ACPI_FAILURE(AcpiGetHandle(hdl, METHOD_NAME__DSD, &mhdl))) {
		char *objname = acpidev_get_object_name(hdl);
		ACPIDEV_DEBUG(CE_NOTE,
		    "!acpidev: method %s doesn't exist under %s",
		    METHOD_NAME__DSD, objname);
		acpidev_free_object_name(objname);
		return (AE_NOT_FOUND);
	}

	dsd_buf.Length = ACPI_ALLOCATE_BUFFER;
	dsd_buf.Pointer = NULL;
	rc = AcpiEvaluateObjectTyped(hdl, METHOD_NAME__DSD, NULL,
	    &dsd_buf, ACPI_TYPE_PACKAGE);
	if (ACPI_SUCCESS(rc)) {
		rc = acpidev_devprop_walker(infop, dsd_buf.Pointer);
		AcpiOsFree(dsd_buf.Pointer);
	} else {
		char *objname = acpidev_get_object_name(hdl);
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to walk resource from "
		    "method %s under %s.", METHOD_NAME__DSD, objname);
		acpidev_free_object_name(objname);
	}

	return (rc);
}

static ACPI_STATUS
acpidev_devprop_process_dsd(acpidev_walk_info_t *infop)
{
	ACPI_HANDLE target;
	ACPI_NAMESPACE_NODE *nnode;
	ACPI_STATUS st;

	st = AcpiGetHandle(infop->awi_hdl, METHOD_NAME__DSD, &target);
	if (st != AE_OK)
		return (AE_OK);	/* no such child object */

	if ((nnode = AcpiNsValidateHandle(target)) == NULL)
		return (AE_ERROR);

	/*
	 * Nobody else needs to do this, why do we? Everybody else just calls
	 * it.
	 */
	if (nnode->Type == ACPI_TYPE_PACKAGE) {
		st = acpidev_devprop_walker(infop, target);
	} else if (nnode->Type == ACPI_TYPE_METHOD) {
		/* it's a method, which should return a package */
		ACPI_BUFFER dsd;

		dsd.Length = ACPI_ALLOCATE_BUFFER;
		dsd.Pointer = NULL;
		st = AcpiEvaluateObjectTyped(target, NULL, NULL, &dsd, ACPI_TYPE_PACKAGE);
		if (ACPI_SUCCESS(st)) {
			st = acpidev_devprop_walker(infop, dsd.Pointer);
			AcpiOsFree(dsd.Pointer);
		}
	} else {
		return (AE_ERROR);
	}

	return (st);
}

ACPI_STATUS
acpidev_devprop_process(acpidev_walk_info_t *infop)
{
	ACPI_STATUS rc = AE_OK;
	char path[MAXPATHLEN];

	/*
	 * Only run on the reprobe pass - at this point we have instances
	 * -- but create... that's on the first pass!
	 */
	ASSERT(infop != NULL);
	if (infop == NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: invalid parameter "
		    "in acpidev_devprop_process().");
		return (AE_BAD_PARAMETER);
	}

	/* Walk all resources. */
	(void) ddi_pathname(infop->awi_dip, path);
	rc = acpidev_devprop_process_dsd(infop);
	if (ACPI_FAILURE(rc)) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: failed to walk ACPI device-specific "
		    "data of %s(%s).", path, infop->awi_name);
		return (rc);
	}

	return (rc);
}
