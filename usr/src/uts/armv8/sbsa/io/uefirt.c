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
 * Copyright 2023 Michael van der Westhuizen
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bootconf.h>
#include <sys/time.h>
#include <sys/clock.h>
#include <sys/rtc.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/promif.h>
#include <sys/platmod.h>

#include <sys/efi.h>

static EFI_RUNTIME_SERVICES64	*rts;
static uint32_t			supp;

int
uefirt_get_time(timestruc_t *ts)
{
	EFI_STATUS64		st;
	todinfo_t		ti;
	EFI_TIME		et;
	EFI_TIME_CAPABILITIES	tcap;
	int			rv;
	label_t			ljb;

	rv = ENOTSUP;

	if (!rts || !(supp & EFI_RT_SUPPORTED_GET_TIME))
		return (rv);

	if (on_fault(&ljb))
		goto faulty_get_time;

	st = rts->GetTime(&et, &tcap);

	if (st == EFI_UNSUPPORTED) {
		supp &= ~(EFI_RT_SUPPORTED_GET_TIME);
	} else if (st == EFI_DEVICE_ERROR) {
		supp &= ~(EFI_RT_SUPPORTED_GET_TIME);
	} else if (st == EFI_INVALID_PARAMETER) {
		rv = EINVAL;
	} else if (st == EFI_SUCCESS) {
		ti.tod_sec = et.Second;
		ti.tod_min = et.Minute;
		ti.tod_hour = et.Hour;
		ti.tod_dow = 0;
		ti.tod_day = et.Day;
		ti.tod_month = et.Month;
		ti.tod_year = et.Year;

		ts->tv_sec = tod_to_utc(ti);
		ts->tv_sec += ggmtl();
		ts->tv_nsec = et.Nanosecond;

		/*
		 * XXXARM: TimeZone adjustments, Daylight adjustments
		 * TimeZone, Daylight
		 * -1440 to 1440 or 2047, Daylight is weird
		 *
		 * Assume EFI_UNSPECIFIED_TIMEZONE for now.
		 */
		rv = 0;
	}

	return (rv);

faulty_get_time:
	no_fault();
	supp &= ~(EFI_RT_SUPPORTED_GET_TIME);
	return (EFAULT);
}

int
uefirt_set_time(timestruc_t ts)
{
	EFI_STATUS64	st;
	todinfo_t	ti;
	EFI_TIME	et;
	int		rv;
	label_t		ljb;

	rv = ENOTSUP;

	if (!rts || !(supp & EFI_RT_SUPPORTED_SET_TIME))
		return (rv);

	ti = utc_to_tod(ts.tv_sec - ggmtl());

	et.Second = ti.tod_sec;
	et.Minute = ti.tod_min;
	et.Hour = ti.tod_hour;
	et.Day = ti.tod_day;
	et.Month = ti.tod_month;
	et.Year = ti.tod_year;
	et.Nanosecond = ts.tv_nsec;
	/* XXXARM: we need to deal with this mess */
	et.TimeZone = EFI_UNSPECIFIED_TIMEZONE;
	et.Daylight = 0;

	if (on_fault(&ljb))
		goto faulty_set_time;

	st = rts->SetTime(&et);

	if (st == EFI_INVALID_PARAMETER)
		rv = EINVAL;
	else if (st == EFI_DEVICE_ERROR)
		supp &= ~(EFI_RT_SUPPORTED_SET_TIME);
	else if (st == EFI_UNSUPPORTED)
		supp &= ~(EFI_RT_SUPPORTED_SET_TIME);
	else if (st == EFI_SUCCESS)
		rv = 0;

	return (rv);

faulty_set_time:
	no_fault();
	supp &= ~(EFI_RT_SUPPORTED_SET_TIME);
	return (EFAULT);
}

/* XXXARM: implement the remaining functions */

static struct modlmisc modlmisc = {
	&mod_miscops, "efirt"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

#if 0
static uint32_t
calc_crc32(uint8_t *data, size_t len)
{
	size_t i;
	uint32_t checksum = 0;

	for (i = 0; i < len; ++i)
		checksum += (uint32_t)data[i];

	checksum = (checksum & 0xffff) + (checksum >> 16);
	checksum ^= 0xffff;
	return checksum;
}
#endif

static EFI_SYSTEM_TABLE64 *
find_systab(void)
{
	uint64_t systab_addr;
	EFI_SYSTEM_TABLE64 *systab;

	if (BOP_GETPROPLEN(bootops, "uefi.systab") > sizeof(systab_addr) ||
	    BOP_GETPROP(bootops, "uefi.systab", &systab_addr) < 0)
		return (NULL);

	systab = (EFI_SYSTEM_TABLE64 *)systab_addr;
	if (systab->Hdr.Signature != EFI_SYSTEM_TABLE_SIGNATURE)
		return (NULL);

#if 0
	if (calc_crc32((uint8_t *)systab, systab->Hdr.HeaderSize) != 0) {
		prom_printf("find_systab: bad CRC\n");
		return (NULL);
	}
#endif

	if (EFI_REV_MAJOR(systab->Hdr.Revision) < 2 ||
	    (EFI_REV_MAJOR(systab->Hdr.Revision) == 2 &&
	    EFI_REV_MINOR(systab->Hdr.Revision) < 7))
		return (NULL);

	return (systab);
}

static int
config_table_matches_guid(EFI_CONFIGURATION_TABLE64 *a, efi_guid_t *b)
{
	int i;

	if (a->VendorGuid.time_low != b->time_low)
		return (0);
	if (a->VendorGuid.time_mid != b->time_mid)
		return (0);
	if (a->VendorGuid.time_hi_and_version != b->time_hi_and_version)
		return (0);
	if (a->VendorGuid.clock_seq_hi_and_reserved != b->clock_seq_hi_and_reserved)
		return (0);
	if (a->VendorGuid.clock_seq_low != b->clock_seq_low)
		return (0);

	for (i = 0; i < 6; i++) {
		if (a->VendorGuid.node_addr[i] != b->node_addr[i])
			return (0);
	}

	return (1);
}

static void
get_rt_caps(EFI_SYSTEM_TABLE64 *st, uint32_t *caps)
{
	EFI_CONFIGURATION_TABLE64 *ct;
	EFI_RT_PROPERTIES_TABLE *prop;
	efi_guid_t guid = EFI_RT_PROPERTIES_TABLE_GUID;
	uint64_t i;

	if (caps == NULL)
		return;

	*caps = 0xffffffff;

	for (prop = NULL, i = 0; i < st->NumberOfTableEntries; ++i) {
		ct = &st->ConfigurationTable[i];
		if (config_table_matches_guid(ct, &guid)) {
			prop = (EFI_RT_PROPERTIES_TABLE *) ct->VendorTable;
			if (prop->Version != EFI_RT_PROPERTIES_TABLE_VERSION)
				break;
			if (prop->Length != sizeof(*prop))
				break;
			*caps = prop->RuntimeServicesSupported;
			break;
		}
	}
}

static EFI_RUNTIME_SERVICES64 *
get_rts(EFI_SYSTEM_TABLE64 *st)
{
	EFI_RUNTIME_SERVICES64 *rt = st->RuntimeServices;

	if (rt->Hdr.Signature != EFI_RUNTIME_SERVICES_SIGNATURE)
		return (NULL);

#if 0
	if (calc_crc32((uint8_t *)rt, rt->Hdr.HeaderSize) != 0) {
		prom_printf("get_rts: bad CRC\n");
		return (NULL);
	}
#endif

	if (EFI_REV_MAJOR(rt->Hdr.Revision) < 2 ||
	    (EFI_REV_MAJOR(rt->Hdr.Revision) == 2 &&
	    EFI_REV_MINOR(rt->Hdr.Revision) < 7))
		return (NULL);

	return (rt);
}

static int
get_uefi_runtime_services(EFI_RUNTIME_SERVICES64 **prt, uint32_t *caps)
{
	EFI_SYSTEM_TABLE64 *st;

	st = find_systab();
	if (st == NULL)
		return (-1);

	get_rt_caps(st, caps);
	*prt = get_rts(st);
	if (*prt == NULL)
		return (-1);

	return (0);
}

int
_init(void)
{
	EFI_RUNTIME_SERVICES64 *rt;
	uint32_t caps;

	if (get_uefi_runtime_services(&rt, &caps) == 0) {
		rts = rt;
		supp = caps;
	}

	return mod_install(&modlinkage);
}

int
_fini(void)
{
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
