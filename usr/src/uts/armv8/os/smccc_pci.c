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

/*
 *  DEN0115: Arm® PCI Configuration Space Access Firmware Interface
 */

#include <sys/types.h>
#include <sys/smccc_pci.h>
#include <sys/smccc.h>
#include <sys/errno.h>
#include <sys/ddi.h>

static boolean_t smccc_pci_initialized = B_FALSE;
static boolean_t smccc_pci_is_available = B_FALSE;
static smccc_pci_version_t smccc_pci_version_number = SMCCC_PCI_UNSUPPORTED;

#define	SMCCC_REQUIRE_VERSION(v)			\
	do {						\
		if (!smccc_pci_is_available)		\
			return (-EIO);			\
		if (smccc_pci_version_number < (v))	\
			return (-ENOTSUP);		\
	} while (0)

static int
smccc_pci_return_to_errno(smccc32_args_t *r)
{
	switch ((int32_t)r->w0) {
	case 0:
		return (0);
	case SMCCC_PCI_NOT_SUPPORTED:
		return (-ENOTSUP);
	case SMCCC_PCI_INVALID_PARAMETER:
		return (-EINVAL);
	case SMCCC_PCI_NOT_IMPLEMENTED:
		return (-ENXIO);
	default:
		return (-EIO);
	}
}

void
smccc_pci_init(void)
{
	smccc32_args_t probe_args = {
		.w0	= SMCCC_PCI_VERSION_ID,
	};

	if (smccc_pci_initialized)
		return;

	if (!smccc_available()) {
		smccc_pci_initialized = B_TRUE;
		smccc_pci_is_available = B_FALSE;
		return;
	}

	if (smccc_version() < SMCCC_VERSION_1_1) {
		smccc_pci_initialized = B_TRUE;
		smccc_pci_is_available = B_FALSE;
		return;
	}

	smccc32_call(&probe_args);
	if ((int32_t)probe_args.w0 >= 0)
		smccc_pci_is_available = B_TRUE;

	if (smccc_pci_is_available) {
		switch ((probe_args.w0 & 0x7FFF0000) >> 16) {
		case 0:
			smccc_pci_is_available = B_FALSE;
			smccc_pci_version_number = SMCCC_PCI_UNSUPPORTED;
			break;
		case 1:
			switch (probe_args.w0 & 0xFFFF) {
			case SMCCC_PCI_VERSION_1_0:
				smccc_pci_version_number =
				    SMCCC_PCI_VERSION_1_0;
				break;
			default:
				smccc_pci_version_number =
				    SMCCC_PCI_VERSION_1_0;
				break;
			}
			break;
		default:
			smccc_pci_version_number =
			    SMCCC_PCI_VERSION_HIGHEST_SUPPORTED;
			break;
		}
	}

	smccc_pci_initialized = B_TRUE;
}

boolean_t
smccc_pci_available(void)
{
	return ((smccc_pci_initialized && smccc_pci_is_available) ?
	    B_TRUE : B_FALSE);
}

int
smccc_pci_version(uint32_t *version)
{
	smccc32_args_t call = {
		.w0	= SMCCC_PCI_VERSION_ID,
	};

	SMCCC_REQUIRE_VERSION(SMCCC_PCI_VERSION_1_0);
	smccc32_call(&call);
	if ((int32_t)call.w0 < 0)
		return (smccc_pci_return_to_errno(&call));

	ASSERT(version != NULL);
	*version = call.w0;
	return (0);
}

int
smccc_pci_features(uint32_t pci_func_id, uint32_t *features)
{
	smccc32_args_t call = {
		.w0	= SMCCC_PCI_FEATURES_ID,
	};

	SMCCC_REQUIRE_VERSION(SMCCC_PCI_VERSION_1_0);
	smccc32_call(&call);
	if ((int32_t)call.w0 < 0)
		return (smccc_pci_return_to_errno(&call));

	if (features)
		*features = call.w0;
	return (0);
}

int
smccc_pci_read(uint16_t segment_group_number, uint8_t bus_number,
    uint8_t device_number, uint8_t function_number, uint32_t register_offset,
    uint32_t access_size, uint32_t *data)
{
	ASSERT(access_size == 1 || access_size == 2 || access_size == 4);
	smccc32_args_t call = {
		.w0	= SMCCC_PCI_READ_ID,
		.w1	= (((uint32_t)segment_group_number) << 16) |
			    (((uint32_t)bus_number) << 8) |
			    (((uint32_t)(device_number & 0x1F)) << 3) |
			    ((uint32_t)(function_number & 0x7)),
		.w2	= register_offset,
		.w3	= access_size
	};

	SMCCC_REQUIRE_VERSION(SMCCC_PCI_VERSION_1_0);
	smccc32_call(&call);
	if ((int32_t)call.w0 < 0 || call.w0 != 0)
		return (smccc_pci_return_to_errno(&call));

	VERIFY(data != NULL);
	*data = call.w1;
	return (0);
}

int
smccc_pci_write(uint16_t segment_group_number, uint8_t bus_number,
    uint8_t device_number, uint8_t function_number, uint32_t register_offset,
    uint32_t access_size, uint32_t data)
{
	ASSERT(access_size == 1 || access_size == 2 || access_size == 4);
	smccc32_args_t call = {
		.w0	= SMCCC_PCI_WRITE_ID,
		.w1	= (((uint32_t)segment_group_number) << 16) |
			    (((uint32_t)bus_number) << 8) |
			    (((uint32_t)(device_number & 0x1F)) << 3) |
			    ((uint32_t)(function_number & 0x7)),
		.w2	= register_offset,
		.w3	= access_size,
		.w4	= data
	};

	SMCCC_REQUIRE_VERSION(SMCCC_PCI_VERSION_1_0);
	smccc32_call(&call);
	if ((int32_t)call.w0 < 0 || call.w0 != 0)
		return (smccc_pci_return_to_errno(&call));
	return (0);
}

int
smccc_pci_get_seg_info(uint16_t pci_seg,
    uint8_t *starting_bus_number, uint8_t *ending_bus_number,
    uint16_t *pci_next_seg)
{
	smccc32_args_t call = {
		.w0	= SMCCC_PCI_GET_SEG_INFO_ID,
		.w1	= pci_seg
	};

	SMCCC_REQUIRE_VERSION(SMCCC_PCI_VERSION_1_0);
	smccc32_call(&call);
	if ((int32_t)call.w0 < 0 || call.w0 != 0)
		return (smccc_pci_return_to_errno(&call));

	VERIFY(starting_bus_number != NULL);
	VERIFY(ending_bus_number != NULL);
	VERIFY(pci_next_seg != NULL);

	*starting_bus_number = call.w1 & 0xFF;
	*ending_bus_number = (call.w1 >> 8) & 0xFF;
	*pci_next_seg = call.w2 & 0xFFFF;
	return (0);
}
