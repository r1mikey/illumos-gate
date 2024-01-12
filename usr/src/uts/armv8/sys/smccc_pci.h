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

#ifndef _SYS_SMCCC_PCI_H
#define	_SYS_SMCCC_PCI_H

/*
 * DEN0115: Arm® PCI Configuration Space Access Firmware Interface
 */

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	SMCCC_PCI_UNSUPPORTED			= 0,
	SMCCC_PCI_VERSION_1_0			= 1,

	SMCCC_PCI_VERSION_HIGHEST_SUPPORTED	= SMCCC_PCI_VERSION_1_0,
} smccc_pci_version_t;

#define	SMCCC_PCI_VERSION_ID			0x84000130
#define	SMCCC_PCI_FEATURES_ID			0x84000131
#define	SMCCC_PCI_READ_ID			0x84000132
#define	SMCCC_PCI_WRITE_ID			0x84000133
#define	SMCCC_PCI_GET_SEG_INFO_ID		0x84000134

#define	SMCCC_PCI_SUCCESS			0u
#define	SMCCC_PCI_NOT_SUPPORTED			0xFFFFFFFFu
#define	SMCCC_PCI_INVALID_PARAMETER		0xFFFFFFFEu
#define	SMCCC_PCI_NOT_IMPLEMENTED		0xFFFFFFFDu

extern void smccc_pci_init(void);
extern boolean_t smccc_pci_available(void);

extern int smccc_pci_version(uint32_t *version);
extern int smccc_pci_features(uint32_t pci_func_id, uint32_t *features);
extern int smccc_pci_read(uint16_t segment_group_number, uint8_t bus_number,
    uint8_t device_number, uint8_t function_number, uint32_t register_offset,
    uint32_t access_size, uint32_t *data);
extern int smccc_pci_write(uint16_t segment_group_number, uint8_t bus_number,
    uint8_t device_number, uint8_t function_number, uint32_t register_offset,
    uint32_t access_size, uint32_t data);
extern int smccc_pci_get_seg_info(uint16_t pci_seg,
    uint8_t *starting_bus_number, uint8_t *ending_bus_number,
    uint16_t *pci_next_seg);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_SMCCC_PCI_H */
