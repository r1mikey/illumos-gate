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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2018, Joyent, Inc.
 */
/*
 * Copyright (c) 2009-2010, Intel Corporation.
 * All rights reserved.
 * Copyright 2019 Western Digital Corporation.
 */

#ifndef _SYS_ACPICA_H
#define	_SYS_ACPICA_H

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/acpi/acpi.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__x86)
typedef struct {
	dev_info_t		*dip;
	kmutex_t		mutex;
	ddi_iblock_cookie_t	iblock_cookie;
} AcpiCA;

/* acpi-user-options options property */
extern unsigned int acpi_options_prop;
#define	ACPI_OUSER_MASK		0x0003
#define	ACPI_OUSER_DFLT		0x0000
#define	ACPI_OUSER_ON		0x0001
#define	ACPI_OUSER_OFF		0x0002
#define	ACPI_OUSER_MADT		0x0004
#define	ACPI_OUSER_LEGACY	0x0008
#endif

/*
 * Initialization state of the ACPI CA subsystem
 */
#define	ACPICA_NOT_INITIALIZED	(0)
#define	ACPICA_INITIALIZED	(1)

extern int acpica_init(void);
#if defined(__x86)
extern void acpica_ec_init(void);
#endif

/*
 * acpi_status property values
 */
#define	ACPI_BOOT_INIT		0x00000001
#define	ACPI_BOOT_ENABLE	0x00000002
#define	ACPI_BOOT_BOOTCONF	0x00000010

#if defined(__x86)
#define	SCI_IPL	(LOCK_LEVEL-1)

/*
 * definitions of Bus Type
 */
#define	BUS_CBUS	1
#define	BUS_CBUSII	2
#define	BUS_EISA	3
#define	BUS_FUTURE	4
#define	BUS_INTERN	5
#define	BUS_ISA		6
#define	BUS_MBI		7
#define	BUS_MBII	8
#define	BUS_PCIE	9
#define	BUS_MPI		10
#define	BUS_MPSA	11
#define	BUS_NUBUS	12
#define	BUS_PCI		13
#define	BUS_PCMCIA	14
#define	BUS_TC		15
#define	BUS_VL		16
#define	BUS_VME		17
#define	BUS_XPRESS	18

/*
 * intr_po - polarity definitions
 */
#define	INTR_PO_CONFORM		0x00
#define	INTR_PO_ACTIVE_HIGH	0x01
#define	INTR_PO_RESERVED	0x02
#define	INTR_PO_ACTIVE_LOW	0x03

/*
 * intr_el edge or level definitions
 */
#define	INTR_EL_CONFORM		0x00
#define	INTR_EL_EDGE		0x01
#define	INTR_EL_RESERVED	0x02
#define	INTR_EL_LEVEL		0x03

/*
 * interrupt flags structure
 */
typedef struct iflag {
	uchar_t	intr_po: 2,
		intr_el: 2,
		bustype: 4;
} iflag_t;

/* _HID for PCI bus object */
#define	HID_PCI_BUS		0x30AD041
#define	HID_PCI_EXPRESS_BUS	0x080AD041
#endif

/* ACPICA subsystem has been fully initialized except SCI interrupt. */
#define	ACPI_FEATURE_FULL_INIT	0x1
/* ACPI SCI interrupt has been enabled. */
#define	ACPI_FEATURE_SCI_EVENT	0x2
/* ACPI device configuration has been enabled. */
#define	ACPI_FEATURE_DEVCFG	0x4
/* ACPI _OSI method should report support of ACPI Module Device. */
#define	ACPI_FEATURE_OSI_MODULE	0x8

/* ACPI device configuration features. */
#define	ACPI_DEVCFG_CPU		0x1
#define	ACPI_DEVCFG_MEMORY	0x2
#define	ACPI_DEVCFG_CONTAINER	0x4
#define	ACPI_DEVCFG_PCI		0x8

#if defined(__x86)
/*
 * isapnp_devs.c
 */
typedef struct device_id {
	struct device_id *next;
	char	*id;
} device_id_t;

typedef struct isapnp_desc {
	const char *ipnp_id;		/* device ID */
	boolean_t ipnp_prefix;		/* prefix match? */
	const char *ipnp_name;		/* dev tree name */
	const char *ipnp_compat;	/* dev tree compatible */
	const char *ipnp_model;		/* dev tree model */
} isapnp_desc_t;

extern const isapnp_desc_t *isapnp_desc_lookup(const device_id_t *);
#endif

/*
 * Function prototypes
 */
#if defined(__x86)
extern ACPI_STATUS acpica_get_sci(int *, iflag_t *);
extern int acpica_get_bdf(dev_info_t *, int *, int *, int *);
#endif
extern ACPI_STATUS acpica_eval_int(ACPI_HANDLE, char *, int *);
extern void acpica_ddi_save_resources(dev_info_t *);
extern void acpica_ddi_restore_resources(dev_info_t *);
#if defined(__x86)
extern void acpi_reset_system(void);
extern void acpica_get_global_FADT(ACPI_TABLE_FADT **);
#endif
extern void acpica_write_cpupm_capabilities(boolean_t, boolean_t);

extern ACPI_STATUS acpica_tag_devinfo(dev_info_t *, ACPI_HANDLE);
extern ACPI_STATUS acpica_untag_devinfo(dev_info_t *, ACPI_HANDLE);
extern ACPI_STATUS acpica_get_devinfo(ACPI_HANDLE, dev_info_t **);
extern ACPI_STATUS acpica_get_handle(dev_info_t *, ACPI_HANDLE *);
#if defined(__x86)
extern ACPI_STATUS acpica_get_handle_cpu(int, ACPI_HANDLE *);
#endif

#if defined(__aarch64__)
extern void acpica_pci_cfgspace_init(void);
extern void acpica_pci_cfgspace_register(dev_info_t *);
#endif
#if defined(__x86)
extern ACPI_STATUS acpica_build_processor_map(void);
#endif
#if defined(__aarch64__)
extern ACPI_STATUS acpica_add_processor_to_map(UINT32, ACPI_HANDLE, UINT64);
#else
extern ACPI_STATUS acpica_add_processor_to_map(UINT32, ACPI_HANDLE, UINT32);
#endif
extern ACPI_STATUS acpica_remove_processor_from_map(UINT32);
extern ACPI_STATUS acpica_map_cpu(processorid_t, UINT32);
extern ACPI_STATUS acpica_unmap_cpu(processorid_t);
extern ACPI_STATUS acpica_get_cpu_object_by_cpuid(processorid_t, ACPI_HANDLE *);
#if defined(__x86)
extern ACPI_STATUS acpica_get_cpu_object_by_procid(UINT32, ACPI_HANDLE *);
#endif
#if defined(__aarch64__)
extern ACPI_STATUS acpica_get_cpu_object_by_mpidr(UINT64, ACPI_HANDLE *);
#else
extern ACPI_STATUS acpica_get_cpu_object_by_apicid(UINT32, ACPI_HANDLE *);
#endif
extern ACPI_STATUS acpica_get_cpu_id_by_object(ACPI_HANDLE, processorid_t *);
#if defined(__x86)
extern ACPI_STATUS acpica_get_apicid_by_object(ACPI_HANDLE, UINT32 *);
#endif
extern ACPI_STATUS acpica_get_procid_by_object(ACPI_HANDLE, UINT32 *);
extern ACPI_STATUS acpica_get_busno(ACPI_HANDLE, int *);

extern uint64_t acpica_get_core_feature(uint64_t);
extern void acpica_set_core_feature(uint64_t);
extern void acpica_clear_core_feature(uint64_t);
extern uint64_t acpica_get_devcfg_feature(uint64_t);
extern void acpica_set_devcfg_feature(uint64_t);
extern void acpica_clear_devcfg_feature(uint64_t);

#if defined(__aarch64__)
extern uint64_t acpica_get_plat_osc(uint64_t);
extern void acpica_set_plat_osc(uint64_t);
extern void acpica_clear_plat_osc(uint64_t);

/*
 * Platform-wide \_SB._OSC Support Field (DWORD 2) bit definitions.
 * ACPI 6.5, Table 6.14.
 */
#define	PLAT_OSC_PROC_AGG	0x00000001	/* Processor Aggr Device */
#define	PLAT_OSC_PPC_OST	0x00000002	/* _PPC _OST Processing */
#define	PLAT_OSC_PR3		0x00000004	/* _PR3 (D3hot/D3) Support */
#define	PLAT_OSC_EJECT_OST	0x00000008	/* Insertion/Ejection _OST */
#define	PLAT_OSC_APEI		0x00000010	/* APEI Support */
#define	PLAT_OSC_CPPC		0x00000020	/* CPPC Support */
#define	PLAT_OSC_CPPC2		0x00000040	/* CPPC Rev 2 (Autonomous) */
#define	PLAT_OSC_PLAT_LPI	0x00000080	/* Platform Coordinated LPI */
#define	PLAT_OSC_OS_LPI		0x00000100	/* OS Initiated LPI */
#define	PLAT_OSC_TFP		0x00000200	/* Fast Thermal Sampling */
#define	PLAT_OSC_GT16_PSTATE	0x00000400	/* >16 P-states */
#define	PLAT_OSC_GED		0x00000800	/* Generic Event Device */
#define	PLAT_OSC_CPPC_DIVERSE	0x00001000	/* Diverse CPPC Highest Perf */
#define	PLAT_OSC_INTR_RSRC	0x00002000	/* Interrupt ResourceSource */
#define	PLAT_OSC_CPPC_FLEX_AS	0x00004000	/* Flexible CPPC Addr Spaces */
#define	PLAT_OSC_GHES_ASSIST	0x00008000	/* GHES_ASSIST */
#define	PLAT_OSC_CPPC_MULTI_PCC	0x00010000	/* Multi PCC for CPPC */
#define	PLAT_OSC_GEN_INIT	0x00020000	/* Generic Initiator (SRAT) */
#define	PLAT_OSC_USB4		0x00040000	/* Native USB4 */
#define	PLAT_OSC_BATT_LIMIT	0x00080000	/* Battery Charge Limiting */
#define	PLAT_OSC_BAR_GAS	0x00100000	/* PCI BAR Target GAS */
#define	PLAT_OSC_PRM		0x00200000	/* Platform Runtime Mechanism */
#define	PLAT_OSC_FFH		0x00400000	/* FFH Operation Regions */
#define	PLAT_OSC_DYN_GPE	0x00800000	/* Dynamic GPE Cap */
#define	PLAT_OSC_RSRC_USAGE	0x01000000	/* Honor ResourceUsage */
#endif

#if defined(__x86)
void scan_d2a_map(void);
#endif

extern ACPI_STATUS acpica_get_object_status(ACPI_HANDLE, int *);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_ACPICA_H */
