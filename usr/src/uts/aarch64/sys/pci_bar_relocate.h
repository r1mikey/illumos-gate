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
 * Copyright 2026 Michael van der Westhuizen
 */

#ifndef _SYS_PCI_BAR_RELOCATE_H
#define	_SYS_PCI_BAR_RELOCATE_H

/*
 * PCI BAR relocation callback framework.
 *
 * Allows subsystems to register a physical address that falls within
 * a PCI BAR.  When pci_boot reprograms that BAR, PRE/POST callbacks
 * fire so the consumer can stall I/O, update its mapping, and resume.
 */

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum pci_bar_relocate_phase {
	PCI_BAR_PRE_RELOCATE,
	PCI_BAR_POST_RELOCATE
} pci_bar_relocate_phase_t;

typedef struct pci_bar_relocate_info {
	uint64_t	bri_old_addr;
	uint64_t	bri_new_addr;	/* POST only; 0 = failed */
	uint64_t	bri_size;
	uint8_t		bri_bus;
	uint8_t		bri_dev;
	uint8_t		bri_func;
	uint_t		bri_bar;
} pci_bar_relocate_info_t;

typedef void (*pci_bar_relocate_fn_t)(pci_bar_relocate_phase_t,
    const pci_bar_relocate_info_t *, void *);

/*
 * BAR relocation observer.  Caller owns the storage — typically a
 * static or module-lifetime allocation.  The framework links it onto
 * its internal list; the caller must not free it while registered.
 *
 * Caller sets brc_fn, brc_arg, and brc_match_addr before calling
 * pci_bar_relocate_register().  All other fields are private.
 */
typedef struct pci_bar_relocate_cb {
	/* public — set by caller before registration */
	pci_bar_relocate_fn_t		brc_fn;
	void				*brc_arg;
	uint64_t			brc_match_addr;
	/* private — managed by framework */
	boolean_t			brc_armed;
	uint8_t				brc_bus;
	uint8_t				brc_dev;
	uint8_t				brc_func;
	uint_t				brc_bar;
	struct pci_bar_relocate_cb	*brc_next;
} pci_bar_relocate_cb_t;

extern void pci_bar_relocate_init(void);
extern void pci_bar_relocate_register(pci_bar_relocate_cb_t *);
extern void pci_bar_relocate_unregister(pci_bar_relocate_cb_t *);
extern void pci_bar_relocate_match(uint64_t bar_base, uint64_t bar_size,
    uint8_t bus, uint8_t dev, uint8_t func, uint_t bar);
extern void pci_bar_relocate_notify(pci_bar_relocate_phase_t phase,
    uint8_t bus, uint8_t dev, uint8_t func, uint_t bar,
    uint64_t old_addr, uint64_t new_addr, uint64_t size);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_PCI_BAR_RELOCATE_H */
