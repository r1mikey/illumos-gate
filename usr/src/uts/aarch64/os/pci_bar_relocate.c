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

/*
 * PCI BAR relocation callback framework.
 *
 * Allows subsystems to register a physical address that falls within
 * a PCI BAR.  When pci_boot reprograms that BAR, PRE/POST callbacks
 * fire so the consumer can stall I/O, update its mapping, and resume.
 *
 * Caller owns the callback struct memory.  The framework links it
 * onto an internal list and calls through the function pointer
 * during BAR reprogramming.
 *
 * Built into unix — must be available before any PCI modules load.
 */

#include <sys/types.h>
#include <sys/null.h>
#include <sys/cmn_err.h>
#include <sys/mutex.h>
#include <sys/debug.h>
#include <sys/pci_bar_relocate.h>

static pci_bar_relocate_cb_t	*pci_bar_relocate_list;
static kmutex_t			pci_bar_relocate_lock;

void
pci_bar_relocate_init(void)
{
	mutex_init(&pci_bar_relocate_lock, NULL, MUTEX_DEFAULT, NULL);
}

void
pci_bar_relocate_register(pci_bar_relocate_cb_t *cb)
{
	ASSERT3P(cb->brc_fn, !=, NULL);

	cb->brc_armed = B_FALSE;

	mutex_enter(&pci_bar_relocate_lock);
	cb->brc_next = pci_bar_relocate_list;
	pci_bar_relocate_list = cb;
	mutex_exit(&pci_bar_relocate_lock);
}

void
pci_bar_relocate_unregister(pci_bar_relocate_cb_t *cb)
{
	pci_bar_relocate_cb_t **pp;

	mutex_enter(&pci_bar_relocate_lock);
	for (pp = &pci_bar_relocate_list; *pp != NULL;
	    pp = &(*pp)->brc_next) {
		if (*pp == cb) {
			*pp = cb->brc_next;
			cb->brc_next = NULL;
			break;
		}
	}
	mutex_exit(&pci_bar_relocate_lock);
}

void
pci_bar_relocate_match(uint64_t bar_base, uint64_t bar_size,
    uint8_t bus, uint8_t dev, uint8_t func, uint_t bar)
{
	pci_bar_relocate_cb_t *cb;

	if (bar_base == 0 || bar_size == 0)
		return;

	mutex_enter(&pci_bar_relocate_lock);
	for (cb = pci_bar_relocate_list; cb != NULL; cb = cb->brc_next) {
		if (cb->brc_armed)
			continue;
		if (cb->brc_match_addr >= bar_base &&
		    cb->brc_match_addr < bar_base + bar_size) {
			cb->brc_armed = B_TRUE;
			cb->brc_bus = bus;
			cb->brc_dev = dev;
			cb->brc_func = func;
			cb->brc_bar = bar;
		}
	}
	mutex_exit(&pci_bar_relocate_lock);
}

void
pci_bar_relocate_notify(pci_bar_relocate_phase_t phase,
    uint8_t bus, uint8_t dev, uint8_t func, uint_t bar,
    uint64_t old_addr, uint64_t new_addr, uint64_t size)
{
	pci_bar_relocate_cb_t *cb;
	pci_bar_relocate_info_t info;

	mutex_enter(&pci_bar_relocate_lock);
	for (cb = pci_bar_relocate_list; cb != NULL; cb = cb->brc_next) {
		if (!cb->brc_armed)
			continue;
		if (cb->brc_bus != bus || cb->brc_dev != dev ||
		    cb->brc_func != func || cb->brc_bar != bar)
			continue;

		info.bri_old_addr = old_addr;
		info.bri_new_addr = new_addr;
		info.bri_size = size;
		info.bri_bus = bus;
		info.bri_dev = dev;
		info.bri_func = func;
		info.bri_bar = bar;

		cb->brc_fn(phase, &info, cb->brc_arg);
	}
	mutex_exit(&pci_bar_relocate_lock);
}
