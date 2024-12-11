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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2012 Garrett D'Amore <garrett@damore.org>
 * Copyright 2014 Pluribus Networks, Inc.
 * Copyright 2016 Nexenta Systems, Inc.
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2018 Joyent, Inc.
 * Copyright 2024 Michael van der Westhuizen
 */

/*
 * aarch64-specific DDI implementation, firmware independent routines.
 */
#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/avintr.h>
#include <sys/mach_intr.h>
#include <sys/promif.h>
#include <sys/sysmacros.h>
#include <sys/stddef.h>
#include <sys/font.h>
#include <sys/conf.h>
#include <sys/ramdisk.h>
#include <sys/bootconf.h>
#include <sys/ontrap.h>
#include <sys/fm/protocol.h>
#include <vm/seg_kmem.h>
#include <vm/hat_aarch64.h>

/*
 * Define IMPL_DDI_DUMP_DEVTREE_INITIAL to dump the device tree immediately
 * after the initial probe completes.
 */
/* #define	IMPL_DDI_DUMP_DEVTREE_INITIAL */
/*
 * Define IMPL_DDI_DUMP_DEVTREE_REPROBE to dump the device tree immediately
 * after the reprobe completes.
 */
/* #define	IMPL_DDI_DUMP_DEVTREE_REPROBE */

/*
 * We use an AVL tree to store contiguous address allocations made with the
 * kalloca() routine, so that we can return the size to free with kfreea().
 * Note that in the future it would be vastly faster if we could eliminate
 * this lookup by insisting that all callers keep track of their own sizes,
 * just as for kmem_alloc().
 */
struct ctgas {
	avl_node_t	ctg_link;
	void		*ctg_addr;
	size_t		ctg_size;
};

static avl_tree_t	ctgtree;
static kmutex_t		ctgmutex;
#define	CTGLOCK()	mutex_enter(&ctgmutex)
#define	CTGUNLOCK()	mutex_exit(&ctgmutex)

/*
 * Minimum pfn value of page_t's put on the free list.  This is to simplify
 * support of ddi dma memory requests which specify small, non-zero addr_lo
 * values.
 *
 * The default value of 2, which corresponds to the only known non-zero addr_lo
 * value used, means a single page will be sacrificed (pfn typically starts
 * at 1).  ddiphysmin can be set to 0 to disable. It cannot be set above 0x100
 * otherwise mp startup panics.
 */
pfn_t	ddiphysmin = 2;

size_t dma_max_copybuf_size = 0x101000;		/* 1M + 4K */
uint64_t ramdisk_start, ramdisk_end;

uint8_t
i_ddi_get8(ddi_acc_impl_t *hdlp, uint8_t *addr)
{
	uint8_t x;
	__asm__ volatile("ldrb %w0, %1" : "=r" (x) : "Q" (*addr) : "memory");
	return (x);
}

uint16_t
i_ddi_get16(ddi_acc_impl_t *hdlp, uint16_t *addr)
{
	uint16_t x;
	__asm__ volatile("ldrh %w0, %1" : "=r" (x) : "Q" (*addr) : "memory");
	return (x);
}

uint32_t
i_ddi_get32(ddi_acc_impl_t *hdlp, uint32_t *addr)
{
	uint32_t x;
	__asm__ volatile("ldr %w0, %1" : "=r" (x) : "Q" (*addr) : "memory");
	return (x);
}

uint64_t
i_ddi_get64(ddi_acc_impl_t *hdlp, uint64_t *addr)
{
	uint64_t x;
	__asm__ volatile("ldr %0, %1" : "=r" (x) : "Q" (*addr) : "memory");
	return (x);
}

void
i_ddi_put8(ddi_acc_impl_t *hdlp, uint8_t *addr, uint8_t value)
{
	__asm__ volatile("strb %w1, %0" : "=Q" (*addr) : "r"(value) : "memory");
}

void
i_ddi_put16(ddi_acc_impl_t *hdlp, uint16_t *addr, uint16_t value)
{
	__asm__ volatile("strh %w1, %0" : "=Q" (*addr) : "r"(value) : "memory");
}

void
i_ddi_put32(ddi_acc_impl_t *hdlp, uint32_t *addr, uint32_t value)
{
	__asm__ volatile("str %w1, %0" : "=Q" (*addr) : "r"(value) : "memory");
}

void
i_ddi_put64(ddi_acc_impl_t *hdlp, uint64_t *addr, uint64_t value)
{
	__asm__ volatile("str %1, %0" : "=Q" (*addr) : "r"(value) : "memory");
}

void
i_ddi_rep_get8(ddi_acc_impl_t *hdlp, uint8_t *host_addr, uint8_t *dev_addr,
    size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("ldrb %w0, %1"
			    : "=r" (*(host_addr++))
			    : "Q" (*(dev_addr++))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("ldrb %w0, %1"
			    : "=r" (*(host_addr++))
			    : "Q" (*(dev_addr))
			    : "memory");
}

void
i_ddi_rep_get16(ddi_acc_impl_t *hdlp, uint16_t *host_addr, uint16_t *dev_addr,
    size_t repcount, const uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("ldrh %w0, %1"
			    : "=r" (*(host_addr++))
			    : "Q" (*(dev_addr++))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("ldrh %w0, %1"
			    : "=r" (*(host_addr++))
			    : "Q" (*(dev_addr))
			    : "memory");
}

void
i_ddi_rep_get32(ddi_acc_impl_t *hdlp, uint32_t *host_addr, uint32_t *dev_addr,
    size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("ldr %w0, %1"
			    : "=r" (*(host_addr++))
			    : "Q" (*(dev_addr++))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("ldr %w0, %1"
			    : "=r" (*(host_addr++))
			    : "Q" (*(dev_addr))
			    : "memory");
}

void
i_ddi_rep_get64(ddi_acc_impl_t *hdlp, uint64_t *host_addr, uint64_t *dev_addr,
    size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("ldr %0, %1"
			    : "=r" (*(host_addr++))
			    : "Q" (*(dev_addr++))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("ldr %0, %1"
			    : "=r" (*(host_addr++))
			    : "Q" (*(dev_addr))
			    : "memory");
}

void
i_ddi_rep_put8(ddi_acc_impl_t *hdlp, uint8_t *host_addr, uint8_t *dev_addr,
    size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("strb %w1, %0"
			    : "=Q" (*(dev_addr++))
			    : "r"(*(host_addr++))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("strb %w1, %0"
			    : "=Q" (*(dev_addr))
			    : "r"(*(host_addr++))
			    : "memory");
}

void
i_ddi_rep_put16(ddi_acc_impl_t *hdlp, uint16_t *host_addr, uint16_t *dev_addr,
    size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("strh %w1, %0"
			    : "=Q" (*(dev_addr++))
			    : "r"(*(host_addr++))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("strh %w1, %0"
			    : "=Q" (*(dev_addr))
			    : "r"(*(host_addr++))
			    : "memory");
}

void
i_ddi_rep_put32(ddi_acc_impl_t *hdlp, uint32_t *host_addr, uint32_t *dev_addr,
    size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("str %w1, %0"
			    : "=Q" (*(dev_addr++))
			    : "r"(*(host_addr++))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("str %w1, %0"
			    : "=Q" (*(dev_addr))
			    : "r"(*(host_addr++))
			    : "memory");
}

void
i_ddi_rep_put64(ddi_acc_impl_t *hdlp, uint64_t *host_addr, uint64_t *dev_addr,
    size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("str %1, %0"
			    : "=Q" (*(dev_addr++))
			    : "r"(*(host_addr++))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("str %1, %0"
			    : "=Q" (*(dev_addr))
			    : "r"(*(host_addr++))
			    : "memory");
}

uint16_t
i_ddi_swap_get16(ddi_acc_impl_t *hdlp, uint16_t *addr)
{
	uint16_t x;
	__asm__ volatile("ldrh %w0, %1"
	    : "=r" (x)
	    : "Q" (*addr)
	    : "memory");
	return (__builtin_bswap16(x));
}

uint32_t
i_ddi_swap_get32(ddi_acc_impl_t *hdlp, uint32_t *addr)
{
	uint32_t x;
	__asm__ volatile("ldr %w0, %1"
	    : "=r" (x)
	    : "Q" (*addr)
	    : "memory");
	return (__builtin_bswap32(x));
}

uint64_t
i_ddi_swap_get64(ddi_acc_impl_t *hdlp, uint64_t *addr)
{
	uint64_t x;
	__asm__ volatile("ldr %0, %1"
	    : "=r" (x)
	    : "Q" (*addr)
	    : "memory");
	return (__builtin_bswap64(x));
}

void
i_ddi_swap_put16(ddi_acc_impl_t *hdlp, uint16_t *addr, uint16_t value)
{
	__asm__ volatile("strh %w1, %0"
	    : "=Q" (*addr)
	    : "r"(__builtin_bswap16(value))
	    : "memory");
}

void
i_ddi_swap_put32(ddi_acc_impl_t *hdlp, uint32_t *addr, uint32_t value)
{
	__asm__ volatile("str %w1, %0"
	    : "=Q" (*addr)
	    : "r"(__builtin_bswap32(value))
	    : "memory");
}

void
i_ddi_swap_put64(ddi_acc_impl_t *hdlp, uint64_t *addr, uint64_t value)
{
	__asm__ volatile("str %1, %0"
	    : "=Q" (*addr)
	    : "r"(__builtin_bswap64(value))
	    : "memory");
}

void
i_ddi_swap_rep_get16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, const uint_t flags)
{
	uint16_t x;
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--) {
			__asm__ volatile("ldrh %w0, %1"
			    : "=r" (x)
			    : "Q" (*(dev_addr++))
			    : "memory");
			*host_addr++ = __builtin_bswap16(x);
		}
	else
		while (repcount--) {
			__asm__ volatile("ldrh %w0, %1"
			    : "=r" (x)
			    : "Q" (*(dev_addr))
			    : "memory");
			*host_addr++ = __builtin_bswap16(x);
		}
}

void
i_ddi_swap_rep_get32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	uint32_t x;
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--) {
			__asm__ volatile("ldr %w0, %1"
			    : "=r" (x)
			    : "Q" (*(dev_addr++))
			    : "memory");
			*host_addr++ = __builtin_bswap32(x);
		}
	else
		while (repcount--) {
			__asm__ volatile("ldr %w0, %1"
			    : "=r" (x)
			    : "Q" (*(dev_addr))
			    : "memory");
			*host_addr++ = __builtin_bswap32(x);
		}
}

void
i_ddi_swap_rep_get64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	uint64_t x;
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--) {
			__asm__ volatile("ldr %0, %1"
			    : "=r" (x)
			    : "Q" (*(dev_addr++))
			    : "memory");
			*host_addr++ = __builtin_bswap64(x);
		}
	else
		while (repcount--) {
			__asm__ volatile("ldr %0, %1"
			    : "=r" (x)
			    : "Q" (*(dev_addr))
			    : "memory");
			*host_addr++ = __builtin_bswap64(x);
		}
}

void
i_ddi_swap_rep_put16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("strh %w1, %0"
			    : "=Q" (*(dev_addr++))
			    : "r"(__builtin_bswap16(*(host_addr++)))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("strh %w1, %0"
			    : "=Q" (*(dev_addr))
			    : "r"(__builtin_bswap16(*(host_addr++)))
			    : "memory");
}

void
i_ddi_swap_rep_put32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("str %w1, %0"
			    : "=Q" (*(dev_addr++))
			    : "r"(__builtin_bswap32(*(host_addr++)))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("str %w1, %0"
			    : "=Q" (*(dev_addr))
			    : "r"(__builtin_bswap32(*(host_addr++)))
			    : "memory");
}

void
i_ddi_swap_rep_put64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("str %1, %0"
			    : "=Q" (*(dev_addr++))
			    : "r"(__builtin_bswap64(*(host_addr++)))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("str %1, %0"
			    : "=Q" (*(dev_addr))
			    : "r"(__builtin_bswap64(*(host_addr++)))
			    : "memory");
}

uint8_t
i_ddi_io_get8(ddi_acc_impl_t *hdlp, uint8_t *addr)
{
	uint8_t *io_addr =
	    (uint8_t *)((uintptr_t)addr + hdlp->ahi_io_port_base);
	uint8_t x;
	__asm__ volatile("ldrb %w0, %1" : "=r" (x) : "Q" (*io_addr) : "memory");
	return (x);
}

uint16_t
i_ddi_io_get16(ddi_acc_impl_t *hdlp, uint16_t *addr)
{
	uint16_t *io_addr =
	    (uint16_t *)((uintptr_t)addr + hdlp->ahi_io_port_base);
	uint16_t x;
	__asm__ volatile("ldrh %w0, %1" : "=r" (x) : "Q" (*io_addr) : "memory");
	return (x);
}

uint32_t
i_ddi_io_get32(ddi_acc_impl_t *hdlp, uint32_t *addr)
{
	uint32_t *io_addr =
	    (uint32_t *)((uintptr_t)addr + hdlp->ahi_io_port_base);
	uint32_t x;
	__asm__ volatile("ldr %w0, %1" : "=r" (x) : "Q" (*io_addr) : "memory");
	return (x);
}

uint64_t
i_ddi_io_get64(ddi_acc_impl_t *hdlp, uint64_t *addr)
{
	uint64_t *io_addr =
	    (uint64_t *)((uintptr_t)addr + hdlp->ahi_io_port_base);
	uint64_t x;
	__asm__ volatile("ldr %0, %1" : "=r" (x) : "Q" (*io_addr) : "memory");
	return (x);
}

void
i_ddi_io_put8(ddi_acc_impl_t *hdlp, uint8_t *addr, uint8_t value)
{
	uint8_t *io_addr =
	    (uint8_t *)((uintptr_t)addr + hdlp->ahi_io_port_base);
	__asm__ volatile("strb %w1, %0"
	    : "=Q" (*io_addr)
	    : "r"(value)
	    : "memory");
}

void
i_ddi_io_put16(ddi_acc_impl_t *hdlp, uint16_t *addr, uint16_t value)
{
	uint16_t *io_addr =
	    (uint16_t *)((uintptr_t)addr + hdlp->ahi_io_port_base);
	__asm__ volatile("strh %w1, %0"
	    : "=Q" (*io_addr)
	    : "r"(value)
	    : "memory");
}

void
i_ddi_io_put32(ddi_acc_impl_t *hdlp, uint32_t *addr, uint32_t value)
{
	uint32_t *io_addr =
	    (uint32_t *)((uintptr_t)addr + hdlp->ahi_io_port_base);
	__asm__ volatile("str %w1, %0"
	    : "=Q" (*io_addr)
	    : "r"(value)
	    : "memory");
}

void
i_ddi_io_put64(ddi_acc_impl_t *hdlp, uint64_t *addr, uint64_t value)
{
	uint64_t *io_addr =
	    (uint64_t *)((uintptr_t)addr + hdlp->ahi_io_port_base);
	__asm__ volatile("str %1, %0"
	    : "=Q" (*io_addr)
	    : "r"(value)
	    : "memory");
}

void
i_ddi_io_rep_get8(ddi_acc_impl_t *hdlp, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount, uint_t flags)
{
	uint8_t *io_dev_addr =
	    (uint8_t *)((uintptr_t)dev_addr + hdlp->ahi_io_port_base);
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("ldrb %w0, %1"
			    : "=r" (*(host_addr++))
			    : "Q" (*(io_dev_addr++))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("ldrb %w0, %1"
			    : "=r" (*(host_addr++))
			    : "Q" (*(io_dev_addr))
			    : "memory");
}

void
i_ddi_io_rep_get16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, const uint_t flags)
{
	uint16_t *io_dev_addr =
	    (uint16_t *)((uintptr_t)dev_addr + hdlp->ahi_io_port_base);
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("ldrh %w0, %1"
			    : "=r" (*(host_addr++))
			    : "Q" (*(io_dev_addr++))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("ldrh %w0, %1"
			    : "=r" (*(host_addr++))
			    : "Q" (*(io_dev_addr))
			    : "memory");
}

void
i_ddi_io_rep_get32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	uint32_t *io_dev_addr =
	    (uint32_t *)((uintptr_t)dev_addr + hdlp->ahi_io_port_base);
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("ldr %w0, %1"
			    : "=r" (*(host_addr++))
			    : "Q" (*(io_dev_addr++))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("ldr %w0, %1"
			    : "=r" (*(host_addr++))
			    : "Q" (*(io_dev_addr))
			    : "memory");
}

void
i_ddi_io_rep_get64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	uint64_t *io_dev_addr =
	    (uint64_t *)((uintptr_t)dev_addr + hdlp->ahi_io_port_base);
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("ldr %0, %1"
			    : "=r" (*(host_addr++))
			    : "Q" (*(io_dev_addr++))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("ldr %0, %1"
			    : "=r" (*(host_addr++))
			    : "Q" (*(io_dev_addr))
			    : "memory");
}

void
i_ddi_io_rep_put8(ddi_acc_impl_t *hdlp, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount, uint_t flags)
{
	uint8_t *io_dev_addr =
	    (uint8_t *)((uintptr_t)dev_addr + hdlp->ahi_io_port_base);
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("strb %w1, %0"
			    : "=Q" (*(io_dev_addr++))
			    : "r"(*(host_addr++))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("strb %w1, %0"
			    : "=Q" (*(io_dev_addr))
			    : "r"(*(host_addr++))
			    : "memory");
}

void
i_ddi_io_rep_put16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	uint16_t *io_dev_addr =
	    (uint16_t *)((uintptr_t)dev_addr + hdlp->ahi_io_port_base);
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("strh %w1, %0"
			    : "=Q" (*(io_dev_addr++))
			    : "r"(*(host_addr++))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("strh %w1, %0"
			    : "=Q" (*(io_dev_addr))
			    : "r"(*(host_addr++))
			    : "memory");
}

void
i_ddi_io_rep_put32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	uint32_t *io_dev_addr =
	    (uint32_t *)((uintptr_t)dev_addr + hdlp->ahi_io_port_base);
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("str %w1, %0"
			    : "=Q" (*(io_dev_addr++))
			    : "r"(*(host_addr++))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("str %w1, %0"
			    : "=Q" (*(io_dev_addr))
			    : "r"(*(host_addr++))
			    : "memory");
}

void
i_ddi_io_rep_put64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	uint64_t *io_dev_addr =
	    (uint64_t *)((uintptr_t)dev_addr + hdlp->ahi_io_port_base);
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("str %1, %0"
			    : "=Q" (*(io_dev_addr++))
			    : "r"(*(host_addr++))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("str %1, %0"
			    : "=Q" (*(io_dev_addr))
			    : "r"(*(host_addr++))
			    : "memory");
}

uint16_t
i_ddi_io_swap_get16(ddi_acc_impl_t *hdlp, uint16_t *addr)
{
	uint16_t *io_addr =
	    (uint16_t *)((uintptr_t)addr + hdlp->ahi_io_port_base);
	uint16_t x;
	__asm__ volatile("ldrh %w0, %1"
	    : "=r" (x)
	    : "Q" (*io_addr)
	    : "memory");
	return (__builtin_bswap16(x));
}

uint32_t
i_ddi_io_swap_get32(ddi_acc_impl_t *hdlp, uint32_t *addr)
{
	uint32_t *io_addr =
	    (uint32_t *)((uintptr_t)addr + hdlp->ahi_io_port_base);
	uint32_t x;
	__asm__ volatile("ldr %w0, %1"
	    : "=r" (x)
	    : "Q" (*io_addr)
	    : "memory");
	return (__builtin_bswap32(x));
}

uint64_t
i_ddi_io_swap_get64(ddi_acc_impl_t *hdlp, uint64_t *addr)
{
	uint64_t *io_addr =
	    (uint64_t *)((uintptr_t)addr + hdlp->ahi_io_port_base);
	uint64_t x;
	__asm__ volatile("ldr %0, %1"
	    : "=r" (x)
	    : "Q" (*io_addr)
	    : "memory");
	return (__builtin_bswap64(x));
}

void
i_ddi_io_swap_put16(ddi_acc_impl_t *hdlp, uint16_t *addr, uint16_t value)
{
	uint16_t *io_addr =
	    (uint16_t *)((uintptr_t)addr + hdlp->ahi_io_port_base);
	__asm__ volatile("strh %w1, %0"
	    : "=Q" (*io_addr)
	    : "r"(__builtin_bswap16(value))
	    : "memory");
}

void
i_ddi_io_swap_put32(ddi_acc_impl_t *hdlp, uint32_t *addr, uint32_t value)
{
	uint32_t *io_addr =
	    (uint32_t *)((uintptr_t)addr + hdlp->ahi_io_port_base);
	__asm__ volatile("str %w1, %0"
	    : "=Q" (*io_addr)
	    : "r"(__builtin_bswap32(value))
	    : "memory");
}

void
i_ddi_io_swap_put64(ddi_acc_impl_t *hdlp, uint64_t *addr, uint64_t value)
{
	uint64_t *io_addr =
	    (uint64_t *)((uintptr_t)addr + hdlp->ahi_io_port_base);
	__asm__ volatile("str %1, %0"
	    : "=Q" (*io_addr)
	    : "r"(__builtin_bswap64(value))
	    : "memory");
}

void
i_ddi_io_swap_rep_get16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, const uint_t flags)
{
	uint16_t *io_dev_addr =
	    (uint16_t *)((uintptr_t)dev_addr + hdlp->ahi_io_port_base);
	uint16_t x;
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--) {
			__asm__ volatile("ldrh %w0, %1"
			    : "=r" (x)
			    : "Q" (*(io_dev_addr++))
			    : "memory");
			*host_addr++ = __builtin_bswap16(x);
		}
	else
		while (repcount--) {
			__asm__ volatile("ldrh %w0, %1"
			    : "=r" (x)
			    : "Q" (*(io_dev_addr))
			    : "memory");
			*host_addr++ = __builtin_bswap16(x);
		}
}

void
i_ddi_io_swap_rep_get32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	uint32_t *io_dev_addr =
	    (uint32_t *)((uintptr_t)dev_addr + hdlp->ahi_io_port_base);
	uint32_t x;
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--) {
			__asm__ volatile("ldr %w0, %1"
			    : "=r" (x)
			    : "Q" (*(io_dev_addr++))
			    : "memory");
			*host_addr++ = __builtin_bswap32(x);
		}
	else
		while (repcount--) {
			__asm__ volatile("ldr %w0, %1"
			    : "=r" (x)
			    : "Q" (*(io_dev_addr))
			    : "memory");
			*host_addr++ = __builtin_bswap32(x);
		}
}

void
i_ddi_io_swap_rep_get64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	uint64_t *io_dev_addr =
	    (uint64_t *)((uintptr_t)dev_addr + hdlp->ahi_io_port_base);
	uint64_t x;
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--) {
			__asm__ volatile("ldr %0, %1"
			    : "=r" (x)
			    : "Q" (*(io_dev_addr++))
			    : "memory");
			*host_addr++ = __builtin_bswap64(x);
		}
	else
		while (repcount--) {
			__asm__ volatile("ldr %0, %1"
			    : "=r" (x)
			    : "Q" (*(io_dev_addr))
			    : "memory");
			*host_addr++ = __builtin_bswap64(x);
		}
}

void
i_ddi_io_swap_rep_put16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	uint16_t *io_dev_addr =
	    (uint16_t *)((uintptr_t)dev_addr + hdlp->ahi_io_port_base);
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("strh %w1, %0"
			    : "=Q" (*(io_dev_addr++))
			    : "r"(__builtin_bswap16(*(host_addr++)))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("strh %w1, %0"
			    : "=Q" (*(io_dev_addr))
			    : "r"(__builtin_bswap16(*(host_addr++)))
			    : "memory");
}

void
i_ddi_io_swap_rep_put32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	uint32_t *io_dev_addr =
	    (uint32_t *)((uintptr_t)dev_addr + hdlp->ahi_io_port_base);
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("str %w1, %0"
			    : "=Q" (*(io_dev_addr++))
			    : "r"(__builtin_bswap32(*(host_addr++)))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("str %w1, %0"
			    : "=Q" (*(io_dev_addr))
			    : "r"(__builtin_bswap32(*(host_addr++)))
			    : "memory");
}

void
i_ddi_io_swap_rep_put64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	uint64_t *io_dev_addr =
	    (uint64_t *)((uintptr_t)dev_addr + hdlp->ahi_io_port_base);
	if (flags == DDI_DEV_AUTOINCR)
		while (repcount--)
			__asm__ volatile("str %1, %0"
			    : "=Q" (*(io_dev_addr++))
			    : "r"(__builtin_bswap64(*(host_addr++)))
			    : "memory");
	else
		while (repcount--)
			__asm__ volatile("str %1, %0"
			    : "=Q" (*(io_dev_addr))
			    : "r"(__builtin_bswap64(*(host_addr++)))
			    : "memory");
}

/*
 * The following functions ready a cautious request to go up to the nexus
 * driver.  It is up to the nexus driver to decide how to process the request.
 * It may choose to call i_ddi_do_caut_get/put in this file, or do it
 * differently.
 */

static void
i_ddi_caut_getput_ctlops(ddi_acc_impl_t *hp, uint64_t host_addr,
    uint64_t dev_addr, size_t size, size_t repcount, uint_t flags,
    ddi_ctl_enum_t cmd)
{
	peekpoke_ctlops_t	cautacc_ctlops_arg;

	cautacc_ctlops_arg.size = size;
	cautacc_ctlops_arg.dev_addr = dev_addr;
	cautacc_ctlops_arg.host_addr = host_addr;
	cautacc_ctlops_arg.handle = (ddi_acc_handle_t)hp;
	cautacc_ctlops_arg.repcount = repcount;
	cautacc_ctlops_arg.flags = flags;

	(void) ddi_ctlops(hp->ahi_common.ah_dip, hp->ahi_common.ah_dip, cmd,
	    &cautacc_ctlops_arg, NULL);
}

uint8_t
i_ddi_caut_get8(ddi_acc_impl_t *hp, uint8_t *addr)
{
	uint8_t value;
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)&value, (uintptr_t)addr,
	    sizeof (uint8_t), 1, 0, DDI_CTLOPS_PEEK);

	return (value);
}

uint16_t
i_ddi_caut_get16(ddi_acc_impl_t *hp, uint16_t *addr)
{
	uint16_t value;
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)&value, (uintptr_t)addr,
	    sizeof (uint16_t), 1, 0, DDI_CTLOPS_PEEK);

	return (value);
}

uint32_t
i_ddi_caut_get32(ddi_acc_impl_t *hp, uint32_t *addr)
{
	uint32_t value;
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)&value, (uintptr_t)addr,
	    sizeof (uint32_t), 1, 0, DDI_CTLOPS_PEEK);

	return (value);
}

uint64_t
i_ddi_caut_get64(ddi_acc_impl_t *hp, uint64_t *addr)
{
	uint64_t value;
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)&value, (uintptr_t)addr,
	    sizeof (uint64_t), 1, 0, DDI_CTLOPS_PEEK);

	return (value);
}

void
i_ddi_caut_put8(ddi_acc_impl_t *hp, uint8_t *addr, uint8_t value)
{
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)&value, (uintptr_t)addr,
	    sizeof (uint8_t), 1, 0, DDI_CTLOPS_POKE);
}

void
i_ddi_caut_put16(ddi_acc_impl_t *hp, uint16_t *addr, uint16_t value)
{
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)&value, (uintptr_t)addr,
	    sizeof (uint16_t), 1, 0, DDI_CTLOPS_POKE);
}

void
i_ddi_caut_put32(ddi_acc_impl_t *hp, uint32_t *addr, uint32_t value)
{
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)&value, (uintptr_t)addr,
	    sizeof (uint32_t), 1, 0, DDI_CTLOPS_POKE);
}

void
i_ddi_caut_put64(ddi_acc_impl_t *hp, uint64_t *addr, uint64_t value)
{
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)&value, (uintptr_t)addr,
	    sizeof (uint64_t), 1, 0, DDI_CTLOPS_POKE);
}

void
i_ddi_caut_rep_get8(ddi_acc_impl_t *hp, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount, uint_t flags)
{
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)host_addr, (uintptr_t)dev_addr,
	    sizeof (uint8_t), repcount, flags, DDI_CTLOPS_PEEK);
}

void
i_ddi_caut_rep_get16(ddi_acc_impl_t *hp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)host_addr, (uintptr_t)dev_addr,
	    sizeof (uint16_t), repcount, flags, DDI_CTLOPS_PEEK);
}

void
i_ddi_caut_rep_get32(ddi_acc_impl_t *hp, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)host_addr, (uintptr_t)dev_addr,
	    sizeof (uint32_t), repcount, flags, DDI_CTLOPS_PEEK);
}

void
i_ddi_caut_rep_get64(ddi_acc_impl_t *hp, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)host_addr, (uintptr_t)dev_addr,
	    sizeof (uint64_t), repcount, flags, DDI_CTLOPS_PEEK);
}

void
i_ddi_caut_rep_put8(ddi_acc_impl_t *hp, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount, uint_t flags)
{
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)host_addr, (uintptr_t)dev_addr,
	    sizeof (uint8_t), repcount, flags, DDI_CTLOPS_POKE);
}

void
i_ddi_caut_rep_put16(ddi_acc_impl_t *hp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)host_addr, (uintptr_t)dev_addr,
	    sizeof (uint16_t), repcount, flags, DDI_CTLOPS_POKE);
}

void
i_ddi_caut_rep_put32(ddi_acc_impl_t *hp, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)host_addr, (uintptr_t)dev_addr,
	    sizeof (uint32_t), repcount, flags, DDI_CTLOPS_POKE);
}

void
i_ddi_caut_rep_put64(ddi_acc_impl_t *hp, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)host_addr, (uintptr_t)dev_addr,
	    sizeof (uint64_t), repcount, flags, DDI_CTLOPS_POKE);
}

/*
 * New DDI interrupt framework
 */

/*
 * i_ddi_intr_ops:
 *
 * This is the interrupt operator function wrapper for the bus function
 * bus_intr_op.
 */
int
i_ddi_intr_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t op,
    ddi_intr_handle_impl_t *hdlp, void * result)
{
	dev_info_t	*pdip = (dev_info_t *)DEVI(dip)->devi_parent;
	int		ret = DDI_FAILURE;

	/* request parent to process this interrupt op */
	if (NEXUS_HAS_INTR_OP(pdip))
		ret = (*(DEVI(pdip)->devi_ops->devo_bus_ops->bus_intr_op))(
		    pdip, rdip, op, hdlp, result);
	else
		cmn_err(CE_WARN, "Failed to process interrupt "
		    "for %s%d due to down-rev nexus driver %s%d",
		    ddi_get_name(rdip), ddi_get_instance(rdip),
		    ddi_get_name(pdip), ddi_get_instance(pdip));
	return (ret);
}

/*
 * i_ddi_add_softint - allocate and add a soft interrupt to the system
 */
int
i_ddi_add_softint(ddi_softint_hdl_impl_t *hdlp)
{
	int ret;

	/* add soft interrupt handler */
	ret = add_avsoftintr((void *)hdlp, hdlp->ih_pri, hdlp->ih_cb_func,
	    DEVI(hdlp->ih_dip)->devi_name, hdlp->ih_cb_arg1, hdlp->ih_cb_arg2);
	return (ret ? DDI_SUCCESS : DDI_FAILURE);
}


void
i_ddi_remove_softint(ddi_softint_hdl_impl_t *hdlp)
{
	(void) rem_avsoftintr((void *)hdlp, hdlp->ih_pri, hdlp->ih_cb_func);
}


extern void (*setsoftint)(int, struct av_softinfo *);
extern boolean_t av_check_softint_pending(struct av_softinfo *, boolean_t);

int
i_ddi_trigger_softint(ddi_softint_hdl_impl_t *hdlp, void *arg2)
{
	if (av_check_softint_pending(hdlp->ih_pending, B_FALSE))
		return (DDI_EPENDING);

	update_avsoftintr_args((void *)hdlp, hdlp->ih_pri, arg2);

	(*setsoftint)(hdlp->ih_pri, hdlp->ih_pending);
	return (DDI_SUCCESS);
}

/*
 * i_ddi_set_softint_pri:
 *
 * The way this works is that it first tries to add a softint vector
 * at the new priority in hdlp. If that succeeds; then it removes the
 * existing softint vector at the old priority.
 */
int
i_ddi_set_softint_pri(ddi_softint_hdl_impl_t *hdlp, uint_t old_pri)
{
	int ret;

	/*
	 * If a softint is pending at the old priority then fail the request.
	 */
	if (av_check_softint_pending(hdlp->ih_pending, B_TRUE))
		return (DDI_FAILURE);

	ret = av_softint_movepri((void *)hdlp, old_pri);
	return (ret ? DDI_SUCCESS : DDI_FAILURE);
}

void
i_ddi_alloc_intr_phdl(ddi_intr_handle_impl_t *hdlp)
{
	hdlp->ih_private = (void *)kmem_zalloc(sizeof (ihdl_plat_t), KM_SLEEP);
}

void
i_ddi_free_intr_phdl(ddi_intr_handle_impl_t *hdlp)
{
	kmem_free(hdlp->ih_private, sizeof (ihdl_plat_t));
	hdlp->ih_private = NULL;
}

/*
 * Implementation instance override functions
 *
 * No override on aarch64
 */
uint_t
impl_assign_instance(dev_info_t *dip __unused)
{
	return ((uint_t)-1);
}

int
impl_keep_instance(dev_info_t *dip __unused)
{
	return (DDI_FAILURE);
}

int
impl_free_instance(dev_info_t *dip __unused)
{
	return (DDI_FAILURE);
}

int
impl_check_cpu(dev_info_t *devi __unused)
{
	return (DDI_SUCCESS);
}

/*
 * Allow for implementation specific correction of PROM property values.
 */

void
impl_fix_props(dev_info_t *dip __unused, dev_info_t *ch_dip __unused,
    char *name __unused, int len __unused, caddr_t buffer __unused)
{
	/*
	 * There are no adjustments needed in this implementation.
	 *
	 * If adjustments are needed for one of FDT or ACPI, promote this
	 * function to the one that does not need the changes, remove it here
	 * and imnplement it in the one that does need changes.
	 */
}

uint_t
softlevel1(caddr_t arg1 __unused, caddr_t arg2 __unused)
{
	softint();
	return (1);
}

/*
 * The "status" property indicates the operational status of a device.
 * If this property is present, the value is a string indicating the
 * status of the device as follows:
 *
 *	"okay"		operational.
 *	"disabled"	not operational, but might become operational.
 *	"fail"		not operational because a fault has been detected,
 *			and it is unlikely that the device will become
 *			operational without repair. no additional details
 *			are available.
 *	"fail-xxx"	not operational because a fault has been detected,
 *			and it is unlikely that the device will become
 *			operational without repair. "xxx" is additional
 *			human-readable information about the particular
 *			fault condition that was detected.
 *
 * The absence of this property means that the operational status is
 * unknown or okay.
 *
 * This routine checks the status property of the specified device node
 * and returns 0 if the operational status indicates failure, and 1 otherwise.
 *
 * The property may exist on plug-in cards the existed before IEEE 1275-1994.
 * And, in that case, the property may not even be a string. So we carefully
 * check for the value "fail", in the beginning of the string, noting
 * the property length.
 */
static int
status_okay(int id, char *buf, int buflen)
{
	char status_buf[OBP_MAXPROPNAME];
	char *bufp = buf;
	int len = buflen;
	int proplen;
	static const char *status = "status";
	static const char *fail = "fail";
	int fail_len = (int)strlen(fail);

	/*
	 * Get the proplen ... if it's smaller than "fail",
	 * or doesn't exist ... then we don't care, since
	 * the value can't begin with the char string "fail".
	 *
	 * NB: proplen, if it's a string, includes the NULL in the
	 * the size of the property, and fail_len does not.
	 */
	proplen = prom_getproplen((pnode_t)id, (caddr_t)status);
	if (proplen <= fail_len)	/* nonexistant or uninteresting len */
		return (1);

	/*
	 * if a buffer was provided, use it
	 */
	if ((buf == (char *)NULL) || (buflen <= 0)) {
		bufp = status_buf;
		len = sizeof (status_buf);
	}
	*bufp = (char)0;

	/*
	 * Get the property into the buffer, to the extent of the buffer,
	 * and in case the buffer is smaller than the property size,
	 * NULL terminate the buffer. (This handles the case where
	 * a buffer was passed in and the caller wants to print the
	 * value, but the buffer was too small).
	 */
	(void) prom_bounded_getprop((pnode_t)id, (caddr_t)status,
	    (caddr_t)bufp, len);
	*(bufp + len - 1) = (char)0;

	/*
	 * If the value begins with the char string "fail",
	 * then it means the node is failed. We don't care
	 * about any other values. We assume the node is ok
	 * although it might be 'disabled'.
	 */
	if (strncmp(bufp, fail, fail_len) == 0)
		return (0);

	return (1);
}

static int
getlongprop_buf(int id, char *name, char *buf, int maxlen)
{
	int size;

	size = prom_getproplen((pnode_t)id, name);
	if (size <= 0 || (size > maxlen - 1))
		return (-1);

	if (-1 == prom_getprop((pnode_t)id, name, buf))
		return (-1);

	if (strcmp("name", name) == 0) {
		if (buf[size - 1] != '\0') {
			buf[size] = '\0';
			size += 1;
		}
	}

	return (size);
}

/*
 * Check the status of the device node passed as an argument.
 *
 *	if ((status is OKAY) || (status is DISABLED))
 *		return DDI_SUCCESS
 *	else
 *		print a warning and return DDI_FAILURE
 */
/*ARGSUSED1*/
int
check_status(int id, char *name, dev_info_t *parent)
{
	char status_buf[64];
	char devtype_buf[OBP_MAXPROPNAME];
	int retval = DDI_FAILURE;

	/*
	 * is the status okay?
	 */
	if (status_okay(id, status_buf, sizeof (status_buf)))
		return (DDI_SUCCESS);

	/*
	 * a status property indicating bad memory will be associated
	 * with a node which has a "device_type" property with a value of
	 * "memory-controller". in this situation, return DDI_SUCCESS
	 */
	if (getlongprop_buf(id, OBP_DEVICETYPE, devtype_buf,
	    sizeof (devtype_buf)) > 0) {
		if (strcmp(devtype_buf, "memory-controller") == 0)
			retval = DDI_SUCCESS;
	}

	/*
	 * print the status property information
	 */
	cmn_err(CE_WARN, "status '%s' for '%s'", status_buf, name);
	return (retval);
}

/*
 * Called from the bus_ctl op of sunbus (sbus, obio, etc) nexus drivers
 * to implement the DDI_CTLOPS_INITCHILD operation.  That is, it names
 * the children of sun busses based on the reg spec.
 *
 * Handles the following properties (in make_ddi_ppd):
 *	Property		value
 *	  Name			type
 *	reg		register spec
 *	intr		old-form interrupt spec
 *	interrupts	new (bus-oriented) interrupt spec
 *	ranges		range spec
 */
int
impl_ddi_sunbus_initchild(dev_info_t *child)
{
	char name[MAXNAMELEN];
	void impl_ddi_sunbus_removechild(dev_info_t *);
	extern int impl_sunbus_name_child(
	    dev_info_t *child, char *name, int namelen);

	/*
	 * Name the child, also makes parent private data if appropriate for
	 * the implementation.
	 */
	(void) impl_sunbus_name_child(child, name, MAXNAMELEN);
	ddi_set_name_addr(child, name);

	/*
	 * Attempt to merge a .conf node; if successful, remove the
	 * .conf node.
	 */
	if ((ndi_dev_is_persistent_node(child) == 0) &&
	    (ndi_merge_node(child, impl_sunbus_name_child) == DDI_SUCCESS)) {
		/*
		 * Return failure to remove node
		 */
		impl_ddi_sunbus_removechild(child);
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

void
impl_free_ddi_ppd(dev_info_t *dip)
{
	struct ddi_parent_private_data *pdptr;
	size_t n;

	if ((pdptr = ddi_get_parent_data(dip)) == NULL)
		return;

	if ((n = (size_t)pdptr->par_nintr) != 0)
		/*
		 * Note that kmem_free is used here (instead of
		 * ddi_prop_free) because the contents of the
		 * property were placed into a separate buffer and
		 * mucked with a bit before being stored in par_intr.
		 * The actual return value from the prop lookup
		 * was freed with ddi_prop_free previously.
		 */
		kmem_free(pdptr->par_intr, n * sizeof (struct intrspec));

	if ((n = (size_t)pdptr->par_nrng) != 0)
		ddi_prop_free((void *)pdptr->par_rng);

	if ((n = pdptr->par_nreg) != 0)
		ddi_prop_free((void *)pdptr->par_reg);

	kmem_free(pdptr, sizeof (*pdptr));
	ddi_set_parent_data(dip, NULL);
}

void
impl_ddi_sunbus_removechild(dev_info_t *dip)
{
	impl_free_ddi_ppd(dip);
	ddi_set_name_addr(dip, NULL);
	/*
	 * Strip the node to properly convert it back to prototype form
	 */
	impl_rem_dev_props(dip);
}

/*
 * DDI Memory/DMA
 */

/*
 * Support for allocating DMAable memory to implement
 * ddi_dma_mem_alloc(9F) interface.
 */

#define	KA_ALIGN_SHIFT	7
#define	KA_ALIGN	(1 << KA_ALIGN_SHIFT)
#define	KA_NCACHE	(PAGESHIFT + 1 - KA_ALIGN_SHIFT)

/*
 * Dummy DMA attribute template for kmem_io[].kmem_io_attr.  We only
 * care about addr_lo, addr_hi, and align.  addr_hi will be dynamically set.
 */

static ddi_dma_attr_t kmem_io_attr = {
	DMA_ATTR_V0,
	0x0000000000000000ULL,		/* dma_attr_addr_lo */
	0x0000000000000000ULL,		/* dma_attr_addr_hi */
	0x00ffffff,
	0x1000,				/* dma_attr_align */
	1, 1, 0xffffffffULL, 0xffffffffULL, 0x1, 1, 0
};

/* kmem io memory ranges and indices */
enum {
	IO_4P, IO_64G, IO_4G, IO_2G, IO_1G, IO_512M,
	IO_256M, IO_128M, IO_64M, IO_32M, IO_16M, MAX_MEM_RANGES
};

static struct {
	vmem_t		*kmem_io_arena;
	kmem_cache_t	*kmem_io_cache[KA_NCACHE];
	ddi_dma_attr_t	kmem_io_attr;
} kmem_io[MAX_MEM_RANGES];

static int kmem_io_idx;		/* index of first populated kmem_io[] */

static page_t *
page_create_io_wrapper(void *addr, size_t len, int vmflag, void *arg)
{
	extern page_t *page_create_io(vnode_t *, u_offset_t, uint_t,
	    uint_t, struct as *, caddr_t, ddi_dma_attr_t *);

	return (page_create_io(&kvp, (u_offset_t)(uintptr_t)addr, len,
	    PG_EXCL | ((vmflag & VM_NOSLEEP) ? 0 : PG_WAIT), &kas, addr, arg));
}

static void *
segkmem_alloc_io_4P(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_xalloc(vmp, NULL, size, vmflag, 0,
	    page_create_io_wrapper, &kmem_io[IO_4P].kmem_io_attr));
}

static void *
segkmem_alloc_io_64G(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_xalloc(vmp, NULL, size, vmflag, 0,
	    page_create_io_wrapper, &kmem_io[IO_64G].kmem_io_attr));
}

static void *
segkmem_alloc_io_4G(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_xalloc(vmp, NULL, size, vmflag, 0,
	    page_create_io_wrapper, &kmem_io[IO_4G].kmem_io_attr));
}

static void *
segkmem_alloc_io_2G(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_xalloc(vmp, NULL, size, vmflag, 0,
	    page_create_io_wrapper, &kmem_io[IO_2G].kmem_io_attr));
}

static void *
segkmem_alloc_io_1G(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_xalloc(vmp, NULL, size, vmflag, 0,
	    page_create_io_wrapper, &kmem_io[IO_1G].kmem_io_attr));
}

static void *
segkmem_alloc_io_512M(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_xalloc(vmp, NULL, size, vmflag, 0,
	    page_create_io_wrapper, &kmem_io[IO_512M].kmem_io_attr));
}

static void *
segkmem_alloc_io_256M(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_xalloc(vmp, NULL, size, vmflag, 0,
	    page_create_io_wrapper, &kmem_io[IO_256M].kmem_io_attr));
}

static void *
segkmem_alloc_io_128M(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_xalloc(vmp, NULL, size, vmflag, 0,
	    page_create_io_wrapper, &kmem_io[IO_128M].kmem_io_attr));
}

static void *
segkmem_alloc_io_64M(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_xalloc(vmp, NULL, size, vmflag, 0,
	    page_create_io_wrapper, &kmem_io[IO_64M].kmem_io_attr));
}

static void *
segkmem_alloc_io_32M(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_xalloc(vmp, NULL, size, vmflag, 0,
	    page_create_io_wrapper, &kmem_io[IO_32M].kmem_io_attr));
}

static void *
segkmem_alloc_io_16M(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_xalloc(vmp, NULL, size, vmflag, 0,
	    page_create_io_wrapper, &kmem_io[IO_16M].kmem_io_attr));
}

struct {
	uint64_t	io_limit;
	char		*io_name;
	void		*(*io_alloc)(vmem_t *, size_t, int);
	int		io_initial;	/* kmem_io_init during startup */
} io_arena_params[MAX_MEM_RANGES] = {
	{0x000fffffffffffffULL,	"kmem_io_4P",	segkmem_alloc_io_4P,	1},
	{0x0000000fffffffffULL,	"kmem_io_64G",	segkmem_alloc_io_64G,	0},
	{0x00000000ffffffffULL,	"kmem_io_4G",	segkmem_alloc_io_4G,	1},
	{0x000000007fffffffULL,	"kmem_io_2G",	segkmem_alloc_io_2G,	1},
	{0x000000003fffffffULL,	"kmem_io_1G",	segkmem_alloc_io_1G,	0},
	{0x000000001fffffffULL,	"kmem_io_512M",	segkmem_alloc_io_512M,	0},
	{0x000000000fffffffULL,	"kmem_io_256M",	segkmem_alloc_io_256M,	0},
	{0x0000000007ffffffULL,	"kmem_io_128M",	segkmem_alloc_io_128M,	0},
	{0x0000000003ffffffULL,	"kmem_io_64M",	segkmem_alloc_io_64M,	0},
	{0x0000000001ffffffULL,	"kmem_io_32M",	segkmem_alloc_io_32M,	0},
	{0x0000000000ffffffULL,	"kmem_io_16M",	segkmem_alloc_io_16M,	1}
};

void
kmem_io_init(int a)
{
	int	c;
	char name[40];

	kmem_io[a].kmem_io_arena = vmem_create(io_arena_params[a].io_name,
	    NULL, 0, PAGESIZE, io_arena_params[a].io_alloc,
	    segkmem_free,
	    heap_arena, 0, VM_SLEEP);

	for (c = 0; c < KA_NCACHE; c++) {
		size_t size = KA_ALIGN << c;
		(void) sprintf(name, "%s_%lu",
		    io_arena_params[a].io_name, size);
		kmem_io[a].kmem_io_cache[c] = kmem_cache_create(name,
		    size, size, NULL, NULL, NULL, NULL,
		    kmem_io[a].kmem_io_arena, 0);
	}
}

/*
 * Return the index of the highest memory range for addr.
 */
static int
kmem_io_index(uint64_t addr)
{
	int n;

	for (n = kmem_io_idx; n < MAX_MEM_RANGES; n++) {
		if (kmem_io[n].kmem_io_attr.dma_attr_addr_hi <= addr) {
			if (kmem_io[n].kmem_io_arena == NULL)
				kmem_io_init(n);
			return (n);
		}
	}
	panic("kmem_io_index: invalid addr - must be at least 16m");

	/*NOTREACHED*/
}

/*
 * Return the index of the next kmem_io populated memory range
 * after curindex.
 */
static int
kmem_io_index_next(int curindex)
{
	int n;

	for (n = curindex + 1; n < MAX_MEM_RANGES; n++) {
		if (kmem_io[n].kmem_io_arena)
			return (n);
	}
	return (-1);
}

/*
 * allow kmem to be mapped in with different PTE cache attribute settings.
 * Used by i_ddi_mem_alloc()
 */
int
kmem_override_cache_attrs(caddr_t kva, size_t size, uint_t order)
{
	uint_t hat_flags;
	caddr_t kva_end;
	uint_t hat_attr;
	pfn_t pfn;

	if (hat_getattr(kas.a_hat, kva, &hat_attr) == -1) {
		return (-1);
	}

	hat_attr &= ~HAT_ORDER_MASK;
	hat_attr |= order | HAT_NOSYNC;
	hat_flags = HAT_LOAD_LOCK;

	kva_end = (caddr_t)(((uintptr_t)kva + size + PAGEOFFSET) &
	    (uintptr_t)PAGEMASK);
	kva = (caddr_t)((uintptr_t)kva & (uintptr_t)PAGEMASK);

	while (kva < kva_end) {
		pfn = hat_getpfnum(kas.a_hat, kva);
		hat_unload(kas.a_hat, kva, PAGESIZE, HAT_UNLOAD_UNLOCK);
		hat_devload(kas.a_hat, kva, PAGESIZE, pfn, hat_attr, hat_flags);
		kva += MMU_PAGESIZE;
	}

	return (0);
}

static int
ctgcompare(const void *a1, const void *a2)
{
	/* we just want to compare virtual addresses */
	a1 = ((struct ctgas *)a1)->ctg_addr;
	a2 = ((struct ctgas *)a2)->ctg_addr;
	return (a1 == a2 ? 0 : (a1 < a2 ? -1 : 1));
}

void
ka_init(void)
{
	int a;
	paddr_t maxphysaddr;
	extern pfn_t physmax;

	maxphysaddr = mmu_ptob((paddr_t)physmax) + MMU_PAGEOFFSET;

	ASSERT(maxphysaddr <= io_arena_params[0].io_limit);

	for (a = 0; a < MAX_MEM_RANGES; a++) {
		if (maxphysaddr >= io_arena_params[a + 1].io_limit) {
			if (maxphysaddr > io_arena_params[a + 1].io_limit)
				io_arena_params[a].io_limit = maxphysaddr;
			else
				a++;
			break;
		}
	}
	kmem_io_idx = a;

	for (; a < MAX_MEM_RANGES; a++) {
		kmem_io[a].kmem_io_attr = kmem_io_attr;
		kmem_io[a].kmem_io_attr.dma_attr_addr_hi =
		    io_arena_params[a].io_limit;
		/*
		 * initialize kmem_io[] arena/cache corresponding to
		 * maxphysaddr and to the "common" io memory ranges that
		 * have io_initial set to a non-zero value.
		 */
		if (io_arena_params[a].io_initial || a == kmem_io_idx)
			kmem_io_init(a);
	}

	/* initialize ctgtree */
	avl_create(&ctgtree, ctgcompare, sizeof (struct ctgas),
	    offsetof(struct ctgas, ctg_link));
}

/*
 * put contig address/size
 */
static void *
putctgas(void *addr, size_t size)
{
	struct ctgas    *ctgp;
	if ((ctgp = kmem_zalloc(sizeof (*ctgp), KM_NOSLEEP)) != NULL) {
		ctgp->ctg_addr = addr;
		ctgp->ctg_size = size;
		CTGLOCK();
		avl_add(&ctgtree, ctgp);
		CTGUNLOCK();
	}
	return (ctgp);
}

/*
 * get contig size by addr
 */
static size_t
getctgsz(void *addr)
{
	struct ctgas    *ctgp;
	struct ctgas    find;
	size_t		sz = 0;

	find.ctg_addr = addr;
	CTGLOCK();
	if ((ctgp = avl_find(&ctgtree, &find, NULL)) != NULL) {
		avl_remove(&ctgtree, ctgp);
	}
	CTGUNLOCK();

	if (ctgp != NULL) {
		sz = ctgp->ctg_size;
		kmem_free(ctgp, sizeof (*ctgp));
	}

	return (sz);
}

/*
 * contig_alloc:
 *
 *	allocates contiguous memory to satisfy the 'size' and dma attributes
 *	specified in 'attr'.
 *
 *	Not all of memory need to be physically contiguous if the
 *	scatter-gather list length is greater than 1.
 */

/*ARGSUSED*/
void *
contig_alloc(size_t size, ddi_dma_attr_t *attr, uintptr_t align, int cansleep)
{
	pgcnt_t		pgcnt = btopr(size);
	size_t		asize = pgcnt * PAGESIZE;
	page_t		*ppl;
	int		pflag;
	void		*addr;

	extern page_t *page_create_io(vnode_t *, u_offset_t, uint_t,
	    uint_t, struct as *, caddr_t, ddi_dma_attr_t *);

	/* segkmem_xalloc */

	if (align <= PAGESIZE)
		addr = vmem_alloc(heap_arena, asize,
		    (cansleep) ? VM_SLEEP : VM_NOSLEEP);
	else
		addr = vmem_xalloc(heap_arena, asize, align, 0, 0, NULL, NULL,
		    (cansleep) ? VM_SLEEP : VM_NOSLEEP);
	if (addr) {
		ASSERT(!((uintptr_t)addr & (align - 1)));

		if (page_resv(pgcnt, (cansleep) ? KM_SLEEP : KM_NOSLEEP) == 0) {
			vmem_free(heap_arena, addr, asize);
			return (NULL);
		}
		pflag = PG_EXCL;

		if (cansleep)
			pflag |= PG_WAIT;

		/* 4k req gets from freelists rather than pfn search */
		if (pgcnt > 1 || align > PAGESIZE)
			pflag |= PG_PHYSCONTIG;

		ppl = page_create_io(&kvp, (u_offset_t)(uintptr_t)addr,
		    asize, pflag, &kas, (caddr_t)addr, attr);

		if (!ppl) {
			vmem_free(heap_arena, addr, asize);
			page_unresv(pgcnt);
			return (NULL);
		}

		while (ppl != NULL) {
			page_t	*pp = ppl;
			page_sub(&ppl, pp);
			ASSERT(page_iolock_assert(pp));
			page_io_unlock(pp);
			page_downgrade(pp);
			hat_memload(kas.a_hat, (caddr_t)(uintptr_t)pp->p_offset,
			    pp, (PROT_ALL & ~PROT_USER) |
			    HAT_NOSYNC, HAT_LOAD_LOCK);
		}
	}
	return (addr);
}

void
contig_free(void *addr, size_t size)
{
	pgcnt_t	pgcnt = btopr(size);
	size_t	asize = pgcnt * PAGESIZE;
	caddr_t	a, ea;
	page_t	*pp;

	hat_unload(kas.a_hat, addr, asize, HAT_UNLOAD_UNLOCK);

	for (a = addr, ea = a + asize; a < ea; a += PAGESIZE) {
		pp = page_find(&kvp, (u_offset_t)(uintptr_t)a);
		if (!pp)
			panic("contig_free: contig pp not found");

		if (!page_tryupgrade(pp)) {
			page_unlock(pp);
			pp = page_lookup(&kvp,
			    (u_offset_t)(uintptr_t)a, SE_EXCL);
			if (pp == NULL)
				panic("contig_free: page freed");
		}
		page_destroy(pp, 0);
	}

	page_unresv(pgcnt);
	vmem_free(heap_arena, addr, asize);
}

/*
 * Allocate from the system, aligned on a specific boundary.
 * The alignment, if non-zero, must be a power of 2.
 */
static void *
kalloca(size_t size, size_t align, int cansleep, int physcontig,
    ddi_dma_attr_t *attr)
{
	size_t *addr, *raddr, rsize;
	size_t hdrsize = 4 * sizeof (size_t);	/* must be power of 2 */
	int a, i, c;
	vmem_t *vmp = NULL;
	kmem_cache_t *cp = NULL;

	if (attr->dma_attr_addr_lo > mmu_ptob((uint64_t)ddiphysmin)) /* XXXARM: this is not in the FDT impl */
		return (NULL);

	align = MAX(align, hdrsize);
	ASSERT((align & (align - 1)) == 0);

	/*
	 * All of our allocators guarantee 16-byte alignment, so we don't
	 * need to reserve additional space for the header.
	 * To simplify picking the correct kmem_io_cache, we round up to
	 * a multiple of KA_ALIGN.
	 */
	rsize = P2ROUNDUP_TYPED(size + align, KA_ALIGN, size_t);

	if (physcontig && rsize > PAGESIZE) {
		if ((addr = contig_alloc(size, attr, align, cansleep)) !=
		    NULL) {
			if (!putctgas(addr, size))
				contig_free(addr, size);
			else
				return (addr);
		}
		return (NULL);
	}

	a = kmem_io_index(attr->dma_attr_addr_hi);

	if (rsize > PAGESIZE) {
		vmp = kmem_io[a].kmem_io_arena;
		raddr = vmem_alloc(vmp, rsize,
		    (cansleep) ? VM_SLEEP : VM_NOSLEEP);
	} else {
		c = highbit((rsize >> KA_ALIGN_SHIFT) - 1);
		cp = kmem_io[a].kmem_io_cache[c];
		raddr = kmem_cache_alloc(cp, (cansleep) ? KM_SLEEP :
		    KM_NOSLEEP);
	}

	if (raddr == NULL) {
		int	na;

		ASSERT(cansleep == 0);
		if (rsize > PAGESIZE)
			return (NULL);
		/*
		 * System does not have memory in the requested range.
		 * Try smaller kmem io ranges and larger cache sizes
		 * to see if there might be memory available in
		 * these other caches.
		 */

		for (na = kmem_io_index_next(a); na >= 0;
		    na = kmem_io_index_next(na)) {
			ASSERT(kmem_io[na].kmem_io_arena);
			cp = kmem_io[na].kmem_io_cache[c];
			raddr = kmem_cache_alloc(cp, KM_NOSLEEP);
			if (raddr)
				goto kallocdone;
		}
		/* now try the larger kmem io cache sizes */
		for (na = a; na >= 0; na = kmem_io_index_next(na)) {
			for (i = c + 1; i < KA_NCACHE; i++) {
				cp = kmem_io[na].kmem_io_cache[i];
				raddr = kmem_cache_alloc(cp, KM_NOSLEEP);
				if (raddr)
					goto kallocdone;
			}
		}
		return (NULL);
	}

kallocdone:
	ASSERT(!P2BOUNDARY((uintptr_t)raddr, rsize, PAGESIZE) ||
	    rsize > PAGESIZE);

	addr = (size_t *)P2ROUNDUP((uintptr_t)raddr + hdrsize, align);
	ASSERT((uintptr_t)addr + size - (uintptr_t)raddr <= rsize);

	addr[-4] = (size_t)cp;
	addr[-3] = (size_t)vmp;
	addr[-2] = (size_t)raddr;
	addr[-1] = rsize;

	return (addr);
}

static void
kfreea(void *addr)
{
	size_t		size;

	if (!((uintptr_t)addr & PAGEOFFSET) && (size = getctgsz(addr))) {
		contig_free(addr, size);
	} else {
		size_t	*saddr = addr;
		if (saddr[-4] == 0)
			vmem_free((vmem_t *)saddr[-3], (void *)saddr[-2],
			    saddr[-1]);
		else
			kmem_cache_free((kmem_cache_t *)saddr[-4],
			    (void *)saddr[-2]);
	}
}

void
i_ddi_devacc_to_hatacc(const ddi_device_acc_attr_t *devaccp, uint_t *hataccp)
{
}

/*
 * Check if the specified cache attribute is supported on the platform.
 * This function must be called before i_ddi_cacheattr_to_hatacc().
 */
boolean_t
i_ddi_check_cache_attr(uint_t flags)
{
	/*
	 * The cache attributes are mutually exclusive. Any combination of
	 * the attributes leads to a failure.
	 */
	uint_t cache_attr = IOMEM_CACHE_ATTR(flags);
	if ((cache_attr != 0) && !ISP2(cache_attr))
		return (B_FALSE);

	/* All cache attributes are supported on X86/X64 */
	if (cache_attr & (IOMEM_DATA_UNCACHED | IOMEM_DATA_CACHED |
	    IOMEM_DATA_UC_WR_COMBINE))
		return (B_TRUE);

	/* undefined attributes */
	return (B_FALSE);
}

/*
 * XXXARM: this is from the Arm port, and subtly different to i86pc
 */
/* set HAT cache attributes from the cache attributes */
void
i_ddi_cacheattr_to_hatacc(uint_t flags, uint_t *hataccp)
{
	uint_t cache_attr = IOMEM_CACHE_ATTR(flags);
	static char *fname = "i_ddi_cacheattr_to_hatacc";

	/*
	 * set HAT attrs according to the cache attrs.
	 */
	switch (cache_attr) {
	case IOMEM_DATA_UNCACHED:
		*hataccp &= ~HAT_ORDER_MASK;
		*hataccp |= (HAT_STRICTORDER | HAT_PLAT_NOCACHE);
		break;
	case IOMEM_DATA_UC_WR_COMBINE:
		*hataccp &= ~HAT_ORDER_MASK;
		*hataccp |= (HAT_MERGING_OK | HAT_PLAT_NOCACHE);
		break;
	case IOMEM_DATA_CACHED:
		*hataccp &= ~HAT_ORDER_MASK;
		*hataccp |= (HAT_STORECACHING_OK | HAT_PLAT_NOCACHE);
		break;
	/*
	 * This case must not occur because the cache attribute is scrutinized
	 * before this function is called.
	 */
	default:
		/*
		 * set cacheable to hat attrs.
		 */
		*hataccp &= ~HAT_ORDER_MASK;
		*hataccp |= HAT_STORECACHING_OK;
		cmn_err(CE_WARN, "%s: cache_attr=0x%x is ignored.",
		    fname, cache_attr);
	}
}

/*
 * This should actually be called i_ddi_dma_mem_alloc. There should
 * also be an i_ddi_pio_mem_alloc. i_ddi_dma_mem_alloc should call
 * through the device tree with the DDI_CTLOPS_DMA_ALIGN ctl ops to
 * get alignment requirements for DMA memory. i_ddi_pio_mem_alloc
 * should use DDI_CTLOPS_PIO_ALIGN. Since we only have i_ddi_mem_alloc
 * so far which is used for both, DMA and PIO, we have to use the DMA
 * ctl ops to make everybody happy.
 */
/*ARGSUSED*/
int
i_ddi_mem_alloc(dev_info_t *dip, ddi_dma_attr_t *oattr,
    size_t length, int cansleep, int flags,
    const ddi_device_acc_attr_t *accattrp, caddr_t *kaddrp,
    size_t *real_length, ddi_acc_hdl_t *ap)
{
	caddr_t a;
	int iomin;
	ddi_acc_impl_t *iap;
	int physcontig = 0;
	pgcnt_t npages;
	pgcnt_t minctg;
	uint_t order;
	int e;

	extern int i_ddi_convert_dma_attr(ddi_dma_attr_t *dst, dev_info_t *dip,
	    const ddi_dma_attr_t *src);

	/*
	 * Check legality of arguments
	 */
	if (length == 0 || kaddrp == NULL || oattr == NULL) {
		return (DDI_FAILURE);
	}

	ddi_dma_attr_t data;
	ddi_dma_attr_t *attr = &data;
	if (i_ddi_convert_dma_attr(attr, dip, oattr) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	if (attr->dma_attr_minxfer == 0 || attr->dma_attr_align == 0 ||
	    !ISP2(attr->dma_attr_align) || !ISP2(attr->dma_attr_minxfer)) {
		return (DDI_FAILURE);
	}

	/*
	 * figure out most restrictive alignment requirement
	 */
	iomin = attr->dma_attr_minxfer;
	iomin = maxbit(iomin, attr->dma_attr_align);
	if (iomin == 0)
		return (DDI_FAILURE);

	ASSERT((iomin & (iomin - 1)) == 0);

	/*
	 * if we allocate memory with IOMEM_DATA_UNCACHED or
	 * IOMEM_DATA_UC_WR_COMBINE, make sure we allocate a page aligned
	 * memory that ends on a page boundry.
	 * Don't want to have to different cache mappings to the same
	 * physical page.
	 */
	if (OVERRIDE_CACHE_ATTR(flags)) {
		iomin = (iomin + MMU_PAGEOFFSET) & MMU_PAGEMASK;
		length = (length + MMU_PAGEOFFSET) & (size_t)MMU_PAGEMASK;
	}

	/*
	 * Determine if we need to satisfy the request for physically
	 * contiguous memory or alignments larger than pagesize.
	 */
	npages = btopr(length + attr->dma_attr_align);
	minctg = howmany(npages, attr->dma_attr_sgllen);

	if (minctg > 1) {
		uint64_t pfnseg = attr->dma_attr_seg >> PAGESHIFT;
		/*
		 * verify that the minimum contig requirement for the
		 * actual length does not cross segment boundary.
		 */
		length = P2ROUNDUP_TYPED(length, attr->dma_attr_minxfer,
		    size_t);
		npages = btopr(length);
		minctg = howmany(npages, attr->dma_attr_sgllen);
		if (minctg > pfnseg + 1)
			return (DDI_FAILURE);
		physcontig = 1;
	} else {
		length = P2ROUNDUP_TYPED(length, iomin, size_t);
	}

	/*
	 * Allocate the requested amount from the system.
	 */
	a = kalloca(length, iomin, cansleep, physcontig, attr);

	if ((*kaddrp = a) == NULL)
		return (DDI_FAILURE);

	/*
	 * if we to modify the cache attributes, go back and muck with the
	 * mappings.
	 */
	if (OVERRIDE_CACHE_ATTR(flags)) {
		order = 0;
		i_ddi_cacheattr_to_hatacc(flags, &order);
		e = kmem_override_cache_attrs(a, length, order);
		if (e != 0) {
			kfreea(a);
			return (DDI_FAILURE);
		}
	}

	if (real_length) {
		*real_length = length;
	}
	if (ap) {
		/*
		 * initialize access handle
		 */
		iap = (ddi_acc_impl_t *)ap->ah_platform_private;
		iap->ahi_acc_attr |= DDI_ACCATTR_CPU_VADDR;
		impl_acc_hdl_init(ap);
	}

	return (DDI_SUCCESS);
}

/* ARGSUSED */
void
i_ddi_mem_free(caddr_t kaddr, ddi_acc_hdl_t *ap)
{
	if (ap != NULL) {
		/*
		 * if we modified the cache attributes on alloc, go back and
		 * fix them since this memory could be returned to the
		 * general pool.
		 */
		if (OVERRIDE_CACHE_ATTR(ap->ah_xfermodes)) {
			uint_t order = 0;
			int e;
			i_ddi_cacheattr_to_hatacc(IOMEM_DATA_CACHED, &order);
			e = kmem_override_cache_attrs(kaddr, ap->ah_len, order);
			if (e != 0) {
				cmn_err(CE_WARN, "i_ddi_mem_free() failed to "
				    "override cache attrs, memory leaked\n");
				return;
			}
		}
	}
	kfreea(kaddr);
}

/*
 * Access Barriers
 *
 */
/*ARGSUSED*/
int
i_ddi_ontrap(ddi_acc_handle_t hp)
{
	return (DDI_FAILURE);
}

/*ARGSUSED*/
void
i_ddi_notrap(ddi_acc_handle_t hp)
{
}

/*
 * Copy console font to kernel memory. The temporary font setup
 * to use font module was done in early console setup, using low
 * memory and data from font module. Now we need to allocate
 * kernel memory and copy data over, so the low memory can be freed.
 * We can have at most one entry in font list from early boot.
 */
static void
get_console_font(void)
{
#if 0
	struct fontlist *fp, *fl;
	bitmap_data_t *bd;
	struct font *fd, *tmp;
	int i;

	if (STAILQ_EMPTY(&fonts))
		return;

	fl = STAILQ_FIRST(&fonts);
	STAILQ_REMOVE_HEAD(&fonts, font_next);
	fp = kmem_zalloc(sizeof (*fp), KM_SLEEP);
	bd = kmem_zalloc(sizeof (*bd), KM_SLEEP);
	fd = kmem_zalloc(sizeof (*fd), KM_SLEEP);

	fp->font_name = NULL;
	fp->font_flags = FONT_BOOT;
	fp->font_data = bd;

	bd->width = fl->font_data->width;
	bd->height = fl->font_data->height;
	bd->uncompressed_size = fl->font_data->uncompressed_size;
	bd->font = fd;

	tmp = fl->font_data->font;
	fd->vf_width = tmp->vf_width;
	fd->vf_height = tmp->vf_height;
	for (i = 0; i < VFNT_MAPS; i++) {
		if (tmp->vf_map_count[i] == 0)
			continue;
		fd->vf_map_count[i] = tmp->vf_map_count[i];
		fd->vf_map[i] = kmem_alloc(fd->vf_map_count[i] *
		    sizeof (*fd->vf_map[i]), KM_SLEEP);
		bcopy(tmp->vf_map[i], fd->vf_map[i], fd->vf_map_count[i] *
		    sizeof (*fd->vf_map[i]));
	}
	fd->vf_bytes = kmem_alloc(bd->uncompressed_size, KM_SLEEP);
	bcopy(tmp->vf_bytes, fd->vf_bytes, bd->uncompressed_size);
	STAILQ_INSERT_HEAD(&fonts, fp, font_next);
#endif
}

static void
check_driver_disable(void)
{
	int proplen = 128;
	char *prop_name;
	char *drv_name, *propval;
	major_t major;

	prop_name = kmem_alloc(proplen, KM_SLEEP);
	for (major = 0; major < devcnt; major++) {
		drv_name = ddi_major_to_name(major);
		if (drv_name == NULL)
			continue;
		(void) snprintf(prop_name, proplen, "disable-%s", drv_name);
		if (ddi_prop_lookup_string(DDI_DEV_T_ANY, ddi_root_node(),
		    DDI_PROP_DONTPASS, prop_name, &propval) == DDI_SUCCESS) {
			if (strcmp(propval, "true") == 0) {
				devnamesp[major].dn_flags |= DN_DRIVER_REMOVED;
				cmn_err(CE_NOTE, "driver %s disabled",
				    drv_name);
			}
			ddi_prop_free(propval);
		}
	}
	kmem_free(prop_name, proplen);
}

static struct bus_probe {
	struct bus_probe *next;
	void (*probe)(int);
} *bus_probes;

void
impl_bus_add_probe(void (*func)(int))
{
	struct bus_probe *probe;
	struct bus_probe *lastprobe = NULL;

	probe = kmem_alloc(sizeof (*probe), KM_SLEEP);
	probe->probe = func;
	probe->next = NULL;

	if (!bus_probes) {
		bus_probes = probe;
		return;
	}

	lastprobe = bus_probes;
	while (lastprobe->next)
		lastprobe = lastprobe->next;
	lastprobe->next = probe;
}

/*ARGSUSED*/
void
impl_bus_delete_probe(void (*func)(int))
{
	struct bus_probe *prev = NULL;
	struct bus_probe *probe = bus_probes;

	while (probe) {
		if (probe->probe == func)
			break;
		prev = probe;
		probe = probe->next;
	}

	if (probe == NULL)
		return;

	if (prev)
		prev->next = probe->next;
	else
		bus_probes = probe->next;

	kmem_free(probe, sizeof (struct bus_probe));
}

#if defined(IMPL_DDI_DUMP_DEVTREE_INITIAL) || \
    defined(IMPL_DDI_DUMP_DEVTREE_REPROBE)
static void
impl_bus_dump_node_prefix(unsigned int lvl)
{
	unsigned int n;

	for (n = 0; n < lvl; ++n) {
		prom_printf("  ");
	}
}

static void
impl_bus_dump_node_info(dev_info_t *dip, unsigned int lvl)
{
	uint_t nelements;
	char **data;
	impl_bus_dump_node_prefix(lvl);
	prom_printf(
	    "name/instance=%s%d, binding_name=%s, driver_name=%s\n",
	    ddi_node_name(dip), ddi_get_instance(dip),
	    ddi_binding_name(dip), ddi_driver_name(dip));
	impl_bus_dump_node_prefix(lvl);
	if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "compatible", &data, &nelements) == DDI_PROP_SUCCESS) {
		uint_t n;
		prom_printf(" -> compatible: ");
		for (n = 0; n < nelements; ++n) {
			prom_printf(data[n]);
			if (n != nelements - 1)
				prom_printf(", ");
		}
		prom_printf("\n");
		ddi_prop_free(data);
	} else {
		prom_printf(" -> no compatible\n");
	}

	impl_bus_dump_node_prefix(lvl);
	if (ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "acpi-namespace") == 1) {
		char *propval;
		if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "acpi-namespace", &propval) ==
		    DDI_SUCCESS) {
			prom_printf(" -> acpi-namespace property: '%s'\n",
			    propval);
			ddi_prop_free(propval);
		} else {
			prom_printf(" -> acpi-namespace property exists\n");
		}
	} else {
		prom_printf(" -> registers property absent\n");
	}

	impl_bus_dump_node_prefix(lvl);
	if (ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS, "reg") == 1)
		prom_printf(" -> registers property exists\n");
	else
		prom_printf(" -> registers property absent\n");

	impl_bus_dump_node_prefix(lvl);
	if (ddi_prop_exists(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "assigned-addresses") == 1)
		prom_printf(" -> assigned-addresses property exists\n");
	else
		prom_printf(" -> assigned-addresses property absent\n");

	impl_bus_dump_node_prefix(lvl);
	if (ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "interrupts") == 1) {
		int *irupts;
		uint_t nirupts;
		uint_t j;
		prom_printf(" -> interrupts property exists");
		if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "interrupts", &irupts, &nirupts)
		    == DDI_PROP_SUCCESS) {
			prom_printf(" with %u elements\n", nirupts);
			impl_bus_dump_node_prefix(lvl);
			prom_printf("      ");
			for (j = 0; j < nirupts; ++j) {
				prom_printf("%d", irupts[j]);
				if (j < (nirupts - 1))
					prom_printf(", ");
			}
			prom_printf("\n");
			ddi_prop_free(irupts);
		} else {
			prom_printf("\n      <error fetching interrupts>\n");
		}
	} else {
		prom_printf(" -> interrupts property absent\n");
	}

	impl_bus_dump_node_prefix(lvl);
	if (ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "dma-channels") == 1)
		prom_printf(" -> dma-channels property exists\n");
	else
		prom_printf(" -> dma-channels property absent\n");

	impl_bus_dump_node_prefix(lvl);
	if (ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "ranges") == 1)
		prom_printf(" -> ranges property exists\n");
	else
		prom_printf(" -> ranges property absent\n");

	impl_bus_dump_node_prefix(lvl);
	if (ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "bus-range") == 1)
		prom_printf(" -> bus-range property exists\n");
	else
		prom_printf(" -> bus-range property absent\n");

	impl_bus_dump_node_prefix(lvl);
	prom_printf(" -> flags:\n");
	if (!DEVI_IS_DEVICE_DOWN(dip) && !DEVI_IS_DEVICE_DEGRADED(dip) &&
	    !DEVI_IS_DEVICE_OFFLINE(dip)) {
		impl_bus_dump_node_prefix(lvl);
		prom_printf("    * is online\n");
	}
	if (DEVI_IS_DEVICE_OFFLINE(dip)) {
		impl_bus_dump_node_prefix(lvl);
		prom_printf("    * is offline\n");
	}
	if (DEVI_IS_DEVICE_DOWN(dip)) {
		impl_bus_dump_node_prefix(lvl);
		prom_printf("    * is down\n");
	}
	if (DEVI_IS_DEVICE_DEGRADED(dip)) {
		impl_bus_dump_node_prefix(lvl);
		prom_printf("    * is degraded\n");
	}
	if (DEVI_IS_DEVICE_REMOVED(dip)) {
		impl_bus_dump_node_prefix(lvl);
		prom_printf("    * is removed\n");
	}
	if (DEVI_IS_BUS_QUIESCED(dip)) {
		impl_bus_dump_node_prefix(lvl);
		prom_printf("    * is bus quiesced\n");
	}
	if (DEVI_IS_BUS_DOWN(dip)) {
		impl_bus_dump_node_prefix(lvl);
		prom_printf("    * is bus down\n");
	}
	if (DEVI_NEED_NDI_CONFIG(dip)) {
		impl_bus_dump_node_prefix(lvl);
		prom_printf("    * needs NDI config\n");
	}
	if (DEVI_IS_ATTACHING(dip)) {
		impl_bus_dump_node_prefix(lvl);
		prom_printf("    * is attaching\n");
	}
	if (DEVI_IS_DETACHING(dip)) {
		impl_bus_dump_node_prefix(lvl);
		prom_printf("    * is detaching\n");
	}
	if (DEVI_IS_ONLINING(dip)) {
		impl_bus_dump_node_prefix(lvl);
		prom_printf("    * is onlining\n");
	}
	if (DEVI_IS_OFFLINING(dip)) {
		impl_bus_dump_node_prefix(lvl);
		prom_printf("    * is offlining\n");
	}
	if (DEVI_IS_IN_RECONFIG(dip)) {
		impl_bus_dump_node_prefix(lvl);
		prom_printf("    * is in reconfig\n");
	}
	if (DEVI_IS_INVOKING_DACF(dip)) {
		impl_bus_dump_node_prefix(lvl);
		prom_printf("    * is invoking DACF\n");
	}
}

static void
impl_bus_dump_node(dev_info_t *dip, unsigned int lvl)
{
	dev_info_t *cdip;
	impl_bus_dump_node_info(dip, lvl);

	for (cdip = ddi_get_child(dip);
	    cdip != NULL;
	    cdip = ddi_get_next_sibling(cdip))
		impl_bus_dump_node(cdip, lvl + 1);
}
#endif	/* IMPL_DDI_DUMP_DEVTREE_INITIAL || IMPL_DDI_DUMP_DEVTREE_REPROBE */

/*
 * impl_bus_initialprobe
 *	Modload the prom simulator, then let it probe to verify existence
 *	and type of PCI support.
 */
static void
impl_bus_initialprobe(void)
{
	struct bus_probe *probe;
#if defined(_AARCH64_ACPI)
	extern void pci_cfgspace_init(void);

	pci_cfgspace_init();

	/* load modules to install bus probes */
	if (modload("misc", "pic_autoconfig") < 0)
		panic("failed to load misc/pic_autoconfig");

	if (modload("misc", "pci_autoconfig") < 0)
		panic("failed to load misc/pci_autoconfig");

	if (modload("misc", "acpidev") < 0)
		panic("failed to load misc/acpidev");
#else
	/*
	 * This has always been here, but doesn't do anything yet.
	 */
	(void) modload("misc", "pci_autoconfig");
#endif

	probe = bus_probes;
	while (probe) {
		/* run the probe functions */
		(*probe->probe)(0);
		probe = probe->next;
	}

#if defined(IMPL_DDI_DUMP_DEVTREE_INITIAL)
	prom_printf("Initial device tree:\n");
	impl_bus_dump_node(ddi_root_node(), 0);
#endif
}

/*
 * impl_bus_reprobe
 *	Reprogram devices not set up by firmware.
 */
void
impl_bus_reprobe(void)
{
	struct bus_probe *probe;

	probe = bus_probes;
	while (probe) {
		/* run the probe function */
		(*probe->probe)(1);
		probe = probe->next;
	}

#if defined(IMPL_DDI_DUMP_DEVTREE_REPROBE)
	prom_printf("Reprobed device tree:\n");
	impl_bus_dump_node(ddi_root_node(), 0);
#endif
}

/*
 * Copy name to property_name, since name
 * is in the low address range below kernelbase.
 */
static void
copy_boot_str(const char *boot_str, char *kern_str, int len)
{
	int i = 0;

	while (i < len - 1 && boot_str[i] != '\0') {
		kern_str[i] = boot_str[i];
		i++;
	}

	kern_str[i] = 0;	/* null terminate */
	if (boot_str[i] != '\0')
		cmn_err(CE_WARN,
		    "boot property string is truncated to %s", kern_str);
}

static void
get_boot_properties(void)
{
	extern char hw_provider[];
	dev_info_t *devi;
	char *name;
	int length, flags;
	char property_name[50], property_val[50];
	void *bop_staging_area;

	bop_staging_area = kmem_zalloc(MMU_PAGESIZE, KM_NOSLEEP);

	/*
	 * Import "root" properties from the boot.
	 *
	 * We do this by invoking BOP_NEXTPROP until the list
	 * is completely copied in.
	 */

	devi = ddi_root_node();
	for (name = BOP_NEXTPROP(bootops, "");		/* get first */
	    name;					/* NULL => DONE */
	    name = BOP_NEXTPROP(bootops, name)) {	/* get next */

		/* copy string to memory above kernelbase */
		copy_boot_str(name, property_name, 50);

		/*
		 * Skip vga properties. They will be picked up later
		 * by get_vga_properties.
		 */
		if (strcmp(property_name, "display-edif-block") == 0 ||
		    strcmp(property_name, "display-edif-id") == 0) {
			continue;
		}

		length = BOP_GETPROPLEN(bootops, property_name);
		if (length < 0)
			continue;
		if (length > MMU_PAGESIZE) {
			cmn_err(CE_NOTE,
			    "boot property %s longer than 0x%lx, ignored\n",
			    property_name, MMU_PAGESIZE);
			continue;
		}
		BOP_GETPROP(bootops, property_name, bop_staging_area);
		flags = do_bsys_getproptype(bootops, property_name);

		/*
		 * special properties:
		 * si-machine, si-hw-provider
		 *	goes to kernel data structures.
		 * bios-boot-device and stdout
		 *	goes to hardware property list so it may show up
		 *	in the prtconf -vp output. This is needed by
		 *	Install/Upgrade. Once we fix install upgrade,
		 *	this can be taken out.
		 */
		if (strcmp(name, "si-machine") == 0) {
			(void) strncpy(utsname.machine, bop_staging_area,
			    SYS_NMLN);
			utsname.machine[SYS_NMLN - 1] = '\0';
			continue;
		}
		if (strcmp(name, "si-hw-provider") == 0) {
			(void) strncpy(hw_provider, bop_staging_area, SYS_NMLN);
			hw_provider[SYS_NMLN - 1] = '\0';
			continue;
		}
		if (strcmp(name, "bios-boot-device") == 0) {
			copy_boot_str(bop_staging_area, property_val, 50);
			(void) ndi_prop_update_string(DDI_DEV_T_NONE, devi,
			    property_name, property_val);
			continue;
		}
		if (strcmp(name, "stdout") == 0) {
			(void) ndi_prop_update_int(DDI_DEV_T_NONE, devi,
			    property_name, *((int *)bop_staging_area));
			continue;
		}

		/* Boolean property */
		if (length == 0) {
			(void) e_ddi_prop_create(DDI_DEV_T_NONE, devi,
			    DDI_PROP_CANSLEEP, property_name, NULL, 0);
			continue;
		}

		/* Now anything else based on type. */
		switch (flags) {
		case DDI_PROP_TYPE_INT:
			if (length == sizeof (int)) {
				(void) e_ddi_prop_update_int(DDI_DEV_T_NONE,
				    devi, property_name,
				    *((int *)bop_staging_area));
			} else {
				(void) e_ddi_prop_update_int_array(
				    DDI_DEV_T_NONE, devi, property_name,
				    bop_staging_area, length / sizeof (int));
			}
			break;
		case DDI_PROP_TYPE_STRING:
			(void) e_ddi_prop_update_string(DDI_DEV_T_NONE, devi,
			    property_name, bop_staging_area);
			break;
		case DDI_PROP_TYPE_BYTE:
			(void) e_ddi_prop_update_byte_array(DDI_DEV_T_NONE,
			    devi, property_name, bop_staging_area, length);
			break;
		case DDI_PROP_TYPE_INT64:
			if (length == sizeof (int64_t)) {
				(void) e_ddi_prop_update_int64(DDI_DEV_T_NONE,
				    devi, property_name,
				    *((int64_t *)bop_staging_area));
			} else {
				(void) e_ddi_prop_update_int64_array(
				    DDI_DEV_T_NONE, devi, property_name,
				    bop_staging_area,
				    length / sizeof (int64_t));
			}
			break;
		default:
			/* Property type unknown, use old prop interface */
			(void) e_ddi_prop_create(DDI_DEV_T_NONE, devi,
			    DDI_PROP_CANSLEEP, property_name, bop_staging_area,
			    length);
		}
	}

	kmem_free(bop_staging_area, MMU_PAGESIZE);
}

void
impl_setup_ddi(void)
{
	dev_info_t *xdip;
	rd_existing_t rd_mem_prop;
	int err __maybe_unused;

	ndi_devi_alloc_sleep(ddi_root_node(), "ramdisk",
	    (pnode_t)DEVI_SID_NODEID, &xdip);

	(void) BOP_GETPROP(bootops,
	    "ramdisk_start", (void *)&ramdisk_start);
	(void) BOP_GETPROP(bootops,
	    "ramdisk_end", (void *)&ramdisk_end);

	rd_mem_prop.phys = ramdisk_start;
	rd_mem_prop.size = ramdisk_end - ramdisk_start + 1;

	(void) ndi_prop_update_byte_array(DDI_DEV_T_NONE, xdip,
	    RD_EXISTING_PROP_NAME, (uchar_t *)&rd_mem_prop,
	    sizeof (rd_mem_prop));
	err = ndi_devi_bind_driver(xdip, 0);
	ASSERT(err == 0);

	/*
	 * Read in the properties from the boot.
	 */
	get_boot_properties();

	/* Copy console font if provided by boot. */
	get_console_font();

	/*
	 * Check for administratively disabled drivers.
	 */
	check_driver_disable();

	/* do bus dependent probes. */
	impl_bus_initialprobe();
}

/*
 * Perform a copy from a memory mapped device (whose devinfo pointer is devi)
 * separately mapped at devaddr in the kernel to a kernel buffer at kaddr.
 */
/*ARGSUSED*/
int
e_ddi_copyfromdev(dev_info_t *devi,
    off_t off, const void *devaddr, void *kaddr, size_t len)
{
	bcopy(devaddr, kaddr, len);
	return (0);
}

/*
 * Perform a copy to a memory mapped device (whose devinfo pointer is devi)
 * separately mapped at devaddr in the kernel from a kernel buffer at kaddr.
 */
/*ARGSUSED*/
int
e_ddi_copytodev(dev_info_t *devi,
    off_t off, const void *kaddr, void *devaddr, size_t len)
{
	bcopy(kaddr, devaddr, len);
	return (0);
}

static int
poke_mem(peekpoke_ctlops_t *in_args)
{
	volatile int err = DDI_SUCCESS;
	on_trap_data_t otd;

	/* Set up protected environment. */
	if (!on_trap(&otd, OT_DATA_ACCESS)) {
		switch (in_args->size) {
		case sizeof (uint8_t):
			*(uint8_t *)(in_args->dev_addr) =
			    *(uint8_t *)in_args->host_addr;
			break;

		case sizeof (uint16_t):
			*(uint16_t *)(in_args->dev_addr) =
			    *(uint16_t *)in_args->host_addr;
			break;

		case sizeof (uint32_t):
			*(uint32_t *)(in_args->dev_addr) =
			    *(uint32_t *)in_args->host_addr;
			break;

		case sizeof (uint64_t):
			*(uint64_t *)(in_args->dev_addr) =
			    *(uint64_t *)in_args->host_addr;
			break;

		default:
			err = DDI_FAILURE;
			break;
		}
	} else
		err = DDI_FAILURE;

	/* Take down protected environment. */
	no_trap();

	return (err);
}

static int
peek_mem(peekpoke_ctlops_t *in_args)
{
	volatile int err = DDI_SUCCESS;
	on_trap_data_t otd;

	if (!on_trap(&otd, OT_DATA_ACCESS)) {
		switch (in_args->size) {
		case sizeof (uint8_t):
			*(uint8_t *)in_args->host_addr =
			    *(uint8_t *)in_args->dev_addr;
			break;

		case sizeof (uint16_t):
			*(uint16_t *)in_args->host_addr =
			    *(uint16_t *)in_args->dev_addr;
			break;

		case sizeof (uint32_t):
			*(uint32_t *)in_args->host_addr =
			    *(uint32_t *)in_args->dev_addr;
			break;

		case sizeof (uint64_t):
			*(uint64_t *)in_args->host_addr =
			    *(uint64_t *)in_args->dev_addr;
			break;

		default:
			err = DDI_FAILURE;
			break;
		}
	} else
		err = DDI_FAILURE;

	no_trap();
	return (err);
}

/*
 * This is called only to process peek/poke when the DIP is NULL.
 * Assume that this is for memory, as nexi take care of device safe accesses.
 */
int
peekpoke_mem(ddi_ctl_enum_t cmd, peekpoke_ctlops_t *in_args)
{
	return (cmd == DDI_CTLOPS_PEEK ? peek_mem(in_args) : poke_mem(in_args));
}

/*
 * we've just done a cautious put/get. Check if it was successful by
 * calling pci_ereport_post() on all puts and for any gets that return -1
 */
static int
pci_peekpoke_check_fma(dev_info_t *dip, void *arg, ddi_ctl_enum_t ctlop,
    void (*scan)(dev_info_t *, ddi_fm_error_t *))
{
	int	rval = DDI_SUCCESS;
	peekpoke_ctlops_t *in_args = (peekpoke_ctlops_t *)arg;
	ddi_fm_error_t de;
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)in_args->handle;
	ddi_acc_hdl_t *hdlp = (ddi_acc_hdl_t *)in_args->handle;
	int check_err = 0;
	int repcount = in_args->repcount;

	if (ctlop == DDI_CTLOPS_POKE &&
	    hdlp->ah_acc.devacc_attr_access != DDI_CAUTIOUS_ACC)
		return (DDI_SUCCESS);

	if (ctlop == DDI_CTLOPS_PEEK &&
	    hdlp->ah_acc.devacc_attr_access != DDI_CAUTIOUS_ACC) {
		for (; repcount; repcount--) {
			switch (in_args->size) {
			case sizeof (uint8_t):
				if (*(uint8_t *)in_args->host_addr == 0xff)
					check_err = 1;
				break;
			case sizeof (uint16_t):
				if (*(uint16_t *)in_args->host_addr == 0xffff)
					check_err = 1;
				break;
			case sizeof (uint32_t):
				if (*(uint32_t *)in_args->host_addr ==
				    0xffffffff)
					check_err = 1;
				break;
			case sizeof (uint64_t):
				if (*(uint64_t *)in_args->host_addr ==
				    0xffffffffffffffff)
					check_err = 1;
				break;
			}
		}
		if (check_err == 0)
			return (DDI_SUCCESS);
	}
	/*
	 * for a cautious put or get or a non-cautious get that returned -1 call
	 * io framework to see if there really was an error
	 */
	bzero(&de, sizeof (ddi_fm_error_t));
	de.fme_version = DDI_FME_VERSION;
	de.fme_ena = fm_ena_generate(0, FM_ENA_FMT1);
	if (hdlp->ah_acc.devacc_attr_access == DDI_CAUTIOUS_ACC) {
		de.fme_flag = DDI_FM_ERR_EXPECTED;
		de.fme_acc_handle = in_args->handle;
	} else if (hdlp->ah_acc.devacc_attr_access == DDI_DEFAULT_ACC) {
		/*
		 * We only get here with DDI_DEFAULT_ACC for config space gets.
		 * Non-hardened drivers may be probing the hardware and
		 * expecting -1 returned. So need to treat errors on
		 * DDI_DEFAULT_ACC as DDI_FM_ERR_EXPECTED.
		 */
		de.fme_flag = DDI_FM_ERR_EXPECTED;
		de.fme_acc_handle = in_args->handle;
	} else {
		/*
		 * Hardened driver doing protected accesses shouldn't
		 * get errors unless there's a hardware problem. Treat
		 * as nonfatal if there's an error, but set UNEXPECTED
		 * so we raise ereports on any errors and potentially
		 * fault the device
		 */
		de.fme_flag = DDI_FM_ERR_UNEXPECTED;
	}
	(void) scan(dip, &de);
	if (hdlp->ah_acc.devacc_attr_access != DDI_DEFAULT_ACC &&
	    de.fme_status != DDI_FM_OK) {
		ndi_err_t *errp = (ndi_err_t *)hp->ahi_err;
		rval = DDI_FAILURE;
		errp->err_ena = de.fme_ena;
		errp->err_expected = de.fme_flag;
		errp->err_status = DDI_FM_NONFATAL;
	}
	return (rval);
}

/*
 * pci_peekpoke_check_nofma() is for when an error occurs on a register access
 * during pci_ereport_post(). We can't call pci_ereport_post() again or we'd
 * recurse, so assume all puts are OK and gets have failed if they return -1
 */
static int
pci_peekpoke_check_nofma(void *arg, ddi_ctl_enum_t ctlop)
{
	int rval = DDI_SUCCESS;
	peekpoke_ctlops_t *in_args = (peekpoke_ctlops_t *)arg;
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)in_args->handle;
	ddi_acc_hdl_t *hdlp = (ddi_acc_hdl_t *)in_args->handle;
	int repcount = in_args->repcount;

	if (ctlop == DDI_CTLOPS_POKE)
		return (rval);

	for (; repcount; repcount--) {
		switch (in_args->size) {
		case sizeof (uint8_t):
			if (*(uint8_t *)in_args->host_addr == 0xff)
				rval = DDI_FAILURE;
			break;
		case sizeof (uint16_t):
			if (*(uint16_t *)in_args->host_addr == 0xffff)
				rval = DDI_FAILURE;
			break;
		case sizeof (uint32_t):
			if (*(uint32_t *)in_args->host_addr == 0xffffffff)
				rval = DDI_FAILURE;
			break;
		case sizeof (uint64_t):
			if (*(uint64_t *)in_args->host_addr ==
			    0xffffffffffffffff)
				rval = DDI_FAILURE;
			break;
		}
	}
	if (hdlp->ah_acc.devacc_attr_access != DDI_DEFAULT_ACC &&
	    rval == DDI_FAILURE) {
		ndi_err_t *errp = (ndi_err_t *)hp->ahi_err;
		errp->err_ena = fm_ena_generate(0, FM_ENA_FMT1);
		errp->err_expected = DDI_FM_ERR_UNEXPECTED;
		errp->err_status = DDI_FM_NONFATAL;
	}
	return (rval);
}

int
pci_peekpoke_check(dev_info_t *dip, dev_info_t *rdip,
    ddi_ctl_enum_t ctlop, void *arg, void *result,
    int (*handler)(dev_info_t *, dev_info_t *, ddi_ctl_enum_t, void *,
    void *), kmutex_t *err_mutexp, kmutex_t *peek_poke_mutexp,
    void (*scan)(dev_info_t *, ddi_fm_error_t *))
{
	int rval;
	peekpoke_ctlops_t *in_args = (peekpoke_ctlops_t *)arg;
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)in_args->handle;

	/*
	 * this function only supports cautious accesses, not peeks/pokes
	 * which don't have a handle
	 */
	if (hp == NULL)
		return (DDI_FAILURE);

	if (hp->ahi_acc_attr & DDI_ACCATTR_CONFIG_SPACE) {
		if (!mutex_tryenter(err_mutexp)) {
			/*
			 * As this may be a recursive call from within
			 * pci_ereport_post() we can't wait for the mutexes.
			 * Fortunately we know someone is already calling
			 * pci_ereport_post() which will handle the error bits
			 * for us, and as this is a config space access we can
			 * just do the access and check return value for -1
			 * using pci_peekpoke_check_nofma().
			 */
			rval = handler(dip, rdip, ctlop, arg, result);
			if (rval == DDI_SUCCESS)
				rval = pci_peekpoke_check_nofma(arg, ctlop);
			return (rval);
		}
		/*
		 * This can't be a recursive call. Drop the err_mutex and get
		 * both mutexes in the right order. If an error hasn't already
		 * been detected by the ontrap code, use pci_peekpoke_check_fma
		 * which will call pci_ereport_post() to check error status.
		 */
		mutex_exit(err_mutexp);
	}
	mutex_enter(peek_poke_mutexp);
	rval = handler(dip, rdip, ctlop, arg, result);
	if (rval == DDI_SUCCESS) {
		mutex_enter(err_mutexp);
		rval = pci_peekpoke_check_fma(dip, arg, ctlop, scan);
		mutex_exit(err_mutexp);
	}
	mutex_exit(peek_poke_mutexp);
	return (rval);
}

dev_t
getrootdev(void)
{
	/*
	 * Usually rootfs.bo_name is initialized by the
	 * the bootpath property from bootenv.rc, but
	 * defaults to "/ramdisk:a" otherwise.
	 */
	return (ddi_pathname_to_dev_t(rootfs.bo_name));
}

boolean_t
i_ddi_copybuf_required(ddi_dma_attr_t *attrp)
{
	uint64_t hi_pa;

	hi_pa = ((uint64_t)physmax + 1ull) << PAGESHIFT;
	if (attrp->dma_attr_addr_hi < hi_pa) {
		return (B_TRUE);
	}

	return (B_FALSE);
}

size_t
i_ddi_copybuf_size()
{
	return (dma_max_copybuf_size);
}

/*
 * i_ddi_dma_max()
 *    returns the maximum DMA size which can be performed in a single DMA
 *    window taking into account the devices DMA contraints (attrp), the
 *    maximum copy buffer size (if applicable), and the worse case buffer
 *    fragmentation.
 */
/*ARGSUSED*/
uint32_t
i_ddi_dma_max(dev_info_t *dip, ddi_dma_attr_t *attrp)
{
	uint64_t maxxfer;


	/*
	 * take the min of maxxfer and the the worse case fragementation
	 * (e.g. every cookie <= 1 page)
	 */
	maxxfer = MIN(attrp->dma_attr_maxxfer,
	    ((uint64_t)(attrp->dma_attr_sgllen - 1) << PAGESHIFT));

	/*
	 * If the DMA engine can't reach all off memory, we also need to take
	 * the max size of the copybuf into consideration.
	 */
	if (i_ddi_copybuf_required(attrp)) {
		maxxfer = MIN(i_ddi_copybuf_size(), maxxfer);
	}

	/*
	 * we only return a 32-bit value. Make sure it's not -1. Round to a
	 * page so it won't be mistaken for an error value during debug.
	 */
	if (maxxfer >= 0xFFFFFFFF) {
		maxxfer = 0xFFFFF000;
	}

	/*
	 * make sure the value we return is a whole multiple of the
	 * granlarity.
	 */
	if (attrp->dma_attr_granular > 1) {
		maxxfer = maxxfer - (maxxfer % attrp->dma_attr_granular);
	}

	return ((uint32_t)maxxfer);
}

void
translate_devid(dev_info_t *dip)
{
}

pfn_t
i_ddi_paddr_to_pfn(paddr_t paddr)
{
	pfn_t pfn;

	pfn = mmu_btop(paddr);

	return (pfn);
}

void
i_ddi_intr_redist_all_cpus()
{
	/* nothing (yet) */
}
