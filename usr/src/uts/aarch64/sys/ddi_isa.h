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
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_DDI_ISA_H
#define	_SYS_DDI_ISA_H

#include <sys/isa_defs.h>
#include <sys/dditypes.h>
#include <sys/ndifm.h>
#ifdef	_KERNEL
#include <sys/ddi_obsolete.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

/*
 * These are the data access functions which the platform
 * can choose to define as functions or macro's.
 */

/*
 * DDI interfaces defined as macro's
 */

/*
 * Helpers for regspec manipulation and conversion.
 */
#define	REGSPEC_BUSTYPE(__rs)	(((__rs)->regspec_bustype >> 24) & 0xff)
#define	REGSPEC_SET_BUSTYPE(__rs, __bt)	do {				\
	(__rs)->regspec_bustype &= (0x00ffffff);			\
	(__rs)->regspec_bustype |= (((uint_t)((__bt) & 0xff)) << 24);	\
} while (0)

#define	REGSPEC_ADDR(__rs)						\
	(((((uint64_t)((__rs)->regspec_bustype & 0x00ffffff)) << 32) |	\
	(__rs)->regspec_addr))
#define	REGSPEC_SET_ADDR(__rs, __addr)	do {				\
	(__rs)->regspec_bustype &= (0xff000000);			\
	(__rs)->regspec_bustype |=					\
	    ((((uint64_t)(__addr)) >> 32) & 0x00ffffff);		\
	(__rs)->regspec_addr = ((__addr) & 0xffffffff);			\
} while (0)
#define	REGSPEC_INCR_ADDR(__rs, __incr)	do {				\
	REGSPEC_SET_ADDR((__rs), (REGSPEC_ADDR((__rs)) + (__incr)));	\
} while (0)

#define	REGSPEC_SIZE(__rs)	((__rs)->regspec_size)
#define	REGSPEC_SET_SIZE(__rs, __sz)	do {				\
	(__rs)->regspec_size = (uint_t)(__sz);				\
} while (0)

#define	REGSPEC_TO_REGSPEC64(__rs, __rs64)	do {			\
	(__rs64)->regspec_bustype = REGSPEC_BUSTYPE((__rs));		\
	(__rs64)->regspec_addr = REGSPEC_ADDR((__rs));			\
	(__rs64)->regspec_size = REGSPEC_SIZE((__rs));			\
} while (0)

#define	REGSPEC64_TO_REGSPEC(__rs64, __rs)	do {			\
	REGSPEC_SET_BUSTYPE((__rs), (__rs64)->regspec_bustype);		\
	VERIFY(((__rs64)->regspec_addr & 0x00fffffffffffffflu) ==	\
	    (__rs64)->regspec_addr);					\
	REGSPEC_SET_ADDR((__rs), (__rs64)->regspec_addr);		\
	VERIFY(((__rs64)->regspec_size & 0xffffffffu) ==		\
	    (__rs64)->regspec_size);					\
	REGSPEC_SET_SIZE((__rs), (__rs64)->regspec_size);		\
} while (0)

/*
 * Helpers for rangespec manipulation and use
 */
#define	RANGESPEC_CHILD_BUSTYPE(__rs)	(((__rs)->rng_cbustype >> 24) & 0xff)
#define	RANGESPEC_SET_CHILD_BUSTYPE(__rs, __bt)	do {			\
	(__rs)->rng_cbustype &= (0x00ffffff);				\
	(__rs)->rng_cbustype |= (((uint_t)((__bt) & 0xff)) << 24);	\
} while (0)

#define	RANGESPEC_CHILD_OFFSET(__rs)					\
	((((uint64_t)((__rs)->rng_cbustype & 0x00ffffff)) << 32) |	\
	(__rs)->rng_coffset)
#define	RANGESPEC_SET_CHILD_OFFSET(__rs, __off)	do {			\
	(__rs)->rng_cbustype &= (0xff000000);				\
	(__rs)->rng_cbustype |= (((__off) >> 32) & 0x00ffffff);		\
	(__rs)->rng_coffset = ((__off) & 0xffffffff);			\
} while (0)

#define	RANGESPEC_BUSTYPE(__rs)	(((__rs)->rng_bustype >> 24) & 0xff)
#define	RANGESPEC_SET_BUSTYPE(__rs, __bt)	do {			\
	(__rs)->rng_bustype &= (0x00ffffff);				\
	(__rs)->rng_bustype |= (((uint_t)((__bt) & 0xff)) << 24);	\
} while (0)

#define	RANGESPEC_OFFSET(__rs)						\
	((((uint64_t)((__rs)->rng_bustype & 0x00ffffff)) << 32) |	\
	    (__rs)->rng_offset)
#define	RANGESPEC_SET_OFFSET(__rs, __off)	do {			\
	(__rs)->rng_bustype &= (0xff000000);				\
	(__rs)->rng_bustype |= (((__off) >> 32) & 0x00ffffff);		\
	(__rs)->rng_offset = ((__off) & 0xffffffff);			\
} while (0)

#define	RANGESPEC_SIZE(__rs)	((__rs)->rng_size)
#define	RANGESPEC_SET_SIZE(__rs, __sz)	do {				\
	(__rs)->rng_size = (uint_t)(__sz);				\
} while (0)

/*
 * DDI interfaces defined as functions
 */

/*
 * ahi_acc_attr flags
 */
#define	DDI_ACCATTR_CONFIG_SPACE	0x1
#define	DDI_ACCATTR_IO_SPACE		0x2
#define	DDI_ACCATTR_CPU_VADDR		0x4
#define	DDI_ACCATTR_DIRECT		0x8

typedef struct ddi_acc_impl {
	ddi_acc_hdl_t	ahi_common;
	uint_t		ahi_acc_attr;
	ulong_t		ahi_io_port_base;

	uint8_t
		(*ahi_get8)(struct ddi_acc_impl *handle, uint8_t *addr);
	uint16_t
		(*ahi_get16)(struct ddi_acc_impl *handle, uint16_t *addr);
	uint32_t
		(*ahi_get32)(struct ddi_acc_impl *handle, uint32_t *addr);
	uint64_t
		(*ahi_get64)(struct ddi_acc_impl *handle, uint64_t *addr);

	void	(*ahi_put8)(struct ddi_acc_impl *handle, uint8_t *addr,
			uint8_t value);
	void	(*ahi_put16)(struct ddi_acc_impl *handle, uint16_t *addr,
			uint16_t value);
	void	(*ahi_put32)(struct ddi_acc_impl *handle, uint32_t *addr,
			uint32_t value);
	void	(*ahi_put64)(struct ddi_acc_impl *handle, uint64_t *addr,
			uint64_t value);

	void	(*ahi_rep_get8)(struct ddi_acc_impl *handle,
			uint8_t *host_addr, uint8_t *dev_addr,
			size_t repcount, uint_t flags);
	void	(*ahi_rep_get16)(struct ddi_acc_impl *handle,
			uint16_t *host_addr, uint16_t *dev_addr,
			size_t repcount, uint_t flags);
	void	(*ahi_rep_get32)(struct ddi_acc_impl *handle,
			uint32_t *host_addr, uint32_t *dev_addr,
			size_t repcount, uint_t flags);
	void	(*ahi_rep_get64)(struct ddi_acc_impl *handle,
			uint64_t *host_addr, uint64_t *dev_addr,
			size_t repcount, uint_t flags);

	void	(*ahi_rep_put8)(struct ddi_acc_impl *handle,
			uint8_t *host_addr, uint8_t *dev_addr,
			size_t repcount, uint_t flags);
	void	(*ahi_rep_put16)(struct ddi_acc_impl *handle,
			uint16_t *host_addr, uint16_t *dev_addr,
			size_t repcount, uint_t flags);
	void	(*ahi_rep_put32)(struct ddi_acc_impl *handle,
			uint32_t *host_addr, uint32_t *dev_addr,
			size_t repcount, uint_t flags);
	void	(*ahi_rep_put64)(struct ddi_acc_impl *handle,
			uint64_t *host_addr, uint64_t *dev_addr,
			size_t repcount, uint_t flags);

	int	(*ahi_fault_check)(struct ddi_acc_impl *handle);
	void	(*ahi_fault_notify)(struct ddi_acc_impl *handle);
	uint32_t	ahi_fault;
	ndi_err_t *ahi_err;
	kmutex_t *ahi_peekpoke_mutexp;
	kmutex_t *ahi_err_mutexp;
	void (*ahi_scan)(dev_info_t *, ddi_fm_error_t *);
	dev_info_t *ahi_scan_dip;
} ddi_acc_impl_t;


/*
 * Input functions to memory mapped IO
 */
uint8_t i_ddi_get8(ddi_acc_impl_t *hdlp, uint8_t *addr);
uint16_t i_ddi_get16(ddi_acc_impl_t *hdlp, uint16_t *addr);
uint32_t i_ddi_get32(ddi_acc_impl_t *hdlp, uint32_t *addr);
uint64_t i_ddi_get64(ddi_acc_impl_t *hdlp, uint64_t *addr);
uint16_t i_ddi_swap_get16(ddi_acc_impl_t *hdlp, uint16_t *addr);
uint32_t i_ddi_swap_get32(ddi_acc_impl_t *hdlp, uint32_t *addr);
uint64_t i_ddi_swap_get64(ddi_acc_impl_t *hdlp, uint64_t *addr);

/*
 * Output functions to memory mapped IO
 */
void i_ddi_put8(ddi_acc_impl_t *hdlp, uint8_t *addr, uint8_t value);
void i_ddi_put16(ddi_acc_impl_t *hdlp, uint16_t *addr, uint16_t value);
void i_ddi_put32(ddi_acc_impl_t *hdlp, uint32_t *addr, uint32_t value);
void i_ddi_put64(ddi_acc_impl_t *hdlp, uint64_t *addr, uint64_t value);
void i_ddi_swap_put16(ddi_acc_impl_t *hdlp, uint16_t *addr, uint16_t value);
void i_ddi_swap_put32(ddi_acc_impl_t *hdlp, uint32_t *addr, uint32_t value);
void i_ddi_swap_put64(ddi_acc_impl_t *hdlp, uint64_t *addr, uint64_t value);

/*
 * Repeated input functions for memory mapped IO
 */
void i_ddi_rep_get8(ddi_acc_impl_t *hdlp, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_rep_get16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_rep_get32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_rep_get64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_swap_rep_get16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_swap_rep_get32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_swap_rep_get64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags);

/*
 * Repeated output functions for memory mapped IO
 */
void i_ddi_rep_put8(ddi_acc_impl_t *hdlp, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_rep_put16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_rep_put32(ddi_acc_impl_t *hdl, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_rep_put64(ddi_acc_impl_t *hdl, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_swap_rep_put16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_swap_rep_put32(ddi_acc_impl_t *hdl, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_swap_rep_put64(ddi_acc_impl_t *hdl, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags);

/*
 * Input functions to IO space
 */
uint8_t i_ddi_io_get8(ddi_acc_impl_t *hdlp, uint8_t *addr);
uint16_t i_ddi_io_get16(ddi_acc_impl_t *hdlp, uint16_t *addr);
uint32_t i_ddi_io_get32(ddi_acc_impl_t *hdlp, uint32_t *addr);
uint64_t i_ddi_io_get64(ddi_acc_impl_t *hdlp, uint64_t *addr);
uint16_t i_ddi_io_swap_get16(ddi_acc_impl_t *hdlp, uint16_t *addr);
uint32_t i_ddi_io_swap_get32(ddi_acc_impl_t *hdlp, uint32_t *addr);
uint64_t i_ddi_io_swap_get64(ddi_acc_impl_t *hdlp, uint64_t *addr);

/*
 * Output functions to IO space
 */
void i_ddi_io_put8(ddi_acc_impl_t *hdlp, uint8_t *addr, uint8_t value);
void i_ddi_io_put16(ddi_acc_impl_t *hdlp, uint16_t *addr, uint16_t value);
void i_ddi_io_put32(ddi_acc_impl_t *hdlp, uint32_t *addr, uint32_t value);
void i_ddi_io_put64(ddi_acc_impl_t *hdlp, uint64_t *addr, uint64_t value);
void i_ddi_io_swap_put16(ddi_acc_impl_t *hdlp, uint16_t *addr, uint16_t value);
void i_ddi_io_swap_put32(ddi_acc_impl_t *hdlp, uint32_t *addr, uint32_t value);
void i_ddi_io_swap_put64(ddi_acc_impl_t *hdlp, uint64_t *addr, uint64_t value);

/*
 * Repeated input functions for IO space
 */
void i_ddi_io_rep_get8(ddi_acc_impl_t *hdlp, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_io_rep_get16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_io_rep_get32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_io_rep_get64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_io_swap_rep_get16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_io_swap_rep_get32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_io_swap_rep_get64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags);

/*
 * Repeated output functions for IO space
 */
void i_ddi_io_rep_put8(ddi_acc_impl_t *hdlp, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_io_rep_put16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_io_rep_put32(ddi_acc_impl_t *hdl, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_io_rep_put64(ddi_acc_impl_t *hdl, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_io_swap_rep_put16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_io_swap_rep_put32(ddi_acc_impl_t *hdl, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_io_swap_rep_put64(ddi_acc_impl_t *hdl, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags);

/*
 * Default fault-checking and notification functions
 */
int
i_ddi_acc_fault_check(ddi_acc_impl_t *hdlp);

void
i_ddi_acc_fault_notify(ddi_acc_impl_t *hdlp);

/* DDI Fault Services functions */
void i_ddi_caut_get(size_t size, void *addr, void *val);

uint8_t i_ddi_caut_get8(ddi_acc_impl_t *hdlp, uint8_t *addr);
uint16_t i_ddi_caut_get16(ddi_acc_impl_t *hdlp, uint16_t *addr);
uint32_t i_ddi_caut_get32(ddi_acc_impl_t *hdlp, uint32_t *addr);
uint64_t i_ddi_caut_get64(ddi_acc_impl_t *hdlp, uint64_t *addr);

void i_ddi_caut_put8(ddi_acc_impl_t *hdlp, uint8_t *addr, uint8_t value);
void i_ddi_caut_put16(ddi_acc_impl_t *hdlp, uint16_t *addr, uint16_t value);
void i_ddi_caut_put32(ddi_acc_impl_t *hdlp, uint32_t *addr, uint32_t value);
void i_ddi_caut_put64(ddi_acc_impl_t *hdlp, uint64_t *addr, uint64_t value);

void i_ddi_caut_rep_get8(ddi_acc_impl_t *hdlp, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_caut_rep_get16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_caut_rep_get32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_caut_rep_get64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags);

void i_ddi_caut_rep_put8(ddi_acc_impl_t *hdlp, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_caut_rep_put16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_caut_rep_put32(ddi_acc_impl_t *hdl, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_caut_rep_put64(ddi_acc_impl_t *hdl, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags);

boolean_t i_ddi_copybuf_required(ddi_dma_attr_t *attrp);
size_t i_ddi_copybuf_size();
uint32_t i_ddi_dma_max(dev_info_t *dip, ddi_dma_attr_t *attrp);

/* handles case of running on top of hypervisor */
pfn_t i_ddi_paddr_to_pfn(paddr_t paddr);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DDI_ISA_H */
