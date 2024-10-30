#ifndef	_SBSA_EARLY_DBG2_H
#define	_SBSA_EARLY_DBG2_H

#define _EARLY_DBG2     0

#if defined(_EARLY_DBG2) && _EARLY_DBG2 > 0
/*
 * qemu sbsa-ref is: 0x60000000ULL
 *     qemu virt is: 0x09000000ULL
 */
#define EARLY_DBG2_PA   0x09000000ULL
#define EARLY_DBG2_TYPE 0x000e
#endif

#endif
