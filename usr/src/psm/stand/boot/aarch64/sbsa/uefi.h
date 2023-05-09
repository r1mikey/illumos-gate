#ifndef	_SBSA_UEFI_H
#define	_SBSA_UEFI_H

extern int init_uefi(struct xboot_info *xbi);

extern void uefi_reset(void) __NORETURN;

#endif
