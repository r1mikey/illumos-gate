#ifndef	_SBSA_SHIM_H
#define	_SBSA_SHIM_H

struct efi_map_header {
	size_t		memory_size;
	size_t		descriptor_size;
	uint32_t	descriptor_version;
};

extern struct efi_map_header *efi_map_header;

extern struct memlist *pfreelistp;
extern struct memlist *pscratchlistp;
extern struct memlist *pinstalledp;
extern struct memlist *piolistp;
extern struct memlist *ptmplistp;
extern struct memlist *plinearlistp;
extern struct memlist *pfwcodelistp;
extern struct memlist *pfwdatalistp;

extern struct xboot_info *bi;

extern void _reset(void) __NORETURN;
extern void fiximp(void);
extern void dump_exception(uint64_t *regs);

extern struct efi_map_header *efi_map_header;

#define	efi_mmap_next(ptr, size) \
	((EFI_MEMORY_DESCRIPTOR *)(((uint8_t *)(ptr)) + (size)))

#define	RNDUP(x, y)	((x) + ((y) - 1ul) & ~((y) - 1ul))
#define	RNDDN(x, y)	((x) & ~((y) - 1ul))

extern void map_efimem(uint64_t offset);

#endif
