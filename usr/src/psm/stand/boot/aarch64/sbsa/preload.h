#ifndef	_SBSA_PRELOAD_H
#define	_SBSA_PRELOAD_H

#include <sys/types.h>

extern int prekern_process_modules(caddr_t modulep, struct xboot_info *xbi,
    uint64_t *pmemmap, uint64_t *pfb,
    uint64_t *ppayload, uint64_t *ppayload_size);

extern const char * prekern_getenv(struct xboot_info *xbi, const char *name);
extern int prekern_getenv_uint64(
    struct xboot_info *xbi, const char *name, uint64_t *data);

#endif
