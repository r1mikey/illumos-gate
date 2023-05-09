#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/bootinfo.h>
#include <string.h>
#include "preload.h"
#include "dbg2.h"

#define	MODINFO_END		0x0000	/* End of list */
#define	MODINFO_NAME		0x0001	/* Name of module (string) */
#define	MODINFO_TYPE		0x0002	/* Type of module (string) */
#define	MODINFO_ADDR		0x0003	/* Loaded address */
#define	MODINFO_SIZE		0x0004	/* Size of module */
#define	MODINFO_EMPTY		0x0005	/* Has been deleted */
#define	MODINFO_ARGS		0x0006	/* Parameters string */
#define	MODINFO_METADATA	0x8000	/* Module-specfic */

#define	MODINFOMD_AOUTEXEC	0x0001	/* a.out exec header */
#define	MODINFOMD_ELFHDR	0x0002	/* ELF header */
#define	MODINFOMD_SSYM		0x0003	/* start of symbols */
#define	MODINFOMD_ESYM		0x0004	/* end of symbols */
#define	MODINFOMD_DYNAMIC	0x0005	/* _DYNAMIC pointer */
#define	MODINFOMD_MB2HDR	0x0006	/* MB2 header info */
#define	MODINFOMD_ENVP		0x0006	/* envp[] */
#define	MODINFOMD_HOWTO		0x0007	/* boothowto */
#define	MODINFOMD_KERNEND	0x0008	/* kernend */
#define	MODINFOMD_SHDR		0x0009	/* section header table */
#define	MODINFOMD_CTORS_ADDR	0x000a	/* address of .ctors */
#define	MODINFOMD_CTORS_SIZE	0x000b	/* size of .ctors */
#define	MODINFOMD_FW_HANDLE	0x000c	/* Firmware dependent handle */
#define	MODINFOMD_KEYBUF	0x000d	/* Crypto key intake buffer */
#define	MODINFOMD_FONT		0x000e	/* Console font */
#define	MODINFOMD_NOCOPY	0x8000	/* don't copy to the kernel */

#define	MODINFOMD_SMAP		0x1001	/* x86 SMAP */
#define	MODINFOMD_SMAP_XATTR	0x1002	/* x86 SMAP extended attrs */
#define	MODINFOMD_DTBP		0x1003	/* DTB pointer */
#define	MODINFOMD_EFI_MAP	0x1004	/* UEFI memory map */
#define	MODINFOMD_EFI_FB	0x1005	/* UEFI framebuffer */
#define	MODINFOMD_MODULEP	0x1006

#define	ENV_BOOTMOD_NAME	"environment"
#define	ROOTFS_BOOTMOD_NAME	"rootfs"

static const char env_boot_module_name[] = ENV_BOOTMOD_NAME;
static const char rootfs_boot_module_name[] = ROOTFS_BOOTMOD_NAME;

#define	PAYLOAD_CMDLINE_MAX_LEN	1023
static char paylad_cmdline[PAYLOAD_CMDLINE_MAX_LEN + 1];

#define	MOD_UINT64(x)	(*((uint64_t *)(&(x)[2])))

struct module_data_t {
	uint64_t	maddr;
	uint64_t	msize;
	const char	*mtype;
	const char	*mname;
	const char	*margs;
	uint64_t	env_addr;
	uint64_t	map_addr;
	uint64_t	font_addr;
	uint64_t	fb_addr;
	uint64_t	systab_addr;
};

static int
prekern_process_module_info(caddr_t mi, struct module_data_t *md)
{
	caddr_t		curp;
	uint32_t	*hdrp;
	unsigned int	mlen;
	uint32_t	type;
	unsigned int	next;

	if (mi == NULL)
		return (-1);

	curp = mi;
	type = 0;

	for (;;) {
		hdrp = (uint32_t *)curp;
		mlen = hdrp[1];

		/*
		 * End of module data? Let the caller deal with it.
		 */
		if (hdrp[0] == MODINFO_END && mlen == 0)
			break;

		/*
		 * We give up once we've looped back to the type what we were
		 * looking at first, which is a MODINFO_NAME.
		 */
		if (type == 0) {
			if (hdrp[0] != MODINFO_NAME)
				return (-1);
			type = MODINFO_NAME;
		} else {
			if (hdrp[0] == type)
				break;
		}

		switch (hdrp[0]) {
		case MODINFO_NAME:
			md->mname = (const char *)&hdrp[2];
			break;
		case MODINFO_TYPE:
			md->mtype = (const char *)&hdrp[2];
			break;
		case MODINFO_ARGS:
			md->margs = (const char *)&hdrp[2];
			break;
		case MODINFO_ADDR:
			md->maddr = MOD_UINT64(hdrp);
			break;
		case MODINFO_SIZE:
			md->msize = MOD_UINT64(hdrp);
			break;
		default:
			if (hdrp[0] & MODINFO_METADATA) {
				switch (hdrp[0] & ~MODINFO_METADATA) {
				/*
				 * MODINFOMD_AOUTEXEC
				 * MODINFOMD_ELFHDR
				 * MODINFOMD_SSYM
				 * MODINFOMD_ESYM
				 * MODINFOMD_DYNAMIC
				 * MODINFOMD_KERNEND
				 * MODINFOMD_SHDR
				 * MODINFOMD_CTORS_ADDR
				 * MODINFOMD_CTORS_SIZE
				 * MODINFOMD_KEYBUF
				 * MODINFOMD_NOCOPY
				 */
				case MODINFOMD_DTBP:
					/* XXXARM: maybe deal with this? */
					break;
				case MODINFOMD_HOWTO:
					/* XXXARM: deal with this */
					break;
				case MODINFOMD_FW_HANDLE:
					md->systab_addr = MOD_UINT64(hdrp);
					break;
				case MODINFOMD_EFI_FB:
					md->fb_addr = (uint64_t)(
					    hdrp + (sizeof (uint32_t) * 2));
					break;
				case MODINFOMD_ENVP:
					md->env_addr = MOD_UINT64(hdrp);
					break;
				case MODINFOMD_EFI_MAP:
					md->map_addr = (uint64_t)&hdrp[2];
					break;
				case MODINFOMD_FONT:
					/*
					 * XXXARM: this might not be right (it
					 * might not be inline)
					 */
					md->font_addr = (uint64_t)&hdrp[2];
					break;
				default:
					break;
				}
			}

			break;
		}

		next = sizeof (uint32_t) * 2 + mlen;
		next = roundup(next, sizeof (u_long));
		curp += next;
	}

	if (type == 0)
		return (-1);

	if (md->mtype == NULL || md->mname == NULL ||
	    md->maddr == 0 || md->msize == 0)
		return (-1);

	return (0);
}

static int64_t
prekern_calc_env_size(const char *env)
{
	const char	*menv;
	char		c;
	char		lastc;

	if (env == NULL)
		return (-1);

	menv = env;

	for (c = *menv, lastc = 0xff;; c = *++menv) {
		if (c == '\0' && lastc == '\0')
			break;
		lastc = c;
	}

	return (int64_t)(((uint64_t)menv) - ((uint64_t)env));
}

int
prekern_process_modules(caddr_t modulep, struct xboot_info *xbi,
    uint64_t *pmemmap, uint64_t *pfb,
    uint64_t *ppayload, uint64_t *ppayload_size)
{
	caddr_t			curp;
	uint32_t		*hdrp;
	unsigned int		mlen;
	unsigned int		next;
	struct boot_modules	*bm;
	const char		*bootfile;
	const char		*cmdline;

	if (modulep == NULL)
		return (-1);

	bootfile = NULL;
	cmdline = NULL;
	curp = modulep;
	bm = (struct boot_modules *)xbi->bi_modules;

	for (;;) {
		struct module_data_t moddata = {
			0, 0, NULL, NULL, NULL, 0, 0, 0,
		};

		hdrp = (uint32_t *)curp;
		mlen = hdrp[1];

		/*
		 * MODINFO_END signals the end of the TLV module list, so we
		 * use this as an additional input when calculating the last
		 * used address.
		 */
		if (hdrp[0] == MODINFO_END && mlen == 0)
			break;

		if (hdrp[0] == MODINFO_NAME) {
			if (prekern_process_module_info(curp, &moddata) != 0)
				return (-1);

			/*
			 * We have a filled module data structure at this point,
			 * move it into the boot modules array as appropriate
			 * and save other args as needed.
			 */
			if (strcmp(moddata.mtype, "elf kernel") == 0 ||
			    strcmp(moddata.mtype, "elf64 kernel") == 0) {
				/*
				 * The environment is stored as module metadata
				 * of the kernel.
				 */
				if (moddata.env_addr) {
					int64_t sz = prekern_calc_env_size(
					    (const char *)moddata.env_addr);
					if (sz < 0)
						return (-1);
					bm[xbi->bi_module_cnt].bm_addr =
					    moddata.env_addr;
					bm[xbi->bi_module_cnt].bm_name =
					    (uint64_t)&env_boot_module_name[0];
					bm[xbi->bi_module_cnt].bm_size =
					    (uint64_t)sz;
					bm[xbi->bi_module_cnt].bm_type =
					    BMT_ENV;
					xbi->bi_module_cnt++;
				}

				/*
				 * Only the kernel (which is actually this shim)
				 * has arguments that we care about.
				 */
				if (moddata.margs)
					cmdline = moddata.margs;

				/*
				 * UEFI memory map is passed back to the caller
				 * to set up memory management.
				 */
				if (moddata.map_addr && pmemmap)
					*pmemmap = moddata.map_addr;

				/*
				 * The font, if present, will be used by the
				 * tem code and passed to the kernel.
				 *
				 * XXXARM: We're not passing this from the
				 * loader yet. Finish it off when we figure
				 * that out.
				 */
				if (moddata.font_addr) {
#if 0
					dbg2_puts("XXX: stash loader font\r\n");
#endif
				}

				/*
				 * The framebuffer, if present, will be used by
				 * the tem code and passed to the kernel.
				 */
				if (moddata.fb_addr && pfb)
					*pfb = moddata.fb_addr;

				if (moddata.systab_addr)
					xbi->bi_uefi_systab =
					    moddata.systab_addr;
			} else if (strcmp(moddata.mtype, "rootfs") == 0) {
				bm[xbi->bi_module_cnt].bm_addr = moddata.maddr;
				bm[xbi->bi_module_cnt].bm_name =
				    (uint64_t)&rootfs_boot_module_name[0];
				bm[xbi->bi_module_cnt].bm_size = moddata.msize;
				bm[xbi->bi_module_cnt].bm_type = BMT_ROOTFS;
				xbi->bi_module_cnt++;
			} else if (strcmp(moddata.mtype, "payload") == 0) {
				if (ppayload != NULL && ppayload_size != NULL) {
					*ppayload = moddata.maddr;
					*ppayload_size = moddata.msize;
					bootfile = moddata.mname;
				}
			}
		}

		next = sizeof (uint32_t) * 2 + mlen;
		next = roundup(next, sizeof (u_long));
		curp += next;
	}

	if (bootfile == NULL)
		return (-1);
	if (strlen(bootfile) > PAYLOAD_CMDLINE_MAX_LEN)
		return (-1);
	strcpy(paylad_cmdline, bootfile);

	if (cmdline != NULL) {
		if (strlen(paylad_cmdline) + strlen(cmdline) + 1 > PAYLOAD_CMDLINE_MAX_LEN)
			return (-1);
		strcat(paylad_cmdline, " ");
		strcat(paylad_cmdline, cmdline);
	}

	xbi->bi_cmdline = (uint64_t)paylad_cmdline;
	return (0);
}


static const char *
prekern_env_next(const char *cp)
{
	if (cp != NULL) {
		while (*cp != 0)
			++cp;
		cp++;
		if (*cp == 0)
			cp = NULL;
	}

	return (cp);
}


static const char *
prekern_getenv_from(const char *envp, const char *limit, const char *name)
{
	const char *cp, *ep;
	size_t len;

	for (cp = envp; cp != NULL && cp <= limit; cp = prekern_env_next(cp)) {
		for (ep = cp; (*ep != '=') && (*ep != 0); ep++)
			;
		if (*ep != '=')
			continue;
		len = ep - cp;
		ep++;
		if (strncmp(name, cp, len) == 0 && name[len] == 0)
			return (ep);
	}

	return (NULL);
}


const char *
prekern_getenv(struct xboot_info *xbi, const char *name)
{
	struct boot_modules	*bm;
	struct boot_modules	*env;
	uint32_t		i;

	if (xbi->bi_modules == 0 || xbi->bi_module_cnt == 0)
		return (NULL);

	bm = (struct boot_modules *)xbi->bi_modules;
	env = NULL;

	for (i = 0; i < xbi->bi_module_cnt; ++i) {
		if (bm[i].bm_type != BMT_ENV)
			continue;

		env = &bm[i];
		break;
	}

	if (env == NULL)
		return (NULL);

	return prekern_getenv_from(
	    (const char *)env->bm_addr,
	    (const char *)(env->bm_addr + env->bm_size),
	    name);
}

int
prekern_getenv_uint64(struct xboot_info *xbi, const char *name, uint64_t *data)
{
	const char *s;
	char *ep;
	unsigned long ul;

	if (data == NULL)
		return (0);

	s = prekern_getenv(xbi, name);
	if (s == NULL)
		return (-1);

	/* XXXARM: check ep as well */
	ul = strtoul(s, &ep, 10);
	if (ul == EINVAL)
		ul = strtoul(s, &ep, 16);
	/* XXXARM: error checking */

	*data = (uint64_t)ul;
	return (0);
}
