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
 * /dev/efi - UEFI variable access pseudo-device driver.
 *
 * Provides userland access to UEFI Runtime Services variable
 * operations via ioctl:
 *
 *   EFIIOC_VAR_GET  - GetVariable
 *   EFIIOC_VAR_SET  - SetVariable
 *   EFIIOC_VAR_NEXT - GetNextVariableName
 *
 * The driver is a thin copyin/copyout shim over the kernel's
 * efi_get_variable(), efi_set_variable(), and
 * efi_get_next_variable_name() wrappers.  Those wrappers handle
 * all the heavy lifting: RT lock serialisation, TTBR0 page table
 * switching, FPU state management, dedicated firmware stack, and
 * on_trap fault protection.
 *
 * Privilege model:
 *   - Reading variables (VAR_GET, VAR_NEXT) requires no special
 *     privilege.  UEFI variables are not secret; firmware exposes
 *     them freely to any OS caller.
 *   - Writing variables (VAR_SET) requires PRIV_SYS_CONFIG.
 *     Modifying boot variables or secure boot state is a
 *     privileged operation.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/policy.h>
#include <sys/kmem.h>
#include <sys/file.h>
#include <sys/efi.h>
#include <sys/efirt.h>
#include <sys/efiio.h>
#include <sys/machsystm.h>

/*
 * Maximum sizes for userland buffers.  These are sanity limits
 * to prevent userland from asking us to allocate unreasonable
 * amounts of kernel memory.
 *
 * UEFI variable names are typically short (< 256 bytes).
 * The UEFI specification does not mandate a maximum variable
 * data size, but 32KB covers all practical cases (boot entries,
 * certificates, etc.).
 */
#define	EFIDEV_MAX_NAME_SIZE	1024
#define	EFIDEV_MAX_DATA_SIZE	(32 * 1024)

static dev_info_t *efidev_dip;

/*
 * Translate an EFI status code to an errno value.
 */
static int
efidev_efi_to_errno(uint64_t status)
{
	switch (status) {
	case EFI_SUCCESS:
		return (0);
	case EFI_NOT_FOUND:
		return (ENOENT);
	case EFI_BUFFER_TOO_SMALL:
		return (EOVERFLOW);
	case EFI_UNSUPPORTED:
		return (ENOTSUP);
	case EFI_DEVICE_ERROR:
		return (EIO);
	case EFI_INVALID_PARAMETER:
		return (EINVAL);
	case EFI_SECURITY_VIOLATION:
		return (EACCES);
	case EFI_WRITE_PROTECTED:
		return (EROFS);
	default:
		return (EIO);
	}
}

/*
 * EFIIOC_VAR_GET ioctl handler.
 */
static int
efidev_var_get(intptr_t arg, int mode)
{
	efi_var_ioc_t	ev;
	uint16_t	*name = NULL;
	void		*data = NULL;
	uint32_t	attrs = 0;
	uint64_t	data_size;
	size_t		alloc_data_size;
	uint64_t	status;
	int		rv = 0;

	if (ddi_copyin((void *)arg, &ev, sizeof (ev), mode) != 0)
		return (EFAULT);

	if (ev.vi_name == NULL || ev.vi_name_size == 0 ||
	    ev.vi_name_size > EFIDEV_MAX_NAME_SIZE)
		return (EINVAL);

	if (ev.vi_name_size % sizeof (uint16_t) != 0)
		return (EINVAL);

	if (ev.vi_data_size > EFIDEV_MAX_DATA_SIZE)
		return (EINVAL);

	name = kmem_alloc(ev.vi_name_size, KM_SLEEP);
	if (ddi_copyin(ev.vi_name, name, ev.vi_name_size,
	    mode) != 0) {
		rv = EFAULT;
		goto out;
	}

	/*
	 * Validate UCS-2 NUL termination.  Firmware will scan
	 * the name until it finds 0x0000; an unterminated buffer
	 * could cause firmware to read past our allocation.
	 */
	if (name[ev.vi_name_size / sizeof (uint16_t) - 1] != 0) {
		rv = EINVAL;
		goto out;
	}

	alloc_data_size = ev.vi_data_size;
	data_size = ev.vi_data_size;
	if (alloc_data_size > 0) {
		data = kmem_alloc(alloc_data_size, KM_SLEEP);
	}

	status = efi_get_variable(name, &ev.vi_vendor, &attrs,
	    &data_size, data);

	if (status == EFI_BUFFER_TOO_SMALL) {
		/*
		 * Return the required size so the caller can
		 * retry with an adequately sized buffer.
		 */
		ev.vi_data_size = (size_t)data_size;
		if (ddi_copyout(&ev, (void *)arg,
		    sizeof (ev), mode) != 0)
			rv = EFAULT;
		else
			rv = EOVERFLOW;
		goto out;
	}

	if (status != EFI_SUCCESS) {
		rv = efidev_efi_to_errno(status);
		goto out;
	}

	/*
	 * Clamp the firmware-returned data_size to our allocation.
	 * A well-behaved firmware returns data_size <= alloc_data_size
	 * on EFI_SUCCESS, but a buggy one could return more and we
	 * must not copyout past our buffer (kernel heap disclosure).
	 */
	if (data_size > alloc_data_size)
		data_size = alloc_data_size;

	/* Copy data out to userland. */
	if (data_size > 0 && ev.vi_data != NULL) {
		if (ddi_copyout(data, ev.vi_data,
		    (size_t)data_size, mode) != 0) {
			rv = EFAULT;
			goto out;
		}
	}

	ev.vi_attrib = attrs;
	ev.vi_data_size = (size_t)data_size;
	if (ddi_copyout(&ev, (void *)arg,
	    sizeof (ev), mode) != 0)
		rv = EFAULT;

out:
	if (name != NULL)
		kmem_free(name, ev.vi_name_size);
	if (data != NULL)
		kmem_free(data, alloc_data_size);
	return (rv);
}

/*
 * EFIIOC_VAR_SET ioctl handler.
 */
static int
efidev_var_set(intptr_t arg, int mode, cred_t *cr)
{
	efi_var_ioc_t	ev;
	uint16_t	*name = NULL;
	void		*data = NULL;
	uint64_t	status;
	int		rv = 0;

	/* Writing variables is a privileged operation. */
	if (secpolicy_sys_config(cr, B_FALSE) != 0)
		return (EPERM);

	if (ddi_copyin((void *)arg, &ev, sizeof (ev), mode) != 0)
		return (EFAULT);

	if (ev.vi_name == NULL || ev.vi_name_size == 0 ||
	    ev.vi_name_size > EFIDEV_MAX_NAME_SIZE)
		return (EINVAL);

	if (ev.vi_name_size % sizeof (uint16_t) != 0)
		return (EINVAL);

	if (ev.vi_data_size > EFIDEV_MAX_DATA_SIZE)
		return (EINVAL);

	name = kmem_alloc(ev.vi_name_size, KM_SLEEP);
	if (ddi_copyin(ev.vi_name, name, ev.vi_name_size,
	    mode) != 0) {
		rv = EFAULT;
		goto out;
	}

	/* Validate UCS-2 NUL termination. */
	if (name[ev.vi_name_size / sizeof (uint16_t) - 1] != 0) {
		rv = EINVAL;
		goto out;
	}

	if (ev.vi_data_size > 0) {
		if (ev.vi_data == NULL) {
			rv = EINVAL;
			goto out;
		}
		data = kmem_alloc(ev.vi_data_size, KM_SLEEP);
		if (ddi_copyin(ev.vi_data, data,
		    ev.vi_data_size, mode) != 0) {
			rv = EFAULT;
			goto out;
		}
	}

	status = efi_set_variable(name, &ev.vi_vendor,
	    ev.vi_attrib, (uint64_t)ev.vi_data_size, data);

	rv = efidev_efi_to_errno(status);

out:
	if (name != NULL)
		kmem_free(name, ev.vi_name_size);
	if (data != NULL)
		kmem_free(data, ev.vi_data_size);
	return (rv);
}

/*
 * EFIIOC_VAR_NEXT ioctl handler.
 */
static int
efidev_var_next(intptr_t arg, int mode)
{
	efi_var_ioc_t	ev;
	uint16_t	*name = NULL;
	uint64_t	name_size;
	size_t		alloc_name_size;
	uint64_t	status;
	int		rv = 0;

	if (ddi_copyin((void *)arg, &ev, sizeof (ev), mode) != 0)
		return (EFAULT);

	if (ev.vi_name == NULL || ev.vi_name_size == 0 ||
	    ev.vi_name_size > EFIDEV_MAX_NAME_SIZE)
		return (EINVAL);

	if (ev.vi_name_size % sizeof (uint16_t) != 0)
		return (EINVAL);

	alloc_name_size = ev.vi_name_size;
	name = kmem_alloc(alloc_name_size, KM_SLEEP);
	if (ddi_copyin(ev.vi_name, name, alloc_name_size,
	    mode) != 0) {
		rv = EFAULT;
		goto out;
	}

	/*
	 * For VAR_NEXT, the initial call uses an empty (NUL-only)
	 * name; subsequent calls seed with the previous name.
	 * Either way the buffer must be NUL-terminated.
	 */
	if (name[ev.vi_name_size / sizeof (uint16_t) - 1] != 0) {
		rv = EINVAL;
		goto out;
	}

	name_size = alloc_name_size;

	status = efi_get_next_variable_name(&name_size, name,
	    &ev.vi_vendor);

	if (status == EFI_BUFFER_TOO_SMALL) {
		ev.vi_name_size = (size_t)name_size;
		if (ddi_copyout(&ev, (void *)arg,
		    sizeof (ev), mode) != 0)
			rv = EFAULT;
		else
			rv = EOVERFLOW;
		goto out;
	}

	if (status != EFI_SUCCESS) {
		rv = efidev_efi_to_errno(status);
		goto out;
	}

	/*
	 * Clamp the firmware-returned name_size to our allocation.
	 * Same defensive measure as efidev_var_get for data_size:
	 * buggy firmware must not cause us to copyout past our buffer.
	 */
	if (name_size > alloc_name_size)
		name_size = alloc_name_size;

	/* Copy updated name back to userland. */
	if (ddi_copyout(name, ev.vi_name,
	    (size_t)name_size, mode) != 0) {
		rv = EFAULT;
		goto out;
	}

	ev.vi_name_size = (size_t)name_size;
	if (ddi_copyout(&ev, (void *)arg,
	    sizeof (ev), mode) != 0)
		rv = EFAULT;

out:
	if (name != NULL)
		kmem_free(name, alloc_name_size);
	return (rv);
}

/* ARGSUSED */
static int
efidev_open(dev_t *devp, int flag, int otyp, cred_t *cr)
{
	if (otyp != OTYP_CHR)
		return (EINVAL);

	if (!efirt_is_active())
		return (ENXIO);

	return (0);
}

/* ARGSUSED */
static int
efidev_close(dev_t dev, int flag, int otyp, cred_t *cr)
{
	return (0);
}

/* ARGSUSED */
static int
efidev_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
    cred_t *cr, int *rvalp)
{
	switch (cmd) {
	case EFIIOC_VAR_GET:
		return (efidev_var_get(arg, mode));
	case EFIIOC_VAR_SET:
		return (efidev_var_set(arg, mode, cr));
	case EFIIOC_VAR_NEXT:
		return (efidev_var_next(arg, mode));
	default:
		return (ENOTTY);
	}
}

/* ARGSUSED */
static int
efidev_info(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
    void **resultp)
{
	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*resultp = efidev_dip;
		return (DDI_SUCCESS);
	case DDI_INFO_DEVT2INSTANCE:
		*resultp = (void *)0;
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

static int
efidev_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (ddi_create_minor_node(dip, "efi", S_IFCHR, 0,
	    DDI_PSEUDO, 0) != DDI_SUCCESS) {
		ddi_remove_minor_node(dip, NULL);
		return (DDI_FAILURE);
	}

	efidev_dip = dip;
	return (DDI_SUCCESS);
}

static int
efidev_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	ddi_remove_minor_node(dip, NULL);
	efidev_dip = NULL;
	return (DDI_SUCCESS);
}

static struct cb_ops efidev_cb_ops = {
	efidev_open,		/* open */
	efidev_close,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	efidev_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* streamtab */
	D_NEW | D_MP,		/* driver compat flag */
	CB_REV,			/* cb_rev */
	nodev,			/* aread */
	nodev			/* awrite */
};

static struct dev_ops efidev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt */
	efidev_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	efidev_attach,		/* attach */
	efidev_detach,		/* detach */
	nodev,			/* reset */
	&efidev_cb_ops,		/* driver operations */
	(struct bus_ops *)0,	/* bus operations */
	nulldev,		/* power */
	ddi_quiesce_not_needed	/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"UEFI variable access",
	&efidev_ops
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
