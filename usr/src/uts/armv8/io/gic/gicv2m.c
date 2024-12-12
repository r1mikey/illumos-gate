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
 * Copyright 2024 Michael van der Westhuizen
 */

#include <sys/types.h>
#include <sys/gic.h>
#include <sys/gic_reg.h>
#include <sys/avintr.h>
#include <sys/smp_impldefs.h>
#include <sys/sunddi.h>
#include <sys/promif.h>
#include <sys/cpuinfo.h>
#include <sys/sysmacros.h>
#include <sys/archsystm.h>

typedef struct {
	dev_info_t		*gc_dip;
	caddr_t			gc_gv2m;
	ddi_acc_handle_t	gc_regh;
	uint32_t		gc_base_spi;
	uint32_t		gc_num_spis;
} gicv2m_sc_t;

#define	GV2M_REG32(sc, offset)	((uint32_t *)((sc)->gc_gv2m + (offset)))

static void *gicv2m_soft_state;

static int
gicv2m_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:	/* fallthrough */
	case DDI_PM_RESUME:
		return (DDI_SUCCESS);
	default:
		dev_err(dip, CE_NOTE, "Unhandled attach command: %d", (int)cmd);
		return (DDI_FAILURE);
	}
	ASSERT3U(cmd, ==, DDI_ATTACH);

	ddi_report_dev(dip);
	return (DDI_SUCCESS);
}

static int
gicv2m_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	return (DDI_FAILURE);
}

static struct dev_ops gicv2m_ops = {
	.devo_rev		= DEVO_REV,
	.devo_refcnt		= 0,
	.devo_getinfo		= ddi_no_info,
	.devo_identify		= nulldev,
	.devo_probe		= nulldev,
	.devo_attach		= gicv2m_attach,
	.devo_detach		= gicv2m_detach,
	.devo_reset		= nodev,
	.devo_cb_ops		= NULL,
	.devo_bus_ops		= NULL,
	.devo_power		= NULL,
	.devo_quiesce		= ddi_quiesce_not_needed,
};

static char modlinkinfo[] =
	"Generic Interrupt Controller v2 MSI Frame";

static struct modldrv gicv2m_modldrv = {
	.drv_modops		= &mod_driverops,
	.drv_linkinfo		= modlinkinfo,
	.drv_dev_ops		= &gicv2m_ops
};

static struct modlinkage modlinkage = {
	.ml_rev			= MODREV_1,
	.ml_linkage		= { &gicv2m_modldrv, NULL }
};

int
_init(void)
{
	int err;

	if ((err = ddi_soft_state_init(&gicv2m_soft_state,
	    sizeof (gicv2m_sc_t), 16)) != 0)
		return (err);

	if ((err = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&gicv2m_soft_state);
		return (err);
	}

	return (err);
}

int
_fini(void)
{
	int err;

	if ((err = mod_remove(&modlinkage)))
		return (err);

	ddi_soft_state_fini(&gicv2m_soft_state);
	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
