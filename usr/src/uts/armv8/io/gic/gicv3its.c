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
	dev_info_t		*sc_dip;
	caddr_t			sc_gits;
	ddi_acc_handle_t	sc_regh;
} gicv3its_sc_t;

#define	GITS_MAX		256
#define	GITS_REG64(sc, offset)	((uint64_t *)((sc)->sc_gits + (offset)))

static void *gicv3its_soft_state;

static int
gicv3its_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int ret;
	int nregs;
	int instance;
	off_t regsize;
	gicv3its_sc_t *sc;

	ddi_device_acc_attr_t gicv3its_reg_acc_attr = {
		.devacc_attr_version		= DDI_DEVICE_ATTR_V0,
		.devacc_attr_endian_flags	= DDI_STRUCTURE_LE_ACC,
		.devacc_attr_dataorder		= DDI_STRICTORDER_ACC
	};


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

	instance = ddi_get_instance(dip);

	if ((ret = ddi_dev_nregs(dip, &nregs)) != DDI_SUCCESS)
		return (ret);

	if (nregs < 1)
		return (DDI_FAILURE);

	if ((ret = ddi_dev_regsize(dip, 0, &regsize)) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if ((ret = ddi_soft_state_zalloc(
	    gicv3its_soft_state, instance)) != DDI_SUCCESS)
		return (ret);
	sc = ddi_get_soft_state(gicv3its_soft_state, instance);
	VERIFY3P(sc, !=, NULL);
	sc->sc_dip = dip;

	if ((ret = ddi_regs_map_setup(dip, 0, &sc->sc_gits, 0, regsize,
	    &gicv3its_reg_acc_attr, &sc->sc_regh)) != DDI_SUCCESS) {
		ddi_soft_state_free(gicv3its_soft_state, instance);
		return (ret);
	}

	ddi_report_dev(dip);
	return (DDI_SUCCESS);
}

static int
gicv3its_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance;
	gicv3its_sc_t *sc;

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:	/* fallthrough */
	case DDI_PM_SUSPEND:	/* fallthrough */
	case DDI_HOTPLUG_DETACH:
		return (DDI_FAILURE);
	default:
		dev_err(dip, CE_NOTE, "Unhandled detach command: %d", (int)cmd);
		return (DDI_FAILURE);
	}
	ASSERT3U(cmd, ==, DDI_DETACH);

	instance = ddi_get_instance(dip);
	sc = ddi_get_soft_state(gicv3its_soft_state, instance);
	VERIFY3P(sc, !=, NULL);
	VERIFY3P(sc->sc_dip, ==, dip);

	ddi_regs_map_free(&sc->sc_regh);
	ddi_soft_state_free(gicv3its_soft_state, instance);
	return (DDI_SUCCESS);
}

static struct dev_ops gicv3its_ops = {
	.devo_rev		= DEVO_REV,
	.devo_refcnt		= 0,
	.devo_getinfo		= ddi_no_info,
	.devo_identify		= nulldev,
	.devo_probe		= nulldev,
	.devo_attach		= gicv3its_attach,
	.devo_detach		= gicv3its_detach,
	.devo_reset		= nodev,
	.devo_cb_ops		= NULL,
	.devo_bus_ops		= NULL,
	.devo_power		= NULL,
	.devo_quiesce		= ddi_quiesce_not_needed,
};

static char modlinkinfo[] =
	"Generic Interrupt Controller v3 Interrupt Translation Service";

static struct modldrv gicv3its_modldrv = {
	.drv_modops		= &mod_driverops,
	.drv_linkinfo		= modlinkinfo,
	.drv_dev_ops		= &gicv3its_ops
};

static struct modlinkage modlinkage = {
	.ml_rev			= MODREV_1,
	.ml_linkage		= { &gicv3its_modldrv, NULL }
};

int
_init(void)
{
	int err;

	if ((err = ddi_soft_state_init(&gicv3its_soft_state,
	    sizeof (gicv3its_sc_t), GITS_MAX)) != 0)
		return (err);

	if ((err = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&gicv3its_soft_state);
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

	ddi_soft_state_fini(&gicv3its_soft_state);
	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
