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
        dev_info_t              *gc_dip;
	caddr_t			gc_gv2m;
	ddi_acc_handle_t	gc_regh;
        uint32_t                gc_base_spi;
        uint32_t                gc_num_spis;
} gicv2m_sc_t;

#define GV2M_REG32(sc, offset)    ((uint32_t *)((sc)->gc_gv2m + (offset)))

static void *gicv2m_soft_state;

static int
gicv2m_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int ret;
	int nregs;
	int instance;
	off_t regsize;
        uint32_t typer;
        uint32_t base_spi;
        uint32_t num_spis;
	gicv2m_sc_t *gc;

	ddi_device_acc_attr_t gicv2m_reg_acc_attr = {
		.devacc_attr_version		= DDI_DEVICE_ATTR_V0,
		.devacc_attr_endian_flags	= DDI_STRUCTURE_LE_ACC,
		.devacc_attr_dataorder		= DDI_STRICTORDER_ACC
	};

	switch (cmd) {
	case DDI_RESUME:
		return (DDI_SUCCESS);
	case DDI_ATTACH:
		break;
	default:
		panic("Unhandled attach command: %d", (int)cmd);
	}

	instance = ddi_get_instance(dip);

	if ((ret = ddi_dev_nregs(dip, &nregs)) != DDI_SUCCESS)
		return (ret);

	if (nregs < 1)
		return (DDI_FAILURE);

	if ((ret = ddi_dev_regsize(dip, 0, &regsize)) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if ((ret = ddi_soft_state_zalloc(
	    gicv2m_soft_state, instance)) != DDI_SUCCESS)
		return (ret);
	gc = ddi_get_soft_state(gicv2m_soft_state, instance);
	VERIFY3P(gc, !=, NULL);
        gc->gc_dip = dip;

	if ((ret = ddi_regs_map_setup(dip, 0, &gc->gc_gv2m, 0, regsize,
	    &gicv2m_reg_acc_attr, &gc->gc_regh)) != DDI_SUCCESS) {
		ddi_soft_state_free(gicv2m_soft_state, instance);
		return (ret);
	}

        typer = ddi_get32(gc->gc_regh, GV2M_REG32(gc, GV2M_TYPER));
        base_spi = (typer >> GV2M_TYPER_BASE_SHIFT) & GV2M_TYPER_BASE_MASK;
        num_spis = (typer >> GV2M_TYPER_NUMBER_SHIFT) & GV2M_TYPER_NUMBER_MASK;

        gc->gc_base_spi = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
            DDI_PROP_DONTPASS, "arm,msi-base-spi", base_spi);
        gc->gc_num_spis = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
            DDI_PROP_DONTPASS, "arm,msi-num-spis", num_spis);

        dev_err(dip, CE_CONT, "?%u MSI/MSI-X interrupts starting at SPI %u\n",
            gc->gc_num_spis, gc->gc_base_spi);

        /*
         * XXXARM: register with the parent GIC
         */
	ddi_report_dev(dip);
	return (DDI_SUCCESS);
}

static int
gicv2m_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
        int instance;
        gicv2m_sc_t *gc;

        switch (cmd) {
        case DDI_DETACH:
                break;
        default:
                return (DDI_FAILURE);
        }

        instance = ddi_get_instance(dip);
	gc = ddi_get_soft_state(gicv2m_soft_state, instance);
	VERIFY3P(gc, !=, NULL);
        VERIFY3P(gc->gc_dip, ==, dip);

        /*
         * XXXARM: when we're registering with the parent GIC we should
         * also deregister here.
         */
        ddi_regs_map_free(&gc->gc_regh);
        ddi_soft_state_free(gicv2m_soft_state, instance);
        return (DDI_SUCCESS);
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
