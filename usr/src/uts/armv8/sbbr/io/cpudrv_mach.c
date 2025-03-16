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
 * CPU power management driver - aarch64 SBBR machine-dependent support.
 *
 * Provides the cpudrv_mach interface for SBBR (ACPI) platforms.
 * On attach, cpudrv_mach_init() evaluates the ACPI _LPI method to
 * discover idle states and registers them with the cpuidle framework,
 * then initializes CPPC for frequency scaling.
 *
 * Frequency scaling is provided via ACPI CPPC (Collaborative Processor
 * Performance Control).  The cppc misc module evaluates per-CPU _CPC
 * objects to discover the performance range and register transports,
 * and this file delegates the cpudrv_mach speed interface to it.
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/cpu.h>
#include <sys/cpuvar.h>
#include <sys/cpuinfo.h>
#include <sys/cpuidle.h>
#include <sys/cpupm.h>
#include <sys/cpudrv_mach.h>
#include <sys/acpicppc.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/acpidev.h>

/*
 * DVFS speed enumeration and release.
 *
 * Called by the CPUDRV_GET_SPEEDS / CPUDRV_FREE_SPEEDS macros in the
 * shared cpudrv_mach.h header.  Delegates to the CPPC module which
 * synthesizes a speed table from the _CPC performance range.
 */
int
cpudrv_mach_get_speeds(cpu_t *cp, int **speeds, int *nspeeds)
{
	ASSERT3P(cp, !=, NULL);
	ASSERT3P(speeds, !=, NULL);
	ASSERT3P(nspeeds, !=, NULL);

	return (cppc_get_speeds(cp, speeds, nspeeds));
}

void
cpudrv_mach_free_speeds(int *speeds, int nspeeds)
{
	cppc_free_speeds(speeds, nspeeds);
}

/*
 * FFH (Functional Fixed Hardware) address space ID.
 */
#define	ACPI_FFH_SPACE_ID	0x7F

/*
 * FFH address values for _LPI entry methods.
 */
#define	FFH_ADDR_WFI		0xFFFFFFFFU
#define	FFH_ADDR_WFI_64		0xFFFFFFFFFFFFFFFFULL

/*
 * Resource template header size: large descriptor tag (1 byte) +
 * length field (2 bytes) = 3 bytes before the GAS payload.
 */
#define	GAS_RT_HDR_LEN		3

/*
 * Minimum buffer length for a resource template containing a GAS:
 * 3-byte header + 12-byte ACPI_GENERIC_ADDRESS.
 */
#define	GAS_RT_MIN_LEN		(GAS_RT_HDR_LEN + \
			    sizeof (ACPI_GENERIC_ADDRESS))

/*
 * _LPI package element indices (ACPI 6.5, Table 5.229).
 */
#define	LPI_PKG_MIN_RESIDENCY		0
#define	LPI_PKG_WAKE_LATENCY		1
#define	LPI_PKG_FLAGS			2
#define	LPI_PKG_CTX_LOSS_FLAGS		3
#define	LPI_PKG_ENTRY_METHOD		6
#define	LPI_PKG_STATE_NAME		9
#define	LPI_PKG_MIN_ELEMENTS		10

/*
 * _LPI Flags bit definitions.
 */
#define	LPI_FLAGS_ENABLED		(1U << 0)
#define	LPI_FLAGS_CTX_VALID		(1U << 1)

/*
 * Parse a single _LPI state descriptor from an ACPI package.
 *
 * Returns B_TRUE if the state was successfully parsed and stored in *lsp,
 * B_FALSE otherwise (state skipped).
 */
static boolean_t
lpi_parse_one_state(ACPI_OBJECT *spkg, lpi_state_t *lsp)
{
	ACPI_OBJECT *se;
	ACPI_GENERIC_ADDRESS *gas;
	uint32_t flags;
	uint64_t addr;

	ASSERT3P(spkg, !=, NULL);
	ASSERT3P(lsp, !=, NULL);

	if (spkg->Type != ACPI_TYPE_PACKAGE ||
	    spkg->Package.Count < LPI_PKG_MIN_ELEMENTS) {
		cmn_err(CE_WARN, "!malformed _LPI record");
		return (B_FALSE);
	}

	se = spkg->Package.Elements;

	/* Element 0: MinResidency (Integer, us) */
	if (se[LPI_PKG_MIN_RESIDENCY].Type != ACPI_TYPE_INTEGER) {
		cmn_err(CE_WARN, "!_LPI: min-residency is not an integer");
		return (B_FALSE);
	}
	lsp->ls_min_residency =
	    (uint32_t)se[LPI_PKG_MIN_RESIDENCY].Integer.Value;

	/* Element 1: WorstCaseWakeLatency (Integer, us) */
	if (se[LPI_PKG_WAKE_LATENCY].Type != ACPI_TYPE_INTEGER) {
		cmn_err(CE_WARN, "!_LPI: wake-latency is not an integer");
		return (B_FALSE);
	}
	lsp->ls_wake_latency =
	    (uint32_t)se[LPI_PKG_WAKE_LATENCY].Integer.Value;

	/* Element 2: Flags */
	if (se[LPI_PKG_FLAGS].Type != ACPI_TYPE_INTEGER) {
		cmn_err(CE_WARN, "!_LPI: flags is not an integer");
		return (B_FALSE);
	}
	flags = (uint32_t)se[LPI_PKG_FLAGS].Integer.Value;

	if (!(flags & LPI_FLAGS_ENABLED)) {
		return (B_FALSE);
	}

	/* Element 6: EntryMethod - must be a ResourceTemplate (buffer) */
	if (se[LPI_PKG_ENTRY_METHOD].Type == ACPI_TYPE_BUFFER) {
		if (se[LPI_PKG_ENTRY_METHOD].Buffer.Length < GAS_RT_MIN_LEN) {
			cmn_err(CE_WARN,
			    "!_LPI: entry-method GAS is too short");
			return (B_FALSE);
		}

		gas = (ACPI_GENERIC_ADDRESS *)
		    (se[LPI_PKG_ENTRY_METHOD].Buffer.Pointer + GAS_RT_HDR_LEN);

		if (gas->SpaceId != ACPI_FFH_SPACE_ID) {
			cmn_err(CE_WARN,
			    "!_LPI: entry-method GAS space is not FFH");
			return (B_FALSE);
		}

		addr = gas->Address;

		if (addr == FFH_ADDR_WFI || addr == FFH_ADDR_WFI_64) {
			lsp->ls_entry_type = LPI_ENTRY_WFI;
			lsp->ls_psci_state = 0;
			lsp->ls_ctx_loss_flags = 0;
		} else {
			lsp->ls_entry_type = LPI_ENTRY_PSCI;
			lsp->ls_psci_state = (uint32_t)addr;

			if (flags & LPI_FLAGS_CTX_VALID) {
				if (se[LPI_PKG_CTX_LOSS_FLAGS].Type !=
				    ACPI_TYPE_INTEGER) {
					cmn_err(CE_WARN, "!_LPI: context-loss "
					    "flags is not an integer");
					return (B_FALSE);
				}

				lsp->ls_ctx_loss_flags = (uint32_t)
				    se[LPI_PKG_CTX_LOSS_FLAGS].Integer.Value;
			} else if (addr & PSCI_STATE_TYPE_POWERDOWN) {
				lsp->ls_ctx_loss_flags =
				    LPI_CTX_LOSS_CPU | LPI_CTX_LOSS_TIMER |
				    LPI_CTX_LOSS_GICR;
			} else {
				lsp->ls_ctx_loss_flags = 0;
			}
		}
	} else if (se[LPI_PKG_ENTRY_METHOD].Type == ACPI_TYPE_INTEGER) {
		/*
		 * Raw integer entry method - used by cluster and system
		 * level _LPI.  Not supported at the CPU level.
		 */
		cmn_err(CE_WARN, "!_LPI: entry-method is an integer, "
		    "which is unsupported at the CPU level");
		return (B_FALSE);
	} else {
		cmn_err(CE_WARN,
		    "!_LPI: entry-method is neither an integer nor a buffer");
		return (B_FALSE);
	}

	lsp->ls_enabled = B_TRUE;
	return (B_TRUE);
}

/*
 * Parse _LPI states for a single CPU.
 *
 * Evaluates the _LPI method on the given ACPI handle and builds an array of
 * lpi_state_t descriptors for the valid, enabled states.
 *
 * On success, *statesp and *nstatesp are set; caller must eventually free
 * *statesp with kmem_free(*statesp, *nstatesp * sizeof (lpi_state_t)).
 *
 * If _LPI is absent or contains no valid states, *statesp and *nstatesp
 * are left unchanged.
 */
static void
lpi_parse_states(ACPI_HANDLE cpu_hdl, lpi_state_t **statesp, int *nstatesp)
{
	ACPI_BUFFER buf;
	ACPI_OBJECT *pkg;
	ACPI_STATUS status;
	lpi_state_t *states;
	lpi_state_t *final;
	int count;
	int nvalid;
	int i;

	ASSERT3P(cpu_hdl, !=, NULL);
	ASSERT3P(statesp, !=, NULL);
	ASSERT3P(nstatesp, !=, NULL);

	buf.Length = ACPI_ALLOCATE_BUFFER;
	buf.Pointer = NULL;

	status = AcpiEvaluateObject(cpu_hdl, "_LPI", NULL, &buf);
	if (ACPI_FAILURE(status)) {
		return;	/* probably just not present */
	}

	pkg = (ACPI_OBJECT *)buf.Pointer;
	if (pkg->Type != ACPI_TYPE_PACKAGE || pkg->Package.Count < 3) {
		AcpiOsFree(buf.Pointer);
		cmn_err(CE_WARN, "!_LPI: type is not a valid package "
		    "of three or more elements");
		return;
	}

	/* Element 0: Revision (integer) */
	if (pkg->Package.Elements[0].Type != ACPI_TYPE_INTEGER) {
		AcpiOsFree(buf.Pointer);
		cmn_err(CE_WARN, "!_LPI: package revision is not an integer");
		return;
	}

	/* Element 2: Count of state descriptors */
	if (pkg->Package.Elements[2].Type != ACPI_TYPE_INTEGER) {
		AcpiOsFree(buf.Pointer);
		cmn_err(CE_WARN,
		    "!_LPI: package state count is not an integer");
		return;
	}
	count = (int)pkg->Package.Elements[2].Integer.Value;

	if (count == 0 || pkg->Package.Count < (UINT32)(3 + count)) {
		AcpiOsFree(buf.Pointer);
		cmn_err(CE_WARN, "!_LPI: malformed package");
		return;
	}

	states = kmem_zalloc(count * sizeof (lpi_state_t), KM_SLEEP);
	nvalid = 0;

	for (i = 0; i < count; i++) {
		if (lpi_parse_one_state(&pkg->Package.Elements[3 + i],
		    &states[nvalid])) {
			nvalid++;
		}
	}

	AcpiOsFree(buf.Pointer);

	if (nvalid == 0) {
		kmem_free(states, count * sizeof (lpi_state_t));
		cmn_err(CE_NOTE, "!_LPI: no valid states");
		return;
	}

	/* Shrink allocation to fit */
	if (nvalid < count) {
		final = kmem_alloc(nvalid * sizeof (lpi_state_t), KM_SLEEP);
		memcpy(final, states, nvalid * sizeof (lpi_state_t));
		kmem_free(states, count * sizeof (lpi_state_t));
		states = final;
	}

	*statesp = states;
	*nstatesp = nvalid;
}

/*
 * Determine the cpu_id for the CPU device.
 * SBBR: MPIDR is set as a property by acpidev during enumeration.
 */
boolean_t
cpudrv_get_cpu_id(dev_info_t *dip, processorid_t *cpu_id)
{
	int64_t mpidr;
	processorid_t id;

	ASSERT3P(dip, !=, NULL);
	ASSERT3P(cpu_id, !=, NULL);

	mpidr = ddi_prop_get_int64(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    ACPIDEV_PROP_NAME_MPIDR, -1);
	if (mpidr == -1) {
		return (B_FALSE);
	}

	id = cpuinfo_id_for_mpidr((uint64_t)mpidr);
	if (id < 0) {
		return (B_FALSE);
	}

	*cpu_id = id;
	return (B_TRUE);
}

/*
 * Change CPU speed via CPPC.
 *
 * The common cpudrv_power() calls this with the target speed level.
 * On success, update cpu_curr_clock from the delivered performance.
 * cppc_get_speed() returns MHz; cpu_curr_clock is in Hz.
 */
int
cpudrv_change_speed(cpudrv_devstate_t *cpudsp, cpudrv_pm_spd_t *new_spd)
{
	cpu_t *cp;
	int ret;
	uint64_t clk;

	ASSERT3P(cpudsp, !=, NULL);
	ASSERT3P(new_spd, !=, NULL);

	cp = cpudsp->cp;
	if (cp == NULL) {
		return (DDI_FAILURE);
	}

	ret = cppc_set_speed(cp, new_spd->speed);
	if (ret != DDI_SUCCESS) {
		return (ret);
	}

	clk = cppc_get_speed(cp);
	if (clk != 0) {
		cp->cpu_curr_clock = clk * 1000000ULL;
	}

	return (DDI_SUCCESS);
}

/*
 * All CPUs are always ready for power transitions.
 */
/* ARGSUSED */
boolean_t
cpudrv_power_ready(cpu_t *cp)
{
	return (B_TRUE);
}

/*
 * No governor thread on aarch64.
 */
/* ARGSUSED */
boolean_t
cpudrv_is_governor_thread(cpudrv_pm_t *cpupm)
{
	return (B_FALSE);
}

/*
 * Machine-dependent initialization.
 *
 * Evaluates _LPI to discover idle states and registers them with the
 * cpuidle framework.  If _LPI is absent (e.g. QEMU), cpuidle provides
 * a WFI fallback.
 *
 * After idle state registration, initializes CPPC for this CPU by
 * calling cppc_cpu_init() with the ACPI handle.  CPPC init failure
 * is non-fatal - the CPU simply will not have DVFS support.
 */
boolean_t
cpudrv_mach_init(cpudrv_devstate_t *cpudsp)
{
	ACPI_HANDLE hdl;
	ACPI_STATUS status;
	lpi_state_t *states;
	int nstates;

	ASSERT3P(cpudsp, !=, NULL);

	status = acpica_get_handle(cpudsp->dip, &hdl);
	if (ACPI_FAILURE(status)) {
		/*
		 * No ACPI handle is not an error - cpuidle provides WFI.
		 * Still attach successfully.
		 */
		(void) cpuidle_register_states(cpudsp->cpu_id, NULL, 0);
		return (B_TRUE);
	}

	states = NULL;
	nstates = 0;
	if (acpica_get_plat_osc(PLAT_OSC_PLAT_LPI) != 0) {
		lpi_parse_states(hdl, &states, &nstates);
	}

	/* Register with cpuidle framework (takes ownership of states) */
	(void) cpuidle_register_states(cpudsp->cpu_id, states, nstates);

	/*
	 * Initialize CPPC for this CPU.  Failure is non-fatal - it
	 * simply means DVFS is not available for this CPU.
	 */
	if (acpica_get_plat_osc(PLAT_OSC_CPPC) != 0) {
		(void) cppc_cpu_init(cpudsp->cp, (void *)hdl);
	}

	return (B_TRUE);
}

/*
 * Machine-dependent cleanup (detach).
 */
/* ARGSUSED */
boolean_t
cpudrv_mach_fini(cpudrv_devstate_t *cpudsp)
{
	return (B_TRUE);
}

/*
 * Check whether cpudrv PM is enabled.
 *
 * When called with NULL (from the global attach gate), returns B_TRUE
 * so the driver attaches and cpudrv_mach_init() can register idle
 * states and initialize CPPC.  When called with a per-instance cpudsp
 * (from the PM setup block), returns B_TRUE only if CPPC was
 * successfully initialized for that CPU, enabling the speed governor.
 */
boolean_t
cpudrv_is_enabled(cpudrv_devstate_t *cpudsp)
{
	if (cpudsp == NULL) {
		return (B_TRUE);
	}

	return (cppc_cpu_available(cpudsp->cp));
}

/*
 * Set supported frequencies from CPPC.
 *
 * Retrieves the synthesized speed table from the cppc module and
 * registers it with the cpupm framework for kstat reporting.
 */
void
cpudrv_set_supp_freqs(cpudrv_devstate_t *cpudsp)
{
	int *speeds;
	int nspeeds;

	ASSERT3P(cpudsp, !=, NULL);

	if (cpudrv_mach_get_speeds(cpudsp->cp, &speeds, &nspeeds) !=
	    DDI_SUCCESS) {
		return;
	}
	cpupm_set_supp_freqs(cpudsp->cp, speeds, (uint_t)nspeeds);
	cpudrv_mach_free_speeds(speeds, nspeeds);
}
