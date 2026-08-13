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

#ifndef _ACPICA_PCC_IMPL_H
#define	_ACPICA_PCC_IMPL_H

/*
 * PCC (Platform Communications Channel) internal header.
 *
 * This header defines the private structures and interfaces for the
 * PCC implementation in the acpipcc module.  It is shared between
 * pcc.c (common code), pcc_type12.c (Types 1-2), pcc_type34.c
 * (Types 3-4), and pcc_opregion.c (PCC OperationRegion handler).
 *
 * The public API is in <sys/acpipcc.h>.  Nothing in this header is
 * exported via the mapfile.
 */

#include <sys/types.h>
#include <sys/mutex.h>
#include <sys/condvar.h>
#include <sys/list.h>
#include <sys/time.h>
#include <sys/acpi/acpi.h>
#include <sys/acpipcc.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Constants (pcc_impl.h).
 */

/* Microseconds between completion poll loops */
#define	PCC_POLL_INTERVAL_US	10
/*
 * Nominal latency multiplier for the completion timeout.  500x
 * nominal matches Linux; a platform that exceeds its own
 * advertised latency by that margin is treated as failed, and
 * the channel is marked failed (see pc_broken) so later sends
 * fail fast.
 */
#define	PCC_TIMEOUT_MULTIPLIER	500
/* Maximum number of PCC subspaces in the PCCT */
#define	PCC_MAX_CHANNELS	256

/*
 * RASF uses a spec-defined ASCII signature (ACPI 6.6 Table 5.87),
 * not the PCC_SIGNATURE_BASE | subspace_id formula.
 */
#define	PCC_SIGNATURE_RASF	0x52415346u	/* "RASF" */

/*
 * PCC OperationRegion: the region covers shared memory after the
 * 4-byte signature, so the 32-bit Command field at PCC_EXT_SHMEM_CMD
 * (offset 12) appears at OpRegion-relative offset 8.
 */
#define	PCC_OPREGION_CMD_OFFSET	8

/*
 * pto_init tri-state return:
 *   DDI_SUCCESS (0)      channel initialised and usable
 *   PCC_INIT_UNUSABLE (1) firmware description valid, but the channel
 *                        cannot be driven (e.g. Command Complete stuck
 *                        clear); pc_valid stays true, pc_usable false
 *   DDI_FAILURE (-1)     firmware description invalid; fail all PCC/CPPC
 */
#define	PCC_INIT_UNUSABLE	1

/*
 * Per-channel initialisation state flags (pc_init_state bitmask).
 * Cleared to zero on allocation.  Each phase sets its flag on
 * success.  On failure, cleanup tests these flags in reverse
 * order to determine which resources to release.
 */
#define	PCC_INIT_PARSED		(1u << 0)	/* pto_parse succeeded */
#define	PCC_INIT_SHMEM		(1u << 1)	/* pc_shmem_va mapped */
#define	PCC_INIT_MAPPED		(1u << 2)	/* pto_map succeeded */
#define	PCC_INIT_SIG_OK		(1u << 3)	/* signature validated */
#define	PCC_INIT_TYPE		(1u << 4)	/* pto_init succeeded */
#define	PCC_INIT_IRQ_LINKED	(1u << 5)	/* linked into irq group;
						 * group refcount incremented;
						 * handler installed on 0->1 */
#define	PCC_INIT_SYNCH		(1u << 6)	/* mutex/cv initialised */

/*
 * Interrupt check result flags.
 *
 * Flags, not exclusive enum values: Types 1-2 can have both
 * Command Complete and Platform Notification set simultaneously.
 */
typedef enum pcc_irq_result {
	PCC_IRQ_NONE		= 0,		/* not for this channel */
	PCC_IRQ_CMD_COMPLETE	= (1 << 0),	/* command response ready */
	PCC_IRQ_NOTIFY		= (1 << 1)	/* platform notification pending */
} pcc_irq_result_t;

/*
 * Register registry entry.
 *
 * Shared doorbell/ack/command-complete/error registers are
 * reference-counted so that multiple channels using the same
 * physical register share a single mapping.
 */
typedef struct pcc_reg_entry {
	uint64_t	pre_addr;	/* GAS Address (PA for MMIO) */
	uint8_t		pre_space_id;	/* GAS AddressSpaceId */
	uint8_t		pre_width;	/* register bit width (32 or 64) */
	caddr_t		pre_va;		/* mapped VA (MMIO only) */
	kmutex_t	pre_lock;	/* RMW serialization */
	uint_t		pre_refcnt;	/* number of channels using this reg */
	list_node_t	pre_node;	/* linkage in pcc_reg_list */
} pcc_reg_entry_t;

/*
 * Per-GSIV interrupt group.
 *
 * Channels sharing a platform interrupt GSIV are linked into a
 * group.  The interrupt handler receives the group as its argument
 * and walks only the channels that could have fired.
 */
typedef struct pcc_irq_group {
	uint32_t	pig_gsiv;
	boolean_t	pig_edge;	/* edge (true) or level */
	uint_t		pig_ipl;	/* interrupt priority level */
	uint_t		pig_refcnt;	/* channels using this GSIV;
					 * handler installed on 0->1,
					 * removed on 1->0 */
	uint32_t	pig_active;	/* handler invocations currently
					 * in flight (atomic_inc_32 on
					 * entry, atomic_dec_32 on
					 * exit); drained before the
					 * group is freed */
	list_t		pig_channels;	/* list of pcc_chan_t on this GSIV */
	list_node_t	pig_node;	/* linkage in pcc_irq_group_list */
} pcc_irq_group_t;

/*
 * Type-specific operations vector.
 */
typedef struct pcc_type_ops {
	int	(*pto_parse)(void *subtable, pcc_chan_t *pc);
					/* extract fields from ACPICA
					 * struct into pcc_chan_t;
					 * MUST set pc_id from the
					 * subtable's subspace ID
					 * field (the firmware
					 * identifier); store raw
					 * GAS fields (address,
					 * space_id, width,
					 * bit_offset, access_size)
					 * but do NOT create registry
					 * entries or map anything */
	int	(*pto_map)(pcc_chan_t *pc);
					/* create register registry
					 * entries and map MMIO via
					 * pcc_reg_lookup_or_create;
					 * all registry entries for
					 * this channel are created
					 * here; on failure, unwind
					 * (release) any entries
					 * already created before
					 * returning, so no partial
					 * state is left behind */
	int	(*pto_init)(pcc_chan_t *pc);
					/* post-map init, NULL if none.
					 * Returns DDI_SUCCESS (usable),
					 * PCC_INIT_UNUSABLE (valid
					 * firmware, channel cannot be
					 * driven), or DDI_FAILURE
					 * (firmware invalid, fail all).
					 * PCC_INIT_UNUSABLE is 1,
					 * distinct from DDI_SUCCESS (0)
					 * and DDI_FAILURE (-1). */
	void	(*pto_unmap)(pcc_chan_t *pc);
					/* release all registry entries
					 * created by pto_map (decrement
					 * refcnt, unmap+free if zero) */
	int	(*pto_prepare_send)(pcc_chan_t *pc, uint32_t cmd,
			uint32_t payload_len, boolean_t trylock);
					/* NULL for Type 4.
					 * If trylock is B_TRUE, the call
					 * is on the panic path of
					 * pcc_chan_send_nowait: the
					 * implementation must not block
					 * on register locks.  It acquires
					 * the registers it needs with
					 * try-lock, holding the doorbell
					 * lock across the Command Complete
					 * clear and the doorbell write,
					 * and returns EBUSY if any needed
					 * lock is busy (only before
					 * ownership is transferred, so the
					 * send stays retryable).  On
					 * DDI_SUCCESS the doorbell has
					 * been rung; the caller must not
					 * ring it again. */
	int	(*pto_poll_complete)(pcc_chan_t *pc, boolean_t *responded);
	int	(*pto_check_error)(pcc_chan_t *pc);
	int	(*pto_irq_check)(pcc_chan_t *pc,
			pcc_irq_result_t *result);
					/* READ-ONLY ownership peek.
					 * Examines the channel's
					 * completion indicator
					 * without modifying any
					 * state.  Sets *result to
					 * PCC_IRQ_NONE (not for this
					 * channel), PCC_IRQ_CMD_COMPLETE,
					 * PCC_IRQ_NOTIFY, or a bitwise
					 * OR.  Must NOT clear status
					 * bits, ACK interrupts, or
					 * signal completion.  The
					 * handler calls this to
					 * determine ownership before
					 * ACKing (shared GSIVs) or
					 * after ACKing (sole GSIVs).
					 * Clearing happens elsewhere:
					 * Types 1-2 Platform IRQ bit
					 * cleared by handler;
					 * Types 1-2 Notify bits cleared
					 * by pcc_type12_clear_notify
					 * (called from
					 * pcc_notify_channel before
					 * the callback); Types 3-4
					 * use the Ack register (written
					 * by handler via
					 * pcc_write_ack). */
	boolean_t pto_edge_only_irq;
					/* if true, the type's platform
					 * interrupt must be
					 * edge-triggered (ACPI 6.6
					 * s14.1.4: Type 1 provides no
					 * way to clear a
					 * level-triggered interrupt);
					 * common code falls back to
					 * polling-only mode otherwise
					 * (pc_has_irq = B_FALSE).
					 * Set for Type 1 only. */
	boolean_t pto_irq_required;
					/* if true, the channel is
					 * non-functional without its
					 * platform interrupt; a pure
					 * OS-side installation failure
					 * marks the channel unusable
					 * instead of falling back to
					 * polling.  Set for Type 4
					 * (responder) only. */
} pcc_type_ops_t;

/*
 * PCC channel.
 *
 * pc_id is the firmware subspace ID (from the PCCT subtable); this
 * is what firmware passes around as the identifier.  pcc_chan_get
 * takes this ID.  pc_idx is the array index in pcc_channels[];
 * not necessarily equal to pc_id.
 */
typedef struct pcc_chan {
	uint32_t		pc_id;		/* firmware subspace ID */
	uint32_t		pc_idx;		/* index in pcc_channels[] */
	uint8_t			pc_type;	/* ACPI subspace type (1-4) */
	boolean_t		pc_valid;	/* firmware description accepted */
	boolean_t		pc_usable;	/* OS bring-up completed;
						 * pcc_chan_get requires
						 * pc_usable */
	boolean_t		pc_opregion;	/* in use by a PCC
						 * OperationRegion handler;
						 * pcc_chan_get returns NULL
						 * if set; set/cleared by
						 * pcc_opregion_setup under
						 * pc_lock */
	uint_t			pc_refcnt;	/* consumers holding this channel
						 * via pcc_chan_get; ACPI 6.6
						 * s8.4.6.1.9 REQUIRES CPPC CPUs
						 * in the same _PSD domain to
						 * share a subspace, so a
						 * refcount (not boolean) is
						 * required */
	const pcc_type_ops_t	*pc_ops;	/* type-specific operations */
	uint_t			pc_init_state;	/* bitmask of completed init
						 * phases (PCC_INIT_*) */

	/* Shared memory */
	uint64_t		pc_shmem_pa;	/* physical address */
	uint64_t		pc_shmem_len;	/* length from PCCT */
	caddr_t			pc_shmem_va;	/* mapped VA (normal memory) */
	uint32_t		pc_hdr_len;	/* PCC_SHMEM_HDR_LEN (8) for
						 * Types 0-2, or
						 * PCC_EXT_SHMEM_HDR_LEN (16)
						 * for Types 3-4; set at parse */
	uint32_t		pc_signature;	/* expected PCC signature */

	/*
	 * Raw GAS fields extracted by pto_parse.  Consumed by pto_map
	 * to create register registry entries.
	 */
	struct {
		uint64_t	addr;
		uint8_t		space_id;
		uint8_t		width;
		uint8_t		bit_offset;
		uint8_t		access_size;
	} pc_db_gas, pc_ack_gas, pc_cc_check_gas, pc_cc_update_gas,
		pc_err_gas;

	/* Doorbell */
	pcc_reg_entry_t		*pc_db_reg;	/* doorbell register */
	uint64_t		pc_db_preserve;	/* doorbell preserve mask */
	uint64_t		pc_db_set;	/* doorbell set mask */
	boolean_t		pc_has_doorbell; /* false if GAS all zeros
						  * (optional for Type 4) */

	/* Ack register (Types 2, 3, 4) */
	pcc_reg_entry_t		*pc_ack_reg;
	uint64_t		pc_ack_preserve;
	uint64_t		pc_ack_set;

	/* Command Complete registers (Types 3, 4) */
	pcc_reg_entry_t		*pc_cc_check_reg;
	uint64_t		pc_cc_check_mask;
	pcc_reg_entry_t		*pc_cc_update_reg;
	uint64_t		pc_cc_update_preserve;
	uint64_t		pc_cc_update_set;

	/* Error Status register (Types 3, 4) */
	pcc_reg_entry_t		*pc_err_reg;
	uint64_t		pc_err_mask;

	/* Interrupt */
	uint32_t		pc_gsiv;	/* platform interrupt GSI */
	uint8_t			pc_irq_flags;	/* edge/level, polarity */
	boolean_t		pc_has_irq;	/* GSIV present and global flag */
	list_node_t		pc_irq_node;	/* linkage in pcc_irq_group_t */

	/* Timing */
	uint32_t		pc_nominal_lat;	/* nominal latency (usec) */
	uint32_t		pc_max_rate;	/* max periodic access rate
						 * (commands/min, 0=unlimited) */
	uint32_t		pc_turnaround;	/* min request turnaround (usec) */
	hrtime_t		pc_last_send;	/* hrtime of last send attempt;
						 * recorded even when the send
						 * fails: attempts put load on the
						 * firmware, so rate limiting
						 * must account for them */

	/* Channel health */
	boolean_t		pc_broken;	/* set when a command times
						 * out: the platform is not
						 * responding.  All future
						 * sends fail fast; never
						 * cleared */

	/* Synchronization */
	kmutex_t		pc_lock;	/* channel mutex */
	kcondvar_t		pc_cv;		/* completion cv */
	boolean_t		pc_cmd_complete; /* set by irq handler before
						  * cv_signal; predicate for
						  * pcc_wait_irq; cleared
						  * before doorbell */

	/* Notification callback */
	pcc_notify_fn_t		pc_notify_fn;	/* registered callback (or NULL) */
	void			*pc_notify_arg;
} pcc_chan_t;

/*
 * Type ops vectors, defined non-static in their type files.
 */
extern const pcc_type_ops_t pcc_type1_ops;
extern const pcc_type_ops_t pcc_type2_ops;
extern const pcc_type_ops_t pcc_type3_ops;
extern const pcc_type_ops_t pcc_type4_ops;

/*
 * Module globals, defined non-static in pcc.c.
 */
extern volatile boolean_t pcc_initialised;

/*
 * Module-private helpers.
 *
 * Defined in pcc.c, declared here, callable by the type handler
 * files and the OpRegion handler.  Not exported via the mapfile.
 * pcc_chan_lookup is deliberately NOT static: pcc_opregion.c
 * needs to call it.
 */

/* Register registry */
pcc_reg_entry_t	*pcc_reg_lookup_or_create(uint64_t addr, uint8_t space_id,
			uint8_t width);
void		pcc_reg_release(pcc_reg_entry_t **regp);
void		pcc_reg_read(pcc_reg_entry_t *reg, uint64_t *val);
void		pcc_reg_write(pcc_reg_entry_t *reg, uint64_t val);
void		pcc_reg_rmw(pcc_reg_entry_t *reg, uint64_t preserve,
			uint64_t set);
void		pcc_reg_rmw_locked(pcc_reg_entry_t *reg, uint64_t preserve,
			uint64_t set);

/* Doorbell and interrupt ACK */
void		pcc_ring_doorbell(pcc_chan_t *pc);
void		pcc_write_ack(pcc_chan_t *pc);

/* Interrupt group management */
int		pcc_irq_group_add(uint32_t gsiv, uint8_t flags,
			pcc_chan_t *pc);
void		pcc_irq_group_remove(pcc_chan_t *pc);
void		pcc_irq_groups_destroy(void);

/* Shared memory mapping (KPM) */
caddr_t		pcc_map_shmem(uint64_t pa, uint64_t len);

/*
 * Internal channel lookup by firmware subspace ID.
 *
 * Used by pcc_opregion_setup and other internal callers that need
 * to distinguish "not found" from "in use".  Does not check
 * pc_usable, pc_opregion, or pc_refcnt; the caller is responsible
 * for those checks under pc_lock.  Module-private (not static)
 * so pcc_opregion.c can call it.
 */
pcc_chan_t	*pcc_chan_lookup(uint32_t subspace_id);

/* Type-specific helpers called across files */
void		pcc_type12_clear_notify(pcc_chan_t *pc);
void		pcc_type4_respond(pcc_chan_t *pc);

extern void pcc_enforce_timing(pcc_chan_t *pc);

#ifdef __cplusplus
}
#endif

#endif /* _ACPICA_PCC_IMPL_H */
