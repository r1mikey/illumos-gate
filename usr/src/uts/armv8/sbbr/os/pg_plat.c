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
 * Processor Group platform support for ACPI-based aarch64 systems.
 *
 * This file shadows armv8/os/pg_plat.c on ACPI (SBBR) platforms, providing
 * authoritative processor topology derived from the PPTT (Processor Properties
 * Topology Table) defined in ACPI 6.2+.
 *
 * PPTT describes a tree of processor nodes (packages, clusters, cores) and
 * cache nodes with explicit sharing relationships.  This replaces the
 * MPIDR-based guesswork in the base pg_plat.c, which cannot accurately
 * reflect cache sharing or physical package boundaries because MPIDR
 * encoding is implementation-defined.
 *
 * Design:
 *
 *   pg_plat_set_fw() is called from mlsetup() before pg_cpu_bootstrap(),
 *   receiving the physical address of the PPTT from dboot via xboot_info.
 *   The table is still mapped at this point (all firmware memory is
 *   accessible until bootstrap memory is released).
 *
 *   Parsing is done in two passes:
 *
 *     Pass 1: Walk every leaf processor node (ACPI_PROCESSOR_ID_VALID set).
 *       For each, look up the processorid_t via cpuinfo_id_for_uid().  Walk
 *       the parent chain to find the physical package (ACPI_PPTT_PHYSICAL_
 *       PACKAGE flag) and any intermediate cluster nodes.  Walk the private
 *       resource list to find cache references, then follow NextLevelOfCache
 *       chains to the terminal (highest-level) cache node.  Record each
 *       CPU's terminal cache node offset and populate package/cluster/core
 *       IDs in the static pptt_info[NCPU] lookup table.
 *
 *     Pass 2: Determine shared caches.  Count how many CPUs reference each
 *       terminal cache node offset.  A cache node referenced by more than
 *       one CPU is shared.  For each CPU, the LLC is the highest cache in
 *       their chain that is shared.  If no shared cache exists (e.g. the
 *       Ampere Altra Max in default SBSA mode with a transparent SLC),
 *       the LLC is the per-core private terminal cache -- each CPU gets
 *       its own unique LLC ID.
 *
 *   Cache node identity uses the PPTT byte offset of the ACPI_PPTT_CACHE
 *   structure.  Two CPUs whose cache chains converge at the same offset
 *   share that cache.
 *
 *   The pptt_info[] array is static, indexed by cpu_id (0 .. NCPU-1),
 *   populated once at boot, and read-only thereafter.  No locking is needed.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/cpuvar.h>
#include <sys/cmt.h>
#include <sys/pghw.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/acpi/acpi.h>
#include <sys/cpuinfo.h>

/*
 * Per-CPU topology information derived from PPTT.
 */
typedef struct pptt_cpu_info {
	uint32_t	pci_packageid;		/* PPTT offset of package node */
	uint32_t	pci_clusterid;		/* PPTT offset of cluster node */
	uint32_t	pci_coreid;		/* PPTT offset of leaf proc */
	uint32_t	pci_llc_id;		/* PPTT offset of LLC cache */
	uint32_t	pci_llc_level;		/* cache level (1, 2, 3, ...) */
	uint64_t	pci_llc_size;		/* LLC size in bytes */
	uint32_t	pci_llc_nsets;		/* number of sets */
	uint32_t	pci_llc_assoc;		/* associativity */
	uint32_t	pci_llc_type;		/* cache type (ACPI attrs) */
	boolean_t	pci_valid;		/* entry populated */
} pptt_cpu_info_t;

static pptt_cpu_info_t pptt_info[NCPU];
static boolean_t pptt_parsed = B_FALSE;

/*
 * Precomputed sharing flags, set during pptt_parse().  These allow
 * pg_plat_hw_shared() to answer in O(1) rather than scanning the
 * full pptt_info[] array on every call.
 */
static boolean_t pptt_has_shared_pkg = B_FALSE;
static boolean_t pptt_has_shared_cache = B_FALSE;

/*
 * Maximum depth when walking PPTT parent chains.  Guards against
 * malformed tables that would cause infinite loops.
 */
#define	PPTT_MAX_DEPTH	16

/*
 * Track terminal cache node offsets for the shared-cache detection pass.
 * We need at most NCPU entries (one per CPU).
 */
static uint32_t	pptt_term_cache[NCPU];

/*
 * Maximum number of processor nodes we track for the leaf detection
 * pre-pass.  This must be at least as large as the total number of
 * processor hierarchy nodes in the PPTT (packages + clusters + cores).
 * 1024 covers systems with up to ~512 cores and deep cluster hierarchies.
 */
#define	PPTT_MAX_PROC_NODES	1024

/*
 * Parent offset set for leaf detection.  Any processor node whose offset
 * does not appear in this array is a leaf (no other processor node
 * references it as a parent).
 */
static uint32_t	pptt_parent_offs[PPTT_MAX_PROC_NODES];
static int	pptt_nparents;

/*
 * Return B_TRUE if the given offset appears in the parent set,
 * meaning at least one other processor node has it as Parent.
 */
static boolean_t
pptt_is_parent(uint32_t offset)
{
	int i;

	for (i = 0; i < pptt_nparents; i++) {
		if (pptt_parent_offs[i] == offset)
			return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * Helper: given a byte offset within the PPTT, return a pointer to the
 * subtable header at that offset.  Returns NULL if the offset is zero
 * or out of bounds.
 */
static ACPI_SUBTABLE_HEADER *
pptt_offset_to_sub(ACPI_TABLE_PPTT *pptt, uint32_t offset)
{
	if (offset == 0 || offset >= pptt->Header.Length)
		return (NULL);
	return ((ACPI_SUBTABLE_HEADER *)((uintptr_t)pptt + offset));
}

/*
 * Walk a processor node's parent chain to find the physical package
 * and the closest intermediate node (cluster).
 *
 * Sets *pkg_off to the offset of the PHYSICAL_PACKAGE node and *clust_off
 * to the offset of the node immediately above the leaf (if one exists
 * between the leaf and the package).  If there is no intermediate node,
 * *clust_off is set equal to *pkg_off.
 */
static void
pptt_find_package_cluster(ACPI_TABLE_PPTT *pptt, ACPI_PPTT_PROCESSOR *leaf,
    uint32_t leaf_off, uint32_t *pkg_off, uint32_t *clust_off)
{
	ACPI_SUBTABLE_HEADER *sub;
	ACPI_PPTT_PROCESSOR *proc;
	uint32_t cur_off;
	uint32_t prev_off;
	int depth;

	*pkg_off = leaf_off;
	*clust_off = leaf_off;

	prev_off = leaf_off;
	cur_off = leaf->Parent;
	depth = 0;

	while (cur_off != 0 && depth < PPTT_MAX_DEPTH) {
		sub = pptt_offset_to_sub(pptt, cur_off);
		if (sub == NULL || sub->Type != ACPI_PPTT_TYPE_PROCESSOR)
			break;

		proc = (ACPI_PPTT_PROCESSOR *)sub;

		if (proc->Flags & ACPI_PPTT_PHYSICAL_PACKAGE) {
			*pkg_off = cur_off;
			/*
			 * If there was a node between the leaf and this
			 * package, that's our cluster.
			 */
			if (prev_off != leaf_off)
				*clust_off = prev_off;
			else
				*clust_off = cur_off;
			return;
		}

		prev_off = cur_off;
		cur_off = proc->Parent;
		depth++;
	}

	/*
	 * If we didn't find a PHYSICAL_PACKAGE node, use the highest
	 * node we reached as the package.
	 */
	*pkg_off = prev_off;
	if (prev_off != leaf_off)
		*clust_off = prev_off;
	else
		*clust_off = leaf_off;
}

/*
 * Walk a processor node's private resource list, find the highest-level
 * cache (following NextLevelOfCache chains), and return its offset within
 * the PPTT.  Also fills in cache properties for the terminal node.
 *
 * Returns 0 if no cache is found.
 */
static uint32_t
pptt_find_terminal_cache(ACPI_TABLE_PPTT *pptt, ACPI_PPTT_PROCESSOR *proc,
    uint32_t proc_off, uint32_t *level, uint64_t *size, uint32_t *nsets,
    uint32_t *assoc, uint32_t *type)
{
	ACPI_SUBTABLE_HEADER *sub;
	ACPI_PPTT_CACHE *cache;
	uint32_t *res;
	uint32_t best_off = 0;
	uint32_t best_level = 0;
	uint32_t i;
	int depth;

	if (proc->NumberOfPrivResources == 0)
		return (0);

	/*
	 * Private resource offsets follow immediately after the
	 * ACPI_PPTT_PROCESSOR structure.
	 */
	res = (uint32_t *)((uintptr_t)proc + sizeof (ACPI_PPTT_PROCESSOR));

	for (i = 0; i < proc->NumberOfPrivResources; i++) {
		uint32_t cur_off = res[i];
		uint32_t cur_level = 1;

		sub = pptt_offset_to_sub(pptt, cur_off);
		if (sub == NULL || sub->Type != ACPI_PPTT_TYPE_CACHE)
			continue;

		cache = (ACPI_PPTT_CACHE *)sub;

		/*
		 * Follow NextLevelOfCache chain to the terminal.
		 */
		depth = 0;
		while (cache->NextLevelOfCache != 0 &&
		    depth < PPTT_MAX_DEPTH) {
			sub = pptt_offset_to_sub(pptt,
			    cache->NextLevelOfCache);
			if (sub == NULL ||
			    sub->Type != ACPI_PPTT_TYPE_CACHE)
				break;
			cache = (ACPI_PPTT_CACHE *)sub;
			cur_level++;
			depth++;
		}

		/*
		 * Use the byte offset within the PPTT to track the
		 * terminal node -- this is the last valid cache we
		 * visited.
		 */
		cur_off = (uint32_t)((uintptr_t)cache - (uintptr_t)pptt);

		if (cur_level > best_level) {
			best_level = cur_level;
			best_off = cur_off;
		}
	}

	if (best_off != 0) {
		cache = (ACPI_PPTT_CACHE *)pptt_offset_to_sub(pptt, best_off);

		*level = best_level;
		*size = (cache->Flags & ACPI_PPTT_SIZE_PROPERTY_VALID) ?
		    cache->Size : 0;
		*nsets = (cache->Flags & ACPI_PPTT_NUMBER_OF_SETS_VALID) ?
		    cache->NumberOfSets : 0;
		*assoc = (cache->Flags & ACPI_PPTT_ASSOCIATIVITY_VALID) ?
		    cache->Associativity : 0;
		*type = (cache->Flags & ACPI_PPTT_CACHE_TYPE_VALID) ?
		    (cache->Attributes & ACPI_PPTT_MASK_CACHE_TYPE) : 0;
	}

	return (best_off);
}

/*
 * Parse the PPTT and populate pptt_info[].
 *
 * Called from pg_plat_set_fw() during early boot, before kmem is available.
 * All data is stored in static arrays.
 */
static void
pptt_parse(ACPI_TABLE_PPTT *pptt)
{
	ACPI_SUBTABLE_HEADER *sub;
	ACPI_PPTT_PROCESSOR *proc;
	uint32_t offset;
	uint32_t end;
	int ncpus_found = 0;
	int i;

	end = pptt->Header.Length;
	offset = sizeof (ACPI_TABLE_PPTT);

	/*
	 * Pre-pass: Build the set of offsets that are referenced as Parent
	 * by at least one processor node.  Any processor node whose own
	 * offset is NOT in this set is a leaf (has no children).  This
	 * handles firmware (e.g. Ampere Altra) that does not set the
	 * ACPI_PPTT_ACPI_PROCESSOR_ID_VALID flag on leaf processors.
	 */
	pptt_nparents = 0;
	while (offset < end) {
		sub = (ACPI_SUBTABLE_HEADER *)((uintptr_t)pptt + offset);

		if (sub->Length < sizeof (ACPI_SUBTABLE_HEADER) ||
		    offset + sub->Length > end)
			break;

		if (sub->Type == ACPI_PPTT_TYPE_PROCESSOR) {
			proc = (ACPI_PPTT_PROCESSOR *)sub;

			if (proc->Parent != 0 &&
			    pptt_nparents < PPTT_MAX_PROC_NODES) {
				/*
				 * Only add if not already present.
				 */
				if (!pptt_is_parent(proc->Parent)) {
					pptt_parent_offs[pptt_nparents++] =
					    proc->Parent;
				}
			}
		}

		offset += sub->Length;
	}

	offset = sizeof (ACPI_TABLE_PPTT);

	/*
	 * Pass 1: Walk all subtables, process leaf processor nodes.
	 */
	while (offset < end) {
		sub = (ACPI_SUBTABLE_HEADER *)((uintptr_t)pptt + offset);

		if (sub->Length < sizeof (ACPI_SUBTABLE_HEADER) ||
		    offset + sub->Length > end)
			break;

		if (sub->Type == ACPI_PPTT_TYPE_PROCESSOR) {
			proc = (ACPI_PPTT_PROCESSOR *)sub;

			/*
			 * A processor node is a leaf if:
			 *  - ACPI_PPTT_ACPI_PROCESSOR_ID_VALID is set, or
			 *  - No other processor node references it as Parent
			 *
			 * The second check handles firmware (e.g. Ampere
			 * Altra Max) that omits the PROCESSOR_ID_VALID
			 * flag on leaf processors.
			 */
			if ((proc->Flags &
			    ACPI_PPTT_ACPI_PROCESSOR_ID_VALID) ||
			    !pptt_is_parent(offset)) {
				processorid_t cpu_id;
				uint32_t pkg_off, clust_off;
				uint32_t llc_level = 0;
				uint64_t llc_size = 0;
				uint32_t llc_nsets = 0, llc_assoc = 0;
				uint32_t llc_type = 0;
				uint32_t term_off;

				cpu_id = cpuinfo_id_for_uid(
				    proc->AcpiProcessorId);
				if (cpu_id == (processorid_t)-1) {
					offset += sub->Length;
					continue;
				}
				if (cpu_id >= NCPU) {
					offset += sub->Length;
					continue;
				}

				pptt_find_package_cluster(pptt, proc,
				    offset, &pkg_off, &clust_off);

				term_off = pptt_find_terminal_cache(pptt,
				    proc, offset, &llc_level, &llc_size,
				    &llc_nsets, &llc_assoc, &llc_type);

				pptt_info[cpu_id].pci_packageid = pkg_off;
				pptt_info[cpu_id].pci_clusterid = clust_off;
				pptt_info[cpu_id].pci_coreid = offset;
				pptt_info[cpu_id].pci_llc_id = term_off;
				pptt_info[cpu_id].pci_llc_level = llc_level;
				pptt_info[cpu_id].pci_llc_size = llc_size;
				pptt_info[cpu_id].pci_llc_nsets = llc_nsets;
				pptt_info[cpu_id].pci_llc_assoc = llc_assoc;
				pptt_info[cpu_id].pci_llc_type = llc_type;
				pptt_info[cpu_id].pci_valid = B_TRUE;

				pptt_term_cache[cpu_id] = term_off;
				ncpus_found++;
			}
		}

		offset += sub->Length;
	}

	if (ncpus_found == 0) {
		cmn_err(CE_WARN, "pg_plat: PPTT contains no leaf processor "
		    "nodes with valid ACPI Processor IDs");
		return;
	}

	/*
	 * Pass 2: Determine shared caches.
	 *
	 * Count how many CPUs reference each terminal cache node.  A cache
	 * referenced by more than one CPU is shared.  Where a shared cache
	 * exists, update the LLC ID to that shared node.
	 *
	 * If no shared cache is found for a given CPU, the LLC remains
	 * per-core (its private terminal cache offset), giving each CPU
	 * its own PGHW_CACHE group of one.
	 *
	 * This is O(n^2) in the number of CPUs, but n is bounded by NCPU
	 * (128 on this platform) and runs once at boot.
	 */
	for (i = 0; i < NCPU; i++) {
		int j, refcnt;

		if (!pptt_info[i].pci_valid || pptt_term_cache[i] == 0)
			continue;

		refcnt = 0;
		for (j = 0; j < NCPU; j++) {
			if (pptt_info[j].pci_valid &&
			    pptt_term_cache[j] == pptt_term_cache[i])
				refcnt++;
		}

		if (refcnt > 1) {
			/*
			 * This terminal cache is shared -- it becomes the
			 * LLC for cache-aware scheduling.
			 */
			pptt_info[i].pci_llc_id = pptt_term_cache[i];
		}
		/* else: pci_llc_id already set to the per-core terminal */
	}

	/*
	 * Precompute sharing flags for pg_plat_hw_shared().
	 */
	for (i = 0; i < NCPU; i++) {
		int j;

		if (!pptt_info[i].pci_valid)
			continue;

		for (j = i + 1; j < NCPU; j++) {
			if (!pptt_info[j].pci_valid)
				continue;

			if (!pptt_has_shared_pkg &&
			    pptt_info[i].pci_packageid ==
			    pptt_info[j].pci_packageid)
				pptt_has_shared_pkg = B_TRUE;

			if (!pptt_has_shared_cache &&
			    pptt_info[i].pci_llc_id != 0 &&
			    pptt_info[i].pci_llc_id ==
			    pptt_info[j].pci_llc_id)
				pptt_has_shared_cache = B_TRUE;

			if (pptt_has_shared_pkg && pptt_has_shared_cache)
				break;
		}

		if (pptt_has_shared_pkg && pptt_has_shared_cache)
			break;
	}

	cmn_err(CE_CONT, "?pg_plat: PPTT parsed, %d CPUs\n", ncpus_found);
	pptt_parsed = B_TRUE;
}

/*
 * Set the PPTT physical address and trigger parsing.
 * Called from mlsetup() before pg_cpu_bootstrap().
 */
void
pg_plat_set_fw(uint64_t pptt_pa)
{
	ACPI_TABLE_PPTT *pptt;

	if (pptt_pa == 0)
		return;

	pptt = (ACPI_TABLE_PPTT *)(uintptr_t)pptt_pa;

	if (pptt->Header.Length < sizeof (ACPI_TABLE_PPTT)) {
		cmn_err(CE_WARN, "pg_plat: PPTT table too short (%u bytes)",
		    pptt->Header.Length);
		return;
	}

	pptt_parse(pptt);
}

/*
 * Return whether the specified hardware type represents a topology level
 * where sharing exists on this platform.  Uses precomputed flags from
 * pptt_parse() for O(1) response.
 */
int
pg_plat_hw_shared(cpu_t *cp, pghw_type_t hw)
{
	if (!pptt_parsed) {
		/*
		 * Fallback: report sharing for CHIP and CACHE.
		 */
		switch (hw) {
		case PGHW_CHIP:
		case PGHW_CACHE:
			return (1);
		default:
			return (0);
		}
	}

	switch (hw) {
	case PGHW_CHIP:
		return (pptt_has_shared_pkg ? 1 : 0);
	case PGHW_CACHE:
		return (pptt_has_shared_cache ? 1 : 0);
	default:
		return (0);
	}
}

/*
 * Compare two CPUs and see if they have a pghw_type_t sharing relationship.
 * If pghw_type_t is an unsupported hardware type, then return -1.
 */
int
pg_plat_cpus_share(cpu_t *cpu_a, cpu_t *cpu_b, pghw_type_t hw)
{
	id_t pgp_a, pgp_b;

	pgp_a = pg_plat_hw_instance_id(cpu_a, hw);
	pgp_b = pg_plat_hw_instance_id(cpu_b, hw);

	if (pgp_a == -1 || pgp_b == -1)
		return (-1);

	return (pgp_a == pgp_b);
}

/*
 * Return a physical instance identifier for known hardware sharing
 * relationships.  CPUs that return the same ID share the given hardware.
 */
id_t
pg_plat_hw_instance_id(cpu_t *cpu, pghw_type_t hw)
{
	pptt_cpu_info_t *info;

	if (!pptt_parsed || cpu->cpu_id >= NCPU)
		return (-1);

	info = &pptt_info[cpu->cpu_id];
	if (!info->pci_valid)
		return (-1);

	switch (hw) {
	case PGHW_CHIP:
		return ((id_t)info->pci_packageid);
	case PGHW_CACHE:
		if (info->pci_llc_id == 0)
			return (-1);
		return ((id_t)info->pci_llc_id);
	default:
		return (-1);
	}
}

/*
 * Override the default CMT dispatcher policy for the specified
 * hardware sharing relationship.
 */
pg_cmt_policy_t
pg_plat_cmt_policy(pghw_type_t hw)
{
	switch (hw) {
	case PGHW_CACHE:
		return (CMT_BALANCE|CMT_AFFINITY);
	default:
		return (CMT_NO_POLICY);
	}
}

id_t
pg_plat_get_core_id(cpu_t *cpu)
{
	pptt_cpu_info_t *info;

	if (!pptt_parsed || cpu->cpu_id >= NCPU)
		return (-1);

	info = &pptt_info[cpu->cpu_id];
	if (!info->pci_valid)
		return (-1);

	return ((id_t)info->pci_coreid);
}

/*
 * Express preference for optimizing for sharing relationship
 * hw1 vs hw2.
 */
pghw_type_t
pg_plat_hw_rank(pghw_type_t hw1, pghw_type_t hw2)
{
	int i, rank1, rank2;

	static pghw_type_t hw_hier[] = {
		PGHW_CACHE,
		PGHW_CHIP,
		PGHW_NUM_COMPONENTS
	};

	rank1 = 0;
	rank2 = 0;

	for (i = 0; hw_hier[i] != PGHW_NUM_COMPONENTS; i++) {
		if (hw_hier[i] == hw1)
			rank1 = i;
		if (hw_hier[i] == hw2)
			rank2 = i;
	}

	if (rank1 > rank2)
		return (hw1);
	else
		return (hw2);
}
