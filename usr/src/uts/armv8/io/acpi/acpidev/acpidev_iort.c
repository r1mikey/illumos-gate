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
 * IORT (I/O Remapping Table) parser.
 *
 * The IORT describes the topology connecting PCIe root complexes to
 * MSI controllers (ITS groups) and, optionally, SMMUs.  We parse it
 * to synthesise msi-parent / msi-map and dma-coherent properties on
 * PCIe root complex device tree nodes created by acpidev_mcfg.c.
 *
 * SMMU nodes are treated as transparent for now -- we follow through
 * them to reach the ITS group on the other side.  Full SMMU support
 * is future work.
 *
 * When no IORT is present but exactly one ITS exists (registered via
 * acpidev_gic.c), we create a wildcard entry so that all root
 * complexes get an msi-parent pointing to the sole ITS.
 */

#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/stdbool.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/acpidev_gic.h>
#include <sys/acpidev_iort.h>

/* Linked list of parsed root complex entries */
static acpidev_iort_rc_t *iort_rc_list = NULL;

/* Saved table header for AcpiPutTable() in fini */
static ACPI_TABLE_HEADER *iort_table_hdr = NULL;

/*
 * Temporary structure used during parsing to index ITS groups
 * by their byte offset within the IORT table (OutputReference
 * in ID mappings is a byte offset from the start of the table).
 */
typedef struct iort_its_group_entry {
	uint32_t		ige_offset;	/* byte offset of IORT node */
	uint32_t		ige_nids;
	uint32_t		*ige_ids;	/* points into ACPI table */
	struct iort_its_group_entry *ige_next;
} iort_its_group_entry_t;

/*
 * Find an ITS group in the temporary list by byte offset.
 */
static iort_its_group_entry_t *
iort_find_its_group(iort_its_group_entry_t *list, uint32_t offset)
{
	iort_its_group_entry_t *e;

	for (e = list; e != NULL; e = e->ige_next) {
		if (e->ige_offset == offset)
			return (e);
	}

	return (NULL);
}

/*
 * Given an IORT node at byte offset 'node_offset' in the table,
 * return a pointer to the ACPI_IORT_NODE.
 */
static ACPI_IORT_NODE *
iort_node_at(ACPI_TABLE_IORT *iort, uint32_t node_offset)
{
	return ((ACPI_IORT_NODE *)((uintptr_t)iort + node_offset));
}

/*
 * Resolve an ID mapping's OutputReference to an ITS group, following
 * through SMMU nodes transparently.  Returns the ITS group entry or
 * NULL if the chain doesn't lead to an ITS group.
 *
 * As we traverse SMMU nodes, we compose the DeviceID translation
 * by accumulating OutputBase offsets from the non-special ID mappings.
 * This matches Linux's iort_node_map_id() behavior: the SMMUv3's
 * IdMappingIndex entry is skipped (it identifies the SMMU's own MSI
 * domain, not the data-path ID translation), and the remaining
 * mappings describe how input StreamIDs map to output DeviceIDs
 * on the next node in the chain.
 *
 * devid_offset accumulates the total OutputBase offset through all
 * intermediate SMMU nodes.  The caller adds this to their own
 * OutputBase to compute the final DeviceID for the ITS.
 *
 * depth_limit prevents infinite loops in malformed tables.
 */
static iort_its_group_entry_t *
iort_resolve_to_its(ACPI_TABLE_IORT *iort, iort_its_group_entry_t *its_list,
    uint32_t target_offset, int depth_limit, uint32_t *devid_offset)
{
	ACPI_IORT_NODE		*target;
	iort_its_group_entry_t	*ige;

	if (depth_limit <= 0)
		return (NULL);

	target = iort_node_at(iort, target_offset);

	switch (target->Type) {
	case ACPI_IORT_NODE_ITS_GROUP:
		ige = iort_find_its_group(its_list, target_offset);
		return (ige);

	case ACPI_IORT_NODE_SMMU:
	case ACPI_IORT_NODE_SMMU_V3: {
		/*
		 * Follow through SMMU to the ITS group, composing
		 * the DeviceID translation along the way.
		 *
		 * For SMMUv3 nodes, the IdMappingIndex entry is the
		 * "special" mapping (typically SINGLE_MAPPING) used
		 * for the SMMU's own MSI domain -- skip it.  The
		 * remaining mappings describe data-path ID translation.
		 *
		 * For SMMUv1/v2 nodes, there is no special index;
		 * we prefer a SINGLE_MAPPING entry if present,
		 * otherwise use the first mapping.
		 */
		ACPI_IORT_ID_MAPPING	*maps;
		ACPI_IORT_ID_MAPPING	*follow;
		uint32_t		k;
		int			skip_index = -1;

		if (target->MappingCount == 0)
			return (NULL);

		maps = (ACPI_IORT_ID_MAPPING *)
		    ((uintptr_t)target + target->MappingOffset);

		/*
		 * For SMMUv3, get the special ID mapping index
		 * and skip it during ID translation (matches
		 * Linux iort_get_id_mapping_index).
		 */
		if (target->Type == ACPI_IORT_NODE_SMMU_V3 &&
		    target->Revision >= 1) {
			ACPI_IORT_SMMU_V3 *smmu;

			smmu = (ACPI_IORT_SMMU_V3 *)target->NodeData;
			/*
			 * The IdMappingIndex is valid when not all
			 * interrupts are wired (GSIV-based).  This
			 * matches Linux's heuristic for rev < 5.
			 */
			if (!(smmu->EventGsiv && smmu->PriGsiv &&
			    smmu->GerrGsiv && smmu->SyncGsiv)) {
				if (smmu->IdMappingIndex <
				    target->MappingCount) {
					skip_index =
					    (int)smmu->IdMappingIndex;
				}
			}
		}

		/*
		 * Find the data-path ID mapping (non-special).
		 * This is the mapping that describes how StreamIDs
		 * are translated to DeviceIDs for the next node.
		 */
		follow = NULL;
		for (k = 0; k < target->MappingCount; k++) {
			if ((int)k == skip_index)
				continue;
			follow = &maps[k];
			break;
		}

		if (follow == NULL) {
			/*
			 * All mappings were skipped (shouldn't happen
			 * in well-formed tables).  Fall back to first
			 * mapping.
			 */
			follow = &maps[0];
		}

		/*
		 * Compose the DeviceID offset.  The SMMU's
		 * non-special mapping translates input IDs to
		 * output IDs via OutputBase.  Accumulate this
		 * so the caller can compute the final DeviceID.
		 */
		if (devid_offset != NULL) {
			*devid_offset += follow->OutputBase;
		}

		return (iort_resolve_to_its(iort, its_list,
		    follow->OutputReference, depth_limit - 1,
		    devid_offset));
	}

	default:
		return (NULL);
	}
}

/*
 * Check whether all mappings for a root complex resolve to a single
 * ITS with an identity RID-to-DeviceID translation covering the full
 * 16-bit RID space.  If so, msi-parent alone suffices (no msi-map).
 *
 * Returns B_TRUE and sets *tridp to the ITS Translation ID if simple.
 */
static boolean_t
iort_is_simple(acpidev_iort_map_t *maps, uint32_t nmaps, uint32_t *tridp)
{
	uint32_t	trid;
	uint32_t	i;
	uint64_t	coverage;

	if (nmaps == 0)
		return (B_FALSE);

	/* All mappings must target the same ITS */
	trid = maps[0].aim_its_trid;
	for (i = 1; i < nmaps; i++) {
		if (maps[i].aim_its_trid != trid)
			return (B_FALSE);
	}

	/*
	 * Check whether the explicit mappings cover [0, 0x10000) with
	 * identity translation (rid_base == devid_base for each range).
	 */
	coverage = 0;
	for (i = 0; i < nmaps; i++) {
		if (maps[i].aim_rid_base != maps[i].aim_devid_base)
			return (B_FALSE);
		coverage += maps[i].aim_rid_count;
	}

	if (coverage >= 0x10000) {
		*tridp = trid;
		return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * Condense adjacent msi-map entries.  Two entries can be merged when
 * they target the same ITS and their RID and DeviceID ranges are
 * contiguous.  Operates in-place; returns the new count.
 *
 * Simple insertion sort by rid_base first, then merge pass.
 */
static uint32_t
iort_condense_maps(acpidev_iort_map_t *maps, uint32_t nmaps)
{
	uint32_t	i, j, out;
	acpidev_iort_map_t tmp;

	if (nmaps <= 1)
		return (nmaps);

	/* Insertion sort by rid_base */
	for (i = 1; i < nmaps; i++) {
		tmp = maps[i];
		j = i;
		while (j > 0 && maps[j - 1].aim_rid_base > tmp.aim_rid_base) {
			maps[j] = maps[j - 1];
			j--;
		}
		maps[j] = tmp;
	}

	/* Merge pass */
	out = 0;
	for (i = 1; i < nmaps; i++) {
		if (maps[out].aim_its_trid == maps[i].aim_its_trid &&
		    maps[out].aim_rid_base + maps[out].aim_rid_count ==
		    maps[i].aim_rid_base &&
		    maps[out].aim_devid_base + maps[out].aim_rid_count ==
		    maps[i].aim_devid_base) {
			maps[out].aim_rid_count += maps[i].aim_rid_count;
		} else {
			out++;
			maps[out] = maps[i];
		}
	}

	return (out + 1);
}

/*
 * Parse the IORT table, building a list of per-root-complex entries
 * that acpidev_mcfg.c will query when creating PCIe device tree nodes.
 */
ACPI_STATUS
acpidev_iort_init(void)
{
	ACPI_TABLE_IORT		*iort;
	ACPI_STATUS		st;
	ACPI_IORT_NODE		*node;
	uint32_t		offset;
	uint32_t		i;
	iort_its_group_entry_t	*its_groups = NULL;
	iort_its_group_entry_t	*ige;

	st = AcpiGetTable(ACPI_SIG_IORT, 1,
	    (ACPI_TABLE_HEADER **)&iort);
	if (st != AE_OK) {
		if (st == AE_NOT_FOUND || st == AE_NOT_EXIST) {
			uint32_t sole_trid;

			/*
			 * No IORT.  If exactly one ITS exists, create a
			 * wildcard entry so all root complexes get an
			 * msi-parent pointing to it.
			 */
			if (acpidev_gic_get_sole_its_trid(&sole_trid)) {
				acpidev_iort_rc_t *rc;

				rc = kmem_zalloc(sizeof (*rc), KM_SLEEP);
				rc->air_segment = UINT32_MAX;
				rc->air_coherent = B_TRUE;
				rc->air_simple = B_TRUE;
				rc->air_its_trid = sole_trid;
				rc->air_nmaps = 0;
				rc->air_maps = NULL;
				rc->air_next = NULL;
				iort_rc_list = rc;

				cmn_err(CE_CONT, "?acpidev: no IORT, "
				    "using sole ITS (translation-id %u) "
				    "for all root complexes\n", sole_trid);
				return (AE_OK);
			}

			cmn_err(CE_WARN, "acpidev: no IORT and multiple "
			    "(or no) ITS instances; MSI unconfigured");
			return (AE_OK);
		}
		return (st);
	}

	/* Save for AcpiPutTable() in fini */
	iort_table_hdr = &iort->Header;

	/*
	 * First pass: collect ITS groups, indexed by byte offset
	 * within the IORT table.
	 */
	offset = iort->NodeOffset;
	for (i = 0; i < iort->NodeCount; i++) {
		node = iort_node_at(iort, offset);

		if (node->Type == ACPI_IORT_NODE_ITS_GROUP) {
			ACPI_IORT_ITS_GROUP *grp;

			grp = (ACPI_IORT_ITS_GROUP *)node->NodeData;

			ige = kmem_zalloc(sizeof (*ige), KM_SLEEP);
			ige->ige_offset = offset;
			ige->ige_nids = grp->ItsCount;
			ige->ige_ids = grp->Identifiers;
			ige->ige_next = its_groups;
			its_groups = ige;

			cmn_err(CE_CONT, "?acpidev: IORT ITS group at "
			    "offset 0x%x, %u ITS(es)\n",
			    offset, grp->ItsCount);
		}

		offset += node->Length;
	}

	/*
	 * Second pass: process root complex nodes.
	 */
	offset = iort->NodeOffset;
	for (i = 0; i < iort->NodeCount; i++) {
		ACPI_IORT_ROOT_COMPLEX	*rc_data;
		ACPI_IORT_MEMORY_ACCESS	*ma;
		ACPI_IORT_ID_MAPPING	*idmap;
		acpidev_iort_map_t	*maps;
		uint32_t		nmaps;
		uint32_t		j;
		boolean_t		coherent;
		acpidev_iort_rc_t	*rc;

		node = iort_node_at(iort, offset);

		if (node->Type != ACPI_IORT_NODE_PCI_ROOT_COMPLEX) {
			offset += node->Length;
			continue;
		}

		rc_data = (ACPI_IORT_ROOT_COMPLEX *)node->NodeData;

		/* Extract coherency from MemoryProperties */
		ma = (ACPI_IORT_MEMORY_ACCESS *)&rc_data->MemoryProperties;
		coherent = (ma->CacheCoherency == ACPI_IORT_NODE_COHERENT);

		cmn_err(CE_CONT, "?acpidev: IORT root complex "
		    "segment %u, %u mapping(s), %scoherent\n",
		    rc_data->PciSegmentNumber, node->MappingCount,
		    coherent ? "" : "not ");

		/*
		 * Walk ID mappings, resolve each to an ITS group.
		 * For each mapping, compose the DeviceID translation
		 * through any intermediate SMMU nodes.
		 */
		maps = NULL;
		nmaps = 0;

		if (node->MappingCount > 0) {
			maps = kmem_zalloc(
			    node->MappingCount * sizeof (*maps), KM_SLEEP);

			idmap = (ACPI_IORT_ID_MAPPING *)
			    ((uintptr_t)node + node->MappingOffset);

			for (j = 0; j < node->MappingCount; j++) {
				iort_its_group_entry_t *target;
				uint32_t smmu_devid_offset = 0;

				target = iort_resolve_to_its(iort, its_groups,
				    idmap[j].OutputReference, 3,
				    &smmu_devid_offset);
				if (target == NULL || target->ige_nids == 0) {
					cmn_err(CE_CONT, "?acpidev: IORT "
					    "mapping %u for segment %u: "
					    "unresolved\n", j,
					    rc_data->PciSegmentNumber);
					continue;
				}

				if (idmap[j].Flags &
				    ACPI_IORT_ID_SINGLE_MAPPING) {
					/*
					 * SINGLE_MAPPING on the RC itself:
					 * entire RID space maps through.
					 * Compose with SMMU offset.
					 */
					maps[nmaps].aim_rid_base = 0;
					maps[nmaps].aim_rid_count = 0x10000;
					maps[nmaps].aim_devid_base =
					    smmu_devid_offset;
				} else {
					maps[nmaps].aim_rid_base =
					    idmap[j].InputBase;
					maps[nmaps].aim_rid_count =
					    idmap[j].IdCount;
					maps[nmaps].aim_devid_base =
					    idmap[j].OutputBase +
					    smmu_devid_offset;
				}

				/* Use first ITS in the group */
				maps[nmaps].aim_its_trid =
				    target->ige_ids[0];
				nmaps++;
			}
		}

		/* Condense adjacent entries */
		if (nmaps > 1)
			nmaps = iort_condense_maps(maps, nmaps);

		/* Allocate the result entry */
		rc = kmem_zalloc(sizeof (*rc), KM_SLEEP);
		rc->air_segment = rc_data->PciSegmentNumber;
		rc->air_coherent = coherent;

		if (nmaps > 0 &&
		    iort_is_simple(maps, nmaps, &rc->air_its_trid)) {
			rc->air_simple = B_TRUE;
			rc->air_nmaps = 0;
			rc->air_maps = NULL;
			if (maps != NULL) {
				kmem_free(maps,
				    node->MappingCount * sizeof (*maps));
			}
		} else {
			rc->air_simple = B_FALSE;
			rc->air_nmaps = nmaps;
			if (nmaps > 0 && nmaps < node->MappingCount) {
				/* Shrink allocation to actual count */
				acpidev_iort_map_t *newmaps;
				newmaps = kmem_alloc(
				    nmaps * sizeof (*newmaps), KM_SLEEP);
				bcopy(maps, newmaps,
				    nmaps * sizeof (*newmaps));
				kmem_free(maps,
				    node->MappingCount * sizeof (*maps));
				maps = newmaps;
			}
			rc->air_maps = (nmaps > 0) ? maps : NULL;
			if (nmaps == 0 && maps != NULL) {
				kmem_free(maps,
				    node->MappingCount * sizeof (*maps));
			}
		}

		rc->air_next = iort_rc_list;
		iort_rc_list = rc;

		offset += node->Length;
	}

	/* Free temporary ITS group list */
	while (its_groups != NULL) {
		ige = its_groups->ige_next;
		kmem_free(its_groups, sizeof (*its_groups));
		its_groups = ige;
	}

	return (AE_OK);
}

/*
 * Look up IORT data for a root complex by PCI segment number.
 * Falls back to the wildcard entry (segment == UINT32_MAX) if
 * no exact match is found.
 */
acpidev_iort_rc_t *
acpidev_iort_lookup_rc(uint32_t segment)
{
	acpidev_iort_rc_t	*rc;
	acpidev_iort_rc_t	*wildcard = NULL;

	for (rc = iort_rc_list; rc != NULL; rc = rc->air_next) {
		if (rc->air_segment == segment)
			return (rc);
		if (rc->air_segment == UINT32_MAX)
			wildcard = rc;
	}

	return (wildcard);
}

/*
 * Free all IORT data and release the ACPI table.
 */
void
acpidev_iort_fini(void)
{
	acpidev_iort_rc_t *rc;

	while (iort_rc_list != NULL) {
		rc = iort_rc_list;
		iort_rc_list = rc->air_next;

		if (rc->air_maps != NULL) {
			kmem_free(rc->air_maps,
			    rc->air_nmaps * sizeof (acpidev_iort_map_t));
		}
		kmem_free(rc, sizeof (*rc));
	}

	if (iort_table_hdr != NULL) {
		AcpiPutTable(iort_table_hdr);
		iort_table_hdr = NULL;
	}
}
