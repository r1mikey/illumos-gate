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
 * Copyright 2022 Michael van der Westhuizen
 */

	.file	"aarch64_idregs.s"

/*
 * Identification register access.
 */

#include <sys/asm_linkage.h>

	/*
	 * MIDR_EL1, Main ID Register
	 * uint64_t read_midr_el1(void);
	 */
	ENTRY(read_midr_el1)
	mrs	x0, MIDR_EL1
	ret
	SET_SIZE(read_midr_el1)

	/*
	 * MPIDR_EL1, Multiprocessor Affinity Register
	 * uint64_t read_mpidr_el1(void);
	 */
	ENTRY(read_mpidr_el1)
	mrs	x0, MPIDR_EL1
	ret
	SET_SIZE(read_mpidr_el1)

	/*
	 * ID_AA64MMFR0_EL1, AArch64 Memory Model Feature Register 0
	 * uint64_t read_id_aa64mmfr0_el1(void);
	 */
	ENTRY(read_id_aa64mmfr0_el1)
	mrs	x0, ID_AA64MMFR0_EL1
	ret
	SET_SIZE(read_id_aa64mmfr0_el1)

	/*
	 * ID_AA64MMFR1_EL1, AArch64 Memory Model Feature Register 1
	 * uint64_t read_id_aa64mmfr1_el1(void);
	 */
	ENTRY(read_id_aa64mmfr1_el1)
	mrs	x0, ID_AA64MMFR1_EL1
	ret
	SET_SIZE(read_id_aa64mmfr1_el1)

	/*
	 * ID_AA64MMFR2_EL1, AArch64 Memory Model Feature Register 2
	 * uint64_t read_id_aa64mmfr2_el1(void);
	 */
	ENTRY(read_id_aa64mmfr2_el1)
	mrs	x0, ID_AA64MMFR2_EL1
	ret
	SET_SIZE(read_id_aa64mmfr2_el1)

	/*
	 * ID_AA64PFR0_EL1, AArch64 Processor Feature Register 0
	 * uint64_t read_id_aa64pfr0_el1(void);
	 */
	ENTRY(read_id_aa64pfr0_el1)
	mrs	x0, ID_AA64PFR0_EL1
	ret
	SET_SIZE(read_id_aa64pfr0_el1)

	/*
	 * ID_AA64PFR0_EL1, AArch64 Processor Feature Register 1
	 * uint64_t read_id_aa64pfr1_el1(void);
	 */
	ENTRY(read_id_aa64pfr1_el1)
	mrs	x0, ID_AA64PFR1_EL1
	ret
	SET_SIZE(read_id_aa64pfr1_el1)

	/*
	 * ID_AA64DFR0_EL1, AArch64 Debug Feature Register 0
	 * uint64_t read_id_aa64dfr0_el1(void);
	 */
	ENTRY(read_id_aa64dfr0_el1)
	mrs	x0, ID_AA64DFR0_EL1
	ret
	SET_SIZE(read_id_aa64dfr0_el1)

	/*
	 * ID_AA64DFR1_EL1, AArch64 Debug Feature Register 1
	 * uint64_t read_id_aa64dfr1_el1(void);
	 */
	ENTRY(read_id_aa64dfr1_el1)
	mrs	x0, ID_AA64DFR1_EL1
	ret
	SET_SIZE(read_id_aa64dfr1_el1)

	/*
	 * ID_AA64ISAR0_EL1, AArch64 Instruction Set Attribute Register 0
	 * uint64_t read_id_aa64isar0_el1(void);
	 */
	ENTRY(read_id_aa64isar0_el1)
	mrs	x0, ID_AA64ISAR0_EL1
	ret
	SET_SIZE(read_id_aa64isar0_el1)

	/*
	 * ID_AA64ISAR1_EL1, AArch64 Instruction Set Attribute Register 1
	 * uint64_t read_id_aa64isar1_el1(void);
	 */
	ENTRY(read_id_aa64isar1_el1)
	mrs	x0, ID_AA64ISAR1_EL1
	ret
	SET_SIZE(read_id_aa64isar1_el1)

	/*
	 * ID_AA64ISAR2_EL1, AArch64 Instruction Set Attribute Register 2
	 * uint64_t read_id_aa64isar2_el1(void);
	 */
	ENTRY(read_id_aa64isar2_el1)
	mrs	x0, ID_AA64ISAR2_EL1
	ret
	SET_SIZE(read_id_aa64isar2_el1)
