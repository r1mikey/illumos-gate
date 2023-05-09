#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright 2020 Hayashi Naoyuki
#

# GELFEDIT = /build/arm64-gate/illumos-gate/../cross/bin/aarch64-unknown-solaris2.11-elfedit
# $(GELFEDIT) --output-osabi Solaris inetboot.out
# ^^^ is in-place, which is shitty
# /build/arm64-gate/illumos-gate/../cross/bin/aarch64-unknown-solaris2.11-elfedit --output-osabi Solaris inetboot.out
# /usr/bin/elfedit -e "ehdr:ei_osabi ELFOSABI_SOLARIS" inetboot.out inetboot.elf

TOPDIR =	../../../../..
# OBJS += virtnet.o virtblk.o
BOARD=	virt

include Makefile.sbsa
ROOT_PSM_DIR=$(ROOT_PLAT_DIR)/ARM,sbsa
KERNEL_SHIM_DIR=$(ROOT_PSM_DIR)/kernel/$(MACH64)
ROOT_PSM_KERNEL_SHIM=$(KERNEL_SHIM_DIR)/unix.shim

.KEEP_STATE:

all: $(NFSBOOT_ELF)
$(NFS_SRT0) $(NFS_OBJS):  $(ASSYM_H)

install: all $(ROOT_PSM_KERNEL_SHIM)

include $(BOOTSRCDIR)/Makefile.rules
include ../Makefile.targ

$(NFSBOOT_ELF): $(NFSBOOT_OUT)
	$(ELFEDIT) -e "ehdr:ei_osabi ELFOSABI_SOLARIS" $(NFSBOOT_OUT) $(NFSBOOT_ELF)

$(ROOT_PSM_KERNEL_SHIM): $(NFSBOOT_ELF) $(KERNEL_SHIM_DIR)
	$(INS.file) $(NFSBOOT_ELF)

$(KERNEL_SHIM_DIR): $(ROOT_PSM_DIR)
	$(INS.dir)
