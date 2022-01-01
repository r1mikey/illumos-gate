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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
#
#	This makefile drives the production of all implementation architecture
#	dependent modules for the armsbsa architecture.
#

UTSBASE = ..

include Makefile.armsbsa

#
#
#
def		:=	TARGET= def
all		:=	TARGET= all
install		:=	TARGET= install
install_h	:=	TARGET= install_h
clean		:=	TARGET= clean
clobber		:=	TARGET= clobber
modlist		:=	TARGET= modlist
modlist	modlist.aarch64 :=	NO_STATE= -K $$MODSTATE$$$$
check		:=	TARGET= check

.KEEP_STATE:

.PARALLEL:	$(PARALLEL_KMODS) $(XMODS) modlist modlist.aarch64

INITIAL_TARGETS = 	\
	genassym	\
	unix

#INITIAL_TARGETS = \
#	genassym \
#	unix \
#	cpu/scripts

#def all clean clobber: setup genassym unix .WAIT \
#	$(KMODS) $(XMODS) $(IMPLEMENTATIONS)
def all clean clobber: setup genassym unix .WAIT \
	$(KMODS) $(XMODS) $(IMPLEMENTATIONS)

install: install_platforms setup genassym unix .WAIT \
	$(KMODS) $(XMODS) $(IMPLEMENTATIONS)
# install: install_platforms setup genassym unix .WAIT

# list the modules under armsbsa.
modlist: unix $(KMODS) $(XMODS) $(IMPLEMENTATIONS)
# modlist: unix $(IMPLEMENTATIONS)

# list the modules for Install -k armsbsa.
modlist.karch: modlist modlist.aarch64

modlist.aarch64:
	@cd $(SRC)/uts/aarch64; pwd; $(MAKE) $(NO_STATE) modlist

genassym unix $(KMODS):	FRC
	@cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

setup: FRC
	@echo "cpu/scripts would be done here"
#	@cd cpu/scripts; pwd; $(MAKE) $(TARGET)

$(IMPLEMENTATIONS):     FRC
	@cd $@; pwd; THISIMPL=$@ $(MAKE) $(NO_STATE) $(TARGET)

$(XMODS):	FRC
	cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

install_h check:	$(IMPLEMENTATIONS) FRC
	@cd sys; pwd; $(MAKE) $(TARGET)

#
# Definitions for the /platform directory aliases.
# Currently none for armsbsa.
#
PLAT_LINKS	=

#
# Make the /platform directories.  This is hardwired here because
# the first stage of the project (KBI) only implements the userland
# changes, but the only reasonable place to record the aliases is
# here in kernel land.
#
install_platforms:	$(ROOT_PSM_DIR) $(USR_PSM_DIR) \
			$(ROOT_PLAT_LINKS) $(USR_PLAT_LINKS) \
			$(OEM_USR_PLAT_LINKS)

include ../Makefile.targ

#
# Cross-reference customization: build a cross-reference over all of the
# armsbsa-related directories.
#
XRDIRS	= ../armsbsa ../aarch64 ../common

XRPRUNE	= sun4v sun4u sun4 sun sparc sfmmu i86pc i86xpv intel

cscope.out tags: FRC
	$(XREF) -x $@
