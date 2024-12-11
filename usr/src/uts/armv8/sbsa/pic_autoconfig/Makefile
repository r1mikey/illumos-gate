#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2024 Michael van der Westhuizen
#

#
# Path to the base of the uts tree (nominally /usr/src/uts).
#
UTSBASE	= ../../..

#
# Define the module and objects used to construct it.
#
MODULE		= pic_autoconfig
OBJECTS		= $(PIC_AUTOCONFIG_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(ROOT_SBSA_MISC_DIR)/$(MODULE)

#
# Include common rules.
#
include $(UTSBASE)/armv8/sbsa/Makefile.sbsa

#
# Define targets
#
ALL_TARGET	= $(BINARY)
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

#
# Depends on the ACPICA library module.
#
LDFLAGS		+= -Nmisc/acpica

#
# Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

install:	$(INSTALL_DEPS)

#
# Include common targets.
#
include $(UTSBASE)/armv8/sbsa/Makefile.targ
