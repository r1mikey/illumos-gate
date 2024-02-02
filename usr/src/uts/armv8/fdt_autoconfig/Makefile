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
# Path to the uts directory tree.
#
UTSBASE	= ../..

#
# Module and objects (sources are derived in a parent Makefile.rules)
#
MODULE		= fdt_autoconfig
OBJECTS		= $(FDT_AUTOCONFIG_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(ROOT_MISC_DIR)/$(MODULE)
INC_PATH	+= $(LIBFDT_INCPATH)

#
# Common rules.
#
include $(UTSBASE)/armv8/Makefile.armv8

#
# Targets
#
ALL_TARGET	= $(BINARY)
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

# LDFLAGS	+= -Nmisc/A -N misc/B

#
# Targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

install:	$(INSTALL_DEPS)

#
# Common targets.
#
include $(UTSBASE)/armv8/Makefile.targ
