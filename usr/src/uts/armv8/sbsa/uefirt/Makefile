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
# Copyright 2023 Michael van der Westhuizen
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../../..

#
#	Define the module and object file sets.
#
MODULE		= uefirt
OBJECTS		= $(UEFIRT_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(ROOT_VIRT_MISC_DIR)/$(MODULE)

#
#	Include common rules.
#
include $(UTSBASE)/armv8/sbsa/Makefile.sbsa

#
#       Define targets
#
ALL_TARGET	= $(BINARY)
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

#
#	Overrides
#
ALL_BUILDS	= $(ALL_BUILDSONLY64)
DEF_BUILDS	= $(DEF_BUILDSONLY64)

#
# For now, disable these warnings; maintainers should endeavor
# to investigate and remove these for maximum coverage.
# Please do not carry these forward to new Makefiles.
#
CFLAGS += $(CCVERBOSE)

#
#	Default build targets.
#
.KEEP_STATE:

all:		$(ALL_DEPS)

def:		$(DEF_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

install:	$(INSTALL_DEPS)


#
#	Include common targets.
#
include $(UTSBASE)/armv8/sbsa/Makefile.targ
