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

UTSBASE	= ../../..
include $(UTSBASE)/../Makefile.master

MODULE		= rootnex
OBJECTS		= $(ROOTNEX_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(ROOT_SBSA_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/armv8/sbsa/io

include ../Makefile.sbsa

ALL_TARGET	= $(BINARY) $(SRC_CONFFILE)
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

# clean this up
CERRWARN	+= -_gcc=-Wno-uninitialized
CERRWARN	+= -_gcc=-Wno-switch
CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= -_gcc=-Wno-unused-function
CERRWARN	+= -_gcc=-Wno-unused-variable

LDFLAGS		+= -N misc/acpica

.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

install:	$(INSTALL_DEPS)

include ../Makefile.targ
