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
# Copyright 2025 Michael van der Westhuizen
#

include $(SRC)/Makefile.master
include $(SRC)/boot/Makefile.inc

i386_MACHINCLUDE = $(MACH64)
aarch64_MACHINCLUDE = arm64
MACHINCLUDE = $($(MACH)_MACHINCLUDE)

install:

SRCS +=					\
	bi.c				\
	efi_get_fdtp.c

OBJS=	$(SRCS:%.c=%.o)

CPPFLAGS += -I.
CPPFLAGS += -I$(BOOTSRC)/sys
CPPFLAGS += -I$(BOOTSRC)/common
CPPFLAGS += -I$(BOOTSRC)/libsa
CPPFLAGS += -I$(BOOTSRC)/include
CPPFLAGS += -I$(SRC)/contrib/libfdt
CPPFLAGS += -I$(BOOTSRC)/efi/include
CPPFLAGS += -I$(BOOTSRC)/efi/libfdtutil
CPPFLAGS += -I$(BOOTSRC)/efi/libmmio_uart

include ../../Makefile.inc

CFLAGS +=       $(CFLAGS64)

libfdtutil.a: $(OBJS)
	$(AR) $(ARFLAGS) $@ $(OBJS)

clean: clobber
clobber:
	$(RM) $(CLEANFILES) $(OBJS) libfdtutil.a

machine:
	$(RM) machine
	$(SYMLINK) ../../../sys/$(MACHINE)/include machine

x86:
	$(RM) x86
	$(SYMLINK) ../../../sys/x86/include x86

%.o:	../%.c
	$(COMPILE.c) $<
