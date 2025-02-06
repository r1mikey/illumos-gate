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

include $(SRC)/Makefile.master
include $(SRC)/boot/Makefile.inc

i386_MACHINCLUDE = $(MACH64)
aarch64_MACHINCLUDE = arm64
MACHINCLUDE = $($(MACH)_MACHINCLUDE)

install:


SRCS += efi_acpi_uart.c acpiuart.c

OBJS=	$(SRCS:%.c=%.o)

CPPFLAGS += -U__sun
CPPFLAGS += -DEFI
CPPFLAGS += -D_EDK2_EFI
CPPFLAGS += -DUSE_STDLIB
CPPFLAGS += -DACPI_USE_LOCAL_CACHE

CPPFLAGS += -DEFI
CPPFLAGS += -I.
CPPFLAGS += -I$(SRC)/uts/common/sys/acpi
CPPFLAGS += -I$(BOOTSRC)/sys
CPPFLAGS += -I$(BOOTSRC)/common
CPPFLAGS += -I$(BOOTSRC)/libsa
CPPFLAGS += -I$(BOOTSRC)/include
CPPFLAGS += -I$(BOOTSRC)/efi/libacpica
CPPFLAGS += -I$(BOOTSRC)/efi/libmmio_uart
CPPFLAGS += -I$(BOOTSRC)/efi/include
CPPFLAGS += -I$(BOOTSRC)/efi/include/$(MACHINCLUDE)

# needed for tbl - I'm sure we can get rid of a lot of this
CPPFLAGS += -I$(SRC)/cmd/acpi/acpidump

include ../../Makefile.inc

CFLAGS += -_gcc=-Wno-unused-variable
CFLAGS += -_gcc=-Wno-parentheses
CFLAGS += -_gcc=-Wno-unused-function

CFLAGS +=       $(CFLAGS64)

libacpiuart.a: $(OBJS)
	$(AR) $(ARFLAGS) $@ $(OBJS)

clean: clobber
clobber:
	$(RM) $(CLEANFILES) $(OBJS) libacpiuart.a

machine:
	$(RM) machine
	$(SYMLINK) ../../../sys/$(MACHINE)/include machine

x86:
	$(RM) x86
	$(SYMLINK) ../../../sys/x86/include x86

%.o:	../%.c
	$(COMPILE.c) $<
