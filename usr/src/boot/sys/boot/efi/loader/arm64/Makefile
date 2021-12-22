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
# Copyright 2016 Toomas Soome <tsoome@me.com>
# Copyright 2016 RackTop Systems.
#

include $(SRC)/Makefile.master

MACHINE=	arm64
EFIPROG=	loader64.efi

all:		$(EFIPROG)

include ../Makefile.com

# XXXAARCH64: pei-aarch64-little would be nice
EFI_TARGET=	binary
LDFLAGS +=	-znocombreloc

efi_main.o := CPPFLAGS += -DLOADER_EFI=L\"loader64.efi\"
CFLAGS +=	-m64 $(CFLAGS64) -_gcc=-mgeneral-regs-only
CCASFLAGS +=	-m64

CLEANFILES +=	machine $(EFIPROG)

$(OBJS):	machine
