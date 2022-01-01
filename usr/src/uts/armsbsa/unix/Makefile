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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2019 Joyent, Inc.
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Define the module and object file sets.
#
UNIX		= unix
EBOOT		= eboot

OBJECTS		= $(SPECIAL_OBJS:%=$(OBJS_DIR)/%) \
		  $(CORE_OBJS:%=$(OBJS_DIR)/%) \
		  $(KRTLD_OBJS:%=$(OBJS_DIR)/%) \
		  $(MACH_NOT_YET_KMODS:%=$(OBJS_DIR)/%)

ROOTMODULE	= $(ROOT_PSM_KERN_DIR)/$(UNIX)

UNIX_BIN	= $(OBJS_DIR)/$(UNIX)

LIBS		= $(GENLIB)

GENUNIX		= genunix
GENUNIX_DIR	= ../../aarch64/$(GENUNIX)

LIBOPTS		= -L $(GENUNIX_DIR)/$(OBJS_DIR) -l $(GENUNIX)

CTFEXTRAOBJS	= $(OBJS_DIR)/vers.o

EBOOT_OBJS_DIR	= eboot/$(OBJS_DIR)
EBOOT_OBJECTS	= $(EBOOT_OBJS:%=$(EBOOT_OBJS_DIR)/%)
EBOOT_BIN	= $(EBOOT_OBJS_DIR)/$(EBOOT)
EBOOT_BIN_BIN	= $(EBOOT_OBJS_DIR)/$(EBOOT).bin
EBOOT_O		= $(OBJS_DIR)/$(EBOOT).o
EBOOT_S		= $(EBOOT_O:%.o=%.s)

#
#	Include common rules.
#
include $(UTSBASE)/armsbsa/Makefile.armsbsa

#
#	Define targets
#
ALL_TARGET	= $(UNIX_BIN)
INSTALL_TARGET	= $(UNIX_BIN) $(ROOTMODULE)

#
#	This is UNIX_DIR. Use a short path.
#
UNIX_DIR	= .

#
#	Overrides
#
CLEANFILES	+=		\
	$(UNIX_O) $(MODSTUBS_O)	\
	$(OBJS_DIR)/vers.c \
	$(OBJS_DIR)/dtracestubs.s \
	$(DTRACESTUBS_O) $(DTRACESTUBS) \
	$(CTFEXTRAOBJS) \
	$(COMMP_CTF_SRC)

CLEANFILES	+=		\
	$(EBOOT_O) $(EBOOT_S)	\
	$(EBOOT_OBJECTS)	\
	$(OBJS_DIR)/bios_call_src.o \
	$(OBJS_DIR)/bios_call_src \
	$(OBJS_DIR)/bios_call.s \
	$(EBOOT_BIN)		\
	$(EBOOT_BIN_BIN)

CLEANFILES	+=		\
	$(EBOOT_OBJS_DIR)/$(FONT).c \
	$(OBJS_DIR)/$(FONT).c

CLEANFILES	+=		\
	$(OBJS_DIR)/fb_swtch_src.o \
	$(OBJS_DIR)/fb_swtch_src \
	$(OBJS_DIR)/fb_swtch.s

CLEANFILES	+= $(ZLIB_OBJS:%.o=$(OBJS_DIR)/%.o)

CLOBBERFILES	= $(CLEANFILES) $(UNIX_BIN)

# instr_size needs a special header
$(OBJS_DIR)/instr_size.o :=	EXTRA_OPTIONS	= -I$(SRC)/common/dis/aarch64

CFLAGS += -DDIS_MEM

#
# For now, disable these checks; maintainers should endeavor
# to investigate and remove these for maximum coverage.
# Please do not carry these forward to new Makefiles.
#
CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= $(CNOWARN_UNINIT)
CERRWARN	+= -_gcc=-Wno-char-subscripts
CERRWARN	+= -_gcc=-Wno-unused-variable
CERRWARN	+= -_gcc=-Wno-unused-function
CERRWARN	+= -_gcc=-Wno-unused-label
CERRWARN	+= -_gcc=-Wno-type-limits
CERRWARN	+= -_gcc=-Wno-clobbered
CERRWARN	+= -_gcc=-Wno-empty-body
CERRWARN	+= -_gcc=-Wno-unused-value

# false positives
SMOFF += index_overflow

# needs work
SMOFF += all_func_returns,deref_check,signed

$(OBJS_DIR)/fmsmb.o := SMOFF += indenting
$(OBJS_DIR)/zutil.o := SMOFF += indenting
$(OBJS_DIR)/bootrd_cpio.o := SMOFF += allocating_enough_data

# too hairy
$(OBJS_DIR)/inflate.o := SMATCH=off

#
#	Default build targets.
#
.KEEP_STATE:

def: $(DEF_DEPS)

all: $(ALL_DEPS)

clean: $(CLEAN_DEPS)

clobber: $(CLOBBER_DEPS)

install: $(INSTALL_DEPS)

MAPFILE_32 = $(UNIX_MAPFILE)
MAPFILE_64 = $(UNIX_MAPFILE).aarch64

MAPFILE_NAME = $(MAPFILE_$(CLASS))

$(UNIX_BIN):	$(UNIX_O) $(MODSTUBS_O) $(MAPFILE_NAME) \
		$(GENLIB) $(DTRACESTUBS) $(EBOOT_O)
	$(LD) -dy -b -o $@ -e eboot_image -znointerp -M $(MAPFILE_NAME) \
	    $(UNIX_O) $(EBOOT_O) $(MODSTUBS_O) $(LIBOPTS) \
	    $(DTRACESTUBS)
	@#$(MBH_PATCH) $(UNIX_BIN)
	$(CTFMERGE_UNIQUIFY_AGAINST_GENUNIX)
	$(POST_PROCESS)

$(UNIX_O):	$(OBJECTS) $(CTFEXTRAOBJS)
	$(LD) -r -o $@ $(OBJECTS) $(OBJS_DIR)/vers.o

#
# For now I use the GNU linker, much like loader.efi.  I'd really like to use
# the native linker, but I need to figure out of it's possible.
#
# $(LD) -dn -e _start -M eboot/Mapfile.eboot -o $(EBOOT_BIN) $(EBOOT_OBJECTS)
#
$(EBOOT_BIN):	$(EBOOT_OBJS_DIR) $(EBOOT_OBJECTS) eboot/Mapfile.eboot
	$(GNU_ROOT)/bin/gld -nostdlib --eh-frame-hdr -shared -Bsymbolic \
	    --hash-style=both --enable-new-dtags -Teboot/eboot.lds \
	    -o $(EBOOT_BIN) $(EBOOT_OBJECTS)

$(EBOOT_BIN_BIN):	$(EBOOT_BIN)
	if [ `$(GNU_ROOT)/bin/gobjdump -t $(EBOOT_BIN) | \
	    fgrep '*UND*' | wc -l` != 0 ]; then \
		$(GNU_ROOT)/bin/gobjdump -t $(EBOOT_BIN) | fgrep '*UND*'; \
		exit 1; \
	fi
	$(GNU_ROOT)/bin/gobjcopy --readonly-text -j .text -j .sdata -j .data \
	    -j .dynamic -j .dynsym -j .rel.dyn -j .rela.dyn -j .reloc \
	    -j .eh_frame --output-target=binary $(EBOOT_BIN) $(EBOOT_BIN_BIN)

#
# GOBJDUMP and GLD should be in Makefile.master
#
#
# The eboot_image symbol is searched for within eboot itself, so if you rename
# this symbol you should also update eboot.
#
# The logic within eboot requires this symbol to be the first symbol in the
# PT_LOAD area, which is then used as the kernel load VA.  So, again, keep a
# careful eye on the interaction between this symbol, eboot itself anf the
# unix mapfile.
#
$(EBOOT_O):	$(EBOOT_BIN_BIN)
	@echo "	.data"					> $(EBOOT_S)
	@echo "	.globl	eboot_image"			>> $(EBOOT_S)
	@echo "	.type	eboot_image,@object"		>> $(EBOOT_S)
	@echo "eboot_image:"				>> $(EBOOT_S)
	@echo ".incbin \"$(EBOOT_BIN_BIN)\""		>> $(EBOOT_S)
	@echo "	.size	eboot_image, . - eboot_image"	>> $(EBOOT_S)
	#$(ELFEXTRACT) $(EBOOT_BIN)			>> $(EBOOT_S)
	$(COMPILE.s) -o $(EBOOT_O) $(EBOOT_S)

$(EBOOT_OBJS_DIR):
	-@mkdir -p $@ 2> /dev/null

#
#	Special rules for generating assym.h for inclusion in assembly files.
#
$(DSF_DIR)/$(OBJS_DIR)/assym.h $(DSF_DIR)/$(OBJS_DIR)/kdi_assym.h:	FRC
	@cd $(DSF_DIR); $(MAKE) all.targ

#
#	Include common targets.
#
include $(UTSBASE)/armsbsa/Makefile.targ
