
SRCS += cache.c \
	exec.c \
	isadir.c \
	start.S

OBJS += cache.o \
	exec.o \
	isadir.o \
	start.o

SRCS +=	nullconsole.c \
	spinconsole.c \
	efiserialio.c

OBJS += nullconsole.o \
	spinconsole.o \
	efiserialio.o

start.o := CCASFLAGS += $(C_BIGPICFLAGS)
