#########################################################################
#
## Makefile for building libssh2 samples (Win32 version - gnu make)
## Use: make -f GNUmakefile [help]
##
## Hacked by: Guenter Knauf
#
#########################################################################

# Edit the path below to point to the base of your Zlib sources.
ifndef ZLIB_PATH
ZLIB_PATH = ../../../zlib-1.2.8
endif

# Edit the path below to point to the base of your OpenSSL package.
ifndef OPENSSL_PATH
OPENSSL_PATH = ../../../openssl-0.9.8zc
endif

# Project root
PROOT	= ../..

# Edit the var below to enable static linking of libssh2 and libz
LINK_STATIC = 1

# Edit the vars below to change target settings.
SAMPLES	= $(PROOT)/example
TARGETS := $(filter-out x11.exe,$(patsubst $(SAMPLES)/%.c,%.exe,$(strip $(wildcard $(SAMPLES)/*.c))))
WWWURL	= https://www.libssh2.org/
DESCR	= libssh2 $(subst .rc,,$(notdir $@)) $(LIBSSH2_VERSION_STR)
#STACK	= 64000

# must be equal to DEBUG or NDEBUG
ifndef DB
	DB	= NDEBUG
	# DB	= DEBUG
endif
# Optimization: -O<n> or debugging: -g
ifeq ($(DB),NDEBUG)
	OPT	= -O2
	OBJDIR	= release
else
	OPT	= -g
	OBJDIR	= debug
endif

# Here you can find a native Win32 binary of the original awk:
# http://www.gknw.net/development/prgtools/awk-20100523.zip
AWK     = awk
ZIP     = zip -qzr9

# Platform-dependent helper tool macros
ifeq ($(findstring /sh,$(SHELL)),/sh)
DEL	= rm -f $1
RMDIR	= rm -fr $1
MKDIR	= mkdir -p $1
COPY	= -cp -afv $1 $2
#COPYR	= -cp -afr $1/* $2
COPYR	= -rsync -aC $1/* $2
TOUCH	= touch $1
CAT	= cat
ECHONL	= echo ""
DL	= '
else
ifeq "$(OS)" "Windows_NT"
DEL	= -del 2>NUL /q /f $(subst /,\,$1)
RMDIR	= -rd 2>NUL /q /s $(subst /,\,$1)
else
DEL	= -del 2>NUL $(subst /,\,$1)
RMDIR	= -deltree 2>NUL /y $(subst /,\,$1)
endif
MKDIR	= -md 2>NUL $(subst /,\,$1)
COPY	= -copy 2>NUL /y $(subst /,\,$1) $(subst /,\,$2)
COPYR	= -xcopy 2>NUL /q /y /e $(subst /,\,$1) $(subst /,\,$2)
TOUCH	= copy 2>&1>NUL /b $(subst /,\,$1) +,,
CAT	= type
ECHONL	= $(ComSpec) /c echo.
endif

# The following line defines your compiler.
ifdef METROWERKS
	CC = mwcc
else
	CC = $(CROSSPREFIX)gcc
endif

# Set environment var ARCH to your architecture to override autodetection.
ifndef ARCH
ifeq ($(findstring gcc,$(CC)),gcc)
ifeq ($(findstring x86_64,$(shell $(CC) -dumpmachine)),x86_64)
ARCH	= w64
else
ARCH	= w32
endif
else
ARCH	= w32
endif
endif

# Include the version info retrieved from libssh2.h
-include $(OBJDIR)/version.inc

# Global flags for all compilers
CFLAGS	= $(OPT) -D$(DB) -DLIBSSH2_WIN32 # -DHAVE_CONFIG_H

ifeq ($(CC),mwcc)
LD	= mwld
RC	= mwwinrc
LDFLAGS	= -nostdlib
AR	= $(LD)
ARFLAGS	= -nostdlib -library -o
LIBEXT	= lib
LIBPATH	+= -lr "$(METROWERKS)/MSL" -lr "$(METROWERKS)/Win32-x86 Support"
LDLIBS	+= -lMSL_Runtime_x86.lib -lMSL_C_x86.lib -lMSL_Extras_x86.lib
LDLIBS	+= -lkernel32.lib -luser32.lib -lwsock32.lib
RCFLAGS	=
CFLAGS	+= -nostdinc -gccinc -msgstyle gcc -inline off -opt nointrinsics -proc 586
CFLAGS	+= -ir "$(METROWERKS)/MSL" -ir "$(METROWERKS)/Win32-x86 Support"
CFLAGS	+= -w on,nounused,nounusedexpr # -ansi strict
else
LD	= $(CROSSPREFIX)gcc
RC	= $(CROSSPREFIX)windres
LDFLAGS	= -s
AR	= $(CROSSPREFIX)ar
ARFLAGS	= -cq
LIBEXT	= a
#LDLIBS	+= -lwsock32
LDLIBS	+= -lws2_32
RCFLAGS	= -I $(PROOT)/include -O coff
CFLAGS	+= -fno-builtin
CFLAGS	+= -fno-strict-aliasing
CFLAGS	+= -Wall #-Wno-unused #-pedantic
ifeq ($(ARCH),w64)
CFLAGS	+= -D_AMD64_
RCFLAGS	+= -F pe-x86-64
else
CFLAGS	+= -m32
RCFLAGS	+= -F pe-i386
endif
endif

INCLUDES = -I$(PROOT)/win32 -I$(PROOT)/include
LIBPATH += -L$(PROOT)/win32

ifdef LINK_STATIC
	LDLIBS += -llibssh2
else
	LDLIBS += -llibssh2dll
endif

ifdef WITH_WINCNG
# CFLAGS	+= -DLIBSSH2_WINCNG
LDLIBS	+= -lbcrypt -lcrypt32
else
# CFLAGS	+= -DLIBSSH2_OPENSSL
ifndef OPENSSL_INCLUDE
	ifeq "$(wildcard $(OPENSSL_PATH)/outinc)" "$(OPENSSL_PATH)/outinc"
		OPENSSL_INCLUDE = $(OPENSSL_PATH)/outinc
	endif
	ifeq "$(wildcard $(OPENSSL_PATH)/include)" "$(OPENSSL_PATH)/include"
		OPENSSL_INCLUDE = $(OPENSSL_PATH)/include
	endif
endif
ifneq "$(wildcard $(OPENSSL_INCLUDE)/openssl/opensslv.h)" "$(OPENSSL_INCLUDE)/openssl/opensslv.h"
$(error Invalid OPENSSL_PATH: $(OPENSSL_PATH))
endif
INCLUDES += -I"$(OPENSSL_INCLUDE)"
ifndef OPENSSL_LIBPATH
	OPENSSL_LIBS_STAT = crypto ssl
	ifeq "$(wildcard $(OPENSSL_PATH)/out)" "$(OPENSSL_PATH)/out"
		OPENSSL_LIBPATH = $(OPENSSL_PATH)/out
		OPENSSL_LIBS_DYN = eay32 ssl32
	endif
	ifeq "$(wildcard $(OPENSSL_PATH)/lib)" "$(OPENSSL_PATH)/lib"
		OPENSSL_LIBPATH = $(OPENSSL_PATH)/lib
		OPENSSL_LIBS_DYN = crypto.dll ssl.dll
	endif
endif
ifdef LINK_STATIC
ifdef LINK_OPENSSL_STATIC
	LDLIBS += $(patsubst %,$(OPENSSL_LIBPATH)/lib%.$(LIBEXT), $(OPENSSL_LIBS_STAT)) -lgdi32
else
	LDLIBS += $(patsubst %,$(OPENSSL_LIBPATH)/lib%.$(LIBEXT), $(OPENSSL_LIBS_DYN))
endif
endif
endif

ifdef WITH_ZLIB
	CFLAGS += -DLIBSSH2_HAVE_ZLIB
	INCLUDES += -I$(ZLIB_PATH)
	ifdef LINK_ZLIB_STATIC
		LDLIBS += $(ZLIB_PATH)/libz.$(LIBEXT)
	else
		LDLIBS += $(ZLIB_PATH)/libzdll.$(LIBEXT)
	endif
endif

CFLAGS	+= $(INCLUDES)

vpath %.c $(PROOT)/example

.PRECIOUS: $(OBJDIR)/%.o $(OBJDIR)/%.rc $(OBJDIR)/%.res


all: prebuild $(TARGETS)

prebuild: $(OBJDIR) $(OBJDIR)/version.inc

$(OBJDIR)/%.o: %.c
#	@echo Compiling $<
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/version.inc: $(PROOT)/include/libssh2.h $(OBJDIR)
	@echo Creating $@
	@$(AWK) -f $(PROOT)/get_ver.awk $< > $@

objclean:
	$(call RMDIR, $(OBJDIR))

clean: objclean
	$(call DEL, $(TARGETS))

$(OBJDIR):
	$(call MKDIR, $@)

%.exe: $(OBJDIR)/%.o $(OBJDIR)/%.res
	@echo Linking $@
	@$(call DEL, $@)
	$(LD) $(LDFLAGS) $^ -o $@ $(LIBPATH) $(LDLIBS)

$(OBJDIR)/%.res: $(OBJDIR)/%.rc
	@echo Creating $@
	@$(RC) $(RCFLAGS) -i $< -o $@

$(OBJDIR)/%.rc: GNUmakefile $(OBJDIR)/version.inc
	@echo $(DL)1 VERSIONINFO$(DL) > $@
	@echo $(DL) FILEVERSION $(LIBSSH2_VERSION),0$(DL) >> $@
	@echo $(DL) PRODUCTVERSION $(LIBSSH2_VERSION),0$(DL) >> $@
	@echo $(DL) FILEFLAGSMASK 0x3fL$(DL) >> $@
	@echo $(DL) FILEOS 0x40004L$(DL) >> $@
	@echo $(DL) FILEFLAGS 0x0L$(DL) >> $@
	@echo $(DL) FILETYPE 0x1L$(DL) >> $@
	@echo $(DL) FILESUBTYPE 0x0L$(DL) >> $@
	@echo $(DL)BEGIN$(DL) >> $@
	@echo $(DL)  BLOCK "StringFileInfo"$(DL) >> $@
	@echo $(DL)  BEGIN$(DL) >> $@
	@echo $(DL)    BLOCK "040904E4"$(DL) >> $@
	@echo $(DL)    BEGIN$(DL) >> $@
	@echo $(DL)      VALUE "LegalCopyright","\xA9 $(LIBSSH2_COPYRIGHT_STR)\0"$(DL) >> $@
ifdef COMPANY
	@echo $(DL)      VALUE "CompanyName","$(COMPANY)\0"$(DL) >> $@
endif
	@echo $(DL)      VALUE "ProductName","$(notdir $(@:.rc=.exe))\0"$(DL) >> $@
	@echo $(DL)      VALUE "ProductVersion","$(LIBSSH2_VERSION_STR)\0"$(DL) >> $@
	@echo $(DL)      VALUE "License","Released under GPL.\0"$(DL) >> $@
	@echo $(DL)      VALUE "FileDescription","$(DESCR)\0"$(DL) >> $@
	@echo $(DL)      VALUE "FileVersion","$(LIBSSH2_VERSION_STR)\0"$(DL) >> $@
	@echo $(DL)      VALUE "InternalName","$(notdir $(@:.rc=))\0"$(DL) >> $@
	@echo $(DL)      VALUE "OriginalFilename","$(notdir $(@:.rc=.exe))\0"$(DL) >> $@
	@echo $(DL)      VALUE "WWW","$(WWWURL)\0"$(DL) >> $@
	@echo $(DL)    END$(DL) >> $@
	@echo $(DL)  END$(DL) >> $@
	@echo $(DL)  BLOCK "VarFileInfo"$(DL) >> $@
	@echo $(DL)  BEGIN$(DL) >> $@
	@echo $(DL)    VALUE "Translation", 0x409, 1252$(DL) >> $@
	@echo $(DL)  END$(DL) >> $@
	@echo $(DL)END$(DL) >> $@
ifdef ICON
	@echo $(DL)10 ICON DISCARDABLE "$(ICON)"$(DL) >> $@
endif

help: $(OBJDIR)/version.inc
	@echo $(DL)===========================================================$(DL)
	@echo $(DL)OpenSSL path    = $(OPENSSL_PATH)$(DL)
	@echo $(DL)Zlib path       = $(ZLIB_PATH)$(DL)
	@echo $(DL)===========================================================$(DL)
	@echo $(DL)libssh $(LIBSSH2_VERSION_STR) - available targets are:$(DL)
	@echo $(DL)$(MAKE) all$(DL)
	@echo $(DL)$(MAKE) clean$(DL)
	@echo $(DL)$(MAKE) objclean$(DL)
	@echo $(DL)===========================================================$(DL)


