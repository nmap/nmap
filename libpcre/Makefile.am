## Process this file with automake to produce Makefile.in.

lib_LIBRARIES =

# Some of the binaries we make are to be installed, and others are
# (non-user-visible) helper programs needed to build libpcre.
bin_PROGRAMS =
noinst_PROGRAMS =

# Additional files to delete on 'make clean' and 'make maintainer-clean'.
CLEANFILES =
MAINTAINERCLEANFILES =

pcre.h.generic: configure.ac
	rm -f $@
	cp -p pcre.h $@

MAINTAINERCLEANFILES += pcre.h.generic

# These are the header files we'll install. We do not distribute pcre.h because
# it is generated from pcre.h.in.
nodist_include_HEADERS = pcre.h
include_HEADERS = pcreposix.h

bin_SCRIPTS = pcre-config

## ---------------------------------------------------------------
## The dftables program is used to rebuild character tables before compiling
## PCRE, if --enable-rebuild-chartables is specified. It is not a user-visible
## program. The default (when --enable-rebuild-chartables is not specified) is
## to copy a distributed set of tables that are defined for ASCII code. In this
## case, dftables is not needed.

if WITH_REBUILD_CHARTABLES

noinst_PROGRAMS += dftables
dftables_SOURCES = dftables.c

pcre_chartables.c: dftables$(EXEEXT)
	./dftables$(EXEEXT) $@
else

pcre_chartables.c: $(srcdir)/pcre_chartables.c.dist
	rm -f $@
	$(LN_S) $(srcdir)/pcre_chartables.c.dist $@

endif # WITH_REBUILD_CHARTABLES


## The main pcre library
lib_LIBRARIES += libpcre.a
libpcre_a_SOURCES = \
  pcre_compile.c \
  pcre_config.c \
  pcre_dfa_exec.c \
  pcre_exec.c \
  pcre_fullinfo.c \
  pcre_get.c \
  pcre_globals.c \
  pcre_info.c \
  pcre_internal.h \
  pcre_maketables.c \
  pcre_newline.c \
  pcre_ord2utf8.c \
  pcre_refcount.c \
  pcre_study.c \
  pcre_tables.c \
  pcre_try_flipped.c \
  pcre_ucp_searchfuncs.c \
  pcre_valid_utf8.c \
  pcre_version.c \
  pcre_xclass.c \
  ucp.h \
  ucpinternal.h \
  ucptable.h

## This file is generated as part of the building process, so don't distribute.
nodist_libpcre_a_SOURCES = pcre_chartables.c

CLEANFILES += pcre_chartables.c

# A compatibility line, the old build system worked with 'make test'
test: check ;

## end Makefile.am
