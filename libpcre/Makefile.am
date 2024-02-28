## Process this file with automake to produce Makefile.in.

AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = -I m4

## This seems to have become necessary for building in non-source directory.

AM_CPPFLAGS="-I$(srcdir)/src"

## Specify the documentation files that are distributed.

dist_doc_DATA = \
  AUTHORS \
  LICENCE

dist_html_DATA =

dist_man_MANS =

# The Libtool libraries to install.  We'll add to this later.

lib_LTLIBRARIES =

# Unit tests you want to run when people type 'make check'.
# TESTS is for binary unit tests, check_SCRIPTS for script-based tests

TESTS =
check_SCRIPTS =
dist_noinst_SCRIPTS =

# Some of the binaries we make are to be installed, and others are
# (non-user-visible) helper programs needed to build the libraries.

bin_PROGRAMS =
noinst_PROGRAMS =

# Additional files to delete on 'make clean', 'make distclean',
# and 'make maintainer-clean'.

CLEANFILES =
DISTCLEANFILES = src/config.h.in~
MAINTAINERCLEANFILES =

# Additional files to bundle with the distribution, over and above what
# the Autotools include by default.

EXTRA_DIST =

# These files contain additional m4 macros that are used by autoconf.

EXTRA_DIST += \
  m4/ax_pthread.m4 m4/pcre2_visibility.m4

# These files are usable versions of pcre2.h and config.h that are distributed
# for the benefit of people who are building PCRE2 manually, without the
# Autotools support.

EXTRA_DIST += \
  src/pcre2.h.generic \
  src/config.h.generic

# The only difference between pcre2.h.in and pcre2.h is the setting of the PCRE
# version number. Therefore, we can create the generic version just by copying.

src/pcre2.h.generic: src/pcre2.h.in configure.ac
	rm -f $@
	cp -p src/pcre2.h $@

# It is more complicated for config.h.generic. We need the version that results
# from a default configuration so as to get all the default values for PCRE
# configuration macros such as MATCH_LIMIT and NEWLINE. We can get this by
# doing a configure in a temporary directory. However, some trickery is needed,
# because the source directory may already be configured. If you just try
# running configure in a new directory, it complains. For this reason, we move
# config.status out of the way while doing the default configuration. The
# resulting config.h is munged by perl to put #ifdefs round any #defines for
# macros with values, and to #undef all boolean macros such as HAVE_xxx and
# SUPPORT_xxx. We also get rid of any gcc-specific visibility settings.

src/config.h.generic: configure.ac
	rm -rf $@ _generic
	mkdir _generic
	cs=$(srcdir)/config.status; test ! -f $$cs || mv -f $$cs $$cs.aside
	cd _generic && $(abs_top_srcdir)/configure || :
	cs=$(srcdir)/config.status; test ! -f $$cs.aside || mv -f $$cs.aside $$cs
	test -f _generic/src/config.h
	perl -n \
	  -e 'BEGIN{$$blank=0;}' \
	  -e 'if(/(.+?)\s*__attribute__ \(\(visibility/){print"$$1\n";$$blank=0;next;}' \
	  -e 'if(/LT_OBJDIR/){print"/* This is ignored unless you are using libtool. */\n";}' \
	  -e 'if(/^#define\s((?:HAVE|SUPPORT|STDC)_\w+)/){print"/* #undef $$1 */\n";$$blank=0;next;}' \
	  -e 'if(/^#define\s(?!PACKAGE|VERSION)(\w+)/){print"#ifndef $$1\n$$_#endif\n";$$blank=0;next;}' \
	  -e 'if(/^\s*$$/){print unless $$blank; $$blank=1;} else{print;$$blank=0;}' \
	  _generic/src/config.h >$@
	rm -rf _generic

MAINTAINERCLEANFILES += src/pcre2.h.generic src/config.h.generic

# These are the header files we'll install. We do not distribute pcre2.h
# because it is generated from pcre2.h.in.

nodist_include_HEADERS = src/pcre2.h
include_HEADERS = src/pcre2posix.h

# This is the "config" script.

bin_SCRIPTS = pcre2-config

## ---------------------------------------------------------------
## The pcre2_dftables program is used to rebuild character tables before
## compiling PCRE2, if --enable-rebuild-chartables is specified. It is not an
## installed program. The default (when --enable-rebuild-chartables is not
## specified) is to copy a distributed set of tables that are defined for ASCII
## code. In this case, pcre2_dftables is not needed.

if WITH_REBUILD_CHARTABLES
noinst_PROGRAMS += pcre2_dftables
pcre2_dftables_SOURCES = src/pcre2_dftables.c
src/pcre2_chartables.c: pcre2_dftables$(EXEEXT)
	rm -f $@
	./pcre2_dftables$(EXEEXT) $@
else
src/pcre2_chartables.c: $(srcdir)/src/pcre2_chartables.c.dist
	rm -f $@
	$(LN_S) $(abs_srcdir)/src/pcre2_chartables.c.dist $(abs_builddir)/src/pcre2_chartables.c
endif # WITH_REBUILD_CHARTABLES

BUILT_SOURCES = src/pcre2_chartables.c
NODIST_SOURCES = src/pcre2_chartables.c

## Define the list of common sources, then arrange to build whichever of the
## 8-, 16-, or 32-bit libraries are configured.

COMMON_SOURCES = \
  src/pcre2_auto_possess.c \
  src/pcre2_chkdint.c \
  src/pcre2_compile.c \
  src/pcre2_config.c \
  src/pcre2_context.c \
  src/pcre2_convert.c \
  src/pcre2_dfa_match.c \
  src/pcre2_error.c \
  src/pcre2_extuni.c \
  src/pcre2_find_bracket.c \
  src/pcre2_internal.h \
  src/pcre2_intmodedep.h \
  src/pcre2_jit_compile.c \
  src/pcre2_maketables.c \
  src/pcre2_match.c \
  src/pcre2_match_data.c \
  src/pcre2_newline.c \
  src/pcre2_ord2utf.c \
  src/pcre2_pattern_info.c \
  src/pcre2_script_run.c \
  src/pcre2_serialize.c \
  src/pcre2_string_utils.c \
  src/pcre2_study.c \
  src/pcre2_substitute.c \
  src/pcre2_substring.c \
  src/pcre2_tables.c \
  src/pcre2_ucd.c \
  src/pcre2_ucp.h \
  src/pcre2_valid_utf.c \
  src/pcre2_xclass.c

# The pcre2_ucptables.c file is #included by pcre2_tables.c

EXTRA_DIST += src/pcre2_ucptables.c

if WITH_PCRE2_8
lib_LTLIBRARIES += libpcre2-8.la
libpcre2_8_la_SOURCES = \
  $(COMMON_SOURCES)
nodist_libpcre2_8_la_SOURCES = \
  $(NODIST_SOURCES)
libpcre2_8_la_CFLAGS = \
  -DPCRE2_CODE_UNIT_WIDTH=8 \
  $(VISIBILITY_CFLAGS) \
  $(CET_CFLAGS) \
  $(AM_CFLAGS)
libpcre2_8_la_LIBADD =
endif # WITH_PCRE2_8

if WITH_PCRE2_16
lib_LTLIBRARIES += libpcre2-16.la
libpcre2_16_la_SOURCES = \
  $(COMMON_SOURCES)
nodist_libpcre2_16_la_SOURCES = \
  $(NODIST_SOURCES)
libpcre2_16_la_CFLAGS = \
  -DPCRE2_CODE_UNIT_WIDTH=16 \
  $(VISIBILITY_CFLAGS) \
  $(CET_CFLAGS) \
  $(AM_CFLAGS)
libpcre2_16_la_LIBADD =
endif # WITH_PCRE2_16

if WITH_PCRE2_32
lib_LTLIBRARIES += libpcre2-32.la
libpcre2_32_la_SOURCES = \
  $(COMMON_SOURCES)
nodist_libpcre2_32_la_SOURCES = \
  $(NODIST_SOURCES)
libpcre2_32_la_CFLAGS = \
  -DPCRE2_CODE_UNIT_WIDTH=32 \
  $(VISIBILITY_CFLAGS) \
  $(CET_CFLAGS) \
  $(AM_CFLAGS)
libpcre2_32_la_LIBADD =
endif # WITH_PCRE2_32

# The pcre2_chartables.c.dist file is the default version of
# pcre2_chartables.c, used unless --enable-rebuild-chartables is specified.

EXTRA_DIST += src/pcre2_chartables.c.dist
CLEANFILES += src/pcre2_chartables.c

if WITH_PCRE2_8
libpcre2_8_la_LDFLAGS = $(EXTRA_LIBPCRE2_8_LDFLAGS)
endif # WITH_PCRE2_8
if WITH_PCRE2_16
libpcre2_16_la_LDFLAGS = $(EXTRA_LIBPCRE2_16_LDFLAGS)
endif # WITH_PCRE2_16
if WITH_PCRE2_32
libpcre2_32_la_LDFLAGS = $(EXTRA_LIBPCRE2_32_LDFLAGS)
endif # WITH_PCRE2_32

if WITH_VALGRIND
if WITH_PCRE2_8
libpcre2_8_la_CFLAGS += $(VALGRIND_CFLAGS)
endif # WITH_PCRE2_8
if WITH_PCRE2_16
libpcre2_16_la_CFLAGS += $(VALGRIND_CFLAGS)
endif # WITH_PCRE2_16
if WITH_PCRE2_32
libpcre2_32_la_CFLAGS += $(VALGRIND_CFLAGS)
endif # WITH_PCRE2_32
endif # WITH_VALGRIND

if WITH_GCOV
if WITH_PCRE2_8
libpcre2_8_la_CFLAGS += $(GCOV_CFLAGS)
endif # WITH_PCRE2_8
if WITH_PCRE2_16
libpcre2_16_la_CFLAGS += $(GCOV_CFLAGS)
endif # WITH_PCRE2_16
if WITH_PCRE2_32
libpcre2_32_la_CFLAGS += $(GCOV_CFLAGS)
endif # WITH_PCRE2_32
endif # WITH_GCOV

## A version of the 8-bit library that has a POSIX API.

if WITH_PCRE2_8
lib_LTLIBRARIES += libpcre2-posix.la
libpcre2_posix_la_SOURCES = src/pcre2posix.c
libpcre2_posix_la_CFLAGS = \
  -DPCRE2_CODE_UNIT_WIDTH=8 @PCRE2POSIX_CFLAG@ \
  $(VISIBILITY_CFLAGS) $(AM_CFLAGS)
libpcre2_posix_la_LDFLAGS = $(EXTRA_LIBPCRE2_POSIX_LDFLAGS)
libpcre2_posix_la_LIBADD = libpcre2-8.la
if WITH_GCOV
libpcre2_posix_la_CFLAGS += $(GCOV_CFLAGS)
endif # WITH_GCOV
endif # WITH_PCRE2_8

# gcov/lcov code coverage reporting
#
# Coverage reporting targets:
#
# coverage: Create a coverage report from 'make check'
# coverage-baseline: Capture baseline coverage information
# coverage-reset: This zeros the coverage counters only
# coverage-report: This creates the coverage report only
# coverage-clean-report: This removes the generated coverage report
#   without cleaning the coverage data itself
# coverage-clean-data: This removes the captured coverage data without
#   removing the coverage files created at compile time (*.gcno)
# coverage-clean: This cleans all coverage data including the generated
#   coverage report.

if WITH_GCOV
COVERAGE_TEST_NAME = $(PACKAGE)
COVERAGE_NAME = $(PACKAGE)-$(VERSION)
COVERAGE_OUTPUT_FILE = $(COVERAGE_NAME)-coverage.info
COVERAGE_OUTPUT_DIR = $(COVERAGE_NAME)-coverage
COVERAGE_LCOV_EXTRA_FLAGS =
COVERAGE_GENHTML_EXTRA_FLAGS =

coverage_quiet = $(coverage_quiet_$(V))
coverage_quiet_ = $(coverage_quiet_$(AM_DEFAULT_VERBOSITY))
coverage_quiet_0 = --quiet

coverage-check: all
	-$(MAKE) $(AM_MAKEFLAGS) -k check

coverage-baseline:
	$(LCOV) $(coverage_quiet) \
		--directory $(top_builddir) \
		--output-file "$(COVERAGE_OUTPUT_FILE)" \
		--capture \
		--initial

coverage-report:
	$(LCOV) $(coverage_quiet) \
		--directory $(top_builddir) \
		--capture \
		--output-file "$(COVERAGE_OUTPUT_FILE).tmp" \
		--test-name "$(COVERAGE_TEST_NAME)" \
		--no-checksum \
		--compat-libtool \
		$(COVERAGE_LCOV_EXTRA_FLAGS)
	$(LCOV) $(coverage_quiet) \
		--directory $(top_builddir) \
		--output-file "$(COVERAGE_OUTPUT_FILE)" \
		--remove "$(COVERAGE_OUTPUT_FILE).tmp" \
		"/tmp/*" \
		"/usr/include/*" \
		"$(includedir)/*"
	-@rm -f "$(COVERAGE_OUTPUT_FILE).tmp"
	LANG=C $(GENHTML) $(coverage_quiet) \
		--prefix $(top_builddir) \
		--output-directory "$(COVERAGE_OUTPUT_DIR)" \
		--title "$(PACKAGE) $(VERSION) Code Coverage Report" \
		--show-details "$(COVERAGE_OUTPUT_FILE)" \
		--legend \
		$(COVERAGE_GENHTML_EXTRA_FLAGS)
	@echo "Code coverage report written to file://$(abs_builddir)/$(COVERAGE_OUTPUT_DIR)/index.html"

coverage-reset:
	-$(LCOV) $(coverage_quiet) --zerocounters --directory $(top_builddir)

coverage-clean-report:
	-rm -f "$(COVERAGE_OUTPUT_FILE)" "$(COVERAGE_OUTPUT_FILE).tmp"
	-rm -rf "$(COVERAGE_OUTPUT_DIR)"

coverage-clean-data:
	-find $(top_builddir) -name "*.gcda" -delete

coverage-clean: coverage-reset coverage-clean-report coverage-clean-data
	-find $(top_builddir) -name "*.gcno" -delete

coverage-distclean: coverage-clean

coverage: coverage-reset coverage-baseline coverage-check coverage-report
clean-local: coverage-clean
distclean-local: coverage-distclean

.PHONY: coverage coverage-baseline coverage-check coverage-report coverage-reset coverage-clean-report coverage-clean-data coverage-clean coverage-distclean

# Without coverage support, still arrange for 'make distclean' to get rid of
# any coverage files that may have been left from a different configuration.

else

coverage:
	@echo "Configuring with --enable-coverage is required to generate code coverage report."

DISTCLEANFILES += src/*.gcda src/*.gcno

distclean-local:
	rm -rf $(PACKAGE)-$(VERSION)-coverage*

endif # WITH_GCOV

## CMake support

EXTRA_DIST += \
  cmake/COPYING-CMAKE-SCRIPTS \
  cmake/FindPackageHandleStandardArgs.cmake \
  cmake/pcre2-config-version.cmake.in \
  cmake/pcre2-config.cmake.in \
  CMakeLists.txt \
  config-cmake.h.in

## end Makefile.am
