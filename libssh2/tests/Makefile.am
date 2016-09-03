AM_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/include -I$(top_builddir)/src
LDADD = ../src/libssh2.la

if SSHD
noinst_PROGRAMS = ssh2
ssh2_SOURCES = ssh2.c
endif

ctests = simple$(EXEEXT)
TESTS = $(ctests) mansyntax.sh
if SSHD
TESTS += ssh2.sh
endif
check_PROGRAMS = $(ctests)

TESTS_ENVIRONMENT = SSHD=$(SSHD) EXEEXT=$(EXEEXT)
TESTS_ENVIRONMENT += srcdir=$(top_srcdir)/tests builddir=$(top_builddir)/tests

EXTRA_DIST = ssh2.sh mansyntax.sh
EXTRA_DIST += etc/host etc/host.pub etc/user etc/user.pub
EXTRA_DIST += CMakeLists.txt libssh2_config_cmake.h.in sshd_fixture.sh.in
