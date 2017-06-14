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
EXTRA_DIST += key_dsa key_dsa.pub key_dsa_wrong key_dsa_wrong.pub key_rsa key_rsa.pub
EXTRA_DIST += openssh_server/authorized_keys openssh_server/Dockerfile openssh_server/ssh_host_rsa_key
EXTRA_DIST += openssh_fixture.c openssh_fixture.h runner.c session_fixture.c session_fixture.h
EXTRA_DIST += test_hostkey.c test_hostkey_hash.c
EXTRA_DIST += test_keyboard_interactive_auth_fails_with_wrong_response.c
EXTRA_DIST += test_keyboard_interactive_auth_succeeds_with_correct_response.c
EXTRA_DIST += test_password_auth_fails_with_wrong_password.c
EXTRA_DIST += test_password_auth_fails_with_wrong_username.c
EXTRA_DIST += test_password_auth_succeeds_with_correct_credentials.c
EXTRA_DIST += test_public_key_auth_fails_with_wrong_key.c
EXTRA_DIST += test_public_key_auth_succeeds_with_correct_dsa_key.c
EXTRA_DIST += test_public_key_auth_succeeds_with_correct_rsa_key.c
