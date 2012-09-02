# ===========================================================================
#       http://www.gnu.org/software/autoconf-archive/ax_have_epoll.html
# ===========================================================================
#
# SYNOPSIS
#
#   AX_HAVE_EPOLL([ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
#   AX_HAVE_EPOLL_PWAIT([ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
#
# DESCRIPTION
#
#   This macro determines whether the system supports the epoll I/O event
#   interface. A neat usage example would be:
#
#     AX_HAVE_EPOLL(
#       [AX_CONFIG_FEATURE_ENABLE(epoll)],
#       [AX_CONFIG_FEATURE_DISABLE(epoll)])
#     AX_CONFIG_FEATURE(
#       [epoll], [This platform supports epoll(7)],
#       [HAVE_EPOLL], [This platform supports epoll(7).])
#
#   The epoll interface was added to the Linux kernel in version 2.5.45, and
#   the macro verifies that a kernel newer than this is installed. This
#   check is somewhat unreliable if <linux/version.h> doesn't match the
#   running kernel, but it is necessary regardless, because glibc comes with
#   stubs for the epoll_create(), epoll_wait(), etc. that allow programs to
#   compile and link even if the kernel is too old; the problem would then
#   be detected only at runtime.
#
#   Linux kernel version 2.6.19 adds the epoll_pwait() call in addition to
#   epoll_wait(). The availability of that function can be tested with the
#   second macro. Generally speaking, it is safe to assume that
#   AX_HAVE_EPOLL would succeed if AX_HAVE_EPOLL_PWAIT has, but not the
#   other way round.
#
# LICENSE
#
#   Copyright (c) 2008 Peter Simons <simons@cryp.to>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

#serial 10

AC_DEFUN([AX_HAVE_EPOLL], [dnl
  ax_have_epoll_cppflags="${CPPFLAGS}"
  AC_CHECK_HEADER([linux/version.h], [CPPFLAGS="${CPPFLAGS} -DHAVE_LINUX_VERSION_H"])
  AC_MSG_CHECKING([for Linux epoll(7) interface])
  AC_CACHE_VAL([ax_cv_have_epoll], [dnl
    AC_LINK_IFELSE([dnl
      AC_LANG_PROGRAM([dnl
#include <sys/epoll.h>
#ifdef HAVE_LINUX_VERSION_H
#  include <linux/version.h>
#  if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,45)
#    error linux kernel version is too old to have epoll
#  endif
#endif
], [dnl
int fd, rc;
struct epoll_event ev;
fd = epoll_create(128);
rc = epoll_wait(fd, &ev, 1, 0);])],
      [ax_cv_have_epoll=yes],
      [ax_cv_have_epoll=no])])
  CPPFLAGS="${ax_have_epoll_cppflags}"
  AS_IF([test "${ax_cv_have_epoll}" = "yes"],
    [AC_MSG_RESULT([yes])
$1],[AC_MSG_RESULT([no])
$2])
])dnl

AC_DEFUN([AX_HAVE_EPOLL_PWAIT], [dnl
  ax_have_epoll_cppflags="${CPPFLAGS}"
  AC_CHECK_HEADER([linux/version.h],
    [CPPFLAGS="${CPPFLAGS} -DHAVE_LINUX_VERSION_H"])
  AC_MSG_CHECKING([for Linux epoll(7) interface with signals extension])
  AC_CACHE_VAL([ax_cv_have_epoll_pwait], [dnl
    AC_LINK_IFELSE([dnl
      AC_LANG_PROGRAM([dnl
#ifdef HAVE_LINUX_VERSION_H
#  include <linux/version.h>
#  if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
#    error linux kernel version is too old to have epoll_pwait
#  endif
#endif
#include <sys/epoll.h>
#include <signal.h>
], [dnl
int fd, rc;
struct epoll_event ev;
fd = epoll_create(128);
rc = epoll_wait(fd, &ev, 1, 0);
rc = epoll_pwait(fd, &ev, 1, 0, (sigset_t const *)(0));])],
      [ax_cv_have_epoll_pwait=yes],
      [ax_cv_have_epoll_pwait=no])])
  CPPFLAGS="${ax_have_epoll_cppflags}"
  AS_IF([test "${ax_cv_have_epoll_pwait}" = "yes"],
    [AC_MSG_RESULT([yes])
$1],[AC_MSG_RESULT([no])
$2])
])dnl
