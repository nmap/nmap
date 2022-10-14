dnl Type of 6th argument to recvfrom(). Usually int or socklen_t.
AC_DEFUN([RECVFROM_ARG6_TYPE],
[
   AC_LANG_PUSH(C++)
   AC_MSG_CHECKING([for type of 6th argument to recvfrom()])
   recvfrom6_t=
   for t in socklen_t int; do
     AC_TRY_COMPILE([
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>],[
$t arg;
recvfrom (0, NULL, 0, 0, NULL, &arg);],[
      recvfrom6_t="$t"
      break])
   done

   if test "x$recvfrom6_t" = x; then
     AC_MSG_WARN([Cannot find type for 6th argument to recvfrom(). Using socklen_t ptr])
     recvfrom6_t="socklen_t"
   fi

   AC_MSG_RESULT($recvfrom6_t)
   AC_DEFINE_UNQUOTED(recvfrom6_t, $recvfrom6_t,
     [Type of 6th argument to recvfrom()])
   AC_LANG_POP(C++)
])

dnl Checks if the pcap version is suitable. The has to be at least version
dnl 0.9.4. Mac OS X 10.6 has a bug in its BIOCSRTIMEOUT ioctl that is worked
dnl around in libpcap 1.1.0 and later; but before that we must use our own copy.
AC_DEFUN([PCAP_IS_SUITABLE],
[
  AC_CHECK_HEADERS(sys/ioccom.h sys/time.h net/bpf.h)
  AC_MSG_CHECKING(if libpcap is suitable)
  AC_TRY_RUN([
#include <stdio.h>
extern char pcap_version[];
int main() {
  int major, minor1, minor2;
  sscanf(pcap_version,"%d.%d.%d", &major, &minor1, &minor2);
  if (major > 0)
    return 0;
  if (minor1 < 9)
    return 1;
  if (minor2 < 4)
    return 1;
  return 0;
}
  ], [
    AC_TRY_RUN([
#include <stdio.h>
#include <sys/types.h>
#ifdef HAVE_SYS_IOCCOM_H
#include <sys/ioccom.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_NET_BPF_H
#include <net/bpf.h>
#endif
extern char pcap_version[];
int main() {
  int major, minor;
  sscanf(pcap_version,"%d.%d", &major, &minor);
  if ((major == 1 && minor >= 1) || major > 1)
    return 0;
#ifdef BIOCSRTIMEOUT
#ifdef IOCPARM_LEN
  if (IOCPARM_LEN(BIOCSRTIMEOUT) != sizeof(struct timeval))
    return 1;
#endif
#endif
  return 0;
}
    ], [
      AC_CHECK_DECL([pcap_get_selectable_fd],
        [AC_MSG_RESULT(yes); $1],
        [AC_MSG_RESULT(no -- pcap_get_selectable_fd not declared); $2],
        [[#include <pcap.h>]])
    ],
    [AC_MSG_RESULT(no -- BPF_TIMEOUT BIOCSRTIMEOUT bug (64-bit OS X)); $2])
  ],
  [AC_MSG_RESULT(no); $2],
  [AC_MSG_RESULT(cross-compiling -- assuming yes); $3])
])

dnl Checks if IPPROTO_RAW induces IP_HDRINCL-like behavior in AF_INET6 sockets.
dnl Defines HAVE_IPV6_IPPROTO_RAW if so. So far I only know this happens on
dnl Linux.
AC_DEFUN([CHECK_IPV6_IPPROTO_RAW],
[
  AC_MSG_CHECKING(if AF_INET6 IPPROTO_RAW sockets include the packet header)
  # This should be replaced with a better test, if possible.
  case "$host" in
    *-linux*)
      AC_DEFINE(HAVE_IPV6_IPPROTO_RAW, 1,
        [If AF_INET6 IPPROTO_RAW sockets include the packet header])
      AC_MSG_RESULT(yes)
      ;;
    *)
      AC_MSG_RESULT(no)
      ;;
  esac
])

AC_DEFUN([LARGE_FILES_IF_NOT_BROKEN],
[
  AC_LANG_PUSH(C++)
  AC_MSG_CHECKING([for broken _LARGE_FILES support, such as with gcc <4.4.0 on AIX])
  AC_CACHE_VAL(ac_cv_large_files_broken,
    AC_TRY_COMPILE(
      [
#define _LARGE_FILES 1
#include<cstdio>],
      [],
      ac_cv_large_files_broken=no,
      ac_cv_large_files_broken=yes))
  if test $ac_cv_large_files_broken = no; then
    AC_SYS_LARGEFILE
  fi
  AC_MSG_RESULT($ac_cv_large_files_broken)
  AC_LANG_POP(C++)
]
)
