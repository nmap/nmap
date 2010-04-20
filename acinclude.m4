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
    exit(0);
  if (minor1 < 9)
    exit(1);
  if (minor2 < 4)
    exit(1);
  exit(0);
}
  ], [
    AC_TRY_RUN([
#include <stdio.h>
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
    ],
    [AC_MSG_RESULT(yes); $1],
    [AC_MSG_RESULT(no -- BPF_TIMEOUT BIOCSRTIMEOUT bug (64-bit OS X)); $2])
  ],
  [AC_MSG_RESULT(no); $2],
  [AC_MSG_RESULT(cross-compiling -- assuming yes); $3])
  ])
])
