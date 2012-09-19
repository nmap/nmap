dnl -----------------------------------------------------------------
dnl Nbase local macros
dnl $Id$
dnl -----------------------------------------------------------------

dnl
dnl check for working getaddrinfo().  This check is from 
dnl Apache 2.0.40
dnl
dnl Note that if the system doesn't have gai_strerror(), we
dnl can't use getaddrinfo() because we can't get strings
dnl describing the error codes.
dnl
AC_DEFUN(APR_CHECK_WORKING_GETADDRINFO,[
  AC_CACHE_CHECK(for working getaddrinfo, ac_cv_working_getaddrinfo,[
  AC_TRY_RUN( [
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

int main(void) {
    struct addrinfo hints, *ai;
    int error;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    error = getaddrinfo("127.0.0.1", NULL, &hints, &ai);
    if (error) {
        return 1;
    }
    if (ai->ai_addr->sa_family != AF_INET) {
        return 1;
    }
    return 0;
}
],[
  ac_cv_working_getaddrinfo="yes"
],[
  ac_cv_working_getaddrinfo="no"
],[
  ac_cv_working_getaddrinfo="yes"
])])
if test "$ac_cv_working_getaddrinfo" = "yes"; then
  if test "$ac_cv_func_gai_strerror" != "yes"; then
    ac_cv_working_getaddrinfo="no"
  else
    AC_DEFINE(HAVE_GETADDRINFO, 1, [Define if getaddrinfo exists and works well enough for APR])
  fi
fi
])

dnl
dnl check for working getnameinfo() -- from Apache 2.0.40
dnl
AC_DEFUN(APR_CHECK_WORKING_GETNAMEINFO,[
  AC_CACHE_CHECK(for working getnameinfo, ac_cv_working_getnameinfo,[
  AC_TRY_RUN( [
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

int main(void) {
    struct sockaddr_in sa;
    char hbuf[256];
    int error;

    sa.sin_family = AF_INET;
    sa.sin_port = 0;
    sa.sin_addr.s_addr = inet_addr("127.0.0.1");
#ifdef SIN6_LEN
    sa.sin_len = sizeof(sa);
#endif

    error = getnameinfo((const struct sockaddr *)&sa, sizeof(sa),
                        hbuf, 256, NULL, 0,
                        NI_NUMERICHOST);
    if (error) {
        return 1;
    } else {
        return 0;
    }
}
],[
  ac_cv_working_getnameinfo="yes"
],[
  ac_cv_working_getnameinfo="no"
],[
  ac_cv_working_getnameinfo="yes"
])])
if test "$ac_cv_working_getnameinfo" = "yes"; then
  AC_DEFINE(HAVE_GETNAMEINFO, 1, [Define if getnameinfo exists])
fi
])

AC_DEFUN(APR_CHECK_SOCKADDR_IN6,[
AC_CACHE_CHECK(for sockaddr_in6, ac_cv_define_sockaddr_in6,[
AC_TRY_COMPILE([
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
],[
struct sockaddr_in6 sa;
],[
    ac_cv_define_sockaddr_in6=yes
],[
    ac_cv_define_sockaddr_in6=no
])
])

if test "$ac_cv_define_sockaddr_in6" = "yes"; then
  have_sockaddr_in6=1
  AC_DEFINE(HAVE_SOCKADDR_IN6)
else
  have_sockaddr_in6=0
fi
])

AC_DEFUN(CHECK_AF_INET6_DEFINE,[
AC_CACHE_CHECK(for AF_INET6 definition, ac_cv_define_af_inet6,[
AC_TRY_COMPILE([
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
],[
int af = AF_INET6;
],[
    ac_cv_define_af_inet6=yes
],[
    ac_cv_define_af_inet6=no
])
])

if test "$ac_cv_define_af_inet6" = "yes"; then
  have_af_inet6=1
  AC_DEFINE(HAVE_AF_INET6)
else
  have_af_inet6=0
fi
])

AC_DEFUN(APR_CHECK_SOCKADDR_STORAGE,[
AC_CACHE_CHECK(for sockaddr_storage, ac_cv_define_sockaddr_storage,[
AC_TRY_COMPILE([
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
],[
struct sockaddr_storage sa;
],[
    ac_cv_define_sockaddr_storage=yes
],[
    ac_cv_define_sockaddr_storage=no
])
])

if test "$ac_cv_define_sockaddr_storage" = "yes"; then
  have_sockaddr_storage=1
  AC_DEFINE(HAVE_SOCKADDR_STORAGE)
else
  have_sockaddr_storage=0
fi
])

dnl This test taken from GCC libjava.
AC_DEFUN(CHECK_PROC_SELF_EXE,[
  if test x"$cross_compiling" = x"no"; then
    AC_CHECK_FILES(/proc/self/exe, [
      AC_DEFINE(HAVE_PROC_SELF_EXE, 1, [Define if you have /proc/self/exe])])
  else
    case $host in
      *-linux*)
      AC_DEFINE(HAVE_PROC_SELF_EXE, 1, [Define if you have /proc/self/exe])
      ;;
    esac
  fi
])
