dnl # -*- mode: fundamental; -*-
dnl # Autoconf configuration file for Nbase
dnl #
dnl # Process this file with autoconf to produce a configure script.
dnl # $Id$

# Because nbase is usually distributed with Nmap, the necessary files
# config.guess, config.guess, and install-sh are not distributed with
# nbase. Rather they are gotten from Nmap.

# Require autoconf 2.13
AC_PREREQ(2.13)

# Include my own macros
m4_include([acinclude.m4])

AC_INIT(nbase.h)

AC_ARG_WITH(localdirs,
  [  --with-localdirs        Explicitly ask compiler to use /usr/local/{include,libs} if they exist ],
  [ case "$with_localdirs" in
      yes)
        user_localdirs=1
        ;;
      no)
        user_localdirs=0
        ;;
    esac
    ],
  [ user_localdirs=0 ] )

if test "$user_localdirs" = 1; then
   if test -d /usr/local/lib; then
     LDFLAGS="$LDFLAGS -L/usr/local/lib"
     fi
   if test -d /usr/local/include; then
     CPPFLAGS="$CPPFLAGS -I/usr/local/include"
   fi
fi

dnl use config.h instad of -D macros
AC_CONFIG_HEADER(nbase_config.h)

dnl Checks for programs.
AC_PROG_CC

 if test -n "$GCC"; then
      CFLAGS="$CFLAGS -Wall "
 fi
AC_PROG_RANLIB
dnl AC_PROG_INSTALL
dnl AC_PATH_PROG(MAKEDEPEND, makedepend)

dnl Host specific hacks
AC_CANONICAL_HOST

dnl equiv to '#define inline' to 'inline', '__inline__', '__inline' or ''
AC_C_INLINE

case "$host" in
  *-sgi-irix5* | *-sgi-irix6*)
    if test -z "$GCC"; then
      AC_DEFINE(inline, )
    fi
    ;;
esac

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS( string.h getopt.h strings.h sys/param.h sys/time.h unistd.h errno.h sys/select.h sys/types.h sys/socket.h netinet/in.h arpa/inet.h sys/stat.h netdb.h sys/wait.h fcntl.h sys/resource.h inttypes.h mach-o/dyld.h)
AC_HEADER_TIME
dnl A special check required for <net/if.h> on Darwin. See
dnl http://www.gnu.org/software/autoconf/manual/html_node/Header-Portability.html.
AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_HEADERS([net/if.h], [], [],
[#include <stdio.h>
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
])

AC_MSG_CHECKING(for __attribute__)
AC_CACHE_VAL(ac_cv___attribute__, [
  AC_TRY_COMPILE(
	[
	#include <stdlib.h>

	static void foo(void) __attribute__ ((noreturn));

	static void
	foo(void)
	{
	  exit(1);
	}
	],
	[
	  foo();
	],
	ac_cv___attribute__=yes,
	ac_cv___attribute__=no
  )
])
if test "$ac_cv___attribute__" = "yes"; then
  AC_DEFINE(HAVE___ATTRIBUTE__, 1, [define if your compiler has __attribute__])
fi
AC_MSG_RESULT($ac_cv___attribute__)

AC_SUBST(CFLAGS)


dnl This test is from the configure.in of Unix Network Programming second
dnl edition example code by W. Richard Stevens
dnl ##################################################################
dnl Check if sockaddr{} has sa_len member.
dnl
AC_CACHE_CHECK(if sockaddr{} has sa_len member, ac_cv_sockaddr_has_sa_len,
        AC_TRY_COMPILE([
               #include <sys/types.h>
               #include <sys/socket.h>],
                [unsigned int i = sizeof(((struct sockaddr *)0)->sa_len)],
        ac_cv_sockaddr_has_sa_len=yes,
        ac_cv_sockaddr_has_sa_len=no))
if test $ac_cv_sockaddr_has_sa_len = yes ; then
        AC_DEFINE(HAVE_SOCKADDR_SA_LEN, 1, [define if sockaddr has sa_len member])
fi

dnl check endedness
AC_C_BIGENDIAN

dnl determine types so nbase can export u32, u16, etc.
AC_TYPE_INT8_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

dnl Checks for library functions.
AC_CHECK_FUNCS( snprintf vsnprintf nanosleep strerror strcasestr strcasecmp strncasecmp signal )

needsnprintf=no
AC_CHECK_FUNCS(vsnprintf snprintf asprintf asnprintf vasprintf vasnprintf,,
        [needsnprintf=yes])
if test $needsnprintf = yes; then
        AC_LIBOBJ([snprintf])
fi

AC_CHECK_FUNCS( getopt getopt_long_only)

AC_CHECK_FUNCS(usleep gettimeofday sleep localtime_s localtime_r)
dnl Some of these time functions are always needed
AC_LIBOBJ([nbase_time])

AC_CHECK_FUNC(getopt_long_only, , 
  [ AC_LIBOBJ([getopt]) ])

AC_CHECK_FUNCS(strcasecmp strncasecmp, , 
  [ AC_LIBOBJ([strcasecmp]) ])

dnl We always want some of our files
AC_LIBOBJ([nbase_str])
AC_LIBOBJ([nbase_misc])
AC_LIBOBJ([nbase_memalloc])
AC_LIBOBJ([nbase_rnd])
AC_LIBOBJ([nbase_addrset])

# Check for IPv6 support -- modified from Apache 2.0.40:

AC_ARG_ENABLE(ipv6,
  [  --disable-ipv6          Disable IPv6 support ],
  [ if test "$enableval" = "no"; then
        user_disabled_ipv6=1
    fi ],
  [ user_disabled_ipv6=0 ] )

AC_SEARCH_LIBS(getaddrinfo, [inet6 socket])
AC_SEARCH_LIBS(gai_strerror, [inet6 socket])
AC_SEARCH_LIBS(getnameinfo, [inet6 socket])
AC_SEARCH_LIBS(inet_ntop, [nsl resolv network], [],
               [AC_LIBOBJ(inet_ntop)
               ])
AC_SEARCH_LIBS(inet_pton, [nsl resolv network], [],
               [AC_LIBOBJ(inet_pton)
               ])
AC_CHECK_FUNCS([gai_strerror inet_pton inet_ntop])
APR_CHECK_WORKING_GETADDRINFO
# The inet_addr function is used by APR_CHECK_WORKING_GETNAMEINFO.
AC_SEARCH_LIBS(inet_addr, [nsl])
APR_CHECK_WORKING_GETNAMEINFO
APR_CHECK_SOCKADDR_IN6
APR_CHECK_SOCKADDR_STORAGE
CHECK_AF_INET6_DEFINE

AC_MSG_CHECKING(for IPv6 support)
have_ipv6="0"
if test "$user_disabled_ipv6" = 1; then
    AC_MSG_RESULT("no -- disabled by user")
else
    if test "x$have_sockaddr_in6" = "x1"; then
        if test "x$ac_cv_working_getaddrinfo" = "xyes"; then
            if test "x$ac_cv_working_getnameinfo" = "xyes"; then
                have_ipv6="1"
                AC_MSG_RESULT(yes)
            else
                AC_MSG_RESULT("no -- no working getnameinfo")
            fi
        else
            AC_MSG_RESULT("no -- no working getaddrinfo")
        fi
    else
        AC_MSG_RESULT("no -- no sockaddr_in6");
    fi
fi

if test "x$ac_cv_working_getaddrinfo" != "xyes"; then
AC_LIBOBJ([getaddrinfo])
fi

if test "x$ac_cv_working_getnameinfo" != "xyes"; then
AC_LIBOBJ([getnameinfo])
fi

if test "$have_ipv6" = "1"; then
  AC_DEFINE(HAVE_IPV6, 1, [define if IPv6 is available])
fi

# First we test whether they specified openssl desires explicitly
use_openssl="yes"
specialssldir=""

AC_ARG_WITH(openssl,
[  --with-openssl=DIR    Use optional openssl libs and includes from [DIR]/lib/ 
and [DIR]/include/openssl/)],
[  case "$with_openssl" in
  yes)
    ;;
  no)
    use_openssl="no"
    ;;
  *)
    specialssldir="$with_openssl"
    ;;
  esac]
)


# If they didn't specify it, we try to find it
if test "$use_openssl" = "yes" -a -z "$specialssldir"; then
  AC_CHECK_HEADER(openssl/ssl.h,,
  [ use_openssl="no"
    AC_MSG_WARN([Failed to find openssl/ssl.h so OpenSSL will not be used. If it
 is installed you can try the --with-openssl=DIR argument]) ])

 if test "$use_openssl" = "yes"; then
   AC_CHECK_HEADER(openssl/err.h,,
    [ use_openssl="no"
    AC_MSG_WARN([Failed to find openssl/err.h so OpenSSL will not be used. If it
 is installed you can try the --with-openssl=DIR argument]) ])
 fi

 if test "$use_openssl" = "yes"; then
   AC_CHECK_HEADER(openssl/rand.h,,
    [ use_openssl="no"
    AC_MSG_WARN([Failed to find openssl/rand.h so OpenSSL will not be used. If i
t is installed you can try the --with-openssl=DIR argument]) ])
 fi

 if test "$use_openssl" = "yes"; then
   AC_CHECK_LIB(crypto, BIO_int_ctrl,
    [],
    [ use_openssl="no"
    AC_MSG_WARN([Failed to find libcrypto so OpenSSL will not be used. If it is installed you can try the --with-openssl=DIR argument]) ])
 fi

 if test "$use_openssl" = "yes"; then
   AC_CHECK_LIB(ssl, SSL_new,
    [],
    [ use_openssl="no"
    AC_MSG_WARN([Failed to find libssl so OpenSSL will not be used. If it is ins
talled you can try the --with-openssl=DIR argument]) ])
 fi
fi

if test "$use_openssl" = "yes"; then
  AC_DEFINE(HAVE_OPENSSL, 1, [define if libssl is available])
fi

CHECK_PROC_SELF_EXE

AC_OUTPUT(Makefile)

