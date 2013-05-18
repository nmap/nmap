# Require autoconf 2.13 -*- mode: fundamental; -*-

# Because nsock is usually distributed with Nmap, the necessary files
# config.guess, config.guess, and install-sh are not distributed with
# nbase. Rather they are gotten from Nmap.

AC_PREREQ(2.13)

dnl Process this file with autoconf to produce a configure script.
AC_INIT(nsock_core.c)

dnl use nsock_config.h instad of -D macros
AC_CONFIG_HEADER(../include/nsock_config.h)

dnl Host specific hacks
AC_CANONICAL_HOST

case "$host" in
  *alpha-dec-osf*)
    AC_DEFINE(DEC)
    ;;
  *-netbsd* | *-knetbsd*-gnu)
    AC_DEFINE(NETBSD)
    ;;
  *-openbsd*)
    AC_DEFINE(OPENBSD)
    ;;
  *-sgi-irix5*)
    AC_DEFINE(IRIX)
    ;;
  *-sgi-irix6*)
    AC_DEFINE(IRIX)
    ;;
  *-hpux*)
    AC_DEFINE(HPUX)
    ;;
  *-solaris2.1[[1-9]]*)
    AC_DEFINE(SOLARIS)
    # Solaris 11 and later use BPF packet capture rather than DLPI.
    AC_DEFINE(SOLARIS_BPF_PCAP_CAPTURE)
    ;;
  *-solaris2.0*)  
    AC_DEFINE(SOLARIS)
    ;;
  *-solaris2.[[1-9]][[0-9]]*)
    AC_DEFINE(SOLARIS)
    ;;
  *-solaris2.1*)
    AC_DEFINE(SOLARIS)
    ;;
  *-solaris2.2*)
    AC_DEFINE(SOLARIS)
    ;;
  *-solaris2.3*)
    AC_DEFINE(SOLARIS)
    ;;
  *-solaris2.4*)
    AC_DEFINE(SOLARIS)
    ;;
  *-solaris2.5.1)
    AC_DEFINE(SOLARIS)
    ;;
  *-solaris*)
    AC_DEFINE(SOLARIS)
    ;;
  *-sunos4*)
    AC_DEFINE(SUNOS)
    ;;
  *-linux*)
    AC_DEFINE(LINUX)
    ;;
  *-freebsd* | *-kfreebsd*-gnu | *-dragonfly*)
    AC_DEFINE(FREEBSD)
    ;;
  *-bsdi*)
    AC_DEFINE(BSDI)
    ;;
  *-apple-darwin*)
    AC_DEFINE(MACOSX)
    ;;
esac


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

pcap_enabled=yes
AC_ARG_WITH(pcap,
  AC_HELP_STRING([--disable-pcap], [Disable pcap functions.]),
  [ pcap_enabled="$withval" ])

if test "$pcap_enabled" != "no"; then
  AC_DEFINE(HAVE_PCAP)
fi

AX_HAVE_EPOLL([AC_DEFINE(HAVE_EPOLL)], )
AX_HAVE_POLL([AC_DEFINE(HAVE_POLL)], )
AC_CHECK_FUNCS(kqueue kevent, [AC_DEFINE(HAVE_KQUEUE)], )

dnl Checks for programs.
AC_PROG_CC
 if test -n "$GCC"; then
      CFLAGS="$CFLAGS -Wall "
 fi
AC_PROG_RANLIB
dnl AC_PROG_INSTALL
dnl AC_PATH_PROG(MAKEDEPEND, makedepend)

dnl Checks for libraries.
dnl AC_CHECK_LIB(m, pow)

dnl If any socket libraries needed
AC_CHECK_FUNC(gethostent, , AC_CHECK_LIB(nsl, gethostent))
AC_CHECK_FUNC(setsockopt, , AC_CHECK_LIB(socket, setsockopt))

dnl need posix4/nanosleep for solaris 2.4
AC_CHECK_FUNC(nanosleep, , AC_CHECK_LIB(posix4, nanosleep))

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(net/bpf.h sys/ioctl.h sys/un.h netdb.h)

# We test whether they specified openssl desires explicitly
use_openssl="yes"
specialssldir=""
AC_ARG_WITH(openssl,
AC_HELP_STRING([--with-openssl=DIR],[Use optional openssl libs and includes from [DIR]/lib/ and [DIR]/include/openssl/)]),
[  case "$with_openssl" in
  yes)
    ;;
  no)
    use_openssl="no"
    ;;
  *)
    specialssldir="$with_openssl"
    CPPFLAGS="$CPPFLAGS -I$with_openssl/include"
    LDFLAGS="$LDFLAGS -L$with_openssl/lib"
    ;;
  esac]
)

# If they didn't specify it, we try to find it
if test "$use_openssl" = "yes" -a -z "$specialssldir"; then
  AC_CHECK_HEADER(openssl/ssl.h,,
  [ use_openssl="no"
    if test "$with_openssl" = "yes"; then
      AC_MSG_ERROR([OpenSSL was explicitly requested but openssl/ssl.h was not found. Try the --with-openssl=DIR argument to give the location of OpenSSL or run configure with --without-openssl.])
    fi
    AC_MSG_WARN([Failed to find openssl/ssl.h so OpenSSL will not be used. If it is installed you can try the --with-openssl=DIR argument])
  ])

# use_openssl="yes" given explicitly in next 2 rules to avoid adding lib to $LIBS
 if test "$use_openssl" = "yes"; then
   AC_CHECK_LIB(crypto, BIO_int_ctrl,
    [ use_openssl="yes"],
    [ use_openssl="no"
    if test "$with_openssl" = "yes"; then
      AC_MSG_ERROR([OpenSSL was explicitly requested but libcrypto was not found. Try the --with-openssl=DIR argument to give the location of OpenSSL or run configure with --without-openssl.])
    fi
    AC_MSG_WARN([Failed to find libcrypto so OpenSSL will not be used. If it is installed you can try the --with-openssl=DIR argument])
   ])
 fi

 if test "$use_openssl" = "yes"; then
   AC_CHECK_LIB(ssl, SSL_new,
    [ use_openssl="yes" ],
    [ use_openssl="no"
    if test "$with_openssl" = "yes"; then
      AC_MSG_ERROR([OpenSSL was explicitly requested but libssl was not found. Try the --with-openssl=DIR argument to give the location of OpenSSL or run configure with --without-openssl.])
    fi
    AC_MSG_WARN([Failed to find libssl so OpenSSL will not be used. If it is installed you can try the --with-openssl=DIR argument]) ],
    [ -lcrypto ])
 fi
fi

# OpenSSL requires dlopen on some platforms
AC_SEARCH_LIBS(dlopen, dl)

OPENSSL_LIBS=
if test "$use_openssl" = "yes"; then
  AC_DEFINE(HAVE_OPENSSL)
  OPENSSL_LIBS="-lssl -lcrypto"
  LIBS="$LIBS $OPENSSL_LIBS"
fi

AC_SUBST(OPENSSL_LIBS)

AC_MSG_CHECKING([for SSL_set_tlsext_host_name])
AC_TRY_LINK([#include <openssl/ssl.h>], [SSL_set_tlsext_host_name(NULL, NULL)],
  [AC_MSG_RESULT([yes]); AC_DEFINE(HAVE_SSL_SET_TLSEXT_HOST_NAME)],
  [AC_MSG_RESULT([no])])

dnl Checks for typedefs, structures, and compiler characteristics.

AC_ARG_WITH(libnbase,
[  --with-libnbase=DIR     Look for nbase include/libs in DIR],
[  case "$with_libnbase" in
  yes)
    ;;
  *)
    NBASEDIR="$with_libnbase"
    ;;
  esac],
NBASEDIR="../../nbase"
)

NSOCKTESTDIR="../tests"

LDFLAGS="$LDFLAGS -L$NBASEDIR"
CPPFLAGS="$CPPFLAGS -I$NBASEDIR"
LIBNBASE_LIBS="$LIBS -lnbase"

AC_SUBST(LIBNBASE_LIBS)
AC_SUBST(NBASEDIR)
AC_SUBST(NSOCKTESTDIR)

AC_SUBST(CFLAGS)

AC_OUTPUT(Makefile)
