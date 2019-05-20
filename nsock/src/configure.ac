# Require autoconf 2.13 -*- mode: fundamental; -*-

# Because nsock is usually distributed with Nmap, the necessary files
# config.guess, config.guess, and install-sh are not distributed with
# nbase. Rather they are gotten from Nmap.

AC_PREREQ(2.13)

dnl Process this file with autoconf to produce a configure script.
AC_INIT(nsock_core.c)

dnl Find the Nmap source for nbase, etc.
if test "${top_nmap_srcdir+set}" != set; then
  top_nmap_srcdir=../..
  export top_nmap_srcdir
fi

dnl Generate these files
AC_CONFIG_FILES([Makefile ../tests/Makefile])

dnl use nsock_config.h instad of -D macros
AC_CONFIG_HEADER(../include/nsock_config.h)

dnl Host specific hacks
AC_CANONICAL_HOST

AH_TEMPLATE(SOLARIS, [Sun/Oracle Solaris])
AH_TEMPLATE(IRIX, [IRIX])

case "$host" in
  *alpha-dec-osf*)
    AC_DEFINE(DEC, 1, [DEC Alpha])
    ;;
  *-netbsd* | *-knetbsd*-gnu)
    AC_DEFINE(NETBSD, 1, [NetBSD])
    ;;
  *-openbsd*)
    AC_DEFINE(OPENBSD, 1, [OpenBSD])
    ;;
  *-sgi-irix5*)
    AC_DEFINE(IRIX)
    ;;
  *-sgi-irix6*)
    AC_DEFINE(IRIX)
    ;;
  *-hpux*)
    AC_DEFINE(HPUX, 1, [HP-UX])
    ;;
  *-solaris2.1[[1-9]]*)
    AC_DEFINE(SOLARIS)
    # Solaris 11 and later use BPF packet capture rather than DLPI.
    AC_DEFINE(SOLARIS_BPF_PCAP_CAPTURE, 1, [BPF packet capture on Solaris])
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
    AC_DEFINE(SUNOS, 1, [SunOS 4])
    ;;
  *-linux*)
    AC_DEFINE(LINUX, 1, [Linux])
    ;;
  *-freebsd* | *-kfreebsd*-gnu | *-dragonfly*)
    AC_DEFINE(FREEBSD, 1, [FreeBSD])
    ;;
  *-bsdi*)
    AC_DEFINE(BSDI, 1, [BSD/OS])
    ;;
  *-apple-darwin*)
    AC_DEFINE(MACOSX, 1, [Apple OS X])
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

dnl Check whether libpcap is already available
have_libpcap=no

# By default, search for pcap library
test "${with_libpcap+set}" != "set" && with_libpcap=yes

AC_ARG_WITH(libpcap,
AC_HELP_STRING([--with-libpcap=DIR], [Look for pcap headers in DIR/include.])
AC_HELP_STRING([--with-libpcap=included], [Always use version included with Nmap])
AC_HELP_STRING([--without-libpcap], [Disable pcap functions.]),
[  case "$with_libpcap" in
  yes)
    AC_CHECK_HEADER(pcap.h,[
      have_libpcap=yes
      LIBPCAP_LIBS=-lpcap ])
    ;;
  included)
    have_libpcap=no
   ;;
  no)
    ;;
  *)
    _cppflags=$CPPFLAGS
    _ldflags=$LDFLAGS

    CPPFLAGS="-I$with_libpcap/include $CPPFLAGS"
    LDFLAGS="-L$with_libpcap/lib $LDFLAGS"

    AC_CHECK_HEADER(pcap.h,[
      AC_CHECK_LIB(pcap, pcap_create,
        [have_libpcap=yes
        LIBPCAP_LIBS=-lpcap
        LIBPCAP_INC=$with_libpcap/include
        LIBPCAP_LIB=$with_libpcap/lib])])

    LDFLAGS=$_ldflags
    CPPFLAGS=$_cppflags
    ;;
  esac]
)

if test "$with_libpcap" != "no" -a "$have_libpcap" = "no"; then
  LIBPCAP_INC=${top_nmap_srcdir}/libpcap
  LIBPCAP_LIB=${top_nmap_srcdir}/libpcap
  LIBPCAP_LIBS=${LIBPCAP_LIB}/libpcap.a
  have_libpcap=yes
  AC_DEFINE(HAVE_PCAP_SET_IMMEDIATE_MODE, 1, [Included libpcap has pcap_set_immediate_mode])
else
  # link with -lpcap for the purposes of this test
  LIBS_OLD="$LIBS"
  LIBS="$LIBS -lpcap"
  AC_CHECK_FUNCS([pcap_set_immediate_mode])
  # Restore libs
  LIBS="$LIBS_OLD"
fi

if test "$have_libpcap" != "no"; then
  AC_DEFINE(HAVE_PCAP, 1, [libpcap is available])
  if test "${LIBPCAP_INC+set}" = "set"; then
    CPPFLAGS="-I$LIBPCAP_INC $CPPFLAGS"
    LDFLAGS="-L$LIBPCAP_LIB $LDFLAGS"
  fi
fi
AC_SUBST(LIBPCAP_LIBS)

AX_HAVE_EPOLL([AC_DEFINE(HAVE_EPOLL, 1, [epoll is available])], )
AX_HAVE_POLL([AC_DEFINE(HAVE_POLL, 1, [poll is available])], )
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
AC_CHECK_HEADERS([linux/vm_sockets.h], , , [#include <sys/socket.h>])

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
  AC_DEFINE(HAVE_OPENSSL, 1, [openssl is available])
  OPENSSL_LIBS="-lssl -lcrypto"
  LIBS_TMP="$LIBS"
  LIBS="$OPENSSL_LIBS $LIBS"
  AC_MSG_CHECKING([for SSL_set_tlsext_host_name])
  AC_TRY_LINK([#include <openssl/ssl.h>], [SSL_set_tlsext_host_name(NULL, NULL)],
    [AC_MSG_RESULT([yes]); AC_DEFINE(HAVE_SSL_SET_TLSEXT_HOST_NAME, 1, [SSL_set_tlsext_host_name available])],
    [AC_MSG_RESULT([no])])
  AC_MSG_CHECKING([for DTLS_client_method])
  AC_TRY_LINK([#include <openssl/ssl.h>], [DTLS_client_method()],
    [AC_MSG_RESULT([yes]); AC_DEFINE(HAVE_DTLS_CLIENT_METHOD, 1, [DTLS_client_method available])],
    [AC_MSG_RESULT([no])])
  AC_MSG_CHECKING([for SSL_set_alpn_protos])
  AC_TRY_LINK([#include <openssl/ssl.h>], [SSL_set_alpn_protos(NULL, NULL, 0)],
    [AC_MSG_RESULT([yes]); AC_DEFINE(HAVE_ALPN_SUPPORT, 1, [SSL ALPN protos support])],
    [AC_MSG_RESULT([no])])
  LIBS="$LIBS_TMP"

fi

AC_SUBST(OPENSSL_LIBS)

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
NBASEDIR="${top_nmap_srcdir}/nbase"
)

NSOCKTESTDIR="../tests"

LDFLAGS="$LDFLAGS -L$NBASEDIR"
CPPFLAGS="$CPPFLAGS -I$NBASEDIR"
LIBNBASE_LIBS="$LIBS -lnbase"

AC_SUBST(LIBNBASE_LIBS)
AC_SUBST(NBASEDIR)
AC_SUBST(NSOCKTESTDIR)

AC_SUBST(CFLAGS)

AC_OUTPUT()
