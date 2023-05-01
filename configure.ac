# Require autoconf 2.13 -*- mode: fundamental; -*-
AC_PREREQ(2.13)

dnl Process this file with autoconf to produce a configure script.
AC_INIT(nmap.cc)

dnl Give us the --enable-nls option, to choose which translated man pages get
dnl installed. This gets replaced with AM_GNU_GETTEXT for full gettext support.
AM_NLS

trace_use=""
trace_no_use=""

AC_ARG_WITH(localdirs,
AC_HELP_STRING([--with-localdirs], [Explicitly ask compiler to use /usr/local/{include,libs} if they exist ]),
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
  trace_use="$trace_use localdirs"
   if test -d /usr/local/lib; then
     LDFLAGS="$LDFLAGS -L/usr/local/lib"
     fi
   if test -d /usr/local/include; then
     CPPFLAGS="$CPPFLAGS -I/usr/local/include"
   fi
else
  trace_no_use="$trace_no_use localdirs"
fi

dnl Let subdirs configure scripts find the Nmap source dir
if test "${top_nmap_srcdir+set}" != set; then
  top_nmap_srcdir=`cd "$srcdir" && pwd`
  export top_nmap_srcdir
fi

libpcapdir=libpcap
AC_SUBST(libpcapdir)

LIBSSH2DIR=libssh2
AC_SUBST(LIBSSH2DIR)

ZLIBDIR=libz
AC_SUBST(ZLIBDIR)

pcredir=libpcre
AC_SUBST(pcredir)

dnl use nmap_config.h instead of -D macros
AC_CONFIG_HEADER(nmap_config.h)

dnl Host specific hacks
AC_CANONICAL_HOST
AC_C_INLINE

dnl Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_RANLIB
AC_PROG_INSTALL
AC_PROG_AWK

dnl For nse_fs.cc
dnl LARGE_FILES_IF_NOT_BROKEN

if test -n "$GXX"; then
  # -fno-strict-aliasing disables strict-aliasing optimizations that assume
  # that pointers of different types never point to the same object.
  CXXFLAGS="$CXXFLAGS -Wall -fno-strict-aliasing"
fi

CFLAGS="$CFLAGS -Wall"

# Remember that all following tests will run with this CXXFLAGS by default
AC_MSG_CHECKING(for __func__)
AH_TEMPLATE(__func__, [C99-specified function identifier])
AC_TRY_COMPILE([
#include <stdio.h>
],[printf ("%s", __func__);],
have_func=yes, have_func=no)
if test "x$have_func" = "xyes"; then
   AC_MSG_RESULT(yes)
else
   AC_MSG_RESULT(no)
   AC_MSG_CHECKING(for __FUNCTION__)
   AC_TRY_COMPILE([
#include <stdio.h>
],[printf ("%s", __FUNCTION__);],
have_function=yes, have_function=no)
   if test "x$have_function" = "xyes"; then
      AC_MSG_RESULT(yes)
      AC_DEFINE(__func__, __FUNCTION__)
   else
      AC_MSG_RESULT(no)
      AC_DEFINE(__func__, __FILE__)
   fi
fi

AC_PATH_TOOL([STRIP], [strip], [/bin/true])

needs_cpp_precomp=no

LUA_CFLAGS="-DLUA_USE_POSIX -DLUA_USE_DLOPEN"

AH_TEMPLATE(SOLARIS, [Sun/Oracle Solaris])
AH_TEMPLATE(STUPID_SOLARIS_CHECKSUM_BUG, [],
            [A bug in Solaris causing incorrect IP checksums])
case "$host" in
  *alpha-dec-osf*)
    AC_DEFINE(DEC, 1, [DEC Alpha])
    ;;
  *-netbsd* | *-knetbsd*-gnu)
    AC_DEFINE(NETBSD, 1, [NetBSD])
    LDFLAGS="-Wl,-E $LDFLAGS" # needed for nse-C-module support
    ;;
  *-openbsd*)
    AC_DEFINE(OPENBSD, 1, [OpenBSD])
    LDFLAGS="-Wl,-E $LDFLAGS" # needed for nse-C-module support
    ;;
  *-freebsd* | *-kfreebsd*-gnu | *-dragonfly*)
    AC_DEFINE(FREEBSD, 1, [FreeBSD])
    LDFLAGS="-Wl,-E $LDFLAGS" # needed for nse-C-module support
    ;;
  *-bsdi*)
    AC_DEFINE(BSDI, 1, [BSD/OS])
    ;;
  *-sgi-irix5* | *-sgi-irix6*)
    AC_DEFINE(IRIX, 1, [IRIX])
    ;;
  *-hpux*)
    AC_DEFINE(HPUX, 1, [HP-UX])
    # To link with libnet and NM (/usr/lib/libnm.sl) library
    # on HP-UX 11.11 (other versions?) Mikhail Zakharov (zmey20000@yahoo.com)
    AC_CHECK_LIB(nm, open_mib)
    ;;
  *-aix*)
    # use some AIX specific libraries
    AC_CHECK_LIB(odm, odm_initialize)
    AC_CHECK_LIB(cfg, _system_configuration)
    AC_CHECK_LIB(crypt, crypt_r)
    ;;
  *-solaris2.1[[1-9]]*)
    AC_DEFINE(SOLARIS)
    # Solaris 11 and later use BPF packet capture rather than DLPI.
    AC_DEFINE(SOLARIS_BPF_PCAP_CAPTURE, 1, [Solaris 11 and later use BPF packet capture rather than DLPI.])
    ;;
  *-solaris2.0*)
    AC_DEFINE(STUPID_SOLARIS_CHECKSUM_BUG)
    AC_DEFINE(SOLARIS)
    ;;
  *-solaris2.[[1-9]][[0-9]]*)
    AC_DEFINE(SOLARIS)
    ;;
  *-solaris2.1*)
    AC_DEFINE(STUPID_SOLARIS_CHECKSUM_BUG)
    AC_DEFINE(SOLARIS)
    ;;
  *-solaris2.2*)
    AC_DEFINE(STUPID_SOLARIS_CHECKSUM_BUG)
    AC_DEFINE(SOLARIS)
    ;;
  *-solaris2.3*)
    AC_DEFINE(STUPID_SOLARIS_CHECKSUM_BUG)
    AC_DEFINE(SOLARIS)
    ;;
  *-solaris2.4*)
    AC_DEFINE(STUPID_SOLARIS_CHECKSUM_BUG)
    AC_DEFINE(SOLARIS)
    ;;
  *-solaris2.5.1)
    AC_DEFINE(STUPID_SOLARIS_CHECKSUM_BUG)
    AC_DEFINE(SOLARIS)
    ;;
  *-solaris*)
    AC_DEFINE(SOLARIS)
    ;;
  *-sunos4*)
    AC_DEFINE(SUNOS, 1, [SunOS 4])
    AC_DEFINE(SPRINTF_RETURNS_STRING, 1,
              [sprintf(9f) returns its first argument, not the number of characters printed])
    ;;
  *-linux*)
    AC_DEFINE(LINUX, 1, [Linux])
    LDFLAGS="-Wl,-E $LDFLAGS" # needed for nse-C-module support
    ;;
  *-apple-darwin*)
    AC_DEFINE(MACOSX, 1, [Apple OS X])
    dnl on Mac OSX the math library seems to contain unwanted getopt cruft
    AC_CHECK_LIB(m, main)
    LUA_CFLAGS="-DLUA_USE_MACOSX"
    needs_cpp_precomp=yes
    ;;
esac

AC_SUBST(LUA_CFLAGS)

dnl Checks for header files.
AC_CHECK_HEADERS(pwd.h termios.h sys/sockio.h stdint.h sys/stat.h fcntl.h)
AC_CHECK_HEADERS(linux/rtnetlink.h,,,[#include <netinet/in.h>])
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

dnl If any socket libraries needed
AC_SEARCH_LIBS(setsockopt, socket)
AC_SEARCH_LIBS(gethostbyname, nsl)

dnl Check IPv6 raw sending flavor.
CHECK_IPV6_IPPROTO_RAW

m4_define_default([_AM_PYTHON_INTERPRETER_LIST],[python3 python])
AM_PATH_PYTHON([3], [HAVE_PYTHON=true], [HAVE_PYTHON=false])

NDIFFDIR=ndiff

# Do they want Ndiff?
AC_ARG_WITH(ndiff, AC_HELP_STRING([--without-ndiff], [Skip installation of the Ndiff utility]), [], [with_ndiff=check])
if $HAVE_PYTHON ; then : ;
else
  if test "$with_ndiff" = "check" ; then
    AC_MSG_WARN([Not building Ndiff because Python was not found])
  elif test "$with_ndiff" = "yes"; then
    AC_MSG_FAILURE([--with-ndiff requires Python])
  fi
  with_ndiff=no
fi
if test "$with_ndiff" = "no"; then
  trace_no_use="$trace_no_use ndiff"
  BUILDNDIFF=""
  INSTALLNDIFF=""
  UNINSTALLNDIFF=""
  NDIFF_CHECK=""
  NDIFF_CLEAN=""
  NDIFF_DIST_CLEAN=""
else
  trace_use="$trace_use ndiff"
  BUILDNDIFF=build-ndiff
  INSTALLNDIFF=install-ndiff
  UNINSTALLNDIFF=uninstall-ndiff
  NDIFF_CHECK="check-ndiff"
  NDIFF_CLEAN=clean-ndiff
  NDIFF_DIST_CLEAN=distclean-ndiff
fi
AC_SUBST(NDIFFDIR)
AC_SUBST(BUILDNDIFF)
AC_SUBST(INSTALLNDIFF)
AC_SUBST(UNINSTALLNDIFF)
AC_SUBST(NDIFF_CHECK)
AC_SUBST(NDIFF_CLEAN)
AC_SUBST(NDIFF_DIST_CLEAN)

ZENMAPDIR=zenmap

# Do they want Zenmap?
AC_ARG_WITH(zenmap, AC_HELP_STRING([--without-zenmap], [Skip installation of the Zenmap graphical frontend]), [], [with_zenmap=check])

if $HAVE_PYTHON ; then : ;
else
  if test "$with_zenmap" = "check"; then
    AC_MSG_WARN([Not building Zenmap because Python was not found])
  elif test "$with_zenmap" = "yes"; then
    AC_MSG_FAILURE([--with-zenmap requires Python])
  fi
  with_zenmap=no
fi
if test "$with_zenmap" = "no"; then
  trace_no_use="$trace_no_use zenmap"
  BUILDZENMAP=""
  INSTALLZENMAP=""
  UNINSTALLZENMAP=""
  ZENMAP_CHECK=""
  ZENMAP_CLEAN=""
  ZENMAP_DIST_CLEAN=""
else
  trace_use="$trace_use zenmap"
  BUILDZENMAP=build-zenmap
  INSTALLZENMAP=install-zenmap
  UNINSTALLZENMAP=uninstall-zenmap
  ZENMAP_CHECK=check-zenmap
  ZENMAP_CLEAN=clean-zenmap
  ZENMAP_DIST_CLEAN=distclean-zenmap
fi
AC_SUBST(ZENMAPDIR)
AC_SUBST(BUILDZENMAP)
AC_SUBST(INSTALLZENMAP)
AC_SUBST(UNINSTALLZENMAP)
AC_SUBST(ZENMAP_CHECK)
AC_SUBST(ZENMAP_CLEAN)
AC_SUBST(ZENMAP_DIST_CLEAN)

NPINGDIR=nping

# Do they want Nping?
AC_ARG_WITH(nping, AC_HELP_STRING([--without-nping], [Skip installation of the Nping utility]), [], [with_nping=check])

if test "$with_nping" = "no"; then
  trace_no_use="$trace_no_use nping"
  BUILDNPING=""
  INSTALLNPING=""
  UNINSTALLNPING=""
  NPING_CLEAN=""
  NPING_DIST_CLEAN=""
else
  trace_use="$trace_use nping"
  BUILDNPING=build-nping
  INSTALLNPING=install-nping
  UNINSTALLNPING=uninstall-nping
  NPING_CLEAN=clean-nping
  NPING_DIST_CLEAN=distclean-nping
  AC_CONFIG_SUBDIRS(nping)
fi
AC_SUBST(NPINGDIR)
AC_SUBST(BUILDNPING)
AC_SUBST(INSTALLNPING)
AC_SUBST(UNINSTALLNPING)
AC_SUBST(NPING_CLEAN)
AC_SUBST(NPING_DIST_CLEAN)

# OpenSSL and NSE C modules can require dlopen
AC_SEARCH_LIBS(dlopen, dl)

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
    ac_configure_args="$ac_configure_args '--with-libssl-prefix=$with_openssl'"
    CPPFLAGS="$CPPFLAGS -I$with_openssl/include"
    LDFLAGS="$LDFLAGS -L$with_openssl/lib"
    ;;
  esac]
)

# If they didn't specify it, we try to find it
if test "$use_openssl" = "yes"; then
  AC_CHECK_HEADER(openssl/ssl.h,,
  [ use_openssl="no"
    if test -n "$specialssldir"; then
      AC_MSG_ERROR([Specific OpenSSL location was requested but openssl/ssl.h was not found. Try correcting the --with-openssl=DIR argument.])
    fi
    if test "$with_openssl" = "yes"; then
      AC_MSG_ERROR([OpenSSL was explicitly requested but openssl/ssl.h was not found. Try the --with-openssl=DIR argument to give the location of OpenSSL or run configure with --without-openssl.])
    fi
    AC_MSG_WARN([Failed to find openssl/ssl.h so OpenSSL will not be used. If it is installed you can try the --with-openssl=DIR argument])
  ])
fi

# use_openssl="yes" given explicitly in next 2 rules to avoid adding lib to $LIBS
if test "$use_openssl" = "yes"; then
  AC_CHECK_LIB(crypto, BIO_int_ctrl,
    [ use_openssl="yes"],
    [ use_openssl="no"
      if test -n "$specialssldir"; then
        AC_MSG_ERROR([Specific OpenSSL location was requested but libcrypto was not found. Try correcting the --with-openssl=DIR argument.])
      fi
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
      if test -n "$specialssldir"; then
        AC_MSG_ERROR([Specific OpenSSL location was requested but libssl was not found. Try correcting the --with-openssl=DIR argument.])
      fi
      if test "$with_openssl" = "yes"; then
        AC_MSG_ERROR([OpenSSL was explicitly requested but libssl was not found. Try the --with-openssl=DIR argument to give the location of OpenSSL or run configure with --without-openssl.])
      fi
      AC_MSG_WARN([Failed to find libssl so OpenSSL will not be used. If it is installed you can try the --with-openssl=DIR argument])
    ],
    [ -lcrypto ])
fi

OPENSSL_LIBS=
if test "$use_openssl" = "yes"; then
  trace_use="$trace_use openssl"
  AC_DEFINE(HAVE_OPENSSL, 1, [Have OpenSSL library])
  OPENSSL_LIBS="-lssl -lcrypto"
else
  trace_no_use="$trace_no_use openssl"
fi

AC_SUBST(OPENSSL_LIBS)

dnl Check whether libpcap is already available
have_libpcap=no

# By default, search for pcap library
test "${with_libpcap+set}" != "set" && with_libpcap=yes

AC_ARG_WITH(libpcap,
AC_HELP_STRING([--with-libpcap=DIR], [Look for pcap in DIR/include and DIR/libs.])
AC_HELP_STRING([--with-libpcap=included], [Always use version included with Nmap]),
[  case "$with_libpcap" in
  yes)
    AC_CHECK_HEADER(pcap.h,[
      AC_CHECK_LIB(pcap, pcap_create,
      [have_libpcap=yes ])])
    ;;
  included)
    have_libpcap=no
   ;;
  *)
    _cppflags=$CPPFLAGS
    _ldflags=$LDFLAGS

    CPPFLAGS="-I$with_libpcap/include $CPPFLAGS"
    LDFLAGS="-L$with_libpcap/lib $LDFLAGS"

    AC_CHECK_HEADER(pcap.h,[
      AC_CHECK_LIB(pcap, pcap_create,
        [have_libpcap=yes
        LIBPCAP_INC=$with_libpcap/include
        LIBPCAP_LIB=$with_libpcap/lib])])

    LDFLAGS=$_ldflags
    CPPFLAGS=$_cppflags
    ;;
  esac]
)

if test $needs_cpp_precomp = yes; then
  CXXFLAGS="-no-cpp-precomp $CXXFLAGS"
fi

if test $have_libpcap = yes; then
  if test "${LIBPCAP_INC+set}" = "set"; then
    CPPFLAGS="-I$LIBPCAP_INC $CPPFLAGS"
    LDFLAGS="-L$LIBPCAP_LIB $LDFLAGS"
  fi

  # link with -lpcap for the purposes of this test
  LIBS_OLD="$LIBS"
  LIBS="$LIBS -lpcap"
  PCAP_IS_SUITABLE([have_libpcap=yes], [have_libpcap=no], [have_libpcap=yes])
  LIBS="$LIBS_OLD"
fi

if test $have_libpcap != yes; then
  AC_CONFIG_SUBDIRS(libpcap)
  if test "${LIBPCAP_INC+set}" = "set"; then
    CPPFLAGS="$CPPFLAGS -I$LIBPCAP_INC"
  else
    CPPFLAGS="$CPPFLAGS -I\$(top_srcdir)/$libpcapdir"
  fi
  LIBPCAP_LIBS='$(LIBPCAPDIR)/libpcap.a'
  PCAP_BUILD="build-pcap"
  PCAP_CLEAN="clean-pcap"
  PCAP_DIST_CLEAN="distclean-pcap"
  AC_DEFINE(PCAP_INCLUDED, 1, [Using included libpcap])
  AC_DEFINE(HAVE_PCAP_SET_IMMEDIATE_MODE, 1, [Included libpcap has pcap_set_immediate_mode])
else
  # We assume our included libpcap doesn't need this check-and-define
  # link with -lpcap for the purposes of this test
  LIBS_OLD="$LIBS"
  LIBS="$LIBS -lpcap"
  AC_CHECK_FUNCS([pcap_set_immediate_mode])
  # Restore libs
  LIBS="$LIBS_OLD"

  AC_DEFINE(HAVE_LIBPCAP, 1, [Have libpcap library])
  LIBPCAP_LIBS="-lpcap"
  PCAP_BUILD=""
  PCAP_CLEAN=""
  PCAP_DIST_CLEAN=""
fi

AC_SUBST(PCAP_BUILD)
AC_SUBST(PCAP_CLEAN)
AC_SUBST(PCAP_DIST_CLEAN)
AC_SUBST(LIBPCAP_LIBS)

have_pcre=no
requested_included_pcre=no
LIBPCREDIR=libpcre

# First we test whether they specified libpcre explicitly
AC_ARG_WITH(libpcre,
AC_HELP_STRING([--with-libpcre=DIR], [Use an existing (compiled) pcre lib from DIR/include and DIR/lib.])
AC_HELP_STRING([--with-libpcre=included], [Always use the version included with Nmap]),
[  case "$with_libpcre" in
  yes)
    ;;
  included)
    requested_included_pcre=yes
    ;;
  *)
    CPPFLAGS="-I$with_libpcre/include $CPPFLAGS"
    LDFLAGS="-L$with_libpcre/lib $LDFLAGS"
    have_pcre=yes
    ;;
  esac]
)

# If they didn't specify it, we try to find it
if test $have_pcre != yes -a $requested_included_pcre != yes ; then
  AC_CHECK_HEADER(pcre.h,
    AC_CHECK_LIB(pcre, pcre_version, [have_pcre=yes ]),
    [AC_CHECK_HEADER(pcre/pcre.h,
      [AC_CHECK_LIB(pcre, pcre_version, [have_pcre=yes])]
    )]
  )
fi

# If we still don't have it, we use our own
if test $have_pcre != yes ; then
  AC_CONFIG_SUBDIRS( libpcre )
  CPPFLAGS="-I\$(top_srcdir)/$LIBPCREDIR $CPPFLAGS"
  LIBPCRE_LIBS="$LIBPCREDIR/libpcre.a"
  PCRE_BUILD="build-pcre"
  PCRE_CLEAN="clean-pcre"
  PCRE_DIST_CLEAN="distclean-pcre"
  AC_DEFINE(PCRE_INCLUDED, 1, [Using included libpcre])
else
# We only need to check for and use this if we are NOT using included pcre
  AC_CHECK_HEADERS(pcre/pcre.h)
  LIBPCRE_LIBS="-lpcre"
  PCRE_BUILD=""
  PCRE_CLEAN=""
  PCRE_DIST_CLEAN=""
fi

AC_SUBST(LIBPCRE_LIBS)
AC_SUBST(LIBPCREDIR)
AC_SUBST(PCRE_BUILD)
AC_SUBST(PCRE_CLEAN)
AC_SUBST(PCRE_DIST_CLEAN)


# We test whether desired libz is specified explicitly
# Since this is a libssh2 dependency, we have to do it first.

have_libz="no"
requested_included_libz="no"
test "${with_libz+set}" != "set" && with_libz="yes"

AC_ARG_WITH(libz,
AC_HELP_STRING([--with-libz=DIR], [Use specific copy of libz])
AC_HELP_STRING([--with-libz=included], [Always use version included with Nmap]),
[
  case "$with_libz" in
  yes)
    ;;
  no)
    # Do nothing
    ;;
  included)
    requested_included_libz="yes"
    ;;
  *)
    _cppflags=$CPPFLAGS
    _ldflags=$LDFLAGS

    CPPFLAGS="-I$with_libz/include $CPPFLAGS"
    LDFLAGS="-L$with_libz/lib $LDFLAGS"

    ac_configure_args="$ac_configure_args '--with-libz-prefix=$with_libz'"
    AC_CHECK_HEADER(zlib.h,[
      AC_CHECK_LIB(z, gzread,
        [have_libz=yes
        ZLIB_INC=$with_libz/include
        ZLIB_LIB=$with_libz/lib],,)
      ])

    LDFLAGS=$_ldflags
    CPPFLAGS=$_cppflags
  ;;
  esac
]
)

if test $with_libz != no; then
  trace_use="$trace_use zlib"

  # If they didn't specify it, we try to find it
  if test $have_libz != yes -a $requested_included_libz != yes; then
    AC_CHECK_HEADER(zlib.h,[
      AC_CHECK_LIB(z, gzread,
        [have_libz="yes"],,[-lm])
      ])
  fi

  if test $have_libz != yes; then
    AC_CONFIG_SUBDIRS(libz)
    # TODO: This doesn't work because libssh2's configure script is looking for
    # already-built libs.  Giving up for now: build libz first or install
    # headers/libs on your own if you want compression support for SSH.
    #ac_configure_args="$ac_configure_args '--with-libz-prefix=../../$ZLIBDIR'"
    CPPFLAGS="-I\$(top_srcdir)/$ZLIBDIR $CPPFLAGS"
    ZLIB_LIBS="$ZLIBDIR/libz.a"
    ZLIB_BUILD="build-zlib"
    ZLIB_CLEAN="clean-zlib"
    ZLIB_DIST_CLEAN="distclean-zlib"
    AC_DEFINE(ZLIB_INCLUDED, 1, [Using included zlib])
  else
    ZLIB_LIBS="-lz"
    ZLIB_BUILD=""
    ZLIB_CLEAN=""
    ZLIB_DIST_CLEAN=""
  fi
  AC_DEFINE(HAVE_LIBZ, 1, [Have zlib library])
else
  trace_no_use="$trace_no_use zlib"
  ZLIB_LIBS=""
  ZLIB_BUILD=""
  ZLIB_CLEAN=""
  ZLIB_DIST_CLEAN=""
fi

AC_SUBST(ZLIB_BUILD)
AC_SUBST(ZLIB_CLEAN)
AC_SUBST(ZLIB_DIST_CLEAN)
AC_SUBST(ZLIB_LIBS)

# We test whether desired libssh2 is specified explicitly

use_libssh2="yes"
have_libssh2="no"
requested_included_libssh2="no"
test "${with_libssh2+set}" != "set" && with_libssh2="yes"

AC_ARG_WITH(libssh2,
AC_HELP_STRING([--with-libssh2=DIR], [Use specific copy of libssh2])
AC_HELP_STRING([--with-libssh2=included], [Always use version included with Nmap])
AC_HELP_STRING([--without-libssh2], [Compile without libssh2]),
[ case "$with_libssh2" in
  yes)
    ;;
  no)
    use_libssh2="no"
    ;;
  included)
    requested_included_libssh2="yes"
    ;;
  *)
    _cppflags=$CPPFLAGS
    _ldflags=$LDFLAGS

    CPPFLAGS="-I$with_libssh2/include $CPPFLAGS"
    LDFLAGS="-L$with_libssh2/lib $LDFLAGS"

    AC_CHECK_HEADER(libssh2.h,[
      AC_CHECK_LIB(ssh2, libssh2_version,
        [have_libssh2=yes
        LIBSSH2_INC=$with_libssh2/include
        LIBSSH2_LIB=$with_libssh2/lib],
        [LDFLAGS=$_ldflags
        CPPFLAGS=$_cppflags],[-lm])
      ])

  ;;
  esac]
)


if test $use_libssh2 = yes -a $use_openssl = yes; then
  trace_use="$trace_use libssh2"

  # If they didn't specify it, we try to find it
  if test $have_libssh2 != yes -a $requested_included_libssh2 != yes; then
    AC_CHECK_HEADER(libssh2.h,[
      AC_CHECK_LIB(ssh2, libssh2_version,
        [have_libssh2="yes"],,[-lm])
      ])
  fi

  # If we still don't have it, we use our own
  if test $have_libssh2 != yes; then
    have_libssh2=yes
    AC_CONFIG_SUBDIRS(libssh2)
    CPPFLAGS="-I\$(top_srcdir)/$LIBSSH2DIR/include $CPPFLAGS"
    LIBSSH2_LIBS="$LIBSSH2DIR/lib/libssh2.a"
    LIBSSH2_BUILD="build-libssh2"
    LIBSSH2_CLEAN="clean-libssh2"
    LIBSSH2_DIST_CLEAN="distclean-libssh2"
    AC_DEFINE(LIBSSH2_INCLUDED, 1, [Using included libssh2])
  else
    LIBSSH2_LIBS="-lssh2"
    LIBSSH2_BUILD=""
    LIBSSH2_CLEAN=""
    LIBSSH2_DIST_CLEAN=""
  fi
  AC_DEFINE(HAVE_LIBSSH2, 1, [Have libssh2 library])
else
  use_libssh2="no"
  trace_no_use="$trace_no_use libssh2"
  LIBSSH2_LIBS=""
  LIBSSH2_BUILD=""
  LIBSSH2_CLEAN=""
  LIBSSH2_DIST_CLEAN=""
fi

AC_SUBST(LIBSSH2_BUILD)
AC_SUBST(LIBSSH2_CLEAN)
AC_SUBST(LIBSSH2_DIST_CLEAN)
AC_SUBST(LIBSSH2_LIBS)


have_dnet=no
requested_included_dnet=no
LIBDNETDIR=libdnet-stripped

# First we test whether they specified libdnet explicitly.
# Unlike the other included libraries (pcap, pcre, lua), we prefer our local
# copy of libdnet. That is, with the other libraries we check for a system
# version by default, whereas with dnet we use the local version unless
# specifically asked to use a system version.  This is because we have
# made many improvements and fixes to our version of dnet.
AC_ARG_WITH(libdnet,
AC_HELP_STRING([--with-libdnet=DIR], [Use an existing (compiled) dnet lib from DIR/include and DIR/lib. This is NOT RECOMMENDED because we have made many important fixes to our included libdnet, as described at ./libdnet-stripped/NMAP_MODIFICATIONS])
AC_HELP_STRING([--with-libdnet=included], [Use the libdnet version included with Nmap (default)]),
[  case "$with_libdnet" in
  yes)
    ;;
  included)
    ;;
  *)
    CPPFLAGS="-I$with_libdnet/include $CPPFLAGS"
    LDFLAGS="-L$with_libdnet/lib $LDFLAGS"
    have_dnet=yes
    ;;
  esac]
)

# If they didn't provide location, we use the included one
if test $have_dnet != yes ; then
  AC_CONFIG_SUBDIRS( libdnet-stripped )
  CPPFLAGS="-I\$(top_srcdir)/$LIBDNETDIR/include $CPPFLAGS"
  LIBDNET_LIBS="\$(top_srcdir)/$LIBDNETDIR/src/.libs/libdnet.a"
  DNET_BUILD="build-dnet"
  DNET_CLEAN="clean-dnet"
  DNET_DIST_CLEAN="distclean-dnet"
  AC_DEFINE(DNET_INCLUDED, 1, [Use included libdnet])
else
  LIBDNET_LIBS="-ldnet"
  DNET_BUILD=""
  DNET_CLEAN=""
  DNET_DIST_CLEAN=""
fi

AC_SUBST(LIBDNET_LIBS)
AC_SUBST(LIBDNETDIR)
AC_SUBST(DNET_BUILD)
AC_SUBST(DNET_CLEAN)
AC_SUBST(DNET_DIST_CLEAN)

LIBLUADIR=liblua

have_lua=no
requested_included_lua=no
no_lua=no

# First we test whether they specified liblua explicitly
AC_ARG_WITH(liblua,
AC_HELP_STRING([--with-liblua=DIR], [Use an existing (compiled) lua lib from DIR/include and DIR/lib.])
AC_HELP_STRING([--with-liblua=included], [Use the liblua version included with Nmap])
AC_HELP_STRING([--without-liblua], [Compile without lua (this will exclude all of NSE from compilation)]),
[  case "$with_liblua" in
  yes)
  ;;
  included)
    CPPFLAGS="-I\$(top_srcdir)/$LIBLUADIR $CPPFLAGS"
    LIBLUA_LIBS="\$(top_srcdir)/$LIBLUADIR/liblua.a"
    LUA_BUILD="build-lua"
    LUA_CLEAN="clean-lua"
    LUA_DIST_CLEAN="distclean-lua"
      have_lua="yes"
    AC_DEFINE(LUA_INCLUDED, 1, [Using included liblua])
  ;;
  no)
    no_lua="yes"
  ;;
  *)
    CPPFLAGS="-I$with_liblua/include $CPPFLAGS"
    LDFLAGS="-L$with_liblua/lib $LDFLAGS"
  ;;
  esac]
)

# They don't want lua
if test "$no_lua" = "yes"; then
  trace_no_use="$trace_no_use lua"
  CPPFLAGS="-DNOLUA $CPPFLAGS"
  NOLUA="yes"
  LUA_BUILD=""
  LUA_CLEAN=""
  LUA_DIST_CLEAN=""
  INSTALLNSE=""

else
  trace_use="$trace_use lua"

  # If they didn't specify it, we try to find it
  if test $have_lua != yes; then
    AC_CHECK_HEADERS([lua5.4/lua.h lua/5.4/lua.h lua.h lua/lua.h], [break])
    AC_SEARCH_LIBS(lua_isyieldable, [lua5.4 lua54 lua], [have_lua=yes],, [-lm])
    AC_LANG_PUSH(C)
    # We need Lua 5.4 exactly
    AC_MSG_CHECKING([for lua version == 504])
    AC_PREPROC_IFELSE([ AC_LANG_PROGRAM( [[
      #ifdef HAVE_LUA5_4_LUA_H
          #include <lua5.4/lua.h>
      #elif defined HAVE_LUA_5_4_LUA_H
          #include <lua/5.4/lua.h>
      #elif defined HAVE_LUA_H || defined LUA_INCLUDED
          #include <lua.h>
      #elif defined HAVE_LUA_LUA_H
          #include <lua/lua.h>
      #endif

      #if (LUA_VERSION_NUM != 504)
          #error Incorrect Lua version
      #endif
        ]],
        [[if(LUA_VERSION_NUM != 504) return 1;]])
    ],
    [have_lua=yes], [have_lua=no])
    AC_LANG_POP(C)

    LUA_BUILD=""
    LUA_CLEAN=""
    LUA_DIST_CLEAN=""
  fi

  # if we didn't find we use our own
  if test $have_lua != yes; then
    AC_MSG_RESULT(no)
    CPPFLAGS="-I\$(top_srcdir)/$LIBLUADIR $CPPFLAGS"
    LIBLUA_LIBS="\$(top_srcdir)/$LIBLUADIR/liblua.a"
    LUA_BUILD="build-lua"
    LUA_CLEAN="clean-lua"
    LUA_DIST_CLEAN="distclean-lua"
    AC_DEFINE(LUA_INCLUDED, 1, [Using included liblua])
  else
    AC_MSG_RESULT(yes)
  fi

  INSTALLNSE="install-nse"
  NSE_CHECK="check-nse"
fi

AC_SUBST(NOLUA)
AC_SUBST(LIBLUA_LIBS)
AC_SUBST(LIBLUADIR)
AC_SUBST(LUA_BUILD)
AC_SUBST(LUA_CLEAN)
AC_SUBST(LUA_DIST_CLEAN)
AC_SUBST(INSTALLNSE)
AC_SUBST(NSE_CHECK)
AC_SUBST(CXXFLAGS)
AC_SUBST(CFLAGS)


LIBLINEARDIR=liblinear
have_liblinear=no

# First we test whether they specified liblinear explicitly
AC_ARG_WITH(liblinear,
AC_HELP_STRING([--with-liblinear=DIR], [Use an existing (compiled) liblinear from DIR/include and DIR/lib.])
AC_HELP_STRING([--with-liblinear=included], [Use the liblinear version included with Nmap]),
[  case "$with_liblinear" in
  yes)
  ;;
  included)
    CPPFLAGS="-I\$(top_srcdir)/$LIBLINEARDIR $CPPFLAGS"
    LIBLINEAR_LIBS="\$(top_srcdir)/$LIBLINEARDIR/liblinear.a"
    LIBLINEAR_BUILD="build-liblinear"
    LIBLINEAR_CLEAN="clean-liblinear"
    LIBLINEAR_DIST_CLEAN="distclean-liblinear"
    have_liblinear=yes
  ;;
  *)
    CPPFLAGS="-I$with_liblinear/include $CPPFLAGS"
    LDFLAGS="-L$with_liblinear/lib $LDFLAGS"
    have_liblinear=yes
  ;;
  esac]
)

# If they didn't specify it, we try to find it
if test $have_liblinear != yes; then
  AC_CHECK_HEADERS([linear.h],
    AC_CHECK_LIB(linear, predict, [have_liblinear=yes; LIBLINEAR_LIBS="-llinear"; break],, [-lm])
  )

  LIBLINEAR_BUILD=""
  LIBLINEAR_CLEAN=""
  LIBLINEAR_DIST_CLEAN=""
fi

# if we didn't find we use our own
if test $have_liblinear != yes; then
  AC_MSG_RESULT(no)
  CPPFLAGS="-I\$(top_srcdir)/$LIBLINEARDIR $CPPFLAGS"
  LIBLINEAR_LIBS="\$(top_srcdir)/$LIBLINEARDIR/liblinear.a"
  LIBLINEAR_BUILD="build-liblinear"
  LIBLINEAR_CLEAN="clean-liblinear"
  LIBLINEAR_DIST_CLEAN="distclean-liblinear"
  AC_DEFINE(LIBLINEAR_INCLUDED, 1, [Using included liblinear])
else
  AC_MSG_RESULT(yes)
fi

AC_SUBST(LIBLINEAR_LIBS)
AC_SUBST(LIBLINEARDIR)
AC_SUBST(LIBLINEAR_BUILD)
AC_SUBST(LIBLINEAR_CLEAN)
AC_SUBST(LIBLINEAR_DIST_CLEAN)


#dnl check endedness
AC_C_BIGENDIAN

AC_MSG_CHECKING([if struct in_addr is a wacky huge structure (some Sun boxes)])
AH_TEMPLATE(IN_ADDR_DEEPSTRUCT, [], [struct in_addr is a wacky huge structure (some Sun boxes)])

AC_TRY_COMPILE([#include <netinet/in.h>], struct in_addr i; i._S_un._S_addr;, \
             AC_DEFINE(IN_ADDR_DEEPSTRUCT) \
             AC_MSG_RESULT(yes) , \
             AC_TRY_COMPILE([#include <sys/types.h>
#include <netinet/in.h>], struct in_addr i; i.S_un.S_addr;, \
                             AC_DEFINE(IN_ADDR_DEEPSTRUCT) \
                             AC_MSG_RESULT(yes) , \
                             AC_MSG_RESULT(no);))

AC_CACHE_CHECK(if struct icmp exists, ac_cv_struct_icmp_exists,
        AC_TRY_COMPILE([
               #include <sys/types.h>
               #include <sys/param.h>
               #include <netinet/in_systm.h>
               #include <netinet/in.h>
               #define __USE_BSD
               #define __FAVOR_BSD
               #define _BSD_SOURCE
               #include <netinet/ip.h>
               #include <netinet/ip_icmp.h>],
                [unsigned int i = sizeof(struct icmp)],
        ac_cv_struct_icmp_exists=yes,
        ac_cv_struct_icmp_exists=no))
if test $ac_cv_struct_icmp_exists = yes ; then
        AC_DEFINE(HAVE_STRUCT_ICMP, 1, [struct icmp is declared])
fi

AC_CACHE_CHECK(if struct ip exists, ac_cv_struct_ip_exists,
        AC_TRY_COMPILE([
               #include <sys/types.h>
               #include <sys/param.h>
               #include <netinet/in_systm.h>
               #include <netinet/in.h>
               #define __USE_BSD
               #define __FAVOR_BSD
               #define _BSD_SOURCE
               #include <netinet/ip.h>],
                [unsigned int i = sizeof(struct ip)],
        ac_cv_struct_ip_exists=yes,
        ac_cv_struct_ip_exists=no))
if test $ac_cv_struct_ip_exists = yes ; then
        AC_DEFINE(HAVE_STRUCT_IP, 1, [struct ip is declared])
fi

AC_CACHE_CHECK(if struct ip has ip_sum member, ac_cv_ip_has_ip_sum,
        AC_TRY_COMPILE([
               #include <sys/types.h>
               #include <sys/param.h>
               #include <netinet/in_systm.h>
               #include <netinet/in.h>
               #define __USE_BSD
               #define __FAVOR_BSD
               #define _BSD_SOURCE
               #include <netinet/ip.h>
               #include <netinet/ip_icmp.h>],
                [unsigned int i = sizeof(((struct ip *)0)->ip_sum)],
        ac_cv_ip_has_ip_sum=yes,
        ac_cv_ip_has_ip_sum=no))
if test $ac_cv_ip_has_ip_sum = yes ; then
        AC_DEFINE(HAVE_IP_IP_SUM, 1, [struct ip has ip_sum member])
fi

dnl Checks for library functions.
AC_CHECK_FUNCS(strerror)
RECVFROM_ARG6_TYPE

AC_ARG_WITH(libnbase,
AC_HELP_STRING([--with-libnbase=DIR], [Look for nbase include/libs in DIR]),
[  case "$with_libnbase" in
  yes)
    ;;
  *)
    NBASEDIR="$with_libnbase"
    NBASE_BUILD=""
    ;;
  esac],
NBASE_BUILD="build-nbase"
NBASEDIR="nbase"
)

LDFLAGS="$LDFLAGS -L$NBASEDIR"
CPPFLAGS="$CPPFLAGS -I\$(top_srcdir)/$NBASEDIR"
LIBNBASE_LIBS="-lnbase"

AC_SUBST(NBASEDIR)
AC_SUBST(NBASE_BUILD)
AC_SUBST(LIBNBASE_LIBS)

AC_CONFIG_SUBDIRS(nbase)

NSOCKDIR="nsock"
NSOCK_BUILD="build-nsock"
NSOCK_CHECK="check-nsock"
AC_ARG_WITH(libnsock,
AC_HELP_STRING([--with-libnsock=DIR], [Compile and link to libnsock in DIR]),
[  case "$with_libnsock" in
  yes)
    ;;
  *)
    NSOCKDIR="$with_libnsock"
    NSOCK_BUILD=""
    NSOCK_CHECK=""
    ;;
  esac]
)

LDFLAGS="$LDFLAGS -L$NSOCKDIR/src/"
CPPFLAGS="$CPPFLAGS -I\$(top_srcdir)/$NSOCKDIR/include"
LIBNSOCK_LIBS="-lnsock"

AC_SUBST(NSOCKDIR)
AC_SUBST(NSOCK_BUILD)
AC_SUBST(NSOCK_CHECK)
AC_SUBST(LIBNSOCK_LIBS)

AC_CONFIG_SUBDIRS(nsock/src)

NCATDIR="ncat"

AC_ARG_WITH(ncat,
  AC_HELP_STRING([--without-ncat], [Skip build and installation of Ncat]), [], [with_ncat=check])

if test "$with_ncat" = "no"; then
  trace_no_use="$trace_no_use ncat"
  NCAT_BUILD=""
  NCAT_CHECK=""
  NCAT_INSTALL=""
  NCAT_UNINSTALL=""
  NCAT_CLEAN=""
  NCAT_DIST_CLEAN=""
else
  trace_use="$trace_use ncat"
  NCAT_BUILD="build-ncat"
  NCAT_CHECK="check-ncat"
  NCAT_INSTALL="install-ncat"
  NCAT_UNINSTALL="uninstall-ncat"
  NCAT_CLEAN="clean-ncat"
  NCAT_DIST_CLEAN="distclean-ncat"
  AC_CONFIG_SUBDIRS(ncat)
fi

AC_SUBST(NCATDIR)
AC_SUBST(NCAT_BUILD)
AC_SUBST(NCAT_CHECK)
AC_SUBST(NCAT_INSTALL)
AC_SUBST(NCAT_UNINSTALL)
AC_SUBST(NCAT_CLEAN)
AC_SUBST(NCAT_DIST_CLEAN)

AC_OUTPUT(Makefile libnetutil/Makefile)

# Krad ASCII ART#!#@$!@#$
# Randomly store the name of one of the ASCII Art files in FILENAME
FILENAME=`ls $srcdir/docs/leet-nmap-ascii-art*.txt 2>/dev/null | $AWK '
    BEGIN {
        srand();
    }

    {
        lines[[++d]] = $0
    }

    END {
        # This makes AWKs random numbers more random
        print lines[[int(rand()*49139)%d+1]];
    }
    '`
# Print the file to screen, if any such file exists (i.e. $FILENAME is not empty)
if test "$FILENAME"; then
  cat "$FILENAME"
fi
echo "  NMAP IS A POWERFUL TOOL -- USE CAREFULLY AND RESPONSIBLY"

echo "Configured with:$trace_use"
echo "Configured without:$trace_no_use"
echo "Type make (or gmake on some *BSD machines) to compile."

if test "x$use_openssl" = "xno" && test "x$with_openssl" != "xno"; then
  echo "WARNING: You are compiling without OpenSSL"
fi

if test "x$use_libssh2" != "xyes"; then
  echo "WARNING: You are compiling without LibSSH2"
fi
