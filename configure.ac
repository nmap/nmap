# Require autoconf 2.13 -*- mode: fundamental; -*-
AC_PREREQ(2.13)

dnl Process this file with autoconf to produce a configure script.
AC_INIT(nmap.cc)

dnl Give us the --enable-nls option, to choose which translated man pages get
dnl installed. This gets replaced with AM_GNU_GETTEXT for full gettext support.
AM_NLS

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
   if test -d /usr/local/lib; then
     LDFLAGS="$LDFLAGS -L/usr/local/lib"
     fi
   if test -d /usr/local/include; then
     CFLAGS="$CFLAGS -I/usr/local/include"
     CXXFLAGS="$CFLAGS -I/usr/local/include"
   fi
fi

libpcapdir=libpcap
AC_SUBST(libpcapdir)

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

if test -n "$GXX"; then
  # -fno-strict-aliasing disables strict-aliasing optimizations that assume
  # that pointers of different types never point to the same object.
  CXXFLAGS="$CXXFLAGS -Wall -fno-strict-aliasing"
fi

# Remember that all following tests will run with this CXXFLAGS by default
AC_MSG_CHECKING(for __func__)
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

AC_SUBST(COMPAT_OBJS)
AC_SUBST(COMPAT_SRCS)

AC_PATH_TOOL([STRIP], [strip], [/bin/true])

needs_cpp_precomp=no

LUA_CFLAGS="-DLUA_USE_POSIX -DLUA_USE_DLOPEN"

case "$host" in
  *alpha-dec-osf*)
    AC_DEFINE(DEC)
    ;;
  *-netbsd* | *-knetbsd*-gnu)
    AC_DEFINE(NETBSD)
    LDFLAGS="-Wl,-E $LDFLAGS" # needed for nse-C-module support
    ;;
  *-openbsd*)
    AC_DEFINE(OPENBSD)
    LDFLAGS="-Wl,-E $LDFLAGS" # needed for nse-C-module support
    ;;
  *-freebsd* | *-kfreebsd*-gnu | *-dragonfly*)
    AC_DEFINE(FREEBSD)
    LDFLAGS="-Wl,-E $LDFLAGS" # needed for nse-C-module support
    ;;
  *-bsdi*)
    AC_DEFINE(BSDI)
    ;;
  *-sgi-irix5* | *-sgi-irix6*)
    AC_DEFINE(IRIX)
    ;;
  *-hpux*)
    AC_DEFINE(HPUX)
    # To link with libnet and NM (/usr/lib/libnm.sl) library
    # on HP-UX 11.11 (other versions?) Mikhail Zakharov (zmey20000@yahoo.com)
    AC_CHECK_LIB(nm, open_mib)
    ;;
  *-aix*)
    # use some AIX specific libraries
    AC_CHECK_LIB(odm, odm_initialize)	
    AC_CHECK_LIB(cfg, _system_configuration)
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
    AC_DEFINE(SUNOS)
    AC_DEFINE(SPRINTF_RETURNS_STRING)
    ;;
  *-linux*)
    AC_DEFINE(LINUX)
    LDFLAGS="-Wl,-E $LDFLAGS" # needed for nse-C-module support
    ;;
  *-apple-darwin*)
    AC_DEFINE(MACOSX)
    dnl on Mac OSX the math library seems to contain unwanted getopt cruft
    AC_CHECK_LIB(m, main)
    LUA_CFLAGS="-DLUA_USE_MACOSX"
    needs_cpp_precomp=yes
    ;;
esac

AC_SUBST(LUA_CFLAGS)

dnl Checks for header files.
AC_CHECK_HEADERS(pwd.h termios.h sys/sockio.h)
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

NDIFFDIR=ndiff

# Do they want Ndiff?
AC_ARG_WITH(ndiff, AC_HELP_STRING([--without-ndiff], [Skip installation of the Ndiff utility]), [], [with_ndiff=check])

if test "$with_ndiff" != "no"; then
  AM_PATH_PYTHON([2.4], [],
  [if test "$with_ndiff" = "check"; then
     AC_MSG_WARN([Not building Ndiff because Python 2.4 or later was not found])
   else
     AC_MSG_FAILURE([--with-ndiff requires Python 2.4 or later])
   fi
   with_ndiff=no])
fi
if test "$with_ndiff" = "no"; then
  BUILDNDIFF=""
  INSTALLNDIFF=""
  NDIFF_CLEAN=""
  NDIFF_DIST_CLEAN=""
else
  BUILDNDIFF=build-ndiff
  INSTALLNDIFF=install-ndiff
  NDIFF_CLEAN=ndiff_clean
  NDIFF_DIST_CLEAN=ndiff_dist_clean
fi
AC_SUBST(NDIFFDIR)
AC_SUBST(BUILDNDIFF)
AC_SUBST(INSTALLNDIFF)
AC_SUBST(NDIFF_CLEAN)
AC_SUBST(NDIFF_DIST_CLEAN)

ZENMAPDIR=zenmap

# Do they want Zenmap?
AC_ARG_WITH(zenmap, AC_HELP_STRING([--without-zenmap], [Skip installation of the Zenmap graphical frontend]), [], [with_zenmap=check])

if test "$with_zenmap" != "no"; then
  AM_PATH_PYTHON([2.4], [],
  [if test "$with_zenmap" = "check"; then
     AC_MSG_WARN([Not building Zenmap because Python 2.4 or later was not found])
   else
     AC_MSG_FAILURE([--with-zenmap requires Python 2.4 or later])
   fi
   with_zenmap=no])
fi
if test "$with_zenmap" = "no"; then
  BUILDZENMAP=""
  INSTALLZENMAP=""
  UNINSTALLZENMAP=""
  ZENMAP_CLEAN=""
  ZENMAP_DIST_CLEAN=""
else
  BUILDZENMAP=build-zenmap
  INSTALLZENMAP=install-zenmap
  UNINSTALLZENMAP=uninstall-zenmap
  ZENMAP_CLEAN=zenmap_clean
  ZENMAP_DIST_CLEAN=zenmap_dist_clean
fi
AC_SUBST(ZENMAPDIR)
AC_SUBST(BUILDZENMAP)
AC_SUBST(INSTALLZENMAP)
AC_SUBST(UNINSTALLZENMAP)
AC_SUBST(ZENMAP_CLEAN)
AC_SUBST(ZENMAP_DIST_CLEAN)

NPINGDIR=nping

# Do they want Nping?
AC_ARG_WITH(nping, AC_HELP_STRING([--without-nping], [Skip installation of the Nping utility]), [], [with_nping=check])

if test "$with_nping" = "no"; then
  BUILDNPING=""
  INSTALLNPING=""
  UNINSTALLNPING=""
  NPING_CLEAN=""
  NPING_DIST_CLEAN=""
else
  BUILDNPING=build-nping
  INSTALLNPING=install-nping
  UNINSTALLNPING=uninstall-nping
  NPING_CLEAN=nping_clean
  NPING_DIST_CLEAN=nping_dist_clean
  AC_CONFIG_SUBDIRS(nping)
fi
AC_SUBST(NPINGDIR)
AC_SUBST(BUILDNPING)
AC_SUBST(INSTALLNPING)
AC_SUBST(UNINSTALLNPING)
AC_SUBST(NPING_CLEAN)
AC_SUBST(NPING_DIST_CLEAN)

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

OPENSSL_LIBS=
if test "$use_openssl" = "yes"; then
  AC_DEFINE(HAVE_OPENSSL)
  OPENSSL_LIBS="-lssl -lcrypto"
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
      AC_CHECK_LIB(pcap, pcap_datalink,
      [have_libpcap=yes ])])
    ;;
  included)
    have_libpcap=no
   ;;
  *)
    _cppflags=$CXXFLAGS
    _ldflags=$LDFLAGS

    CPPFLAGS="-I$with_libpcap/include $CPPFLAGS"
    LDFLAGS="-L$with_libpcap/lib $LDFLAGS"

    AC_CHECK_HEADER(pcap.h,[
      AC_CHECK_LIB(pcap, pcap_datalink,
	[have_libpcap=yes
	LIBPCAP_INC=$with_libpcap/include
	LIBPCAP_LIB=$with_libpcap/lib])])

    LDFLAGS=$_ldflags
    CXXFLAGS=$_cppflags
    ;;
  esac]
)

if test $needs_cpp_precomp = yes; then
  CXXFLAGS="-no-cpp-precomp $CXXFLAGS"
fi

if test $have_libpcap = yes; then
  if test "${LIBPCAP_INC+set}" = "set"; then
    _cflags=$CXXFLAGS
    _ldflags=$LDFLAGS

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
  PCAP_DEPENDS='$(LIBPCAPDIR)/libpcap.a'
  PCAP_BUILD="pcap_build"
  PCAP_CLEAN="pcap_clean"
  PCAP_DIST_CLEAN="pcap_dist_clean"
  AC_DEFINE(PCAP_INCLUDED)

  # libpcap can require libnl
  AC_SEARCH_LIBS(nl_handle_alloc, nl)
else
  AC_DEFINE(HAVE_LIBPCAP)
  LIBPCAP_LIBS="-lpcap"
  PCAP_DEPENDS=""
  PCAP_BUILD=""
  PCAP_CLEAN=""
  PCAP_DIST_CLEAN=""
fi

AC_SUBST(PCAP_DEPENDS)
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
  PCRE_DEPENDS="$LIBPCREDIR/libpcre.a"
  PCRE_BUILD="pcre_build"
  PCRE_CLEAN="pcre_clean"
  PCRE_DIST_CLEAN="pcre_dist_clean"
  AC_DEFINE(PCRE_INCLUDED)
else
# We only need to check for and use this if we are NOT using included pcre
  AC_CHECK_HEADERS(pcre/pcre.h)
  LIBPCRE_LIBS="-lpcre"
  PCRE_DEPENDS=""
  PCRE_BUILD=""
  PCRE_CLEAN=""
  PCRE_DIST_CLEAN=""
fi

AC_SUBST(LIBPCRE_LIBS)
AC_SUBST(LIBPCREDIR)
AC_SUBST(PCRE_DEPENDS)
AC_SUBST(PCRE_BUILD)
AC_SUBST(PCRE_CLEAN)
AC_SUBST(PCRE_DIST_CLEAN)

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
AC_HELP_STRING([--with-libdnet=DIR], [Use an existing (compiled) dnet lib from DIR/include and DIR/lib. This is NOT RECOMMENDED because we have made many important fixes to our included libdnet, as described at http://nmap.org/svn/libdnet-stripped/NMAP_MODIFICATIONS])
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
  DNET_DEPENDS="\$(top_srcdir)/$LIBDNETDIR/src/.libs/libdnet.a"
  DNET_BUILD="dnet_build"
  DNET_CLEAN="dnet_clean"
  DNET_DIST_CLEAN="dnet_dist_clean"
  AC_DEFINE(DNET_INCLUDED)
else
  LIBDNET_LIBS="-ldnet"
  DNET_DEPENDS=""
  DNET_BUILD=""
  DNET_CLEAN=""
  DNET_DIST_CLEAN=""
fi

AC_SUBST(LIBDNET_LIBS)
AC_SUBST(LIBDNETDIR)
AC_SUBST(DNET_DEPENDS)
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
    LUA_DEPENDS="\$(top_srcdir)/$LIBLUADIR/liblua.a"
    LUA_BUILD="lua_build"
    LUA_CLEAN="lua_clean"
    LUA_DIST_CLEAN="lua_dist_clean"
	have_lua="yes"
	
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

# OpenSSL and NSE C modules can require dlopen
AC_SEARCH_LIBS(dlopen, dl)

# They don't want lua
if test "$no_lua" = "yes"; then
  CPPFLAGS="-DNOLUA $CPPFLAGS"
  LIBLUA_LIBS=""
  LUA_DEPENDS=""
  LUA_BUILD=""
  LUA_CLEAN=""
  LUA_DIST_CLEAN=""
  INSTALLNSE=""

else 

  # If they didn't specify it, we try to find it
  if test $have_lua != yes; then
    AC_CHECK_HEADERS([lua.h lua/lua.h lua5.1/lua.h],
      AC_CHECK_LIB(lua, lua_call, [have_lua=yes; LIBLUA_LIBS="-llua"; CPPFLAGS="-I/usr/include/lua $CPPFLAGS"; break],, [-lm])
      AC_CHECK_LIB(lua5.1, lua_call, [have_lua=yes; LIBLUA_LIBS="-llua5.1"; CPPFLAGS="-I/usr/include/lua5.1 $CPPFLAGS"; break],, [-lm])
    )

    AC_LANG_PUSH(C++)
    AC_MSG_CHECKING([for lua version >= 501])
    AC_RUN_IFELSE([ AC_LANG_PROGRAM(
    	[[#include <lua.h>]], 
    	[[if(LUA_VERSION_NUM < 501) return 1;]])], 
    	have_lua=yes, have_lua=no, AC_MSG_RESULT(cross-compiling -- assuming yes); have_lua=yes)
    AC_LANG_POP(C++)
  
    LUA_DEPENDS=""
    LUA_BUILD=""
    LUA_CLEAN=""
    LUA_DIST_CLEAN=""
  fi

  # if we didn't find we use our own
  if test $have_lua != yes; then
    AC_MSG_RESULT(no) 
    CPPFLAGS="-I\$(top_srcdir)/$LIBLUADIR $CPPFLAGS"
    LIBLUA_LIBS="\$(top_srcdir)/$LIBLUADIR/liblua.a"
    LUA_DEPENDS="\$(top_srcdir)/$LIBLUADIR/liblua.a"
    LUA_BUILD="lua_build"
    LUA_CLEAN="lua_clean"
    LUA_DIST_CLEAN="lua_dist_clean"
    AC_DEFINE(LUA_INCLUDED)
  else
    AC_MSG_RESULT(yes) 
  fi

  INSTALLNSE="install-nse"
fi

AC_SUBST(LIBLUA_LIBS)
AC_SUBST(LIBLUADIR)
AC_SUBST(LUA_DEPENDS)
AC_SUBST(LUA_BUILD)
AC_SUBST(LUA_CLEAN)
AC_SUBST(LUA_DIST_CLEAN)
AC_SUBST(INSTALLNSE)
AC_SUBST(CXXFLAGS)

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
        AC_DEFINE(HAVE_SOCKADDR_SA_LEN)
fi

#dnl check endedness
AC_C_BIGENDIAN

AC_MSG_CHECKING([if struct in_addr is a wacky huge structure (some Sun boxes)])

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
        AC_DEFINE(HAVE_STRUCT_ICMP)
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
        AC_DEFINE(HAVE_STRUCT_IP)
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
        AC_DEFINE(HAVE_IP_IP_SUM)
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
NBASE_BUILD="nbase_build"
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
NSOCK_BUILD="nsock_build"
AC_ARG_WITH(libnsock,
AC_HELP_STRING([--with-libnsock=DIR], [Compile and link to libnsock in DIR]),
[  case "$with_libnsock" in
  yes)
    ;;
  *)
    NSOCKDIR="$with_libnsock"
    NSOCK_BUILD=""
    ;;
  esac]
)

LDFLAGS="$LDFLAGS -L$NSOCKDIR/src/"
CPPFLAGS="$CPPFLAGS -I\$(top_srcdir)/$NSOCKDIR/include"
LIBNSOCK_LIBS="-lnsock"

AC_SUBST(NSOCKDIR)
AC_SUBST(NSOCK_BUILD)
AC_SUBST(LIBNSOCK_LIBS)

AC_CONFIG_SUBDIRS(nsock/src)

NCATDIR="ncat"

AC_ARG_WITH(ncat,
	AC_HELP_STRING([--without-ncat], [Skip build and installation of Ncat]), [], [with_ncat=check])

if test "$with_ncat" = "no"; then
  NCAT_BUILD=""
  NCAT_INSTALL=""
  NCAT_UNINSTALL=""
  NCAT_CLEAN=""
  NCAT_DIST_CLEAN=""
else
  NCAT_BUILD="ncat_build"
  NCAT_INSTALL="install-ncat"
  NCAT_UNINSTALL="uninstall-ncat"
  NCAT_CLEAN="ncat_clean"
  NCAT_DIST_CLEAN="ncat_dist_clean"
  AC_CONFIG_SUBDIRS(ncat)
fi

AC_SUBST(NCATDIR)
AC_SUBST(NCAT_BUILD)
AC_SUBST(NCAT_INSTALL)
AC_SUBST(NCAT_UNINSTALL)
AC_SUBST(NCAT_CLEAN)
AC_SUBST(NCAT_DIST_CLEAN)

AC_OUTPUT(Makefile libnetutil/Makefile)
# Krad ASCII ART#!#@$!@#$
if test -f docs/leet-nmap-ascii-art.txt; then
	cat docs/leet-nmap-ascii-art.txt
fi
echo "Configuration complete.  Type make (or gmake on some *BSD machines) to compile."
