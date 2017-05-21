# Require autoconf 2.13 -*- mode: fundamental; -*-
AC_PREREQ(2.13)

dnl Process this file with autoconf to produce a configure script.
AC_INIT(nping.cc)

m4_include([../acinclude.m4])

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
     CPPFLAGS="$CPPFLAGS -I/usr/local/include"
   fi
fi

libpcapdir=../libpcap
AC_SUBST(libpcapdir)

pcredir=libpcre
AC_SUBST(pcredir)

dnl use nping_config.h instead of -D macros
AC_CONFIG_HEADER(nping_config.h)

dnl Host specific hacks
AC_CANONICAL_HOST
AC_C_INLINE

dnl Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL

 if test -n "$GXX"; then
      CXXFLAGS="$CXXFLAGS -Wall "
 fi

AC_MSG_CHECKING([whether the compiler is gcc 4 or greater])
if test x"$GXX" = xno; then
  AC_MSG_RESULT([no])
else
  # On some distros, there are snapshots available as gcc4
  if test -z "$ac_cv_prog_CC" || test x"$CC" = xgcc4; then
    our_gcc="$CC"
  else
    our_gcc="$ac_cv_prog_CC"
  fi

  nping_gcc_major_version=0
  case `$our_gcc --version | sed -e 's,\..*,.,' -e q` in
    *4.)
      nping_gcc_major_version=4
      ;;
  esac

  if test 4 -ge $nping_gcc_major_version; then
    AC_MSG_RESULT([yes])
    CXXFLAGS="$CXXFLAGS -fno-strict-aliasing"
  else
    AC_MSG_RESULT([no])
  fi
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

AC_PATH_TOOL([STRIP], [strip], [/bin/true])

needs_cpp_precomp=no

dnl Checks for header files.
AC_CHECK_HEADERS(pwd.h termios.h sys/sockio.h)

dnl If any socket libraries needed
AC_SEARCH_LIBS(setsockopt, socket)
AC_SEARCH_LIBS(gethostbyname, nsl)

# OpenSSL and NSE C modules can require dlopen
AC_SEARCH_LIBS(dlopen, dl)

# libpcap can require libnl
AC_SEARCH_LIBS(nl_handle_alloc, nl)

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
  LIBS_TMP="$LIBS"
  LIBS="$OPENSSL_LIBS $LIBS"
  # Check whether the installed OpenSSL supports SHA-256 (ver 0.9.8 or later).
  AC_CHECK_FUNC(EVP_sha256,, AC_MSG_ERROR([Your version of OpenSSL does not support SHA-256. Please install OpenSSL 0.9.8 or later.]))
  LIBS="$LIBS_TMP"
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
    _cppflags=$CPPFLAGS
    _ldflags=$LDFLAGS

    CPPFLAGS="-I$with_libpcap/include $CPPFLAGS"
    LDFLAGS="-L$with_libpcap/lib $LDFLAGS"

    AC_CHECK_HEADER(pcap.h,[
      AC_CHECK_LIB(pcap, pcap_datalink,
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
  if test "${LIBPCAP_INC+set}" = "set"; then
    LDFLAGS="-L$libpcapdir $_ldflags"
    CPPFLAGS="$CPPFLAGS -I$LIBPCAP_INC"
  else
    LDFLAGS="-L$libpcapdir $LDFLAGS"
    CPPFLAGS="$CPPFLAGS -I$libpcapdir"
  fi
  LIBPCAP_LIBS='$(LIBPCAPDIR)/libpcap.a'
  PCAP_DEPENDS='$(LIBPCAPDIR)/libpcap.a'
  PCAP_BUILD="build-pcap"
  PCAP_CLEAN="clean-pcap"
  PCAP_DIST_CLEAN="distclean-pcap"
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

if test $have_libpcap != yes ; then
        AC_CONFIG_SUBDIRS(libpcap)
fi


have_dnet=no
requested_included_dnet=no
LIBDNETDIR=../libdnet-stripped

# First we test whether they specified libdnet explicitly.
# Unlike the other included libraries (pcap, pcre, lua), we prefer our local
# copy of libdnet. That is, with the other libraries we check for a system
# version by default, whereas with dnet we use the local version unless
# specifically asked to use a system version.
AC_ARG_WITH(libdnet,
AC_HELP_STRING([--with-libdnet=DIR], [Use an existing (compiled) dnet lib from DIR/include and DIR/lib.])
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
  CPPFLAGS="-I$LIBDNETDIR/include $CPPFLAGS"
  LIBDNET_LIBS="$LIBDNETDIR/src/.libs/libdnet.a"
  DNET_DEPENDS="$LIBDNETDIR/src/.libs/libdnet.a"
  DNET_BUILD="build-dnet"
  DNET_CLEAN="clean-dnet"
  DNET_DIST_CLEAN="distclean-dnet"
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


dnl Check if the sockaddr_in implementation has member sin_len
dnl ##################################################################
dnl Check if sockaddr_in{} has sin_len member.
dnl
AC_CACHE_CHECK(if sockaddr_in{} has sin_len member, ac_cv_sockaddr_in_has_sin_len,
        AC_TRY_COMPILE([
               #include <sys/types.h>
               #include <netinet/in.h>
               #include <sys/socket.h>],
                [unsigned int i = sizeof(((struct sockaddr_in *)0)->sin_len)],
        ac_cv_sockaddr_in_has_sin_len=yes,
        ac_cv_sockaddr_in_has_sin_len=no))
if test $ac_cv_sockaddr_in_has_sin_len = yes ; then
        AC_DEFINE(HAVE_SOCKADDR_IN_SIN_LEN)
fi


dnl Check if the sockaddr_in6 implementation has member sin6_len
dnl ##################################################################
dnl Check if sockaddr_in6{} has sin6_len member.
dnl
AC_CACHE_CHECK(if sockaddr_in6{} has sin6_len member, ac_cv_sockaddr_in6_has_sin6_len,
        AC_TRY_COMPILE([
               #include <sys/types.h>
               #include <netinet/in.h>
               #include <sys/socket.h>],
                [unsigned int i = sizeof(((struct sockaddr_in6 *)0)->sin6_len)],
        ac_cv_sockaddr_in6_has_sin6_len=yes,
        ac_cv_sockaddr_in6_has_sin6_len=no))
if test $ac_cv_sockaddr_in6_has_sin6_len = yes ; then
        AC_DEFINE(HAVE_SOCKADDR_IN6_SIN6_LEN)
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

#AC_CACHE_CHECK(if struct icmp exists, ac_cv_struct_icmp_exists,
        #AC_TRY_COMPILE([
               ##include <sys/types.h>
               ##include <sys/param.h>
               ##include <netinet/in_systm.h>
               ##include <netinet/in.h>               
               ##define __USE_BSD
               ##define __FAVOR_BSD
               ##define _BSD_SOURCE
               ##include <netinet/ip.h>
               ##include <netinet/ip_icmp.h>],
                #[unsigned int i = sizeof(struct icmp)],
        #ac_cv_struct_icmp_exists=yes,
        #ac_cv_struct_icmp_exists=no))
#if test $ac_cv_struct_icmp_exists = yes ; then
        #AC_DEFINE(HAVE_STRUCT_ICMP)
#fi

#AC_CACHE_CHECK(if struct ip exists, ac_cv_struct_ip_exists,
        #AC_TRY_COMPILE([
               ##include <sys/types.h>
               ##include <sys/param.h>
               ##include <netinet/in_systm.h>
               ##include <netinet/in.h>               
               ##define __USE_BSD
               ##define __FAVOR_BSD
               ##define _BSD_SOURCE
               ##include <netinet/ip.h>],
                #[unsigned int i = sizeof(struct ip)],
        #ac_cv_struct_ip_exists=yes,
        #ac_cv_struct_ip_exists=no))
#if test $ac_cv_struct_ip_exists = yes ; then
        #AC_DEFINE(HAVE_STRUCT_IP)
#fi

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

AC_CACHE_CHECK(if function signal is accessible, ac_cv_have_signal,
        AC_TRY_COMPILE(
                [
                    #include <signal.h>
                ],
                [
                    void handler(int signo){
                     int a=0;
                    }

                    int main () {
                        ssignal(SIGINT, handler);
                        return 0;
                    }
                ],
        ac_cv_have_signal=yes,
        ac_cv_have_signal=no))
if test $ac_cv_have_signal = yes ; then
        AC_DEFINE(HAVE_SIGNAL)
fi




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
  *-freebsd* | *-kfreebsd*-gnu | *-dragonfly*)
    AC_DEFINE(FREEBSD)
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
    AC_CHECK_LIB(crypt, crypt_r)
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
    ;;
  *-apple-darwin*)
    AC_DEFINE(MACOSX)
    dnl on Mac OSX the math library seems to contain unwanted getopt cruft
    AC_CHECK_LIB(m, main)
    needs_cpp_precomp=yes
    ;;
esac







dnl Checks for library functions.
AC_CHECK_FUNCS(strerror)
#RECVFROM_ARG6_TYPE

AC_OUTPUT(Makefile)
# Some ASCII ART#!#@$!@#$
if test -f docs/leet-nping-ascii-art.txt; then
	cat docs/leet-nping-ascii-art.txt
fi
echo "Configuration complete.  Type make (or gmake on some *BSD machines) to compile."
