#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(ncat_main.c)

AC_CONFIG_HEADER(config.h)

m4_include([../acinclude.m4])

AC_CANONICAL_HOST

use_openssl="yes"
specialssldir=""
AC_ARG_WITH(openssl,[  --with-openssl=DIR    Use optional openssl libs and includes from [DIR]/lib/ and [DIR]/include/openssl/],
[  case "$with_openssl" in
  yes)
  ;;
  no)
    use_openssl="no"
  ;;
  *)
    specialssldir="$with_openssl"
    LDFLAGS="$LDFLAGS -L$with_openssl/lib"
    CFLAGS="-I$with_openssl/include $CFLAGS"
  ;;
  esac]
)

# Checks for programs.
AC_PROG_CC
if test -n "$GCC"; then
  CFLAGS="$CFLAGS -Wall"
fi
AC_PROG_INSTALL

AC_PATH_TOOL([STRIP], [strip], [/bin/true])

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([fcntl.h limits.h netdb.h netinet/in.h stdlib.h string.h strings.h sys/param.h sys/socket.h sys/time.h sys/timeb.h unistd.h sys/un.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STAT
AC_C_CONST
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([dup2 gettimeofday inet_ntoa memset select socket strcasecmp strchr strdup strerror strncasecmp strtol])
AC_SEARCH_LIBS(setsockopt, socket)
# Ncat does not call gethostbyname directly, but some of the libraries
# it links to (such as libpcap) do. Instead it calls getaddrinfo. At
# one point we changed this test to use getaddrinfo rather than
# gethostbyname, but on a Solaris 9 SPARC box that function could be
# called without -lnsl, while gethostbyname sitll required -lnsl, so
# we changed the test back.
AC_SEARCH_LIBS(gethostbyname, nsl)
# OpenSSL requires dlopen on some platforms
AC_SEARCH_LIBS(dlopen, dl)

# If they didn't specify it, we try to find it
if test "$use_openssl" = "yes" -a -z "$specialssldir" ; then
	AC_CHECK_HEADER(openssl/ssl.h,,
			[ use_openssl="no"
        AC_MSG_WARN([Failed to find openssl/ssl.h so OpenSSL will not be used. 
	If it is installed you can try the --with-openssl=DIR argument]) ])

	if test "$use_openssl" = "yes"; then
	     AC_CHECK_HEADER(openssl/err.h,,
	         [ use_openssl="no"
		     AC_MSG_WARN([Failed to find openssl/err.h so OpenSSL will not be used.
		      If it is installed you can try the --with-openssl=DIR argument]) ])
	fi

	if test "$use_openssl" = "yes"; then
		   AC_CHECK_HEADER(openssl/rand.h,,
		       [ use_openssl="no"
		         AC_MSG_WARN([Failed to find openssl/rand.h so OpenSSL will not be used.
			  If it is installed you can try the --with-openssl=DIR argument]) ])
	fi

	if test "$use_openssl" = "yes"; then
	 AC_CHECK_LIB(crypto, BIO_int_ctrl,
	   [],
	   [ use_openssl="no"
	   AC_MSG_WARN([Failed to find libcrypto so OpenSSL will not be used.
	    If it is installed you can try the --with-openssl=DIR argument]) ])
	fi
										     
	if test "$use_openssl" = "yes"; then
	   AC_CHECK_LIB(ssl, SSL_new,
	   [],
	   [ use_openssl="no"
	   AC_MSG_WARN([Failed to find libssl so OpenSSL will not be used. 
If it is installed you can try the --with-openssl=DIR argument]) ])
	fi
fi

OPENSSL_LIBS=
if test "$use_openssl" = "yes"; then
  AC_DEFINE([HAVE_OPENSSL], [1], [Define to 1 if you have OpenSSL.])
  AC_DEFINE([HAVE_HTTP_DIGEST], [1], [Define to 1 to enable HTTP Digest authentication (requires OpenSSL).])
  OPENSSL_LIBS="-lssl -lcrypto"
  # Define in Makefile also.
  HAVE_OPENSSL=yes
  AC_SUBST(HAVE_OPENSSL)
fi

AC_SUBST(OPENSSL_LIBS)    

libpcapdir=../libpcap
AC_SUBST(libpcapdir)

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

PCAP_LIBS="-lpcap"
if test $have_libpcap = yes; then
  PCAP_DEPENDS=""
  PCAP_BUILD=""
  PCAP_CLEAN=""
  PCAP_DIST_CLEAN=""
  AC_DEFINE(HAVE_LIBPCAP)
else
  if test "${LIBPCAP_INC+set}" = "set"; then
    LDFLAGS="-L$libpcapdir $_ldflags"
    CPPFLAGS="$CPPFLAGS -I$LIBPCAP_INC"
  else
    LDFLAGS="-L$libpcapdir $LDFLAGS"
    CPPFLAGS="$CPPFLAGS -I$libpcapdir"
  fi
  PCAP_DEPENDS='$(LIBPCAPDIR)/libpcap.a'
  PCAP_BUILD="pcap_build"
  PCAP_CLEAN="pcap_clean"
  PCAP_DIST_CLEAN="pcap_dist_clean"
fi

AC_SUBST(PCAP_DEPENDS)
AC_SUBST(PCAP_BUILD)
AC_SUBST(PCAP_CLEAN)
AC_SUBST(PCAP_DIST_CLEAN)
AC_SUBST(PCAP_LIBS)

# Needed on AIX.
AC_CHECK_LIB(odm, odm_initialize)

# Needed on AIX.
AC_CHECK_LIB(odm, odm_initialize)
AC_CHECK_LIB(cfg, _system_configuration)



LIBLUADIR=../liblua

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

LUA_CFLAGS="-DLUA_USE_POSIX -DLUA_USE_DLOPEN"
AC_SUBST(LUA_CFLAGS)

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
    AC_CHECK_HEADERS([lua.h lua/lua.h lua5.2/lua.h],
      AC_CHECK_LIB(lua, lua_yieldk, [have_lua=yes; LIBLUA_LIBS="-llua"; CPPFLAGS="-I/usr/include/lua $CPPFLAGS"; break],, [-lm])
      AC_CHECK_LIB(lua52, lua_yieldk, [have_lua=yes; LIBLUA_LIBS="-llua52"; CPPFLAGS="-I/usr/include/lua52 $CPPFLAGS"; break],, [-lm])
      AC_CHECK_LIB(lua5.2, lua_yieldk, [have_lua=yes; LIBLUA_LIBS="-llua5.2"; CPPFLAGS="-I/usr/include/lua5.2 $CPPFLAGS"; break],, [-lm])
    )

    AC_LANG_PUSH(C++)
    AC_MSG_CHECKING([for lua version >= 502])
    AC_RUN_IFELSE([ AC_LANG_PROGRAM(
    	[[#include <lua.h>]], 
    	[[if(LUA_VERSION_NUM < 502) return 1;]])], 
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



AC_CONFIG_FILES(Makefile)
AC_OUTPUT
# NCAT ASCII ART
if test -f docs/ncat-ascii-art.txt; then
	cat docs/ncat-ascii-art.txt
fi

echo "Configuration complete."
