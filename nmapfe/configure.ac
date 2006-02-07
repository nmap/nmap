dnl Process this file with autoconf to produce a configure script.

AC_INIT(nmapfe.c)

#AM_INIT_AUTOMAKE(nmapfe, 0.9.5)

AC_PROG_CC

AM_PATH_GTK_2_0(2.0.0,
            [LIBS="$LIBS $GTK_LIBS" CFLAGS="$CFLAGS $GTK_CFLAGS"],
            AC_DEFINE(MISSING_GTK) \
	    AC_MSG_WARN(NMAPFE WILL NOT BE BUILT -- BUT NMAP SHOULD STILL WORK ))

dnl Host specific hacks
AC_CANONICAL_HOST


linux=no
macosx=no
needs_cpp_precomp=no
case "$host" in
  *-netbsd* | *-knetbsd*-gnu)
    AC_DEFINE(NETBSD)
    ;;
  *-openbsd*)
    AC_DEFINE(OPENBSD)
    ;;
  *-sgi-irix5*)
    AC_DEFINE(IRIX)
    if test -z "$GCC"; then
      sgi_cc=yes
    fi
    ;;
  *-sgi-irix6*)
    AC_DEFINE(IRIX)
    if test -z "$GCC"; then
      sgi_cc=yes
    fi
    ;;
  *-hpux*)
    AC_DEFINE(HPUX)
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
    linux=yes
    AC_DEFINE(LINUX)
    AC_DEFINE(PCAP_TIMEOUT_IGNORED)  # libpcap doesn't even LOOK at
                                     # the timeout you give it under Linux
    ;;
  *-freebsd* | *-kfreebsd*-gnu | *-dragonfly*)
    AC_DEFINE(FREEBSD)
    ;;
  *-bsdi*)
    AC_DEFINE(BSDI)
    ;;
  *-apple-darwin*)
    macosx=yes
    AC_DEFINE(MACOSX)
    needs_cpp_precomp=yes
    ;;
esac

dnl Only use -Wall if we have gcc
if test "x$GCC" = "xyes"; then
  if test -z "`echo "$CFLAGS" | grep "\-Wall" 2> /dev/null`" ; then
    CFLAGS="$CFLAGS -Wall"
  fi
fi

if test $needs_cpp_precomp = yes; then
  CFLAGS="-no-cpp-precomp $CFLAGS"
fi

AC_ARG_WITH(libnbase,
[  --with-libnbase=DIR     Look for nbase include/libs in DIR],
[  case "$with_libnbase" in
  yes)
    ;;
  *)
    NBASEDIR="$with_libnbase"
    ;;
  esac],
NBASEDIR="../nbase"
)
LDFLAGS="$LDFLAGS -L$NBASEDIR"
CFLAGS="$CFLAGS -I$NBASEDIR"
LIBS="$LIBS -lnbase"
AC_SUBST(NBASEDIR)

AC_OUTPUT(Makefile)
