dnl Process this file with autoconf to produce a configure script.

dnl This has been stripped down a bit by fyodor@insecure.org for
dnl inclusion in Nmap (removed libtool and dynamic library stuff)

dnl This configure.in file has been hacked around quite a lot as a result of
dnl patches that various people have sent to me (PH). Sometimes the information
dnl I get is contradictory. I've tried to put in comments that explain things,
dnl but in some cases the information is second-hand and I have no way of
dnl verifying it. I am not an autoconf or libtool expert!

dnl This is required at the start; the name is the name of a file
dnl it should be seeing, to verify it is in the same directory.

AC_INIT(dftables.c)
AC_CONFIG_SRCDIR([pcre.h])

dnl A safety precaution

AC_PREREQ(2.57)

dnl Arrange to build config.h from config.h.in.
dnl Manual says this macro should come right after AC_INIT.
AC_CONFIG_HEADER(config.h)

dnl Default values for miscellaneous macros

POSIX_MALLOC_THRESHOLD=-DPOSIX_MALLOC_THRESHOLD=10

dnl Provide versioning information for libtool shared libraries that
dnl are built by default on Unix systems.

PCRE_LIB_VERSION=0:1:0
PCRE_POSIXLIB_VERSION=0:0:0

dnl Find the PCRE version from the pcre.h file. The PCRE_VERSION variable is
dnl substituted in pcre-config.in.

PCRE_MAJOR=`grep '#define PCRE_MAJOR' ${srcdir}/pcre.h | cut -c 29-`
PCRE_MINOR=`grep '#define PCRE_MINOR' ${srcdir}/pcre.h | cut -c 29-`
PCRE_PRERELEASE=`grep '#define PCRE_PRERELEASE' ${srcdir}/pcre.h | cut -c 29-`
PCRE_VERSION=${PCRE_MAJOR}.${PCRE_MINOR}${PCRE_PRERELEASE}

dnl Checks for programs.

AC_PROG_CC

AC_PROG_RANLIB

dnl We need to find a compiler for compiling a program to run on the local host
dnl while building. It needs to be different from CC when cross-compiling.
dnl There is a macro called AC_PROG_CC_FOR_BUILD in the GNU archive for
dnl figuring this out automatically. Unfortunately, it does not work with the
dnl latest versions of autoconf. So for the moment, we just default to the
dnl same values as the "main" compiler. People who are cross-compiling will
dnl just have to adjust the Makefile by hand or set these values when they
dnl run "configure".

CC_FOR_BUILD=${CC_FOR_BUILD:-'$(CC)'}
CFLAGS_FOR_BUILD=${CFLAGS_FOR_BUILD:-'$(CFLAGS)'}
CPPFLAGS_FOR_BUILD=${CFLAGS_FOR_BUILD:-'$(CPPFLAGS)'}
BUILD_EXEEXT=${BUILD_EXEEXT:-'$(EXEEXT)'}
BUILD_OBJEXT=${BUILD_OBJEXT:-'$(OBJEXT)'}

dnl Checks for header files.

AC_HEADER_STDC
AC_CHECK_HEADERS(limits.h)

dnl Checks for typedefs, structures, and compiler characteristics.

AC_C_CONST
AC_TYPE_SIZE_T

AC_CHECK_TYPES([long long], [pcre_have_long_long="1"], [pcre_have_long_long="0"])
AC_CHECK_TYPES([unsigned long long], [pcre_have_ulong_long="1"], [pcre_have_ulong_long="0"])
AC_SUBST(pcre_have_long_long)
AC_SUBST(pcre_have_ulong_long)

dnl Checks for library functions.

AC_CHECK_FUNCS(bcopy memmove strerror strtoq strtoll)

dnl Handle --enable-utf8

AC_ARG_ENABLE(utf8,
[  --enable-utf8           enable UTF8 support],
if test "$enableval" = "yes"; then
  UTF8=-DSUPPORT_UTF8
fi
)

dnl Handle --enable-unicode-properties

AC_ARG_ENABLE(unicode-properties,
[  --enable-unicode-properties  enable Unicode properties support],
if test "$enableval" = "yes"; then
  UCP=-DSUPPORT_UCP
fi
)

dnl Handle --enable-newline-is-cr

AC_ARG_ENABLE(newline-is-cr,
[  --enable-newline-is-cr  use CR as the newline character],
if test "$enableval" = "yes"; then
  NEWLINE=-DNEWLINE=13
fi
)

dnl Handle --enable-newline-is-lf

AC_ARG_ENABLE(newline-is-lf,
[  --enable-newline-is-lf  use LF as the newline character],
if test "$enableval" = "yes"; then
  NEWLINE=-DNEWLINE=10
fi
)

dnl Handle --enable-newline-is-crlf

AC_ARG_ENABLE(newline-is-crlf,
[  --enable-newline-is-crlf  use CRLF as the newline sequence],
if test "$enableval" = "yes"; then
  NEWLINE=-DNEWLINE=3338
fi
)

dnl Handle --enable-ebcdic

AC_ARG_ENABLE(ebcdic,
[  --enable-ebcdic         assume EBCDIC coding rather than ASCII],
if test "$enableval" == "yes"; then
  EBCDIC=-DEBCDIC=1
fi
)

dnl Handle --disable-stack-for-recursion

AC_ARG_ENABLE(stack-for-recursion,
[  --disable-stack-for-recursion  disable use of stack recursion when matching],
if test "$enableval" = "no"; then
  NO_RECURSE=-DNO_RECURSE
fi
)

dnl There doesn't seem to be a straightforward way of having parameters
dnl that set values, other than fudging the --with thing. So that's what
dnl I've done.

dnl Handle --with-posix-malloc-threshold=n

AC_ARG_WITH(posix-malloc-threshold,
[  --with-posix-malloc-threshold=10  threshold for POSIX malloc usage],
  POSIX_MALLOC_THRESHOLD=-DPOSIX_MALLOC_THRESHOLD=$withval
)

dnl Handle --with-link-size=n

AC_ARG_WITH(link-size,
[  --with-link-size=2    internal link size (2, 3, or 4 allowed)],
  LINK_SIZE=-DLINK_SIZE=$withval
)

dnl Handle --with-match-limit=n

AC_ARG_WITH(match-limit,
[  --with-match-limit=10000000  default limit on internal looping],
  MATCH_LIMIT=-DMATCH_LIMIT=$withval
)

dnl Handle --with-match-limit_recursion=n

AC_ARG_WITH(match-limit-recursion,
[  --with-match-limit-recursion=10000000  default limit on internal recursion],
  MATCH_LIMIT_RECURSION=-DMATCH_LIMIT_RECURSION=$withval
)

dnl Unicode character property support implies UTF-8 support

if test "$UCP" != "" ; then
  UTF8=-DSUPPORT_UTF8
fi

dnl MacOSX on Intel Hack to remove thread-jumps
AC_CANONICAL_HOST

case "$host" in
  i386-apple-darwin*)
     macosx=yes
     AC_DEFINE(MACOSX)
     needs_cpp_precomp=yes
     CFLAGS="$CFLAGS -fno-thread-jumps"
     ;;
esac

dnl "Export" these variables

AC_SUBST(BUILD_EXEEXT)
AC_SUBST(BUILD_OBJEXT)
AC_SUBST(CC_FOR_BUILD)
AC_SUBST(CFLAGS_FOR_BUILD)
AC_SUBST(CXXLDFLAGS)
AC_SUBST(EBCDIC)
AC_SUBST(HAVE_MEMMOVE)
AC_SUBST(HAVE_STRERROR)
AC_SUBST(LINK_SIZE)
AC_SUBST(MATCH_LIMIT)
AC_SUBST(MATCH_LIMIT_RECURSION)
AC_SUBST(NEWLINE)
AC_SUBST(NO_RECURSE)
AC_SUBST(PCRE_LIB_VERSION)
AC_SUBST(PCRE_POSIXLIB_VERSION)
AC_SUBST(PCRE_VERSION)
AC_SUBST(POSIX_MALLOC_THRESHOLD)
AC_SUBST(UCP)
AC_SUBST(UTF8)
AC_SUBST(CFLAGS)

AC_SUBST(POSIX_OBJ)
AC_SUBST(POSIX_LOBJ)
AC_SUBST(POSIX_LIB)

if test "x$enable_shared" = "xno" ; then
    AC_DEFINE([PCRE_STATIC],[1],[to link statically])
fi

dnl This must be last; it determines what files are written as well as config.h
AC_OUTPUT(Makefile )
