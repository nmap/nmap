dnl Process this file with autoconf to produce a configure script.

dnl NOTE FOR MAINTAINERS: Do not use minor version numbers 08 or 09 because
dnl the leading zeros may cause them to be treated as invalid octal constants
dnl if a PCRE2 user writes code that uses PCRE2_MINOR as a number. There is now
dnl a check further down that throws an error if 08 or 09 are used.

dnl The PCRE2_PRERELEASE feature is for identifying release candidates. It might
dnl be defined as -RC2, for example. For real releases, it should be empty.

m4_define(pcre2_major, [10])
m4_define(pcre2_minor, [43])
m4_define(pcre2_prerelease, [])
m4_define(pcre2_date, [2024-02-16])

# Libtool shared library interface versions (current:revision:age)
m4_define(libpcre2_8_version,     [12:0:12])
m4_define(libpcre2_16_version,    [12:0:12])
m4_define(libpcre2_32_version,    [12:0:12])
m4_define(libpcre2_posix_version, [3:5:0])

# NOTE: The CMakeLists.txt file searches for the above variables in the first
# 50 lines of this file. Please update that if the variables above are moved.

AC_PREREQ([2.62])
AC_INIT([PCRE2],pcre2_major.pcre2_minor[]pcre2_prerelease,[],[pcre2])
AC_CONFIG_SRCDIR([src/pcre2.h.in])
AM_INIT_AUTOMAKE([foreign])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_CONFIG_HEADERS(src/config.h)

# This was added at the suggestion of libtoolize (03-Jan-10)
AC_CONFIG_MACRO_DIR([m4])

# The default CFLAGS in Autoconf are "-g -O2" for gcc and just "-g" for any
# other compiler. There doesn't seem to be a standard way of getting rid of the
# -g (which I don't think is needed for a production library). This fudge seems
# to achieve the necessary. First, we remember the externally set values of
# CFLAGS. Then call the AC_PROG_CC macro to find the compiler - if CFLAGS is
# not set, it will be set to Autoconf's defaults. Afterwards, if the original
# values were not set, remove the -g from the Autoconf defaults.

remember_set_CFLAGS="$CFLAGS"

m4_version_prereq(2.70, [AC_PROG_CC], [AC_PROG_CC_C99])
AM_PROG_CC_C_O
AC_USE_SYSTEM_EXTENSIONS

if test "x$remember_set_CFLAGS" = "x"
then
  if test "$CFLAGS" = "-g -O2"
  then
    CFLAGS="-O2"
  elif test "$CFLAGS" = "-g"
  then
    CFLAGS=""
  fi
fi

# This is a new thing required to stop a warning from automake 1.12
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

# Check for a 64-bit integer type
AC_TYPE_INT64_T

AC_PROG_INSTALL
LT_INIT([win32-dll])
AC_PROG_LN_S

AC_SYS_LARGEFILE

# Check for GCC visibility feature

PCRE2_VISIBILITY

# Check for the mul_overflow() builtin

AC_MSG_CHECKING([for __builtin_mul_overflow()])
AC_LANG_PUSH([C])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
		#ifdef HAVE_SYS_TYPES_H
		#include <sys/types.h>
		#endif
		#include <stddef.h>

		int a, b;
		size_t m;
	]], [[__builtin_mul_overflow(a, b, &m)]])],
	[pcre2_cc_cv_builtin_mul_overflow=yes],
	[pcre2_cc_cv_builtin_mul_overflow=no])
AC_MSG_RESULT([$pcre2_cc_cv_builtin_mul_overflow])
if test "$pcre2_cc_cv_builtin_mul_overflow" = yes; then
	AC_DEFINE([HAVE_BUILTIN_MUL_OVERFLOW], 1,
		[Define this if your compiler provides __builtin_mul_overflow()])
fi
AC_LANG_POP([C])

# Check for Clang __attribute__((uninitialized)) feature

AC_MSG_CHECKING([for __attribute__((uninitialized))])
AC_LANG_PUSH([C])
tmp_CFLAGS=$CFLAGS
CFLAGS="$CFLAGS -Werror"
AC_COMPILE_IFELSE([AC_LANG_PROGRAM(,
                   [[char buf[128] __attribute__((uninitialized));(void)buf]])],
                   [pcre2_cc_cv_attribute_uninitialized=yes],
                   [pcre2_cc_cv_attribute_uninitialized=no])
AC_MSG_RESULT([$pcre2_cc_cv_attribute_uninitialized])
if test "$pcre2_cc_cv_attribute_uninitialized" = yes; then
  AC_DEFINE([HAVE_ATTRIBUTE_UNINITIALIZED], 1, [Define this if your compiler
             supports __attribute__((uninitialized))])
fi
CFLAGS=$tmp_CFLAGS
AC_LANG_POP([C])

# Versioning

PCRE2_MAJOR="pcre2_major"
PCRE2_MINOR="pcre2_minor"
PCRE2_PRERELEASE="pcre2_prerelease"
PCRE2_DATE="pcre2_date"

if test "$PCRE2_MINOR" = "08" -o "$PCRE2_MINOR" = "09"
then
  echo "***"
  echo "*** Minor version number $PCRE2_MINOR must not be used. ***"
  echo "*** Use only 00 to 07 or 10 onwards, to avoid octal issues. ***"
  echo "***"
  exit 1
fi

AC_SUBST(PCRE2_MAJOR)
AC_SUBST(PCRE2_MINOR)
AC_SUBST(PCRE2_PRERELEASE)
AC_SUBST(PCRE2_DATE)

# Set a more sensible default value for $(htmldir).
if test "x$htmldir" = 'x${docdir}'
then
  htmldir='${docdir}/html'
fi

# Force an error for PCRE1 size options
AC_ARG_ENABLE(pcre8,,,enable_pcre8=no)
AC_ARG_ENABLE(pcre16,,,enable_pcre16=no)
AC_ARG_ENABLE(pcre32,,,enable_pcre32=no)

if test "$enable_pcre8$enable_pcre16$enable_pcre32" != "nonono"
then
  echo "** ERROR: Use --[[en|dis]]able-pcre2-[[8|16|32]], not --[[en|dis]]able-pcre[[8|16|32]]"
  exit 1
fi

# Handle --disable-pcre2-8 (enabled by default)
AC_ARG_ENABLE(pcre2-8,
              AS_HELP_STRING([--disable-pcre2-8],
                             [disable 8 bit character support]),
              , enable_pcre2_8=unset)
AC_SUBST(enable_pcre2_8)

# Handle --enable-pcre2-16 (disabled by default)
AC_ARG_ENABLE(pcre2-16,
              AS_HELP_STRING([--enable-pcre2-16],
                             [enable 16 bit character support]),
              , enable_pcre2_16=unset)
AC_SUBST(enable_pcre2_16)

# Handle --enable-pcre2-32 (disabled by default)
AC_ARG_ENABLE(pcre2-32,
              AS_HELP_STRING([--enable-pcre2-32],
                             [enable 32 bit character support]),
              , enable_pcre2_32=unset)
AC_SUBST(enable_pcre2_32)

# Handle --enable-debug (disabled by default)
AC_ARG_ENABLE(debug,
              AS_HELP_STRING([--enable-debug],
                             [enable debugging code]),
              , enable_debug=no)

# Handle --enable-rebuild-chartables
AC_ARG_ENABLE(rebuild-chartables,
              AS_HELP_STRING([--enable-rebuild-chartables],
                             [rebuild character tables in current locale]),
              , enable_rebuild_chartables=no)

# Handle --disable-unicode (enabled by default)
AC_ARG_ENABLE(unicode,
              AS_HELP_STRING([--disable-unicode],
                             [disable Unicode support]),
              , enable_unicode=unset)

# Handle newline options
ac_pcre2_newline=lf
AC_ARG_ENABLE(newline-is-cr,
              AS_HELP_STRING([--enable-newline-is-cr],
                             [use CR as newline character]),
              ac_pcre2_newline=cr)
AC_ARG_ENABLE(newline-is-lf,
              AS_HELP_STRING([--enable-newline-is-lf],
                             [use LF as newline character (default)]),
              ac_pcre2_newline=lf)
AC_ARG_ENABLE(newline-is-crlf,
              AS_HELP_STRING([--enable-newline-is-crlf],
                             [use CRLF as newline sequence]),
              ac_pcre2_newline=crlf)
AC_ARG_ENABLE(newline-is-anycrlf,
              AS_HELP_STRING([--enable-newline-is-anycrlf],
                             [use CR, LF, or CRLF as newline sequence]),
              ac_pcre2_newline=anycrlf)
AC_ARG_ENABLE(newline-is-any,
              AS_HELP_STRING([--enable-newline-is-any],
                             [use any valid Unicode newline sequence]),
              ac_pcre2_newline=any)
AC_ARG_ENABLE(newline-is-nul,
              AS_HELP_STRING([--enable-newline-is-nul],
                             [use NUL (binary zero) as newline character]),
              ac_pcre2_newline=nul)
enable_newline="$ac_pcre2_newline"

# Handle --enable-bsr-anycrlf
AC_ARG_ENABLE(bsr-anycrlf,
              AS_HELP_STRING([--enable-bsr-anycrlf],
                             [\R matches only CR, LF, CRLF by default]),
              , enable_bsr_anycrlf=no)

# Handle --enable-never-backslash-C
AC_ARG_ENABLE(never-backslash-C,
              AS_HELP_STRING([--enable-never-backslash-C],
                             [use of \C causes an error]),
              , enable_never_backslash_C=no)

# Handle --enable-ebcdic
AC_ARG_ENABLE(ebcdic,
              AS_HELP_STRING([--enable-ebcdic],
                             [assume EBCDIC coding rather than ASCII; incompatible with --enable-utf; use only in (uncommon) EBCDIC environments; it implies --enable-rebuild-chartables]),
              , enable_ebcdic=no)

# Handle --enable-ebcdic-nl25
AC_ARG_ENABLE(ebcdic-nl25,
              AS_HELP_STRING([--enable-ebcdic-nl25],
                             [set EBCDIC code for NL to 0x25 instead of 0x15; it implies --enable-ebcdic]),
              , enable_ebcdic_nl25=no)

# Handle --with-link-size=N
AC_ARG_WITH(link-size,
            AS_HELP_STRING([--with-link-size=N],
                           [internal link size (2, 3, or 4 allowed; default=2)]),
            , with_link_size=2)

# Handle --with-max-varlookbehind=N
AC_ARG_WITH(max-varlookbehind,
            AS_HELP_STRING([--with-max-varlookbehind=N],
                           [maximum length of variable lookbehind (default=255)]),
            , with_max_varlookbehind=255)

# Handle --with-parens-nest-limit=N
AC_ARG_WITH(parens-nest-limit,
            AS_HELP_STRING([--with-parens-nest-limit=N],
                           [nested parentheses limit (default=250)]),
            , with_parens_nest_limit=250)

# Handle --with-heap-limit
AC_ARG_WITH(heap-limit,
            AS_HELP_STRING([--with-heap-limit=N],
                           [default limit on heap memory (kibibytes, default=20000000)]),
            , with_heap_limit=20000000)

# Handle --with-match-limit=N
AC_ARG_WITH(match-limit,
            AS_HELP_STRING([--with-match-limit=N],
                           [default limit on internal looping (default=10000000)]),
            , with_match_limit=10000000)

# Handle --with-match-limit-depth=N
# Recognize old synonym --with-match-limit-recursion
#
# Note: In config.h, the default is to define MATCH_LIMIT_DEPTH symbolically as
# MATCH_LIMIT, which in turn is defined to be some numeric value (e.g.
# 10000000). MATCH_LIMIT_DEPTH can otherwise be set to some different numeric
# value (or even the same numeric value as MATCH_LIMIT, though no longer
# defined in terms of the latter).
#
AC_ARG_WITH(match-limit-depth,
            AS_HELP_STRING([--with-match-limit-depth=N],
                           [default limit on match tree depth (default=MATCH_LIMIT)]),
            , with_match_limit_depth=MATCH_LIMIT)

AC_ARG_WITH(match-limit-recursion,,
            , with_match_limit_recursion=UNSET)

# Handle --enable-valgrind
AC_ARG_ENABLE(valgrind,
              AS_HELP_STRING([--enable-valgrind],
                             [enable valgrind support]),
              , enable_valgrind=no)

# Enable code coverage reports using gcov
AC_ARG_ENABLE(coverage,
              AS_HELP_STRING([--enable-coverage],
                             [enable code coverage reports using gcov]),
              , enable_coverage=no)

# Handle --disable-stack-for-recursion
# This option became obsolete at release 10.30.
AC_ARG_ENABLE(stack-for-recursion,,
              , enable_stack_for_recursion=yes)

# Original code
# AC_ARG_ENABLE(stack-for-recursion,
#               AS_HELP_STRING([--disable-stack-for-recursion],
#                              [don't use stack recursion when matching]),
#               , enable_stack_for_recursion=yes)

# Handle --disable-percent_zt (set as "auto" by default)
AC_ARG_ENABLE(percent-zt,
              AS_HELP_STRING([--disable-percent-zt],
                             [disable the use of z and t formatting modifiers]),
              , enable_percent_zt=auto)

# Set the default value for pcre2-8
if test "x$enable_pcre2_8" = "xunset"
then
  enable_pcre2_8=yes
fi

# Set the default value for pcre2-16
if test "x$enable_pcre2_16" = "xunset"
then
  enable_pcre2_16=no
fi

# Set the default value for pcre2-32
if test "x$enable_pcre2_32" = "xunset"
then
  enable_pcre2_32=no
fi

# Make sure at least one library is selected
if test "x$enable_pcre2_8$enable_pcre2_16$enable_pcre2_32" = "xnonono"
then
  AC_MSG_ERROR([At least one of the 8, 16 or 32 bit libraries must be enabled])
fi

# Unicode is enabled by default.
if test "x$enable_unicode" = "xunset"
then
  enable_unicode=yes
fi

# Convert the newline identifier into the appropriate integer value. These must
# agree with the PCRE2_NEWLINE_xxx values in pcre2.h.

case "$enable_newline" in
  cr)      ac_pcre2_newline_value=1 ;;
  lf)      ac_pcre2_newline_value=2 ;;
  crlf)    ac_pcre2_newline_value=3 ;;
  any)     ac_pcre2_newline_value=4 ;;
  anycrlf) ac_pcre2_newline_value=5 ;;
  nul)     ac_pcre2_newline_value=6 ;;
  *)
  AC_MSG_ERROR([invalid argument "$enable_newline" to --enable-newline option])
  ;;
esac

# --enable-ebcdic-nl25 implies --enable-ebcdic
if test "x$enable_ebcdic_nl25" = "xyes"; then
  enable_ebcdic=yes
fi

# Make sure that if enable_ebcdic is set, rebuild_chartables is also enabled.
# Also check that UTF support is not requested, because PCRE2 cannot handle
# EBCDIC and UTF in the same build. To do so it would need to use different
# character constants depending on the mode. Also, EBCDIC cannot be used with
# 16-bit and 32-bit libraries.
#
if test "x$enable_ebcdic" = "xyes"; then
  enable_rebuild_chartables=yes
  if test "x$enable_unicode" = "xyes"; then
    AC_MSG_ERROR([support for EBCDIC and Unicode cannot be enabled at the same time])
  fi
  if test "x$enable_pcre2_16" = "xyes" -o "x$enable_pcre2_32" = "xyes"; then
    AC_MSG_ERROR([EBCDIC support is available only for the 8-bit library])
  fi
fi

# Check argument to --with-link-size
case "$with_link_size" in
  2|3|4) ;;
  *)
  AC_MSG_ERROR([invalid argument "$with_link_size" to --with-link-size option])
  ;;
esac

AH_TOP([
/* PCRE2 is written in Standard C, but there are a few non-standard things it
can cope with, allowing it to run on SunOS4 and other "close to standard"
systems.

In environments that support the GNU autotools, config.h.in is converted into
config.h by the "configure" script. In environments that use CMake,
config-cmake.in is converted into config.h. If you are going to build PCRE2 "by
hand" without using "configure" or CMake, you should copy the distributed
config.h.generic to config.h, and edit the macro definitions to be the way you
need them. You must then add -DHAVE_CONFIG_H to all of your compile commands,
so that config.h is included at the start of every source.

Alternatively, you can avoid editing by using -D on the compiler command line
to set the macro values. In this case, you do not have to set -DHAVE_CONFIG_H,
but if you do, default values will be taken from config.h for non-boolean
macros that are not defined on the command line.

Boolean macros such as HAVE_STDLIB_H and SUPPORT_PCRE2_8 should either be
defined (conventionally to 1) for TRUE, and not defined at all for FALSE. All
such macros are listed as a commented #undef in config.h.generic. Macros such
as MATCH_LIMIT, whose actual value is relevant, have defaults defined, but are
surrounded by #ifndef/#endif lines so that the value can be overridden by -D.

PCRE2 uses memmove() if HAVE_MEMMOVE is defined; otherwise it uses bcopy() if
HAVE_BCOPY is defined. If your system has neither bcopy() nor memmove(), make
sure both macros are undefined; an emulation function will then be used. */])

# Checks for header files.
AC_CHECK_HEADERS(limits.h sys/types.h sys/stat.h dirent.h)
AC_CHECK_HEADERS([windows.h], [HAVE_WINDOWS_H=1])
AC_CHECK_HEADERS([sys/wait.h], [HAVE_SYS_WAIT_H=1])

# Conditional compilation
AM_CONDITIONAL(WITH_PCRE2_8, test "x$enable_pcre2_8" = "xyes")
AM_CONDITIONAL(WITH_PCRE2_16, test "x$enable_pcre2_16" = "xyes")
AM_CONDITIONAL(WITH_PCRE2_32, test "x$enable_pcre2_32" = "xyes")
AM_CONDITIONAL(WITH_DEBUG, test "x$enable_debug" = "xyes")
AM_CONDITIONAL(WITH_REBUILD_CHARTABLES, test "x$enable_rebuild_chartables" = "xyes")
AM_CONDITIONAL(WITH_UNICODE, test "x$enable_unicode" = "xyes")
AM_CONDITIONAL(WITH_VALGRIND, test "x$enable_valgrind" = "xyes")

# Checks for typedefs, structures, and compiler characteristics.

AC_C_CONST
AC_TYPE_SIZE_T

# Checks for library functions.

AC_CHECK_FUNCS(bcopy memfd_create memmove mkostemp secure_getenv strerror)
AC_MSG_CHECKING([for realpath])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <stdlib.h>
#include <limits.h>
]],[[
char buffer[PATH_MAX];
realpath(".", buffer);
]])],
[AC_MSG_RESULT([yes])
 AC_DEFINE([HAVE_REALPATH], 1,
  [Define to 1 if you have the `realpath' function.])
],
AC_MSG_RESULT([no]))

PCRE2_STATIC_CFLAG=""
if test "x$enable_shared" = "xno" ; then
  AC_DEFINE([PCRE2_STATIC], [1], [
    Define to any value if linking statically (TODO: make nice with Libtool)])
  PCRE2_STATIC_CFLAG="-DPCRE2_STATIC"
fi
AC_SUBST(PCRE2_STATIC_CFLAG)

PCRE2POSIX_CFLAG=""
if test "x$enable_shared" = "xyes" ; then
  PCRE2POSIX_CFLAG="-DPCRE2POSIX_SHARED"
fi
AC_SUBST(PCRE2POSIX_CFLAG)

# Here is where PCRE2-specific defines are handled

if test "$enable_pcre2_8" = "yes"; then
  AC_DEFINE([SUPPORT_PCRE2_8], [], [
    Define to any value to enable the 8 bit PCRE2 library.])
fi

if test "$enable_pcre2_16" = "yes"; then
  AC_DEFINE([SUPPORT_PCRE2_16], [], [
    Define to any value to enable the 16 bit PCRE2 library.])
fi

if test "$enable_pcre2_32" = "yes"; then
  AC_DEFINE([SUPPORT_PCRE2_32], [], [
    Define to any value to enable the 32 bit PCRE2 library.])
fi

if test "$enable_debug" = "yes"; then
  AC_DEFINE([PCRE2_DEBUG], [], [
    Define to any value to include debugging code.])
fi

if test "$enable_percent_zt" = "no"; then
  AC_DEFINE([DISABLE_PERCENT_ZT], [], [
    Define to any value to disable the use of the z and t modifiers in
    formatting settings such as %zu or %td (this is rarely needed).])
else
  enable_percent_zt=auto
fi

if test "$enable_unicode" = "yes"; then
  AC_DEFINE([SUPPORT_UNICODE], [], [
    Define to any value to enable support for Unicode and UTF encoding.
    This will work even in an EBCDIC environment, but it is incompatible
    with the EBCDIC macro. That is, PCRE2 can support *either* EBCDIC
    code *or* ASCII/Unicode, but not both at once.])
fi

AC_DEFINE_UNQUOTED([NEWLINE_DEFAULT], [$ac_pcre2_newline_value], [
  The value of NEWLINE_DEFAULT determines the default newline character
  sequence. PCRE2 client programs can override this by selecting other values
  at run time. The valid values are 1 (CR), 2 (LF), 3 (CRLF), 4 (ANY),
  5 (ANYCRLF), and 6 (NUL).])

if test "$enable_bsr_anycrlf" = "yes"; then
  AC_DEFINE([BSR_ANYCRLF], [], [
    By default, the \R escape sequence matches any Unicode line ending
    character or sequence of characters. If BSR_ANYCRLF is defined (to any
    value), this is changed so that backslash-R matches only CR, LF, or CRLF.
    The build-time default can be overridden by the user of PCRE2 at runtime.])
fi

if test "$enable_never_backslash_C" = "yes"; then
  AC_DEFINE([NEVER_BACKSLASH_C], [], [
    Defining NEVER_BACKSLASH_C locks out the use of \C in all patterns.])
fi

AC_DEFINE_UNQUOTED([LINK_SIZE], [$with_link_size], [
  The value of LINK_SIZE determines the number of bytes used to store
  links as offsets within the compiled regex. The default is 2, which
  allows for compiled patterns up to 65535 code units long. This covers the
  vast majority of cases. However, PCRE2 can also be compiled to use 3 or 4
  bytes instead. This allows for longer patterns in extreme cases.])

AC_DEFINE_UNQUOTED([MAX_VARLOOKBEHIND], [$with_max_varlookbehind], [
  The value of MAX_VARLOOKBEHIND specifies the default maximum length, in
  characters, for a variable-length lookbehind assertion.])

AC_DEFINE_UNQUOTED([PARENS_NEST_LIMIT], [$with_parens_nest_limit], [
  The value of PARENS_NEST_LIMIT specifies the maximum depth of nested
  parentheses (of any kind) in a pattern. This limits the amount of system
  stack that is used while compiling a pattern.])

AC_DEFINE_UNQUOTED([MATCH_LIMIT], [$with_match_limit], [
  The value of MATCH_LIMIT determines the default number of times the
  pcre2_match() function can record a backtrack position during a single
  matching attempt. The value is also used to limit a loop counter in
  pcre2_dfa_match(). There is a runtime interface for setting a different
  limit. The limit exists in order to catch runaway regular expressions that
  take forever to determine that they do not match. The default is set very
  large so that it does not accidentally catch legitimate cases.])

# --with-match-limit-recursion is an obsolete synonym for --with-match-limit-depth

if test "$with_match_limit_recursion" != "UNSET"; then
cat <<EOF

WARNING: --with-match-limit-recursion is an obsolete option. Please use
  --with-match-limit-depth in future. If both are set, --with-match-limit-depth
  will be used. See also --with-heap-limit.

EOF
if test "$with_match_limit_depth" = "MATCH_LIMIT"; then
  with_match_limit_depth=$with_match_limit_recursion
fi
fi

AC_DEFINE_UNQUOTED([MATCH_LIMIT_DEPTH], [$with_match_limit_depth], [
  The above limit applies to all backtracks, whether or not they are nested. In
  some environments it is desirable to limit the nesting of backtracking (that
  is, the depth of tree that is searched) more strictly, in order to restrict
  the maximum amount of heap memory that is used. The value of
  MATCH_LIMIT_DEPTH provides this facility. To have any useful effect, it must
  be less than the value of MATCH_LIMIT. The default is to use the same value
  as MATCH_LIMIT. There is a runtime method for setting a different limit. In
  the case of pcre2_dfa_match(), this limit controls the depth of the internal
  nested function calls that are used for pattern recursions, lookarounds, and
  atomic groups.])

AC_DEFINE_UNQUOTED([HEAP_LIMIT], [$with_heap_limit], [
  This limits the amount of memory that may be used while matching
  a pattern. It applies to both pcre2_match() and pcre2_dfa_match(). It does
  not apply to JIT matching. The value is in kibibytes (units of 1024 bytes).])

AC_DEFINE([MAX_NAME_SIZE], [32], [
  This limit is parameterized just in case anybody ever wants to
  change it. Care must be taken if it is increased, because it guards
  against integer overflow caused by enormously large patterns.])

AC_DEFINE([MAX_NAME_COUNT], [10000], [
  This limit is parameterized just in case anybody ever wants to
  change it. Care must be taken if it is increased, because it guards
  against integer overflow caused by enormously large patterns.])

AH_VERBATIM([PCRE2_EXP_DEFN], [
/* If you are compiling for a system other than a Unix-like system or
   Win32, and it needs some magic to be inserted before the definition
   of a function that is exported by the library, define this macro to
   contain the relevant magic. If you do not define this macro, a suitable
   __declspec value is used for Windows systems; in other environments
   a compiler relevant "extern" is used with any "visibility" related
   attributes from PCRE2_EXPORT included.
   This macro apears at the start of every exported function that is part
   of the external API. It does not appear on functions that are "external"
   in the C sense, but which are internal to the library. */
#undef PCRE2_EXP_DEFN])

if test "$enable_ebcdic" = "yes"; then
  AC_DEFINE_UNQUOTED([EBCDIC], [], [
    If you are compiling for a system that uses EBCDIC instead of ASCII
    character codes, define this macro to any value. When EBCDIC is set, PCRE2
    assumes that all input strings are in EBCDIC. If you do not define this
    macro, PCRE2 will assume input strings are ASCII or UTF-8/16/32 Unicode. It
    is not possible to build a version of PCRE2 that supports both EBCDIC and
    UTF-8/16/32.])
fi

if test "$enable_ebcdic_nl25" = "yes"; then
  AC_DEFINE_UNQUOTED([EBCDIC_NL25], [], [
    In an EBCDIC environment, define this macro to any value to arrange for
    the NL character to be 0x25 instead of the default 0x15. NL plays the role
    that LF does in an ASCII/Unicode environment.])
fi

if test "$enable_valgrind" = "yes"; then
  AC_DEFINE_UNQUOTED([SUPPORT_VALGRIND], [], [
     Define to any value for valgrind support to find invalid memory reads.])
fi

# Platform specific issues
NO_UNDEFINED=
EXPORT_ALL_SYMBOLS=
case $host_os in
  cygwin* | mingw* )
    if test X"$enable_shared" = Xyes; then
      NO_UNDEFINED="-no-undefined"
      EXPORT_ALL_SYMBOLS="-Wl,--export-all-symbols"
    fi
    ;;
esac

# The extra LDFLAGS for each particular library. The libpcre2*_version values
# are m4 variables, assigned above.

EXTRA_LIBPCRE2_8_LDFLAGS="$EXTRA_LIBPCRE2_8_LDFLAGS \
  $NO_UNDEFINED -version-info libpcre2_8_version"

EXTRA_LIBPCRE2_16_LDFLAGS="$EXTRA_LIBPCRE2_16_LDFLAGS \
  $NO_UNDEFINED -version-info libpcre2_16_version"

EXTRA_LIBPCRE2_32_LDFLAGS="$EXTRA_LIBPCRE2_32_LDFLAGS \
  $NO_UNDEFINED -version-info libpcre2_32_version"

EXTRA_LIBPCRE2_POSIX_LDFLAGS="$EXTRA_LIBPCRE2_POSIX_LDFLAGS \
  $NO_UNDEFINED -version-info libpcre2_posix_version"

AC_SUBST(EXTRA_LIBPCRE2_8_LDFLAGS)
AC_SUBST(EXTRA_LIBPCRE2_16_LDFLAGS)
AC_SUBST(EXTRA_LIBPCRE2_32_LDFLAGS)
AC_SUBST(EXTRA_LIBPCRE2_POSIX_LDFLAGS)

# When we run 'make distcheck', use these arguments. Turning off compiler
# optimization makes it run faster.
DISTCHECK_CONFIGURE_FLAGS="CFLAGS='' CXXFLAGS='' --enable-pcre2-16 --enable-pcre2-32 --enable-jit"
AC_SUBST(DISTCHECK_CONFIGURE_FLAGS)

# Handle valgrind support

if test "$enable_valgrind" = "yes"; then
  m4_ifdef([PKG_CHECK_MODULES],
           [PKG_CHECK_MODULES([VALGRIND],[valgrind])],
           [AC_MSG_ERROR([pkg-config not supported])])
fi

# Handle code coverage reporting support
if test "$enable_coverage" = "yes"; then
  if test "x$GCC" != "xyes"; then
    AC_MSG_ERROR([Code coverage reports can only be generated when using GCC])
  fi

  # ccache is incompatible with gcov
  AC_PATH_PROG([SHTOOL],[shtool],[false])
  case `$SHTOOL path $CC` in
    *ccache*) cc_ccache=yes;;
    *) cc_ccache=no;;
  esac

  if test "$cc_ccache" = "yes"; then
    if test -z "$CCACHE_DISABLE" -o "$CCACHE_DISABLE" != "1"; then
      AC_MSG_ERROR([must export CCACHE_DISABLE=1 to disable ccache for code coverage])
    fi
  fi

  AC_ARG_VAR([LCOV],[the ltp lcov program])
  AC_PATH_PROG([LCOV],[lcov],[false])
  if test "x$LCOV" = "xfalse"; then
    AC_MSG_ERROR([lcov not found])
  fi

  AC_ARG_VAR([GENHTML],[the ltp genhtml program])
  AC_PATH_PROG([GENHTML],[genhtml],[false])
  if test "x$GENHTML" = "xfalse"; then
    AC_MSG_ERROR([genhtml not found])
  fi

  # Set flags needed for gcov
  GCOV_CFLAGS="-O0 -ggdb3 -fprofile-arcs -ftest-coverage"
  GCOV_CXXFLAGS="-O0 -ggdb3 -fprofile-arcs -ftest-coverage"
  GCOV_LIBS="-lgcov"
  AC_SUBST([GCOV_CFLAGS])
  AC_SUBST([GCOV_CXXFLAGS])
  AC_SUBST([GCOV_LIBS])
fi # enable_coverage

AM_CONDITIONAL([WITH_GCOV],[test "x$enable_coverage" = "xyes"])

AC_MSG_CHECKING([whether Intel CET is enabled])
AC_LANG_PUSH([C])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM(,
                   [[#ifndef __CET__
# error CET is not enabled
#endif]])],
                   [pcre2_cc_cv_intel_cet_enabled=yes],
                   [pcre2_cc_cv_intel_cet_enabled=no])
AC_MSG_RESULT([$pcre2_cc_cv_intel_cet_enabled])
if test "$pcre2_cc_cv_intel_cet_enabled" = yes; then
  CET_CFLAGS="-mshstk"
  AC_SUBST([CET_CFLAGS])
fi
AC_LANG_POP([C])

# LIB_POSTFIX is used by CMakeLists.txt for Windows debug builds.
# Pass empty LIB_POSTFIX to *.pc files and pcre2-config here.
AC_SUBST(LIB_POSTFIX)

# Produce these files, in addition to config.h.

AC_CONFIG_FILES(
	Makefile
	pcre2-config
	src/pcre2.h
)

# Make the generated script files executable.
AC_CONFIG_COMMANDS([script-chmod], [chmod a+x pcre2-config])

# Make sure that pcre2_chartables.c is removed in case the method for
# creating it was changed by reconfiguration.
AC_CONFIG_COMMANDS([delete-old-chartables], [rm -f pcre2_chartables.c])

AC_OUTPUT

# --disable-stack-for-recursion is obsolete and has no effect.

if test "$enable_stack_for_recursion" = "no"; then
cat <<EOF

WARNING: --disable-stack-for-recursion is obsolete and has no effect.
EOF
fi

# Print out a nice little message after configure is run displaying the
# chosen options.

ebcdic_nl_code=n/a
if test "$enable_ebcdic_nl25" = "yes"; then
  ebcdic_nl_code=0x25
elif test "$enable_ebcdic" = "yes"; then
  ebcdic_nl_code=0x15
fi

cat <<EOF

$PACKAGE-$VERSION configuration summary:

    Install prefix ..................... : ${prefix}
    C preprocessor ..................... : ${CPP}
    C compiler ......................... : ${CC}
    Linker ............................. : ${LD}
    C preprocessor flags ............... : ${CPPFLAGS}
    C compiler flags ................... : ${CFLAGS} ${VISIBILITY_CFLAGS}
    Linker flags ....................... : ${LDFLAGS}
    Extra libraries .................... : ${LIBS}

    Build 8-bit pcre2 library .......... : ${enable_pcre2_8}
    Build 16-bit pcre2 library ......... : ${enable_pcre2_16}
    Build 32-bit pcre2 library ......... : ${enable_pcre2_32}
    Include debugging code ............. : ${enable_debug}
    Enable Unicode support ............. : ${enable_unicode}
    Newline char/sequence .............. : ${enable_newline}
    \R matches only ANYCRLF ............ : ${enable_bsr_anycrlf}
    \C is disabled ..................... : ${enable_never_backslash_C}
    EBCDIC coding ...................... : ${enable_ebcdic}
    EBCDIC code for NL ................. : ${ebcdic_nl_code}
    Rebuild char tables ................ : ${enable_rebuild_chartables}
    Internal link size ................. : ${with_link_size}
    Maximum variable lookbehind ........ : ${with_max_varlookbehind}
    Nested parentheses limit ........... : ${with_parens_nest_limit}
    Heap limit ......................... : ${with_heap_limit} kibibytes
    Match limit ........................ : ${with_match_limit}
    Match depth limit .................. : ${with_match_limit_depth}
    Build shared libs .................. : ${enable_shared}
    Build static libs .................. : ${enable_static}
    Valgrind support ................... : ${enable_valgrind}
    Code coverage ...................... : ${enable_coverage}
    Use %zu and %td .................... : ${enable_percent_zt}

EOF

dnl end configure.ac
