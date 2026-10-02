# ===========================================================================
#     https://www.gnu.org/software/autoconf-archive/ax_check_vscript.html
# ===========================================================================
#
# Our pcre2_check_vscript.m4 is derived from the upstream ax_check_vscript.m4,
# with several modifications.
#
# The original upstream file requires the following notice:
#
# LICENSE
#
#   Copyright (c) 2014 Kevin Cernekee <cernekee@gmail.com>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

#serial 2.99 PCRE2

# _PCRE2_CHECK_VSCRIPT_SHLIB(flag, map-contents, action-if-link-succeeds)
# Build a shared library with the given linker flag and map file contents.
# This properly tests version script support by building a shared library
# rather than an executable, avoiding issues with executable-specific symbols
# (e.g. FreeBSD's crt1.o symbols, Solaris linker symbols in values-Xc.o).
# Uses libtool for portability across different platforms.
AC_DEFUN([_PCRE2_CHECK_VSCRIPT_SHLIB], [
  rm -rf conftest.vscript
  mkdir conftest.vscript
  cat > conftest.vscript/conftest.c <<_ACEOF
int hidethis(void) { return 0; }
int exposethis(void) { return hidethis(); }
_ACEOF
  echo "$2" > conftest.vscript/conftest.map
  _pcre2_abs_top_builddir="$ac_pwd"
  _pcre2_vscript_libtool="$SHELL $_pcre2_abs_top_builddir/libtool"
  _pcre2_vscript_cc="$CC"
  _pcre2_vscript_compile_flags="$CFLAGS $CPPFLAGS"
  _pcre2_vscript_ld_flags="$CFLAGS $LDFLAGS"
  _pcre2_vscript_script_flag="$1"
  export _pcre2_vscript_libtool
  export _pcre2_vscript_cc
  export _pcre2_vscript_compile_flags
  export _pcre2_vscript_ld_flags
  export _pcre2_vscript_script_flag
  AS_IF([(cd conftest.vscript && \
    $_pcre2_vscript_libtool --tag=CC --mode=compile $_pcre2_vscript_cc $_pcre2_vscript_compile_flags -c -o conftest.lo conftest.c && \
    $_pcre2_vscript_libtool --tag=CC --mode=link $_pcre2_vscript_cc $_pcre2_vscript_ld_flags -o libconftest.la conftest.lo -rpath /usr/lib -Wl,$_pcre2_vscript_script_flag,conftest.map) >&AS_MESSAGE_LOG_FD 2>&1], [$3])
  unset _pcre2_vscript_libtool
  unset _pcre2_vscript_cc
  unset _pcre2_vscript_compile_flags
  unset _pcre2_vscript_ld_flags
  unset _pcre2_vscript_script_flag
  rm -rf conftest.vscript
]) dnl _PCRE2_CHECK_VSCRIPT_SHLIB

AC_DEFUN([PCRE2_CHECK_VSCRIPT], [

  AC_ARG_ENABLE([symvers],
    AS_HELP_STRING([--disable-symvers],
                   [disable library symbol versioning [default=auto]]),
    [want_symvers=$enableval],
    [want_symvers=yes]
  )

  AS_IF([test x$want_symvers = xyes], [

    dnl First, test --version-script and -M with a simple wildcard.
    AC_CACHE_CHECK([linker version script flag], pcre2_cv_check_vscript_flag, [
      pcre2_cv_check_vscript_flag=unsupported

      _PCRE2_CHECK_VSCRIPT_SHLIB([--version-script],
        [PCRE2_10.00 { global: exposethis; local: *; };],
        [pcre2_cv_check_vscript_flag=--version-script])
      AS_IF([test x$pcre2_cv_check_vscript_flag = xunsupported], [
        _PCRE2_CHECK_VSCRIPT_SHLIB([-M],
          [PCRE2_10.00 { global: exposethis; local: *; };],
          [pcre2_cv_check_vscript_flag=-M])
      ])

      dnl The linker may interpret -M (no argument) as "produce a load map."
      dnl If "-M conftest.map" doesn't fail when conftest.map contains
      dnl obvious syntax errors, assume this is the case.

      AS_IF([test x$pcre2_cv_check_vscript_flag != xunsupported], [
        _PCRE2_CHECK_VSCRIPT_SHLIB([$pcre2_cv_check_vscript_flag],
          [PCRE2_10.00 { global: exposethis; local: *; };  {],
          [pcre2_cv_check_vscript_flag=unsupported])
      ])
    ])

    AS_IF([test x$pcre2_cv_check_vscript_flag != xunsupported], [

      dnl Test without wildcard - for detecting Solaris, which requires the
      dnl wildcard (or else a much more complex and brittle configuration).
      AC_CACHE_CHECK([if version scripts work without wildcard],
                     pcre2_cv_check_vscript_no_star, [
        pcre2_cv_check_vscript_no_star=no
        _PCRE2_CHECK_VSCRIPT_SHLIB([$pcre2_cv_check_vscript_flag],
          [PCRE2_10.00 { global: exposethis; local: hidethis; };],
          [pcre2_cv_check_vscript_no_star=yes])
      ])

      pcre2_check_vscript_flag=$pcre2_cv_check_vscript_flag
      pcre2_check_vscript_no_star=$pcre2_cv_check_vscript_no_star
    ], [
      pcre2_check_vscript_flag=
      pcre2_check_vscript_no_star=no
    ])
  ], [
    AC_MSG_CHECKING([linker version script flag])
    AC_MSG_RESULT([disabled])

    pcre2_check_vscript_flag=
    pcre2_check_vscript_no_star=no
  ])

]) dnl PCRE2_CHECK_VSCRIPT
