# ===========================================================================
#     https://www.gnu.org/software/autoconf-archive/ax_check_vscript.html
# ===========================================================================
#
# SYNOPSIS
#
#   AX_CHECK_VSCRIPT
#
# DESCRIPTION
#
#   Check whether the linker supports version scripts.  Version scripts are
#   used when building shared libraries to bind symbols to version nodes
#   (helping to detect incompatibilities) or to limit the visibility of
#   non-public symbols.
#
#   Output:
#
#   If version scripts are supported, VSCRIPT_LDFLAGS will contain the
#   appropriate flag to pass to the linker.  On GNU systems this would
#   typically be "-Wl,--version-script", and on Solaris it would typically
#   be "-Wl,-M".
#
#   Two Automake conditionals are also set:
#
#    HAVE_VSCRIPT is true if the linker supports version scripts with
#    entries that use simple wildcards, like "local: *".
#
#    HAVE_VSCRIPT_COMPLEX is true if the linker supports version scripts with
#    pattern matching wildcards, like "global: Java_*".
#
#   On systems that do not support symbol versioning, such as Mac OS X, both
#   conditionals will be false.  They will also be false if the user passes
#   "--disable-symvers" on the configure command line.
#
#   Example:
#
#    configure.ac:
#
#     AX_CHECK_VSCRIPT
#
#    Makefile.am:
#
#     if HAVE_VSCRIPT
#     libfoo_la_LDFLAGS += $(VSCRIPT_LDFLAGS),@srcdir@/libfoo.map
#     endif
#
#     if HAVE_VSCRIPT_COMPLEX
#     libbar_la_LDFLAGS += $(VSCRIPT_LDFLAGS),@srcdir@/libbar.map
#     endif
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

# _AX_CHECK_VSCRIPT(flag, global-sym, action-if-link-succeeds, [junk-file=no])
AC_DEFUN([_AX_CHECK_VSCRIPT], [
  AC_LANG_PUSH([C])
  ax_check_vscript_save_flags="$LDFLAGS"
  echo "V1 { global: $2; local: *; };" > conftest.map
  AS_IF([test x$4 = xyes], [
    echo "{" >> conftest.map
  ])
  LDFLAGS="$LDFLAGS -Wl,$1,conftest.map"
  AC_LINK_IFELSE([AC_LANG_PROGRAM([[int show, hide;]], [])], [$3])
  LDFLAGS="$ax_check_vscript_save_flags"
  rm -f conftest.map
  AC_LANG_POP([C])
]) dnl _AX_CHECK_VSCRIPT

AC_DEFUN([AX_CHECK_VSCRIPT], [

  AC_ARG_ENABLE([symvers],
    AS_HELP_STRING([--disable-symvers],
                   [disable library symbol versioning [default=auto]]),
    [want_symvers=$enableval],
    [want_symvers=yes]
  )

  AS_IF([test x$want_symvers = xyes], [

    dnl First test --version-script and -M with a simple wildcard.

    AC_CACHE_CHECK([linker version script flag], ax_cv_check_vscript_flag, [
      ax_cv_check_vscript_flag=unsupported
      _AX_CHECK_VSCRIPT([--version-script], [show], [
        ax_cv_check_vscript_flag=--version-script
      ])
      AS_IF([test x$ax_cv_check_vscript_flag = xunsupported], [
        # PCRE2: Support for FreeBSD. Rather annoyingly, AC_LINK_IFELSE will
        # only test linking executables, and in turn, on FreeBSD the main
        # entrypoint will fail to link if you use "local: *" to hide the
        # visibility of various shared symbols injected from /usr/lib/crt1.o.
        # It's not at all pretty to hardcode those symbol names here, but I
        # can't think of an obvious way to improve on this.
        _AX_CHECK_VSCRIPT([--version-script], [show;environ;__progname], [
          ax_cv_check_vscript_flag=--version-script
        ])
      ])
      AS_IF([test x$ax_cv_check_vscript_flag = xunsupported], [
        _AX_CHECK_VSCRIPT([-M], [show], [ax_cv_check_vscript_flag=-M])
      ])

      dnl The linker may interpret -M (no argument) as "produce a load map."
      dnl If "-M conftest.map" doesn't fail when conftest.map contains
      dnl obvious syntax errors, assume this is the case.

      AS_IF([test x$ax_cv_check_vscript_flag != xunsupported], [
        _AX_CHECK_VSCRIPT([$ax_cv_check_vscript_flag], [show],
	                  [ax_cv_check_vscript_flag=unsupported], [yes])
      ])
    ])

    dnl If the simple wildcard worked, retest with a complex wildcard.

    AS_IF([test x$ax_cv_check_vscript_flag != xunsupported], [
      ax_check_vscript_flag=$ax_cv_check_vscript_flag
      AC_CACHE_CHECK([if version scripts can use complex wildcards],
                     ax_cv_check_vscript_complex_wildcards, [
        ax_cv_check_vscript_complex_wildcards=no
        _AX_CHECK_VSCRIPT([$ax_cv_check_vscript_flag], [sh*], [
        ax_cv_check_vscript_complex_wildcards=yes])
      ])
      ax_check_vscript_complex_wildcards="$ax_cv_check_vscript_complex_wildcards"
    ], [
      ax_check_vscript_flag=
      ax_check_vscript_complex_wildcards=no
    ])
  ], [
    AC_MSG_CHECKING([linker version script flag])
    AC_MSG_RESULT([disabled])

    ax_check_vscript_flag=
    ax_check_vscript_complex_wildcards=no
  ])

  AS_IF([test x$ax_check_vscript_flag != x], [
    VSCRIPT_LDFLAGS="-Wl,$ax_check_vscript_flag"
    AC_SUBST([VSCRIPT_LDFLAGS])
  ])

  AM_CONDITIONAL([HAVE_VSCRIPT],
    [test x$ax_check_vscript_flag != x])
  AM_CONDITIONAL([HAVE_VSCRIPT_COMPLEX],
    [test x$ax_check_vscript_complex_wildcards = xyes])

]) dnl AX_CHECK_VSCRIPT
