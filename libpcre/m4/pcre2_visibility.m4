# visibility.m4 serial 4 (gettext-0.18.2)
dnl Copyright (C) 2005, 2008, 2010-2011 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

dnl Originally From Bruno Haible.

dnl Tests whether the compiler supports the command-line option
dnl -fvisibility=hidden and the function attribute
dnl __attribute__((__visibility__("default"))).
dnl
dnl Set the variable VISIBILITY_CFLAGS.
dnl Defines and sets the variable HAVE_VISIBILITY.
dnl Defines and sets the variable WORKING_WERROR.

dnl Modified to fit with PCRE build environment by Cristian Rodríguez.
dnl Adjusted for PCRE2 by PH.
dnl Refactored to work with non GCC (but compatible) compilers.

AC_DEFUN([PCRE2_VISIBILITY],
[
  AC_REQUIRE([AC_PROG_CC])
  VISIBILITY_CFLAGS=
  HAVE_VISIBILITY=0
  dnl First, check whether -Werror can be added to the command line, or
  dnl whether it leads to an error because of some other option that the
  dnl user has put into $CC $CFLAGS $CPPFLAGS.
  AC_MSG_CHECKING([whether the -Werror option is usable])
  AC_CACHE_VAL([pcre2_cv_cc_vis_werror], [
    pcre2_save_CFLAGS="$CFLAGS"
    CFLAGS="$CFLAGS -Werror"
    pcre2_cv_cc_vis_werror=no
    AC_COMPILE_IFELSE(
      [AC_LANG_PROGRAM([[]], [[]])],
      [
	AC_COMPILE_IFELSE(
	  [AC_LANG_PROGRAM([[]], [[ #warning e ]])],
          [], [pcre2_cv_cc_vis_werror=yes]
	)
      ], [])
    CFLAGS="$pcre2_save_CFLAGS"])
  AC_MSG_RESULT([$pcre2_cv_cc_vis_werror])
  if test -n "$pcre2_cv_cc_vis_werror" && test $pcre2_cv_cc_vis_werror = yes
  then
    WORKING_WERROR=1
  else
    WORKING_WERROR=0
  fi
  if test $pcre2_cv_cc_vis_werror = yes; then
    dnl Now check whether GCC compatible visibility declarations are supported.
    AC_MSG_CHECKING([for GCC compatible visibility declarations])
    AC_CACHE_VAL([pcre2_cv_cc_visibility], [
      pcre2_save_CFLAGS="$CFLAGS"
      CFLAGS="$CFLAGS -Werror -fvisibility=hidden"
      dnl We use the option -Werror and a function dummyfunc, because on some
      dnl platforms (Cygwin 1.7) the use of -fvisibility triggers a warning
      dnl "visibility attribute not supported in this configuration; ignored"
      dnl at the first function definition in every compilation unit, and we
      dnl don't want to use the option in this case.
      AC_COMPILE_IFELSE(
        [AC_LANG_PROGRAM(
           [[extern __attribute__((__visibility__("hidden"))) int hiddenfunc (void);
             extern __attribute__((__visibility__("default"))) int exportedfunc (void);
             void dummyfunc (void) {}
           ]],
           [[]])],
        [pcre2_cv_cc_visibility=yes],
        [pcre2_cv_cc_visibility=no])
      CFLAGS="$pcre2_save_CFLAGS"])
      AC_MSG_RESULT([$pcre2_cv_cc_visibility])
  fi
  if test -n "$pcre2_cv_cc_visibility" && test $pcre2_cv_cc_visibility = yes
  then
    VISIBILITY_CFLAGS="-fvisibility=hidden"
    HAVE_VISIBILITY=1
    AC_DEFINE(PCRE2_EXPORT, [__attribute__ ((visibility ("default")))], [to make a symbol visible])
  else
    AC_DEFINE(PCRE2_EXPORT, [], [to make a symbol visible])
  fi
  AC_SUBST([VISIBILITY_CFLAGS])
  AC_SUBST([HAVE_VISIBILITY])
  AC_DEFINE_UNQUOTED([HAVE_VISIBILITY], [$HAVE_VISIBILITY],
    [Define to 1 if the compiler supports GCC compatible visibility declarations.])
])
