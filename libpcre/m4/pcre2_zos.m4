dnl Tests whether the compiler requires an additional flag in order to fail on
dnl undefined headers.

dnl The concept of setting this commandline flag was learned from patches and
dnl mailing list discussions of the gnulib and gawk projects (credit to
dnl Bruno Haible).

AC_DEFUN([PCRE2_ZOS_FIXES],
[
  AC_CACHE_CHECK([for OS/390 (z/OS)], [pcre2_cv_os390],
    [if test "`uname`" = "OS/390"; then
       pcre2_cv_os390=yes
     else
       pcre2_cv_os390=no
     fi])
  if test "$pcre2_cv_os390" = "yes"; then
    AC_CACHE_CHECK([whether the compiler supports -qhaltonmsg=CCN3296], [pcre2_cv_xlc_qhaltonmsg_support],
      [save_CFLAGS="$CFLAGS"
      CFLAGS="$CFLAGS -qhaltonmsg=CCN3296"
      AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
                        [pcre2_cv_xlc_qhaltonmsg_support=yes],
                        [pcre2_cv_xlc_qhaltonmsg_support=no])
      CFLAGS="$save_CFLAGS"
      ])

    AC_CACHE_CHECK([whether non-existent headers fail the compile], [pcre2_cv_xlc_nonexistent_fatal],
      [AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <thereshouldbenoheader.h>]])],
                         [pcre2_cv_xlc_nonexistent_fatal=no],
                         [pcre2_cv_xlc_nonexistent_fatal=yes])
      ])

    if test "$pcre2_cv_xlc_nonexistent_fatal" = "no" && test "$pcre2_cv_xlc_qhaltonmsg_support" = "yes"; then
      AC_CACHE_CHECK([whether -qhaltonmsg=CCN3296 fixes the non-existent-header issue], [pcre2_cv_xlc_qhaltonmsg_fixes],
        [save_CFLAGS="$CFLAGS"
        CFLAGS="$CFLAGS -qhaltonmsg=CCN3296"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <thereshouldbenoheader.h>]])],
                          [pcre2_cv_xlc_qhaltonmsg_fixes=no],
                          [pcre2_cv_xlc_qhaltonmsg_fixes=yes])
        CFLAGS="$save_CFLAGS"
        ])

      if test "$pcre2_cv_xlc_qhaltonmsg_fixes" = "no"; then
        AC_MSG_ERROR([-qhaltonmsg=CCN3296 not effective on non-existent headers])
      fi

      CFLAGS="$CFLAGS -qhaltonmsg=CCN3296"
    fi

  fi
])
