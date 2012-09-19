#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([nmap-update.c])
AC_CONFIG_HEADERS([config.h])

m4_include([../acinclude.m4])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PATH_TOOL([STRIP], [strip], [/bin/true])

# GCC-specific flags
if test -n "$GCC"; then
  # -Wno-deprecated-declarations is because we use an older version of the
  # Subversion API for compatibility.
  CFLAGS="$CFLAGS -Wall -Wno-deprecated-declarations"
fi

APR_FIND_APR(, , 1, 1)
if test "$apr_found" = "no"; then
  AC_MSG_ERROR([libapr is required to build nmap-update.])
fi
CPPFLAGS="$CPPFLAGS $($apr_config --cppflags --includes)"
LIBS="$LIBS $($apr_config --link-ld)"

AC_ARG_WITH(subversion,
AC_HELP_STRING([--with-subversion=DIR], [Look for libsvn1 in DIR/include and DIR/libs.]),
[
case "$with_subversion" in
  yes)
    ;;
  no)
    AC_MSG_ERROR([Subversion and libsvn1 are required to build nmap-update.])
    ;;
  *)
    CPPFLAGS="-I$with_subversion/include $CPPFLAGS"
    LDFLAGS="-L$with_subversion/lib $LDFLAGS"
    ;;
  esac
])

# Checks for libraries.
AC_CHECK_LIB([svn_client-1], [svn_client_create_context])
AC_CHECK_LIB([svn_subr-1], [svn_handle_error2])
AC_CHECK_LIB([apr-1], [apr_pool_destroy])

# Checks for header files.
AC_CHECK_HEADERS([svn_client.h subversion-1/svn_client.h])

# Checks for typedefs, structures, and compiler characteristics.
# AC_TYPE_SIZE_T

# Checks for library functions.
# AC_CHECK_FUNCS([mkdir strerror strtoul])

AC_OUTPUT(Makefile)
