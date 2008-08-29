AC_PREREQ([2.13])
AC_INIT([nselib], [0.0])

AC_PROG_CC

# we want to compile lua modules written in C - which are shared libraries
# therefore disable building static libs - we shouldn't need them
AC_DISABLE_STATIC
AC_LIBTOOL_DLOPEN
AC_PROG_LIBTOOL
AC_SUBST([LIBTOOL])

AC_SUBST([LIBTOOL_DEPS])

AC_CANONICAL_HOST

# Don't bother with --without-liblua because this directory isn't even
# configured if that's the case.
AC_ARG_WITH([liblua],
AC_HELP_STRING([--with-liblua=DIR], [Use an existing (compiled) lua lib from DIR/include and DIR/lib.])
AC_HELP_STRING([--with-liblua=included], [Use the liblua version included with Nmap]),
[ case "$with_liblua" in
  yes)
    with_liblua=
  ;;
  included)
    with_liblua=../liblua
  ;;
  *)
  ;;
esac ]
)

# If no liblua location was given search for one.
if test "x$with_liblua" = "x"; then
  AC_CHECK_HEADER([lua.h], 
    AC_CHECK_LIB([lua], [lua_call], [system_liblua=yes]))
  # If none was found use the included liblua.
  if test "$system_liblua" != "yes"; then
    with_liblua=../liblua
  fi
fi

if test "x$with_liblua" != "x"; then
  CPPFLAGS="-I$with_liblua $CPPFLAGS"
  LDFLAGS="-L$with_liblua $LDFLAGS"
fi

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
