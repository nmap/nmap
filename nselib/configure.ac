AC_PREREQ(2.13)
AC_INIT([nselib.h])

AC_PROG_CC

# we want to compile lua modules written in C - which are shared libraries
# therefore disable building static libs - we shouldn't need them
AC_DISABLE_STATIC
AC_LIBTOOL_DLOPEN
AC_PROG_LIBTOOL
AC_SUBST(LIBTOOL)

AC_SUBST(LIBTOOL_DEPS)

AC_CANONICAL_HOST

# needed for lua-includes
AC_CHECK_HEADER([lua.h],,[AC_MSG_NOTICE(using lua-includefiles provided with nmap);[LUAINCLUDE=-I../liblua/]],)
AC_SUBST(LUAINCLUDE)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

