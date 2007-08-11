AC_PREREQ(2.13)
AC_INIT([nselib.h])
AC_CONFIG_AUX_DIR([.])

AC_PROG_CC

# we want to compile lua modules written in C - which are shared libraries
# therefore disable building static libs - we shouldn't need them
AC_DISABLE_STATIC
AC_LIBTOOL_DLOPEN
AC_PROG_LIBTOOL
AC_SUBST(LIBTOOL)

AC_SUBST(LIBTOOL_DEPS)

AC_CANONICAL_HOST


AC_CONFIG_FILES([Makefile])
AC_OUTPUT

