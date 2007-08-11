AC_PREREQ(2.13)
AC_INIT([nselib.h])
AC_CONFIG_AUX_DIR([.])

AC_PROG_CC

# we want to compile lua modules written in C - which are shared libraries
# therefore disable building static libs - we shouldn't need them
AC_DISABLE_STATIC
AC_PROG_LIBTOOL
AC_SUBST(LIBTOOL)

AC_SUBST(LIBTOOL_DEPS)

AC_CANONICAL_HOST

case "$host" in
	*-freebsd* | *-kfreebsd*-gnu | *-dragonfly*)
		LIBSUFFIX=.so.0
		;;
	*bsd*) # need to verify this
		LIBSUFFIX=.so.0
		;;
	*-linux*)
		LIBSUFFIX=.so.0.0.0
		;;
	*-apple-darwin*) # need to verify this
		LIBSUFFIX=.bundle
		;;
	*) # maybe this will work
		LIBSUFFIX=.so
		;;
esac

AC_SUBST(LIBSUFFIX)

AC_HEADER_STDC

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

