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

# needed for lua-includes
AC_CHECK_HEADER([lua.h],,[AC_MSG_NOTICE(using lua-includefiles provided with nmap);[LUAINCLUDE=-I../liblua/]],)
AC_SUBST(LUAINCLUDE)

#needed for pcre - libpcre and nbase
AC_ARG_WITH(libnbase,
AC_HELP_STRING([--with-libnbase=DIR], [Look for nbase include/libs in DIR]),
[  case "$with_libnbase" in
  yes)
    ;;
  *)
    NBASEDIR="$with_libnbase"
    ;;
  esac],
NBASEDIR="../nbase"
)


NBASE_INCLUDE="-I$NBASEDIR"
NBASE_LD="-L$NBASEDIR"
NBASE_LIBS="-lnbase"

AC_SUBST(NBASE_LIBS)
AC_SUBST(NBASE_LD)
AC_SUBST(NBASE_INCLUDE)

# First we test whether they specified libpcre explicitly
AC_ARG_WITH(libpcre,
AC_HELP_STRING([--with-libpcre=DIR], [Use an existing (compiled) pcre lib from DIR/include and DIR/lib.])
AC_HELP_STRING([--with-libpcre=included], [Always use the version included with Nmap]),
[  case "$with_libpcre" in
  yes)
    ;;
  included)
	PCREDIR="../libpcre"
    ;;
  *)
    PCREDIR="$with_libpcre"
    ;;
  esac], 
PCREDIR="../libpcre"
)
PCRE_INCLUDE="-I$PCREDIR"
PCRE_LD="-L$PCREDIR"
PCRE_LIBS="-lpcre"

# AC_SUBST(PCREDIR)
AC_SUBST(PCRE_INCLUDE)
AC_SUBST(PCRE_LD)
AC_SUBST(PCRE_LIBS)


AC_CONFIG_FILES([Makefile])
AC_OUTPUT

