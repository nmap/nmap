# generated automatically by aclocal 1.16.5 -*- Autoconf -*-

# Copyright (C) 1996-2021 Free Software Foundation, Inc.

# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.

m4_ifndef([AC_CONFIG_MACRO_DIRS], [m4_defun([_AM_CONFIG_MACRO_DIRS], [])m4_defun([AC_CONFIG_MACRO_DIRS], [_AM_CONFIG_MACRO_DIRS($@)])])
# Copyright (C) 1999-2021 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.


# AM_PATH_PYTHON([MINIMUM-VERSION], [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
# ---------------------------------------------------------------------------
# Adds support for distributing Python modules and packages.  To
# install modules, copy them to $(pythondir), using the python_PYTHON
# automake variable.  To install a package with the same name as the
# automake package, install to $(pkgpythondir), or use the
# pkgpython_PYTHON automake variable.
#
# The variables $(pyexecdir) and $(pkgpyexecdir) are provided as
# locations to install python extension modules (shared libraries).
# Another macro is required to find the appropriate flags to compile
# extension modules.
#
# If your package is configured with a different prefix to python,
# users will have to add the install directory to the PYTHONPATH
# environment variable, or create a .pth file (see the python
# documentation for details).
#
# If the MINIMUM-VERSION argument is passed, AM_PATH_PYTHON will
# cause an error if the version of python installed on the system
# doesn't meet the requirement.  MINIMUM-VERSION should consist of
# numbers and dots only.
AC_DEFUN([AM_PATH_PYTHON],
 [
  dnl Find a Python interpreter.  Python versions prior to 2.0 are not
  dnl supported. (2.0 was released on October 16, 2000).
  m4_define_default([_AM_PYTHON_INTERPRETER_LIST],
[python python2 python3 dnl
 python3.9 python3.8 python3.7 python3.6 python3.5 python3.4 python3.3 dnl
 python3.2 python3.1 python3.0 dnl
 python2.7 python2.6 python2.5 python2.4 python2.3 python2.2 python2.1 dnl
 python2.0])

  AC_ARG_VAR([PYTHON], [the Python interpreter])

  m4_if([$1],[],[
    dnl No version check is needed.
    # Find any Python interpreter.
    if test -z "$PYTHON"; then
      AC_PATH_PROGS([PYTHON], _AM_PYTHON_INTERPRETER_LIST, :)
    fi
    am_display_PYTHON=python
  ], [
    dnl A version check is needed.
    if test -n "$PYTHON"; then
      # If the user set $PYTHON, use it and don't search something else.
      AC_MSG_CHECKING([whether $PYTHON version is >= $1])
      AM_PYTHON_CHECK_VERSION([$PYTHON], [$1],
			      [AC_MSG_RESULT([yes])],
			      [AC_MSG_RESULT([no])
			       AC_MSG_ERROR([Python interpreter is too old])])
      am_display_PYTHON=$PYTHON
    else
      # Otherwise, try each interpreter until we find one that satisfies
      # VERSION.
      AC_CACHE_CHECK([for a Python interpreter with version >= $1],
	[am_cv_pathless_PYTHON],[
	for am_cv_pathless_PYTHON in _AM_PYTHON_INTERPRETER_LIST none; do
	  test "$am_cv_pathless_PYTHON" = none && break
	  AM_PYTHON_CHECK_VERSION([$am_cv_pathless_PYTHON], [$1], [break])
	done])
      # Set $PYTHON to the absolute path of $am_cv_pathless_PYTHON.
      if test "$am_cv_pathless_PYTHON" = none; then
	PYTHON=:
      else
        AC_PATH_PROG([PYTHON], [$am_cv_pathless_PYTHON])
      fi
      am_display_PYTHON=$am_cv_pathless_PYTHON
    fi
  ])

  if test "$PYTHON" = :; then
    dnl Run any user-specified action, or abort.
    m4_default([$3], [AC_MSG_ERROR([no suitable Python interpreter found])])
  else

  dnl Query Python for its version number.  Although site.py simply uses
  dnl sys.version[:3], printing that failed with Python 3.10, since the
  dnl trailing zero was eliminated. So now we output just the major
  dnl and minor version numbers, as numbers. Apparently the tertiary
  dnl version is not of interest.
  dnl
  AC_CACHE_CHECK([for $am_display_PYTHON version], [am_cv_python_version],
    [am_cv_python_version=`$PYTHON -c "import sys; print ('%u.%u' % sys.version_info[[:2]])"`])
  AC_SUBST([PYTHON_VERSION], [$am_cv_python_version])

  dnl At times, e.g., when building shared libraries, you may want
  dnl to know which OS platform Python thinks this is.
  dnl
  AC_CACHE_CHECK([for $am_display_PYTHON platform], [am_cv_python_platform],
    [am_cv_python_platform=`$PYTHON -c "import sys; sys.stdout.write(sys.platform)"`])
  AC_SUBST([PYTHON_PLATFORM], [$am_cv_python_platform])

  dnl emacs-page
  dnl If --with-python-sys-prefix is given, use the values of sys.prefix
  dnl and sys.exec_prefix for the corresponding values of PYTHON_PREFIX
  dnl and PYTHON_EXEC_PREFIX. Otherwise, use the GNU ${prefix} and
  dnl ${exec_prefix} variables.
  dnl
  dnl The two are made distinct variables so they can be overridden if
  dnl need be, although general consensus is that you shouldn't need
  dnl this separation.
  dnl
  dnl Also allow directly setting the prefixes via configure options,
  dnl overriding any default.
  dnl
  if test "x$prefix" = xNONE; then
    am__usable_prefix=$ac_default_prefix
  else
    am__usable_prefix=$prefix
  fi

  # Allow user to request using sys.* values from Python,
  # instead of the GNU $prefix values.
  AC_ARG_WITH([python-sys-prefix],
  [AS_HELP_STRING([--with-python-sys-prefix],
                  [use Python's sys.prefix and sys.exec_prefix values])],
  [am_use_python_sys=:],
  [am_use_python_sys=false])

  # Allow user to override whatever the default Python prefix is.
  AC_ARG_WITH([python_prefix],
  [AS_HELP_STRING([--with-python_prefix],
                  [override the default PYTHON_PREFIX])],
  [am_python_prefix_subst=$withval
   am_cv_python_prefix=$withval
   AC_MSG_CHECKING([for explicit $am_display_PYTHON prefix])
   AC_MSG_RESULT([$am_cv_python_prefix])],
  [
   if $am_use_python_sys; then
     # using python sys.prefix value, not GNU
     AC_CACHE_CHECK([for python default $am_display_PYTHON prefix],
     [am_cv_python_prefix],
     [am_cv_python_prefix=`$PYTHON -c "import sys; sys.stdout.write(sys.prefix)"`])

     dnl If sys.prefix is a subdir of $prefix, replace the literal value of
     dnl $prefix with a variable reference so it can be overridden.
     case $am_cv_python_prefix in
     $am__usable_prefix*)
       am__strip_prefix=`echo "$am__usable_prefix" | sed 's|.|.|g'`
       am_python_prefix_subst=`echo "$am_cv_python_prefix" | sed "s,^$am__strip_prefix,\\${prefix},"`
       ;;
     *)
       am_python_prefix_subst=$am_cv_python_prefix
       ;;
     esac
   else # using GNU prefix value, not python sys.prefix
     am_python_prefix_subst='${prefix}'
     am_python_prefix=$am_python_prefix_subst
     AC_MSG_CHECKING([for GNU default $am_display_PYTHON prefix])
     AC_MSG_RESULT([$am_python_prefix])
   fi])
  # Substituting python_prefix_subst value.
  AC_SUBST([PYTHON_PREFIX], [$am_python_prefix_subst])

  # emacs-page Now do it all over again for Python exec_prefix, but with yet
  # another conditional: fall back to regular prefix if that was specified.
  AC_ARG_WITH([python_exec_prefix],
  [AS_HELP_STRING([--with-python_exec_prefix],
                  [override the default PYTHON_EXEC_PREFIX])],
  [am_python_exec_prefix_subst=$withval
   am_cv_python_exec_prefix=$withval
   AC_MSG_CHECKING([for explicit $am_display_PYTHON exec_prefix])
   AC_MSG_RESULT([$am_cv_python_exec_prefix])],
  [
   # no explicit --with-python_exec_prefix, but if
   # --with-python_prefix was given, use its value for python_exec_prefix too.
   AS_IF([test -n "$with_python_prefix"],
   [am_python_exec_prefix_subst=$with_python_prefix
    am_cv_python_exec_prefix=$with_python_prefix
    AC_MSG_CHECKING([for python_prefix-given $am_display_PYTHON exec_prefix])
    AC_MSG_RESULT([$am_cv_python_exec_prefix])],
   [
    # Set am__usable_exec_prefix whether using GNU or Python values,
    # since we use that variable for pyexecdir.
    if test "x$exec_prefix" = xNONE; then
      am__usable_exec_prefix=$am__usable_prefix
    else
      am__usable_exec_prefix=$exec_prefix
    fi
    #
    if $am_use_python_sys; then # using python sys.exec_prefix, not GNU
      AC_CACHE_CHECK([for python default $am_display_PYTHON exec_prefix],
      [am_cv_python_exec_prefix],
      [am_cv_python_exec_prefix=`$PYTHON -c "import sys; sys.stdout.write(sys.exec_prefix)"`])
      dnl If sys.exec_prefix is a subdir of $exec_prefix, replace the
      dnl literal value of $exec_prefix with a variable reference so it can
      dnl be overridden.
      case $am_cv_python_exec_prefix in
      $am__usable_exec_prefix*)
        am__strip_prefix=`echo "$am__usable_exec_prefix" | sed 's|.|.|g'`
        am_python_exec_prefix_subst=`echo "$am_cv_python_exec_prefix" | sed "s,^$am__strip_prefix,\\${exec_prefix},"`
        ;;
      *)
        am_python_exec_prefix_subst=$am_cv_python_exec_prefix
        ;;
     esac
   else # using GNU $exec_prefix, not python sys.exec_prefix
     am_python_exec_prefix_subst='${exec_prefix}'
     am_python_exec_prefix=$am_python_exec_prefix_subst
     AC_MSG_CHECKING([for GNU default $am_display_PYTHON exec_prefix])
     AC_MSG_RESULT([$am_python_exec_prefix])
   fi])])
  # Substituting python_exec_prefix_subst.
  AC_SUBST([PYTHON_EXEC_PREFIX], [$am_python_exec_prefix_subst])

  # Factor out some code duplication into this shell variable.
  am_python_setup_sysconfig="\
import sys
# Prefer sysconfig over distutils.sysconfig, for better compatibility
# with python 3.x.  See automake bug#10227.
try:
    import sysconfig
except ImportError:
    can_use_sysconfig = 0
else:
    can_use_sysconfig = 1
# Can't use sysconfig in CPython 2.7, since it's broken in virtualenvs:
# <https://github.com/pypa/virtualenv/issues/118>
try:
    from platform import python_implementation
    if python_implementation() == 'CPython' and sys.version[[:3]] == '2.7':
        can_use_sysconfig = 0
except ImportError:
    pass"

  dnl emacs-page Set up 4 directories:

  dnl 1. pythondir: where to install python scripts.  This is the
  dnl    site-packages directory, not the python standard library
  dnl    directory like in previous automake betas.  This behavior
  dnl    is more consistent with lispdir.m4 for example.
  dnl Query distutils for this directory.
  dnl
  AC_CACHE_CHECK([for $am_display_PYTHON script directory (pythondir)],
  [am_cv_python_pythondir],
  [if test "x$am_cv_python_prefix" = x; then
     am_py_prefix=$am__usable_prefix
   else
     am_py_prefix=$am_cv_python_prefix
   fi
   am_cv_python_pythondir=`$PYTHON -c "
$am_python_setup_sysconfig
if can_use_sysconfig:
  sitedir = sysconfig.get_path('purelib', vars={'base':'$am_py_prefix'})
else:
  from distutils import sysconfig
  sitedir = sysconfig.get_python_lib(0, 0, prefix='$am_py_prefix')
sys.stdout.write(sitedir)"`
   #
   case $am_cv_python_pythondir in
   $am_py_prefix*)
     am__strip_prefix=`echo "$am_py_prefix" | sed 's|.|.|g'`
     am_cv_python_pythondir=`echo "$am_cv_python_pythondir" | sed "s,^$am__strip_prefix,\\${PYTHON_PREFIX},"`
     ;;
   *)
     case $am_py_prefix in
       /usr|/System*) ;;
       *) am_cv_python_pythondir="\${PYTHON_PREFIX}/lib/python$PYTHON_VERSION/site-packages"
          ;;
     esac
     ;;
   esac
  ])
  AC_SUBST([pythondir], [$am_cv_python_pythondir])

  dnl 2. pkgpythondir: $PACKAGE directory under pythondir.  Was
  dnl    PYTHON_SITE_PACKAGE in previous betas, but this naming is
  dnl    more consistent with the rest of automake.
  dnl
  AC_SUBST([pkgpythondir], [\${pythondir}/$PACKAGE])

  dnl 3. pyexecdir: directory for installing python extension modules
  dnl    (shared libraries).
  dnl Query distutils for this directory.
  dnl
  AC_CACHE_CHECK([for $am_display_PYTHON extension module directory (pyexecdir)],
  [am_cv_python_pyexecdir],
  [if test "x$am_cv_python_exec_prefix" = x; then
     am_py_exec_prefix=$am__usable_exec_prefix
   else
     am_py_exec_prefix=$am_cv_python_exec_prefix
   fi
   am_cv_python_pyexecdir=`$PYTHON -c "
$am_python_setup_sysconfig
if can_use_sysconfig:
  sitedir = sysconfig.get_path('platlib', vars={'platbase':'$am_py_exec_prefix'})
else:
  from distutils import sysconfig
  sitedir = sysconfig.get_python_lib(1, 0, prefix='$am_py_exec_prefix')
sys.stdout.write(sitedir)"`
   #
   case $am_cv_python_pyexecdir in
   $am_py_exec_prefix*)
     am__strip_prefix=`echo "$am_py_exec_prefix" | sed 's|.|.|g'`
     am_cv_python_pyexecdir=`echo "$am_cv_python_pyexecdir" | sed "s,^$am__strip_prefix,\\${PYTHON_EXEC_PREFIX},"`
     ;;
   *)
     case $am_py_exec_prefix in
       /usr|/System*) ;;
       *) am_cv_python_pyexecdir="\${PYTHON_EXEC_PREFIX}/lib/python$PYTHON_VERSION/site-packages"
          ;;
     esac
     ;;
   esac
  ])
  AC_SUBST([pyexecdir], [$am_cv_python_pyexecdir])

  dnl 4. pkgpyexecdir: $(pyexecdir)/$(PACKAGE)
  dnl
  AC_SUBST([pkgpyexecdir], [\${pyexecdir}/$PACKAGE])

  dnl Run any user-specified action.
  $2
  fi
])


# AM_PYTHON_CHECK_VERSION(PROG, VERSION, [ACTION-IF-TRUE], [ACTION-IF-FALSE])
# ---------------------------------------------------------------------------
# Run ACTION-IF-TRUE if the Python interpreter PROG has version >= VERSION.
# Run ACTION-IF-FALSE otherwise.
# This test uses sys.hexversion instead of the string equivalent (first
# word of sys.version), in order to cope with versions such as 2.2c1.
# This supports Python 2.0 or higher. (2.0 was released on October 16, 2000).
AC_DEFUN([AM_PYTHON_CHECK_VERSION],
 [prog="import sys
# split strings by '.' and convert to numeric.  Append some zeros
# because we need at least 4 digits for the hex conversion.
# map returns an iterator in Python 3.0 and a list in 2.x
minver = list(map(int, '$2'.split('.'))) + [[0, 0, 0]]
minverhex = 0
# xrange is not present in Python 3.0 and range returns an iterator
for i in list(range(0, 4)): minverhex = (minverhex << 8) + minver[[i]]
sys.exit(sys.hexversion < minverhex)"
  AS_IF([AM_RUN_LOG([$1 -c "$prog"])], [$3], [$4])])

# Copyright (C) 2001-2021 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# AM_RUN_LOG(COMMAND)
# -------------------
# Run COMMAND, save the exit status in ac_status, and log it.
# (This has been adapted from Autoconf's _AC_RUN_LOG macro.)
AC_DEFUN([AM_RUN_LOG],
[{ echo "$as_me:$LINENO: $1" >&AS_MESSAGE_LOG_FD
   ($1) >&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD
   ac_status=$?
   echo "$as_me:$LINENO: \$? = $ac_status" >&AS_MESSAGE_LOG_FD
   (exit $ac_status); }])

m4_include([m4/ax_check_compile_flag.m4])
m4_include([m4/nls.m4])
m4_include([acinclude.m4])
