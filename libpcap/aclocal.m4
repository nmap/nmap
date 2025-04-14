dnl Copyright (c) 1995, 1996, 1997, 1998
dnl	The Regents of the University of California.  All rights reserved.
dnl
dnl Redistribution and use in source and binary forms, with or without
dnl modification, are permitted provided that: (1) source code distributions
dnl retain the above copyright notice and this paragraph in its entirety, (2)
dnl distributions including binary code include the above copyright notice and
dnl this paragraph in its entirety in the documentation or other materials
dnl provided with the distribution, and (3) all advertising materials mentioning
dnl features or use of this software display the following acknowledgement:
dnl ``This product includes software developed by the University of California,
dnl Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
dnl the University nor the names of its contributors may be used to endorse
dnl or promote products derived from this software without specific prior
dnl written permission.
dnl THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
dnl WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
dnl MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
dnl
dnl LBL autoconf macros
dnl

dnl
dnl Do whatever AC_LBL_C_INIT work is necessary before using AC_PROG_CC.
dnl
dnl It appears that newer versions of autoconf (2.64 and later) will,
dnl if you use AC_TRY_COMPILE in a macro, stick AC_PROG_CC at the
dnl beginning of the macro, even if the macro itself calls AC_PROG_CC.
dnl See the "Prerequisite Macros" and "Expanded Before Required" sections
dnl in the Autoconf documentation.
dnl
dnl This causes a steaming heap of fail in our case, as we were, in
dnl AC_LBL_C_INIT, doing the tests we now do in AC_LBL_C_INIT_BEFORE_CC,
dnl calling AC_PROG_CC, and then doing the tests we now do in
dnl AC_LBL_C_INIT.  Now, we run AC_LBL_C_INIT_BEFORE_CC, AC_PROG_CC,
dnl and AC_LBL_C_INIT at the top level.
dnl
AC_DEFUN(AC_LBL_C_INIT_BEFORE_CC,
[
    AC_BEFORE([$0], [AC_LBL_C_INIT])
    AC_BEFORE([$0], [AC_PROG_CC])
    AC_BEFORE([$0], [AC_LBL_FIXINCLUDES])
    AC_BEFORE([$0], [AC_LBL_DEVEL])
    AC_ARG_WITH(gcc, [  --without-gcc           don't use gcc])
    $1=""
    if test "${srcdir}" != "." ; then
	    $1="-I\$(srcdir)"
    fi
    if test "${CFLAGS+set}" = set; then
	    LBL_CFLAGS="$CFLAGS"
    fi
    if test -z "$CC" ; then
	    case "$host_os" in

	    bsdi*)
		    AC_CHECK_PROG(SHLICC2, shlicc2, yes, no)
		    if test $SHLICC2 = yes ; then
			    CC=shlicc2
			    export CC
		    fi
		    ;;
	    esac
    fi
    if test -z "$CC" -a "$with_gcc" = no ; then
	    CC=cc
	    export CC
    fi
])

dnl
dnl Determine which compiler we're using (cc or gcc)
dnl If using gcc, determine the version number
dnl If using cc:
dnl     require that it support ansi prototypes
dnl     use -O (AC_PROG_CC will use -g -O2 on gcc, so we don't need to
dnl     do that ourselves for gcc)
dnl     add -g flags, as appropriate
dnl     explicitly specify /usr/local/include
dnl
dnl NOTE WELL: with newer versions of autoconf, "gcc" means any compiler
dnl that defines __GNUC__, which means clang, for example, counts as "gcc".
dnl
dnl usage:
dnl
dnl	AC_LBL_C_INIT(copt, incls)
dnl
dnl results:
dnl
dnl	$1 (copt set)
dnl	$2 (incls set)
dnl	CC
dnl	LDFLAGS
dnl	LBL_CFLAGS
dnl
AC_DEFUN(AC_LBL_C_INIT,
[
    AC_BEFORE([$0], [AC_LBL_FIXINCLUDES])
    AC_BEFORE([$0], [AC_LBL_DEVEL])
    AC_BEFORE([$0], [AC_LBL_SHLIBS_INIT])
    if test "$GCC" = yes ; then
	    #
	    # -Werror forces warnings to be errors.
	    #
	    ac_lbl_cc_force_warning_errors=-Werror

	    #
	    # Try to have the compiler default to hiding symbols,
	    # so that only symbols explicitly exported with
	    # PCAP_API will be visible outside (shared) libraries.
	    #
	    AC_LBL_CHECK_COMPILER_OPT($1, -fvisibility=hidden)
    else
	    $2="$$2 -I/usr/local/include"
	    LDFLAGS="$LDFLAGS -L/usr/local/lib"

	    case "$host_os" in

	    darwin*)
		    #
		    # This is assumed either to be GCC or clang, both
		    # of which use -Werror to force warnings to be errors.
		    #
		    ac_lbl_cc_force_warning_errors=-Werror

		    #
		    # Try to have the compiler default to hiding symbols,
		    # so that only symbols explicitly exported with
		    # PCAP_API will be visible outside (shared) libraries.
		    #
		    AC_LBL_CHECK_COMPILER_OPT($1, -fvisibility=hidden)
		    ;;

	    hpux*)
		    #
		    # HP C, which is what we presume we're using, doesn't
		    # exit with a non-zero exit status if we hand it an
		    # invalid -W flag, can't be forced to do so even with
		    # +We, and doesn't handle GCC-style -W flags, so we
		    # don't want to try using GCC-style -W flags.
		    #
		    ac_lbl_cc_dont_try_gcc_dashW=yes
		    ;;

	    irix*)
		    #
		    # MIPS C, which is what we presume we're using, doesn't
		    # necessarily exit with a non-zero exit status if we
		    # hand it an invalid -W flag, can't be forced to do
		    # so, and doesn't handle GCC-style -W flags, so we
		    # don't want to try using GCC-style -W flags.
		    #
		    ac_lbl_cc_dont_try_gcc_dashW=yes
		    #
		    # It also, apparently, defaults to "char" being
		    # unsigned, unlike most other C implementations;
		    # I suppose we could say "signed char" whenever
		    # we want to guarantee a signed "char", but let's
		    # just force signed chars.
		    #
		    # -xansi is normally the default, but the
		    # configure script was setting it; perhaps -cckr
		    # was the default in the Old Days.  (Then again,
		    # that would probably be for backwards compatibility
		    # in the days when ANSI C was Shiny and New, i.e.
		    # 1989 and the early '90's, so maybe we can just
		    # drop support for those compilers.)
		    #
		    # -g is equivalent to -g2, which turns off
		    # optimization; we choose -g3, which generates
		    # debugging information but doesn't turn off
		    # optimization (even if the optimization would
		    # cause inaccuracies in debugging).
		    #
		    $1="$$1 -xansi -signed -g3"
		    ;;

	    osf*)
		    #
		    # Presumed to be DEC OSF/1, Digital UNIX, or
		    # Tru64 UNIX.
		    #
		    # The DEC C compiler, which is what we presume we're
		    # using, doesn't exit with a non-zero exit status if we
		    # hand it an invalid -W flag, can't be forced to do
		    # so, and doesn't handle GCC-style -W flags, so we
		    # don't want to try using GCC-style -W flags.
		    #
		    ac_lbl_cc_dont_try_gcc_dashW=yes
		    #
		    # -g is equivalent to -g2, which turns off
		    # optimization; we choose -g3, which generates
		    # debugging information but doesn't turn off
		    # optimization (even if the optimization would
		    # cause inaccuracies in debugging).
		    #
		    $1="$$1 -g3"
		    ;;

	    solaris*)
		    #
		    # Assumed to be Sun C, which requires -errwarn to force
		    # warnings to be treated as errors.
		    #
		    ac_lbl_cc_force_warning_errors=-errwarn

		    #
		    # Try to have the compiler default to hiding symbols,
		    # so that only symbols explicitly exported with
		    # PCAP_API will be visible outside (shared) libraries.
		    #
		    AC_LBL_CHECK_COMPILER_OPT($1, -xldscope=hidden)
		    ;;

	    ultrix*)
		    AC_MSG_CHECKING(that Ultrix $CC hacks const in prototypes)
		    AC_CACHE_VAL(ac_cv_lbl_cc_const_proto,
			AC_TRY_COMPILE(
			    [#include <sys/types.h>],
			    [struct a { int b; };
			    void c(const struct a *)],
			    ac_cv_lbl_cc_const_proto=yes,
			    ac_cv_lbl_cc_const_proto=no))
		    AC_MSG_RESULT($ac_cv_lbl_cc_const_proto)
		    if test $ac_cv_lbl_cc_const_proto = no ; then
			    AC_DEFINE(const,[],
			        [to handle Ultrix compilers that don't support const in prototypes])
		    fi
		    ;;
	    esac
	    $1="$$1 -O"
    fi
])

dnl
dnl Save the values of various variables that affect compilation and
dnl linking, and that we don't ourselves modify persistently; done
dnl before a test involving compiling or linking is done, so that we
dnl can restore those variables after the test is done.
dnl
AC_DEFUN(AC_LBL_SAVE_CHECK_STATE,
[
	save_CFLAGS="$CFLAGS"
	save_LIBS="$LIBS"
	save_LDFLAGS="$LDFLAGS"
])

dnl
dnl Restore the values of variables saved by AC_LBL_SAVE_CHECK_STATE.
dnl
AC_DEFUN(AC_LBL_RESTORE_CHECK_STATE,
[
	CFLAGS="$save_CFLAGS"
	LIBS="$save_LIBS"
	LDFLAGS="$save_LDFLAGS"
])

dnl
dnl Check whether the compiler option specified as the second argument
dnl is supported by the compiler and, if so, add it to the macro
dnl specified as the first argument
dnl
dnl If a third argument is supplied, treat it as C code to be compiled
dnl with the flag in question, and the "treat warnings as errors" flag
dnl set, and don't add the flag to the first argument if the compile
dnl fails; this is for warning options cause problems that can't be
dnl worked around.  If a third argument is supplied, a fourth argument
dnl should also be supplied; it's a message describing what the test
dnl program is checking.
dnl
AC_DEFUN(AC_LBL_CHECK_COMPILER_OPT,
    [
	AC_MSG_CHECKING([whether the compiler supports the $2 option])
	save_CFLAGS="$CFLAGS"
	CFLAGS="$CFLAGS $2"
	#
	# XXX - yes, this depends on the way AC_LANG_WERROR works,
	# but no mechanism is provided to turn AC_LANG_WERROR on
	# *and then turn it back off*, so that we *only* do it when
	# testing compiler options - 15 years after somebody asked
	# for it:
	#
	#     https://autoconf.gnu.narkive.com/gTAVmfKD/how-to-cancel-flags-set-by-ac-lang-werror
	#
	save_ac_c_werror_flag="$ac_c_werror_flag"
	ac_c_werror_flag=yes
	#
	# We use AC_LANG_SOURCE() so that we can control the complete
	# content of the program being compiled.  We do not, for example,
	# want the default "int main()" that AC_LANG_PROGRAM() generates,
	# as it will generate a warning with -Wold-style-definition, meaning
	# that we would treat it as not working, as the test will fail if
	# *any* error output, including a warning due to the flag we're
	# testing, is generated; see
	#
	#    https://www.postgresql.org/message-id/2192993.1591682589%40sss.pgh.pa.us
	#    https://www.postgresql.org/message-id/2192993.1591682589%40sss.pgh.pa.us
	#
	# This may, as per those two messages, be fixed in autoconf 2.70,
	# but we only require 2.69 or newer for now.
	#
	AC_COMPILE_IFELSE(
	    [AC_LANG_SOURCE([[int main(void) { return 0; }]])],
	    [
		AC_MSG_RESULT([yes])
		can_add_to_cflags=yes
		#
		# The compile supports this; do we have some C code for
		# which the warning should *not* appear?
		# We test the fourth argument because the third argument
		# could contain quotes, breaking the test.
		#
		if test "x$4" != "x"
		then
		    CFLAGS="$CFLAGS $ac_lbl_cc_force_warning_errors"
		    AC_MSG_CHECKING(whether $2 $4)
		    AC_COMPILE_IFELSE(
		      [AC_LANG_SOURCE($3)],
		      [
			#
			# Not a problem.
			#
			AC_MSG_RESULT(no)
		      ],
		      [
			#
			# A problem.
			#
			AC_MSG_RESULT(yes)
			can_add_to_cflags=no
		      ])
		fi
		CFLAGS="$save_CFLAGS"
		if test x"$can_add_to_cflags" = "xyes"
		then
		    $1="$$1 $2"
		fi
	    ],
	    [
		AC_MSG_RESULT([no])
		CFLAGS="$save_CFLAGS"
	    ])
	ac_c_werror_flag="$save_ac_c_werror_flag"
    ])

dnl
dnl Check whether the compiler supports an option to generate
dnl Makefile-style dependency lines
dnl
dnl GCC uses -M for this.  Non-GCC compilers that support this
dnl use a variety of flags, including but not limited to -M.
dnl
dnl We test whether the flag in question is supported, as older
dnl versions of compilers might not support it.
dnl
dnl We don't try all the possible flags, just in case some flag means
dnl "generate dependencies" on one compiler but means something else
dnl on another compiler.
dnl
dnl Most compilers that support this send the output to the standard
dnl output by default.  IBM's XLC, however, supports -M but sends
dnl the output to {sourcefile-basename}.u, and AIX has no /dev/stdout
dnl to work around that, so we don't bother with XLC.
dnl
AC_DEFUN(AC_LBL_CHECK_DEPENDENCY_GENERATION_OPT,
    [
	AC_MSG_CHECKING([whether the compiler supports generating dependencies])
	if test "$GCC" = yes ; then
		#
		# GCC, or a compiler deemed to be GCC by AC_PROG_CC (even
		# though it's not); we assume that, in this case, the flag
		# would be -M.
		#
		ac_lbl_dependency_flag="-M"
	else
		#
		# Not GCC or a compiler deemed to be GCC; what platform is
		# this?  (We're assuming that if the compiler isn't GCC
		# it's the compiler from the vendor of the OS; that won't
		# necessarily be true for x86 platforms, where it might be
		# the Intel C compiler.)
		#
		case "$host_os" in

		irix*|osf*|darwin*)
			#
			# MIPS C for IRIX, DEC C, and clang all use -M.
			#
			ac_lbl_dependency_flag="-M"
			;;

		solaris*)
			#
			# Sun C uses -xM.
			#
			ac_lbl_dependency_flag="-xM"
			;;

		hpux*)
			#
			# HP's older C compilers don't support this.
			# HP's newer C compilers support this with
			# either +M or +Make; the older compilers
			# interpret +M as something completely
			# different, so we use +Make so we don't
			# think it works with the older compilers.
			#
			ac_lbl_dependency_flag="+Make"
			;;

		*)
			#
			# Not one of the above; assume no support for
			# generating dependencies.
			#
			ac_lbl_dependency_flag=""
			;;
		esac
	fi

	#
	# Is ac_lbl_dependency_flag defined and, if so, does the compiler
	# complain about it?
	#
	# Note: clang doesn't seem to exit with an error status when handed
	# an unknown non-warning error, even if you pass it
	# -Werror=unknown-warning-option.  However, it always supports
	# -M, so the fact that this test always succeeds with clang
	# isn't an issue.
	#
	if test ! -z "$ac_lbl_dependency_flag"; then
		AC_LANG_CONFTEST(
		    [AC_LANG_SOURCE([[int main(void) { return 0; }]])])
		if AC_RUN_LOG([eval "$CC $ac_lbl_dependency_flag conftest.c >/dev/null 2>&1"]); then
			AC_MSG_RESULT([yes, with $ac_lbl_dependency_flag])
			DEPENDENCY_CFLAG="$ac_lbl_dependency_flag"
			MKDEP='${top_srcdir}/mkdep'
		else
			AC_MSG_RESULT([no])
			#
			# We can't run mkdep, so have "make depend" do
			# nothing.
			#
			MKDEP='${top_srcdir}/nomkdep'
		fi
		rm -rf conftest*
	else
		AC_MSG_RESULT([no])
		#
		# We can't run mkdep, so have "make depend" do
		# nothing.
		#
		MKDEP='${top_srcdir}/nomkdep'
	fi
	AC_SUBST(DEPENDENCY_CFLAG)
	AC_SUBST(MKDEP)
    ])

dnl
dnl Determine what options are needed to build a shared library
dnl
dnl usage:
dnl
dnl	AC_LBL_SHLIBS_INIT
dnl
dnl results:
dnl
dnl	V_SHLIB_CCOPT (modified to build position-independent code)
dnl	V_SHLIB_CMD
dnl	V_SHLIB_OPT
dnl	V_SONAME_OPT
dnl
AC_DEFUN(AC_LBL_SHLIBS_INIT,
    [AC_PREREQ(2.50)
    if test "$GCC" = yes ; then
	    #
	    # On platforms where we build a shared library:
	    #
	    #	add options to generate position-independent code,
	    #	if necessary (it's the default in AIX and Darwin/macOS);
	    #
	    #	define option to set the soname of the shared library,
	    #	if the OS supports that;
	    #
	    #	add options to specify, at link time, a directory to
	    #	add to the run-time search path, if that's necessary.
	    #
	    V_SHLIB_CMD="\$(CC)"
	    V_SHLIB_OPT="-shared"
	    case "$host_os" in

	    aix*)
		    ;;

	    freebsd*|netbsd*|openbsd*|dragonfly*|linux*|osf*|haiku*|midipix*)
		    #
		    # Platforms where the C compiler is GCC or accepts
		    # compatible command-line arguments, and the linker
		    # is the GNU linker or accepts compatible command-line
		    # arguments.
		    #
		    # Some instruction sets require -fPIC on some
		    # operating systems.  Check for them.  If you
		    # have a combination that requires it, add it
		    # here.
		    #
		    PIC_OPT=-fpic
		    case "$host_cpu" in

		    sparc64*)
			case "$host_os" in

			freebsd*|openbsd*|linux*)
			    PIC_OPT=-fPIC
			    ;;
			esac
			;;
		    esac
		    V_SHLIB_CCOPT="$V_SHLIB_CCOPT $PIC_OPT"
		    V_SONAME_OPT="-Wl,-soname,"
		    ;;

	    hpux*)
		    V_SHLIB_CCOPT="$V_SHLIB_CCOPT -fpic"
		    #
		    # XXX - this assumes GCC is using the HP linker,
		    # rather than the GNU linker, and that the "+h"
		    # option is used on all HP-UX platforms, both .sl
		    # and .so.
		    #
		    V_SONAME_OPT="-Wl,+h,"
		    #
		    # By default, directories specified with -L
		    # are added to the run-time search path, so
		    # we don't add them in pcap-config.
		    #
		    ;;

	    solaris*)
		    V_SHLIB_CCOPT="$V_SHLIB_CCOPT -fpic"
		    #
		    # Sun/Oracle's C compiler, GCC, and GCC-compatible
		    # compilers support -Wl,{comma-separated list of options},
		    # and we use the C compiler, not ld, for all linking,
		    # including linking to produce a shared library.
		    #
		    V_SONAME_OPT="-Wl,-h,"
		    ;;
	    esac
    else
	    #
	    # Set the appropriate compiler flags and, on platforms
	    # where we build a shared library:
	    #
	    #	add options to generate position-independent code,
	    #	if necessary (it's the default in Darwin/macOS);
	    #
	    #	if we generate ".so" shared libraries, define the
	    #	appropriate options for building the shared library;
	    #
	    #	add options to specify, at link time, a directory to
	    #	add to the run-time search path, if that's necessary.
	    #
	    # Note: spaces after V_SONAME_OPT are significant; on
	    # some platforms the soname is passed with a GCC-like
	    # "-Wl,-soname,{soname}" option, with the soname part
	    # of the option, while on other platforms the C compiler
	    # driver takes it as a regular option with the soname
	    # following the option.
	    #
	    case "$host_os" in

	    aix*)
		    V_SHLIB_CMD="\$(CC)"
		    V_SHLIB_OPT="-G -bnoentry -bexpall"
		    ;;

	    freebsd*|netbsd*|openbsd*|dragonfly*|linux*)
		    #
		    # Platforms where the C compiler is GCC or accepts
		    # compatible command-line arguments, and the linker
		    # is the GNU linker or accepts compatible command-line
		    # arguments.
		    #
		    # XXX - does 64-bit SPARC require -fPIC?
		    #
		    V_SHLIB_CCOPT="$V_SHLIB_CCOPT -fpic"
		    V_SHLIB_CMD="\$(CC)"
		    V_SHLIB_OPT="-shared"
		    V_SONAME_OPT="-Wl,-soname,"
		    ;;

	    hpux*)
		    V_SHLIB_CCOPT="$V_SHLIB_CCOPT +z"
		    V_SHLIB_CMD="\$(LD)"
		    V_SHLIB_OPT="-b"
		    V_SONAME_OPT="+h "
		    #
		    # By default, directories specified with -L
		    # are added to the run-time search path, so
		    # we don't add them in pcap-config.
		    #
		    ;;

	    osf*)
		    #
		    # Presumed to be DEC OSF/1, Digital UNIX, or
		    # Tru64 UNIX.
		    #
		    V_SHLIB_CMD="\$(CC)"
		    V_SHLIB_OPT="-shared"
		    V_SONAME_OPT="-soname "
		    ;;

	    solaris*)
		    V_SHLIB_CCOPT="$V_SHLIB_CCOPT -Kpic"
		    V_SHLIB_CMD="\$(CC)"
		    V_SHLIB_OPT="-G"
		    #
		    # Sun/Oracle's C compiler, GCC, and GCC-compatible
		    # compilers support -Wl,{comma-separated list of options},
		    # and we use the C compiler, not ld, for all linking,
		    # including linking to produce a shared library.
		    #
		    V_SONAME_OPT="-Wl,-h,"
		    ;;
	    esac
    fi
])

#
# Try compiling a sample of the type of code that appears in
# gencode.c with "inline", "__inline__", and "__inline".
#
# Autoconf's AC_C_INLINE, at least in autoconf 2.13, isn't good enough,
# as it just tests whether a function returning "int" can be inlined;
# at least some versions of HP's C compiler can inline that, but can't
# inline a function that returns a struct pointer.
#
# Make sure we use the V_CCOPT flags, because some of those might
# disable inlining.
#
AC_DEFUN(AC_LBL_C_INLINE,
    [AC_MSG_CHECKING(for inline)
    save_CFLAGS="$CFLAGS"
    CFLAGS="$V_CCOPT"
    AC_CACHE_VAL(ac_cv_lbl_inline, [
	ac_cv_lbl_inline=""
	ac_lbl_cc_inline=no
	for ac_lbl_inline in inline __inline__ __inline
	do
	    AC_TRY_COMPILE(
		[#define inline $ac_lbl_inline
		static inline struct iltest *foo(void);
		struct iltest {
		    int iltest1;
		    int iltest2;
		};

		static inline struct iltest *
		foo()
		{
		    static struct iltest xxx;

		    return &xxx;
		}],,ac_lbl_cc_inline=yes,)
	    if test "$ac_lbl_cc_inline" = yes ; then
		break;
	    fi
	done
	if test "$ac_lbl_cc_inline" = yes ; then
	    ac_cv_lbl_inline=$ac_lbl_inline
	fi])
    CFLAGS="$save_CFLAGS"
    if test ! -z "$ac_cv_lbl_inline" ; then
	AC_MSG_RESULT($ac_cv_lbl_inline)
    else
	AC_MSG_RESULT(no)
    fi
    AC_DEFINE_UNQUOTED(inline, $ac_cv_lbl_inline, [Define as token for inline if inlining supported])])

#
# Test whether we have __atomic_load_n() and __atomic_store_n().
#
# We use AC_TRY_LINK because AC_TRY_COMPILE will succeed, as the
# compiler will just think that those functions are undefined,
# and perhaps warn about that, but not fail to compile.
#
AC_DEFUN(AC_PCAP_C___ATOMICS,
    [
	AC_MSG_CHECKING(for __atomic_load_n)
	AC_CACHE_VAL(ac_cv_have___atomic_load_n,
	    AC_TRY_LINK([],
		[
		    int i = 17;
		    int j;
		    j = __atomic_load_n(&i, __ATOMIC_RELAXED);
		],
		ac_have___atomic_load_n=yes,
		ac_have___atomic_load_n=no))
	AC_MSG_RESULT($ac_have___atomic_load_n)
	if test $ac_have___atomic_load_n = yes ; then
	    AC_DEFINE(HAVE___ATOMIC_LOAD_N, 1,
		[define if __atomic_load_n is supported by the compiler])
	fi

	AC_MSG_CHECKING(for __atomic_store_n)
	AC_CACHE_VAL(ac_cv_have___atomic_store_n,
	    AC_TRY_LINK([],
		[
		    int i;
		    __atomic_store_n(&i, 17, __ATOMIC_RELAXED);
		],
		ac_have___atomic_store_n=yes,
		ac_have___atomic_store_n=no))
	AC_MSG_RESULT($ac_have___atomic_store_n)
	if test $ac_have___atomic_store_n = yes ; then
	    AC_DEFINE(HAVE___ATOMIC_STORE_N, 1,
		[define if __atomic_store_n is supported by the compiler])
	fi])

dnl
dnl If using gcc, make sure we have ANSI ioctl definitions
dnl
dnl usage:
dnl
dnl	AC_LBL_FIXINCLUDES
dnl
AC_DEFUN(AC_LBL_FIXINCLUDES,
    [if test "$GCC" = yes ; then
	    AC_MSG_CHECKING(for ANSI ioctl definitions)
	    AC_CACHE_VAL(ac_cv_lbl_gcc_fixincludes,
		AC_TRY_COMPILE(
		    [/*
		     * This generates a "duplicate case value" when fixincludes
		     * has not be run.
		     */
#		include <sys/types.h>
#		include <sys/time.h>
#		include <sys/ioctl.h>
#		ifdef HAVE_SYS_IOCCOM_H
#		include <sys/ioccom.h>
#		endif],
		    [switch (0) {
		    case _IO('A', 1):;
		    case _IO('B', 1):;
		    }],
		    ac_cv_lbl_gcc_fixincludes=yes,
		    ac_cv_lbl_gcc_fixincludes=no))
	    AC_MSG_RESULT($ac_cv_lbl_gcc_fixincludes)
	    if test $ac_cv_lbl_gcc_fixincludes = no ; then
		    # Don't cache failure
		    unset ac_cv_lbl_gcc_fixincludes
		    AC_MSG_ERROR(see the INSTALL for more info)
	    fi
    fi])

dnl
dnl Checks to see if union wait is used with WEXITSTATUS()
dnl
dnl usage:
dnl
dnl	AC_LBL_UNION_WAIT
dnl
dnl results:
dnl
dnl	DECLWAITSTATUS (defined)
dnl
AC_DEFUN(AC_LBL_UNION_WAIT,
    [AC_MSG_CHECKING(if union wait is used)
    AC_CACHE_VAL(ac_cv_lbl_union_wait,
	AC_TRY_COMPILE([
#	include <sys/types.h>
#	include <sys/wait.h>],
	    [int status;
	    u_int i = WEXITSTATUS(status);
	    u_int j = waitpid(0, &status, 0);],
	    ac_cv_lbl_union_wait=no,
	    ac_cv_lbl_union_wait=yes))
    AC_MSG_RESULT($ac_cv_lbl_union_wait)
    if test $ac_cv_lbl_union_wait = yes ; then
	    AC_DEFINE(DECLWAITSTATUS,union wait,[type for wait])
    else
	    AC_DEFINE(DECLWAITSTATUS,int,[type for wait])
    fi])

dnl
dnl Checks to see if -R is used
dnl
dnl usage:
dnl
dnl	AC_LBL_HAVE_RUN_PATH
dnl
dnl results:
dnl
dnl	ac_cv_lbl_have_run_path (yes or no)
dnl
AC_DEFUN(AC_LBL_HAVE_RUN_PATH,
    [AC_MSG_CHECKING(for ${CC-cc} -R)
    AC_CACHE_VAL(ac_cv_lbl_have_run_path,
	[echo 'main(){}' > conftest.c
	${CC-cc} -o conftest conftest.c -R/a1/b2/c3 >conftest.out 2>&1
	if test ! -s conftest.out ; then
		ac_cv_lbl_have_run_path=yes
	else
		ac_cv_lbl_have_run_path=no
	fi
	rm -f -r conftest*])
    AC_MSG_RESULT($ac_cv_lbl_have_run_path)
    ])

dnl
dnl If the file .devel exists:
dnl	Add some warning flags if the compiler supports them
dnl	If an os prototype include exists, symlink os-proto.h to it
dnl
dnl usage:
dnl
dnl	AC_LBL_DEVEL(copt)
dnl
dnl results:
dnl
dnl	$1 (copt appended)
dnl	HAVE_OS_PROTO_H (defined)
dnl	os-proto.h (symlinked)
dnl
AC_DEFUN(AC_LBL_DEVEL,
    [rm -f os-proto.h
    if test "${LBL_CFLAGS+set}" = set; then
	    $1="$$1 ${LBL_CFLAGS}"
    fi
    if test -f .devel ; then
	    #
	    # Skip all the warning option stuff on some compilers.
	    #
	    if test "$ac_lbl_cc_dont_try_gcc_dashW" != yes; then
		    AC_LBL_CHECK_COMPILER_OPT($1, -W)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wall)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wcomma)
		    # Warns about safeguards added in case the enums are
		    # extended
		    # AC_LBL_CHECK_COMPILER_OPT($1, -Wcovered-switch-default)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wdocumentation)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wformat-nonliteral)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wmissing-noreturn)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wmissing-prototypes)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wmissing-variable-declarations)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wnull-pointer-subtraction)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wpointer-arith)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wpointer-sign)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wshadow)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wshorten-64-to-32)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wsign-compare)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wstrict-prototypes)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wundef)
		    #
		    # This can cause problems with ntohs(), ntohl(),
		    # htons(), and htonl() on some platforms, such
		    # as OpenBSD 6.3 with Clang 5.0.1.  I guess the
		    # problem is that the macro that ultimately does
		    # the byte-swapping involves a conditional
		    # expression that tests whether the value being
		    # swapped is a compile-time constant or not,
		    # using __builtin_constant_p(), and, depending
		    # on whether it is, does a compile-time swap or
		    # a run-time swap; perhaps the compiler always
		    # considers one of the two results of the
		    # conditional expression is never evaluated,
		    # because the conditional check is done at
		    # compile time, and thus always says "that
		    # expression is never executed".
		    #
		    # (Perhaps there should be a way of flagging
		    # an expression that you *want* evaluated at
		    # compile time, so that the compiler 1) warns
		    # if it *can't* be evaluated at compile time
		    # and 2) *doesn't* warn that the true or false
		    # branch will never be reached.)
		    #
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wunreachable-code,
		      [
#include <arpa/inet.h>

unsigned short
testme(unsigned short a)
{
	return ntohs(a);
}
		      ],
		      [generates warnings from ntohs()])
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wunused-but-set-parameter)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wunused-but-set-variable)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wunused-parameter)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wused-but-marked-unused)
	    fi
	    AC_LBL_CHECK_DEPENDENCY_GENERATION_OPT()
	    #
	    # We used to set -n32 for IRIX 6 when not using GCC (presumed
	    # to mean that we're using MIPS C or MIPSpro C); it specified
	    # the "new" faster 32-bit ABI, introduced in IRIX 6.2.  I'm
	    # not sure why that would be something to do *only* with a
	    # .devel file; why should the ABI for which we produce code
	    # depend on .devel?
	    #
	    os=`echo $host_os | sed -e 's/\([[0-9]][[0-9]]*\)[[^0-9]].*$/\1/'`
	    name="lbl/os-$os.h"
	    if test -f $name ; then
		    ln -s $name os-proto.h
		    AC_DEFINE(HAVE_OS_PROTO_H, 1,
			[if there's an os_proto.h for this platform, to use additional prototypes])
	    else
		    AC_MSG_WARN(can't find $name)
	    fi
    fi])

dnl
dnl Improved version of AC_CHECK_LIB
dnl
dnl Thanks to John Hawkinson (jhawk@mit.edu)
dnl
dnl usage:
dnl
dnl	AC_LBL_CHECK_LIB(LIBRARY, FUNCTION [, ACTION-IF-FOUND [,
dnl	    ACTION-IF-NOT-FOUND [, OTHER-LIBRARIES]]])
dnl
dnl results:
dnl
dnl	LIBS
dnl
dnl XXX - "AC_LBL_LIBRARY_NET" was redone to use "AC_SEARCH_LIBS"
dnl rather than "AC_LBL_CHECK_LIB", so this isn't used any more.
dnl We keep it around for reference purposes in case it's ever
dnl useful in the future.
dnl

define(AC_LBL_CHECK_LIB,
[AC_MSG_CHECKING([for $2 in -l$1])
dnl Use a cache variable name containing the library, function
dnl name, and extra libraries to link with, because the test really is
dnl for library $1 defining function $2, when linked with potinal
dnl library $5, not just for library $1.  Separate tests with the same
dnl $1 and different $2's or $5's may have different results.
ac_lib_var=`echo $1['_']$2['_']$5 | sed 'y%./+- %__p__%'`
AC_CACHE_VAL(ac_cv_lbl_lib_$ac_lib_var,
[ac_save_LIBS="$LIBS"
LIBS="-l$1 $5 $LIBS"
AC_TRY_LINK(dnl
ifelse([$2], [main], , dnl Avoid conflicting decl of main.
[/* Override any gcc2 internal prototype to avoid an error.  */
]ifelse(AC_LANG, CPLUSPLUS, [#ifdef __cplusplus
extern "C"
#endif
])dnl
[/* We use char because int might match the return type of a gcc2
    builtin and then its argument prototype would still apply.  */
char $2();
]),
	    [$2()],
	    eval "ac_cv_lbl_lib_$ac_lib_var=yes",
	    eval "ac_cv_lbl_lib_$ac_lib_var=no")
LIBS="$ac_save_LIBS"
])dnl
if eval "test \"`echo '$ac_cv_lbl_lib_'$ac_lib_var`\" = yes"; then
  AC_MSG_RESULT(yes)
  ifelse([$3], ,
[changequote(, )dnl
  ac_tr_lib=HAVE_LIB`echo $1 | sed -e 's/[^a-zA-Z0-9_]/_/g' \
    -e 'y/abcdefghijklmnopqrstuvwxyz/ABCDEFGHIJKLMNOPQRSTUVWXYZ/'`
changequote([, ])dnl
  AC_DEFINE_UNQUOTED($ac_tr_lib)
  LIBS="-l$1 $LIBS"
], [$3])
else
  AC_MSG_RESULT(no)
ifelse([$4], , , [$4
])dnl
fi
])

dnl
dnl AC_LBL_LIBRARY_NET
dnl
dnl Look for various networking-related libraries that we may need.
dnl
dnl We need getaddrinfo() to translate host names in filters to IP
dnl addresses. We use getaddrinfo() because we want a portable
dnl thread-safe way of getting information for a host name or port;
dnl there exist _r versions of gethostbyname() and getservbyname() on
dnl some platforms, but not on all platforms.
dnl
dnl We may also need socket() and other socket functions to support:
dnl
dnl   Local packet capture with capture mechanisms that use sockets.
dnl
dnl   Local capture device enumeration if a socket call is needed to
dnl   enumerate devices or get device attributes.
dnl
dnl   Packet capture from services that put captured packets on the
dnl   network, such as rpcap servers.
dnl
dnl We may also need getnameinfo() for packet capture from services
dnl that put packets on the network.
dnl
AC_DEFUN(AC_LBL_LIBRARY_NET, [
    #
    # Most operating systems have getaddrinfo(), and the other routines
    # we may need, in the default searched libraries (e.g., libc).
    # Check there first.
    #
    AC_CHECK_FUNC(getaddrinfo,,
    [
	#
	# Not found in the standard system libraries.
	#
	# In some versions of Solaris, we need to link with libsocket
	# and libnsl, so check in libsocket and also link with liblnsl
	# when doing this test.
	#
	# Linking with libsocket and libnsl will find all the routines
	# we need.
	#
	AC_CHECK_LIB(socket, getaddrinfo,
	[
	    #
	    # OK, we found it in libsocket.
	    #
	    LIBS="-lsocket -lnsl $LIBS"
	],
	[
	    #
	    # Not found in libsocket; test for it in libnetwork, which
	    # is where it is in Haiku.
	    #
	    # Linking with libnetwork will find all the routines we
	    # need.
	    #
	    AC_CHECK_LIB(network, getaddrinfo,
	    [
		#
		# OK, we found it in libnetwork.
		#
		LIBS="-lnetwork $LIBS"
	    ],
	    [
		#
		# We didn't find it.
		#
		AC_MSG_ERROR([getaddrinfo is required, but wasn't found])
	    ])
	], -lnsl)

	#
	# We require a version of recvmsg() that conforms to the Single
	# UNIX Specification, so that we can check whether a datagram
	# received with recvmsg() was truncated when received due to the
	# buffer being too small.
	#
	# On most systems, the version of recvmsg() in the libraries
	# found above conforms to the SUS.
	#
	# On at least some versions of Solaris, it does not conform to
	# the SUS, and we need the version in libxnet, which does
	# conform.
	#
	# Check whether libxnet exists and has a version of recvmsg();
	# if it does, link with libxnet before we link with libsocket,
	# to get that version.
	#
	# This test also links with libsocket and libnsl.
	#
	AC_CHECK_LIB(xnet, recvmsg,
	[
	    #
	    # libxnet has recvmsg(); link with it as well.
	    #
	    LIBS="-lxnet $LIBS"
	], , -lsocket -lnsl)
    ])

    #
    # DLPI needs putmsg under HP-UX, so test for -lstr while we're at it.
    #
    AC_SEARCH_LIBS(putmsg, str)
])

m4_ifndef([AC_CONFIG_MACRO_DIRS], [m4_defun([_AM_CONFIG_MACRO_DIRS], [])m4_defun([AC_CONFIG_MACRO_DIRS], [_AM_CONFIG_MACRO_DIRS($@)])])
dnl pkg.m4 - Macros to locate and utilise pkg-config.   -*- Autoconf -*-
dnl serial 11 (pkg-config-0.29)
dnl
dnl Copyright © 2004 Scott James Remnant <scott@netsplit.com>.
dnl Copyright © 2012-2015 Dan Nicholson <dbn.lists@gmail.com>
dnl
dnl This program is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; either version 2 of the License, or
dnl (at your option) any later version.
dnl
dnl This program is distributed in the hope that it will be useful, but
dnl WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
dnl General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public License
dnl along with this program; if not, write to the Free Software
dnl Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
dnl 02111-1307, USA.
dnl
dnl As a special exception to the GNU General Public License, if you
dnl distribute this file as part of a program that contains a
dnl configuration script generated by Autoconf, you may include it under
dnl the same distribution terms that you use for the rest of that
dnl program.

dnl PKG_PREREQ(MIN-VERSION)
dnl -----------------------
dnl Since: 0.29
dnl
dnl Verify that the version of the pkg-config macros are at least
dnl MIN-VERSION. Unlike PKG_PROG_PKG_CONFIG, which checks the user's
dnl installed version of pkg-config, this checks the developer's version
dnl of pkg.m4 when generating configure.
dnl
dnl To ensure that this macro is defined, also add:
dnl m4_ifndef([PKG_PREREQ],
dnl     [m4_fatal([must install pkg-config 0.29 or later before running autoconf/autogen])])
dnl
dnl See the "Since" comment for each macro you use to see what version
dnl of the macros you require.
m4_defun([PKG_PREREQ],
[m4_define([PKG_MACROS_VERSION], [0.29])
m4_if(m4_version_compare(PKG_MACROS_VERSION, [$1]), -1,
    [m4_fatal([pkg.m4 version $1 or higher is required but ]PKG_MACROS_VERSION[ found])])
])dnl PKG_PREREQ

dnl PKG_PROG_PKG_CONFIG([MIN-VERSION])
dnl ----------------------------------
dnl Since: 0.16
dnl
dnl Search for the pkg-config tool and set the PKG_CONFIG variable to
dnl first found in the path. Checks that the version of pkg-config found
dnl is at least MIN-VERSION. If MIN-VERSION is not specified, 0.17.0 is
dnl used since that's the first version where --static was supported.
AC_DEFUN([PKG_PROG_PKG_CONFIG],
[m4_pattern_forbid([^_?PKG_[A-Z_]+$])
m4_pattern_allow([^PKG_CONFIG(_(PATH|LIBDIR|SYSROOT_DIR|ALLOW_SYSTEM_(CFLAGS|LIBS)))?$])
m4_pattern_allow([^PKG_CONFIG_(DISABLE_UNINSTALLED|TOP_BUILD_DIR|DEBUG_SPEW)$])
AC_ARG_VAR([PKG_CONFIG], [path to pkg-config utility])
AC_ARG_VAR([PKG_CONFIG_PATH], [directories to add to pkg-config's search path])
AC_ARG_VAR([PKG_CONFIG_LIBDIR], [path overriding pkg-config's built-in search path])

if test "x$ac_cv_env_PKG_CONFIG_set" != "xset"; then
	AC_PATH_TOOL([PKG_CONFIG], [pkg-config])
fi
if test -n "$PKG_CONFIG"; then
	_pkg_min_version=m4_default([$1], [0.17.0])
	AC_MSG_CHECKING([pkg-config is at least version $_pkg_min_version])
	if $PKG_CONFIG --atleast-pkgconfig-version $_pkg_min_version; then
		AC_MSG_RESULT([yes])
	else
		AC_MSG_RESULT([no])
		PKG_CONFIG=""
	fi
fi[]dnl
])dnl PKG_PROG_PKG_CONFIG

dnl PKG_CHECK_EXISTS(MODULE, [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
dnl -------------------------------------------------------------------
dnl Since: 0.18
dnl
dnl Check to see whether a particular module exists. Similar to
dnl PKG_CHECK_MODULE(), but does not set variables or print errors.
AC_DEFUN([PKG_CHECK_EXISTS],
[
if test -n "$PKG_CONFIG" && \
    AC_RUN_LOG([$PKG_CONFIG --exists --print-errors "$1"]); then
  m4_default([$2], [:])
m4_ifvaln([$3], [else
  $3])dnl
fi])

dnl _PKG_CONFIG_WITH_FLAGS([VARIABLE], [FLAGS], [MODULE])
dnl ---------------------------------------------
dnl Internal wrapper calling pkg-config via PKG_CONFIG and, if
dnl pkg-config fails, reporting the error and quitting.
m4_define([_PKG_CONFIG_WITH_FLAGS],
[if test ! -n "$$1"; then
    $1=`$PKG_CONFIG $2 "$3" 2>/dev/null`
    if test "x$?" != "x0"; then
        #
        # That failed - report an error.
        # Re-run the command, telling pkg-config to print an error
        # message, capture the error message, and report it.
        # This causes the configuration script to fail, as it means
        # the script is almost certainly doing something wrong.
        #
        _PKG_SHORT_ERRORS_SUPPORTED
	if test $_pkg_short_errors_supported = yes; then
	    _pkg_error_string=`$PKG_CONFIG --short-errors --print-errors $2 "$3" 2>&1`
	else
	    _pkg_error_string=`$PKG_CONFIG --print-errors $2 "$3" 2>&1`
	fi
        AC_MSG_ERROR([$PKG_CONFIG $2 "$3" failed: $_pkg_error_string])
    fi
 fi[]dnl
])dnl _PKG_CONFIG_WITH_FLAGS


dnl _PKG_CONFIG([VARIABLE], [FLAGS], [MODULE])
dnl ---------------------------------------------
dnl Internal wrapper calling pkg-config via PKG_CONFIG and setting
dnl pkg_failed based on the result.
m4_define([_PKG_CONFIG],
[if test -n "$$1"; then
    pkg_cv_[]$1="$$1"
 elif test -n "$PKG_CONFIG"; then
    PKG_CHECK_EXISTS([$3],
                     [pkg_cv_[]$1=`$PKG_CONFIG $2 "$3" 2>/dev/null`
		      test "x$?" != "x0" && pkg_failed=yes ],
		     [pkg_failed=yes])
 else
    pkg_failed=untried
fi[]dnl
])dnl _PKG_CONFIG

dnl _PKG_SHORT_ERRORS_SUPPORTED
dnl ---------------------------
dnl Internal check to see if pkg-config supports short errors.
AC_DEFUN([_PKG_SHORT_ERRORS_SUPPORTED],
[
if $PKG_CONFIG --atleast-pkgconfig-version 0.20; then
        _pkg_short_errors_supported=yes
else
        _pkg_short_errors_supported=no
fi[]dnl
])dnl _PKG_SHORT_ERRORS_SUPPORTED


dnl PKG_CHECK_MODULE(VARIABLE-PREFIX, MODULE, [ACTION-IF-FOUND],
dnl   [ACTION-IF-NOT-FOUND])
dnl --------------------------------------------------------------
dnl Since: 0.4.0
AC_DEFUN([PKG_CHECK_MODULE],
[
AC_MSG_CHECKING([for $2 with pkg-config])
if test -n "$PKG_CONFIG"; then
    AC_ARG_VAR([$1][_CFLAGS], [C compiler flags for $2, overriding pkg-config])dnl
    AC_ARG_VAR([$1][_LIBS], [linker flags for $2, overriding pkg-config])dnl
    AC_ARG_VAR([$1][_LIBS_STATIC], [static-link linker flags for $2, overriding pkg-config])dnl

    if AC_RUN_LOG([$PKG_CONFIG --exists --print-errors "$2"]); then
	#
	# The package was found, so try to get its C flags and
	# libraries.
	#
        AC_MSG_RESULT([found])
	_PKG_CONFIG_WITH_FLAGS([$1][_CFLAGS], [--cflags], [$2])
	_PKG_CONFIG_WITH_FLAGS([$1][_LIBS], [--libs], [$2])
	_PKG_CONFIG_WITH_FLAGS([$1][_LIBS_STATIC], [--libs --static], [$2])
        m4_default([$3], [:])
    else
        AC_MSG_RESULT([not found])
        m4_default([$4], [:])
    fi
else
    # No pkg-config, so obviously not found with pkg-config.
    AC_MSG_RESULT([pkg-config not found])
    m4_default([$4], [:])
fi
])dnl PKG_CHECK_MODULE


dnl PKG_CHECK_MODULE_STATIC(VARIABLE-PREFIX, MODULE, [ACTION-IF-FOUND],
dnl   [ACTION-IF-NOT-FOUND])
dnl ---------------------------------------------------------------------
dnl Since: 0.29
dnl
dnl Checks for existence of MODULE and gathers its build flags with
dnl static libraries enabled. Sets VARIABLE-PREFIX_CFLAGS from --cflags
dnl and VARIABLE-PREFIX_LIBS from --libs.
AC_DEFUN([PKG_CHECK_MODULE_STATIC],
[
_save_PKG_CONFIG=$PKG_CONFIG
PKG_CONFIG="$PKG_CONFIG --static"
PKG_CHECK_MODULE($@)
PKG_CONFIG=$_save_PKG_CONFIG[]dnl
])dnl PKG_CHECK_MODULE_STATIC


dnl PKG_INSTALLDIR([DIRECTORY])
dnl -------------------------
dnl Since: 0.27
dnl
dnl Substitutes the variable pkgconfigdir as the location where a module
dnl should install pkg-config .pc files. By default the directory is
dnl $libdir/pkgconfig, but the default can be changed by passing
dnl DIRECTORY. The user can override through the --with-pkgconfigdir
dnl parameter.
AC_DEFUN([PKG_INSTALLDIR],
[m4_pushdef([pkg_default], [m4_default([$1], ['${libdir}/pkgconfig'])])
m4_pushdef([pkg_description],
    [pkg-config installation directory @<:@]pkg_default[@:>@])
AC_ARG_WITH([pkgconfigdir],
    [AS_HELP_STRING([--with-pkgconfigdir], pkg_description)],,
    [with_pkgconfigdir=]pkg_default)
AC_SUBST([pkgconfigdir], [$with_pkgconfigdir])
m4_popdef([pkg_default])
m4_popdef([pkg_description])
])dnl PKG_INSTALLDIR


dnl PKG_NOARCH_INSTALLDIR([DIRECTORY])
dnl --------------------------------
dnl Since: 0.27
dnl
dnl Substitutes the variable noarch_pkgconfigdir as the location where a
dnl module should install arch-independent pkg-config .pc files. By
dnl default the directory is $datadir/pkgconfig, but the default can be
dnl changed by passing DIRECTORY. The user can override through the
dnl --with-noarch-pkgconfigdir parameter.
AC_DEFUN([PKG_NOARCH_INSTALLDIR],
[m4_pushdef([pkg_default], [m4_default([$1], ['${datadir}/pkgconfig'])])
m4_pushdef([pkg_description],
    [pkg-config arch-independent installation directory @<:@]pkg_default[@:>@])
AC_ARG_WITH([noarch-pkgconfigdir],
    [AS_HELP_STRING([--with-noarch-pkgconfigdir], pkg_description)],,
    [with_noarch_pkgconfigdir=]pkg_default)
AC_SUBST([noarch_pkgconfigdir], [$with_noarch_pkgconfigdir])
m4_popdef([pkg_default])
m4_popdef([pkg_description])
])dnl PKG_NOARCH_INSTALLDIR


dnl PKG_CHECK_VAR(VARIABLE, MODULE, CONFIG-VARIABLE,
dnl [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
dnl -------------------------------------------
dnl Since: 0.28
dnl
dnl Retrieves the value of the pkg-config variable for the given module.
AC_DEFUN([PKG_CHECK_VAR],
[
AC_ARG_VAR([$1], [value of $3 for $2, overriding pkg-config])dnl

_PKG_CONFIG([$1], [--variable="][$3]["], [$2])
AS_VAR_COPY([$1], [pkg_cv_][$1])

AS_VAR_IF([$1], [""], [$5], [$4])dnl
])dnl PKG_CHECK_VAR
