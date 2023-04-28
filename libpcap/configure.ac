dnl
dnl Copyright (c) 1994, 1995, 1996, 1997
dnl	The Regents of the University of California.  All rights reserved.
dnl
dnl Process this file with autoconf to produce a configure script.
dnl

#
# See
#
#	https://ftp.gnu.org/gnu/config/README
#
# for the URLs to use to fetch new versions of config.guess and
# config.sub.
#

AC_PREREQ(2.69)

AC_INIT(pcap, m4_esyscmd_s([cat VERSION]))
AC_CONFIG_SRCDIR(pcap.c)
AC_SUBST(PACKAGE_NAME)

#
# These are the variables that are used in Makefile, pcap-config, and
# libpcap.pc.
#
# CFLAGS: inherited from the environment, not modified by us (except
# temporarily during tests that involve compilation).  Used only when
# compiling C source.
#
# CXXFLAGS: inherited from the environment, not modified by us.  Used only
# when compiling C++ source.
#
# LDFLAGS: inherited from the environment, not modified by us.
#
# LIBS: inherited from the environment; we add libraries required by
# libpcap.  Librares that the core libpcap code requires are added
# first; libraries required by additional pcap modules are first
# added to ADDITIONAL_LIBS, and only added to LIBS at the end, after
# we're finished doing configuration tests for the modules.
#
# LIBS_STATIC: libraries with which a program using the libpcap *static*
# library needs to be linked.  This is a superset of LIBS, used in
# pcap-config, so that "pcap-config --libs --static" will report them.
# Initialized to LIBS.
#
# REQUIRES_PRIVATE: pkg-config package names for additional libraries
# with which a program using the libpcap *static* library needs to be
# linked and for which a .pc file exists.  This is used in libpcap.pc,
# so that "pkg-config --libs --static" will report them, and so that
# those libraries will be determined using the library's .pc file, not
# from our .pc file.  Initialized to an empty string.
#
# V_CCOPT: additional compiler flags other than -I and -D flags
# needed when compiling libpcap.  Used in Makefile for both C and
# C++ source.
#
# V_DEFS: additional -D compiler flags needed when compiling
# libpcap.  Used in Makefile for both C and C++ source.
#
# V_INCLS: additional -I compiler flags needed when compiling
# libpcap.  Used in Makefile for both C and C++ source.
#
# ADDITIONAL_LIBS: additional libraries with which the libpcap dynamic
# library needs to be linked.  Used in Makwfile; not used in pcap-config
# or libpcap.pc, as, in all platforms on which we run, if a dynamic
# library is linked with other dynamic libraries, a program using
# that dynamic library doesn't have to link with those libraries -
# they will be automatically loaded at run time.  Initialized to an
# empty string.
#
# ADDITIONAL_LIBS_STATIC: additional libraries with which a program
# using the libpcap *static* library needs to be linked.  This is used
# in pcap-config, so that "pcap-config --libs --static" will report
# them.  Initialized to an empty string.
#
# REQUIRES_PRIVATE: pkg-config package names for additional libraries
# with which a program using the libpcap *static* library needs to be
# linked and for which a .pc file exists.  This is used in libpcap.pc,
# so that "pkg-config --libs --static" will report them, and so that
# those libraries will be determined using the library's .pc file, not
# from our .pc file.  Initialized to an empty string.
#
# LIBS_PRIVATE: pkg-config package names for additional libraries with
# which a program using the libpcap *static* library needs to be linked
# and for which a .pc file does not exist.  This is used in libpcap.pc,
# so that "pkg-config --libs --static" will report them (those libraries
# cannot be determined using the library's .pc file, as there is no such
# file, so it has to come from our .pc file.  Initialized to an empty
# string.
#
LIBS_STATIC=""
REQUIRES_PRIVATE=""
LIBS_PRIVATE=""

AC_SUBST(V_CCOPT)
AC_SUBST(V_DEFS)
AC_SUBST(V_INCLS)
AC_SUBST(LIBS_STATIC)
AC_SUBST(REQUIRES_PRIVATE)
AC_SUBST(LIBS_PRIVATE)

AC_CANONICAL_SYSTEM

AC_LBL_C_INIT_BEFORE_CC(V_CCOPT, V_INCLS)
#
# We require C99 or later.
# Try to get it, which may involve adding compiler flags;
# if that fails, give up.
#
AC_PROG_CC_C99
if test "$ac_cv_prog_cc_c99" = "no"; then
	AC_MSG_ERROR([The C compiler does not support C99])
fi

#
# Get the size of a void *, to determine whether this is a 32-bit
# or 64-bit build.
#
AC_CHECK_SIZEOF([void *])
ac_lbl_c_sizeof_void_p="$ac_cv_sizeof_void_p"

#
# We only need a C++ compiler for Haiku; all code except for its
# pcap module is in C.
#
case "$host_os" in
haiku*)
	AC_PROG_CXX

	#
	# Make sure C and C++ have the same pointer sizes with the flags
	# they're given; if they don't, it means that the compilers for the
	# languages will, with those flags, not produce code that can be
	# linked together.
	#
	# We have to use different data types, because the results of
	# a test are cached, so if we test for the size of a given type
	# in C, the subsequent test in C++ will use the cached variable.
	# We trick autoconf by testing the size of a "void *" in C and a
	# "const void *" in C++.
	#
	AC_LANG_PUSH([C++])
	AC_CHECK_SIZEOF([const void *])
	ac_lbl_cxx_sizeof_void_p="$ac_cv_sizeof_const_void_p"
	AC_LANG_POP([C++])
	if test "$ac_lbl_cxx_sizeof_void_p" -eq 0; then
		AC_MSG_ERROR([No C++ compiler was found])
	fi
	if test "$ac_lbl_c_sizeof_void_p" -ne "$ac_lbl_cxx_sizeof_void_p"; then
		AC_MSG_ERROR([C compiler $CC produces code with $ac_lbl_c_sizeof_void_p-byte pointers
while C++ compiler $CXX produces code with $ac_lbl_cxx_sizeof_void_p-byte pointers.  This prevents
code in those languages from being combined.])
	fi
	;;
esac

AC_LBL_C_INIT(V_CCOPT, V_INCLS)
AC_LBL_SHLIBS_INIT
AC_LBL_C_INLINE
AC_PCAP_C___ATOMICS

#
# Try to arrange for large file support.
#
AC_SYS_LARGEFILE
AC_FUNC_FSEEKO

dnl
dnl Even if <net/bpf.h> were, on all OSes that support BPF, fixed to
dnl include <sys/ioccom.h>, and we were to drop support for older
dnl releases without that fix, so that pcap-bpf.c doesn't need to
dnl include <sys/ioccom.h>, the test program in "AC_LBL_FIXINCLUDES"
dnl in "aclocal.m4" uses it, so we would still have to test for it
dnl and set "HAVE_SYS_IOCCOM_H" if we have it, otherwise
dnl "AC_LBL_FIXINCLUDES" wouldn't work on some platforms such as Solaris.
dnl
AC_CHECK_HEADERS(sys/ioccom.h sys/sockio.h)
AC_CHECK_HEADERS(netpacket/packet.h)

AC_LBL_SAVE_CHECK_STATE
case "$host_os" in
haiku*)
	#
	# Haiku needs _BSD_SOURCE for the _IO* macros because it doesn't use them.
	#
	CFLAGS="$CFLAGS -D_BSD_SOURCE"
	#
	# Haiku has getpass in libbsd.
	#
	AC_CHECK_LIB(bsd, getpass)
	;;
esac

AC_LBL_FIXINCLUDES
AC_LBL_RESTORE_CHECK_STATE

AC_CHECK_FUNCS(strerror)
AC_CHECK_FUNC(strerror_r,
    [
	#
	# We have strerror_r; if we define _GNU_SOURCE, is it a
	# POSIX-compliant strerror_r() or a GNU strerror_r()?
	#
	AC_MSG_CHECKING(whether strerror_r is GNU-style)
	AC_COMPILE_IFELSE(
	    [
		AC_LANG_SOURCE(
#define _GNU_SOURCE
#include <string.h>

/* Define it GNU-style; that will cause an error if it's not GNU-style */
extern char *strerror_r(int, char *, size_t);

int
main(void)
{
	return 0;
}
)
	    ],
	    [
		# GNU-style
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_GNU_STRERROR_R,,
		    [Define to 1 if you have a GNU-style `strerror_r' function.])
	    ],
	    [
		AC_MSG_RESULT(no)
		AC_DEFINE(HAVE_POSIX_STRERROR_R,,
		    [Define to 1 if you have a POSIX-style `strerror_r' function.])
	    ])
    ],
    [
	#
	# We don't have strerror_r; do we have _wcserror_s?
	#
	AC_CHECK_FUNCS(_wcserror_s)
    ])

#
# Thanks, IBM, for not providing vsyslog() in AIX!
#
AC_CHECK_FUNCS(vsyslog)

#
# Make sure we have vsnprintf() and snprintf(); we require them.
#
AC_CHECK_FUNC(vsnprintf,,
    AC_MSG_ERROR([vsnprintf() is required but wasn't found]))
AC_CHECK_FUNC(snprintf,,
    AC_MSG_ERROR([snprintf() is required but wasn't found]))

needasprintf=no
AC_CHECK_FUNCS(vasprintf asprintf,,
	[needasprintf=yes])
if test $needasprintf = yes; then
	AC_LIBOBJ([asprintf])
fi

needstrlcat=no
AC_CHECK_FUNCS(strlcat,,
	[needstrlcat=yes])
if test $needstrlcat = yes; then
	AC_LIBOBJ([strlcat])
fi

needstrlcpy=no
AC_CHECK_FUNCS(strlcpy,,
	[needstrlcpy=yes])
if test $needstrlcpy = yes; then
	AC_LIBOBJ([strlcpy])
fi

needstrtok_r=no
AC_CHECK_FUNCS(strtok_r,,
	[needstrtok_r=yes])
if test $needstrtok_r = yes; then
	AC_LIBOBJ([strtok_r])
fi

#
# Do we have ffs(), and is it declared in <strings.h>?
#
AC_CHECK_FUNCS(ffs)
if test "$ac_cv_func_ffs" = yes; then
	#
	# We have ffs(); is it declared in <strings.h>?
	#
	# This test fails if we don't have <strings.h> or if we do
	# but it doesn't declare ffs().
	#
	AC_CHECK_DECL(ffs,
	    [
		AC_DEFINE(STRINGS_H_DECLARES_FFS,,
		    [Define to 1 if strings.h declares `ffs'])
	    ],,
	    [
#include <strings.h>
	    ])
fi

#
# Do this before checking for ether_hostton(), as it's a
# "getaddrinfo()-ish function".
#
AC_LBL_LIBRARY_NET

#
# Check for reentrant versions of getnetbyname_r(), as provided by
# Linux (glibc), Solaris/IRIX, and AIX (with three different APIs!).
# If we don't find one, we just use getnetbyname(), which uses
# thread-specific data on many platforms, but doesn't use it on
# NetBSD or OpenBSD, and may not use it on older versions of other
# platforms.
#
# Only do the check if we have a declaration of getnetbyname_r();
# without it, we can't check which API it has.  (We assume that
# if there's a declaration, it has a prototype, so that the API
# can be checked.)
#
AC_CHECK_DECL(getnetbyname_r,
    [
	AC_MSG_CHECKING([for the Linux getnetbyname_r()])
	AC_TRY_LINK(
	    [#include <netdb.h>],
	    [
		struct netent netent_buf;
		char buf[1024];
		struct netent *resultp;
		int h_errnoval;

		return getnetbyname_r((const char *)0, &netent_buf, buf, sizeof buf, &resultp, &h_errnoval);
	    ],
	    [
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_LINUX_GETNETBYNAME_R, 1,
		    [define if we have the Linux getnetbyname_r()])
	    ],
	    [
		AC_MSG_RESULT(no)

		AC_MSG_CHECKING([for Solaris/IRIX getnetbyname_r()])
		AC_TRY_LINK(
		    [#include <netdb.h>],
		    [
			struct netent netent_buf;
			char buf[1024];

			return getnetbyname_r((const char *)0, &netent_buf, buf, (int)sizeof buf) != NULL;
		    ],
		    [
			AC_MSG_RESULT(yes)
			AC_DEFINE(HAVE_SOLARIS_IRIX_GETNETBYNAME_R, 1,
			    [define if we have the Solaris/IRIX getnetbyname_r()])
		    ],
		    [
			AC_MSG_RESULT(no)

			AC_MSG_CHECKING([for AIX getnetbyname_r()])
			AC_TRY_LINK(
			    [#include <netdb.h>],
			    [
				struct netent netent_buf;
				struct netent_data net_data;

				return getnetbyname_r((const char *)0, &netent_buf, &net_data);
			    ],
			    [
				AC_MSG_RESULT(yes)
				AC_DEFINE(HAVE_AIX_GETNETBYNAME_R, 1,
				    [define if we have the AIX getnetbyname_r()])
			    ],
			    [
				AC_MSG_RESULT(no)
			    ])
		    ])
	    ])
    ],,[#include <netdb.h>])

#
# Check for reentrant versions of getprotobyname_r(), as provided by
# Linux (glibc), Solaris/IRIX, and AIX (with three different APIs!).
# If we don't find one, we just use getprotobyname(), which uses
# thread-specific data on many platforms, but doesn't use it on
# NetBSD or OpenBSD, and may not use it on older versions of other
# platforms.
#
# Only do the check if we have a declaration of getprotobyname_r();
# without it, we can't check which API it has.  (We assume that
# if there's a declaration, it has a prototype, so that the API
# can be checked.)
#
AC_CHECK_DECL(getprotobyname_r,
    [
	AC_MSG_CHECKING([for the Linux getprotobyname_r()])
	AC_TRY_LINK(
	    [#include <netdb.h>],
	    [
		struct protoent protoent_buf;
		char buf[1024];
		struct protoent *resultp;

		return getprotobyname_r((const char *)0, &protoent_buf, buf, sizeof buf, &resultp);
	    ],
	    [
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_LINUX_GETPROTOBYNAME_R, 1,
		    [define if we have the Linux getprotobyname_r()])
	    ],
	    [
		AC_MSG_RESULT(no)

		AC_MSG_CHECKING([for Solaris/IRIX getprotobyname_r()])
		AC_TRY_LINK(
		    [#include <netdb.h>],
		    [
			struct protoent protoent_buf;
			char buf[1024];

			return getprotobyname_r((const char *)0, &protoent_buf, buf, (int)sizeof buf) != NULL;
		    ],
		    [
			AC_MSG_RESULT(yes)
			AC_DEFINE(HAVE_SOLARIS_IRIX_GETPROTOBYNAME_R, 1,
			    [define if we have the Solaris/IRIX getprotobyname_r()])
		    ],
		    [
			AC_MSG_RESULT(no)

			AC_MSG_CHECKING([for AIX getprotobyname_r()])
			AC_TRY_LINK(
			    [#include <netdb.h>],
			    [
				struct protoent protoent_buf;
				struct protoent_data proto_data;

				return getprotobyname_r((const char *)0, &protoent_buf, &proto_data);
			    ],
			    [
				AC_MSG_RESULT(yes)
				AC_DEFINE(HAVE_AIX_GETPROTOBYNAME_R, 1,
				    [define if we have the AIX getprotobyname_r()])
			    ],
			    [
				AC_MSG_RESULT(no)
			    ])
		    ])
	    ])
    ],,[#include <netdb.h>])

#
# You are in a twisty little maze of UN*Xes, all different.
# Some might not have ether_hostton().
# Some might have it and declare it in <net/ethernet.h>.
# Some might have it and declare it in <netinet/ether.h>
# Some might have it and declare it in <sys/ethernet.h>.
# Some might have it and declare it in <arpa/inet.h>.
# Some might have it and declare it in <netinet/if_ether.h>.
# Some might have it and not declare it in any header file.
#
# Before you is a C compiler.
#
AC_CHECK_FUNCS(ether_hostton)
if test "$ac_cv_func_ether_hostton" = yes; then
	#
	# OK, we have ether_hostton().  Is it declared in <net/ethernet.h>?
	#
	# This test fails if we don't have <net/ethernet.h> or if we do
	# but it doesn't declare ether_hostton().
	#
	AC_CHECK_DECL(ether_hostton,
	    [
		AC_DEFINE(NET_ETHERNET_H_DECLARES_ETHER_HOSTTON,,
		    [Define to 1 if net/ethernet.h declares `ether_hostton'])
	    ],,
	    [
#include <net/ethernet.h>
	    ])
	#
	# Did that succeed?
	#
	if test "$ac_cv_have_decl_ether_hostton" != yes; then
		#
		# No, how about <netinet/ether.h>, as on Linux?
		#
		# This test fails if we don't have <netinet/ether.h>
		# or if we do but it doesn't declare ether_hostton().
		#
		# Unset ac_cv_have_decl_ether_hostton so we don't
		# treat the previous failure as a cached value and
		# suppress the next test.
		#
		unset ac_cv_have_decl_ether_hostton
		AC_CHECK_DECL(ether_hostton,
		    [
			AC_DEFINE(NETINET_ETHER_H_DECLARES_ETHER_HOSTTON,,
			    [Define to 1 if netinet/ether.h declares `ether_hostton'])
		    ],,
		    [
#include <netinet/ether.h>
		    ])
	fi
	#
	# Did that succeed?
	#
	if test "$ac_cv_have_decl_ether_hostton" != yes; then
		#
		# No, how about <sys/ethernet.h>, as on Solaris 10
		# and later?
		#
		# This test fails if we don't have <sys/ethernet.h>
		# or if we do but it doesn't declare ether_hostton().
		#
		# Unset ac_cv_have_decl_ether_hostton so we don't
		# treat the previous failure as a cached value and
		# suppress the next test.
		#
		unset ac_cv_have_decl_ether_hostton
		AC_CHECK_DECL(ether_hostton,
		    [
			AC_DEFINE(SYS_ETHERNET_H_DECLARES_ETHER_HOSTTON,,
			    [Define to 1 if sys/ethernet.h declares `ether_hostton'])
		    ],,
		    [
#include <sys/ethernet.h>
		    ])
	fi
	#
	# Did that succeed?
	#
	if test "$ac_cv_have_decl_ether_hostton" != yes; then
		#
		# No, how about <arpa/inet.h>, as in AIX?
		#
		# This test fails if we don't have <arpa/inet.h>
		# (if we have ether_hostton(), we should have
		# networking, and if we have networking, we should
		# have <arpa/inet.h>) or if we do but it doesn't
		# declare ether_hostton().
		#
		# Unset ac_cv_have_decl_ether_hostton so we don't
		# treat the previous failure as a cached value and
		# suppress the next test.
		#
		unset ac_cv_have_decl_ether_hostton
		AC_CHECK_DECL(ether_hostton,
		    [
			AC_DEFINE(ARPA_INET_H_DECLARES_ETHER_HOSTTON,,
			    [Define to 1 if arpa/inet.h declares `ether_hostton'])
		    ],,
		    [
#include <arpa/inet.h>
		    ])
	fi
	#
	# Did that succeed?
	#
	if test "$ac_cv_have_decl_ether_hostton" != yes; then
		#
		# No, how about <netinet/if_ether.h>?
		# On some platforms, it requires <net/if.h> and
		# <netinet/in.h>, and we always include it with
		# both of them, so test it with both of them.
		#
		# This test fails if we don't have <netinet/if_ether.h>
		# and the headers we include before it, or if we do but
		# <netinet/if_ether.h> doesn't declare ether_hostton().
		#
		# Unset ac_cv_have_decl_ether_hostton so we don't
		# treat the previous failure as a cached value and
		# suppress the next test.
		#
		unset ac_cv_have_decl_ether_hostton
		AC_CHECK_DECL(ether_hostton,
		    [
			AC_DEFINE(NETINET_IF_ETHER_H_DECLARES_ETHER_HOSTTON,,
			    [Define to 1 if netinet/if_ether.h declares `ether_hostton'])
		    ],,
		    [
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
		    ])
	fi
	#
	# After all that, is ether_hostton() declared?
	#
	if test "$ac_cv_have_decl_ether_hostton" = yes; then
		#
		# Yes.
		#
		AC_DEFINE(HAVE_DECL_ETHER_HOSTTON, 1,
		    [Define to 1 if you have the declaration of `ether_hostton'])
        else
		#
		# No, we'll have to declare it ourselves.
		# Do we have "struct ether_addr" if we include
		# <netinet/if_ether.h>?
		#
		AC_CHECK_TYPES(struct ether_addr,,,
		    [
			#include <sys/types.h>
			#include <sys/socket.h>
			#include <net/if.h>
			#include <netinet/in.h>
			#include <netinet/if_ether.h>
		    ])
	fi
fi

#
# For various things that might use pthreads.
#
AC_CHECK_HEADER(pthread.h,
    [
	#
	# OK, we have pthread.h.  Do we have pthread_create in the
	# system libraries?
	#
	AC_CHECK_FUNC(pthread_create,
	    [
		#
		# Yes.
		#
		ac_lbl_have_pthreads="found"
	    ],
	    [
		#
		# No - do we have it in -lpthreads?
		#
		AC_CHECK_LIB(pthreads, pthread_create,
		    [
			#
			# Yes - add -lpthreads.
			#
			ac_lbl_have_pthreads="found"
			PTHREAD_LIBS="$PTHREAD_LIBS -lpthreads"
		    ],
		    [
			#
			# No - do we have it in -lpthread?
			#
			AC_CHECK_LIB(pthread, pthread_create,
			    [
				#
				# Yes - add -lpthread.
				#
                                ac_lbl_have_pthreads="found"
				PTHREAD_LIBS="$PTHREAD_LIBS -lpthread"
			    ],
			    [
				#
				# No.
				#
				ac_lbl_have_pthreads="not found"
			    ])
		    ])
	    ])
    ],
    [
	#
	# We didn't find pthread.h.
	#
	ac_lbl_have_pthreads="not found"
    ]
)

dnl to pacify those who hate protochain insn
AC_MSG_CHECKING(if --disable-protochain option is specified)
AC_ARG_ENABLE(protochain,
AS_HELP_STRING([--disable-protochain],[disable \"protochain\" insn]))
case "x$enable_protochain" in
xyes)	enable_protochain=enabled	;;
xno)	enable_protochain=disabled	;;
x)	enable_protochain=enabled	;;
esac

if test "$enable_protochain" = "disabled"; then
	AC_DEFINE(NO_PROTOCHAIN,1,[do not use protochain])
fi
AC_MSG_RESULT(${enable_protochain})

#
# valgrindtest directly uses the native capture mechanism, but
# only tests with BPF and PF_PACKET sockets; only enable it if
# we have BPF or PF_PACKET sockets.
#
VALGRINDTEST_SRC=

AC_ARG_WITH(pcap,
AS_HELP_STRING([--with-pcap=TYPE],[use packet capture TYPE]))
if test ! -z "$with_pcap" ; then
	V_PCAP="$withval"
else
	#
	# Check for a bunch of headers for various packet
	# capture mechanisms.
	#
	AC_CHECK_HEADERS(net/bpf.h)
	if test "$ac_cv_header_net_bpf_h" = yes; then
		#
		# Does it define BIOCSETIF?
		# I.e., is it a header for an LBL/BSD-style capture
		# mechanism, or is it just a header for a BPF filter
		# engine?  Some versions of Arch Linux, for example,
		# have a net/bpf.h that doesn't define BIOCSETIF;
		# as it's a Linux, it should use packet sockets,
		# instead.
		#
		# We need:
		#
		#  sys/types.h, because FreeBSD 10's net/bpf.h
		#  requires that various BSD-style integer types
		#  be defined;
		#
		#  sys/time.h, because AIX 5.2 and 5.3's net/bpf.h
		#  doesn't include it but does use struct timeval
		#  in ioctl definitions;
		#
		#  sys/ioctl.h and, if we have it, sys/ioccom.h,
		#  because net/bpf.h defines ioctls;
		#
		#  net/if.h, because it defines some structures
		#  used in ioctls defined by net/bpf.h;
		#
		#  sys/socket.h, because OpenBSD 5.9's net/bpf.h
		#  defines some structure fields as being
		#  struct sockaddrs;
		#
		# and net/bpf.h doesn't necessarily include all
		# of those headers itself.
		#
		AC_MSG_CHECKING(if net/bpf.h defines BIOCSETIF)
		AC_CACHE_VAL(ac_cv_lbl_bpf_h_defines_biocsetif,
			AC_TRY_COMPILE(
[
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_IOCCOM_H
#include <sys/ioccom.h>
#endif
#include <net/bpf.h>
#include <net/if.h>
],
			[u_int i = BIOCSETIF;],
			ac_cv_lbl_bpf_h_defines_biocsetif=yes,
			ac_cv_lbl_bpf_h_defines_biocsetif=no))
		AC_MSG_RESULT($ac_cv_lbl_bpf_h_defines_biocsetif)
	fi
	AC_CHECK_HEADERS(net/pfilt.h net/enet.h)
	AC_CHECK_HEADERS(net/nit.h sys/net/nit.h)
	AC_CHECK_HEADERS(linux/socket.h net/raw.h sys/dlpi.h)
	AC_CHECK_HEADERS(config/HaikuConfig.h)

	if test "$ac_cv_lbl_bpf_h_defines_biocsetif" = yes; then
		#
		# BPF.
		# Check this before DLPI, so that we pick BPF on
		# Solaris 11 and later.
		#
		V_PCAP=bpf

		#
		# We have BPF, so build valgrindtest with "make test"
		# on macOS and FreeBSD (add your OS once there's a
		# valgrind for it).
		#
		case "$host_os" in

		freebsd*|darwin*|linux*)
			VALGRINDTEST_SRC=valgrindtest.c
			;;
		esac
	elif test "$ac_cv_header_linux_socket_h" = yes; then
		#
		# No prizes for guessing this one.
		#
		V_PCAP=linux
		VALGRINDTEST_SRC=valgrindtest.c
	elif test "$ac_cv_header_net_pfilt_h" = yes; then
		#
		# DEC OSF/1, Digital UNIX, Tru64 UNIX
		#
		V_PCAP=pf
	elif test "$ac_cv_header_net_enet_h" = yes; then
		#
		# Stanford Enetfilter.
		#
		V_PCAP=enet
	elif test "$ac_cv_header_net_nit_h" = yes; then
		#
		# SunOS 4.x STREAMS NIT.
		#
		V_PCAP=snit
	elif test "$ac_cv_header_sys_net_nit_h" = yes; then
		#
		# Pre-SunOS 4.x non-STREAMS NIT.
		#
		V_PCAP=nit
	elif test "$ac_cv_header_net_raw_h" = yes; then
		#
		# IRIX snoop.
		#
		V_PCAP=snoop
	elif test "$ac_cv_header_sys_dlpi_h" = yes; then
		#
		# DLPI on pre-Solaris 11 SunOS 5, HP-UX, possibly others.
		#
		V_PCAP=dlpi
	elif test "$ac_cv_header_config_HaikuConfig_h" = yes; then
		#
		# Haiku.
		#
		V_PCAP=haiku
	else
		#
		# Nothing we support.
		#
		V_PCAP=null
		AC_MSG_WARN(cannot determine packet capture interface)
		AC_MSG_WARN((see the INSTALL.md file for more info))
	fi
fi
AC_MSG_CHECKING(packet capture type)
AC_MSG_RESULT($V_PCAP)
AC_SUBST(VALGRINDTEST_SRC)

#
# Do we have pkg-config?
#
PKG_PROG_PKG_CONFIG

#
# Do we have the brew command from Homebrew?
#
AC_PATH_PROG([BREW], [brew])

#
# Solaris pkg-config is annoying.  For at least one package (D-Bus, I'm
# looking at *you*!), there are separate include files for 32-bit and
# 64-bit builds (I guess using "unsigned long long" as a 64-bit integer
# type on a 64-bit build is like crossing the beams or soething), and
# there are two separate .pc files, so if we're doing a 32-bit build we
# should make sure we look in /usr/lib/pkgconfig for .pc files and if
# we're doing a 64-bit build we should make sure we look in
# /usr/lib/amd64/pkgconfig for .pc files.
#
case "$host_os" in

solaris*)
	if test "$ac_cv_sizeof_void_p" -eq 8; then
		#
		# 64-bit build.  If the path is empty, set it to
                # /usr/lib/amd64/pkgconfig; otherwise, if
                # /usr/lib/pkgconfig appears in the path, prepend
		# /usr/lib/amd64/pkgconfig to it; otherwise, put
		# /usr/lib/amd64/pkgconfig at the end.
		#
		if test -z "$PKG_CONFIG_PATH"; then
			#
			# Not set, or empty.  Set it to
			# /usr/lib/amd64/pkgconfig.
			#
			PKG_CONFIG_PATH=/usr/lib/amd64/pkgconfig
		elif test ! -z `echo "$PKG_CONFIG_PATH" | grep "/usr/lib/pkgconfig"`; then
			#
			# It contains /usr/lib/pkgconfig.  Prepend
			# /usr/lib/amd64/pkgconfig to /usr/lib/pkgconfig.
			#
			PKG_CONFIG_PATH=`echo "$PKG_CONFIG_PATH" | sed "s;/usr/lib/pkgconfig;/usr/lib/amd64/pkgconfig:/usr/lib/pkgconfig;"`
		else
			#
			# Not empty, but doesn't contain /usr/lib/pkgconfig.
			# Append /usr/lib/amd64/pkgconfig to it.
			#
			PKG_CONFIG_PATH="$PKG_CONFIG_PATH:/usr/lib/amd64/pkgconfig"
		fi
		export PKG_CONFIG_PATH
	elif test "$ac_cv_sizeof_void_p" -eq 4; then
		#
		# 32-bit build.  If /usr/amd64/lib/pkgconfig appears
		# in the path, prepend /usr/lib/pkgconfig to it.
		#
		if test ! -z `echo "$PKG_CONFIG_PATH" | grep "/usr/lib/amd64/pkgconfig"`; then
			#
			# It contains /usr/lib/amd64/pkgconfig.  Prepend
			# /usr/lib/pkgconfig to /usr/lib/amd64/pkgconfig.
			#
			PKG_CONFIG_PATH=`echo "$PKG_CONFIG_PATH" | sed "s;/usr/lib/amd64/pkgconfig;/usr/lib/pkgconfig:/usr/lib/amd64/pkgconfig;"`
			export PKG_CONFIG_PATH
		fi
	fi
esac

#
# Handle each capture type.
#
case "$V_PCAP" in
dlpi)
	#
	# Checks for some header files.
	#
	AC_CHECK_HEADERS(sys/bufmod.h sys/dlpi_ext.h)

	#
	# Checks to see if Solaris has the public libdlpi(3LIB) library.
	# Note: The existence of /usr/include/libdlpi.h does not mean it is the
	# public libdlpi(3LIB) version. Before libdlpi was made public, a
	# private version also existed, which did not have the same APIs.
	# Due to a gcc bug, the default search path for 32-bit libraries does
	# not include /lib, we add it explicitly here.
	# [http://bugs.opensolaris.org/view_bug.do?bug_id=6619485].
	# Also, due to the bug above applications that link to libpcap with
	# libdlpi will have to add "-L/lib" option to "configure".
	#
	save_LDFLAGS="$LDFLAGS"
	LDFLAGS="$LIBS -L/lib"
	AC_CHECK_LIB(dlpi, dlpi_walk,
		[
			LIBS="-ldlpi $LIBS"
			LIBS_STATIC="-ldlpi $LIBS_STATIC"
			LIBS_PRIVATE="-ldlpi $LIBS_PRIVATE"
			V_PCAP=libdlpi

			#
			# Capture module plus common code needed for
			# common functions used by pcap-[dlpi,libdlpi].c
			#
			PLATFORM_C_SRC="pcap-libdlpi.c dlpisubs.c"
			AC_DEFINE(HAVE_LIBDLPI,1,[if libdlpi exists])
		],
		[
			V_PCAP=dlpi

			#
			# Capture module plus common code needed for
			# common functions used by pcap-[dlpi,libdlpi].c
			#
			PLATFORM_C_SRC="pcap-dlpi.c dlpisubs.c"
		])
	LDFLAGS="$save_LDFLAGS"

	#
	# Checks whether <sys/dlpi.h> is usable, to catch weird SCO
	# versions of DLPI.
	#
	AC_MSG_CHECKING(whether <sys/dlpi.h> is usable)
	AC_CACHE_VAL(ac_cv_sys_dlpi_usable,
		AC_TRY_COMPILE(
		    [
			#include <sys/types.h>
			#include <sys/time.h>
			#include <sys/dlpi.h>
		    ],
		    [int i = DL_PROMISC_PHYS;],
		    ac_cv_sys_dlpi_usable=yes,
		    ac_cv_sys_dlpi_usable=no))
	AC_MSG_RESULT($ac_cv_sys_dlpi_usable)
	if test $ac_cv_sys_dlpi_usable = no ; then
		AC_MSG_ERROR(<sys/dlpi.h> is not usable on this system; it probably has a non-standard DLPI)
	fi

	#
	# Check to see if Solaris has the dl_passive_req_t struct defined
	# in <sys/dlpi.h>.
	# This check is for DLPI support for passive modes.
	# See dlpi(7P) for more details.
	#
	AC_CHECK_TYPES(dl_passive_req_t,,,
	    [
		#include <sys/types.h>
		#include <sys/dlpi.h>
	    ])
	;;

enet)
	#
	# Capture module
	#
	PLATFORM_C_SRC="pcap-enet.c"
	;;

haiku)
	#
	# Capture module
	#
	PLATFORM_CXX_SRC="pcap-haiku.cpp"

	#
	# Just for the sake of it.
	#
	AC_CHECK_HEADERS(net/if.h net/if_dl.h net/if_types.h)
	;;

linux)
	#
	# Capture module
	#
	PLATFORM_C_SRC="pcap-linux.c"

	#
	# Do we have the wireless extensions?
	#
	AC_CHECK_HEADERS(linux/wireless.h, [], [],
	[
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/types.h>
	])

	#
	# Do we have libnl?
	# We only want version 3.  Version 2 was, apparently,
	# short-lived, and version 1 is source and binary
	# incompatible with version 3, and it appears that,
	# these days, everybody's using version 3.  We're
	# not supporting older versions of the Linux kernel;
	# let's drop support for older versions of libnl, too.
	#
	AC_ARG_WITH(libnl,
	AS_HELP_STRING([--without-libnl],[disable libnl support @<:@default=disabled@:>@]),
		with_libnl=$withval,with_libnl=if_available)

	if test x$with_libnl = xyes ; then
		#
		# Check for libnl-genl-3.0 with pkg-config.
		#
		PKG_CHECK_MODULES(LIBNL, libnl-genl-3.0,
		    [
			pkg_config_found_libnl=yes
			V_INCLS="$V_INCLS $LIBNL_CFLAGS"
			ADDITIONAL_LIBS="$LIBNL_LIBS $ADDITIONAL_LIBS"
			ADDITIONAL_LIBS_STATIC="$LIBNL_LIBS_STATIC $ADDITIONAL_LIBS_STATIC"
			REQUIRES_PRIVATE="libnl-genl-3.0 $REQUIRES_PRIVATE"
			AC_DEFINE(HAVE_LIBNL,1,[if libnl exists])
		    ])

		if test x$pkg_config_found_libnl != xyes; then
			#
			# OK, either we don't have pkg-config or there
			# wasn't a .pc file for it; Check for it directly.
			#
			case "$with_libnl" in

			yes|if_available)
				incdir=-I/usr/include/libnl3
				libnldir=
				;;

			*)
				if test -d $withval; then
					libnldir=-L${withval}/lib
					incdir=-I${withval}/include
				fi
				;;
			esac

			AC_CHECK_LIB(nl-3, nl_socket_alloc,
			[
				#
				# Yes, we have libnl 3.x.
				#
				ADDITIONAL_LIBS="${libnldir} -lnl-genl-3 -lnl-3 $ADDITIONAL_LIBS"
				ADDITIONAL_LIBS_STATIC="${libnldir} -lnl-genl-3 -lnl-3 $ADDITIONAL_LIBS_STATIC"
				LIBS_PRIVATE="${libnldir} -lnl-genl-3 -lnl-3 $LIBS_PRIVATE"
				AC_DEFINE(HAVE_LIBNL,1,[if libnl exists])
				V_INCLS="$V_INCLS ${incdir}"
			],[
				#
				# No, we don't have libnl at all.
				# Fail if the user explicitly requested
				# it.
				#
				if test x$with_libnl = xyes ; then
					AC_MSG_ERROR([libnl support requested but libnl not found])
				fi
			], ${incdir} ${libnldir} -lnl-genl-3 -lnl-3 )
		fi
	fi

	#
	# Check to see if the tpacket_auxdata struct has a tp_vlan_tci member.
	#
	# NOTE: any failure means we conclude that it doesn't have that
	# member, so if we don't have tpacket_auxdata, we conclude it
	# doesn't have that member (which is OK, as either we won't be
	# using code that would use that member, or we wouldn't compile
	# in any case).
	AC_CHECK_MEMBERS([struct tpacket_auxdata.tp_vlan_tci],,,
	    [
		#include <sys/types.h>
		#include <linux/if_packet.h>
	    ])
	;;

bpf)
	#
	# Capture module
	#
	PLATFORM_C_SRC="pcap-bpf.c"

	#
	# Check whether we have the *BSD-style ioctls.
	#
	AC_CHECK_HEADERS(net/if_media.h)

	#
	# Check whether we have struct BPF_TIMEVAL.
	#
	AC_CHECK_TYPES(struct BPF_TIMEVAL,,,
	    [
		#include <sys/types.h>
		#include <sys/ioctl.h>
		#ifdef HAVE_SYS_IOCCOM_H
		#include <sys/ioccom.h>
		#endif
		#include <net/bpf.h>
	    ])
	;;

pf)
	#
	# Capture module
	#
	PLATFORM_C_SRC="pcap-pf.c"
	;;

snit)
	#
	# Capture module
	#
	PLATFORM_C_SRC="pcap-snit.c"
	;;

snoop)
	#
	# Capture module
	#
	PLATFORM_C_SRC="pcap-snoop.c"
	;;

dag)
	#
	# --with-pcap=dag is the only way to get here, and it means
	# "DAG support but nothing else"
	#
	V_DEFS="$V_DEFS -DDAG_ONLY"
	PLATFORM_C_SRC="pcap-dag.c"
	xxx_only=yes
	;;

dpdk)
	#
	# --with-pcap=dpdk is the only way to get here, and it means
	# "DPDK support but nothing else"
	#
	V_DEFS="$V_DEFS -DDPDK_ONLY"
	PLATFORM_C_SRC="pcap-dpdk.c"
	xxx_only=yes
	;;

septel)
	#
	# --with-pcap=septel is the only way to get here, and it means
	# "Septel support but nothing else"
	#
	V_DEFS="$V_DEFS -DSEPTEL_ONLY"
	PLATFORM_C_SRC="pcap-septel.c"
	xxx_only=yes
	;;

snf)
	#
	# --with-pcap=snf is the only way to get here, and it means
	# "SNF support but nothing else"
	#
	V_DEFS="$V_DEFS -DSNF_ONLY"
	PLATFORM_C_SRC="pcap-snf.c"
	xxx_only=yes
	;;

null)
	#
	# Capture module
	#
	PLATFORM_C_SRC="pcap-null.c"
	;;

*)
	AC_MSG_ERROR($V_PCAP is not a valid pcap type)
	;;
esac

dnl
dnl Now figure out how we get a list of interfaces and addresses,
dnl if we support capturing.  Don't bother if we don't support
dnl capturing.
dnl
if test "$V_PCAP" != null
then
	AC_CHECK_FUNC(getifaddrs,[
		#
		# We have "getifaddrs()"; make sure we have <ifaddrs.h>
		# as well, just in case some platform is really weird.
		#
		AC_CHECK_HEADER(ifaddrs.h,[
		    #
		    # We have the header, so we use "getifaddrs()" to
		    # get the list of interfaces.
		    #
		    PLATFORM_C_SRC="$PLATFORM_C_SRC fad-getad.c"
		],[
		    #
		    # We don't have the header - give up.
		    # XXX - we could also fall back on some other
		    # mechanism, but, for now, this'll catch this
		    # problem so that we can at least try to figure
		    # out something to do on systems with "getifaddrs()"
		    # but without "ifaddrs.h", if there is something
		    # we can do on those systems.
		    #
		    AC_MSG_ERROR([Your system has getifaddrs() but doesn't have a usable <ifaddrs.h>.])
		])
	],[
		#
		# Well, we don't have "getifaddrs()", at least not with the
		# libraries with which we've decided we need to link
		# libpcap with, so we have to use some other mechanism.
		#
		# Note that this may happen on Solaris, which has
		# getifaddrs(), but in -lsocket, not in -lxnet, so we
		# won't find it if we link with -lxnet, which we want
		# to do for other reasons.
		#
		# For now, we use either the SIOCGIFCONF ioctl or the
		# SIOCGLIFCONF ioctl, preferring the latter if we have
		# it; the latter is a Solarisism that first appeared
		# in Solaris 8.  (Solaris's getifaddrs() appears to
		# be built atop SIOCGLIFCONF; using it directly
		# avoids a not-all-that-useful middleman.)
		#
		AC_MSG_CHECKING(whether we have SIOCGLIFCONF)
		AC_CACHE_VAL(ac_cv_lbl_have_siocglifconf,
		    AC_TRY_COMPILE(
			[#include <sys/param.h>
			#include <sys/file.h>
			#include <sys/ioctl.h>
			#include <sys/socket.h>
			#include <sys/sockio.h>],
			[ioctl(0, SIOCGLIFCONF, (char *)0);],
			ac_cv_lbl_have_siocglifconf=yes,
			ac_cv_lbl_have_siocglifconf=no))
		AC_MSG_RESULT($ac_cv_lbl_have_siocglifconf)
		if test $ac_cv_lbl_have_siocglifconf = yes ; then
			PLATFORM_C_SRC="$PLATFORM_C_SRC fad-glifc.c"
		else
			PLATFORM_C_SRC="$PLATFORM_C_SRC fad-gifc.c"
		fi
	])
fi

dnl check for hardware timestamp support
case "$host_os" in
linux*)
	AC_CHECK_HEADERS([linux/net_tstamp.h])
	;;
*)
	AC_MSG_NOTICE(no hardware timestamp support implemented for $host_os)
	;;
esac

#
# Check for socklen_t.
#
AC_CHECK_TYPES(socklen_t,,,
    [
	#include <sys/types.h>
	#include <sys/socket.h>
    ])

AC_ARG_ENABLE(ipv6,
AS_HELP_STRING([--enable-ipv6],[build IPv6-capable version @<:@default=yes@:>@]),
    [],
    [enable_ipv6=yes])
if test "$enable_ipv6" != "no"; then
	#
	# We've already made sure we have getaddrinfo above in
	# AC_LBL_LIBRARY_NET.
	#
	AC_DEFINE(INET6,1,[IPv6])
fi

# Check for Endace DAG card support.
AC_ARG_WITH([dag],
AS_HELP_STRING([--with-dag@<:@=DIR@:>@],[include Endace DAG support (located in directory DIR, if supplied).  @<:@default=yes, if present@:>@]),
[
	if test "$withval" = no
	then
		# User doesn't want DAG support.
		want_dag=no
	elif test "$withval" = yes
	then
		# User wants DAG support but hasn't specified a directory.
		want_dag=yes
	else
		# User wants DAG support and has specified a directory, so use the provided value.
		want_dag=yes
		dag_root=$withval
	fi
],[
	if test "$V_PCAP" = dag; then
		# User requested DAG-only libpcap, so we'd better have
		# the DAG API.
		want_dag=yes
	elif test "xxx_only" = yes; then
		# User requested something-else-only pcap, so they don't
		# want DAG support.
		want_dag=no
	else
		#
		# Use DAG API if present, otherwise don't
		#
		want_dag=ifpresent
	fi
])

AC_ARG_WITH([dag-includes],
AS_HELP_STRING([--with-dag-includes=IDIR],[Endace DAG include directory, if not DIR/include]),
[
	# User wants DAG support and has specified a header directory, so use the provided value.
	want_dag=yes
	dag_include_dir=$withval
],[])

AC_ARG_WITH([dag-libraries],
AS_HELP_STRING([--with-dag-libraries=LDIR],[Endace DAG library directory, if not DIR/lib]),
[
	# User wants DAG support and has specified a library directory, so use the provided value.
	want_dag=yes
	dag_lib_dir=$withval
],[])

if test "$want_dag" != no; then

	# If necessary, set default paths for DAG API headers and libraries.
	if test -z "$dag_root"; then
		dag_root=/usr/local
	fi

	if test -z "$dag_include_dir"; then
		dag_include_dir="$dag_root/include"
	fi

	if test -z "$dag_lib_dir"; then
		dag_lib_dir="$dag_root/lib"
		#
		# Handle multiarch systems.
		#
		if test -d "$dag_lib_dir/$host"
		then
			dag_lib_dir="$dag_lib_dir/$host"
		fi
	fi

	AC_LBL_SAVE_CHECK_STATE
	CFLAGS="$CFLAGS -I$dag_include_dir"
	AC_CHECK_HEADERS([dagapi.h])
	AC_LBL_RESTORE_CHECK_STATE

	if test "$ac_cv_header_dagapi_h" = yes; then

		V_INCLS="$V_INCLS -I$dag_include_dir"

		if test $V_PCAP != dag ; then
			 MODULE_C_SRC="$MODULE_C_SRC pcap-dag.c"
		fi

		# Check for various DAG API functions.
		# Don't need to save and restore LIBS to prevent -ldag being
		# included if there's a found-action (arg 3).
		AC_LBL_SAVE_CHECK_STATE
		LDFLAGS="-L$dag_lib_dir"
		AC_CHECK_LIB([dag], [dag_attach_stream],
		    [
			#
			# We assume that if we have libdag we have
			# libdagconf, as they're installed at the
			# same time from the same package.
			#
			ADDITIONAL_LIBS="-L$dag_lib_dir $ADDITIONAL_LIBS -ldag -ldagconf"
			ADDITIONAL_LIBS_STATIC="-L$dag_lib_dir $ADDITIONAL_LIBS_STATIC -ldag -ldagconf"
			LIBS_PRIVATE="-L$dag_lib_dir $LIBS_PRIVATE -ldag -ldagconf"
		    ],
		    [AC_MSG_ERROR(DAG library lacks streams support)])
		AC_CHECK_LIB([dag], [dag_attach_stream64], [dag_large_streams="1"], [dag_large_streams="0"])
		AC_CHECK_LIB([dag],[dag_get_erf_types], [
			AC_DEFINE(HAVE_DAG_GET_ERF_TYPES, 1, [define if you have dag_get_erf_types()])])
		AC_CHECK_LIB([dag],[dag_get_stream_erf_types], [
			AC_DEFINE(HAVE_DAG_GET_STREAM_ERF_TYPES, 1, [define if you have dag_get_stream_erf_types()])])
		AC_LBL_RESTORE_CHECK_STATE

		#
		# We assume that if we have libdag we have libdagconf,
		# as they're installed at the same time from the same
		# package.
		#
		if test "$dag_large_streams" = 1; then
			AC_DEFINE(HAVE_DAG_LARGE_STREAMS_API, 1, [define if you have large streams capable DAG API])
			AC_LBL_SAVE_CHECK_STATE
			LIBS="$LIBS -ldag -ldagconf"
			LDFLAGS="$LDFLAGS -L$dag_lib_dir"
			AC_CHECK_LIB([vdag],[vdag_set_device_info], [ac_dag_have_vdag="1"], [ac_dag_have_vdag="0"])
			AC_LBL_RESTORE_CHECK_STATE
			if test "$ac_dag_have_vdag" = 1; then
				AC_DEFINE(HAVE_DAG_VDAG, 1, [define if you have vdag_set_device_info()])
				if test "$ac_lbl_have_pthreads" != "found"; then
					AC_MSG_ERROR([DAG requires pthreads, but we didn't find them])
				fi
				ADDITIONAL_LIBS="$ADDITIONAL_LIBS $PTHREAD_LIBS"
				ADDITIONAL_LIBS_STATIC="$ADDITIONAL_LIBS_STATIC $PTHREAD_LIBS"
				LIBS_PRIVATE="$LIBS_PRIVATE $PTHREAD_LIBS"
			fi
		fi

		AC_DEFINE(HAVE_DAG_API, 1, [define if you have the DAG API])
	else
		if test "$V_PCAP" = dag; then
			# User requested "dag" capture type but we couldn't
			# find the DAG API support.
			AC_MSG_ERROR([DAG support requested with --with-pcap=dag, but the DAG headers weren't found at $dag_include_dir: make sure the DAG support is installed, specify a different path or paths if necessary, or don't request DAG support])
		fi

		if test "$want_dag" = yes; then
			# User wanted DAG support but we couldn't find it.
			AC_MSG_ERROR([DAG support requested with --with-dag, but the DAG headers weren't found at $dag_include_dir: make sure the DAG support is installed, specify a different path or paths if necessary, or don't request DAG support])
		fi
	fi
	CFLAGS="$save_CFLAGS"
fi

AC_ARG_WITH(septel,
AS_HELP_STRING([--with-septel@<:@=DIR@:>@],[include Septel support (located in directory DIR, if supplied).  @<:@default=yes, if present@:>@]),
[
	if test "$withval" = no
	then
		want_septel=no
	elif test "$withval" = yes
	then
		want_septel=yes
		septel_root=
	else
		want_septel=yes
		septel_root=$withval
	fi
],[
	if test "$V_PCAP" = septel; then
		# User requested Septel-only libpcap, so we'd better have
		# the Septel API.
		want_septel=yes
	elif test "xxx_only" = yes; then
		# User requested something-else-only pcap, so they don't
		# want Septel support.
		want_septel=no
	else
		#
		# Use Septel API if present, otherwise don't
		#
		want_septel=ifpresent
	fi
])

ac_cv_lbl_septel_api=no
if test "$with_septel" != no; then

	AC_MSG_CHECKING([whether we have Septel API headers])

	# If necessary, set default paths for Septel API headers and libraries.
	if test -z "$septel_root"; then
		septel_root=$srcdir/../septel
	fi

	septel_tools_dir="$septel_root"
	septel_include_dir="$septel_root/INC"

	if test -r "$septel_include_dir/msg.h"; then
		ac_cv_lbl_septel_api=yes
	fi

	if test "$ac_cv_lbl_septel_api" = yes; then
		AC_MSG_RESULT([yes ($septel_include_dir)])

		V_INCLS="$V_INCLS -I$septel_include_dir"
		ADDLOBJS="$ADDLOBJS $septel_tools_dir/asciibin.o $septel_tools_dir/bit2byte.o $septel_tools_dir/confirm.o $septel_tools_dir/fmtmsg.o $septel_tools_dir/gct_unix.o $septel_tools_dir/hqueue.o $septel_tools_dir/ident.o $septel_tools_dir/mem.o $septel_tools_dir/pack.o $septel_tools_dir/parse.o $septel_tools_dir/pool.o $septel_tools_dir/sdlsig.o $septel_tools_dir/strtonum.o $septel_tools_dir/timer.o $septel_tools_dir/trace.o"
		ADDLARCHIVEOBJS="$ADDLARCHIVEOBJS $septel_tools_dir/asciibin.o $septel_tools_dir/bit2byte.o $septel_tools_dir/confirm.o $septel_tools_dir/fmtmsg.o $septel_tools_dir/gct_unix.o $septel_tools_dir/hqueue.o $septel_tools_dir/ident.o $septel_tools_dir/mem.o $septel_tools_dir/pack.o $septel_tools_dir/parse.o $septel_tools_dir/pool.o $septel_tools_dir/sdlsig.o $septel_tools_dir/strtonum.o $septel_tools_dir/timer.o $septel_tools_dir/trace.o"

		if test "$V_PCAP" != septel ; then
			 MODULE_C_SRC="$MODULE_C_SRC pcap-septel.c"
		fi

		AC_DEFINE(HAVE_SEPTEL_API, 1, [define if you have the Septel API])
	else
		AC_MSG_RESULT(no)

		if test "$V_PCAP" = septel; then
			# User requested "septel" capture type but
			# we couldn't find the Septel API support.
			AC_MSG_ERROR([Septel support requested with --with-pcap=septel, but the Septel headers weren't found at $septel_include_dir: make sure the Septel support is installed, specify a different path or paths if necessary, or don't request Septel support])
		fi

		if test "$want_septel" = yes; then
			# User wanted Septel support but we couldn't find it.
			AC_MSG_ERROR([Septel support requested with --with-septel, but the Septel headers weren't found at $septel_include_dir: make sure the Septel support is installed, specify a different path or paths if necessary, or don't request Septel support])
		fi
	fi
fi

# Check for Myricom SNF support.
AC_ARG_WITH([snf],
AS_HELP_STRING([--with-snf@<:@=DIR@:>@],[include Myricom SNF support (located in directory DIR, if supplied).  @<:@default=yes, if present@:>@]),
[
	if test "$withval" = no
	then
		# User explicitly doesn't want SNF
		want_snf=no
	elif test "$withval" = yes
	then
		# User wants SNF support but hasn't specified a directory.
		want_snf=yes
	else
		# User wants SNF support with a specified directory.
		want_snf=yes
		snf_root=$withval
	fi
],[
	if test "$V_PCAP" = snf; then
		# User requested Sniffer-only libpcap, so we'd better have
		# the Sniffer API.
		want_snf=yes
	elif test "xxx_only" = yes; then
		# User requested something-else-only pcap, so they don't
		# want SNF support.
		want_snf=no
	else
		#
		# Use Sniffer API if present, otherwise don't
		#
		want_snf=ifpresent
	fi
])

AC_ARG_WITH([snf-includes],
AS_HELP_STRING([--with-snf-includes=IDIR],[Myricom SNF include directory, if not DIR/include]),
[
	# User wants SNF with specific header directory
	want_snf=yes
	snf_include_dir=$withval
],[])

AC_ARG_WITH([snf-libraries],
AS_HELP_STRING([--with-snf-libraries=LDIR],[Myricom SNF library directory, if not DIR/lib]),
[
	# User wants SNF with specific lib directory
	want_snf=yes
	snf_lib_dir=$withval
],[])

ac_cv_lbl_snf_api=no
if test "$with_snf" != no; then

	AC_MSG_CHECKING(whether we have Myricom Sniffer API)

	# If necessary, set default paths for Sniffer headers and libraries.
	if test -z "$snf_root"; then
		snf_root=/opt/snf
	fi

	if test -z "$snf_include_dir"; then
		snf_include_dir="$snf_root/include"
	fi

	if test -z "$snf_lib_dir"; then
		snf_lib_dir="$snf_root/lib"
		#
		# Handle multiarch systems.
		#
		if test -d "$snf_lib_dir/$host"
		then
			snf_lib_dir="$snf_lib_dir/$host"
		fi
	fi

	if test -f "$snf_include_dir/snf.h"; then
		# We found a header; make sure we can link with the library
		AC_LBL_SAVE_CHECK_STATE
		LDFLAGS="$LDFLAGS -L$snf_lib_dir"
		AC_CHECK_LIB([snf], [snf_init], [ac_cv_lbl_snf_api="yes"])
		AC_LBL_RESTORE_CHECK_STATE
		if test "$ac_cv_lbl_snf_api" = no; then
			AC_MSG_ERROR(SNF API cannot correctly be linked; check config.log)
		fi
	fi

	if test "$ac_cv_lbl_snf_api" = yes; then
		AC_MSG_RESULT([yes ($snf_root)])

		V_INCLS="$V_INCLS -I$snf_include_dir"
		ADDITIONAL_LIBS="$ADDITIONAL_LIBS -L$snf_lib_dir -lsnf"
		ADDITIONAL_LIBS_STATIC="$ADDITIONAL_LIBS_STATIC -L$snf_lib_dir -lsnf"
		LIBS_PRIVATE="$LIBS_PRIVATE -L$snf_lib_dir -lsnf"

		if test "$V_PCAP" != snf ; then
			MODULE_C_SRC="$MODULE_C_SRC pcap-snf.c"
		fi

		AC_DEFINE(HAVE_SNF_API, 1, [define if you have the Myricom SNF API])
	else
		AC_MSG_RESULT(no)

		if test "$want_snf" = yes; then
			# User requested "snf" capture type but
			# we couldn't find the Sniffer API support.
			AC_MSG_ERROR([Myricom Sniffer support requested with --with-pcap=snf, but the Sniffer headers weren't found at $snf_include_dir: make sure the Sniffer support is installed, specify a different path or paths if necessary, or don't request Sniffer support])
		fi

		if test "$want_snf" = yes; then
			AC_MSG_ERROR([Myricom Sniffer support requested with --with-snf, but the Sniffer headers weren't found at $snf_include_dir: make sure the Sniffer support is installed, specify a different path or paths if necessary, or don't request Sniffer support])
		fi
	fi
fi

# Check for Riverbed TurboCap support.
AC_ARG_WITH([turbocap],
AS_HELP_STRING([--with-turbocap@<:@=DIR@:>@],[include Riverbed TurboCap support (located in directory DIR, if supplied).  @<:@default=yes, if present@:>@]),
[
	if test "$withval" = no
	then
		# User explicitly doesn't want TurboCap
		want_turbocap=no
	elif test "$withval" = yes
	then
		# User wants TurboCap support but hasn't specified a directory.
		want_turbocap=yes
	else
		# User wants TurboCap support with a specified directory.
		want_turbocap=yes
		turbocap_root=$withval
	fi
],[
	if test "xxx_only" = yes; then
		# User requested something-else-only pcap, so they don't
		# want TurboCap support.
		want_turbocap=no
	else
		#
		# Use TurboCap API if present, otherwise don't
		#
		want_turbocap=ifpresent
	fi
])

ac_cv_lbl_turbocap_api=no
if test "$want_turbocap" != no; then

	AC_MSG_CHECKING(whether TurboCap is supported)

	AC_LBL_SAVE_CHECK_STATE
	if test ! -z "$turbocap_root"; then
		TURBOCAP_CFLAGS="-I$turbocap_root/include"
		TURBOCAP_LDFLAGS="-L$turbocap_root/lib"
		CFLAGS="$CFLAGS $TURBOCAP_CFLAGS"
		LDFLAGS="$LDFLAGS $TURBOCAP_LDFLAGS"
	fi

	AC_TRY_COMPILE(
	[
	    #include <TcApi.h>
	],
	[
	    TC_INSTANCE a; TC_PORT b; TC_BOARD c;
	    TC_INSTANCE i;
	    (void)TcInstanceCreateByName("foo", &i);
	],
	ac_cv_lbl_turbocap_api=yes)

	AC_LBL_RESTORE_CHECK_STATE
	if test $ac_cv_lbl_turbocap_api = yes; then
		AC_MSG_RESULT(yes)

		MODULE_C_SRC="$MODULE_C_SRC pcap-tc.c"
		V_INCLS="$V_INCLS $TURBOCAP_CFLAGS"
		ADDITIONAL_LIBS="$ADDITIONAL_LIBS $TURBOCAP_LDFLAGS -lTcApi -lpthread -lstdc++"
		ADDITIONAL_LIBS_STATIC="$ADDITIONAL_LIBS_STATIC $TURBOCAP_LDFLAGS -lTcApi -lpthread -lstdc++"
		LIBS_PRIVATE="$LIBS_PRIVATE $TURBOCAP_LDFLAGS -lTcApi -lpthread -lstdc++"

		AC_DEFINE(HAVE_TC_API, 1, [define if you have the TurboCap API])
	else
		AC_MSG_RESULT(no)

		if test "$want_turbocap" = yes; then
			# User wanted Turbo support but we couldn't find it.
			AC_MSG_ERROR([TurboCap support requested with --with-turbocap, but the TurboCap headers weren't found: make sure the TurboCap support is installed or don't request TurboCap support])
		fi
	fi
fi

dnl
dnl Allow the user to enable remote capture.
dnl It's off by default, as that increases the attack surface of
dnl libpcap, exposing it to malicious servers.
dnl
AC_MSG_CHECKING([whether to enable remote packet capture])
AC_ARG_ENABLE([remote],
   [AS_HELP_STRING([--enable-remote],
     [enable remote packet capture @<:@default=no@:>@])],
   [],
   [enableval=no])
case "$enableval" in
yes)	AC_MSG_RESULT(yes)
	AC_WARN([Remote packet capture may expose libpcap-based applications])
	AC_WARN([to attacks by malicious remote capture servers!])
	#
	# rpcapd requires pthreads on UN*X.
	#
	if test "$ac_lbl_have_pthreads" != "found"; then
		AC_MSG_ERROR([rpcapd requires pthreads, but we didn't find them])
	fi
	#
	# It also requires crypt().
	# Do we have it in the system libraries?
	#
	AC_CHECK_FUNC(crypt,,
	    [
		#
		# No.  Do we have it in -lcrypt?
		#
		AC_CHECK_LIB(crypt, crypt,
		    [
			#
			# Yes; add -lcrypt to the libraries for rpcapd.
			#
			RPCAPD_LIBS="$RPCAPD_LIBS -lcrypt"
		    ],
		    [
			AC_MSG_ERROR([rpcapd requires crypt(), but we didn't find it])
		    ])
	    ])

	#
	# OK, we have crypt().  Do we have getspnam()?
	#
	AC_CHECK_FUNCS(getspnam)

	#
	# Check for various members of struct msghdr.
	#
	AC_CHECK_MEMBERS([struct msghdr.msg_control],,,
	    [
		#include "ftmacros.h"
		#include <sys/socket.h>
	    ])
	AC_CHECK_MEMBERS([struct msghdr.msg_flags],,,
	    [
		#include "ftmacros.h"
		#include <sys/socket.h>
	    ])

	#
	# Optionally, we may want to support SSL.
	# Check for OpenSSL/libressl.
	#
	# First, try looking for it with pkg-config, if we have it.
	#
	# Homebrew's pkg-config does not, by default, look for
	# pkg-config files for packages it has installed.
	# Furthermore, at least for OpenSSL, they appear to be
	# dumped in package-specific directories whose paths are
	# not only package-specific but package-version-specific.
	#
	# So the only way to find openssl is to get the value of
	# PKG_CONFIG_PATH from "brew --env openssl" and add that
	# to PKG_CONFIG_PATH.  (No, we can't just assume it's under
	# /usr/local; Homebrew have conveniently chosen to put it
	# under /opt/homebrew on ARM.)
	#
	# That's the nice thing about Homebrew - it makes things easier!
	# Thanks!
	#
	save_PKG_CONFIG_PATH="$PKG_CONFIG_PATH"
	if test -n "$BREW"; then
		openssl_pkgconfig_dir=`$BREW --env --plain openssl | sed -n 's/PKG_CONFIG_PATH: //p'`
		PKG_CONFIG_PATH="$openssl_pkgconfig_dir:$PKG_CONFIG_PATH"
	fi
	PKG_CHECK_MODULES(OPENSSL, openssl,
	    [
		#
		# We found OpenSSL/libressl.
		#
		HAVE_OPENSSL=yes
		REQUIRES_PRIVATE="$REQUIRES_PRIVATE openssl"
	    ])
	PKG_CONFIG_PATH="$save_PKG_CONFIG_PATH"

	#
	# If it wasn't found, and we have Homebrew installed, see
	# if it's in Homebrew.
	#
	if test "x$HAVE_OPENSSL" != "xyes" -a -n "$BREW"; then
		AC_MSG_CHECKING(for openssl in Homebrew)
		#
		# The brew man page lies when it speaks of
		# $BREW --prefix --installed <formula>
		# outputting nothing.  In Homebrew 3.3.16,
		# it produces output regardless of whether
		# the formula is installed or not, so we
		# send the standard output and error to
		# the bit bucket.
		#
		if $BREW --prefix --installed openssl >/dev/null 2>&1; then
			#
			# Yes.  Get the include directory and library
			# directory.  (No, we can't just assume it's
			# under /usr/local; Homebrew have conveniently
			# chosen to put it under /opt/homebrew on ARM.)
			#
			AC_MSG_RESULT(yes)
			HAVE_OPENSSL=yes
			openssl_path=`$BREW --prefix openssl`
			OPENSSL_CFLAGS="-I$openssl_path/include"
			OPENSSL_LIBS="-L$openssl_path/lib -lssl -lcrypto"
			OPENSSL_LIBS_STATIC="-L$openssl_path/lib -lssl -lcrypto"
			OPENSSL_LIBS_PRIVATE="-L$openssl_path/lib -lssl -lcrypto"
		else
			AC_MSG_RESULT(no)
		fi
	fi

	#
	# If it wasn't found, and /usr/local/include and /usr/local/lib
	# exist, check if it's in /usr/local.  (We check whether they
	# exist because, if they don't exist, the compiler will warn
	# about that and then ignore the argument, so they test
	# using just the system header files and libraries.)
	#
	# We include the standard include file to 1) make sure that
	# it's installed (if it's just a shared library for the
	# benefit of existing programs, that's not useful) and 2)
	# because SSL_library_init() is a library routine in some
	# versions and a #defined wrapper around OPENSSL_init_ssl()
	# in others.
	#
	if test "x$HAVE_OPENSSL" != "xyes" -a -d "/usr/local/include" -a -d "/usr/local/lib"; then
		AC_LBL_SAVE_CHECK_STATE
		CFLAGS="$CFLAGS -I/usr/local/include"
		LIBS="$LIBS -L/usr/local/lib -lssl -lcrypto"
		AC_MSG_CHECKING(whether we have OpenSSL/libressl in /usr/local that we can use)
		AC_TRY_LINK(
		    [
#include <openssl/ssl.h>
		    ],
		    [
SSL_library_init();
return 0;
		    ],
		    [
			AC_MSG_RESULT(yes)
			HAVE_OPENSSL=yes
			OPENSSL_CFLAGS="-I/usr/local/include"
			OPENSSL_LIBS="-L/usr/local/lib -lssl -lcrypto"
			OPENSSL_LIBS_STATIC="-L/usr/local/lib -lssl -lcrypto"
			OPENSSL_LIBS_PRIVATE="-L/usr/local/lib -lssl -lcrypto"
		    ],
		    AC_MSG_RESULT(no))
		AC_LBL_RESTORE_CHECK_STATE
	fi

	#
	# If it wasn't found, check if it's a system library.
	#
	# We include the standard include file to 1) make sure that
	# it's installed (if it's just a shared library for the
	# benefit of existing programs, that's not useful) and 2)
	# because SSL_library_init() is a library routine in some
	# versions and a #defined wrapper around OPENSSL_init_ssl()
	# in others.
	#
	if test "x$HAVE_OPENSSL" != "xyes"; then
		AC_LBL_SAVE_CHECK_STATE
		LIBS="$LIBS -lssl -lcrypto"
		AC_MSG_CHECKING(whether we have a system OpenSSL/libressl that we can use)
		AC_TRY_LINK(
		    [
#include <openssl/ssl.h>
		    ],
		    [
SSL_library_init();
return 0;
		    ],
		    [
			AC_MSG_RESULT(yes)
			HAVE_OPENSSL=yes
			OPENSSL_LIBS="-lssl -lcrypto"
			OPENSSL_LIBS_STATIC="-lssl -lcrypto"
			OPENSSL_LIBS_PRIVATE="-lssl -lcrypto"
		    ],
		    AC_MSG_RESULT(no))
		AC_LBL_RESTORE_CHECK_STATE
	fi

	#
	# OK, did we find it?
	#
	if test "x$HAVE_OPENSSL" = "xyes"; then
		AC_DEFINE([HAVE_OPENSSL], [1], [Use OpenSSL])
		V_INCLS="$V_INCLS $OPENSSL_CFLAGS"
		ADDITIONAL_LIBS="$ADDITIONAL_LIBS $OPENSSL_LIBS"
		ADDITIONAL_LIBS_STATIC="$ADDITIONAL_LIBS_STATIC $OPENSSL_LIBS_STATIC"
		LIBS_PRIVATE="$LIBS_PRIVATE $OPENSSL_LIBS_PRIVATE"
		REQUIRES_PRIVATE="$REQUIRES_PRIVATE $OPENSSL_REQUIRES_PRIVATE"
	else
		AC_MSG_NOTICE(OpenSSL not found)
	fi

	AC_DEFINE(ENABLE_REMOTE,,
	    [Define to 1 if remote packet capture is to be supported])
	REMOTE_C_SRC="$REMOTE_C_SRC pcap-new.c pcap-rpcap.c rpcap-protocol.c sockutils.c sslutils.c"
	BUILD_RPCAPD=build-rpcapd
	INSTALL_RPCAPD=install-rpcapd
	;;
*)	AC_MSG_RESULT(no)
	;;
esac

AC_MSG_CHECKING(whether to build optimizer debugging code)
AC_ARG_ENABLE(optimizer-dbg,
AS_HELP_STRING([--enable-optimizer-dbg],[build optimizer debugging code]))
if test "$enable_optimizer_dbg" = "yes"; then
	AC_DEFINE(BDEBUG,1,[Enable optimizer debugging])
fi
AC_MSG_RESULT(${enable_optimizer_dbg-no})

AC_MSG_CHECKING(whether to build parser debugging code)
AC_ARG_ENABLE(yydebug,
AS_HELP_STRING([--enable-yydebug],[build parser debugging code]))
if test "$enable_yydebug" = "yes"; then
	AC_DEFINE(YYDEBUG,1,[Enable parser debugging])
fi
AC_MSG_RESULT(${enable_yydebug-no})

#
# Do various checks for various OSes and versions of those OSes.
#
# Assume, by default, no support for shared libraries and V7/BSD
# convention for man pages (devices in section 4, file formats in
# section 5, miscellaneous info in section 7, administrative commands
# and daemons in section 8).  Individual cases can override this.
#
DYEXT="none"
MAN_DEVICES=4
MAN_FILE_FORMATS=5
MAN_MISC_INFO=7
MAN_ADMIN_COMMANDS=8
case "$host_os" in

aix*)
	dnl Workaround to enable certain features
	AC_DEFINE(_SUN,1,[define on AIX to get certain functions])

	#
	# AIX makes it fun to build shared and static libraries,
	# because they're *both* ".a" archive libraries.  We
	# build the static library for the benefit of the traditional
	# scheme of building libpcap and tcpdump in subdirectories of
	# the same directory, with tcpdump statically linked with the
	# libpcap in question, but we also build a shared library as
	# "libpcap.shareda" and install *it*, rather than the static
	# library, as "libpcap.a".
	#
	DYEXT="shareda"

	case "$V_PCAP" in

	dlpi)
		#
		# If we're using DLPI, applications will need to
		# use /lib/pse.exp if present, as we use the
		# STREAMS routines.
		#
		pseexe="/lib/pse.exp"
		AC_MSG_CHECKING(for $pseexe)
		if test -f $pseexe ; then
			AC_MSG_RESULT(yes)
			LIBS="-I:$pseexe"
		fi
		;;

	bpf)
		#
		# If we're using BPF, we need "-lodm" and "-lcfg", as
		# we use them to load the BPF module.
		#
		LIBS="-lodm -lcfg"
		;;
	esac
	;;

darwin*)
	DYEXT="dylib"
	V_CCOPT="$V_CCOPT -fno-common"
	AC_ARG_ENABLE(universal,
	AS_HELP_STRING([--disable-universal],[don't build universal on macOS]))
	if test "$enable_universal" != "no"; then
		case "$host_os" in

		darwin[[0-7]].*)
			#
			# Pre-Tiger.  Build only for 32-bit PowerPC; no
			# need for any special compiler or linker flags.
			#
			;;

		darwin8.[[0123]]|darwin8.[[0123]].*)
			#
			# Tiger, prior to Intel support.  Build
			# libraries and executables for 32-bit PowerPC
			# and 64-bit PowerPC, with 32-bit PowerPC first.
			# (I'm guessing that's what Apple does.)
			#
			# (The double brackets are needed because
			# autotools/m4 use brackets as a quoting
			# character; the double brackets turn into
			# single brackets in the generated configure
			# file.)
			#
			V_LIB_CCOPT_FAT="-arch ppc -arch ppc64"
			V_LIB_LDFLAGS_FAT="-arch ppc -arch ppc64"
			V_PROG_CCOPT_FAT="-arch ppc -arch ppc64"
			V_PROG_LDFLAGS_FAT="-arch ppc -arch ppc64"
			;;

		darwin8.[[456]]|darwin8.[[456]].*)
			#
			# Tiger, subsequent to Intel support but prior
			# to x86-64 support.  Build libraries and
			# executables for 32-bit PowerPC, 64-bit
			# PowerPC, and 32-bit x86, with 32-bit PowerPC
			# first.  (I'm guessing that's what Apple does.)
			#
			# (The double brackets are needed because
			# autotools/m4 use brackets as a quoting
			# character; the double brackets turn into
			# single brackets in the generated configure
			# file.)
			#
			V_LIB_CCOPT_FAT="-arch ppc -arch ppc64 -arch i386"
			V_LIB_LDFLAGS_FAT="-arch ppc -arch ppc64 -arch i386"
			V_PROG_CCOPT_FAT="-arch ppc -arch ppc64 -arch i386"
			V_PROG_LDFLAGS_FAT="-arch ppc -arch ppc64 -arch i386"
			;;

		darwin8.*)
			#
			# All other Tiger, so subsequent to x86-64
			# support.  Build libraries and executables for
			# 32-bit PowerPC, 64-bit PowerPC, 32-bit x86,
			# and x86-64, with 32-bit PowerPC first.  (I'm
			# guessing that's what Apple does.)
			#
			V_LIB_CCOPT_FAT="-arch ppc -arch ppc64 -arch i386 -arch x86_64"
			V_LIB_LDFLAGS_FAT="-arch ppc -arch ppc64 -arch i386 -arch x86_64"
			V_PROG_CCOPT_FAT="-arch ppc -arch ppc64 -arch i386 -arch x86_64"
			V_PROG_LDFLAGS_FAT="-arch ppc -arch ppc64 -arch i386 -arch x86_64"
			;;

		darwin9.*)
			#
			# Leopard.  Build libraries for 32-bit PowerPC,
			# 64-bit PowerPC, 32-bit x86, and x86-64, with
			# 32-bit PowerPC first, and build executables
			# for 32-bit x86 and 32-bit PowerPC, with 32-bit
			# x86 first.  (That's what Apple does.)
			#
			V_LIB_CCOPT_FAT="-arch ppc -arch ppc64 -arch i386 -arch x86_64"
			V_LIB_LDFLAGS_FAT="-arch ppc -arch ppc64 -arch i386 -arch x86_64"
			V_PROG_CCOPT_FAT="-arch i386 -arch ppc"
			V_PROG_LDFLAGS_FAT="-arch i386 -arch ppc"
			;;

		darwin10.*)
			#
			# Snow Leopard.  Build libraries for x86-64,
			# 32-bit x86, and 32-bit PowerPC, with x86-64
			# first, and build executables for x86-64 and
			# 32-bit x86, with x86-64 first.  (That's what
			# Apple does, even though Snow Leopard doesn't
			# run on PPC, so PPC libpcap runs under Rosetta,
			# and Rosetta doesn't support BPF ioctls, so PPC
			# programs can't do live captures.)
			#
			V_LIB_CCOPT_FAT="-arch x86_64 -arch i386 -arch ppc"
			V_LIB_LDFLAGS_FAT="-arch x86_64 -arch i386 -arch ppc"
			V_PROG_CCOPT_FAT="-arch x86_64 -arch i386"
			V_PROG_LDFLAGS_FAT="-arch x86_64 -arch i386"
			;;

		darwin1[[1-8]]*)
			#
			# Post-Snow Leopard, pre-Catalina.  Build
			# libraries for x86-64 and 32-bit x86, with
			# x86-64 first, and build executables only for
			# x86-64.  (That's what Apple does.)  This
			# requires no special flags for programs.
			#
			# We check whether we *can* build for i386 and,
			# if not, suggest that the user install the
			# /usr/include headers if they want to build
			# fat.
			#
			AC_MSG_CHECKING(whether building for 32-bit x86 is supported)
			AC_LBL_SAVE_CHECK_STATE
			CFLAGS="$CFLAGS -arch i386"
			AC_TRY_LINK(
			    [],
			    [return 0;],
			    [
				AC_MSG_RESULT(yes)
				V_LIB_CCOPT_FAT="-arch x86_64"
				V_LIB_LDFLAGS_FAT="-arch x86_64"

				#
				# OpenSSL installation on macOS seems
				# to install only the libs for 64-bit
				# x86 - at least that's what Brew does:
				# only configure 32-bit builds if we
				# don't have OpenSSL.
				#
				if test "$HAVE_OPENSSL" != yes; then
					V_LIB_CCOPT_FAT="$V_LIB_CCOPT_FAT -arch i386"
					V_LIB_LDFLAGS_FAT="$V_LIB_LDFLAGS_FAT -arch i386"
				fi
			    ],
			    [
				AC_MSG_RESULT(no)
				V_LIB_CCOPT_FAT="-arch x86_64"
				V_LIB_LDFLAGS_FAT="-arch x86_64"
				case "$host_os" in

				darwin18.*)
					#
					# Mojave; you need to install the
					# /usr/include headers to get
					# 32-bit x86 builds to work.
					#
					AC_MSG_WARN([Compiling for 32-bit x86 gives an error; try installing the command-line tools and, after that, installing the /usr/include headers from the /Library/Developer/CommandLineTools/Packages/macOS_SDK_headers_for_macOS_10.14.pkg package])
					;;

				*)
					#
					# Pre-Mojave; the command-line
					# tools should be sufficient to
					# enable 32-bit x86 builds.
					#
					AC_MSG_WARN([Compiling for 32-bit x86 gives an error; try installing the command-line tools])
					;;
				esac
			    ])
			AC_LBL_RESTORE_CHECK_STATE
			;;

		darwin19*)
			#
			# Catalina.  Build libraries and executables
			# only for x86-64.  (That's what Apple does;
			# 32-bit x86 binaries are not supported on
			# Catalina.)
			#
			V_LIB_CCOPT_FAT="-arch x86_64"
			V_LIB_LDFLAGS_FAT="-arch x86_64"
			V_PROG_CCOPT_FAT="-arch x86_64"
			V_PROG_LDFLAGS_FAT="-arch x86_64"
			;;

		darwin*)
			#
			# Post-Catalina.  Build libraries and
			# executables for x86-64 and ARM64.
			# (That's what Apple does, except they
			# build for arm64e, which may include
			# some of the pointer-checking extensions.)
			#
			# If we're building with libssl, make sure
			# we can build fat with it (i.e., that it
			# was built fat); if we can't, don't set
			# the target architectures, and just
			# build for the host we're on.
			#
			# Otherwise, just add both of them.
			#
			if test "$HAVE_OPENSSL" = yes; then
				AC_MSG_CHECKING(whether building fat with libssl is supported)
				AC_LBL_SAVE_CHECK_STATE
				CFLAGS="$CFLAGS -arch x86_64 -arch arm64"
				LDFLAGS="$LDFLAGS $OPENSSL_LIBS"
				AC_TRY_LINK(
				    [
					#include <openssl/ssl.h>
				    ],
				    [
					SSL_library_init();
					return 0;
				    ],
				    [
					AC_MSG_RESULT(yes)
					V_LIB_CCOPT_FAT="-arch x86_64 -arch arm64"
					V_LIB_LDFLAGS_FAT="-arch x86_64 -arch arm64"
					V_PROG_CCOPT_FAT="-arch x86_64 -arch arm64"
					V_PROG_LDFLAGS_FAT="-arch x86_64 -arch arm64"
				    ],
				    [AC_MSG_RESULT(no)]
				)
				AC_LBL_RESTORE_CHECK_STATE
			else
				V_LIB_CCOPT_FAT="-arch x86_64 -arch arm64"
				V_LIB_LDFLAGS_FAT="-arch x86_64 -arch arm64"
				V_PROG_CCOPT_FAT="-arch x86_64 -arch arm64"
				V_PROG_LDFLAGS_FAT="-arch x86_64 -arch arm64"
			fi
			;;
		esac
	fi
	;;

hpux9*)
	AC_DEFINE(HAVE_HPUX9,1,[on HP-UX 9.x])

	#
	# Use System V conventions for man pages.
	#
	MAN_ADMIN_COMMANDS=1m
	MAN_FILE_FORMATS=4
	MAN_MISC_INFO=5
	;;

hpux10.0*)

	#
	# Use System V conventions for man pages.
	#
	MAN_ADMIN_COMMANDS=1m
	MAN_FILE_FORMATS=4
	MAN_MISC_INFO=5
	;;

hpux10.1*)

	#
	# Use System V conventions for man pages.
	#
	MAN_ADMIN_COMMANDS=1m
	MAN_FILE_FORMATS=4
	MAN_MISC_INFO=5
	;;

hpux*)
	dnl HPUX 10.20 and above is similar to HPUX 9, but
	dnl not the same....
	dnl
	dnl XXX - DYEXT should be set to "sl" if this is building
	dnl for 32-bit PA-RISC, but should be left as "so" for
	dnl 64-bit PA-RISC or, I suspect, IA-64.
	AC_DEFINE(HAVE_HPUX10_20_OR_LATER,1,[on HP-UX 10.20 or later])
	if test "`uname -m`" = "ia64"; then
		DYEXT="so"
	else
		DYEXT="sl"
	fi

	#
	# "-b" builds a shared library; "+h" sets the soname.
	#
	SHLIB_OPT="-b"
	SONAME_OPT="+h"

	#
	# Use System V conventions for man pages.
	#
	MAN_FILE_FORMATS=4
	MAN_MISC_INFO=5
	;;

irix*)
	#
	# Use IRIX conventions for man pages; they're the same as the
	# System V conventions, except that they use section 8 for
	# administrative commands and daemons.
	#
	MAN_FILE_FORMATS=4
	MAN_MISC_INFO=5
	;;

linux*|freebsd*|netbsd*|openbsd*|dragonfly*|kfreebsd*|gnu*|haiku*|midipix*)
	DYEXT="so"
	;;

osf*)
	DYEXT="so"

	#
	# DEC OSF/1, a/k/a Digital UNIX, a/k/a Tru64 UNIX.
	# Use Tru64 UNIX conventions for man pages; they're the same as
	# the System V conventions except that they use section 8 for
	# administrative commands and daemons.
	#
	MAN_FILE_FORMATS=4
	MAN_MISC_INFO=5
	MAN_DEVICES=7
	;;

sinix*)
	AC_MSG_CHECKING(if SINIX compiler defines sinix)
	AC_CACHE_VAL(ac_cv_cc_sinix_defined,
		AC_TRY_COMPILE(
		    [],
		    [int i = sinix;],
		    ac_cv_cc_sinix_defined=yes,
		    ac_cv_cc_sinix_defined=no))
	    AC_MSG_RESULT($ac_cv_cc_sinix_defined)
	    if test $ac_cv_cc_sinix_defined = no ; then
		    AC_DEFINE(sinix,1,[on sinix])
	    fi
	;;

solaris*)
	AC_DEFINE(HAVE_SOLARIS,1,[On solaris])

	DYEXT="so"

	#
	# Make sure errno is thread-safe, in case we're called in
	# a multithreaded program.  We don't guarantee that two
	# threads can use the *same* pcap_t safely, but the
	# current version does guarantee that you can use different
	# pcap_t's in different threads, and even that pcap_compile()
	# is thread-safe (it wasn't thread-safe in some older versions).
	#
	V_CCOPT="$V_CCOPT -D_TS_ERRNO"

	case "`uname -r`" in

	5.12)
		;;

	*)
		#
		# Use System V conventions for man pages.
		#
		MAN_ADMIN_COMMANDS=1m
		MAN_FILE_FORMATS=4
		MAN_MISC_INFO=5
		MAN_DEVICES=7D
	esac
	;;
esac
AC_SUBST(V_LIB_CCOPT_FAT)
AC_SUBST(V_LIB_LDFLAGS_FAT)
AC_SUBST(V_PROG_CCOPT_FAT)
AC_SUBST(V_PROG_LDFLAGS_FAT)
AC_SUBST(DYEXT)
AC_SUBST(MAN_DEVICES)
AC_SUBST(MAN_FILE_FORMATS)
AC_SUBST(MAN_MISC_INFO)
AC_SUBST(MAN_ADMIN_COMMANDS)

AC_ARG_ENABLE(shared,
AS_HELP_STRING([--enable-shared],[build shared libraries @<:@default=no@:>@]))
test "x$enable_shared" != "xyes" && DYEXT="none"

AC_PROG_RANLIB
AC_CHECK_TOOL([AR], [ar])

AC_PROG_LN_S
AC_SUBST(LN_S)

AC_LBL_DEVEL(V_CCOPT)

#
# Check to see if the sockaddr struct has the 4.4 BSD sa_len member.
#
AC_CHECK_MEMBERS([struct sockaddr.sa_len],,,
    [
	#include <sys/types.h>
	#include <sys/socket.h>
    ])

#
# Check to see if there's a sockaddr_storage structure.
#
AC_CHECK_TYPES(struct sockaddr_storage,,,
    [
	#include <sys/types.h>
	#include <sys/socket.h>
    ])

#
# Check to see if the dl_hp_ppa_info_t struct has the HP-UX 11.00
# dl_module_id_1 member.
#
# NOTE: any failure means we conclude that it doesn't have that member,
# so if we don't have DLPI, don't have a <sys/dlpi_ext.h> header, or
# have one that doesn't declare a dl_hp_ppa_info_t type, we conclude
# it doesn't have that member (which is OK, as either we won't be
# using code that would use that member, or we wouldn't compile in
# any case).
#
AC_CHECK_MEMBERS([dl_hp_ppa_info_t.dl_module_id_1],,,
    [
	#include <sys/types.h>
	#include <sys/dlpi.h>
	#include <sys/dlpi_ext.h>
    ])

#
# Various Linux-specific mechanisms.
#
AC_ARG_ENABLE([usb],
[AS_HELP_STRING([--enable-usb],[enable USB capture support @<:@default=no@:>@])],
    [],
    [enable_usb=no])

#
# If somebody requested an XXX-only pcap, that doesn't include
# additional mechanisms.
#
if test "xxx_only" != yes; then
  case "$host_os" in
  linux*)
    dnl check for USB sniffing support
    AC_MSG_CHECKING(for Linux usbmon USB sniffing support)
    if test "x$enable_usb" != "xno" ; then
      AC_DEFINE(PCAP_SUPPORT_LINUX_USBMON, 1, [target host supports Linux usbmon for USB sniffing])
      MODULE_C_SRC="$MODULE_C_SRC pcap-usb-linux.c"
      AC_MSG_RESULT(yes)
      #
      # Note: if the directory for special files is *EVER* somewhere
      # other than the UN*X standard of /dev (which will break any
      # software that looks for /dev/null or /dev/tty, for example,
      # so doing that is *REALLY* not a good idea), please provide
      # some mechanism to determine that directory at *run time*,
      # rather than *configure time*, so that it works when doinga
      # a cross-build, and that works with *multiple* distributions,
      # with our without udev, and with multiple versions of udev,
      # with udevinfo or udevadm or any other mechanism to get the
      # special files directory.
      #
      # Do we have a version of <linux/compiler.h> available?
      # If so, we might need it for <linux/usbdevice_fs.h>.
      #
      AC_CHECK_HEADERS(linux/compiler.h)
      if test "$ac_cv_header_linux_compiler_h" = yes; then
        #
        # Yes - include it when testing for <linux/usbdevice_fs.h>.
        #
        AC_CHECK_HEADERS(linux/usbdevice_fs.h,,,[#include <linux/compiler.h>])
      else
        AC_CHECK_HEADERS(linux/usbdevice_fs.h)
      fi
      if test "$ac_cv_header_linux_usbdevice_fs_h" = yes; then
        #
        # OK, does it define bRequestType?  Older versions of the kernel
        # define fields with names like "requesttype, "request", and
        # "value", rather than "bRequestType", "bRequest", and
        # "wValue".
        #
        AC_CHECK_MEMBERS([struct usbdevfs_ctrltransfer.bRequestType],,,
          [
            AC_INCLUDES_DEFAULT
            #ifdef HAVE_LINUX_COMPILER_H
            #include <linux/compiler.h>
            #endif
            #include <linux/usbdevice_fs.h>
          ])
      fi
    else
      AC_MSG_RESULT(no)
    fi

    #
    # Life's too short to deal with trying to get this to compile
    # if you don't get the right types defined with
    # __KERNEL_STRICT_NAMES getting defined by some other include.
    #
    # Check whether the includes Just Work.  If not, don't turn on
    # netfilter support.
    #
    AC_MSG_CHECKING(whether we can compile the netfilter support)
    AC_CACHE_VAL(ac_cv_netfilter_can_compile,
      AC_TRY_COMPILE([
AC_INCLUDES_DEFAULT
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/types.h>

#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_log.h>
#include <linux/netfilter/nfnetlink_queue.h>],
        [],
        ac_cv_netfilter_can_compile=yes,
        ac_cv_netfilter_can_compile=no))
    AC_MSG_RESULT($ac_cv_netfilter_can_compile)
    if test $ac_cv_netfilter_can_compile = yes ; then
      AC_DEFINE(PCAP_SUPPORT_NETFILTER, 1,
        [target host supports netfilter sniffing])
      MODULE_C_SRC="$MODULE_C_SRC pcap-netfilter-linux.c"
    fi
    ;;
  esac
fi
AC_SUBST(PCAP_SUPPORT_LINUX_USBMON)
AC_SUBST(PCAP_SUPPORT_NETFILTER)

AC_ARG_ENABLE([netmap],
[AS_HELP_STRING([--enable-netmap],[enable netmap support @<:@default=yes, if support available@:>@])],
    [],
    [enable_netmap=yes])

if test "x$enable_netmap" != "xno" ; then
	#
	# Check whether net/netmap_user.h is usable if NETMAP_WITH_LIBS is
	# defined; it's not usable on DragonFly BSD 4.6 if NETMAP_WITH_LIBS
	# is defined, for example, as it includes a non-existent malloc.h
	# header.
	#
	AC_MSG_CHECKING(whether we can compile the netmap support)
	AC_CACHE_VAL(ac_cv_net_netmap_user_can_compile,
	  AC_TRY_COMPILE([
AC_INCLUDES_DEFAULT
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>],
	    [],
	    ac_cv_net_netmap_user_can_compile=yes,
	    ac_cv_net_netmap_user_can_compile=no))
	AC_MSG_RESULT($ac_cv_net_netmap_user_can_compile)
	if test $ac_cv_net_netmap_user_can_compile = yes ; then
	  AC_DEFINE(PCAP_SUPPORT_NETMAP, 1,
	    [target host supports netmap])
	    MODULE_C_SRC="$MODULE_C_SRC pcap-netmap.c"
	fi
	AC_SUBST(PCAP_SUPPORT_NETMAP)
fi

# Check for DPDK support.
AC_ARG_WITH([dpdk],
AS_HELP_STRING([--with-dpdk@<:@=DIR@:>@],[include DPDK support (located in directory DIR, if supplied).  @<:@default=yes, if present@:>@]),
[
	if test "$withval" = no
	then
		# User doesn't want DPDK support.
		want_dpdk=no
	elif test "$withval" = yes
	then
		# User wants DPDK support but hasn't specified a directory.
		want_dpdk=yes
	else
		# User wants DPDK support and has specified a directory,
		# so use the provided value.
		want_dpdk=yes
		dpdk_dir=$withval
	fi
],[
	if test "$V_PCAP" = dpdk; then
		# User requested DPDK-only libpcap, so we'd better have
		# the DPDK API.
		want_dpdk=yes
	elif test "xxx_only" = yes; then
		# User requested something-else-only pcap, so they don't
		# want DPDK support.
		want_dpdk=no
	else
		#
		# Use DPDK API if present, otherwise don't
		#
		want_dpdk=ifpresent
	fi
])

if test "$want_dpdk" != no; then
	#
	# The user didn't explicitly say they don't want DPDK,
	# so see if we have it.
	#
	# We only try to find it using pkg-config; DPDK is *SO*
	# complicated - DPDK 19.02, for example, has about 117(!)
	# libraries, and the precise set of libraries required has
	# changed over time - so attempting to guess which libraries
	# you need, and hardcoding that in an attempt to find the
	# libraries without DPDK, rather than relying on DPDK to
	# tell you, with a .pc file, what libraries are needed,
	# is *EXTREMELY* fragile and has caused some bug reports,
	# so we're just not going to do it.
	#
	# If that causes a problem, the only thing we will do is
	# accept an alternative way of finding the appropriate
	# library set for the installed version of DPDK that is
	# as robust as pkg-config (i.e., it had better work as well
	# as pkg-config with *ALL* versions of DPDK that provide a
	# libdpdk.pc file).
	#
	# If --with-dpdk={path} was specified, add {path}/pkgconfig
	# to PKG_CONFIG_PATH, so we look for the .pc file there,
	# first.
	#
	save_PKG_CONFIG_PATH="$PKG_CONFIG_PATH"
	if test -n "$dpdk_dir"; then
		PKG_CONFIG_PATH="$dpdk_dir:$PKG_CONFIG_PATH"
	fi
	PKG_CHECK_MODULES(DPDK, libdpdk,
	    [
		found_dpdk=yes
	    ])
	PKG_CONFIG_PATH="$save_PKG_CONFIG_PATH"

	#
	# Did we find DPDK?
	#
	if test "$found_dpdk" = yes; then
		#
		# Found it.
		#
		# We call rte_eth_dev_count_avail(), and older versions
		# of DPDK didn't have it, so check for it.
		#
		AC_LBL_SAVE_CHECK_STATE
		CFLAGS="$CFLAGS $DPDK_CFLAGS"
		LIBS="$LIBS $DPDK_LIBS"
		AC_CHECK_FUNC(rte_eth_dev_count_avail)
		AC_LBL_RESTORE_CHECK_STATE
	fi

	if test "$ac_cv_func_rte_eth_dev_count_avail" = yes; then
		#
		# We found a usable DPDK.
		#
		# Check whether the rte_ether.h file defines
		# struct ether_addr or struct rte_ether_addr.
		#
		# ("API compatibility?  That's for losers!")
		#
		AC_LBL_SAVE_CHECK_STATE
		CFLAGS="$CFLAGS $DPDK_CFLAGS"
		LIBS="$LIBS $DPDK_LIBS"
		AC_CHECK_TYPES(struct rte_ether_addr,,,
		    [
			#include <rte_ether.h>
		    ])
		AC_LBL_RESTORE_CHECK_STATE

		#
		# We can build with DPDK.
		#
		V_INCLS="$V_INCLS $DPDK_CFLAGS"
		ADDITIONAL_LIBS="$ADDITIONAL_LIBS $DPDK_LIBS"
		ADDITIONAL_LIBS_STATIC="$ADDITIONAL_LIBS_STATIC $DPDK_LIBS_STATIC"
		REQUIRES_PRIVATE="$REQUIRES_PRIVATE libdpdk"
		AC_DEFINE(PCAP_SUPPORT_DPDK, 1, [target host supports DPDK])
		if test $V_PCAP != dpdk ; then
			MODULE_C_SRC="$MODULE_C_SRC pcap-dpdk.c"
		fi
	else
		#
		# We didn't find a usable DPDK.
		# If we required it (with --with-dpdk or --with-pcap=dpdk),
		# fail with an appropriate message telling the user what
		# the problem was, otherwise note the problem with a
		# warning.
		#
		if test "$found_dpdk" != yes; then
			#
			# Not found with pkg-config.  Note that we
			# require that DPDK must be findable with
			# pkg-config.
			#
			if test "$V_PCAP" = dpdk; then
				#
				# User requested DPDK-only capture support.
				#
				AC_MSG_ERROR(
[DPDK support requested with --with-pcap=dpdk, but
we couldn't find DPDK with pkg-config.  Make sure that pkg-config is
installed, that DPDK 18.02.2 or later is installed, and that DPDK
provides a .pc file.])
			fi

			if test "$want_dpdk" = yes; then
				#
				# User requested that libpcap include
				# DPDK capture support.
				#
				AC_MSG_ERROR(
[DPDK support requested with --with-dpdk, but we
couldn't find DPDK with pkg-config.  Make sure that pkg-config
is installed, that DPDK 18.02.2 or later is installed, and that
DPDK provides .pc file.])
			fi

			#
			# User didn't indicate whether they wanted DPDK
			# or not; just warn why we didn't find it.
			#
			AC_MSG_WARN(
[We couldn't find DPDK with pkg-config.  If
you want DPDK support, make sure that pkg-config is installed,
that DPDK 18.02.2 or later is installed, and that DPDK provides a
.pc file.])
		elif test "$ac_cv_func_rte_eth_dev_count_avail" != yes; then
			#
			# Found with pkg-config, but we couldn't compile
			# a program that calls rte_eth_dev_count(); we
			# probably have the developer package installed,
			# but don't have a sufficiently recent version
			# of DPDK.  Note that we need a sufficiently
			# recent version of DPDK.
			#
			if test "$V_PCAP" = dpdk; then
				#
				# User requested DPDK-only capture support.
				#
				AC_MSG_ERROR(
[DPDK support requested with --with-pcap=dpdk, but we
can't compile libpcap with DPDK.  Make sure that DPDK 18.02.2 or later
is installed.])
			fi

			if test "$want_dpdk" = yes; then
				#
				# User requested that libpcap include
				# DPDK capture support.
				#
				AC_MSG_ERROR(
[DPDK support requested with --with-dpdk, but
we can't compile libpcap with DPDK.  Make sure that DPDK 18.02.2
or later is DPDK is installed.])
			fi

			#
			# User didn't indicate whether they wanted DPDK
			# or not; just warn why we didn't find it.
			#
			AC_MSG_WARN(
[DPDK was found, but we can't compile libpcap with it.
Make sure that DPDK 18.02.2 or later is installed.])
		fi
	fi
fi
AC_SUBST(PCAP_SUPPORT_DPDK)

AC_ARG_ENABLE([bluetooth],
[AS_HELP_STRING([--enable-bluetooth],[enable Bluetooth support @<:@default=no@:>@])],
    [],
    [enable_bluetooth=no])

if test "xxx_only" = yes; then
	# User requested something-else-only pcap, so they don't
	# want Bluetooth support.
	enable_bluetooth=no
fi

if test "x$enable_bluetooth" != "xno" ; then
	dnl check for Bluetooth sniffing support
	case "$host_os" in
	linux*)
		AC_CHECK_HEADER(bluetooth/bluetooth.h,
		    [
			#
			# We have bluetooth.h, so we support Bluetooth
			# sniffing.
			#
			AC_DEFINE(PCAP_SUPPORT_BT, 1, [target host supports Bluetooth sniffing])
			MODULE_C_SRC="$MODULE_C_SRC pcap-bt-linux.c"
			AC_MSG_NOTICE(Bluetooth sniffing is supported)
			ac_lbl_bluetooth_available=yes

			#
			# OK, does struct sockaddr_hci have an hci_channel
			# member?
			#
			AC_CHECK_MEMBERS([struct sockaddr_hci.hci_channel],
			    [
				#
				# Yes; is HCI_CHANNEL_MONITOR defined?
				#
				AC_MSG_CHECKING(if HCI_CHANNEL_MONITOR is defined)
				AC_CACHE_VAL(ac_cv_lbl_hci_channel_monitor_is_defined,
				    AC_TRY_COMPILE(
					[
					    #include <bluetooth/bluetooth.h>
					    #include <bluetooth/hci.h>
					],
					[
					    u_int i = HCI_CHANNEL_MONITOR;
					],
					[
					    AC_MSG_RESULT(yes)
					    AC_DEFINE(PCAP_SUPPORT_BT_MONITOR,,
					      [target host supports Bluetooth Monitor])
					    MODULE_C_SRC="$MODULE_C_SRC pcap-bt-monitor-linux.c"
					],
					[
					    AC_MSG_RESULT(no)
					]))
			    ],,
			    [
				#include <bluetooth/bluetooth.h>
				#include <bluetooth/hci.h>
			    ])
		    ],
		    [
			#
			# We don't have bluetooth.h, so we don't support
			# Bluetooth sniffing.
			#
			if test "x$enable_bluetooth" = "xyes" ; then
				AC_MSG_ERROR(Bluetooth sniffing is not supported; install bluez-lib devel to enable it)
			else
				AC_MSG_NOTICE(Bluetooth sniffing is not supported; install bluez-lib devel to enable it)
			fi
		    ])
		;;
	*)
		if test "x$enable_bluetooth" = "xyes" ; then
			AC_MSG_ERROR(no Bluetooth sniffing support implemented for $host_os)
		else
			AC_MSG_NOTICE(no Bluetooth sniffing support implemented for $host_os)
		fi
		;;
	esac
	AC_SUBST(PCAP_SUPPORT_BT)
fi

AC_ARG_ENABLE([dbus],
[AS_HELP_STRING([--enable-dbus],[enable D-Bus capture support @<:@default=no@:>@])],
    [],
    [enable_dbus=no])

if test "xxx_only" = yes; then
	# User requested something-else-only pcap, so they don't
	# want D-Bus support.
	enable_dbus=no
fi

if test "x$enable_dbus" != "xno"; then
	if test "x$enable_dbus" = "xyes"; then
		case "$host_os" in

		darwin*)
			#
			# We don't support D-Bus sniffing on macOS; see
			#
			# https://bugs.freedesktop.org/show_bug.cgi?id=74029
			#
			# The user requested it, so fail.
			#
			AC_MSG_ERROR([Due to freedesktop.org bug 74029, D-Bus capture support is not available on macOS])
		esac
	else
		case "$host_os" in

		darwin*)
			#
			# We don't support D-Bus sniffing on macOS; see
			#
			# https://bugs.freedesktop.org/show_bug.cgi?id=74029
			#
			# The user dind't explicitly request it, so just
			# silently refuse to enable it.
			#
			enable_dbus="no"
			;;
		esac
	fi
fi

if test "x$enable_dbus" != "xno"; then
	PKG_CHECK_MODULES(DBUS, dbus-1,
	    [
		AC_LBL_SAVE_CHECK_STATE
		CFLAGS="$CFLAGS $DBUS_CFLAGS"
		LIBS="$LIBS $DBUS_LIBS"
		AC_MSG_CHECKING(whether the D-Bus library defines dbus_connection_read_write)
		AC_TRY_LINK(
		    [#include <string.h>

		     #include <time.h>
		     #include <sys/time.h>

		     #include <dbus/dbus.h>],
		    [return dbus_connection_read_write(NULL, 0);],
		    [
			AC_MSG_RESULT([yes])
			AC_DEFINE(PCAP_SUPPORT_DBUS, 1, [support D-Bus sniffing])
			MODULE_C_SRC="$MODULE_C_SRC pcap-dbus.c"
			V_INCLS="$V_INCLS $DBUS_CFLAGS"
			ADDITIONAL_LIBS="$ADDITIONAL_LIBS $DBUS_LIBS"
			ADDITIONAL_LIBS_STATIC="$ADDITIONAL_LIBS_STATIC $DBUS_LIBS_STATIC"
			REQUIRES_PRIVATE="$REQUIRES_PRIVATE dbus-1"
		    ],
		    [
			AC_MSG_RESULT([no])
			if test "x$enable_dbus" = "xyes"; then
			    AC_MSG_ERROR([--enable-dbus was given, but the D-Bus library doesn't define dbus_connection_read_write()])
			fi
		     ])
		AC_LBL_RESTORE_CHECK_STATE
	    ],
	    [
		if test "x$enable_dbus" = "xyes"; then
			AC_MSG_ERROR([--enable-dbus was given, but the dbus-1 package is not installed])
		fi
	    ])
	AC_SUBST(PCAP_SUPPORT_DBUS)
fi

AC_ARG_ENABLE([rdma],
[AS_HELP_STRING([--enable-rdma],[enable RDMA capture support @<:@default=yes, if support available@:>@])],
    [],
    [enable_rdma=ifavailable])

if test "xxx_only" = yes; then
	# User requested something-else-only pcap, so they don't
	# want RDMA support.
	enable_rdma=no
fi

if test "x$enable_rdma" != "xno"; then
	PKG_CHECK_MODULES(LIBIBVERBS, libibverbs,
	    [
		found_libibverbs=yes
		LIBIBVERBS_REQUIRES_PRIVATE="libibverbs"
	    ])

	if test "x$found_libibverbs" != "xyes"; then
		AC_CHECK_LIB(ibverbs, ibv_get_device_list,
		    [
			found_libibverbs=yes
			LIBIBVERBS_CFLAGS=""
			LIBIBVERBS_LIBS="-libverbs"
			# XXX - at least on Ubuntu 20.04, there are many more
			# libraries needed; is there any platform where
			# libibverbs is available but where pkg-config isn't
			# available or libibverbs doesn't use it?  If not,
			# we should only use pkg-config for it.
			LIBIBVERBS_LIBS_STATIC="-libverbs"
			LIBIBVERBS_LIBS_PRIVATE="-libverbs"
		    ]
		)
	fi

	if test "x$found_libibverbs" = "xyes"; then
		AC_LBL_SAVE_CHECK_STATE
		CFLAGS="$CFLAGS $LIBIBVERBS_CFLAGS"
		LIBS="$LIBS $LIBIBVERBS_LIBS"
		AC_CHECK_HEADER(infiniband/verbs.h, [
			#
			# ibv_create_flow may be defined as a static inline
			# function in infiniband/verbs.h, so we can't
			# use AC_CHECK_LIB.
			#
			# Too bad autoconf has no AC_SYMBOL_EXISTS()
			# macro that works like CMake's check_symbol_exists()
			# function, to check do a compile check like
			# this (they do a clever trick to avoid having
			# to know the function's signature).
			#
			AC_MSG_CHECKING(whether libibverbs defines ibv_create_flow)
			AC_TRY_LINK(
				[
					#include <infiniband/verbs.h>
				],
				[
					(void) ibv_create_flow((struct ibv_qp *) NULL,
							       (struct ibv_flow_attr *) NULL);
				],
				[
					AC_MSG_RESULT([yes])
					found_usable_libibverbs=yes
				],
				[
					AC_MSG_RESULT([no])
				]
			)
		])
		AC_LBL_RESTORE_CHECK_STATE
	fi

	if test "x$found_usable_libibverbs" = "xyes"
	then
		AC_DEFINE(PCAP_SUPPORT_RDMASNIFF, , [target host supports RDMA sniffing])
		MODULE_C_SRC="$MODULE_C_SRC pcap-rdmasniff.c"
		CFLAGS="$LIBIBVERBS_CFLAGS $CFLAGS"
		ADDITIONAL_LIBS="$LIBIBVERBS_LIBS $ADDITIONAL_LIBS"
		ADDITIONAL_LIBS_STATIC="$LIBIBVERBS_LIBS_STATIC $ADDITIONAL_LIBS_STATIC"
		LIBS_PRIVATE="$LIBIBVERBS_LIBS_PRIVATE $LIBS_PRIVATE"
		REQUIRES_PRIVATE="$REQUIRES_PRIVATE $LIBIBVERBS_REQUIRES_PRIVATE"
	fi
	AC_SUBST(PCAP_SUPPORT_RDMASNIFF)
fi

#
# If this is a platform where we need to have the .pc file and
# pcap-config script supply an rpath option to specify the directory
# in which the libpcap shared library is installed, and the install
# prefix /usr (meaning we're not installing a system library), provide
# the rpath option.
#
# (We must check $prefix, as $libdir isn't necessarily /usr/lib in this
# case - for example, Linux distributions for 64-bit platforms that
# also provide support for binaries for a 32-bit version of the
# platform may put the 64-bit libraries, the 32-bit libraries, or both
# in directories other than /usr/lib.)
#
# In AIX, do we have to do this?
#
# In Darwin-based OSes, the full paths of the shared libraries with
# which the program was linked are stored in the executable, so we don't
# need to provide an rpath option.
#
# With the HP-UX linker, directories specified with -L are, by default,
# added to the run-time search path, so we don't need to supply them.
#
# For Tru64 UNIX, "-rpath" works with DEC's^WCompaq's^WHP's C compiler
# for Alpha, but isn't documented as working with GCC, and no GCC-
# compatible option is documented as working with the DEC compiler.
# If anybody needs this on Tru64/Alpha, they're welcome to figure out a
# way to make it work.
#
# This must *not* depend on the compiler, as, on platforms where there's
# a GCC-compatible compiler and a vendor compiler, we need to work with
# both.
#
if test "$prefix" != "/usr"; then
	case "$host_os" in

	freebsd*|netbsd*|openbsd*|dragonfly*|linux*|haiku*|midipix*|gnu*)
		#
		# Platforms where the "native" C compiler is GCC or
		# accepts compatible command-line arguments, and the
		# "native" linker is the GNU linker or accepts
		# compatible command-line arguments.
		#
		RPATH="-Wl,-rpath,\${libdir}"
		;;

	solaris*)
		#
		# Sun/Oracle's linker, the GNU linker, and
		# GNU-compatible linkers all support -R.
		#
		RPATH="-Wl,-R,\${libdir}"
		;;
	esac
fi

AC_PROG_INSTALL

AC_CONFIG_HEADER(config.h)

AC_SUBST(V_SHLIB_CCOPT)
AC_SUBST(V_SHLIB_CMD)
AC_SUBST(V_SHLIB_OPT)
AC_SUBST(V_SONAME_OPT)
AC_SUBST(RPATH)
AC_SUBST(ADDLOBJS)
AC_SUBST(ADDLARCHIVEOBJS)
AC_SUBST(PLATFORM_C_SRC)
AC_SUBST(PLATFORM_CXX_SRC)
AC_SUBST(MODULE_C_SRC)
AC_SUBST(REMOTE_C_SRC)
AC_SUBST(PTHREAD_LIBS)
AC_SUBST(BUILD_RPCAPD)
AC_SUBST(INSTALL_RPCAPD)
AC_SUBST(RPCAPD_LIBS)

#
# We're done with configuration operations; add ADDITIONAL_LIBS and
# ADDITIONAL_LIBS_STATIC to LIBS and LIBS_STATIC, respectively.
#
LIBS="$ADDITIONAL_LIBS $LIBS"
LIBS_STATIC="$ADDITIONAL_LIBS_STATIC $LIBS_STATIC"

AC_OUTPUT_COMMANDS([if test -f .devel; then
	echo timestamp > stamp-h
	cat $srcdir/Makefile-devel-adds >> Makefile
	make depend || exit 1
fi])
AC_OUTPUT(Makefile grammar.y pcap-filter.manmisc pcap-linktype.manmisc
	pcap-tstamp.manmisc pcap-savefile.manfile pcap.3pcap
	pcap_compile.3pcap pcap_datalink.3pcap pcap_dump_open.3pcap
	pcap_get_tstamp_precision.3pcap pcap_list_datalinks.3pcap
	pcap_list_tstamp_types.3pcap pcap_open_dead.3pcap
	pcap_open_offline.3pcap pcap_set_immediate_mode.3pcap
	pcap_set_tstamp_precision.3pcap pcap_set_tstamp_type.3pcap
	)
exit 0
