dnl @(#) $Header$ (LBL)
dnl
dnl Copyright (c) 1994, 1995, 1996, 1997
dnl	The Regents of the University of California.  All rights reserved.
dnl
dnl Process this file with autoconf to produce a configure script.
dnl

AC_REVISION($Revision$)
AC_PREREQ(2.50)
AC_INIT(pcap.c)

AC_CANONICAL_SYSTEM

AC_LBL_C_INIT(V_CCOPT, V_INCLS, V_LIBS)
AC_LBL_C_INLINE
AC_C___ATTRIBUTE__

AC_LBL_CHECK_TYPE(u_int8_t, u_char)
AC_LBL_CHECK_TYPE(u_int16_t, u_short)
AC_LBL_CHECK_TYPE(u_int32_t, u_int)

dnl
dnl libpcap doesn't itself use <sys/ioccom.h>; however, the test program
dnl in "AC_LBL_FIXINCLUDES" in "aclocal.m4" uses it, so we have to
dnl test for it and set "HAVE_SYS_IOCCOM_H" if we have it, otherwise
dnl "AC_LBL_FIXINCLUDES" won't work on some platforms such as Solaris.
dnl
AC_CHECK_HEADERS(sys/ioccom.h sys/sockio.h ifaddrs.h limits.h)
AC_CHECK_HEADERS(netinet/if_ether.h, , , [#include <sys/types.h>
#include <sys/socket.h>])

AC_LBL_FIXINCLUDES

AC_CHECK_FUNCS(ether_hostton strerror strlcpy)

needsnprintf=no
AC_CHECK_FUNCS(vsnprintf snprintf,,
	[needsnprintf=yes])
if test $needsnprintf = yes; then
	AC_LIBOBJ(snprintf)
fi

dnl to pacify those who hate protochain insn
AC_MSG_CHECKING(if --disable-protochain option is specified)
AC_ARG_ENABLE(protochain, [  --disable-protochain    disable \"protochain\" insn])
case "x$enable_protochain" in
xyes)	enable_protochain=enabled	;;
xno)	enable_protochain=disabled	;;
x)	enable_protochain=enabled	;;
esac

if test "$enable_protochain" = "disabled"; then
	AC_DEFINE(NO_PROTOCHAIN,1,[do not use protochain])
fi
AC_MSG_RESULT(${enable_protochain})

dnl
dnl Not all versions of test support -c (character special) but it's a
dnl better way of testing since the device might be protected. So we
dnl check in our normal order using -r and then check the for the /dev
dnl guys again using -c.
dnl
dnl XXX This could be done for cross-compiling, but for now it's not.
dnl
if test -z "$with_pcap" && test "$cross_compiling" = yes; then
	AC_MSG_ERROR(pcap type not determined when cross-compiling; use --with-pcap=...)
fi
AC_ARG_WITH(pcap, [  --with-pcap=TYPE        use packet capture TYPE])
AC_MSG_CHECKING(packet capture type)
if test ! -z "$with_pcap" ; then
	V_PCAP="$withval"
elif test -r /dev/bpf0 ; then
	V_PCAP=bpf
elif test -r /usr/include/net/pfilt.h ; then
	V_PCAP=pf
elif test -r /dev/enet ; then
	V_PCAP=enet
elif test -r /dev/nit ; then
	V_PCAP=snit
elif test -r /usr/include/sys/net/nit.h ; then
	V_PCAP=nit
elif test -r /usr/include/linux/socket.h ; then
	V_PCAP=linux
elif test -r /usr/include/net/raw.h ; then
	V_PCAP=snoop
elif test -r /usr/include/odmi.h ; then
	#
	# On AIX, the BPF devices might not yet be present - they're
	# created the first time libpcap runs after booting.
	# We check for odmi.h instead.
	#
	V_PCAP=bpf
elif test -r /usr/include/sys/dlpi.h ; then
	V_PCAP=dlpi
elif test -c /dev/bpf0 ; then		# check again in case not readable
	V_PCAP=bpf
elif test -c /dev/enet ; then		# check again in case not readable
	V_PCAP=enet
elif test -c /dev/nit ; then		# check again in case not readable
	V_PCAP=snit
else
	V_PCAP=null
fi
AC_MSG_RESULT($V_PCAP)

dnl
dnl Now figure out how we get a list of interfaces and addresses.
dnl
AC_CHECK_FUNC(getifaddrs,[
	#
	# We have "getifaddrs()", so we use that to get the list
	#
	V_FINDALLDEVS=getad
],[
	#
	# Well, we don't have "getifaddrs()", so we have to use some
	# other mechanism; determine what that mechanism is.
	#
	# The first thing we use is the type of capture mechanism,
	# which is somewhat of a proxy for the OS we're using.
	#
	case "$V_PCAP" in

	dlpi)
		#
		# This might be Solaris 8 or later, with SIOCGLIFCONF,
		# or it might be some other OS, with just SIOCGIFCONF.
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
			V_FINDALLDEVS=glifc
		else
			V_FINDALLDEVS=gifc
		fi
		;;

	null)
		#
		# We can't capture, so we can't open any capture
		# devices, so we won't return any interfaces.
		#
		V_FINDALLDEVS=null
		;;

	*)
		#
		# Assume we just have SIOCGIFCONF.
		# (XXX - on at least later Linux kernels, there's
		# another mechanism, and we should be using that
		# instead.)
		#
		V_FINDALLDEVS=gifc
		;;
	esac])

AC_MSG_CHECKING(if --enable-ipv6 option is specified)
AC_ARG_ENABLE(ipv6, [  --enable-ipv6           build IPv6-capable version])
if test "$enable_ipv6" = "yes"; then
	AC_DEFINE(INET6,1,[IPv6])
fi
AC_MSG_RESULT(${enable_ipv6-no})

AC_MSG_CHECKING(whether to build optimizer debugging code)
AC_ARG_ENABLE(optimizer-dbg, [  --enable-optimizer-dbg  build optimizer debugging code])
if test "$enable_optimizer_dbg" = "yes"; then
	AC_DEFINE(BDEBUG,1,[Enable optimizer debugging])
fi
AC_MSG_RESULT(${enable_optimizer_dbg-no})

AC_MSG_CHECKING(whether to build parser debugging code)
AC_ARG_ENABLE(yydebug, [  --enable-yydebug        build parser debugging code])
if test "$enable_yydebug" = "yes"; then
	AC_DEFINE(YYDEBUG,1,[Enable parser debugging])
fi
AC_MSG_RESULT(${enable_yydebug-no})

case "$V_PCAP" in

dlpi)
	AC_CHECK_HEADERS(sys/bufmod.h sys/dlpi_ext.h)
	AC_MSG_CHECKING(for /dev/dlpi device)
	if test -c /dev/dlpi ; then
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_DEV_DLPI, 1, [define if you have a /dev/dlpi])
	else
		AC_MSG_RESULT(no)
		dir="/dev/dlpi"
		AC_MSG_CHECKING(for $dir directory)
		if test -d $dir ; then
			AC_MSG_RESULT(yes)
			AC_DEFINE_UNQUOTED(PCAP_DEV_PREFIX, "$dir", [/dev/dlpi directory])
		else
			AC_MSG_RESULT(no)
		fi
	fi
	;;

linux)
	AC_MSG_CHECKING(Linux kernel version)
 	if test "$cross_compiling" = yes; then
 		AC_CACHE_VAL(ac_cv_linux_vers,
 		    ac_cv_linux_vers=unknown)
 	else
 		AC_CACHE_VAL(ac_cv_linux_vers,
 		    ac_cv_linux_vers=`uname -r 2>&1 | \
 			sed -n -e '$s/.* //' -e '$s/\..*//p'`)
 	fi
	AC_MSG_RESULT($ac_cv_linux_vers)
 	if test $ac_cv_linux_vers = unknown ; then
 		AC_MSG_ERROR(cannot determine linux version when cross-compiling)
 	fi
	if test $ac_cv_linux_vers -lt 2 ; then
		AC_MSG_ERROR(version 2 or higher required; see the INSTALL doc for more info)
	fi
	AC_LBL_TPACKET_STATS
	;;

dag)
	V_DEFS="$V_DEFS -DDAG_ONLY"
	;;	

null)
	AC_MSG_WARN(cannot determine packet capture interface)
	AC_MSG_WARN((see the INSTALL doc for more info))
	;;

esac

AC_MSG_CHECKING(whether we have /proc/net/dev)
if test -r /proc/net/dev ; then
	ac_cv_lbl_proc_net_dev=yes
else
	ac_cv_lbl_proc_net_dev=no
fi
if test $ac_cv_lbl_proc_net_dev = yes; then
	AC_DEFINE(HAVE_PROC_NET_DEV, 1, [define if you have a /proc/net/dev])
fi
AC_MSG_RESULT($ac_cv_lbl_proc_net_dev)

AC_ARG_WITH(dag, [  --with-dag[=DIR]        include DAG support (located in directory DIR, if supplied).  [default=yes, on BSD and Linux, if present]],
[
	if test "$withval" = no
	then
		want_dag=no
	elif test "$withval" = yes
	then
		want_dag=yes
		dag_root=
	else
		want_dag=yes
		dag_root=$withval
	fi
],[
	#
	# Use DAG API if present, otherwise don't
	#
	want_dag=ifpresent
	dag_root=/root/dag
])
ac_cv_lbl_dag_api=no
case "$V_PCAP" in
linux|bpf|dag)
	#
	# We support the DAG API on Linux or BSD, or if we're building a
	# DAG-only libpcap.
	#
	;;
*)
	#
	# If the user explicitly requested DAG, tell them it's not
	# supported.
	#
	# If they expressed no preference, don't include it.
	#
	if test $want_dag = yes; then
		AC_MSG_ERROR(DAG support only available with 'linux' 'bpf' and 'dag' packet capture types)
	elif test $want_dag = yes; then
		want_dag=no
	fi
	;;
esac

if test "$with_dag" != no; then
	AC_MSG_CHECKING(whether we have DAG API)

	if test -z "$dag_root"; then
		dag_root=$srcdir/../dag
	fi

	if test -r "$dag_root/tools" -a -r "$dag_root/include"; then
		dag_tools_dir="$dag_root/tools"
		dag_include_dir="$dag_root/include"
	else
		dag_tools_dir="$dag_root"
		dag_include_dir="$dag_root"
	fi

	ac_cv_lbl_dag_api=no
	if test -r "$dag_include_dir/dagapi.h" -a -r "$dag_tools_dir/dagapi.o" -a -r "$dag_tools_dir/dagopts.o"; then
		V_INCLS="$V_INCLS -I $dag_include_dir"
		V_LIBS="$V_LIBS $dag_tools_dir/dagapi.o $dag_tools_dir/dagopts.o"
		if test "$V_PCAP" != dag ; then
			 SSRC="pcap-dag.c"
		fi
		ac_cv_lbl_dag_api=yes
	fi
	if test -r "$dag_root/lib/dagreg.c"; then # DAG 2.5.x
		if test -r "$dag_tools_dir/dagreg.o"; then
			V_LIBS="$V_LIBS $dag_tools_dir/dagreg.o"
		else
			ac_cv_lbl_dag_api=no
		fi
	fi
	dag_version=
	if test $ac_cv_lbl_dag_api = yes -a -r "$dag_root/VERSION"; then
		dag_version=" (`cat $dag_root/VERSION`)"
	fi
	AC_MSG_RESULT($ac_cv_lbl_dag_api$dag_version)
	if test $ac_cv_lbl_dag_api = no; then
		if test "$want_dag" = yes; then
			AC_MSG_ERROR(DAG API not found under directory $dag_root; use --without-dag)
		fi
	else
		AC_DEFINE(HAVE_DAG_API, 1, [define if you have a DAG API])
	fi
fi

if test "$V_PCAP" = dag -a "$ac_cv_lbl_dag_api" = no; then
	AC_MSG_ERROR(Specifying the capture type as 'dag' requires the DAG API to be present; use --with-dag=DIR)
fi

case "$host_os" in

aix*)
	dnl Workaround to enable certain features
	AC_DEFINE(_SUN,1,[define on AIX to get certain functions])
	;;

hpux9*)
	AC_DEFINE(HAVE_HPUX9,1,[on HP-UX 9.x])
	;;

hpux10.0*)
	;;

hpux10.1*)
	;;

hpux*)
	dnl HPUX 10.20 and above is similar to HPUX 9...
	AC_DEFINE(HAVE_HPUX10_20,1,[on HP-UX 10.20])
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
	;;
esac

AC_PROG_RANLIB

AC_LBL_DEVEL(V_CCOPT)

AC_LBL_SOCKADDR_SA_LEN

AC_LBL_SOCKADDR_STORAGE

AC_LBL_HP_PPA_INFO_T_DL_MODULE_ID_1

AC_LBL_UNALIGNED_ACCESS

rm -f net
ln -s ${srcdir}/bpf/net net

AC_SUBST(V_CCOPT)
AC_SUBST(V_DEFS)
AC_SUBST(V_INCLS)
AC_SUBST(V_LIBS)
AC_SUBST(V_PCAP)
AC_SUBST(V_FINDALLDEVS)
AC_SUBST(V_RANLIB)
AC_SUBST(SSRC)

AC_PROG_INSTALL

AC_CONFIG_HEADER(config.h)

AC_OUTPUT(Makefile)

if test -f .devel ; then
	make depend
fi
exit 0
