dnl Type of 6th argument to recvfrom(). Usually int or socklen_t.
AC_DEFUN([RECVFROM_ARG6_TYPE],
[
   AC_LANG_PUSH(C++)
   AC_MSG_CHECKING([for type of 6th argument to recvfrom()])
   recvfrom6_t=
   for t in socklen_t int; do
     AC_TRY_COMPILE([
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>],[
$t arg;
recvfrom (0, NULL, 0, 0, NULL, &arg);],[
      recvfrom6_t="$t"
      break])
   done

   if test "x$recvfrom6_t" = x; then
     AC_MSG_WARN([Cannot find type for 6th argument to recvfrom(). Using socklen_t ptr])
     recvfrom6_t="socklen_t"
   fi

   AC_MSG_RESULT($recvfrom6_t)
   AC_DEFINE_UNQUOTED(recvfrom6_t, $recvfrom6_t,
     [Type of 6th argument to recvfrom()])
   AC_LANG_POP(C++)
])

dnl Checks if the pcap version is suitable. The has to be at least version
dnl 0.9.4. Mac OS X 10.6 has a bug in its BIOCSRTIMEOUT ioctl that is worked
dnl around in libpcap 1.1.0 and later; but before that we must use our own copy.
AC_DEFUN([PCAP_IS_SUITABLE],
[
  AC_CHECK_HEADERS(sys/ioccom.h sys/time.h net/bpf.h)
  AC_MSG_CHECKING(if libpcap is suitable)
  AC_TRY_RUN([
#include <stdio.h>
extern char pcap_version[];
int main() {
  int major, minor1, minor2;
  sscanf(pcap_version,"%d.%d.%d", &major, &minor1, &minor2);
  if (major > 0) 
    return 0;
  if (minor1 < 9)
    return 1;
  if (minor2 < 4)
    return 1;
  return 0;
}
  ], [
    AC_TRY_RUN([
#include <stdio.h>
#include <sys/types.h>
#ifdef HAVE_SYS_IOCCOM_H
#include <sys/ioccom.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_NET_BPF_H
#include <net/bpf.h>
#endif
extern char pcap_version[];
int main() {
  int major, minor;
  sscanf(pcap_version,"%d.%d", &major, &minor);
  if ((major == 1 && minor >= 1) || major > 1)
    return 0;
#ifdef BIOCSRTIMEOUT
#ifdef IOCPARM_LEN
  if (IOCPARM_LEN(BIOCSRTIMEOUT) != sizeof(struct timeval))
    return 1;
#endif
#endif
  return 0;
}
    ], [
      AC_CHECK_DECL([pcap_get_selectable_fd],
        [AC_MSG_RESULT(yes); $1],
        [AC_MSG_RESULT(no -- pcap_get_selectable_fd not declared); $2],
        [[#include <pcap.h>]])
    ],
    [AC_MSG_RESULT(no -- BPF_TIMEOUT BIOCSRTIMEOUT bug (64-bit OS X)); $2])
  ],
  [AC_MSG_RESULT(no); $2],
  [AC_MSG_RESULT(cross-compiling -- assuming yes); $3])
])

dnl Checks if IPPROTO_RAW induces IP_HDRINCL-like behavior in AF_INET6 sockets.
dnl Defines HAVE_IPV6_IPPROTO_RAW if so. So far I only know this happens on
dnl Linux.
AC_DEFUN([CHECK_IPV6_IPPROTO_RAW],
[
  AC_MSG_CHECKING(if AF_INET6 IPPROTO_RAW sockets include the packet header)
  # This should be replaced with a better test, if possible.
  case "$host" in
    *-linux*)
      AC_DEFINE(HAVE_IPV6_IPPROTO_RAW)
      AC_MSG_RESULT(yes)
      ;;
    *)
      AC_MSG_RESULT(no)
      ;;
  esac
])

dnl -------------------------------------------------------- -*- autoconf -*-
dnl Licensed to the Apache Software Foundation (ASF) under one or more
dnl contributor license agreements.  See the NOTICE file distributed with
dnl this work for additional information regarding copyright ownership.
dnl The ASF licenses this file to You under the Apache License, Version 2.0
dnl (the "License"); you may not use this file except in compliance with
dnl the License.  You may obtain a copy of the License at
dnl
dnl     http://www.apache.org/licenses/LICENSE-2.0
dnl
dnl Unless required by applicable law or agreed to in writing, software
dnl distributed under the License is distributed on an "AS IS" BASIS,
dnl WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
dnl See the License for the specific language governing permissions and
dnl limitations under the License.

dnl
dnl find_apr.m4 : locate the APR include files and libraries
dnl
dnl This macro file can be used by applications to find and use the APR
dnl library. It provides a standardized mechanism for using APR. It supports
dnl embedding APR into the application source, or locating an installed
dnl copy of APR.
dnl
dnl APR_FIND_APR(srcdir, builddir, implicit-install-check, acceptable-majors,
dnl              detailed-check)
dnl
dnl   where srcdir is the location of the bundled APR source directory, or
dnl   empty if source is not bundled.
dnl
dnl   where builddir is the location where the bundled APR will will be built,
dnl   or empty if the build will occur in the srcdir.
dnl
dnl   where implicit-install-check set to 1 indicates if there is no
dnl   --with-apr option specified, we will look for installed copies.
dnl
dnl   where acceptable-majors is a space separated list of acceptable major
dnl   version numbers. Often only a single major version will be acceptable.
dnl   If multiple versions are specified, and --with-apr=PREFIX or the
dnl   implicit installed search are used, then the first (leftmost) version
dnl   in the list that is found will be used.  Currently defaults to [0 1].
dnl
dnl   where detailed-check is an M4 macro which sets the apr_acceptable to
dnl   either "yes" or "no". The macro will be invoked for each installed
dnl   copy of APR found, with the apr_config variable set appropriately.
dnl   Only installed copies of APR which are considered acceptable by
dnl   this macro will be considered found. If no installed copies are
dnl   considered acceptable by this macro, apr_found will be set to either
dnl   either "no" or "reconfig".
dnl
dnl Sets the following variables on exit:
dnl
dnl   apr_found : "yes", "no", "reconfig"
dnl
dnl   apr_config : If the apr-config tool exists, this refers to it. If
dnl                apr_found is "reconfig", then the bundled directory
dnl                should be reconfigured *before* using apr_config.
dnl
dnl Note: this macro file assumes that apr-config has been installed; it
dnl       is normally considered a required part of an APR installation.
dnl
dnl If a bundled source directory is available and needs to be (re)configured,
dnl then apr_found is set to "reconfig". The caller should reconfigure the
dnl (passed-in) source directory, placing the result in the build directory,
dnl as appropriate.
dnl
dnl If apr_found is "yes" or "reconfig", then the caller should use the
dnl value of apr_config to fetch any necessary build/link information.
dnl

AC_DEFUN([APR_FIND_APR], [
  apr_found="no"

  if test "$target_os" = "os2-emx"; then
    # Scripts don't pass test -x on OS/2
    TEST_X="test -f"
  else
    TEST_X="test -x"
  fi

  ifelse([$4], [], [
         ifdef(AC_WARNING,AC_WARNING([$0: missing argument 4 (acceptable-majors): Defaulting to APR 0.x then APR 1.x]))
         acceptable_majors="0 1"],
         [acceptable_majors="$4"])

  apr_temp_acceptable_apr_config=""
  for apr_temp_major in $acceptable_majors
  do
    case $apr_temp_major in
      0)
      apr_temp_acceptable_apr_config="$apr_temp_acceptable_apr_config apr-config"
      ;;
      *)
      apr_temp_acceptable_apr_config="$apr_temp_acceptable_apr_config apr-$apr_temp_major-config"
      ;;
    esac
  done

  AC_MSG_CHECKING(for APR)
  AC_ARG_WITH(apr,
  [  --with-apr=PATH         prefix for installed APR or the full path to 
                             apr-config],
  [
    if test "$withval" = "no" || test "$withval" = "yes"; then
      AC_MSG_ERROR([--with-apr requires a directory or file to be provided])
    fi

    for apr_temp_apr_config_file in $apr_temp_acceptable_apr_config
    do
      for lookdir in "$withval/bin" "$withval"
      do
        if $TEST_X "$lookdir/$apr_temp_apr_config_file"; then
          apr_config="$lookdir/$apr_temp_apr_config_file"
          ifelse([$5], [], [], [
          apr_acceptable="yes"
          $5
          if test "$apr_acceptable" != "yes"; then
            AC_MSG_WARN([Found APR in $apr_config, but we think it is considered unacceptable])
            continue
          fi])
          apr_found="yes"
          break 2
        fi
      done
    done

    if test "$apr_found" != "yes" && $TEST_X "$withval" && $withval --help > /dev/null 2>&1 ; then
      apr_config="$withval"
      ifelse([$5], [], [apr_found="yes"], [
          apr_acceptable="yes"
          $5
          if test "$apr_acceptable" = "yes"; then
                apr_found="yes"
          fi])
    fi

    dnl if --with-apr is used, it is a fatal error for its argument
    dnl to be invalid
    if test "$apr_found" != "yes"; then
      AC_MSG_ERROR([the --with-apr parameter is incorrect. It must specify an install prefix, a build directory, or an apr-config file.])
    fi
  ],[
    dnl If we allow installed copies, check those before using bundled copy.
    if test -n "$3" && test "$3" = "1"; then
      for apr_temp_apr_config_file in $apr_temp_acceptable_apr_config
      do
        if $apr_temp_apr_config_file --help > /dev/null 2>&1 ; then
          apr_config="$apr_temp_apr_config_file"
          ifelse([$5], [], [], [
          apr_acceptable="yes"
          $5
          if test "$apr_acceptable" != "yes"; then
            AC_MSG_WARN([skipped APR at $apr_config, version not acceptable])
            continue
          fi])
          apr_found="yes"
          break
        else
          dnl look in some standard places
          for lookdir in /usr /usr/local /usr/local/apr /opt/apr; do
            if $TEST_X "$lookdir/bin/$apr_temp_apr_config_file"; then
              apr_config="$lookdir/bin/$apr_temp_apr_config_file"
              ifelse([$5], [], [], [
              apr_acceptable="yes"
              $5
              if test "$apr_acceptable" != "yes"; then
                AC_MSG_WARN([skipped APR at $apr_config, version not acceptable])
                continue
              fi])
              apr_found="yes"
              break 2
            fi
          done
        fi
      done
    fi
    dnl if we have not found anything yet and have bundled source, use that
    if test "$apr_found" = "no" && test -d "$1"; then
      apr_temp_abs_srcdir="`cd \"$1\" && pwd`"
      apr_found="reconfig"
      apr_bundled_major="`sed -n '/#define.*APR_MAJOR_VERSION/s/^[^0-9]*\([0-9]*\).*$/\1/p' \"$1/include/apr_version.h\"`"
      case $apr_bundled_major in
        "")
          AC_MSG_ERROR([failed to find major version of bundled APR])
        ;;
        0)
          apr_temp_apr_config_file="apr-config"
        ;;
        *)
          apr_temp_apr_config_file="apr-$apr_bundled_major-config"
        ;;
      esac
      if test -n "$2"; then
        apr_config="$2/$apr_temp_apr_config_file"
      else
        apr_config="$1/$apr_temp_apr_config_file"
      fi
    fi
  ])

  AC_MSG_RESULT($apr_found)
])
