/***************************************************************************
 * netutils.c -- This contains some useful little network/socket related   *
 * utility functions.                                                      *
 *                                                                         *
 ***********************IMPORTANT NSOCK LICENSE TERMS***********************
 *                                                                         *
 * The nsock parallel socket event library is (C) 1999-2016 Insecure.Com   *
 * LLC This library is free software; you may redistribute and/or          *
 * modify it under the terms of the GNU General Public License as          *
 * published by the Free Software Foundation; Version 2.  This guarantees  *
 * your right to use, modify, and redistribute this software under certain *
 * conditions.  If this license is unacceptable to you, Insecure.Com LLC   *
 * may be willing to sell alternative licenses (contact                    *
 * sales@insecure.com ).                                                   *
 *                                                                         *
 * As a special exception to the GPL terms, Insecure.Com LLC grants        *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two. You must obey the GNU GPL in all *
 * respects for all of the code used other than OpenSSL.  If you modify    *
 * this file, you may extend this exception to your version of the file,   *
 * but you are not obligated to do so.                                     *
 *                                                                         *
 * If you received these files with a written license agreement stating    *
 * terms other than the (GPL) terms above, then that alternative license   *
 * agreement takes precedence over this comment.                           *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to the dev@nmap.org mailing list for possible incorporation into the    *
 * main distribution.  By sending these changes to Fyodor or one of the    *
 * Insecure.Org development mailing lists, or checking them into the Nmap  *
 * source code repository, it is understood (unless you specify otherwise) *
 * that you are offering the Nmap Project (Insecure.Com LLC) the           *
 * unlimited, non-exclusive right to reuse, modify, and relicense the      *
 * code.  Nmap will always be available Open Source, but this is important *
 * because the inability to relicense code has caused devastating problems *
 * for other Free Software projects (such as KDE and NASM).  We also       *
 * occasionally relicense the code to third parties as discussed above.    *
 * If you wish to specify special license conditions of your               *
 * contributions, just say so when you send them.                          *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License v2.0 for more details                            *
 * (http://www.gnu.org/licenses/gpl-2.0.html).                             *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */

#include "netutils.h"
#include "error.h"

#if WIN32
#include "Winsock2.h"
#endif

#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#if HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#if HAVE_SYS_UN_H
#include <sys/un.h>
#endif

static int netutils_debugging = 0;

/* maximize the number of file descriptors (including sockets) allowed for this
 * process and return that maximum value (note -- you better not actually open
 * this many -- stdin, stdout, other files opened by libraries you use, etc. all
 * count toward this limit.  Leave a little slack */
int maximize_fdlimit(void) {

#ifndef WIN32
  struct rlimit r;
  static int maxfds = -1;

  if (maxfds > 0)
    return maxfds;

#if(defined(RLIMIT_NOFILE))
  if (!getrlimit(RLIMIT_NOFILE, &r)) {
    r.rlim_cur = r.rlim_max;
    if (setrlimit(RLIMIT_NOFILE, &r))
      if (netutils_debugging)
        perror("setrlimit RLIMIT_NOFILE failed");

    if (!getrlimit(RLIMIT_NOFILE, &r)) {
      maxfds = r.rlim_cur;
      return maxfds;
    } else {
      return 0;
    }
  }
#endif

#if(defined(RLIMIT_OFILE) && !defined(RLIMIT_NOFILE))
  if (!getrlimit(RLIMIT_OFILE, &r)) {
    r.rlim_cur = r.rlim_max;
    if (setrlimit(RLIMIT_OFILE, &r))
      if (netutils_debugging)
        perror("setrlimit RLIMIT_OFILE failed");

    if (!getrlimit(RLIMIT_OFILE, &r)) {
      maxfds = r.rlim_cur;
      return maxfds;
    } else {
      return 0;
    }
  }
#endif
#endif /* !WIN32 */
  return 0;
}

#if HAVE_SYS_UN_H
  #define PEER_STR_LEN sizeof(((struct sockaddr_un *) 0)->sun_path)
#else
  #define PEER_STR_LEN sizeof("[ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255]:xxxxx")
#endif

#if HAVE_SYS_UN_H
/* Get the UNIX domain socket path or empty string if the address family != AF_UNIX. */
const char *get_unixsock_path(const struct sockaddr_storage *addr) {
  struct sockaddr_un *su = (struct sockaddr_un *)addr;

  if (!addr || addr->ss_family != AF_UNIX)
    return "";

  return (const char *)su->sun_path;
}
#endif

static int get_port(const struct sockaddr_storage *ss) {
  if (ss->ss_family == AF_INET)
    return ntohs(((struct sockaddr_in *) ss)->sin_port);
#if HAVE_IPV6
  else if (ss->ss_family == AF_INET6)
    return ntohs(((struct sockaddr_in6 *) ss)->sin6_port);
#endif

  return -1;
}

static char *get_addr_string(const struct sockaddr_storage *ss, size_t sslen) {
  static char buffer[PEER_STR_LEN];

#if HAVE_SYS_UN_H
  if (ss->ss_family == AF_UNIX) {
    sprintf(buffer, "%s", get_unixsock_path(ss));
    return buffer;
  }
#endif

  sprintf(buffer, "%s:%d", inet_ntop_ez(ss, sslen), get_port(ss));
  return buffer;
}

/* Get the peer/host address string.
 * In case we have support for UNIX domain sockets, function returns
 * string containing path to UNIX socket if the address family is AF_UNIX,
 * otherwise it returns string containing "<address>:<port>". */
char *get_peeraddr_string(const struct niod *iod) {
  if (iod->peerlen > 0)
    return get_addr_string(&iod->peer, iod->peerlen);
  else
    return "peer unspecified";
}

/* Get the local bind address string. */
char *get_localaddr_string(const struct niod *iod) {
  return get_addr_string(&iod->local, iod->locallen);
}
