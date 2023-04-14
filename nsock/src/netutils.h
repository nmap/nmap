/***************************************************************************
 * netutils.h -- This contains some useful little network/socket related   *
 * utility functions.                                                      *
 *                                                                         *
 ***********************IMPORTANT NSOCK LICENSE TERMS***********************
 *
 * The nsock parallel socket event library is (C) 1999-2023 Nmap Software LLC
 * This library is free software; you may redistribute and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; Version 2. This guarantees your right to use, modify, and
 * redistribute this software under certain conditions. If this license is
 * unacceptable to you, Nmap Software LLC may be willing to sell alternative
 * licenses (contact sales@nmap.com ).
 *
 * As a special exception to the GPL terms, Nmap Software LLC grants permission
 * to link the code of this program with any version of the OpenSSL library
 * which is distributed under a license identical to that listed in the included
 * docs/licenses/OpenSSL.txt file, and distribute linked combinations including
 * the two. You must obey the GNU GPL in all respects for all of the code used
 * other than OpenSSL. If you modify this file, you may extend this exception to
 * your version of the file, but you are not obligated to do so.
 *
 * If you received these files with a written license agreement stating terms
 * other than the (GPL) terms above, then that alternative license agreement
 * takes precedence over this comment.
 *
 * Source is provided to this software because we believe users have a right to
 * know exactly what a program is going to do before they run it. This also
 * allows you to audit the software for security holes.
 *
 * Source code also allows you to port Nmap to new platforms, fix bugs, and add
 * new features. You are highly encouraged to send your changes to the
 * dev@nmap.org mailing list for possible incorporation into the main
 * distribution. By sending these changes to Fyodor or one of the Insecure.Org
 * development mailing lists, or checking them into the Nmap source code
 * repository, it is understood (unless you specify otherwise) that you are
 * offering the Nmap Project (Nmap Software LLC) the unlimited, non-exclusive
 * right to reuse, modify, and relicense the code. Nmap will always be available
 * Open Source, but this is important because the inability to relicense code
 * has caused devastating problems for other Free Software projects (such as KDE
 * and NASM). We also occasionally relicense the code to third parties as
 * discussed above. If you wish to specify special license conditions of your
 * contributions, just say so when you send them.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License v2.0 for more
 * details (http://www.gnu.org/licenses/gpl-2.0.html).
 *
 ***************************************************************************/

/* $Id$ */

#ifndef NETUTILS_H
#define NETUTILS_H

#ifdef HAVE_CONFIG_H
#include "nsock_config.h"
#include "nbase_config.h"
#endif

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "nsock_internal.h"

#ifdef WIN32
#include "nbase_winconfig.h"
/* nbase_winunix.h somehow reason.h to get included */
#include "nbase_winunix.h"
#endif

#if HAVE_SYS_UN_H
#include <sys/un.h>
#endif

#if HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#else
#ifndef rlim_t
#define rlim_t int
#endif
#endif
/* Maximize the number of file descriptors (including sockets) allowed for this
 * process and return that maximum value (note -- you better not actually open
 * this many -- stdin, stdout, other files opened by libraries you use, etc. all
 * count toward this limit.  Leave a little slack */
rlim_t maximize_fdlimit(void);

/* Get the UNIX domain socket path or empty string if the address family != AF_UNIX. */
const char *get_unixsock_path(const struct sockaddr_storage *addr);

/* Get the peer address string. In case of a Unix domain socket, returns the
 * path to UNIX socket, otherwise it returns string containing
 * "<address>:<port>". */
char *get_peeraddr_string(const struct niod *iod);

/* Get the local bind address string. */
char *get_localaddr_string(const struct niod *iod);

#endif /* NETUTILS_H */

