/***************************************************************************
 * getnameinfo.c -- A **PARTIAL** implementation of the getnameinfo(3)     *
 * host resolution call.  In particular, IPv6 is not supported and neither *
 * are some of the flags.  Service "names" are always returned as decimal  *
 * port numbers.                                                           *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *
 * The Nmap Security Scanner is (C) 1996-2023 Nmap Software LLC ("The Nmap
 * Project"). Nmap is also a registered trademark of the Nmap Project.
 *
 * This program is distributed under the terms of the Nmap Public Source
 * License (NPSL). The exact license text applying to a particular Nmap
 * release or source code control revision is contained in the LICENSE
 * file distributed with that version of Nmap or source code control
 * revision. More Nmap copyright/legal information is available from
 * https://nmap.org/book/man-legal.html, and further information on the
 * NPSL license itself can be found at https://nmap.org/npsl/ . This
 * header summarizes some key points from the Nmap license, but is no
 * substitute for the actual license text.
 *
 * Nmap is generally free for end users to download and use themselves,
 * including commercial use. It is available from https://nmap.org.
 *
 * The Nmap license generally prohibits companies from using and
 * redistributing Nmap in commercial products, but we sell a special Nmap
 * OEM Edition with a more permissive license and special features for
 * this purpose. See https://nmap.org/oem/
 *
 * If you have received a written Nmap license agreement or contract
 * stating terms other than these (such as an Nmap OEM license), you may
 * choose to use and redistribute Nmap under those terms instead.
 *
 * The official Nmap Windows builds include the Npcap software
 * (https://npcap.com) for packet capture and transmission. It is under
 * separate license terms which forbid redistribution without special
 * permission. So the official Nmap Windows builds may not be redistributed
 * without special permission (such as an Nmap OEM license).
 *
 * Source is provided to this software because we believe users have a
 * right to know exactly what a program is going to do before they run it.
 * This also allows you to audit the software for security holes.
 *
 * Source code also allows you to port Nmap to new platforms, fix bugs, and add
 * new features. You are highly encouraged to submit your changes as a Github PR
 * or by email to the dev@nmap.org mailing list for possible incorporation into
 * the main distribution. Unless you specify otherwise, it is understood that
 * you are offering us very broad rights to use your submissions as described in
 * the Nmap Public Source License Contributor Agreement. This is important
 * because we fund the project by selling licenses with various terms, and also
 * because the inability to relicense code has caused devastating problems for
 * other Free Software projects (such as KDE and NASM).
 *
 * The free version of Nmap is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranties,
 * indemnification and commercial support are all available through the
 * Npcap OEM program--see https://nmap.org/oem/
 *
 ***************************************************************************/

/* $Id$ */
#include "nbase.h"

#if HAVE_NETDB_H
#include <netdb.h>
#endif
#include <assert.h>
#include <stdio.h>
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

int getnameinfo(const struct sockaddr *sa, size_t salen,
                char *host, size_t hostlen,
                char *serv, size_t servlen, int flags) {

  struct sockaddr_in *sin = (struct sockaddr_in *)sa;
  struct hostent *he;

  if (sin->sin_family != AF_INET || salen != sizeof(struct sockaddr_in))
    return EAI_FAMILY;

  if (serv != NULL) {
    Snprintf(serv, servlen, "%d", ntohs(sin->sin_port));
    return 0;
  }

  if (host) {
    if (flags & NI_NUMERICHOST) {
      Strncpy(host, inet_ntoa(sin->sin_addr), hostlen);
      return 0;
    } else {
      he = gethostbyaddr((char *)&sin->sin_addr, sizeof(struct in_addr),
                         AF_INET);
      if (he == NULL) {
        if (flags & NI_NAMEREQD)
          return EAI_NONAME;

        Strncpy(host, inet_ntoa(sin->sin_addr), hostlen);
        return 0;
      }

      assert(he->h_name);
      Strncpy(host, he->h_name, hostlen);
      return 0;
    }
  }
  return 0;
}
