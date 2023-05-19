/***************************************************************************
 * getaddrinfo.c -- A **PARTIAL** implementation of the getaddrinfo(3)     *
 * hostname resolution call.  In particular, IPv6 is not supported and     *
 * neither are some of the flags.  Service "names" are always returned as  *
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
#if HAVE_NETDB_H
#include <netdb.h>
#endif
#include <assert.h>


#if !defined(HAVE_GAI_STRERROR) || defined(__MINGW32__)
#ifdef __MINGW32__
#undef gai_strerror
#endif

const char *gai_strerror(int errcode) {
  static char customerr[64];
  switch (errcode) {
  case EAI_FAMILY:
    return "ai_family not supported";
  case EAI_NODATA:
    return "no address associated with hostname";
  case EAI_NONAME:
    return "hostname nor servname provided, or not known";
  default:
    Snprintf(customerr, sizeof(customerr), "unknown error (%d)", errcode);
    return "unknown error.";
  }
  return NULL; /* unreached */
}
#endif

#ifdef __MINGW32__
char* WSAAPI gai_strerrorA (int errcode)
{
  return gai_strerror(errcode);
}
#endif

#ifndef HAVE_GETADDRINFO
void freeaddrinfo(struct addrinfo *res) {
  struct addrinfo *next;

  do {
    next = res->ai_next;
    free(res);
  } while ((res = next) != NULL);
}

/* Allocates and initializes a new AI structure with the port and IPv4
   address specified in network byte order */
static struct addrinfo *new_ai(unsigned short portno, u32 addr)
{
        struct addrinfo *ai;

        ai = (struct addrinfo *) safe_malloc(sizeof(struct addrinfo) + sizeof(struct sockaddr_in));

        memset(ai, 0, sizeof(struct addrinfo) + sizeof(struct sockaddr_in));

        ai->ai_family = AF_INET;
        ai->ai_addrlen = sizeof(struct sockaddr_in);
        ai->ai_addr = (struct sockaddr *)(ai + 1);
        ai->ai_addr->sa_family = AF_INET;
#if HAVE_SOCKADDR_SA_LEN
        ai->ai_addr->sa_len = ai->ai_addrlen;
#endif
        ((struct sockaddr_in *)(ai)->ai_addr)->sin_port = portno;
        ((struct sockaddr_in *)(ai)->ai_addr)->sin_addr.s_addr = addr;

        return(ai);
}


int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res) {

  struct addrinfo *cur, *prev = NULL;
  struct hostent *he;
  struct in_addr ip;
  unsigned short portno;
  int i;

  if (service)
    portno = htons(atoi(service));
  else
    portno = 0;

  if (hints && hints->ai_flags & AI_PASSIVE) {
    *res = new_ai(portno, htonl(0x00000000));
    return 0;
  }

  if (!node) {
    *res = new_ai(portno, htonl(0x7f000001));
    return 0;
  }

  if (inet_pton(AF_INET, node, &ip)) {
    *res = new_ai(portno, ip.s_addr);
    return 0;
  }

  he = gethostbyname(node);
  if (he && he->h_addr_list[0]) {
    for (i = 0; he->h_addr_list[i]; i++) {
      cur = new_ai(portno, ((struct in_addr *)he->h_addr_list[i])->s_addr);

      if (prev)
        prev->ai_next = cur;
      else
        *res = cur;

      prev = cur;
    }
    return 0;
  }

  return EAI_NODATA;
}
#endif /* HAVE_GETADDRINFO */
