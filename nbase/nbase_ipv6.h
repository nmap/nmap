
/***************************************************************************
 * nbase_ipv6.h -- IPv6 portability classes and structures These were      *
 * written by fyodor@nmap.org .                                        *
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

#ifndef NBASE_IPV6_H
#define NBASE_IPV6_H

#ifdef __amigaos__
#ifndef _NMAP_AMIGAOS_H_
#include "../nmap_amigaos.h"
#endif
#endif

#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifndef HAVE_AF_INET6
#define AF_INET6 10
#define PF_INET6 10
#endif /* HAVE_AF_INET6 */
#ifndef HAVE_INET_PTON
/* int
 * inet_pton(af, src, dst)
 *      convert from presentation format (which usually means ASCII printable)
 *      to network format (which is usually some kind of binary format).
 * return:
 *      1 if the address was valid for the specified address family
 *      0 if the address wasn't valid (`dst' is untouched in this case)
 *      -1 if some other error occurred (`dst' is untouched in this case, too)
 * author:
 *      Paul Vixie, 1996.
 */
int inet_pton(int af, const char *src, void *dst);
#endif /* HAVE_INET_PTON */

#ifndef HAVE_INET_NTOP
/* char *
 * inet_ntop(af, src, dst, size)
 *	convert a network format address to presentation format.
 * return:
 *	pointer to presentation format address (`dst'), or NULL (see errno).
 * author:
 *	Paul Vixie, 1996.
 */
const char *inet_ntop(int af, const void *src, char *dst, size_t size);
#endif /* HAVE_INET_NTOP */

#ifndef HAVE_SOCKADDR_STORAGE
struct sockaddr_storage {
  u16 ss_family;
  u16 __align_to_64[3];
  u64 __padding[16];
};
#endif /* SOCKADDR_STORAGE */

/* Compares two sockaddr_storage structures with a return value like strcmp.
   First the address families are compared, then the addresses if the families
   are equal. The structures must be real full-length sockaddr_storage
   structures, not something shorter like sockaddr_in. */
int sockaddr_storage_cmp(const struct sockaddr_storage *a,
  const struct sockaddr_storage *b);

/* Does sockaddr_storage_cmp(a, b) == 0 for you. */
int sockaddr_storage_equal(const struct sockaddr_storage *a,
  const struct sockaddr_storage *b);

/* This function is an easier version of inet_ntop because you don't
   need to pass a dest buffer.  Instead, it returns a static buffer that
   you can use until the function is called again (by the same or another
   thread in the process).  If there is a weird error (like sslen being
   too short) then NULL will be returned. */
const char *inet_ntop_ez(const struct sockaddr_storage *ss, size_t sslen);


#if !HAVE_GETNAMEINFO || !HAVE_GETADDRINFO
#if !defined(EAI_MEMORY)
#define EAI_ADDRFAMILY   1      /* address family for hostname not supported */
#define EAI_AGAIN        2      /* temporary failure in name resolution */
#define EAI_BADFLAGS     3      /* invalid value for ai_flags */
#define EAI_FAIL         4      /* non-recoverable failure in name resolution */
#define EAI_FAMILY       5      /* ai_family not supported */
#define EAI_MEMORY       6      /* memory allocation failure */
#define EAI_NODATA       7      /* no address associated with hostname */
#define EAI_NONAME       8      /* hostname nor servname provided, or not known */
#define EAI_SERVICE      9      /* servname not supported for ai_socktype */
#define EAI_SOCKTYPE    10      /* ai_socktype not supported */
#define EAI_SYSTEM      11      /* system error returned in errno */
#define EAI_BADHINTS    12
#define EAI_PROTOCOL    13
#define EAI_MAX         14
#endif /* EAI_MEMORY */
#endif /* !HAVE_GETNAMEINFO || !HAVE_GETADDRINFO */

#if !HAVE_GETNAMEINFO
/* This replacement version is *NOT* a full implementation by any
   stretch of the imagination */
/* getnameinfo flags */
#if !defined(NI_NAMEREQD)
#define NI_NOFQDN 8
#define NI_NUMERICHOST 16
#define NI_NAMEREQD 32
#define NI_NUMERICSERV 64
#define NI_DGRAM 128
#endif

struct sockaddr;
int getnameinfo(const struct sockaddr *sa, size_t salen,
                char *host, size_t hostlen,
                char *serv, size_t servlen, int flags);
#endif /* !HAVE_GETNAMEINFO */

#if !HAVE_GETADDRINFO
/* This replacement version is *NOT* a full implementation by any
   stretch of the imagination */
struct addrinfo {
  int ai_flags;      /*  AI_PASSIVE, AI_CANONNAME, AI_NUMERICHOST */
  int ai_family;    /* PF_xxx */
  int ai_socktype;  /* SOCK_xxx */
  int ai_protocol;  /* 0 or IPPROTO_xxx for IPv4 and IPv6 */
  size_t ai_addrlen;   /* length of ai_addr */
  char *ai_canonname; /* canonical name for nodename */
  struct sockaddr  *ai_addr; /* binary address */
  struct  addrinfo  *ai_next; /* next structure in linked list */
};

/* getaddrinfo Flags */
#if !defined(AI_PASSIVE) || !defined(AI_CANONNAME) || !defined(AI_NUMERICHOST)
#define AI_PASSIVE 1
#define AI_CANONNAME 2
#define AI_NUMERICHOST 4
#endif

void freeaddrinfo(struct addrinfo *res);
int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res);

#endif /* !HAVE_GETADDRINFO */

#ifndef HAVE_GAI_STRERROR
const char *gai_strerror(int errcode);
#endif

int sockaddr_storage_inet_pton(const char * ip_str, struct sockaddr_storage * addr);
const char *sockaddr_storage_iptop(const struct sockaddr_storage * addr, char * dst);

#endif /* NBASE_IPV6_H */
