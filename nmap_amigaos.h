
/***************************************************************************
 * nmap_amigaos.h -- Handles various compilation issues for the Amiga port *
 * done by Diego Casorran (dcr8520@amiga.org)                              *
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

#ifndef _NMAP_AMIGAOS_H_
#define _NMAP_AMIGAOS_H_

#include <proto/miami.h>
#include <proto/miamibpf.h>
#include <proto/miamipcap.h>
#include <libraries/miami.h>
#include <devices/timer.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netdb.h>


//Pcap functions replacement using miamipcap.library (MiamiSDK v2.11)
#define pcap_open_live(a, b, c, d...)	MiamiPCapOpenLive(a, b, 0, d)
#define pcap_filter(args...)		MiamiPCapFilter(args)
#define pcap_close(args...)		MiamiPCapClose(args)
#define pcap_datalink(args...)		MiamiPCapDatalink(args)
#define pcap_geterr(args...)		MiamiPCapGeterr(args)
#define pcap_next(args...)		MiamiPCapNext(args)
#define pcap_lookupnet(args...)		MiamiPCapLookupnet(args)
#define pcap_compile(args...)		MiamiPCapCompile(args)
#define pcap_setfilter(args...)		MiamiPCapSetfilter(args)

#ifndef DLT_MIAMI
#define DLT_MIAMI 100
#endif

#ifndef NI_NAMEREQD
#define NI_NAMEREQD 4
#endif

#define NBASE_IPV6_H

struct addrinfo {
  long		ai_flags;		/* AI_PASSIVE, AI_CANONNAME */
  long		ai_family;		/* PF_xxx */
  long		ai_socktype;		/* SOCK_xxx */
  long		ai_protocol;		/* IPPROTO_xxx for IPv4 and IPv6 */
  size_t	ai_addrlen;		/* length of ai_addr */
  char		*ai_canonname;		/* canonical name for host */
  struct sockaddr	*ai_addr;	/* binary address */
  struct addrinfo	*ai_next;	/* next structure in linked list */
};

#endif /* _NMAP_AMIGAOS_H_ */

