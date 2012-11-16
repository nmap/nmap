/***************************************************************************
 * ncat.h                                                                  *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2012 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 with the clarifications and exceptions described  *
 * below.  This guarantees your right to use, modify, and redistribute     *
 * this software under certain conditions.  If you wish to embed Nmap      *
 * technology into proprietary software, we sell alternative licenses      *
 * (contact sales@insecure.com).  Dozens of software vendors already       *
 * license Nmap technology such as host discovery, port scanning, OS       *
 * detection, version detection, and the Nmap Scripting Engine.            *
 *                                                                         *
 * Note that the GPL places important restrictions on "derived works", yet *
 * it does not provide a detailed definition of that term.  To avoid       *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * "derivative work" for the purpose of this license if it does any of the *
 * following:                                                              *
 * o Integrates source code from Nmap                                      *
 * o Reads or includes Nmap copyrighted data files, such as                *
 *   nmap-os-db or nmap-service-probes.                                    *
 * o Executes Nmap and parses the results (as opposed to typical shell or  *
 *   execution-menu apps, which simply display raw Nmap output and so are  *
 *   not derivative works.)                                                *
 * o Integrates/includes/aggregates Nmap into a proprietary executable     *
 *   installer, such as those produced by InstallShield.                   *
 * o Links to a library or executes a program that does any of the above   *
 *                                                                         *
 * The term "Nmap" should be taken to also include any portions or derived *
 * works of Nmap, as well as other software we distribute under this       *
 * license such as Zenmap, Ncat, and Nping.  This list is not exclusive,   *
 * but is meant to clarify our interpretation of derived works with some   *
 * common examples.  Our interpretation applies only to Nmap--we don't     *
 * speak for other people's GPL works.                                     *
 *                                                                         *
 * If you have any questions about the GPL licensing restrictions on using *
 * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
 * we also offer alternative license to integrate Nmap into proprietary    *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates.  They also fund the      *
 * continued development of Nmap.  Please email sales@insecure.com for     *
 * further information.                                                    *
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
 * If you received these files with a written license agreement or         *
 * contract stating terms other than the terms above, then that            *
 * alternative license agreement takes precedence over these comments.     *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes (none     *
 * have been found so far).                                                *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to nmap-dev@insecure.org for possible incorporation into the main       *
 * distribution.  By sending these changes to Fyodor or one of the         *
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
 * General Public License v2.0 for more details at                         *
 * http://www.gnu.org/licenses/gpl-2.0.html , or in the COPYING file       *
 * included with Nmap.                                                     *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */

#ifndef NCAT_H_
#define NCAT_H_

#include "ncat_config.h"

#include <nbase.h>

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#endif

#include "nsock.h"
#include "util.h"
#include "sys_wrap.h"

#include "ncat_connect.h"
#include "ncat_core.h"
#include "ncat_exec.h"
#include "ncat_listen.h"
#include "ncat_proxy.h"
#include "ncat_ssl.h"

/* Ncat information for output, etc. */
#define NCAT_NAME "Ncat"
#define NCAT_URL "http://nmap.org/ncat"
#define NCAT_VERSION "6.20BETA1"

#ifndef __GNUC__
#ifndef __attribute__
#define __attribute__(x)
#endif
#endif

/* structs */

#ifdef WIN32
#pragma pack(1)
#endif
struct socks4_data {
    char version;
    char type;
    unsigned short port;
    unsigned long address;
    char username[256];
} __attribute__((packed));
#ifdef WIN32
#pragma pack()
#endif

/* defines */

/* Client-mode timeout for reads, infinite */
#define DEFAULT_READ_TIMEOUT -1

/* Client-mode timeout for writes, in msecs */
#define DEFAULT_WRITE_TIMEOUT 2000

/* Client-mode timeout for connection establishment, in msecs */
#define DEFAULT_CONNECT_TIMEOUT 10000

/* The default length of Ncat buffers */
#define DEFAULT_BUF_LEN      (1024)
#define DEFAULT_TCP_BUF_LEN  (1024 * 8)
#define DEFAULT_UDP_BUF_LEN  (1024 * 128)

/* Default Ncat port */
#define DEFAULT_NCAT_PORT 31337

/* Default port for SOCKS4 */
#define DEFAULT_SOCKS4_PORT 1080

/* The default port Ncat will connect to when trying to connect to an HTTP
 * proxy server.  The current setting is the default for squid and probably
 * other HTTP proxies. But it may also be 8080, 8888, etc.
 */
#define DEFAULT_PROXY_PORT 3128

/* Listen() backlog */
#define BACKLOG 10

/* The default maximum number of simultaneous connections Ncat will accept to
 * a listening port. You may want to increase or decrease this value depending
 * on your specific needs.
 */
#define DEFAULT_MAX_CONNS 100

/* SOCKS4 protocol responses */
#define SOCKS4_VERSION          4
#define SOCKS_CONNECT           1
#define SOCKS_BIND              2
#define SOCKS_CONN_ACC          90 /* woot */
#define SOCKS_CONN_REF          91
#define SOCKS_CONN_IDENT        92
#define SOCKS_CONN_IDENTDIFF    93

/* Length of IPv6 address */
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif

/* Dummy WNOHANG for Windows */
#ifndef WNOHANG
#define WNOHANG 0
#endif

#endif
