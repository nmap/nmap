/***************************************************************************
 * ncat.h                                                                  *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2016 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE CLARIFICATIONS  *
 * AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your right to use,    *
 * modify, and redistribute this software under certain conditions.  If    *
 * you wish to embed Nmap technology into proprietary software, we sell    *
 * alternative licenses (contact sales@nmap.com).  Dozens of software      *
 * vendors already license Nmap technology such as host discovery, port    *
 * scanning, OS detection, version detection, and the Nmap Scripting       *
 * Engine.                                                                 *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files, such as Nmap's nmap-os-db   *
 * or nmap-service-probes.                                                 *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * Nmap with other software in compressed or archival form does not        *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * As another special exception to the GPL terms, Insecure.Com LLC grants  *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two.                                  *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * Nmap or grant special permissions to use it in other open source        *
 * software.  Please contact fyodor@nmap.org with any such requests.       *
 * Similarly, we don't incorporate incompatible open source software into  *
 * Covered Software without special permission from the copyright holders. *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * Nmap in other works, are happy to help.  As mentioned above, we also    *
 * offer alternative license to integrate Nmap into proprietary            *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates.  They also fund the      *
 * continued development of Nmap.  Please email sales@nmap.com for further *
 * information.                                                            *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the Nmap      *
 * license file for more details (it's in a COPYING file included with     *
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING)        *
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
#define NCAT_URL "https://nmap.org/ncat"
#define NCAT_VERSION "7.25SVN"

#ifndef __GNUC__
#ifndef __attribute__
#define __attribute__(x)
#endif
#endif

#define SOCKS_BUFF_SIZE 512

/* structs */

#ifdef WIN32
#pragma pack(1)
#endif
struct socks4_data {
    char version;
    char type;
    unsigned short port;
    uint32_t address;
    char data[SOCKS_BUFF_SIZE]; // this has to be able to hold FQDN and username
} __attribute__((packed));

struct socks5_connect {
    char ver;
    char nmethods;
    char methods[3];
} __attribute__((packed));

struct socks5_auth {
  char ver; // must be always 1
  char data[SOCKS_BUFF_SIZE];
} __attribute__((packed));

struct socks5_request {
    char ver;
    char cmd;
    char rsv;
    char atyp;
    char dst[SOCKS_BUFF_SIZE]; // addr/name and port info
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

/* Default port for SOCKS5 */
#define DEFAULT_SOCKS5_PORT 1080


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
#ifdef WIN32
/* Windows is commonly limited to 64 sockets, so keep the default somewhat below
   that. http://www.tangentsoft.net/wskfaq/advanced.html#64sockets */
#define DEFAULT_MAX_CONNS 60
#else
#define DEFAULT_MAX_CONNS 100
#endif

/* SOCKS4 protocol responses */
#define SOCKS4_VERSION          4
#define SOCKS_CONNECT           1
#define SOCKS_BIND              2
#define SOCKS4_CONN_ACC         90 /* woot */
#define SOCKS4_CONN_REF         91
#define SOCKS4_CONN_IDENT       92
#define SOCKS4_CONN_IDENTDIFF   93

/* SOCKS5 protocol */
#define SOCKS5_VERSION          5
#define SOCKS5_AUTH_NONE        0
#define SOCKS5_AUTH_GSSAPI      1
#define SOCKS5_AUTH_USERPASS    2
#define SOCKS5_AUTH_FAILED      255
#define SOCKS5_ATYP_IPv4        1
#define SOCKS5_ATYP_NAME        3
#define SOCKS5_ATYP_IPv6        4


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
