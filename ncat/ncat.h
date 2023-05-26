/***************************************************************************
 * ncat.h                                                                  *
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

#ifndef NCAT_H_
#define NCAT_H_

#include "ncat_config.h"

#include <nbase.h>

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
#define NCAT_VERSION "7.94SVN"

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
    unsigned char nmethods;
    char methods[3];
} __attribute__((packed));

struct socks5_auth {
    char ver; // must be always 1
    unsigned char data[SOCKS_BUFF_SIZE];
} __attribute__((packed));

struct socks5_request {
    char ver;
    char cmd;
    char rsv;
    char atyp;
    unsigned char dst[SOCKS_BUFF_SIZE]; // addr/name and port info
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

#define SOCKS5_USR_MAXLEN       255
#define SOCKS5_PWD_MAXLEN       255
#define SOCKS5_DST_MAXLEN       255

#if SOCKS_BUFF_SIZE < (1 + SOCKS5_USR_MAXLEN) + (1 + SOCKS5_PWD_MAXLEN)
#error SOCKS_BUFF_SIZE is defined too small to handle SOCKS5 authentication
#endif

#if SOCKS_BUFF_SIZE < (1 + SOCKS5_DST_MAXLEN) + 2
#error SOCKS_BUFF_SIZE is defined too small to handle SOCKS5 destination
#endif

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
