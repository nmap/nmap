/***************************************************************************
 * ncat_core.c -- Contains option defintions and miscellaneous functions.  *
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

#include "ncat.h"
#include "util.h"
#include "sys_wrap.h"

#ifndef WIN32
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <time.h>
#include <assert.h>

/* Only two for now because we might have to listen on IPV4 and IPV6 */
union sockaddr_u listenaddrs[NUM_LISTEN_ADDRS];
int num_listenaddrs = 0;

union sockaddr_u srcaddr;
size_t srcaddrlen;

union sockaddr_u targetss;
size_t targetsslen;

union sockaddr_u httpconnect;
union sockaddr_u socksconnect;

/* Global options structure. */
struct options o;

/* The time the program was started, for exit statistics in connect mode. */
struct timeval start_time;

/* Initializes global options to their default values. */
void options_init(void)
{
    o.verbose = 0;
    o.debug = 0;
    o.target = NULL;
    o.af = AF_UNSPEC;
    o.broker = 0;
    o.listen = 0;
    o.keepopen = 0;
    o.sendonly = 0;
    o.recvonly = 0;
    o.telnet = 0;
    o.udp = 0;
    o.sctp = 0;
    o.linedelay = 0;
    o.chat = 0;
    o.nodns = 0;
    o.normlog = NULL;
    o.hexlog = NULL;
    o.normlogfd = -1;
    o.hexlogfd = -1;
    o.append = 0;
    o.idletimeout = 0;
    o.crlf = 0;
    o.allow = 0;
    o.deny = 0;
    addrset_init(&o.allowset);
    addrset_init(&o.denyset);
    o.httpserver = 0;

    o.nsock_engine = 0;

    o.numsrcrtes = 0;
    o.srcrteptr = 4;

    o.conn_limit = -1;  /* Unset. */
    o.conntimeout = DEFAULT_CONNECT_TIMEOUT;

    o.cmdexec = NULL;
    o.shellexec = 0;
    o.proxy_auth = NULL;
    o.proxytype = NULL;

#ifdef HAVE_OPENSSL
    o.ssl = 0;
    o.sslcert = NULL;
    o.sslkey = NULL;
    o.sslverify = 0;
    o.ssltrustfile = NULL;
#endif
}

/* Internal helper for resolve and resolve_numeric. addl_flags is ored into
   hints.ai_flags, so you can add AI_NUMERICHOST. */
static int resolve_internal(const char *hostname, unsigned short port,
    struct sockaddr_storage *ss, size_t *sslen, int af, int addl_flags)
{
    struct addrinfo hints;
    struct addrinfo *result;
    char portbuf[16];
    int rc;

    assert(hostname);
    assert(ss);
    assert(sslen);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = af;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags |= addl_flags;

    /* Make the port number a string to give to getaddrinfo. */
    rc = Snprintf(portbuf, sizeof(portbuf), "%hu", port);
    assert(rc >= 0 && (size_t) rc < sizeof(portbuf));

    rc = getaddrinfo(hostname, portbuf, &hints, &result);
    if (rc != 0)
        return rc;
    if (result == NULL)
        return EAI_NONAME;
    assert(result->ai_addrlen > 0 && result->ai_addrlen <= (int) sizeof(struct sockaddr_storage));
    *sslen = result->ai_addrlen;
    memcpy(ss, result->ai_addr, *sslen);
    freeaddrinfo(result);

    return 0;
}

/* Resolves the given hostname or IP address with getaddrinfo, and stores the
   first result (if any) in *ss and *sslen. The value of port will be set in the
   appropriate place in *ss; set to 0 if you don't care. af may be AF_UNSPEC, in
   which case getaddrinfo may return e.g. both IPv4 and IPv6 results; which one
   is first depends on the system configuration. Returns 0 on success, or a
   getaddrinfo return code (suitable for passing to gai_strerror) on failure.
   *ss and *sslen are always defined when this function returns 0.

   If the global o.nodns is true, then do not resolve any names with DNS. */
int resolve(const char *hostname, unsigned short port,
    struct sockaddr_storage *ss, size_t *sslen, int af)
{
    int flags;

    flags = 0;
    if (o.nodns)
        flags |= AI_NUMERICHOST;

    return resolve_internal(hostname, port, ss, sslen, af, flags);
}

int fdinfo_close(struct fdinfo *fdn)
{
#ifdef HAVE_OPENSSL
    if (o.ssl && fdn->ssl != NULL) {
        SSL_shutdown(fdn->ssl);
        SSL_free(fdn->ssl);
        fdn->ssl = NULL;
    }
#endif

    return close(fdn->fd);
}

/* Do a recv on an fdinfo, without other side effects. */
int fdinfo_recv(struct fdinfo *fdn, char *buf, size_t size)
{
#ifdef HAVE_OPENSSL
    if (o.ssl && fdn->ssl)
        return SSL_read(fdn->ssl, buf, size);
#endif
    return recv(fdn->fd, buf, size, 0);
}

int fdinfo_pending(struct fdinfo *fdn)
{
#ifdef HAVE_OPENSSL
    if (o.ssl && fdn->ssl)
        return SSL_pending(fdn->ssl);
#endif
    return 0;
}

/* Read from a client socket into buf, returning the number of bytes read, or -1
   on an error. This takes care of delays, Telnet negotiation, and logging.

   If there is more data pending that won't be noticed by select, a 1 is stored
   in *pending, otherwise 0 is stored there. The caller must loop, processing
   read data until *pending is false. The reason for this is the SSL_read
   function that this function may call, which takes data out of the socket
   buffer (so select may not indicate the socket is readable) and keeps it in
   its own buffer. *pending holds the result of calling SSL_pending. See
   http://www.mail-archive.com/openssl-dev@openssl.org/msg24324.html. */
int ncat_recv(struct fdinfo *fdn, char *buf, size_t size, int *pending)
{
    int n;

    *pending = 0;

    n = fdinfo_recv(fdn, buf, size);

    if (n <= 0)
        return n;

    if (o.linedelay)
        ncat_delay_timer(o.linedelay);
    if (o.telnet)
        dotelnet(fdn->fd, (unsigned char *) buf, n);
    ncat_log_recv(buf, n);

    /* SSL can buffer our input, so doing another select() won't necessarily
       work for us. Indicate to the caller that this function must be called
       again to get more data. */
    *pending = fdinfo_pending(fdn);

    return n;
}

/* Do a send on an fdinfo, without any logging or other side effects. */
int fdinfo_send(struct fdinfo *fdn, const char *buf, size_t size)
{
#ifdef HAVE_OPENSSL
    if (o.ssl && fdn->ssl != NULL)
        return SSL_write(fdn->ssl, buf, size);
#endif
    return send(fdn->fd, buf, size, 0);
}

/* If we are sending a large amount of data, we might momentarily run out of send
   space and get an EAGAIN when we send. Temporarily convert a socket to
   blocking more, do the send, and unblock it again. Assumes that the socket was
   in nonblocking mode to begin with; it has the side effect of leaving the
   socket nonblocking on return. */
static int blocking_fdinfo_send(struct fdinfo *fdn, const char *buf, size_t size)
{
    int ret;

    block_socket(fdn->fd);
    ret = fdinfo_send(fdn, buf, size);
    unblock_socket(fdn->fd);

    return ret;
}

int ncat_send(struct fdinfo *fdn, const char *buf, size_t size)
{
    int n;

    if (o.recvonly)
        return size;

    n = blocking_fdinfo_send(fdn, buf, size);
    if (n <= 0)
        return n;

    ncat_log_send(buf, size);

    return n;
}

/* Broadcast a message to all the descriptors in fds. Returns -1 if any of the
   sends failed. */
int ncat_broadcast(fd_set *fds, const fd_list_t *fdlist, const char *msg, size_t size)
{
    struct fdinfo *fdn;
    int i, ret;

    if (o.recvonly)
        return size;

    ret = 0;
    for (i = 0; i <= fdlist->fdmax; i++) {
        if (!FD_ISSET(i, fds))
            continue;

        fdn = get_fdinfo(fdlist, i);
        if (blocking_fdinfo_send(fdn, msg, size) <= 0) {
            if (o.debug > 1)
                logdebug("Error sending to fd %d: %s.\n", i, socket_strerror(socket_errno()));
            ret = -1;
        }
    }

    ncat_log_send(msg, size);

    return ret;
}

/* Do telnet WILL/WONT DO/DONT negotiations */
void dotelnet(int s, unsigned char *buf, size_t bufsiz)
{
    unsigned char *end = buf + bufsiz, *p;
    unsigned char tbuf[3];

    for (p = buf; buf < end; p++) {
        if (*p != 255) /* IAC */
            break;

        tbuf[0] = *p++;

        /* Answer DONT for WILL or WONT */
        if (*p == 251 || *p == 252)
            tbuf[1] = 254;

        /* Answer WONT for DO or DONT */
        else if (*p == 253 || *p == 254)
            tbuf[1] = 252;

        tbuf[2] = *++p;

        send(s, (const char *) tbuf, 3, 0);
    }
}

/* sleep(), usleep(), msleep(), Sleep() -- all together now, "portability".
 *
 * There is no upper or lower limit to the delayval, so if you pass in a short
 * length of time <100ms, then you're likely going to get odd results.
 * This is because the Linux timeslice is 10ms-200ms. So don't expect
 * it to return for atleast that long.
 *
 * Block until the specified time has elapsed, then return 1.
 */
int ncat_delay_timer(int delayval)
{
    struct timeval s;

    s.tv_sec = delayval / 1000;
    s.tv_usec = (delayval % 1000) * (long) 1000;

    select(0, NULL, NULL, NULL, &s);
    return 1;
}

/* Open a logfile for writing.
 * Return the open file descriptor. */
int ncat_openlog(const char *logfile, int append)
{
    if (append)
        return Open(logfile, O_WRONLY | O_CREAT | O_APPEND, 0664);
    else
        return Open(logfile, O_WRONLY | O_CREAT | O_TRUNC, 0664);
}

static int ncat_hexdump(int logfd, const char *data, int len);

void ncat_log_send(const char *data, size_t len)
{
    if (o.normlogfd != -1)
        Write(o.normlogfd, data, len);

    if (o.hexlogfd != -1)
        ncat_hexdump(o.hexlogfd, data, len);
}

void ncat_log_recv(const char *data, size_t len)
{
    /* Currently the log formats don't distinguish sends and receives. */
    ncat_log_send(data, len);
}

/* Convert session data to a neat hexdump logfile */
static int ncat_hexdump(int logfd, const char *data, int len)
{
    const char *p = data;
    char c;
    int i;
    char bytestr[4] = { 0 };
    char addrstr[10] = { 0 };
    char hexstr[16 * 3 + 5] = { 0 };
    char charstr[16 * 1 + 5] = { 0 };
    char outstr[80] = { 0 };

    /* FIXME: needs to be audited closer */
    for (i = 1; i <= len; i++) {
        if (i % 16 == 1) {
            /* Hex address output */
            Snprintf(addrstr, sizeof(addrstr), "%.4x", (u_int) (p - data));
        }

        c = *p;

        /* If the character isn't printable. Control characters, etc. */
        if (isprint((int) (unsigned char) c) == 0)
            c = '.';

        /* hex for output */
        Snprintf(bytestr, sizeof(bytestr), "%02X ", (unsigned char) *p);
        strncat(hexstr, bytestr, sizeof(hexstr) - strlen(hexstr) - 1);

        /* char for output */
        Snprintf(bytestr, sizeof(bytestr), "%c", c);
        strncat(charstr, bytestr, sizeof(charstr) - strlen(charstr) - 1);

        if (i % 16 == 0) {
            /* neatly formatted output */
            Snprintf(outstr, sizeof(outstr), "[%4.4s]   %-50.50s  %s\n",
                     addrstr, hexstr, charstr);

            Write(logfd, outstr, strlen(outstr));
            zmem(outstr, sizeof(outstr));

            hexstr[0] = 0;
            charstr[0] = 0;
        } else if (i % 8 == 0) {
            /* cat whitespaces where necessary */
            strncat(hexstr, "  ", sizeof(hexstr) - strlen(hexstr) - 1);
            strncat(charstr, " ", sizeof(charstr) - strlen(charstr) - 1);
        }

        /* get the next byte */
        p++;
    }

    /* if there's still data left in the buffer, print it */
    if (strlen(hexstr) > 0) {
        Snprintf(outstr, sizeof(outstr), "[%4.4s]   %-50.50s  %s\n",
                    addrstr, hexstr, charstr);

        Write(logfd, outstr, strlen(outstr));
        zmem(outstr, sizeof(outstr));
    }

    return 1;
}
