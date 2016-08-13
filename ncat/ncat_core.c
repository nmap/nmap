/***************************************************************************
 * ncat_core.c -- Contains option definitions and miscellaneous functions. *
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

/* Only two for now because we might have to listen on IPV4 and IPV6 */
union sockaddr_u listenaddrs[NUM_LISTEN_ADDRS];
int num_listenaddrs = 0;

union sockaddr_u srcaddr;
size_t srcaddrlen;

union sockaddr_u targetss;
size_t targetsslen;

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
    o.proto = IPPROTO_TCP;
    o.broker = 0;
    o.listen = 0;
    o.keepopen = 0;
    o.sendonly = 0;
    o.recvonly = 0;
    o.noshutdown = 0;
    o.telnet = 0;
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

    o.test = 0;

    o.numsrcrtes = 0;
    o.srcrteptr = 4;

    o.conn_limit = -1;  /* Unset. */
    o.conntimeout = DEFAULT_CONNECT_TIMEOUT;

    o.cmdexec = NULL;
    o.execmode = EXEC_PLAIN;
    o.proxy_auth = NULL;
    o.proxytype = NULL;
    o.zerobyte = 0;

#ifdef HAVE_OPENSSL
    o.ssl = 0;
    o.sslcert = NULL;
    o.sslkey = NULL;
    o.sslverify = 0;
    o.ssltrustfile = NULL;
    o.sslciphers = NULL;
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

    ncat_assert(hostname != NULL);
    ncat_assert(ss != NULL);
    ncat_assert(sslen != NULL);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = af;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags |= addl_flags;

    /* Make the port number a string to give to getaddrinfo. */
    rc = Snprintf(portbuf, sizeof(portbuf), "%hu", port);
    ncat_assert(rc >= 0 && (size_t) rc < sizeof(portbuf));

    rc = getaddrinfo(hostname, portbuf, &hints, &result);
    if (rc != 0)
        return rc;
    if (result == NULL)
        return EAI_NONAME;
    ncat_assert(result->ai_addrlen > 0 && result->ai_addrlen <= (int) sizeof(struct sockaddr_storage));
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
        ncat_assert(fdn != NULL);
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
 * it to return for at least that long.
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

/* this function will return in what format the target
 * host is specified. It will return:
 * 1 - for ipv4,
 * 2 - for ipv6,
 * -1 - for hostname
 * this has to work even if there is no IPv6 support on
 * local system, proxy may support it.
 */
int getaddrfamily(const char *addr)
{
    int ret;
    struct addrinfo hint, *info = 0;

    if (strchr(addr,':'))
      return 2;

    zmem(&hint,sizeof(hint));
    hint.ai_family = AF_UNSPEC;
    hint.ai_flags = AI_NUMERICHOST;
    ret = getaddrinfo(addr, 0, &hint, &info);
    if (ret)
        return -1;
    freeaddrinfo(info);
    return 1;
}

void setup_environment(struct fdinfo *info)
{
    union sockaddr_u su;
    char ip[INET6_ADDRSTRLEN];
    char port[16];
    socklen_t alen = sizeof(su);

    if (getpeername(info->fd, &su.sockaddr, &alen) != 0) {
        bye("getpeername failed: %s", socket_strerror(socket_errno()));
    }
#ifdef HAVE_SYS_UN_H
    if (su.sockaddr.sa_family == AF_UNIX) {
        /* say localhost to keep it backwards compatible */
        setenv_portable("NCAT_REMOTE_ADDR", "localhost");
        setenv_portable("NCAT_REMOTE_PORT", "");
    } else
#endif
    if (getnameinfo((struct sockaddr *)&su, alen, ip, sizeof(ip),
            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
        setenv_portable("NCAT_REMOTE_ADDR", ip);
        setenv_portable("NCAT_REMOTE_PORT", port);
    } else {
        bye("getnameinfo failed: %s", socket_strerror(socket_errno()));
    }

    if (getsockname(info->fd, (struct sockaddr *)&su, &alen) < 0) {
        bye("getsockname failed: %s", socket_strerror(socket_errno()));
    }
#ifdef HAVE_SYS_UN_H
    if (su.sockaddr.sa_family == AF_UNIX) {
        /* say localhost to keep it backwards compatible, else su.un.sun_path */
        setenv_portable("NCAT_LOCAL_ADDR", "localhost");
        setenv_portable("NCAT_LOCAL_PORT", "");
    } else
#endif
    if (getnameinfo((struct sockaddr *)&su, alen, ip, sizeof(ip),
            port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
        setenv_portable("NCAT_LOCAL_ADDR", ip);
        setenv_portable("NCAT_LOCAL_PORT", port);
    } else {
        bye("getnameinfo failed: %s", socket_strerror(socket_errno()));
    }

    switch(o.proto) {
        case IPPROTO_TCP:
            setenv_portable("NCAT_PROTO", "TCP");
            break;
        case IPPROTO_SCTP:
            setenv_portable("NCAT_PROTO", "SCTP");
            break;
        case IPPROTO_UDP:
            setenv_portable("NCAT_PROTO", "UDP");
            break;
    }
}
