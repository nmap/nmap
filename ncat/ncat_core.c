/***************************************************************************
 * ncat_core.c -- Contains option definitions and miscellaneous functions. *
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

struct sockaddr_list *targetaddrs;

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
    o.allowset = addrset_new();
    o.denyset = addrset_new();
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
    o.proxyaddr = NULL;
    o.proxydns = PROXYDNS_REMOTE;
    o.zerobyte = 0;

#ifdef HAVE_OPENSSL
    o.ssl = 0;
    o.sslcert = NULL;
    o.sslkey = NULL;
    o.sslverify = 0;
    o.ssltrustfile = NULL;
    o.sslciphers = NULL;
    o.sslservername = NULL;
    o.sslalpn = NULL;
#endif
}

/* Internal helper for resolve and resolve_numeric. addl_flags is ored into
   hints.ai_flags, so you can add AI_NUMERICHOST.
   sl is a pointer to first element of sockaddr linked list, which is always
   statically allocated. Next list elements are dynamically allocated.
   If multiple_addrs is false then only first address is returned. */
static int resolve_internal(const char *hostname, unsigned short port,
    struct sockaddr_list *sl, int af, int addl_flags, int multiple_addrs)
{
    struct addrinfo hints;
    struct addrinfo *result;
    struct addrinfo *next;
    struct sockaddr_list **item_ptr = &sl;
    struct sockaddr_list *new_item;
    char portbuf[16];
    int rc;

    ncat_assert(hostname != NULL);

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
    for (next = result; next != NULL; next = next->ai_next) {
        if (*item_ptr == NULL)
        {
            *item_ptr = (struct sockaddr_list *)safe_malloc(sizeof(struct sockaddr_list));
            (**item_ptr).next = NULL;
        }
        new_item = *item_ptr;
        new_item->addrlen = next->ai_addrlen;
        memcpy(&new_item->addr.storage, next->ai_addr, next->ai_addrlen);
        if (!multiple_addrs)
            break;
        item_ptr = &new_item->next;
    }
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
    struct sockaddr_list sl;
    int result;

    flags = 0;
    if (o.nodns)
        flags |= AI_NUMERICHOST;

    result = resolve_internal(hostname, port, &sl, af, flags, 0);
    *ss = sl.addr.storage;
    *sslen = sl.addrlen;
    return result;
}

/* Resolves the given hostname or IP address with getaddrinfo, and stores the
   first result (if any) in *ss and *sslen. The value of port will be set in the
   appropriate place in *ss; set to 0 if you don't care. af may be AF_UNSPEC, in
   which case getaddrinfo may return e.g. both IPv4 and IPv6 results; which one
   is first depends on the system configuration. Returns 0 on success, or a
   getaddrinfo return code (suitable for passing to gai_strerror) on failure.
   *ss and *sslen are always defined when this function returns 0.

   Resolve the hostname with DNS only if global o.proxydns includes PROXYDNS_LOCAL. */
int proxyresolve(const char *hostname, unsigned short port,
    struct sockaddr_storage *ss, size_t *sslen, int af)
{
    int flags;
    struct sockaddr_list sl;
    int result;

    flags = 0;
    if (!(o.proxydns & PROXYDNS_LOCAL))
        flags |= AI_NUMERICHOST;

    result = resolve_internal(hostname, port, &sl, af, flags, 0);
    *ss = sl.addr.storage;
    *sslen = sl.addrlen;
    return result;
}

/* Resolves the given hostname or IP address with getaddrinfo, and stores
   all results into a linked list.
   The rest of the behavior is same as resolve(). */
int resolve_multi(const char *hostname, unsigned short port,
    struct sockaddr_list *sl, int af)
{
    int flags;

    flags = 0;
    if (o.nodns)
        flags |= AI_NUMERICHOST;

    return resolve_internal(hostname, port, sl, af, flags, 1);
}

void free_sockaddr_list(struct sockaddr_list *sl)
{
    struct sockaddr_list *current, *next = sl;
    while (next != NULL) {
        current = next;
        next = current->next;
        free(current);
    }
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
    int n;
#ifdef HAVE_OPENSSL
    int err = SSL_ERROR_NONE;
    if (o.ssl && fdn->ssl)
    {
        do {
            n = SSL_read(fdn->ssl, buf, size);
            /* SSL_read returns <0 in some cases like renegotiation. In these
             * cases, SSL_get_error gives SSL_ERROR_WANT_{READ,WRITE}, and we
             * should try the SSL_read again. */
            err = (n < 0) ? SSL_get_error(fdn->ssl, n) : SSL_ERROR_NONE;
        } while (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE);
        if (err != SSL_ERROR_NONE) {
            fdn->lasterr = err;
            logdebug("SSL_read error on %d: %s\n", fdn->fd, ERR_error_string(err, NULL));
        }
        return n;
    }
#endif
    n = recv(fdn->fd, buf, size, 0);
    if (n == 0)
        fdn->lasterr = EOF;
    else if (n < 0)
        fdn->lasterr = socket_errno();
    return n;
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
    int n;
#ifdef HAVE_OPENSSL
    int err = SSL_ERROR_NONE;
    if (o.ssl && fdn->ssl != NULL)
    {
        do {
            n = SSL_write(fdn->ssl, buf, size);
            /* SSL_write returns <0 in some cases like renegotiation. In these
             * cases, SSL_get_error gives SSL_ERROR_WANT_{READ,WRITE}, and we
             * should try the SSL_write again. */
            err = (n < 0) ? SSL_get_error(fdn->ssl, n) : SSL_ERROR_NONE;
        } while (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE);
        if (err != SSL_ERROR_NONE) {
            fdn->lasterr = err;
            logdebug("SSL_write error on %d: %s\n", fdn->fd, ERR_error_string(err, NULL));
        }
        return n;
    }
#endif
    n = send(fdn->fd, buf, size, 0);
    if (n <= 0)
        fdn->lasterr = socket_errno();
    return n;
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
    for (i = 0; i < fdlist->nfds; i++) {
        fdn = &fdlist->fds[i];
        if (!checked_fd_isset(fdn->fd, fds))
            continue;

        if (blocking_fdinfo_send(fdn, msg, size) <= 0) {
            if (o.debug > 1)
                logdebug("Error sending to fd %d: %s.\n", fdn->fd, socket_strerror(fdn->lasterr));
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
  char *str = NULL;
  str = hexdump((u8 *) data, len);
  if (str) {
    Write(logfd, str, strlen(str));
    free(str);
  }
  else {
    return 0;
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
#ifdef HAVE_LINUX_VM_SOCKETS_H
    if (su.sockaddr.sa_family == AF_VSOCK) {
        char char_u32[11];

        snprintf(char_u32, sizeof(char_u32), "%u", su.vm.svm_cid);
        setenv_portable("NCAT_REMOTE_ADDR", char_u32);

        snprintf(char_u32, sizeof(char_u32), "%u", su.vm.svm_port);
        setenv_portable("NCAT_REMOTE_PORT", char_u32);
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
#ifdef HAVE_LINUX_VM_SOCKETS_H
    if (su.sockaddr.sa_family == AF_VSOCK) {
        char char_u32[11];

        snprintf(char_u32, sizeof(char_u32), "%u", su.vm.svm_cid);
        setenv_portable("NCAT_LOCAL_ADDR", char_u32);

        snprintf(char_u32, sizeof(char_u32), "%u", su.vm.svm_port);
        setenv_portable("NCAT_LOCAL_PORT", char_u32);
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
