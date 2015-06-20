/***************************************************************************
 * util.c -- Various utility functions.                                    *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2015 Insecure.Com LLC. Nmap is    *
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

#include "sys_wrap.h"
#include "util.h"
#include "ncat.h"
#include "nbase.h"
#include "sockaddr_u.h"

#include <stdio.h>
#ifdef WIN32
#include <iphlpapi.h>
#endif
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

/* safely add 2 size_t */
size_t sadd(size_t l, size_t r)
{
    size_t t;

    t = l + r;
    if (t < l)
        bye("integer overflow %lu + %lu.", (u_long) l, (u_long) r);
    return t;
}

/* safely multiply 2 size_t */
size_t smul(size_t l, size_t r)
{
    size_t t;

    t = l * r;
    if (l && t / l != r)
        bye("integer overflow %lu * %lu.", (u_long) l, (u_long) r);
    return t;
}

#ifdef WIN32
void windows_init()
{
    WORD werd;
    WSADATA data;

    werd = MAKEWORD(2, 2);
    if ((WSAStartup(werd, &data)) != 0)
        bye("Failed to start WinSock.");
}
#endif

/* Use this to print debug or diagnostic messages to avoid polluting the user
   stream. */
void loguser(const char *fmt, ...)
{
    va_list ap;

    fprintf(stderr, "%s: ", NCAT_NAME);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fflush(stderr);
}

/* Log a user message without the "Ncat: " prefix, to allow building up a line
   with a series of strings. */
void loguser_noprefix(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fflush(stderr);
}

void logdebug(const char *fmt, ...)
{
    va_list ap;

    fprintf(stderr, "NCAT DEBUG: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fflush(stderr);
}

void logtest(const char *fmt, ...)
{
    va_list ap;

    fprintf(stderr, "NCAT TEST: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fflush(stderr);
}

/* Exit status 2 indicates a program error other than a network error. */
void die(char *err)
{
    perror(err);
    fflush(stderr);
    exit(2);
}

/* adds newline for you */
void bye(const char *fmt, ...)
{
    va_list ap;

    fprintf(stderr, "%s: ", NCAT_NAME);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, " QUITTING.\n");
    fflush(stderr);

    exit(2);
}

/* zero out some mem, bzero() is deprecated */
void zmem(void *mem, size_t n)
{
    memset(mem, 0, n);
}

/* Append n bytes starting at s to a malloc-allocated buffer. Reallocates the
   buffer and updates the variables to make room if necessary. */
int strbuf_append(char **buf, size_t *size, size_t *offset, const char *s, size_t n)
{
    ncat_assert(*offset <= *size);

    if (n >= *size - *offset) {
        *size += n + 1;
        *buf = (char *) safe_realloc(*buf, *size);
    }

    memcpy(*buf + *offset, s, n);
    *offset += n;
    (*buf)[*offset] = '\0';

    return n;
}

/* Append a '\0'-terminated string as with strbuf_append. */
int strbuf_append_str(char **buf, size_t *size, size_t *offset, const char *s)
{
    return strbuf_append(buf, size, offset, s, strlen(s));
}

/* Do a sprintf at the given offset into a malloc-allocated buffer. Reallocates
   the buffer and updates the variables to make room if necessary. */
int strbuf_sprintf(char **buf, size_t *size, size_t *offset, const char *fmt, ...)
{
    va_list va;
    int n;

    ncat_assert(*offset <= *size);

    if (*buf == NULL) {
        *size = 1;
        *buf = (char *) safe_malloc(*size);
    }

    for (;;) {
        va_start(va, fmt);
        n = Vsnprintf(*buf + *offset, *size - *offset, fmt, va);
        va_end(va);
        if (n < 0)
            *size = MAX(*size, 1) * 2;
        else if (n >= *size - *offset)
            *size += n + 1;
        else
            break;
        *buf = (char *) safe_realloc(*buf, *size);
    }
    *offset += n;

    return n;
}

/* Return true if the given address is a local one. */
int addr_is_local(const union sockaddr_u *su)
{
    struct addrinfo hints = { 0 }, *addrs, *addr;
    char hostname[128];

    /* Check loopback addresses. */
    if (su->storage.ss_family == AF_INET) {
        if ((ntohl(su->in.sin_addr.s_addr) & 0xFF000000UL) == 0x7F000000UL)
            return 1;
        if (ntohl(su->in.sin_addr.s_addr) == 0x00000000UL)
            return 1;
    }
#ifdef HAVE_IPV6
    else if (su->storage.ss_family == AF_INET6) {
        if (memcmp(&su->in6.sin6_addr, &in6addr_any, sizeof(su->in6.sin6_addr)) == 0
            || memcmp(&su->in6.sin6_addr, &in6addr_loopback, sizeof(su->in6.sin6_addr)) == 0)
            return 1;
    }
#endif

    /* Check addresses assigned to the local host name. */
    if (gethostname(hostname, sizeof(hostname)) == -1)
        return 0;
    hints.ai_family = su->storage.ss_family;
    if (getaddrinfo(hostname, NULL, &hints, &addrs) != 0)
        return 0;
    for (addr = addrs; addr != NULL; addr = addr->ai_next) {
        union sockaddr_u addr_su;

        if (addr->ai_family != su->storage.ss_family)
            continue;
        if (addr->ai_addrlen > sizeof(addr_su)) {
            bye("getaddrinfo returned oversized address (%lu > %lu)",
                (unsigned long) addr->ai_addrlen, (unsigned long) sizeof(addr_su));
        }
        memcpy(&addr_su, addr->ai_addr, addr->ai_addrlen);
        if (su->storage.ss_family == AF_INET) {
            if (su->in.sin_addr.s_addr == addr_su.in.sin_addr.s_addr)
                break;
        } else if (su->storage.ss_family == AF_INET6) {
            if (memcmp(&su->in6.sin6_addr, &addr_su.in6.sin6_addr, sizeof(su->in6.sin6_addr)) == 0)
                break;
        }
    }
    if (addr != NULL) {
        freeaddrinfo(addrs);
        return 1;
    } else {
        return 0;
    }
}

/* Converts an IP address given in a sockaddr_u to an IPv4 or
   IPv6 IP address string.  Since a static buffer is returned, this is
   not thread-safe and can only be used once in calls like printf()
*/
const char *inet_socktop(const union sockaddr_u *su)
{
    static char buf[INET6_ADDRSTRLEN + 1];
    void *addr;

    if (su->storage.ss_family == AF_INET)
        addr = (void *) &su->in.sin_addr;
#if HAVE_IPV6
    else if (su->storage.ss_family == AF_INET6)
        addr = (void *) &su->in6.sin6_addr;
#endif
    else
        addr = NULL;

    if (inet_ntop(su->storage.ss_family, addr, buf, sizeof(buf)) == NULL) {
        bye("Failed to convert address to presentation format!  Error: %s.",
            strerror(socket_errno()));
    }

    return buf;
}

/* Returns the port number in HOST BYTE ORDER based on the su's family */
unsigned short inet_port(const union sockaddr_u *su)
{
    if (su->storage.ss_family == AF_INET)
        return ntohs(su->in.sin_port);
#if HAVE_IPV6
    else if (su->storage.ss_family == AF_INET6)
        return ntohs(su->in6.sin6_port);
#endif

    bye("Invalid address family passed to inet_port().");
    return 0;
}

/* Return a listening socket after setting various characteristics on it.
   Returns -1 on error. */
int do_listen(int type, int proto, const union sockaddr_u *srcaddr_u)
{
    int sock = 0, option_on = 1;
    size_t sa_len;

    if (type != SOCK_STREAM && type != SOCK_DGRAM)
        return -1;

    /* We need a socket that can be inherited by child processes in
       ncat_exec_win.c, for --exec and --sh-exec. inheritable_socket is from
       nbase. */
    sock = inheritable_socket(srcaddr_u->storage.ss_family, type, proto);
    if (sock < 0)
        return -1;

    Setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &option_on, sizeof(int));

/* IPPROTO_IPV6 is defined in Visual C++ only when _WIN32_WINNT >= 0x501.
   Nbase's nbase_winunix.h defines _WIN32_WINNT to a lower value for
   compatibility with older versions of Windows. This code disables IPv6 sockets
   that also receive IPv4 connections. This is the default on Windows anyway so
   it doesn't make a difference.
   http://support.microsoft.com/kb/950688
   http://msdn.microsoft.com/en-us/library/bb513665
*/
#ifdef IPPROTO_IPV6
#ifdef IPV6_V6ONLY
    if (srcaddr_u->storage.ss_family == AF_INET6) {
        int set = 1;
        /* Tell it to not try and bind to IPV4 */
        if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &set, sizeof(set)) == -1)
            die("Unable to set IPV6 socket to bind only to IPV6");
    }
#endif
#endif

    switch(srcaddr_u->storage.ss_family) {
#ifdef HAVE_SYS_UN_H
      case AF_UNIX:
        sa_len = SUN_LEN(&srcaddr_u->un);
        break;
#endif
#ifdef HAVE_SOCKADDR_SA_LEN
      default:
        sa_len = srcaddr_u->sockaddr.sa_len;
        break;
#else
      case AF_INET:
        sa_len = sizeof (struct sockaddr_in);
        break;
#ifdef AF_INET6
      case AF_INET6:
        sa_len = sizeof (struct sockaddr_in6);
        break;
#endif
      default:
        sa_len = sizeof(*srcaddr_u);
        break;
#endif
    }

    if (bind(sock, &srcaddr_u->sockaddr, sa_len) < 0) {
#ifdef HAVE_SYS_UN_H
        if (srcaddr_u->storage.ss_family == AF_UNIX)
            bye("bind to %s: %s.", srcaddr_u->un.sun_path,
                socket_strerror(socket_errno()));
        else
#endif
            bye("bind to %s:%hu: %s.", inet_socktop(srcaddr_u),
                inet_port(srcaddr_u), socket_strerror(socket_errno()));
    }

    if (type == SOCK_STREAM)
        Listen(sock, BACKLOG);

    if (o.verbose) {
#ifdef HAVE_SYS_UN_H
        if (srcaddr_u->storage.ss_family == AF_UNIX)
            loguser("Listening on %s\n", srcaddr_u->un.sun_path);
        else
#endif
            loguser("Listening on %s:%hu\n", inet_socktop(srcaddr_u), inet_port(srcaddr_u));
    }
    if (o.test)
        logtest("LISTEN\n");

    return sock;
}

int do_connect(int type)
{
    int sock = 0;

    if (type != SOCK_STREAM && type != SOCK_DGRAM)
        return -1;

    /* We need a socket that can be inherited by child processes in
       ncat_exec_win.c, for --exec and --sh-exec. inheritable_socket is from
       nbase. */
    sock = inheritable_socket(targetss.storage.ss_family, type, 0);

    if (srcaddr.storage.ss_family != AF_UNSPEC) {
        size_t sa_len;

#ifdef HAVE_SOCKADDR_SA_LEN
        sa_len = srcaddr.sockaddr.sa_len;
#else
        sa_len = sizeof(srcaddr);
#endif
        if (bind(sock, &srcaddr.sockaddr, sa_len) < 0) {
            bye("bind to %s:%hu: %s.", inet_socktop(&srcaddr),
                inet_port(&srcaddr), socket_strerror(socket_errno()));
        }
    }

    if (sock != -1) {
        if (connect(sock, &targetss.sockaddr, (int) targetsslen) != -1)
            return sock;
        else if (socket_errno() == EINPROGRESS || socket_errno() == EAGAIN)
            return sock;
    }
    return -1;
}

unsigned char *buildsrcrte(struct in_addr dstaddr, struct in_addr routes[],
                  int numroutes, int ptr, size_t *len)
{
    int x;
    unsigned char *opts, *p;

    *len = (numroutes + 1) * sizeof(struct in_addr) + 4;

    if (numroutes > 8)
        bye("Bad number of routes passed to buildsrcrte().");

    opts = (unsigned char *) safe_malloc(*len);
    p = opts;

    zmem(opts, *len);

    *p++ = 0x01; /* IPOPT_NOP, for alignment */
    *p++ = 0x83; /* IPOPT_LSRR */
    *p++ = (char) (*len - 1); /* subtract nop */
    *p++ = (char) ptr;

    for (x = 0; x < numroutes; x++) {
        memcpy(p, &routes[x], sizeof(routes[x]));
        p += sizeof(routes[x]);
    }

    memcpy(p, &dstaddr, sizeof(dstaddr));

    return opts;
}

int allow_access(const union sockaddr_u *su)
{
    /* A host not in the allow set is denied, but only if the --allow or
       --allowfile option was given. */
    if (o.allow && !addrset_contains(&o.allowset, &su->sockaddr))
        return 0;
    if (addrset_contains(&o.denyset, &su->sockaddr))
        return 0;

    return 1;
}

/*
 * Fills the given timeval struct with proper
 * values based on the given time in milliseconds.
 * The pointer to timeval struct must NOT be NULL.
 */
void ms_to_timeval(struct timeval *tv, long ms)
{
    tv->tv_sec = ms / 1000;
    tv->tv_usec = (ms - (tv->tv_sec * 1000)) * 1000;
}

/*
 * ugly code to maintain our list of fds so we can have proper fdmax for
 * select().  really this should be generic list code, not this silly bit of
 * stupidity. -sean
 */

/* add an fdinfo to our list */
int add_fdinfo(fd_list_t *fdl, struct fdinfo *s)
{
    if (fdl->nfds >= fdl->maxfds)
        return -1;

    fdl->fds[fdl->nfds] = *s;

    fdl->nfds++;

    if (s->fd > fdl->fdmax)
        fdl->fdmax = s->fd;

    if (o.debug > 1)
        logdebug("Added fd %d to list, nfds %d, maxfd %d\n", s->fd, fdl->nfds, fdl->fdmax);
    return 0;
}

/* Add a descriptor to the list. Use this when you are only adding to the list
 * for the side effect of increasing fdmax, and don't care about fdinfo
 * members. */
int add_fd(fd_list_t *fdl, int fd)
{
    struct fdinfo info = { 0 };

    info.fd = fd;

    return add_fdinfo(fdl, &info);
}

/* remove a descriptor from our list */
int rm_fd(fd_list_t *fdl, int fd)
{
    int x = 0, last = fdl->nfds;

    /* make sure we have a list */
    if (last == 0)
        bye("Program bug: Trying to remove fd from list with no fds.");

    /* find the fd in the list */
    for (x = 0; x < last; x++)
        if (fdl->fds[x].fd == fd)
            break;

    /* make sure we found it */
    if (x == last)
        bye("Program bug: fd (%d) not on list.", fd);

    /* remove it, does nothing if (last == 1) */
    if (o.debug > 1)
        logdebug("Swapping fd[%d] (%d) with fd[%d] (%d)\n",
                 x, fdl->fds[x].fd, last - 1, fdl->fds[last - 1].fd);
    fdl->fds[x] = fdl->fds[last - 1];

    fdl->nfds--;

    /* was it the max */
    if (fd == fdl->fdmax)
        fdl->fdmax = get_maxfd(fdl);

    if (o.debug > 1)
        logdebug("Removed fd %d from list, nfds %d, maxfd %d\n", fd, fdl->nfds, fdl->fdmax);
    return 0;
}

/* find the max descriptor in our list */
int get_maxfd(fd_list_t *fdl)
{
    int x = 0, max = -1, nfds = fdl->nfds;

    for (x = 0; x < nfds; x++)
        if (fdl->fds[x].fd > max)
            max = fdl->fds[x].fd;

    return max;
}

struct fdinfo *get_fdinfo(const fd_list_t *fdl, int fd)
{
    int x;

    for (x = 0; x < fdl->nfds; x++)
        if (fdl->fds[x].fd == fd)
            return &fdl->fds[x];

    return NULL;
}

void init_fdlist(fd_list_t *fdl, int maxfds)
{
    fdl->fds = (struct fdinfo *) Calloc(maxfds, sizeof(struct fdinfo));
    fdl->nfds = 0;
    fdl->fdmax = -1;
    fdl->maxfds = maxfds;

    if (o.debug > 1)
        logdebug("Initialized fdlist with %d maxfds\n", maxfds);
}

void free_fdlist(fd_list_t *fdl)
{
    free(fdl->fds);
    fdl->nfds = 0;
    fdl->fdmax = -1;
}


/*  If any changes need to be made to EOL sequences to comply with --crlf
 *  then dst will be populated with the modified src, len will be adjusted
 *  accordingly and the return will be non-zero.
 *
 *  state is used to keep track of line endings that span more than one call to
 *  this function. On the first call, state should be a pointer to a int
 *  containing 0. Thereafter, keep passing the same pointer. Separate logical
 *  streams should use separate state pointers.
 *
 *  Returns 0 if changes were not made - len and dst will remain untouched.
 */
int fix_line_endings(char *src, int *len, char **dst, int *state)
{
    int fix_count;
    int i, j;
    int num_bytes = *len;
    int prev_state = *state;

    /* *state is true iff the last byte of the previous block was \r. */
    if (num_bytes > 0)
        *state = (src[num_bytes - 1] == '\r');

    /* get count of \n without matching \r */
    fix_count = 0;
    for (i = 0; i < num_bytes; i++) {
        if (src[i] == '\n' && ((i == 0) ? !prev_state : src[i - 1] != '\r'))
            fix_count++;
    }
    if (fix_count <= 0)
        return 0;

    /* now insert matching \r */
    *dst = (char *) safe_malloc(num_bytes + fix_count);
    j = 0;

    for (i = 0; i < num_bytes; i++) {
        if (src[i] == '\n' && ((i == 0) ? !prev_state : src[i - 1] != '\r')) {
            memcpy(*dst + j, "\r\n", 2);
            j += 2;
        } else {
            memcpy(*dst + j, src + i, 1);
            j++;
        }
    }
    *len += fix_count;

    return 1;
}
