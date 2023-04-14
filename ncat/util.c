/***************************************************************************
 * util.c -- Various utility functions.                                    *
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
#include <stddef.h>

#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#if HAVE_LINUX_VM_SOCKETS_H
#include <linux/vm_sockets.h>
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
#ifdef WIN32
  int error_number;
  char *strerror_s;
  error_number = GetLastError();
  FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM,
      NULL, error_number, MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),
      (LPTSTR) &strerror_s,  0, NULL);
  fprintf(stderr, "%s: %s\n", err, strerror_s);
  HeapFree(GetProcessHeap(), 0, strerror_s);
#else
    perror(err);
#endif
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

/* Converts a sockaddr_u to a string representation. Since a static buffer is
 * returned, this is not thread-safe and can only be used once in calls like
 * printf(). ss_len may be 0 if it is not already known.
*/
const char *socktop(const union sockaddr_u *su, socklen_t ss_len)
{
    static char buf[INET6_ADDRSTRLEN + sizeof(union sockaddr_u)];
    size_t size = sizeof(buf);

    switch (su->storage.ss_family) {
#if HAVE_SYS_UN_H
        case AF_UNIX:
            ncat_assert(ss_len <= sizeof(struct sockaddr_un));
            if (ss_len == sizeof(sa_family_t)) {
                /* Unnamed socket */
                Strncpy(buf, "(unnamed socket)", sizeof(buf));
            }
            else {
                if (ss_len < sizeof(sa_family_t)) {
                    /* socket path not guaranteed to be valid, but we'll try. */
                    size = sizeof(su->un.sun_path);
                }
                else {
                    /* We will add null terminator at size + 1 in case it was missing. */
                    size = MIN(sizeof(buf) - 1,
                            ss_len - offsetof(struct sockaddr_un, sun_path));
                }
                if (su->un.sun_path[0] == '\0') {
                    /* Abstract socket (Linux extension) */
                    memcpy(buf, su->un.sun_path + 1, size - 1);
                    Strncpy(buf + size, " (abstract socket)", sizeof(buf) - size);
                }
                else {
                    memcpy(buf, su->un.sun_path, size);
                    buf[size+1] = '\0';
                }
                /* In case we got junk data, make it safe. */
                replacenonprintable(buf, strlen(buf), '?');
            }
            break;
#endif
#ifdef HAVE_LINUX_VM_SOCKETS_H
        case AF_VSOCK:
            Snprintf(buf, sizeof(buf), "%u:%u", su->vm.svm_cid, su->vm.svm_port);
            break;
#endif
        case AF_INET:
            Snprintf(buf, sizeof(buf), "%s:%hu", inet_socktop(su), inet_port(su));
            break;
        case AF_INET6:
            Snprintf(buf, sizeof(buf), "[%s]:%hu", inet_socktop(su), inet_port(su));
            break;
        default:
            return NULL;
            break;
    }
    return buf;
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
        bye("Invalid address family passed to inet_socktop().");

    if (inet_ntop(su->storage.ss_family, addr, buf, sizeof(buf)) == NULL) {
        bye("Failed to convert address to presentation format!  Error: %s.",
            strerror(socket_errno()));
    }

    return buf;
}

/* Returns the port number in HOST BYTE ORDER based on the su's family */
unsigned short inet_port(const union sockaddr_u *su)
{
    switch (su->storage.ss_family) {
        case AF_INET:
            return ntohs(su->in.sin_port);
            break;
#if HAVE_IPV6
        case AF_INET6:
            return ntohs(su->in6.sin6_port);
            break;
#endif
        default:
            bye("Invalid address family passed to inet_port().");
            break;
    }
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

    sa_len = get_socklen(srcaddr_u);

    if (bind(sock, &srcaddr_u->sockaddr, sa_len) < 0) {
        bye("bind to %s: %s.", socktop(srcaddr_u, sa_len),
                socket_strerror(socket_errno()));
    }

    if (type == SOCK_STREAM)
        Listen(sock, BACKLOG);

    if (o.verbose) {
        loguser("Listening on %s\n", socktop(srcaddr_u, sa_len));
    }
    if (o.test)
        logtest("LISTEN\n");

    return sock;
}

/* Only used in proxy connect functions, so doesn't need to support address
 * families that don't support proxying like AF_UNIX and AF_VSOCK */
int do_connect(int type)
{
    int sock = 0;

    if (type != SOCK_STREAM && type != SOCK_DGRAM)
        return -1;

    /* We need a socket that can be inherited by child processes in
       ncat_exec_win.c, for --exec and --sh-exec. inheritable_socket is from
       nbase. */
    sock = inheritable_socket(targetaddrs->addr.storage.ss_family, type, 0);

    if (srcaddr.storage.ss_family != AF_UNSPEC) {
        size_t sa_len = get_socklen(&srcaddr);

        if (bind(sock, &srcaddr.sockaddr, sa_len) < 0) {
            bye("bind to %s: %s.", socktop(&srcaddr, sa_len),
                    socket_strerror(socket_errno()));
        }
    }

    if (sock != -1) {
        if (connect(sock, &targetaddrs->addr.sockaddr, (int) targetaddrs->addrlen) != -1)
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
    if (o.allow && !addrset_contains(o.allowset, &su->sockaddr))
        return 0;
    if (addrset_contains(o.denyset, &su->sockaddr))
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
    int found = -1;
    int newfdmax = 0;

    /* make sure we have a list */
    if (last == 0)
        bye("Program bug: Trying to remove fd from list with no fds.");

    /* find the fd in the list */
    for (x = 0; x < last; x++) {
        struct fdinfo *fdi = &fdl->fds[x];
        if (fdi->fd == fd) {
            found = x;
            /* If it's not the max, we can bail early. */
            if (fd < fdl->fdmax) {
                newfdmax = fdl->fdmax;
                break;
            }
        }
        else if (fdi->fd > newfdmax)
            newfdmax = fdi->fd;
    }
    fdl->fdmax = newfdmax;

    /* make sure we found it */
    if (found < 0)
        bye("Program bug: fd (%d) not on list.", fd);

    /* remove it, does nothing if (last == 1) */
    if (o.debug > 1)
        logdebug("Swapping fd[%d] (%d) with fd[%d] (%d)\n",
                 found, fdl->fds[found].fd, last - 1, fdl->fds[last - 1].fd);
    fdl->fds[found] = fdl->fds[last - 1];
    fdl->state++;

    fdl->nfds--;

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
    fdl->state = 0;

    if (o.debug > 1)
        logdebug("Initialized fdlist with %d maxfds\n", maxfds);
}

void free_fdlist(fd_list_t *fdl)
{
    free(fdl->fds);
    fdl->nfds = 0;
    fdl->fdmax = -1;
    fdl->state = 0;
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

/*-
 * next_protos_parse parses a comma separated list of strings into a string
 * in a format suitable for passing to SSL_CTX_set_next_protos_advertised.
 *   outlen: (output) set to the length of the resulting buffer on success.
 *   err: NULL on failure
 *   in: a NULL terminated string like "abc,def,ghi"
 *
 *   returns: a malloc'd buffer or NULL on failure.
 */
unsigned char *next_protos_parse(size_t *outlen, const char *in)
{
    size_t len;
    unsigned char *out;
    size_t i, start = 0;

    len = strlen(in);
    if (len >= 65535)
        return NULL;

    out = (unsigned char *)safe_malloc(strlen(in) + 1);
    for (i = 0; i <= len; ++i) {
        if (i == len || in[i] == ',') {
            if (i - start > 255) {
                free(out);
                return NULL;
            }
            out[start] = i - start;
            start = i + 1;
        } else
            out[i + 1] = in[i];
    }

    *outlen = len + 1;
    return out;
}
