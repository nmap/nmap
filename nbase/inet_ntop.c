/* Copyright (c) 1996 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/* Modified by Fyodor (fyodor@nmap.org) for inclusion in the Nmap
 * Security Scanner.
 *
 * $Id$
 */

#include "nbase.h"

#ifndef HAVE_INET_NTOP

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
#include <string.h>
#if HAVE_ERRNO_H
#include <errno.h>
#endif
#include <stdio.h>

#ifndef IN6ADDRSZ
#define IN6ADDRSZ   16
#endif

#ifndef INT16SZ
#define INT16SZ sizeof(u16)
#endif

#if !defined(EAFNOSUPPORT) && defined(WSAEAFNOSUPPORT)
#define EAFNOSUPPORT WSAEAFNOSUPPORT
#endif

/*
 * WARNING: Don't even consider trying to compile this on a system where
 * sizeof(int) < 4.  sizeof(int) > 4 is fine; all the world's not a VAX.
 */

static const char *inet_ntop4(const unsigned char *src, char *dst, size_t size);
#if HAVE_IPV6
static const char *inet_ntop6(const unsigned char *src, char *dst, size_t size);
#endif

/* char *
 * inet_ntop(af, src, dst, size)
 *        convert a network format address to presentation format.
 * return:
 *        pointer to presentation format address (`dst'), or NULL (see errno).
 * author:
 *        Paul Vixie, 1996.
 */
const char *
inet_ntop(int af, const void *src, char *dst, size_t size)
{
        switch (af) {
        case AF_INET:
                return (inet_ntop4((const unsigned char *) src, dst, size));
#if HAVE_IPV6
        case AF_INET6:
                return (inet_ntop6((const unsigned char *) src, dst, size));
#endif
        default:
#ifndef WIN32
                errno = EAFNOSUPPORT;
#endif
                return (NULL);
        }
        /* NOTREACHED */
}

/* const char *
 * inet_ntop4(src, dst, size)
 *        format an IPv4 address, more or less like inet_ntoa()
 * return:
 *        `dst' (as a const)
 * notes:
 *        (1) uses no statics
 *        (2) takes a u_char* not an in_addr as input
 * author:
 *        Paul Vixie, 1996.
 */
static const char *
inet_ntop4(const unsigned char *src, char *dst, size_t size)
{
        const size_t MIN_SIZE = 16; /* space for 255.255.255.255\0 */
        int n = 0;
        char *next = dst;

        if (size < MIN_SIZE) {
#ifndef WIN32
            errno = ENOSPC;
#endif
            return NULL;
        }
        do {
            unsigned char u = *src++;
            if (u > 99) {
                *next++ = '0' + u/100;
                u %= 100;
                *next++ = '0' + u/10;
                u %= 10;
            }
            else if (u > 9) {
                *next++ = '0' + u/10;
                u %= 10;
            }
            *next++ = '0' + u;
            *next++ = '.';
            n++;
        } while (n < 4);
        *--next = 0;
        return dst;
}

#if HAVE_IPV6
/* const char *
 * inet_ntop6(src, dst, size)
 *        convert IPv6 binary address into presentation (printable) format
 * author:
 *        Paul Vixie, 1996.
 */
static const char *
inet_ntop6(const unsigned char *src, char *dst, size_t size)
{
    /*
     * Note that int32_t and int16_t need only be "at least" large enough
     * to contain a value of the specified size.  On some systems, like
     * Crays, there is no such thing as an integer variable with 16 bits.
     * Keep this in mind if you think this function should have been coded
     * to use pointer overlays.  All the world's not a VAX.
     */
    char tmp[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"], *tp;
    struct { int base, len; } best, cur;
    u16 words[IN6ADDRSZ / INT16SZ];
    int i;
    const unsigned char *next_src, *src_end;
    u16 *next_dest;

    /*
     * Preprocess:
     *        Copy the input (bytewise) array into a wordwise array.
     *        Find the longest run of 0x00's in src[] for :: shorthanding.
     */
    next_src = src;
    src_end = src + IN6ADDRSZ;
    next_dest = words;
    best.base = -1;
    cur.base = -1;
    i = 0;
    do {
        unsigned int next_word = (unsigned int)*next_src++;
        next_word <<= 8;
        next_word |= (unsigned int)*next_src++;
        *next_dest++ = next_word;

        if (next_word == 0) {
            if (cur.base == -1) {
                cur.base = i;
                cur.len = 1;
            }
            else {
                cur.len++;
            }
        } else {
            if (cur.base != -1) {
                if (best.base == -1 || cur.len > best.len) {
                    best = cur;
                }
                cur.base = -1;
            }
        }

        i++;
    } while (next_src < src_end);

    if (cur.base != -1) {
        if (best.base == -1 || cur.len > best.len) {
            best = cur;
        }
    }
    if (best.base != -1 && best.len < 2) {
        best.base = -1;
    }

    /*
     * Format the result.
     */
    tp = tmp;
    for (i = 0; i < (IN6ADDRSZ / INT16SZ);) {
        /* Are we inside the best run of 0x00's? */
        if (i == best.base) {
            *tp++ = ':';
            i += best.len;
            continue;
        }
        /* Are we following an initial run of 0x00s or any real hex? */
        if (i != 0) {
            *tp++ = ':';
        }
        /* Is this address an encapsulated IPv4? */
        if (i == 6 && best.base == 0 &&
            (best.len == 6 || (best.len == 5 && words[5] == 0xffff))) {
            if (!inet_ntop4(src+12, tp, sizeof tmp - (tp - tmp))) {
                return (NULL);
            }
            tp += strlen(tp);
            break;
        }
        tp += Snprintf(tp, sizeof tmp - (tp - tmp), "%x", words[i]);
        i++;
    }
    /* Was it a trailing run of 0x00's? */
    if (best.base != -1 && (best.base + best.len) == (IN6ADDRSZ / INT16SZ)) {
        *tp++ = ':';
    }
    *tp++ = '\0';

    /*
     * Check for overflow, copy, and we're done.
     */
    if ((size_t)(tp - tmp) > size) {
#ifndef WIN32
        errno = ENOSPC;
#endif
        return (NULL);
    }
    strncpy(dst, tmp, size);
    return (dst);
}
#endif

#endif /* ifndef HAVE_INET_NTOP */
