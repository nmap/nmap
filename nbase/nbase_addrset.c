/***************************************************************************
 * nbase_addrset.c -- Address set (addrset) management.                          *
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

/* The code in this file has tests in the file ncat/tests/test-addrset.sh. Run that
   program after making any big changes. Also, please add tests for any new
   features. */

#include "nbase.h"
#include "nbase_addrset.h"

/* A fancy logging system to allow this file to take advantage of different logging
   systems used by various programs */

static void default_log_user(const char * a, ...){};

static void (*log_user)(const char *, ...) = default_log_user;

static void default_log_debug(const char * a, ...){};

static void (*log_debug)(const char *, ...) = default_log_debug;

void nbase_set_log(void (*log_user_func)(const char *, ...),void (*log_debug_func)(const char *, ...)){
    if (log_user_func == NULL)
        log_user = default_log_user;
    else
        log_user = log_user_func;
    if (log_debug_func == NULL)
        log_debug = default_log_debug;
    else
        log_debug = log_debug_func;
}

void addrset_init(struct addrset *set)
{
    set->head = NULL;
}

void addrset_free(struct addrset *set)
{
    struct addrset_elem *elem, *next;

    for (elem = set->head; elem != NULL; elem = next) {
        next = elem->next;
        free(elem);
    }
}

/* A debugging function to print out the contents of an addrset_elem. For IPv4
   this is the four bit vectors. For IPv6 it is the address and netmask. */
void addrset_elem_print(FILE *fp, const struct addrset_elem *elem)
{
    const size_t num_bitvector = sizeof(octet_bitvector) / sizeof(bitvector_t);
    int i;
    size_t j;

    if (elem->type == ADDRSET_TYPE_IPV4_BITVECTOR) {
        for (i = 0; i < 4; i++) {
            for (j = 0; j < num_bitvector; j++)
                fprintf(fp, "%0*lX ", (int) (sizeof(bitvector_t) * 2), elem->u.ipv4.bits[i][num_bitvector - 1 - j]);
            fprintf(fp, "\n");
        }
#ifdef HAVE_IPV6
    } else if (elem->type == ADDRSET_TYPE_IPV6_NETMASK) {
        for (i = 0; i < 16; i += 2) {
            if (i > 0)
                fprintf(fp, ":");
            fprintf(fp, "%02X", elem->u.ipv6.addr.s6_addr[i]);
            fprintf(fp, "%02X", elem->u.ipv6.addr.s6_addr[i + 1]);
        }
        fprintf(fp, " ");
        for (i = 0; i < 16; i += 2) {
            if (i > 0)
                fprintf(fp, ":");
            fprintf(fp, "%02X", elem->u.ipv6.mask.s6_addr[i]);
            fprintf(fp, "%02X", elem->u.ipv6.mask.s6_addr[i + 1]);
        }
        fprintf(fp, "\n");
#endif
    }
}

/* This is a wrapper around getaddrinfo that automatically handles hints for
   IPv4/IPv6, TCP/UDP, and whether name resolution is allowed. */
static int resolve_name(const char *name, struct addrinfo **result, int af, int use_dns)
{
    struct addrinfo hints = { 0 };
    int rc;

    hints.ai_protocol = IPPROTO_TCP;

    /* First do a non-DNS lookup for any address family (just checks for a valid
       numeric address). We recognize numeric addresses no matter the setting of
       af. This is also the last step if use_dns is false. */
    hints.ai_flags |= AI_NUMERICHOST;
    hints.ai_family = AF_UNSPEC;
    *result = NULL;
    rc = getaddrinfo(name, NULL, &hints, result);
    if (rc == 0 || !use_dns)
        return rc;

    /* Do a DNS lookup now. When we look up a name we only want addresses
       corresponding to the value of af. */
    hints.ai_flags &= ~AI_NUMERICHOST;
    hints.ai_family = af;
    *result = NULL;
    rc = getaddrinfo(name, NULL, &hints, result);

    return rc;
}

/* This is an address family-agnostic version of inet_ntop. */
static char *address_to_string(const struct sockaddr *sa, size_t sa_len,
                               char *buf, size_t len)
{
    getnameinfo(sa, sa_len, buf, len, NULL, 0, NI_NUMERICHOST);

    return buf;
}

/* Break an IPv4 address into an array of octets. octets[0] contains the most
   significant octet and octets[3] the least significant. */
static void in_addr_to_octets(const struct in_addr *ia, uint8_t octets[4])
{
    u32 hbo = ntohl(ia->s_addr);

    octets[0] = (uint8_t) ((hbo & (0xFFU << 24)) >> 24);
    octets[1] = (uint8_t) ((hbo & (0xFFU << 16)) >> 16);
    octets[2] = (uint8_t) ((hbo & (0xFFU << 8)) >> 8);
    octets[3] = (uint8_t) (hbo & 0xFFU);
}

#define BITVECTOR_BITS (sizeof(bitvector_t) * CHAR_BIT)
#define BIT_SET(v, n) ((v)[(n) / BITVECTOR_BITS] |= 1UL << ((n) % BITVECTOR_BITS))
#define BIT_IS_SET(v, n) (((v)[(n) / BITVECTOR_BITS] & 1UL << ((n) % BITVECTOR_BITS)) != 0)

static int parse_ipv4_ranges(struct addrset_elem *elem, const char *spec);
static void apply_ipv4_netmask_bits(struct addrset_elem *elem, int bits);
#ifdef HAVE_IPV6
static void make_ipv6_netmask(struct in6_addr *mask, int bits);
#endif

/* Add a host specification into the address set. Returns 1 on success, 0 on
   error. */
int addrset_add_spec(struct addrset *set, const char *spec, int af, int dns)
{
    char *local_spec;
    char *netmask_s;
    char *tail;
    long netmask_bits;
    struct addrinfo *addrs, *addr;
    struct addrset_elem *elem;
    int rc;

    /* Make a copy of the spec to mess with. */
    local_spec = strdup(spec);
    if (local_spec == NULL)
        return 0;

    /* Read the CIDR netmask bits, if present. */
    netmask_s = strchr(local_spec, '/');
    if (netmask_s == NULL) {
        /* A negative value means unspecified; default depends on the address
           family. */
        netmask_bits = -1;
    } else {
        *netmask_s = '\0';
        netmask_s++;
        errno = 0;
        netmask_bits = parse_long(netmask_s, &tail);
        if (errno != 0 || *tail != '\0' || tail == netmask_s) {
            log_user("Error parsing netmask in \"%s\".\n", spec);
            free(local_spec);
            return 0;
        }
    }

    elem = (struct addrset_elem *) safe_malloc(sizeof(*elem));
    memset(elem->u.ipv4.bits, 0, sizeof(elem->u.ipv4.bits));

    /* Check if this is an IPv4 address, with optional ranges and wildcards. */
    if (parse_ipv4_ranges(elem, local_spec)) {
        if (netmask_bits > 32) {
            log_user("Illegal netmask in \"%s\". Must be between 0 and 32.\n", spec);
            free(local_spec);
            free(elem);
            return 0;
        }
        apply_ipv4_netmask_bits(elem, netmask_bits);
        log_debug("Add IPv4 range %s/%ld to addrset.\n", local_spec, netmask_bits > 0 ? netmask_bits : 32);
        elem->type = ADDRSET_TYPE_IPV4_BITVECTOR;
        elem->next = set->head;
        set->head = elem;
        free(local_spec);
        return 1;
    } else {
        free(elem);
    }

    /* When all else fails, resolve the name. */
    rc = resolve_name(local_spec, &addrs, af, dns);
    if (rc != 0) {
        log_user("Error resolving name \"%s\": %s\n", local_spec, gai_strerror(rc));
        free(local_spec);
        return 0;
    }
    if (addrs == NULL)
        log_user("Warning: no addresses found for %s.\n", local_spec);
    free(local_spec);

    /* Walk the list of addresses and add them all to the set with netmasks. */
    for (addr = addrs; addr != NULL; addr = addr->ai_next) {
        char addr_string[128];

        elem = (struct addrset_elem *) safe_malloc(sizeof(*elem));
        memset(elem->u.ipv4.bits, 0, sizeof(elem->u.ipv4.bits));

        address_to_string(addr->ai_addr, addr->ai_addrlen, addr_string, sizeof(addr_string));

        /* Note: it is possible that in this loop we are dealing with addresses
           of more than one family (e.g., IPv4 and IPv6). But we have at most
           one netmask value for all of them. Whatever netmask we have is
           applied blindly to whatever addresses there are, which may not be
           what you want if a /24 is applied to IPv6 and will cause an error if
           a /120 is applied to IPv4. */
        if (addr->ai_family == AF_INET) {
            const struct sockaddr_in *sin = (struct sockaddr_in *) addr->ai_addr;
            uint8_t octets[4];

            elem->type = ADDRSET_TYPE_IPV4_BITVECTOR;

            in_addr_to_octets(&sin->sin_addr, octets);
            BIT_SET(elem->u.ipv4.bits[0], octets[0]);
            BIT_SET(elem->u.ipv4.bits[1], octets[1]);
            BIT_SET(elem->u.ipv4.bits[2], octets[2]);
            BIT_SET(elem->u.ipv4.bits[3], octets[3]);

            if (netmask_bits > 32) {
                log_user("Illegal netmask in \"%s\". Must be between 0 and 32.\n", spec);
                free(elem);
                return 0;
            }
            apply_ipv4_netmask_bits(elem, netmask_bits);
            log_debug("Add IPv4 %s/%ld to addrset.\n", addr_string, netmask_bits > 0 ? netmask_bits : 32);

#ifdef HAVE_IPV6
        } else if (addr->ai_family == AF_INET6) {
            const struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) addr->ai_addr;

            elem->type = ADDRSET_TYPE_IPV6_NETMASK;

            elem->u.ipv6.addr = sin6->sin6_addr;

            if (netmask_bits > 128) {
                log_user("Illegal netmask in \"%s\". Must be between 0 and 128.\n", spec);
                free(elem);
                return 0;
            }
            make_ipv6_netmask(&elem->u.ipv6.mask, netmask_bits);
            log_debug("Add IPv6 %s/%ld to addrset.\n", addr_string, netmask_bits > 0 ? netmask_bits : 128);
#endif
        } else {
            log_debug("ignoring address %s for %s. Family %d socktype %d protocol %d.\n", addr_string, spec, addr->ai_family, addr->ai_socktype, addr->ai_protocol);
            free(elem);
            continue;
        }

        elem->next = set->head;
        set->head = elem;
    }

    if (addrs != NULL)
        freeaddrinfo(addrs);

    return 1;
}

/* Add whitespace-separated host specifications from fd into the address set.
   Returns 1 on success, 0 on error. */
int addrset_add_file(struct addrset *set, FILE *fd, int af, int dns)
{
    char buf[1024];
    int c, i;

    for (;;) {
        /* Skip whitespace. */
        while ((c = getc(fd)) != EOF) {
            if (!isspace(c))
                break;
        }
        if (c == EOF)
            break;
        ungetc(c, fd);

        i = 0;
        while ((c = getc(fd)) != EOF) {
            if (isspace(c))
                break;
            if (i + 1 > sizeof(buf) - 1) {
                /* Truncate the specification to give a little context. */
                buf[11] = '\0';
                log_user("Host specification starting with \"%s\" is too long.\n", buf);
                return 0;
            }
            buf[i++] = c;
        }
        buf[i] = '\0';

        if (!addrset_add_spec(set, buf, af, dns))
            return 0;
    }

    return 1;
}

/* Parse an IPv4 address with optional ranges and wildcards into bit vectors.
   Each octet must match the regular expression '(\*|#?(-#?)?(,#?(-#?)?)*)',
   where '#' stands for an integer between 0 and 255. Return 1 on success, 0 on
   error. */
static int parse_ipv4_ranges(struct addrset_elem *elem, const char *spec)
{
    const char *p;
    int octet_index, i;

    p = spec;
    octet_index = 0;
    while (*p != '\0' && octet_index < 4) {
        if (*p == '*') {
            for (i = 0; i < 256; i++)
                BIT_SET(elem->u.ipv4.bits[octet_index], i);
            p++;
        } else {
            for (;;) {
                long start, end;
                char *tail;

                errno = 0;
                start = parse_long(p, &tail);
                /* Is this a range open on the left? */
                if (tail == p) {
                    if (*p == '-')
                        start = 0;
                    else
                        return 0;
                }
                if (errno != 0 || start < 0 || start > 255)
                    return 0;
                p = tail;

                /* Look for a range. */
                if (*p == '-') {
                    p++;
                    errno = 0;
                    end = parse_long(p, &tail);
                    /* Is this range open on the right? */
                    if (tail == p)
                        end = 255;
                    if (errno != 0 || end < 0 || end > 255 || end < start)
                        return 0;
                    p = tail;
                } else {
                    end = start;
                }

                /* Fill in the range in the bit vector. */
                for (i = start; i <= end; i++)
                    BIT_SET(elem->u.ipv4.bits[octet_index], i);

                if (*p != ',')
                    break;
                p++;
            }
        }
        octet_index++;
        if (octet_index < 4) {
            if (*p != '.')
                return 0;
            p++;
        }
    }
    if (*p != '\0' || octet_index < 4)
        return 0;

    return 1;
}

/* Expand a single-octet bit vector to include any additional addresses that
   result when mask is applied. */
static void apply_ipv4_netmask_octet(octet_bitvector bits, uint8_t mask)
{
    unsigned int i, j;
    uint32_t chunk_size;

    /* Process the bit vector in chunks, first of size 1, then of size 2, up to
       size 128. Check the next bit of the mask. If it is 1, do nothing.
       Otherwise, pair up the chunks (first with the second, third with the
       fourth, etc.). For each pair of chunks, set a bit in one chunk if it is
       set in the other. chunk_size also serves as an index into the mask. */
    for (chunk_size = 1; chunk_size < 256; chunk_size <<= 1) {
        if ((mask & chunk_size) != 0)
            continue;
        for (i = 0; i < 256; i += chunk_size * 2) {
            for (j = 0; j < chunk_size; j++) {
                if (BIT_IS_SET(bits, i + j))
                    BIT_SET(bits, i + j + chunk_size);
                else if (BIT_IS_SET(bits, i + j + chunk_size))
                    BIT_SET(bits, i + j);
            }
        }
    }
}

/* Expand an addrset_elem's IPv4 bit vectors to include any additional addresses
   that result when the given netmask is applied. The mask is in network byte
   order. */
static void apply_ipv4_netmask(struct addrset_elem *elem, uint32_t mask)
{
    mask = ntohl(mask);
    /* Apply the mask one octet at a time. It's done this way because ranges
       span exactly one octet. */
    apply_ipv4_netmask_octet(elem->u.ipv4.bits[0], (mask & 0xFF000000) >> 24);
    apply_ipv4_netmask_octet(elem->u.ipv4.bits[1], (mask & 0x00FF0000) >> 16);
    apply_ipv4_netmask_octet(elem->u.ipv4.bits[2], (mask & 0x0000FF00) >> 8);
    apply_ipv4_netmask_octet(elem->u.ipv4.bits[3], (mask & 0x000000FF));
}

/* Expand an addrset_elem's IPv4 bit vectors to include any additional addresses
   that result from the application of a CIDR-style netmask with the given
   number of bits. If bits is negative it is taken to be 32. */
static void apply_ipv4_netmask_bits(struct addrset_elem *elem, int bits)
{
    uint32_t mask;

    if (bits > 32)
        return;
    if (bits < 0)
        bits = 32;

    if (bits == 0)
        mask = htonl(0x00000000);
    else
        mask = htonl(0xFFFFFFFF << (32 - bits));
    apply_ipv4_netmask(elem, mask);
}

#ifdef HAVE_IPV6
/* Fill in an in6_addr with a CIDR-style netmask with the given number of bits.
   If bits is negative it is taken to be 128. The netmask is written in network
   byte order. */
static void make_ipv6_netmask(struct in6_addr *mask, int bits)
{
    int i;

    memset(mask, 0, sizeof(*mask));

    if (bits > 128)
        return;
    if (bits < 0)
        bits = 128;

    if (bits == 0)
        return;

    i = 0;
    /* 0 < bits <= 128, so this loop goes at most 15 times. */
    for ( ; bits > 8; bits -= 8)
        mask->s6_addr[i++] = 0xFF;
    mask->s6_addr[i] = 0xFF << (8 - bits);
}
#endif

static int match_ipv4_bits(const octet_bitvector bits[4], const struct sockaddr *sa)
{
    uint8_t octets[4];

    if (sa->sa_family != AF_INET)
        return 0;

    in_addr_to_octets(&((const struct sockaddr_in *) sa)->sin_addr, octets);

    return BIT_IS_SET(bits[0], octets[0])
        && BIT_IS_SET(bits[1], octets[1])
        && BIT_IS_SET(bits[2], octets[2])
        && BIT_IS_SET(bits[3], octets[3]);
}

#ifdef HAVE_IPV6
static int match_ipv6_netmask(const struct in6_addr *addr,
    const struct in6_addr *mask, const struct sockaddr *sa)
{
    const uint8_t *a = addr->s6_addr;
    const uint8_t *m = mask->s6_addr;
    const uint8_t *b = ((const struct sockaddr_in6 *) sa)->sin6_addr.s6_addr;
    int i;

    if (sa->sa_family != AF_INET6)
        return 0;

    for (i = 0; i < 16; i++) {
        if ((a[i] & m[i]) != (b[i] & m[i]))
            return 0;
    }

    return 1;
}
#endif

static int addrset_elem_match(const struct addrset_elem *elem, const struct sockaddr *sa)
{
    switch (elem->type) {
        case ADDRSET_TYPE_IPV4_BITVECTOR:
            return match_ipv4_bits(elem->u.ipv4.bits, sa);
#ifdef HAVE_IPV6
        case ADDRSET_TYPE_IPV6_NETMASK:
            return match_ipv6_netmask(&elem->u.ipv6.addr, &elem->u.ipv6.mask, sa);
#endif
    }

    return 0;
}

int addrset_contains(const struct addrset *set, const struct sockaddr *sa)
{
    struct addrset_elem *elem;

    for (elem = set->head; elem != NULL; elem = elem->next) {
        if (addrset_elem_match(elem, sa))
            return 1;
    }

    return 0;
}
