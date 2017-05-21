/*
 * addr.c
 *
 * Network address operations.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: addr.c 610 2005-06-26 18:23:26Z dugsong $
 */

#ifdef WIN32
#include "dnet_winconfig.h"
#else
#include "config.h"
#endif

#include <sys/types.h>
#ifdef HAVE_NET_IF_H
# include <sys/socket.h>
# include <net/if.h>
#endif
#ifdef HAVE_NET_IF_DL_H
# include <net/if_dl.h>
#endif
#ifdef HAVE_NET_RAW_H
# include <net/raw.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dnet.h"

#ifndef MAXHOSTNAMELEN
# define MAXHOSTNAMELEN	256
#endif

union sockunion {
#ifdef HAVE_NET_IF_DL_H
	struct sockaddr_dl	sdl;
#endif
	struct sockaddr_in	sin;
#ifdef HAVE_SOCKADDR_IN6
	struct sockaddr_in6	sin6;
#endif
	struct sockaddr		sa;
#ifdef AF_RAW
	struct sockaddr_raw	sr;
#endif
};

int
addr_cmp(const struct addr *a, const struct addr *b)
{
	int i, j, k;

	/* XXX */
	if ((i = a->addr_type - b->addr_type) != 0)
		return (i);
	
	/* XXX - 10.0.0.1 is "smaller" than 10.0.0.0/8? */
	if ((i = a->addr_bits - b->addr_bits) != 0)
		return (i);
	
	j = b->addr_bits / 8;

	for (i = 0; i < j; i++) {
		if ((k = a->addr_data8[i] - b->addr_data8[i]) != 0)
			return (k);
	}
	if ((k = b->addr_bits % 8) == 0)
		return (0);

	k = ~0 << (8 - k);
	i = b->addr_data8[j] & k;
	j = a->addr_data8[j] & k;
	
	return (j - i);
}

int
addr_net(const struct addr *a, struct addr *b)
{
	uint32_t mask;
	int i, j;

	if (a->addr_type == ADDR_TYPE_IP) {
		addr_btom(a->addr_bits, &mask, IP_ADDR_LEN);
		b->addr_type = ADDR_TYPE_IP;
		b->addr_bits = IP_ADDR_BITS;
		b->addr_ip = a->addr_ip & mask;
	} else if (a->addr_type == ADDR_TYPE_ETH) {
		memcpy(b, a, sizeof(*b));
		if (a->addr_data8[0] & 0x1)
			memset(b->addr_data8 + 3, 0, 3);
		b->addr_bits = ETH_ADDR_BITS;
	} else if (a->addr_type == ADDR_TYPE_IP6) {
	  if (a->addr_bits > IP6_ADDR_BITS)
	    return (-1);
		b->addr_type = ADDR_TYPE_IP6;
		b->addr_bits = IP6_ADDR_BITS;
		memset(&b->addr_ip6, 0, IP6_ADDR_LEN);
		
		switch ((i = a->addr_bits / 32)) {
		case 4: b->addr_data32[3] = a->addr_data32[3];
		case 3: b->addr_data32[2] = a->addr_data32[2];
		case 2: b->addr_data32[1] = a->addr_data32[1];
		case 1: b->addr_data32[0] = a->addr_data32[0];
		}
		if ((j = a->addr_bits % 32) > 0) {
			addr_btom(j, &mask, sizeof(mask));
			b->addr_data32[i] = a->addr_data32[i] & mask;
		}
	} else
		return (-1);
	
	return (0);
}

int
addr_bcast(const struct addr *a, struct addr *b)
{
	struct addr mask;
	
	if (a->addr_type == ADDR_TYPE_IP) {
		addr_btom(a->addr_bits, &mask.addr_ip, IP_ADDR_LEN);
		b->addr_type = ADDR_TYPE_IP;
		b->addr_bits = IP_ADDR_BITS;
		b->addr_ip = (a->addr_ip & mask.addr_ip) |
		    (~0L & ~mask.addr_ip);
	} else if (a->addr_type == ADDR_TYPE_ETH) {
		b->addr_type = ADDR_TYPE_ETH;
		b->addr_bits = ETH_ADDR_BITS;
		memcpy(&b->addr_eth, ETH_ADDR_BROADCAST, ETH_ADDR_LEN);
	} else {
		/* XXX - no broadcast addresses in IPv6 */
		errno = EINVAL;
		return (-1);
	}
	return (0);
}

char *
addr_ntop(const struct addr *src, char *dst, size_t size)
{
	if (src->addr_type == ADDR_TYPE_IP && size >= 20) {
		if (ip_ntop(&src->addr_ip, dst, size) != NULL) {
			if (src->addr_bits != IP_ADDR_BITS)
				sprintf(dst + strlen(dst), "/%d",
				    src->addr_bits);
			return (dst);
		}
	} else if (src->addr_type == ADDR_TYPE_IP6 && size >= 42) {
		if (ip6_ntop(&src->addr_ip6, dst, size) != NULL) {
			if (src->addr_bits != IP6_ADDR_BITS)
				sprintf(dst + strlen(dst), "/%d",
				    src->addr_bits);
			return (dst);
		}
	} else if (src->addr_type == ADDR_TYPE_ETH && size >= 18) {
		if (src->addr_bits == ETH_ADDR_BITS)
			return (eth_ntop(&src->addr_eth, dst, size));
	}
	errno = EINVAL;
	return (NULL);
}

int
addr_pton(const char *src, struct addr *dst)
{
	struct hostent *hp;
	char *ep, tmp[300];
	long bits = -1;
	int i;
	
	for (i = 0; i < (int)sizeof(tmp) - 1; i++) {
		if (src[i] == '/') {
			tmp[i] = '\0';
			if (strchr(&src[i + 1], '.')) {
				uint32_t m;
				uint16_t b;
				/* XXX - mask is specified like /255.0.0.0 */
				if (ip_pton(&src[i + 1], &m) != 0) {
					errno = EINVAL;
					return (-1);
				}
				addr_mtob(&m, sizeof(m), &b);
				bits = b;
			} else {
				bits = strtol(&src[i + 1], &ep, 10);
				if (ep == src || *ep != '\0' || bits < 0) {
					errno = EINVAL;
					return (-1);
				}
			}
			break;
		} else if ((tmp[i] = src[i]) == '\0')
			break;
	}
	if (ip_pton(tmp, &dst->addr_ip) == 0) {
		dst->addr_type = ADDR_TYPE_IP;
		dst->addr_bits = IP_ADDR_BITS;
	} else if (eth_pton(tmp, &dst->addr_eth) == 0) {
		dst->addr_type = ADDR_TYPE_ETH;
		dst->addr_bits = ETH_ADDR_BITS;
	} else if (ip6_pton(tmp, &dst->addr_ip6) == 0) {
		dst->addr_type = ADDR_TYPE_IP6;
		dst->addr_bits = IP6_ADDR_BITS;
	} else if ((hp = gethostbyname(tmp)) != NULL) {
		memcpy(&dst->addr_ip, hp->h_addr, IP_ADDR_LEN);
		dst->addr_type = ADDR_TYPE_IP;
		dst->addr_bits = IP_ADDR_BITS;
	} else {
		errno = EINVAL;
		return (-1);
	}
	if (bits >= 0) {
		if (bits > dst->addr_bits) {
			errno = EINVAL;
			return (-1);
		}
		dst->addr_bits = (uint16_t)bits;
	}
	return (0);
}

char *
addr_ntoa(const struct addr *a)
{
	static char *p, buf[BUFSIZ];
	char *q = NULL;
	
	if (p == NULL || p > buf + sizeof(buf) - 64 /* XXX */)
		p = buf;
	
	if (addr_ntop(a, p, (buf + sizeof(buf)) - p) != NULL) {
		q = p;
		p += strlen(p) + 1;
	}
	return (q);
}

int
addr_ntos(const struct addr *a, struct sockaddr *sa)
{
	union sockunion *so = (union sockunion *)sa;
	
	switch (a->addr_type) {
	case ADDR_TYPE_ETH:
#ifdef HAVE_NET_IF_DL_H
		memset(&so->sdl, 0, sizeof(so->sdl));
# ifdef HAVE_SOCKADDR_SA_LEN
		so->sdl.sdl_len = sizeof(so->sdl);
# endif
# ifdef AF_LINK
		so->sdl.sdl_family = AF_LINK;
# else
		so->sdl.sdl_family = AF_UNSPEC;
# endif
		so->sdl.sdl_alen = ETH_ADDR_LEN;
		memcpy(LLADDR(&so->sdl), &a->addr_eth, ETH_ADDR_LEN);
#else
		memset(sa, 0, sizeof(*sa));
# ifdef AF_LINK
		sa->sa_family = AF_LINK;
# else
		sa->sa_family = AF_UNSPEC;
# endif
		memcpy(sa->sa_data, &a->addr_eth, ETH_ADDR_LEN);
#endif
		break;
#ifdef HAVE_SOCKADDR_IN6
	case ADDR_TYPE_IP6:
		memset(&so->sin6, 0, sizeof(so->sin6));
#ifdef HAVE_SOCKADDR_SA_LEN
		so->sin6.sin6_len = sizeof(so->sin6);
#endif
		so->sin6.sin6_family = AF_INET6;
		memcpy(&so->sin6.sin6_addr, &a->addr_ip6, IP6_ADDR_LEN);
		break;
#endif
	case ADDR_TYPE_IP:
		memset(&so->sin, 0, sizeof(so->sin));
#ifdef HAVE_SOCKADDR_SA_LEN
		so->sin.sin_len = sizeof(so->sin);
#endif
		so->sin.sin_family = AF_INET;
		so->sin.sin_addr.s_addr = a->addr_ip;
		break;
	default:
		errno = EINVAL;
		return (-1);
	}
	return (0);
}

int
addr_ston(const struct sockaddr *sa, struct addr *a)
{
	union sockunion *so = (union sockunion *)sa;
	
	memset(a, 0, sizeof(*a));
	
	switch (sa->sa_family) {
#ifdef HAVE_NET_IF_DL_H
# ifdef AF_LINK
	case AF_LINK:
		if (so->sdl.sdl_alen != ETH_ADDR_LEN) {
			errno = EINVAL;
			return (-1);
		}
		a->addr_type = ADDR_TYPE_ETH;
		a->addr_bits = ETH_ADDR_BITS;
		memcpy(&a->addr_eth, LLADDR(&so->sdl), ETH_ADDR_LEN);
		break;
# endif
#endif
	case AF_UNSPEC:
	case ARP_HRD_ETH:	/* XXX- Linux arp(7) */
	case ARP_HRD_APPLETALK: /* AppleTalk DDP */
	case ARP_HRD_INFINIBAND: /* InfiniBand */
	case ARP_HDR_IEEE80211: /* IEEE 802.11 */
	case ARP_HRD_IEEE80211_PRISM: /* IEEE 802.11 + prism header */
	case ARP_HRD_IEEE80211_RADIOTAP: /* IEEE 802.11 + radiotap header */
		a->addr_type = ADDR_TYPE_ETH;
		a->addr_bits = ETH_ADDR_BITS;
		memcpy(&a->addr_eth, sa->sa_data, ETH_ADDR_LEN);
		break;
		
#ifdef AF_RAW
	case AF_RAW:		/* XXX - IRIX raw(7f) */
		a->addr_type = ADDR_TYPE_ETH;
		a->addr_bits = ETH_ADDR_BITS;
		memcpy(&a->addr_eth, so->sr.sr_addr, ETH_ADDR_LEN);
		break;
#endif
#ifdef HAVE_SOCKADDR_IN6
	case AF_INET6:
		a->addr_type = ADDR_TYPE_IP6;
		a->addr_bits = IP6_ADDR_BITS;
		memcpy(&a->addr_ip6, &so->sin6.sin6_addr, IP6_ADDR_LEN);
		break;
#endif
	case AF_INET:
		a->addr_type = ADDR_TYPE_IP;
		a->addr_bits = IP_ADDR_BITS;
		a->addr_ip = so->sin.sin_addr.s_addr;
		break;
	case ARP_HRD_VOID:
		memset(&a->addr_eth, 0, ETH_ADDR_LEN);
		break;
	default:
		errno = EINVAL;
		return (-1);
	}
	return (0);
}

int
addr_btos(uint16_t bits, struct sockaddr *sa)
{
	union sockunion *so = (union sockunion *)sa;

#ifdef HAVE_SOCKADDR_IN6
	if (bits > IP_ADDR_BITS && bits <= IP6_ADDR_BITS) {
		memset(&so->sin6, 0, sizeof(so->sin6));
#ifdef HAVE_SOCKADDR_SA_LEN
		so->sin6.sin6_len = IP6_ADDR_LEN + (bits / 8) + (bits % 8);
#endif
		so->sin6.sin6_family = AF_INET6;
		return (addr_btom(bits, &so->sin6.sin6_addr, IP6_ADDR_LEN));
	} else
#endif
	if (bits <= IP_ADDR_BITS) {
		memset(&so->sin, 0, sizeof(so->sin));
#ifdef HAVE_SOCKADDR_SA_LEN
		so->sin.sin_len = IP_ADDR_LEN + (bits / 8) + (bits % 8);
#endif
		so->sin.sin_family = AF_INET;
		return (addr_btom(bits, &so->sin.sin_addr, IP_ADDR_LEN));
	}
	errno = EINVAL;
	return (-1);
}

int
addr_stob(const struct sockaddr *sa, uint16_t *bits)
{
	union sockunion *so = (union sockunion *)sa;
	int i, j, len;
	uint16_t n;
	u_char *p;

#ifdef HAVE_SOCKADDR_IN6
	if (sa->sa_family == AF_INET6) {
		p = (u_char *)&so->sin6.sin6_addr;
#ifdef HAVE_SOCKADDR_SA_LEN
		len = sa->sa_len - ((void *) p - (void *) sa);
		/* Handles the special case of sa->sa_len == 0. */
		if (len < 0)
			len = 0;
		else if (len > IP6_ADDR_LEN)
			len = IP6_ADDR_LEN;
#else
		len = IP6_ADDR_LEN;
#endif
	} else
#endif
	{
		p = (u_char *)&so->sin.sin_addr.s_addr;
#ifdef HAVE_SOCKADDR_SA_LEN
		len = sa->sa_len - ((void *) p - (void *) sa);
		/* Handles the special case of sa->sa_len == 0. */
		if (len < 0)
			len = 0;
		else if (len > IP_ADDR_LEN)
			len = IP_ADDR_LEN;
#else
		len = IP_ADDR_LEN;
#endif
	}
	for (n = i = 0; i < len; i++, n += 8) {
		if (p[i] != 0xff)
			break;
	}
	if (i != len && p[i]) {
		for (j = 7; j > 0; j--, n++) {
			if ((p[i] & (1 << j)) == 0)
				break;
		}
	}
	*bits = n;
	
	return (0);
}
	
int
addr_btom(uint16_t bits, void *mask, size_t size)
{
	int net, host;
	u_char *p;

	if (size == IP_ADDR_LEN) {
		if (bits > IP_ADDR_BITS) {
			errno = EINVAL;
			return (-1);
		}
		*(uint32_t *)mask = bits ?
		    htonl(~0 << (IP_ADDR_BITS - bits)) : 0;
	} else {
		if (size * 8 < bits) {
			errno = EINVAL;
			return (-1);
		}
		p = (u_char *)mask;
		
		if ((net = bits / 8) > 0)
			memset(p, 0xff, net);
		
		if ((host = bits % 8) > 0) {
			p[net] = 0xff << (8 - host);
			memset(&p[net + 1], 0, size - net - 1);
		} else
			memset(&p[net], 0, size - net);
	}
	return (0);
}

int
addr_mtob(const void *mask, size_t size, uint16_t *bits)
{
	uint16_t n;
	u_char *p;
	int i, j;

	p = (u_char *)mask;
	
	for (n = i = 0; i < (int)size; i++, n += 8) {
		if (p[i] != 0xff)
			break;
	}
	if (i != (int)size && p[i]) {
		for (j = 7; j > 0; j--, n++) {
			if ((p[i] & (1 << j)) == 0)
				break;
		}
	}
	*bits = n;

	return (0);
}
