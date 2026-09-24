/*
 * ip6.c
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#include "config.h"

#include "dnet.h"
#include <string.h>
#include <errno.h>

#define IP6_IS_EXT(n)	\
	((n) == IP_PROTO_HOPOPTS || (n) == IP_PROTO_DSTOPTS || \
	 (n) == IP_PROTO_ROUTING || (n) == IP_PROTO_FRAGMENT)

void
ip6_checksum(void *buf, size_t len)
{
	struct ip6_hdr *ip6 = (struct ip6_hdr *)buf;
	struct ip6_ext_hdr *ext;
	u_char *p, nxt;
	int i, sum;
	
	nxt = ip6->ip6_nxt;
	
	for (i = IP6_HDR_LEN; IP6_IS_EXT(nxt); i += (ext->ext_len + 1) << 3) {
		if (i >= (int)len) return;
		ext = (struct ip6_ext_hdr *)((u_char *)buf + i);
		nxt = ext->ext_nxt;
	}
	p = (u_char *)buf + i;
	len -= i;
	
	if (nxt == IP_PROTO_TCP) {
		struct tcp_hdr *tcp = (struct tcp_hdr *)p;
		
		if (len >= TCP_HDR_LEN) {
			tcp->th_sum = 0;
			sum = ip_cksum_add(tcp, len, 0) + htons(nxt + len);
			sum = ip_cksum_add(&ip6->ip6_src, 32, sum);
			tcp->th_sum = ip_cksum_carry(sum);
		}
	} else if (nxt == IP_PROTO_UDP) {
		struct udp_hdr *udp = (struct udp_hdr *)p;

		if (len >= UDP_HDR_LEN) {
			udp->uh_sum = 0;
			sum = ip_cksum_add(udp, len, 0) + htons(nxt + len);
			sum = ip_cksum_add(&ip6->ip6_src, 32, sum);
			if ((udp->uh_sum = ip_cksum_carry(sum)) == 0)
				udp->uh_sum = 0xffff;
		}
	} else if (nxt == IP_PROTO_ICMPV6) {
		struct icmp_hdr *icmp = (struct icmp_hdr *)p;

		if (len >= ICMP_HDR_LEN) {
			icmp->icmp_cksum = 0;
			sum = ip_cksum_add(icmp, len, 0) + htons(nxt + len);
			sum = ip_cksum_add(&ip6->ip6_src, 32, sum);
			icmp->icmp_cksum = ip_cksum_carry(sum);
		}		
	} else if (nxt == IP_PROTO_ICMP || nxt == IP_PROTO_IGMP) {
		struct icmp_hdr *icmp = (struct icmp_hdr *)p;
		
		if (len >= ICMP_HDR_LEN) {
			icmp->icmp_cksum = 0;
			sum = ip_cksum_add(icmp, len, 0);
			icmp->icmp_cksum = ip_cksum_carry(sum);
		}
	}
}

ssize_t
ip6_add_option(void *buf, size_t len, int proto,
    const void *optbuf, size_t optlen)
{
	struct ip6_hdr *ip6;
	struct tcp_hdr *tcp = NULL;
	u_char *p;
	int hl, datalen, padlen;

	if (proto != IP_PROTO_TCP) {
		errno = EINVAL;
		return (-1);
	}

	ip6 = (struct ip6_hdr *)buf;
	p = (u_char *)buf + IP6_HDR_LEN;

	tcp = (struct tcp_hdr *)p;
	hl = tcp->th_off << 2;
	p = (u_char *)tcp + hl;

	datalen = ntohs(ip6->ip6_plen) + IP6_HDR_LEN - (p - (u_char *)buf);

	/* Compute padding to next word boundary. */
	if ((padlen = 4 - (optlen % 4)) == 4)
		padlen = 0;

	/* XXX - IP_HDR_LEN_MAX == TCP_HDR_LEN_MAX */
	if (hl + optlen + padlen > IP_HDR_LEN_MAX ||
	    ntohs(ip6->ip6_plen) + IP6_HDR_LEN + optlen + padlen > len) {
		errno = EINVAL;
		return (-1);
	}

	/* Shift any existing data. */
	if (datalen) {
		memmove(p + optlen + padlen, p, datalen);
	}
	/* XXX - IP_OPT_NOP == TCP_OPT_NOP */
	if (padlen) {
		memset(p, IP_OPT_NOP, padlen);
		p += padlen;
	}
	memmove(p, optbuf, optlen);
	p += optlen;
	optlen += padlen;

	tcp->th_off = (p - (u_char *)tcp) >> 2;

	ip6->ip6_plen = htons(ntohs(ip6->ip6_plen) + optlen);

	return (optlen);
}
