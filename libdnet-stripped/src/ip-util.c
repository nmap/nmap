/*
 * ip-util.c
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id: ip-util.c 595 2005-02-17 02:55:56Z dugsong $
 */

#ifdef _WIN32
#include "dnet_winconfig.h"
#else
#include "config.h"
#endif

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "dnet.h"
#include "crc32ct.h"

/* CRC-32C (Castagnoli). Public domain. */
static unsigned long
_crc32c(unsigned char *buf, int len)
{
	int i;
	unsigned long crc32 = ~0L;
	unsigned long result;
	unsigned char byte0, byte1, byte2, byte3;

	for (i = 0; i < len; i++) {
		CRC32C(crc32, buf[i]);
	}

	result = ~crc32;

	byte0 =  result        & 0xff;
	byte1 = (result >>  8) & 0xff;
	byte2 = (result >> 16) & 0xff;
	byte3 = (result >> 24) & 0xff;
	crc32 = ((byte0 << 24) | (byte1 << 16) | (byte2 <<  8) | byte3);
	return crc32;
}

ssize_t
ip_add_option(void *buf, size_t len, int proto,
    const void *optbuf, size_t optlen)
{
	struct ip_hdr *ip;
	struct tcp_hdr *tcp = NULL;
	u_char *p;
	int hl, datalen, padlen;
	
	if (proto != IP_PROTO_IP && proto != IP_PROTO_TCP) {
		errno = EINVAL;
		return (-1);
	}
	ip = (struct ip_hdr *)buf;
	hl = ip->ip_hl << 2;
	p = (u_char *)buf + hl;
	
	if (proto == IP_PROTO_TCP) {
		tcp = (struct tcp_hdr *)p;
		hl = tcp->th_off << 2;
		p = (u_char *)tcp + hl;
	}
	datalen = (int) (ntohs(ip->ip_len) - (p - (u_char *)buf));
	
	/* Compute padding to next word boundary. */
	if ((padlen = 4 - (optlen % 4)) == 4)
		padlen = 0;

	/* XXX - IP_HDR_LEN_MAX == TCP_HDR_LEN_MAX */
	if (hl + optlen + padlen > IP_HDR_LEN_MAX ||
	    ntohs(ip->ip_len) + optlen + padlen > len) {
		errno = EINVAL;
		return (-1);
	}
	/* XXX - IP_OPT_TYPEONLY() == TCP_OPT_TYPEONLY */
	if (IP_OPT_TYPEONLY(((struct ip_opt *)optbuf)->opt_type))
		optlen = 1;
	
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
	
	if (proto == IP_PROTO_IP)
		ip->ip_hl = (int) ((p - (u_char *)ip) >> 2);
	else if (proto == IP_PROTO_TCP)
		tcp->th_off = (int) ((p - (u_char *)tcp) >> 2);

	ip->ip_len = htons((u_short) (ntohs(ip->ip_len) + optlen));
	
	return (ssize_t)(optlen);
}

void
ip_checksum(void *buf, size_t len)
{
	struct ip_hdr *ip;
	int hl, off, sum;

	if (len < IP_HDR_LEN)
		return;
	
	ip = (struct ip_hdr *)buf;
	hl = ip->ip_hl << 2;
	ip->ip_sum = 0;
	sum = ip_cksum_add(ip, hl, 0);
	ip->ip_sum = ip_cksum_carry(sum);

	off = htons(ip->ip_off);
	
	if ((off & IP_OFFMASK) != 0 || (off & IP_MF) != 0)
		return;
	
	len -= hl;
	
	if (ip->ip_p == IP_PROTO_TCP) {
		struct tcp_hdr *tcp = (struct tcp_hdr *)((u_char *)ip + hl);
		
		if (len >= TCP_HDR_LEN) {
			tcp->th_sum = 0;
			sum = ip_cksum_add(tcp, len, 0) +
			    htons((u_short)(ip->ip_p + len));
			sum = ip_cksum_add(&ip->ip_src, 8, sum);
			tcp->th_sum = ip_cksum_carry(sum);
		}
	} else if (ip->ip_p == IP_PROTO_UDP) {
		struct udp_hdr *udp = (struct udp_hdr *)((u_char *)ip + hl);

		if (len >= UDP_HDR_LEN) {
			udp->uh_sum = 0;
			sum = ip_cksum_add(udp, len, 0) +
			    htons((u_short)(ip->ip_p + len));
			sum = ip_cksum_add(&ip->ip_src, 8, sum);
			udp->uh_sum = ip_cksum_carry(sum);
			if (!udp->uh_sum)
				udp->uh_sum = 0xffff;	/* RFC 768 */
		}
	} else if (ip->ip_p == IP_PROTO_SCTP) {
		struct sctp_hdr *sctp = (struct sctp_hdr *)((u_char *)ip + hl);

		if (len >= SCTP_HDR_LEN) {
			sctp->sh_sum = 0;
			sctp->sh_sum = htonl(_crc32c((u_char *)sctp, len));
		}
	} else if (ip->ip_p == IP_PROTO_ICMP || ip->ip_p == IP_PROTO_IGMP) {
		struct icmp_hdr *icmp = (struct icmp_hdr *)((u_char *)ip + hl);
		
		if (len >= ICMP_HDR_LEN) {
			icmp->icmp_cksum = 0;
			sum = ip_cksum_add(icmp, len, 0);
			icmp->icmp_cksum = ip_cksum_carry(sum);
		}
	}
}

int
ip_cksum_add(const void *buf, size_t len, int cksum)
{
	uint16_t *sp = (uint16_t *)buf;
	int n, sn;
	
	sn = (int) len / 2;
	n = (sn + 15) / 16;

	/* XXX - unroll loop using Duff's device. */
	switch (sn % 16) {
	case 0:	do {
		cksum += *sp++;
	case 15:
		cksum += *sp++;
	case 14:
		cksum += *sp++;
	case 13:
		cksum += *sp++;
	case 12:
		cksum += *sp++;
	case 11:
		cksum += *sp++;
	case 10:
		cksum += *sp++;
	case 9:
		cksum += *sp++;
	case 8:
		cksum += *sp++;
	case 7:
		cksum += *sp++;
	case 6:
		cksum += *sp++;
	case 5:
		cksum += *sp++;
	case 4:
		cksum += *sp++;
	case 3:
		cksum += *sp++;
	case 2:
		cksum += *sp++;
	case 1:
		cksum += *sp++;
		} while (--n > 0);
	}
	if (len & 1)
		cksum += htons(*(u_char *)sp << 8);

	return (cksum);
}
