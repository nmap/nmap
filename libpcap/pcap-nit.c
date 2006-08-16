/*
 * Copyright (c) 1990, 1991, 1992, 1993, 1994, 1995, 1996
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */
#ifndef lint
static const char rcsid[] _U_ =
    "@(#) $Header: /tcpdump/master/libpcap/pcap-nit.c,v 1.57.2.1 2005/05/03 18:54:37 guy Exp $ (LBL)";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/timeb.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/nit.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/ip_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/tcp.h>
#include <netinet/tcpip.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>

#include "pcap-int.h"

#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

/*
 * The chunk size for NIT.  This is the amount of buffering
 * done for read calls.
 */
#define CHUNKSIZE (2*1024)

/*
 * The total buffer space used by NIT.
 */
#define BUFSPACE (4*CHUNKSIZE)

/* Forwards */
static int nit_setflags(int, int, int, char *);

static int
pcap_stats_nit(pcap_t *p, struct pcap_stat *ps)
{

	/*
	 * "ps_recv" counts packets handed to the filter, not packets
	 * that passed the filter.  As filtering is done in userland,
	 * this does not include packets dropped because we ran out
	 * of buffer space.
	 *
	 * "ps_drop" presumably counts packets dropped by the socket
	 * because of flow control requirements or resource exhaustion;
	 * it doesn't count packets dropped by the interface driver.
	 * As filtering is done in userland, it counts packets regardless
	 * of whether they would've passed the filter.
	 *
	 * These statistics don't include packets not yet read from the
	 * kernel by libpcap or packets not yet read from libpcap by the
	 * application.
	 */
	*ps = p->md.stat;
	return (0);
}

static int
pcap_read_nit(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
{
	register int cc, n;
	register struct bpf_insn *fcode = p->fcode.bf_insns;
	register u_char *bp, *cp, *ep;
	register struct nit_hdr *nh;
	register int caplen;

	cc = p->cc;
	if (cc == 0) {
		cc = read(p->fd, (char *)p->buffer, p->bufsize);
		if (cc < 0) {
			if (errno == EWOULDBLOCK)
				return (0);
			snprintf(p->errbuf, sizeof(p->errbuf), "pcap_read: %s",
				pcap_strerror(errno));
			return (-1);
		}
		bp = p->buffer;
	} else
		bp = p->bp;

	/*
	 * Loop through each packet.  The increment expression
	 * rounds up to the next int boundary past the end of
	 * the previous packet.
	 */
	n = 0;
	ep = bp + cc;
	while (bp < ep) {
		/*
		 * Has "pcap_breakloop()" been called?
		 * If so, return immediately - if we haven't read any
		 * packets, clear the flag and return -2 to indicate
		 * that we were told to break out of the loop, otherwise
		 * leave the flag set, so that the *next* call will break
		 * out of the loop without having read any packets, and
		 * return the number of packets we've processed so far.
		 */
		if (p->break_loop) {
			if (n == 0) {
				p->break_loop = 0;
				return (-2);
			} else {
				p->cc = ep - bp;
				p->bp = bp;
				return (n);
			}
		}

		nh = (struct nit_hdr *)bp;
		cp = bp + sizeof(*nh);

		switch (nh->nh_state) {

		case NIT_CATCH:
			break;

		case NIT_NOMBUF:
		case NIT_NOCLUSTER:
		case NIT_NOSPACE:
			p->md.stat.ps_drop = nh->nh_dropped;
			continue;

		case NIT_SEQNO:
			continue;

		default:
			snprintf(p->errbuf, sizeof(p->errbuf),
			    "bad nit state %d", nh->nh_state);
			return (-1);
		}
		++p->md.stat.ps_recv;
		bp += ((sizeof(struct nit_hdr) + nh->nh_datalen +
		    sizeof(int) - 1) & ~(sizeof(int) - 1));

		caplen = nh->nh_wirelen;
		if (caplen > p->snapshot)
			caplen = p->snapshot;
		if (bpf_filter(fcode, cp, nh->nh_wirelen, caplen)) {
			struct pcap_pkthdr h;
			h.ts = nh->nh_timestamp;
			h.len = nh->nh_wirelen;
			h.caplen = caplen;
			(*callback)(user, &h, cp);
			if (++n >= cnt && cnt >= 0) {
				p->cc = ep - bp;
				p->bp = bp;
				return (n);
			}
		}
	}
	p->cc = 0;
	return (n);
}

static int
pcap_inject_nit(pcap_t *p, const void *buf, size_t size)
{
	struct sockaddr sa;
	int ret;

	memset(&sa, 0, sizeof(sa));
	strncpy(sa.sa_data, device, sizeof(sa.sa_data));
	ret = sendto(p->fd, buf, size, 0, &sa, sizeof(sa));
	if (ret == -1) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "send: %s",
		    pcap_strerror(errno));
		return (-1);
	}
	return (ret);
}                           

static int
nit_setflags(int fd, int promisc, int to_ms, char *ebuf)
{
	struct nit_ioc nioc;

	memset(&nioc, 0, sizeof(nioc));
	nioc.nioc_bufspace = BUFSPACE;
	nioc.nioc_chunksize = CHUNKSIZE;
	nioc.nioc_typetomatch = NT_ALLTYPES;
	nioc.nioc_snaplen = p->snapshot;
	nioc.nioc_bufalign = sizeof(int);
	nioc.nioc_bufoffset = 0;

	if (to_ms != 0) {
		nioc.nioc_flags |= NF_TIMEOUT;
		nioc.nioc_timeout.tv_sec = to_ms / 1000;
		nioc.nioc_timeout.tv_usec = (to_ms * 1000) % 1000000;
	}
	if (promisc)
		nioc.nioc_flags |= NF_PROMISC;

	if (ioctl(fd, SIOCSNIT, &nioc) < 0) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "SIOCSNIT: %s",
		    pcap_strerror(errno));
		return (-1);
	}
	return (0);
}

static void
pcap_close_nit(pcap_t *p)
{
	pcap_close_common(p);
	if (p->device != NULL)
		free(p->device);
}

pcap_t *
pcap_open_live(const char *device, int snaplen, int promisc, int to_ms,
    char *ebuf)
{
	int fd;
	struct sockaddr_nit snit;
	register pcap_t *p;

	p = (pcap_t *)malloc(sizeof(*p));
	if (p == NULL) {
		strlcpy(ebuf, pcap_strerror(errno), PCAP_ERRBUF_SIZE);
		return (NULL);
	}

	if (snaplen < 96)
		/*
		 * NIT requires a snapshot length of at least 96.
		 */
		snaplen = 96;

	memset(p, 0, sizeof(*p));
	p->fd = fd = socket(AF_NIT, SOCK_RAW, NITPROTO_RAW);
	if (fd < 0) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE,
		    "socket: %s", pcap_strerror(errno));
		goto bad;
	}
	snit.snit_family = AF_NIT;
	(void)strncpy(snit.snit_ifname, device, NITIFSIZ);

	if (bind(fd, (struct sockaddr *)&snit, sizeof(snit))) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE,
		    "bind: %s: %s", snit.snit_ifname, pcap_strerror(errno));
		goto bad;
	}
	p->snapshot = snaplen;
	nit_setflags(p->fd, promisc, to_ms, ebuf);

	/*
	 * NIT supports only ethernets.
	 */
	p->linktype = DLT_EN10MB;

	p->bufsize = BUFSPACE;
	p->buffer = (u_char *)malloc(p->bufsize);
	if (p->buffer == NULL) {
		strlcpy(ebuf, pcap_strerror(errno), PCAP_ERRBUF_SIZE);
		goto bad;
	}

	/*
	 * We need the device name in order to send packets.
	 */
	p->device = strdup(device);
	if (p->device == NULL) {
		strlcpy(ebuf, pcap_strerror(errno), PCAP_ERRBUF_SIZE);
		free(p->buffer);
		goto bad;
	}

	/*
	 * "p->fd" is a socket, so "select()" should work on it.
	 */
	p->selectable_fd = p->fd;

	/*
	 * This is (presumably) a real Ethernet capture; give it a
	 * link-layer-type list with DLT_EN10MB and DLT_DOCSIS, so
	 * that an application can let you choose it, in case you're
	 * capturing DOCSIS traffic that a Cisco Cable Modem
	 * Termination System is putting out onto an Ethernet (it
	 * doesn't put an Ethernet header onto the wire, it puts raw
	 * DOCSIS frames out on the wire inside the low-level
	 * Ethernet framing).
	 */
	p->dlt_list = (u_int *) malloc(sizeof(u_int) * 2);
	/*
	 * If that fails, just leave the list empty.
	 */
	if (p->dlt_list != NULL) {
		p->dlt_list[0] = DLT_EN10MB;
		p->dlt_list[1] = DLT_DOCSIS;
		p->dlt_count = 2;
	}

	p->read_op = pcap_read_nit;
	p->inject_op = pcap_inject_nit;
	p->setfilter_op = install_bpf_program;	/* no kernel filtering */
	p->setdirection_op = NULL;	/* Not implemented. */
	p->set_datalink_op = NULL;	/* can't change data link type */
	p->getnonblock_op = pcap_getnonblock_fd;
	p->setnonblock_op = pcap_setnonblock_fd;
	p->stats_op = pcap_stats_nit;
	p->close_op = pcap_close_nit;

	return (p);
 bad:
	if (fd >= 0)
		close(fd);
	free(p);
	return (NULL);
}

int
pcap_platform_finddevs(pcap_if_t **alldevsp, char *errbuf)
{
	return (0);
}
