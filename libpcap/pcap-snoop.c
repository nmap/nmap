/*
 * Copyright (c) 1993, 1994, 1995, 1996, 1997
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
    "@(#) $Header: /tcpdump/master/libpcap/pcap-snoop.c,v 1.54.2.1 2005/05/03 18:54:38 guy Exp $ (LBL)";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/param.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <net/raw.h>
#include <net/if.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/ip_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/tcp.h>
#include <netinet/tcpip.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pcap-int.h"

#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

static int
pcap_read_snoop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
{
	int cc;
	register struct snoopheader *sh;
	register u_int datalen;
	register u_int caplen;
	register u_char *cp;

again:
	/*
	 * Has "pcap_breakloop()" been called?
	 */
	if (p->break_loop) {
		/*
		 * Yes - clear the flag that indicates that it
		 * has, and return -2 to indicate that we were
		 * told to break out of the loop.
		 */
		p->break_loop = 0;
		return (-2);
	}
	cc = read(p->fd, (char *)p->buffer, p->bufsize);
	if (cc < 0) {
		/* Don't choke when we get ptraced */
		switch (errno) {

		case EINTR:
			goto again;

		case EWOULDBLOCK:
			return (0);			/* XXX */
		}
		snprintf(p->errbuf, sizeof(p->errbuf),
		    "read: %s", pcap_strerror(errno));
		return (-1);
	}
	sh = (struct snoopheader *)p->buffer;
	datalen = sh->snoop_packetlen;

	/*
	 * XXX - Sigh, snoop_packetlen is a 16 bit quantity.  If we
	 * got a short length, but read a full sized snoop pakcet,
	 * assume we overflowed and add back the 64K...
	 */
	if (cc == (p->snapshot + sizeof(struct snoopheader)) &&
	    (datalen < p->snapshot))
		datalen += (64 * 1024);

	caplen = (datalen < p->snapshot) ? datalen : p->snapshot;
	cp = (u_char *)(sh + 1) + p->offset;		/* XXX */

	/* 
	 * XXX unfortunately snoop loopback isn't exactly like
	 * BSD's.  The address family is encoded in the first 2
	 * bytes rather than the first 4 bytes!  Luckily the last
	 * two snoop loopback bytes are zeroed.
	 */
	if (p->linktype == DLT_NULL && *((short *)(cp + 2)) == 0) {
		u_int *uip = (u_int *)cp;
		*uip >>= 16;
	}

	if (p->fcode.bf_insns == NULL ||
	    bpf_filter(p->fcode.bf_insns, cp, datalen, caplen)) {
		struct pcap_pkthdr h;
		++p->md.stat.ps_recv;
		h.ts.tv_sec = sh->snoop_timestamp.tv_sec;
		h.ts.tv_usec = sh->snoop_timestamp.tv_usec;
		h.len = datalen;
		h.caplen = caplen;
		(*callback)(user, &h, cp);
		return (1);
	}
	return (0);
}

static int
pcap_inject_snoop(pcap_t *p, const void *buf, size_t size)
{
	int ret;

	/*
	 * XXX - libnet overwrites the source address with what I
	 * presume is the interface's address; is that required?
	 */
	ret = write(p->fd, buf, size);
	if (ret == -1) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "send: %s",
		    pcap_strerror(errno));
		return (-1);
	}
	return (ret);
}                           

static int
pcap_stats_snoop(pcap_t *p, struct pcap_stat *ps)
{
	register struct rawstats *rs;
	struct rawstats rawstats;

	rs = &rawstats;
	memset(rs, 0, sizeof(*rs));
	if (ioctl(p->fd, SIOCRAWSTATS, (char *)rs) < 0) {
		snprintf(p->errbuf, sizeof(p->errbuf),
		    "SIOCRAWSTATS: %s", pcap_strerror(errno));
		return (-1);
	}

	/*
	 * "ifdrops" are those dropped by the network interface
	 * due to resource shortages or hardware errors.
	 *
	 * "sbdrops" are those dropped due to socket buffer limits.
	 *
	 * As filter is done in userland, "sbdrops" counts packets
	 * regardless of whether they would've passed the filter.
	 *
	 * XXX - does this count *all* Snoop or Drain sockets,
	 * rather than just this socket?  If not, why does it have
	 * both Snoop and Drain statistics?
	 */
	p->md.stat.ps_drop =
	    rs->rs_snoop.ss_ifdrops + rs->rs_snoop.ss_sbdrops +
	    rs->rs_drain.ds_ifdrops + rs->rs_drain.ds_sbdrops;

	/*
	 * "ps_recv" counts only packets that passed the filter.
	 * As filtering is done in userland, this does not include
	 * packets dropped because we ran out of buffer space.
	 */
	*ps = p->md.stat;
	return (0);
}

/* XXX can't disable promiscuous */
pcap_t *
pcap_open_live(const char *device, int snaplen, int promisc, int to_ms,
    char *ebuf)
{
	int fd;
	struct sockaddr_raw sr;
	struct snoopfilter sf;
	u_int v;
	int ll_hdrlen;
	int snooplen;
	pcap_t *p;
	struct ifreq ifr;

	p = (pcap_t *)malloc(sizeof(*p));
	if (p == NULL) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "malloc: %s",
		    pcap_strerror(errno));
		return (NULL);
	}
	memset(p, 0, sizeof(*p));
	fd = socket(PF_RAW, SOCK_RAW, RAWPROTO_SNOOP);
	if (fd < 0) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "snoop socket: %s",
		    pcap_strerror(errno));
		goto bad;
	}
	p->fd = fd;
	memset(&sr, 0, sizeof(sr));
	sr.sr_family = AF_RAW;
	(void)strncpy(sr.sr_ifname, device, sizeof(sr.sr_ifname));
	if (bind(fd, (struct sockaddr *)&sr, sizeof(sr))) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "snoop bind: %s",
		    pcap_strerror(errno));
		goto bad;
	}
	memset(&sf, 0, sizeof(sf));
	if (ioctl(fd, SIOCADDSNOOP, &sf) < 0) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "SIOCADDSNOOP: %s",
		    pcap_strerror(errno));
		goto bad;
	}
	v = 64 * 1024;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *)&v, sizeof(v));
	/*
	 * XXX hack - map device name to link layer type
	 */
	if (strncmp("et", device, 2) == 0 ||	/* Challenge 10 Mbit */
	    strncmp("ec", device, 2) == 0 ||	/* Indigo/Indy 10 Mbit,
						   O2 10/100 */
	    strncmp("ef", device, 2) == 0 ||	/* O200/2000 10/100 Mbit */
	    strncmp("eg", device, 2) == 0 ||	/* Octane/O2xxx/O3xxx Gigabit */
	    strncmp("gfe", device, 3) == 0 ||	/* GIO 100 Mbit */
	    strncmp("fxp", device, 3) == 0 ||	/* Challenge VME Enet */
	    strncmp("ep", device, 2) == 0 ||	/* Challenge 8x10 Mbit EPLEX */
	    strncmp("vfe", device, 3) == 0 ||	/* Challenge VME 100Mbit */
	    strncmp("fa", device, 2) == 0 ||
	    strncmp("qaa", device, 3) == 0 ||
	    strncmp("cip", device, 3) == 0 ||
	    strncmp("el", device, 2) == 0) {
		p->linktype = DLT_EN10MB;
		p->offset = RAW_HDRPAD(sizeof(struct ether_header));
		ll_hdrlen = sizeof(struct ether_header);
		/*
		 * This is (presumably) a real Ethernet capture; give it a
		 * link-layer-type list with DLT_EN10MB and DLT_DOCSIS, so
		 * that an application can let you choose it, in case you're
		 * capturing DOCSIS traffic that a Cisco Cable Modem
		 * Termination System is putting out onto an Ethernet (it
		 * doesn't put an Ethernet header onto the wire, it puts raw
		 * DOCSIS frames out on the wire inside the low-level
		 * Ethernet framing).
		 *
		 * XXX - are there any sorts of "fake Ethernet" that have
		 * Ethernet link-layer headers but that *shouldn't offer
		 * DLT_DOCSIS as a Cisco CMTS won't put traffic onto it
		 * or get traffic bridged onto it?  "el" is for ATM LANE
		 * Ethernet devices, so that might be the case for them;
		 * the same applies for "qaa" classical IP devices.  If
		 * "fa" devices are for FORE SPANS, that'd apply to them
		 * as well; what are "cip" devices - some other ATM
		 * Classical IP devices?
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
	} else if (strncmp("ipg", device, 3) == 0 ||
		   strncmp("rns", device, 3) == 0 ||	/* O2/200/2000 FDDI */
		   strncmp("xpi", device, 3) == 0) {
		p->linktype = DLT_FDDI;
		p->offset = 3;				/* XXX yeah? */
		ll_hdrlen = 13;
	} else if (strncmp("ppp", device, 3) == 0) {
		p->linktype = DLT_RAW;
		ll_hdrlen = 0;	/* DLT_RAW meaning "no PPP header, just the IP packet"? */
	} else if (strncmp("qfa", device, 3) == 0) {
		p->linktype = DLT_IP_OVER_FC;
		ll_hdrlen = 24;
	} else if (strncmp("pl", device, 2) == 0) {
		p->linktype = DLT_RAW;
		ll_hdrlen = 0;	/* Cray UNICOS/mp pseudo link */
	} else if (strncmp("lo", device, 2) == 0) {
		p->linktype = DLT_NULL;
		ll_hdrlen = 4;
	} else {
		snprintf(ebuf, PCAP_ERRBUF_SIZE,
		    "snoop: unknown physical layer type");
		goto bad;
	}
#ifdef SIOCGIFMTU
	/*
	 * XXX - IRIX appears to give you an error if you try to set the
	 * capture length to be greater than the MTU, so let's try to get
	 * the MTU first and, if that succeeds, trim the snap length
	 * to be no greater than the MTU.
	 */
	(void)strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
	if (ioctl(fd, SIOCGIFMTU, (char *)&ifr) < 0) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "SIOCGIFMTU: %s",
		    pcap_strerror(errno));
		goto bad;
	}
	/*
	 * OK, we got it.
	 *
	 * XXX - some versions of IRIX 6.5 define "ifr_mtu" and have an
	 * "ifru_metric" member of the "ifr_ifru" union in an "ifreq"
	 * structure, others don't.
	 *
	 * I've no idea what's going on, so, if "ifr_mtu" isn't defined,
	 * we define it as "ifr_metric", as using that field appears to
	 * work on the versions that lack "ifr_mtu" (and, on those that
	 * don't lack it, "ifru_metric" and "ifru_mtu" are both "int"
	 * members of the "ifr_ifru" union, which suggests that they
	 * may be interchangeable in this case).
	 */
#ifndef ifr_mtu
#define ifr_mtu	ifr_metric
#endif
	if (snaplen > ifr.ifr_mtu + ll_hdrlen)
		snaplen = ifr.ifr_mtu + ll_hdrlen;
#endif

	/*
	 * The argument to SIOCSNOOPLEN is the number of link-layer
	 * payload bytes to capture - it doesn't count link-layer
	 * header bytes.
	 */
	snooplen = snaplen - ll_hdrlen;
	if (snooplen < 0)
		snooplen = 0;
	if (ioctl(fd, SIOCSNOOPLEN, &snooplen) < 0) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "SIOCSNOOPLEN: %s",
		    pcap_strerror(errno));
		goto bad;
	}
	p->snapshot = snaplen;
	v = 1;
	if (ioctl(fd, SIOCSNOOPING, &v) < 0) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "SIOCSNOOPING: %s",
		    pcap_strerror(errno));
		goto bad;
	}

	p->bufsize = 4096;				/* XXX */
	p->buffer = (u_char *)malloc(p->bufsize);
	if (p->buffer == NULL) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "malloc: %s",
		    pcap_strerror(errno));
		goto bad;
	}

	/*
	 * "p->fd" is a socket, so "select()" should work on it.
	 */
	p->selectable_fd = p->fd;

	p->read_op = pcap_read_snoop;
	p->inject_op = pcap_inject_snoop;
	p->setfilter_op = install_bpf_program;	/* no kernel filtering */
	p->setdirection_op = NULL;	/* Not implemented. */
	p->set_datalink_op = NULL;	/* can't change data link type */
	p->getnonblock_op = pcap_getnonblock_fd;
	p->setnonblock_op = pcap_setnonblock_fd;
	p->stats_op = pcap_stats_snoop;
	p->close_op = pcap_close_common;

	return (p);
 bad:
	(void)close(fd);
	/*
	 * Get rid of any link-layer type list we allocated.
	 */
	if (p->dlt_list != NULL)
		free(p->dlt_list);
	free(p);
	return (NULL);
}

int
pcap_platform_finddevs(pcap_if_t **alldevsp, char *errbuf)
{
	return (0);
}
