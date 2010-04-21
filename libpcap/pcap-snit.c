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
 *
 * Modifications made to accommodate the new SunOS4.0 NIT facility by
 * Micky Liu, micky@cunixc.cc.columbia.edu, Columbia University in May, 1989.
 * This module now handles the STREAMS based NIT.
 */

#ifndef lint
static const char rcsid[] _U_ =
    "@(#) $Header: /tcpdump/master/libpcap/pcap-snit.c,v 1.77 2008-04-14 20:40:58 guy Exp $ (LBL)";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/timeb.h>
#include <sys/dir.h>
#include <sys/fcntlcom.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stropts.h>

#include <net/if.h>
#include <net/nit.h>
#include <net/nit_if.h>
#include <net/nit_pf.h>
#include <net/nit_buf.h>

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
#include <string.h>
#include <unistd.h>

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
pcap_stats_snit(pcap_t *p, struct pcap_stat *ps)
{

	/*
	 * "ps_recv" counts packets handed to the filter, not packets
	 * that passed the filter.  As filtering is done in userland,
	 * this does not include packets dropped because we ran out
	 * of buffer space.
	 *
	 * "ps_drop" counts packets dropped inside the "/dev/nit"
	 * device because of flow control requirements or resource
	 * exhaustion; it doesn't count packets dropped by the
	 * interface driver, or packets dropped upstream.  As filtering
	 * is done in userland, it counts packets regardless of whether
	 * they would've passed the filter.
	 *
	 * These statistics don't include packets not yet read from the
	 * kernel by libpcap or packets not yet read from libpcap by the
	 * application.
	 */
	*ps = p->md.stat;
	return (0);
}

static int
pcap_read_snit(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
{
	register int cc, n;
	register u_char *bp, *cp, *ep;
	register struct nit_bufhdr *hdrp;
	register struct nit_iftime *ntp;
	register struct nit_iflen *nlp;
	register struct nit_ifdrops *ndp;
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
	 * loop through each snapshot in the chunk
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
				p->bp = bp;
				p->cc = ep - bp;
				return (n);
			}
		}

		++p->md.stat.ps_recv;
		cp = bp;

		/* get past NIT buffer  */
		hdrp = (struct nit_bufhdr *)cp;
		cp += sizeof(*hdrp);

		/* get past NIT timer   */
		ntp = (struct nit_iftime *)cp;
		cp += sizeof(*ntp);

		ndp = (struct nit_ifdrops *)cp;
		p->md.stat.ps_drop = ndp->nh_drops;
		cp += sizeof *ndp;

		/* get past packet len  */
		nlp = (struct nit_iflen *)cp;
		cp += sizeof(*nlp);

		/* next snapshot        */
		bp += hdrp->nhb_totlen;

		caplen = nlp->nh_pktlen;
		if (caplen > p->snapshot)
			caplen = p->snapshot;

		if (bpf_filter(p->fcode.bf_insns, cp, nlp->nh_pktlen, caplen)) {
			struct pcap_pkthdr h;
			h.ts = ntp->nh_timestamp;
			h.len = nlp->nh_pktlen;
			h.caplen = caplen;
			(*callback)(user, &h, cp);
			if (++n >= cnt && cnt > 0) {
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
pcap_inject_snit(pcap_t *p, const void *buf, size_t size)
{
	struct strbuf ctl, data;
	
	/*
	 * XXX - can we just do
	 *
	ret = write(pd->f, buf, size);
	 */
	ctl.len = sizeof(*sa);	/* XXX - what was this? */
	ctl.buf = (char *)sa;
	data.buf = buf;
	data.len = size;
	ret = putmsg(p->fd, &ctl, &data);
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
	bpf_u_int32 flags;
	struct strioctl si;
	struct timeval timeout;

	si.ic_timout = INFTIM;
	if (to_ms != 0) {
		timeout.tv_sec = to_ms / 1000;
		timeout.tv_usec = (to_ms * 1000) % 1000000;
		si.ic_cmd = NIOCSTIME;
		si.ic_len = sizeof(timeout);
		si.ic_dp = (char *)&timeout;
		if (ioctl(fd, I_STR, (char *)&si) < 0) {
			snprintf(ebuf, PCAP_ERRBUF_SIZE, "NIOCSTIME: %s",
			    pcap_strerror(errno));
			return (-1);
		}
	}
	flags = NI_TIMESTAMP | NI_LEN | NI_DROPS;
	if (promisc)
		flags |= NI_PROMISC;
	si.ic_cmd = NIOCSFLAGS;
	si.ic_len = sizeof(flags);
	si.ic_dp = (char *)&flags;
	if (ioctl(fd, I_STR, (char *)&si) < 0) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "NIOCSFLAGS: %s",
		    pcap_strerror(errno));
		return (-1);
	}
	return (0);
}

static int
pcap_activate_snit(pcap_t *p)
{
	struct strioctl si;		/* struct for ioctl() */
	struct ifreq ifr;		/* interface request struct */
	int chunksize = CHUNKSIZE;
	int fd;
	static char dev[] = "/dev/nit";

	if (p->opt.rfmon) {
		/*
		 * No monitor mode on SunOS 4.x (no Wi-Fi devices on
		 * hardware supported by SunOS 4.x).
		 */
		return (PCAP_ERROR_RFMON_NOTSUP);
	}

	if (p->snapshot < 96)
		/*
		 * NIT requires a snapshot length of at least 96.
		 */
		p->snapshot = 96;

	/*
	 * Initially try a read/write open (to allow the inject
	 * method to work).  If that fails due to permission
	 * issues, fall back to read-only.  This allows a
	 * non-root user to be granted specific access to pcap
	 * capabilities via file permissions.
	 *
	 * XXX - we should have an API that has a flag that
	 * controls whether to open read-only or read-write,
	 * so that denial of permission to send (or inability
	 * to send, if sending packets isn't supported on
	 * the device in question) can be indicated at open
	 * time.
	 */
	p->fd = fd = open(dev, O_RDWR);
	if (fd < 0 && errno == EACCES)
		p->fd = fd = open(dev, O_RDONLY);
	if (fd < 0) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "%s: %s", dev,
		    pcap_strerror(errno));
		goto bad;
	}

	/* arrange to get discrete messages from the STREAM and use NIT_BUF */
	if (ioctl(fd, I_SRDOPT, (char *)RMSGD) < 0) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "I_SRDOPT: %s",
		    pcap_strerror(errno));
		goto bad;
	}
	if (ioctl(fd, I_PUSH, "nbuf") < 0) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "push nbuf: %s",
		    pcap_strerror(errno));
		goto bad;
	}
	/* set the chunksize */
	si.ic_cmd = NIOCSCHUNK;
	si.ic_timout = INFTIM;
	si.ic_len = sizeof(chunksize);
	si.ic_dp = (char *)&chunksize;
	if (ioctl(fd, I_STR, (char *)&si) < 0) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "NIOCSCHUNK: %s",
		    pcap_strerror(errno));
		goto bad;
	}

	/* request the interface */
	strncpy(ifr.ifr_name, p->opt.source, sizeof(ifr.ifr_name));
	ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';
	si.ic_cmd = NIOCBIND;
	si.ic_len = sizeof(ifr);
	si.ic_dp = (char *)&ifr;
	if (ioctl(fd, I_STR, (char *)&si) < 0) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "NIOCBIND: %s: %s",
			ifr.ifr_name, pcap_strerror(errno));
		goto bad;
	}

	/* set the snapshot length */
	si.ic_cmd = NIOCSSNAP;
	si.ic_len = sizeof(p->snapshot);
	si.ic_dp = (char *)&p->snapshot;
	if (ioctl(fd, I_STR, (char *)&si) < 0) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "NIOCSSNAP: %s",
		    pcap_strerror(errno));
		goto bad;
	}
	if (nit_setflags(p->fd, p->opt.promisc, p->md.timeout, p->errbuf) < 0)
		goto bad;

	(void)ioctl(fd, I_FLUSH, (char *)FLUSHR);
	/*
	 * NIT supports only ethernets.
	 */
	p->linktype = DLT_EN10MB;

	p->bufsize = BUFSPACE;
	p->buffer = (u_char *)malloc(p->bufsize);
	if (p->buffer == NULL) {
		strlcpy(p->errbuf, pcap_strerror(errno), PCAP_ERRBUF_SIZE);
		goto bad;
	}

	/*
	 * "p->fd" is an FD for a STREAMS device, so "select()" and
	 * "poll()" should work on it.
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

	p->read_op = pcap_read_snit;
	p->inject_op = pcap_inject_snit;
	p->setfilter_op = install_bpf_program;	/* no kernel filtering */
	p->setdirection_op = NULL;	/* Not implemented. */
	p->set_datalink_op = NULL;	/* can't change data link type */
	p->getnonblock_op = pcap_getnonblock_fd;
	p->setnonblock_op = pcap_setnonblock_fd;
	p->stats_op = pcap_stats_snit;

	return (0);
 bad:
	pcap_cleanup_live_common(p);
	return (PCAP_ERROR);
}

pcap_t *
pcap_create(const char *device, char *ebuf)
{
	pcap_t *p;

	p = pcap_create_common(device, ebuf);
	if (p == NULL)
		return (NULL);

	p->activate_op = pcap_activate_snit;
	return (p);
}

int
pcap_platform_finddevs(pcap_if_t **alldevsp, char *errbuf)
{
	return (0);
}
