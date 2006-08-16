/*
 *  pcap-linux.c: Packet capture interface to the Linux kernel
 *
 *  Copyright (c) 2000 Torsten Landschoff <torsten@debian.org>
 *  		       Sebastian Krahmer  <krahmer@cs.uni-potsdam.de>
 *
 *  License: BSD
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *  3. The names of the authors may not be used to endorse or promote
 *     products derived from this software without specific prior
 *     written permission.
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 *  IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifndef lint
static const char rcsid[] _U_ =
    "@(#) $Header: /tcpdump/master/libpcap/pcap-linux.c,v 1.110.2.6 2005/08/16 04:25:26 guy Exp $ (LBL)";
#endif

/*
 * Known problems with 2.0[.x] kernels:
 *
 *   - The loopback device gives every packet twice; on 2.2[.x] kernels,
 *     if we use PF_PACKET, we can filter out the transmitted version
 *     of the packet by using data in the "sockaddr_ll" returned by
 *     "recvfrom()", but, on 2.0[.x] kernels, we have to use
 *     PF_INET/SOCK_PACKET, which means "recvfrom()" supplies a
 *     "sockaddr_pkt" which doesn't give us enough information to let
 *     us do that.
 *
 *   - We have to set the interface's IFF_PROMISC flag ourselves, if
 *     we're to run in promiscuous mode, which means we have to turn
 *     it off ourselves when we're done; the kernel doesn't keep track
 *     of how many sockets are listening promiscuously, which means
 *     it won't get turned off automatically when no sockets are
 *     listening promiscuously.  We catch "pcap_close()" and, for
 *     interfaces we put into promiscuous mode, take them out of
 *     promiscuous mode - which isn't necessarily the right thing to
 *     do, if another socket also requested promiscuous mode between
 *     the time when we opened the socket and the time when we close
 *     the socket.
 *
 *   - MSG_TRUNC isn't supported, so you can't specify that "recvfrom()"
 *     return the amount of data that you could have read, rather than
 *     the amount that was returned, so we can't just allocate a buffer
 *     whose size is the snapshot length and pass the snapshot length
 *     as the byte count, and also pass MSG_TRUNC, so that the return
 *     value tells us how long the packet was on the wire.
 *
 *     This means that, if we want to get the actual size of the packet,
 *     so we can return it in the "len" field of the packet header,
 *     we have to read the entire packet, not just the part that fits
 *     within the snapshot length, and thus waste CPU time copying data
 *     from the kernel that our caller won't see.
 *
 *     We have to get the actual size, and supply it in "len", because
 *     otherwise, the IP dissector in tcpdump, for example, will complain
 *     about "truncated-ip", as the packet will appear to have been
 *     shorter, on the wire, than the IP header said it should have been.
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pcap-int.h"
#include "sll.h"

#ifdef HAVE_DAG_API
#include "pcap-dag.h"
#endif /* HAVE_DAG_API */

#ifdef HAVE_SEPTEL_API
#include "pcap-septel.h"
#endif /* HAVE_SEPTEL_API */
	  
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <net/if_arp.h>

/*
 * If PF_PACKET is defined, we can use {SOCK_RAW,SOCK_DGRAM}/PF_PACKET
 * sockets rather than SOCK_PACKET sockets.
 *
 * To use them, we include <linux/if_packet.h> rather than
 * <netpacket/packet.h>; we do so because
 *
 *	some Linux distributions (e.g., Slackware 4.0) have 2.2 or
 *	later kernels and libc5, and don't provide a <netpacket/packet.h>
 *	file;
 *
 *	not all versions of glibc2 have a <netpacket/packet.h> file
 *	that defines stuff needed for some of the 2.4-or-later-kernel
 *	features, so if the system has a 2.4 or later kernel, we
 *	still can't use those features.
 *
 * We're already including a number of other <linux/XXX.h> headers, and
 * this code is Linux-specific (no other OS has PF_PACKET sockets as
 * a raw packet capture mechanism), so it's not as if you gain any
 * useful portability by using <netpacket/packet.h>
 *
 * XXX - should we just include <linux/if_packet.h> even if PF_PACKET
 * isn't defined?  It only defines one data structure in 2.0.x, so
 * it shouldn't cause any problems.
 */
#ifdef PF_PACKET
# include <linux/if_packet.h>

 /*
  * On at least some Linux distributions (for example, Red Hat 5.2),
  * there's no <netpacket/packet.h> file, but PF_PACKET is defined if
  * you include <sys/socket.h>, but <linux/if_packet.h> doesn't define
  * any of the PF_PACKET stuff such as "struct sockaddr_ll" or any of
  * the PACKET_xxx stuff.
  *
  * So we check whether PACKET_HOST is defined, and assume that we have
  * PF_PACKET sockets only if it is defined.
  */
# ifdef PACKET_HOST
#  define HAVE_PF_PACKET_SOCKETS
# endif /* PACKET_HOST */
#endif /* PF_PACKET */

#ifdef SO_ATTACH_FILTER
#include <linux/types.h>
#include <linux/filter.h>
#endif

#ifndef __GLIBC__
typedef int		socklen_t;
#endif

#ifndef MSG_TRUNC
/*
 * This is being compiled on a system that lacks MSG_TRUNC; define it
 * with the value it has in the 2.2 and later kernels, so that, on
 * those kernels, when we pass it in the flags argument to "recvfrom()"
 * we're passing the right value and thus get the MSG_TRUNC behavior
 * we want.  (We don't get that behavior on 2.0[.x] kernels, because
 * they didn't support MSG_TRUNC.)
 */
#define MSG_TRUNC	0x20
#endif

#ifndef SOL_PACKET
/*
 * This is being compiled on a system that lacks SOL_PACKET; define it
 * with the value it has in the 2.2 and later kernels, so that we can
 * set promiscuous mode in the good modern way rather than the old
 * 2.0-kernel crappy way.
 */
#define SOL_PACKET	263
#endif

#define MAX_LINKHEADER_SIZE	256

/*
 * When capturing on all interfaces we use this as the buffer size.
 * Should be bigger then all MTUs that occur in real life.
 * 64kB should be enough for now.
 */
#define BIGGER_THAN_ALL_MTUS	(64*1024)

/*
 * Prototypes for internal functions
 */
static void map_arphrd_to_dlt(pcap_t *, int, int);
static int live_open_old(pcap_t *, const char *, int, int, char *);
static int live_open_new(pcap_t *, const char *, int, int, char *);
static int pcap_read_linux(pcap_t *, int, pcap_handler, u_char *);
static int pcap_read_packet(pcap_t *, pcap_handler, u_char *);
static int pcap_inject_linux(pcap_t *, const void *, size_t);
static int pcap_stats_linux(pcap_t *, struct pcap_stat *);
static int pcap_setfilter_linux(pcap_t *, struct bpf_program *);
static int pcap_setdirection_linux(pcap_t *, pcap_direction_t);
static void pcap_close_linux(pcap_t *);

/*
 * Wrap some ioctl calls
 */
#ifdef HAVE_PF_PACKET_SOCKETS
static int	iface_get_id(int fd, const char *device, char *ebuf);
#endif
static int	iface_get_mtu(int fd, const char *device, char *ebuf);
static int 	iface_get_arptype(int fd, const char *device, char *ebuf);
#ifdef HAVE_PF_PACKET_SOCKETS
static int 	iface_bind(int fd, int ifindex, char *ebuf);
#endif
static int 	iface_bind_old(int fd, const char *device, char *ebuf);

#ifdef SO_ATTACH_FILTER
static int	fix_program(pcap_t *handle, struct sock_fprog *fcode);
static int	fix_offset(struct bpf_insn *p);
static int	set_kernel_filter(pcap_t *handle, struct sock_fprog *fcode);
static int	reset_kernel_filter(pcap_t *handle);

static struct sock_filter	total_insn
	= BPF_STMT(BPF_RET | BPF_K, 0);
static struct sock_fprog	total_fcode
	= { 1, &total_insn };
#endif

/*
 *  Get a handle for a live capture from the given device. You can
 *  pass NULL as device to get all packages (without link level
 *  information of course). If you pass 1 as promisc the interface
 *  will be set to promiscous mode (XXX: I think this usage should
 *  be deprecated and functions be added to select that later allow
 *  modification of that values -- Torsten).
 *
 *  See also pcap(3).
 */
pcap_t *
pcap_open_live(const char *device, int snaplen, int promisc, int to_ms,
    char *ebuf)
{
	pcap_t		*handle;
	int		mtu;
	int		err;
	int		live_open_ok = 0;
	struct utsname	utsname;

#ifdef HAVE_DAG_API
	if (strstr(device, "dag")) {
		return dag_open_live(device, snaplen, promisc, to_ms, ebuf);
	}
#endif /* HAVE_DAG_API */

#ifdef HAVE_SEPTEL_API
	if (strstr(device, "septel")) {
		return septel_open_live(device, snaplen, promisc, to_ms, ebuf);
	}
#endif /* HAVE_SEPTEL_API */

	/* Allocate a handle for this session. */

	handle = malloc(sizeof(*handle));
	if (handle == NULL) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "malloc: %s",
			 pcap_strerror(errno));
		return NULL;
	}

	/* Initialize some components of the pcap structure. */

	memset(handle, 0, sizeof(*handle));
	handle->snapshot	= snaplen;
	handle->md.timeout	= to_ms;

	/*
	 * NULL and "any" are special devices which give us the hint to
	 * monitor all devices.
	 */
	if (!device || strcmp(device, "any") == 0) {
		device			= NULL;
		handle->md.device	= strdup("any");
		if (promisc) {
			promisc = 0;
			/* Just a warning. */
			snprintf(ebuf, PCAP_ERRBUF_SIZE,
			    "Promiscuous mode not supported on the \"any\" device");
		}

	} else
		handle->md.device	= strdup(device);

	if (handle->md.device == NULL) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "strdup: %s",
			 pcap_strerror(errno) );
		free(handle);
		return NULL;
	}

	/*
	 * Current Linux kernels use the protocol family PF_PACKET to
	 * allow direct access to all packets on the network while
	 * older kernels had a special socket type SOCK_PACKET to
	 * implement this feature.
	 * While this old implementation is kind of obsolete we need
	 * to be compatible with older kernels for a while so we are
	 * trying both methods with the newer method preferred.
	 */

	if ((err = live_open_new(handle, device, promisc, to_ms, ebuf)) == 1)
		live_open_ok = 1;
	else if (err == 0) {
		/* Non-fatal error; try old way */
		if (live_open_old(handle, device, promisc, to_ms, ebuf))
			live_open_ok = 1;
	}
	if (!live_open_ok) {
		/*
		 * Both methods to open the packet socket failed. Tidy
		 * up and report our failure (ebuf is expected to be
		 * set by the functions above).
		 */

		if (handle->md.device != NULL)
			free(handle->md.device);
		free(handle);
		return NULL;
	}

	/*
	 * Compute the buffer size.
	 *
	 * If we're using SOCK_PACKET, this might be a 2.0[.x] kernel,
	 * and might require special handling - check.
	 */
	if (handle->md.sock_packet && (uname(&utsname) < 0 ||
	    strncmp(utsname.release, "2.0", 3) == 0)) {
		/*
		 * We're using a SOCK_PACKET structure, and either
		 * we couldn't find out what kernel release this is,
		 * or it's a 2.0[.x] kernel.
		 *
		 * In the 2.0[.x] kernel, a "recvfrom()" on
		 * a SOCK_PACKET socket, with MSG_TRUNC set, will
		 * return the number of bytes read, so if we pass
		 * a length based on the snapshot length, it'll
		 * return the number of bytes from the packet
		 * copied to userland, not the actual length
		 * of the packet.
		 *
		 * This means that, for example, the IP dissector
		 * in tcpdump will get handed a packet length less
		 * than the length in the IP header, and will
		 * complain about "truncated-ip".
		 *
		 * So we don't bother trying to copy from the
		 * kernel only the bytes in which we're interested,
		 * but instead copy them all, just as the older
		 * versions of libpcap for Linux did.
		 *
		 * The buffer therefore needs to be big enough to
		 * hold the largest packet we can get from this
		 * device.  Unfortunately, we can't get the MRU
		 * of the network; we can only get the MTU.  The
		 * MTU may be too small, in which case a packet larger
		 * than the buffer size will be truncated *and* we
		 * won't get the actual packet size.
		 *
		 * However, if the snapshot length is larger than
		 * the buffer size based on the MTU, we use the
		 * snapshot length as the buffer size, instead;
		 * this means that with a sufficiently large snapshot
		 * length we won't artificially truncate packets
		 * to the MTU-based size.
		 *
		 * This mess just one of many problems with packet
		 * capture on 2.0[.x] kernels; you really want a
		 * 2.2[.x] or later kernel if you want packet capture
		 * to work well.
		 */
		mtu = iface_get_mtu(handle->fd, device, ebuf);
		if (mtu == -1) {
			pcap_close_linux(handle);
			free(handle);
			return NULL;
		}
		handle->bufsize = MAX_LINKHEADER_SIZE + mtu;
		if (handle->bufsize < handle->snapshot)
			handle->bufsize = handle->snapshot;
	} else {
		/*
		 * This is a 2.2[.x] or later kernel (we know that
		 * either because we're not using a SOCK_PACKET
		 * socket - PF_PACKET is supported only in 2.2
		 * and later kernels - or because we checked the
		 * kernel version).
		 *
		 * We can safely pass "recvfrom()" a byte count
		 * based on the snapshot length.
		 */
		handle->bufsize = handle->snapshot;
	}

	/* Allocate the buffer */

	handle->buffer	 = malloc(handle->bufsize + handle->offset);
	if (!handle->buffer) {
	        snprintf(ebuf, PCAP_ERRBUF_SIZE,
			 "malloc: %s", pcap_strerror(errno));
		pcap_close_linux(handle);
		free(handle);
		return NULL;
	}

	/*
	 * "handle->fd" is a socket, so "select()" and "poll()"
	 * should work on it.
	 */
	handle->selectable_fd = handle->fd;

	handle->read_op = pcap_read_linux;
	handle->inject_op = pcap_inject_linux;
	handle->setfilter_op = pcap_setfilter_linux;
	handle->setdirection_op = pcap_setdirection_linux;
	handle->set_datalink_op = NULL;	/* can't change data link type */
	handle->getnonblock_op = pcap_getnonblock_fd;
	handle->setnonblock_op = pcap_setnonblock_fd;
	handle->stats_op = pcap_stats_linux;
	handle->close_op = pcap_close_linux;

	return handle;
}

/*
 *  Read at most max_packets from the capture stream and call the callback
 *  for each of them. Returns the number of packets handled or -1 if an
 *  error occured.
 */
static int
pcap_read_linux(pcap_t *handle, int max_packets, pcap_handler callback, u_char *user)
{
	/*
	 * Currently, on Linux only one packet is delivered per read,
	 * so we don't loop.
	 */
	return pcap_read_packet(handle, callback, user);
}

/*
 *  Read a packet from the socket calling the handler provided by
 *  the user. Returns the number of packets received or -1 if an
 *  error occured.
 */
static int
pcap_read_packet(pcap_t *handle, pcap_handler callback, u_char *userdata)
{
	u_char			*bp;
	int			offset;
#ifdef HAVE_PF_PACKET_SOCKETS
	struct sockaddr_ll	from;
	struct sll_header	*hdrp;
#else
	struct sockaddr		from;
#endif
	socklen_t		fromlen;
	int			packet_len, caplen;
	struct pcap_pkthdr	pcap_header;

#ifdef HAVE_PF_PACKET_SOCKETS
	/*
	 * If this is a cooked device, leave extra room for a
	 * fake packet header.
	 */
	if (handle->md.cooked)
		offset = SLL_HDR_LEN;
	else
		offset = 0;
#else
	/*
	 * This system doesn't have PF_PACKET sockets, so it doesn't
	 * support cooked devices.
	 */
	offset = 0;
#endif

	/* Receive a single packet from the kernel */

	bp = handle->buffer + handle->offset;
	do {
		/*
		 * Has "pcap_breakloop()" been called?
		 */
		if (handle->break_loop) {
			/*
			 * Yes - clear the flag that indicates that it
			 * has, and return -2 as an indication that we
			 * were told to break out of the loop.
			 */
			handle->break_loop = 0;
			return -2;
		}
		fromlen = sizeof(from);
		packet_len = recvfrom(
			handle->fd, bp + offset,
			handle->bufsize - offset, MSG_TRUNC,
			(struct sockaddr *) &from, &fromlen);
	} while (packet_len == -1 && errno == EINTR);

	/* Check if an error occured */

	if (packet_len == -1) {
		if (errno == EAGAIN)
			return 0;	/* no packet there */
		else {
			snprintf(handle->errbuf, sizeof(handle->errbuf),
				 "recvfrom: %s", pcap_strerror(errno));
			return -1;
		}
	}

#ifdef HAVE_PF_PACKET_SOCKETS
	if (!handle->md.sock_packet) {
		/*
		 * Do checks based on packet direction.
		 * We can only do this if we're using PF_PACKET; the
		 * address returned for SOCK_PACKET is a "sockaddr_pkt"
		 * which lacks the relevant packet type information.
		 */
		if (from.sll_pkttype == PACKET_OUTGOING) {
			/*
			 * Outgoing packet.
			 * If this is from the loopback device, reject it;
			 * we'll see the packet as an incoming packet as well,
			 * and we don't want to see it twice.
			 */
			if (from.sll_ifindex == handle->md.lo_ifindex)
				return 0;

			/*
			 * If the user only wants incoming packets, reject it.
			 */
			if (handle->direction == PCAP_D_IN)
				return 0;
		} else {
			/*
			 * Incoming packet.
			 * If the user only wants outgoing packets, reject it.
			 */
			if (handle->direction == PCAP_D_OUT)
				return 0;
		}
	}
#endif

#ifdef HAVE_PF_PACKET_SOCKETS
	/*
	 * If this is a cooked device, fill in the fake packet header.
	 */
	if (handle->md.cooked) {
		/*
		 * Add the length of the fake header to the length
		 * of packet data we read.
		 */
		packet_len += SLL_HDR_LEN;

		hdrp = (struct sll_header *)bp;

		/*
		 * Map the PACKET_ value to a LINUX_SLL_ value; we
		 * want the same numerical value to be used in
		 * the link-layer header even if the numerical values
		 * for the PACKET_ #defines change, so that programs
		 * that look at the packet type field will always be
		 * able to handle DLT_LINUX_SLL captures.
		 */
		switch (from.sll_pkttype) {

		case PACKET_HOST:
			hdrp->sll_pkttype = htons(LINUX_SLL_HOST);
			break;

		case PACKET_BROADCAST:
			hdrp->sll_pkttype = htons(LINUX_SLL_BROADCAST);
			break;

		case PACKET_MULTICAST:
			hdrp->sll_pkttype = htons(LINUX_SLL_MULTICAST);
			break;

		case PACKET_OTHERHOST:
			hdrp->sll_pkttype = htons(LINUX_SLL_OTHERHOST);
			break;

		case PACKET_OUTGOING:
			hdrp->sll_pkttype = htons(LINUX_SLL_OUTGOING);
			break;

		default:
			hdrp->sll_pkttype = -1;
			break;
		}

		hdrp->sll_hatype = htons(from.sll_hatype);
		hdrp->sll_halen = htons(from.sll_halen);
		memcpy(hdrp->sll_addr, from.sll_addr,
		    (from.sll_halen > SLL_ADDRLEN) ?
		      SLL_ADDRLEN :
		      from.sll_halen);
		hdrp->sll_protocol = from.sll_protocol;
	}
#endif

	/*
	 * XXX: According to the kernel source we should get the real
	 * packet len if calling recvfrom with MSG_TRUNC set. It does
	 * not seem to work here :(, but it is supported by this code
	 * anyway.
	 * To be honest the code RELIES on that feature so this is really
	 * broken with 2.2.x kernels.
	 * I spend a day to figure out what's going on and I found out
	 * that the following is happening:
	 *
	 * The packet comes from a random interface and the packet_rcv
	 * hook is called with a clone of the packet. That code inserts
	 * the packet into the receive queue of the packet socket.
	 * If a filter is attached to that socket that filter is run
	 * first - and there lies the problem. The default filter always
	 * cuts the packet at the snaplen:
	 *
	 * # tcpdump -d
	 * (000) ret      #68
	 *
	 * So the packet filter cuts down the packet. The recvfrom call
	 * says "hey, it's only 68 bytes, it fits into the buffer" with
	 * the result that we don't get the real packet length. This
	 * is valid at least until kernel 2.2.17pre6.
	 *
	 * We currently handle this by making a copy of the filter
	 * program, fixing all "ret" instructions with non-zero
	 * operands to have an operand of 65535 so that the filter
	 * doesn't truncate the packet, and supplying that modified
	 * filter to the kernel.
	 */

	caplen = packet_len;
	if (caplen > handle->snapshot)
		caplen = handle->snapshot;

	/* Run the packet filter if not using kernel filter */
	if (!handle->md.use_bpf && handle->fcode.bf_insns) {
		if (bpf_filter(handle->fcode.bf_insns, bp,
		                packet_len, caplen) == 0)
		{
			/* rejected by filter */
			return 0;
		}
	}

	/* Fill in our own header data */

	if (ioctl(handle->fd, SIOCGSTAMP, &pcap_header.ts) == -1) {
		snprintf(handle->errbuf, sizeof(handle->errbuf),
			 "ioctl: %s", pcap_strerror(errno));
		return -1;
	}
	pcap_header.caplen	= caplen;
	pcap_header.len		= packet_len;

	/*
	 * Count the packet.
	 *
	 * Arguably, we should count them before we check the filter,
	 * as on many other platforms "ps_recv" counts packets
	 * handed to the filter rather than packets that passed
	 * the filter, but if filtering is done in the kernel, we
	 * can't get a count of packets that passed the filter,
	 * and that would mean the meaning of "ps_recv" wouldn't
	 * be the same on all Linux systems.
	 *
	 * XXX - it's not the same on all systems in any case;
	 * ideally, we should have a "get the statistics" call
	 * that supplies more counts and indicates which of them
	 * it supplies, so that we supply a count of packets
	 * handed to the filter only on platforms where that
	 * information is available.
	 *
	 * We count them here even if we can get the packet count
	 * from the kernel, as we can only determine at run time
	 * whether we'll be able to get it from the kernel (if
	 * HAVE_TPACKET_STATS isn't defined, we can't get it from
	 * the kernel, but if it is defined, the library might
	 * have been built with a 2.4 or later kernel, but we
	 * might be running on a 2.2[.x] kernel without Alexey
	 * Kuznetzov's turbopacket patches, and thus the kernel
	 * might not be able to supply those statistics).  We
	 * could, I guess, try, when opening the socket, to get
	 * the statistics, and if we can not increment the count
	 * here, but it's not clear that always incrementing
	 * the count is more expensive than always testing a flag
	 * in memory.
	 */
	handle->md.stat.ps_recv++;

	/* Call the user supplied callback function */
	callback(userdata, &pcap_header, bp);

	return 1;
}

static int
pcap_inject_linux(pcap_t *handle, const void *buf, size_t size)
{
	int ret;

#ifdef HAVE_PF_PACKET_SOCKETS
	if (!handle->md.sock_packet) {
		/* PF_PACKET socket */
		if (handle->md.ifindex == -1) {
			/*
			 * We don't support sending on the "any" device.
			 */
			strlcpy(handle->errbuf,
			    "Sending packets isn't supported on the \"any\" device",
			    PCAP_ERRBUF_SIZE);
			return (-1);
		}

		if (handle->md.cooked) {
			/*
			 * We don't support sending on the "any" device.
			 *
			 * XXX - how do you send on a bound cooked-mode
			 * socket?
			 * Is a "sendto()" required there?
			 */
			strlcpy(handle->errbuf,
			    "Sending packets isn't supported in cooked mode",
			    PCAP_ERRBUF_SIZE);
			return (-1);
		}
	}
#endif

	ret = send(handle->fd, buf, size, 0);
	if (ret == -1) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "send: %s",
		    pcap_strerror(errno));
		return (-1);
	}
	return (ret);
}                           

/*
 *  Get the statistics for the given packet capture handle.
 *  Reports the number of dropped packets iff the kernel supports
 *  the PACKET_STATISTICS "getsockopt()" argument (2.4 and later
 *  kernels, and 2.2[.x] kernels with Alexey Kuznetzov's turbopacket
 *  patches); otherwise, that information isn't available, and we lie
 *  and report 0 as the count of dropped packets.
 */
static int
pcap_stats_linux(pcap_t *handle, struct pcap_stat *stats)
{
#ifdef HAVE_TPACKET_STATS
	struct tpacket_stats kstats;
	socklen_t len = sizeof (struct tpacket_stats);
#endif

#ifdef HAVE_TPACKET_STATS
	/*
	 * Try to get the packet counts from the kernel.
	 */
	if (getsockopt(handle->fd, SOL_PACKET, PACKET_STATISTICS,
			&kstats, &len) > -1) {
		/*
		 * In "linux/net/packet/af_packet.c", at least in the
		 * 2.4.9 kernel, "tp_packets" is incremented for every
		 * packet that passes the packet filter *and* is
		 * successfully queued on the socket; "tp_drops" is
		 * incremented for every packet dropped because there's
		 * not enough free space in the socket buffer.
		 *
		 * When the statistics are returned for a PACKET_STATISTICS
		 * "getsockopt()" call, "tp_drops" is added to "tp_packets",
		 * so that "tp_packets" counts all packets handed to
		 * the PF_PACKET socket, including packets dropped because
		 * there wasn't room on the socket buffer - but not
		 * including packets that didn't pass the filter.
		 *
		 * In the BSD BPF, the count of received packets is
		 * incremented for every packet handed to BPF, regardless
		 * of whether it passed the filter.
		 *
		 * We can't make "pcap_stats()" work the same on both
		 * platforms, but the best approximation is to return
		 * "tp_packets" as the count of packets and "tp_drops"
		 * as the count of drops.
		 *
		 * Keep a running total because each call to 
		 *    getsockopt(handle->fd, SOL_PACKET, PACKET_STATISTICS, ....
		 * resets the counters to zero.
		 */
		handle->md.stat.ps_recv += kstats.tp_packets;
		handle->md.stat.ps_drop += kstats.tp_drops;
	}
	else
	{
		/*
		 * If the error was EOPNOTSUPP, fall through, so that
		 * if you build the library on a system with
		 * "struct tpacket_stats" and run it on a system
		 * that doesn't, it works as it does if the library
		 * is built on a system without "struct tpacket_stats".
		 */
		if (errno != EOPNOTSUPP) {
			snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			    "pcap_stats: %s", pcap_strerror(errno));
			return -1;
		}
	}
#endif
	/*
	 * On systems where the PACKET_STATISTICS "getsockopt()" argument
	 * is supported on PF_PACKET sockets:
	 *
	 *	"ps_recv" counts only packets that *passed* the filter,
	 *	not packets that didn't pass the filter.  This includes
	 *	packets later dropped because we ran out of buffer space.
	 *
	 *	"ps_drop" counts packets dropped because we ran out of
	 *	buffer space.  It doesn't count packets dropped by the
	 *	interface driver.  It counts only packets that passed
	 *	the filter.
	 *
	 *	Both statistics include packets not yet read from the
	 *	kernel by libpcap, and thus not yet seen by the application.
	 *
	 * On systems where the PACKET_STATISTICS "getsockopt()" argument
	 * is not supported on PF_PACKET sockets:
	 *
	 *	"ps_recv" counts only packets that *passed* the filter,
	 *	not packets that didn't pass the filter.  It does not
	 *	count packets dropped because we ran out of buffer
	 *	space.
	 *
	 *	"ps_drop" is not supported.
	 *
	 *	"ps_recv" doesn't include packets not yet read from
	 *	the kernel by libpcap.
	 */
	*stats = handle->md.stat;
	return 0;
}

/*
 * Description string for the "any" device.
 */
static const char any_descr[] = "Pseudo-device that captures on all interfaces";

int
pcap_platform_finddevs(pcap_if_t **alldevsp, char *errbuf)
{
	if (pcap_add_if(alldevsp, "any", 0, any_descr, errbuf) < 0)
		return (-1);

#ifdef HAVE_DAG_API
	if (dag_platform_finddevs(alldevsp, errbuf) < 0)
		return (-1);
#endif /* HAVE_DAG_API */

#ifdef HAVE_SEPTEL_API
	if (septel_platform_finddevs(alldevsp, errbuf) < 0)
		return (-1);
#endif /* HAVE_SEPTEL_API */

	return (0);
}

/*
 *  Attach the given BPF code to the packet capture device.
 */
static int
pcap_setfilter_linux(pcap_t *handle, struct bpf_program *filter)
{
#ifdef SO_ATTACH_FILTER
	struct sock_fprog	fcode;
	int			can_filter_in_kernel;
	int			err = 0;
#endif

	if (!handle)
		return -1;
	if (!filter) {
	        strncpy(handle->errbuf, "setfilter: No filter specified",
			sizeof(handle->errbuf));
		return -1;
	}

	/* Make our private copy of the filter */

	if (install_bpf_program(handle, filter) < 0)
		/* install_bpf_program() filled in errbuf */
		return -1;

	/*
	 * Run user level packet filter by default. Will be overriden if
	 * installing a kernel filter succeeds.
	 */
	handle->md.use_bpf = 0;

	/* Install kernel level filter if possible */

#ifdef SO_ATTACH_FILTER
#ifdef USHRT_MAX
	if (handle->fcode.bf_len > USHRT_MAX) {
		/*
		 * fcode.len is an unsigned short for current kernel.
		 * I have yet to see BPF-Code with that much
		 * instructions but still it is possible. So for the
		 * sake of correctness I added this check.
		 */
		fprintf(stderr, "Warning: Filter too complex for kernel\n");
		fcode.filter = NULL;
		can_filter_in_kernel = 0;
	} else
#endif /* USHRT_MAX */
	{
		/*
		 * Oh joy, the Linux kernel uses struct sock_fprog instead
		 * of struct bpf_program and of course the length field is
		 * of different size. Pointed out by Sebastian
		 *
		 * Oh, and we also need to fix it up so that all "ret"
		 * instructions with non-zero operands have 65535 as the
		 * operand, and so that, if we're in cooked mode, all
		 * memory-reference instructions use special magic offsets
		 * in references to the link-layer header and assume that
		 * the link-layer payload begins at 0; "fix_program()"
		 * will do that.
		 */
		switch (fix_program(handle, &fcode)) {

		case -1:
		default:
			/*
			 * Fatal error; just quit.
			 * (The "default" case shouldn't happen; we
			 * return -1 for that reason.)
			 */
			return -1;

		case 0:
			/*
			 * The program performed checks that we can't make
			 * work in the kernel.
			 */
			can_filter_in_kernel = 0;
			break;

		case 1:
			/*
			 * We have a filter that'll work in the kernel.
			 */
			can_filter_in_kernel = 1;
			break;
		}
	}

	if (can_filter_in_kernel) {
		if ((err = set_kernel_filter(handle, &fcode)) == 0)
		{
			/* Installation succeded - using kernel filter. */
			handle->md.use_bpf = 1;
		}
		else if (err == -1)	/* Non-fatal error */
		{
			/*
			 * Print a warning if we weren't able to install
			 * the filter for a reason other than "this kernel
			 * isn't configured to support socket filters.
			 */
			if (errno != ENOPROTOOPT && errno != EOPNOTSUPP) {
				fprintf(stderr,
				    "Warning: Kernel filter failed: %s\n",
					pcap_strerror(errno));
			}
		}
	}

	/*
	 * If we're not using the kernel filter, get rid of any kernel
	 * filter that might've been there before, e.g. because the
	 * previous filter could work in the kernel, or because some other
	 * code attached a filter to the socket by some means other than
	 * calling "pcap_setfilter()".  Otherwise, the kernel filter may
	 * filter out packets that would pass the new userland filter.
	 */
	if (!handle->md.use_bpf)
		reset_kernel_filter(handle);

	/*
	 * Free up the copy of the filter that was made by "fix_program()".
	 */
	if (fcode.filter != NULL)
		free(fcode.filter);

	if (err == -2)
		/* Fatal error */
		return -1;
#endif /* SO_ATTACH_FILTER */

	return 0;
}

/*
 * Set direction flag: Which packets do we accept on a forwarding
 * single device? IN, OUT or both?
 */
static int
pcap_setdirection_linux(pcap_t *handle, pcap_direction_t d)
{
#ifdef HAVE_PF_PACKET_SOCKETS
	if (!handle->md.sock_packet) {
		handle->direction = d;
		return 0;
	}
#endif
	/*
	 * We're not using PF_PACKET sockets, so we can't determine
	 * the direction of the packet.
	 */
	snprintf(handle->errbuf, sizeof(handle->errbuf),
	    "Setting direction is not supported on SOCK_PACKET sockets");
	return -1;
}

/*
 *  Linux uses the ARP hardware type to identify the type of an
 *  interface. pcap uses the DLT_xxx constants for this. This
 *  function takes a pointer to a "pcap_t", and an ARPHRD_xxx
 *  constant, as arguments, and sets "handle->linktype" to the
 *  appropriate DLT_XXX constant and sets "handle->offset" to
 *  the appropriate value (to make "handle->offset" plus link-layer
 *  header length be a multiple of 4, so that the link-layer payload
 *  will be aligned on a 4-byte boundary when capturing packets).
 *  (If the offset isn't set here, it'll be 0; add code as appropriate
 *  for cases where it shouldn't be 0.)
 *
 *  If "cooked_ok" is non-zero, we can use DLT_LINUX_SLL and capture
 *  in cooked mode; otherwise, we can't use cooked mode, so we have
 *  to pick some type that works in raw mode, or fail.
 *
 *  Sets the link type to -1 if unable to map the type.
 */
static void map_arphrd_to_dlt(pcap_t *handle, int arptype, int cooked_ok)
{
	switch (arptype) {

	case ARPHRD_ETHER:
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
		 * ARPHRD_ETHER but that *shouldn't offer DLT_DOCSIS as
		 * a Cisco CMTS won't put traffic onto it or get traffic
		 * bridged onto it?  ISDN is handled in "live_open_new()",
		 * as we fall back on cooked mode there; are there any
		 * others?
		 */
		handle->dlt_list = (u_int *) malloc(sizeof(u_int) * 2);
		/*
		 * If that fails, just leave the list empty.
		 */
		if (handle->dlt_list != NULL) {
			handle->dlt_list[0] = DLT_EN10MB;
			handle->dlt_list[1] = DLT_DOCSIS;
			handle->dlt_count = 2;
		}
		/* FALLTHROUGH */

	case ARPHRD_METRICOM:
	case ARPHRD_LOOPBACK:
		handle->linktype = DLT_EN10MB;
		handle->offset = 2;
		break;

	case ARPHRD_EETHER:
		handle->linktype = DLT_EN3MB;
		break;

	case ARPHRD_AX25:
		handle->linktype = DLT_AX25;
		break;

	case ARPHRD_PRONET:
		handle->linktype = DLT_PRONET;
		break;

	case ARPHRD_CHAOS:
		handle->linktype = DLT_CHAOS;
		break;

#ifndef ARPHRD_IEEE802_TR
#define ARPHRD_IEEE802_TR 800	/* From Linux 2.4 */
#endif
	case ARPHRD_IEEE802_TR:
	case ARPHRD_IEEE802:
		handle->linktype = DLT_IEEE802;
		handle->offset = 2;
		break;

	case ARPHRD_ARCNET:
		handle->linktype = DLT_ARCNET_LINUX;
		break;

#ifndef ARPHRD_FDDI	/* From Linux 2.2.13 */
#define ARPHRD_FDDI	774
#endif
	case ARPHRD_FDDI:
		handle->linktype = DLT_FDDI;
		handle->offset = 3;
		break;

#ifndef ARPHRD_ATM  /* FIXME: How to #include this? */
#define ARPHRD_ATM 19
#endif
	case ARPHRD_ATM:
		/*
		 * The Classical IP implementation in ATM for Linux
		 * supports both what RFC 1483 calls "LLC Encapsulation",
		 * in which each packet has an LLC header, possibly
		 * with a SNAP header as well, prepended to it, and
		 * what RFC 1483 calls "VC Based Multiplexing", in which
		 * different virtual circuits carry different network
		 * layer protocols, and no header is prepended to packets.
		 *
		 * They both have an ARPHRD_ type of ARPHRD_ATM, so
		 * you can't use the ARPHRD_ type to find out whether
		 * captured packets will have an LLC header, and,
		 * while there's a socket ioctl to *set* the encapsulation
		 * type, there's no ioctl to *get* the encapsulation type.
		 *
		 * This means that
		 *
		 *	programs that dissect Linux Classical IP frames
		 *	would have to check for an LLC header and,
		 *	depending on whether they see one or not, dissect
		 *	the frame as LLC-encapsulated or as raw IP (I
		 *	don't know whether there's any traffic other than
		 *	IP that would show up on the socket, or whether
		 *	there's any support for IPv6 in the Linux
		 *	Classical IP code);
		 *
		 *	filter expressions would have to compile into
		 *	code that checks for an LLC header and does
		 *	the right thing.
		 *
		 * Both of those are a nuisance - and, at least on systems
		 * that support PF_PACKET sockets, we don't have to put
		 * up with those nuisances; instead, we can just capture
		 * in cooked mode.  That's what we'll do, if we can.
		 * Otherwise, we'll just fail.
		 */
		if (cooked_ok)
			handle->linktype = DLT_LINUX_SLL;
		else
			handle->linktype = -1;
		break;

#ifndef ARPHRD_IEEE80211  /* From Linux 2.4.6 */
#define ARPHRD_IEEE80211 801
#endif
	case ARPHRD_IEEE80211:
		handle->linktype = DLT_IEEE802_11;
		break;

#ifndef ARPHRD_IEEE80211_PRISM  /* From Linux 2.4.18 */
#define ARPHRD_IEEE80211_PRISM 802
#endif
	case ARPHRD_IEEE80211_PRISM:
		handle->linktype = DLT_PRISM_HEADER;
		break;

#ifndef ARPHRD_IEEE80211_RADIOTAP /* new */
#define ARPHRD_IEEE80211_RADIOTAP 803
#endif
	case ARPHRD_IEEE80211_RADIOTAP:
		handle->linktype = DLT_IEEE802_11_RADIO;
		break;

	case ARPHRD_PPP:
		/*
		 * Some PPP code in the kernel supplies no link-layer
		 * header whatsoever to PF_PACKET sockets; other PPP
		 * code supplies PPP link-layer headers ("syncppp.c");
		 * some PPP code might supply random link-layer
		 * headers (PPP over ISDN - there's code in Ethereal,
		 * for example, to cope with PPP-over-ISDN captures
		 * with which the Ethereal developers have had to cope,
		 * heuristically trying to determine which of the
		 * oddball link-layer headers particular packets have).
		 *
		 * As such, we just punt, and run all PPP interfaces
		 * in cooked mode, if we can; otherwise, we just treat
		 * it as DLT_RAW, for now - if somebody needs to capture,
		 * on a 2.0[.x] kernel, on PPP devices that supply a
		 * link-layer header, they'll have to add code here to
		 * map to the appropriate DLT_ type (possibly adding a
		 * new DLT_ type, if necessary).
		 */
		if (cooked_ok)
			handle->linktype = DLT_LINUX_SLL;
		else {
			/*
			 * XXX - handle ISDN types here?  We can't fall
			 * back on cooked sockets, so we'd have to
			 * figure out from the device name what type of
			 * link-layer encapsulation it's using, and map
			 * that to an appropriate DLT_ value, meaning
			 * we'd map "isdnN" devices to DLT_RAW (they
			 * supply raw IP packets with no link-layer
			 * header) and "isdY" devices to a new DLT_I4L_IP
			 * type that has only an Ethernet packet type as
			 * a link-layer header.
			 *
			 * But sometimes we seem to get random crap
			 * in the link-layer header when capturing on
			 * ISDN devices....
			 */
			handle->linktype = DLT_RAW;
		}
		break;

#ifndef ARPHRD_CISCO
#define ARPHRD_CISCO 513 /* previously ARPHRD_HDLC */
#endif
	case ARPHRD_CISCO:
		handle->linktype = DLT_C_HDLC;
		break;

	/* Not sure if this is correct for all tunnels, but it
	 * works for CIPE */
	case ARPHRD_TUNNEL:
#ifndef ARPHRD_SIT
#define ARPHRD_SIT 776	/* From Linux 2.2.13 */
#endif
	case ARPHRD_SIT:
	case ARPHRD_CSLIP:
	case ARPHRD_SLIP6:
	case ARPHRD_CSLIP6:
	case ARPHRD_ADAPT:
	case ARPHRD_SLIP:
#ifndef ARPHRD_RAWHDLC
#define ARPHRD_RAWHDLC 518
#endif
	case ARPHRD_RAWHDLC:
#ifndef ARPHRD_DLCI
#define ARPHRD_DLCI 15
#endif
	case ARPHRD_DLCI:
		/*
		 * XXX - should some of those be mapped to DLT_LINUX_SLL
		 * instead?  Should we just map all of them to DLT_LINUX_SLL?
		 */
		handle->linktype = DLT_RAW;
		break;

#ifndef ARPHRD_FRAD
#define ARPHRD_FRAD 770
#endif
	case ARPHRD_FRAD:
		handle->linktype = DLT_FRELAY;
		break;

	case ARPHRD_LOCALTLK:
		handle->linktype = DLT_LTALK;
		break;

#ifndef ARPHRD_FCPP
#define ARPHRD_FCPP	784
#endif
	case ARPHRD_FCPP:
#ifndef ARPHRD_FCAL
#define ARPHRD_FCAL	785
#endif
	case ARPHRD_FCAL:
#ifndef ARPHRD_FCPL
#define ARPHRD_FCPL	786
#endif
	case ARPHRD_FCPL:
#ifndef ARPHRD_FCFABRIC
#define ARPHRD_FCFABRIC	787
#endif
	case ARPHRD_FCFABRIC:
		/*
		 * We assume that those all mean RFC 2625 IP-over-
		 * Fibre Channel, with the RFC 2625 header at
		 * the beginning of the packet.
		 */
		handle->linktype = DLT_IP_OVER_FC;
		break;

#ifndef ARPHRD_IRDA
#define ARPHRD_IRDA	783
#endif
	case ARPHRD_IRDA:
		/* Don't expect IP packet out of this interfaces... */
		handle->linktype = DLT_LINUX_IRDA;
		/* We need to save packet direction for IrDA decoding,
		 * so let's use "Linux-cooked" mode. Jean II */
		//handle->md.cooked = 1;
		break;

	default:
		handle->linktype = -1;
		break;
	}
}

/* ===== Functions to interface to the newer kernels ================== */

/*
 *  Try to open a packet socket using the new kernel interface.
 *  Returns 0 on failure.
 *  FIXME: 0 uses to mean success (Sebastian)
 */
static int
live_open_new(pcap_t *handle, const char *device, int promisc,
	      int to_ms, char *ebuf)
{
#ifdef HAVE_PF_PACKET_SOCKETS
	int			sock_fd = -1, arptype;
	int			err;
	int			fatal_err = 0;
	struct packet_mreq	mr;

	/* One shot loop used for error handling - bail out with break */

	do {
		/*
		 * Open a socket with protocol family packet. If a device is
		 * given we try to open it in raw mode otherwise we use
		 * the cooked interface.
		 */
		sock_fd = device ?
			socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))
		      : socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));

		if (sock_fd == -1) {
			snprintf(ebuf, PCAP_ERRBUF_SIZE, "socket: %s",
				 pcap_strerror(errno) );
			break;
		}

		/* It seems the kernel supports the new interface. */
		handle->md.sock_packet = 0;

		/*
		 * Get the interface index of the loopback device.
		 * If the attempt fails, don't fail, just set the
		 * "md.lo_ifindex" to -1.
		 *
		 * XXX - can there be more than one device that loops
		 * packets back, i.e. devices other than "lo"?  If so,
		 * we'd need to find them all, and have an array of
		 * indices for them, and check all of them in
		 * "pcap_read_packet()".
		 */
		handle->md.lo_ifindex = iface_get_id(sock_fd, "lo", ebuf);

		/*
		 * Default value for offset to align link-layer payload
		 * on a 4-byte boundary.
		 */
		handle->offset	 = 0;

		/*
		 * What kind of frames do we have to deal with? Fall back
		 * to cooked mode if we have an unknown interface type.
		 */

		if (device) {
			/* Assume for now we don't need cooked mode. */
			handle->md.cooked = 0;

			arptype	= iface_get_arptype(sock_fd, device, ebuf);
			if (arptype == -1) {
				fatal_err = 1;
				break;
			}
			map_arphrd_to_dlt(handle, arptype, 1);
			if (handle->linktype == -1 ||
			    handle->linktype == DLT_LINUX_SLL ||
			    handle->linktype == DLT_LINUX_IRDA ||
			    (handle->linktype == DLT_EN10MB &&
			     (strncmp("isdn", device, 4) == 0 ||
			      strncmp("isdY", device, 4) == 0))) {
				/*
				 * Unknown interface type (-1), or a
				 * device we explicitly chose to run
				 * in cooked mode (e.g., PPP devices),
				 * or an ISDN device (whose link-layer
				 * type we can only determine by using
				 * APIs that may be different on different
				 * kernels) - reopen in cooked mode.
				 */
				if (close(sock_fd) == -1) {
					snprintf(ebuf, PCAP_ERRBUF_SIZE,
						 "close: %s", pcap_strerror(errno));
					break;
				}
				sock_fd = socket(PF_PACKET, SOCK_DGRAM,
						 htons(ETH_P_ALL));
				if (sock_fd == -1) {
					snprintf(ebuf, PCAP_ERRBUF_SIZE,
						 "socket: %s", pcap_strerror(errno));
					break;
				}
				handle->md.cooked = 1;

				/*
				 * Get rid of any link-layer type list
				 * we allocated - this only supports cooked
				 * capture.
				 */
				if (handle->dlt_list != NULL) {
					free(handle->dlt_list);
					handle->dlt_list = NULL;
					handle->dlt_count = 0;
				}

				if (handle->linktype == -1) {
					/*
					 * Warn that we're falling back on
					 * cooked mode; we may want to
					 * update "map_arphrd_to_dlt()"
					 * to handle the new type.
					 */
					snprintf(ebuf, PCAP_ERRBUF_SIZE,
						"arptype %d not "
						"supported by libpcap - "
						"falling back to cooked "
						"socket",
						arptype);
				}
				/* IrDA capture is not a real "cooked" capture,
				 * it's IrLAP frames, not IP packets. */
				if (handle->linktype != DLT_LINUX_IRDA)
					handle->linktype = DLT_LINUX_SLL;
			}

			handle->md.ifindex = iface_get_id(sock_fd, device, ebuf);
			if (handle->md.ifindex == -1)
				break;

			if ((err = iface_bind(sock_fd, handle->md.ifindex,
			    ebuf)) < 0) {
				if (err == -2)
					fatal_err = 1;
				break;
			}
		} else {
			/*
			 * This is cooked mode.
			 */
			handle->md.cooked = 1;
			handle->linktype = DLT_LINUX_SLL;

			/*
			 * We're not bound to a device.
			 * XXX - true?  Or true only if we're using
			 * the "any" device?
			 * For now, we're using this as an indication
			 * that we can't transmit; stop doing that only
			 * if we figure out how to transmit in cooked
			 * mode.
			 */
			handle->md.ifindex = -1;
		}

		/*
		 * Select promiscuous mode on if "promisc" is set.
		 *
		 * Do not turn allmulti mode on if we don't select
		 * promiscuous mode - on some devices (e.g., Orinoco
		 * wireless interfaces), allmulti mode isn't supported
		 * and the driver implements it by turning promiscuous
		 * mode on, and that screws up the operation of the
		 * card as a normal networking interface, and on no
		 * other platform I know of does starting a non-
		 * promiscuous capture affect which multicast packets
		 * are received by the interface.
		 */

		/*
		 * Hmm, how can we set promiscuous mode on all interfaces?
		 * I am not sure if that is possible at all.
		 */

		if (device && promisc) {
			memset(&mr, 0, sizeof(mr));
			mr.mr_ifindex = handle->md.ifindex;
			mr.mr_type    = PACKET_MR_PROMISC;
			if (setsockopt(sock_fd, SOL_PACKET,
				PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) == -1)
			{
				snprintf(ebuf, PCAP_ERRBUF_SIZE,
					"setsockopt: %s", pcap_strerror(errno));
				break;
			}
		}

		/* Save the socket FD in the pcap structure */

		handle->fd 	 = sock_fd;

		return 1;

	} while(0);

	if (sock_fd != -1)
		close(sock_fd);

	if (fatal_err) {
		/*
		 * Get rid of any link-layer type list we allocated.
		 */
		if (handle->dlt_list != NULL)
			free(handle->dlt_list);
		return -2;
	} else
		return 0;
#else
	strncpy(ebuf,
		"New packet capturing interface not supported by build "
		"environment", PCAP_ERRBUF_SIZE);
	return 0;
#endif
}

#ifdef HAVE_PF_PACKET_SOCKETS
/*
 *  Return the index of the given device name. Fill ebuf and return
 *  -1 on failure.
 */
static int
iface_get_id(int fd, const char *device, char *ebuf)
{
	struct ifreq	ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

	if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE,
			 "ioctl: %s", pcap_strerror(errno));
		return -1;
	}

	return ifr.ifr_ifindex;
}

/*
 *  Bind the socket associated with FD to the given device.
 */
static int
iface_bind(int fd, int ifindex, char *ebuf)
{
	struct sockaddr_ll	sll;
	int			err;
	socklen_t		errlen = sizeof(err);

	memset(&sll, 0, sizeof(sll));
	sll.sll_family		= AF_PACKET;
	sll.sll_ifindex		= ifindex;
	sll.sll_protocol	= htons(ETH_P_ALL);

	if (bind(fd, (struct sockaddr *) &sll, sizeof(sll)) == -1) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE,
			 "bind: %s", pcap_strerror(errno));
		return -1;
	}

	/* Any pending errors, e.g., network is down? */

	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) == -1) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE,
			"getsockopt: %s", pcap_strerror(errno));
		return -2;
	}

	if (err > 0) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE,
			"bind: %s", pcap_strerror(err));
		return -2;
	}

	return 0;
}

#endif


/* ===== Functions to interface to the older kernels ================== */

/*
 * With older kernels promiscuous mode is kind of interesting because we
 * have to reset the interface before exiting. The problem can't really
 * be solved without some daemon taking care of managing usage counts.
 * If we put the interface into promiscuous mode, we set a flag indicating
 * that we must take it out of that mode when the interface is closed,
 * and, when closing the interface, if that flag is set we take it out
 * of promiscuous mode.
 */

/*
 * List of pcaps for which we turned promiscuous mode on by hand.
 * If there are any such pcaps, we arrange to call "pcap_close_all()"
 * when we exit, and have it close all of them to turn promiscuous mode
 * off.
 */
static struct pcap *pcaps_to_close;

/*
 * TRUE if we've already called "atexit()" to cause "pcap_close_all()" to
 * be called on exit.
 */
static int did_atexit;

static void	pcap_close_all(void)
{
	struct pcap *handle;

	while ((handle = pcaps_to_close) != NULL)
		pcap_close(handle);
}

static void	pcap_close_linux( pcap_t *handle )
{
	struct pcap	*p, *prevp;
	struct ifreq	ifr;

	if (handle->md.clear_promisc) {
		/*
		 * We put the interface into promiscuous mode; take
		 * it out of promiscuous mode.
		 *
		 * XXX - if somebody else wants it in promiscuous mode,
		 * this code cannot know that, so it'll take it out
		 * of promiscuous mode.  That's not fixable in 2.0[.x]
		 * kernels.
		 */
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, handle->md.device, sizeof(ifr.ifr_name));
		if (ioctl(handle->fd, SIOCGIFFLAGS, &ifr) == -1) {
			fprintf(stderr,
			    "Can't restore interface flags (SIOCGIFFLAGS failed: %s).\n"
			    "Please adjust manually.\n"
			    "Hint: This can't happen with Linux >= 2.2.0.\n",
			    strerror(errno));
		} else {
			if (ifr.ifr_flags & IFF_PROMISC) {
				/*
				 * Promiscuous mode is currently on; turn it
				 * off.
				 */
				ifr.ifr_flags &= ~IFF_PROMISC;
				if (ioctl(handle->fd, SIOCSIFFLAGS, &ifr) == -1) {
					fprintf(stderr,
					    "Can't restore interface flags (SIOCSIFFLAGS failed: %s).\n"
					    "Please adjust manually.\n"
					    "Hint: This can't happen with Linux >= 2.2.0.\n",
					    strerror(errno));
				}
			}
		}

		/*
		 * Take this pcap out of the list of pcaps for which we
		 * have to take the interface out of promiscuous mode.
		 */
		for (p = pcaps_to_close, prevp = NULL; p != NULL;
		    prevp = p, p = p->md.next) {
			if (p == handle) {
				/*
				 * Found it.  Remove it from the list.
				 */
				if (prevp == NULL) {
					/*
					 * It was at the head of the list.
					 */
					pcaps_to_close = p->md.next;
				} else {
					/*
					 * It was in the middle of the list.
					 */
					prevp->md.next = p->md.next;
				}
				break;
			}
		}
	}

	if (handle->md.device != NULL)
		free(handle->md.device);
	handle->md.device = NULL;
	pcap_close_common(handle);
}

/*
 *  Try to open a packet socket using the old kernel interface.
 *  Returns 0 on failure.
 *  FIXME: 0 uses to mean success (Sebastian)
 */
static int
live_open_old(pcap_t *handle, const char *device, int promisc,
	      int to_ms, char *ebuf)
{
	int		arptype;
	struct ifreq	ifr;

	do {
		/* Open the socket */

		handle->fd = socket(PF_INET, SOCK_PACKET, htons(ETH_P_ALL));
		if (handle->fd == -1) {
			snprintf(ebuf, PCAP_ERRBUF_SIZE,
				 "socket: %s", pcap_strerror(errno));
			break;
		}

		/* It worked - we are using the old interface */
		handle->md.sock_packet = 1;

		/* ...which means we get the link-layer header. */
		handle->md.cooked = 0;

		/* Bind to the given device */

		if (!device) {
		        strncpy(ebuf, "pcap_open_live: The \"any\" device isn't supported on 2.0[.x]-kernel systems",
				PCAP_ERRBUF_SIZE);
			break;
		}
		if (iface_bind_old(handle->fd, device, ebuf) == -1)
			break;

		/*
		 * Try to get the link-layer type.
		 */
		arptype = iface_get_arptype(handle->fd, device, ebuf);
		if (arptype == -1)
			break;

		/*
		 * Try to find the DLT_ type corresponding to that
		 * link-layer type.
		 */
		map_arphrd_to_dlt(handle, arptype, 0);
		if (handle->linktype == -1) {
			snprintf(ebuf, PCAP_ERRBUF_SIZE,
				 "unknown arptype %d", arptype);
			break;
		}

		/* Go to promisc mode if requested */

		if (promisc) {
			memset(&ifr, 0, sizeof(ifr));
			strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
			if (ioctl(handle->fd, SIOCGIFFLAGS, &ifr) == -1) {
				snprintf(ebuf, PCAP_ERRBUF_SIZE,
					 "ioctl: %s", pcap_strerror(errno));
				break;
			}
			if ((ifr.ifr_flags & IFF_PROMISC) == 0) {
				/*
				 * Promiscuous mode isn't currently on,
				 * so turn it on, and remember that
				 * we should turn it off when the
				 * pcap_t is closed.
				 */

				/*
				 * If we haven't already done so, arrange
				 * to have "pcap_close_all()" called when
				 * we exit.
				 */
				if (!did_atexit) {
					if (atexit(pcap_close_all) == -1) {
						/*
						 * "atexit()" failed; don't
						 * put the interface in
						 * promiscuous mode, just
						 * give up.
						 */
						strncpy(ebuf, "atexit failed",
							PCAP_ERRBUF_SIZE);
						break;
					}
					did_atexit = 1;
				}

				ifr.ifr_flags |= IFF_PROMISC;
				if (ioctl(handle->fd, SIOCSIFFLAGS, &ifr) == -1) {
				        snprintf(ebuf, PCAP_ERRBUF_SIZE,
						 "ioctl: %s",
						 pcap_strerror(errno));
					break;
				}
				handle->md.clear_promisc = 1;

				/*
				 * Add this to the list of pcaps
				 * to close when we exit.
				 */
				handle->md.next = pcaps_to_close;
				pcaps_to_close = handle;
			}
		}

		/*
		 * Default value for offset to align link-layer payload
		 * on a 4-byte boundary.
		 */
		handle->offset	 = 0;

		return 1;

	} while (0);

	pcap_close_linux(handle);
	return 0;
}

/*
 *  Bind the socket associated with FD to the given device using the
 *  interface of the old kernels.
 */
static int
iface_bind_old(int fd, const char *device, char *ebuf)
{
	struct sockaddr	saddr;
	int		err;
	socklen_t	errlen = sizeof(err);

	memset(&saddr, 0, sizeof(saddr));
	strncpy(saddr.sa_data, device, sizeof(saddr.sa_data));
	if (bind(fd, &saddr, sizeof(saddr)) == -1) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE,
			 "bind: %s", pcap_strerror(errno));
		return -1;
	}

	/* Any pending errors, e.g., network is down? */

	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) == -1) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE,
			"getsockopt: %s", pcap_strerror(errno));
		return -1;
	}

	if (err > 0) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE,
			"bind: %s", pcap_strerror(err));
		return -1;
	}

	return 0;
}


/* ===== System calls available on all supported kernels ============== */

/*
 *  Query the kernel for the MTU of the given interface.
 */
static int
iface_get_mtu(int fd, const char *device, char *ebuf)
{
	struct ifreq	ifr;

	if (!device)
		return BIGGER_THAN_ALL_MTUS;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

	if (ioctl(fd, SIOCGIFMTU, &ifr) == -1) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE,
			 "ioctl: %s", pcap_strerror(errno));
		return -1;
	}

	return ifr.ifr_mtu;
}

/*
 *  Get the hardware type of the given interface as ARPHRD_xxx constant.
 */
static int
iface_get_arptype(int fd, const char *device, char *ebuf)
{
	struct ifreq	ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE,
			 "ioctl: %s", pcap_strerror(errno));
		return -1;
	}

	return ifr.ifr_hwaddr.sa_family;
}

#ifdef SO_ATTACH_FILTER
static int
fix_program(pcap_t *handle, struct sock_fprog *fcode)
{
	size_t prog_size;
	register int i;
	register struct bpf_insn *p;
	struct bpf_insn *f;
	int len;

	/*
	 * Make a copy of the filter, and modify that copy if
	 * necessary.
	 */
	prog_size = sizeof(*handle->fcode.bf_insns) * handle->fcode.bf_len;
	len = handle->fcode.bf_len;
	f = (struct bpf_insn *)malloc(prog_size);
	if (f == NULL) {
		snprintf(handle->errbuf, sizeof(handle->errbuf),
			 "malloc: %s", pcap_strerror(errno));
		return -1;
	}
	memcpy(f, handle->fcode.bf_insns, prog_size);
	fcode->len = len;
	fcode->filter = (struct sock_filter *) f;

	for (i = 0; i < len; ++i) {
		p = &f[i];
		/*
		 * What type of instruction is this?
		 */
		switch (BPF_CLASS(p->code)) {

		case BPF_RET:
			/*
			 * It's a return instruction; is the snapshot
			 * length a constant, rather than the contents
			 * of the accumulator?
			 */
			if (BPF_MODE(p->code) == BPF_K) {
				/*
				 * Yes - if the value to be returned,
				 * i.e. the snapshot length, is anything
				 * other than 0, make it 65535, so that
				 * the packet is truncated by "recvfrom()",
				 * not by the filter.
				 *
				 * XXX - there's nothing we can easily do
				 * if it's getting the value from the
				 * accumulator; we'd have to insert
				 * code to force non-zero values to be
				 * 65535.
				 */
				if (p->k != 0)
					p->k = 65535;
			}
			break;

		case BPF_LD:
		case BPF_LDX:
			/*
			 * It's a load instruction; is it loading
			 * from the packet?
			 */
			switch (BPF_MODE(p->code)) {

			case BPF_ABS:
			case BPF_IND:
			case BPF_MSH:
				/*
				 * Yes; are we in cooked mode?
				 */
				if (handle->md.cooked) {
					/*
					 * Yes, so we need to fix this
					 * instruction.
					 */
					if (fix_offset(p) < 0) {
						/*
						 * We failed to do so.
						 * Return 0, so our caller
						 * knows to punt to userland.
						 */
						return 0;
					}
				}
				break;
			}
			break;
		}
	}
	return 1;	/* we succeeded */
}

static int
fix_offset(struct bpf_insn *p)
{
	/*
	 * What's the offset?
	 */
	if (p->k >= SLL_HDR_LEN) {
		/*
		 * It's within the link-layer payload; that starts at an
		 * offset of 0, as far as the kernel packet filter is
		 * concerned, so subtract the length of the link-layer
		 * header.
		 */
		p->k -= SLL_HDR_LEN;
	} else if (p->k == 14) {
		/*
		 * It's the protocol field; map it to the special magic
		 * kernel offset for that field.
		 */
		p->k = SKF_AD_OFF + SKF_AD_PROTOCOL;
	} else {
		/*
		 * It's within the header, but it's not one of those
		 * fields; we can't do that in the kernel, so punt
		 * to userland.
		 */
		return -1;
	}
	return 0;
}

static int
set_kernel_filter(pcap_t *handle, struct sock_fprog *fcode)
{
	int total_filter_on = 0;
	int save_mode;
	int ret;
	int save_errno;

	/*
	 * The socket filter code doesn't discard all packets queued
	 * up on the socket when the filter is changed; this means
	 * that packets that don't match the new filter may show up
	 * after the new filter is put onto the socket, if those
	 * packets haven't yet been read.
	 *
	 * This means, for example, that if you do a tcpdump capture
	 * with a filter, the first few packets in the capture might
	 * be packets that wouldn't have passed the filter.
	 *
	 * We therefore discard all packets queued up on the socket
	 * when setting a kernel filter.  (This isn't an issue for
	 * userland filters, as the userland filtering is done after
	 * packets are queued up.)
	 *
	 * To flush those packets, we put the socket in read-only mode,
	 * and read packets from the socket until there are no more to
	 * read.
	 *
	 * In order to keep that from being an infinite loop - i.e.,
	 * to keep more packets from arriving while we're draining
	 * the queue - we put the "total filter", which is a filter
	 * that rejects all packets, onto the socket before draining
	 * the queue.
	 *
	 * This code deliberately ignores any errors, so that you may
	 * get bogus packets if an error occurs, rather than having
	 * the filtering done in userland even if it could have been
	 * done in the kernel.
	 */
	if (setsockopt(handle->fd, SOL_SOCKET, SO_ATTACH_FILTER,
		       &total_fcode, sizeof(total_fcode)) == 0) {
		char drain[1];

		/*
		 * Note that we've put the total filter onto the socket.
		 */
		total_filter_on = 1;

		/*
		 * Save the socket's current mode, and put it in
		 * non-blocking mode; we drain it by reading packets
		 * until we get an error (which is normally a
		 * "nothing more to be read" error).
		 */
		save_mode = fcntl(handle->fd, F_GETFL, 0);
		if (save_mode != -1 &&
		    fcntl(handle->fd, F_SETFL, save_mode | O_NONBLOCK) >= 0) {
			while (recv(handle->fd, &drain, sizeof drain,
			       MSG_TRUNC) >= 0)
				;
			save_errno = errno;
			fcntl(handle->fd, F_SETFL, save_mode);
			if (save_errno != EAGAIN) {
				/* Fatal error */
				reset_kernel_filter(handle);
				snprintf(handle->errbuf, sizeof(handle->errbuf),
				 "recv: %s", pcap_strerror(save_errno));
				return -2;
			}
		}
	}

	/*
	 * Now attach the new filter.
	 */
	ret = setsockopt(handle->fd, SOL_SOCKET, SO_ATTACH_FILTER,
			 fcode, sizeof(*fcode));
	if (ret == -1 && total_filter_on) {
		/*
		 * Well, we couldn't set that filter on the socket,
		 * but we could set the total filter on the socket.
		 *
		 * This could, for example, mean that the filter was
		 * too big to put into the kernel, so we'll have to
		 * filter in userland; in any case, we'll be doing
		 * filtering in userland, so we need to remove the
		 * total filter so we see packets.
		 */
		save_errno = errno;

		/*
		 * XXX - if this fails, we're really screwed;
		 * we have the total filter on the socket,
		 * and it won't come off.  What do we do then?
		 */
		reset_kernel_filter(handle);

		errno = save_errno;
	}
	return ret;
}

static int
reset_kernel_filter(pcap_t *handle)
{
	/* setsockopt() barfs unless it get a dummy parameter */
	int dummy;

	return setsockopt(handle->fd, SOL_SOCKET, SO_DETACH_FILTER,
				   &dummy, sizeof(dummy));
}
#endif
