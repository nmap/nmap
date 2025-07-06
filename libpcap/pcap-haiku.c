/*
 * Copyright 2006-2010, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 *
 * Authors:
 *		Axel Dörfler, axeld@pinc-software.de
 *		James Woodcock
 */


#include <config.h>
#include "pcap-int.h"

#include <OS.h>

#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/utsname.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_media.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>


// IFT_TUN was renamed to IFT_TUNNEL in the master branch after R1/beta4 (the
// integer value didn't change).  Even though IFT_TUN is a no-op in versions
// that define it, for the time being it is desirable to support compiling
// libpcap on versions with the old macro and using it on later versions that
// support tunnel interfaces.
#ifndef IFT_TUNNEL
#define IFT_TUNNEL IFT_TUN
#endif

/*
 * Private data for capturing on Haiku sockets.
 */
struct pcap_haiku {
	struct pcap_stat	stat;
	int aux_socket;
	struct ifreq ifreq;
	// The original state of the promiscuous mode at the activation time,
	// if the capture should be run in promiscuous mode.
	int orig_promisc;
};


static int
pcap_read_haiku(pcap_t* handle, int maxPackets _U_, pcap_handler callback,
	u_char* userdata)
{
	// Receive a single packet

	u_char* buffer = (u_char*)handle->buffer;
	ssize_t bytesReceived;
	do {
		if (handle->break_loop) {
			handle->break_loop = 0;
			return PCAP_ERROR_BREAK;
		}
		bytesReceived = recvfrom(handle->fd, buffer, handle->bufsize, MSG_TRUNC,
		                         NULL, NULL);
	} while (bytesReceived < 0 && errno == B_INTERRUPTED);

	// The kernel does not implement timestamping of network packets, so
	// doing it ASAP in userland is the best that can be done.
	bigtime_t ts = real_time_clock_usecs();

	if (bytesReceived < 0) {
		if (errno == B_WOULD_BLOCK) {
			// there is no packet for us
			return 0;
		}

		pcapint_fmt_errmsg_for_errno(handle->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "recvfrom");
		return PCAP_ERROR;
	}

	struct pcap_haiku* handlep = (struct pcap_haiku*)handle->priv;
	// BPF is 32-bit, which is more than sufficient for any realistic
	// packet size.
	if (bytesReceived > UINT32_MAX)
		goto drop;
	// At this point, if the recvfrom() call populated its struct sockaddr
	// and socklen_t arguments, it would be the right time to drop packets
	// that have .sa_family not valid for the current DLT.  But in the
	// current master branch (hrev57588) this would erroneously drop some
	// valid packets: recvfrom(), at least for tap mode tunnels, sets the
	// address length to 0 for all incoming packets and sets .sa_len and
	// .sa_family to 0 for packets that are broadcast or multicast.  So it
	// cannot be done yet, if there is a good reason to do it in the first
	// place.
	handlep->stat.ps_recv++;

	bpf_u_int32 wireLength = (bpf_u_int32)bytesReceived;
	// As long as the buffer is large enough, the captured length is equal
	// to the wire length, but let's get the lengths right anyway in case
	// packets grow bigger or the buffer grows smaller in future and the
	// MSG_TRUNC effect kicks in.
	bpf_u_int32 captureLength =
		wireLength <= handle->bufsize ? wireLength : handle->bufsize;

	// run the packet filter
	if (handle->fcode.bf_insns) {
		// NB: pcapint_filter() takes the wire length and the captured
		// length, not the snapshot length of the pcap_t handle.
		if (pcapint_filter(handle->fcode.bf_insns, buffer, wireLength,
		                   captureLength) == 0)
			goto drop;
	}

	// fill in pcap_header
	struct pcap_pkthdr header;
	header.caplen = captureLength <= (bpf_u_int32)handle->snapshot ?
	                captureLength :
	                (bpf_u_int32)handle->snapshot;
	header.len = wireLength;
	header.ts.tv_usec = ts % 1000000;
	header.ts.tv_sec = ts / 1000000;

	/* Call the user supplied callback function */
	callback(userdata, &header, buffer);
	return 1;
drop:
	handlep->stat.ps_drop++;
	return 0;
}


static int
dgram_socket(const int af, char *errbuf)
{
	int ret = socket(af, SOCK_DGRAM, 0);
	if (ret < 0) {
		pcapint_fmt_errmsg_for_errno(errbuf, PCAP_ERRBUF_SIZE, errno,
		    "socket");
		return PCAP_ERROR;
	}
	return ret;
}


static int
ioctl_ifreq(const int fd, const unsigned long op, const char *name,
             struct ifreq *ifreq, char *errbuf)
{
	if (ioctl(fd, op, ifreq, sizeof(struct ifreq)) < 0) {
		pcapint_fmt_errmsg_for_errno(errbuf, PCAP_ERRBUF_SIZE, errno,
		    "%s", name);
		return PCAP_ERROR;
	}
	return 0;
}


static int
get_promisc(pcap_t *handle)
{
	struct pcap_haiku *handlep = (struct pcap_haiku *)handle->priv;
	// SIOCGIFFLAGS would work fine for AF_LINK too.
	if (ioctl_ifreq(handlep->aux_socket, SIOCGIFFLAGS, "SIOCGIFFLAGS",
	                &handlep->ifreq, handle->errbuf) < 0)
		return PCAP_ERROR;
	return (handlep->ifreq.ifr_flags & IFF_PROMISC) != 0;
}


static int
set_promisc(pcap_t *handle, const int enable)
{
	struct pcap_haiku *handlep = (struct pcap_haiku *)handle->priv;
	if (enable)
		handlep->ifreq.ifr_flags |= IFF_PROMISC;
	else
		handlep->ifreq.ifr_flags &= ~IFF_PROMISC;
	// SIOCSIFFLAGS works for AF_INET, but not for AF_LINK.
	return ioctl_ifreq(handlep->aux_socket, SIOCSIFFLAGS, "SIOCSIFFLAGS",
	                   &handlep->ifreq, handle->errbuf);
}


static void
pcap_cleanup_haiku(pcap_t *handle)
{
	struct pcap_haiku *handlep = (struct pcap_haiku *)handle->priv;
	if (handlep->aux_socket >= 0) {
		// Closing the sockets has no effect on IFF_PROMISC, hence the
		// need to restore the original state on one hand and the
		// possibility of clash with other processes managing the same
		// interface flag.  Unset promiscuous mode iff the activation
		// function had set it and it is still set now.
		if (handle->opt.promisc && ! handlep->orig_promisc &&
		    get_promisc(handle))
			(void)set_promisc(handle, 0);
		close(handlep->aux_socket);
		handlep->aux_socket = -1;
	}
	pcapint_cleanup_live_common(handle);
}


static int
pcap_inject_haiku(pcap_t *handle, const void *buffer _U_, int size _U_)
{
	// Haiku currently (hrev57588) does not support sending raw packets.
	// https://dev.haiku-os.org/ticket/18810
	strlcpy(handle->errbuf, "Sending packets isn't supported yet",
		PCAP_ERRBUF_SIZE);
	return PCAP_ERROR;
}


static int
pcap_stats_haiku(pcap_t *handle, struct pcap_stat *stats)
{
	struct pcap_haiku* handlep = (struct pcap_haiku*)handle->priv;
	*stats = handlep->stat;
	// Now ps_recv and ps_drop are accurate, but ps_ifdrop still equals to
	// the snapshot value from the activation time.
	if (ioctl_ifreq(handlep->aux_socket, SIOCGIFSTATS, "SIOCGIFSTATS",
	                &handlep->ifreq, handle->errbuf) < 0)
		return PCAP_ERROR;
	// The result is subject to wrapping around the 32-bit integer space,
	// but that cannot be significantly improved as long as it has to fit
	// into a 32-bit member of pcap_stats.
	stats->ps_ifdrop = handlep->ifreq.ifr_stats.receive.dropped - stats->ps_ifdrop;
	return 0;
}


static int
pcap_activate_haiku(pcap_t *handle)
{
	struct pcap_haiku *handlep = (struct pcap_haiku *)handle->priv;
	int ret = PCAP_ERROR;

	// we need a socket to talk to the networking stack
	if ((handlep->aux_socket = dgram_socket(AF_INET, handle->errbuf)) < 0)
		goto error;

	// pcap_stats_haiku() will need a baseline for ps_ifdrop.
	// At the time of this writing SIOCGIFSTATS returns EINVAL for AF_LINK
	// sockets.
	if (ioctl_ifreq(handlep->aux_socket, SIOCGIFSTATS, "SIOCGIFSTATS",
	                &handlep->ifreq, handle->errbuf) < 0) {
		// Detect a non-existent network interface at least at the
		// first ioctl() use.
		if (errno == EINVAL)
			ret = PCAP_ERROR_NO_SUCH_DEVICE;
		goto error;
	}
	handlep->stat.ps_ifdrop = handlep->ifreq.ifr_stats.receive.dropped;

	// get link level interface for this interface
	if ((handle->fd = dgram_socket(AF_LINK, handle->errbuf)) < 0)
		goto error;

	// Derive a DLT from the interface type.
	// At the time of this writing SIOCGIFTYPE cannot be used for this
	// purpose: it returns EINVAL for AF_LINK sockets and sets ifr_type to
	// 0 for AF_INET sockets.  Use the same method as Haiku ifconfig does
	// (SIOCGIFADDR and AF_LINK).
	if (ioctl_ifreq(handle->fd, SIOCGIFADDR, "SIOCGIFADDR",
	                &handlep->ifreq, handle->errbuf) < 0)
		goto error;
	struct sockaddr_dl *sdl = (struct sockaddr_dl *)&handlep->ifreq.ifr_addr;
	if (sdl->sdl_family != AF_LINK) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
		         "Got AF %d instead of AF_LINK for interface \"%s\".",
		         sdl->sdl_family, handle->opt.device);
		goto error;
	}
	switch (sdl->sdl_type) {
	case IFT_ETHER:
		// Ethernet on all versions, also tap (L2) mode tunnels on
		// versions after R1/beta4.
		handle->linktype = DLT_EN10MB;
		break;
	case IFT_TUNNEL:
		// Unused on R1/beta4 and earlier versions, tun (L3) mode
		// tunnels on later versions.
	case IFT_LOOP:
		// The loopback interface on all versions.
		// Both IFT_TUNNEL and IFT_LOOP prepended a dummy Ethernet
		// header until hrev57585: https://dev.haiku-os.org/ticket/18801
		handle->linktype = DLT_RAW;
		break;
	default:
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
		         "Unknown interface type 0x%0x for interface \"%s\".",
		         sdl->sdl_type, handle->opt.device);
		goto error;
	}

	// start monitoring
	if (ioctl_ifreq(handle->fd, SIOCSPACKETCAP, "SIOCSPACKETCAP",
	                &handlep->ifreq, handle->errbuf) < 0)
		goto error;

	handle->selectable_fd = handle->fd;
	handle->read_op = pcap_read_haiku;
	handle->setfilter_op = pcapint_install_bpf_program; /* no kernel filtering */
	handle->inject_op = pcap_inject_haiku;
	handle->stats_op = pcap_stats_haiku;
	handle->cleanup_op = pcap_cleanup_haiku;

	// use default hooks where possible
	handle->getnonblock_op = pcapint_getnonblock_fd;
	handle->setnonblock_op = pcapint_setnonblock_fd;

	/*
	 * Turn a negative snapshot value (invalid), a snapshot value of
	 * 0 (unspecified), or a value bigger than the normal maximum
	 * value, into the maximum allowed value.
	 *
	 * If some application really *needs* a bigger snapshot
	 * length, we should just increase MAXIMUM_SNAPLEN.
	 */
	if (handle->snapshot <= 0 || handle->snapshot > MAXIMUM_SNAPLEN)
		handle->snapshot = MAXIMUM_SNAPLEN;

	// Although it would be trivial to size the buffer at the kernel end of
	// the capture socket using setsockopt() and SO_RCVBUF, there seems to
	// be no point in doing so: setting the size low silently drops some
	// packets in the kernel, setting it high does not result in a visible
	// improvement.  Let's leave this buffer as it is until it is clear why
	// it would need resizing.  Meanwhile pcap_set_buffer_size() will have
	// no effect on Haiku.

	// It would be wrong to size the buffer at the libpcap end of the
	// capture socket to the interface MTU, which limits only outgoing
	// packets and only at layer 3.  For example, an Ethernet interface
	// with ifconfig/ioctl() MTU set to 1500 ordinarily sends layer 2
	// packets as large as 1514 bytes and receives layer 2 packets as large
	// as the NIC and the driver happen to accept (e.g. 9018 bytes for
	// ipro1000).  This way, valid packets larger than the MTU can occur in
	// a capture and will arrive truncated to pcap_read_haiku() if the
	// buffer is not large enough.  So let's keep it large enough for most
	// if not all practical use cases, then pcap_read_haiku() can handle
	// the unlikely truncation as and if necessary.
	handle->bufsize = 65536;

	// allocate buffer for monitoring the device
	handle->buffer = (u_char*)malloc(handle->bufsize);
	if (handle->buffer == NULL) {
		pcapint_fmt_errmsg_for_errno(handle->errbuf, PCAP_ERRBUF_SIZE,
			errno, "buffer malloc");
		goto error;
	}

	if (handle->opt.promisc) {
		// Set promiscuous mode iff required, in any case remember the
		// original state.
		if ((handlep->orig_promisc = get_promisc(handle)) < 0)
			goto error;
		if (! handlep->orig_promisc && set_promisc(handle, 1) < 0)
			return PCAP_WARNING_PROMISC_NOTSUP;
	}
	return 0;
error:
	pcap_cleanup_haiku(handle);
	return ret;
}


static int
validate_ifname(const char *device, char *errbuf)
{
	if (strlen(device) >= IF_NAMESIZE) {
		snprintf(errbuf, PCAP_ERRBUF_SIZE,
		         "Interface name \"%s\" is too long.", device);
		return PCAP_ERROR;
	}
	return 0;
}


//	#pragma mark - pcap API


static int
can_be_bound(const char *name)
{
	if (strcmp(name, "loop") != 0)
		return 1;

	// In Haiku versions before hrev57010 the loopback interface allows to
	// start a capture, but the capture never receives any packets.
	//
	// Since compiling libpcap on one Haiku version and using the binary on
	// another seems to be commonplace, comparing B_HAIKU_VERSION at the
	// compile time would not always work as intended.  Let's at least
	// remove unsuitable well-known 64-bit versions (with or without
	// updates) from the problem space at run time.
	const char *badversions[] = {
		"hrev56578", // R1/beta4
		"hrev55182", // R1/beta3
		"hrev54154", // R1/beta2
		"hrev52295", // R1/beta1
		"hrev44702", // R1/alpha4
		NULL
	};
	struct utsname uts;
	(void)uname(&uts);
	for (const char **s = badversions; *s; s++)
		if (! strncmp(uts.version, *s, strlen(*s)))
			return 0;
	return 1;
}


pcap_t *
pcapint_create_interface(const char *device, char *errorBuffer)
{
	if (validate_ifname(device, errorBuffer) < 0)
		return NULL;
	if (! can_be_bound(device)) {
		snprintf(errorBuffer, PCAP_ERRBUF_SIZE,
		         "Interface \"%s\" does not support capturing traffic.", device);
		return NULL;
	}

	pcap_t* handle = PCAP_CREATE_COMMON(errorBuffer, struct pcap_haiku);
	if (handle == NULL)
		return NULL;
	handle->activate_op = pcap_activate_haiku;

	struct pcap_haiku *handlep = (struct pcap_haiku *)handle->priv;
	handlep->aux_socket = -1;
	strcpy(handlep->ifreq.ifr_name, device);

	return handle;
}


static int
get_if_flags(const char *name, bpf_u_int32 *flags, char *errbuf)
{
	if (validate_ifname(name, errbuf) < 0)
		return PCAP_ERROR;

	if (*flags & PCAP_IF_LOOPBACK ||
	    ! strncmp(name, "tun", strlen("tun")) ||
	    ! strncmp(name, "tap", strlen("tap"))) {
		/*
		 * Loopback devices aren't wireless, and "connected"/
		 * "disconnected" doesn't apply to them.
		 *
		 * Neither does it to tunnel interfaces.  A tun mode tunnel
		 * can be identified by the IFT_TUNNEL value, but tap mode
		 * tunnels and Ethernet interfaces both use IFT_ETHER, so let's
		 * use the interface name prefix until there is a better
		 * solution.
		 */
		*flags |= PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE;
		return (0);
	}

	int fd = dgram_socket(AF_LINK, errbuf);
	if (fd < 0)
		return PCAP_ERROR;
	struct ifreq ifreq;
	strcpy(ifreq.ifr_name, name);
	if (ioctl_ifreq(fd, SIOCGIFFLAGS, "SIOCGIFFLAGS", &ifreq, errbuf) < 0) {
		close(fd);
		return PCAP_ERROR;
	}
	*flags |= (ifreq.ifr_flags & IFF_LINK) ?
	          PCAP_IF_CONNECTION_STATUS_CONNECTED :
	          PCAP_IF_CONNECTION_STATUS_DISCONNECTED;
	if (ioctl_ifreq(fd, SIOCGIFMEDIA, "SIOCGIFMEDIA", &ifreq, errbuf) < 0) {
		close(fd);
		return PCAP_ERROR;
	}
	if (IFM_TYPE(ifreq.ifr_media) == IFM_IEEE80211)
		*flags |= PCAP_IF_WIRELESS;
	close(fd);

	return (0);
}

int
pcapint_platform_finddevs(pcap_if_list_t* _allDevices, char* errorBuffer)
{
	return pcapint_findalldevs_interfaces(_allDevices, errorBuffer, can_be_bound,
		get_if_flags);
}

/*
 * Libpcap version string.
 */
const char *
pcap_lib_version(void)
{
	return (PCAP_VERSION_STRING);
}
