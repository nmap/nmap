/*
 * Copyright 2006-2010, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 *
 * Authors:
 *		Axel Dörfler, axeld@pinc-software.de
 *		James Woodcock
 */


#include "config.h"
#include "pcap-int.h"

#include <OS.h>

#include <sys/socket.h>
#include <sys/sockio.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/*
 * Private data for capturing on Haiku sockets.
 */
struct pcap_haiku {
	struct pcap_stat	stat;
	char	*device;	/* device name */
};


bool
prepare_request(struct ifreq& request, const char* name)
{
	if (strlen(name) >= IF_NAMESIZE)
		return false;

	strcpy(request.ifr_name, name);
	return true;
}


static int
pcap_read_haiku(pcap_t* handle, int maxPackets _U_, pcap_handler callback,
	u_char* userdata)
{
	// Receive a single packet

	u_char* buffer = (u_char*)handle->buffer + handle->offset;
	struct sockaddr_dl from;
	ssize_t bytesReceived;
	do {
		if (handle->break_loop) {
			// Clear the break loop flag, and return -2 to indicate our
			// reasoning
			handle->break_loop = 0;
			return -2;
		}

		socklen_t fromLength = sizeof(from);
		bytesReceived = recvfrom(handle->fd, buffer, handle->bufsize, MSG_TRUNC,
			(struct sockaddr*)&from, &fromLength);
	} while (bytesReceived < 0 && errno == B_INTERRUPTED);

	if (bytesReceived < 0) {
		if (errno == B_WOULD_BLOCK) {
			// there is no packet for us
			return 0;
		}

		snprintf(handle->errbuf, sizeof(handle->errbuf),
			"recvfrom: %s", strerror(errno));
		return -1;
	}

	int32 captureLength = bytesReceived;
	if (captureLength > handle->snapshot)
		captureLength = handle->snapshot;

	// run the packet filter
	if (handle->fcode.bf_insns) {
		if (pcap_filter(handle->fcode.bf_insns, buffer, bytesReceived,
				captureLength) == 0) {
			// packet got rejected
			return 0;
		}
	}

	// fill in pcap_header
	pcap_pkthdr header;
	header.caplen = captureLength;
	header.len = bytesReceived;
	header.ts.tv_usec = system_time() % 1000000;
	header.ts.tv_sec = system_time() / 1000000;
	// TODO: get timing from packet!!!

	/* Call the user supplied callback function */
	callback(userdata, &header, buffer);
	return 1;
}


static int
pcap_inject_haiku(pcap_t *handle, const void *buffer, int size)
{
	// we don't support injecting packets yet
	// TODO: use the AF_LINK protocol (we need another socket for this) to
	// inject the packets
	strlcpy(handle->errbuf, "Sending packets isn't supported yet",
		PCAP_ERRBUF_SIZE);
	return -1;
}


static int
pcap_stats_haiku(pcap_t *handle, struct pcap_stat *stats)
{
	struct pcap_haiku* handlep = (struct pcap_haiku*)handle->priv;
	ifreq request;
	int socket = ::socket(AF_INET, SOCK_DGRAM, 0);
	if (socket < 0) {
		return -1;
	}
	prepare_request(request, handlep->device);
	if (ioctl(socket, SIOCGIFSTATS, &request, sizeof(struct ifreq)) < 0) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "pcap_stats: %s",
			strerror(errno));
		close(socket);
		return -1;
	}

	close(socket);
	handlep->stat.ps_recv += request.ifr_stats.receive.packets;
	handlep->stat.ps_drop += request.ifr_stats.receive.dropped;
	*stats = handlep->stat;
	return 0;
}


static int
pcap_activate_haiku(pcap_t *handle)
{
	struct pcap_haiku* handlep = (struct pcap_haiku*)handle->priv;

	const char* device = handle->opt.device;

	handle->read_op = pcap_read_haiku;
	handle->setfilter_op = install_bpf_program; /* no kernel filtering */
	handle->inject_op = pcap_inject_haiku;
	handle->stats_op = pcap_stats_haiku;

	// use default hooks where possible
	handle->getnonblock_op = pcap_getnonblock_fd;
	handle->setnonblock_op = pcap_setnonblock_fd;

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

	handlep->device	= strdup(device);
	if (handlep->device == NULL) {
		pcap_fmt_errmsg_for_errno(handle->errbuf, PCAP_ERRBUF_SIZE,
			errno, "strdup");
		return PCAP_ERROR;
	}

	handle->bufsize = 65536;
	// TODO: should be determined by interface MTU

	// allocate buffer for monitoring the device
	handle->buffer = (u_char*)malloc(handle->bufsize);
	if (handle->buffer == NULL) {
		pcap_fmt_errmsg_for_errno(handle->errbuf, PCAP_ERRBUF_SIZE,
			errno, "buffer malloc");
		return PCAP_ERROR;
	}

	handle->offset = 0;
	handle->linktype = DLT_EN10MB;
	// TODO: check interface type!

	return 0;
}


//	#pragma mark - pcap API


extern "C" pcap_t *
pcap_create_interface(const char *device, char *errorBuffer)
{
	// TODO: handle promiscuous mode!

	// we need a socket to talk to the networking stack
	int socket = ::socket(AF_INET, SOCK_DGRAM, 0);
	if (socket < 0) {
		snprintf(errorBuffer, PCAP_ERRBUF_SIZE,
			"The networking stack doesn't seem to be available.\n");
		return NULL;
	}

	struct ifreq request;
	if (!prepare_request(request, device)) {
		snprintf(errorBuffer, PCAP_ERRBUF_SIZE,
			"Interface name \"%s\" is too long.", device);
		close(socket);
		return NULL;
	}

	// check if the interface exist
	if (ioctl(socket, SIOCGIFINDEX, &request, sizeof(request)) < 0) {
		snprintf(errorBuffer, PCAP_ERRBUF_SIZE,
			"Interface \"%s\" does not exist.\n", device);
		close(socket);
		return NULL;
	}

	close(socket);
	// no longer needed after this point

	// get link level interface for this interface

	socket = ::socket(AF_LINK, SOCK_DGRAM, 0);
	if (socket < 0) {
		snprintf(errorBuffer, PCAP_ERRBUF_SIZE, "No link level: %s\n",
			strerror(errno));
		return NULL;
	}

	// start monitoring
	if (ioctl(socket, SIOCSPACKETCAP, &request, sizeof(struct ifreq)) < 0) {
		snprintf(errorBuffer, PCAP_ERRBUF_SIZE, "Cannot start monitoring: %s\n",
			strerror(errno));
		close(socket);
		return NULL;
	}

	struct wrapper_struct { pcap_t __common; struct pcap_haiku __private; };
	pcap_t* handle = pcap_create_common(errorBuffer,
		sizeof (struct wrapper_struct),
		offsetof (struct wrapper_struct, __private));

	if (handle == NULL) {
		snprintf(errorBuffer, PCAP_ERRBUF_SIZE, "malloc: %s", strerror(errno));
		close(socket);
		return NULL;
	}

	handle->selectable_fd = socket;
	handle->fd = socket;

	handle->activate_op = pcap_activate_haiku;

	return handle;
}

static int
can_be_bound(const char *name _U_)
{
	return 1;
}

static int
get_if_flags(const char *name, bpf_u_int32 *flags, char *errbuf)
{
	/* TODO */
	if (*flags & PCAP_IF_LOOPBACK) {
		/*
		 * Loopback devices aren't wireless, and "connected"/
		 * "disconnected" doesn't apply to them.
		 */
		*flags |= PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE;
		return (0);
	}
	return (0);
}

extern "C" int
pcap_platform_finddevs(pcap_if_list_t* _allDevices, char* errorBuffer)
{
	return pcap_findalldevs_interfaces(_allDevices, errorBuffer, can_be_bound,
		get_if_flags);
}

/*
 * Libpcap version string.
 */
extern "C" const char *
pcap_lib_version(void)
{
	return (PCAP_VERSION_STRING);
}
