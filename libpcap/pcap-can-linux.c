/*
 * Copyright (c) 2009 Felix Obenhuber
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 * products derived from this software without specific prior written
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * SocketCan sniffing API implementation for Linux platform
 * By Felix Obenhuber <felix@obenhuber.de>
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pcap-int.h"
#include "pcap-can-linux.h"

#ifdef NEED_STRERROR_H
#include "strerror.h"
#endif

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <linux/can.h>
#include <linux/can/raw.h>

/* not yet defined anywhere */
#ifndef PF_CAN
#define PF_CAN 29
#endif
#ifndef AF_CAN
#define AF_CAN PF_CAN
#endif

/* forward declaration */
static int can_activate(pcap_t *);
static int can_read_linux(pcap_t *, int , pcap_handler , u_char *);
static int can_inject_linux(pcap_t *, const void *, size_t);
static int can_setfilter_linux(pcap_t *, struct bpf_program *);
static int can_setdirection_linux(pcap_t *, pcap_direction_t);
static int can_stats_linux(pcap_t *, struct pcap_stat *);

/*
 * Private data for capturing on Linux CANbus devices.
 */
struct pcap_can {
	int ifindex;		/* interface index of device we're bound to */
};

int
can_findalldevs(pcap_if_t **devlistp, char *errbuf)
{
	/*
	 * There are no platform-specific devices since each device
	 * exists as a regular network interface.
	 *
	 * XXX - true?
	 */
	return 0;
}

pcap_t *
can_create(const char *device, char *ebuf, int *is_ours)
{
	const char *cp;
	char *cpend;
	long devnum;
	pcap_t* p;

	/* Does this look like a CANbus device? */
	cp = strrchr(device, '/');
	if (cp == NULL)
		cp = device;
	/* Does it begin with "can" or "vcan"? */
	if (strncmp(cp, "can", 3) == 0) {
		/* Begins with "can" */
		cp += 3;	/* skip past "can" */
	} else if (strncmp(cp, "vcan", 4) == 0) {
		/* Begins with "vcan" */
		cp += 4;
	} else {
		/* Nope, doesn't begin with "can" or "vcan" */
		*is_ours = 0;
		return NULL;
	}
	/* Yes - is "can" or "vcan" followed by a number from 0? */
	devnum = strtol(cp, &cpend, 10);
	if (cpend == cp || *cpend != '\0') {
		/* Not followed by a number. */
		*is_ours = 0;
		return NULL;
	}
	if (devnum < 0) {
		/* Followed by a non-valid number. */
		*is_ours = 0;
		return NULL;
	}

	/* OK, it's probably ours. */
	*is_ours = 1;

	p = pcap_create_common(device, ebuf, sizeof (struct pcap_can));
	if (p == NULL)
		return (NULL);

	p->activate_op = can_activate;
	return (p);
}


static int
can_activate(pcap_t* handle)
{
	struct pcap_can *handlep = handle->priv;
	struct sockaddr_can addr;
	struct ifreq ifr;

	/* Initialize some components of the pcap structure. */
	handle->bufsize = 24;
	handle->offset = 8;
	handle->linktype = DLT_CAN_SOCKETCAN;
	handle->read_op = can_read_linux;
	handle->inject_op = can_inject_linux;
	handle->setfilter_op = can_setfilter_linux;
	handle->setdirection_op = can_setdirection_linux;
	handle->set_datalink_op = NULL;
	handle->getnonblock_op = pcap_getnonblock_fd;
	handle->setnonblock_op = pcap_setnonblock_fd;
	handle->stats_op = can_stats_linux;

	/* Create socket */
	handle->fd = socket(PF_CAN, SOCK_RAW, CAN_RAW);
	if (handle->fd < 0)
	{
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "Can't create raw socket %d:%s",
			errno, strerror(errno));
		return PCAP_ERROR;
	}

	/* get interface index */
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, handle->opt.source, sizeof(ifr.ifr_name));
	if (ioctl(handle->fd, SIOCGIFINDEX, &ifr) < 0)
	{
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
				"Unable to get interface index: %s",
			pcap_strerror(errno));
		pcap_cleanup_live_common(handle);
		return PCAP_ERROR;
	}
	handlep->ifindex = ifr.ifr_ifindex;

	/* allocate butter */
	handle->buffer = malloc(handle->bufsize);
	if (!handle->buffer)
	{
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "Can't allocate dump buffer: %s",
			pcap_strerror(errno));
		pcap_cleanup_live_common(handle);
		return PCAP_ERROR;
	}

	/* Bind to the socket */
	addr.can_family = AF_CAN;
	addr.can_ifindex = handlep->ifindex;
	if( bind( handle->fd, (struct sockaddr*)&addr, sizeof(addr) ) < 0  )
	{
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "Can't attach to device %d %d:%s",
			handlep->ifindex, errno, strerror(errno));
		pcap_cleanup_live_common(handle);
		return PCAP_ERROR;
	}

	if (handle->opt.rfmon)
	{
		/* Monitor mode doesn't apply to CAN devices. */
		pcap_cleanup_live_common(handle);
		return PCAP_ERROR_RFMON_NOTSUP;
	}

	handle->selectable_fd = handle->fd;
	return 0;

}


static int
can_read_linux(pcap_t *handle, int max_packets, pcap_handler callback, u_char *user)
{
	struct msghdr msg;
	struct pcap_pkthdr pkth;
	struct iovec iv;
	struct can_frame* cf;

	iv.iov_base = &handle->buffer[handle->offset];
	iv.iov_len = handle->snapshot;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iv;
	msg.msg_iovlen = 1;
	msg.msg_control = handle->buffer;
	msg.msg_controllen = handle->offset;

	do
	{
		pkth.caplen = recvmsg(handle->fd, &msg, 0);
		if (handle->break_loop)
		{
			handle->break_loop = 0;
			return -2;
		}
	} while ((pkth.caplen == -1) && (errno == EINTR));

	if (pkth.caplen == -1)
	{
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "Can't receive packet %d:%s",
			errno, strerror(errno));
		return -1;
	}

	/* adjust capture len according to frame len */
	cf = (struct can_frame*)&handle->buffer[8];
	pkth.caplen -= 8 - cf->can_dlc;
	pkth.len = pkth.caplen;

	cf->can_id = htonl( cf->can_id );

	if( -1 == gettimeofday(&pkth.ts, NULL) )
	{
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "Can't get time of day %d:%s",
			errno, strerror(errno));
		return -1;
	}

	callback(user, &pkth, &handle->buffer[8]);

	return 1;
}


static int
can_inject_linux(pcap_t *handle, const void *buf, size_t size)
{
	/* not yet implemented */
	snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "inject not supported on "
		"can devices");
	return (-1);
}


static int
can_stats_linux(pcap_t *handle, struct pcap_stat *stats)
{
	/* not yet implemented */
	stats->ps_recv = 0;			 /* number of packets received */
	stats->ps_drop = 0;			 /* number of packets dropped */
	stats->ps_ifdrop = 0;		 /* drops by interface -- only supported on some platforms */
	return 0;
}


static int
can_setfilter_linux(pcap_t *p, struct bpf_program *fp)
{
	/* not yet implemented */
	return 0;
}


static int
can_setdirection_linux(pcap_t *p, pcap_direction_t d)
{
	/* no support for PCAP_D_OUT */
	if (d == PCAP_D_OUT)
	{
		snprintf(p->errbuf, sizeof(p->errbuf),
			"Setting direction to PCAP_D_OUT is not supported on can");
		return -1;
	}

	p->direction = d;

	return 0;
}


/* eof */
