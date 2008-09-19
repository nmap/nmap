/*
 * tun-linux.c
 *
 * Universal TUN/TAP driver, in Linux 2.4+
 * /usr/src/linux/Documentation/networking/tuntap.txt
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: tun-linux.c 612 2005-09-12 02:18:06Z dugsong $
 */

#include "config.h"

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dnet.h"

struct tun {
	int fd;
	intf_t *intf;
	struct ifreq ifr;
};

tun_t *
tun_open(struct addr *src, struct addr *dst, int mtu)
{
	tun_t *tun;
	struct intf_entry ifent;
	
	if ((tun = calloc(1, sizeof(*tun))) == NULL)
		return (NULL);

	if ((tun->fd = open("/dev/net/tun", O_RDWR, 0)) < 0 ||
	    (tun->intf = intf_open()) == NULL)
		return (tun_close(tun));
	
	tun->ifr.ifr_flags = IFF_TUN;

	if (ioctl(tun->fd, TUNSETIFF, (void *) &tun->ifr) < 0)
		return (tun_close(tun));

	memset(&ifent, 0, sizeof(ifent));
	strlcpy(ifent.intf_name, tun->ifr.ifr_name, sizeof(ifent.intf_name));
	ifent.intf_flags = INTF_FLAG_UP|INTF_FLAG_POINTOPOINT;
	ifent.intf_addr = *src;
	ifent.intf_dst_addr = *dst;	
	ifent.intf_mtu = mtu;
	
	if (intf_set(tun->intf, &ifent) < 0)
		return (tun_close(tun));
	
	return (tun);
}

const char *
tun_name(tun_t *tun)
{
	return (tun->ifr.ifr_name);
}

int
tun_fileno(tun_t *tun)
{
	return (tun->fd);
}

ssize_t
tun_send(tun_t *tun, const void *buf, size_t size)
{
	struct iovec iov[2];
	uint32_t type = ETH_TYPE_IP;
	
	iov[0].iov_base = &type;
	iov[0].iov_len = sizeof(type);
	iov[1].iov_base = (void *)buf;
	iov[1].iov_len = size;
	
	return (writev(tun->fd, iov, 2));
}

ssize_t
tun_recv(tun_t *tun, void *buf, size_t size)
{
	struct iovec iov[2];
	uint32_t type;

	iov[0].iov_base = &type;
	iov[0].iov_len = sizeof(type);
	iov[1].iov_base = (void *)buf;
	iov[1].iov_len = size;
	
	return (readv(tun->fd, iov, 2) - sizeof(type));
}

tun_t *
tun_close(tun_t *tun)
{
	if (tun->fd > 0)
		close(tun->fd);
	if (tun->intf != NULL)
		intf_close(tun->intf);
	free(tun);
	return (NULL);
}
