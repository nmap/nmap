/*
 * tun-bsd.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: tun-bsd.c 573 2005-02-10 23:50:04Z dugsong $
 */

#include "config.h"

#include <sys/socket.h>
#include <sys/uio.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dnet.h"

struct tun {
	int               fd;
	intf_t           *intf;
	struct intf_entry save;
};

#define MAX_DEVS	16	/* XXX - max number of tunnel devices */

tun_t *
tun_open(struct addr *src, struct addr *dst, int mtu)
{
	struct intf_entry ifent;
	tun_t *tun;
	char dev[128];
	int i;

	if (src->addr_type != ADDR_TYPE_IP || dst->addr_type != ADDR_TYPE_IP ||
	    src->addr_bits != IP_ADDR_BITS || dst->addr_bits != IP_ADDR_BITS) {
		errno = EINVAL;
		return (NULL);
	}
	if ((tun = calloc(1, sizeof(*tun))) == NULL)
		return (NULL);

	if ((tun->intf = intf_open()) == NULL)
		return (tun_close(tun));

	memset(&ifent, 0, sizeof(ifent));
	ifent.intf_len = sizeof(ifent);
	
	for (i = 0; i < MAX_DEVS; i++) {
		snprintf(dev, sizeof(dev), "/dev/tun%d", i);
		strlcpy(ifent.intf_name, dev + 5, sizeof(ifent.intf_name));
		tun->save = ifent;
		
		if ((tun->fd = open(dev, O_RDWR, 0)) != -1 &&
		    intf_get(tun->intf, &tun->save) == 0) {
			route_t *r;
			struct route_entry entry;
			
			ifent.intf_flags = INTF_FLAG_UP|INTF_FLAG_POINTOPOINT;
			ifent.intf_addr = *src;
			ifent.intf_dst_addr = *dst;	
			ifent.intf_mtu = mtu;
			
			if (intf_set(tun->intf, &ifent) < 0)
				tun = tun_close(tun);

			/* XXX - try to ensure our route got set */
			if ((r = route_open()) != NULL) {
				entry.route_dst = *dst;
				entry.route_gw = *src;
				route_add(r, &entry);
				route_close(r);
			}
			break;
		}
	}
	if (i == MAX_DEVS)
		tun = tun_close(tun);
	return (tun);
}

const char *
tun_name(tun_t *tun)
{
	return (tun->save.intf_name);
}

int
tun_fileno(tun_t *tun)
{
	return (tun->fd);
}

ssize_t
tun_send(tun_t *tun, const void *buf, size_t size)
{
#ifdef __OpenBSD__
	struct iovec iov[2];
	uint32_t af = htonl(AF_INET);

	iov[0].iov_base = &af;
	iov[0].iov_len = sizeof(af);
	iov[1].iov_base = (void *)buf;
	iov[1].iov_len = size;
	
	return (writev(tun->fd, iov, 2));
#else
	return (write(tun->fd, buf, size));
#endif
}

ssize_t
tun_recv(tun_t *tun, void *buf, size_t size)
{
#ifdef __OpenBSD__
	struct iovec iov[2];
	uint32_t af;
	
	iov[0].iov_base = &af;
	iov[0].iov_len = sizeof(af);
	iov[1].iov_base = (void *)buf;
	iov[1].iov_len = size;
	
	return (readv(tun->fd, iov, 2) - sizeof(af));
#else
	return (read(tun->fd, buf, size));
#endif
}

tun_t *
tun_close(tun_t *tun)
{
	if (tun->fd > 0)
		close(tun->fd);
	if (tun->intf != NULL) {
		/* Restore interface configuration on close. */
		intf_set(tun->intf, &tun->save);
		intf_close(tun->intf);
	}
	free(tun);
	return (NULL);
}
