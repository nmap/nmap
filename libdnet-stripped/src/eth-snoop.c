/*
 * eth-snoop.c
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: eth-snoop.c 548 2005-01-30 06:01:57Z dugsong $
 */

#include "config.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/raw.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "dnet.h"

struct eth_handle {
	int		fd;
	struct ifreq	ifr;
};

eth_t *
eth_open(const char *device)
{
	struct sockaddr_raw sr;
	eth_t *e;
	int n;
	
	if ((e = calloc(1, sizeof(*e))) == NULL)
		return (NULL);

	if ((e->fd = socket(PF_RAW, SOCK_RAW, RAWPROTO_SNOOP)) < 0)
		return (eth_close(e));
	
	memset(&sr, 0, sizeof(sr));
	sr.sr_family = AF_RAW;
	strlcpy(sr.sr_ifname, device, sizeof(sr.sr_ifname));

	if (bind(e->fd, (struct sockaddr *)&sr, sizeof(sr)) < 0)
		return (eth_close(e));
	
	n = 60000;
	if (setsockopt(e->fd, SOL_SOCKET, SO_SNDBUF, &n, sizeof(n)) < 0)
		return (eth_close(e));
	
	strlcpy(e->ifr.ifr_name, device, sizeof(e->ifr.ifr_name));
	
	return (e);
}

int
eth_get(eth_t *e, eth_addr_t *ea)
{
	struct addr ha;
	
	if (ioctl(e->fd, SIOCGIFADDR, &e->ifr) < 0)
		return (-1);

	if (addr_ston(&e->ifr.ifr_addr, &ha) < 0)
		return (-1);

	if (ha.addr_type != ADDR_TYPE_ETH) {
		errno = EINVAL;
		return (-1);
	}
	memcpy(ea, &ha.addr_eth, sizeof(*ea));
	
	return (0);
}

int
eth_set(eth_t *e, const eth_addr_t *ea)
{
	struct addr ha;

	ha.addr_type = ADDR_TYPE_ETH;
	ha.addr_bits = ETH_ADDR_BITS;
	memcpy(&ha.addr_eth, ea, ETH_ADDR_LEN);
	    
	if (addr_ntos(&ha, &e->ifr.ifr_addr) < 0)
		return (-1);
	
	return (ioctl(e->fd, SIOCSIFADDR, &e->ifr));
}

ssize_t
eth_send(eth_t *e, const void *buf, size_t len)
{
	return (write(e->fd, buf, len));
}

eth_t *
eth_close(eth_t *e)
{
	if (e != NULL) {
		if (e->fd >= 0)
			close(e->fd);
		free(e);
	}
	return (NULL);
}
