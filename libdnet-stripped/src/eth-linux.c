/*
 * eth-linux.c
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: eth-linux.c 547 2005-01-25 21:30:40Z dugsong $
 */

#include "config.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <net/if.h>
#include <features.h>
#if __GLIBC__ >= 2 && __GLIBC_MINOR >= 1
#include <netpacket/packet.h>
#include <net/ethernet.h>
#else
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#endif /* __GLIBC__ */
#include <netinet/in.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dnet.h"

struct eth_handle {
	int			fd;
	struct ifreq		ifr;
	struct sockaddr_ll	sll;
};

eth_t *
eth_open(const char *device)
{
	eth_t *e;
	int n;
	
	if ((e = calloc(1, sizeof(*e))) != NULL) {
		if ((e->fd = socket(PF_PACKET, SOCK_RAW,
			 htons(ETH_P_ALL))) < 0)
			return (eth_close(e));
#ifdef SO_BROADCAST
		n = 1;
		if (setsockopt(e->fd, SOL_SOCKET, SO_BROADCAST, &n,
			sizeof(n)) < 0)
			return (eth_close(e));
#endif
		strlcpy(e->ifr.ifr_name, device, sizeof(e->ifr.ifr_name));
		
		if (ioctl(e->fd, SIOCGIFINDEX, &e->ifr) < 0)
			return (eth_close(e));
		
		e->sll.sll_family = AF_PACKET;
		e->sll.sll_ifindex = e->ifr.ifr_ifindex;
	}
	return (e);
}

ssize_t
eth_send(eth_t *e, const void *buf, size_t len)
{
	struct eth_hdr *eth = (struct eth_hdr *)buf;
	
	e->sll.sll_protocol = eth->eth_type;

	return (sendto(e->fd, buf, len, 0, (struct sockaddr *)&e->sll,
	    sizeof(e->sll)));
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

int
eth_get(eth_t *e, eth_addr_t *ea)
{
	struct addr ha;
	
	if (ioctl(e->fd, SIOCGIFHWADDR, &e->ifr) < 0)
		return (-1);
	
	if (addr_ston(&e->ifr.ifr_hwaddr, &ha) < 0)
		return (-1);

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

	addr_ntos(&ha, &e->ifr.ifr_hwaddr);

	return (ioctl(e->fd, SIOCSIFHWADDR, &e->ifr));
}
