/*
 * eth-pfilt.c
 *
 * XXX - requires 'cd dev && ./MAKEDEV pfilt' if not already configured...
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: eth-pfilt.c 563 2005-02-10 17:06:36Z dugsong $
 */

#include "config.h"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>

#include <net/if.h>
#include <net/pfilt.h>

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dnet.h"

struct eth_handle {
	int	fd;
	int	sock;
	char	device[16];
};

eth_t *
eth_open(const char *device)
{
	struct eth_handle *e;
	int fd;
	
	if ((e = calloc(1, sizeof(*e))) != NULL) {
		strlcpy(e->device, device, sizeof(e->device));
		if ((e->fd = pfopen(e->device, O_WRONLY)) < 0 ||
		    (e->sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
			e = eth_close(e);
	}
	return (e);
}

int
eth_get(eth_t *e, eth_addr_t *ea)
{
	struct ifdevea ifd;

	strlcpy(ifd.ifr_name, e->device, sizeof(ifd.ifr_name));
	if (ioctl(e->sock, SIOCRPHYSADDR, &ifd) < 0)
		return (-1);
	memcpy(ea, ifd.current_pa, ETH_ADDR_LEN);
	return (0);
}

int
eth_set(eth_t *e, const eth_addr_t *ea)
{
	struct ifdevea ifd;

	strlcpy(ifd.ifr_name, e->device, sizeof(ifd.ifr_name));
	memcpy(ifd.current_pa, ea, ETH_ADDR_LEN);
	return (ioctl(e->sock, SIOCSPHYSADDR, &ifd));
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
		if (e->sock >= 0)
			close(e->sock);
		free(e);
	}
	return (NULL);
}
