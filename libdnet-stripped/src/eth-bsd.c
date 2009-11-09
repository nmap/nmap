/*
 * eth-bsd.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: eth-bsd.c 630 2006-02-02 04:17:39Z dugsong $
 */

#include "config.h"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#if defined(HAVE_SYS_SYSCTL_H) && defined(HAVE_ROUTE_RT_MSGHDR)
#include <sys/sysctl.h>
#include <net/route.h>
#include <net/if_dl.h>
#endif
#include <net/bpf.h>
#include <net/if.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dnet.h"

struct eth_handle {
	int	fd;
	char	device[16];
};

eth_t *
eth_open(const char *device)
{
	struct ifreq ifr;
	char file[32];
	eth_t *e;
	int i;

	if ((e = calloc(1, sizeof(*e))) != NULL) {
		for (i = 0; i < 128; i++) {
			snprintf(file, sizeof(file), "/dev/bpf%d", i);
			/* This would be O_WRONLY, but Mac OS X 10.6 has a bug
			   where that prevents other users of the interface
			   from seeing incoming traffic, even in other
			   processes. */
			e->fd = open(file, O_RDWR);
			if (e->fd != -1 || errno != EBUSY)
				break;
		}
		if (e->fd < 0)
			return (eth_close(e));
		
		memset(&ifr, 0, sizeof(ifr));
		strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
		
		if (ioctl(e->fd, BIOCSETIF, (char *)&ifr) < 0)
			return (eth_close(e));
#ifdef BIOCSHDRCMPLT
		i = 1;
		if (ioctl(e->fd, BIOCSHDRCMPLT, &i) < 0)
			return (eth_close(e));
#endif
		strlcpy(e->device, device, sizeof(e->device));
	}
	return (e);
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

#if defined(HAVE_SYS_SYSCTL_H) && defined(HAVE_ROUTE_RT_MSGHDR)
int
eth_get(eth_t *e, eth_addr_t *ea)
{
	struct if_msghdr *ifm;
	struct sockaddr_dl *sdl;
	struct addr ha;
	u_char *p, *buf;
	size_t len;
	int mib[] = { CTL_NET, AF_ROUTE, 0, AF_LINK, NET_RT_IFLIST, 0 };

	if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0)
		return (-1);
	
	if ((buf = malloc(len)) == NULL)
		return (-1);
	
	if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
		free(buf);
		return (-1);
	}
	for (p = buf; p < buf + len; p += ifm->ifm_msglen) {
		ifm = (struct if_msghdr *)p;
		sdl = (struct sockaddr_dl *)(ifm + 1);
		
		if (ifm->ifm_type != RTM_IFINFO ||
		    (ifm->ifm_addrs & RTA_IFP) == 0)
			continue;
		
		if (sdl->sdl_family != AF_LINK || sdl->sdl_nlen == 0 ||
		    memcmp(sdl->sdl_data, e->device, sdl->sdl_nlen) != 0)
			continue;
		
		if (addr_ston((struct sockaddr *)sdl, &ha) == 0)
			break;
	}
	free(buf);
	
	if (p >= buf + len) {
		errno = ESRCH;
		return (-1);
	}
	memcpy(ea, &ha.addr_eth, sizeof(*ea));
	
	return (0);
}
#else
int
eth_get(eth_t *e, eth_addr_t *ea)
{
	errno = ENOSYS;
	return (-1);
}
#endif

#if defined(SIOCSIFLLADDR)
int
eth_set(eth_t *e, const eth_addr_t *ea)
{
	struct ifreq ifr;
	struct addr ha;

	ha.addr_type = ADDR_TYPE_ETH;
	ha.addr_bits = ETH_ADDR_BITS;
	memcpy(&ha.addr_eth, ea, ETH_ADDR_LEN);
	
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, e->device, sizeof(ifr.ifr_name));
	addr_ntos(&ha, &ifr.ifr_addr);
	
	return (ioctl(e->fd, SIOCSIFLLADDR, &ifr));
}
#else
int
eth_set(eth_t *e, const eth_addr_t *ea)
{
	errno = ENOSYS;
	return (-1);
}
#endif
