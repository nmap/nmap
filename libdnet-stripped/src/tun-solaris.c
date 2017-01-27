/*
 * tun-solaris.c
 *
 * Universal TUN/TAP driver
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: tun-solaris.c 547 2005-01-25 21:30:40Z dugsong $
 */

#include "config.h"

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>

#include <net/if.h>
#include <net/if_tun.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stropts.h>
#include <unistd.h>

#include "dnet.h"

#define DEV_TUN		"/dev/tun"
#define DEV_IP		"/dev/ip"

struct tun {
	int		 fd;
	int		 ip_fd;
	int		 if_fd;
	char		 name[16];
};

tun_t *
tun_open(struct addr *src, struct addr *dst, int mtu)
{
	tun_t *tun;
	char cmd[512];
	int ppa;

	if ((tun = calloc(1, sizeof(*tun))) == NULL)
		return (NULL);

	tun->fd = tun->ip_fd = tun->if_fd = -1;
	
	if ((tun->fd = open(DEV_TUN, O_RDWR, 0)) < 0)
		return (tun_close(tun));

	if ((tun->ip_fd = open(DEV_IP, O_RDWR, 0)) < 0)
		return (tun_close(tun));
	
	if ((ppa = ioctl(tun->fd, TUNNEWPPA, ppa)) < 0)
		return (tun_close(tun));

	if ((tun->if_fd = open(DEV_TUN, O_RDWR, 0)) < 0)
		return (tun_close(tun));

	if (ioctl(tun->if_fd, I_PUSH, "ip") < 0)
		return (tun_close(tun));
	
	if (ioctl(tun->if_fd, IF_UNITSEL, (char *)&ppa) < 0)
		return (tun_close(tun));

	if (ioctl(tun->ip_fd, I_LINK, tun->if_fd) < 0)
		return (tun_close(tun));

	snprintf(tun->name, sizeof(tun->name), "tun%d", ppa);
	
	snprintf(cmd, sizeof(cmd), "ifconfig %s %s/32 %s mtu %d up",
	    tun->name, addr_ntoa(src), addr_ntoa(dst), mtu);
	
	if (system(cmd) < 0)
		return (tun_close(tun));
	
	return (tun);
}

const char *
tun_name(tun_t *tun)
{
	return (tun->name);
}

int
tun_fileno(tun_t *tun)
{
	return (tun->fd);
}

ssize_t
tun_send(tun_t *tun, const void *buf, size_t size)
{
	struct strbuf sbuf;

	sbuf.buf = buf;
	sbuf.len = size;
	return (putmsg(tun->fd, NULL, &sbuf, 0) >= 0 ? sbuf.len : -1);
}

ssize_t
tun_recv(tun_t *tun, void *buf, size_t size)
{
	struct strbuf sbuf;
	int flags = 0;
	
	sbuf.buf = buf;
	sbuf.maxlen = size;
	return (getmsg(tun->fd, NULL, &sbuf, &flags) >= 0 ? sbuf.len : -1);
}

tun_t *
tun_close(tun_t *tun)
{
	if (tun->if_fd >= 0)
		close(tun->if_fd);
	if (tun->ip_fd >= 0)
		close(tun->ip_fd);
	if (tun->fd >= 0)
		close(tun->fd);
	free(tun);
	return (NULL);
}
