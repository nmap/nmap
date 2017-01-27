/*
 * ip.c
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: ip.c 547 2005-01-25 21:30:40Z dugsong $
 */

#include "config.h"

#include <netinet/in.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dnet.h"

struct ip_handle {
	int	fd;
};

ip_t *
ip_open(void)
{
	ip_t *i;
	int n;
	socklen_t len;

	if ((i = calloc(1, sizeof(*i))) == NULL)
		return (NULL);

	if ((i->fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
		return (ip_close(i));
#ifdef IP_HDRINCL
	n = 1;
	if (setsockopt(i->fd, IPPROTO_IP, IP_HDRINCL, &n, sizeof(n)) < 0)
		return (ip_close(i));
#endif
#ifdef SO_SNDBUF
	len = sizeof(n);
	if (getsockopt(i->fd, SOL_SOCKET, SO_SNDBUF, &n, &len) < 0)
		return (ip_close(i));

	for (n += 128; n < 1048576; n += 128) {
		if (setsockopt(i->fd, SOL_SOCKET, SO_SNDBUF, &n, len) < 0) {
			if (errno == ENOBUFS)
				break;
			return (ip_close(i));
		}
	}
#endif
#ifdef SO_BROADCAST
	n = 1;
	if (setsockopt(i->fd, SOL_SOCKET, SO_BROADCAST, &n, sizeof(n)) < 0)
		return (ip_close(i));
#endif
	return (i);
}

ssize_t
ip_send(ip_t *i, const void *buf, size_t len)
{
	struct ip_hdr *ip;
	struct sockaddr_in sin;

	ip = (struct ip_hdr *)buf;

	memset(&sin, 0, sizeof(sin));
#ifdef HAVE_SOCKADDR_SA_LEN       
	sin.sin_len = sizeof(sin);
#endif
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = ip->ip_dst;
	
#ifdef HAVE_RAWIP_HOST_OFFLEN
	ip->ip_len = ntohs(ip->ip_len);
	ip->ip_off = ntohs(ip->ip_off);

	len = sendto(i->fd, buf, len, 0,
	    (struct sockaddr *)&sin, sizeof(sin));
	
	ip->ip_len = htons(ip->ip_len);
	ip->ip_off = htons(ip->ip_off);

	return (len);
#else
	return (sendto(i->fd, buf, len, 0,
	    (struct sockaddr *)&sin, sizeof(sin)));
#endif
}

ip_t *
ip_close(ip_t *i)
{
	if (i != NULL) {
		if (i->fd >= 0)
			close(i->fd);
		free(i);
	}
	return (NULL);
}
