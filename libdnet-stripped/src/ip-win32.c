/*
 * ip-win32.c
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id: ip-win32.c 547 2005-01-25 21:30:40Z dugsong $
 */

#ifdef _WIN32
#include "dnet_winconfig.h"
#else
#include "config.h"
#endif

#include <ws2tcpip.h>

#include <errno.h>
#include <stdlib.h>

#include "dnet.h"

struct ip_handle {
	WSADATA			wsdata;
	SOCKET			fd;
	struct sockaddr_in	sin;
};

ip_t *
ip_open(void)
{
	BOOL on;
	ip_t *ip;

	if ((ip = calloc(1, sizeof(*ip))) != NULL) {
		if (WSAStartup(MAKEWORD(2, 2), &ip->wsdata) != 0) {
			free(ip);
			return (NULL);
		}
		if ((ip->fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) ==
		    INVALID_SOCKET)
			return (ip_close(ip));
		
		on = TRUE;
		if (setsockopt(ip->fd, IPPROTO_IP, IP_HDRINCL,
			(const char *)&on, sizeof(on)) == SOCKET_ERROR) {
			SetLastError(ERROR_NETWORK_ACCESS_DENIED);
			return (ip_close(ip));
		}
		ip->sin.sin_family = AF_INET;
		ip->sin.sin_port = htons(666);
	}
	return (ip);
}

ssize_t
ip_send(ip_t *ip, const void *buf, size_t len)
{
	struct ip_hdr *hdr = (struct ip_hdr *)buf;
	
	ip->sin.sin_addr.s_addr = hdr->ip_src;
	
	if ((len = sendto(ip->fd, (const char *)buf, (int)len, 0,
	    (struct sockaddr *)&ip->sin, sizeof(ip->sin))) != SOCKET_ERROR)
		return (ssize_t)(len);
	
	return (-1);
}

ip_t *
ip_close(ip_t *ip)
{
	if (ip != NULL) {
		WSACleanup();
		if (ip->fd != INVALID_SOCKET)
			closesocket(ip->fd);
		free(ip);
	}
	return (NULL);
}
