/*
 * arp-bsd.c
 * 
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: arp-bsd.c 539 2005-01-23 07:36:54Z dugsong $
 */

#include "config.h"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif
#ifdef HAVE_STREAMS_ROUTE
#include <sys/stream.h>
#include <sys/stropts.h>
#endif

#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dnet.h"

struct arp_handle {
	int	fd;
	int	seq;
};

struct arpmsg {
	struct rt_msghdr	rtm;
	u_char			addrs[256];
};

arp_t *
arp_open(void)
{
	arp_t *arp;

	if ((arp = calloc(1, sizeof(*arp))) != NULL) {
#ifdef HAVE_STREAMS_ROUTE
		if ((arp->fd = open("/dev/route", O_RDWR, 0)) < 0)
#else
		if ((arp->fd = socket(PF_ROUTE, SOCK_RAW, 0)) < 0)
#endif
			return (arp_close(arp));
	}
	return (arp);
}

static int
arp_msg(arp_t *arp, struct arpmsg *msg)
{
	struct arpmsg smsg;
	int len, i = 0;
	pid_t pid;
	
	msg->rtm.rtm_version = RTM_VERSION;
	msg->rtm.rtm_seq = ++arp->seq; 
	memcpy(&smsg, msg, sizeof(smsg));
	
#ifdef HAVE_STREAMS_ROUTE
	return (ioctl(arp->fd, RTSTR_SEND, &msg->rtm));
#else
	if (write(arp->fd, &smsg, smsg.rtm.rtm_msglen) < 0) {
		if (errno != ESRCH || msg->rtm.rtm_type != RTM_DELETE)
			return (-1);
	}
	pid = getpid();
	
	/* XXX - should we only read RTM_GET responses here? */
	while ((len = read(arp->fd, msg, sizeof(*msg))) > 0) {
		if (len < (int)sizeof(msg->rtm))
			return (-1);

		if (msg->rtm.rtm_pid == pid) {
			if (msg->rtm.rtm_seq == arp->seq)
				break;
			continue;
		} else if ((i++ % 2) == 0)
			continue;
		
		/* Repeat request. */
		if (write(arp->fd, &smsg, smsg.rtm.rtm_msglen) < 0) {
			if (errno != ESRCH || msg->rtm.rtm_type != RTM_DELETE)
				return (-1);
		}
	}
	if (len < 0)
		return (-1);
	
	return (0);
#endif
}

int
arp_add(arp_t *arp, const struct arp_entry *entry)
{
	struct arpmsg msg;
	struct sockaddr_in *sin;
	struct sockaddr *sa;
	int index, type;
	
	if (entry->arp_pa.addr_type != ADDR_TYPE_IP ||
	    entry->arp_ha.addr_type != ADDR_TYPE_ETH) {
		errno = EAFNOSUPPORT;
		return (-1);
	}
	sin = (struct sockaddr_in *)msg.addrs;
	sa = (struct sockaddr *)(sin + 1);
	
	if (addr_ntos(&entry->arp_pa, (struct sockaddr *)sin) < 0)
		return (-1);
	
	memset(&msg.rtm, 0, sizeof(msg.rtm));
	msg.rtm.rtm_type = RTM_GET;
	msg.rtm.rtm_addrs = RTA_DST;
	msg.rtm.rtm_msglen = sizeof(msg.rtm) + sizeof(*sin);
	
	if (arp_msg(arp, &msg) < 0)
		return (-1);
	
	if (msg.rtm.rtm_msglen < (int)sizeof(msg.rtm) +
	    sizeof(*sin) + sizeof(*sa)) {
		errno = EADDRNOTAVAIL;
		return (-1);
	}
	if (sin->sin_addr.s_addr == entry->arp_pa.addr_ip) {
		if ((msg.rtm.rtm_flags & RTF_LLINFO) == 0 ||
		    (msg.rtm.rtm_flags & RTF_GATEWAY) != 0) {
			errno = EADDRINUSE;
			return (-1);
		}
	}
	if (sa->sa_family != AF_LINK) {
		errno = EADDRNOTAVAIL;
		return (-1);
	} else {
		index = ((struct sockaddr_dl *)sa)->sdl_index;
		type = ((struct sockaddr_dl *)sa)->sdl_type;
	}
	if (addr_ntos(&entry->arp_pa, (struct sockaddr *)sin) < 0 ||
	    addr_ntos(&entry->arp_ha, sa) < 0)
		return (-1);

	((struct sockaddr_dl *)sa)->sdl_index = index;
	((struct sockaddr_dl *)sa)->sdl_type = type;
	
	memset(&msg.rtm, 0, sizeof(msg.rtm));
	msg.rtm.rtm_type = RTM_ADD;
	msg.rtm.rtm_addrs = RTA_DST | RTA_GATEWAY;
	msg.rtm.rtm_inits = RTV_EXPIRE;
	msg.rtm.rtm_flags = RTF_HOST | RTF_STATIC;
#ifdef HAVE_SOCKADDR_SA_LEN
	msg.rtm.rtm_msglen = sizeof(msg.rtm) + sin->sin_len + sa->sa_len;
#else
	msg.rtm.rtm_msglen = sizeof(msg.rtm) + sizeof(*sin) + sizeof(*sa);
#endif
	return (arp_msg(arp, &msg));
}

int
arp_delete(arp_t *arp, const struct arp_entry *entry)
{
	struct arpmsg msg;
	struct sockaddr_in *sin;
	struct sockaddr *sa;

	if (entry->arp_pa.addr_type != ADDR_TYPE_IP) {
		errno = EAFNOSUPPORT;
		return (-1);
	}
	sin = (struct sockaddr_in *)msg.addrs;
	sa = (struct sockaddr *)(sin + 1);

	if (addr_ntos(&entry->arp_pa, (struct sockaddr *)sin) < 0)
		return (-1);

	memset(&msg.rtm, 0, sizeof(msg.rtm));
	msg.rtm.rtm_type = RTM_GET;
	msg.rtm.rtm_addrs = RTA_DST;
	msg.rtm.rtm_msglen = sizeof(msg.rtm) + sizeof(*sin);
	
	if (arp_msg(arp, &msg) < 0)
		return (-1);
	
	if (msg.rtm.rtm_msglen < (int)sizeof(msg.rtm) +
	    sizeof(*sin) + sizeof(*sa)) {
		errno = ESRCH;
		return (-1);
	}
	if (sin->sin_addr.s_addr == entry->arp_pa.addr_ip) {
		if ((msg.rtm.rtm_flags & RTF_LLINFO) == 0 ||
		    (msg.rtm.rtm_flags & RTF_GATEWAY) != 0) {
			errno = EADDRINUSE;
			return (-1);
		}
	}
	if (sa->sa_family != AF_LINK) {
		errno = ESRCH;
		return (-1);
	}
	msg.rtm.rtm_type = RTM_DELETE;
	
	return (arp_msg(arp, &msg));
}

int
arp_get(arp_t *arp, struct arp_entry *entry)
{
	struct arpmsg msg;
	struct sockaddr_in *sin;
	struct sockaddr *sa;
	
	if (entry->arp_pa.addr_type != ADDR_TYPE_IP) {
		errno = EAFNOSUPPORT;
		return (-1);
	}
	sin = (struct sockaddr_in *)msg.addrs;
	sa = (struct sockaddr *)(sin + 1);
	
	if (addr_ntos(&entry->arp_pa, (struct sockaddr *)sin) < 0)
		return (-1);
	
	memset(&msg.rtm, 0, sizeof(msg.rtm));
	msg.rtm.rtm_type = RTM_GET;
	msg.rtm.rtm_addrs = RTA_DST;
	msg.rtm.rtm_flags = RTF_LLINFO;
	msg.rtm.rtm_msglen = sizeof(msg.rtm) + sizeof(*sin);
	
	if (arp_msg(arp, &msg) < 0)
		return (-1);
	
	if (msg.rtm.rtm_msglen < (int)sizeof(msg.rtm) +
	    sizeof(*sin) + sizeof(*sa) ||
	    sin->sin_addr.s_addr != entry->arp_pa.addr_ip ||
	    sa->sa_family != AF_LINK) {
		errno = ESRCH;
		return (-1);
	}
	if (addr_ston(sa, &entry->arp_ha) < 0)
		return (-1);
	
	return (0);
}

#ifdef HAVE_SYS_SYSCTL_H
int
arp_loop(arp_t *arp, arp_handler callback, void *arg)
{
	struct arp_entry entry;
	struct rt_msghdr *rtm;
	struct sockaddr_in *sin;
	struct sockaddr *sa;
	char *buf, *lim, *next;
	size_t len;
	int ret, mib[6] = { CTL_NET, PF_ROUTE, 0, AF_INET,
			    NET_RT_FLAGS, RTF_LLINFO };

	if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0)
		return (-1);

	if (len == 0)
		return (0);

	if ((buf = malloc(len)) == NULL)
		return (-1);
	
	if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
		free(buf);
		return (-1);
	}
	lim = buf + len;
	ret = 0;
	
	for (next = buf; next < lim; next += rtm->rtm_msglen) {
		rtm = (struct rt_msghdr *)next;
		sin = (struct sockaddr_in *)(rtm + 1);
		sa = (struct sockaddr *)(sin + 1);
		
		if (addr_ston((struct sockaddr *)sin, &entry.arp_pa) < 0 ||
		    addr_ston(sa, &entry.arp_ha) < 0)
			continue;
		
		if ((ret = callback(&entry, arg)) != 0)
			break;
	}
	free(buf);
	
	return (ret);
}
#else
int
arp_loop(arp_t *arp, arp_handler callback, void *arg)
{
	errno = ENOSYS;
	return (-1);
}
#endif

arp_t *
arp_close(arp_t *arp)
{
	if (arp != NULL) {
		if (arp->fd >= 0)
			close(arp->fd);
		free(arp);
	}
	return (NULL);
}
