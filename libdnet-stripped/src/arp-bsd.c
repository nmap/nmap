/*
 * arp-bsd.c
 * 
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id$
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

/* NetBSD 10+ removed RTF_LLINFO */
#ifndef RTF_LLINFO
#define RTF_LLINFO 0
#endif

#if defined(RT_ROUNDUP) && defined(__NetBSD__)
/* NetBSD defines this macro rounding to 64-bit boundaries.
   http://fxr.watson.org/fxr/ident?v=NETBSD;i=RT_ROUNDUP */
#define ROUNDUP(a) RT_ROUNDUP(a)
#else
/* Unix Network Programming, 3rd edition says that sockaddr structures in
   rt_msghdr should be padded so their addresses start on a multiple of
   sizeof(u_long). But on 64-bit Mac OS X 10.6 at least, this is false. Apple's
   netstat code uses 4-byte padding, not 8-byte. This is relevant for IPv6
   addresses, for which sa_len == 28.
   http://www.opensource.apple.com/source/network_cmds/network_cmds-329.2.2/netstat.tproj/route.c */
#ifdef __APPLE__
#define RT_MSGHDR_ALIGNMENT sizeof(uint32_t)
#else
#define RT_MSGHDR_ALIGNMENT sizeof(unsigned long)
#endif
#define ROUNDUP(a) \
	((a) > 0 ? (1 + (((a) - 1) | (RT_MSGHDR_ALIGNMENT - 1))) : RT_MSGHDR_ALIGNMENT)
#endif

#ifdef HAVE_SOCKADDR_SA_LEN
#define SA_LEN(s) ((s)->sa_len)
#else
#define SA_LEN(s) (sizeof(*(s)))
#endif
#define NEXTSA(s) \
	((struct sockaddr *)((u_char *)(s) + ROUNDUP(SA_LEN(s))))

struct arp_handle {
	int	fd;
	int	seq;
};

struct arpmsg {
	struct rt_msghdr	rtm;
	u_char			addrs[512];
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

static int sockaddr_equal_addr(const struct sockaddr *sa, const struct addr *b)
{
	if (sa->sa_family == AF_INET) {
		return (b->addr_type == ADDR_TYPE_IP && 
				((struct sockaddr_in *)sa)->sin_addr.s_addr == b->addr_ip);
	}
	else if (sa->sa_family == AF_INET6) {
		return (b->addr_type == ADDR_TYPE_IP6 &&
				0 == memcmp(
					((struct sockaddr_in6 *)sa)->sin6_addr.s6_addr,
					b->addr_ip6.data,
					IP6_ADDR_LEN));
	}
	return 0;
}

int
arp_add(arp_t *arp, const struct arp_entry *entry)
{
	struct arpmsg msg;
	struct sockaddr *sin;
	struct sockaddr *sa;
	int index, type;
	
	if ((entry->arp_pa.addr_type != ADDR_TYPE_IP && 
	     entry->arp_pa.addr_type != ADDR_TYPE_IP6) ||
	    entry->arp_ha.addr_type != ADDR_TYPE_ETH) {
		errno = EAFNOSUPPORT;
		return (-1);
	}
	sin = (struct sockaddr *)msg.addrs;
	
	if (addr_ntos(&entry->arp_pa, (struct sockaddr *)sin) < 0)
		return (-1);
	
	sa = NEXTSA(sin);
	memset(&msg.rtm, 0, sizeof(msg.rtm));
	msg.rtm.rtm_type = RTM_GET;
	msg.rtm.rtm_addrs = RTA_DST;
	msg.rtm.rtm_msglen = sizeof(msg.rtm) + ROUNDUP(SA_LEN(sin));
	msg.rtm.rtm_msglen = ((char *)sin - (char *)&msg) + ROUNDUP(SA_LEN(sin));
	
	if (arp_msg(arp, &msg) < 0)
		return (-1);
	
	if (msg.rtm.rtm_msglen < (int)sizeof(msg.rtm) +
	    ROUNDUP(SA_LEN(sin)) + SA_LEN(sa)) {
		errno = EADDRNOTAVAIL;
		return (-1);
	}
    if (sockaddr_equal_addr(sin, &entry->arp_pa)) {
        if ((RTF_LLINFO && ((msg.rtm.rtm_flags & RTF_LLINFO) == 0)) ||
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
	msg.rtm.rtm_msglen = sizeof(msg.rtm) + ROUNDUP(SA_LEN(sin)) + ROUNDUP(SA_LEN(sa));

	return (arp_msg(arp, &msg));
}

int
arp_delete(arp_t *arp, const struct arp_entry *entry)
{
	struct arpmsg msg;
	struct sockaddr *sin;
	struct sockaddr *sa;

	if (entry->arp_pa.addr_type != ADDR_TYPE_IP && 
	    entry->arp_pa.addr_type != ADDR_TYPE_IP6) {
		errno = EAFNOSUPPORT;
		return (-1);
	}
	sin = (struct sockaddr *)msg.addrs;

	if (addr_ntos(&entry->arp_pa, (struct sockaddr *)sin) < 0)
		return (-1);

	sa = NEXTSA(sin);
	memset(&msg.rtm, 0, sizeof(msg.rtm));
	msg.rtm.rtm_type = RTM_GET;
	msg.rtm.rtm_addrs = RTA_DST;
	msg.rtm.rtm_msglen = sizeof(msg.rtm) + ROUNDUP(SA_LEN(sin));
	
	if (arp_msg(arp, &msg) < 0)
		return (-1);
	
	if (msg.rtm.rtm_msglen < (int)sizeof(msg.rtm) +
	    ROUNDUP(SA_LEN(sin)) + SA_LEN(sa)) {
		errno = ESRCH;
		return (-1);
	}
	if (sockaddr_equal_addr(sin, &entry->arp_pa)) {
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
	struct sockaddr *sin;
	struct sockaddr *sa;
	
	if (entry->arp_pa.addr_type != ADDR_TYPE_IP && 
	    entry->arp_pa.addr_type != ADDR_TYPE_IP6) {
		errno = EAFNOSUPPORT;
		return (-1);
	}
	sin = (struct sockaddr *)msg.addrs;
	
	if (addr_ntos(&entry->arp_pa, (struct sockaddr *)sin) < 0)
		return (-1);

	sa = NEXTSA(sin);
	memset(&msg.rtm, 0, sizeof(msg.rtm));
	msg.rtm.rtm_type = RTM_GET;
	msg.rtm.rtm_addrs = RTA_DST;
	msg.rtm.rtm_flags = RTF_LLINFO;
	msg.rtm.rtm_msglen = sizeof(msg.rtm) + ROUNDUP(SA_LEN(sin));
	
	if (arp_msg(arp, &msg) < 0)
		return (-1);
	
	if (msg.rtm.rtm_msglen < (int)sizeof(msg.rtm) +
	    ROUNDUP(SA_LEN(sin)) + SA_LEN(sa) ||
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
	struct sockaddr *sin;
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
		sin = (struct sockaddr *)(rtm + 1);
		sa = NEXTSA(sin);
		
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
