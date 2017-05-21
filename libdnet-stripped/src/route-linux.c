/*
 * route-linux.c
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: route-linux.c 619 2006-01-15 07:33:29Z dugsong $
 */

#include "config.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <asm/types.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <net/route.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dnet.h"

#define ADDR_ISHOST(a)	(((a)->addr_type == ADDR_TYPE_IP &&	\
			  (a)->addr_bits == IP_ADDR_BITS) ||	\
			 ((a)->addr_type == ADDR_TYPE_IP6 &&	\
			  (a)->addr_bits == IP6_ADDR_BITS))

#define PROC_ROUTE_FILE		"/proc/net/route"
#define PROC_IPV6_ROUTE_FILE	"/proc/net/ipv6_route"

struct route_handle {
	int	 fd;
	int	 nlfd;
};

route_t *
route_open(void)
{
	struct sockaddr_nl snl;
	route_t *r;

	if ((r = calloc(1, sizeof(*r))) != NULL) {
		r->fd = r->nlfd = -1;
		
		if ((r->fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
			return (route_close(r));
		
		if ((r->nlfd = socket(AF_NETLINK, SOCK_RAW,
			 NETLINK_ROUTE)) < 0)
			return (route_close(r));
		
		memset(&snl, 0, sizeof(snl));
		snl.nl_family = AF_NETLINK;
		
		if (bind(r->nlfd, (struct sockaddr *)&snl, sizeof(snl)) < 0)
			return (route_close(r));
	}
	return (r);
}

int
route_add(route_t *r, const struct route_entry *entry)
{
	struct rtentry rt;
	struct addr dst;

	memset(&rt, 0, sizeof(rt));
	rt.rt_flags = RTF_UP | RTF_GATEWAY;

	if (ADDR_ISHOST(&entry->route_dst)) {
		rt.rt_flags |= RTF_HOST;
		memcpy(&dst, &entry->route_dst, sizeof(dst));
	} else
		addr_net(&entry->route_dst, &dst);
	
	if (addr_ntos(&dst, &rt.rt_dst) < 0 ||
	    addr_ntos(&entry->route_gw, &rt.rt_gateway) < 0 ||
	    addr_btos(entry->route_dst.addr_bits, &rt.rt_genmask) < 0)
		return (-1);
	
	return (ioctl(r->fd, SIOCADDRT, &rt));
}

int
route_delete(route_t *r, const struct route_entry *entry)
{
	struct rtentry rt;
	struct addr dst;
	
	memset(&rt, 0, sizeof(rt));
	rt.rt_flags = RTF_UP;

	if (ADDR_ISHOST(&entry->route_dst)) {
		rt.rt_flags |= RTF_HOST;
		memcpy(&dst, &entry->route_dst, sizeof(dst));
	} else
		addr_net(&entry->route_dst, &dst);
	
	if (addr_ntos(&dst, &rt.rt_dst) < 0 ||
	    addr_btos(entry->route_dst.addr_bits, &rt.rt_genmask) < 0)
		return (-1);
	
	return (ioctl(r->fd, SIOCDELRT, &rt));
}

int
route_get(route_t *r, struct route_entry *entry)
{
	static int seq;
	struct nlmsghdr *nmsg;
	struct rtmsg *rmsg;
	struct rtattr *rta;
	struct sockaddr_nl snl;
	struct iovec iov;
	struct msghdr msg;
	u_char buf[512];
	int i, af, alen;

	switch (entry->route_dst.addr_type) {
	case ADDR_TYPE_IP:
		af = AF_INET;
		alen = IP_ADDR_LEN;
		break;
	case ADDR_TYPE_IP6:
		af = AF_INET6;
		alen = IP6_ADDR_LEN;
		break;
	default:
		errno = EINVAL;
		return (-1);
	}
	memset(buf, 0, sizeof(buf));

	nmsg = (struct nlmsghdr *)buf;
	nmsg->nlmsg_len = NLMSG_LENGTH(sizeof(*nmsg)) + RTA_LENGTH(alen);
	nmsg->nlmsg_flags = NLM_F_REQUEST;
	nmsg->nlmsg_type = RTM_GETROUTE;
	nmsg->nlmsg_seq = ++seq;

	rmsg = (struct rtmsg *)(nmsg + 1);
	rmsg->rtm_family = af;
	rmsg->rtm_dst_len = entry->route_dst.addr_bits;
	
	rta = RTM_RTA(rmsg);
	rta->rta_type = RTA_DST;
	rta->rta_len = RTA_LENGTH(alen);

	/* XXX - gross hack for default route */
	if (af == AF_INET && entry->route_dst.addr_ip == IP_ADDR_ANY) {
		i = htonl(0x60060606);
		memcpy(RTA_DATA(rta), &i, alen);
	} else
		memcpy(RTA_DATA(rta), entry->route_dst.addr_data8, alen);
	
	memset(&snl, 0, sizeof(snl));
	snl.nl_family = AF_NETLINK;

	iov.iov_base = nmsg;
	iov.iov_len = nmsg->nlmsg_len;
	
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &snl;
	msg.msg_namelen = sizeof(snl);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	
	if (sendmsg(r->nlfd, &msg, 0) < 0)
		return (-1);

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	
	if ((i = recvmsg(r->nlfd, &msg, 0)) <= 0)
		return (-1);

	if (nmsg->nlmsg_len < (int)sizeof(*nmsg) || nmsg->nlmsg_len > i ||
	    nmsg->nlmsg_seq != seq) {
		errno = EINVAL;
		return (-1);
	}
	if (nmsg->nlmsg_type == NLMSG_ERROR)
		return (-1);
	
	i -= NLMSG_LENGTH(sizeof(*nmsg));
	
	entry->route_gw.addr_type = ADDR_TYPE_NONE;
	entry->intf_name[0] = '\0';
	for (rta = RTM_RTA(rmsg); RTA_OK(rta, i); rta = RTA_NEXT(rta, i)) {
		if (rta->rta_type == RTA_GATEWAY) {
			entry->route_gw.addr_type = entry->route_dst.addr_type;
			memcpy(entry->route_gw.addr_data8, RTA_DATA(rta), alen);
			entry->route_gw.addr_bits = alen * 8;
		} else if (rta->rta_type == RTA_OIF) {
			char ifbuf[IFNAMSIZ];
			char *p;
			int intf_index;

			intf_index = *(int *) RTA_DATA(rta);
			p = if_indextoname(intf_index, ifbuf);
			if (p == NULL)
				return (-1);
			strlcpy(entry->intf_name, ifbuf, sizeof(entry->intf_name));
		}
	}
	if (entry->route_gw.addr_type == ADDR_TYPE_NONE) {
		errno = ESRCH;
		return (-1);
	}
	
	return (0);
}

int
route_loop(route_t *r, route_handler callback, void *arg)
{
	FILE *fp;
	struct route_entry entry;
	char buf[BUFSIZ];
	char ifbuf[16];
	int ret = 0;

	if ((fp = fopen(PROC_ROUTE_FILE, "r")) != NULL) {
		int i, iflags, refcnt, use, metric, mss, win, irtt;
		uint32_t mask;
		
		while (fgets(buf, sizeof(buf), fp) != NULL) {
			i = sscanf(buf, "%15s %X %X %X %d %d %d %X %d %d %d\n",
			    ifbuf, &entry.route_dst.addr_ip,
			    &entry.route_gw.addr_ip, &iflags, &refcnt, &use,
			    &metric, &mask, &mss, &win, &irtt);
			
			if (i < 11 || !(iflags & RTF_UP))
				continue;
		
			strlcpy(entry.intf_name, ifbuf, sizeof(entry.intf_name));

			entry.route_dst.addr_type = entry.route_gw.addr_type =
			    ADDR_TYPE_IP;
		
			if (addr_mtob(&mask, IP_ADDR_LEN,
				&entry.route_dst.addr_bits) < 0)
				continue;
			
			entry.route_gw.addr_bits = IP_ADDR_BITS;
			entry.metric = metric;
			
			if ((ret = callback(&entry, arg)) != 0)
				break;
		}
		fclose(fp);
	}
	if (ret == 0 && (fp = fopen(PROC_IPV6_ROUTE_FILE, "r")) != NULL) {
		char s[33], d[8][5], n[8][5];
		int i, iflags, metric;
		u_int slen, dlen;
		
		while (fgets(buf, sizeof(buf), fp) != NULL) {
			i = sscanf(buf, "%04s%04s%04s%04s%04s%04s%04s%04s %02x "
			    "%32s %02x %04s%04s%04s%04s%04s%04s%04s%04s "
			    "%x %*x %*x %x %15s",
			    d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7],
			    &dlen, s, &slen,
			    n[0], n[1], n[2], n[3], n[4], n[5], n[6], n[7],
			    &metric, &iflags, ifbuf);
			
			if (i < 21 || !(iflags & RTF_UP))
				continue;

			strlcpy(entry.intf_name, ifbuf, sizeof(entry.intf_name));

			snprintf(buf, sizeof(buf), "%s:%s:%s:%s:%s:%s:%s:%s/%d",
			    d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7],
			    dlen);
			addr_aton(buf, &entry.route_dst);
			snprintf(buf, sizeof(buf), "%s:%s:%s:%s:%s:%s:%s:%s/%d",
			    n[0], n[1], n[2], n[3], n[4], n[5], n[6], n[7],
			    IP6_ADDR_BITS);
			addr_aton(buf, &entry.route_gw);
			entry.metric = metric;
			
			if ((ret = callback(&entry, arg)) != 0)
				break;
		}
		fclose(fp);
	}
	return (ret);
}

route_t *
route_close(route_t *r)
{
	if (r != NULL) {
		if (r->fd >= 0)
			close(r->fd);
		if (r->nlfd >= 0)
			close(r->nlfd);
		free(r);
	}
	return (NULL);
}
