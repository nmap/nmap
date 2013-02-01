/*
 * route-hpux.c
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: route-hpux.c 483 2004-01-14 04:52:11Z dugsong $
 */

#include "config.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mib.h>
#include <sys/socket.h>

#include <net/route.h>

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

struct route_handle {
	int	fd;
};

route_t *
route_open(void)
{
	route_t *r;

	if ((r = calloc(1, sizeof(*r))) != NULL) {
		if ((r->fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
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
	    addr_btom(entry->route_dst.addr_bits, &rt.rt_subnetmask,
		IP_ADDR_LEN) < 0)
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
	    addr_btom(entry->route_dst.addr_bits, &rt.rt_subnetmask,
		IP_ADDR_LEN) < 0)
		return (-1);
	
	return (ioctl(r->fd, SIOCDELRT, &rt));
}

int
route_get(route_t *r, struct route_entry *entry)
{
	struct rtreq rtr;

	memset(&rtr, 0, sizeof(rtr));

	/* XXX - gross hack for default route */
	if (entry->route_dst.addr_ip == IP_ADDR_ANY) {
		rtr.rtr_destaddr = htonl(0x60060606);
		rtr.rtr_subnetmask = 0xffffffff;
	} else {
		memcpy(&rtr.rtr_destaddr, &entry->route_dst.addr_ip,
		    IP_ADDR_LEN);
		if (entry->route_dst.addr_bits < IP_ADDR_BITS)
			addr_btom(entry->route_dst.addr_bits,
			    &rtr.rtr_subnetmask, IP_ADDR_LEN);
	}
	if (ioctl(r->fd, SIOCGRTENTRY, &rtr) < 0)
		return (-1);

	if (rtr.rtr_gwayaddr == 0) {
		errno = ESRCH;
		return (-1);
	}
	entry->intf_name[0] = '\0';
	entry->route_gw.addr_type = ADDR_TYPE_IP;
	entry->route_gw.addr_bits = IP_ADDR_BITS;
	memcpy(&entry->route_gw.addr_ip, &rtr.rtr_gwayaddr, IP_ADDR_LEN);
	entry->metric = 0;
	
	return (0);
}

#define MAX_RTENTRIES	256	/* XXX */

int
route_loop(route_t *r, route_handler callback, void *arg)
{
	struct nmparms nm;
	struct route_entry entry;
	mib_ipRouteEnt rtentries[MAX_RTENTRIES];
	int fd, i, n, ret;
	
	if ((fd = open_mib("/dev/ip", O_RDWR, 0 /* XXX */, 0)) < 0)
		return (-1);
	
	nm.objid = ID_ipRouteTable;
	nm.buffer = rtentries;
	n = sizeof(rtentries);
	nm.len = &n;
	
	if (get_mib_info(fd, &nm) < 0) {
		close_mib(fd);
		return (-1);
	}
	close_mib(fd);

	n /= sizeof(*rtentries);
	ret = 0;
	
	for (i = 0; i < n; i++) {
		if (rtentries[i].Type != NMDIRECT &&
		    rtentries[i].Type != NMREMOTE)
			continue;
		
		entry.intf_name[0] = '\0';
		entry.route_dst.addr_type = entry.route_gw.addr_type = ADDR_TYPE_IP;
		entry.route_dst.addr_bits = entry.route_gw.addr_bits = IP_ADDR_BITS;
		entry.route_dst.addr_ip = rtentries[i].Dest;
		addr_mtob(&rtentries[i].Mask, IP_ADDR_LEN,
		    &entry.route_dst.addr_bits);
		entry.route_gw.addr_ip = rtentries[i].NextHop;
		entry.metric = 0;

		if ((ret = callback(&entry, arg)) != 0)
			break;
	}
	return (ret);
}

route_t *
route_close(route_t *r)
{
	if (r != NULL) {
		if (r->fd >= 0)
			close(r->fd);
		free(r);
	}
	return (NULL);
}
