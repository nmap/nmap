/*
 * intf.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: intf.c 616 2006-01-09 07:09:49Z dugsong $
 */

#ifdef _WIN32
#include "dnet_winconfig.h"
#else
#include "config.h"
#endif

#include <sys/param.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_SOCKIO_H
# include <sys/sockio.h>
#endif
/* XXX - AIX */
#ifndef IP_MULTICAST
# define IP_MULTICAST
#endif
#include <net/if.h>
#ifdef HAVE_NET_IF_VAR_H
# include <net/if_var.h>
#endif
#undef IP_MULTICAST
/* XXX - IPv6 ioctls */
#ifdef HAVE_NETINET_IN_VAR_H
# include <netinet/in.h>
# include <netinet/in_var.h>
#endif
#ifdef HAVE_NETINET_IN6_VAR_H
# include <sys/protosw.h>
# include <netinet/in6_var.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dnet.h"

/* XXX - Tru64 */
#if defined(SIOCRIPMTU) && defined(SIOCSIPMTU)
# define SIOCGIFMTU	SIOCRIPMTU
# define SIOCSIFMTU	SIOCSIPMTU
#endif

/* XXX - HP-UX */
#if defined(SIOCADDIFADDR) && defined(SIOCDELIFADDR)
# define SIOCAIFADDR	SIOCADDIFADDR
# define SIOCDIFADDR	SIOCDELIFADDR
#endif

/* XXX - HP-UX, Solaris */
#if !defined(ifr_mtu) && defined(ifr_metric)
# define ifr_mtu	ifr_metric
#endif

#ifdef HAVE_SOCKADDR_SA_LEN
# define max(a, b) ((a) > (b) ? (a) : (b))
# define NEXTIFR(i)	((struct ifreq *) \
				max((u_char *)i + sizeof(struct ifreq), \
				(u_char *)&i->ifr_addr + i->ifr_addr.sa_len))
#else
# define NEXTIFR(i)	(i + 1)
#endif

#define NEXTLIFR(i)	(i + 1)

/* XXX - superset of ifreq, for portable SIOC{A,D}IFADDR */
struct dnet_ifaliasreq {
	char		ifra_name[IFNAMSIZ];
	union {
		struct sockaddr ifrau_addr;
		int             ifrau_align;
	} ifra_ifrau;
#ifndef ifra_addr
#define ifra_addr      ifra_ifrau.ifrau_addr
#endif
	struct sockaddr ifra_brdaddr;
	struct sockaddr ifra_mask;
	int		ifra_cookie;	/* XXX - IRIX!@#$ */
};

struct intf_handle {
	int		fd;
	int		fd6;
	struct ifconf	ifc;
#ifdef SIOCGLIFCONF
	struct lifconf	lifc;
#endif
	u_char		ifcbuf[4192];
};

static int
intf_flags_to_iff(u_short flags, int iff)
{
	if (flags & INTF_FLAG_UP)
		iff |= IFF_UP;
	else
		iff &= ~IFF_UP;
	if (flags & INTF_FLAG_NOARP)
		iff |= IFF_NOARP;
	else
		iff &= ~IFF_NOARP;
	
	return (iff);
}

static u_int
intf_iff_to_flags(uint64_t iff)
{
	u_int n = 0;

	if (iff & IFF_UP)
		n |= INTF_FLAG_UP;	
	if (iff & IFF_LOOPBACK)
		n |= INTF_FLAG_LOOPBACK;
	if (iff & IFF_POINTOPOINT)
		n |= INTF_FLAG_POINTOPOINT;
	if (iff & IFF_NOARP)
		n |= INTF_FLAG_NOARP;
	if (iff & IFF_BROADCAST)
		n |= INTF_FLAG_BROADCAST;
	if (iff & IFF_MULTICAST)
		n |= INTF_FLAG_MULTICAST;
#ifdef IFF_IPMP
	/* Unset the BROADCAST and MULTICAST flags from Solaris IPMP interfaces,
	 * otherwise _intf_set_type will think they are INTF_TYPE_ETH. */
	if (iff & IFF_IPMP)
		n &= ~(INTF_FLAG_BROADCAST | INTF_FLAG_MULTICAST);
#endif

	return (n);
}

intf_t *
intf_open(void)
{
	intf_t *intf;
	int one = 1;
	
	if ((intf = calloc(1, sizeof(*intf))) != NULL) {
		intf->fd = intf->fd6 = -1;
		
		if ((intf->fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
			return (intf_close(intf));

		setsockopt(intf->fd, SOL_SOCKET, SO_BROADCAST,
			(const char *) &one, sizeof(one));

#if defined(SIOCGLIFCONF) || defined(SIOCGIFNETMASK_IN6) || defined(SIOCGIFNETMASK6)
		if ((intf->fd6 = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
#  ifdef EPROTONOSUPPORT
			if (errno != EPROTONOSUPPORT)
#  endif
				return (intf_close(intf));
		}
#endif
	}
	return (intf);
}

static int
_intf_delete_addrs(intf_t *intf, struct intf_entry *entry)
{
#if defined(SIOCDIFADDR)
	struct dnet_ifaliasreq ifra;
	
	memset(&ifra, 0, sizeof(ifra));
	strlcpy(ifra.ifra_name, entry->intf_name, sizeof(ifra.ifra_name));
	if (entry->intf_addr.addr_type == ADDR_TYPE_IP) {
		addr_ntos(&entry->intf_addr, &ifra.ifra_addr);
		ioctl(intf->fd, SIOCDIFADDR, &ifra);
	}
	if (entry->intf_dst_addr.addr_type == ADDR_TYPE_IP) {
		addr_ntos(&entry->intf_dst_addr, &ifra.ifra_addr);
		ioctl(intf->fd, SIOCDIFADDR, &ifra);
	}
#elif defined(SIOCLIFREMOVEIF)
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, entry->intf_name, sizeof(ifr.ifr_name));
	/* XXX - overloading Solaris lifreq with ifreq */
	ioctl(intf->fd, SIOCLIFREMOVEIF, &ifr);
#endif
	return (0);
}

static int
_intf_delete_aliases(intf_t *intf, struct intf_entry *entry)
{
	int i;
#if defined(SIOCDIFADDR) && !defined(__linux__)	/* XXX - see Linux below */
	struct dnet_ifaliasreq ifra;
	
	memset(&ifra, 0, sizeof(ifra));
	strlcpy(ifra.ifra_name, entry->intf_name, sizeof(ifra.ifra_name));
	
	for (i = 0; i < (int)entry->intf_alias_num; i++) {
		addr_ntos(&entry->intf_alias_addrs[i], &ifra.ifra_addr);
		ioctl(intf->fd, SIOCDIFADDR, &ifra);
	}
#else
	struct ifreq ifr;
	
	for (i = 0; i < entry->intf_alias_num; i++) {
		snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s:%d",
		    entry->intf_name, i + 1);
# ifdef SIOCLIFREMOVEIF
		/* XXX - overloading Solaris lifreq with ifreq */
		ioctl(intf->fd, SIOCLIFREMOVEIF, &ifr);
# else
		/* XXX - only need to set interface down on Linux */
		ifr.ifr_flags = 0;
		ioctl(intf->fd, SIOCSIFFLAGS, &ifr);
# endif
	}
#endif
	return (0);
}

static int
_intf_add_aliases(intf_t *intf, const struct intf_entry *entry)
{
	int i;
#ifdef SIOCAIFADDR
	struct dnet_ifaliasreq ifra;
	struct addr bcast;
	
	memset(&ifra, 0, sizeof(ifra));
	strlcpy(ifra.ifra_name, entry->intf_name, sizeof(ifra.ifra_name));
	
	for (i = 0; i < (int)entry->intf_alias_num; i++) {
		if (entry->intf_alias_addrs[i].addr_type != ADDR_TYPE_IP)
			continue;
		
		if (addr_ntos(&entry->intf_alias_addrs[i],
		    &ifra.ifra_addr) < 0)
			return (-1);
		addr_bcast(&entry->intf_alias_addrs[i], &bcast);
		addr_ntos(&bcast, &ifra.ifra_brdaddr);
		addr_btos(entry->intf_alias_addrs[i].addr_bits,
		    &ifra.ifra_mask);
		
		if (ioctl(intf->fd, SIOCAIFADDR, &ifra) < 0)
			return (-1);
	}
#else
	struct ifreq ifr;
	int n = 1;
	
	for (i = 0; i < entry->intf_alias_num; i++) {
		if (entry->intf_alias_addrs[i].addr_type != ADDR_TYPE_IP)
			continue;
		
		snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s:%d",
		    entry->intf_name, n++);
# ifdef SIOCLIFADDIF
		if (ioctl(intf->fd, SIOCLIFADDIF, &ifr) < 0)
			return (-1);
# endif
		if (addr_ntos(&entry->intf_alias_addrs[i], &ifr.ifr_addr) < 0)
			return (-1);
		if (ioctl(intf->fd, SIOCSIFADDR, &ifr) < 0)
			return (-1);
	}
	strlcpy(ifr.ifr_name, entry->intf_name, sizeof(ifr.ifr_name));
#endif
	return (0);
}

int
intf_set(intf_t *intf, const struct intf_entry *entry)
{
	struct ifreq ifr;
	struct intf_entry *orig;
	struct addr bcast;
	u_char buf[BUFSIZ];
	
	orig = (struct intf_entry *)buf;
	orig->intf_len = sizeof(buf);
	strcpy(orig->intf_name, entry->intf_name);
	
	if (intf_get(intf, orig) < 0)
		return (-1);
	
	/* Delete any existing aliases. */
	if (_intf_delete_aliases(intf, orig) < 0)
		return (-1);

	/* Delete any existing addrs. */
	if (_intf_delete_addrs(intf, orig) < 0)
		return (-1);
	
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, entry->intf_name, sizeof(ifr.ifr_name));
	
	/* Set interface MTU. */
	if (entry->intf_mtu != 0) {
		ifr.ifr_mtu = entry->intf_mtu;
#ifdef SIOCSIFMTU
		if (ioctl(intf->fd, SIOCSIFMTU, &ifr) < 0)
#endif
			return (-1);
	}
	/* Set interface address. */
	if (entry->intf_addr.addr_type == ADDR_TYPE_IP) {
#if defined(BSD) && !defined(__OPENBSD__)
		/* XXX - why must this happen before SIOCSIFADDR? */
		if (addr_btos(entry->intf_addr.addr_bits,
		    &ifr.ifr_addr) == 0) {
			if (ioctl(intf->fd, SIOCSIFNETMASK, &ifr) < 0)
				return (-1);
		}
#endif
		if (addr_ntos(&entry->intf_addr, &ifr.ifr_addr) < 0)
			return (-1);
		if (ioctl(intf->fd, SIOCSIFADDR, &ifr) < 0 && errno != EEXIST)
			return (-1);
		
		if (addr_btos(entry->intf_addr.addr_bits, &ifr.ifr_addr) == 0
#ifdef __linux__
		    && entry->intf_addr.addr_ip != 0
#endif
		    ) {
			if (ioctl(intf->fd, SIOCSIFNETMASK, &ifr) < 0)
				return (-1);
		}
		if (addr_bcast(&entry->intf_addr, &bcast) == 0) {
			if (addr_ntos(&bcast, &ifr.ifr_broadaddr) == 0) {
				/* XXX - ignore error from non-broadcast ifs */
				ioctl(intf->fd, SIOCSIFBRDADDR, &ifr);
			}
		}
	}
	/* Set link-level address. */
	if (entry->intf_link_addr.addr_type == ADDR_TYPE_ETH &&
	    addr_cmp(&entry->intf_link_addr, &orig->intf_link_addr) != 0) {
#if defined(SIOCSIFHWADDR)
		if (addr_ntos(&entry->intf_link_addr, &ifr.ifr_hwaddr) < 0)
			return (-1);
		if (ioctl(intf->fd, SIOCSIFHWADDR, &ifr) < 0)
			return (-1);
#elif defined (SIOCSIFLLADDR)
		memcpy(ifr.ifr_addr.sa_data, &entry->intf_link_addr.addr_eth,
		    ETH_ADDR_LEN);
		ifr.ifr_addr.sa_len = ETH_ADDR_LEN;
		if (ioctl(intf->fd, SIOCSIFLLADDR, &ifr) < 0)
			return (-1);
#else
		eth_t *eth;

		if ((eth = eth_open(entry->intf_name)) == NULL)
			return (-1);
		if (eth_set(eth, &entry->intf_link_addr.addr_eth) < 0) {
			eth_close(eth);
			return (-1);
		}
		eth_close(eth);
#endif
	}
	/* Set point-to-point destination. */
	if (entry->intf_dst_addr.addr_type == ADDR_TYPE_IP) {
		if (addr_ntos(&entry->intf_dst_addr, &ifr.ifr_dstaddr) < 0)
			return (-1);
		if (ioctl(intf->fd, SIOCSIFDSTADDR, &ifr) < 0 &&
		    errno != EEXIST)
			return (-1);
	}
	/* Add aliases. */
	if (_intf_add_aliases(intf, entry) < 0)
		return (-1);
	
	/* Set interface flags. */
	if (ioctl(intf->fd, SIOCGIFFLAGS, &ifr) < 0)
		return (-1);
	
	ifr.ifr_flags = intf_flags_to_iff(entry->intf_flags, ifr.ifr_flags);
	
	if (ioctl(intf->fd, SIOCSIFFLAGS, &ifr) < 0)
		return (-1);
	
	return (0);
}

/* XXX - this is total crap. how to do this without walking ifnet? */
static void
_intf_set_type(struct intf_entry *entry)
{
	if ((entry->intf_flags & INTF_FLAG_LOOPBACK) != 0)
		entry->intf_type = INTF_TYPE_LOOPBACK;
	else if ((entry->intf_flags & INTF_FLAG_BROADCAST) != 0)
		entry->intf_type = INTF_TYPE_ETH;
	else if ((entry->intf_flags & INTF_FLAG_POINTOPOINT) != 0)
		entry->intf_type = INTF_TYPE_TUN;
	else
		entry->intf_type = INTF_TYPE_OTHER;
}

#ifdef SIOCGLIFCONF
int
_intf_get_noalias(intf_t *intf, struct intf_entry *entry)
{
	struct lifreq lifr;
	int fd;

	/* Get interface index. */
	entry->intf_index = if_nametoindex(entry->intf_name);
	if (entry->intf_index == 0)
		return (-1);

	strlcpy(lifr.lifr_name, entry->intf_name, sizeof(lifr.lifr_name));

	/* Get interface flags. Here he also check whether we need to use fd or
	 * fd6 in the rest of the function. Using the wrong address family in
	 * the ioctls gives ENXIO on Solaris. */
	if (ioctl(intf->fd, SIOCGLIFFLAGS, &lifr) >= 0)
		fd = intf->fd;
	else if (intf->fd6 != -1 && ioctl(intf->fd6, SIOCGLIFFLAGS, &lifr) >= 0)
		fd = intf->fd6;
	else
		return (-1);
	
	entry->intf_flags = intf_iff_to_flags(lifr.lifr_flags);
	_intf_set_type(entry);
	
	/* Get interface MTU. */
#ifdef SIOCGLIFMTU
	if (ioctl(fd, SIOCGLIFMTU, &lifr) < 0)
#endif
		return (-1);
	entry->intf_mtu = lifr.lifr_mtu;

	entry->intf_addr.addr_type = entry->intf_dst_addr.addr_type =
	    entry->intf_link_addr.addr_type = ADDR_TYPE_NONE;
	
	/* Get primary interface address. */
	if (ioctl(fd, SIOCGLIFADDR, &lifr) == 0) {
		addr_ston((struct sockaddr *)&lifr.lifr_addr, &entry->intf_addr);
		if (ioctl(fd, SIOCGLIFNETMASK, &lifr) < 0)
			return (-1);
		addr_stob((struct sockaddr *)&lifr.lifr_addr, &entry->intf_addr.addr_bits);
	}
	/* Get other addresses. */
	if (entry->intf_type == INTF_TYPE_TUN) {
		if (ioctl(fd, SIOCGLIFDSTADDR, &lifr) == 0) {
			if (addr_ston((struct sockaddr *)&lifr.lifr_addr,
			    &entry->intf_dst_addr) < 0)
				return (-1);
		}
	} else if (entry->intf_type == INTF_TYPE_ETH) {
		eth_t *eth;
		
		if ((eth = eth_open(entry->intf_name)) != NULL) {
			if (!eth_get(eth, &entry->intf_link_addr.addr_eth)) {
				entry->intf_link_addr.addr_type =
				    ADDR_TYPE_ETH;
				entry->intf_link_addr.addr_bits =
				    ETH_ADDR_BITS;
			}
			eth_close(eth);
		}
	}
	return (0);
}
#else
static int
_intf_get_noalias(intf_t *intf, struct intf_entry *entry)
{
	struct ifreq ifr;

	/* Get interface index. */
	entry->intf_index = if_nametoindex(entry->intf_name);
	if (entry->intf_index == 0)
		return (-1);

	strlcpy(ifr.ifr_name, entry->intf_name, sizeof(ifr.ifr_name));

	/* Get interface flags. */
	if (ioctl(intf->fd, SIOCGIFFLAGS, &ifr) < 0)
		return (-1);
	
	entry->intf_flags = intf_iff_to_flags(ifr.ifr_flags);
	_intf_set_type(entry);
	
	/* Get interface MTU. */
#ifdef SIOCGIFMTU
	if (ioctl(intf->fd, SIOCGIFMTU, &ifr) < 0)
#endif
		return (-1);
	entry->intf_mtu = ifr.ifr_mtu;

	entry->intf_addr.addr_type = entry->intf_dst_addr.addr_type =
	    entry->intf_link_addr.addr_type = ADDR_TYPE_NONE;
	
	/* Get primary interface address. */
	if (ioctl(intf->fd, SIOCGIFADDR, &ifr) == 0) {
		addr_ston(&ifr.ifr_addr, &entry->intf_addr);
		if (ioctl(intf->fd, SIOCGIFNETMASK, &ifr) < 0)
			return (-1);
		addr_stob(&ifr.ifr_addr, &entry->intf_addr.addr_bits);
	}
	/* Get other addresses. */
	if (entry->intf_type == INTF_TYPE_TUN) {
		if (ioctl(intf->fd, SIOCGIFDSTADDR, &ifr) == 0) {
			if (addr_ston(&ifr.ifr_addr,
			    &entry->intf_dst_addr) < 0)
				return (-1);
		}
	} else if (entry->intf_type == INTF_TYPE_ETH) {
#if defined(SIOCGIFHWADDR)
		if (ioctl(intf->fd, SIOCGIFHWADDR, &ifr) < 0)
			return (-1);
		if (addr_ston(&ifr.ifr_addr, &entry->intf_link_addr) < 0)
			return (-1);
#elif defined(SIOCRPHYSADDR)
		/* Tru64 */
		struct ifdevea *ifd = (struct ifdevea *)&ifr; /* XXX */
		
		if (ioctl(intf->fd, SIOCRPHYSADDR, ifd) < 0)
			return (-1);
		addr_pack(&entry->intf_link_addr, ADDR_TYPE_ETH, ETH_ADDR_BITS,
		    ifd->current_pa, ETH_ADDR_LEN);
#else
		eth_t *eth;
		
		if ((eth = eth_open(entry->intf_name)) != NULL) {
			if (!eth_get(eth, &entry->intf_link_addr.addr_eth)) {
				entry->intf_link_addr.addr_type =
				    ADDR_TYPE_ETH;
				entry->intf_link_addr.addr_bits =
				    ETH_ADDR_BITS;
			}
			eth_close(eth);
		}
#endif
	}
	return (0);
}
#endif

#ifdef SIOCLIFADDR
/* XXX - aliases on IRIX don't show up in SIOCGIFCONF */
static int
_intf_get_aliases(intf_t *intf, struct intf_entry *entry)
{
	struct dnet_ifaliasreq ifra;
	struct addr *ap, *lap;
	
	strlcpy(ifra.ifra_name, entry->intf_name, sizeof(ifra.ifra_name));
	addr_ntos(&entry->intf_addr, &ifra.ifra_addr);
	addr_btos(entry->intf_addr.addr_bits, &ifra.ifra_mask);
	memset(&ifra.ifra_brdaddr, 0, sizeof(ifra.ifra_brdaddr));
	ifra.ifra_cookie = 1;

	ap = entry->intf_alias_addrs;
	lap = (struct addr *)((u_char *)entry + entry->intf_len);
	
	while (ioctl(intf->fd, SIOCLIFADDR, &ifra) == 0 &&
	    ifra.ifra_cookie > 0 && (ap + 1) < lap) {
		if (addr_ston(&ifra.ifra_addr, ap) < 0)
			break;
		ap++, entry->intf_alias_num++;
	}
	entry->intf_len = (u_char *)ap - (u_char *)entry;
	
	return (0);
}
#elif defined(SIOCGLIFCONF)
static int
_intf_get_aliases(intf_t *intf, struct intf_entry *entry)
{
	struct lifreq *lifr, *llifr;
	struct lifreq tmplifr;
	struct addr *ap, *lap;
	char *p;
	
	if (intf->lifc.lifc_len < (int)sizeof(*lifr)) {
		errno = EINVAL;
		return (-1);
	}
	entry->intf_alias_num = 0;
	ap = entry->intf_alias_addrs;
	llifr = (struct lifreq *)intf->lifc.lifc_buf + 
	    (intf->lifc.lifc_len / sizeof(*llifr));
	lap = (struct addr *)((u_char *)entry + entry->intf_len);
	
	/* Get addresses for this interface. */
	for (lifr = intf->lifc.lifc_req; lifr < llifr && (ap + 1) < lap;
	    lifr = NEXTLIFR(lifr)) {
		/* XXX - Linux, Solaris ifaliases */
		if ((p = strchr(lifr->lifr_name, ':')) != NULL)
			*p = '\0';
		
		if (strcmp(lifr->lifr_name, entry->intf_name) != 0) {
			if (p) *p = ':';
			continue;
		}
		
		/* Fix the name back up */
		if (p) *p = ':';

		if (addr_ston((struct sockaddr *)&lifr->lifr_addr, ap) < 0)
			continue;
		
		/* XXX */
		if (ap->addr_type == ADDR_TYPE_ETH) {
			memcpy(&entry->intf_link_addr, ap, sizeof(*ap));
			continue;
		} else if (ap->addr_type == ADDR_TYPE_IP) {
			if (ap->addr_ip == entry->intf_addr.addr_ip ||
			    ap->addr_ip == entry->intf_dst_addr.addr_ip)
				continue;
			strlcpy(tmplifr.lifr_name, lifr->lifr_name, sizeof(tmplifr.lifr_name));
			if (ioctl(intf->fd, SIOCGIFNETMASK, &tmplifr) == 0)
				addr_stob((struct sockaddr *)&tmplifr.lifr_addr, &ap->addr_bits);
		} else if (ap->addr_type == ADDR_TYPE_IP6 && intf->fd6 != -1) {
			if (memcmp(&ap->addr_ip6, &entry->intf_addr.addr_ip6, IP6_ADDR_LEN) == 0 ||
			    memcmp(&ap->addr_ip6, &entry->intf_dst_addr.addr_ip6, IP6_ADDR_LEN) == 0)
				continue;
			strlcpy(tmplifr.lifr_name, lifr->lifr_name, sizeof(tmplifr.lifr_name));
			if (ioctl(intf->fd6, SIOCGLIFNETMASK, &tmplifr) == 0) {
				addr_stob((struct sockaddr *)&tmplifr.lifr_addr,
				    &ap->addr_bits);
			}
			else perror("SIOCGLIFNETMASK");
		}
		ap++, entry->intf_alias_num++;
	}
	entry->intf_len = (u_char *)ap - (u_char *)entry;
	
	return (0);
}
#else
static int
_intf_get_aliases(intf_t *intf, struct intf_entry *entry)
{
	struct ifreq *ifr, *lifr;
	struct ifreq tmpifr;
	struct addr *ap, *lap;
	char *p;
	
	if (intf->ifc.ifc_len < (int)sizeof(*ifr)) {
		errno = EINVAL;
		return (-1);
	}
	entry->intf_alias_num = 0;
	ap = entry->intf_alias_addrs;
	lifr = (struct ifreq *)intf->ifc.ifc_buf + 
	    (intf->ifc.ifc_len / sizeof(*lifr));
	lap = (struct addr *)((u_char *)entry + entry->intf_len);
	
	/* Get addresses for this interface. */
	for (ifr = intf->ifc.ifc_req; ifr < lifr && (ap + 1) < lap;
	    ifr = NEXTIFR(ifr)) {
		/* XXX - Linux, Solaris ifaliases */
		if ((p = strchr(ifr->ifr_name, ':')) != NULL)
			*p = '\0';
		
		if (strcmp(ifr->ifr_name, entry->intf_name) != 0) {
			if (p) *p = ':';
			continue;
		}
		
		/* Fix the name back up */
		if (p) *p = ':';

		if (addr_ston(&ifr->ifr_addr, ap) < 0)
			continue;
		
		/* XXX */
		if (ap->addr_type == ADDR_TYPE_ETH) {
			memcpy(&entry->intf_link_addr, ap, sizeof(*ap));
			continue;
		} else if (ap->addr_type == ADDR_TYPE_IP) {
			if (ap->addr_ip == entry->intf_addr.addr_ip ||
			    ap->addr_ip == entry->intf_dst_addr.addr_ip)
				continue;
			strlcpy(tmpifr.ifr_name, ifr->ifr_name, sizeof(tmpifr.ifr_name));
			if (ioctl(intf->fd, SIOCGIFNETMASK, &tmpifr) == 0)
				addr_stob(&tmpifr.ifr_addr, &ap->addr_bits);
		}
#ifdef SIOCGIFNETMASK_IN6
		else if (ap->addr_type == ADDR_TYPE_IP6 && intf->fd6 != -1) {
			struct in6_ifreq ifr6;

			/* XXX - sizeof(ifr) < sizeof(ifr6) */
			memcpy(&ifr6, ifr, sizeof(ifr6));
			
			if (ioctl(intf->fd6, SIOCGIFNETMASK_IN6, &ifr6) == 0) {
				addr_stob((struct sockaddr *)&ifr6.ifr_addr,
				    &ap->addr_bits);
			}
			else perror("SIOCGIFNETMASK_IN6");
		}
#else
#ifdef SIOCGIFNETMASK6
		else if (ap->addr_type == ADDR_TYPE_IP6 && intf->fd6 != -1) {
			struct in6_ifreq ifr6;

			/* XXX - sizeof(ifr) < sizeof(ifr6) */
			memcpy(&ifr6, ifr, sizeof(ifr6));
			
			if (ioctl(intf->fd6, SIOCGIFNETMASK6, &ifr6) == 0) {
				/* For some reason this is 0 after the ioctl. */
				ifr6.ifr_Addr.sin6_family = AF_INET6;
				addr_stob((struct sockaddr *)&ifr6.ifr_Addr,
				    &ap->addr_bits);
			}
			else perror("SIOCGIFNETMASK6");
		}
#endif
#endif
		ap++, entry->intf_alias_num++;
	}
#ifdef HAVE_LINUX_PROCFS
#define PROC_INET6_FILE	"/proc/net/if_inet6"
	{
		FILE *f;
		char buf[256], s[8][5], name[INTF_NAME_LEN];
		u_int idx, bits, scope, flags;
		
		if ((f = fopen(PROC_INET6_FILE, "r")) != NULL) {
			while (ap < lap &&
			       fgets(buf, sizeof(buf), f) != NULL) {
				sscanf(buf, "%04s%04s%04s%04s%04s%04s%04s%04s %x %02x %02x %02x %32s\n",
				    s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
				    &idx, &bits, &scope, &flags, name);
				if (strcmp(name, entry->intf_name) == 0) {
					snprintf(buf, sizeof(buf), "%s:%s:%s:%s:%s:%s:%s:%s/%d",
					    s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], bits);
					addr_aton(buf, ap);
					ap++, entry->intf_alias_num++;
				}
			}
			fclose(f);
		}
	}
#endif
	entry->intf_len = (u_char *)ap - (u_char *)entry;
	
	return (0);
}
#endif /* SIOCLIFADDR */

int
intf_get(intf_t *intf, struct intf_entry *entry)
{
	if (_intf_get_noalias(intf, entry) < 0)
		return (-1);
#ifndef SIOCLIFADDR
	intf->ifc.ifc_buf = (caddr_t)intf->ifcbuf;
	intf->ifc.ifc_len = sizeof(intf->ifcbuf);
	
	if (ioctl(intf->fd, SIOCGIFCONF, &intf->ifc) < 0)
		return (-1);
#endif
	return (_intf_get_aliases(intf, entry));
}

/* Look up an interface from an index, such as a sockaddr_in6.sin6_scope_id. */
int
intf_get_index(intf_t *intf, struct intf_entry *entry, int af, unsigned int index)
{
	char namebuf[IFNAMSIZ];
	char *devname;

	/* af is ignored; only used in intf-win32.c. */
	devname = if_indextoname(index, namebuf);
	if (devname == NULL)
		return (-1);
	strlcpy(entry->intf_name, devname, sizeof(entry->intf_name));
	return intf_get(intf, entry);
}

static int
_match_intf_src(const struct intf_entry *entry, void *arg)
{
	struct intf_entry *save = (struct intf_entry *)arg;
	int matched = 0, cnt;
	
	if (entry->intf_addr.addr_type == ADDR_TYPE_IP &&
	    entry->intf_addr.addr_ip == save->intf_addr.addr_ip)
		matched = 1;

	for (cnt = 0; !matched && cnt < (int) entry->intf_alias_num; cnt++) {
		if (entry->intf_alias_addrs[cnt].addr_type != ADDR_TYPE_IP)
			continue;
		if (entry->intf_alias_addrs[cnt].addr_ip == save->intf_addr.addr_ip)
			matched = 1;
	}

	if (matched) {
		/* XXX - truncated result if entry is too small. */
		if (save->intf_len < entry->intf_len)
			memcpy(save, entry, save->intf_len);
		else
			memcpy(save, entry, entry->intf_len);
		return (1);
	}
	return (0);
}

int
intf_get_src(intf_t *intf, struct intf_entry *entry, struct addr *src)
{
	memcpy(&entry->intf_addr, src, sizeof(*src));
	
	if (intf_loop(intf, _match_intf_src, entry) != 1) {
		errno = ENXIO;
		return (-1);
	}
	return (0);
}

int
intf_get_dst(intf_t *intf, struct intf_entry *entry, struct addr *dst)
{
	struct sockaddr_in sin;
	socklen_t n;
	
	if (dst->addr_type != ADDR_TYPE_IP) {
		errno = EINVAL;
		return (-1);
	}
	addr_ntos(dst, (struct sockaddr *)&sin);
	sin.sin_port = htons(666);
	
	if (connect(intf->fd, (struct sockaddr *)&sin, sizeof(sin)) < 0)
		return (-1);
	
	n = sizeof(sin);
	if (getsockname(intf->fd, (struct sockaddr *)&sin, &n) < 0)
		return (-1);
	
	addr_ston((struct sockaddr *)&sin, &entry->intf_addr);
	
	if (intf_loop(intf, _match_intf_src, entry) != 1)
		return (-1);
	
	return (0);
}

#ifdef HAVE_LINUX_PROCFS
#define PROC_DEV_FILE	"/proc/net/dev"

int
intf_loop(intf_t *intf, intf_handler callback, void *arg)
{
	FILE *fp;
	struct intf_entry *entry;
	char *p, buf[BUFSIZ], ebuf[BUFSIZ];
	int ret;

	entry = (struct intf_entry *)ebuf;
	
	if ((fp = fopen(PROC_DEV_FILE, "r")) == NULL)
		return (-1);
	
	intf->ifc.ifc_buf = (caddr_t)intf->ifcbuf;
	intf->ifc.ifc_len = sizeof(intf->ifcbuf);
	
	if (ioctl(intf->fd, SIOCGIFCONF, &intf->ifc) < 0) {
		fclose(fp);
		return (-1);
	}

	ret = 0;
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		if ((p = strchr(buf, ':')) == NULL)
			continue;
		*p = '\0';
		for (p = buf; *p == ' '; p++)
			;

		memset(ebuf, 0, sizeof(ebuf));
		strlcpy(entry->intf_name, p, sizeof(entry->intf_name));
		entry->intf_len = sizeof(ebuf);
		
		if (_intf_get_noalias(intf, entry) < 0) {
			ret = -1;
			break;
		}
		if (_intf_get_aliases(intf, entry) < 0) {
			ret = -1;
			break;
		}
		if ((ret = (*callback)(entry, arg)) != 0)
			break;
	}
	if (ferror(fp))
		ret = -1;
	
	fclose(fp);
	
	return (ret);
}
#elif defined(SIOCGLIFCONF)
int
intf_loop(intf_t *intf, intf_handler callback, void *arg)
{
	struct intf_entry *entry;
	struct lifreq *lifr, *llifr, *plifr;
	char *p, ebuf[BUFSIZ];
	int ret;

	entry = (struct intf_entry *)ebuf;

	/* http://www.unix.com/man-page/opensolaris/7p/if_tcp */
	intf->lifc.lifc_family = AF_UNSPEC;
	intf->lifc.lifc_flags = 0;
#ifdef LIFC_UNDER_IPMP
	intf->lifc.lifc_flags |= LIFC_UNDER_IPMP;
#endif
	intf->lifc.lifc_buf = (caddr_t)intf->ifcbuf;
	intf->lifc.lifc_len = sizeof(intf->ifcbuf);
	
	if (ioctl(intf->fd, SIOCGLIFCONF, &intf->lifc) < 0)
		return (-1);

	llifr = (struct lifreq *)&intf->lifc.lifc_buf[intf->lifc.lifc_len];
	
	for (lifr = intf->lifc.lifc_req; lifr < llifr; lifr = NEXTLIFR(lifr)) {
		/* XXX - Linux, Solaris ifaliases */
		if ((p = strchr(lifr->lifr_name, ':')) != NULL)
			*p = '\0';
		
		for (plifr = intf->lifc.lifc_req; plifr < lifr; plifr = NEXTLIFR(lifr)) {
			if (strcmp(lifr->lifr_name, plifr->lifr_name) == 0)
				break;
		}
		if (lifr > intf->lifc.lifc_req && plifr < lifr)
			continue;

		memset(ebuf, 0, sizeof(ebuf));
		strlcpy(entry->intf_name, lifr->lifr_name,
		    sizeof(entry->intf_name));
		entry->intf_len = sizeof(ebuf);

		/* Repair the alias name back up */
		if (p) *p = ':';

		/* Ignore IPMP interfaces. These are virtual interfaces made up
		 * of physical interfaces. IPMP interfaces do not support things
		 * like packet sniffing; it is necessary to use one of the
		 * underlying physical interfaces instead. This works as long as
		 * the physical interface's test address is on the same subnet
		 * as the IPMP interface's address. */
		if (ioctl(intf->fd, SIOCGLIFFLAGS, lifr) >= 0)
			;
		else if (intf->fd6 != -1 && ioctl(intf->fd6, SIOCGLIFFLAGS, lifr) >= 0)
			;
		else
			return (-1);
#ifdef IFF_IPMP
		if (lifr->lifr_flags & IFF_IPMP) {
			continue;
		}
#endif
		
		if (_intf_get_noalias(intf, entry) < 0)
			return (-1);
		if (_intf_get_aliases(intf, entry) < 0)
			return (-1);
		
		if ((ret = (*callback)(entry, arg)) != 0)
			return (ret);
	}
	return (0);
}
#else
int
intf_loop(intf_t *intf, intf_handler callback, void *arg)
{
	struct intf_entry *entry;
	struct ifreq *ifr, *lifr, *pifr;
	char *p, ebuf[BUFSIZ];
	int ret;

	entry = (struct intf_entry *)ebuf;

	intf->ifc.ifc_buf = (caddr_t)intf->ifcbuf;
	intf->ifc.ifc_len = sizeof(intf->ifcbuf);
	
	if (ioctl(intf->fd, SIOCGIFCONF, &intf->ifc) < 0)
		return (-1);

	pifr = NULL;
	lifr = (struct ifreq *)&intf->ifc.ifc_buf[intf->ifc.ifc_len];
	
	for (ifr = intf->ifc.ifc_req; ifr < lifr; ifr = NEXTIFR(ifr)) {
		/* XXX - Linux, Solaris ifaliases */
		if ((p = strchr(ifr->ifr_name, ':')) != NULL)
			*p = '\0';
		
		if (pifr != NULL && strcmp(ifr->ifr_name, pifr->ifr_name) == 0) {
			if (p) *p = ':';
			continue;
		}

		memset(ebuf, 0, sizeof(ebuf));
		strlcpy(entry->intf_name, ifr->ifr_name,
		    sizeof(entry->intf_name));
		entry->intf_len = sizeof(ebuf);

		/* Repair the alias name back up */
		if (p) *p = ':';
		
		if (_intf_get_noalias(intf, entry) < 0)
			return (-1);
		if (_intf_get_aliases(intf, entry) < 0)
			return (-1);
		
		if ((ret = (*callback)(entry, arg)) != 0)
			return (ret);

		pifr = ifr;
	}
	return (0);
}
#endif /* !HAVE_LINUX_PROCFS */

intf_t *
intf_close(intf_t *intf)
{
	if (intf != NULL) {
		if (intf->fd >= 0)
			close(intf->fd);
		if (intf->fd6 >= 0)
			close(intf->fd6);
		free(intf);
	}
	return (NULL);
}
