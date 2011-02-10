/*
 * intf-win32.c
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id: intf-win32.c 632 2006-08-10 04:36:52Z dugsong $
 */

#ifdef _WIN32
#include "dnet_winconfig.h"
#else
#include "config.h"
#endif

#include <iphlpapi.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dnet.h"
#include "pcap.h"
#include <Packet32.h>
#include <Ntddndis.h>

struct ifcombo {
	DWORD		*idx;
	int		 cnt;
	int		 max;
};

/* XXX - ipifcons.h incomplete, use IANA ifTypes MIB */
#define MIB_IF_TYPE_TUNNEL	131
#define MIB_IF_TYPE_MAX		MAX_IF_TYPE

struct intf_handle {
	struct ifcombo	 ifcombo[MIB_IF_TYPE_MAX];
	MIB_IFTABLE	*iftable;
	MIB_IPADDRTABLE	*iptable;
};

static char *
_ifcombo_name(int type)
{
	char *name = "eth";	/* XXX */
	
	if (type == MIB_IF_TYPE_TOKENRING) {
		name = "tr";
	} else if (type == MIB_IF_TYPE_FDDI) {
		name = "fddi";
	} else if (type == MIB_IF_TYPE_PPP) {
		name = "ppp";
	} else if (type == MIB_IF_TYPE_LOOPBACK) {
		name = "lo";
	} else if (type == MIB_IF_TYPE_SLIP) {
		name = "sl";
	} else if (type == MIB_IF_TYPE_TUNNEL) {
		name = "tun";
	}
	return (name);
}

static int
_ifcombo_type(const char *device)
{
	int type = INTF_TYPE_OTHER;
	
	if (strncmp(device, "eth", 3) == 0) {
		type = INTF_TYPE_ETH;
	} else if (strncmp(device, "tr", 2) == 0) {
		type = INTF_TYPE_TOKENRING;
	} else if (strncmp(device, "fd", 2) == 0) {
		type = INTF_TYPE_FDDI;
	} else if (strncmp(device, "ppp", 3) == 0) {
		type = INTF_TYPE_PPP;
	} else if (strncmp(device, "lo", 2) == 0) {
		type = INTF_TYPE_LOOPBACK;
	} else if (strncmp(device, "sl", 2) == 0) {
		type = INTF_TYPE_SLIP;
	} else if (strncmp(device, "tun", 3) == 0) {
		type = INTF_TYPE_TUN;
	}
	return (type);
}

static void
_ifcombo_add(struct ifcombo *ifc, DWORD idx)
{
	if (ifc->cnt == ifc->max) {
		if (ifc->idx) {
			ifc->max *= 2;
			ifc->idx = realloc(ifc->idx,
			    sizeof(ifc->idx[0]) * ifc->max);
		} else {
			ifc->max = 8;
			ifc->idx = malloc(sizeof(ifc->idx[0]) * ifc->max);
		}
	}
	ifc->idx[ifc->cnt++] = idx;
}

/* Map an MIB_IFROW.dwType interface type into an internal interface
   type. The internal types are never exposed to users of this library;
   they exist only for the sake of ordering interface types within an
   intf_handle, which has an array of ifcombo structures ordered by
   type. Entries in an intf_handle must not be stored or accessed by a
   raw MIB_IFROW.dwType number because they will not be able to be found
   by a device name such as "net0" if the device name does not map
   exactly to the dwType. */
static int
_if_type_canonicalize(int type)
{
       return _ifcombo_type(_ifcombo_name(type));
}

static void
_ifrow_to_entry(intf_t *intf, MIB_IFROW *ifrow, struct intf_entry *entry)
{
	struct addr *ap, *lap;
	int i;
	int type;
	
	/* The total length of the entry may be passed inside entry.
           Remember it and clear the entry. */
	u_int intf_len = entry->intf_len;
	memset(entry, 0, sizeof(*entry));
	entry->intf_len = intf_len;

	type = _if_type_canonicalize(ifrow->dwType);
	for (i = 0; i < intf->ifcombo[type].cnt; i++) {
		if (intf->ifcombo[type].idx[i] == ifrow->dwIndex)
			break;
	}
	/* XXX - type matches MIB-II ifType. */
	snprintf(entry->intf_name, sizeof(entry->intf_name), "%s%lu",
	    _ifcombo_name(type), i);
	entry->intf_type = (uint16_t)type;
	
	/* Get interface flags. */
	entry->intf_flags = 0;
	if (ifrow->dwAdminStatus == MIB_IF_ADMIN_STATUS_UP &&
	    (ifrow->dwOperStatus == MIB_IF_OPER_STATUS_OPERATIONAL ||
	     ifrow->dwOperStatus == MIB_IF_OPER_STATUS_CONNECTED))
		entry->intf_flags |= INTF_FLAG_UP;
	if (ifrow->dwType == MIB_IF_TYPE_LOOPBACK)
		entry->intf_flags |= INTF_FLAG_LOOPBACK;
	else
		entry->intf_flags |= INTF_FLAG_MULTICAST;
	
	/* Get interface MTU. */
	entry->intf_mtu = ifrow->dwMtu;
	
	/* Get hardware address. */
	if (ifrow->dwPhysAddrLen == ETH_ADDR_LEN) {
		entry->intf_link_addr.addr_type = ADDR_TYPE_ETH;
		entry->intf_link_addr.addr_bits = ETH_ADDR_BITS;
		memcpy(&entry->intf_link_addr.addr_eth, ifrow->bPhysAddr,
		    ETH_ADDR_LEN);
	}
	/* Get addresses. */
	ap = entry->intf_alias_addrs;
	lap = ap + ((entry->intf_len - sizeof(*entry)) /
	    sizeof(entry->intf_alias_addrs[0]));
	for (i = 0; i < (int)intf->iptable->dwNumEntries; i++) {
		if (intf->iptable->table[i].dwIndex == ifrow->dwIndex &&
		    intf->iptable->table[i].dwAddr != 0) {
			if (entry->intf_addr.addr_type == ADDR_TYPE_NONE) {
				/* Set primary address if unset. */
				entry->intf_addr.addr_type = ADDR_TYPE_IP;
				entry->intf_addr.addr_ip =
				    intf->iptable->table[i].dwAddr;
				addr_mtob(&intf->iptable->table[i].dwMask,
				    IP_ADDR_LEN, &entry->intf_addr.addr_bits);
			} else if (ap < lap) {
				/* Set aliases. */
				ap->addr_type = ADDR_TYPE_IP;
				ap->addr_ip = intf->iptable->table[i].dwAddr;
				addr_mtob(&intf->iptable->table[i].dwMask,
				    IP_ADDR_LEN, &ap->addr_bits);
				ap++, entry->intf_alias_num++;
			}
		}
	}
	entry->intf_len = (u_int) ((u_char *)ap - (u_char *)entry);
}

static int
_refresh_tables(intf_t *intf)
{
	MIB_IFROW *ifrow;
	ULONG len;
	u_int i, ret;

	/* Get interface table. */
	for (len = sizeof(intf->iftable[0]); ; ) {
		if (intf->iftable)
			free(intf->iftable);
		intf->iftable = malloc(len);
		ret = GetIfTable(intf->iftable, &len, FALSE);
		if (ret == NO_ERROR)
			break;
		else if (ret != ERROR_INSUFFICIENT_BUFFER)
			return (-1);
	}
	/* Get IP address table. */
	for (len = sizeof(intf->iptable[0]); ; ) {
		if (intf->iptable)
			free(intf->iptable);
		intf->iptable = malloc(len);
		ret = GetIpAddrTable(intf->iptable, &len, FALSE);
		if (ret == NO_ERROR)
			break;
		else if (ret != ERROR_INSUFFICIENT_BUFFER)
			return (-1);
	}
	/*
	 * Map "unfriendly" win32 interface indices to ours.
	 * XXX - like IP_ADAPTER_INFO ComboIndex
	 */
	for (i = 0; i < intf->iftable->dwNumEntries; i++) {
		int type;
		ifrow = &intf->iftable->table[i];
		type = _if_type_canonicalize(ifrow->dwType);
		if (type < MIB_IF_TYPE_MAX) {
			_ifcombo_add(&intf->ifcombo[type], ifrow->dwIndex);
		} else
			return (-1);
	}
	return (0);
}

static int
_find_ifindex(intf_t *intf, const char *device)
{
	char *p = (char *)device;
	int n, type = _ifcombo_type(device);
	
	while (isalpha((int) (unsigned char) *p)) p++;
	n = atoi(p);

	return (intf->ifcombo[type].idx[n]);
}

intf_t *
intf_open(void)
{
	return (calloc(1, sizeof(intf_t)));
}

int
intf_get(intf_t *intf, struct intf_entry *entry)
{
	MIB_IFROW ifrow;
	
	if (_refresh_tables(intf) < 0)
		return (-1);
	
	ifrow.dwIndex = _find_ifindex(intf, entry->intf_name);
	
	if (GetIfEntry(&ifrow) != NO_ERROR)
		return (-1);

	_ifrow_to_entry(intf, &ifrow, entry);
	
	return (0);
}

int
intf_get_src(intf_t *intf, struct intf_entry *entry, struct addr *src)
{
	MIB_IFROW ifrow;
	MIB_IPADDRROW *iprow;
	int i;

	if (src->addr_type != ADDR_TYPE_IP) {
		errno = EINVAL;
		return (-1);
	}
	if (_refresh_tables(intf) < 0)
		return (-1);
	
	for (i = 0; i < (int)intf->iptable->dwNumEntries; i++) {
		iprow = &intf->iptable->table[i];
		if (iprow->dwAddr == src->addr_ip) {
			ifrow.dwIndex = iprow->dwIndex;
			if (GetIfEntry(&ifrow) != NO_ERROR)
				return (-1);
			_ifrow_to_entry(intf, &ifrow, entry);
			return (0);
		}
	}
	errno = ENXIO;
	return (-1);
}

int
intf_get_dst(intf_t *intf, struct intf_entry *entry, struct addr *dst)
{
	MIB_IFROW ifrow;
	
	if (dst->addr_type != ADDR_TYPE_IP) {
		errno = EINVAL;
		return (-1);
	}
	if (GetBestInterface(dst->addr_ip, &ifrow.dwIndex) != NO_ERROR)
		return (-1);

	if (GetIfEntry(&ifrow) != NO_ERROR)
		return (-1);
	
	if (_refresh_tables(intf) < 0)
		return (-1);
	
	_ifrow_to_entry(intf, &ifrow, entry);
	
	return (0);
}

int
intf_set(intf_t *intf, const struct intf_entry *entry)
{
	/*
	 * XXX - could set interface up/down via SetIfEntry(),
	 * but what about the rest of the configuration? :-(
	 * {Add,Delete}IPAddress for 2000/XP only
	 */
#if 0
	/* Set interface address. XXX - 2000/XP only? */
	if (entry->intf_addr.addr_type == ADDR_TYPE_IP) {
		ULONG ctx = 0, inst = 0;
		UINT ip, mask;

		memcpy(&ip, &entry->intf_addr.addr_ip, IP_ADDR_LEN);
		addr_btom(entry->intf_addr.addr_bits, &mask, IP_ADDR_LEN);
		
		if (AddIPAddress(ip, mask,
			_find_ifindex(intf, entry->intf_name),
			&ctx, &inst) != NO_ERROR) {
			return (-1);
		}
		return (0);
	}
#endif
	errno = ENOSYS;
	SetLastError(ERROR_NOT_SUPPORTED);
	return (-1);
}

int
intf_loop(intf_t *intf, intf_handler callback, void *arg)
{
	struct intf_entry *entry;
	u_char ebuf[1024];
	int i, ret = 0;

	if (_refresh_tables(intf) < 0)
		return (-1);
	
	entry = (struct intf_entry *)ebuf;
	
	for (i = 0; i < (int)intf->iftable->dwNumEntries; i++) {
		entry->intf_len = sizeof(ebuf);
		_ifrow_to_entry(intf, &intf->iftable->table[i], entry);
		if ((ret = (*callback)(entry, arg)) != 0)
			break;
	}
	return (ret);
}

intf_t *
intf_close(intf_t *intf)
{
	int i;

	if (intf != NULL) {
		for (i = 0; i < MIB_IF_TYPE_MAX; i++) {
			if (intf->ifcombo[i].idx)
				free(intf->ifcombo[i].idx);
		}
		if (intf->iftable)
			free(intf->iftable);
		if (intf->iptable)
			free(intf->iptable);
		free(intf);
	}
	return (NULL);
}

/* Converts a libdnet interface name to its pcap equivalent. The pcap name is
   stored in pcapdev up to a length of pcapdevlen, including the terminating
   '\0'. Returns -1 on error. */
int
intf_get_pcap_devname(const char *intf_name, char *pcapdev, int pcapdevlen)
{
	wchar_t descr_wc[512];
	pcap_if_t *pcapdevs;
	pcap_if_t *pdev, *selected;
	intf_t *intf;
	MIB_IFROW ifrow;

	if ((intf = intf_open()) == NULL)
		return (-1);
	if (_refresh_tables(intf) < 0) {
		intf_close(intf);
		return (-1);
	}
	ifrow.dwIndex = _find_ifindex(intf, intf_name);
	intf_close(intf);

	if (GetIfEntry(&ifrow) != NO_ERROR)
		return (-1);

	/* OID_GEN_FRIENDLY_NAME returns a wide-character string, so convert
	   the description to wide characters for string comparison. */
	mbstowcs(descr_wc, ifrow.bDescr, sizeof(descr_wc) / sizeof(descr_wc[0]) - 1);
	descr_wc[sizeof(descr_wc) / sizeof(descr_wc[0]) - 1] = L'\0';

	if (pcap_findalldevs(&pcapdevs, NULL) == -1)
		return (-1);

	/* Loop through all the pcap devices until we find a match. pcap gets
	   its interface list from the registry; dnet gets it from GetIfList.
	   We must match them up using values common to both data sets. We do
	   it by comparing hardware addresses and interface descriptions. */
	selected = NULL;
	for (pdev = pcapdevs; pdev != NULL; pdev = pdev->next) {
		PACKET_OID_DATA *data;
		u_char buf[512];
		LPADAPTER lpa;

		lpa = PacketOpenAdapter(pdev->name);
		if (lpa == NULL)
			continue;
		if (lpa->hFile == INVALID_HANDLE_VALUE)
			goto close_adapter;

		data = (PACKET_OID_DATA *) buf;

		/* Check the MAC address if available. */
		data->Oid = OID_802_3_CURRENT_ADDRESS;
		data->Length = sizeof(buf) - sizeof(*data);
		if (!PacketRequest(lpa, FALSE, data))
			goto close_adapter;
		if (data->Length != ifrow.dwPhysAddrLen)
			goto close_adapter;
		if (memcmp(ifrow.bPhysAddr, data->Data, data->Length) != 0)
			goto close_adapter;

		/* A hardware address match is good enough, but we will prefer
		   an additional match with the description if available. */
		if (selected == NULL)
			selected = pdev;

		/* Distinct interfaces can have the same MAC address in the
		   case of "teamed" interfaces. Additionally check the
		   description string. */
		data->Oid = OID_GEN_FRIENDLY_NAME;
		data->Length = sizeof(buf) - sizeof(*data);
		if (PacketRequest(lpa, FALSE, data) != TRUE)
			goto close_adapter;
		if (wcscmp(descr_wc, (wchar_t *) data->Data) != 0)
			goto close_adapter;

		/* This matches both the hardware address and description, so
		   it's the best candidate. */
		selected = pdev;
		PacketCloseAdapter(lpa);
		break;

close_adapter:
		PacketCloseAdapter(lpa);
	}

	if (selected != NULL)
		strlcpy(pcapdev, selected->name, pcapdevlen);
	pcap_freealldevs(pcapdevs);
	if (selected == NULL)
		return -1;
	else
		return 0;
}
