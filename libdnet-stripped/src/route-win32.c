/*
 * route-win32.c
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id: route-win32.c 589 2005-02-15 07:11:32Z dugsong $
 */

#ifdef _WIN32
#include "dnet_winconfig.h"
#else
#include "config.h"
#endif

#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "dnet.h"

typedef DWORD (WINAPI *GETIPFORWARDTABLE2)(ADDRESS_FAMILY, PMIB_IPFORWARD_TABLE2 *);

struct route_handle {
	HINSTANCE iphlpapi;
	MIB_IPFORWARDTABLE *ipftable;
	MIB_IPFORWARD_TABLE2 *ipftable2;
};

route_t *
route_open(void)
{
	route_t *r;

	r = calloc(1, sizeof(route_t));
	if (r == NULL)
		return NULL;
	r->iphlpapi = GetModuleHandle("iphlpapi.dll");

	return r;
}

int
route_add(route_t *route, const struct route_entry *entry)
{
	MIB_IPFORWARDROW ipfrow;
	struct addr net;

	memset(&ipfrow, 0, sizeof(ipfrow));

	if (GetBestInterface(entry->route_gw.addr_ip,
	    &ipfrow.dwForwardIfIndex) != NO_ERROR)
		return (-1);

	if (addr_net(&entry->route_dst, &net) < 0 ||
	    net.addr_type != ADDR_TYPE_IP)
		return (-1);
	
	ipfrow.dwForwardDest = net.addr_ip;
	addr_btom(entry->route_dst.addr_bits,
	    &ipfrow.dwForwardMask, IP_ADDR_LEN);
	ipfrow.dwForwardNextHop = entry->route_gw.addr_ip;
	ipfrow.dwForwardType = 4;	/* XXX - next hop != final dest */
	ipfrow.dwForwardProto = 3;	/* XXX - MIB_PROTO_NETMGMT */
	
	if (CreateIpForwardEntry(&ipfrow) != NO_ERROR)
		return (-1);
	
	return (0);
}

int
route_delete(route_t *route, const struct route_entry *entry)
{
	MIB_IPFORWARDROW ipfrow;
	DWORD mask;
	
	if (entry->route_dst.addr_type != ADDR_TYPE_IP ||
	    GetBestRoute(entry->route_dst.addr_ip,
	    IP_ADDR_ANY, &ipfrow) != NO_ERROR)
		return (-1);

	addr_btom(entry->route_dst.addr_bits, &mask, IP_ADDR_LEN);
	
	if (ipfrow.dwForwardDest != entry->route_dst.addr_ip ||
	    ipfrow.dwForwardMask != mask) {
		errno = ENXIO;
		SetLastError(ERROR_NO_DATA);
		return (-1);
	}
	if (DeleteIpForwardEntry(&ipfrow) != NO_ERROR)
		return (-1);
	
	return (0);
}

int
route_get(route_t *route, struct route_entry *entry)
{
	MIB_IPFORWARDROW ipfrow;
	DWORD mask;
	intf_t *intf;
	struct intf_entry intf_entry;

	if (entry->route_dst.addr_type != ADDR_TYPE_IP ||
	    GetBestRoute(entry->route_dst.addr_ip,
	    IP_ADDR_ANY, &ipfrow) != NO_ERROR)
		return (-1);

	if (ipfrow.dwForwardProto == 2 &&	/* XXX - MIB_IPPROTO_LOCAL */
	    (ipfrow.dwForwardNextHop|IP_CLASSA_NET) !=
	    (IP_ADDR_LOOPBACK|IP_CLASSA_NET) &&
	    !IP_LOCAL_GROUP(ipfrow.dwForwardNextHop)) { 
		errno = ENXIO;
		SetLastError(ERROR_NO_DATA);
		return (-1);
	}
	addr_btom(entry->route_dst.addr_bits, &mask, IP_ADDR_LEN);
	
	entry->route_gw.addr_type = ADDR_TYPE_IP;
	entry->route_gw.addr_bits = IP_ADDR_BITS;
	entry->route_gw.addr_ip = ipfrow.dwForwardNextHop;
	entry->metric = ipfrow.dwForwardMetric1;

	entry->intf_name[0] = '\0';
	intf = intf_open();
	if (intf_get_index(intf, &intf_entry,
	    AF_INET, ipfrow.dwForwardIfIndex) == 0) {
		strlcpy(entry->intf_name, intf_entry.intf_name, sizeof(entry->intf_name));
	}
	intf_close(intf);
	
	return (0);
}

static int
route_loop_getipforwardtable(route_t *r, route_handler callback, void *arg)
{
 	struct route_entry entry;
	intf_t *intf;
	ULONG len;
	int i, ret;
 	
	for (len = sizeof(r->ipftable[0]); ; ) {
		if (r->ipftable)
			free(r->ipftable);
		r->ipftable = malloc(len);
		if (r->ipftable == NULL)
			return (-1);
		ret = GetIpForwardTable(r->ipftable, &len, FALSE);
		if (ret == NO_ERROR)
			break;
		else if (ret != ERROR_INSUFFICIENT_BUFFER)
			return (-1);
	}

	intf = intf_open();
	
	ret = 0;
	for (i = 0; i < (int)r->ipftable->dwNumEntries; i++) {
		struct intf_entry intf_entry;

		entry.route_dst.addr_type = ADDR_TYPE_IP;
		entry.route_dst.addr_bits = IP_ADDR_BITS;

		entry.route_gw.addr_type = ADDR_TYPE_IP;
		entry.route_gw.addr_bits = IP_ADDR_BITS;

		entry.route_dst.addr_ip = r->ipftable->table[i].dwForwardDest;
		addr_mtob(&r->ipftable->table[i].dwForwardMask, IP_ADDR_LEN,
		    &entry.route_dst.addr_bits);
		entry.route_gw.addr_ip =
		    r->ipftable->table[i].dwForwardNextHop;
		entry.metric = r->ipftable->table[i].dwForwardMetric1;

		/* Look up the interface name. */
		entry.intf_name[0] = '\0';
		intf_entry.intf_len = sizeof(intf_entry);
		if (intf_get_index(intf, &intf_entry,
		    AF_INET, r->ipftable->table[i].dwForwardIfIndex) == 0) {
			strlcpy(entry.intf_name, intf_entry.intf_name, sizeof(entry.intf_name));
		}
		
		if ((ret = (*callback)(&entry, arg)) != 0)
			break;
	}

	intf_close(intf);

	return ret;
}

static int
route_loop_getipforwardtable2(GETIPFORWARDTABLE2 GetIpForwardTable2,
	route_t *r, route_handler callback, void *arg)
{
	struct route_entry entry;
	intf_t *intf;
	ULONG i;
	int ret;
	
	ret = GetIpForwardTable2(AF_UNSPEC, &r->ipftable2);
	if (ret != NO_ERROR)
		return (-1);

	intf = intf_open();

	ret = 0;
	for (i = 0; i < r->ipftable2->NumEntries; i++) {
		struct intf_entry intf_entry;
		MIB_IPFORWARD_ROW2 *row;
		MIB_IPINTERFACE_ROW ifrow;
		ULONG metric;

		row = &r->ipftable2->Table[i];
		addr_ston((struct sockaddr *) &row->DestinationPrefix.Prefix, &entry.route_dst);
		entry.route_dst.addr_bits = row->DestinationPrefix.PrefixLength;
		addr_ston((struct sockaddr *) &row->NextHop, &entry.route_gw);

		/* Look up the interface name. */
		entry.intf_name[0] = '\0';
		intf_entry.intf_len = sizeof(intf_entry);
		if (intf_get_index(intf, &intf_entry,
		    row->DestinationPrefix.Prefix.si_family,
		    row->InterfaceIndex) == 0) {
			strlcpy(entry.intf_name, intf_entry.intf_name, sizeof(entry.intf_name));
		}

		ifrow.Family = row->DestinationPrefix.Prefix.si_family;
		ifrow.InterfaceLuid = row->InterfaceLuid;
		ifrow.InterfaceIndex = row->InterfaceIndex;
		if (GetIpInterfaceEntry(&ifrow) != NO_ERROR) {
			return (-1);
		}
		metric = ifrow.Metric + row->Metric;
		if (metric < INT_MAX)
			entry.metric = metric;
		else
			entry.metric = INT_MAX;
		
		if ((ret = (*callback)(&entry, arg)) != 0)
			break;
	}

	intf_close(intf);

	return ret;
}

int
route_loop(route_t *r, route_handler callback, void *arg)
{
	GETIPFORWARDTABLE2 GetIpForwardTable2;

	/* GetIpForwardTable2 is only available on Vista and later, dynamic load. */
	GetIpForwardTable2 = NULL;
	if (r->iphlpapi != NULL)
		GetIpForwardTable2 = (GETIPFORWARDTABLE2) GetProcAddress(r->iphlpapi, "GetIpForwardTable2");

	if (GetIpForwardTable2 == NULL)
		return route_loop_getipforwardtable(r, callback, arg);
	else
		return route_loop_getipforwardtable2(GetIpForwardTable2, r, callback, arg);
}

route_t *
route_close(route_t *r)
{
	if (r != NULL) {
		if (r->ipftable != NULL)
			free(r->ipftable);
		if (r->ipftable2 != NULL)
			FreeMibTable(r->ipftable2);
		free(r);
	}
	return (NULL);
}
