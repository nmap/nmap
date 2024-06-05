/*
 * arp-win32.c
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id: arp-win32.c 539 2005-01-23 07:36:54Z dugsong $
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

struct arp_handle {
	MIB_IPNET_TABLE2 *iptable;
};

arp_t *
arp_open(void)
{
	return (calloc(1, sizeof(arp_t)));
}

int
arp_add(arp_t *arp, const struct arp_entry *entry)
{
	MIB_IPFORWARDROW ipfrow;
	MIB_IPNETROW iprow;
	
	if (GetBestRoute(entry->arp_pa.addr_ip,
	    IP_ADDR_ANY, &ipfrow) != NO_ERROR)
		return (-1);

	iprow.dwIndex = ipfrow.dwForwardIfIndex;
	iprow.dwPhysAddrLen = ETH_ADDR_LEN;
	memcpy(iprow.bPhysAddr, &entry->arp_ha.addr_eth, ETH_ADDR_LEN);
	iprow.dwAddr = entry->arp_pa.addr_ip;
	iprow.dwType = 4;	/* XXX - static */

	if (CreateIpNetEntry(&iprow) != NO_ERROR)
		return (-1);

	return (0);
}

int
arp_delete(arp_t *arp, const struct arp_entry *entry)
{
	MIB_IPFORWARDROW ipfrow;
	MIB_IPNETROW iprow;

	if (GetBestRoute(entry->arp_pa.addr_ip,
	    IP_ADDR_ANY, &ipfrow) != NO_ERROR)
		return (-1);

	memset(&iprow, 0, sizeof(iprow));
	iprow.dwIndex = ipfrow.dwForwardIfIndex;
	iprow.dwAddr = entry->arp_pa.addr_ip;

	if (DeleteIpNetEntry(&iprow) != NO_ERROR) {
		errno = ENXIO;
		return (-1);
	}
	return (0);
}

static int
_arp_get_entry(const struct arp_entry *entry, void *arg)
{
	struct arp_entry *e = (struct arp_entry *)arg;
	
	if (addr_cmp(&entry->arp_pa, &e->arp_pa) == 0) {
		memcpy(&e->arp_ha, &entry->arp_ha, sizeof(e->arp_ha));
		return (1);
	}
	return (0);
}

int
arp_get(arp_t *arp, struct arp_entry *entry)
{
	if (arp_loop(arp, _arp_get_entry, entry) != 1) {
		errno = ENXIO;
		SetLastError(ERROR_NO_DATA);
		return (-1);
	}
	return (0);
}

int
arp_loop(arp_t *arp, arp_handler callback, void *arg)
{
	struct arp_entry entry;
	int ret;

	if (arp->iptable)
		FreeMibTable(arp->iptable);
	ret = GetIpNetTable2(AF_UNSPEC, &arp->iptable);
	switch (ret) {
		case NO_ERROR:
			break;
		case ERROR_NOT_FOUND:
			return 0;
			break;
		default:
			return -1;
			break;
	}
	
	entry.arp_ha.addr_type = ADDR_TYPE_ETH;
	entry.arp_ha.addr_bits = ETH_ADDR_BITS;
	
	for (ULONG i = 0; i < arp->iptable->NumEntries; i++) {
		MIB_IPNET_ROW2 *row = &arp->iptable->Table[i];
		if (row->PhysicalAddressLength != ETH_ADDR_LEN ||
				row->IsUnreachable ||
				row->State < NlnsReachable)
			continue;
		switch (row->Address.si_family) {
			case AF_INET:
				entry.arp_pa.addr_type = ADDR_TYPE_IP;
				entry.arp_pa.addr_bits = IP_ADDR_BITS;
				entry.arp_pa.addr_ip = row->Address.Ipv4.sin_addr.S_un.S_addr;
				break;
			case AF_INET6:
				entry.arp_pa.addr_type = ADDR_TYPE_IP6;
				entry.arp_pa.addr_bits = IP6_ADDR_BITS;
				memcpy(&entry.arp_pa.addr_ip6,
						row->Address.Ipv6.sin6_addr.u.Byte, IP6_ADDR_LEN);
				break;
			default:
				continue;
				break;
		}
		memcpy(&entry.arp_ha.addr_eth,
		    row->PhysicalAddress, ETH_ADDR_LEN);
		
		if ((ret = (*callback)(&entry, arg)) != 0)
			return (ret);
	}
	return (0);
}

arp_t *
arp_close(arp_t *arp)
{
	if (arp != NULL) {
		if (arp->iptable != NULL)
			FreeMibTable(arp->iptable);
		free(arp);
	}
	return (NULL);
}
