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

int g_has_npcap_loopback = 0;
#define _DEVICE_PREFIX "\\Device\\"

struct ifcombo {
	struct {
		DWORD	ipv4;
		DWORD	ipv6;
	} *idx;
	int		 cnt;
	int		 max;
};

/* XXX - ipifcons.h incomplete, use IANA ifTypes MIB */
#define MIB_IF_TYPE_TUNNEL	131
#define MIB_IF_TYPE_MAX		MAX_IF_TYPE

struct intf_handle {
	struct ifcombo	 ifcombo[MIB_IF_TYPE_MAX];
	IP_ADAPTER_ADDRESSES	*iftable;
};

static char *
_ifcombo_name(int type)
{
	char *name = NULL;
	
	switch (type) {
		case IF_TYPE_ETHERNET_CSMACD:
		case IF_TYPE_IEEE80211:
			name = "eth";
			break;
		case IF_TYPE_ISO88025_TOKENRING:
			name = "tr";
			break;
		case IF_TYPE_PPP:
			name = "ppp";
			break;
		case IF_TYPE_SOFTWARE_LOOPBACK:
			name = "lo";
			break;
		case IF_TYPE_TUNNEL:
			name = "tun";
			break;
		default:
			name = "unk";
			break;
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
	} else if (strncmp(device, "ppp", 3) == 0) {
		type = INTF_TYPE_PPP;
	} else if (strncmp(device, "lo", 2) == 0) {
		type = INTF_TYPE_LOOPBACK;
	} else if (strncmp(device, "tun", 3) == 0) {
		type = INTF_TYPE_TUN;
	}
	return (type);
}

static void
_ifcombo_add(struct ifcombo *ifc, DWORD ipv4_idx, DWORD ipv6_idx)
{
	void* pmem = NULL;
	if (ifc->cnt == ifc->max) {
		if (ifc->idx) {
			ifc->max *= 2;
			pmem = realloc(ifc->idx,
			    sizeof(ifc->idx[0]) * ifc->max);
		} else {
			ifc->max = 8;
			pmem = malloc(sizeof(ifc->idx[0]) * ifc->max);
		}
		if (!pmem) {
			/* malloc or realloc failed. Restore state.
			 * TODO: notify caller. */
			ifc->max = ifc->cnt;
			return;
		}
		ifc->idx = pmem;
	}
	ifc->idx[ifc->cnt].ipv4 = ipv4_idx;
	ifc->idx[ifc->cnt].ipv6 = ipv6_idx;
	ifc->cnt++;
}

/* Map an MIB interface type into an internal interface type. The
   internal types are never exposed to users of this library; they exist
   only for the sake of ordering interface types within an intf_handle,
   which has an array of ifcombo structures ordered by type. Entries in
   an intf_handle must not be stored or accessed by a raw MIB type
   number because they will not be able to be found by a device name
   such as "net0" if the device name does not map exactly to the type. */
static int
_if_type_canonicalize(int type)
{
       return _ifcombo_type(_ifcombo_name(type));
}

static void
_adapter_address_to_entry(intf_t *intf, IP_ADAPTER_ADDRESSES *a,
	struct intf_entry *entry)
{
	struct addr *ap, *lap;
	int i;
	int type;
	IP_ADAPTER_UNICAST_ADDRESS *addr;
	
	/* The total length of the entry may be passed inside entry.
           Remember it and clear the entry. */
	u_int intf_len = entry->intf_len;
	memset(entry, 0, sizeof(*entry));
	entry->intf_len = intf_len;

	type = _if_type_canonicalize(a->IfType);
	for (i = 0; i < intf->ifcombo[type].cnt; i++) {
		if (intf->ifcombo[type].idx[i].ipv4 == a->IfIndex &&
		    intf->ifcombo[type].idx[i].ipv6 == a->Ipv6IfIndex) {
			break;
		}
	}
	/* XXX - type matches MIB-II ifType. */
	snprintf(entry->intf_name, sizeof(entry->intf_name), "%s%lu",
	    _ifcombo_name(a->IfType), i);
	entry->intf_type = (uint16_t)type;
	
	/* Get interface flags. */
	entry->intf_flags = 0;
	if (a->OperStatus == IfOperStatusUp)
		entry->intf_flags |= INTF_FLAG_UP;
	if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
		entry->intf_flags |= INTF_FLAG_LOOPBACK;
	else
		entry->intf_flags |= INTF_FLAG_MULTICAST;
	
	/* Get interface MTU. */
	entry->intf_mtu = a->Mtu;
	
	/* Get hardware address. */
	if (a->PhysicalAddressLength == ETH_ADDR_LEN) {
		entry->intf_link_addr.addr_type = ADDR_TYPE_ETH;
		entry->intf_link_addr.addr_bits = ETH_ADDR_BITS;
		memcpy(&entry->intf_link_addr.addr_eth, a->PhysicalAddress,
		    ETH_ADDR_LEN);
	}
	/* Get addresses. */
	ap = entry->intf_alias_addrs;
	lap = ap + ((entry->intf_len - sizeof(*entry)) /
	    sizeof(entry->intf_alias_addrs[0]));
	for (addr = a->FirstUnicastAddress; addr != NULL; addr = addr->Next) {
		IP_ADAPTER_PREFIX *prefix;
		unsigned short bits;

		/* Find the netmask length. This is stored in a parallel list.
		   We just take the first one with a matching address family,
		   but that may not be right. Windows Vista and later has an
		   OnLinkPrefixLength member that is stored right with the
		   unicast address. */
		bits = 0;
    if (addr->Length >= 48) {
      /* "The size of the IP_ADAPTER_UNICAST_ADDRESS structure changed on
       * Windows Vista and later. The Length member should be used to determine
       * which version of the IP_ADAPTER_UNICAST_ADDRESS structure is being
       * used."
       * Empirically, 48 is the value on Windows 8.1, so should include the
       * OnLinkPrefixLength member.*/
      bits = addr->OnLinkPrefixLength;
    }
    else {
		for (prefix = a->FirstPrefix; prefix != NULL; prefix = prefix->Next) {
			if (prefix->Address.lpSockaddr->sa_family == addr->Address.lpSockaddr->sa_family) {
				bits = (unsigned short) prefix->PrefixLength;
				break;
			}
		}
    }

		if (entry->intf_addr.addr_type == ADDR_TYPE_NONE) {
			/* Set primary address if unset. */
			addr_ston(addr->Address.lpSockaddr, &entry->intf_addr);
			entry->intf_addr.addr_bits = bits;
		} else if (ap < lap) {
			/* Set aliases. */
			addr_ston(addr->Address.lpSockaddr, ap);
			ap->addr_bits = bits;
			ap++;
			entry->intf_alias_num++;
		}
	}
	entry->intf_len = (u_int) ((u_char *)ap - (u_char *)entry);
}

#define NPCAP_SERVICE_REGISTRY_KEY "SYSTEM\\CurrentControlSet\\Services\\npcap"

/* The name of the Npcap loopback adapter is stored in the npcap service's
 * Registry key in the LoopbackAdapter value. For legacy loopback support, this
 * is a name like "NPF_{GUID}", but for newer Npcap the name is "NPF_Loopback"
 */
int intf_get_loopback_name(char *buffer, int buf_size)
{
	HKEY hKey;
	DWORD type;
	int size = buf_size;
	int res = 0;

	memset(buffer, 0, buf_size);

	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, NPCAP_SERVICE_REGISTRY_KEY "\\Parameters", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
	{
		if (RegQueryValueExA(hKey, "LoopbackAdapter", 0, &type, (LPBYTE)buffer, &size) == ERROR_SUCCESS && type == REG_SZ)
		{
			res = 1;
		}
		else
		{
			res = 0;
		}

		RegCloseKey(hKey);
	}
	else
	{
		res = 0;
	}

	return res;
}

static IP_ADAPTER_ADDRESSES*
_update_tables_for_npcap_loopback(IP_ADAPTER_ADDRESSES *p)
{
	IP_ADAPTER_ADDRESSES *a_prev = NULL;
	IP_ADAPTER_ADDRESSES *a;
	IP_ADAPTER_ADDRESSES *a_original_loopback_prev = NULL;
	IP_ADAPTER_ADDRESSES *a_original_loopback = NULL;
	IP_ADAPTER_ADDRESSES *a_npcap_loopback = NULL;
	static char npcap_loopback_name[1024] = {0};

	/* Don't bother hitting the registry every time. Not ideal for long-running
	 * processes, but works for Nmap.  */
	if (npcap_loopback_name[0] == '\0')
		g_has_npcap_loopback = intf_get_loopback_name(npcap_loopback_name, 1024);
	else if (g_has_npcap_loopback == 0)
		return p;

	if (!p)
		return p;

	/* Loop through the addresses looking for the dummy loopback interface from Windows. */
	for (a = p; a != NULL; a = a->Next) {
		if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) {
			/* Dummy loopback. Keep track of it. */
			a_original_loopback = a;
			a_original_loopback_prev = a_prev;
		}
		else if (strcmp(a->AdapterName, npcap_loopback_name + strlen(_DEVICE_PREFIX) - 1) == 0) {
			/* Legacy loopback adapter. The modern one doesn't show up in GetAdaptersAddresses. */
			a_npcap_loopback = a;
		}
		a_prev = a;
	}

	/* If there's no loopback on this system, something's wrong. Windows is
	 * supposed to create this. */
	if (!a_original_loopback)
		return p;
	g_has_npcap_loopback = 1;
	/* If we didn't find the legacy adapter, use the modern adapter name. */
	if (!a_npcap_loopback) {
		/* Overwrite the name we got from the Registry, in case it's a broken legacy
		 * install, in which case we'll never find the legacy adapter anyway. */
		strlcpy(npcap_loopback_name, _DEVICE_PREFIX "NPF_Loopback", 1024);
		/* Overwrite the AdapterName from the system's own loopback adapter with
		 * the NPF_Loopback name. This is what we use to open the adapter with
		 * Packet.dll later. */
		a_original_loopback->AdapterName = npcap_loopback_name + sizeof(_DEVICE_PREFIX) - 1;
		return p;
	}
	else {
		/* Legacy loopback adapter was found. Copy some key info from the system's
		 * loopback adapter. */
		a_npcap_loopback->IfType = a_original_loopback->IfType;
		a_npcap_loopback->FirstUnicastAddress = a_original_loopback->FirstUnicastAddress;
		a_npcap_loopback->FirstPrefix = a_original_loopback->FirstPrefix;
		memset(a_npcap_loopback->PhysicalAddress, 0, ETH_ADDR_LEN);
		/* Unlink the original loopback adapter from the list. We'll use Npcap's instead. */
		if (a_original_loopback_prev) {
			a_original_loopback_prev->Next = a_original_loopback_prev->Next->Next;
			return p;
		}
		else if (a_original_loopback == p) {
			return a_original_loopback->Next;
		}
		else {
			return p;
		}
	}
}

static int
_refresh_tables(intf_t *intf)
{
	IP_ADAPTER_ADDRESSES *p;
	DWORD ret;
	ULONG len;

	p = NULL;
	/* GetAdaptersAddresses is supposed to return ERROR_BUFFER_OVERFLOW and
	 * set len to the required size when len is too small. So normally we
	 * would call the function once with a small len, and then again with
	 * the longer len. But, on Windows 2003, apparently you only get
	 * ERROR_BUFFER_OVERFLOW the *first* time you call the function with a
	 * too-small len--the next time you get ERROR_INVALID_PARAMETER. So this
	 * function would fail the second and later times it is called.
	 *
	 * So, make the first call using a large len. On Windows 2003, this will
	 * work the first time as long as there are not too many adapters. (It
	 * will still fail with ERROR_INVALID_PARAMETER if there are too many
	 * adapters, but this will happen infrequently because of the large
	 * buffer.) Other systems that always return ERROR_BUFFER_OVERFLOW when
	 * appropriate will enlarge the buffer if the initial len is too short. */
	len = 16384;
	do {
		free(p);
		p = malloc(len);
		if (p == NULL)
			return (-1);
		ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST, NULL, p, &len);
	} while (ret == ERROR_BUFFER_OVERFLOW);

	if (ret != NO_ERROR) {
		free(p);
		return (-1);
	}
	p = _update_tables_for_npcap_loopback(p);
	intf->iftable = p;

	/*
	 * Map "unfriendly" win32 interface indices to ours.
	 * XXX - like IP_ADAPTER_INFO ComboIndex
	 */
	for (p = intf->iftable; p != NULL; p = p->Next) {
		int type;
		type = _if_type_canonicalize(p->IfType);
		if (type < MIB_IF_TYPE_MAX)
			_ifcombo_add(&intf->ifcombo[type], p->IfIndex, p->Ipv6IfIndex);
		else
			return (-1);
	}
	return (0);
}

static IP_ADAPTER_ADDRESSES *
_find_adapter_address(intf_t *intf, const char *device)
{
	IP_ADAPTER_ADDRESSES *a;
	char *p = (char *)device;
	int n, type = _ifcombo_type(device);
	
	while (isalpha((int) (unsigned char) *p)) p++;
	n = atoi(p);

	for (a = intf->iftable; a != NULL; a = a->Next) {
		if ( intf->ifcombo[type].idx != NULL &&
		    intf->ifcombo[type].idx[n].ipv4 == a->IfIndex &&
		    intf->ifcombo[type].idx[n].ipv6 == a->Ipv6IfIndex) {
			return a;
		}
	}

	return NULL;
}

static IP_ADAPTER_ADDRESSES *
_find_adapter_address_by_index(intf_t *intf, int af, unsigned int index)
{
	IP_ADAPTER_ADDRESSES *a;

	for (a = intf->iftable; a != NULL; a = a->Next) {
		if (af == AF_INET && index == a->IfIndex)
			return a;
		if (af == AF_INET6 && index == a->Ipv6IfIndex)
			return a;
	}

	return NULL;
}

intf_t *
intf_open(void)
{
	return (calloc(1, sizeof(intf_t)));
}

int
intf_get(intf_t *intf, struct intf_entry *entry)
{
	IP_ADAPTER_ADDRESSES *a;
	
	if (_refresh_tables(intf) < 0)
		return (-1);
	
	a = _find_adapter_address(intf, entry->intf_name);
	if (a == NULL)
		return (-1);

	_adapter_address_to_entry(intf, a, entry);
	
	return (0);
}

/* Look up an interface from an index, such as a sockaddr_in6.sin6_scope_id. */
int
intf_get_index(intf_t *intf, struct intf_entry *entry, int af, unsigned int index)
{
	IP_ADAPTER_ADDRESSES *a;

	if (_refresh_tables(intf) < 0)
		return (-1);

	a = _find_adapter_address_by_index(intf, af, index);
	if (a == NULL)
		return (-1);

	_adapter_address_to_entry(intf, a, entry);

	return (0);
}

int
intf_get_src(intf_t *intf, struct intf_entry *entry, struct addr *src)
{
	IP_ADAPTER_ADDRESSES *a;
	IP_ADAPTER_UNICAST_ADDRESS *addr;

	if (src->addr_type != ADDR_TYPE_IP) {
		errno = EINVAL;
		return (-1);
	}
	if (_refresh_tables(intf) < 0)
		return (-1);
	
	for (a = intf->iftable; a != NULL; a = a->Next) {
		for (addr = a->FirstUnicastAddress; addr != NULL; addr = addr->Next) {
			struct addr dnet_addr;

			addr_ston(addr->Address.lpSockaddr, &dnet_addr);
			if (addr_cmp(&dnet_addr, src) == 0) {
				_adapter_address_to_entry(intf, a, entry);
				return (0);
			}
		}
	}
	errno = ENXIO;
	return (-1);
}

int
intf_get_dst(intf_t *intf, struct intf_entry *entry, struct addr *dst)
{
	errno = ENOSYS;
	SetLastError(ERROR_NOT_SUPPORTED);
	return (-1);
}

int
intf_set(intf_t *intf, const struct intf_entry *entry)
{
	/*
	 * XXX - could set interface up/down via SetIfEntry(),
	 * but what about the rest of the configuration? :-(
	 * {Add,Delete}IPAddress for 2000/XP only
	 */
	errno = ENOSYS;
	SetLastError(ERROR_NOT_SUPPORTED);
	return (-1);
}

int
intf_loop(intf_t *intf, intf_handler callback, void *arg)
{
	IP_ADAPTER_ADDRESSES *a;
	struct intf_entry *entry;
	u_char ebuf[1024];
	int ret = 0;

	if (_refresh_tables(intf) < 0)
		return (-1);
	
	entry = (struct intf_entry *)ebuf;
	
	for (a = intf->iftable; a != NULL; a = a->Next) {
		entry->intf_len = sizeof(ebuf);
		_adapter_address_to_entry(intf, a, entry);
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
		free(intf);
	}
	return (NULL);
}

/* Converts a libdnet interface name to its pcap equivalent. The pcap name is
   stored in pcapdev up to a length of pcapdevlen, including the terminating
   '\0'. Returns -1 on error. */
int
intf_get_pcap_devname_cached(const char *intf_name, char *pcapdev, int pcapdevlen, int refresh)
{
	IP_ADAPTER_ADDRESSES *a;
	static pcap_if_t *pcapdevs = NULL;
	pcap_if_t *pdev;
	intf_t *intf;
	char errbuf[PCAP_ERRBUF_SIZE];

	if ((intf = intf_open()) == NULL)
		return (-1);
	if (_refresh_tables(intf) < 0) {
		intf_close(intf);
		return (-1);
	}
	a = _find_adapter_address(intf, intf_name);

	if (a == NULL) {
		intf_close(intf);
		return (-1);
	}

  if (refresh) {
    pcap_freealldevs(pcapdevs);
    pcapdevs = NULL;
  }

  if (pcapdevs == NULL) {
    if (pcap_findalldevs(&pcapdevs, errbuf) == -1) {
      intf_close(intf);
      return (-1);
    }
  }

	/* Loop through all the pcap devices until we find a match. */
	for (pdev = pcapdevs; pdev != NULL; pdev = pdev->next) {
		char *name;

		if (pdev->name == NULL || strlen(pdev->name) < sizeof(_DEVICE_PREFIX))
			continue;
		/* "\\Device\\NPF_{GUID}"
		 * "\\Device\\NPF_Loopback"
		 * Find the '{'after device prefix.
		 */
		name = strchr(pdev->name + sizeof(_DEVICE_PREFIX) - 1, '{');
		if (name == NULL) {
			/* If no GUID, just match the whole device name */
			name = pdev->name + sizeof(_DEVICE_PREFIX) - 1;
		}
		if (strcmp(name, a->AdapterName) == 0)
			break;
	}
	if (pdev != NULL)
		strlcpy(pcapdev, pdev->name, pcapdevlen);
	intf_close(intf);
	if (pdev == NULL)
		return -1;
	else
		return 0;
}
int
intf_get_pcap_devname(const char *intf_name, char *pcapdev, int pcapdevlen)
{
  return intf_get_pcap_devname_cached(intf_name, pcapdev, pcapdevlen, 0);
}
