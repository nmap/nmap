/*
 * eth-win32.c
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: eth-win32.c,v 1.11 2005/02/15 06:37:06 dugsong Exp $
 */

#ifdef _WIN32
#include "dnet_winconfig.h"
#else
#include "config.h"
#endif

/* XXX - VC++ 6.0 bogosity 
#define sockaddr_storage sockaddr */
/* #include <Packet32.h> */
/* #undef sockaddr_storage */
/* #include <Ntddndis.h> */

#include <errno.h>
#include <stdlib.h>

#include "dnet.h"
#include <winsock2.h>
#include "pcap.h"
#include <Packet32.h>
#include <Ntddndis.h>

struct eth_handle {
	LPADAPTER	 lpa;
	LPPACKET	 pkt;
};

struct adapter {
	char		 name[64];
	char		*desc;
};

eth_t *
eth_open(const char *device)
{
	eth_t *eth;
	char pname[128];
	
    if (intf_get_pcap_devname(device, pname, sizeof(pname)) != 0)
		return NULL;
	
	if ((eth = calloc(1, sizeof(*eth))) == NULL)
		return (NULL);
	
	if ((eth->lpa = PacketOpenAdapter(pname)) == NULL ||
	    eth->lpa->hFile == INVALID_HANDLE_VALUE)
		return (eth_close(eth));

	PacketSetBuff(eth->lpa, 512000);
	
	if ((eth->pkt = PacketAllocatePacket()) == NULL)
		return (eth_close(eth));
	
	return (eth);
}

ssize_t
eth_send(eth_t *eth, const void *buf, size_t len)
{
	PacketInitPacket(eth->pkt, (void *)buf, (UINT) len);
	PacketSendPacket(eth->lpa, eth->pkt, TRUE);
	return ((ssize_t) len);
}

eth_t *
eth_close(eth_t *eth)
{
	if (eth != NULL) {
		if (eth->pkt != NULL)
			PacketFreePacket(eth->pkt);
		if (eth->lpa != NULL)
			PacketCloseAdapter(eth->lpa);
		free(eth);
	}
	return (NULL);
}

int
eth_get(eth_t *eth, eth_addr_t *ea)
{
	PACKET_OID_DATA *data;
	u_char buf[512];

	data = (PACKET_OID_DATA *)buf;
	data->Oid = OID_802_3_CURRENT_ADDRESS;
	data->Length = ETH_ADDR_LEN;

	if (PacketRequest(eth->lpa, FALSE, data) == TRUE) {
		memcpy(ea, data->Data, ETH_ADDR_LEN);
		return (0);
	}
	return (-1);
}

int
eth_set(eth_t *eth, const eth_addr_t *ea)
{
	PACKET_OID_DATA *data;
	u_char buf[512];

	data = (PACKET_OID_DATA *)buf;
	data->Oid = OID_802_3_CURRENT_ADDRESS;
	memcpy(data->Data, ea, ETH_ADDR_LEN);
	data->Length = ETH_ADDR_LEN;
	
	if (PacketRequest(eth->lpa, TRUE, data) == TRUE)
		return (0);
	
	return (-1);
}

/* Converts a dnet interface name (ifname) to its pcap equivalent, which is stored in
pcapdev (up to a length of pcapdevlen).  Returns 0 and fills in pcapdev if successful. */
int intf_get_pcap_devname(const char *ifname, char *pcapdev, int pcapdevlen) {
	int i;
	intf_t *intf;
	struct intf_entry ie;
	pcap_if_t *pcapdevs;
	pcap_if_t *pdev;
	char pname[128];
	struct sockaddr_in devip;
	pcap_addr_t *pa;

	if ((intf = intf_open()) == NULL)
		return -1;
	
	pname[0] = '\0';
	memset(&ie, 0, sizeof(ie));
	strlcpy(ie.intf_name, ifname, sizeof(ie.intf_name));
	if (intf_get(intf, &ie) != 0) {
		intf_close(intf);
		return -1;
	}
	intf_close(intf);
	
	/* Next we must find the pcap device name corresponding to the device.
	   The device description used to be compared with those from PacketGetAdapterNames(), but
	   that was unrelaible because dnet and pcap sometimes give different descriptions.  For example, 
	   dnet gave me "AMD PCNET Family PCI Ethernet Adapter - Packet Scheduler Miniport" for one of my 
	   adapters (in vmware), while pcap described it as "VMware Accelerated AMD PCNet Adapter (Microsoft's
	   Packet Scheduler)". Plus,  Packet* functions aren't really supported for external use by the 
	   WinPcap folks.  So I have rewritten this to compare interface addresses (which has its own 
	   problems -- what if you want to listen an an interface with no IP address set?) --Fyodor */
	if (pcap_findalldevs(&pcapdevs, NULL) == -1)
		return -1;

	for(pdev=pcapdevs; pdev && !pname[0]; pdev = pdev->next) {
		for (pa=pdev->addresses; pa && !pname[0]; pa = pa->next) {
			if (pa->addr->sa_family != AF_INET)
				continue;

			/* Match this address of pdev against all the addresses of ie.
			   i == -1 tests against the primary address of the interface.
			   i >= 0 tests against alias addresses. */
			for (i = -1; i < (int) ie.intf_alias_num; i++) {
				if (i == -1) {
					if (ie.intf_addr.addr_type != ADDR_TYPE_IP)
						continue;
					addr_ntos(&ie.intf_addr, (struct sockaddr *) &devip);
				} else {
					if (ie.intf_alias_addrs[i].addr_type != ADDR_TYPE_IP)
						continue;
					addr_ntos(&ie.intf_alias_addrs[i], (struct sockaddr *) &devip);
				}
				if (((struct sockaddr_in *)pa->addr)->sin_addr.s_addr == devip.sin_addr.s_addr) {
					/* Found it -- Yay! */
					strlcpy(pname, pdev->name, sizeof(pname));
					/* Assigning pname[0] breaks out of the outer loops too. */
					break;
				}
			}
		}
	}

	pcap_freealldevs(pcapdevs);
	if (pname[0]) {
		strlcpy(pcapdev, pname, pcapdevlen);
		return 0;
	}
	return -1;
}
