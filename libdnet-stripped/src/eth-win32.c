/*
 * eth-win32.c
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: eth-win32.c 613 2005-09-26 02:46:57Z dugsong $
 */

#ifdef _WIN32
#include "dnet_winconfig.h"
#else
#include "config.h"
#endif

/* XXX - VC++ 6.0 bogosity */
#define sockaddr_storage sockaddr
#undef sockaddr_storage

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

eth_t *
eth_open(const char *device)
{
	eth_t *eth;
	char pcapdev[128];

	if (eth_get_pcap_devname(device, pcapdev, sizeof(pcapdev)) != 0)
		return (NULL);

	if ((eth = calloc(1, sizeof(*eth))) == NULL)
		return (NULL);
	eth->lpa = PacketOpenAdapter(pcapdev);
	if (eth->lpa == NULL) {
		eth_close(eth);
		return (NULL);
	}
	PacketSetBuff(eth->lpa, 512000);
	eth->pkt = PacketAllocatePacket();
	if (eth->pkt == NULL) {
		eth_close(eth);
		return NULL;
	}

	return (eth);
}

ssize_t
eth_send(eth_t *eth, const void *buf, size_t len)
{
	PacketInitPacket(eth->pkt, (void *)buf, (UINT) len);
	PacketSendPacket(eth->lpa, eth->pkt, TRUE);
	return (ssize_t)(len);
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

int
eth_get_pcap_devname(const char *intf_name, char *pcapdev, int pcapdevlen)
{
	return intf_get_pcap_devname(intf_name, pcapdev, pcapdevlen);
}
