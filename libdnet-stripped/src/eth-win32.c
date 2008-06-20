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
