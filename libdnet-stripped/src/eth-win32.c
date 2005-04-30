/*
 * eth-win32.c
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: eth-win32.c,v 1.11 2005/02/15 06:37:06 dugsong Exp $
 */

#include "config.h"

/* XXX - VC++ 6.0 bogosity */
#define sockaddr_storage sockaddr
#include <Packet32.h>
#undef sockaddr_storage
#include <Ntddndis.h>

#include <errno.h>
#include <stdlib.h>

#include "dnet.h"

struct eth_handle {
	LPADAPTER	 lpa;
	LPPACKET	 pkt;
};

struct adapter {
	char		 name[64];
	char		*desc;
};

/* XXX */
extern const char *intf_get_desc(intf_t *intf, const char *device);

eth_t *
eth_open(const char *device)
{
	eth_t *eth;
	struct adapter alist[16];
	WCHAR *name, wbuf[2048];
	ULONG wlen;
	char *desc, *namea;
	int i, j, alen;
	OSVERSIONINFO osvi;
	intf_t *intf;

	if ((intf = intf_open()) == NULL)
		return (NULL);
	
	device = intf_get_desc(intf, device);
	intf_close(intf);

	if (device == NULL)
		return (NULL);
	
	alen = sizeof(alist) / sizeof(alist[0]);
	wlen = sizeof(wbuf) / sizeof(wbuf[0]);
	
	PacketGetAdapterNames((char *)wbuf, &wlen);

	/* Determine Windows version */
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	GetVersionEx(&osvi);

	if ((osvi.dwPlatformId == VER_PLATFORM_WIN32_NT) &&
	    (osvi.dwMajorVersion >= 4)) {
		for (name = wbuf, i = 0; *name != '\0' && i < alen; i++) {
			wcstombs(alist[i].name, name, sizeof(alist[0].name));
			while (*name++ != '\0')
				;
		}
		for (desc = (char *)name + 2, j = 0; *desc != '\0' && j < alen;
		    j++) {
			alist[j].desc = desc;
			while (*desc++ != '\0')
				;
		}
	} else {
		for (namea = (char *)wbuf, i = 0; *namea != '\0' && i < alen;
		    i++) {
			strlcpy(alist[i].name, namea, sizeof(alist[0].name));
			while (*namea++ != '\0')
				;
		}
		for (desc = namea + 1, j = 0; *desc != '\0' && j < alen; j++) {
			alist[j].desc = desc;
			while (*desc++ != '\0')
				;
		}
	}
	for (i = 0; i < j; i++) {
		if (strcmp(device, alist[i].desc) == 0)
			break;
	}
	if (i == j)
		return (NULL);
	
	if ((eth = calloc(1, sizeof(*eth))) == NULL)
		return (NULL);
	
	if ((eth->lpa = PacketOpenAdapter(alist[i].name)) == NULL ||
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
	PacketInitPacket(eth->pkt, (void *)buf, len);
	PacketSendPacket(eth->lpa, eth->pkt, TRUE);
	return (len);
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
