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

/* From Npcap's Loopback.h */
/*
 * * Structure of a DLT_NULL header.
 * */
typedef struct _DLT_NULL_HEADER
{
    UINT  null_type;
} DLT_NULL_HEADER, *PDLT_NULL_HEADER;

/*
 * * The length of the combined header.
 * */
#define DLT_NULL_HDR_LEN  sizeof(DLT_NULL_HEADER)

/*
 * * Types in a DLT_NULL (Loopback) header.
 * */
#define DLTNULLTYPE_IP    0x00000002  /* IP protocol */
#define DLTNULLTYPE_IPV6  0x00000018 /* IPv6 */
/* END Loopback.h */

struct eth_handle {
	LPADAPTER	 lpa;
	LPPACKET	 pkt;
	NetType    type;
};

eth_t *
eth_open(const char *device)
{
	eth_t *eth;
	char pcapdev[128];
  HANDLE pcapMutex;
  DWORD wait;

	if (eth_get_pcap_devname(device, pcapdev, sizeof(pcapdev)) != 0)
		return (NULL);

	if ((eth = calloc(1, sizeof(*eth))) == NULL)
		return (NULL);
  pcapMutex = CreateMutex(NULL, 0, "Global\\DnetPcapHangAvoidanceMutex");
  wait = WaitForSingleObject(pcapMutex, INFINITE);
	eth->lpa = PacketOpenAdapter(pcapdev);
  if (wait == WAIT_ABANDONED || wait == WAIT_OBJECT_0) {
    ReleaseMutex(pcapMutex);
  }
  CloseHandle(pcapMutex);
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
	if (!PacketGetNetType(eth->lpa, &eth->type)) {
	  eth_close(eth);
	  return NULL;
  }

	return (eth);
}

ssize_t
eth_send(eth_t *eth, const void *buf, size_t len)
{
  /* 14-byte Ethernet header, but DLT_NULL is a 4-byte header. Skip over the difference */
  DLT_NULL_HEADER *hdr = (uint8_t *)buf + ETH_HDR_LEN - DLT_NULL_HDR_LEN;
  if (eth->type.LinkType == NdisMediumNull) {
    switch (ntohs(((struct eth_hdr *)buf)->eth_type)) {
      case ETH_TYPE_IP:
        hdr->null_type = DLTNULLTYPE_IP;
        break;
      case ETH_TYPE_IPV6:
        hdr->null_type = DLTNULLTYPE_IPV6;
        break;
      default:
        hdr->null_type = 0;
        break;
    }
    PacketInitPacket(eth->pkt, (void *)((uint8_t *)buf + ETH_HDR_LEN - DLT_NULL_HDR_LEN), (UINT) (len - ETH_HDR_LEN + DLT_NULL_HDR_LEN));
    PacketSendPacket(eth->lpa, eth->pkt, TRUE);
  }
  else {
    PacketInitPacket(eth->pkt, (void *)buf, (UINT) len);
    PacketSendPacket(eth->lpa, eth->pkt, TRUE);
  }
	return (ssize_t)(len);
}

eth_t *
eth_close(eth_t *eth)
{
  HANDLE pcapMutex;
  DWORD wait;
	if (eth != NULL) {
		if (eth->pkt != NULL)
			PacketFreePacket(eth->pkt);
		if (eth->lpa != NULL)
    {
      pcapMutex = CreateMutex(NULL, 0, "Global\\DnetPcapHangAvoidanceMutex");
      wait = WaitForSingleObject(pcapMutex, INFINITE);
			PacketCloseAdapter(eth->lpa);
      if (wait == WAIT_ABANDONED || wait == WAIT_OBJECT_0) {
        ReleaseMutex(pcapMutex);
      }
      CloseHandle(pcapMutex);
    }
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
