#ifndef WINIP_H
#define WINIP_H

/*

winip.h: interface definition to the winip library
Copyright (C) 2000  Andy Lutomirski

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License, version 2.1, as published by the Free Software
Foundation, with the exception that if this copy of the library
is distributed under the Lesser GNU Public License (as opposed
to the ordinary GPL), you may ignore section 6b, and that all
copies distributed without exercising section 3 must retain this
paragraph in its entirety.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

*/

/*	The ifType spec from RFCs 1156 and 1213


other(1),          -- none of the following
regular1822(2),
hdh1822(3),
ddn-x25(4),
rfc877-x25(5),
ethernet-csmacd(6),
iso88023-csmacd(7),
iso88024-tokenBus(8),
iso88025-tokenRing(9),
iso88026-man(10),
starLan(11),
proteon-10MBit(12),
proteon-80MBit(13),
hyperchannel(14),
fddi(15),
lapb(16),
sdlc(17),
t1-carrier(18),
cept(19),          -- european equivalent of T-1
basicIsdn(20),
primaryIsdn(21),   -- proprietary serial
propPointToPointSerial(22)
ppp(23)
softwareLoopback(24)
eon(25)
ethernet-3Mbit(26)
nsip(27)
slip(28)
ultra(29)
ds3(30)
sip(31)
frame-relay(32)

  */

#include <pcap.h>

#define IF_other 1
#define IF_regular1822 2
#define IF_hdh1822 3
#define IF_ddn_x25 4
#define IF_rfc877_x25 5
#define IF_ethernet_csmacd 6
#define IF_iso88023_csmacd 7
#define IF_iso88024_tokenBus 8
#define IF_iso88025_tokenRing 9
#define IF_iso88026_man 10
#define IF_starLan 11
#define IF_proteon_10MBit 12
#define IF_proteon_80MBit 13
#define IF_hyperchannel 14
#define IF_fddi 15
#define IF_lapb 16
#define IF_sdlc 17
#define IF_t1_carrier 18
#define IF_cept 19 // european equivalent of T_1
#define IF_basicIsdn 20
#define IF_primaryIsdn 21 // proprietary serial
#define IF_propPointToPointSerial 22
#define IF_ppp 23
#define IF_softwareLoopback 24
#define IF_eon 25
#define IF_ethernet_3Mbit 26
#define IF_nsip 27
#define IF_slip 28
#define IF_ultra 29
#define IF_ds3 30
#define IF_sip 31
#define IF_frame_relay 32

#include <windows.h>

#ifndef EXTERNC
# ifdef __cplusplus
#  define EXTERNC extern "C"
# else
#  define EXTERNC extern
# endif
#endif


//	change to <iphlpapi.h> if you have the SDK
#include "iphlpapi.h"

//	windows-specific options
struct winops {
	int norawsock, nopcap, forcerawsock, listinterfaces, nt4route, noiphlpapi, trace;
};

EXTERNC struct winops wo;

/* Sets a pcap filter function -- makes SOCK_RAW reads easier */
typedef int (*PFILTERFN)(const char *packet, unsigned int len); /* 1 to keep */

//	Makes gcc happy
//	One wonders why VC doesn't complain...
class Target;
EXTERNC void set_pcap_filter(const char *device, pcap_t *pd, PFILTERFN filter, char *bpf, ...);


typedef struct _IPNODE {
	DWORD ip;	//	net order
	struct _IPNODE *next;
	DWORD ifi;	//	amusing hack :)
} IPNODE;

typedef struct _WINIP_IF {
	int winif;	//	The IpHlpApi index
	char name[16];	//	The name
	DWORD type;

	BYTE physaddr[MAXLEN_PHYSADDR];
	int physlen;
	
	IPNODE *firstip;

	//	pcap support
	char *pcapname;	//	might be pointer to Unicode
} WINIP_IF;

/*   (exported) functions   */
EXTERNC void winip_init();
EXTERNC void winip_postopt_init();
EXTERNC void winip_barf(const char *msg);
EXTERNC int winip_corruption_possible();

//	name translation
EXTERNC int name2ifi(const char *name);
EXTERNC const char *ifi2name(int ifi);
EXTERNC int ifi2winif(int ifi);
EXTERNC int winif2ifi(int winif);
EXTERNC int ifi2ipaddr(int ifi, struct in_addr *addr);
EXTERNC int ipaddr2ifi(DWORD ip);
EXTERNC const WINIP_IF* ifi2ifentry(int ifi);

//extern int pcap_avail;
//extern int rawsock_avail;

EXTERNC int get_best_route(DWORD dest, PMIB_IPFORWARDROW r);



//	pcapsend interface
EXTERNC void pcapsend_init();
EXTERNC pcap_t *my_real_pcap_open_live(const char *device, int snaplen, int promisc, int to_ms);
EXTERNC int pcapsendraw(const char *packet, int len, 
						struct sockaddr *to, int tolen);

//	rawrecv interface
EXTERNC pcap_t *rawrecv_open(const char *dev);
EXTERNC void rawrecv_close(pcap_t *pd);
EXTERNC char *rawrecv_readip(pcap_t *pd, unsigned int *len, long to_usec, struct timeval *rcvdtime);
EXTERNC void rawrecv_setfilter(pcap_t *pd, PFILTERFN filterfn);
EXTERNC char *readip_pcap_real(pcap_t *pd, unsigned int *len, long to_usec);

//	Win95 support
EXTERNC DWORD GetIfTableSafe(PMIB_IFTABLE, DWORD*, BOOL);
EXTERNC DWORD GetIpAddrTableSafe(PMIB_IPADDRTABLE, DWORD*, BOOL);
EXTERNC DWORD GetIpNetTableSafe(PMIB_IPNETTABLE, DWORD*, BOOL);
EXTERNC DWORD GetIpForwardTableSafe(PMIB_IPFORWARDTABLE, DWORD*, BOOL);

#endif

