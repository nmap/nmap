/*

pcapsend.c: raw IP sends using winpcap
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

Implements raw sends using winpcap.
Not as easy as it sounds...

Note: this was inspired by ryan@eeye.com's attempt to
do the same thing.  It no longer bears much (any?)
resemblance to the original.  This version uses no
registry calls or undoc'd features, and works on 98,
NT4, W2K, and probably Me.  (Ryan's didn't work on
98, or, as far as I can tell, Win2K).

Routing is done with GetBestRoute, or a homebrew version
for NT4.  ARP is in a separate thread to avoid issues
when scanning multiple hosts.  There is a slight ARP
latency issue (250ms max).

Performance when scanning multiple local hosts will go
down the drain if o.maxparallelism > FAILCACHELEN and
there are lots of continuous down hosts.  Oh, well.

Lastly, a question for Fyodor:  is WSAEHOSTUNREACH a good
error return for a failed ARP query?  (It should convince
nmap not to try the host again, while not confusing nmap.)

Update 12/08/04: Dana Epp (dana_at_vulscan.com) sdded SendARP stuff
for XP firewall (on by default w/SP2)

*/

#include "..\tcpip.h"
#include "..\..\NmapOps.h"
#include "winip.h"

#define MAXARPTRIES 3
#define ARPINTERVAL 200	//	should be _less_ than a multiple of POLLINTERVAL
#define POLLINTERVAL 250
#define FAILCACHELEN 25	//	make it high
#define ARPCACHELEN 25

void pcapsend_init();

#ifdef _DEBUG
//#define THREAD_DEBUG 1
#endif

#define REALSEND_WATCH

static void pcapsend_cleanup(void);

static int realsend(LPADAPTER pAdap,
					const char *packet, int len,
					BYTE *to, BYTE *from, int addrlen,
					DWORD linktype, DWORD protocol);

#define ETH_IP  0x0800
#define ETH_ARP 0x0806


#if defined(THREAD_DEBUG) && THREAD_DEBUG > 1
#define foo0 printf
#define foo1 printf
#define foo2 printf
#else
#define foo0(x) ((void)0)
#define foo1(x,y) ((void)0)
#define foo2(x,y,z) ((void)0)
#endif

static int pcapsend_inited = 0;

static LPADAPTER if2adapter(int ifi, BYTE* phys, int *physlen, DWORD *type);
static void cleanup_if_cache();

//	-1 on failure
static int ip2route(const struct in_addr *dest, DWORD *nexthop, DWORD *ifi);

static void releaseadapter();

static void send_arp(DWORD ifi, DWORD ip);
static void send_raw_arp(DWORD ifi, DWORD ip);
static int lookupip(DWORD ip, DWORD ifi);

//	ARP cache
static void AddToARPCache(DWORD ip, int ifi, BYTE *phys, int physlen);
static int SearchARP(DWORD ip, int ifi, BYTE *phys, int *physlen);


static CRITICAL_SECTION csAdapter, csQueue, csFailCache, csArpCache, csArpTable;
static HANDLE hEvWakeup, hThread, hSemQueue;
static int killthread = 0;

//	For rawsock fallback
extern SOCKET global_raw_socket;
extern int rawsock_avail;
extern int iphlp_avail;

extern NmapOps o;

#define SENDQUEUE_LEN 10	//	max outstanding ARP's

struct ethernet_hdr
{
#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination ethernet address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* source ethernet address */
    u_short ether_type;                     /* packet type ID */
};

struct arp_hdr
{
    u_short ar_hrd;                         /* format of hardware address */
#define ARPHRD_ETHER     1                  /* ethernet hardware format */
    u_short ar_pro;                         /* format of protocol address */
    u_char  ar_hln;                         /* length of hardware address */
    u_char  ar_pln;                         /* length of protocol addres */
    u_short ar_op;                          /* operation type */
#define ARPOP_REQUEST    1                  /* req to resolve address */
#define ARPOP_REPLY      2                  /* resp to previous request */
#define ARPOP_REVREQUEST 3                  /* req protocol address given hardware */
#define ARPOP_REVREPLY   4                  /* resp giving protocol address */
#define ARPOP_INVREQUEST 8                  /* req to identify peer */
#define ARPOP_INVREPLY   9                  /* resp identifying peer */

    /*
     *  These should implementation defined but I've hardcoded eth/IP.
     */
    u_char ar_sha[6];                         /* sender hardware address */
    u_char ar_spa[4];                         /* sender protocol address */
    u_char ar_tha[6];                         /* target hardware address */
    u_char ar_tpa[4];                         /* target protocol address */
};

static int build_ethernet(u_char *dst, u_char *src, u_short type, const u_char *payload, int payload_s, u_char *buf)
{
    struct ethernet_hdr eth_hdr;

    if (!buf)
    {
        return (-1);
    }

    memcpy(eth_hdr.ether_dhost, dst, ETHER_ADDR_LEN);  /* destination address */
    memcpy(eth_hdr.ether_shost, src, ETHER_ADDR_LEN);  /* source address */
    eth_hdr.ether_type = htons(type);                  /* packet type */

    if (payload && payload_s)
    {
        /*
         *  Unchecked runtime error for buf + ETH_H payload to be greater than
         *  the allocated heap memory.
         */
        memcpy(buf + 14, payload, payload_s);
    }
    memcpy(buf, &eth_hdr, sizeof(eth_hdr));
    return (1);
}

//	assumes Ethernet
static int realsend(LPADAPTER pAdap,
					const char *packet, int len,
					BYTE *to, BYTE *from, int addrlen,
					DWORD linktype, DWORD protocol)
{
	u_char packetbuf[2048];
	LPPACKET   lpPacket;

#ifdef REALSEND_WATCH
	if(o.debugging > 2)
	{
		int i;
		printf("realsend: %d bytes ", len);
		for(i = 0; i < addrlen; i++)
			printf("%02X", from[i]);
		printf(" => ");
		for(i = 0; i < addrlen; i++)
			printf("%02X", to[i]);
		printf(" (link %d, proto %d)\n", linktype, protocol);
	}
#endif

	memset(packetbuf,0,2048);

	if(addrlen != 6)
		fatal("realsend: non-ethernet address\n");

	build_ethernet(to, from, protocol, (unsigned char *) packet, len, packetbuf);		

	if((lpPacket = PacketAllocatePacket())==NULL)
	{
		printf("\nError:failed to allocate the LPPACKET structure.");
		return (-1);
	}

	PacketInitPacket(lpPacket, packetbuf, len+14);
	if(!PacketSendPacket(pAdap, lpPacket, TRUE))
	{
		if(o.debugging)
			printf("realsend: synchronous send failed (%d)\n", GetLastError());
	}
	PacketFreePacket(lpPacket);

	return (len);
}

//	The queue
#define Q_PACKET_SIZE(x) (x + sizeof(int) + sizeof(struct _Q_PACKET))
typedef struct _Q_PACKET {
	int len;
	struct _Q_PACKET *next;
	BYTE data[1];
} Q_PACKET;

typedef struct _Q_ROUTE {
	DWORD ip;
	int numpackets;
	int tries, timelasttry, timefirsttry;
	Q_PACKET *head, *tail;
	int ifi;	//	-1 for free
} Q_ROUTE;

typedef struct _Q_FREE {
	struct _Q_FREE *next;
} Q_FREE;

typedef struct _Q_FAIL {
	DWORD ip;
	int ifi;
} Q_FAIL;

Q_FAIL failcache[FAILCACHELEN];
int failfirst = 0;	//	0 <= failfirst < FAILCACHELEN

typedef struct _Q_ARP {
	DWORD ip;
	int ifi;
	BYTE phys[MAXLEN_PHYSADDR];
	int physlen;
} Q_ARP;

Q_ARP arpcache[ARPCACHELEN];
int arpfirst = 0;	//	0 <= arpfirst < ARPCACHELEN

PMIB_IPNETTABLE pArpTable;
unsigned long arpalloclen;
int arprefresh = 1;

//	statistics
static int totaltimetofail = 0;
static int numfails = 0;
static int maxfailtime = 0;
static long queuelen = 0;

//	The actual structure
static Q_ROUTE sendqueue[SENDQUEUE_LEN];
static Q_FREE *nextfree = 0;	//	protected by the hSemQueue

//	The send thread
static unsigned int WINAPI SendThreadProc(LPVOID unused0)
{
	//	this thread manages send ops

/*	the cycle:

  1. acquire the queue
  2. loop the routes
  2a. is it resolved? then send it
  2b. have 200 ms elapsed since last try? then send an ARP
  2c. have we timed out (3 tries, 600ms)? then kill it
  3. release the queue
  4. wait for 250ms or hEvWakeup
  */

#ifdef _MSC_VER
__try {
#endif

	while(!killthread)
	{
		int nRes;
		int i;
		DWORD time;

		arprefresh = (queuelen ? 1 : 0);

		time = GetTickCount();	//	handle the wrap correctly

//	Step 1: acquire the queue
		foo0("sendthread: try acquire csQueue\n");
		EnterCriticalSection(&csQueue);
		foo0("sendthread: acquired csQueue\n");

//	Step 2: loop the routes
		for(i = 0; i < SENDQUEUE_LEN; i++)
		{
			BYTE phys[MAXLEN_PHYSADDR];
			int physlen = MAXLEN_PHYSADDR;
			if(sendqueue[i].ifi == -1) continue;	//	free

//	Step 2a: is it resolved?
			if(0 == SearchARP(sendqueue[i].ip, sendqueue[i].ifi,
				phys, &physlen))
			{
				//	we got it!
				Q_FREE *f;
				Q_PACKET *p = sendqueue[i].head;
				BYTE myphys[MAXLEN_PHYSADDR];
				int myphyslen = MAXLEN_PHYSADDR;
				unsigned long mytype;
				LPADAPTER pAdap;

#ifdef THREAD_DEBUG
				printf("sendthread: resolved %s\n", inet_ntoa(*(struct in_addr*)&sendqueue[i].ip));
#endif

				pAdap = if2adapter(sendqueue[i].ifi,
					myphys, &myphyslen, &mytype);
				if(!pAdap) fatal("if2adapter failed?!?\n");
				while(p)
				{
					Q_PACKET *next = p->next;
					realsend(pAdap, (char *) p->data, p->len, phys,
						myphys, myphyslen, mytype, ETH_IP);
					free(p);
					p = next;
				}
				f = (Q_FREE*)&sendqueue[i];
				sendqueue[i].ifi = -1;
				f->next = nextfree;
				nextfree = f;
				releaseadapter();

				//	notify that we have a free
				InterlockedDecrement(&queuelen);
				ReleaseSemaphore(hSemQueue, 1, 0);
			}

//	Step 2b: should we try again?
			else if(sendqueue[i].tries < MAXARPTRIES
				&& sendqueue[i].timelasttry <= time - ARPINTERVAL)
			{
				//	try again
				send_arp(sendqueue[i].ifi, sendqueue[i].ip);
				sendqueue[i].tries++;
				sendqueue[i].timelasttry = time;
			}

//	Step 2c: should we kill it?
			else if((sendqueue[i].tries >= MAXARPTRIES
				&& sendqueue[i].timelasttry <= time - ARPINTERVAL))
			{
				//	kill it
				Q_FREE *f;
				Q_PACKET *p = sendqueue[i].head;
				while(p)
				{
					Q_PACKET *next = p->next;
					free(p);
					p = next;
				}

				//	cache the failure
				foo0("sendthread: try acquire csFailCache\n");
				EnterCriticalSection(&csFailCache);
				foo0("sendthread: acquired csFailCache\n");
				failcache[failfirst].ifi = sendqueue[i].ifi;
				failcache[failfirst].ip = sendqueue[i].ip;
				failfirst = (failfirst + 1) % FAILCACHELEN;
				LeaveCriticalSection(&csFailCache);

				//	gather stats
				numfails++;
				totaltimetofail += (time - sendqueue[i].timefirsttry);
				if((time - sendqueue[i].timefirsttry) > maxfailtime)
					maxfailtime = (time - sendqueue[i].timefirsttry);

#ifdef THREAD_DEBUG
				printf("sendthread: %s failed (avg = %lu ms; max = %lu ms)\n",
					inet_ntoa(*(struct in_addr*)&sendqueue[i].ip),
					totaltimetofail / numfails, maxfailtime);
#endif

				//	free it
				f = (Q_FREE*)&sendqueue[i];
				sendqueue[i].ifi = -1;
				f->next = nextfree;
				nextfree = f;

				//	and notify that we have a free
				InterlockedDecrement(&queuelen);
				ReleaseSemaphore(hSemQueue, 1, 0);
			}
			//	else do nothing
		}

//	Step 3: release the queue
		LeaveCriticalSection(&csQueue);

//	Step 4: wait
		//	yah yah I know...  but i'm too lazy to fix this
		WaitForSingleObject(hEvWakeup, POLLINTERVAL);
	}

#ifdef _MSC_VER
} __except(printf("\n\n***** ERROR IN SEND THREAD *****\n\n"),
		   EXCEPTION_CONTINUE_SEARCH) {}
#endif

	return 0;
}

//	helpers
static void AddPacketToQueue(const void *data, int len, DWORD ip, int ifi)
{
	int i;
	Q_ROUTE *r;
	Q_PACKET *p;

begin:
	//	Is it already there?
	EnterCriticalSection(&csQueue);
	for(i = 0; i < SENDQUEUE_LEN; i++)
	{
		if(sendqueue[i].ifi == ifi && sendqueue[i].ip == ip)
		{
			//	We're good to go!

			if(sendqueue[i].numpackets >= 5)
			{
				//	Alas, we need to wait so we don't kill the system
				LeaveCriticalSection(&csQueue);
				Sleep(500);	//	give it a chance
				goto begin;
			}

			p = (Q_PACKET*)malloc(Q_PACKET_SIZE(len));
			memcpy(p->data, data, len);
			p->len = len;
			p->next = 0;

#ifdef _DEBUG
			{
				int foo = 0;
				if(sendqueue[i].tail) foo++;
				if(sendqueue[i].head) foo++;
				if(sendqueue[i].numpackets) foo++;
				if(foo != 0 && foo != 3)
					fatal("corrupt packet cache\n");
			}
#endif

			if(sendqueue[i].tail)
				sendqueue[i].tail->next = p;
			else sendqueue[i].head = p;
			sendqueue[i].tail = p;
			sendqueue[i].numpackets++;

			LeaveCriticalSection(&csQueue);
			return;
		}
	}

	//	it's not already there -- leave the CS
	LeaveCriticalSection(&csQueue);

	//	get a spot in line
	while(WAIT_TIMEOUT == WaitForSingleObject(hSemQueue, 10000))
		printf("addpackettoqueue: this is taking WAY too long (%lu/%lu)...\n",
		queuelen, SENDQUEUE_LEN);

	//	and write it
	EnterCriticalSection(&csQueue);

	//	we should grab a new route obj
	if(!nextfree) fatal("where'd my block go?\n");
	r = (Q_ROUTE*)nextfree;
	nextfree = nextfree->next;
	r->ifi = ifi;
	r->ip = ip;
	r->numpackets = 1;
	r->tries = 1;
	r->timefirsttry = r->timelasttry = GetTickCount();
	send_arp(ifi, ip);	//	post the first try now
	p = (Q_PACKET*)malloc(Q_PACKET_SIZE(len));
	if(!p) fatal("out of memory\n");
	r->head = p;
	r->tail = p;
	memcpy(p->data, data, len);
	p->len = len;
	p->next = 0;
	InterlockedIncrement(&queuelen);
#ifdef THREAD_DEBUG
	printf("addpacket: %s (len = %lu)\n",
		inet_ntoa(*(struct in_addr*)&ip), queuelen);
#endif
	LeaveCriticalSection(&csQueue);

	return;
}

//	this needs to change for non-Ethernet
static void send_arp(DWORD ifi, DWORD ip)
{
  /* Used to send raw ARP packet on the wire, and then read the result
     out of the system cache.  Kinda ugly, but anyway ... Windows
     Firewall (default-on with XP SP2) started ignoring the responses
     because it didn't send them (reasonable), thus breaking the
     technique.  Now the SendARP iphlpapi function is used.  A
     downside is that I believe it blocks, so it may cause
     local-network ping scans to take much longer on Windows.  I
     suppose we should send raw and then read results from pcap.  But
     for now, we have this */
  HRESULT ret;
  ULONG uMACAddr[2];
  ULONG uSize = 6;
  PBYTE pBuffer;
  struct in_addr myip;

  /* For windows95 machines that does not load iphlpapi.dll, send raw
     ARP packet */ 
  if( !iphlp_avail )
    {
      send_raw_arp(ifi,ip);
      return;
    } 

  ret = SendARP( ip, 0, uMACAddr, &uSize );

  if( NO_ERROR == ret )
    {
      pBuffer = (PBYTE)uMACAddr;
      AddToARPCache( ip, ifi, pBuffer, (int)uSize );
    } 
} 

//      this to send raw arp packet 
static void send_raw_arp(DWORD ifi, DWORD ip)
{
        struct arp_hdr  arp_h;
        LPADAPTER pAdap;
        BYTE mymac[6];
        int len;
        unsigned long mytype;
        struct in_addr myip;
        BYTE bcastmac[6];       //      more Ethernet code !
        memset(bcastmac, 0xFF, 6);

        if(0 != ifi2ipaddr(ifi, &myip))
                fatal("sendarp: failed to find my ip ?!?\n");

        //      get the MAC et al
        len = 6;
        pAdap = if2adapter(ifi, mymac, &len, &mytype);
        if(!pAdap)
        {
                //      do nothing for localhost scan
                if(myip.s_addr == 0x0100007f) return;
                else fatal("send_arp: can't send on this interface\n");
        }

        arp_h.ar_hrd=0x0100;

        arp_h.ar_pro=0x0008;                    /* format of protocol address */
        arp_h.ar_hln=6;                         /* length of hardware address */
    arp_h.ar_pln=4;                         /* length of protocol addres */
    arp_h.ar_op=0x0100 ;
        memcpy(arp_h.ar_sha,mymac,6);
        memcpy(arp_h.ar_spa,&myip.s_addr,4);
        memset(arp_h.ar_tha,0,6);
        memcpy(arp_h.ar_tpa,&ip,4);

        realsend(pAdap, (char*)&arp_h, sizeof(arp_h),
                bcastmac, mymac, len, mytype, ETH_ARP);

        releaseadapter();
}

//	resolves an ip addr into a nexthop and index
static int ip2route(const struct in_addr *dest, DWORD *nexthop, DWORD *ifi)
{
	static DWORD last_ip = 0;
	static int last_nexthop;
	static int last_ifi;

	MIB_IPFORWARDROW route;

	//	check the cache
	if(last_ip == dest->s_addr)
	{
		if(nexthop) *nexthop = last_nexthop;
		if(ifi) *ifi = last_ifi;
		return 0;
	}

	if(0 != get_best_route(dest->s_addr, &route))
		return -1;	//	failure

	last_ip = 0;	//	if we abort, mark as bad

	//	Compute the next hop
	switch(route.dwForwardType)
	{
	case 3:
		//	local route; the dest is the next hop
		last_nexthop = dest->s_addr;
		break;

	case 4:
		//	remote route; use the specified gateway
		last_nexthop = route.dwForwardNextHop;
		break;

	case 2:
		fatal("corrupt route table\n");
		break;

	default:
		fatal("unknown route format %d\n", route.dwForwardType);
		break;
	}

	//	save the index
	last_ifi = winif2ifi(route.dwForwardIfIndex);

	//	mark it valid
	last_ip = dest->s_addr;

	//	Try to return the answer
	if(nexthop) *nexthop = last_nexthop;
	if(ifi) *ifi = last_ifi;

	if(o.debugging > 1)
	{
		printf("%s is routed through ", inet_ntoa(*(struct in_addr*)&last_ip));
		printf("%s\n", inet_ntoa(*(struct in_addr*)&last_nexthop));
	}

	return 0;
}

//	The adapter cache
typedef struct _IFC_ROW {
	int ifi;
	LPADAPTER pAdapter;
	BYTE phys[MAXLEN_PHYSADDR];
	int physlen;
	DWORD type;
} IFC_ROW;

static IFC_ROW last_if = {-1};

/*
static int numif = 0;
static IFC_ROW *ifcache = 0;
*/
static void cleanup_if_cache()
{
	if(last_if.pAdapter)
	{
		PacketCloseAdapter(last_if.pAdapter);
		last_if.pAdapter = 0;
	}

	last_if.ifi = -1;
}

static LPADAPTER if2adapter(int ifi, BYTE* phys, int *physlen, DWORD *type)
{
	const WINIP_IF *ifentry;
	char *name;

	EnterCriticalSection(&csAdapter);

	if(last_if.ifi == ifi)
	{
		if(last_if.physlen == -1) return 0;
		if(last_if.pAdapter)
		{
			if(physlen && (*physlen < last_if.physlen)) return 0;
			if(phys) memcpy(phys, last_if.phys, last_if.physlen);
			*physlen = last_if.physlen;
			if(type) *type = last_if.type;

			//	we do not release the CS
			return last_if.pAdapter;
		}
	}

	ifentry = ifi2ifentry(ifi);
	if(!ifentry || !ifentry->pcapname)
	{
		LeaveCriticalSection(&csAdapter);
		return 0;	//	Can't do this one...
	}

	cleanup_if_cache();

	last_if.pAdapter = PacketOpenAdapter(ifentry->pcapname);

	//	This is required on Win9x (defaults to 0)
	//	It's probably a good idea on WinNT/2K
	PacketSetNumWrites(last_if.pAdapter, 1);

	if(!last_if.pAdapter)
	{
		last_if.physlen = -1;
		LeaveCriticalSection(&csAdapter);
		return 0;
	}

	last_if.physlen = ifentry->physlen;
	memcpy(last_if.phys, ifentry->physaddr, ifentry->physlen);
	last_if.type = ifentry->type;
	last_if.ifi = ifi;

	//	Try to return the answer
	if(physlen && (*physlen < last_if.physlen))
	{
		LeaveCriticalSection(&csAdapter);
		return 0;
	}
	if(phys) memcpy(phys, last_if.phys, last_if.physlen);
	*physlen = last_if.physlen;
	if(type) *type = last_if.type;

	//	We do not leave the CS
	return last_if.pAdapter;
}

static void releaseadapter()
{
	LeaveCriticalSection(&csAdapter);
}

static int fallback_raw_send(const char *packet, int len, 
	   struct sockaddr *to, int tolen) 
{
	if(!rawsock_avail) {
		fatal("fallback_raw_send: no raw sockets\n"
			"This means that you tried to send to an unsupported interface.\n");
	}

	return sendto(global_raw_socket, packet, len, 0, to, tolen);
}

//	The almighty pcapsendraw
//	This is the whole point of this file :)
int pcapsendraw(const char *packet, int len, 
	   struct sockaddr *to, int tolen) 
{
	struct sockaddr_in *sin = (struct sockaddr_in *) to;
	int cb = 0;
	int nRes, i;
	DWORD nextip;
	unsigned long ifi;
	LPADAPTER pAdap;
	BYTE myphys[MAXLEN_PHYSADDR], tphys[MAXLEN_PHYSADDR];
	int physlen = MAXLEN_PHYSADDR;
	DWORD type;
	const WINIP_IF *target_ifentry;

	if(!pcapsend_inited)
		return fallback_raw_send(packet, len, to, tolen);

	if(-1 == ip2route(&sin->sin_addr, &nextip, &ifi))
	{
		WSASetLastError(WSAENETUNREACH);
		return -1;	//	no route to host
	}

	target_ifentry = ifi2ifentry(ifi);
	if(!target_ifentry || !target_ifentry->pcapname)
		return fallback_raw_send(packet, len, to, tolen);

	//	check the failcache
	EnterCriticalSection(&csFailCache);
	for(i = 0; i < FAILCACHELEN; i++)
	{
		if(failcache[i].ip == nextip && failcache[i].ifi == ifi)
		{
			//	it failed
			WSASetLastError(WSAEHOSTUNREACH);
#ifdef THREAD_DEBUG
			printf("sendto: autofailed %s\n", inet_ntoa(*(struct in_addr*)&failcache[i].ip));
#endif
			LeaveCriticalSection(&csFailCache);
			return -1;
		}
	}
	LeaveCriticalSection(&csFailCache);

	//	Read the data
	nRes = SearchARP(nextip, ifi, tphys, &physlen);
	if(-1 == nRes)
	{
		//	defer the send
		AddPacketToQueue(packet, len, nextip, ifi);
		return len;	//	it's in the queue, so it worked...
	}

	//	otherwise, we have an address
	pAdap = if2adapter(ifi, myphys, &physlen, &type);
	if(!pAdap)
		fatal("can't send to this interface\n");
	realsend(pAdap, packet, len, tphys, myphys, physlen, type, ETH_IP);
	releaseadapter();
	return len;
}

void pcapsend_init()
{
	int i, nRes;
	unsigned int id;

	if(pcapsend_inited) return;
	pcapsend_inited = 1;

	if(o.debugging > 1)
		printf("Initializing winpcap send support...");

	for(i = 0; i < SENDQUEUE_LEN; i++)
	{
		Q_FREE *f;
		sendqueue[i].ifi = -1;
		f = (Q_FREE*)&sendqueue[i];
		f->next = nextfree;
		nextfree = f;
	}

	InitializeCriticalSection(&csQueue);
	InitializeCriticalSection(&csAdapter);
	InitializeCriticalSection(&csFailCache);
	InitializeCriticalSection(&csArpCache);
	InitializeCriticalSection(&csArpTable);

	hEvWakeup = CreateEvent(0, 0, 0, 0);
	hSemQueue = CreateSemaphore(0, SENDQUEUE_LEN, SENDQUEUE_LEN, 0);

	//	allocate the ARP cache
	arpalloclen = 0;
	pArpTable = (PMIB_IPNETTABLE)&i;
	nRes = GetIpNetTableSafe(pArpTable, &arpalloclen, FALSE);
	if(arpalloclen == 0)
	{
		if(o.debugging && nRes != ERROR_NO_DATA)
			printf("ARP table length failure (%lu) during init -- try kludge1 :(\n", nRes);
		arpalloclen = 100 * sizeof(MIB_IPNETROW) + 8;
	}

	//	Read the data
	arpalloclen += 3 * sizeof(MIB_IPNETROW);
	pArpTable = (PMIB_IPNETTABLE)malloc(arpalloclen);
	if(!pArpTable)
	{
		pcapsend_inited = 0;
		fatal("out of memory\n");
	}
	nRes = GetIpNetTableSafe(pArpTable, &arpalloclen, TRUE);

	if(nRes != NO_ERROR)
	{
		if(o.debugging && nRes != ERROR_NO_DATA)
			printf("ARP failure (%lu) during init -- trying kludge2\n", nRes);
		pArpTable->dwNumEntries = 0;
	}

	//	Start the send thread
	hThread = (HANDLE)_beginthreadex(0, 0, SendThreadProc, 0, 0, &id);
	if(!hThread)
	{
		pcapsend_inited = 0;
		fatal("failed to start thread\n");
	}

	atexit(pcapsend_cleanup);

	pcapsend_inited = 1;

	if(o.debugging > 1)
		printf(" Done\n");
}

//	the name cache
typedef struct _IFNAME_ROW {
	int ifi;
	char name[128];
	DWORD ip;	//	This is one of the interface's IPs
	DWORD type;
} IFNAME_ROW;

static IFNAME_ROW *names = 0;
static int num_names;

static void pcapsend_cleanup(void)
{
	if(!pcapsend_inited)
		return;

	assert(!killthread);

	killthread = 1;
	SetEvent(hEvWakeup);
	if(WAIT_TIMEOUT == WaitForSingleObject(hThread, 10000))
	{
		error("timed out waiting for thread exit; terminating...\n");
		TerminateThread(hThread, 0);
	}

	CloseHandle(hEvWakeup);
	CloseHandle(hThread);
	CloseHandle(hSemQueue);
	DeleteCriticalSection(&csQueue);
	DeleteCriticalSection(&csAdapter);
	DeleteCriticalSection(&csFailCache);
	DeleteCriticalSection(&csArpCache);
	DeleteCriticalSection(&csArpTable);
	cleanup_if_cache();

	if(names) free(names);
	if(pArpTable) free(pArpTable);
}

//	safe implementation for getbestroute
typedef DWORD (__stdcall *PGBR)(DWORD, DWORD, PMIB_IPFORWARDROW);
int get_best_route(DWORD dest, PMIB_IPFORWARDROW r)
{
	static PGBR GBR = 0;
	static int inited = 0;

	int winif = -1, ifi = -1;

	if(!inited)
	{
		HINSTANCE hInst = GetModuleHandle("iphlpapi.dll");
		inited = 1;
		if(hInst && !wo.nt4route)
			GBR = (PGBR)GetProcAddress(hInst, "GetBestRoute");
		if(o.debugging > 1 && !GBR)
			printf("get_best_route: using NT4-compatible method\n");
	}

	//	Find the index
	if(*o.device)
	{
		ifi = name2ifi(o.device);
		winif = ifi2winif(ifi);
		if(winif == -1)
			fatal("get_best_route: nonexistant interface \"%s\"\n", o.device);
	}

	//	Can we simply redirect?
tryagain:
	if(GBR)
	{
		DWORD source = 0;
		DWORD nRes;

		if(ifi != -1)
		{
			if(-1 == ifi2ipaddr(ifi, (struct in_addr*)&source))
				source = 0;	//	wtf?
		}

		nRes = GBR(dest, source, r);
		if(nRes == ERROR_CALL_NOT_IMPLEMENTED)
		{
			GBR = 0;
			goto tryagain;
		}

		if(nRes != 0) return nRes;

		//	verify we have a good match
		if(winif != -1 && r->dwForwardIfIndex != winif)
			return -1;

		return 0;
	}

	//	We need to do this for real
	else
	{
		PMIB_IPFORWARDTABLE pTable = 0;
		unsigned long cb = 0;
		int bestmatch = -1;
		int bestmask, bestmetric;
		int nRes, i;

		nRes = GetIpForwardTableSafe(pTable, &cb, FALSE);
		if(cb == 0) return (nRes ? nRes : -1);

		cb += sizeof(MIB_IPFORWARDROW);
		pTable = (PMIB_IPFORWARDTABLE)_alloca(cb);
		nRes = GetIpForwardTableSafe(pTable, &cb, FALSE);
		if(nRes != NO_ERROR) return nRes;

		if(pTable->dwNumEntries < 1) return -1;

		for(i = 0; i < pTable->dwNumEntries; i++)
		{
			//	is it a match?
			if(pTable->table[i].dwForwardDest != (dest & pTable->table[i].dwForwardMask))
				continue;

			if(winif != -1 && pTable->table[i].dwForwardIfIndex != winif) continue;

/*			if(bestmatch == -1 || (pTable->table[i].dwForwardMask > bestmask)
				|| (pTable->table[i].dwForwardMask == bestmask
				&& pTable->table[i].dwForwardMetric1 < bestmetric))*/
			if(bestmatch == -1 || (pTable->table[i].dwForwardMetric1 > bestmetric)
				|| (pTable->table[i].dwForwardMetric1 == bestmetric
				&& pTable->table[i].dwForwardMask > bestmask))

			{
				bestmatch = i;
				bestmask = pTable->table[i].dwForwardMask;
				bestmetric = pTable->table[i].dwForwardMetric1;
			}
		}

		if(bestmatch == -1) return -1;

		memcpy(r, &pTable->table[bestmatch], sizeof(MIB_IPFORWARDROW));

		return 0;
	}
}

//	ARP cache
static void AddToARPCache(DWORD ip, int ifi, BYTE *phys, int physlen)
{
	if(physlen > MAXLEN_PHYSADDR)
		fatal("physical address too long!\n");

	foo0("addtoarpcache: try acquire csArpCache\n");
	EnterCriticalSection(&csArpCache);
	foo0("addtoarpcache: acquired csArpCache\n");
	arpcache[arpfirst].ifi = ifi;
	arpcache[arpfirst].ip = ip;
	memcpy(arpcache[arpfirst].phys, phys, physlen);
	arpcache[arpfirst].physlen = physlen;
	arpfirst = (arpfirst + 1) % ARPCACHELEN;
	LeaveCriticalSection(&csArpCache);
}

static int lookupip(DWORD ip, DWORD ifi)
{
	DWORD time = GetTickCount();
	int nRes;
	int low, high;
	int pass = 0;
	DWORD winif = ifi2winif(ifi);

	EnterCriticalSection(&csArpTable);

	goto pass0;

pass1:
	pass = 1;

	if(arprefresh)
	{
		//	refresh
		unsigned long len = arpalloclen;

#ifdef THREAD_DEBUG
		printf("lookupip: refreshing ARP table\n");
#endif

		arprefresh = 0;

readarp:
		nRes = GetIpNetTableSafe(pArpTable, &len, TRUE);

		if(nRes == ERROR_MORE_DATA)
			len += 2 * sizeof(MIB_IPNETROW);	//	give the benefit of the doubt

		if(len == arpalloclen && nRes != NO_ERROR)
		{
			//	Windows bug -- just assume the table is empty
			pArpTable->dwNumEntries = 0;
			LeaveCriticalSection(&csArpTable);
			return -1;
		}

		if(len > arpalloclen)
		{
			//	need to try that again
			free(pArpTable);
			pArpTable = (PMIB_IPNETTABLE)malloc(len);
			arpalloclen = len;
			if(!pArpTable) fatal("out of memory\n");
			goto readarp;	//	please don't infinite loop!
		}
	}

pass0:

	low = 0;
	high = pArpTable->dwNumEntries - 1;
	while(low <= high)
	{
		int i = low + (high - low) / 2;
		if(pArpTable->table[i].dwAddr == ip
			&& pArpTable->table[i].dwType != 2)
		{
			//	we found it
			if(pArpTable->table[i].dwIndex != winif)
			{
				fatal("lookupip: found ip on wrong interface\n"
					"e-mail amluto@hotmail.com if you think this should have worked\n");
			}

			LeaveCriticalSection(&csArpTable);
			return i;
		}

		//	Otherwise, we need to narrow search region
		if(pArpTable->table[i].dwAddr < ip)
			low = i + 1;
		else high = i - 1;
	}

	if(pass == 0) goto pass1;

	LeaveCriticalSection(&csArpTable);
	return -1;
}

static int SearchARP(DWORD ip, int ifi, BYTE *phys, int *physlen)
{
	int i;

	foo0("searcharp: try acquire csArpCache\n");
	EnterCriticalSection(&csArpCache);
	foo0("searcharp: acquired csArpCache\n");

	//	Is it in the ARP cache?
	for(i = 0; i < ARPCACHELEN; i++)
	{
		if(arpcache[i].ip == ip && arpcache[i].ifi == ifi)
		{
			//	we got it!
			if(*physlen < arpcache[i].physlen)
				fatal("searcharp: can't return the answer\n");

			memcpy(phys, arpcache[i].phys, arpcache[i].physlen);
			*physlen = arpcache[i].physlen;
#ifdef THREAD_DEBUG
			printf("searcharp: found %s in cache\n", inet_ntoa(*(struct in_addr*)&ip));
#endif
			LeaveCriticalSection(&csArpCache);
			return 0;
		}
	}

	//	else look it up
	i = lookupip(ip, ifi);

	LeaveCriticalSection(&csArpCache);

	if(i == -1) return -1;

	if(*physlen < pArpTable->table[i].dwPhysAddrLen)
		fatal("insufficient space for physaddr\n");

	*physlen = pArpTable->table[i].dwPhysAddrLen;
	memcpy(phys, pArpTable->table[i].bPhysAddr,
		pArpTable->table[i].dwPhysAddrLen);

#ifdef THREAD_DEBUG
	printf("searcharp: found %s in system ARP table\n", inet_ntoa(*(struct in_addr*)&ip));
#endif

	AddToARPCache(ip, ifi, phys, pArpTable->table[i].dwPhysAddrLen);

	return 0;
}
