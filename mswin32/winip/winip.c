/*

winip.c: non-pcap-or-rawsock-specific code for the winip library
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

This is designed to be used by nmap but should be
adaptable to anything.

This module implements the tables needed for
routing and interface selection

A winif is for iphlpapi
An ifindex is an index into iftable

Note: if used outside nmap in a non-GPL app, you need to reimplement
readip_pcap_real and my_real_open_pcap_live for licensing reasons.
If used outside nmap in a GPL'ed app, just copy them from wintcpip.c.

*/

#include "nmap.h"
#include "..\tcpip.h"
#include "winip.h"
#include "..\..\NmapOps.h"
#include "ntddndis.h"

#ifdef _MSC_VER
# include <delayimp.h>
#endif

#undef socket
#undef sendto
#undef pcap_close

#define   IP_HDRINCL      2 /* header is included with data */

#ifdef _MSC_VER
#define DLI_ERROR VcppException(ERROR_SEVERITY_ERROR, ERROR_MOD_NOT_FOUND)
#endif

extern NmapOps o;

int pcap_avail = 0;
int rawsock_avail = 0;
int winbug = 0;
extern int iphlp_avail;
extern int net_avail;

/*   internal functions   */
static void winip_cleanup(void);
static void winip_init_pcap(char *a);
static void winip_test(int needraw);
static void winip_list_interfaces();

/*   delay-load hooks only for troubleshooting   */
#ifdef _MSC_VER
static int dli_done = 0;
static FARPROC WINAPI winip_dli_fail_hook(unsigned code, PDelayLoadInfo info);
#endif

//   The tables

typedef struct _WINIP_NAME {
  char name[16];
  int ifi;
} WINIP_NAME;

PCHAR iftnames[] =
  {"net", "eth", "ppp", "loopback", "serial", "isdn", "slip"};
// 0      1      2         3         4         5       6

int iftypes[] = {0,
   0, 0, 0, 0, 0,   //   1-5
   1, 0, 0, 0, 0,   //   6-10
   0, 0, 0, 0, 0,   //   11-15
   0, 0, 0, 0, 5,   //   16-20
   5, 4, 2, 3, 0,   //   21-25
   1, 0, 6, 0, 0,   //   26-30
   0, 0};         //   31-32

int iftnums[7];

static WINIP_IF *iftable;
static int numifs, numips;
static WINIP_NAME *nametable;

static int inited;
static char pcaplist[4096];

//   windows-specific options
struct winops wo;

//   Free this on cleanup
static IPNODE *ipblock;

//   For XP-friendly raw sends
SOCKET global_raw_socket;

//   Fix for MinGW
//   MinGW support
#ifndef _MSC_VER
typedef struct _OSVERSIONINFOEXA {
  DWORD dwOSVersionInfoSize;
  DWORD dwMajorVersion;
  DWORD dwMinorVersion;
  DWORD dwBuildNumber;
  DWORD dwPlatformId;
  CHAR   szCSDVersion[ 128 ];
  WORD   wServicePackMajor;
  WORD   wServicePackMinor;
  WORD   wSuiteMask;
  BYTE  wProductType;
  BYTE  wReserved;
} OSVERSIONINFOEXA, *POSVERSIONINFOEXA, *LPOSVERSIONINFOEXA, OSVERSIONINFOEX, *POSVERSIONINFOEX;
#endif // _MSC_VER

void winip_barf(const char *msg)
{
  if(inited != 3) fatal("%s", msg ? msg : "You need raw support for this.\n"
   " run \"nmap --win_list_interfaces --win_trace\" to troubleshoot\n");
  if(msg) printf("%s\n\n", msg);
  printf("\nYour system doesn't have iphlpapi.dll\n\nIf you have Win95, "
  "maybe you could grab it from a Win98 system\n"
  "If you have NT4, you need service pack 4 or higher\n"
  "If you have NT3.51, try grabbing it from an NT4 system\n"
  "Otherwise, your system has problems ;-)\n");
  exit(0);
}

void winip_init()
{
  if(inited != 0) return;
  inited = 1;

  ZeroMemory(&wo, sizeof(wo));
}

void winip_postopt_init()
{
  //   variables
  DWORD cb = 0;
  PMIB_IFTABLE pTable = (PMIB_IFTABLE)&cb;
  DWORD nRes;
  OSVERSIONINFOEX ver;
  PMIB_IPADDRTABLE pIp = 0;
  int i;
  IPNODE *nextip;
  int numipsleft;
  WORD werd;
  WSADATA data;

  if(inited != 1)
    return;
  inited = 2;

#ifdef _MSC_VER
#if _MSC_VER >= 1300
  __pfnDliFailureHook2 = winip_dli_fail_hook;
#else
  __pfnDliFailureHook = winip_dli_fail_hook;
#endif
#endif

  werd = MAKEWORD( 2, 2 );
  if( (WSAStartup(werd, &data)) !=0 )
    fatal("failed to start winsock.\n");

  ver.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
  if(!GetVersionEx((LPOSVERSIONINFO)&ver))
    {
      if(wo.trace) printf("***WinIP***  not win2k -- trying basic version info\n");
      ver.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
      if(!GetVersionEx((LPOSVERSIONINFO)&ver))
 fatal("GetVersionEx failed\n");

      ver.wServicePackMajor = 0;
      ver.wServicePackMinor = 0;
    }

  /*   //   Test for win_noiphlpapi
       if(wo.noiphlpapi)
       {
       if(wo.trace) printf("***WinIP***  testing absence of iphlpapi\n");
       o.isr00t = 0;
       inited = 3;
       if(wo.listinterfaces) winip_barf(0);
       return;
       }*/

  //   Read the size
  if(wo.trace) printf("***WinIP***  initializing if tables\n");
  nRes = GetIfTableSafe(pTable, &cb, TRUE);

  if(!net_avail)
    {
      //   we have neither iphlpapi.dll nor inetmib1.dll
      o.isr00t = 0;
      inited = 3;
      if(wo.trace) printf("***WinIP***  neither iphlpapi nor inetmib1 is available\n");
      if(wo.listinterfaces) winip_barf(0);
      return;
    }

  if(!iphlp_avail && wo.trace)
    printf("***WinIP***  no iphlpapi; using inetmib1 instead\n");

  if(nRes != NO_ERROR && nRes != ERROR_INSUFFICIENT_BUFFER
     && nRes != ERROR_BUFFER_OVERFLOW)
    fatal("failed to get size of interface table\n");

  //   Read the data
  pTable = (PMIB_IFTABLE)_alloca(cb + sizeof(MIB_IFROW));
  nRes = GetIfTableSafe(pTable, &cb, TRUE);
  if(nRes != NO_ERROR)
    fatal("failed to read interface table -- try again\n");
  numifs = pTable->dwNumEntries;

  cb = 0;
  nRes = GetIpAddrTableSafe(pIp, &cb, FALSE);
  if(nRes != NO_ERROR && nRes != ERROR_INSUFFICIENT_BUFFER)
    fatal("failed to get size of IP address table\n");

  //   Read the data
  pIp = (PMIB_IPADDRTABLE)_alloca(cb + sizeof(MIB_IPADDRROW));
  nRes = GetIpAddrTableSafe(pIp, &cb, FALSE);
  if(nRes != NO_ERROR)
    fatal("failed to read IP address table\n");

  //   Allocate storage
  iftable = (WINIP_IF*)calloc(numifs, sizeof(WINIP_IF));
  nametable = (WINIP_NAME*)calloc(numifs, sizeof(WINIP_NAME));
  ipblock = (IPNODE*)calloc(pIp->dwNumEntries, sizeof(IPNODE));
  nextip = ipblock;
  numipsleft = pIp->dwNumEntries;
  numips = pIp->dwNumEntries;

  //   Fill in the table
  for(i = 0; i < numifs; i++)
    {
      int ift;
      int j;

      iftable[i].winif = pTable->table[i].dwIndex;
      iftable[i].type = pTable->table[i].dwType;
      iftable[i].firstip = 0;

      nametable[i].ifi = i;

      memcpy(iftable[i].physaddr,
      pTable->table[i].bPhysAddr,
      pTable->table[i].dwPhysAddrLen);
      iftable[i].physlen = pTable->table[i].dwPhysAddrLen;

      ift = iftypes[iftable[i].type];
      sprintf(iftable[i].name, "%s%d", iftnames[ift], iftnums[ift]++);
      strcpy(nametable[i].name, iftable[i].name);

      //   Find an IP address
      for(j = 0; j < pIp->dwNumEntries; j++)
 {
   if(pIp->table[j].dwIndex == iftable[i].winif)
     {
       if(!numipsleft)
  fatal("internal error in winip_init\n");
       numipsleft--;

       nextip->ip = pIp->table[j].dwAddr;
       nextip->next = iftable[i].firstip;
       nextip->ifi = i;
       iftable[i].firstip = nextip;
       nextip++;
     }
 }
    }

  if(wo.trace) printf("***WinIP***  if tables complete :)\n");

  //   Try to initialize winpcap
#ifdef _MSC_VER
  __try
#endif
    {
      ULONG len = sizeof(pcaplist);

      if(wo.nopcap)
 {
   if(o.debugging > 1 && wo.trace)
     printf("***WinIP***  winpcap support disabled\n");
 }
      else
 {
   pcap_avail = 1;
   if(wo.trace) printf("***WinIP***  trying to initialize winpcap 2.1\n");
   PacketGetAdapterNames(pcaplist, &len);
   if(o.debugging || wo.trace)
	   printf("***WinIP***  winpcap present, dynamic linked to: %s\n", pcap_lib_version());
 }
    }
#ifdef _MSC_VER
  __except(GetExceptionCode() == DLI_ERROR)
    {
      pcap_avail = 0;
      printf("WARNING: Failed to locate Winpcap. Nmap may not function properly until this is installed!  WinPcap is freely available from http://winpcap.polito.it.\n");
    }
#endif

  //   Check for a wpcap.dll (so we don't crash on old winpcap
  //   But only with VC++.NET, since old versions do not
  //   provide this functionality :(
#if defined(_MSC_VER) && _MSC_VER >= 1300
  if(pcap_avail)
    {
      if(FAILED(__HrLoadAllImportsForDll("wpcap.dll")))
 {
   if(wo.trace) printf("***WinIP*** your winpcap is too old\n");
   pcap_avail = 0;
 }
    }
#endif

  //   Do we have rawsock?
  if(wo.forcerawsock ||
     (ver.dwPlatformId == VER_PLATFORM_WIN32_NT
      && ver.dwMajorVersion >= 5 && !wo.norawsock))
    {
      SOCKET s = INVALID_SOCKET;
      //   we need to bind before non-admin
      //   will detect the failure
      struct sockaddr_in sin;
      ZeroMemory(&sin, sizeof(sin));
      sin.sin_family = AF_INET;
      sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

      if(wo.trace) printf("***WinIP***  testing for raw sockets\n");

      s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
      if(s != INVALID_SOCKET
  && !bind(s, (struct sockaddr*)&sin, sizeof(sin)))
 {
   rawsock_avail = 1;
   global_raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
   sethdrinclude((int)global_raw_socket);
   unblock_socket(global_raw_socket);
   closesocket(s);
   if(o.debugging > 1 || wo.trace)
     printf("***WinIP***  rawsock is available\n");
 }
      else if(o.debugging > 1 || wo.trace)
 {
   if(s == INVALID_SOCKET)
     printf("***WinIP***  rawsock init failed\n");
   else printf("***WinIP***  rawsock bind failed (most likely not admin)\n");
 }
    }
  else if(o.debugging > 1 || wo.trace)
    printf("***WinIP***  didn't try rawsock\n");

  if(rawsock_avail && o.ipprotscan
     && ver.dwPlatformId == VER_PLATFORM_WIN32_NT
     && ver.dwMajorVersion == 5
     && ver.dwMajorVersion == 0
     && ver.wServicePackMajor == 0)
    {
      //   Prevent a BSOD (we're on W2K SP0)
      if(wo.trace) printf("***WinIP***  disabling rawsock to avoid BSOD due to ipprotoscan\n");
      winbug = 1;
      rawsock_avail = 0;
    }

  if(pcap_avail)
    {
      if(wo.trace) printf("***WinIP***  reading winpcap interface list\n");

               if(ver.dwPlatformId == VER_PLATFORM_WIN32_NT && pcaplist[1] == '\0')  
 {
                       //      NT version or WinPcap using Unicode names
   WCHAR *a = (WCHAR*)pcaplist;
   while(*a)
     {
                               if (wo.trace) printf("***WinIP***  init %S (Unicode)\n", a);
       winip_init_pcap((char*)a);
       a += wcslen(a) + 1;
     }
 }
      else
 {
                       //      9x/Me version or WinPcap 3.1 using ASCII names
   char *a = pcaplist;
   while(*a)
     {
                               if (wo.trace) printf("***WinIP***  init %s (ASCII)\n", a);
       winip_init_pcap(a);
       a += strlen(a) + 1;
     }
 }
    }

  o.isr00t = (pcap_avail | rawsock_avail);
  if(wo.trace) printf("***WinIP***  o.isr00t = %d\n", o.isr00t);

  qsort(nametable, numifs, sizeof(WINIP_NAME), (int (*)(const void *, const void *)) strcmp);
  atexit(winip_cleanup);

  if(wo.listinterfaces)
    {
      winip_list_interfaces();
      exit(0);
    }

  //   Check for NT4 (grr...)
  if(ver.dwPlatformId == VER_PLATFORM_WIN32_NT
     && ver.dwMajorVersion < 5) wo.nt4route = 1;

  //   Mark load as complete so that dli errors are handled
#ifdef _MSC_VER
  dli_done = 1;
#endif
}

static void winip_test(int needraw)
{
  if(inited < 2)
    fatal("winip not initialized yet\n");
  else if(needraw && inited == 3) winip_barf(0);
}

static void winip_init_pcap(char *a)
{
  //   Write the names to the cache
  PPACKET_OID_DATA OidData;
  int i;

  //   Get the physaddr from Packet32
  BYTE phys[MAXLEN_PHYSADDR];
  int len = 6;   //   Ethernet

  LPADAPTER pAdap;

  char *foobar = a[1] ? "%s" : "%S";
  if(wo.trace)
    {
      printf("pcap device:  ");
      printf(foobar, a);
      printf("\n");
    }
   
  OidData=(struct _PACKET_OID_DATA *) _alloca(sizeof(PACKET_OID_DATA)+MAXLEN_PHYSADDR-1);

  //   The next line needs to be changed to support non-Ethernet devices
  OidData->Oid = OID_802_3_CURRENT_ADDRESS;
  OidData->Length = len;

  pAdap = PacketOpenAdapter(a);
  if(!pAdap)
    {
      if(wo.trace) printf(" result:       failed to open\n");
      return;   //   unopenable
    }

  if(PacketRequest(pAdap,FALSE,OidData))
    {
      //   we have an supported device
      for(i = 0; i < numifs; i++)
 {
   if(iftable[i].physlen == 6
      && 0 == memcmp(iftable[i].physaddr, OidData->Data, len))
     {
       if(wo.trace)
  {
    int l;
    printf(" result:       physaddr (0x");
    for(l = 0; l < len; l++)
      {
        char blah[3];
        printf("%02s", _itoa(OidData->Data[l], blah, 16));
      }
    printf(") matches %s\n", iftable[i].name);
  }
       iftable[i].pcapname = a;
       break;   //   Out of the j-loop
     }
 }

      //   else ignore the non-Ethernet device
      if(i == numifs && wo.trace)
 {
   int l;
   printf(" result:      no match (physaddr = 0x");
   for(l = 0; l < len; l++)
     {
       char blah[3];
       printf("%02s", _itoa(OidData->Data[l], blah, 16));
     }
   printf(")\n");
 }
    }


  PacketCloseAdapter(pAdap);
}

static void winip_cleanup(void)
{
  free(ipblock);

  WSACleanup();
}

//   name translation
int name2ifi(const char *name)
{
  WINIP_NAME *n = (WINIP_NAME*)bsearch(name, nametable, numifs,
        sizeof(WINIP_NAME), (int (*)(const void *, const void *)) strcmp);
  if(!n) return -1;

  return n->ifi;
}

const char *ifi2name(int ifi)
{
  if(ifi < 0 || ifi >= numifs) return 0;

  return iftable[ifi].name;
}

int ifi2winif(int ifi)
{
  if(ifi < 0 || ifi >= numifs) return -1;

  return iftable[ifi].winif;
}

const WINIP_IF* ifi2ifentry(int ifi)
{
  if(ifi < 0 || ifi >= numifs) return 0;

  return iftable + ifi;
}

static int cmp_uint(const void *e1, const void *e2)
{
  return *(DWORD*)e1 - *(DWORD*)e2;
}

int winif2ifi(int winif)
{
  WINIP_IF *x = (WINIP_IF*)bsearch(&winif, iftable, numifs,
    sizeof(WINIP_IF), cmp_uint);
  if(!x) return -1;

  return x - iftable;
}

int ifi2ipaddr(int ifi, struct in_addr *addr)
{
  if(ifi < 0 || ifi >= numifs) return -1;

  if(!iftable[ifi].firstip) return -1;

  addr->s_addr = iftable[ifi].firstip->ip;
  return 0;
}

int ipaddr2ifi(DWORD ip)
{
  //   Amusing hack
  //   Note:  this is slow since I see no reason to make it fast
  int i;
  for(i = 0; i < numips; i++)
    {
      if(ipblock[i].ip == ip)
 return ipblock[i].ifi;
    }

  return -1;
}

int devname2ipaddr(char *dev, struct in_addr *addr)
{
  return ifi2ipaddr(name2ifi(dev), addr);
}

int ipaddr2devname( char *dev, const struct in_addr *addr )
{
  int ifi = ipaddr2ifi(addr->s_addr);
  if(ifi == -1) return -1;

  strcpy(dev, iftable[ifi].name);
  return 0;
}

static void winip_list_interfaces()
{
  int i;

  if(inited == 3)
    winip_barf(0);

  printf("Available interfaces:\n\n");

  //      0000000000111111111122222222223333333333
  //      0123456789012345678901234567890123456789
  printf("Name        Raw mode  IP\n");

  for(i = 0; i < numifs; i++)
    {
      /*      char *addr = "(query failed)";
       char extra[32];
       if(iftable[i].firstip)
       addr = inet_ntoa(*(struct in_addr*)&iftable[i].firstip->ip);
       if(iftable[i].pcapname)
       strcpy(extra, rawsock_avail ? "winpcap, rawsock" : "winpcap");
       else strcpy(extra, rawsock_avail ? "rawsock" : "no raw");
       printf("%s: %s (%s)\n", iftable[i].name,
       addr, extra);
       if(o.debugging && iftable[i].pcapname)
       printf(iftable[i].pcapname[1] ? " winpcap: %s\n"
       : " winpcap: %ls\n", iftable[i].pcapname);*/

      IPNODE *ip = iftable[i].firstip;

      printf("%-12s%-10s", iftable[i].name,
      (iftable[i].pcapname ? "winpcap" : (rawsock_avail ? "SOCK_RAW" : "none")));
      if(!ip) printf("[none]\n");
      else while(ip)
 {
   if(ip != iftable[i].firstip) printf("                                -- ");
   printf("%s\n", inet_ntoa(*(struct in_addr*)&ip->ip));
   ip = ip->next;
 }

      if(o.debugging && iftable[i].pcapname)
 printf(iftable[i].pcapname[1] ? " winpcap: %s\n"
        : " winpcap: %ls\n", iftable[i].pcapname);
    }
}

//   Find a route to dest.  Fill in source, return device

//   I will fail this if no raw, so nmap will still work

typedef DWORD (__stdcall *PGBI)(IPAddr, PDWORD);
char *routethrough(const struct in_addr *dest, struct in_addr *source)
{
  /*
    In theory, GetBestInterface is ideal. But we need
    the source address. Even though GetBestInterface
    is still the fastest way to get the name,
    ipaddr2devname is fast enough.  So we use
    SIO_ROUTING_INTERFACE_QUERY.
  */

  //   the raw senders tend to iterate this
  //   so we cache the results
  static DWORD last_dest = 0;
  static DWORD last_source;
  static char dev[128];
  struct sockaddr_in sin_dest, sin_source;

  winip_test(0);
  if(inited == 3)
    {
      static int warned = 0;
      if(!warned)
 printf("routethrough: failing due to lack of any raw support\n");
      warned = 1;
    }

  if(last_dest == dest->s_addr)
    {
      source->s_addr = last_source;
      return dev;
    }

  ZeroMemory(&sin_dest, sizeof(sin_dest));
  sin_dest.sin_family = AF_INET;
  sin_dest.sin_addr = *dest;

  if(wo.nt4route)
    {
      MIB_IPFORWARDROW ir;
      int ifi;

      if(0 != get_best_route(sin_dest.sin_addr.s_addr, &ir))
 {
   if(o.debugging > 1)
     printf("get_best_route failed, so routethrough will fail\n");

   return NULL;
 }

      if(-1 == (ifi = winif2ifi(ir.dwForwardIfIndex)))
 fatal("routethrough: got unmappable (new?) interface\n");

      if(0 != ifi2ipaddr(ifi, &sin_source.sin_addr))
 fatal("routethrough: no IP for device %s\n", ifi2name(ifi));

      if(!rawsock_avail && !iftable[ifi].pcapname) return NULL;

      strcpy(dev, ifi2name(ifi));
    }
  else
    {
      SOCKET s;
      DWORD br;

      s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
      if(s == INVALID_SOCKET)
 fatal("failed to create socket\n");

      if(0 != WSAIoctl(s, SIO_ROUTING_INTERFACE_QUERY,
         &sin_dest, sizeof(sin_dest),
         &sin_source, sizeof(sin_source), &br, 0, 0))
 {
   if(o.debugging)
     printf("SIO_ROUTING_INTERFACE_QUERY(%s) failed (%d)\n", inet_ntoa(*dest), WSAGetLastError());
   closesocket(s);
   return NULL;
 }

      closesocket(s);
    }

  //   localhost scan (fake) support
  //   this allows localhost, but not 127.0.0.1, scans to seem to work
  if(sin_source.sin_addr.s_addr == htonl(INADDR_LOOPBACK))
    sin_source.sin_addr.s_addr = dest->s_addr;

  if(0 != ipaddr2devname(dev, &sin_source.sin_addr))
    {
      if(o.debugging)
 {
   printf("routethrough: %s routes through ", inet_ntoa(*dest));
   printf("%s, but inaddr2devname failed\n",
   inet_ntoa(sin_source.sin_addr));
 }

      return 0;
    }

  if(!rawsock_avail &&
     !iftable[ipaddr2ifi(sin_source.sin_addr.s_addr)].pcapname)
    return NULL;

  last_dest = dest->s_addr;
  last_source = sin_source.sin_addr.s_addr;
  *source = sin_source.sin_addr;

  if(o.debugging > 1)
    {
      printf("%s will use interface ", inet_ntoa(*(struct in_addr*)&last_dest));
      printf("%s\n", inet_ntoa(*(struct in_addr*)&last_source));
    }

  return dev;
}


//   socket and sendto replacements
int win32_sendto(int sd, const char *packet, int len, 
   unsigned int flags, struct sockaddr *to, int tolen)
{
  if(sd == 501)
    return pcapsendraw(packet, len, to, tolen);
  else return sendto(sd, packet, len, flags, to, tolen);
}

int Sendto(char *functionname, int sd, const unsigned char *packet, int len, 
    unsigned int flags, struct sockaddr *to, int tolen)
{
 PacketTrace::trace(PacketTrace::SENT, packet, len);
 return win32_sendto(sd, (char *) packet, len, flags, to, tolen);
}

int win32_socket(int af, int type, int proto)
{
  SOCKET s;
  winip_test(0);

  if(type == SOCK_RAW && proto == IPPROTO_RAW)
    {
      winip_test(1);
      pcapsend_init();
      return 501;
    }

  s = socket(af, type, proto);

  // Do this here to save a little time
  if(type == SOCK_RAW && proto == IPPROTO_RAW) sethdrinclude(s);

  return s;
}

void win32_pcap_close(pcap_t *pd)
{
  if(-2 != (long)pd) pcap_close(pd);
  else rawrecv_close(pd);
}

pcap_t *my_pcap_open_live(char *device, int snaplen, int promisc, int to_ms)
{
  int ifi = name2ifi(device);
  if(ifi == -1)
    fatal("my_pcap_open_live: invalid device %s\n");

  winip_test(1);

  if(iftable[ifi].pcapname)
    return my_real_pcap_open_live(device, snaplen, promisc, to_ms);

  else if(rawsock_avail)
    {
      if(promisc)
 fatal("promiscuous capture not available on non-pcap device %s\n", device);
      return rawrecv_open(device);
    }

  else
    fatal(winbug ? "%s: rawsock disabled to avoid BSOD\n"
   : "%s: no raw access\n", device);

  return 0;   //   to make the compiler happy
}

int winip_corruption_possible()
{
  return rawsock_avail;   //   for now
}

void sethdrinclude(int sd) 
{
  int one = 1;
  if(sd != 501)
    {
      //      error("sethdrinclude called -- this probably shouldn't happen\n");
      setsockopt(sd, IPPROTO_IP, IP_HDRINCL, (char *) &one, sizeof(one));
    }
}

void set_pcap_filter(Target *target,
       pcap_t *pd, PFILTERFN filter, char *bpf, ...)
{
  va_list ap;
  char buf[3072]; // same size as bpf ie size of filter in scan_engine.cc
  struct bpf_program fcode;
  unsigned int localnet, netmask;
  char err0r[256];

  if(-2 == (long)pd)
    {
      rawrecv_setfilter(pd, filter);
      return;
    }

  if (pcap_lookupnet(target->device, &localnet, &netmask, err0r) == -1)
    ; /* fatal("Failed to lookup device subnet/netmask: %s", err0r);*/

  va_start(ap, bpf);
  if (vsnprintf(buf, sizeof(buf), bpf, ap) < 0)
    {
      fatal("Failed to copy the filter string %s",bpf);
    }
  va_end(ap);

  if (o.debugging)
    log_write(LOG_STDOUT, "Packet capture filter: %s\n", buf);

  /* Due to apparent bug in libpcap */
  if (islocalhost(target->v4hostip()))
    buf[0] = '\0';

  if (pcap_compile(pd, &fcode, buf, 0, netmask) < 0)
    fatal("Error compiling our pcap filter: %s\n", pcap_geterr(pd));
  if (pcap_setfilter(pd, &fcode) < 0 )
    fatal("Failed to set the pcap filter: %s\n", pcap_geterr(pd));
}

#ifdef _MSC_VER
static FARPROC WINAPI winip_dli_fail_hook(unsigned code, PDelayLoadInfo info)
{
  if(wo.trace)
    {
      printf("***WinIP***  delay load error:\n");
      switch(code)
 {
 case dliFailLoadLib:
   printf(" failed to load dll: %s\n", info->szDll);
   break;

 case dliFailGetProc:
   printf(" failed to load ");
   if(info->dlp.fImportByName)
     printf("function %s", info->dlp.szProcName + 2);
   else printf("ordinal %d", info->dlp.dwOrdinal);
   printf(" in dll %s\n", info->szDll);
   break;

 default:
   printf(" unknown error\n");
   break;
 }
    }

  if(dli_done)
    {
      printf("******* Unexpected delay-load failure *******\n");

      switch(code)
 {
 case dliFailLoadLib:
   printf(" failed to load dll: %s\n", info->szDll);
   if(!stricmp(info->szDll, "wpcap.dll"))
     printf(" this is most likely because you have"
     " winpcap 2.0 (2.1 or later is required)\n"
     "Get it from http://netgroup-serv.polito.it/winpcap\n");
   break;

 case dliFailGetProc:
   printf(" failed to load ");
   if(info->dlp.fImportByName)
     printf("function %s", info->dlp.szProcName + 2);
   else printf("ordinal %d", info->dlp.dwOrdinal);
   printf(" in dll %s\n", info->szDll);
   break;

 default:
   printf(" unknown error\n");
   break;
  }
    }

  return 0;
}
#endif // _MSC_VER
