
/***************************************************************************
 * tcpip.h -- Various functions relating to low level TCP/IP handling,     *
 * including sending raw packets, routing, printing packets, reading from  *
 * libpcap, etc.                                                           *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2011 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 with the clarifications and exceptions described  *
 * below.  This guarantees your right to use, modify, and redistribute     *
 * this software under certain conditions.  If you wish to embed Nmap      *
 * technology into proprietary software, we sell alternative licenses      *
 * (contact sales@insecure.com).  Dozens of software vendors already       *
 * license Nmap technology such as host discovery, port scanning, OS       *
 * detection, and version detection.                                       *
 *                                                                         *
 * Note that the GPL places important restrictions on "derived works", yet *
 * it does not provide a detailed definition of that term.  To avoid       *
 * misunderstandings, we consider an application to constitute a           *
 * "derivative work" for the purpose of this license if it does any of the *
 * following:                                                              *
 * o Integrates source code from Nmap                                      *
 * o Reads or includes Nmap copyrighted data files, such as                *
 *   nmap-os-db or nmap-service-probes.                                    *
 * o Executes Nmap and parses the results (as opposed to typical shell or  *
 *   execution-menu apps, which simply display raw Nmap output and so are  *
 *   not derivative works.)                                                *
 * o Integrates/includes/aggregates Nmap into a proprietary executable     *
 *   installer, such as those produced by InstallShield.                   *
 * o Links to a library or executes a program that does any of the above   *
 *                                                                         *
 * The term "Nmap" should be taken to also include any portions or derived *
 * works of Nmap.  This list is not exclusive, but is meant to clarify our *
 * interpretation of derived works with some common examples.  Our         *
 * interpretation applies only to Nmap--we don't speak for other people's  *
 * GPL works.                                                              *
 *                                                                         *
 * If you have any questions about the GPL licensing restrictions on using *
 * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
 * we also offer alternative license to integrate Nmap into proprietary    *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates as well as helping to     *
 * fund the continued development of Nmap technology.  Please email        *
 * sales@insecure.com for further information.                             *
 *                                                                         *
 * As a special exception to the GPL terms, Insecure.Com LLC grants        *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two. You must obey the GNU GPL in all *
 * respects for all of the code used other than OpenSSL.  If you modify    *
 * this file, you may extend this exception to your version of the file,   *
 * but you are not obligated to do so.                                     *
 *                                                                         *
 * If you received these files with a written license agreement or         *
 * contract stating terms other than the terms above, then that            *
 * alternative license agreement takes precedence over these comments.     *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes (none     *
 * have been found so far).                                                *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to nmap-dev@insecure.org for possible incorporation into the main       *
 * distribution.  By sending these changes to Fyodor or one of the         *
 * Insecure.Org development mailing lists, it is assumed that you are      *
 * offering the Nmap Project (Insecure.Com LLC) the unlimited,             *
 * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
 * will always be available Open Source, but this is important because the *
 * inability to relicense code has caused devastating problems for other   *
 * Free Software projects (such as KDE and NASM).  We also occasionally    *
 * relicense the code to third parties as discussed above.  If you wish to *
 * specify special license conditions of your contributions, just say so   *
 * when you send them.                                                     *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License v2.0 for more details at                         *
 * http://www.gnu.org/licenses/gpl-2.0.html , or in the COPYING file       *
 * included with Nmap.                                                     *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */


#ifndef TCPIP_H
#define TCPIP_H

#ifdef HAVE_CONFIG_H
#include "nmap_config.h"
#endif

#include "nbase.h"

#ifdef WIN32
#include "mswin32\winclude.h"
#else

#ifdef STDC_HEADERS
#include <stdlib.h>
#else
void *malloc();
void *realloc();
#endif

#if STDC_HEADERS || HAVE_STRING_H
#include <string.h>
#if !STDC_HEADERS && HAVE_MEMORY_H
#include <memory.h>
#endif
#endif
#if HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_BSTRING_H
#include <bstring.h>
#endif

#include <ctype.h>
#include <sys/types.h>

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h> /* Defines MAXHOSTNAMELEN on BSD*/
#endif

/* Linux uses these defines in netinet/ip.h to use the correct struct ip */
#ifndef __FAVOR_BSD
#define __FAVOR_BSD 1
#endif
#ifndef _BSD_SOURCE
#define _BSD_SOURCE 1
#endif
#ifndef __USE_BSD
#define __USE_BSD 1
#endif
/* BSDI needs this to insure the correct struct ip */
#undef _IP_VHL

#include <stdio.h>

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_RPC_TYPES_H
#include <rpc/types.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#include <arpa/inet.h>
#ifndef NETINET_IN_SYSTM_H  /* This guarding is needed for at least some versions of OpenBSD */
#include <netinet/in_systm.h> /* defines n_long needed for netinet/ip.h */
#define NETINET_IN_SYSTM_H
#endif
#ifndef NETINET_IP_H  /* This guarding is needed for at least some versions of OpenBSD */
#include <netinet/ip.h>
#define NETINET_IP_H
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include <sys/ioctl.h>

#ifdef __cplusplus
extern "C" {
#endif
#include <pcap.h>
#ifdef __cplusplus
}
#endif

#if HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>  /* SIOCGIFCONF for Solaris */
#endif
#endif /* WIN32 */

#include <setjmp.h>
#include <errno.h>
#include <signal.h>
#include <dnet.h>
#ifndef WIN32
#include <netinet/ip_icmp.h>
#endif



#include "nmap.h"
#include "global_structures.h"

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif


/* Used for tracing all packets sent or received (eg the
   --packet-trace option) */

class PacketTrace {
 public:
  static const int SENT=1; /* These two values must not be changed */
  static const int RCVD=2;
  typedef int pdirection;
  /* Takes an IP PACKET and prints it if packet tracing is enabled.
     'packet' must point to the IPv4 header. The direction must be
     PacketTrace::SENT or PacketTrace::RCVD .  Optional 'now' argument
     makes this function slightly more efficient by avoiding a gettimeofday()
     call. */
  static void trace(pdirection pdir, const u8 *packet, u32 len,
		    struct timeval *now=NULL);
/* Adds a trace entry when a connect() is attempted if packet tracing
   is enabled.  Pass IPPROTO_TCP or IPPROTO_UDP as the protocol.  The
   sock may be a sockaddr_in or sockaddr_in6.  The return code of
   connect is passed in connectrc.  If the return code is -1, get the
   errno and pass that as connect_errno. */
  static void traceConnect(u8 proto, const struct sockaddr *sock, 
			   int socklen, int connectrc, int connect_errno,
			   const struct timeval *now);
  /* Takes an ARP PACKET (including ethernet header) and prints it if
     packet tracing is enabled.  'frame' must point to the 14-byte
     ethernet header (e.g. starting with destination addr). The
     direction must be PacketTrace::SENT or PacketTrace::RCVD .
     Optional 'now' argument makes this function slightly more
     efficient by avoiding a gettimeofday() call. */
  static void traceArp(pdirection pdir, const u8 *frame, u32 len,
				    struct timeval *now);
};

class PacketCounter {
 public:
  PacketCounter() : sendPackets(0), sendBytes(0), recvPackets(0), recvBytes(0) {}
#if WIN32
  unsigned __int64
#else
  unsigned long long
#endif
	  sendPackets, sendBytes, recvPackets, recvBytes;
};


#ifndef HAVE_STRUCT_IP
#define HAVE_STRUCT_IP

/* From Linux glibc, which apparently borrowed it from
   BSD code.  Slightly modified for portability --fyodor@insecure.org */
/*
 * Structure of an internet header, naked of options.
 */
struct ip
  {
#if WORDS_BIGENDIAN
    u_int8_t ip_v:4;                    /* version */
    u_int8_t ip_hl:4;                   /* header length */
#else
    u_int8_t ip_hl:4;                   /* header length */
    u_int8_t ip_v:4;                    /* version */ 
#endif
    u_int8_t ip_tos;                    /* type of service */
    u_short ip_len;                     /* total length */
    u_short ip_id;                      /* identification */
    u_short ip_off;                     /* fragment offset field */
#define IP_RF 0x8000                    /* reserved fragment flag */
#define IP_DF 0x4000                    /* dont fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
#define IP_OFFMASK 0x1fff               /* mask for fragmenting bits */
    u_int8_t ip_ttl;                    /* time to live */
    u_int8_t ip_p;                      /* protocol */
    u_short ip_sum;                     /* checksum */
    struct in_addr ip_src, ip_dst;      /* source and dest address */
  };

#endif /* HAVE_STRUCT_IP */

#ifndef HAVE_STRUCT_ICMP
#define HAVE_STRUCT_ICMP
/* From Linux /usr/include/netinet/ip_icmp.h GLIBC */

/*
 * Internal of an ICMP Router Advertisement
 */
struct icmp_ra_addr
{
  u_int32_t ira_addr;
  u_int32_t ira_preference;
};

struct icmp
{
  u_int8_t  icmp_type;  /* type of message, see below */
  u_int8_t  icmp_code;  /* type sub code */
  u_int16_t icmp_cksum; /* ones complement checksum of struct */
  union
  {
    struct ih_idseq             /* echo datagram */
    {
      u_int16_t icd_id;
      u_int16_t icd_seq;
    } ih_idseq;
    u_int32_t ih_void;

    /* ICMP_UNREACH_NEEDFRAG -- Path MTU Discovery (RFC1191) */
    struct ih_pmtu
    {
      u_int16_t ipm_void;
      u_int16_t ipm_nextmtu;
    } ih_pmtu;

    struct ih_rtradv
    {
      u_int8_t irt_num_addrs;
      u_int8_t irt_wpa;
      u_int16_t irt_lifetime;
    } ih_rtradv;
  } icmp_hun;
  /* Removed icmp_pptr and icmp_gwaddr from union and #defines because they conflict with dnet */
#define icmp_id         icmp_hun.ih_idseq.icd_id
#define icmp_seq        icmp_hun.ih_idseq.icd_seq
#define icmp_void       icmp_hun.ih_void
#define icmp_pmvoid     icmp_hun.ih_pmtu.ipm_void
#define icmp_nextmtu    icmp_hun.ih_pmtu.ipm_nextmtu
#define icmp_num_addrs  icmp_hun.ih_rtradv.irt_num_addrs
#define icmp_wpa        icmp_hun.ih_rtradv.irt_wpa
#define icmp_lifetime   icmp_hun.ih_rtradv.irt_lifetime
  union
  {
    struct
    {
      u_int32_t its_otime;
      u_int32_t its_rtime;
      u_int32_t its_ttime;
    } id_ts;
    struct
    {
      struct ip idi_ip;
      /* options and then 64 bits of data */
    } id_ip;
    struct icmp_ra_addr id_radv;
    u_int32_t   id_mask;
    u_int8_t    id_data[1];
  } icmp_dun;
#define icmp_otime      icmp_dun.id_ts.its_otime
#define icmp_rtime      icmp_dun.id_ts.its_rtime
#define icmp_ttime      icmp_dun.id_ts.its_ttime
#define icmp_ip         icmp_dun.id_ip.idi_ip
#define icmp_radv       icmp_dun.id_radv
#define icmp_mask       icmp_dun.id_mask
#define icmp_data       icmp_dun.id_data
};
#endif /* HAVE_STRUCT_ICMP */

/* Some systems might not have this */
#ifndef IPPROTO_IGMP
#define IPPROTO_IGMP 2
#endif

/* Prototypes */
/* Converts an IP address given in a sockaddr_storage to an IPv4 or
   IPv6 IP address string.  Since a static buffer is returned, this is
   not thread-safe and can only be used once in calls like printf() 
*/
const char *inet_socktop(struct sockaddr_storage *ss);

/* Tries to resolve the given name (or literal IP) into a sockaddr
   structure. This function calls getaddrinfo and returns the same
   addrinfo linked list that getaddrinfo produces. Returns NULL for any
   error or failure to resolve. */
struct addrinfo *resolve_all(char *hostname, int pf);

/* Takes a destination address (dst) and tries to determine the
   source address and interface necessary to route to this address.
   If no route is found, false is returned and rnfo is undefined.  If
   a route is found, true is returned and rnfo is filled in with all
   of the routing details.  This function takes into account -S and -e
   options set by user (o.spoofsource, o.device) */
int nmap_route_dst(const struct sockaddr_storage * const dst, struct route_nfo *rnfo);

/* Determines what interface packets destined to 'dest' should be
   routed through.  It can also discover the appropriate next hop (if
   any) for ethernet routing.  If direct_connect is passed in, it will
   be set to 1 if dst is directly connected on the ifentry network and
   0 if it requires routing.  If nexthop_ip is not NULL, and routing
   is required, the next hop is filled into nexthop_ip.  This function
   returns false if no appropiate interface or route was found and
   true if it succeeds. */
bool routethrough(const struct sockaddr_storage * const dest, 
		  struct intf_entry *ifentry, 
		  int *direct_connect, struct sockaddr_storage *nexthop_ip);

unsigned short in_cksum(u16 *ptr,int nbytes);


/* Build and send a raw tcp packet.  If TTL is -1, a partially random
   (but likely large enough) one is chosen */
int send_tcp_raw( int sd, struct eth_nfo *eth,
		  const struct in_addr *source, const struct in_addr *victim, 
		  int ttl, bool df,
		  u8* ipopt, int ipoptlen,
		  u16 sport, u16 dport,
		  u32 seq, u32 ack, u8 reserved, u8 flags, u16 window, u16 urp,
		  u8 *options, int optlen,
		  char *data, u16 datalen);
int send_udp_raw( int sd, struct eth_nfo *eth,
		  struct in_addr *source, const struct in_addr *victim,
		  int ttl, u16 ipid,
		  u8* ipopt, int ipoptlen,
		  u16 sport, u16 dport,
		  char *data, u16 datalen);

/* Builds a TCP packet (including an IP header) by packing the fields
   with the given information.  It allocates a new buffer to store the
   packet contents, and then returns that buffer.  The packet is not
   actually sent by this function.  Caller must delete the buffer when
   finished with the packet.  The packet length is returned in
   packetlen, which must be a valid int pointer. */
u8 *build_tcp_raw(const struct in_addr *source, const struct in_addr *victim,
		  int ttl, u16 ipid, u8 tos, bool df,
		  const u8* ipopt, int ipoptlen,
		  u16 sport, u16 dport,
		  u32 seq, u32 ack, u8 reserved, u8 flags, u16 window, u16 urp,
		  const u8 *options, int optlen,
		  char *data, u16 datalen,
		  u32 *packetlen);

/* Builds a UDP packet (including an IP header) by packing the fields
   with the given information.  It allocates a new buffer to store the
   packet contents, and then returns that buffer.  The packet is not
   actually sent by this function.  Caller must delete the buffer when
   finished with the packet.  The packet length is returned in
   packetlen, which must be a valid int pointer. */
u8 *build_udp_raw(const struct in_addr *source, const struct in_addr *victim,
 		  int ttl, u16 ipid, u8 tos, bool df,
		  u8* ipopt, int ipoptlen,
 		  u16 sport, u16 dport, 
 		  const char *data, u16 datalen,
 		  u32 *packetlen);

/* Builds an SCTP packet (including an IP header) by packing the fields
   with the given information.  It allocates a new buffer to store the
   packet contents, and then returns that buffer.  The packet is not
   actually sent by this function.  Caller must delete the buffer when
   finished with the packet.  The packet length is returned in
   packetlen, which must be a valid int pointer. */
u8 *build_sctp_raw(const struct in_addr *source, const struct in_addr *victim,
		   int ttl, u16 ipid, u8 tos, bool df,
		   u8* ipopt, int ipoptlen,
		   u16 sport, u16 dport,
		   u32 vtag, char *chunks, int chunkslen,
		   char *data, u16 datalen,
		   u32 *packetlen);

/* Builds an ICMP packet (including an IP header) by packing the
   fields with the given information.  It allocates a new buffer to
   store the packet contents, and then returns that buffer.  The
   packet is not actually sent by this function.  Caller must delete
   the buffer when finished with the packet.  The packet length is
   returned in packetlen, which must be a valid int pointer. The
   id/seq will be converted to network byte order (if it differs from
   HBO) */
u8 *build_icmp_raw(const struct in_addr *source, const struct in_addr *victim, 
		   int ttl, u16 ipid, u8 tos, bool df,
		   u8* ipopt, int ipoptlen,
		   u16 seq, unsigned short id, u8 ptype, u8 pcode,
		   char *data, u16 datalen, u32 *packetlen);

/* Builds an IGMP packet (including an IP header) by packing the fields
   with the given information.  It allocates a new buffer to store the
   packet contents, and then returns that buffer.  The packet is not
   actually sent by this function.  Caller must delete the buffer when
   finished with the packet.  The packet length is returned in packetlen,
   which must be a valid int pointer.
 */
u8 *build_igmp_raw(const struct in_addr *source, const struct in_addr *victim, 
		   int ttl, u16 ipid, u8 tos, bool df,
		   u8* ipopt, int ipoptlen,
		   u8 ptype, u8 pcode,
		   char *data, u16 datalen, u32 *packetlen);

/* Builds an IP packet (including an IP header) by packing the fields
   with the given information.  It allocates a new buffer to store the
   packet contents, and then returns that buffer.  The packet is not
   actually sent by this function.  Caller must delete the buffer when
   finished with the packet.  The packet length is returned in
   packetlen, which must be a valid int pointer. */
u8 *build_ip_raw(const struct in_addr *source, const struct in_addr *victim, 
		 u8 proto,
		 int ttl, u16 ipid, u8 tos, bool df,
		 u8* ipopt, int ipoptlen,
		 char *data, u16 datalen, 
		 u32 *packetlen);

/* Send a pre-built IPv4 packet */
int send_ip_packet(int sd, struct eth_nfo *eth, u8 *packet, 
		   unsigned int packetlen);

/* Decoy versions of the raw packet sending functions ... */
int send_tcp_raw_decoys( int sd, struct eth_nfo *eth, 
			 const struct in_addr *victim,
			 int ttl, bool df, 
			 u8* ipopt, int ipoptlen,
			 u16 sport, u16 dport,
			 u32 seq, u32 ack, u8 reserved, u8 flags, u16 window, u16 urp,
			 u8 *options, int optlen,
			 char *data, u16 datalen);

int send_udp_raw_decoys( int sd, struct eth_nfo *eth, 
			 const struct in_addr *victim,
			 int ttl, u16 ipid,
			 u8* ipops, int ip,
			 u16 sport, u16 dport,
			 char *data, u16 datalen);


// Returns whether the packet receive time value obtaned from libpcap
// (and thus by readip_pcap()) should be considered valid.  When
// invalid (Windows and Amiga), readip_pcap returns the time you called it.
bool pcap_recv_timeval_valid();

/* Prints stats from a pcap descriptor (number of received and dropped
   packets). */
void pcap_print_stats(int logt, pcap_t *pd);



/* A simple function I wrote to help in debugging, shows the important fields
   of a TCP packet*/
int readtcppacket(const u8 *packet, int readdata);
int readudppacket(const u8 *packet, int readdata);

/* Looks for an interface assigned to the given IP (ss), and returns
   the interface_info for the first one found.  If non found, returns NULL */
struct interface_info *getInterfaceByIP(struct sockaddr_storage *ss);


pcap_if_t *getpcapinterfaces();


/* Fill buf (up to buflen -- truncate if necessary but always
   terminate) with a short representation of the packet stats.
   Returns buf.  Aborts if there is a problem. */
char *getFinalPacketStats(char *buf, int buflen);

/* This function tries to determine the target's ethernet MAC address
   from a received packet as follows:
   1) If linkhdr is an ethernet header, grab the src mac (otherwise give up)
   2) If overwrite is 0 and a MAC is already set for this target, give up.
   3) If the packet source address is not the target, give up.
   4) Use the routing table to try to determine rather target is
      directly connected to the src host running Nmap.  If it is, set the MAC.

   This function returns 0 if it ends up setting the MAC, nonzero otherwise

   This function assumes that ip has already been verified as
   containing a complete IP header (or at least the first 20 bytes).
*/  

int setTargetMACIfAvailable(Target *target, struct link_header *linkhdr,
			    struct ip *ip, int overwrite);

/* This function ensures that the next hop MAC address for a target is
   filled in.  This address is the target's own MAC if it is directly
   connected, and the next hop mac otherwise.  Returns true if the
   address is set when the function ends, false if not.  This function
   firt checks if it is already set, if not it tries the arp cache,
   and if that fails it sends an ARP request itself.  This should be called
   after an ARP scan if many directly connected machines are involved. */
bool setTargetNextHopMAC(Target *target);

bool getNextHopMAC(char *iface, u8 *srcmac, struct sockaddr_storage *srcss,
		   struct sockaddr_storage *dstss, u8 *dstmac);



/* Hex dump */
int get_link_offset(char *device);
/* If rcvdtime is non-null and a packet is returned, rcvd will be
   filled with the time that packet was captured from the wire by
   pcap.  If linknfo is not NULL, lnknfo->headerlen and
   lnkinfo->header will be filled with the appropriate values. */
char *readip_pcap(pcap_t *pd, unsigned int *len, long to_usec, 
		  struct timeval *rcvdtime, struct link_header *linknfo, bool validate);

/* Attempts to read one IPv4/Ethernet ARP reply packet from the pcap
   descriptor pd.  If it receives one, fills in sendermac (must pass
   in 6 bytes), senderIP, and rcvdtime (can be NULL if you don't care)
   and returns 1.  If it times out and reads no arp requests, returns
   0.  to_usec is the timeout period in microseconds.  Use 0 to avoid
   blocking to the extent possible, and -1 to block forever.  Returns
   -1 or exits if ther is an error. */
int read_arp_reply_pcap(pcap_t *pd, u8 *sendermac, struct in_addr *senderIP,
		       long to_usec, struct timeval *rcvdtime);

/* Examines the given tcp packet and obtains the TCP timestamp option
   information if available.  Note that the CALLER must ensure that
   "tcp" contains a valid header (in particular the th_off must be the
   true packet length and tcp must contain it).  If a valid timestamp
   option is found in the header, nonzero is returned and the
   'timestamp' and 'echots' parameters are filled in with the
   appropriate value (if non-null).  Otherwise 0 is returned and the
   parameters (if non-null) are filled with 0.  Remember that the
   correct way to check for errors is to look at the return value
   since a zero ts or echots could possibly be valid. */
int gettcpopt_ts(struct tcp_hdr *tcp, u32 *timestamp, u32 *echots);

/* Maximize the receive buffer of a socket descriptor (up to 500K) */
void max_rcvbuf(int sd);

/* Give broadcast permission to a socket */
void broadcast_socket(int sd);

/* Do a receive (recv()) on a socket and stick the results (upt to
   len) into buf .  Give up after 'seconds'.  Returns the number of
   bytes read (or -1 in the case of an error.  It only does one recv
   (it will not keep going until len bytes are read).  If timedout is
   not NULL, it will be set to zero (no timeout occured) or 1 (it
   did). */
int recvtime(int sd, char *buf, int len, int seconds, int *timedout);

/* Sets a pcap filter function -- makes SOCK_RAW reads easier */
#ifndef WINIP_H
void set_pcap_filter(const char *device, pcap_t *pd, const char *bpf, ...);
#endif

#endif /*TCPIP_H*/

