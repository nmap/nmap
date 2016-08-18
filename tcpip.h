
/***************************************************************************
 * tcpip.h -- Various functions relating to low level TCP/IP handling,     *
 * including sending raw packets, routing, printing packets, reading from  *
 * libpcap, etc.                                                           *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2016 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE CLARIFICATIONS  *
 * AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your right to use,    *
 * modify, and redistribute this software under certain conditions.  If    *
 * you wish to embed Nmap technology into proprietary software, we sell    *
 * alternative licenses (contact sales@nmap.com).  Dozens of software      *
 * vendors already license Nmap technology such as host discovery, port    *
 * scanning, OS detection, version detection, and the Nmap Scripting       *
 * Engine.                                                                 *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files, such as Nmap's nmap-os-db   *
 * or nmap-service-probes.                                                 *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * Nmap with other software in compressed or archival form does not        *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * As another special exception to the GPL terms, Insecure.Com LLC grants  *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two.                                  *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * Nmap or grant special permissions to use it in other open source        *
 * software.  Please contact fyodor@nmap.org with any such requests.       *
 * Similarly, we don't incorporate incompatible open source software into  *
 * Covered Software without special permission from the copyright holders. *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * Nmap in other works, are happy to help.  As mentioned above, we also    *
 * offer alternative license to integrate Nmap into proprietary            *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates.  They also fund the      *
 * continued development of Nmap.  Please email sales@nmap.com for further *
 * information.                                                            *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to the dev@nmap.org mailing list for possible incorporation into the    *
 * main distribution.  By sending these changes to Fyodor or one of the    *
 * Insecure.Org development mailing lists, or checking them into the Nmap  *
 * source code repository, it is understood (unless you specify otherwise) *
 * that you are offering the Nmap Project (Insecure.Com LLC) the           *
 * unlimited, non-exclusive right to reuse, modify, and relicense the      *
 * code.  Nmap will always be available Open Source, but this is important *
 * because the inability to relicense code has caused devastating problems *
 * for other Free Software projects (such as KDE and NASM).  We also       *
 * occasionally relicense the code to third parties as discussed above.    *
 * If you wish to specify special license conditions of your               *
 * contributions, just say so when you send them.                          *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the Nmap      *
 * license file for more details (it's in a COPYING file included with     *
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING)        *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */


#ifndef TCPIP_H
#define TCPIP_H

#include "nbase.h"

#include <pcap.h>
#ifdef WIN32
/* WinPCAP doesn't have this, but Npcap does.
 * Using 0 is safe for both, but change this if we decide to drop WinPcap */
#undef PCAP_NETMASK_UNKNOWN
#define PCAP_NETMASK_UNKNOWN 0
#endif

class Target;

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif

int nmap_raw_socket();

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
  static void traceND(pdirection pdir, const u8 *frame, u32 len,
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
struct addrinfo *resolve_all(const char *hostname, int pf);

/* Takes a destination address (dst) and tries to determine the
   source address and interface necessary to route to this address.
   If no route is found, false is returned and rnfo is undefined.  If
   a route is found, true is returned and rnfo is filled in with all
   of the routing details.  This function takes into account -S and -e
   options set by user (o.spoofsource, o.device) */
int nmap_route_dst(const struct sockaddr_storage *dst, struct route_nfo *rnfo);

unsigned short in_cksum(u16 *ptr,int nbytes);


/* Send a pre-built IPv4 or IPv6 packet */
int send_ip_packet(int sd, const struct eth_nfo *eth,
  const struct sockaddr_storage *dst,
  const u8 *packet, unsigned int packetlen);

/* Builds an IP packet (including an IP header) by packing the fields
   with the given information.  It allocates a new buffer to store the
   packet contents, and then returns that buffer.  The packet is not
   actually sent by this function.  Caller must delete the buffer when
   finished with the packet.  The packet length is returned in
   packetlen, which must be a valid int pointer. */
u8 *build_ip_raw(const struct in_addr *source, const struct in_addr *victim,
                 u8 proto,
                 int ttl, u16 ipid, u8 tos, bool df,
                 const u8* ipopt, int ipoptlen,
                 const char *data, u16 datalen,
                 u32 *packetlen);

u8 *build_ipv6_raw(const struct in6_addr *source,
                   const struct in6_addr *victim, u8 tc, u32 flowlabel,
                   u8 nextheader, int hoplimit,
                   const char *data, u16 datalen, u32 *outpacketlen);

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
                  const char *data, u16 datalen,
                  u32 *packetlen);

u8 *build_tcp_raw_ipv6(const struct in6_addr *source,
                       const struct in6_addr *victim, u8 tc, u32 flowlabel,
                       u8 hoplimit, u16 sport, u16 dport, u32 seq, u32 ack,
                       u8 reserved, u8 flags, u16 window, u16 urp,
                       const u8 *tcpopt, int tcpoptlen, const char *data,
                       u16 datalen, u32 *packetlen);

/* Build and send a raw tcp packet.  If TTL is -1, a partially random
   (but likely large enough) one is chosen */
int send_tcp_raw(int sd, const struct eth_nfo *eth,
                  const struct in_addr *source, const struct in_addr *victim,
                  int ttl, bool df,
                  u8* ipopt, int ipoptlen,
                  u16 sport, u16 dport,
                  u32 seq, u32 ack, u8 reserved, u8 flags, u16 window, u16 urp,
                  u8 *options, int optlen,
                  const char *data, u16 datalen);

int send_tcp_raw_decoys(int sd, const struct eth_nfo *eth,
                         const struct in_addr *victim,
                         int ttl, bool df,
                         u8* ipopt, int ipoptlen,
                         u16 sport, u16 dport,
                         u32 seq, u32 ack, u8 reserved, u8 flags, u16 window, u16 urp,
                         u8 *options, int optlen,
                         const char *data, u16 datalen);

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

u8 *build_udp_raw_ipv6(const struct in6_addr *source,
                       const struct in6_addr *victim, u8 tc, u32 flowlabel,
                       u8 hoplimit, u16 sport, u16 dport,
                       const char *data, u16 datalen, u32 *packetlen);

int send_udp_raw(int sd, const struct eth_nfo *eth,
                  struct in_addr *source, const struct in_addr *victim,
                  int ttl, u16 ipid,
                  u8* ipopt, int ipoptlen,
                  u16 sport, u16 dport,
                  const char *data, u16 datalen);

int send_udp_raw_decoys(int sd, const struct eth_nfo *eth,
                         const struct in_addr *victim,
                         int ttl, u16 ipid,
                         u8* ipops, int ip,
                         u16 sport, u16 dport,
                         const char *data, u16 datalen);

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
                   const char *data, u16 datalen,
                   u32 *packetlen);

u8 *build_sctp_raw_ipv6(const struct in6_addr *source,
                        const struct in6_addr *victim, u8 tc, u32 flowlabel,
                        u8 hoplimit, u16 sport, u16 dport, u32 vtag,
                        char *chunks, int chunkslen, const char *data, u16 datalen,
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
                   const char *data, u16 datalen, u32 *packetlen);

u8 *build_icmpv6_raw(const struct in6_addr *source,
                     const struct in6_addr *victim, u8 tc, u32 flowlabel,
                     u8 hoplimit, u16 seq, u16 id, u8 ptype, u8 pcode,
                     const char *data, u16 datalen, u32 *packetlen);

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
                   const char *data, u16 datalen, u32 *packetlen);


// Returns whether the packet receive time value obtained from libpcap
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
*/

int setTargetMACIfAvailable(Target *target, struct link_header *linkhdr,
                            const struct sockaddr_storage *src, int overwrite);

/* This function ensures that the next hop MAC address for a target is
   filled in.  This address is the target's own MAC if it is directly
   connected, and the next hop mac otherwise.  Returns true if the
   address is set when the function ends, false if not.  This function
   firt checks if it is already set, if not it tries the arp cache,
   and if that fails it sends an ARP request itself.  This should be called
   after an ARP scan if many directly connected machines are involved. */
bool setTargetNextHopMAC(Target *target);

bool getNextHopMAC(const char *iface, const u8 *srcmac, const struct sockaddr_storage *srcss,
                   const struct sockaddr_storage *dstss, u8 *dstmac);



/* Hex dump */
int get_link_offset(char *device);
/* If rcvdtime is non-null and a packet is returned, rcvd will be
   filled with the time that packet was captured from the wire by
   pcap.  If linknfo is not NULL, lnkinfo->headerlen and
   lnkinfo->header will be filled with the appropriate values. */
char *readipv4_pcap(pcap_t *pd, unsigned int *len, long to_usec,
                    struct timeval *rcvdtime, struct link_header *linknfo, bool validate);

char *readip_pcap(pcap_t *pd, unsigned int *len, long to_usec,
                  struct timeval *rcvdtime, struct link_header *linknfo, bool validate);

int read_na_pcap(pcap_t *pd, u8 *sendermac, struct sockaddr_in6 *senderIP, long to_usec,
                  struct timeval *rcvdtime, bool *has_mac);

/* Attempts to read one IPv4/Ethernet ARP reply packet from the pcap
   descriptor pd.  If it receives one, fills in sendermac (must pass
   in 6 bytes), senderIP, and rcvdtime (can be NULL if you don't care)
   and returns 1.  If it times out and reads no arp requests, returns
   0.  to_usec is the timeout period in microseconds.  Use 0 to avoid
   blocking to the extent possible, and -1 to block forever.  Returns
   -1 or exits if there is an error. */
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
   not NULL, it will be set to zero (no timeout occurred) or 1 (it
   did). */
int recvtime(int sd, char *buf, int len, int seconds, int *timedout);

/* Sets a pcap filter function -- makes SOCK_RAW reads easier */
void set_pcap_filter(const char *device, pcap_t *pd, const char *bpf, ...);

#endif /*TCPIP_H*/

