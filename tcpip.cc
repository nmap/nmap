
/***************************************************************************
 * tcpip.cc -- Various functions relating to low level TCP/IP handling,    *
 * including sending raw packets, routing, printing packets, reading from  *
 * libpcap, etc.                                                           *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2004 Insecure.Com LLC. Nmap       *
 * is also a registered trademark of Insecure.Com LLC.  This program is    *
 * free software; you may redistribute and/or modify it under the          *
 * terms of the GNU General Public License as published by the Free        *
 * Software Foundation; Version 2.  This guarantees your right to use,     *
 * modify, and redistribute this software under certain conditions.  If    *
 * you wish to embed Nmap technology into proprietary software, we may be  *
 * willing to sell alternative licenses (contact sales@insecure.com).      *
 * Many security scanner vendors already license Nmap technology such as  *
 * our remote OS fingerprinting database and code, service/version         *
 * detection system, and port scanning code.                               *
 *                                                                         *
 * Note that the GPL places important restrictions on "derived works", yet *
 * it does not provide a detailed definition of that term.  To avoid       *
 * misunderstandings, we consider an application to constitute a           *
 * "derivative work" for the purpose of this license if it does any of the *
 * following:                                                              *
 * o Integrates source code from Nmap                                      *
 * o Reads or includes Nmap copyrighted data files, such as                *
 *   nmap-os-fingerprints or nmap-service-probes.                          *
 * o Executes Nmap and parses the results (as opposed to typical shell or  *
 *   execution-menu apps, which simply display raw Nmap output and so are  *
 *   not derivative works.)                                                * 
 * o Integrates/includes/aggregates Nmap into a proprietary executable     *
 *   installer, such as those produced by InstallShield.                   *
 * o Links to a library or executes a program that does any of the above   *
 *                                                                         *
 * The term "Nmap" should be taken to also include any portions or derived *
 * works of Nmap.  This list is not exclusive, but is just meant to        *
 * clarify our interpretation of derived works with some common examples.  *
 * These restrictions only apply when you actually redistribute Nmap.  For *
 * example, nothing stops you from writing and selling a proprietary       *
 * front-end to Nmap.  Just distribute it by itself, and point people to   *
 * http://www.insecure.org/nmap/ to download Nmap.                         *
 *                                                                         *
 * We don't consider these to be added restrictions on top of the GPL, but *
 * just a clarification of how we interpret "derived works" as it applies  *
 * to our GPL-licensed Nmap product.  This is similar to the way Linus     *
 * Torvalds has announced his interpretation of how "derived works"        *
 * applies to Linux kernel modules.  Our interpretation refers only to     *
 * Nmap - we don't speak for any other GPL products.                       *
 *                                                                         *
 * If you have any questions about the GPL licensing restrictions on using *
 * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
 * we also offer alternative license to integrate Nmap into proprietary    *
 * applications and appliances.  These contracts have been sold to many    *
 * security vendors, and generally include a perpetual license as well as  *
 * providing for priority support and updates as well as helping to fund   *
 * the continued development of Nmap technology.  Please email             *
 * sales@insecure.com for further information.                             *
 *                                                                         *
 * As a special exception to the GPL terms, Insecure.Com LLC grants        *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included Copying.OpenSSL file, and distribute linked      *
 * combinations including the two. You must obey the GNU GPL in all        *
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
 * to fyodor@insecure.org for possible incorporation into the main         *
 * distribution.  By sending these changes to Fyodor or one the            *
 * Insecure.Org development mailing lists, it is assumed that you are      *
 * offering Fyodor and Insecure.Com LLC the unlimited, non-exclusive right *
 * to reuse, modify, and relicense the code.  Nmap will always be          *
 * available Open Source, but this is important because the inability to   *
 * relicense code has caused devastating problems for other Free Software  *
 * projects (such as KDE and NASM).  We also occasionally relicense the    *
 * code to third parties as discussed above.  If you wish to specify       *
 * special license conditions of your contributions, just say so when you  *
 * send them.                                                              *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License for more details at                              *
 * http://www.gnu.org/copyleft/gpl.html , or in the COPYING file included  *
 * with Nmap.                                                              *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */


#include "tcpip.h"
#include "NmapOps.h"

#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#if HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#if HAVE_UNISTD_H
/* #include <sys/unistd.h> */
#include <unistd.h>
#endif

extern NmapOps o;

#ifdef __amigaos__
extern void CloseLibs(void);
#endif

/*  predefined filters -- I need to kill these globals at some pont. */
extern unsigned long flt_dsthost, flt_srchost;
extern unsigned short flt_baseport;

#ifdef WIN32
#include "mswin32/winip/winip.h"

#include "pcap-int.h"

void nmapwin_init();
void nmapwin_cleanup();
void nmapwin_list_interfaces();

int if2nameindex(int ifi);
#endif

static PacketCounter PktCt;

#ifndef WIN32 /* Already defined in wintcpip.c for now */
void sethdrinclude(int sd) {
#ifdef IP_HDRINCL
int one = 1;
setsockopt(sd, IPPROTO_IP, IP_HDRINCL, (const char *) &one, sizeof(one));
#endif
}
#endif /* WIN32 */

// Takes a protocol number like IPPROTO_TCP, IPPROTO_UDP, or
// IPPROTO_TCP and returns a ascii representation (or "unknown" if it
// doesn't recognize the number).  If uppercase is true, the returned
// value will be in all uppercase letters.  You can skip this
// parameter to use lowercase.
const char *proto2ascii(u8 proto, bool uppercase) {

  switch(proto) {
  case IPPROTO_TCP:
    return uppercase? "TCP" : "tcp"; break;
  case IPPROTO_UDP:
    return uppercase? "UDP" : "udp"; break;
  case IPPROTO_IP:
    return uppercase? "IP" : "ip"; break;
  default:
    return uppercase? "UNKNOWN" : "unknown";
  }

  return NULL; // Unreached

}

static char *ll2shortascii(unsigned long long bytes, char *buf, int buflen) {
  if (buflen < 2 || !buf) fatal("Bogus parameter passed to ll2shortascii");

  if (bytes > 1000000) {
    snprintf(buf, buflen, "%.3gMB", bytes / 1000000.0);
  } else if (bytes > 10000) {
    snprintf(buf, buflen, "%.3gKB", bytes / 1000.0);
  } else snprintf(buf, buflen, "%uB", (unsigned int) bytes);
    
  return buf;
}

/* Fill buf (up to buflen -- truncate if necessary but always
   terminate) with a short representation of the packet stats.
   Returns buf.  Aborts if there is a problem. */
char *getFinalPacketStats(char *buf, int buflen) {
  char sendbytesasc[16], recvbytesasc[16];

  if (buflen <= 10 || !buf)
    fatal("getFinalPacketStats called with woefully inadequate parameters");

  snprintf(buf, buflen, 
#if WIN32
	  "Raw packets sent: %I64u (%s) | Rcvd: %I64u (%s)",
#else
	  "Raw packets sent: %llu (%s) | Rcvd: %llu (%s)",
#endif
	   PktCt.sendPackets,
	   ll2shortascii(PktCt.sendBytes, sendbytesasc, sizeof(sendbytesasc)),
	   PktCt.recvPackets,
	   ll2shortascii(PktCt.recvBytes, recvbytesasc, sizeof(recvbytesasc)));
  return buf;
}


  /* Takes an IP PACKET and prints it if packet tracing is enabled.
     'packet' must point to the IPv4 header. The direction must be
     PacketTrace::SENT or PacketTrace::RCVD .  Optional 'now' argument
     makes this function slightly more efficient by avoiding a gettimeofday()
     call. */
void PacketTrace::trace(pdirection pdir, const u8 *packet, u32 len,
			struct timeval *now) {
  struct timeval tv;

  if (pdir == SENT) {
    PktCt.sendPackets++;
    PktCt.sendBytes += len;
  } else {
    PktCt.recvPackets++;
    PktCt.recvBytes += len;
  }

  if (!o.packetTrace()) return;

  if (now)
    tv = *now;
  else gettimeofday(&tv, NULL);

  if (len < 20) {
    error("Packet tracer: tiny packet encountered");
    return;
  }

  log_write(LOG_STDOUT|LOG_NORMAL, "%s (%.4fs) %s\n", (pdir == SENT)? "SENT" : "RCVD",  o.TimeSinceStartMS(&tv) / 1000.0, ippackethdrinfo(packet, len));

  return;
}

/* Adds a trace entry when a connect() is attempted if packet tracing
   is enabled.  Pass IPPROTO_TCP or IPPROTO_UDP as the protocol.  The
   sock may be a sockaddr_in or sockaddr_in6.  The return code of
   connect is passed in connectrc.  If the return code is -1, get the
   errno and pass that as connect_errno. */
void PacketTrace::traceConnect(u8 proto, const struct sockaddr *sock, 
			       int socklen, int connectrc, int connect_errno,
			       const struct timeval *now) {
  struct sockaddr_in *sin = (struct sockaddr_in *) sock;
#if HAVE_IPV6
  struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) sock;
#endif
  struct timeval tv;
  char errbuf[64] = "";
  char targetipstr[INET6_ADDRSTRLEN] = "";
  u16 targetport = 0;

  if (!o.packetTrace()) return;
  
  if (now)
    tv = *now;
  else gettimeofday(&tv, NULL);

  assert(proto == IPPROTO_TCP || proto == IPPROTO_UDP);

  if (connectrc == 0)
    Strncpy(errbuf, "Connected", sizeof(errbuf));
  else {
    snprintf(errbuf, sizeof(errbuf), "%s", strerror(connect_errno));
  }

  if (sin->sin_family == AF_INET) {
    if (inet_ntop(sin->sin_family, (char *) &sin->sin_addr, targetipstr, 
		  sizeof(targetipstr)) == NULL)
      fatal("Failed to convert target IPv4 address to presentation format!?!");
    targetport = ntohs(sin->sin_port);
  } else {
#if HAVE_IPV6
    assert(sin->sin_family == AF_INET6);
    if (inet_ntop(sin->sin_family, (char *) &sin6->sin6_addr, targetipstr, 
		  sizeof(targetipstr)) == NULL)
      fatal("Failed to convert target IPv4 address to presentation format!?!");
    targetport = ntohs(sin6->sin6_port);
#else
    assert(0);
#endif
  }

  log_write(LOG_STDOUT|LOG_NORMAL, "CONN (%.4fs) %s localhost > %s:%d => %s\n",
	    o.TimeSinceStartMS(&tv) / 1000.0, 
	    (proto == IPPROTO_TCP)? "TCP" : "UDP", targetipstr, targetport, 
	    errbuf);
}

/* Converts an IP address given in a sockaddr_storage to an IPv4 or
   IPv6 IP address string.  Since a static buffer is returned, this is
   not thread-safe and can only be used once in calls like printf() 
*/
const char *inet_socktop(struct sockaddr_storage *ss) {
  static char buf[INET6_ADDRSTRLEN];
  struct sockaddr_in *sin = (struct sockaddr_in *) ss;
#if HAVE_IPV6
  struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) ss;
#endif

  if (inet_ntop(sin->sin_family, (sin->sin_family == AF_INET)? 
                (char *) &sin->sin_addr : 
#if HAVE_IPV6
				(char *) &sin6->sin6_addr, 
#else
                (char *) NULL,
#endif /* HAVE_IPV6 */
                buf, sizeof(buf)) == NULL) {
    fatal("Failed to convert target address to presentation format in inet_socktop!?!  Error: %s", strerror(socket_errno()));
  }
  return buf;
}

/* Tries to resolve the given name (or literal IP) into a sockaddr
   structure.  The af should be PF_INET (for IPv4) or PF_INET6.  Returns 0
   if hostname cannot be resolved.  It is OK to pass in a sockaddr_in or 
   sockaddr_in6 casted to a sockaddr_storage as long as you use the matching 
   pf.*/
int resolve(char *hostname, struct sockaddr_storage *ss, size_t *sslen,
	    int pf) {

  struct addrinfo hints;
  struct addrinfo *result;
  int rc;

  assert(ss);
  assert(sslen);
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = pf;
  rc = getaddrinfo(hostname, NULL, &hints, &result);
  if (rc != 0)
    return 0;
  assert(result->ai_addrlen > 0 && result->ai_addrlen <= (int) sizeof(struct sockaddr_storage));
  *sslen = result->ai_addrlen;
  memcpy(ss, result->ai_addr, *sslen);
  freeaddrinfo(result);
  return 1;
}


/* Returns a buffer of ASCII information about a packet that may look
   like "TCP 127.0.0.1:50923 > 127.0.0.1:3 S ttl=61 id=39516 iplen=40
   seq=625950769" or "ICMP PING (0/1) ttl=61 id=39516 iplen=40".
   Since this is a static buffer, don't use threads or call twice
   within (say) printf().  And certainly don't try to free() it!  The
   returned buffer is NUL-terminated */
const char *ippackethdrinfo(const u8 *packet, u32 len) {
  static char protoinfo[256];
  struct ip *ip = (struct ip *) packet;
  struct tcphdr *tcp;
  udphdr_bsd *udp;
  char ipinfo[64];
  char srchost[INET6_ADDRSTRLEN], dsthost[INET6_ADDRSTRLEN];
  char *p;
  struct in_addr saddr, daddr;
  int frag_off = 0, more_fragments = 0;
  char fragnfo[64] = "";
  char tflags[10];
  if (ip->ip_v != 4)
    return "BOGUS!  IP Version in packet is not 4";

  if (len < sizeof(struct ip))
    return "BOGUS!  Packet too short.";

  saddr.s_addr = ip->ip_src.s_addr;
  daddr.s_addr = ip->ip_dst.s_addr;

  inet_ntop(AF_INET, &saddr, srchost, sizeof(srchost));
  inet_ntop(AF_INET, &daddr, dsthost, sizeof(dsthost));

  frag_off = 8 * (BSDUFIX(ip->ip_off) & 8191) /* 2^13 - 1 */;
  more_fragments = BSDUFIX(ip->ip_off) & IP_MF;
  if (frag_off || more_fragments) {
    snprintf(fragnfo, sizeof(fragnfo), " frag offset=%d%s", frag_off, more_fragments ? "+" : "");
  }
  

  snprintf(ipinfo, sizeof(ipinfo), "ttl=%d id=%d iplen=%d%s", 
	   ip->ip_ttl, ntohs(ip->ip_id), BSDUFIX(ip->ip_len), fragnfo);

  if (ip->ip_p == IPPROTO_TCP) {
    char tcpinfo[64] = "";
    char buf[32];
    tcp = (struct tcphdr *)  (packet + ip->ip_hl * 4);
    if (frag_off > 8 || len < (u32) ip->ip_hl * 4 + 8) 
      snprintf(protoinfo, sizeof(protoinfo), "TCP %s:?? > %s:?? ?? %s (incomplete)", srchost, dsthost, ipinfo);
    else if (frag_off == 8 && len >= (u32) ip->ip_hl * 4 + 8) {// we can get TCP flags nad ACKn
      tcp = (struct tcphdr *)((u8 *) tcp - frag_off); // ugly?
      p = tflags;
      /* These are basically in tcpdump order */
      if (tcp->th_flags & TH_SYN) *p++ = 'S';
      if (tcp->th_flags & TH_FIN) *p++ = 'F';
      if (tcp->th_flags & TH_RST) *p++ = 'R';
      if (tcp->th_flags & TH_PUSH) *p++ = 'P';
      if (tcp->th_flags & TH_ACK) {
	*p++ = 'A';
	snprintf(tcpinfo, sizeof(tcpinfo), " ack=%lu", 
		 (unsigned long) ntohl(tcp->th_ack));
      }
      if (tcp->th_flags & TH_URG) *p++ = 'U';
      if (tcp->th_flags & TH_ECE) *p++ = 'E'; /* rfc 2481/3168 */
      if (tcp->th_flags & TH_CWR) *p++ = 'C'; /* rfc 2481/3168 */
      *p++ = '\0';

      snprintf(protoinfo, sizeof(protoinfo), "TCP %s:?? > %s:?? %s %s %s",
	       srchost, dsthost, tflags, ipinfo, tcpinfo);
    } else if (len < (u32) ip->ip_hl * 4 + 16) { // we can get ports an seq
      snprintf(tcpinfo, sizeof(tcpinfo), "seq=%lu (incomplete)", (unsigned long) ntohl(tcp->th_seq));
      snprintf(protoinfo, sizeof(protoinfo), "TCP %s:%d > %s:%d ?? %s %s",
	       srchost, ntohs(tcp->th_sport), dsthost, ntohs(tcp->th_dport), ipinfo, tcpinfo);
    } else if (len < (u32) ip->ip_hl * 4 + 16 && !frag_off) { // we can't get TCP flags
      snprintf(protoinfo, sizeof(protoinfo), "TCP %s:%d > %s:%d ?? %s %s (incomplete)",
	       srchost, ntohs(tcp->th_sport), dsthost, ntohs(tcp->th_dport),
	       ipinfo, tcpinfo);
    } else { // at least first 16 bytes of TCP header are there (everything we need)

      snprintf(tcpinfo, sizeof(tcpinfo), "seq=%lu win=%hi", 
	       (unsigned long) ntohl(tcp->th_seq),
	       ntohs(tcp->th_win));
      p = tflags;
      /* These are basically in tcpdump order */
      if (tcp->th_flags & TH_SYN) *p++ = 'S';
      if (tcp->th_flags & TH_FIN) *p++ = 'F';
      if (tcp->th_flags & TH_RST) *p++ = 'R';
      if (tcp->th_flags & TH_PUSH) *p++ = 'P';
      if (tcp->th_flags & TH_ACK) {
	*p++ = 'A';
	snprintf(buf, sizeof(buf), " ack=%lu", 
		 (unsigned long) ntohl(tcp->th_ack));
	strncat(tcpinfo, buf, sizeof(tcpinfo));
      }
      if (tcp->th_flags & TH_URG) *p++ = 'U';
      if (tcp->th_flags & TH_ECE) *p++ = 'E'; /* rfc 2481/3168 */
      if (tcp->th_flags & TH_CWR) *p++ = 'C'; /* rfc 2481/3168 */
      *p++ = '\0';

      snprintf(protoinfo, sizeof(protoinfo), "TCP %s:%d > %s:%d %s %s %s",
	       srchost, ntohs(tcp->th_sport), dsthost, ntohs(tcp->th_dport),
	       tflags, ipinfo, tcpinfo);
    }
  } else if (ip->ip_p == IPPROTO_UDP && frag_off) {
      snprintf(protoinfo, sizeof(protoinfo), "UDP %s:?? > %s:?? fragment %s (incomplete)", srchost, dsthost, ipinfo);
  } else if (ip->ip_p == IPPROTO_UDP) {
    udp =  (udphdr_bsd *) (packet + sizeof(struct ip));

    snprintf(protoinfo, sizeof(protoinfo), "UDP %s:%d > %s:%d %s",
	     srchost, ntohs(udp->uh_sport), dsthost, ntohs(udp->uh_dport),
	     ipinfo);
  } else if (ip->ip_p == IPPROTO_ICMP && frag_off) {
      snprintf(protoinfo, sizeof(protoinfo), "ICMP %s > %s fragment %s (incomplete)", srchost, dsthost, ipinfo);
  } else if (ip->ip_p == IPPROTO_ICMP) {
    char icmptype[128];
    struct ppkt {
      unsigned char type;
      unsigned char code;
      unsigned short checksum;
      unsigned short id;
      unsigned short seq;
    } *ping;
    ping = (struct ppkt *) ((ip->ip_hl * 4) + (char *) ip);
    switch(ping->type) {
    case 0:
      strcpy(icmptype, "Echo reply"); break;
    case 3:
      if (ping->code == 0)
	strcpy(icmptype, "network unreachable");
      else if (ping->code == 1)
	strcpy(icmptype, "host unreachable");
      else if (ping->code == 2)
	strcpy(icmptype, "protocol unreachable");
      else if (ping->code == 3)
	strcpy(icmptype, "port unreachable");
      else if (ping->code == 4)
	strcpy(icmptype, "fragmentation required");
      else if (ping->code == 5)
	strcpy(icmptype, "source route failed");
      else if (ping->code == 6)
	strcpy(icmptype, "destination network unknown");
      else if (ping->code == 7)
	strcpy(icmptype, "destination host unknown");
      else if (ping->code == 8)
	strcpy(icmptype, "source host isolated");
      else if (ping->code == 9)
	strcpy(icmptype, "destination network administratively prohibited");
      else if (ping->code == 10)
	strcpy(icmptype, "destination host administratively prohibited");
      else if (ping->code == 11)
	strcpy(icmptype, "network unreachable for TOS");
      else if (ping->code == 12)
	strcpy(icmptype, "host unreachable for TOS");
      else if (ping->code == 13)
	strcpy(icmptype, "communication administratively prohibited by filtering");
      else if (ping->code == 14)
	strcpy(icmptype, "host precedence violation");
      else if (ping->code == 15)
	strcpy(icmptype, "precedence cutoff in effect");
      else
	strcpy(icmptype, "unknown unreachable code");
      break;
    case 4:
      strcpy(icmptype, "source quench"); break;
    case 5:
      if (ping->code == 0)
	strcpy(icmptype, "network redirect");
      else if (ping->code == 1)
	strcpy(icmptype, "host redirect");
      else strcpy(icmptype, "unknown redirect");
      break;
    case 8:
      strcpy(icmptype, "Echo request"); break;
    case 11:
      if (ping->code == 0)
	strcpy(icmptype, "TTL=0 during transit");
      else if (ping->code == 1)
	strcpy(icmptype, "TTL=0 during reassembly");
      else strcpy(icmptype, "TTL exceeded (unknown code)");
      break;
    case 12:
      if (ping->code == 0)
	strcpy(icmptype, "IP header bad");
      else 
	strcpy(icmptype, "Misc. parameter problem");
      break;
    case 13: 
      strcpy(icmptype, "Timestamp request"); break;
    case 14: 
      strcpy(icmptype, "Timestamp reply"); break;
    case 15:
      strcpy(icmptype, "Information request"); break;
    case 16: 
      strcpy(icmptype, "Information reply"); break;
    case 17:
      strcpy(icmptype, "Address mask request"); break;
    case 18: 
      strcpy(icmptype, "Address mask reply"); break;
    case 30:
      strcpy(icmptype, "Traceroute"); break;
    case 37:
      strcpy(icmptype, "Domain name request"); break;
    case 38:
      strcpy(icmptype, "Domain name reply"); break; 
    case 40:
      strcpy(icmptype, "Security failures"); /* rfc 2521 */ break;
      
    default:
      strcpy(icmptype, "Unknown type"); break;
      break;
    }
    snprintf(protoinfo, sizeof(protoinfo), "ICMP %s > %s %s (type=%d/code=%d) %s",
	     srchost, dsthost, icmptype, ping->type, ping->code, ipinfo);
  } else {
    snprintf(protoinfo, sizeof(protoinfo), "Unknown protocol (%d): %s", 
	     ip->ip_p, ipinfo);
  }    

  return protoinfo;
}


int islocalhost(const struct in_addr * const addr) {
char dev[128];
  /* If it is 0.0.0.0 or starts with 127.0.0.1 then it is 
     probably localhost */
  if ((addr->s_addr & htonl(0xFF000000)) == htonl(0x7F000000))
    return 1;

  if (!addr->s_addr)
    return 1;

  /* If it is the same addy as a local interface, then it is
     probably localhost */

  if (ipaddr2devname(dev, addr) != -1)
    return 1;

  /* OK, so to a first approximation, this addy is probably not
     localhost */
  return 0;
}

/* Calls pcap_open_live and spits out an error (and quits) if the call
   faile.  So a valid pcap_t will always be returned.  Note that the
   Windows/UNIX versions are separate since they differ so much.
   Also, the actual my_pcap_open_live() for Windows is in
   mswin32/winip/winip.c.  It calls the function below if pcap is
   being used, otherwise it uses Windows raw sockets. */
#ifdef WIN32
pcap_t *my_real_pcap_open_live(char *device, int snaplen, int promisc, int to_ms) 
{
  char err0r[PCAP_ERRBUF_SIZE];
  pcap_t *pt;
  const WINIP_IF *ifentry;
  int ifi = name2ifi(device);
  
  if(ifi == -1)
    fatal("my_real_pcap_open_live: invalid device %s\n", device);
  
  if(o.debugging > 1)
    printf("Trying to open %s for receive with winpcap.\n", device);
  
  ifentry = ifi2ifentry(ifi);
  
  //	check for bogus interface
  if(!ifentry->pcapname)
    {
      fatal("my_real_pcap_open_live: called with non-pcap interface %s!\n",
	    device);
    }
  
  if (!((pt = pcap_open_live(ifentry->pcapname, snaplen, promisc, to_ms, err0r)))) 	
    fatal("pcap_open_live: %s");
	  
	  
  //	This should help
  pcap_setmintocopy(pt, 1);
  
  return pt;
}

#else // !WIN32
pcap_t *my_pcap_open_live(char *device, int snaplen, int promisc, int to_ms) 
{
  char err0r[PCAP_ERRBUF_SIZE];
  pcap_t *pt;
  if (!((pt = pcap_open_live(device, snaplen, promisc, to_ms, err0r)))) {
    fatal("pcap_open_live: %s\nThere are several possible reasons for this, depending on your operating system:\n"
          "LINUX: If you are getting Socket type not supported, try modprobe af_packet or recompile your kernel with SOCK_PACKET enabled.\n"
          "*BSD:  If you are getting device not configured, you need to recompile your kernel with Berkeley Packet Filter support.  If you are getting No such file or directory, try creating the device (eg cd /dev; MAKEDEV <device>; or use mknod).\n"
          "SOLARIS:  If you are trying to scan localhost and getting '/dev/lo0: No such file or directory', complain to Sun.  I don't think Solaris can support advanced localhost scans.  You can probably use \"-P0 -sT localhost\" though.\n\n", err0r);
  }
  return pt;
}
#endif // WIN32

/* Standard BSD internet checksum routine */
unsigned short in_cksum(u16 *ptr,int nbytes) {

register u32 sum;
u16 oddbyte;
register u16 answer;

/*
 * Our algorithm is simple, using a 32-bit accumulator (sum),
 * we add sequential 16-bit words to it, and at the end, fold back
 * all the carry bits from the top 16 bits into the lower 16 bits.
 */

sum = 0;
while (nbytes > 1)  {
sum += *ptr++;
nbytes -= 2;
}

/* mop up an odd byte, if necessary */
if (nbytes == 1) {
oddbyte = 0;            /* make sure top half is zero */
*((u_char *) &oddbyte) = *(u_char *)ptr;   /* one byte only */
sum += oddbyte;
}

/*
 * Add back carry outs from top 16 bits to low 16 bits.
 */

sum  = (sum >> 16) + (sum & 0xffff);    /* add high-16 to low-16 */
sum += (sum >> 16);                     /* add carry */
answer = ~sum;          /* ones-complement, then truncate to 16 bits */
return(answer);
}

/* LEGACY resolve() function that only supports IPv4 -- see IPv6 version
   above.  Tries to resolve given hostname and stores
   result in ip .  returns 0 if hostname cannot
   be resolved */
int resolve(char *hostname, struct in_addr *ip) {
  struct hostent *h;

  if (!hostname || !*hostname)
    fatal("NULL or zero-length hostname passed to resolve()");

  if (inet_aton(hostname, ip))
    return 1; /* damn, that was easy ;) */
  if ((h = gethostbyname(hostname))) {
    memcpy(ip, h->h_addr_list[0], sizeof(struct in_addr));
    return 1;
  }
  return 0;
}

int send_tcp_raw_decoys( int sd, const struct in_addr *victim, int ttl,
			 u16 sport, u16 dport, u32 seq, u32 ack, u8 flags,
			 u16 window, u8 *options, int optlen, char *data,
			 u16 datalen) 
{
  int decoy;

  for(decoy = 0; decoy < o.numdecoys; decoy++) 
    if (send_tcp_raw(sd, &o.decoys[decoy], victim, ttl, sport, dport, seq, ack,
		     flags, window, options, optlen, data, datalen) == -1)
      return -1;

  return 0;
}

/* Builds a TCP packet (including an IP header) by packing the fields
   with the given information.  It allocates a new buffer to store the
   packet contents, and then returns that buffer.  The packet is not
   actually sent by this function.  Caller must delete the buffer when
   finished with the packet.  The packet length is returned in
   packetlen, which must be a valid int pointer. */
u8 *build_tcp_raw(const struct in_addr *source, 
		  const struct in_addr *victim, int ttl, 
		  u16 ipid, u16 sport, u16 dport, u32 seq, u32 ack, u8 flags,
		  u16 window, u8 *options, int optlen, char *data, 
		  u16 datalen, u32 *packetlen) {

struct pseudo_header { 
  /*for computing TCP checksum, see TCP/IP Illustrated p. 145 */
  u32 s_addy;
  u32 d_addr;
  u8 zer0;
  u8 protocol;
  u16 length;
};
u8 *packet = (u8 *) safe_malloc(sizeof(struct ip) + sizeof(struct tcphdr) + optlen + datalen);
struct ip *ip = (struct ip *) packet;
struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof(struct ip));
struct pseudo_header *pseudo =  (struct pseudo_header *) (packet + sizeof(struct ip) - sizeof(struct pseudo_header)); 
static int myttl = 0;

assert(victim);
assert(source);

if (optlen % 4) {
  fatal("build_tcp_raw() called with an option length argument of %d which is illegal because it is not divisible by 4", optlen);
}

/* Time to live */
if (ttl == -1) {
  myttl = (get_random_uint() % 23) + 37;
} else {
  myttl = ttl;
}

memset((char *) packet, 0, sizeof(struct ip) + sizeof(struct tcphdr));

pseudo->s_addy = source->s_addr;
pseudo->d_addr = victim->s_addr;
pseudo->protocol = IPPROTO_TCP;
pseudo->length = htons(sizeof(struct tcphdr) + optlen + datalen);

tcp->th_sport = htons(sport);
tcp->th_dport = htons(dport);
if (seq) {
  tcp->th_seq = htonl(seq);
}
else if (flags & TH_SYN) {
  get_random_bytes(&(tcp->th_seq), 4);
}

if (ack)
  tcp->th_ack = htonl(ack);
/*else if (flags & TH_ACK)
  tcp->th_ack = rand() + rand();*/

tcp->th_off = 5 + (optlen /4) /*words*/;
tcp->th_flags = flags;

if (window)
  tcp->th_win = htons(window);
else tcp->th_win = htons(1024 * (myttl % 4 + 1)); /* Who cares */

 /* We should probably copy the data over too */
 if (data && datalen)
   memcpy(packet + sizeof(struct ip) + sizeof(struct tcphdr) + optlen, data, datalen);
 /* And the options */
 if (optlen) {
   memcpy(packet + sizeof(struct ip) + sizeof(struct tcphdr), options, optlen);
 }

#if STUPID_SOLARIS_CHECKSUM_BUG
 tcp->th_sum = sizeof(struct tcphdr) + optlen + datalen; 
#else
tcp->th_sum = in_cksum((unsigned short *)pseudo, sizeof(struct tcphdr) + 
		       optlen + sizeof(struct pseudo_header) + datalen);
#endif
/* Now for the ip header */

memset(packet, 0, sizeof(struct ip)); 
ip->ip_v = 4;
ip->ip_hl = 5;
ip->ip_len = BSDFIX(sizeof(struct ip) + sizeof(struct tcphdr) + optlen + datalen);
get_random_bytes(&(ip->ip_id), 2);
ip->ip_ttl = myttl;
ip->ip_p = IPPROTO_TCP;
ip->ip_id = ipid;
ip->ip_src.s_addr = source->s_addr;
#ifdef WIN32
// I'm not sure why this is --Fyodor
if (source->s_addr == victim->s_addr) ip->ip_src.s_addr++;
#endif

ip->ip_dst.s_addr= victim->s_addr;
#if HAVE_IP_IP_SUM
ip->ip_sum = in_cksum((unsigned short *)ip, sizeof(struct ip));
#endif

if (TCPIP_DEBUGGING > 1) {
  log_write(LOG_STDOUT, "Raw TCP packet creation completed!  Here it is:\n");
  readtcppacket(packet,BSDUFIX(ip->ip_len));
}

 *packetlen = BSDUFIX(ip->ip_len);
 return packet;

}

/* You need to call sethdrinclude(sd) on the sending sd before calling this */
int send_tcp_raw( int sd, const struct in_addr *source, 
		  const struct in_addr *victim, int ttl, 
		  u16 sport, u16 dport, u32 seq, u32 ack, u8 flags,
		  u16 window, u8 *options, int optlen, char *data, 
		  u16 datalen) 
{
  unsigned int packetlen;
  int res = -1;

  u8 *packet = build_tcp_raw(source, victim, ttl, get_random_u16(), sport, 
			     dport, seq, ack, flags, window, options, optlen, 
			     data, datalen, &packetlen);
  if (!packet) return -1;
  res = send_ip_packet(sd, packet, packetlen);

  free(packet);
  return res;
}

/* Send a pre-built IPv4 packet */
int send_ip_packet(int sd, u8 *packet, unsigned int packetlen) {
  struct sockaddr_in sock;
  int res;
  struct ip *ip = (struct ip *) packet;
  struct tcphdr *tcp = NULL;
  udphdr_bsd *udp;

  assert(sd >= 0);
  assert(packet);
  assert( (int) packetlen > 0);

  // fragmentation requested && packet is bigger than MTU
  if (o.fragscan && ( packetlen - ip->ip_hl * 4 > (unsigned int) o.fragscan ))
      return send_frag_ip_packet(sd, packet, packetlen, o.fragscan);

  memset(&sock, 0, sizeof(sock));
  sock.sin_family = AF_INET;
#if HAVE_SOCKADDR_SA_LEN
  sock.sin_len = sizeof(sock);
#endif
  /* It is bogus that I need the address and port info when sending a RAW IP 
     packet, but it doesn't seem to work w/o them */
  if (packetlen >= 20) {
    sock.sin_addr.s_addr = ip->ip_dst.s_addr;
    if (ip->ip_p == IPPROTO_TCP && packetlen >= (unsigned int) ip->ip_hl * 4 + 20) {
      tcp = (struct tcphdr *) ((u8 *) ip + ip->ip_hl * 4);
      sock.sin_port = tcp->th_dport;
    } else if (ip->ip_p == IPPROTO_UDP && packetlen >= (unsigned int) ip->ip_hl * 4 + 8) {
      udp = (udphdr_bsd *) ((u8 *) ip + ip->ip_hl * 4);
      sock.sin_port = udp->uh_dport;
    }
  }
  /* I'll try leaving out dest port and address and see what happens */
  /* sock.sin_port = htons(dport);
     sock.sin_addr.s_addr = victim->s_addr; */
  
  res = Sendto("send_ip_packet", sd, packet, BSDUFIX(ip->ip_len), 0,
	       (struct sockaddr *)&sock,  (int)sizeof(struct sockaddr_in));
  return res;
}

/* Create and send all fragments of a pre-built IPv4 packet
 * Minimal MTU for IPv4 is 68 and maximal IPv4 header size is 60
 * which gives us a right to cut TCP header after 8th byte
 * (shouldn't we inflate the header to 60 bytes too?) */
int send_frag_ip_packet(int sd, u8 *packet, unsigned int packetlen, unsigned int mtu)
{
    struct ip *ip = (struct ip *) packet;
    int headerlen = ip->ip_hl * 4; // better than sizeof(struct ip)
    unsigned int datalen = packetlen - headerlen;
    int fdatalen = 0, res = 0;

    assert(headerlen <= (int) packetlen);
    assert(headerlen >= 20 && headerlen <= 60); // sanity check (RFC791)
    assert(mtu > 0 && mtu % 8 == 0); // otherwise, we couldn't set Fragment offset (ip->ip_off) correctly

    if (datalen <= mtu) {
        error("Warning: fragmentation (mtu=%i) requested but the payload is too small already (%i)", mtu, datalen);
        return send_ip_packet(sd, packet, packetlen);
    }

    u8 *fpacket = (u8 *) safe_malloc(headerlen + mtu);
    memcpy(fpacket, packet, headerlen + mtu);
    ip = (struct ip *) fpacket;

    // create fragments and send them
    for (int fragment = 1; fragment * mtu < datalen + mtu; fragment++) {
        fdatalen = (fragment * mtu <= datalen ? mtu : datalen % mtu);
        ip->ip_len = BSDFIX(headerlen + fdatalen);
        ip->ip_off = BSDFIX((fragment-1) * mtu / 8);
        if ((fragment-1) * mtu + fdatalen < datalen)
            ip->ip_off |= BSDFIX(IP_MF);
#if HAVE_IP_IP_SUM
        ip->ip_sum = in_cksum((unsigned short *)ip, headerlen);
#endif
        if (fragment > 1) // copy data payload
            memcpy(fpacket + headerlen, packet + headerlen + (fragment - 1) * mtu, fdatalen);
        res = send_ip_packet(sd, fpacket, headerlen + fdatalen);
        if (res == -1)
            break;
    }

    free(fpacket);

    return res;
}

/* Builds an ICMP packet (including an IP header) by packing the fields
   with the given information.  It allocates a new buffer to store the
   packet contents, and then returns that buffer.  The packet is not
   actually sent by this function.  Caller must delete the buffer when
   finished with the packet.  The packet length is returned in
   packetlen, which must be a valid int pointer. */
u8 *build_icmp_raw(const struct in_addr *source, const struct in_addr *victim, 
		   int ttl, u16 ipid, u16 seq, unsigned short id, u8 ptype, 
		   u8 pcode, char *data, u16 datalen, u32 *packetlen) {

struct ppkt {
  u8 type;
  u8 code;
  u16 checksum;
  u16 id;
  u16 seq;
  u8 data[1500]; /* Note -- first 4-12 bytes can be used for ICMP header */
} pingpkt;
u32 *datastart = (u32 *) pingpkt.data;
int dlen = sizeof(pingpkt.data); 
int icmplen=0;
char *ping = (char *) &pingpkt;

 pingpkt.type = ptype;
 pingpkt.code = pcode;

 if (ptype == 8 && pcode == 0) /* echo request */ {
   icmplen = 8;
 } else if (ptype == 13 && pcode == 0) /* ICMP timestamp req */ {
   icmplen = 20;
   memset(datastart, 0, 12);
   datastart += 12;
   datalen -= 12;
 } else if (ptype == 17 && pcode == 0) /* icmp netmask req */ {
   icmplen = 12;
   *datastart++ = 0;
   datalen -= 4;
 } else 
   fatal("Unknown icmp type/code (%d/%d) in build_icmp_raw", ptype, pcode);

 if (datalen > 0) {
   icmplen += MIN(dlen, datalen);
   memset(datastart, 0, MIN(dlen, datalen));
 }
/* Fill out the ping packet */

pingpkt.code = 0;
pingpkt.id = id;
pingpkt.seq = seq;
pingpkt.checksum = 0;
pingpkt.checksum = in_cksum((unsigned short *)ping, icmplen);

return build_ip_raw(source, victim, o.ttl, IPPROTO_ICMP, get_random_u16(),
		    ping, icmplen, packetlen);
}

void readippacket(const u8 *packet, int readdata) {
  struct ip *ip = (struct ip *) packet;
  switch(ip->ip_p) {
  case IPPROTO_UDP:
    readudppacket(packet, readdata);
    break;
    /* Should add ICMP here at some point */
  default:
    readtcppacket(packet, readdata);
    break;
  }

}

/* A simple function I wrote to help in debugging, shows the important fields
   of a TCP packet*/
int readtcppacket(const u8 *packet, int readdata) {

struct ip *ip = (struct ip *) packet;
struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof(struct ip));
const unsigned char *data = packet +  sizeof(struct ip) + sizeof(struct tcphdr);
int tot_len;
struct in_addr bullshit, bullshit2;
char sourcehost[16];
int i;
int realfrag = 0;

if (!packet) {
  fprintf(stderr, "readtcppacket: packet is NULL!\n");
  return -1;
    }

bullshit.s_addr = ip->ip_src.s_addr; bullshit2.s_addr = ip->ip_dst.s_addr;
/* this is gay */
realfrag = BSDFIX(ntohs(ip->ip_off) & 8191 /* 2^13 - 1 */);
tot_len = BSDFIX(ip->ip_len);
strncpy(sourcehost, inet_ntoa(bullshit), 16);
i =  4 * (ntohs(ip->ip_hl) + ntohs(tcp->th_off));
if (ip->ip_p== IPPROTO_TCP) {
  if (realfrag) 
    printf("Packet is fragmented, offset field: %u\n", realfrag);
  else {
    printf("TCP packet: %s:%d -> %s:%d (total: %d bytes)\n", sourcehost, 
	   ntohs(tcp->th_sport), inet_ntoa(bullshit2), 
	   ntohs(tcp->th_dport), tot_len);
    printf("Flags: ");
    if (!tcp->th_flags) printf("(none)");
    if (tcp->th_flags & TH_RST) printf("RST ");
    if (tcp->th_flags & TH_SYN) printf("SYN ");
    if (tcp->th_flags & TH_ACK) printf("ACK ");
    if (tcp->th_flags & TH_PUSH) printf("PSH ");
    if (tcp->th_flags & TH_FIN) printf("FIN ");
    if (tcp->th_flags & TH_URG) printf("URG ");
    printf("\n");

    printf("ipid: %hu ttl: %hu ", ntohs(ip->ip_id), ip->ip_ttl);

    if (tcp->th_flags & (TH_SYN | TH_ACK)) printf("Seq: %u\tAck: %u\n", 
						  (unsigned int) ntohl(tcp->th_seq), (unsigned int) ntohl(tcp->th_ack));
    else if (tcp->th_flags & TH_SYN) printf("Seq: %u\n", (unsigned int) ntohl(tcp->th_seq));
    else if (tcp->th_flags & TH_ACK) printf("Ack: %u\n", (unsigned int) ntohl(tcp->th_ack));
  }
}
if (readdata && i < tot_len) {
  printf("Data portion:\n");
  while(i < tot_len)  {
    printf("%2X%c", data[i], ((i+1) %16)? ' ' : '\n');
    i++;
  }
  printf("\n");
}
return 0;
}

/* A simple function I wrote to help in debugging, shows the important fields
   of a UDP packet*/
int readudppacket(const u8 *packet, int readdata) {

struct ip *ip = (struct ip *) packet;
udphdr_bsd *udp = (udphdr_bsd *) (packet + sizeof(struct ip));
const unsigned char *data = packet +  sizeof(struct ip) + sizeof(udphdr_bsd);
int tot_len;
struct in_addr bullshit, bullshit2;
char sourcehost[16];
int i;
int realfrag = 0;

if (!packet) {
  fprintf(stderr, "readudppacket: packet is NULL!\n");
  return -1;
    }

bullshit.s_addr = ip->ip_src.s_addr; bullshit2.s_addr = ip->ip_dst.s_addr;
/* this is gay */
realfrag = BSDFIX(ntohs(ip->ip_off) & 8191 /* 2^13 - 1 */);
tot_len = BSDFIX(ip->ip_len);
strncpy(sourcehost, inet_ntoa(bullshit), 16);
i =  4 * (ntohs(ip->ip_hl)) + 8;
if (ip->ip_p== IPPROTO_UDP) {
  if (realfrag) 
    printf("Packet is fragmented, offset field: %u\n", realfrag);
  else {
    printf("UDP packet: %s:%d -> %s:%d (total: %d bytes)\n", sourcehost, 
	   ntohs(udp->uh_sport), inet_ntoa(bullshit2), 
	   ntohs(udp->uh_dport), tot_len);

    printf("ttl: %hu ", ip->ip_ttl);
  }
}
 if (readdata && i < tot_len) {
   printf("Data portion:\n");
   while(i < tot_len)  {
     printf("%2X%c", data[i], ((i+1)%16)? ' ' : '\n');
     i++;
   }
   printf("\n");
 }
 return 0;
}

int send_udp_raw_decoys( int sd, const struct in_addr *victim, int ttl, 
			 u16 sport, u16 dport, u16 ipid, char *data, 
			 u16 datalen) {
  int decoy;
  
  for(decoy = 0; decoy < o.numdecoys; decoy++) 
    if (send_udp_raw(sd, &o.decoys[decoy], victim, ttl, sport, dport, ipid,
		     data, datalen) == -1)
      return -1;

  return 0;
}


/* Builds a UDP packet (including an IP header) by packing the fields
   with the given information.  It allocates a new buffer to store the
   packet contents, and then returns that buffer.  The packet is not
   actually sent by this function.  Caller must delete the buffer when
   finished with the packet.  The packet length is returned in
   packetlen, which must be a valid int pointer. */
u8 *build_udp_raw(struct in_addr *source, const struct in_addr *victim,
 		  int ttl, u16 sport, u16 dport, u16 ipid, char *data, 
		  u16 datalen, u32 *packetlen) 
{
  unsigned char *packet = (unsigned char *) safe_malloc(sizeof(struct ip) + sizeof(udphdr_bsd) + datalen);
  struct ip *ip = (struct ip *) packet;
  udphdr_bsd *udp = (udphdr_bsd *) (packet + sizeof(struct ip));
  static int myttl = 0;
  
  struct pseudo_udp_hdr {
    struct in_addr source;
    struct in_addr dest;        
    u8 zero;
    u8 proto;        
    u16 length;
  } *pseudo = (struct pseudo_udp_hdr *) ((char *)udp - 12) ;

  *packetlen = 0;

  /* check that required fields are there and not too silly */
  if ( !victim) {
    fprintf(stderr, "build_udp_raw: One or more of your parameters suck!\n");
    free(packet);
    return NULL;
  }
  
  /* Time to live */
  if (ttl == -1) {
    myttl = (get_random_uint() % 23) + 37;
  } else {
    myttl = ttl;
  }
  
  memset((char *) packet, 0, sizeof(struct ip) + sizeof(udphdr_bsd));
  
  udp->uh_sport = htons(sport);
  udp->uh_dport = htons(dport);
  udp->uh_ulen = htons(8 + datalen);
  
  /* We should probably copy the data over too */
  if (data)
    memcpy(packet + sizeof(struct ip) + sizeof(udphdr_bsd), data, datalen);
  
  /* Now the psuedo header for checksuming */
  pseudo->source.s_addr = source->s_addr;
  pseudo->dest.s_addr = victim->s_addr;
  pseudo->proto = IPPROTO_UDP;
  pseudo->length = htons(sizeof(udphdr_bsd) + datalen);
  
  /* OK, now we should be able to compute a valid checksum */
#if STUPID_SOLARIS_CHECKSUM_BUG
  udp->uh_sum = sizeof(udphdr_bsd) + datalen;
#else
  udp->uh_sum = in_cksum((unsigned short *)pseudo, 20 /* pseudo + UDP headers */ + datalen);
#endif
  
  /* Goodbye, pseudo header! */
  memset(pseudo, 0, sizeof(*pseudo));
  
  /* Now for the ip header */
  ip->ip_v = 4;
  ip->ip_hl = 5;
  ip->ip_len = BSDFIX(sizeof(struct ip) + sizeof(udphdr_bsd) + datalen);
  ip->ip_id = htons(ipid);
  ip->ip_ttl = myttl;
  ip->ip_p = IPPROTO_UDP;
  ip->ip_src.s_addr = source->s_addr;
#ifdef WIN32
  // I'm not exactly sure why this is needed --Fyodor
  if(source->s_addr == victim->s_addr) ip->ip_src.s_addr;
#endif
  ip->ip_dst.s_addr= victim->s_addr;
#if HAVE_IP_IP_SUM
  ip->ip_sum = in_cksum((unsigned short *)ip, sizeof(struct ip));
#endif
  
  if (TCPIP_DEBUGGING > 1) {
    printf("Raw UDP packet creation completed!  Here it is:\n");
    readudppacket(packet,1);
  }
  
  *packetlen = BSDUFIX(ip->ip_len);
  return packet;
}

int send_udp_raw( int sd, struct in_addr *source, const struct in_addr *victim,
 		  int ttl, u16 sport, u16 dport, u16 ipid, char *data, 
		  u16 datalen) 
{
  unsigned int packetlen;
  int res = -1;
  u8 *packet = build_udp_raw(source, victim, ttl, sport, dport, ipid, data, 
			     datalen, &packetlen);
  if (!packet) return -1;
  res = send_ip_packet(sd, packet, packetlen);

  free(packet);
  return res;
}

/* Builds an IP packet (including an IP header) by packing the fields
   with the given information.  It allocates a new buffer to store the
   packet contents, and then returns that buffer.  The packet is not
   actually sent by this function.  Caller must delete the buffer when
   finished with the packet.  The packet length is returned in
   packetlen, which must be a valid int pointer. */
u8 *build_ip_raw(const struct in_addr *source, const struct in_addr *victim, 
		 int ttl, u8 proto, u16 ipid, char *data, u16 datalen, 
		 u32 *packetlen) 
{

unsigned char *packet = (unsigned char *) safe_malloc(sizeof(struct ip) + datalen);
struct ip *ip = (struct ip *) packet;
static int myttl = 0;

/* check that required fields are there and not too silly */
if ( !victim) {
  fprintf(stderr, "send_ip_raw: One or more of your parameters suck!\n");
  free(packet);
  return NULL;
}

/* Time to live */
if (ttl == -1) {
	        myttl = (get_random_uint() % 23) + 37;
} else {
	        myttl = ttl;
}

memset((char *) packet, 0, sizeof(struct ip));

/* Now for the ip header */

ip->ip_v = 4;
ip->ip_hl = 5;
ip->ip_len = BSDFIX(sizeof(struct ip) + datalen);
ip->ip_id = htons(ipid);
ip->ip_ttl = myttl;
ip->ip_p = proto;
ip->ip_src.s_addr = source->s_addr;
#ifdef WIN32
// TODO: Should this be removed? I'm not sure why this is here -- Fyodor
if(source->s_addr == victim->s_addr) ip->ip_src.s_addr++;
#endif
ip->ip_dst.s_addr = victim->s_addr;
#if HAVE_IP_IP_SUM
ip->ip_sum = in_cksum((unsigned short *)ip, sizeof(struct ip));
#endif

 /* We should probably copy the data over too */
 if (data)
   memcpy(packet + sizeof(struct ip), data, datalen);

if (TCPIP_DEBUGGING > 1) {
  printf("Raw IP packet creation completed!  Here it is:\n");
  hdump(packet, BSDUFIX(ip->ip_len));
}

 *packetlen = BSDUFIX(ip->ip_len);
 return packet;
}


/* You need to call sethdrinclude(sd) on the sending sd before calling this */
int send_ip_raw( int sd, struct in_addr *source, const struct in_addr *victim, 
		 int ttl, u8 proto, char *data, u16 datalen) 
{
  unsigned int packetlen;
  int res = -1;

  u8 *packet = build_ip_raw(source, victim, ttl, proto, get_random_u16(), 
			    data, datalen, &packetlen);
  if (!packet) return -1;

  res = send_ip_packet(sd, packet, packetlen);

  free(packet);
  return res;
}

int unblock_socket(int sd) {
#ifdef WIN32
u_long one = 1;
if(sd != 501) // Hack related to WinIP Raw Socket support
  ioctlsocket (sd, FIONBIO, &one);
#else
int options;
/*Unblock our socket to prevent recvfrom from blocking forever
  on certain target ports. */
options = O_NONBLOCK | fcntl(sd, F_GETFL);
fcntl(sd, F_SETFL, options);
#endif //WIN32
return 1;
}

/* Get the source address and interface name */
#if 0
char *getsourceif(struct in_addr *src, struct in_addr *dst) {
int sd, sd2;
u16 p1;
struct sockaddr_in sock;
int socklen = sizeof(struct sockaddr_in);
struct sockaddr sa;
recvfrom6_t sasize = sizeof(struct sockaddr);
int ports, res;
u8 buf[65536];
struct timeval tv;
unsigned int start;
int data_offset, ihl, *intptr;
int done = 0;

  /* Get us some unreserved port numbers */
  get_random_bytes(&p1, 2);
  if (p1 < 5000) p1 += 5000;

  if (!getuid()) {
    if ((sd2 = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL))) == -1)
      {perror("Linux Packet Socket troubles"); return 0;}
    unblock_socket(sd2);
    if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
      {perror("Socket troubles"); return 0;}
    sock.sin_family = AF_INET;
    sock.sin_addr = *dst;
    sock.sin_port = htons(p1);
    if (connect(sd, (struct sockaddr *) &sock, sizeof(struct sockaddr_in)) == -1)
      { perror("UDP connect()");
      close(sd);
      close(sd2);
      return NULL;
      }
    if (getsockname(sd, (SA *)&sock, &socklen) == -1) {
      perror("getsockname");
      close(sd);
      close(sd2);
      return NULL;
    }
    ports = (ntohs(sock.sin_port) << 16) + p1;
#if ( TCPIP_DEBUGGING )
      printf("ports is %X\n", ports);
#endif
    if (send(sd, "", 0, 0) == -1)
    fatal("Could not send UDP packet");
    start = time(NULL);
    do {
      tv.tv_sec = 2;
      tv.tv_usec = 0;
      res = recvfrom(sd2, buf, 65535, 0, &sa, &sasize);
      if (res < 0) {
	if (socket_errno() != EWOULDBLOCK)
	  perror("recvfrom");
      }
      if (res > 0) {
#if ( TCPIP_DEBUGGING )
	printf("Got packet!\n");
	printf("sa.sa_data: %s\n", sa.sa_data);
	printf("Hex dump of packet (len %d):\n", res);
	hdump(buf, res);
#endif
	data_offset = get_link_offset(sa.sa_data);
	ihl = (*(buf + data_offset) & 0xf) * 4;
	/* If it is big enough and it is IPv4 */
	if (res >=  data_offset + ihl + 4 &&
	    (*(buf + data_offset) & 0x40)) {
	  intptr = (int *)  ((char *) buf + data_offset + ihl);
	  if (*intptr == ntohl(ports)) {
	    intptr = (int *) ((char *) buf + data_offset + 12);
#if ( TCPIP_DEBUGGING )
	    printf("We've found our packet [krad]\n");
#endif
	    memcpy(src, buf + data_offset + 12, 4);
	    close(sd);
	    close(sd2);
	    return strdup(sa.sa_data);
	  }
	}
      }        
    } while(!done && time(NULL) - start < 2);
    close(sd);
    close(sd2);
  }

return NULL;
}
#endif /* 0 */

int getsourceip(struct in_addr *src, const struct in_addr * const dst) {
  int sd;
  struct sockaddr_in sock;
  recvfrom6_t socklen = sizeof(struct sockaddr_in);
  u16 p1;

  get_random_bytes(&p1, sizeof(p1));
  if (p1 < 5000) p1 += 5000;

  if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {perror("Socket troubles"); return 0;}
  sock.sin_family = AF_INET;
  sock.sin_addr = *dst;
  sock.sin_port = htons(p1);
  if (connect(sd, (struct sockaddr *) &sock, sizeof(struct sockaddr_in)) == -1)
    { perror("UDP connect()");
    close(sd);
    return 0;
    }
  memset(&sock, 0, sizeof(sock));
  if (getsockname(sd, (SA *)&sock, &socklen) == -1) {
    perror("getsockname");
    close(sd);
    return 0;
  }

  src->s_addr = sock.sin_addr.s_addr;
  close(sd);
  return 1; /* Calling function responsible for checking validity */
}

#if 0
int get_link_offset(char *device) {
int sd;
struct ifreq ifr;
sd = socket(AF_INET, SOCK_DGRAM, 0);
memset(&ifr, 0, sizeof(ifr));
strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
#if (defined(SIOCGIFHWADDR) && defined(ARPHRD_ETHER) && 
     defined(ARPHRD_METRICOM) && defined(ARPHRD_SLIP) && defined(ARPHRD_CSLIP)
     && defined(ARPHRD_SLIP6) && defined(ARPHRD_PPP) && 
     defined(ARPHRD_LOOPBACK) )
if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0 ) {
  fatal("Can't obtain link offset.  What kind of interface are you using?");
  }
close(sd);
switch (ifr.ifr_hwaddr.sa_family) {
case ARPHRD_ETHER:  /* These two are standard ethernet */
case ARPHRD_METRICOM:
  return 14;
  break;
case ARPHRD_SLIP:
case ARPHRD_CSLIP:
case ARPHRD_SLIP6:
case ARPHRD_CSLIP6:
case ARPHRD_PPP:
  return 0;
  break;
case ARPHRD_LOOPBACK:  /* Loopback interface (obviously) */
  return 14;
  break;
default:
  fatal("Unknown link layer device: %d", ifr.ifr_hwaddr.sa_family);
}
#else
printf("get_link_offset called even though your host doesn't support it.  Assuming Ethernet or Loopback connection (wild guess)\n");
return 14;
#endif
/* Not reached */
exit(1);
}
#endif

/* Read an IP packet using libpcap .  We return the packet and take
   a pcap descripter and a pointer to the packet length (which we set
   in the function. If you want a maximum length returned, you
   should specify that in pcap_open_live() */

/* to_usec is the timeout period in microseconds -- use 0 to skip the
   test and -1 to block forever.  Note that we don't interrupt pcap, so
   low values (and 0) degenerate to the timeout specified 
   in pcap_open_live()
 */

/* If rcvdtime is non-null and a packet is returned, rcvd will be
   filled with the time that packet was captured from the wire by
   pcap.  If linknfo is not NULL, linknfo->headerlen and
   linknfo->header will be filled with the appropriate values. */
char *readip_pcap(pcap_t *pd, unsigned int *len, long to_usec, 
		  struct timeval *rcvdtime, struct link_header *linknfo) {
unsigned int offset = 0;
struct pcap_pkthdr head;
char *p;
int datalink;
int timedout = 0;
struct timeval tv_start, tv_end;
static char *alignedbuf = NULL;
static unsigned int alignedbufsz=0;
static int warning = 0;
if (linknfo) { memset(linknfo, 0, sizeof(*linknfo)); }

#ifdef WIN32
long to_left;

// We use WinXP raw packet support when available
 if (-2 == (long) pd) return rawrecv_readip(pd, len, to_usec, rcvdtime);
#endif

if (!pd) fatal("NULL packet device passed to readip_pcap");

 if (to_usec < 0) {
   if (!warning) {
     warning = 1;
     error("WARNING: Negative timeout value (%lu) passed to readip_pcap() -- using 0", to_usec);
   }
   to_usec = 0;
 }

/* New packet capture device, need to recompute offset */
 if ( (datalink = pcap_datalink(pd)) < 0)
   fatal("Cannot obtain datalink information: %s", pcap_geterr(pd));

 /* NOTE: IF A NEW OFFSET EVER EXCEEDS THE CURRENT MAX (24), ADJUST
    MAX_LINK_HEADERSZ in tcpip.h */
 switch(datalink) {
 case DLT_EN10MB: offset = 14; break;
 case DLT_IEEE802: offset = 22; break;
#ifdef __amigaos__
 case DLT_MIAMI: offset = 16; break;
#endif
#ifdef DLT_LOOP
 case DLT_LOOP:
#endif
 case DLT_NULL: offset = 4; break;
 case DLT_SLIP:
#ifdef DLT_SLIP_BSDOS
 case DLT_SLIP_BSDOS:
#endif
#if (FREEBSD || OPENBSD || NETBSD || BSDI || MACOSX)
   offset = 16;
#else
   offset = 24; /* Anyone use this??? */
#endif
   break;
 case DLT_PPP: 
#ifdef DLT_PPP_BSDOS
 case DLT_PPP_BSDOS:
#endif
#ifdef DLT_PPP_SERIAL
 case DLT_PPP_SERIAL:
#endif
#ifdef DLT_PPP_ETHER
 case DLT_PPP_ETHER:
#endif
#if (FREEBSD || OPENBSD || NETBSD || BSDI || MACOSX)
   offset = 4;
#else
#ifdef SOLARIS
   offset = 8;
#else
   offset = 24; /* Anyone use this? */
#endif /* ifdef solaris */
#endif /* if freebsd || openbsd || netbsd || bsdi */
   break;
 case DLT_RAW: offset = 0; break;
 case DLT_FDDI: offset = 21; break;
#ifdef DLT_ENC
 case DLT_ENC: offset = 12; break;
#endif /* DLT_ENC */
#ifdef DLT_LINUX_SLL
 case DLT_LINUX_SLL: offset = 16; break;
#endif
 default:
   p = (char *) pcap_next(pd, &head);
   if (head.caplen == 0) {
     /* Lets sleep a brief time and try again to increase the chance of seeing
	a real packet ... */
     usleep(500000);
     p = (char *) pcap_next(pd, &head);
   }
   if (head.caplen > 100000) {
     fatal("FATAL: readip_pcap: bogus caplen from libpcap (%d) on interface type %d", head.caplen, datalink);
   } 
   error("FATAL:  Unknown datalink type (%d). Caplen: %d; Packet:\n", datalink, head.caplen);
   lamont_hdump(p, head.caplen);
   exit(1);
 }

 if (to_usec > 0) {
   gettimeofday(&tv_start, NULL);
 }
 do {
#ifdef WIN32
   gettimeofday(&tv_end, NULL);
   to_left = MAX(1, (to_usec - TIMEVAL_SUBTRACT(tv_end, tv_start)) / 1000);
   // Set the timeout (BUGBUG: this is cheating)
   PacketSetReadTimeout(pd->adapter, to_left);
#endif

   p = (char *) pcap_next(pd, &head);

   if (p) {
     if (head.caplen <= offset) {
       *len = 0;
       return NULL;
     }
     if (offset && linknfo) {
       linknfo->datalinktype = datalink;
       linknfo->headerlen = offset;
       assert(offset < MAX_LINK_HEADERSZ);
       memcpy(linknfo->header, p, MIN(sizeof(linknfo->header), offset));
     }
     p += offset;
   }
   if (!p || (*p & 0x40) != 0x40) {
     /* Should we timeout? */
     if (to_usec == 0) {
       timedout = 1;
     } else if (to_usec > 0) {
       gettimeofday(&tv_end, NULL);
       if (TIMEVAL_SUBTRACT(tv_end, tv_start) >= to_usec) {
	 timedout = 1;     
       }
     }
   }
 } while(!timedout && (!p || (*p & 0x40) != 0x40)); /* Go until we get IPv4 packet */
 
if (timedout) {
   *len = 0;
   return NULL;
 }
 *len = head.caplen - offset;
 if (*len > alignedbufsz) {
   alignedbuf = (char *) realloc(alignedbuf, *len);
   if (!alignedbuf) {
     fatal("Unable to realloc %d bytes of mem", *len);
   }
   alignedbufsz = *len;
 }
 memcpy(alignedbuf, p, *len);

 // printf("Just got a packet at %li,%li\n", head.ts.tv_sec, head.ts.tv_usec);
 if (rcvdtime) {
   // FIXME: I eventually need to figure out why Windows head.ts time is sometimes BEFORE the time I
   // sent the packet (which is according to gettimeofday() in nbase).  For now, I will sadly have to
   // use gettimeofday() for Windows in this case
   // Actually I now allow .05 discrepancy.   So maybe this isn't needed.  I'll comment out for now.
   // Nope: it is still needed at least for Windows.  Sometimes the time from he pcap header is a 
   // COUPLE SECONDS before the gettimeofday() results :(.
#if defined(WIN32) || defined(__amigaos__)
   gettimeofday(&tv_end, NULL);
   *rcvdtime = tv_end;
#else
   *rcvdtime = head.ts;
   assert(head.ts.tv_sec);
#endif
 }

 if (rcvdtime)
   PacketTrace::trace(PacketTrace::RCVD, (u8 *) alignedbuf, *len, rcvdtime);
 else PacketTrace::trace(PacketTrace::RCVD, (u8 *) alignedbuf, *len);

 return alignedbuf;
}
 
// Returns whether the packet receive time value obtaned from libpcap
// (and thus by readip_pcap()) should be considered valid.  When
// invalid (Windows and Amiga), readip_pcap returns the time you called it.
bool pcap_recv_timeval_valid() {
#if defined(WIN32) || defined(__amigaos__)
  return false;
#else
  return true;
#endif
}


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
			      struct ip *ip, int overwrite) {
  struct sockaddr_storage ss;
  size_t sslen;

  if (!linkhdr || !target || !ip)
    return 1;

  if (linkhdr->datalinktype != DLT_EN10MB || linkhdr->headerlen != 14)
    return 2;

  if (!overwrite && target->MACAddress())
    return 3;

  if (ip->ip_src.s_addr != target->v4host().s_addr)
    return 4;

  /* Sometimes bogus MAC address still gets through, like during some localhost scans */
  if (memcmp(linkhdr->header+6, "\0\0\0\0\0\0", 6) == 0)
    return 5;

  target->TargetSockAddr(&ss, &sslen);
  if (IPisDirectlyConnected(&ss, sslen) == 1) {
    /* Yay!  This MAC address seems valid */
    target->setMACAddress(linkhdr->header + 6);
    return 0;
  }

  return 5;
}
 

#ifndef WIN32 /* Windows version of next few functions is currently 
                 in wintcpip.c.  Should be merged at some point. */
/* Set a pcap filter */
void set_pcap_filter(Target *target,
		     pcap_t *pd, PFILTERFN filter, char *bpf, ...)
{
  va_list ap;
  char buf[3072];
  struct bpf_program fcode;
#ifndef __amigaos__
  unsigned int localnet, netmask;
#else
  bpf_u_int32 localnet, netmask;
#endif
  char err0r[256];
  
  if (pcap_lookupnet(target->device, &localnet, &netmask, err0r) < 0)
    fatal("Failed to lookup device subnet/netmask: %s", err0r);
  
  va_start(ap, bpf);
  if (vsnprintf(buf, sizeof(buf), bpf, ap) >= (int) sizeof(buf))
    fatal("set_pcap_filter called with too-large filter arg\n");
  va_end(ap);

  /* Due to apparent bug in libpcap */
  if (islocalhost(target->v4hostip()))
    buf[0] = '\0';

  if (o.debugging)
    log_write(LOG_STDOUT, "Packet capture filter (device %s): %s\n", target->device, buf);
  
  if (pcap_compile(pd, &fcode, buf, 0, netmask) < 0)
    fatal("Error compiling our pcap filter: %s\n", pcap_geterr(pd));
  if (pcap_setfilter(pd, &fcode) < 0 )
    fatal("Failed to set the pcap filter: %s\n", pcap_geterr(pd));
}

#endif /* WIN32 */

/* This is ugly :(.  We need to get rid of these at some point */
unsigned long flt_dsthost, flt_srchost;	/* _net_ order */
unsigned short flt_baseport;	/*	_host_ order */

/* Just accept everything ... TODO: Need a better approach than this flt_ 
   stuff */
int flt_all(const char *packet, unsigned int len) {
  return 1;
}

int flt_icmptcp(const char *packet, unsigned int len)
{
  struct ip* ip = (struct ip*)packet;
  if(ip->ip_dst.s_addr != flt_dsthost) return 0;
  if(ip->ip_p == IPPROTO_ICMP) return 1;
  if(ip->ip_src.s_addr != flt_srchost) return 0;
  if(ip->ip_p == IPPROTO_TCP) return 1;
  return 0;
}

int flt_icmptcp_2port(const char *packet, unsigned int len)
{
  unsigned short dport;
  struct ip* ip = (struct ip*)packet;
  if(ip->ip_dst.s_addr != flt_dsthost) return 0;
  if(ip->ip_p == IPPROTO_ICMP) return 1;
  if(ip->ip_src.s_addr != flt_srchost) return 0;
  if(ip->ip_p == IPPROTO_TCP)
    {
      struct tcphdr* tcp = (struct tcphdr *) (((char *) ip) + 4 * ip->ip_hl);
      if(len < (unsigned) 4 * ip->ip_hl + 4) return 0;
	  dport = ntohs(tcp->th_dport);
      if(dport == flt_baseport || dport == flt_baseport + 1)
	return 1;
    }
  
  return 0;
}

int flt_icmptcp_5port(const char *packet, unsigned int len)
{
  unsigned short dport;
  struct ip* ip = (struct ip*)packet;
  if(ip->ip_dst.s_addr != flt_dsthost) return 0;
  if(ip->ip_p == IPPROTO_ICMP) return 1;
  if(ip->ip_p == IPPROTO_TCP)
    {
      struct tcphdr* tcp = (struct tcphdr *) (((char *) ip) + 4 * ip->ip_hl);
      if(len < (unsigned) 4 * ip->ip_hl + 4) return 0;
      dport = ntohs(tcp->th_dport);
      if(dport >= flt_baseport && dport <= flt_baseport + 4) return 1;
    }
  
  return 0;
}


#ifndef WIN32 /* Currently the Windows code for next few functions is 
                 in wintcpip.c -- should probably be merged at some
				 point */
int ipaddr2devname( char *dev, const struct in_addr *addr ) {
struct interface_info *mydevs;
int numdevs;
int i;
mydevs = getinterfaces(&numdevs);

if (!mydevs) return -1;

for(i=0; i < numdevs; i++) {
  if (addr->s_addr == mydevs[i].addr.s_addr) {
    strcpy(dev, mydevs[i].name);
    return 0;
  }
}
return -1;
}

int devname2ipaddr(char *dev, struct in_addr *addr) {
struct interface_info *mydevs;
int numdevs;
int i;
mydevs = getinterfaces(&numdevs);

if (!mydevs) return -1;

for(i=0; i < numdevs; i++) {
  if (!strcmp(dev, mydevs[i].name)) {  
    memcpy(addr, (char *) &mydevs[i].addr, sizeof(struct in_addr));
    return 0;
  }
}
return -1;
}
#endif /* WIN32 */

#ifndef WIN32 /* ifdef'd out for now because 'doze apparently doesn't
		         support ioctl() */
struct interface_info *getinterfaces(int *howmany) {
  static int initialized = 0;
  static struct interface_info *mydevs;
  static int numinterfaces = 0;
  int ii_capacity = 0;
  int sd, len, rc;
  char *p;
  char buf[10240];
  struct ifconf ifc;
  struct ifreq *ifr;
  struct ifreq tmpifr;
  struct sockaddr_in *sin;

  if (!initialized) {
    initialized = 1;

    ii_capacity = 32;
    mydevs = (struct interface_info *) safe_malloc(sizeof(struct interface_info) * ii_capacity);

    /* Dummy socket for ioctl */
    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0) pfatal("socket in getinterfaces");
    memset(buf, 0, sizeof(buf));
    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sd, SIOCGIFCONF, &ifc) < 0) {
      fatal("Failed to determine your configured interfaces!\n");
    }
    ifr = (struct ifreq *) buf;
    if (ifc.ifc_len == 0) 
      fatal("getinterfaces: SIOCGIFCONF claims you have no network interfaces!\n");
#if HAVE_SOCKADDR_SA_LEN
    /*    len = MAX(sizeof(struct sockaddr), ifr->ifr_addr.sa_len);*/
    len = ifr->ifr_addr.sa_len + sizeof(ifr->ifr_name);
#else
    len = sizeof(struct ifreq);
    /* len = sizeof(SA); */
#endif

#if TCPIP_DEBUGGING
    printf("ifnet list length = %d\n",ifc.ifc_len);
    printf("sa_len = %d\n",len);
    hdump((unsigned char *) buf, ifc.ifc_len);
    printf("ifr = %X\n",(unsigned)(*(char **)&ifr));
    printf("Size of struct ifreq: %d\n", sizeof(struct ifreq));
#endif

    for(; ifr && *((char *)ifr) && ((char *)ifr) < buf + ifc.ifc_len; 
	((*(char **)&ifr) += len )) {
#if TCPIP_DEBUGGING
      printf("ifr_name size = %d\n", sizeof(ifr->ifr_name));
      printf("ifr = %X\n",(unsigned)(*(char **)&ifr));
#endif

      /* skip any device with no name */
      if (!*((char *)ifr))
        continue;

      sin = (struct sockaddr_in *) &ifr->ifr_addr;
      memcpy(&(mydevs[numinterfaces].addr), (char *) &(sin->sin_addr), sizeof(struct in_addr));

      Strncpy(tmpifr.ifr_name, ifr->ifr_name, IFNAMSIZ);
      memcpy(&(tmpifr.ifr_addr), &(sin->sin_addr), sizeof(tmpifr.ifr_addr));
      rc = ioctl(sd, SIOCGIFNETMASK, &tmpifr);
      if (rc < 0 && errno != EADDRNOTAVAIL)
	pfatal("Failed to determine the netmask of %s!", ifr->ifr_name);
      else if (rc < 0)
	mydevs[numinterfaces].netmask.s_addr = (unsigned) -1;
      else {
	sin = (struct sockaddr_in *) &(tmpifr.ifr_addr); /* ifr_netmask only on Linux */
	memcpy(&(mydevs[numinterfaces].netmask), (char *) &(sin->sin_addr), sizeof(struct in_addr));
      }
      /* In case it is a stinkin' alias */
      if ((p = strchr(ifr->ifr_name, ':')))
	*p = '\0';
      Strncpy(mydevs[numinterfaces].name, ifr->ifr_name, IFNAMSIZ);

      //  printf("ifr name=%s addr=%s, mask=%X\n", mydevs[numinterfaces].name, inet_ntoa(mydevs[numinterfaces].addr), mydevs[numinterfaces].netmask.s_addr); 
#if TCPIP_DEBUGGING
      printf("Interface %d is %s\n",numinterfaces,mydevs[numinterfaces].name);
#endif

      numinterfaces++;
      if (numinterfaces == ii_capacity)  {      
	ii_capacity <<= 2;
	mydevs = (struct interface_info *) realloc(mydevs, sizeof(struct interface_info) * ii_capacity);
	assert(mydevs);
      }
#if HAVE_SOCKADDR_SA_LEN
      /* len = MAX(sizeof(struct sockaddr), ifr->ifr_addr.sa_len);*/
      len = ifr->ifr_addr.sa_len + sizeof(ifr->ifr_name);
#endif 
      mydevs[numinterfaces].name[0] = '\0';
    }
    close(sd);
  }
  if (howmany) *howmany = numinterfaces;
  return mydevs;
}
#endif

/* Check whether an IP address appears to be directly connected to an
   interface on the computer (e.g. on the same ethernet network rather
   than having to route).  Returns 1 if yes, -1 if maybe, 0 if not.
   The Windows version tries to give an accurate answer, which I'm
   not sure is the right thing to do in rawsock mode... */
int IPisDirectlyConnected(struct sockaddr_storage *ss, size_t ss_len) {
#if WIN32
  struct sockaddr_in *sin = (struct sockaddr_in *) ss;
  MIB_IPFORWARDROW route;
  if(get_best_route(sin->sin_addr.s_addr, &route) < 0)
         return -1;
  return route.dwForwardType == 3 ? 1 : 0;
#else
  struct interface_info *interfaces;
  int numinterfaces;
  int i;
  struct sockaddr_in *sin = (struct sockaddr_in *) ss;

  if (sin->sin_family != AF_INET)
    fatal("IPisDirectlyConnected passed a non IPv4 address");

  interfaces =  getinterfaces(&numinterfaces);

  for(i=0; i < numinterfaces; i++) {
    if ((interfaces[i].addr.s_addr & interfaces[i].netmask.s_addr) == (sin->sin_addr.s_addr & interfaces[i].netmask.s_addr))
      return 1;
  }
  return 0;
#endif /* !WIN32 */
}


/* An awesome function to determine what interface a packet to a given
   destination should be routed through.  It returns NULL if no appropriate
   interface is found, oterwise it returns the device name and fills in the
   source parameter.   Some of the stuff is
   from Stevens' Unix Network Programming V2.  He had an easier suggestion
   for doing this (in the book), but it isn't portable :( */
#ifndef WIN32 /* Windows functionality is currently in wintcpip.c --
                 should probably be merged at some point */

char *routethrough(const struct in_addr * const dest, struct in_addr *source) {
  static int initialized = 0;
  int i;
  struct in_addr addy;
  static enum { procroutetechnique, connectsockettechnique, guesstechnique } technique = procroutetechnique;
  char buf[10240];
  struct interface_info *mydevs;
  static struct myroute {
    struct interface_info *dev;
    u32 mask;
    u32 dest;
  } *myroutes;
  int myroutes_capacity = 0;
  int numinterfaces = 0;
  char *p, *endptr;
  char iface[64];
  static int numroutes = 0;
  FILE *routez;

  if (!dest) fatal("routethrough passed a NULL dest address");

  if (!initialized) {  
    /* Dummy socket for ioctl */
    initialized = 1;
    mydevs = getinterfaces(&numinterfaces);
    myroutes_capacity = 64;
    myroutes = (struct myroute *) safe_malloc((sizeof(struct myroute) * myroutes_capacity));
    /* Now we must go through several techniques to determine info */
    routez = fopen("/proc/net/route", "r");

    if (routez) {
      /* OK, linux style /proc/net/route ... we can handle this ... */
      /* Now that we've got the interfaces, we g0 after the r0ut3Z */
      
      fgets(buf, sizeof(buf), routez); /* Kill the first line */
      while(fgets(buf,sizeof(buf), routez)) {
	p = strtok(buf, " \t\n");
	if (!p) {
	  error("Could not find interface in /proc/net/route line");
	  continue;
	}
	if (*p == '*')
	  continue; /* Deleted route -- any other valid reason for
		       a route to start with an asterict? */
	Strncpy(iface, p, sizeof(iface));
	if ((p = strchr(iface, ':'))) {
	  *p = '\0'; /* To support IP aliasing */
	}
	p = strtok(NULL, " \t\n");
	endptr = NULL;
	myroutes[numroutes].dest = strtoul(p, &endptr, 16);
	if (!endptr || *endptr) {
	  error("Failed to determine Destination from /proc/net/route");
	  continue;
	}
	for(i=0; i < 6; i++) {
	  p = strtok(NULL, " \t\n");
	  if (!p) break;
	}
	if (!p) {
	  error("Failed to find field %d in /proc/net/route", i + 2);
	  continue;
	}
	endptr = NULL;
	myroutes[numroutes].mask = strtoul(p, &endptr, 16);
	if (!endptr || *endptr) {
	  error("Failed to determine mask from /proc/net/route");
	  continue;
	}


#if TCPIP_DEBUGGING
	  printf("#%d: for dev %s, The dest is %X and the mask is %X\n", numroutes, iface, myroutes[numroutes].dest, myroutes[numroutes].mask);
#endif
	  for(i=0; i < numinterfaces; i++)
	    if (!strcmp(iface, mydevs[i].name)) {
	      myroutes[numroutes].dev = &mydevs[i];
	      break;
	    }
	  if (i == numinterfaces) 
	    fatal("Failed to find interface %s mentioned in /proc/net/route\n", iface);
	  numroutes++;
	  if (numroutes == myroutes_capacity) {
	    // Gotta grow it
	    myroutes_capacity <<= 3;
	    myroutes = (struct myroute *) realloc(myroutes, myroutes_capacity * (sizeof(struct myroute)));
	    assert(myroutes);
	  }
      }
      fclose(routez);
    } else {
      technique = connectsockettechnique;
    }
  } else {  
    mydevs = getinterfaces(&numinterfaces);
  }
  /* WHEW, that takes care of initializing, now we have the easy job of 
     finding which route matches */
  if (islocalhost(dest)) {

    /* I used to set the source to 127.0.0.1 in this case, but that
       seems to cause problems on Linux, where the dang system will
       reply from another addy:
         0.160995    127.0.0.1 -> 192.168.0.42 TCP 63331 > 1 [SYN] Seq=1321326640 Ack=0 Win=1024 Len=0
         0.161027 192.168.0.42 -> 192.168.0.42 TCP 1 > 63331 [RST, ACK] Seq=0 Ack=1321326641 Win=0 Len=0
         So I'll try just using the localhost device, but keeping the
         more proper source 
    //    if (source)
    //      source->s_addr = htonl(0x7F000001);
    */
    /* Now we find the localhost interface name, assuming 127.0.0.1 is
       localhost (it damn well better be!)... */
    for(i=0; i < numinterfaces; i++) {    
      if (mydevs[i].addr.s_addr == htonl(0x7F000001)) {
	return mydevs[i].name;
      }
    }
    return NULL;
  }

  if (technique == procroutetechnique) {    
    for(i=0; i < numroutes; i++) {  
      if ((dest->s_addr & myroutes[i].mask) == myroutes[i].dest) {
	if (source) {
	  source->s_addr = myroutes[i].dev->addr.s_addr;
	}
	return myroutes[i].dev->name;      
      }
    }
  } else if (technique == connectsockettechnique) {
      if (!getsourceip(&addy, dest))
	return NULL;
      if (!addy.s_addr)  {  /* Solaris 2.4 */
        struct hostent *myhostent = NULL;
        char myname[MAXHOSTNAMELEN + 1];
        if (gethostname(myname, MAXHOSTNAMELEN) || 
           !(myhostent = gethostbyname(myname)))
	  fatal("Cannot get hostname!  Try using -S <my_IP_address> or -e <interface to scan through>\n");
        memcpy(&(addy.s_addr), myhostent->h_addr_list[0], sizeof(struct in_addr));
#if ( TCPIP_DEBUGGING )
      printf("We skillfully deduced that your address is %s\n", 
        inet_ntoa(*source));
#endif
      }

      /* Now we insure this claimed address is a real interface ... */
      for(i=0; i < numinterfaces; i++)
	if (mydevs[i].addr.s_addr == addy.s_addr) {
	  if (source) {
	    source->s_addr = addy.s_addr;	  
	  }
	  return mydevs[i].name;
	}  
      return NULL;
    } else 
      fatal("I know sendmail technique ... I know rdist technique ... but I don't know what the hell kindof technique you are attempting!!!");
    return NULL;
}
#endif /* WIN32 */

/* Maximize the receive buffer of a socket descriptor (up to 500K) */
void max_rcvbuf(int sd) {
  int optval = 524288 /*2^19*/;
  recvfrom6_t optlen = sizeof(int);

#ifndef WIN32
  if (setsockopt(sd, SOL_SOCKET, SO_RCVBUF, (const char *) &optval, optlen))
    if (o.debugging) perror("Problem setting large socket receive buffer");
  if (o.debugging) {
    getsockopt(sd, SOL_SOCKET, SO_RCVBUF,(char *) &optval, &optlen);
    log_write(LOG_STDOUT, "Our buffer size is now %d\n", optval);
  }
#endif /* WIN32 */
}

/* Maximize the open file descriptor limit for this process go up to the
   max allowed  */
int max_sd() {
#ifndef WIN32
  struct rlimit r;
  static int maxfds = -1;

  if (maxfds > 0)
    return maxfds;

#if(defined(RLIMIT_NOFILE))
  if (!getrlimit(RLIMIT_NOFILE, &r)) {
    r.rlim_cur = r.rlim_max;
    if (setrlimit(RLIMIT_NOFILE, &r))
      if (o.debugging) perror("setrlimit RLIMIT_NOFILE failed");
    if (!getrlimit(RLIMIT_NOFILE, &r)) {
      maxfds = r.rlim_cur;
      return maxfds;
    } else return 0;
  }
#endif
#if(defined(RLIMIT_OFILE) && !defined(RLIMIT_NOFILE))
  if (!getrlimit(RLIMIT_OFILE, &r)) {
    r.rlim_cur = r.rlim_max;
    if (setrlimit(RLIMIT_OFILE, &r))
      if (o.debugging) perror("setrlimit RLIMIT_OFILE failed");
    if (!getrlimit(RLIMIT_OFILE, &r)) {
      maxfds = r.rlim_cur;
      return maxfds;
    }
    else return 0;
  }
#endif
#endif /* WIN32 */
  return 0;
}

/* Convert a socket to blocking mode */
int block_socket(int sd) {
#ifdef WIN32
  unsigned long options=0;
  if(sd == 501) return 1;
  ioctlsocket(sd, FIONBIO, (unsigned long *)&options);
#else
  int options;
  options = (~O_NONBLOCK) & fcntl(sd, F_GETFL);
  fcntl(sd, F_SETFL, options);
#endif

  return 1;
}

/* Give broadcast permission to a socket */
void broadcast_socket(int sd) {
  int one = 1;
#ifdef WIN32
  if(sd == 501) return;
#endif
  if (setsockopt(sd, SOL_SOCKET, SO_BROADCAST, (const char *)&one, sizeof(int)) != 0) {
    fprintf(stderr, "Failed to secure socket broadcasting permission\n");
    perror("setsockopt");
  }
}

/* Do a receive (recv()) on a socket and stick the results (upt to
   len) into buf .  Give up after 'seconds'.  Returns the number of
   bytes read (or -1 in the case of an error.  It only does one recv
   (it will not keep going until len bytes are read).  If timedout is
   not NULL, it will be set to zero (no timeout occured) or 1 (it
   did). */
int recvtime(int sd, char *buf, int len, int seconds, int *timedout) {

  int res;
  struct timeval timeout;
  fd_set readfd;

  timeout.tv_sec = seconds;
  timeout.tv_usec = 0;
  FD_ZERO(&readfd);
  FD_SET(sd, &readfd);
  if (timedout) *timedout = 0;
  res = select(sd + 1, &readfd, NULL, NULL, &timeout);
  if (res > 0 ) {
    res = recv(sd, buf, len, 0);
    if (res >= 0) return res;
    perror("recv in recvtime");
    return 0; 
  }
  else if (!res) {
    if (timedout) *timedout = 1;
    return 0;
  }
  perror("select() in recvtime");
  return -1;
}

/* This attempts to calculate the round trip time (rtt) to a host by timing a
   connect() to a port which isn't listening.  A better approach is to time a
   ping (since it is more likely to get through firewalls (note, this isn't
   always true nowadays --fyodor).  This is now 
   implemented in isup() for users who are root.  */
unsigned long calculate_sleep(struct in_addr target) {
  struct timeval begin, end;
  int sd;
  struct sockaddr_in sock;
  int res;

  if ((sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
    {perror("Socket troubles"); exit(1);}

  sock.sin_family = AF_INET;
  sock.sin_addr.s_addr = target.s_addr;
  sock.sin_port = htons(o.magic_port);

  gettimeofday(&begin, NULL);
  if ((res = connect(sd, (struct sockaddr *) &sock, 
		     sizeof(struct sockaddr_in))) != -1)
    fprintf(stderr, "WARNING: You might want to use a different value of -g (or change o.magic_port in the include file), as it seems to be listening on the target host!\n");
  close(sd);
  gettimeofday(&end, NULL);
  if (end.tv_sec - begin.tv_sec > 5 ) /*uh-oh!*/
    return 0;
  return (end.tv_sec - begin.tv_sec) * 1000000 + (end.tv_usec - begin.tv_usec);
}


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
int gettcpopt_ts(struct tcphdr *tcp, u32 *timestamp, u32 *echots) {

  unsigned char *p;
  int len = 0;
  int op;
  int oplen;

  /* first we find where the tcp options start ... */
  p = ((unsigned char *)tcp) + 20;
  len = 4 * tcp->th_off - 20;
  while(len > 0 && *p != 0 /* TCPOPT_EOL */) {
    op = *p++;
    if (op == 0 /* TCPOPT_EOL */) break;
    if (op == 1 /* TCPOPT_NOP */) { len--; continue; }
    oplen = *p++;
    if (oplen < 2) break; /* No infinite loops, please */
    if (oplen > len) break; /* Not enough space */
    if (op == 8 /* TCPOPT_TIMESTAMP */ && oplen == 10) {
      /* Legitimate ts option */
      if (timestamp) { 
	memcpy((char *) timestamp, p, 4); 
	*timestamp = ntohl(*timestamp); 
      }
      p += 4;
      if (echots) { 
	memcpy((char *) echots, p, 4);
	*echots = ntohl(*echots);
      }
      return 1;
    }
    len -= oplen;
    p += oplen - 2;
  }

  /* Didn't find anything */
if (timestamp) *timestamp = 0;
if (echots) *echots = 0;
return 0;
}

#ifndef WIN32 // An alternative version of this function is defined in 
              // mswin32/winip/winip.c
int Sendto(char *functionname, int sd, const unsigned char *packet, int len, 
	   unsigned int flags, struct sockaddr *to, int tolen) {

struct sockaddr_in *sin = (struct sockaddr_in *) to;
int res;
int retries = 0;
int sleeptime = 0;

do {
  if (TCPIP_DEBUGGING > 1) {  
    log_write(LOG_STDOUT, "trying sendto(%d, packet, %d, 0, %s, %d)",
	   sd, len, inet_ntoa(sin->sin_addr), tolen);
  }
  if ((res = sendto(sd, (const char *) packet, len, flags, to, tolen)) == -1) {
    int err = socket_errno();

    error("sendto in %s: sendto(%d, packet, %d, 0, %s, %d) => %s",
	  functionname, sd, len, inet_ntoa(sin->sin_addr), tolen,
	  strerror(err));
    if (retries > 2 || err == EPERM || err == EACCES || err == EADDRNOTAVAIL)
      return -1;
    sleeptime = 15 * (1 << (2 * retries));
    error("Sleeping %d seconds then retrying", sleeptime);
    fflush(stderr);
    sleep(sleeptime);
  }
  retries++;
} while( res == -1);

 PacketTrace::trace(PacketTrace::SENT, packet, len); 

if (TCPIP_DEBUGGING > 1)
  log_write(LOG_STDOUT, "successfully sent %d bytes of raw_tcp!\n", res);

return res;
}
#endif

IPProbe::IPProbe() {
  packetbuflen = 0;
  packetbuf = NULL;
  Reset();
}

void IPProbe::Reset() {
  if (packetbuf)
    free(packetbuf);
  packetbuflen = 0;
  packetbuf = NULL;
  ipv4 = NULL;
  icmp = NULL;
  tcp = NULL;
  udp = NULL;
}

IPProbe::~IPProbe() {
  if (packetbuf) {
    free(packetbuf);
    packetbuf = NULL;
    packetbuflen = 0;
  }
  Reset();
}

int IPProbe::storePacket(u8 *ippacket, u32 len) {
  assert(packetbuf == NULL);
  af = AF_INET;
  packetbuf = (u8 *) safe_malloc(len);
  memcpy(packetbuf, ippacket, len);
  packetbuflen = len;
  ipv4 = (struct ip *) packetbuf;
  assert(ipv4->ip_v == 4);
  assert(len >= 20);
  assert(len == (u32) BSDUFIX(ipv4->ip_len));
  if (ipv4->ip_p == IPPROTO_TCP) {
    if (len >= (unsigned) ipv4->ip_hl * 4 + 20)
      tcp = (struct tcphdr *) ((u8 *) ipv4 + ipv4->ip_hl * 4);
  } else if (ipv4->ip_p == IPPROTO_ICMP) {
    if (len >= (unsigned) ipv4->ip_hl * 4 + 8)
      icmp = (struct icmp *) ((u8 *) ipv4 + ipv4->ip_hl * 4);
  } else if (ipv4->ip_p == IPPROTO_UDP) {
    if (len >= (unsigned) ipv4->ip_hl * 4 + 8)
      udp = (udphdr_bsd *) ((u8 *) ipv4 + ipv4->ip_hl * 4);
  }
  return 0;
}

