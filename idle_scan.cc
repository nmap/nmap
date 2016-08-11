
/***************************************************************************
 * idle_scan.cc -- Includes the function specific to "Idle Scan" support   *
 * (-sI).  This is an extraordinarily cool scan type that can allow for    *
 * completely blind scanning (eg no packets sent to the target from your   *
 * own IP address) and can also be used to penetrate firewalls and scope   *
 * out router ACLs.  This is one of the "advanced" scans meant for         *
 * experienced Nmap users.                                                 *
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

/* IPv6 fragment ID sequence algorithms. http://seclists.org/nmap-dev/2013/q3/369.
        Android 4.1 (Linux 3.0.15) | Per host, incremental (1)
        FreeBSD 7.4 | Random
        FreeBSD 9.1 | Random
        iOS 6.1.2 | Random
        Linux 2.6.32 | Per host, incremental (2)
        Linux 3.2 | Per host, incremental (1)
        Linux 3.8 | Per host, incremental
        OpenBSD 4.6 | Random
        OpenBSD 5.2 | Random
        OS X 10.6.7 | Global, incremental (3)
        OS X 10.8.3 | Random
        Solaris 11 | Per host, incremental
        Windows Server 2003 R2 Standard 64bit, SP2 | Global, incremental
        Windows Server 2008 Standard 32bit,  SP1 | Global, incremental
        Windows Server 2008 R2 Standard 64bit, SP1 | Global, incremental by 2
        Windows Server 2012 Standard 64bit | Global, incremental by 2
        Windows XP Professional 32bit, SP3 | Global, incremental (4)
        Windows Vista Business 64bit, SP1 | Global, incremental
        Windows 7 Home Premium 32bit, SP1 | Global, incremental by 2
        Windows 7 Ultimate 32bit, SP1 | Global, incremental by 2
        Windows 8 Enterprise 32 bit | Global, incremental by 2
*/

#include "libnetutil/npacket.h"

#include "idle_scan.h"
#include "timing.h"
#include "osscan2.h"
#include "nmap.h"
#include "NmapOps.h"
#include "services.h"
#include "Target.h"
#include "nmap_error.h"
#include "output.h"

#include "struct_ip.h"

#include <stdio.h>

extern NmapOps o;
#ifdef WIN32
/* from libdnet's intf-win32.c */
extern "C" int g_has_npcap_loopback;
#endif

struct idle_proxy_info {
  Target host; /* contains name, IP, source IP, timing info, etc. */
  int seqclass; /* IP ID sequence class (IPID_SEQ_* defined in nmap.h) */
  u32 latestid; /* The most recent IP ID we have received from the proxy */
  u16 probe_port; /* The port we use for probing IP ID infoz */
  u16 max_groupsz; /* We won't test groups larger than this ... */
  u16 min_groupsz; /* We won't allow the group size to fall below this
                      level.  Affected by --min-parallelism */
  double current_groupsz; /* Current group size being used ... depends on
                          conditions ... won't be higher than
                          max_groupsz */
  int senddelay; /* Delay between sending pr0be SYN packets to target
                    (in microseconds) */
  int max_senddelay; /* Maximum time we are allowed to wait between
                        sending probes (when we send a bunch in a row.
                        In microseconds. */

  pcap_t *pd; /* A Pcap descriptor which (starting in
                 initialize_idleproxy) listens for TCP packets from
                 the probe_port of the proxy box */
  int rawsd; /* Socket descriptor for sending probe packets to the proxy */
  struct eth_nfo eth; // For when we want to send probes via raw IP instead.
  struct eth_nfo *ethptr; // points to eth if filled out, otherwise NULL
};

/* Finds the IPv6 extension header for fragmentation in an IPv6 packet, and returns
 * the identification value of the fragmentation header
*/
int ipv6_get_fragment_id(const struct ip6_hdr *ip6, unsigned int len) {
  const unsigned char *p, *end;
  u8 hdr;
  struct ip6_ext_data_fragment *frag_header = NULL;

  if (len < sizeof(*ip6))
    return -1;

  p = (unsigned char *) ip6;
  end = p + len;

  hdr = ip6->ip6_nxt;
  p += sizeof(*ip6);

  /* If the first extension header is not the fragmentation, we search our way
   * through the extension headers until we find the fragmentation header */
  while (p < end && hdr != IP_PROTO_FRAGMENT) {
    if (p + 2 > end)
      return -1;
    hdr = *p;
    p += (*(p + 1) + 1) * 8;
  }

  if (hdr != IP_PROTO_FRAGMENT ||  (p + 2 + sizeof(ip6_ext_data_fragment)) > end)
    return -1;

  frag_header = (struct ip6_ext_data_fragment *)( p + 2 );

  return (ntohl(frag_header->ident));

}

/* Sends an IP ID probe to the proxy machine and returns the IP ID.
   This function handles retransmissions, and returns -1 if it fails.
   Proxy timing is adjusted, but proxy->latestid is NOT ADJUSTED --
   you'll have to do that yourself.   Probes_sent is set to the number
   of probe packets sent during execution */
static int ipid_proxy_probe(struct idle_proxy_info *proxy, int *probes_sent,
                            int *probes_rcvd) {
  struct timeval tv_end;
  int tries = 0;
  int trynum;
  int sent = 0, rcvd = 0;
  int maxtries = 3; /* The maximum number of tries before we give up */
  struct timeval tv_sent[3], rcvdtime;
  int ipid = -1;
  int to_usec;
  unsigned int bytes;
  int base_port;
  struct ip *ip;
  struct tcp_hdr *tcp = NULL;
  static u32 seq_base = 0;
  static u32 ack = 0;
  static int packet_send_count = 0; /* Total # of probes sent by this program -- to ensure that our sequence # always changes */
  u32 packetlen = 0;
  u8 *ipv6_packet = NULL;
  struct sockaddr_storage ss;
  size_t sslen;
  struct ip6_hdr *ip6 = NULL;
  const void *ipv6_data;
  u8 hdr;
  int res;

  if (o.magic_port_set)
    base_port = o.magic_port;
  else
    base_port = o.magic_port + get_random_u8();

  if (seq_base == 0)
    seq_base = get_random_u32();
  if (!ack)
    ack = get_random_u32();


  do {
    gettimeofday(&tv_sent[tries], NULL);

    /* Time to send the pr0be!*/
    if (o.af() == AF_INET)
      send_tcp_raw(proxy->rawsd, proxy->ethptr,
                  proxy->host.v4sourceip(), proxy->host.v4hostip(),
                  o.ttl, false,
                  o.ipoptions, o.ipoptionslen,
                  base_port + tries, proxy->probe_port,
                  seq_base + (packet_send_count++ * 500) + 1, ack, 0, TH_SYN | TH_ACK, 0, 0,
                  (u8 *) TCP_SYN_PROBE_OPTIONS, TCP_SYN_PROBE_OPTIONS_LEN,
                  NULL, 0);
    else {
      ipv6_packet = build_tcp_raw_ipv6(proxy->host.v6sourceip(), proxy->host.v6hostip(),
                        0x00, 0x0000,
                        o.ttl,
                        base_port + tries, proxy->probe_port,
                        seq_base + (packet_send_count++ * 500) + 1, ack, 0, TH_SYN | TH_ACK, 0, 0,
                        (u8 *) TCP_SYN_PROBE_OPTIONS, TCP_SYN_PROBE_OPTIONS_LEN,
                        NULL, 0,
                        &packetlen);
      proxy->host.TargetSockAddr(&ss, &sslen);
      res = send_ip_packet(proxy->rawsd, proxy->ethptr, &ss, ipv6_packet, packetlen);
      if (res == -1)
        fatal("Error occurred while trying to send IPv6 packet");
      free(ipv6_packet);
    }
    sent++;
    tries++;

    /* Now it is time to wait for the response ... */
    to_usec = proxy->host.to.timeout;
    gettimeofday(&tv_end, NULL);
    while ((ipid == -1 || sent > rcvd) && to_usec > 0) {

      to_usec = proxy->host.to.timeout - TIMEVAL_SUBTRACT(tv_end, tv_sent[tries - 1]);
      if (to_usec < 0)
        to_usec = 0; // Final no-block poll
      ip = (struct ip *) readip_pcap(proxy->pd, &bytes, to_usec, &rcvdtime, NULL, true);
      gettimeofday(&tv_end, NULL);
      if (ip) {
        if (o.af() == AF_INET) {
          if (bytes < (4 * ip->ip_hl) + 14U)
            continue;
          if (ip->ip_p == IPPROTO_TCP)
            tcp = ((struct tcp_hdr *) (((char *) ip) + 4 * ip->ip_hl));
        } else if (o.af() == AF_INET6) {
          if (ip->ip_v != 6) {
            error("IPv6 packet with a version field != 6 received");
          } else {
            ip6 = (struct ip6_hdr *) ip;
            ipv6_data = ipv6_get_data(ip6, &packetlen, &hdr);
            if (hdr == IPPROTO_TCP && ipv6_data != NULL) {
              tcp = (struct tcp_hdr *) ipv6_data;
            }
          }
        }
        if (tcp) {
          if (ntohs(tcp->th_dport) < base_port || ntohs(tcp->th_dport) - base_port >= tries  || ntohs(tcp->th_sport) != proxy->probe_port || ((tcp->th_flags & TH_RST) == 0)) {
            if (ntohs(tcp->th_dport) > o.magic_port && ntohs(tcp->th_dport) < (o.magic_port + 260)) {
              if (o.debugging) {
                error("Received IP ID zombie probe response which probably came from an earlier prober instance ... increasing rttvar from %d to %d",
                      proxy->host.to.rttvar, (int) (proxy->host.to.rttvar * 1.2));
              }
              proxy->host.to.rttvar = (int) (proxy->host.to.rttvar * 1.2);
              rcvd++;
            } else if (o.debugging > 1) {
              char straddr[INET6_ADDRSTRLEN];
              if (o.af() == AF_INET)
                inet_ntop(AF_INET, &(ip->ip_src), straddr, sizeof(straddr));
              else if (o.af() == AF_INET6)
                inet_ntop(AF_INET6, &(ip6->ip6_src), straddr, sizeof(straddr));
              error("Received unexpected response packet from %s during IP ID zombie probing:", straddr);
              readtcppacket((unsigned char *) ip, MIN(ntohs(ip->ip_len), bytes));
            }
            continue;
          }

          trynum = ntohs(tcp->th_dport) - base_port;
          rcvd++;

          if (o.af() == AF_INET)
            ipid = ntohs(ip->ip_id);
          else if (o.af() == AF_INET6)
            ipid = ipv6_get_fragment_id(ip6, bytes);
          adjust_timeouts2(&(tv_sent[trynum]), &rcvdtime, &(proxy->host.to));
        }
      }
    }
  } while (ipid == -1 && tries < maxtries);

  if (probes_sent)
    *probes_sent = sent;
  if (probes_rcvd)
    *probes_rcvd = rcvd;

  return ipid;
}

static u16 byteswap_u16(u16 h) {
  return ((h&0xff) << 8) | ((h>>8)&0xff);
}

/* Returns the number of increments between an early IP ID and a later
   one, assuming the given IP ID Sequencing class.  Returns -1 if the
   distance cannot be determined */

static int ipid_distance(int seqclass , u32 startid, u32 endid) {
  if (seqclass == IPID_SEQ_INCR)
    return endid - startid;

  if (seqclass == IPID_SEQ_BROKEN_INCR) {
    /* Convert to network byte order */
    startid = byteswap_u16((u16) startid);
    endid = byteswap_u16((u16) endid);
    return endid - startid;
  }

  if (seqclass == IPID_SEQ_INCR_BY_2) {
    return (endid - startid)/2;
  }

  return -1;

}

static void initialize_proxy_struct(struct idle_proxy_info *proxy) {
  proxy->seqclass = proxy->latestid = proxy->probe_port = 0;
  proxy->max_groupsz = proxy->min_groupsz = 0;
  proxy->current_groupsz = 0;
  proxy->senddelay = 0;
  proxy->max_senddelay = 0;
  proxy->pd = NULL;
  proxy->rawsd = -1;
  proxy->ethptr = NULL;
}

/* Forces the permanent use of the IPv6 extension header for fragmentation in each IPv6 packet sent from
 * the idle host to the target or the attacker
 * This is achieved by first sending a ping, and afterwards an ICMPv6 Packet Too Big message
 * which states that the response from the ping was too big, our MTU is smaller than the IPv6 minimum MTU */
static void ipv6_force_fragmentation(struct idle_proxy_info *proxy, Target *target) {
  int hardtimeout = 9000000; /* Generally don't wait more than 9 secs total */
  char filter[512]; /* Libpcap filter string */
  struct ip *ip;
  /* The maximum data size we can create without fragmenting, considering that the headers also need place */
  char data[IP6_MTU_MIN - IPv6_HEADER_LEN - ETH_HDR_LEN - ICMPv6_MIN_HEADER_LEN];
  unsigned int datalen, bytes;
  const unsigned int proxy_reply_timeout = 2000;
  const void *rdata; //the data received in the echo response
  struct timeval tmptv, rcvdtime, ipv6_packet_send_time;
  struct abstract_ip_hdr hdr;
  bool response_received = false;
  struct icmpv6_hdr *icmp6_header;
  u8 *ipv6_packet = NULL;
  u32 packetlen = 0;
  u16 pingid = 0;
  u16 seq = 0;
  struct sockaddr_storage ss;
  size_t sslen;
  int res;
  assert(proxy);

  /* First, we force the proxy to provide us with a fragmentation header in each packet
     by sending an ping and afterwards an ICMPv6 Packet Too Big */
  memset(data,'A', sizeof(data));
  pingid = get_random_u16();
  seq = get_random_u16();

  /* pcap, to get the answer. Max size here is the IPv6 minimum MTU  */
  if ((proxy->pd = my_pcap_open_live(proxy->host.deviceName(), IP6_MTU_MIN,  (o.spoofsource) ? 1 : 0, 50)) == NULL)
    fatal("%s", PCAP_OPEN_ERRMSG);

  Snprintf(filter, sizeof(filter), "icmp6 and src host %s and dst host %s", proxy->host.targetipstr(), proxy->host.sourceipstr());
  if (o.debugging)
    log_write(LOG_STDOUT, "Packet capture filter (device %s): %s\n", proxy->host.deviceFullName(), filter);

  /* Make a ping that is in total 1280 byte long and send it */
  proxy->host.TargetSockAddr(&ss, &sslen);
  ipv6_packet = build_icmpv6_raw(proxy->host.v6sourceip(), proxy->host.v6hostip(), 0x00, 0x0000, o.ttl, seq , pingid, ICMPV6_ECHO, 0x00, data, sizeof(data) , &packetlen);
  res = send_ip_packet(proxy->rawsd, proxy->ethptr, &ss, ipv6_packet, packetlen);
  if (res == -1)
    fatal("Error occurred while trying to send ICMPv6 Echo Request to the idle host");
  free(ipv6_packet);
  gettimeofday(&ipv6_packet_send_time, NULL);

  /* Now let's wait for the answer */
  while (!response_received) {
    gettimeofday(&tmptv, NULL);
    ip = (struct ip *) readip_pcap(proxy->pd, &bytes, proxy_reply_timeout, &rcvdtime, NULL, true);
    if (!ip) {
      if (TIMEVAL_SUBTRACT(tmptv, ipv6_packet_send_time) >= hardtimeout) {
            fatal("Idle scan zombie %s (%s) port %hu cannot be used because it has not returned any of our ICMPv6 Echo Requests -- perhaps it is down or firewalled.",
                  proxy->host.HostName(), proxy->host.targetipstr(),
                  proxy->probe_port);
      }
      continue;
    }
    datalen = bytes;
    rdata = ip_get_data(ip, &datalen, &hdr);
    if (hdr.version == 6 && hdr.proto == IPPROTO_ICMPV6) {
      icmp6_header = (struct icmpv6_hdr *) rdata;
      if (icmp6_header->icmpv6_type == ICMPV6_ECHOREPLY) {
        const struct icmpv6_msg_echo *echo;
        echo = (struct icmpv6_msg_echo *) ((u8 *) icmp6_header + sizeof(*icmp6_header));
        if (ntohs(echo->icmpv6_id) == pingid && ntohs(echo->icmpv6_seq) == seq)
          response_received=true;
      }
    }
  }

  if (proxy->pd)
    pcap_close(proxy->pd);

  /* Now we can tell the idle host that its reply was too big, we want it smaller than the IPV6 minimum MTU */
  /* the data contains first the MTU we want, and then the received IPv6 package */
  *(uint32_t *)&data = ntohl(IP6_MTU_MIN - 2);
  memcpy(&data[4], ip, sizeof(data)-4);

  ipv6_packet = build_icmpv6_raw(proxy->host.v6sourceip(), proxy->host.v6hostip(), 0x00, 0x0000, o.ttl, 0x00 , 0x00, 0x02, 0x00, data, sizeof(data) , &packetlen);
  res = send_ip_packet(proxy->rawsd, proxy->ethptr, &ss, ipv6_packet, packetlen);
  if (res == -1)
    fatal("Error occurred while trying to send spoofed ICMPv6 Echo Request to the idle host");

  free(ipv6_packet);

  /* Now we do the same in the name of the target */
  /* No pcap this time, we won't receive the answer */
  memset(data,'A', sizeof(data));
  pingid = get_random_u16();
  seq = get_random_u16();

  ipv6_packet = build_icmpv6_raw(target->v6hostip(), proxy->host.v6hostip(), 0x00, 0x0000, o.ttl, seq , pingid, ICMPV6_ECHO, 0x00, data, sizeof(data) , &packetlen);
  res = send_ip_packet(proxy->rawsd, proxy->ethptr, &ss, ipv6_packet, packetlen);
  if (res == -1)
    fatal("Error occurred while trying to send ICMPv6 Echo Request to the idle host");

  free(ipv6_packet);

  /* Now we guess what answer the decoy host sent to the target, so that we can piggyback this on the ICMPV6 Packet too Big message */
  ipv6_packet = build_icmpv6_raw(proxy->host.v6hostip(), target->v6hostip(), 0x00, 0x0000, o.ttl, seq , pingid, ICMPV6_ECHOREPLY, 0x00, data, sizeof(data) , &packetlen);
  *(uint32_t *)&data = ntohl(IP6_MTU_MIN - 2);
  memcpy(&data[4], ipv6_packet, sizeof(data)-4);
  free(ipv6_packet);

  ipv6_packet = build_icmpv6_raw(target->v6hostip(), proxy->host.v6hostip(), 0x00, 0x0000, o.ttl, 0x00 , 0x00, 0x02, 0x00, data, sizeof(data) , &packetlen);
  /* give the decoy host time to reply to the target */
  usleep(10000);
  res = send_ip_packet(proxy->rawsd, proxy->ethptr, &ss, ipv6_packet, packetlen);
  if (res == -1)
    fatal("Error occurred while trying to send ICMPv6 PTB to the idle host");
  free(ipv6_packet);
}

/* takes a proxy name/IP, resolves it if necessary, tests it for IP ID
   suitability, and fills out an idle_proxy_info structure.  If the
   proxy is determined to be unsuitable, the function whines and exits
   the program */
#define NUM_IPID_PROBES 6
static void initialize_idleproxy(struct idle_proxy_info *proxy, char *proxyName,
                                 Target *target, const struct scan_lists *ports) {
  unsigned int probes_sent = 0, probes_returned = 0;
  int hardtimeout = 9000000; /* Generally don't wait more than 9 secs total */
  unsigned int bytes, to_usec;
  int timedout = 0;
  char *p, *q = NULL, *r;
  char *endptr = NULL;
  int seq_response_num;
  int newipid;
  unsigned int i;
  char filter[512]; /* Libpcap filter string */
  char name[FQDN_LEN + 1];
  struct sockaddr_storage ss;
  size_t sslen;
  u32 sequence_base;
  u32 ack = 0;
  struct timeval probe_send_times[NUM_IPID_PROBES], tmptv, rcvdtime;
  u32 lastipid = 0;
  struct ip *ip;
  struct tcp_hdr *tcp;
  int distance;
  u32 ipids[NUM_IPID_PROBES];
  u8 probe_returned[NUM_IPID_PROBES];
  struct route_nfo rnfo;
  assert(proxyName);
  u8 *ipv6_packet = NULL;
  u32 packetlen = 0;
  const struct ip6_hdr *ip6;
  u8 ip6hdr;
  const void *ip6data;
  bool retried_forcing_fragmentation = false;
  assert(proxy);
  assert(proxyName);
  int res;

  ack = get_random_u32();

  for (i = 0; i < NUM_IPID_PROBES; i++)
    probe_returned[i] = 0;

  initialize_proxy_struct(proxy);
  initialize_timeout_info(&proxy->host.to);

  proxy->min_groupsz = o.min_parallelism ? o.min_parallelism : 4;
  proxy->max_groupsz = MAX(proxy->min_groupsz, o.max_parallelism ? o.max_parallelism : 100);
  proxy->max_senddelay = 100000;


  /* If we have an IPv6 address, we specify the port with [address]:port */
  if (o.af() == AF_INET)
    q = strchr(proxyName, ':');
  else if (o.af() == AF_INET6) {
    r = strstr(proxyName, "]:");
    if (r != NULL)
      q = strchr(r, ':');
    else
      q = NULL;
  }

  /* If we have a : in IPv4 or [] in IPv6, we strip them off */
  if (o.af() == AF_INET && q != NULL ) {
    /* I'm lazy, using a size_t we already had around */
    sslen = MIN(strcspn(proxyName,":"), sizeof(name) - 1);
    strncpy(name, proxyName, sslen);
    /* Ensure NULL termination */
    name[sslen] = '\0';
  }
  else if (o.af() == AF_INET6 && strchr(proxyName, '[') != NULL && strchr(proxyName, ']') != NULL) {
    sslen = MIN(strcspn(proxyName,"]") - strcspn(proxyName, "[") - 1, sizeof(name) - 1);
    strncpy(name, strchr(proxyName, '[') + 1, sslen);
    name[sslen] = '\0';
  }
  else
    strncpy(name, proxyName, sizeof(name));

  if (q) {
    q++;
    proxy->probe_port = strtoul(q, &endptr, 10);
    if (*q == 0 || !endptr || *endptr != '\0' || !proxy->probe_port) {
      fatal("Invalid port number given in IP ID zombie specification: %s", proxyName);
    }
  } else {
    if (ports->syn_ping_count > 0) {
      proxy->probe_port = ports->syn_ping_ports[0];
    } else if (ports->ack_ping_count > 0) {
      proxy->probe_port = ports->ack_ping_ports[0];
    } else {
      u16 *ports;
      int count;

      getpts_simple(DEFAULT_TCP_PROBE_PORT_SPEC, SCAN_TCP_PORT, &ports, &count);
      assert(count > 0);
      proxy->probe_port = ports[0];
      free(ports);
    }
  }

  proxy->host.setHostName(name);
  int rc = resolve(name, 0, &ss, &sslen, o.pf());
  if (rc != 0) {
    fatal("Could not resolve idle scan zombie host \"%s\": %s", name, gai_strerror(rc));
  }
  proxy->host.setTargetSockAddr(&ss, sslen);

  /* Lets figure out the appropriate source address to use when sending
     the probes */
  proxy->host.TargetSockAddr(&ss, &sslen);
  if (!nmap_route_dst(&ss, &rnfo))
    fatal("Unable to find appropriate source address and device interface to use when sending packets to %s", proxyName);

  if (o.spoofsource) {
    o.SourceSockAddr(&ss, &sslen);
    proxy->host.setSourceSockAddr(&ss, sslen);
    proxy->host.setDeviceNames(o.device, o.device);
  } else {
    proxy->host.setDeviceNames(rnfo.ii.devname, rnfo.ii.devfullname);
    proxy->host.setSourceSockAddr(&rnfo.srcaddr, sizeof(rnfo.srcaddr));
  }
  if (rnfo.direct_connect) {
    proxy->host.setDirectlyConnected(true);
  } else {
    proxy->host.setDirectlyConnected(false);
    proxy->host.setNextHop(&rnfo.nexthop, sizeof(rnfo.nexthop));
  }
  proxy->host.setIfType(rnfo.ii.device_type);
  if (rnfo.ii.device_type == devt_ethernet)
    proxy->host.setSrcMACAddress(rnfo.ii.mac);

  /* Now lets send some probes to check IP ID algorithm ... */
  /* First we need a raw socket ... */
  if ((o.sendpref & PACKET_SEND_ETH) && (proxy->host.ifType() == devt_ethernet
#ifdef WIN32
    || (g_has_npcap_loopback && proxy->host.ifType() == devt_loopback)
#endif
    )) {
    if (!setTargetNextHopMAC(&proxy->host))
      fatal("%s: Failed to determine dst MAC address for Idle proxy", __func__);
    memcpy(proxy->eth.srcmac, proxy->host.SrcMACAddress(), 6);
    memcpy(proxy->eth.dstmac, proxy->host.NextHopMACAddress(), 6);
    proxy->eth.ethsd = eth_open_cached(proxy->host.deviceName());
    if (proxy->eth.ethsd == NULL)
      fatal("%s: Failed to open ethernet device (%s)", __func__, proxy->host.deviceName());
    proxy->rawsd = -1;
    proxy->ethptr = &proxy->eth;
  } else {
#ifdef WIN32
    win32_fatal_raw_sockets(proxy->host.deviceName());
#endif
    proxy->rawsd = nmap_raw_socket();
    if (proxy->rawsd < 0)
      pfatal("socket troubles in %s", __func__);
    unblock_socket(proxy->rawsd);
    proxy->eth.ethsd = NULL;
    proxy->ethptr = NULL;
  }

  if (proxy->host.af() == AF_INET6)
    ipv6_force_fragmentation(proxy, target);

  /* Now for the pcap opening nonsense ...
     Snaplen will be the IPv6 minimum MTU of 1280, because an IPv6 packet
     may have any number of extension header up to the minimal IPv6 MTU */
  if ((proxy->pd = my_pcap_open_live(proxy->host.deviceName(), IP6_MTU_MIN,  (o.spoofsource) ? 1 : 0, 50)) == NULL)
    fatal("%s", PCAP_OPEN_ERRMSG);


  p = (char *) proxy->host.targetipstr();
  q = (char *) proxy->host.sourceipstr();

  /* libpcap doesn't find the source port in IPv6 if there is an extension header. So we check for this later in the tcp header.  */
  Snprintf(filter, sizeof(filter), "tcp and src host %s and dst host %s", p, q);
  set_pcap_filter(proxy->host.deviceFullName(), proxy->pd,  filter);
  if (o.debugging)
    log_write(LOG_STDOUT, "Packet capture filter (device %s): %s\n", proxy->host.deviceFullName(), filter);
  /* Windows nonsense -- I am not sure why this is needed, but I should
     get rid of it at sometime */

  sequence_base = get_random_u32();

  /* Yahoo!  It is finally time to send our probes! */

  while (probes_sent < NUM_IPID_PROBES) {
    if (o.scan_delay)
      enforce_scan_delay(NULL);
    else if (probes_sent != 0)
      usleep(30000);

    /* TH_SYN|TH_ACK is what the proxy will really be receiving from
       the target, and is more likely to get through firewalls.  But
       TH_SYN allows us to get a nonzero ACK back so we can associate
       a response with the exact request for timing purposes.  So I
       think I'll use TH_SYN, although it is a tough call. */
    /* We can't use decoys 'cause that would screw up the IP IDs */
    if (o.af() == AF_INET)
      send_tcp_raw(proxy->rawsd, proxy->ethptr,
                   proxy->host.v4sourceip(), proxy->host.v4hostip(),
                   o.ttl, false,
                   o.ipoptions, o.ipoptionslen,
                   o.magic_port + probes_sent + 1, proxy->probe_port,
                   sequence_base + probes_sent + 1, ack, 0, TH_SYN | TH_ACK, 0, 0,
                   (u8 *) TCP_SYN_PROBE_OPTIONS, TCP_SYN_PROBE_OPTIONS_LEN,
                   NULL, 0);
    else if (o.af() == AF_INET6) {
      ipv6_packet = build_tcp_raw_ipv6(proxy->host.v6sourceip(), proxy->host.v6hostip(),
                                       0x00, 0x0000,
                                       o.ttl,
                                       o.magic_port + probes_sent + 1, proxy->probe_port,
                                       sequence_base + probes_sent + 1, ack, 0, TH_SYN | TH_ACK, 0, 0,
                                       (u8 *) TCP_SYN_PROBE_OPTIONS, TCP_SYN_PROBE_OPTIONS_LEN,
                                       NULL, 0,
                                       &packetlen);
      res = send_ip_packet(proxy->rawsd, proxy->ethptr, &ss, ipv6_packet, packetlen);
      if (res == -1)
        fatal("Error occurred while trying to send IPv6 packet");
      free(ipv6_packet);
    }

    gettimeofday(&probe_send_times[probes_sent], NULL);
    probes_sent++;

    /* Time to collect any replies */
    while (probes_returned < probes_sent && !timedout) {

      to_usec = (probes_sent == NUM_IPID_PROBES) ? hardtimeout : 1000;
      ip = (struct ip *) readip_pcap(proxy->pd, &bytes, to_usec, &rcvdtime, NULL, true);

      gettimeofday(&tmptv, NULL);

      if (!ip) {
        if (probes_sent < NUM_IPID_PROBES)
          break;
        if (TIMEVAL_SUBTRACT(tmptv, probe_send_times[probes_sent - 1]) >= hardtimeout) {
          timedout = 1;
        }
        continue;
      } else if (TIMEVAL_SUBTRACT(tmptv, probe_send_times[probes_sent - 1]) >= hardtimeout)  {
        timedout = 1;
      }

      if (o.af() == AF_INET) {
        if (ip->ip_v != 4) {
          error("Received a packet with version field != 4");
          continue;
        }
        if (lastipid != 0 && ip->ip_id == lastipid) {
          continue; /* probably a duplicate */
        }
        lastipid = ip->ip_id;
        if (bytes < (4 * ip->ip_hl) + 14U)
          continue;

        if (ip->ip_p == IPPROTO_TCP) {
          tcp = ((struct tcp_hdr *) (((char *) ip) + 4 * ip->ip_hl));
          /* Checking now for the source port, which we were not able to do in the libpcap filter */
          if (ntohs(tcp->th_sport) != proxy->probe_port) {
             continue;
          }

          if (ntohs(tcp->th_dport) < (o.magic_port + 1) || ntohs(tcp->th_dport) - o.magic_port > NUM_IPID_PROBES || ((tcp->th_flags & TH_RST) == 0)) {
            if (o.debugging > 1)
              error("Received unexpected response packet from %s during initial IP ID zombie testing", inet_ntoa(ip->ip_src));
            continue;
          }

          seq_response_num = probes_returned;

          /* The stuff below only works when we send SYN packets instead of
             SYN|ACK, but then are slightly less stealthy and have less chance
             of sneaking through the firewall.  Plus SYN|ACK is what they will
             be receiving back from the target */
          probes_returned++;
          ipids[seq_response_num] = ntohs(ip->ip_id);
          probe_returned[seq_response_num] = 1;
          adjust_timeouts2(&probe_send_times[seq_response_num], &rcvdtime, &(proxy->host.to));
        }
      } else if (o.af() == AF_INET6) {
        if (ip->ip_v != 6) {
          error("Received a packet with version field != 6");
          continue;
        } else {
          ip6 = (struct ip6_hdr *) ip;
          newipid = ipv6_get_fragment_id(ip6, bytes);
          if (newipid < 0 ) {
            /* ok, the idle host does not seem to append the extension header for fragmentation. Let's try this once more,
            * maybe the idle host just adjusted its Path MTU. If we keep on having the problem, we quit */
            if (!retried_forcing_fragmentation) {
              ipv6_force_fragmentation(proxy, target);
              retried_forcing_fragmentation = true;
            } else
              fatal("IPv6 packet without fragmentation header received - issues with the zombie?");
          }
          /* now that the additional ipv6 stuff is done, we do as for IPv4 */
          if (lastipid != 0 && newipid == (int)lastipid) {
            continue; /* probably a duplicate */
          }
          lastipid = newipid;

          ip6data = ipv6_get_data(ip6, &packetlen, &ip6hdr);
          if (ip6hdr == IPPROTO_TCP && ip6data != NULL) {
              tcp = (struct tcp_hdr *) ip6data;
              /* Checking now for the source port, which we were not able to do in the libpcap filter */
              if (ntohs(tcp->th_sport) != proxy->probe_port) {
                continue;
              }
          }else
          {
            error("Malformed packet received");
            continue;
          }

          if (ntohs(tcp->th_dport) < (o.magic_port + 1) || ntohs(tcp->th_dport) - o.magic_port > NUM_IPID_PROBES  || ((tcp->th_flags & TH_RST) == 0)) {
            if (o.debugging > 1)
              error("Received unexpected response packet from %s during initial IP ID zombie testing", inet_ntoa(ip->ip_src));
            continue;
          }

          seq_response_num = probes_returned;

          /* The stuff below only works when we send SYN packets instead of
             SYN|ACK, but then are slightly less stealthy and have less chance
             of sneaking through the firewall.  Plus SYN|ACK is what they will
             be receiving back from the target */
          probes_returned++;
          ipids[seq_response_num] = newipid;
          probe_returned[seq_response_num] = 1;
          adjust_timeouts2(&probe_send_times[seq_response_num], &rcvdtime, &(proxy->host.to));
        }
      }
    }
  }

  /* Yeah!  We're done sending/receiving probes ... now lets ensure all of our responses are adjacent in the array */
  for (i = 0, probes_returned = 0; i < NUM_IPID_PROBES; i++) {
    if (probe_returned[i]) {
      if (i > probes_returned)
        ipids[probes_returned] = ipids[i];
      probes_returned++;
    }
  }

  if (probes_returned == 0)
    fatal("Idle scan zombie %s (%s) port %hu cannot be used because it has not returned any of our probes -- perhaps it is down or firewalled.",
          proxy->host.HostName(), proxy->host.targetipstr(),
          proxy->probe_port);

  if (o.af() == AF_INET)
    proxy->seqclass = get_ipid_sequence_16(probes_returned, ipids, 0);
  else
    proxy->seqclass = get_ipid_sequence_32(probes_returned, ipids, 0);
  switch (proxy->seqclass) {
  case IPID_SEQ_INCR:
  case IPID_SEQ_INCR_BY_2:
  case IPID_SEQ_BROKEN_INCR:
    log_write(LOG_PLAIN, "Idle scan using zombie %s (%s:%hu); Class: %s\n", proxy->host.HostName(), proxy->host.targetipstr(), proxy->probe_port, ipidclass2ascii(proxy->seqclass));
    break;
  default:
    fatal("Idle scan zombie %s (%s) port %hu cannot be used because IP ID sequence class is: %s.  Try another proxy.", proxy->host.HostName(), proxy->host.targetipstr(), proxy->probe_port, ipidclass2ascii(proxy->seqclass));
  }

  proxy->latestid = ipids[probes_returned - 1];
  proxy->current_groupsz = MIN(proxy->max_groupsz, 30);

  if (probes_returned < NUM_IPID_PROBES) {
    /* Yikes!  We're already losing packets ... clamp down a bit ... */
    if (o.debugging)
      error("Idle scan initial zombie qualification test: %d probes sent, only %d returned", NUM_IPID_PROBES, probes_returned);
    proxy->current_groupsz = MIN(12, proxy->max_groupsz);
    proxy->current_groupsz = MAX(proxy->current_groupsz, proxy->min_groupsz);
    proxy->senddelay += 5000;
  }

  /* OK, through experimentation I have found that some hosts *cough*
   Solaris APPEAR to use simple IP ID incrementing, but in reality they
   assign a new IP ID base to each host which connects with them.  This
   is actually a good idea on several fronts, but it totally
   frustrates our efforts (which rely on side-channel IP ID info
   leaking to different hosts).  The good news is that we can easily
   detect the problem by sending some spoofed packets "from" the first
   target to the zombie and then probing to verify that the proxy IP ID
   changed.  This will also catch the case where the Nmap user is
   behind an egress filter or other measure that prevents this sort of
   sp00fery */
  /* this behavior gets quite common in IPv6 so now its even more important to check */
  if (target->v4hostip() || target->v6hostip()) {
    for (probes_sent = 0; probes_sent < 4; probes_sent++) {
      if (probes_sent != 0)
        usleep(50000);
      if (target->v4hostip()) {
        send_tcp_raw(proxy->rawsd, proxy->ethptr,
                    target->v4hostip(), proxy->host.v4hostip(),
                    o.ttl, false,
                    o.ipoptions, o.ipoptionslen,
                    o.magic_port, proxy->probe_port,
                    sequence_base + probes_sent + 1, ack, 0, TH_SYN | TH_ACK, 0, 0,
                    (u8 *) TCP_SYN_PROBE_OPTIONS,
                    TCP_SYN_PROBE_OPTIONS_LEN, NULL, 0);
      } else {
        ipv6_packet = build_tcp_raw_ipv6(target->v6hostip(), proxy->host.v6hostip(),
                                         0x00, 0x0000,
                                         o.ttl,
                                         o.magic_port, proxy->probe_port,
                                         sequence_base + probes_sent + 1, ack, 0, TH_SYN | TH_ACK, 0, 0,
                                         (u8 *) TCP_SYN_PROBE_OPTIONS,
                                         TCP_SYN_PROBE_OPTIONS_LEN, NULL, 0,
                                         &packetlen);
        res = send_ip_packet(proxy->rawsd, proxy->ethptr, &ss, ipv6_packet, packetlen);
        if (res == -1)
          fatal("Error occurred while trying to send IPv6 packet ");
        free(ipv6_packet);
      }
    }

    /* Sleep a little while to give packets time to reach their destination */
    usleep(300000);
    newipid = ipid_proxy_probe(proxy, NULL, NULL);
    if (newipid == -1)
      newipid = ipid_proxy_probe(proxy, NULL, NULL); /* OK, we'll give it one more try */

    if (newipid < 0)
      fatal("Your IP ID Zombie (%s; %s) is behaving strangely -- suddenly cannot obtain IP ID", proxy->host.HostName(), proxy->host.targetipstr());

    distance = ipid_distance(proxy->seqclass, proxy->latestid, newipid);
    if (distance <= 0) {
      fatal("Your IP ID Zombie (%s; %s) is behaving strangely -- suddenly cannot obtain valid IP ID distance.", proxy->host.HostName(), proxy->host.targetipstr());
    } else if (distance == 1) {
      fatal("Even though your Zombie (%s; %s) appears to be vulnerable to IP ID sequence prediction (class: %s), our attempts have failed.  This generally means that either the Zombie uses a separate IP ID base for each host (like Solaris), or because you cannot spoof IP packets (perhaps your ISP has enabled egress filtering to prevent IP spoofing), or maybe the target network recognizes the packet source as bogus and drops them", proxy->host.HostName(), proxy->host.targetipstr(), ipidclass2ascii(proxy->seqclass));
    }
    if (o.debugging && distance != 5) {
      error("WARNING: IP ID spoofing test sent 4 packets and expected a distance of 5, but instead got %d", distance);
    }
    proxy->latestid = newipid;
  }

}




/* Adjust timing parameters up or down given that an idlescan found a
   count of 'testcount' while the 'realcount' is as given.  If the
   testcount was correct, timing is made more aggressive, while it is
   slowed down in the case of an error */
static void adjust_idle_timing(struct idle_proxy_info *proxy,
                               Target *target, int testcount,
                               int realcount) {

  static int notidlewarning = 0;

  if (o.debugging > 1) {
    log_write(LOG_STDOUT, "%s: tested/true %d/%d -- old grpsz/delay: %f/%d ",
              __func__, testcount, realcount, proxy->current_groupsz, proxy->senddelay);
  } else if (o.debugging && testcount != realcount) {
    error("%s: testcount: %d  realcount: %d -- old grpsz/delay: %f/%d",
          __func__, testcount, realcount, proxy->current_groupsz, proxy->senddelay);
  }

  if (testcount < realcount) {
    /* We must have missed a port -- our probe could have been
    dropped, the response to proxy could have been dropped, or we
    didn't wait long enough before probing the proxy IP ID.  The
    third case is covered elsewhere in the scan, so we worry most
    about the first two.  The solution is to decrease our group
    size and add a sending delay */

    /* packets could be dropped because too many sent at once */
    proxy->current_groupsz = MAX(proxy->min_groupsz, proxy->current_groupsz * 0.8);
    proxy->senddelay += 10000;
    proxy->senddelay = MIN(proxy->max_senddelay, proxy->senddelay);
    /* No group size should be greater than .5s of send delays */
    proxy->current_groupsz = MAX(proxy->min_groupsz, MIN(proxy->current_groupsz, 500000 / (proxy->senddelay + 1)));

  } else if (testcount > realcount) {
    /* Perhaps the proxy host is not really idle ... */
    /* I guess all I can do is decrease the group size, so that if the proxy is not really idle, at least we may be able to scan cnunks more quickly in between outside packets */
    proxy->current_groupsz = MAX(proxy->min_groupsz, proxy->current_groupsz * 0.8);

    if (!notidlewarning && o.verbose) {
      notidlewarning = 1;
      error("WARNING: idle scan has erroneously detected phantom ports -- is the proxy %s (%s) really idle?", proxy->host.HostName(), proxy->host.targetipstr());
    }
  } else {
    /* W00p We got a perfect match.  That means we get a slight increase
    in allowed group size and we can lightly decrease the senddelay */

    proxy->senddelay = (int) (proxy->senddelay * 0.9);
    if (proxy->senddelay < 500)
      proxy->senddelay = 0;
    proxy->current_groupsz = MIN(proxy->current_groupsz * 1.1, 500000 / (proxy->senddelay + 1));
    proxy->current_groupsz = MIN(proxy->max_groupsz, proxy->current_groupsz);

  }
  if (o.debugging > 1)
    log_write(LOG_STDOUT, "-> %f/%d\n", proxy->current_groupsz, proxy->senddelay);
}


/* OK, now this is the hardcore idle scan function which actually does
   the testing (most of the other cruft in this file is just
   coordination, preparation, etc).  This function simply uses the
   idle scan technique to try and count the number of open ports in the
   given port array.  The sent_time and rcv_time are filled in with
   the times that the probe packet & response were sent/received.
   They can be NULL if you don't want to use them.  The purpose is for
   timing adjustments if the numbers turn out to be accurate */

static int idlescan_countopen2(struct idle_proxy_info *proxy,
                               Target *target, u16 *ports, int numports,
                               struct timeval *sent_time, struct timeval *rcv_time) {
  int openports;
  int tries;
  int proxyprobes_sent = 0; /* diff. from tries 'cause sometimes we
                               skip tries */
  int proxyprobes_rcvd = 0; /* To determine if packets were dr0pped */
  int sent, rcvd;
  int ipid_dist;
  struct timeval start, end, latestchange, now;
  struct timeval probe_times[4];
  int pr0be;
  static u32 seq = 0;
  int newipid = 0;
  int sleeptime;
  int lasttry = 0;
  int dotry3 = 0;
  struct eth_nfo eth;
  u8 *packet = NULL;
  struct sockaddr_storage ss;
  size_t sslen;
  u32 packetlen = 0;
  int res;

  if (seq == 0)
    seq = get_random_u32();

  target->TargetSockAddr(&ss, &sslen);
  memset(&end, 0, sizeof(end));
  memset(&latestchange, 0, sizeof(latestchange));
  gettimeofday(&start, NULL);
  if (sent_time)
    memset(sent_time, 0, sizeof(*sent_time));
  if (rcv_time)
    memset(rcv_time, 0, sizeof(*rcv_time));

  if (proxy->rawsd < 0) {
    if (!setTargetNextHopMAC(target))
      fatal("%s: Failed to determine dst MAC address for Idle proxy", __func__);
    memcpy(eth.srcmac, target->SrcMACAddress(), 6);
    memcpy(eth.dstmac, target->NextHopMACAddress(), 6);
    eth.ethsd = eth_open_cached(target->deviceName());
    if (eth.ethsd == NULL)
      fatal("%s: Failed to open ethernet device (%s)", __func__, target->deviceName());
  } else eth.ethsd = NULL;

  /* I start by sending out the SYN probes */
  for (pr0be = 0; pr0be < numports; pr0be++) {
    if (o.scan_delay)
      enforce_scan_delay(NULL);
    else if (proxy->senddelay && pr0be > 0) usleep(proxy->senddelay);

    /* Maybe I should involve decoys in the picture at some point --
       but doing it the straightforward way (using the same decoys as
       we use in probing the proxy box is risky.  I'll have to think
       about this more. */
   if (o.af() == AF_INET ) {
      send_tcp_raw(proxy->rawsd, eth.ethsd ? &eth : NULL,
                   proxy->host.v4hostip(), target->v4hostip(),
                   o.ttl, false,
                   o.ipoptions, o.ipoptionslen,
                   proxy->probe_port, ports[pr0be], seq, 0, 0, TH_SYN, 0, 0,
                   (u8 *) TCP_SYN_PROBE_OPTIONS, TCP_SYN_PROBE_OPTIONS_LEN,
                   o.extra_payload, o.extra_payload_length);
   } else {
        packet = build_tcp_raw_ipv6(proxy->host.v6hostip(), target->v6hostip(),
                                    0x00, 0x0000,
                                    o.ttl,
                                    proxy->probe_port, ports[pr0be], seq, 0, 0, TH_SYN, 0, 0,
                                    (u8 *) TCP_SYN_PROBE_OPTIONS, TCP_SYN_PROBE_OPTIONS_LEN,
                                    o.extra_payload, o.extra_payload_length,
                                    &packetlen);
        res = send_ip_packet(proxy->rawsd, eth.ethsd ? &eth : NULL, &ss, packet, packetlen);
        if (res == -1)
          fatal("Error occurred while trying to send IPv6 packet");
        free(packet);
    }
  }
  gettimeofday(&end, NULL);

  openports = -1;
  tries = 0;
  TIMEVAL_MSEC_ADD(probe_times[0], start, MAX(50, (target->to.srtt * 3 / 4) / 1000));
  TIMEVAL_MSEC_ADD(probe_times[1], start, target->to.srtt / 1000 );
  TIMEVAL_MSEC_ADD(probe_times[2], end, MAX(75, (2 * target->to.srtt +
                   target->to.rttvar) / 1000));
  TIMEVAL_MSEC_ADD(probe_times[3], end, MIN(4000, (2 * target->to.srtt +
                   (target->to.rttvar << 2 )) / 1000));

  do {
    if (tries == 2)
      dotry3 = (get_random_u8() > 200);
    if (tries == 3 && !dotry3)
      break; /* We usually want to skip the long-wait test */
    if (tries == 3 || (tries == 2 && !dotry3))
      lasttry = 1;

    gettimeofday(&now, NULL);
    sleeptime = TIMEVAL_SUBTRACT(probe_times[tries], now);
    if (!lasttry && proxyprobes_sent > 0 && sleeptime < 50000)
      continue; /* No point going again so soon */

    if (tries == 0 && sleeptime < 500)
      sleeptime = 500;
    if (o.debugging > 1)
      error("In preparation for idle scan probe try #%d, sleeping for %d usecs", tries, sleeptime);
    if (sleeptime > 0)
      usleep(sleeptime);

    newipid = ipid_proxy_probe(proxy, &sent, &rcvd);
    proxyprobes_sent += sent;
    proxyprobes_rcvd += rcvd;

    if (newipid > 0) {
      ipid_dist = ipid_distance(proxy->seqclass, proxy->latestid, newipid);
      /* I used to only do this if ipid_sit >= proxyprobes_sent, but I'd
      rather have a negative number in that case */
      if (ipid_dist < proxyprobes_sent) {
        if (o.debugging)
          error("%s: Must have lost a sent packet because ipid_dist is %d while proxyprobes_sent is %d.", __func__, ipid_dist, proxyprobes_sent);
        /* I no longer whack timing here ... done at bottom */
      }
      ipid_dist -= proxyprobes_sent;
      if (ipid_dist > openports) {
        openports = ipid_dist;
        gettimeofday(&latestchange, NULL);
      } else if (ipid_dist < openports && ipid_dist >= 0) {
        /* Uh-oh.  Perhaps I dropped a packet this time */
        if (o.debugging > 1) {
          error("%s: Counted %d open ports in try #%d, but counted %d earlier ... probably a proxy_probe problem", __func__, ipid_dist, tries, openports);
        }
        /* I no longer whack timing here ... done at bottom */
      }
    }

    if (openports > numports || (numports <= 2 && (openports == numports)))
      break;
  } while (tries++ < 3);

  if (proxyprobes_sent > proxyprobes_rcvd) {
    /* Uh-oh.  It looks like we lost at least one proxy probe packet */
    if (o.debugging) {
      error("%s: Sent %d probes; only %d responses.  Slowing scan.", __func__, proxyprobes_sent, proxyprobes_rcvd);
    }
    proxy->senddelay += 5000;
    proxy->senddelay = MIN(proxy->max_senddelay, proxy->senddelay);
    /* No group size should be greater than .5s of send delays */
    proxy->current_groupsz = MAX(proxy->min_groupsz, MIN(proxy->current_groupsz, 500000 / (proxy->senddelay + 1)));
  } else {
    /* Yeah, we got as many responses as we sent probes.  This calls for a
       very light timing acceleration ... */
    proxy->senddelay = (int) (proxy->senddelay * 0.95);
    if (proxy->senddelay < 500)
      proxy->senddelay = 0;
    proxy->current_groupsz = MAX(proxy->min_groupsz, MIN(proxy->current_groupsz, 500000 / (proxy->senddelay + 1)));
  }

  if ((openports > 0) && (openports <= numports)) {
    /* Yeah, we found open ports... lets adjust the timing ... */
    if (o.debugging > 2)
      error("%s:  found %d open ports (out of %d) in %lu usecs", __func__, openports, numports, (unsigned long) TIMEVAL_SUBTRACT(latestchange, start));
    if (sent_time)
      *sent_time = start;
    if (rcv_time)
      *rcv_time = latestchange;
  }
  if (newipid > 0)
    proxy->latestid = newipid;
  if (eth.ethsd) {
    eth.ethsd = NULL;  /* don't need to close it due to caching */
  }
  return openports;
}



/* The job of this function is to use the idle scan technique to count
   the number of open ports in the given list.  Under the covers, this
   function just farms out the hard work to another function */
static int idlescan_countopen(struct idle_proxy_info *proxy,
                              Target *target, u16 *ports, int numports,
                              struct timeval *sent_time, struct timeval *rcv_time) {
  int tries = 0;
  int openports;

  do {
    openports = idlescan_countopen2(proxy, target, ports, numports, sent_time, rcv_time);
    tries++;
    if (tries == 6 || (openports >= 0 && openports <= numports))
      break;

    if (o.debugging) {
      error("%s: In try #%d, counted %d open ports out of %d.  Retrying", __func__, tries, openports, numports);
    }
    /* Sleep for a little while -- maybe proxy host had brief birst of
       traffic or similar problem */
    sleep(tries * tries);
    if (tries == 5)
      sleep(45); /* We're gonna give up if this fails, so we will be a bit
                    patient */
    /* Since the host may have received packets while we were sleeping,
       lets update our proxy IP ID counter */
    proxy->latestid = ipid_proxy_probe(proxy, NULL, NULL);
  } while (1);

  if (openports < 0 || openports > numports ) {
    /* Oh f*ck!!!! */
    fatal("Idle scan is unable to obtain meaningful results from proxy %s (%s).  I'm sorry it didn't work out.", proxy->host.HostName(),
          proxy->host.targetipstr());
  }

  if (o.debugging > 2)
    error("%s: %d ports found open out of %d, starting with %hu", __func__, openports, numports, ports[0]);

  return openports;
}

/* Recursively idle scans scans a group of ports using a depth-first
   divide-and-conquer strategy to find the open one(s) */

static int idle_treescan(struct idle_proxy_info *proxy, Target *target,
                         u16 *ports, int numports, int expectedopen) {

  int firstHalfSz = (numports + 1) / 2;
  int secondHalfSz = numports - firstHalfSz;
  int flatcount1, flatcount2;
  int deepcount1 = -1, deepcount2 = -1;
  struct timeval sentTime1, rcvTime1, sentTime2, rcvTime2;
  int retrycount = -1, retry2 = -1;
  int totalfound = 0;
  /* Scan the first half of the range */

  if (o.debugging > 1) {
    error("%s: Called against %s with %d ports, starting with %hu. expectedopen: %d", __func__, target->targetipstr(), numports, ports[0], expectedopen);
    error("IDLE SCAN TIMING: grpsz: %.3f delay: %d srtt: %d rttvar: %d",
          proxy->current_groupsz, proxy->senddelay, target->to.srtt,
          target->to.rttvar);
  }

  flatcount1 = idlescan_countopen(proxy, target, ports, firstHalfSz, &sentTime1, &rcvTime1);



  if (firstHalfSz > 1 && flatcount1 > 0) {
    /* A port appears open!  We dig down deeper to find it ... */
    deepcount1 = idle_treescan(proxy, target, ports, firstHalfSz, flatcount1);
    /* Now we assume deepcount1 is right, and adjust timing if flatcount1 was
       wrong */
    adjust_idle_timing(proxy, target, flatcount1, deepcount1);
  }

  /* I guess we had better do the second half too ... */

  flatcount2 = idlescan_countopen(proxy, target, ports + firstHalfSz, secondHalfSz, &sentTime2, &rcvTime2);

  if ((secondHalfSz) > 1 && flatcount2 > 0) {
    /* A port appears open!  We dig down deeper to find it ... */
    deepcount2 = idle_treescan(proxy, target, ports + firstHalfSz,
                               secondHalfSz, flatcount2);
    /* Now we assume deepcount1 is right, and adjust timing if flatcount1 was
       wrong */
    adjust_idle_timing(proxy, target, flatcount2, deepcount2);
  }

  totalfound = (deepcount1 == -1) ? flatcount1 : deepcount1;
  totalfound += (deepcount2 == -1) ? flatcount2 : deepcount2;

  if ((flatcount1 + flatcount2 == totalfound) &&
      (expectedopen == totalfound || expectedopen == -1)) {

    if (flatcount1 > 0) {
      if (o.debugging > 1) {
        error("Adjusting timing -- idlescan_countopen correctly found %d open ports (out of %d, starting with %hu)", flatcount1, firstHalfSz, ports[0]);
      }
      adjust_timeouts2(&sentTime1, &rcvTime1, &(target->to));
    }

    if (flatcount2 > 0) {
      if (o.debugging > 2) {
        error("Adjusting timing -- idlescan_countopen correctly found %d open ports (out of %d, starting with %hu)", flatcount2, secondHalfSz,
              ports[firstHalfSz]);
      }
      adjust_timeouts2(&sentTime2, &rcvTime2, &(target->to));
    }
  }

  if (totalfound != expectedopen) {
    if (deepcount1 == -1) {
      retrycount = idlescan_countopen(proxy, target, ports, firstHalfSz, NULL, NULL);
      if (retrycount != flatcount1) {
        /* We have to do a deep count if new ports were found and
           there are more than 1 total */
        if (firstHalfSz > 1 && retrycount > 0) {
          retry2 = retrycount;
          retrycount = idle_treescan(proxy, target, ports, firstHalfSz,
                                     retrycount);
          adjust_idle_timing(proxy, target, retry2, retrycount);
        } else {
          if (o.debugging)
            error("Adjusting timing because my first scan of %d ports, starting with %hu found %d open, while second scan yielded %d", firstHalfSz, ports[0], flatcount1, retrycount);
          adjust_idle_timing(proxy, target, flatcount1, retrycount);
        }
        totalfound += retrycount - flatcount1;
        flatcount1 = retrycount;

        /* If our first count erroneously found and added an open port,
           we must delete it */
        if (firstHalfSz == 1 && flatcount1 == 1 && retrycount == 0)
          target->ports.forgetPort(ports[0], IPPROTO_TCP);

      }
    }

    if (deepcount2 == -1) {
      retrycount = idlescan_countopen(proxy, target, ports + firstHalfSz, secondHalfSz, NULL, NULL);
      if (retrycount != flatcount2) {
        if (secondHalfSz > 1 && retrycount > 0) {
          retry2 = retrycount;
          retrycount = idle_treescan(proxy, target, ports + firstHalfSz,
                                     secondHalfSz, retrycount);
          adjust_idle_timing(proxy, target, retry2, retrycount);
        } else {
          if (o.debugging)
            error("Adjusting timing because my first scan of %d ports, starting with %hu found %d open, while second scan yielded %d", secondHalfSz, ports[firstHalfSz], flatcount2, retrycount);
          adjust_idle_timing(proxy, target, flatcount2, retrycount);
        }

        totalfound += retrycount - flatcount2;
        flatcount2 = retrycount;

        /* If our first count erroneously found and added an open port,
           we must delete it */
        if (secondHalfSz == 1 && flatcount2 == 1 && retrycount == 0)
          target->ports.forgetPort(ports[firstHalfSz], IPPROTO_TCP);


      }
    }
  }

  if (firstHalfSz == 1 && flatcount1 == 1)
    target->ports.setPortState(ports[0], IPPROTO_TCP, PORT_OPEN);

  if ((secondHalfSz == 1) && flatcount2 == 1)
    target->ports.setPortState(ports[firstHalfSz], IPPROTO_TCP, PORT_OPEN);
  return totalfound;

}



/* The very top-level idle scan function -- scans the given target
   host using the given proxy -- the proxy is cached so that you can keep
   calling this function with different targets */
void idle_scan(Target *target, u16 *portarray, int numports,
               char *proxyName, const struct scan_lists *ports) {

  static char lastproxy[FQDN_LEN + 1] = ""; /* The proxy used in any previous call */
  static struct idle_proxy_info proxy;
  int groupsz;
  int portidx = 0; /* Used for splitting the port array into chunks */
  int portsleft;
  char scanname[128];
  Snprintf(scanname, sizeof(scanname), "idle scan against %s", target->NameIP());
  ScanProgressMeter SPM(scanname);

  if (numports == 0)
    return; /* nothing to scan for */
  if (!proxyName)
    fatal("idle scan requires a proxy host");

  if (*lastproxy && strcmp(proxyName, lastproxy))
    fatal("%s: You are not allowed to change proxies midstream.  Sorry", __func__);
  assert(target);

  if (target->timedOut(NULL))
    return;

  if (target->ifType() == devt_loopback) {
    log_write(LOG_STDOUT, "Skipping Idle Scan against %s -- you can't idle scan your own machine (localhost).\n", target->NameIP());
    return;
  }

  target->startTimeOutClock(NULL);

  /* If this is the first call,  */
  if (!*lastproxy) {
    initialize_idleproxy(&proxy, proxyName, target, ports);
    strncpy(lastproxy, proxyName, sizeof(lastproxy));
  }

  /* If we don't have timing infoz for the new target, we'll use values
     derived from the proxy */
  if (target->to.srtt == -1 && target->to.rttvar == -1) {
    target->to.srtt = MAX(200000, 2 * proxy.host.to.srtt);
    target->to.rttvar = MAX(10000, MIN(proxy.host.to.rttvar, 2000000));
    target->to.timeout = target->to.srtt + (target->to.rttvar << 2);
  } else {
    target->to.srtt = MAX(target->to.srtt, proxy.host.to.srtt);
    target->to.rttvar = MAX(target->to.rttvar, proxy.host.to.rttvar);
    target->to.timeout = target->to.srtt + (target->to.rttvar << 2);
  }

  /* Now I guess it is time to let the scanning begin!  Since Idle
     scan is sort of tree structured (we scan a group and then divide
     it up and drill down in subscans of the group), we split the port
     space into smaller groups and then call a recursive
     divide-and-conquer function to find the open ports */
  while (portidx < numports) {
    portsleft = numports - portidx;
    /* current_groupsz is doubled below because idle_subscan cuts in half */
    groupsz = MIN(portsleft, (int) (proxy.current_groupsz * 2));
    idle_treescan(&proxy, target, portarray + portidx, groupsz, -1);
    portidx += groupsz;
  }


  char additional_info[14];
  Snprintf(additional_info, sizeof(additional_info), "%d ports", numports);
  SPM.endTask(NULL, additional_info);

  /* Now we go through the ports which were scanned but not determined
     to be open, and add them in the "closed|filtered" state */
  for (portidx = 0; portidx < numports; portidx++) {
    if (target->ports.portIsDefault(portarray[portidx], IPPROTO_TCP)) {
      target->ports.setPortState(portarray[portidx], IPPROTO_TCP, PORT_CLOSEDFILTERED);
      target->ports.setStateReason(portarray[portidx], IPPROTO_TCP, ER_NOIPIDCHANGE, 0, NULL);
    } else {
      target->ports.setStateReason(portarray[portidx], IPPROTO_TCP, ER_IPIDCHANGE, 0, NULL);
    }
  }

  target->stopTimeOutClock(NULL);
  return;
}
