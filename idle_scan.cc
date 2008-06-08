
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
 * The Nmap Security Scanner is (C) 1996-2008 Insecure.Com LLC. Nmap is    *
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
 * works of Nmap.  This list is not exclusive, but is just meant to        *
 * clarify our interpretation of derived works with some common examples.  *
 * These restrictions only apply when you actually redistribute Nmap.  For *
 * example, nothing stops you from writing and selling a proprietary       *
 * front-end to Nmap.  Just distribute it by itself, and point people to   *
 * http://nmap.org to download Nmap.                                       *
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
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates as well as helping to     *
 * fund the continued development of Nmap technology.  Please email        *
 * sales@insecure.com for further information.                             *
 *                                                                         *
 * As a special exception to the GPL terms, Insecure.Com LLC grants        *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included COPYING.OpenSSL file, and distribute linked      *
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
 * distribution.  By sending these changes to Fyodor or one of the         *
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
 * General Public License v2.0 for more details at                         *
 * http://www.gnu.org/licenses/gpl-2.0.html , or in the COPYING file       *
 * included with Nmap.                                                     *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */

#include "idle_scan.h"
#include "timing.h"
#include "osscan2.h"
#include "nmap.h"
#include "NmapOps.h"
#include "services.h"
#include "Target.h"
#include "utils.h"

#include <stdio.h>

/* For unknown reasons, MS VC++ is warning about lines like:
   proxy->senddelay *= 0.95;

   This is the brute-force way to fix that.
 */ 
#ifdef _MSC_VER
#pragma warning(disable: 4244)
#endif

extern NmapOps o;

struct idle_proxy_info {
  Target host; /* contains name, IP, source IP, timing info, etc. */
  int seqclass; /* IP ID sequence class (IPID_SEQ_* defined in nmap.h) */
  u16 latestid; /* The most recent IP ID we have received from the proxy */
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
                        sending pr0bes (when we send a bunch in a row.
                        In microseconds. */

  pcap_t *pd; /* A Pcap descriptor which (starting in
                 initialize_idleproxy) listens for TCP packets from
                 the probe_port of the proxy box */
  int rawsd; /* Socket descriptor for sending probe packets to the proxy */
  struct eth_nfo eth; // For when we want to send probes via raw IP instead.
  struct eth_nfo *ethptr; // points to eth if filled out, otherwise NULL
};


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
  int sent=0, rcvd=0;
  int maxtries = 3; /* The maximum number of tries before we give up */
  struct timeval tv_sent[3], rcvdtime;
  int ipid = -1;
  int to_usec;
  unsigned int bytes;
  int timedout = 0;
  int base_port;
  struct ip *ip;
  struct tcp_hdr *tcp;
  static u32 seq_base = 0;
  static u32 ack = 0;
  static int packet_send_count = 0; /* Total # of probes sent by this program -- to ensure that our sequence # always changes */

  if (o.magic_port_set)
    base_port = o.magic_port;
  else base_port = o.magic_port + get_random_u8();

  if (seq_base == 0) seq_base = get_random_u32();
  if (!ack) ack = get_random_u32();


  do {
    timedout = 0;
    gettimeofday(&tv_sent[tries], NULL);

    /* Time to send the pr0be!*/
    send_tcp_raw(proxy->rawsd, proxy->ethptr,
    		proxy->host.v4sourceip(), proxy->host.v4hostip(),
    		o.ttl, false,
    		o.ipoptions, o.ipoptionslen,
    		base_port + tries, proxy->probe_port,
		seq_base + (packet_send_count++ * 500) + 1, ack, 0, TH_SYN|TH_ACK, 0, 0,
		(u8 *) "\x02\x04\x05\xb4", 4,
		NULL, 0);
    sent++;
    tries++;

    /* Now it is time to wait for the response ... */
    to_usec = proxy->host.to.timeout;
    gettimeofday(&tv_end, NULL);
    while((ipid == -1 || sent > rcvd) && to_usec > 0) {

      to_usec = proxy->host.to.timeout - TIMEVAL_SUBTRACT(tv_end, tv_sent[tries-1]);
      if (to_usec < 0) to_usec = 0; // Final no-block poll
      ip = (struct ip *) readip_pcap(proxy->pd, &bytes, to_usec, &rcvdtime, NULL);      
      gettimeofday(&tv_end, NULL);
      if (ip) {
	if (bytes < ( 4 * ip->ip_hl) + 14U)
	  continue;

	if (ip->ip_p == IPPROTO_TCP) {

	  tcp = ((struct tcp_hdr *) (((char *) ip) + 4 * ip->ip_hl));
	  if (ntohs(tcp->th_dport) < base_port || ntohs(tcp->th_dport) - base_port >= tries  || ntohs(tcp->th_sport) != proxy->probe_port || ((tcp->th_flags & TH_RST) == 0)) {
	    if (ntohs(tcp->th_dport) > o.magic_port && ntohs(tcp->th_dport) < (o.magic_port + 260)) {
	      if (o.debugging) {
		error("Received IP ID zombie probe response which probably came from an earlier prober instance ... increasing rttvar from %d to %d", 
		      proxy->host.to.rttvar, (int) (proxy->host.to.rttvar * 1.2));
	      }
	      proxy->host.to.rttvar = (int) (proxy->host.to.rttvar * 1.2);
	      rcvd++;
	    }
	    else if (o.debugging > 1) {
	      error("Received unexpected response packet from %s during IP ID zombie probing:", inet_ntoa(ip->ip_src));
	      readtcppacket( (unsigned char *) ip,ntohs(ip->ip_len));
	    }
	    continue;
	  }
	  
	  trynum = ntohs(tcp->th_dport) - base_port;
	  rcvd++;

	  ipid = ntohs(ip->ip_id);
	  adjust_timeouts2(&(tv_sent[trynum]), &rcvdtime, &(proxy->host.to));
	}
      }
    }
  } while(ipid == -1 && tries < maxtries);

  if (probes_sent) *probes_sent = sent;
  if (probes_rcvd) *probes_rcvd = rcvd;

  return ipid;
}


/* Returns the number of increments between an early IP ID and a later
   one, assuming the given IP ID Sequencing class.  Returns -1 if the
   distance cannot be determined */

static int ipid_distance(int seqclass , u16 startid, u16 endid) {
  if (seqclass == IPID_SEQ_INCR)
    return endid - startid;
  
  if (seqclass == IPID_SEQ_BROKEN_INCR) {
    /* Convert to network byte order */
    startid = htons(startid);
    endid = htons(endid);
    return endid - startid;
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

/* takes a proxy name/IP, resolves it if neccessary, tests it for IP ID
   suitability, and fills out an idle_proxy_info structure.  If the
   proxy is determined to be unsuitable, the function whines and exits
   the program */
#define NUM_IPID_PROBES 6
static void initialize_idleproxy(struct idle_proxy_info *proxy, char *proxyName,
			  const struct in_addr *first_target, const struct scan_lists * ports) {
  int probes_sent = 0, probes_returned = 0;
  int hardtimeout = 9000000; /* Generally don't wait more than 9 secs total */
  unsigned int bytes, to_usec;
  int timedout = 0;
  char *p, *q;
  char *endptr = NULL;
  int seq_response_num;
  int newipid;
  int i;
  char filter[512]; /* Libpcap filter string */
  char name[MAXHOSTNAMELEN + 1];
  struct sockaddr_storage ss;
  size_t sslen;
  u32 sequence_base;
  u32 ack = 0;
  struct timeval probe_send_times[NUM_IPID_PROBES], tmptv, rcvdtime;
  u16 lastipid = 0;
  struct ip *ip;
  struct tcp_hdr *tcp;
  int distance;
  int ipids[NUM_IPID_PROBES]; 
  u8 probe_returned[NUM_IPID_PROBES];
  struct route_nfo rnfo;
  assert(proxy);
  assert(proxyName);

  ack = get_random_u32();

  for(i=0; i < NUM_IPID_PROBES; i++) probe_returned[i] = 0;

  initialize_proxy_struct(proxy);
  initialize_timeout_info(&proxy->host.to);

  proxy->max_groupsz = (o.max_parallelism)? o.max_parallelism : 100;
  proxy->min_groupsz = (o.min_parallelism)? o.min_parallelism : 4;
  proxy->max_senddelay = 100000;

  Strncpy(name, proxyName, sizeof(name));
  q = strchr(name, ':');
  if (q) {
    *q++ = '\0';
    proxy->probe_port = strtoul(q, &endptr, 10);
    if (*q==0 || !endptr || *endptr != '\0' || !proxy->probe_port) {
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
  if (resolve(name, &ss, &sslen, o.pf()) == 0) {
    fatal("Could not resolve idle scan zombie host: %s", name);
  }
  proxy->host.setTargetSockAddr(&ss, sslen);
  
  /* Lets figure out the appropriate source address to use when sending
     the pr0bez */
  proxy->host.TargetSockAddr(&ss, &sslen);
  if (!route_dst(&ss, &rnfo))
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
    proxy->host.setNextHop(&rnfo.nexthop, 
			   sizeof(rnfo.nexthop));
  }
  proxy->host.setIfType(rnfo.ii.device_type);
  if (rnfo.ii.device_type == devt_ethernet)
    proxy->host.setSrcMACAddress(rnfo.ii.mac);
  
  /* Now lets send some probes to check IP ID algorithm ... */
  /* First we need a raw socket ... */
  if ((o.sendpref & PACKET_SEND_ETH) &&  proxy->host.ifType() == devt_ethernet) {
    if (!setTargetNextHopMAC(&proxy->host))
      fatal("%s: Failed to determine dst MAC address for Idle proxy", 
	    __func__);
    memcpy(proxy->eth.srcmac, proxy->host.SrcMACAddress(), 6);
    memcpy(proxy->eth.dstmac, proxy->host.NextHopMACAddress(), 6);
    proxy->eth.ethsd = eth_open_cached(proxy->host.deviceName());
    if (proxy->eth.ethsd == NULL)
      fatal("%s: Failed to open ethernet device (%s)", __func__, proxy->host.deviceName());
    proxy->rawsd = -1;
    proxy->ethptr = &proxy->eth;
  } else {
    if ((proxy->rawsd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0 )
      pfatal("socket troubles in %s", __func__);
    unblock_socket(proxy->rawsd);
    broadcast_socket(proxy->rawsd);
#ifndef WIN32
    sethdrinclude(proxy->rawsd);
#endif
    proxy->eth.ethsd = NULL;
    proxy->ethptr = NULL;
  }

/* Now for the pcap opening nonsense ... */
 /* Note that the snaplen is 152 = 64 byte max IPhdr + 24 byte max link_layer
  * header + 64 byte max TCP header. */
  proxy->pd = my_pcap_open_live(proxy->host.deviceName(), 152,  (o.spoofsource)? 1 : 0, 50);

  p = strdup(proxy->host.targetipstr());
  q = strdup(inet_ntoa(proxy->host.v4source()));
  Snprintf(filter, sizeof(filter), "tcp and src host %s and dst host %s and src port %hu", p, q, proxy->probe_port);
 free(p); 
 free(q);
 set_pcap_filter(proxy->host.deviceName(), proxy->pd,  filter);
/* Windows nonsense -- I am not sure why this is needed, but I should
   get rid of it at sometime */

 sequence_base = get_random_u32();

 /* Yahoo!  It is finally time to send our pr0beZ! */

  while(probes_sent < NUM_IPID_PROBES) {
    if (o.scan_delay) enforce_scan_delay(NULL);
    else if (probes_sent) usleep(30000);

    /* TH_SYN|TH_ACK is what the proxy will really be receiving from
       the target, and is more likely to get through firewalls.  But
       TH_SYN allows us to get a nonzero ACK back so we can associate
       a response with the exact request for timing purposes.  So I
       think I'll use TH_SYN, although it is a tough call. */
    /* We can't use decoys 'cause that would screw up the IP IDs */
    send_tcp_raw(proxy->rawsd, proxy->ethptr,
    		proxy->host.v4sourceip(), proxy->host.v4hostip(),
    		o.ttl, false,
    		o.ipoptions, o.ipoptionslen,
		 o.magic_port + probes_sent + 1, proxy->probe_port, 
		sequence_base + probes_sent + 1, ack, 0, TH_SYN|TH_ACK, 0, 0,
		(u8 *) "\x02\x04\x05\xb4",4,
		NULL, 0);
    gettimeofday(&probe_send_times[probes_sent], NULL);
    probes_sent++;

    /* Time to collect any replies */
    while(probes_returned < probes_sent && !timedout) {

      to_usec = (probes_sent == NUM_IPID_PROBES)? hardtimeout : 1000;
      ip = (struct ip *) readip_pcap(proxy->pd, &bytes, to_usec, &rcvdtime, NULL);

      gettimeofday(&tmptv, NULL);
      
      if (!ip) {
	if (probes_sent < NUM_IPID_PROBES)
	  break;
	if (TIMEVAL_SUBTRACT(tmptv, probe_send_times[probes_sent - 1]) >= hardtimeout) {
	  timedout = 1;
	}
	continue;
      } else if (TIMEVAL_SUBTRACT(tmptv, probe_send_times[probes_sent - 1]) >=
		 hardtimeout)  {      
	timedout = 1;
      }

      if (lastipid != 0 && ip->ip_id == lastipid) {
	continue; /* probably a duplicate */
      }
      lastipid = ip->ip_id;

      if (bytes < ( 4 * ip->ip_hl) + 14U)
	continue;

      if (ip->ip_p == IPPROTO_TCP) {
	tcp = ((struct tcp_hdr *) (((char *) ip) + 4 * ip->ip_hl));
	if (ntohs(tcp->th_dport) < (o.magic_port+1) || ntohs(tcp->th_dport) - o.magic_port > NUM_IPID_PROBES  || ntohs(tcp->th_sport) != proxy->probe_port || ((tcp->th_flags & TH_RST) == 0)) {
	  if (o.debugging > 1) error("Received unexpected response packet from %s during initial IP ID zombie testing", inet_ntoa(ip->ip_src));
	  continue;
	}
	
	seq_response_num = probes_returned;

	/* The stuff below only works when we send SYN packets instead of
	   SYN|ACK, but then are slightly less stealthy and have less chance
	   of sneaking through the firewall.  Plus SYN|ACK is what they will
	   be receiving back from the target */
	probes_returned++;
	ipids[seq_response_num] = (u16) ntohs(ip->ip_id);
	probe_returned[seq_response_num] = 1;
	adjust_timeouts2(&probe_send_times[seq_response_num], &rcvdtime, &(proxy->host.to));
      }
    }
  }

  /* Yeah!  We're done sending/receiving probes ... now lets ensure all of our responses are adjacent in the array */
  for(i=0,probes_returned=0; i < NUM_IPID_PROBES; i++) {
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

  proxy->seqclass = get_ipid_sequence(probes_returned, ipids, 0);
  switch(proxy->seqclass) {
  case IPID_SEQ_INCR:
  case IPID_SEQ_BROKEN_INCR:
    log_write(LOG_PLAIN, "Idle scan using zombie %s (%s:%hu); Class: %s\n", proxy->host.HostName(), proxy->host.targetipstr(), proxy->probe_port, ipidclass2ascii(proxy->seqclass));
    break;
  default:
    fatal("Idle scan zombie %s (%s) port %hu cannot be used because IP ID sequencability class is: %s.  Try another proxy.", proxy->host.HostName(), proxy->host.targetipstr(), proxy->probe_port, ipidclass2ascii(proxy->seqclass));
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
  if (first_target) {  
    for (probes_sent = 0; probes_sent < 4; probes_sent++) {  
      if (probes_sent) usleep(50000);
      send_tcp_raw(proxy->rawsd, proxy->ethptr,
      		first_target, proxy->host.v4hostip(), 
		o.ttl, false,
		o.ipoptions, o.ipoptionslen,
		o.magic_port, proxy->probe_port, 
		sequence_base + probes_sent + 1, ack, 0, TH_SYN|TH_ACK, 0, 0,
		(u8 *) "\x02\x04\x05\xb4",
		4, NULL, 0);

    }

    /* Sleep a little while to give packets time to reach their destination */
    usleep(300000);
    newipid = ipid_proxy_probe(proxy, NULL, NULL);
    if (newipid == -1)
      newipid = ipid_proxy_probe(proxy, NULL, NULL); /* OK, we'll give it one more try */

    if (newipid < 0) fatal("Your IP ID Zombie (%s; %s) is behaving strangely -- suddenly cannot obtain IP ID", proxy->host.HostName(), proxy->host.targetipstr());
      
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

  if (o.debugging > 1)
    log_write(LOG_STDOUT, 
	  "%s: tested/true %d/%d -- old grpsz/delay: %f/%d ",
	  __func__, testcount, realcount, proxy->current_groupsz, proxy->senddelay);
  else if (o.debugging && testcount != realcount) {
    error("%s: testcount: %d  realcount: %d -- old grpsz/delay: %f/%d", __func__, testcount, realcount, proxy->current_groupsz, proxy->senddelay);
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
      if (proxy->senddelay < 500) proxy->senddelay = 0;
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
			struct timeval *sent_time, struct timeval *rcv_time) 
{

#if 0 /* Testing code */
  int i;
  for(i=0; i < numports; i++)
    if (ports[i] == 22)
      return 1;
  return 0;
#endif

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

  if (seq == 0) seq = get_random_u32();

  memset(&end, 0, sizeof(end));
  memset(&latestchange, 0, sizeof(latestchange));
  gettimeofday(&start, NULL);
  if (sent_time) memset(sent_time, 0, sizeof(*sent_time));
  if (rcv_time) memset(rcv_time, 0, sizeof(*rcv_time));

  if (proxy->rawsd < 0) {
    if (!setTargetNextHopMAC(target))
      fatal("%s: Failed to determine dst MAC address for Idle proxy", 
	    __func__);
    memcpy(eth.srcmac, target->SrcMACAddress(), 6);
    memcpy(eth.dstmac, target->NextHopMACAddress(), 6);
    eth.ethsd = eth_open_cached(target->deviceName());
    if (eth.ethsd == NULL)
      fatal("%s: Failed to open ethernet device (%s)", __func__, target->deviceName());
  } else eth.ethsd = NULL;

  /* I start by sending out the SYN pr0bez */
  for(pr0be = 0; pr0be < numports; pr0be++) {
    if (o.scan_delay) enforce_scan_delay(NULL);
    else if (proxy->senddelay && pr0be > 0) usleep(proxy->senddelay);

    /* Maybe I should involve decoys in the picture at some point --
       but doing it the straightforward way (using the same decoys as
       we use in probing the proxy box is risky.  I'll have to think
       about this more. */
    send_tcp_raw(proxy->rawsd, eth.ethsd? &eth : NULL,
    		proxy->host.v4hostip(), target->v4hostip(),
		o.ttl, false,
		o.ipoptions, o.ipoptionslen,
		proxy->probe_port, ports[pr0be], seq, 0, 0, TH_SYN, 0, 0,
		(u8 *) "\x02\x04\x05\xb4", 4,
		o.extra_payload, o.extra_payload_length);
  }
  gettimeofday(&end, NULL);

  openports = -1;
  tries = 0;
  TIMEVAL_MSEC_ADD(probe_times[0], start, MAX(50, (target->to.srtt * 3/4) / 1000));
  TIMEVAL_MSEC_ADD(probe_times[1], start, target->to.srtt / 1000 );
  TIMEVAL_MSEC_ADD(probe_times[2], end, MAX(75, (2 * target->to.srtt + 
						   target->to.rttvar) / 1000));
  TIMEVAL_MSEC_ADD(probe_times[3], end, MIN(4000, (2 * target->to.srtt + 
						     (target->to.rttvar << 2 )) / 1000));

  do {
    if (tries == 2) dotry3 = (get_random_u8() > 200);
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
    if (o.debugging > 1) error("In preparation for idle scan probe try #%d, sleeping for %d usecs", tries, sleeptime);
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
  } while(tries++ < 3);

  if (proxyprobes_sent > proxyprobes_rcvd) {
    /* Uh-oh.  It looks like we lost at least one proxy probe packet */
    if (o.debugging) {
      error("%s: Sent %d probes; only %d responses.  Slowing scan.", __func__, proxyprobes_sent, proxyprobes_rcvd);
    }
    proxy->senddelay += 5000;
    proxy->senddelay = MIN(proxy->max_senddelay, proxy->senddelay);
    /* No group size should be greater than .5s of send delays */
    proxy->current_groupsz = MAX(proxy->min_groupsz, MIN(proxy->current_groupsz, 500000 / (proxy->senddelay+1)));
  } else {
    /* Yeah, we got as many responses as we sent probes.  This calls for a 
       very light timing acceleration ... */
    proxy->senddelay = (int) (proxy->senddelay * 0.95);
    if (proxy->senddelay < 500) proxy->senddelay = 0;
    proxy->current_groupsz = MAX(proxy->min_groupsz, MIN(proxy->current_groupsz, 500000 / (proxy->senddelay+1)));
  }

  if ((openports > 0) && (openports <= numports)) {
    /* Yeah, we found open ports... lets adjust the timing ... */
    if (o.debugging > 2) error("%s:  found %d open ports (out of %d) in %lu usecs", __func__, openports, numports, (unsigned long) TIMEVAL_SUBTRACT(latestchange, start));
    if (sent_time) *sent_time = start;
    if (rcv_time) *rcv_time = latestchange;
  }
  if (newipid > 0) proxy->latestid = newipid;
  if (eth.ethsd) { eth.ethsd = NULL; } /* don't need to close it due to caching */
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
    openports = idlescan_countopen2(proxy, target, ports, numports, sent_time,
				    rcv_time);
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
  } while(1);

  if (openports < 0 || openports > numports ) {
    /* Oh f*ck!!!! */
    fatal("Idle scan is unable to obtain meaningful results from proxy %s (%s).  I'm sorry it didn't work out.", proxy->host.HostName(), 
	  proxy->host.targetipstr());
  }

  if (o.debugging > 2) error("%s: %d ports found open out of %d, starting with %hu", __func__, openports, numports, ports[0]);

  return openports;
}

/* Recursively idle scans scans a group of ports using a depth-first
   divide-and-conquer strategy to find the open one(s) */

static int idle_treescan(struct idle_proxy_info *proxy, Target *target,
		 u16 *ports, int numports, int expectedopen) {

  int firstHalfSz = (numports + 1)/2;
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

  flatcount1 = idlescan_countopen(proxy, target, ports, firstHalfSz, 
				  &sentTime1, &rcvTime1);
  

  
  if (firstHalfSz > 1 && flatcount1 > 0) {
    /* A port appears open!  We dig down deeper to find it ... */
    deepcount1 = idle_treescan(proxy, target, ports, firstHalfSz, flatcount1);
    /* Now we assume deepcount1 is right, and adjust timing if flatcount1 was
       wrong */
    adjust_idle_timing(proxy, target, flatcount1, deepcount1);
  }

  /* I guess we had better do the second half too ... */

  flatcount2 = idlescan_countopen(proxy, target, ports + firstHalfSz, 
				  secondHalfSz, &sentTime2, &rcvTime2);
  
  if ((secondHalfSz) > 1 && flatcount2 > 0) {
    /* A port appears open!  We dig down deeper to find it ... */
    deepcount2 = idle_treescan(proxy, target, ports + firstHalfSz, 
			       secondHalfSz, flatcount2);
    /* Now we assume deepcount1 is right, and adjust timing if flatcount1 was
       wrong */
    adjust_idle_timing(proxy, target, flatcount2, deepcount2);
  }

  totalfound = (deepcount1 == -1)? flatcount1 : deepcount1;
  totalfound += (deepcount2 == -1)? flatcount2 : deepcount2;

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
      retrycount = idlescan_countopen(proxy, target, ports, firstHalfSz, NULL,
				      NULL);
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
	  target->ports.removePort(ports[0], IPPROTO_TCP);

      }
    }
    
    if (deepcount2 == -1) {
      retrycount = idlescan_countopen(proxy, target, ports + firstHalfSz, 
				      secondHalfSz, NULL, NULL);
      if (retrycount != flatcount2) {
	if (secondHalfSz > 1 && retrycount > 0) {	
	  retry2 = retrycount;
	  retrycount = idle_treescan(proxy, target, ports + firstHalfSz, 
				     secondHalfSz, retrycount);
	  adjust_idle_timing(proxy, target, retry2, retrycount);
	} else {
	  if (o.debugging)
	    error("Adjusting timing because my first scan of %d ports, starting with %hu found %d open, while second scan yeilded %d", secondHalfSz, ports[firstHalfSz], flatcount2, retrycount);
	  adjust_idle_timing(proxy, target, flatcount2, retrycount);
	}

	totalfound += retrycount - flatcount2;
	flatcount2 = retrycount;

	/* If our first count erroneously found and added an open port,
	   we must delete it */
	if (secondHalfSz == 1 && flatcount2 == 1 && retrycount == 0)
	  target->ports.removePort(ports[firstHalfSz], IPPROTO_TCP);


      }
    }
  }

  if (firstHalfSz == 1 && flatcount1 == 1) 
    target->ports.addPort(ports[0], IPPROTO_TCP, NULL, PORT_OPEN);
  
  if ((secondHalfSz == 1) && flatcount2 == 1) 
    target->ports.addPort(ports[firstHalfSz], IPPROTO_TCP, NULL, PORT_OPEN);
  return totalfound;

}



/* The very top-level idle scan function -- scans the given target
   host using the given proxy -- the proxy is cached so that you can keep
   calling this function with different targets */
void idle_scan(Target *target, u16 *portarray, int numports,
	       char *proxyName, const struct scan_lists * ports) {

  static char lastproxy[MAXHOSTNAMELEN + 1] = ""; /* The proxy used in any previous call */
  static struct idle_proxy_info proxy;
  int groupsz;
  int portidx = 0; /* Used for splitting the port array into chunks */
  int portsleft;
  time_t starttime;
  char scanname[128];
  Snprintf(scanname, sizeof(scanname), "idle scan against %s", target->NameIP());
  ScanProgressMeter SPM(scanname);

  if (numports == 0) return; /* nothing to scan for */
  if (!proxyName) fatal("idle scan requires a proxy host");

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
    initialize_idleproxy(&proxy, proxyName, target->v4hostip(), ports);
  }

  starttime = time(NULL);

  /* If we don't have timing infoz for the new target, we'll use values 
     derived from the proxy */
  if (target->to.srtt == -1 && target->to.rttvar == -1) {
    target->to.srtt = MAX(200000,2 * proxy.host.to.srtt);
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
     divide-and-counquer function to find the open ports */
  while(portidx < numports) {
    portsleft = numports - portidx;
    /* current_groupsz is doubled below because idle_subscan cuts in half */
    groupsz = MIN(portsleft, (int) (proxy.current_groupsz * 2));
    idle_treescan(&proxy, target, portarray + portidx, groupsz, -1);
    portidx += groupsz;
  }


  char additional_info[14];
  Snprintf(additional_info, sizeof(additional_info), "%d ports", numports);
  SPM.endTask(NULL, additional_info);

  /* Now we go through the ports which were not determined were scanned
     but not determined to be open, and add them in the "closed" state */
  for(portidx = 0; portidx < numports; portidx++) {
    if (target->ports.getPortEntry(portarray[portidx], IPPROTO_TCP) == NULL) {
      target->ports.addPort(portarray[portidx], IPPROTO_TCP, NULL,
	      PORT_CLOSEDFILTERED);
	  target->ports.setStateReason(portarray[portidx], IPPROTO_TCP, ER_NOIPIDCHANGE, 0, 0);
    } else 
      target->ports.setStateReason(portarray[portidx], IPPROTO_TCP, ER_IPIDCHANGE, 0, 0);
  }

  target->stopTimeOutClock(NULL);
  return;
}
