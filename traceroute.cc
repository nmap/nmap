/***************************************************************************
 * traceroute.cc -- Parallel multi-protocol traceroute feature             *
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
 * Many security scanner vendors already license Nmap technology such as   *
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


/*
 * Written by Eddie Bell <ejlbell@gmail.com> as part of SoC2006
 * A multi-protocol parallel traceroute implementation for nmap.
 *
 * For more information on how traceroutes work:
 * http://en.wikipedia.org/wiki/Traceroute
 *
 * Traceroute takes in a list of scanned targets and determines a valid
 * responsive port to trace to based on the scan results, scan protocol and 
 * various pieces of protocol data.
 *
 * Nmap first sends a probe to the target port, from the reply traceroute is able
 * to infer how many hops away the target is. Nmap starts the trace by sending 
 * a packet with a TTL equal to that of the hop distance guess. If it gets an 
 * ICMP_TTL_EXCEEDED message back it know the hop distance guess was under so
 * nmap will continue sending probes with incremental TTLs until it receives a
 * reply from the target host.
 *
 * Once a reply from the host is received nmap sets the TTL to one below the 
 * hop guess and continues to send probes with decremental TTLs until it reaches
 * TTL 0. Then we have a complete trace to the target. If nmap does not get a 
 * hop distance probe reply, the trace TTL starts at one and is incremented 
 * until it hits the target host.
 *
 * Forwards/Backwards tracing example
 *  hop guess:20
 *  send:20  --> ICMP_TTL_EXCEEDED
 *  send:21  --> ICMP_TTL_EXCEEDED
 *  send:22  --> Reply from host
 *  send:19  --> ICMP_TTL_EXCEEDED
 *  ....
 *  send:1   --> ICMP_TTL_EXCEEDED
 *
 * The forward/backwards tracing method seems a little convoluted at first but 
 * there is a reason for it. The first host traced in a Target group is
 * designated as the reference trace. All other traces 
 * (once they have reached their destination host)  are compared against the
 * reference trace. If a match is found the trace is ended prematurely and the 
 * remaining hops are assumed to be the same as the reference trace. This 
 * normally only happens in the lower TTls, which rarely change. On average nmap
 * sends 5 less packets per host. If nmap is tracing related hosts 
 * (EG. 1.2.3.0/24) it will send a lot less packets. Depending on the network 
 * topology it may only have to send a single packet to each host.
 *   
 * Nmap's traceroute employs a dynamic timing model similar to nmap's scanning engine
 * but a little more light weight. It keeps track of sent, received and dropped
 * packet, then adjusts timing parameters accordingly. The parameters are; number of
 * retransmissions, delay between each sent packet and the amount of time to wait 
 * for a reply. They are initially based on the timing level (-T0 to -T5). 
 * Traceroute also has to watch out for rate-limiting of ICMP TTL EXCEEDED
 * messages, sometimes there is nothing we can do and just have to settle with a
 * timedout hop.
 *
 * The output from each trace is consolidated to save space, XML logging and debug
 * mode ignore consolidation. There are two type of consolidation time-out and 
 * reference trace.
 *
 * Timed out
 *  23  ... 24 no response
 *
 * Reference trace
 *   Hops 1-10 are the same as for X.X.X.X
 *
 * Traceroute does not work with connect scans or idle scans and has trouble
 * with ICMP_TIMESTAMP and ICMP_ADDRESSMASK scans because so many host filter 
 * them out. The quickest seems to be SYN scan.
 *
 * Bugs
 * ----
 *  o The code, currently, only works with ipv4.
 *  o Should send both UDP and TCP hop distance probes no matter what the
 *    scan protocol
 */

#include "traceroute.h"
#include "NmapOps.h"
#include "NmapOutputTable.h"
#include "nmap_tty.h"
#include "nmap_dns.h"
#include "osscan2.h"
#include "protocols.h"
#include "timing.h"
#include "utils.h"
#include <algorithm>
#include <stdlib.h>

using namespace std;
extern NmapOps o;

static void enforce_scan_delay (struct timeval *, int);
static char *hostStr (u32 ip);

/* Each target group has a single reference trace. All
 * other traces are compared to it and if a match is
 * found the trace is ended prematurely and the 
 * remaining hops are assumed to match the reference
 * trace */
unsigned long commonPath[MAX_TTL + 1];

Traceroute::Traceroute (const char *device_name, devtype type) {
    fd = -1;
    ethsd = NULL;
    hops = NULL;
    pd = NULL;
    total_size = 0;
    memset(&ref_ipaddr, '\0', sizeof(struct in_addr));

    if(type == devt_loopback) 
        return;

    /* open various socks to send and read from on windows and 
     * unix */
    if ((o.sendpref & PACKET_SEND_ETH) && type == devt_ethernet) {
        /* We'll send ethernet packets with dnet */
        ethsd = eth_open_cached (device_name);
        if (ethsd == NULL)
            fatal ("dnet: Failed to open device %s", device_name);
    } else {
        if ((fd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
            pfatal ("Traceroute: socket troubles");
        broadcast_socket (fd);
#ifndef WIN32
        sethdrinclude (fd);
#endif
    }

    /* rely on each group using the same device */
    pd = my_pcap_open_live (device_name, 100, o.spoofsource ? 1 : 0, 2);

    scaninfo.initial_proto = IPPROTO_IP;
    scaninfo.open_response = 0;
    scaninfo.open_state = PORT_OPEN;
    scaninfo.closed_state = PORT_CLOSED;

    /* Set up which protocols, tcp flags and responsive
     * states to use with the current scan type.
     *
     * Horribly messy but it is better then peppering
     * the nmap source code with references to traceroute */
    if (o.synscan) {
        scaninfo.scan_flags = TH_SYN;
        scaninfo.open_response = TH_SYN | TH_ACK;
        scaninfo.closed_response = TH_RST;
    } else if (o.ackscan) {
        scaninfo.scan_flags = TH_ACK;
        scaninfo.open_response = TH_RST;
        scaninfo.closed_response = TH_RST;
        scaninfo.open_state = PORT_UNFILTERED;
        scaninfo.closed_state = PORT_UNFILTERED;
    } else if (o.finscan) {
        scaninfo.scan_flags = TH_FIN;
        scaninfo.closed_response = TH_RST;
    } else if (o.xmasscan) {
        scaninfo.scan_flags = TH_FIN | TH_URG | TH_PUSH;
        scaninfo.closed_response = TH_RST;
    } else if (o.nullscan) {
        scaninfo.scan_flags = 0;
        scaninfo.closed_response = TH_RST;
    } else if (o.windowscan) {
        scaninfo.scan_flags = TH_ACK;
        scaninfo.open_response = TH_RST;
        scaninfo.closed_response = TH_RST;
    } else if (o.maimonscan) {
        scaninfo.scan_flags = TH_FIN | TH_ACK;
        scaninfo.open_response = TH_RST;
        scaninfo.closed_response = TH_RST;
    }

    if (o.udpscan)
        scaninfo.initial_proto = IPPROTO_UDP;
    if (o.synscan || o.finscan || o.xmasscan || o.nullscan ||
        o.ackscan || o.windowscan || o.maimonscan)
        scaninfo.initial_proto = IPPROTO_TCP;

    if(o.pingscan) {
        scaninfo.open_state = HOST_UP;
        if (o.pingtype & PINGTYPE_TCP_USE_SYN) {
            scaninfo.scan_flags = TH_SYN;
            scaninfo.open_response = TH_SYN | TH_ACK;
            scaninfo.closed_response = TH_RST;
            scaninfo.initial_proto = IPPROTO_TCP;
        } else if (o.pingtype & PINGTYPE_TCP_USE_ACK) {
            scaninfo.scan_flags = TH_ACK;
            scaninfo.open_response = TH_RST;
            scaninfo.closed_response = TH_RST;
            scaninfo.initial_proto = IPPROTO_TCP;
        } else if (o.pingtype & PINGTYPE_UDP) {
            scaninfo.initial_proto = IPPROTO_UDP;
        } else if (o.pingtype & PINGTYPE_ICMP_PING) {
            scaninfo.initial_proto = IPPROTO_ICMP;
            scaninfo.icmp_type = ICMP_ECHO;
        } else if (o.pingtype & PINGTYPE_ICMP_TS) {
            scaninfo.initial_proto = IPPROTO_ICMP;
            scaninfo.icmp_type = ICMP_TIMESTAMP;
        } else if(o.pingtype & PINGTYPE_ICMP_MASK) {
            scaninfo.initial_proto = IPPROTO_ICMP;
            scaninfo.icmp_type = ICMP_ADDRESS;
        }
    }

    if (o.scanflags != -1)
        scaninfo.scan_flags = o.scanflags;
    memset (commonPath, 0, sizeof (commonPath));
}

Traceroute::~Traceroute () {
    map < u32, TraceGroup * >::iterator it = TraceGroups.begin ();
    while ((--total_size) >= 0) 
        delete(hops[total_size]);
    if(hops)
        free(hops);
    for (; it != TraceGroups.end (); ++it)
        delete (it->second);
    if (ethsd)
        ethsd = NULL;
    if (fd != -1)
        close (fd);
    if(pd)
        pcap_close (pd);
}

/* get an open or closed port from the portlist. Traceroute requires a positive response, 
 * positive responses are generated by different port states depending on the type of scan */
inline int
Traceroute::getTracePort (u8 proto, Target * t) {
    u16 open_port = 1;
    u16 closed_port = 1;
    u16 filtered_port = 1;
    u16 state = 0;
    u16 port = 0;

    /* Use the first specified port for ping traceroutes */
    if (o.pingscan) {
        if (o.pingtype & PINGTYPE_TCP_USE_SYN)
            return o.ping_synprobes[0];
        else if (o.pingtype & PINGTYPE_TCP_USE_ACK)
            return o.ping_ackprobes[0];
        else if (o.pingtype & PINGTYPE_UDP)
            return o.ping_udpprobes[0];
        else
            return 0;
    }

    if (proto == IPPROTO_TCP) {
        /* can't use filtered ports for tcp */
        filtered_port = 0;
        open_port = (!scaninfo.open_response) ? 0 : 1;
    }

    /* First we try to find an open port, if not we try to find a closed
     * port and lastly we try to find a filtered port */
    if (open_port && t->ports.getStateCounts (proto, scaninfo.open_state))
        state = scaninfo.open_state;
    else if (closed_port && t->ports.getStateCounts (proto, scaninfo.closed_state))
        state = scaninfo.closed_state;
    else if (filtered_port && t->ports.getStateCounts (proto, PORT_FILTERED)) {
        state = PORT_FILTERED;
        if (o.verbose)
            log_write (LOG_PLAIN, "%s: only filtered %s available, results may be incorrect\n",
                       t->targetipstr (), o.ipprotscan ? "protocols" : "ports");
    } else {
        return -1;
    }

    port = t->ports.nextPort (NULL, proto, state)->portno;

    /* If this is a protocol scan traceroute and we are using
     * one of the major protocols, set up the required information
     * so we include the correct protocol headers */
    if (proto == IPPROTO_IP) {
        if (port == IPPROTO_TCP) {
            scaninfo.initial_proto = IPPROTO_TCP;
            scaninfo.scan_flags = TH_ACK;
            scaninfo.open_response = TH_RST;
            scaninfo.closed_response = TH_RST;
        } else if (port == IPPROTO_UDP) {
            scaninfo.initial_proto = IPPROTO_UDP;
        } else if (port == IPPROTO_ICMP) {
            scaninfo.initial_proto = IPPROTO_ICMP;
            scaninfo.icmp_type = ICMP_ECHO;
        }
    }
    return port;
}

/* finite state machine that reads all incoming packets
 * and attempts to match them with sent probes */
inline bool
Traceroute::readTraceResponses () {
    struct ip *ip = NULL;
    struct ip *ip2 = NULL;
    struct icmp *icmp = NULL;
    struct icmp *icmp2 = NULL;
    struct tcp_hdr *tcp = NULL;
    struct udp_hdr *udp = NULL;
    struct link_header linkhdr;
    unsigned int bytes;
    struct timeval rcvdtime;
    TraceProbe *tp = NULL;
    TraceGroup *tg = NULL;
    u16 sport;
    u32 ipaddr;

    /* Got to look into readip_pcap's timeout value, perhaps make it dynamic */
    ip = (struct ip *) readip_pcap (pd, &bytes, 10000, &rcvdtime, &linkhdr);

    if (ip == NULL)
        return finished ();
    if ((unsigned) ip->ip_hl * 4 + 20 > bytes)
        return finished ();

    switch (ip->ip_p) {
    case IPPROTO_ICMP:
        icmp = (struct icmp *) ((char *) ip + 4 * ip->ip_hl);
        ipaddr = ip->ip_src.s_addr;
        sport = ntohs(icmp->icmp_id);

        /* Process ICMP replies that encapsulate our original probe */
        if (icmp->icmp_type == ICMP_DEST_UNREACH || icmp->icmp_type == ICMP_TIME_EXCEEDED) {
            ip2 = (struct ip *) (((char *) ip) + 4 * ip->ip_hl + 8);
            if (ip2->ip_p == IPPROTO_TCP) {
                tcp = (struct tcp_hdr *) ((u8 *) ip2 + ip2->ip_hl * 4);
                sport = htons (tcp->th_sport);
            } else if (ip2->ip_p == IPPROTO_UDP) {
                udp = (struct udp_hdr *) ((u8 *) ip2 + ip2->ip_hl * 4);
                sport = htons (udp->uh_sport);
            } else if (ip2->ip_p == IPPROTO_ICMP) {
                icmp2 = (struct icmp *) ((char *) ip2 + 4 * ip2->ip_hl);
                sport = ntohs(icmp2->icmp_id);
            } else {
                sport = htons(ip2->ip_id);
            }
            ipaddr = ip2->ip_dst.s_addr;
        }

        if (TraceGroups.find (ipaddr) != TraceGroups.end ())
            tg = TraceGroups[ipaddr];
        else
            break;

        if (tg->TraceProbes.find (sport) != tg->TraceProbes.end ())
            tp = tg->TraceProbes[sport];
        else
            break;

        if (tp->ipreplysrc.s_addr)
            break;

        if ((tg->proto == IPPROTO_UDP && ip2->ip_p == IPPROTO_UDP) ||
            (icmp->icmp_type == ICMP_DEST_UNREACH)) {
            switch (icmp->icmp_code) {
                /* reply from a closed port */
            case ICMP_PORT_UNREACH:
                /* replies from a filtered port */
            case ICMP_HOST_UNREACH:
            case ICMP_PROT_UNREACH:
            case ICMP_NET_ANO:
            case ICMP_HOST_ANO:
            case ICMP_PKT_FILTERED:
                if (tp->probeType () == PROBE_TTL) {
                   tg->setHopDistance (o.ttl - ip2->ip_ttl, 0);
                   tg->start_ttl = tg->ttl = tg->hopDistance;
                } else {
                    tg->gotReply = true;
                    if (tg->start_ttl < tg->ttl)
                        tg->ttl = tg->start_ttl + 1;
                }
            }
        }
        /* icmp ping scan replies */
        else if (tg->proto == IPPROTO_ICMP && (icmp->icmp_type == ICMP_ECHOREPLY ||
                icmp->icmp_type == ICMP_ADDRESSREPLY || icmp->icmp_type == ICMP_TIMESTAMPREPLY)) {
            if (tp->probeType () == PROBE_TTL) {
                tg->setHopDistance (get_initial_ttl_guess (ip->ip_ttl), ip->ip_ttl);
                tg->start_ttl = tg->ttl = tg->hopDistance;
            } else {
                tg->gotReply = true;
                if (tg->start_ttl < tg->ttl)
                    tg->ttl = tg->start_ttl + 1;
            }
        }

        if (tp->timing.getState () == P_TIMEDOUT)
            tp->timing.setState (P_OK);
        else
            tg->decRemaining ();

        tg->repliedPackets++;
        tg->consecTimeouts = 0;
        tp->timing.adjustTimeouts (&rcvdtime, tg->scanDelay);
        tp->ipreplysrc.s_addr = ip->ip_src.s_addr;

        /* check to see if this hop is in the referece trace. If 
         * it is then we stop tracing this target and assume
         * all subsequent hops match the common path */
        if (commonPath[tp->ttl] == tp->ipreplysrc.s_addr &&
            tp->ttl > 1 && tg->gotReply && tg->getState () != G_FINISH) {
            tg->setState (G_FINISH);
            tg->consolidation_start = tp->ttl+1;
            break;
        } else if (commonPath[tp->ttl] == 0) {
            commonPath[tp->ttl] = tp->ipreplysrc.s_addr;
	    /* remember which host is the reference trace */
	    if(tp->ttl == 1)
		ref_ipaddr.s_addr = tg->ipdst;
	}
        break;
    case IPPROTO_TCP:
        if ((unsigned) ip->ip_hl * 4 + 20 > bytes)
            break;

        tcp = (struct tcp_hdr *) ((char *) ip + 4 * ip->ip_hl);

        if (TraceGroups.find (ip->ip_src.s_addr) != TraceGroups.end ())
            tg = TraceGroups[ip->ip_src.s_addr];
        else
            break;

        if (tg->TraceProbes.find (htons (tcp->th_dport)) != tg->TraceProbes.end ())
            tp = tg->TraceProbes[htons (tcp->th_dport)];
        else
            break;

        /* already got the tcp packet for this group,
         * could be a left over rst or syn-ack */
        if (tp->ipreplysrc.s_addr)
            break;

        /* We have reached the destination host and the 
         * trace can stop for this target */
        if (tcp->th_flags & scaninfo.open_response || tcp->th_flags & scaninfo.closed_response) {

            /* We might have got a late reply */
            if (tp->timing.getState () == P_TIMEDOUT)
                tp->timing.setState (P_OK);
            else
                tg->decRemaining ();

            tp->timing.recvTime = rcvdtime;
            tp->ipreplysrc = ip->ip_src;
            tg->repliedPackets++;
            /* The probe was the reply from a ttl guess */
            if (tp->probeType () == PROBE_TTL) {
                tg->setHopDistance (get_initial_ttl_guess (ip->ip_ttl), ip->ip_ttl);
                tg->start_ttl = tg->ttl = tg->hopDistance;
            } else {
                tg->gotReply = true;
                if (tg->start_ttl < tg->ttl)
                    tg->ttl = tg->start_ttl + 1;
            }
        }
        break;
    case IPPROTO_UDP:
        if ((unsigned) ip->ip_hl * 4 + 8 > bytes)
            break;
        udp = (udp_hdr *) ((u8 *) ip + ip->ip_hl * 4);

        if (TraceGroups.find (ip->ip_src.s_addr) != TraceGroups.end ())
            tg = TraceGroups[ip->ip_src.s_addr];
        else
            break;

        if (tg->TraceProbes.find (htons (udp->uh_dport)) != tg->TraceProbes.end ())
            tp = tg->TraceProbes[htons (udp->uh_dport)];
        else
            break;

        if (tp->ipreplysrc.s_addr)
            break;

        /* We might have got a late reply */
        if (tp->timing.getState () == P_TIMEDOUT)
            tp->timing.setState (P_OK);
        else
            tg->decRemaining ();

        tp->timing.recvTime = rcvdtime;
        tp->ipreplysrc.s_addr = ip->ip_src.s_addr;
        tg->repliedPackets++;

        if (tp->probeType () == PROBE_TTL) {
            tg->setHopDistance (get_initial_ttl_guess (ip->ip_ttl), ip->ip_ttl);
            tg->setState (G_OK);
            tg->start_ttl = tg->ttl = tg->hopDistance;
        } else {
            tg->gotReply = true;
            if (tg->start_ttl < tg->ttl)
                tg->ttl = tg->start_ttl + 1;
        }
        break;
    default:
        ;
    }
    return finished ();
}

/* Estimate how many hops away a host is by actively probing it.
 *
 * If the scan protocol isn't udp we guesstimate how many hops away
 * the target is by sending a probe to an open or closed port and
 * calculating a possible hop distance based on the returned ttl
 *
 * If the scan protocol is udp then we send a probe to a closed,
 * filtered or open port. Closed ports are more accurate because
 * we can exactly determine the hop distance based on the packet
 * return in the icmp port unreachable's payload. Open ports use
 * the same estimation method as tcp probes. Filtered ports are
 * only used as a last resort, although the hop distance guess is
 * accurate, the filtered response may not be from the destination
 * target, it may be from a node filtering the target */
inline void
Traceroute::sendTTLProbes (vector < Target * >&Targets, vector < Target * >&valid_targets) {
    Target *t = NULL;
    long dport = 0;
    u16 sport = 0;
    u8 proto;
    TraceProbe *tp;
    TraceGroup *tg = NULL;
    vector < Target * >::iterator it = Targets.begin ();

    for (; it != Targets.end (); ++it) {
        t = *it;
        proto = scaninfo.initial_proto;

        /* No point in tracing directly connected nodes */
        if (t->directlyConnected ())
            continue;

        /* This node has already been sent a hop distance probe */
        if (TraceGroups.find (t->v4hostip ()->s_addr) != TraceGroups.end ()) {
            valid_targets.push_back (t);
            continue;
        }

        /* Determine active port to probe */
        if ((dport = getTracePort (proto, t)) == -1) {
            /* If we could not find a responsive tcp port then try
             * to find a responsive udp port */
            if (o.udpscan && proto != IPPROTO_UDP) {
                proto = IPPROTO_UDP;
                dport = getTracePort (proto, t);
            }
        }

        if (dport == -1) {
            if (o.verbose > 1)
                log_write (LOG_STDOUT, "%s: no responsive %s\n",
                           t->targetipstr (), o.ipprotscan ? "protocols" : "ports");
            continue;
        }

        /* If this is a protocol scan getTracePort() returns 
         * a protocol number for so we need a random destination 
         * port */
        if (o.ipprotscan) {
            proto = dport;
            dport = get_random_u16 ();
            scaninfo.initial_proto = IPPROTO_IP;
        }

        /* start off with a random source port and increment 
         * it for each probes sent. The source port is the
         * distinguishing value used to identify each probe */
        sport = get_random_u16 ();
        tg = new TraceGroup (t->v4hostip ()->s_addr, sport, dport, proto);
        tg->src_mac_addr = t->SrcMACAddress ();
        tg->nxt_mac_addr = t->NextHopMACAddress ();
        tg->sport++;
        TraceGroups[tg->ipdst] = tg;

        /* OS fingerprint engine may already have the distance so
         * we don't need to calculate it */
        if (t->distance != -1) {
            tg->setHopDistance (0, t->distance);
	    } else {
            tp = new TraceProbe (proto, t->v4hostip ()->s_addr,
                                 t->v4sourceip ()->s_addr, sport, dport);
            tp->setProbeType (PROBE_TTL);
            tp->ttl = o.ttl;
            tg->TraceProbes[sport] = tp;
            tg->incRemaining ();
            sendProbe (tp);
        }
        valid_targets.push_back (t);
    }
}

/* Send a single traceprobe object */
int
Traceroute::sendProbe (TraceProbe * tp) {
    u8 *tcpopts = NULL;
    int tcpoptslen = 0;
    u32 ack = 0;
    u8 *packet = NULL;
    u32 packetlen = 0;
    TraceGroup *tg = NULL;
    int decoy = 0;
    struct in_addr source;
    struct eth_nfo eth;
    struct eth_nfo *ethptr = NULL;

    if (scaninfo.scan_flags & TH_ACK)
        ack = rand ();
    if (scaninfo.scan_flags & TH_SYN) {
        tcpopts = (u8 *) "\x02\x04\x05\xb4";
        tcpoptslen = 4;
    }

    if (TraceGroups.find (tp->ipdst.s_addr) == TraceGroups.end ())
        return -1;
    tg = TraceGroups[tp->ipdst.s_addr];

    /* required to send raw packets in windows */
    if (ethsd) {
        memcpy (eth.srcmac, tg->src_mac_addr, 6);
        memcpy (eth.dstmac, tg->nxt_mac_addr, 6);
        eth.ethsd = ethsd;
        eth.devname[0] = '\0';
        ethptr = &eth;
    }

    if (tg->TraceProbes.find (tp->sport) == tg->TraceProbes.end ()) {
        tg->nextTTL ();

        if (tg->ttl > MAX_TTL) {
            tg->setState (G_ALIVE_TTL);
            return -1;
        }
        if (!tg->ttl || tg->gotReply && tg->noDistProbe) {
            tg->setState (G_FINISH);
            return 0;
        }
        tg->sport++;
        tp->ttl = tg->ttl;
        tp->dport = tg->dport;
        tg->incRemaining ();
    } else {
        /* this probe is a retransmission */
        tp->timing.setState (P_OK);
    }

    tg->TraceProbes[tp->sport] = tp;

    for (decoy = 0; decoy < o.numdecoys; decoy++) {
        enforce_scan_delay (&tp->timing.sendTime, tg->scanDelay);

        if (decoy == o.decoyturn)
            source = tp->ipsrc;
        else
            source = o.decoys[decoy];

        switch (tp->proto) {
        case IPPROTO_TCP:
            packet = build_tcp_raw (&source, &tp->ipdst, tp->ttl, get_random_u16 (),
                                    get_random_u8 (), 0, NULL, 0, tp->sport, tp->dport,
                                    get_random_u32 (), ack, 0, scaninfo.scan_flags,
                                    get_random_u16 (), 0, tcpopts, tcpoptslen,
                                    o.extra_payload, o.extra_payload_length, &packetlen);
            break;
        case IPPROTO_UDP:
            packet = build_udp_raw (&source, &tp->ipdst, tp->ttl, get_random_u16 (),
                                    get_random_u8 (), false,
                                    NULL, 0, tp->sport,
                                    tp->dport, o.extra_payload, o.extra_payload_length, &packetlen);
            break;
        case IPPROTO_ICMP:
            packet = build_icmp_raw (&source, &tp->ipdst, tp->ttl, 0, 0, false,
                                     NULL, 0, get_random_u16 (), tp->sport, scaninfo.icmp_type, 0,
                                     o.extra_payload, o.extra_payload_length, &packetlen);
            break;
        default:
            packet = build_ip_raw (&source, &tp->ipdst, tp->proto, tp->ttl, tp->sport,
                                   get_random_u8 (), false, NULL, 0, o.extra_payload,
                                   o.extra_payload_length, &packetlen);
        }
        send_ip_packet (fd, ethptr, packet, packetlen);
        free (packet);
    }
    return 0;
}

/* true if all groups have finished or failed */
bool
Traceroute::finished () {
    map < u32, TraceGroup * >::iterator it = TraceGroups.begin ();
    for (; it != TraceGroups.end (); ++it) {
        if (it->second->getState () == G_OK || it->second->getRemaining ())
            return false;
    }
    return true;
}

/* Main parallel send and recv loop */
void
Traceroute::trace (vector < Target * >&Targets) {
    map < u32, TraceGroup * >::iterator it;
    vector < Target * >::iterator targ;
    vector < Target * >valid_targets;
    vector < Target * >reference;
    vector < TraceProbe * >retrans_probes;
    vector < TraceGroup * >::size_type pcount;
    TraceProbe *tp = NULL;
    TraceGroup *tg = NULL;
    Target *t = NULL;
    ScanProgressMeter *SPM;
    u16 total_size, total_complete;

    if (o.af () == AF_INET6) {
        error ("Traceroute does not support ipv6\n");
        return;
    }

    /* perform the reference trace first */
    if (Targets.size () > 1) {
        o.current_scantype = TRACEROUTE;
        for (targ = Targets.begin (); targ != Targets.end (); ++targ) {
            reference.push_back (*targ);
            sendTTLProbes (reference, valid_targets);
            if (valid_targets.size ()) {
                o.current_scantype = REF_TRACEROUTE;
                this->trace (valid_targets);
                o.current_scantype = TRACEROUTE;
                break;
            }
        }
    }

    /* guess hop distance to targets. valid_targets
     * is populated with all Target object that are
     * legitimate to trace to */
    sendTTLProbes (Targets, valid_targets);

    if (!valid_targets.size())
        return;

    SPM = new ScanProgressMeter ("Traceroute");

    while (!readTraceResponses ()) {
        for (targ = valid_targets.begin (); targ != valid_targets.end (); ++targ) {
            t = *targ;
            tg = TraceGroups[t->v4host ().s_addr];

            /* Check for any timedout probes and 
             * retransmit them. If too many probes
             * are outstanding we wait for replies or
             * timeouts before sending any more */
            if (tg->getRemaining ()) {
                tg->retransmissions (retrans_probes);
                for (pcount = 0; pcount < retrans_probes.size (); pcount++)
                    sendProbe (retrans_probes[pcount]);
                retrans_probes.clear ();
                /* Max number of packets outstanding is 2 if we don't have a reply yet
                 * otherwise it is equal to o.timing_level. If the timing level it 0 
                 * it is equal to 1 */
                if (tg->getRemaining () >=
                    (tg->gotReply ? (!o.timing_level ? 1 : o.timing_level) : 2))
                    continue;
            }
            if (tg->getState () != G_OK || !tg->hopDistance)
                continue;

            tp = new TraceProbe (tg->proto, t->v4hostip ()->s_addr,
                                 t->v4sourceip ()->s_addr, tg->sport, 0);
            sendProbe (tp);
        }

        if (!keyWasPressed ())
            continue;

        total_size = total_complete = 0;
        for (it = TraceGroups.begin (); it != TraceGroups.end (); ++it) {
            total_complete += it->second->size ();
            total_size += it->second->hopDistance;
        }

        if (!total_size)
            continue;

        if (total_size < total_complete)
            swap (total_complete, total_size);
        SPM->printStats (MIN ((double) total_complete / total_size, 0.99), NULL);
    }
    SPM->endTask(NULL, NULL);
    delete (SPM);
  }

/* Resolves traceroute hops through nmaps
 * parallel caching rdns infrastructure.
 * The <hops> class variable should be NULL and needs
 * freeing after the hostnames are finished 
 * with 
 *
 * N.B TraceProbes contain pointers into the Target
 * structure, if it is free'ed prematurely something
 * nasty will happen */
void Traceroute::resolveHops () {
    map<u32, TraceGroup *>::iterator tg_iter;
    map<u16, TraceProbe *>::iterator tp_iter;
    int count = 0;
    struct sockaddr_storage ss;
    struct sockaddr_in *sin = (struct sockaddr_in *) &ss;
  
    if(o.noresolve)
        return;

    assert(hops == NULL);

    memset(&ss, '\0', sizeof(ss));
    sin->sin_family = o.af();

    for(tg_iter = TraceGroups.begin(); tg_iter != TraceGroups.end(); ++tg_iter) 
        total_size += tg_iter->second->size();
    if(!total_size)
        return;
    hops = (Target **) safe_zalloc(sizeof(Target *) * total_size);

    /* Move hop IP address to Target structures and point TraceProbes to
     * Targets hostname */
    for(tg_iter = TraceGroups.begin(); tg_iter != TraceGroups.end(); ++tg_iter) {
        tp_iter = tg_iter->second->TraceProbes.begin();
        for(; tp_iter != tg_iter->second->TraceProbes.end(); ++tp_iter) {
            if(tp_iter->second->ipreplysrc.s_addr && tp_iter->second->probeType() != PROBE_TTL) {
                sin->sin_addr = tp_iter->second->ipreplysrc;
                hops[count] = new Target();
                hops[count]->setTargetSockAddr(&ss, sizeof(ss));
                hops[count]->flags = HOST_UP;
                tp_iter->second->hostname = &hops[count]->hostname; 
                count++;
            }
        }
    }
    /* resolve all hops in this group at onces */
    nmap_mass_rdns(hops, count);
}

void
Traceroute::addConsolidationMessage(NmapOutputTable *Tbl, unsigned short row_count, unsigned short ttl) {
	char mbuf[64];
	int len;

	assert(ref_ipaddr.s_addr);
	char *ip = inet_ntoa(ref_ipaddr);

	if(ttl == 1)
		len = Snprintf(mbuf, 64, "Hop 1 is the same as for %s", ip);
	else
		len = Snprintf(mbuf, 64, "Hops 1-%d are the same as for %s", ttl, ip);

	assert(len);
	Tbl->addItem(row_count, HOP_COL, true, "-", 1);
	Tbl->addItem(row_count, RTT_COL, true, true, mbuf, len);
}

/* print a trace in plain text format */
void
Traceroute::outputTarget (Target * t) {
    map < u16, TraceProbe * >::const_iterator it;
    map < u16, TraceProbe * >::size_type ttl_count;
    map < u16, TraceProbe * >sortedProbes;
    TraceProbe *tp = NULL;
    TraceGroup *tg = NULL;
    NmapOutputTable *Tbl = NULL;

    struct protoent *proto;
    bool last_consolidation = false;
    bool common_consolidation = false;
    char row_count = 0;
    char timebuf[16];
    u8 consol_count = 0;

    if ((TraceGroups.find (t->v4host ().s_addr)) == TraceGroups.end ())
        return;
    tg = TraceGroups[t->v4host ().s_addr];

    /* sort into ttl order */
    for (it = tg->TraceProbes.begin (); it != tg->TraceProbes.end (); ++it)
        sortedProbes[it->second->ttl] = it->second;
    sortedProbes.swap (tg->TraceProbes);

    /* clean up and consolidate traces */
    tg->consolidateHops ();

    this->outputXMLTrace(tg);

    /* table headers */
    Tbl = new NmapOutputTable (tg->hopDistance+1, 3);
    Tbl->addItem (row_count, HOP_COL, false, "HOP", 3);
    Tbl->addItem (row_count, RTT_COL, false, "RTT", 3);
    Tbl->addItem (row_count, HOST_COL, false, "ADDRESS", 7);

    for (ttl_count = 1; ttl_count <= tg->hopDistance; ttl_count++) {
	
	assert(row_count <= tg->hopDistance);

        /* consolidate hops based on the reference trace (commonPath)  */
        if(commonPath[ttl_count] && ttl_count <= tg->consolidation_start) { 
            /* do not consolidate in debug mode */
            if(o.debugging) {
                row_count++;
                Tbl->addItemFormatted(row_count, HOP_COL, false, "%d", ttl_count);
                Tbl->addItemFormatted(row_count, RTT_COL, false, "--");
                Tbl->addItemFormatted(row_count, HOST_COL, false, "%s", hostStr(commonPath[ttl_count]));
            } else if(!common_consolidation) {
                row_count++;
                common_consolidation = true;
            }
        }

 	/* here we print the final hop for a trace that is fully consolidated */
        if ((it = tg->TraceProbes.find (ttl_count)) == tg->TraceProbes.end ()) {
		if (common_consolidation && ttl_count == tg->hopDistance) {
			if(ttl_count-2 == 1) {
				Tbl->addItemFormatted(row_count, RTT_COL, false, "--");
				Tbl->addItemFormatted(row_count, HOST_COL,false,  "%s", hostStr(commonPath[ttl_count-2]));
			} else {
				addConsolidationMessage(Tbl, row_count, ttl_count-2);
			}
			common_consolidation = false;
			break;
		}
		continue;
	}
        /* Here we consolidate the probe that first matched the common path */
        if (ttl_count < tg->consolidation_start) 
              continue;

        tp = tg->TraceProbes[ttl_count];

        /* end of reference trace consolidation */
        if(common_consolidation) {
            if(ttl_count-1 == 1) {
                Tbl->addItemFormatted(row_count, RTT_COL, false, "--", ttl_count-1);
                Tbl->addItemFormatted(row_count, HOST_COL,false,  "%s", hostStr(commonPath[ttl_count-1]));
            } else {
		addConsolidationMessage(Tbl, row_count, ttl_count-1);
	    }
            common_consolidation = false;
        }

        row_count++;

        /* timeout consolidation */
        if(tp->timing.consolidated) {
            consol_count++;
            if(!last_consolidation) {
                last_consolidation = true;
                Tbl->addItemFormatted(row_count, HOP_COL, false, "%d", tp->ttl);
            }
            else if(tg->getState() == G_DEAD_TTL && ttl_count == tg->hopDistance) 
               Tbl->addItem (row_count, RTT_COL, false, "... 50");
            row_count--;
        } else if(!tp->timing.consolidated && last_consolidation) { 
	    Tbl->addItem(row_count, HOST_COL, false, "no response", 11);
            if(consol_count>1) 
                Tbl->addItemFormatted(row_count, RTT_COL, false, "... %d", tp->ttl-1);
            else
                Tbl->addItemFormatted(row_count, RTT_COL, false, "...");

            row_count++;
            last_consolidation = false;
            consol_count = 0;
        }

        /* normal hop output (rtt, ip and hostname) */
        if (!tp->timing.consolidated && !last_consolidation) {
            Snprintf(timebuf, 16, "%.2f", (float) 
            TIMEVAL_SUBTRACT (tp->timing.recvTime, tp->timing.sendTime) / 1000);
            Tbl->addItemFormatted (row_count, HOP_COL, false, "%d", tp->ttl);
        if (tp->timing.getState () != P_TIMEDOUT) {
            Tbl->addItem (row_count, RTT_COL, true, timebuf);
            Tbl->addItem (row_count, HOST_COL, true, tp->nameIP ());
        } else 
           Tbl->addItemFormatted (row_count, RTT_COL, false, "...");
    }

    }

    /* Traceroute header and footer */
    proto = nmap_getprotbynum(htons(tg->proto));
    if(o.ipprotscan || (o.pingscan && !(o.pingtype & PINGTYPE_TCP || o.pingtype & PINGTYPE_UDP))) 
        log_write(LOG_PLAIN, "\nTRACEROUTE (using proto %d/%s)\n", tg->proto, proto?proto->p_name:"unknown");
    else 
        log_write(LOG_PLAIN, "\nTRACEROUTE (using port %d/%s)\n", tg->dport, proto2ascii(tg->proto));
    log_write (LOG_PLAIN, "%s", Tbl->printableTable(NULL));

    if(G_TTL(tg->getState()))
        log_write(LOG_PLAIN, "! maximum TTL reached (50)\n");
    else if(!tg->gotReply || (tp && (tp->ipreplysrc.s_addr != tg->ipdst)))
        log_write(LOG_PLAIN, "! destination not reached (%s)\n", inet_ntoa(tp->ipdst));

    log_flush (LOG_PLAIN);
    delete Tbl;
}

/* print a trace in xml */
void
Traceroute::outputXMLTrace(TraceGroup * tg) {
    map < u16, TraceProbe * >::const_iterator it;
    TraceProbe *tp = NULL;
    const char *hostname_tmp = NULL;
    struct protoent *proto;
    struct in_addr addr;
    long timediff;
    short ttl_count;

    /* XML traceroute header */
    log_write(LOG_XML, "<trace ");
    if ((o.pingscan && (o.pingtype & PINGTYPE_TCP || o.pingtype & PINGTYPE_UDP)) || (!o.ipprotscan && !o.pingscan))
	log_write(LOG_XML, "port=\"%d\" ", tg->dport);
    if((proto = nmap_getprotbynum(htons(tg->proto))))
        log_write(LOG_XML, "proto=\"%s\"", proto->p_name);
    else
        log_write(LOG_XML, "proto=\"%d\"", tg->proto);
    log_write(LOG_XML, ">\n");

    /* add missing hosts host from the common path */
    for(ttl_count = 1 ; ttl_count < tg->TraceProbes.begin()->second->ttl; ttl_count++) {
        addr.s_addr = commonPath[ttl_count];
        log_write(LOG_XML, "<hop ttl=\"%d\" rtt=\"--\" ", ttl_count);
        log_write(LOG_XML, "ipaddr=\"%s\"", inet_ntoa(addr));
        if((hostname_tmp = lookup_cached_host(commonPath[ttl_count])) != "")
            log_write(LOG_XML, " host=\"%s\"", hostname_tmp);
        log_write(LOG_XML, "/>\n");
    }

    /* display normal traceroute nodes.  Consolidation based on the
     * common path is not performed */
    for(it = tg->TraceProbes.begin() ;it != tg->TraceProbes.end(); it++) {
        tp = it->second;

        if(tp->probeType() == PROBE_TTL)
            break;

        if(tp->timing.getState() == P_TIMEDOUT) {
            continue;
	}

        timediff = TIMEVAL_SUBTRACT (tp->timing.recvTime, tp->timing.sendTime);

        log_write(LOG_XML, "<hop ttl=\"%d\" rtt=\"%.2f\" ipaddr=\"%s\"", tp->ttl, (float)timediff/1000, tp->ipReplyStr());
        if(tp->HostName() != NULL)
            log_write(LOG_XML, " host=\"%s\"", tp->HostName());
        log_write(LOG_XML, "/>\n");
    }

    if(G_TTL(tg->getState()))
        log_write(LOG_XML, "<error errorstr=\"maximum TTL reached\"/>\n");
    else if(!tg->gotReply || (tp && (tp->ipreplysrc.s_addr != tg->ipdst)))
        log_write(LOG_XML, "<error errorstr=\"destination not reached (%s)\"/>\n", inet_ntoa(tp->ipdst));

    /* traceroute XML footer */
    log_write(LOG_XML, "</trace>\n");
    log_flush(LOG_XML);
} 

TraceGroup::TraceGroup (u32 dip, u16 sport, u16 dport, u8 proto) {
    this->ipdst = dip;
    this->dport = dport;
    this->sport = sport;
    this->proto = proto;
    ttl = 0;
    state = G_OK;
    remaining = 0;
    hopDistance = 0;
    start_ttl = 0;
    TraceProbes.clear ();
    gotReply = false;
    noDistProbe = false;
    scanDelay = o.scan_delay ? o.scan_delay : 0;
    maxRetransmissions = (o.getMaxRetransmissions () < 2) ? 2 : o.getMaxRetransmissions () / 2;
    droppedPackets = 0;
    repliedPackets = 0;
    consecTimeouts = 0;
    consolidation_start = 0;
}

TraceGroup::~TraceGroup () {
    map < u16, TraceProbe * >::const_iterator it = TraceProbes.begin ();
    for (; it != TraceProbes.end (); ++it)
        delete (it->second);
}

/* go through all probes in a group and check if any have timedout. 
 * If too many packets have been dropped then the groups scan delay
 * is increased */
void
TraceGroup::retransmissions (vector < TraceProbe * >&retrans) {
    map < u16, TraceProbe * >::iterator it;
    u32 timediff;
    struct timeval now;
    double threshold = (o.timing_level >= 4) ? 0.40 : 0.30;

    for (it = TraceProbes.begin (); it != TraceProbes.end (); ++it) {
        if (it->second->timing.gotReply () || it->second->timing.getState () == P_TIMEDOUT)
            continue;

        gettimeofday (&now, NULL);
        timediff = TIMEVAL_SUBTRACT (now, it->second->timing.sendTime);

        if (timediff < it->second->timing.probeTimeout ())
            continue;

        if (it->second->timing.retranLimit () >= maxRetransmissions) {
            /* this probe has timedout */
            it->second->timing.setState (P_TIMEDOUT);
            decRemaining ();

            if(it->second->ttl > MAX_TTL)
                setState(G_DEAD_TTL);

            if ((++consecTimeouts) > 5 && maxRetransmissions > 2)
                maxRetransmissions = 2;
            if (it->second->probeType () == PROBE_TTL) {
                hopDistance = 1;
                noDistProbe = true;
                if (o.verbose)
                    log_write (LOG_STDOUT, "%s: no reply to our hop distance probe!\n", IPStr ());
            }
        } else {
            droppedPackets++;
            it->second->timing.setState (P_RETRANS);
            retrans.push_back (it->second);
        }

        /* Calculate dynamic timing adjustments */
        if (repliedPackets > droppedPackets / 5)
            maxRetransmissions = (maxRetransmissions == 2) ? 2 : maxRetransmissions - 1;
        else
            maxRetransmissions = MIN (o.getMaxRetransmissions (), maxRetransmissions + 1);

        if (droppedPackets > 10 && (droppedPackets /
                                    ((double) droppedPackets + repliedPackets) > threshold)) {
            if (!scanDelay)
                scanDelay = (proto == IPPROTO_TCP) ? 5 : 50;
            else
                scanDelay = MIN (scanDelay * 2, MAX (scanDelay, 800));
            droppedPackets = 0;
            repliedPackets = 0;
        } else {
            scanDelay = MAX (scanDelay - (scanDelay / 5), 5);
        }
    }
}

/* Remove uneeded probes and mark timed out probes for consolidation */
void TraceGroup::consolidateHops () {
    map < u16, TraceProbe * >::size_type ttl_count;
    map < u16, u32 >::iterator com_iter;
    TraceProbe *tp;
    int timeout_count = 0;

    /* remove any superfluous probes */
    for (ttl_count = hopDistance + 1; ttl_count <= TraceProbes.size () + 1; ttl_count++)
        TraceProbes.erase (ttl_count);

    for (ttl_count = 1; ttl_count <= hopDistance; ttl_count++) {
        tp = TraceProbes[ttl_count];
        if(!tp) {
            TraceProbes.erase (ttl_count);
            continue;
        }

        /* timeout consolidation flags, ignore if in debugging more */
        if (tp->timing.getState () != P_TIMEDOUT) {
            timeout_count = 0;
        } else {
            if (++timeout_count > 1 && !o.debugging) {
                TraceProbes[(ttl_count == 1) ? 1 : ttl_count - 1]->timing.consolidated = true;
                TraceProbes[(ttl_count == 1) ? 1 : ttl_count]->timing.consolidated = true;
            }
        } 

        if (tp->ipreplysrc.s_addr == ipdst)
            break;
    }

    /* we may have accidently shot past the intended destination */
    while (ttl_count <= hopDistance)
        TraceProbes.erase (++ttl_count);
}

u8
TraceGroup::setState (u8 state) {
    if (state <= G_FINISH || state >= G_OK)
        this->state = state;
    else if (o.debugging)
        log_write (LOG_STDOUT, "%s: invalid tracegroup state %d\n", IPStr (), state);
    return this->state;
}

u8
TraceGroup::setHopDistance (u8 hop_distance, u8 ttl) {
    if (this->hopDistance)
        return 0;

    this->hopDistance = hop_distance;

    if(o.debugging)
        log_write(LOG_STDOUT, "%s: hop distance parameters -> hg:%d ttl:%d\n", IPStr(), hop_distance, ttl);

    if (this->hopDistance && ttl) 
        this->hopDistance -= ttl;
    else if(!this->hopDistance && ttl)
        this->hopDistance = ttl;
    else
        this->hopDistance = hop_distance;

    /* guess is too big */
    if (this->hopDistance >= MAX_TTL)
        this->hopDistance = MAX_TTL- 2;
    /* guess is too small */
    else if(this->hopDistance == 0)
        this->hopDistance = 1;

    if (o.verbose)
        log_write (LOG_STDOUT, "%s: guessing hop distance at %d\n", IPStr (), this->hopDistance);
    return this->hopDistance;
}

TraceProbe::TraceProbe (u8 proto, u32 dip, u32 sip, u16 sport, u16 dport) {
    this->proto = proto;
    this->sport = sport;
    this->dport = dport;
    ipdst.s_addr = dip;
    ipsrc.s_addr = sip;
    ipreplysrc.s_addr = 0;
    hostnameip = NULL;
    hostname = NULL;
    probetype = PROBE_TRACE;
}

TraceProbe::~TraceProbe () {
    if (hostnameip)
        free (hostnameip);
}

const char *TraceProbe::nameIP(void) {
	hostnameip = (char *) safe_zalloc(NAMEIPLEN);

	if(hostname == NULL || *hostname == NULL)
		Snprintf(hostnameip, NAMEIPLEN, "%s", inet_ntoa(ipreplysrc));
	else
		Snprintf(hostnameip, NAMEIPLEN, "%s (%s)",*hostname, inet_ntoa(ipreplysrc));
		
	return hostnameip;
}

TimeInfo::TimeInfo () {
    memset (&sendTime, 0, sizeof (struct timeval));
    memset (&recvTime, 0, sizeof (struct timeval));
    retransmissions = 0;
    state = P_OK;
    consolidated = false;
    initialize_timeout_info (&to);
}

u8
TimeInfo::setState (u8 state) {
    if (state <= P_OK)
        this->state = state;
    else if (o.debugging)
        log_write (LOG_STDOUT, ": invalid traceprobe state %d\n", state);
    return state;
}

int
TimeInfo::retranLimit () {
    return ++this->retransmissions;
}

void
TimeInfo::adjustTimeouts (struct timeval *received, u16 scan_delay) {
    long delta = 0;

    if (received)
        recvTime = *received;

    if (o.debugging > 3) {
        log_write (LOG_STDOUT, "Timeout vals: srtt: %d rttvar: %d to: %d ", to.srtt, to.rttvar,
                   to.timeout);
    }

    delta = TIMEVAL_SUBTRACT (*received, sendTime);

    /* Argh ... pcap receive time is sometimes a little off my
       getimeofday() results on various platforms :(.  So a packet may
       appear to be received as much as a hundredth of a second before
       it was sent.  So I will allow small negative RTT numbers */
    if (delta < 0 && delta > -50000) {
        if (o.debugging > 2)
            log_write (LOG_STDOUT, "Small negative delta - adjusting from %lius to %dus\n", delta,
                       10000);
        delta = 10000;
    }


    if (to.srtt == -1 && to.rttvar == -1) {
        /* We need to initialize the sucker ... */
        to.srtt = delta;
        to.rttvar = MAX (5000, MIN (to.srtt, 2000000));
        to.timeout = to.srtt + (to.rttvar << 2);
    } else {
        if (delta >= 8000000 || delta < 0) {
            if (o.verbose)
                error
                    ("adjust_timeout: packet supposedly had rtt of %lu microseconds.  Ignoring time.",
                     delta);
            return;
        }
        delta -= to.srtt;
        /* sanity check 2 */
        if (delta > 1500000 && delta > 3 * to.srtt + 2 * to.rttvar) {
            if (o.debugging)
                log_write (LOG_STDOUT, "Bogus delta: %ld (srtt %d) ... ignoring\n", delta, to.srtt);
            return;
        }

        to.srtt += delta >> 3;
        to.rttvar += (ABS (delta) - to.rttvar) >> 2;
        to.timeout = to.srtt + (to.rttvar << 2);
    }

    if (to.rttvar > 2300000) {
        log_write (LOG_STDOUT, "RTTVAR has grown to over 2.3 seconds, decreasing to 2.0\n");
        to.rttvar = 2000000;
    }

    /* It hurts to do this ... it really does ... but otherwise we are being
       too risky */
    to.timeout = box (o.minRttTimeout () * 1000, o.maxRttTimeout () * 1000, to.timeout);

    if (scan_delay)
        to.timeout = MAX (to.timeout, scan_delay * 1000);

    if (o.debugging > 3) {
        log_write (LOG_STDOUT, "delta %ld ==> srtt: %d rttvar: %d to: %d\n",
                   delta, to.srtt, to.rttvar, to.timeout);
    }
}

/* Sleeps if necessary to ensure that it isn't called twice within less
 * time than send_delay.  If it is passed a non-null tv, the POST-SLEEP
 * time is recorded in it */
static void
enforce_scan_delay (struct timeval *tv, int scan_delay) {
    static int init = -1;
    static struct timeval lastcall;
    struct timeval now;
    int time_diff;

    if (!scan_delay) {
        if (tv)
            gettimeofday (tv, NULL);
        return;
    }

    if (init == -1) {
        gettimeofday (&lastcall, NULL);
        init = 0;
        if (tv)
            memcpy (tv, &lastcall, sizeof (struct timeval));
        return;
    }

    gettimeofday (&now, NULL);
    time_diff = TIMEVAL_MSEC_SUBTRACT (now, lastcall);
    if (time_diff < (int) scan_delay) {
        if (o.debugging > 2)
            log_write (LOG_STDOUT, "Sleeping for %d milliseconds in %s()\n",
                       scan_delay - time_diff, __func__);
        usleep ((scan_delay - time_diff) * 1000);
        gettimeofday (&lastcall, NULL);
    } else
        memcpy (&lastcall, &now, sizeof (struct timeval));
    if (tv) {
        memcpy (tv, &lastcall, sizeof (struct timeval));
    }
    return;
}

static char *
hostStr (u32 ip) {
    static char nameipbuf[MAXHOSTNAMELEN + INET6_ADDRSTRLEN] = { '0' };
    const char *hname;
    struct in_addr addr;

    memset (nameipbuf, '\0', MAXHOSTNAMELEN + INET6_ADDRSTRLEN);
    addr.s_addr = ip;
    if((hname = lookup_cached_host(ip)) == "")
        Snprintf(nameipbuf, MAXHOSTNAMELEN+INET6_ADDRSTRLEN, "%s", inet_ntoa(addr));
    else
        Snprintf (nameipbuf, MAXHOSTNAMELEN + INET6_ADDRSTRLEN, "%s (%s)", hname, inet_ntoa (addr));
    return nameipbuf;
}
