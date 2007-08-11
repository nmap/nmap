/***************************************************************************
 * traceroute.h -- Traces the route a packet takes to a host               *
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
 ***************************************************************************
 *
 * Eddie Bell <ejlbell@gmail.com>  
 * See Traceroute.cc for an indepth explanation
 */

#include "Target.h"

/* Probe types */
#define PROBE_TRACE 0
#define PROBE_TTL 1

/* Probe states */
#define P_TIMEDOUT 0            /* probe has timedout */
#define P_RETRANS 1             /* probe needs to be retransmitted */
#define P_OK 2                  /* waiting for response or received response */

/* Group states */
#define G_OK P_OK
#define G_DEAD_TTL 3            /* TTL has reached maximum value */
#define G_ALIVE_TTL 4            /* TTL has reached maximum value */
#define G_FINISH 5         /* tracing has complete successfully */

#define G_TTL(x) (x == G_ALIVE_TTL || x == G_DEAD_TTL)

#define MAX_TTL 50

#define HOP_COL 0
#define RTT_COL 1
#define HOST_COL 2

#define NAMEIPLEN MAXHOSTNAMELEN+INET6_ADDRSTRLEN

#ifndef ICMP_ECHOREPLY
 #define ICMP_ECHOREPLY 0
#endif
#ifndef ICMP_DEST_UNREACH
 #define ICMP_DEST_UNREACH 3
#endif
#ifndef ICMP_ECHO
 #define ICMP_ECHO 8
#endif
#ifndef ICMP_TIME_EXCEEDED
 #define ICMP_TIME_EXCEEDED 11
#endif
#ifndef ICMP_TIMESTAMP
 #define ICMP_TIMESTAMP 13
#endif
#ifndef ICMP_TIMESTAMPREPLY
 #define ICMP_TIMESTAMPREPLY 14
#endif
#ifndef ICMP_ADDRESS
 #define ICMP_ADDRESS 17
#endif
#ifndef ICMP_ADDRESSREPLY
 #define ICMP_ADDRESSREPLY 18
#endif
#ifndef ICMP_HOST_UNREACH
 #define ICMP_HOST_UNREACH 1
#endif
#ifndef ICMP_PROT_UNREACH
 #define ICMP_PROT_UNREACH 2
#endif
#ifndef ICMP_PORT_UNREACH
 #define ICMP_PORT_UNREACH 3
#endif
#ifndef ICMP_NET_ANO
 #define ICMP_NET_ANO 9
#endif
#ifndef ICMP_HOST_ANO
 #define ICMP_HOST_ANO 10
#endif
#ifndef ICMP_PKT_FILTERED
 #define ICMP_PKT_FILTERED 13
#endif

class NmapOutputTable;

/* various pieces of scan data used by
 * traceroute to find responsive ports
 * and match probes */
struct scan_info {
    u8 initial_proto;
    u8 icmp_type;
    u8 scan_flags;
    u8 open_response;
    u8 open_state;
    u8 closed_response;
    u8 closed_state;
};

/* Keeps track of each probes timing state */
class TimeInfo {
  public:
    TimeInfo ();
    int retranLimit ();
    void adjustTimeouts (struct timeval *recv, u16 scan_delay);

    unsigned long probeTimeout () { return MIN (10000000, to.timeout * 10); }
    /* true if this probe has been replied to */ 
    u8 gotReply () { return (recvTime.tv_usec != 0 && recvTime.tv_sec != 0); }
    u8 getState () { return state; }
    u8 setState (u8 state);

    struct timeout_info to;
    /* set to true if this probe is going to
     * consolidated because it has timed out */
    bool consolidated;

    /* Rtt and timeout calculation */
    struct timeval recvTime;
    struct timeval sendTime;

  private:
    u8 retransmissions;
    u8 state;
};

/* traceprobes represent a single packet at a specific
 * ttl. Traceprobes are stored inside tracegroups. */
class TraceProbe {
  public:
    TraceProbe (u8 proto, u32 dip, u32 sip, u16 sport, u16 dport);
    ~TraceProbe ();

    /* Return the ip address and resolved hostname in a string 
     * EG
     *   host.com (1.2.3.4)  
     * Or
     *   6.6.6.6
     */
    const char *nameIP ();
    const char *HostName ()
      { if(!hostname || !(*hostname))
             return NULL;
	else
	  return *hostname; 
	 }
    /* probe type is either a standard probe (PROBE_TRACE) or
     * a hop distance probe (PROBE_TTL) */
    void setProbeType (u8 type) { this->probetype = type; }
    u8 probeType () { return probetype; }
    char *ipReplyStr () { return inet_ntoa (ipreplysrc); }

    /* protocol information for this probe */
    TimeInfo timing;
    struct in_addr ipdst;
    struct in_addr ipsrc;
    struct in_addr ipreplysrc;
    u16 sport;
    u16 dport;
    u8 proto;
    u8 ttl;
    char **hostname;

  private:
    u8 probetype;
    char *hostnameip;
};

/* each trace group represents a target ip and contains
 * a map of probes that have been sent/recv'ed to/from
 * the ip */
class TraceGroup {
  public:
    TraceGroup (u32 dip, u16 dport, u16 sport, u8 proto);
    ~TraceGroup ();
    /* map of all probes sent to this TraceGroups IP address. The map 
     * is keyed by the source port of the probe */
    std::map < u16, TraceProbe * >TraceProbes;
    std::map < u16, TraceProbe * >::size_type size () { return TraceProbes.size ();}
    /* checks for timedout probes and retransmits them 
     * Any probe that exceeds the timing limits is 
     * considered non-responsive */ 
     void retransmissions (std::vector < TraceProbe * >&retrans);
    /* consolidate timeouts, remove common paths elements
     * and performs general upkeep on a finished trace */
    void consolidateHops ();
    /* the next ttl to send, if the destination has replied
     * the ttl is decremented, if it hasn't it is incremented */
    void nextTTL () { if (gotReply) ttl--; else { ttl++; hopDistance++;}}
    /* number of probes currently waiting for replies */
    void incRemaining () { if (remaining < 255) ++remaining; }
    void decRemaining () { if (remaining > 0) --remaining; }
    char *IPStr () { struct in_addr s; s.s_addr = ipdst; return inet_ntoa (s);}
    u8 getRemaining () { return remaining;}
    u8 getState () { return state; }
    u8 setState (u8 state);
    u8 setHopDistance (u8 hop_distance, u8 ttl);

    bool gotReply;
    bool noDistProbe;

    /* Group wide timing */
    int scanDelay;
    int maxRetransmissions;
    u16 droppedPackets;
    u16 repliedPackets;
    u8 consecTimeouts;
    /* protocol information */
    u8 proto;
    u16 sport;
    u16 dport;
    u32 ipdst;
    /* estimated ttl distance to target */
    u8 hopDistance;
    /* largest ttl send so far */
    u8 ttl;
    /* the initial ttl guess. This is needed because the ttl 
     * may have to be incremented to reach the destination host. 
     * Once nmap has reached the destination it needs to 
     * start decrementing the ttl from the original value
     * so no duplicate probes are sent
     *
     * EG. If the guess is 20 but the target is at 23. We will
     *     start tracing backwards at 19 
     */
    u8 start_ttl;
    u8 consolidation_start;
    const u8 *src_mac_addr;
    const u8 *nxt_mac_addr;

  private:
    /* the number of probes sent but and not yet replied to */
    u8 remaining;
    /* default state is G_OK, set to G_FINISH when
     * complete or one of the G_* error codes if this
     * group fails */
    u8 state;
};

/* Public interface to traceroute functionality */
class Traceroute {
  public:
    Traceroute (const char *device_name, devtype type);
     ~Traceroute ();

    /* perform the traceroute on a list of targets */
    void trace (std::vector < Target * >&Targets);
    /* Use nmaps rDNS functions to mass resolve the hops ip addresses */
    void resolveHops ();
    /* display plain and XML traceroutes for target t */
    void outputTarget (Target * t);

  private:
    /* map of all TraceGroups, keyed by 
     * the groups destination IP address */
     std::map < u32, TraceGroup * >TraceGroups;


    struct scan_info scaninfo;
    Target **hops;
    pcap_t *pd;
    eth_t *ethsd;
    int fd, total_size;
    struct in_addr ref_ipaddr;

    /* called by outputTarget to log XML data */
    void outputXMLTrace (TraceGroup * tg);
    /* find a responsive port for t based on scan results */
    int getTracePort (u8 proto, Target * t);
    /* sendTTLProbes() guesses the hop distance to a 
     * target by actively probing the host. */
    void sendTTLProbes (std::vector < Target * >&Targets, std::vector < Target * >&vaild_targets);
    int sendProbe (TraceProbe * tp);
    /* reads probe replies for all protocols.
     * returns finished(), which returns true
     * when all groups have finished or failed */
    bool readTraceResponses ();
    bool finished ();
    /* add message to output table "hops 1 to X are the
     * same as <reference ip>". This message should always
     * come before none-consolidated hop output */
    void addConsolidationMessage(NmapOutputTable *Tbl, unsigned short row_count, unsigned short ttl);

};
