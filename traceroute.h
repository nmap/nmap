
/***************************************************************************
 * traceroute.h -- Parallel multi-protocol traceroute feature              *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2009 Insecure.Com LLC. Nmap is    *
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

/* $Id: nmap.h 6676 2008-01-12 22:39:34Z fyodor $ */

#include "Target.h"

#include <vector>

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
#define G_FINISH 5              /* tracing has complete successfully */

#define MAX_TTL 50

#define HOP_COL 0
#define RTT_COL 1
#define HOST_COL 2

#define NAMEIPLEN MAXHOSTNAMELEN+INET6_ADDRSTRLEN

class NmapOutputTable;

/* Keeps track of each probes timing state */
class TimeInfo {
  public:
    TimeInfo();
    int retranLimit();
    void adjustTimeouts(struct timeval *recv, u16 scan_delay);

    unsigned long probeTimeout() {
        return MIN(10000000, to.timeout * 10);
    }
    /* true if this probe has been replied to */ 
    u8 gotReply() {
        return recvTime.tv_usec != 0 && recvTime.tv_sec != 0;
    }
    u8 getState() {
        return state;
    }
    u8 setState(u8 state);

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

/* traceprobes represent a single packet at a specific ttl. Traceprobes are
 * stored inside tracegroups. */
class TraceProbe {
  public:
    TraceProbe(u32 dip, u32 sip, u16 sport, struct probespec& probe);
    ~TraceProbe();

    /* Return the ip address and resolved hostname in a string such as
     * "host.com (1.2.3.4)" or "6.6.6.6". */
    const char *nameIP();
    const char *HostName() {
        if (!hostname || !(*hostname))
            return NULL;
        else
            return *hostname; 
    }
    /* probe type is either a standard probe (PROBE_TRACE) or a hop distance
     * probe (PROBE_TTL) */
    void setProbeType(u8 type) {
        this->probetype = type;
    }
    u8 probeType() {
        return probetype;
    }
    char *ipReplyStr() {
        return inet_ntoa (ipreplysrc);
    }

    /* protocol information for this probe */
    TimeInfo timing;
    struct in_addr ipdst;
    struct in_addr ipsrc;
    struct in_addr ipreplysrc;
    struct probespec probe;
    u16 sport;
    u8 ttl;
    char **hostname;

  private:
    u8 probetype;
    char *hostnameip;
};

/* each trace group represents a target ip and contains a map of probes that
 * have been sent/recv'ed to/from the ip */
class TraceGroup {
  public:
    TraceGroup(u32 dip, u16 sport, struct probespec& probe);
    ~TraceGroup();
    /* map of all probes sent to this TraceGroups IP address. The map is keyed
     * by the source port number of the probe */
    std::map < u16, TraceProbe * >TraceProbes;
    std::map < u16, TraceProbe * >::size_type size() {
        return TraceProbes.size ();
    }
    /* checks for timedout probes and retransmits them Any probe that exceeds
     * the timing limits is considered non-responsive */ 
     void retransmissions(std::vector < TraceProbe * >&retrans);
    /* Returns a map from TTLs to probes, stripped of all unneeded probes and
     * with timed-out probes marked for consolidation. */
    std::map < u8, TraceProbe * > consolidateHops();
    /* the next ttl to send, if the destination has replied the ttl is
     * decremented, if it hasn't it is incremented */
    void nextTTL();
    /* number of probes currently waiting for replies */
    void incRemaining();
    void decRemaining();
    char *IPStr();
    u8 getRemaining() {
        return remaining;
    }
    u8 getState() {
        return state;
    }
    u8 setState(u8 state);
    u8 setHopDistance(u8 hop_distance, u8 ttl);

    /* Get the number of hops to the target, or -1 if unknown. Use this instead
     * of reading hopDistance, which despite its name does not contain the final
     * hop count. */
    int getDistance();

    bool gotReply;
    bool noDistProbe;

    /* Group wide timing */
    int scanDelay;
    int maxRetransmissions;
    u16 droppedPackets;
    u16 repliedPackets;
    u8 consecTimeouts;
    /* protocol information */
    struct probespec probe;
    u16 sport;
    u32 ipdst;
    /* estimated ttl distance to target */
    u8 hopDistance;
    /* largest ttl send so far */
    u8 ttl;
    /* the initial ttl guess. This is needed because the ttl may have to be
     * incremented to reach the destination host. Once nmap has reached the
     * destination it needs to start decrementing the ttl from the original
     * value so no duplicate probes are sent.
     *
     * For example, if the guess is 20 but the target is at 23. We will start
     * tracing backwards at 19. */
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
    Traceroute(const char *device_name, devtype type, const scan_lists * probe_ports);
     ~Traceroute();

    /* perform the traceroute on a list of targets */
    void trace(std::vector < Target * >&Targets);
    /* Use nmaps rDNS functions to mass resolve the hops ip addresses */
    void resolveHops();
    /* display plain and XML traceroutes for target t */
    void outputTarget(Target * t);

  private:
    /* map of all TraceGroups, keyed by 
     * the groups destination IP address */
     std::map < u32, TraceGroup * >TraceGroups;

    const struct scan_lists * scanlists;
    Target **hops;
    pcap_t *pd;
    eth_t *ethsd;
    int fd, total_size, cp_flag;
    struct in_addr ref_ipaddr;

    /* called by outputTarget to log XML data */
    void outputXMLTrace(TraceGroup * tg);
    /* find a responsive port for t based on scan results */
    const probespec getTraceProbe(Target * t);
    /* sendTTLProbes() guesses the hop distance to a target by actively probing
     * the host. */
    void sendTTLProbes(std::vector < Target * >&Targets, std::vector < Target * >&vaild_targets);
    int sendProbe(TraceProbe * tp);
    /* reads probe replies for all protocols. returns finished(), which returns
     * true when all groups have finished or failed */
    bool readTraceResponses();
    bool finished();
    /* add message to output table "hops 1 to X are the same as <reference ip>".
     * This message should always come before none-consolidated hop output */
    void addConsolidationMessage(NmapOutputTable *Tbl, unsigned short row_count, unsigned short ttl);
};
