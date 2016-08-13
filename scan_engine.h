
/***************************************************************************
 * scan_engine.h -- Includes much of the "engine" functions for scanning,  *
 * such as ultra_scan.  It also includes dependent functions such as       *
 * those for collecting SYN/connect scan responses.                        *
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

#ifndef SCAN_ENGINE_H
#define SCAN_ENGINE_H

#include "nmap.h" /* stype */

#include <dnet.h>

#include "timing.h"
#include "tcpip.h"
#include <list>
#include <vector>
#include <set>
#include <algorithm>

struct probespec_tcpdata {
  u16 dport;
  u8 flags;
};

struct probespec_udpdata {
  u16 dport;
};

struct probespec_sctpdata {
  u16 dport;
  u8 chunktype;
};

struct probespec_icmpdata {
  u8 type;
  u8 code;
};

struct probespec_icmpv6data {
  u8 type;
  u8 code;
};

#define PS_NONE 0
#define PS_TCP 1
#define PS_UDP 2
#define PS_PROTO 3
#define PS_ICMP 4
#define PS_ARP 5
#define PS_CONNECTTCP 6
#define PS_SCTP 7
#define PS_ICMPV6 8
#define PS_ND 9

/* The size of this structure is critical, since there can be tens of
   thousands of them stored together ... */
typedef struct probespec {
  /* To save space, I changed this from private enum (took 4 bytes) to
     u8 that uses #defines above */
  u8 type;
  u8 proto; /* If not PS_ARP -- Protocol number ... eg IPPROTO_TCP, etc. */
  union {
    struct probespec_tcpdata tcp; /* If type is PS_TCP or PS_CONNECTTCP. */
    struct probespec_udpdata udp; /* PS_UDP */
    struct probespec_sctpdata sctp; /* PS_SCTP */
    struct probespec_icmpdata icmp; /* PS_ICMP */
    struct probespec_icmpv6data icmpv6; /* PS_ICMPV6 */
    /* Nothing needed for PS_ARP, since src mac and target IP are
       avail from target structure anyway */
  } pd;
} probespec;

/* 3rd generation Nmap scanning function.  Handles most Nmap port scan types */
void ultra_scan(std::vector<Target *> &Targets, struct scan_lists *ports,
                stype scantype, struct timeout_info *to = NULL);

/* Determines an ideal number of hosts to be scanned (port scan, os
   scan, version detection, etc.) in parallel after the ping scan is
   completed.  This is a balance between efficiency (more hosts in
   parallel often reduces scan time per host) and results latency (you
   need to wait for all hosts to finish before Nmap can spit out the
   results).  Memory consumption usually also increases with the
   number of hosts scanned in parallel, though rarely to significant
   levels. */
int determineScanGroupSize(int hosts_scanned_so_far,
                           struct scan_lists *ports);

class UltraScanInfo;

struct ppkt { /* Beginning of ICMP Echo/Timestamp header         */
  u8 type;
  u8 code;
  u16 checksum;
  u16 id;
  u16 seq;
};

class ConnectProbe {
public:
  ConnectProbe();
  ~ConnectProbe();
  int sd; /* Socket descriptor used for connection.  -1 if not valid. */
};

struct IPExtraProbeData_icmp {
  u16 ident;
};

struct IPExtraProbeData_tcp {
  u16 sport;
  u32 seq; /* host byte order (like the other fields */
};

struct IPExtraProbeData_udp {
  u16 sport;
};

struct IPExtraProbeData_sctp {
  u16 sport;
  u32 vtag;
};

struct IPExtraProbeData {
  u32 ipid; /* host byte order */
  union {
    struct IPExtraProbeData_icmp icmp;
    struct IPExtraProbeData_tcp tcp;
    struct IPExtraProbeData_udp udp;
    struct IPExtraProbeData_sctp sctp;
  } pd;
};

/* At least for now, I'll just use this like a struct and access
   all the data members directly */
class UltraProbe {
public:
  UltraProbe();
  ~UltraProbe();
  enum UPType { UP_UNSET, UP_IP, UP_CONNECT, UP_ARP, UP_ND } type; /* The type of probe this is */

  /* Sets this UltraProbe as type UP_IP and creates & initializes the
     internal IPProbe.  The relevant probespec is necessary for setIP
     because pspec.type is ambiguous with just the ippacket (e.g. a
     tcp packet could be PS_PROTO or PS_TCP). */
  void setIP(u8 *ippacket, u32 iplen, const probespec *pspec);
  /* Sets this UltraProbe as type UP_CONNECT, preparing to connect to given
   port number*/
  void setConnect(u16 portno);
  /* Pass an arp packet, including ethernet header. Must be 42bytes */
  void setARP(u8 *arppkt, u32 arplen);
  void setND(u8 *ndpkt, u32 ndlen);
  // The 4 accessors below all return in HOST BYTE ORDER
  // source port used if TCP, UDP or SCTP
  u16 sport() const {
    switch (mypspec.proto) {
    case IPPROTO_TCP:
      return probes.IP.pd.tcp.sport;
    case IPPROTO_UDP:
      return probes.IP.pd.udp.sport;
    case IPPROTO_SCTP:
      return probes.IP.pd.sctp.sport;
    default:
      return 0;
    }
    /* not reached */
  }
  // destination port used if TCP, UDP or SCTP
  u16 dport() const {
    switch (mypspec.proto) {
    case IPPROTO_TCP:
      return mypspec.pd.tcp.dport;
    case IPPROTO_UDP:
      return mypspec.pd.udp.dport;
    case IPPROTO_SCTP:
      return mypspec.pd.sctp.dport;
    default:
      /* dport() can get called for other protos if we
       * get ICMP responses during IP proto scans. */
      return 0;
    }
    /* not reached */
  }
  u32 ipid() const {
    return probes.IP.ipid;
  }
  u16 icmpid() const; // ICMP ident if protocol is ICMP
  u32 tcpseq() const; // TCP sequence number if protocol is TCP
  u32 sctpvtag() const; // SCTP vtag if protocol is SCTP
  /* Number, such as IPPROTO_TCP, IPPROTO_UDP, etc. */
  u8 protocol() const {
    return mypspec.proto;
  }
  ConnectProbe *CP() {
    return probes.CP;  // if type == UP_CONNECT
  }
  // Arpprobe removed because not used.
  //  ArpProbe *AP() { return probes.AP; } // if UP_ARP
  // Returns the protocol number, such as IPPROTO_TCP, or IPPROTO_UDP, by
  // reading the appropriate fields of the probespec.

  /* Get general details about the probe */
  const probespec *pspec() const {
    return &mypspec;
  }

  /* Returns true if the given tryno and pingseq match those within this
     probe. */
  bool check_tryno_pingseq(unsigned int tryno, unsigned int pingseq) const {
    return (pingseq == 0 && tryno == this->tryno) || (pingseq > 0 && pingseq == this->pingseq);
  }

  u8 tryno; /* Try (retransmission) number of this probe */
  u8 pingseq; /* 0 if this is not a scanping. Otherwise a positive ping seq#. */
  /* If true, probe is considered no longer active due to timeout, but it
     may be kept around a while, just in case a reply comes late */
  bool timedout;
  /* A packet may be timedout for a while before being retransmitted due to
     packet sending rate limitations */
  bool retransmitted;

  struct timeval sent;
  /* Time the previous probe was sent, if this is a retransmit (tryno > 0) */
  struct timeval prevSent;
  bool isPing() {
    return pingseq > 0;
  }

private:
  probespec mypspec; /* Filled in by the appropriate set* function */
  union {
    IPExtraProbeData IP;
    ConnectProbe *CP;
    //    ArpProbe *AP;
  } probes;
};

/* Global info for the connect scan */
class ConnectScanInfo {
public:
  ConnectScanInfo();
  ~ConnectScanInfo();

  /* Watch a socket descriptor (add to fd_sets and maxValidSD).  Returns
     true if the SD was absent from the list, false if you tried to
     watch an SD that was already being watched. */
  bool watchSD(int sd);

  /* Clear SD from the fd_sets and maxValidSD.  Returns true if the SD
   was in the list, false if you tried to clear an sd that wasn't
   there in the first place. */
  bool clearSD(int sd);
  int maxValidSD; /* The maximum socket descriptor in any of the fd_sets */
  fd_set fds_read;
  fd_set fds_write;
  fd_set fds_except;
  int numSDs; /* Number of socket descriptors being watched */
  int maxSocketsAllowed; /* No more than this many sockets may be created @once */
};

class HostScanStats;

/* These are ultra_scan() statistics for the whole group of Targets */
class GroupScanStats {
public:
  struct timeval timeout; /* The time at which we abort the scan */
  /* Most recent host tested for sendability */
  struct sockaddr_storage latestip;
  GroupScanStats(UltraScanInfo *UltraSI);
  ~GroupScanStats();
  void probeSent(unsigned int nbytes);
  /* Returns true if the GLOBAL system says that sending is OK. */
  bool sendOK(struct timeval *when);
  /* Total # of probes outstanding (active) for all Hosts */
  int num_probes_active;
  UltraScanInfo *USI; /* The USI which contains this GSS.  Use for at least
                         getting the current time w/o gettimeofday() */
  struct ultra_timing_vals timing;
  struct timeout_info to; /* Group-wide packet rtt/timeout info */
  int numtargets; /* Total # of targets scanned -- includes finished and incomplete hosts */
  int numprobes; /* Number of probes/ports scanned on each host */
  /* The last time waitForResponses finished (initialized to GSS creation time */
  int probes_sent; /* Number of probes sent in total.  This DOES include pings and retransmissions */

  /* The most recently received probe response time -- initialized to scan
     start time. */
  struct timeval lastrcvd;
  /* The time the most recent ping was sent (initialized to scan begin time) */
  struct timeval lastping_sent;
  /* Value of numprobes_sent at lastping_sent time -- to ensure that we don't
     send too many pings when probes are going slowly. */
  int lastping_sent_numprobes;

  /* These two variables control minimum- and maximum-rate sending (--min-rate
     and --max-rate). send_no_earlier_than is for --max-rate and
     send_no_later_than is for --min-rate; they have effect only when the
     respective command-line option is given. An attempt is made to keep the
     sending rate within the interval, however for send_no_later_than it is not
     guaranteed. */
  struct timeval send_no_earlier_than;
  struct timeval send_no_later_than;

  /* The host to which global pings are sent. This is kept updated to be the
     most recent host that was found up. */
  HostScanStats *pinghost;

  struct timeval last_wait;
  int probes_sent_at_last_wait;
  // number of hosts that timed out during scan, or were already timedout
  int num_hosts_timedout;
  ConnectScanInfo *CSI;
};

struct send_delay_nfo {
  unsigned int delayms; /* Milliseconds to delay between probes */
  /* The number of successful and dropped probes since the last time the delay
     was changed. The ratio controls when the rate drops. */
  unsigned int goodRespSinceDelayChanged;
  unsigned int droppedRespSinceDelayChanged;
  struct timeval last_boost; /* Most recent time of increase to delayms.  Init to creation time. */
};

/* To test for rate limiting, there is a delay in sending the first packet
   of a certain retransmission number.  These values help track that. */
struct rate_limit_detection_nfo {
  unsigned int max_tryno_sent; /* What is the max tryno we have sent so far (starts at 0) */
  bool rld_waiting; /* Are we currently waiting due to RLD? */
  struct timeval rld_waittime; /* if RLD waiting, when can we send? */
};

/* The ultra_scan() statistics that apply to individual target hosts in a
   group */
class HostScanStats {
public:
  Target *target; /* A copy of the Target that these stats refer to. */
  HostScanStats(Target *t, UltraScanInfo *UltraSI);
  ~HostScanStats();
  int freshPortsLeft(); /* Returns the number of ports remaining to probe */
  int next_portidx; /* Index of the next port to probe in the relevant
                       ports array in USI.ports */
  bool sent_arp; /* Has an ARP probe been sent for the target yet? */

  /* massping state. */
  /* The index of the next ACK port in o.ping_ackprobes to probe during ping
     scan. */
  int next_ackportpingidx;
  /* The index of the next SYN port in o.ping_synprobes to probe during ping
     scan. */
  int next_synportpingidx;
  /* The index of the next UDP port in o.ping_udpprobes to probe during ping
     scan. */
  int next_udpportpingidx;
  /* The index of the next SCTP port in o.ping_protoprobes to probe during ping
     scan. */
  int next_sctpportpingidx;
  /* The index of the next IP protocol in o.ping_protoprobes to probe during ping
     scan. */
  int next_protoportpingidx;
  /* Whether we have sent an ICMP echo request. */
  bool sent_icmp_ping;
  /* Whether we have sent an ICMP address mask request. */
  bool sent_icmp_mask;
  /* Whether we have sent an ICMP timestamp request. */
  bool sent_icmp_ts;

  /* Have we warned that we've given up on a port for this host yet? Only one
     port per host is reported. */
  bool retry_capped_warned;

  void probeSent(unsigned int nbytes);

  /* How long I am currently willing to wait for a probe response
     before considering it timed out.  Uses the host values from
     target if they are available, otherwise from gstats.  Results
     returned in MICROseconds.  */
  unsigned long probeTimeout();

  /* How long I'll wait until completely giving up on a probe.
     Timedout probes are often marked as such (and sometimes
     considered a drop), but kept in the list juts in case they come
     really late.  But after probeExpireTime(), I don't waste time
     keeping them around. Give in MICROseconds */
  unsigned long probeExpireTime(const UltraProbe *probe);
  /* Returns OK if sending a new probe to this host is OK (to avoid
     flooding). If when is non-NULL, fills it with the time that sending
     will be OK assuming no pending probes are resolved by responses
     (call it again if they do).  when will become now if it returns
     true. */
  bool sendOK(struct timeval *when);

  /* If there are pending probe timeouts, fills in when with the time of
     the earliest one and returns true.  Otherwise returns false and
     puts now in when. */
  bool nextTimeout(struct timeval *when);
  UltraScanInfo *USI; /* The USI which contains this HSS */

  /* Removes a probe from probes_outstanding, adjusts HSS and USS
     active probe stats accordingly, then deletes the probe. */
  void destroyOutstandingProbe(std::list<UltraProbe *>::iterator probeI);

  /* Removes all probes from probes_outstanding using
     destroyOutstandingProbe. This is used in ping scan to quit waiting
     for responses once a host is known to be up. Invalidates iterators
     pointing into probes_outstanding. */
  void destroyAllOutstandingProbes();

  /* Mark an outstanding probe as timedout.  Adjusts stats
     accordingly.  For connect scans, this closes the socket. */
  void markProbeTimedout(std::list<UltraProbe *>::iterator probeI);

  /* New (active) probes are appended to the end of this list.  When a
     host times out, it will be marked as such, but may hang around on
     the list for a while just in case a response comes in.  So use
     num_probes_active to learn how many active (not timed out) probes
     are outstanding.  Probes on the bench (reached the current
     maximum tryno and expired) are not counted in
     probes_outstanding.  */
  std::list<UltraProbe *> probes_outstanding;
  /* The number of probes in probes_outstanding, minus the inactive (timed out) ones */
  unsigned int num_probes_active;
  /* Probes timed out but not yet retransmitted because of congestion
     control limits or because more retransmits may not be
     necessary.  Note that probes on probe_bench are not included
     in this value. */
  unsigned int num_probes_waiting_retransmit;
  unsigned int num_probes_outstanding() {
    return probes_outstanding.size();
  }

  /* The bench is a stock of probes (compacted into just the
     probespec) that have met the current maximum tryno, and are on
     ice until that tryno increases (so we can retransmit again), or
     solidifies (so we can mark the port firewalled or whatever).  The
     tryno of bench members is bench_tryno.  If the maximum tryno
     increases, everyone on the bench is moved to the retry_stack.
   */
  std::vector<probespec> probe_bench;
  unsigned int bench_tryno; /* # tryno of probes on the bench */
  /* The retry_stack are probespecs that were on the bench but are now
     slated to be retried.  It is kept sorted such that probes with highest
     retry counts are on top, ready to be taken first. */
  std::vector<probespec> retry_stack;
  /* retry_stack_tries MUST BE KEPT IN SYNC WITH retry_stack.
     retry_stack_tries[i] is the number of completed retries for the
     probe in retry_stack[i] */
  std::vector<u8> retry_stack_tries;
  /* tryno of probes on the retry queue */
  /* Moves the given probe from the probes_outstanding list, to
     probe_bench, and decrements num_probes_waiting_retransmit accordingly */
  void moveProbeToBench(std::list<UltraProbe *>::iterator probeI);
  /* Dismiss all probe attempts on bench -- the ports are marked
     'filtered' or whatever is appropriate for having no response */
  void dismissBench();
  /* Move all members of bench to retry_stack for probe retransmission */
  void retransmitBench();

  bool completed(); /* Whether or not the scan of this Target has completed */
  struct timeval completiontime; /* When this Target completed */

  /* This function provides the proper cwnd and ssthresh to use.  It
     may differ from versions in timing member var because when no
     responses have been received for this host, may look at others in
     the group.  For CHANGING this host's timing, use the timing
     memberval instead. */
  void getTiming(struct ultra_timing_vals *tmng);
  struct ultra_timing_vals timing;
  /* The most recently received probe response time -- initialized to scan start time. */
  struct timeval lastrcvd;
  struct timeval lastping_sent; /* The time the most recent ping was sent (initialized to scan begin time) */

  /* Value of numprobes_sent at lastping_sent time -- to ensure that we
     don't send too many pings when probes are going slowly. */
  int lastping_sent_numprobes;
  struct timeval lastprobe_sent; /* Most recent probe send (including pings) by host.  Init to scan begin time. */
  /* gives the maximum try number (try numbers start at zero and
     increments for each retransmission) that may be used, based on
     the scan type, observed network reliability, timing mode, etc.
     This may change during the scan based on network traffic.  If
     capped is not null, it will be filled with true if the tryno is
     at its upper limit.  That often calls for a warning to be issued,
     and marking of remaining timedout ports firewalled or whatever is
     appropriate.  If mayincrease is non-NULL, it is set to whether
     the allowedTryno may increase again.  If it is false, any probes
     which have reached the given limit may be dealt with. */
  unsigned int allowedTryno(bool *capped, bool *mayincrease);


  /* Provides the next ping sequence number.  This starts at one, goes
   up to 255, then wraps around back to 1.  If inc is true, it is
   incremented.  Otherwise you just get a peek at what the next one
   will be. */
  u8 nextPingSeq(bool inc = true) {
    u8 ret = nxtpseq;
    if (inc) {
      nxtpseq++;
      if (nxtpseq == 0)
        nxtpseq++;
    }
    return ret;
  }
  /* This is the highest try number that has produced useful results
     (such as port status change). */
  unsigned int max_successful_tryno;
  /* This starts as true because tryno may increase based on results, but
     it becomes false if it becomes clear that tryno will not increase
     further during the scan */
  bool tryno_mayincrease;
  int ports_finished; /* The number of ports of this host that have been determined */
  int numprobes_sent; /* Number of port probes (not counting pings, but counting retransmits) sent to this host */
  /* Boost the scan delay for this host, usually because too many packet
     drops were detected. */
  void boostScanDelay();
  struct send_delay_nfo sdn;
  struct rate_limit_detection_nfo rld;

private:
  u8 nxtpseq; /* the next scanping sequence number to use */
};

/* A few extra performance tuning parameters specific to ultra_scan. */
struct ultra_scan_performance_vars : public scan_performance_vars {
  /* When a successful ping response comes back, it counts as this many
     "normal" responses, because the fact that pings are necessary means
     we aren't getting much input. */
  int ping_magnifier;
  /* Try to send a scanping if no response has been received from a target host
     in this many usecs */
  int pingtime;
  unsigned int tryno_cap; /* The maximum trynumber (starts at zero) allowed */

  void init();
};

struct HssPredicate {
public:
  int operator() (HostScanStats *lhs, HostScanStats *rhs);
  static struct sockaddr_storage *ss;
};

class UltraScanInfo {
public:
  UltraScanInfo();
  UltraScanInfo(std::vector<Target *> &Targets, struct scan_lists *pts, stype scantype) {
    Init(Targets, pts, scantype);
  }
  ~UltraScanInfo();
  /* Must call Init if you create object with default constructor */
  void Init(std::vector<Target *> &Targets, struct scan_lists *pts, stype scantp);

  unsigned int numProbesPerHost();

  /* Consults with the group stats, and the hstats for every
     incomplete hosts to determine whether any probes may be sent.
     Returns true if they can be sent immediately.  If when is non-NULL,
     it is filled with the next possible time that probes can be sent
     (which will be now, if the function returns true */
  bool sendOK(struct timeval *tv);
  stype scantype;
  bool tcp_scan; /* scantype is a type of TCP scan */
  bool udp_scan;
  bool sctp_scan; /* scantype is a type of SCTP scan */
  bool prot_scan;
  bool ping_scan; /* Includes trad. ping scan & arp scan */
  bool ping_scan_arp; /* ONLY includes arp ping scan */
  bool ping_scan_nd; /* ONLY includes ND ping scan */
  bool noresp_open_scan; /* Whether no response means a port is open */

  /* massping state. */
  /* If ping_scan is true (unless ping_scan_arp is also true), this is the set
     of ping techniques to use (ICMP, raw ICMP, TCP connect, raw TCP, or raw
     UDP). */
  struct {
    unsigned int rawicmpscan: 1,
      connecttcpscan: 1,
      rawtcpscan: 1,
      rawudpscan: 1,
      rawsctpscan: 1,
      rawprotoscan: 1;
  } ptech;

  bool isRawScan();

  struct timeval now; /* Updated after potentially meaningful delays.  This can
                         be used to save a call to gettimeofday() */
  GroupScanStats *gstats;
  struct ultra_scan_performance_vars perf;
  /* A circular buffer of the incompleteHosts.  nextIncompleteHost() gives
     the next one.  The first time it is called, it will give the
     first host in the list.  If incompleteHosts is empty, returns
     NULL. */
  HostScanStats *nextIncompleteHost();
  /* Removes any hosts that have completed their scans from the incompleteHosts
     list, and remove any hosts from completedHosts which have exceeded their
     lifetime.  Returns the number of hosts removed. */
  int removeCompletedHosts();
  /* Find a HostScanStats by its IP address in the incomplete and completed
     lists.  Returns NULL if none are found. */
  HostScanStats *findHost(struct sockaddr_storage *ss);

  double getCompletionFraction();

  unsigned int numIncompleteHosts() {
    return incompleteHosts.size();
  }
  /* Call this instead of checking for numIncompleteHosts() == 0 because it
     avoids a potential traversal of the list to find the size. */
  bool incompleteHostsEmpty() {
    return incompleteHosts.empty();
  }
  bool numIncompleteHostsLessThan(unsigned int n);

  unsigned int numInitialHosts() {
    return numInitialTargets;
  }

  void log_overall_rates(int logt);
  void log_current_rates(int logt, bool update = true);

  /* Any function which messes with (removes elements from)
     incompleteHosts may have to manipulate nextI */
  std::set<HostScanStats *, HssPredicate> incompleteHosts;
  /* Hosts are moved from incompleteHosts to completedHosts as they are
     completed. We keep them around because sometimes responses come back very
     late, after we consider a host completed. */
  std::set<HostScanStats *, HssPredicate> completedHosts;
  /* How long (in msecs) we keep a host in completedHosts */
  unsigned int completedHostLifetime;
  /* The last time we went through completedHosts to remove hosts */
  struct timeval lastCompletedHostRemoval;

  ScanProgressMeter *SPM;
  PacketRateMeter send_rate_meter;
  struct scan_lists *ports;
  int rawsd; /* raw socket descriptor */
  pcap_t *pd;
  eth_t *ethsd;
  u32 seqmask; /* This mask value is used to encode values in sequence
                  numbers.  It is set randomly in UltraScanInfo::Init() */
private:

  unsigned int numInitialTargets;
  std::set<HostScanStats *>::iterator nextI;

};

/* Whether this is storing timing stats for a whole group or an
   individual host */
enum ultra_timing_type { TIMING_HOST, TIMING_GROUP };

const char *pspectype2ascii(int type);

void ultrascan_port_probe_update(UltraScanInfo *USI, HostScanStats *hss,
                                 std::list<UltraProbe *>::iterator probeI,
                                 int newstate, struct timeval *rcvdtime,
                                 bool adjust_timing_hint = true);

void ultrascan_host_probe_update(UltraScanInfo *USI, HostScanStats *hss,
                                        std::list<UltraProbe *>::iterator probeI,
                                        int newstate, struct timeval *rcvdtime,
                                        bool adjust_timing_hint = true);

void ultrascan_ping_update(UltraScanInfo *USI, HostScanStats *hss,
                                  std::list<UltraProbe *>::iterator probeI,
                                  struct timeval *rcvdtime,
                                  bool adjust_timing = true);
#endif /* SCAN_ENGINE_H */

