
/***************************************************************************
 * scan_engine.h -- Includes much of the "engine" functions for scanning,  *
 * such as ultra_scan.  It also includes dependent functions such as       *
 * those for collecting SYN/connect scan responses.                        *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *
 * The Nmap Security Scanner is (C) 1996-2025 Nmap Software LLC ("The Nmap
 * Project"). Nmap is also a registered trademark of the Nmap Project.
 *
 * This program is distributed under the terms of the Nmap Public Source
 * License (NPSL). The exact license text applying to a particular Nmap
 * release or source code control revision is contained in the LICENSE
 * file distributed with that version of Nmap or source code control
 * revision. More Nmap copyright/legal information is available from
 * https://nmap.org/book/man-legal.html, and further information on the
 * NPSL license itself can be found at https://nmap.org/npsl/ . This
 * header summarizes some key points from the Nmap license, but is no
 * substitute for the actual license text.
 *
 * Nmap is generally free for end users to download and use themselves,
 * including commercial use. It is available from https://nmap.org.
 *
 * The Nmap license generally prohibits companies from using and
 * redistributing Nmap in commercial products, but we sell a special Nmap
 * OEM Edition with a more permissive license and special features for
 * this purpose. See https://nmap.org/oem/
 *
 * If you have received a written Nmap license agreement or contract
 * stating terms other than these (such as an Nmap OEM license), you may
 * choose to use and redistribute Nmap under those terms instead.
 *
 * The official Nmap Windows builds include the Npcap software
 * (https://npcap.com) for packet capture and transmission. It is under
 * separate license terms which forbid redistribution without special
 * permission. So the official Nmap Windows builds may not be redistributed
 * without special permission (such as an Nmap OEM license).
 *
 * Source is provided to this software because we believe users have a
 * right to know exactly what a program is going to do before they run it.
 * This also allows you to audit the software for security holes.
 *
 * Source code also allows you to port Nmap to new platforms, fix bugs, and
 * add new features. You are highly encouraged to submit your changes as a
 * Github PR or by email to the dev@nmap.org mailing list for possible
 * incorporation into the main distribution. Unless you specify otherwise, it
 * is understood that you are offering us very broad rights to use your
 * submissions as described in the Nmap Public Source License Contributor
 * Agreement. This is important because we fund the project by selling licenses
 * with various terms, and also because the inability to relicense code has
 * caused devastating problems for other Free Software projects (such as KDE
 * and NASM).
 *
 * The free version of Nmap is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranties,
 * indemnification and commercial support are all available through the
 * Npcap OEM program--see https://nmap.org/oem/
 *
 ***************************************************************************/

/* $Id$ */

#ifndef SCAN_ENGINE_H
#define SCAN_ENGINE_H

#include "scan_lists.h"
#include "probespec.h"

#include <dnet.h>

#include "timing.h"

#include <pcap.h>
#include <list>
#include <vector>
#include <set>
#include <algorithm>
class Target;

/* 3rd generation Nmap scanning function.  Handles most Nmap port scan types */
void ultra_scan(std::vector<Target *> &Targets, const struct scan_lists *ports,
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
                           const struct scan_lists *ports);

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

union _tryno_u {
  struct {
  u8 isPing : 1; // Is this a ping, not a scanprobe?
  u8 seqnum : 7; // Sequence number, 0-127
  } fields;
  u8 opaque;
};
typedef union _tryno_u tryno_t;

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
  void setIP(const u8 *ippacket, u32 iplen, const probespec *pspec);
  /* Sets this UltraProbe as type UP_CONNECT, preparing to connect to given
   port number*/
  void setConnect(u16 portno);
  /* Pass an arp packet, including ethernet header. Must be 42bytes */
  void setARP(const u8 *arppkt, u32 arplen);
  void setND(const u8 *ndpkt, u32 ndlen);
  // The 4 accessors below all return in HOST BYTE ORDER
  // source port used if TCP, UDP or SCTP
  u16 sport() const;
  // destination port used if TCP, UDP or SCTP
  u16 dport() const;
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
  ConnectProbe *CP() const {
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

  /* Returns true if the given tryno matches this probe. */
  bool check_tryno(u8 tryno) const {
    return tryno == this->tryno.opaque;
  }

  /* Helper for checking protocol/port match from a packet. */
  bool check_proto_port(u8 proto, u16 sport_or_icmpid, u16 dport) const;

  /* tryno/pingseq, depending on what type of probe this is (ping vs scanprobe) */
  tryno_t tryno; /* Try (retransmission) number of this probe */
  /* If true, probe is considered no longer active due to timeout, but it
     may be kept around a while, just in case a reply comes late */
  bool timedout;
  /* A packet may be timedout for a while before being retransmitted due to
     packet sending rate limitations */
  bool retransmitted;

  struct timeval sent;
  /* Time the previous probe was sent, if this is a retransmit (tryno > 0) */
  struct timeval prevSent;
  bool isPing() const {
    return tryno.fields.isPing;
  }
  u8 get_tryno() const {
    return tryno.fields.seqnum;
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
  /* Try to get a socket that's good for select(). Return true if it worked;
   * false if it didn't. */
  bool sendOK();
  int maxValidSD; /* The maximum socket descriptor in any of the fd_sets */
  fd_set fds_read;
  fd_set fds_write;
  fd_set fds_except;
  int numSDs; /* Number of socket descriptors being watched */
  int getSocket();
private:
  int nextSD;
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
  bool sendOK(struct timeval *when) const;
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
  int maxdelay;
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
  bool freshPortsLeft() const; /* Returns true if there are ports remaining to probe */
  int numFreshPortsLeft() const; /* Returns the number of ports remaining to probe */
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
  unsigned long probeTimeout() const;

  /* How long I'll wait until completely giving up on a probe.
     Timedout probes are often marked as such (and sometimes
     considered a drop), but kept in the list juts in case they come
     really late.  But after probeExpireTime(), I don't waste time
     keeping them around. Give in MICROseconds */
  unsigned long probeExpireTime(const UltraProbe *probe, unsigned long to_us) const;
  /* Returns OK if sending a new probe to this host is OK (to avoid
     flooding). If when is non-NULL, fills it with the time that sending
     will be OK assuming no pending probes are resolved by responses
     (call it again if they do).  when will become now if it returns
     true. */
  bool sendOK(struct timeval *when) const;

  /* If there are pending probe timeouts, compares the earliest one with `when`;
     if it is earlier than `when`, replaces `when` with the time of
     the earliest one and returns true.  Otherwise returns false. */
  bool soonerTimeout(struct timeval *when) const;
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
  unsigned int num_probes_outstanding() const {
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

  bool completed() const; /* Whether or not the scan of this Target has completed */
  struct timeval completiontime; /* When this Target completed */

  /* This function provides the proper cwnd and ssthresh to use.  It
     may differ from versions in timing member var because when no
     responses have been received for this host, may look at others in
     the group.  For CHANGING this host's timing, use the timing
     memberval instead. */
  void getTiming(struct ultra_timing_vals *tmng) const;
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
  unsigned int allowedTryno(bool *capped, bool *mayincrease) const;

  /* Provides the next ping sequence number.  This starts at zero, goes
   up to 127, then wraps around back to 0. */
  u8 nextPingSeq() {
    // Has to fit in 7 bits: tryno.fields.seqnum
    nxtpseq = (nxtpseq + 1) % 0x80;
    return nxtpseq;
  }
  /* This is the highest try number that has produced useful results
     (such as port status change). */
  unsigned int max_successful_tryno;
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
  int operator() (const HostScanStats *lhs, const HostScanStats *rhs) const;
  static const struct sockaddr_storage *ss;
};

class UltraScanInfo {
public:
  UltraScanInfo();
  UltraScanInfo(std::vector<Target *> &Targets, const struct scan_lists *pts, stype scantype) {
    Init(Targets, pts, scantype);
  }
  ~UltraScanInfo();
  /* Must call Init if you create object with default constructor */
  void Init(std::vector<Target *> &Targets, const struct scan_lists *pts, stype scantp);

  unsigned int numProbesPerHost() const;

  /* Consults with the group stats, and the hstats for every
     incomplete hosts to determine whether any probes may be sent.
     Returns true if they can be sent immediately.  If when is non-NULL,
     it is filled with the next possible time that probes can be sent
     (which will be now, if the function returns true */
  bool sendOK(struct timeval *tv) const;
  stype scantype;
  bool tcp_scan; /* scantype is a type of TCP scan */
  bool udp_scan;
  bool sctp_scan; /* scantype is a type of SCTP scan */
  bool prot_scan;
  bool ping_scan; /* Includes trad. ping scan & arp scan */
  bool ping_scan_arp; /* ONLY includes arp ping scan */
  bool ping_scan_nd; /* ONLY includes ND ping scan */
  bool noresp_open_scan; /* Whether no response means a port is open */
#ifdef WIN32
  bool has_tcp_maxrtms; /* Whether TCP_MAXRTMS socket option is available */
#endif

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

  bool isRawScan() const;

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
  HostScanStats *findHost(const struct sockaddr_storage *ss) const;

  double getCompletionFraction() const;

  unsigned int numIncompleteHosts() const {
    return incompleteHosts.size();
  }
  /* Call this instead of checking for numIncompleteHosts() == 0 because it
     avoids a potential traversal of the list to find the size. */
  bool incompleteHostsEmpty() const {
    return incompleteHosts.empty();
  }

  unsigned int numInitialHosts() const {
    return numInitialTargets;
  }

  void log_overall_rates(int logt) const;
  void log_current_rates(int logt, bool update = true);

  /* Any function which messes with (removes elements from)
     incompleteHosts may have to manipulate nextI */
  std::multiset<HostScanStats *, HssPredicate> incompleteHosts;
  /* Hosts are moved from incompleteHosts to completedHosts as they are
     completed. We keep them around because sometimes responses come back very
     late, after we consider a host completed. */
  std::multiset<HostScanStats *, HssPredicate> completedHosts;
  /* The last time we went through completedHosts to remove hosts */
  struct timeval lastCompletedHostRemoval;

  ScanProgressMeter *SPM;
  PacketRateMeter send_rate_meter;
  const struct scan_lists *ports;
  int rawsd; /* raw socket descriptor */
  pcap_t *pd;
  eth_t *ethsd;
  u32 seqmask; /* This mask value is used to encode values in sequence
                  numbers.  It is set randomly in UltraScanInfo::Init() */
  u16 base_port;
  const struct sockaddr_storage *SourceSockAddr() const { return &sourceSockAddr; }

private:

  unsigned int numInitialTargets;
  std::multiset<HostScanStats *, HssPredicate>::iterator nextI;
  // All targets in an invocation will have the same source address.
  struct sockaddr_storage sourceSockAddr;
  /* We encode per-probe information like the tryno in the source
     port, for protocols that use ports. (Except when o.magic_port_set is
     true--then we honor the requested source port.) The tryno is
     encoded as offsets from base_port, a base source port number (see
     sport_encode and sport_decode). To avoid interpreting a late response from a
     previous invocation of ultra_scan as a response for the same port in the
     current invocation, we increase base_port by a healthy amount designed to be
     greater than any offset likely to be used by a probe, each time ultra_scan is
     run.

     If we don't increase the base port, then there is the risk of something like
     the following happening:
     1. Nmap sends an ICMP echo and a TCP ACK probe to port 80 for host discovery.
     2. Nmap receives an ICMP echo reply and marks the host up.
     3. Nmap sends a TCP SYN probe to port 80 for port scanning.
     4. Nmap finally receives a delayed TCP RST in response to its earlier ACK
     probe, and wrongly marks port 80 as closed. */

  /* Base port must be chosen so that there is room to add an 8-bit value (tryno)
   * without exceeding 16 bits. We increment modulo the largest prime number N
   * such that 33000 + N + 256 < 65536, which ensures no overlapping cycles. */
  // Nearest prime not exceeding 65536 - 256 - 33000:
#define PRIME_32K 32261
  /* Change base_port to a new number in a safe port range that is unlikely to
     conflict with nearby past or future invocations of ultra_scan. */
  static u16 increment_base_port() {
    static u16 g_base_port = 33000 + get_random_uint() % PRIME_32K;
    g_base_port = 33000 + (g_base_port - 33000 + 256) % PRIME_32K;
    return g_base_port;
  }

};

/* Whether this is storing timing stats for a whole group or an
   individual host */
enum ultra_timing_type { TIMING_HOST, TIMING_GROUP };

const char *pspectype2ascii(int type);

void ultrascan_port_probe_update(UltraScanInfo *USI, HostScanStats *hss,
                                 std::list<UltraProbe *>::iterator probeI,
                                 int newstate, const struct timeval *rcvdtime,
                                 bool adjust_timing_hint = true);

void ultrascan_host_probe_update(UltraScanInfo *USI, HostScanStats *hss,
                                        std::list<UltraProbe *>::iterator probeI,
                                        int newstate, const struct timeval *rcvdtime,
                                        bool adjust_timing_hint = true);

void ultrascan_ping_update(UltraScanInfo *USI, HostScanStats *hss,
                                  std::list<UltraProbe *>::iterator probeI,
                                  const struct timeval *rcvdtime,
                                  bool adjust_timing = true);
#endif /* SCAN_ENGINE_H */

