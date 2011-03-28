
/***************************************************************************
 * scan_engine.cc -- Includes much of the "engine" functions for scanning, *
 * such as pos_scan and ultra_scan.  It also includes dependant functions  *
 * such as those for collecting SYN/connect scan responses.                *
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

#ifdef WIN32
#include "nmap_winconfig.h"
#endif
#include "portreasons.h"
#include <dnet.h>
#include "scan_engine.h"
#include "timing.h"
#include "NmapOps.h"
#include "nmap_tty.h"
#include "nmap_rpc.h"
#include "payload.h"
#include "Target.h"
#include "targets.h"
#include "utils.h"
#include <math.h>
#include <list>
#include <map>

using namespace std;
extern NmapOps o;
class UltraScanInfo;

struct ultra_scan_performance_vars {
  int low_cwnd;  /* The lowest cwnd (congestion window) allowed */
  int host_initial_cwnd; /* Initial congestion window for ind. hosts */
  int group_initial_cwnd; /* Initial congestion window for all hosts as a group */
  int max_cwnd; /* I should never have more than this many probes
		   outstanding */
  int slow_incr; /* How many probes are incremented for each response
		    in slow start mode */
  int ca_incr; /* How many probes are incremented per (roughly) rtt in 
		  congestion avoidance mode */
  int cc_scale_max; /* The maximum scaling factor for congestion window
		       increments. */
  int initial_ssthresh;
  /* When a successful ping response comes back, it counts as this many
     "normal" responses, because the fact that pings are necessary means
     we aren't getting much input. */
  int ping_magnifier;
/* Try to send a scanping if no response has been received from a target host
   in this many usecs */
  int pingtime; 
  double group_drop_cwnd_divisor; /* all-host group cwnd divided by this
				     value if any packet drop occurs */
  double group_drop_ssthresh_divisor; /* used to drop the group ssthresh when
					 any drop occurs */
  double host_drop_ssthresh_divisor; /* used to drop the host ssthresh when
					 any drop occurs */
  int tryno_cap; /* The maximum trynumber (starts at zero) allowed */
};

/* Some of the algorithms used here are TCP congestion control
   techniques from RFC2581. */
struct ultra_timing_vals {
  double cwnd; /* Congestion window - in probes */
  int ssthresh; /* The threshold above which mode is changed from slow start
		   to congestion avoidance */
  /* The number of replies we would expect if every probe produced a reply. This
     is almost like the total number of probes sent but it is not incremented
     until a reply is received or a probe times out. This and
     num_replies_received are used to scale congestion window increments. */
  int num_replies_expected;
  /* The number of replies we've received to probes of any type. */
  int num_replies_received;
  /* Number of updates to this timing structure (generally packet receipts). */
  int num_updates;
  /* Last time values were adjusted for a drop (you usually only want
     to adjust again based on probes sent after that adjustment so a
     sudden batch of drops doesn't destroy timing.  Init to now */
  struct timeval last_drop; 
};

static const char *pspectype2ascii(int type) {
  switch(type) {
  case PS_NONE:
    return "NONE";
  case PS_TCP:
    return "TCP";
  case PS_UDP:
    return "UDP";
  case PS_SCTP:
    return "SCTP";
  case PS_PROTO:
    return "IP Proto";
  case PS_ICMP:
    return "ICMP";
  case PS_ARP:
    return "ARP";
  case PS_CONNECTTCP:
    return "connect";
  default:
    fatal("%s: Unknown type: %d", __func__, type);
  }
  return ""; // Unreached
}

class ConnectProbe {
public:
  ConnectProbe();
  ~ConnectProbe();
  int sd; /* Socket descriptor used for connection.  -1 if not valid. */
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
  u16 ipid; /* host byte order */
  union {
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
  enum UPType { UP_UNSET, UP_IP, UP_CONNECT, UP_RPC, UP_ARP } type; /* The type of probe this is */

  /* Sets this UltraProbe as type UP_IP and creates & initializes the
     internal IPProbe.  The relevent probespec is necessary for setIP
     because pspec.type is ambiguous with just the ippacket (e.g. a
     tcp packet could be PS_PROTO or PS_TCP). */
  void setIP(u8 *ippacket, u32 iplen, const probespec *pspec);
  /* Sets this UltraProbe as type UP_CONNECT, preparing to connect to given
   port number*/
  void setConnect(u16 portno);
  /* Pass an arp packet, including ethernet header. Must be 42bytes */
  void setARP(u8 *arppkt, u32 arplen);
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
  u16 ipid() const { return probes.IP.ipid; }
  u32 tcpseq() const; // TCP sequence number if protocol is TCP
  u32 sctpvtag() const; // SCTP vtag if protocol is SCTP
  /* Number, such as IPPROTO_TCP, IPPROTO_UDP, etc. */
  u8 protocol() const { return mypspec.proto; }
  ConnectProbe *CP() { return probes.CP; } // if type == UP_CONNECT
  // Arpprobe removed because not used.
  //  ArpProbe *AP() { return probes.AP; } // if UP_ARP
  // Returns the protocol number, such as IPPROTO_TCP, or IPPROTO_UDP, by 
  // reading the appropriate fields of the probespec.

/* Get general details about the probe */
  const probespec *pspec() const { return &mypspec; }

  /* Returns true if the given tryno and pingseq match those within this
     probe. */
  bool check_tryno_pingseq(unsigned int tryno, unsigned int pingseq) const {
    return (pingseq == 0 && tryno == this->tryno) || (pingseq > 0 && pingseq == this->pingseq);
  }

  u8 tryno; /* Try (retransmission) number of this probe */
  u8 pingseq; /* 0 if this is not a scanping. Otherwise a posative ping seq#. */
/* If true, probe is considered no longer active due to timeout, but it
   may be kept around a while, just in case a reply comes late */
  bool timedout;
/* A packet may be timedout for a while before being retransmitted due to
   packet sending rate limitations */
  bool retransmitted; 

  struct timeval sent;
  /* Time the previous probe was sent, if this is a retransmit (tryno > 0) */
  struct timeval prevSent; 
  bool isPing() { return pingseq > 0; }

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

  /* Returns the scaling factor to use when incrementing the congestion
     window. */
  double cc_scale();

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
  int next_portidx; /* Index of the next port to probe in the relevent
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
  void destroyOutstandingProbe(list<UltraProbe *>::iterator probeI);

  /* Removes all probes from probes_outstanding using
     destroyOutstandingProbe. This is used in ping scan to quit waiting
     for responses once a host is known to be up. Invalidates iterators
     pointing into probes_outstanding. */
  void destroyAllOutstandingProbes();

  /* Mark an outstanding probe as timedout.  Adjusts stats
     accordingly.  For connect scans, this closes the socket. */
  void markProbeTimedout(list<UltraProbe *>::iterator probeI);

  /* New (active) probes are appended to the end of this list.  When a
     host times out, it will be marked as such, but may hang around on
     the list for a while just in case a response comes in.  So use
     num_probes_active to learn how many active (not timed out) probes
     are outstanding.  Probes on the bench (reached the current
     maximum tryno and expired) are not counted in
     probes_outstanding.  */
  list<UltraProbe *> probes_outstanding;
  /* The number of probes in probes_outstanding, minus the inactive (timed out) ones */
  unsigned int num_probes_active;
  /* Probes timed out but not yet retransmitted because of congestion
     control limits or because more retransmits may not be
     necessary.  Note that probes on probe_bench are not included
     in this value. */
  unsigned int num_probes_waiting_retransmit;
  unsigned int num_probes_outstanding() { return probes_outstanding.size(); }

  /* The bench is a stock of probes (compacted into just the
     probespec) that have met the current maximum tryno, and are on
     ice until that tryno increases (so we can retransmit again), or
     solidifies (so we can mark the port firewalled or whatever).  The
     tryno of benh members is bench_tryno.  If the maximum tryno
     increases, everyone on the bench is moved to the retry_stack.
   */
  vector<probespec> probe_bench;
  unsigned int bench_tryno; /* # tryno of probes on the bench */
  /* The retry_stack are probespecs that were on the bench but are now
     slated to be retried.  It is kept sorted such that probes with highest
     retry counts are on top, ready to be taken first. */
  vector<probespec> retry_stack;
  /* retry_stack_tries MUST BE KEPT IN SYNC WITH retry_stack.
     retry_stack_tries[i] is the number of completed retries for the
     probe in retry_stack[i] */
  vector<u8> retry_stack_tries; 
  /* tryno of probes on the retry queue */
  /* Moves the given probe from the probes_outstanding list, to
     probe_bench, and decrements num_probes_waiting_retransmit accordingly */
  void moveProbeToBench(list<UltraProbe *>::iterator probeI);
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
     which have reached the given limit may be dealth with. */
  unsigned int allowedTryno(bool *capped, bool *mayincrease);


  /* Provides the next ping sequence number.  This starts at one, goes
   up to 255, then wraps around back to 1.  If inc is true, it is
   incremented.  Otherwise you just get a peek at what the next one
   will be. */
  u8 nextPingSeq(bool inc=true) {
    u8 ret = nxtpseq;
    if (inc) {
      nxtpseq++;
      if (nxtpseq == 0) nxtpseq++;
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
  /* Returns the scaling factor to use when incrementing the congestion
     window. */
  double cc_scale();
  /* Boost the scan delay for this host, usually because too many packet
     drops were detected. */
  void boostScanDelay();
  struct send_delay_nfo sdn;
  struct rate_limit_detection_nfo rld;

private:
  u8 nxtpseq; /* the next scanping sequence number to use */
};

class UltraScanInfo {
public:
  UltraScanInfo();
  UltraScanInfo(vector<Target *> &Targets, struct scan_lists *pts, stype scantype) { Init(Targets, pts, scantype); }
  ~UltraScanInfo();
  /* Must call Init if you create object with default constructor */
  void Init(vector<Target *> &Targets, struct scan_lists *pts, stype scantp);

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
  bool noresp_open_scan; /* Whether no response means a port is open */

  /* massping state. */
  /* If ping_scan is true (unless ping_scan_arp is also true), this is the set
     of ping techniques to use (ICMP, raw ICMP, TCP connect, raw TCP, or raw
     UDP). */
  struct pingtech ptech;

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

  unsigned int numIncompleteHosts() { return incompleteHosts.size(); }
  /* Call this instead of checking for numIncompleteHosts() == 0 because it
     avoids a potential traversal of the list to find the size. */
  bool incompleteHostsEmpty() { return incompleteHosts.empty(); }
  bool numIncompleteHostsLessThan(unsigned int n);

  unsigned int numInitialHosts() { return numInitialTargets; }

  void log_overall_rates(int logt) {
    log_write(logt, "Overall sending rates: %.2f packets / s", send_rate_meter.getOverallPacketRate(&now));
    if (send_rate_meter.getNumBytes() > 0)
      log_write(logt, ", %.2f bytes / s", send_rate_meter.getOverallByteRate(&now));
    log_write(logt, ".\n");
  }

  void log_current_rates(int logt, bool update = true) {
    log_write(logt, "Current sending rates: %.2f packets / s", send_rate_meter.getCurrentPacketRate(&now, update));
    if (send_rate_meter.getNumBytes() > 0)
      log_write(logt, ", %.2f bytes / s", send_rate_meter.getCurrentByteRate(&now));
    log_write(logt, ".\n");
  }

  /* Any function which messes with (removes elements from)
     incompleteHosts may have to manipulate nextI */
  list<HostScanStats *> incompleteHosts;
  /* Hosts are moved from incompleteHosts to completedHosts as they are
     completed. We keep them around because sometimes responses come back very
     late, after we consider a host completed. */
  list<HostScanStats *> completedHosts;
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
  list<HostScanStats *>::iterator nextI;

};

/* Whether this is storing timing stats for a whole group or an
   individual host */
enum ultra_timing_type { TIMING_HOST, TIMING_GROUP };
/* Initialize the ultra_timing_vals structure timing.  The utt must be
   TIMING_HOST or TIMING_GROUP.  If you happen to have the current
   time handy, pass it as now, otherwise pass NULL */
static void init_ultra_timing_vals(ultra_timing_vals *timing, 
				   enum ultra_timing_type utt, 
				   int num_hosts_in_group, 
				   struct ultra_scan_performance_vars *perf,
				   struct timeval *now);

/* Take a buffer, buf, of size bufsz (64 bytes is sufficient) and 
   writes a short description of the probe (arg1) into buf.  It also returns 
   buf. */
static char *probespec2ascii(const probespec *pspec, char *buf, unsigned int bufsz) {
  char flagbuf[32];
  char *f;
  switch(pspec->type) {
  case PS_TCP:
    if (!pspec->pd.tcp.flags) Strncpy(flagbuf, "(none)", sizeof(flagbuf));
    else {
      f = flagbuf;
      if (pspec->pd.tcp.flags & TH_SYN) *f++ = 'S';
      if (pspec->pd.tcp.flags & TH_FIN) *f++ = 'F';
      if (pspec->pd.tcp.flags & TH_RST) *f++ = 'R';
      if (pspec->pd.tcp.flags & TH_PUSH) *f++ = 'P';
      if (pspec->pd.tcp.flags & TH_ACK) *f++ = 'A';
      if (pspec->pd.tcp.flags & TH_URG) *f++ = 'U';
      if (pspec->pd.tcp.flags & TH_ECE) *f++ = 'E'; /* rfc 2481/3168 */
      if (pspec->pd.tcp.flags & TH_CWR) *f++ = 'C'; /* rfc 2481/3168 */
      *f++ = '\0';
    }
    Snprintf(buf, bufsz, "tcp to port %hu; flags: %s", pspec->pd.tcp.dport, 
	     flagbuf);
    break;
  case PS_UDP:
    Snprintf(buf, bufsz, "udp to port %hu", pspec->pd.udp.dport);
    break;
  case PS_SCTP:
    switch (pspec->pd.sctp.chunktype) {
      case SCTP_INIT:
        Strncpy(flagbuf, "INIT", sizeof(flagbuf));
        break;
      case SCTP_COOKIE_ECHO:
        Strncpy(flagbuf, "COOKIE-ECHO", sizeof(flagbuf));
        break;
      default:
        Strncpy(flagbuf, "(unknown)", sizeof(flagbuf));
    }
    Snprintf(buf, bufsz, "sctp to port %hu; chunk: %s", pspec->pd.sctp.dport,
             flagbuf);
    break;
  case PS_PROTO:
    Snprintf(buf, bufsz, "protocol %u", (unsigned int) pspec->proto);
    break;
  case PS_ICMP:
    Snprintf(buf, bufsz, "icmp type %d code %d",
             pspec->pd.icmp.type, pspec->pd.icmp.code);
    break;
  case PS_ARP:
    Snprintf(buf, bufsz, "ARP");
    break;
  case PS_CONNECTTCP:
    Snprintf(buf, bufsz, "connect to port %hu", pspec->pd.tcp.dport);
    break;
  default:
    fatal("Unexpected %s type encountered", __func__);
    break;
  }
  return buf;  
}

ConnectProbe::ConnectProbe() {
  sd = -1;
}

ConnectProbe::~ConnectProbe() {
  if (sd > 0) close(sd);
  sd = -1;
}

UltraProbe::UltraProbe() {
  type = UP_UNSET;
  tryno = 0;
  timedout = false;
  retransmitted = false;
  pingseq = 0;
  mypspec.type = PS_NONE;
  memset(&sent, 0, sizeof(prevSent));
  memset(&prevSent, 0, sizeof(prevSent));
}

UltraProbe::~UltraProbe() {
  if (type == UP_CONNECT)
    delete probes.CP;
}

/* Pass an arp packet, including ethernet header. Must be 42bytes */

void UltraProbe::setARP(u8 *arppkt, u32 arplen) {
  type = UP_ARP;
  mypspec.type = PS_ARP;
  return;
}

 /* Sets this UltraProbe as type UP_IP and creates & initializes the
     internal IPProbe.  The relevent probespec is necessary for setIP
     because pspec.type is ambiguous with just the ippacket (e.g. a
     tcp packet could be PS_PROTO or PS_TCP). */
void UltraProbe::setIP(u8 *ippacket, u32 iplen, const probespec *pspec) {
  struct ip *ipv4 = (struct ip *) ippacket;
  struct tcp_hdr *tcp = NULL;
  struct udp_hdr *udp = NULL;
  struct sctp_hdr *sctp = NULL;

  type = UP_IP;
  if (ipv4->ip_v != 4)
    fatal("Bogus packet passed to %s -- only IPv4 packets allowed", 
	  __func__);
  assert(iplen >= 20);
  assert(iplen == (u32) ntohs(ipv4->ip_len));
  probes.IP.ipid = ntohs(ipv4->ip_id);
  if (ipv4->ip_p == IPPROTO_TCP) {
    assert (iplen >= (unsigned) ipv4->ip_hl * 4 + 20);    
    tcp = (struct tcp_hdr *) ((u8 *) ipv4 + ipv4->ip_hl * 4);
    probes.IP.pd.tcp.sport = ntohs(tcp->th_sport);
    probes.IP.pd.tcp.seq = ntohl(tcp->th_seq);
  } else if (ipv4->ip_p == IPPROTO_UDP) {
    assert(iplen >= (unsigned) ipv4->ip_hl * 4 + 8);
    udp = (struct udp_hdr *) ((u8 *) ipv4 + ipv4->ip_hl * 4);
    probes.IP.pd.udp.sport = ntohs(udp->uh_sport);
  } else if (ipv4->ip_p == IPPROTO_SCTP) {
    assert(iplen >= (unsigned) ipv4->ip_hl * 4 + 12);
    sctp = (struct sctp_hdr *) ((u8 *) ipv4 + ipv4->ip_hl * 4);
    probes.IP.pd.sctp.sport = ntohs(sctp->sh_sport);
    probes.IP.pd.sctp.vtag = ntohl(sctp->sh_vtag);
  }

  mypspec = *pspec;
  return;
}

u32 UltraProbe::tcpseq() const {
  if (mypspec.proto == IPPROTO_TCP)
    return probes.IP.pd.tcp.seq;
  else
    fatal("Bogus seq number request to %s -- type is %s", __func__, 
	  pspectype2ascii(mypspec.type));

  return 0; // Unreached
}

u32 UltraProbe::sctpvtag() const {
  assert(mypspec.proto == IPPROTO_SCTP);
  return probes.IP.pd.sctp.vtag;
}

/* Sets this UltraProbe as type UP_CONNECT, preparing to connect to given
   port number*/
void UltraProbe::setConnect(u16 portno) {
  type = UP_CONNECT;
  probes.CP = new ConnectProbe();
  mypspec.type = PS_CONNECTTCP;
  mypspec.proto = IPPROTO_TCP;
  mypspec.pd.tcp.dport = portno;
  mypspec.pd.tcp.flags = TH_SYN;
}

ConnectScanInfo::ConnectScanInfo() {
  maxValidSD = -1;
  numSDs = 0;
  /* Subtracting 5 from max_sd accounts for
     stdin
     stdout
     stderr
     /dev/tty
     /var/run/utmpx, which is opened on Mac OS X at least. */
  maxSocketsAllowed = (o.max_parallelism)? o.max_parallelism : MAX(5, max_sd() - 5);
  FD_ZERO(&fds_read);
  FD_ZERO(&fds_write);
  FD_ZERO(&fds_except);
}

/* Nothing really to do here. */
ConnectScanInfo::~ConnectScanInfo() {}

/* Watch a socket descriptor (add to fd_sets and maxValidSD).  Returns
   true if the SD was absent from the list, false if you tried to
   watch an SD that was already being watched. */
bool ConnectScanInfo::watchSD(int sd) {
  assert(sd >= 0);
  if (!FD_ISSET(sd, &fds_read)) {
    FD_SET(sd, &fds_read);
    FD_SET(sd, &fds_write);
    FD_SET(sd, &fds_except);
    numSDs++;
    if (sd > maxValidSD)
      maxValidSD = sd;
  } else return false;
  return true;
}

/* Clear SD from the fd_sets and maxValidSD.  Returns true if the SD
   was in the list, false if you tried to clear an sd that wasn't
   there in the first place. */
bool ConnectScanInfo::clearSD(int sd) {
  assert(sd >= 0);
  if (FD_ISSET(sd, &fds_read)) {
    FD_CLR(sd, &fds_read);
    FD_CLR(sd, &fds_write);
    FD_CLR(sd, &fds_except);
    assert(numSDs > 0);
    numSDs--;
    if (sd == maxValidSD)
      maxValidSD--;
  } else return false;
  return true;
}

GroupScanStats::GroupScanStats(UltraScanInfo *UltraSI) {
  memset(&latestip, 0, sizeof(latestip));
  memset(&timeout, 0, sizeof(timeout));
  USI = UltraSI;
  init_ultra_timing_vals(&timing, TIMING_GROUP, USI->numIncompleteHosts(), &(USI->perf), &USI->now);
  initialize_timeout_info(&to);
  /* Default timout should be much lower for arp */
  if (USI->ping_scan_arp)
    to.timeout = MAX(o.minRttTimeout(), MIN(o.initialRttTimeout(), INITIAL_ARP_RTT_TIMEOUT)) * 1000;
  num_probes_active = 0;
  numtargets = USI->numIncompleteHosts(); // They are all incomplete at the beginning
  numprobes = USI->numProbesPerHost();
  
  if (USI->scantype == CONNECT_SCAN || USI->ptech.connecttcpscan)
    CSI = new ConnectScanInfo;
  else CSI = NULL;
  probes_sent = probes_sent_at_last_wait = 0;
  lastping_sent = lastrcvd = USI->now;
  send_no_earlier_than = USI->now;
  send_no_later_than = USI->now;
  lastping_sent_numprobes = 0;
  pinghost = NULL;
  gettimeofday(&last_wait, NULL);
  num_hosts_timedout = 0;
}

GroupScanStats::~GroupScanStats() {
  delete CSI;
}

/* Called whenever a probe is sent to any host. Should only be called by
   HostScanStats::probeSent. */
void GroupScanStats::probeSent(unsigned int nbytes) {
  USI->send_rate_meter.update(nbytes, &USI->now);

  /* Find a new scheduling interval for minimum- and maximum-rate sending.
     Recall that these have effect only when --min-rate or --max-rate is
     given. */

  TIMEVAL_ADD(send_no_earlier_than, send_no_earlier_than,
    (time_t) (1000000.0 / o.max_packet_send_rate));
  /* Allow send_no_earlier_than to slip into the past. This allows the sending
     scheduler to catch up and make up for delays in other parts of the scan
     engine. If we were to update send_no_earlier_than to the present the
     sending rate could be much less than the maximum requested, even if the
     connection is capable of the maximum. */

  if (TIMEVAL_SUBTRACT(send_no_later_than, USI->now) > 0) {
    /* The next scheduled send is in the future. That means there's slack time
       during which the sending rate could drop. Pull the time back to the
       present to prevent that. */
    send_no_later_than = USI->now;
  }
  TIMEVAL_ADD(send_no_later_than, send_no_later_than,
    (time_t) (1000000.0 / o.min_packet_send_rate));
}

  /* Returns true if the GLOBAL system says that sending is OK.*/
bool GroupScanStats::sendOK(struct timeval *when) {
  int recentsends;

  /* In case it's not okay to send, arbitrarily say to check back in one
     second. */
  if (when)
    TIMEVAL_MSEC_ADD(*when, USI->now, 1000); 

  if ((USI->scantype == CONNECT_SCAN || USI->ptech.connecttcpscan)
      && CSI->numSDs >= CSI->maxSocketsAllowed)
    return false;

  /* We need to stop sending if it has been a long time since
     the last listen call, at least for systems such as Windoze that
     don't give us a proper pcap time.  Also for connect scans, since
     we don't get an exact response time with them either. */
  recentsends = USI->gstats->probes_sent - USI->gstats->probes_sent_at_last_wait;
  if (recentsends > 0 && 
      (USI->scantype == CONNECT_SCAN || USI->ptech.connecttcpscan || !pcap_recv_timeval_valid())) {
    int to_ms = (int) MAX(to.srtt * .75 / 1000, 50);
    if (TIMEVAL_MSEC_SUBTRACT(USI->now, last_wait) > to_ms)
      return false;
  }

  /* There are good arguments for limiting the number of probes sent
     between waits even when we do get appropriate receive times.  For
     example, overflowing the pcap receive buffer with responses is no
     fun.  On one of my Linux boxes, it seems to hold about 113
     responses when I scan localhost.  And half of those are the @#$#
     sends being received.  I think I'll put a limit of 50 sends per
     wait */
  if (recentsends >= 50)
    return false;

  /* Enforce a maximum scanning rate, if necessary. If it's too early to send,
     return false. If not, mark now as a good time to send and allow the
     congestion control to override it. */
  if (o.max_packet_send_rate != 0.0) {
    if (TIMEVAL_SUBTRACT(send_no_earlier_than, USI->now) > 0) {
      if (when)
        *when = send_no_earlier_than;
      return false;
    } else {
      if (when)
        *when = USI->now;
    }
  }

  /* Enforce a minimum scanning rate, if necessary. If we're ahead of schedule,
     record the time of the next scheduled send and submit to congestion
     control. If we're behind schedule, return true to indicate that we need to
     send right now. */
  if (o.min_packet_send_rate != 0.0) {
    if (TIMEVAL_SUBTRACT(send_no_later_than, USI->now) > 0) {
      if (when)
        *when = send_no_later_than;
    } else {
      if (when)
        *when = USI->now;
      return true;
    }
  }

  /* In case the user specifically asked for no group congestion control */
  if (o.nogcc) {
    if (when)
      *when = USI->now;
    return true;
  }

  /* When there is only one target left, let the host congestion
     stuff deal with it. */
  if (USI->numIncompleteHostsLessThan(2)) {
    if (when)
      *when = USI->now;
    return true;
  }

  if (timing.cwnd >= num_probes_active + 0.5) {
    if (when)
      *when = USI->now;
    return true;
  }

  return false;
}

/* Returns the scaling factor to use when incrementing the congestion window.
   This is the minimum of num_replies_expected / num_replies_received and
   cc_scale_max. */
double GroupScanStats::cc_scale() {
  double ratio;

  assert(timing.num_replies_received > 0);
  ratio = (double) timing.num_replies_expected / timing.num_replies_received;

  return MIN(ratio, USI->perf.cc_scale_max);
}

/* Return true if pingprobe is an appropriate ping probe for the currently
   running scan. Because ping probes persist between host discovery and port
   scanning stages, it's possible to have a ping probe that is not relevant for
   the scan type, or won't be caught by the pcap filters. Examples of
   inappropriate ping probes are an ARP ping for a TCP scan, or a raw SYN ping
   for a connect scan. */
static bool pingprobe_is_appropriate(const UltraScanInfo *USI,
                                     const probespec *pingprobe) {
  switch(pingprobe->type){
    case(PS_NONE):
        return true;
    case(PS_CONNECTTCP):
        return USI->scantype == CONNECT_SCAN || (USI->ping_scan && USI->ptech.connecttcpscan);
  case(PS_TCP):
  case(PS_UDP):
  case(PS_SCTP):
	return (USI->tcp_scan && USI->scantype != CONNECT_SCAN) ||
            USI->udp_scan ||
            USI->sctp_scan ||
            (USI->ping_scan && (USI->ptech.rawtcpscan || USI->ptech.rawudpscan || USI->ptech.rawsctpscan));
  case(PS_PROTO):
    return USI->prot_scan || (USI->ping_scan && USI->ptech.rawprotoscan);
  case(PS_ICMP):
    return ((USI->ping_scan && !USI->ping_scan_arp )|| pingprobe->pd.icmp.type == 3);
  case(PS_ARP):
    return USI->ping_scan_arp;
  }
  return false;
}

HostScanStats::HostScanStats(Target *t, UltraScanInfo *UltraSI) {
  target = t; 
  USI=UltraSI; 
  next_portidx = 0; 
  sent_arp = false;
  next_ackportpingidx = 0;
  next_synportpingidx = 0;
  next_udpportpingidx = 0;
  next_sctpportpingidx = 0;
  next_protoportpingidx = 0;
  sent_icmp_ping = false;
  sent_icmp_mask = false;
  sent_icmp_ts = false;
  retry_capped_warned = false;
  num_probes_active = 0; 
  num_probes_waiting_retransmit = 0;
  lastping_sent = lastprobe_sent = lastrcvd = USI->now;
  lastping_sent_numprobes = 0;
  nxtpseq = 1;
  max_successful_tryno = 0;
  tryno_mayincrease = true;
  ports_finished = 0;
  numprobes_sent = 0;
  memset(&completiontime, 0, sizeof(completiontime));
  init_ultra_timing_vals(&timing, TIMING_HOST, 1, &(USI->perf), &USI->now);
  bench_tryno = 0;
  memset(&sdn, 0, sizeof(sdn));
  sdn.last_boost = USI->now;
  sdn.delayms = o.scan_delay;
  rld.max_tryno_sent = 0;
  rld.rld_waiting = false;
  rld.rld_waittime = USI->now;
  if (!pingprobe_is_appropriate(USI, &target->pingprobe)) {
    if (o.debugging > 1)
      log_write(LOG_STDOUT, "%s pingprobe type %s is inappropriate for this scan type; resetting.\n", target->targetipstr(), pspectype2ascii(target->pingprobe.type));
    memset(&target->pingprobe, 0, sizeof(target->pingprobe));
    target->pingprobe_state = PORT_UNKNOWN;
  }
}

HostScanStats::~HostScanStats() {
  list<UltraProbe *>::iterator probeI, next;

/* Move any hosts from the bench to probes_outstanding for easier deletion  */
  for(probeI = probes_outstanding.begin(); probeI != probes_outstanding.end(); 
      probeI = next) {
    next = probeI;
    next++;
    destroyOutstandingProbe(probeI);
  }
}

/* Called whenever a probe is sent to this host. Takes care of updating scan
   delay and rate limiting variables. */
void HostScanStats::probeSent(unsigned int nbytes) {
  lastprobe_sent = USI->now;

  /* Update group variables. */
  USI->gstats->probeSent(nbytes);
}

/* How long I am currently willing to wait for a probe response before
   considering it timed out.  Uses the host values from target if they
   are available, otherwise from gstats.  Results returned in
   MICROseconds.  */
unsigned long HostScanStats::probeTimeout() {
  if (target->to.srtt > 0) {
    /* We have at least one timing value to use.  Good enough, I suppose */
    return target->to.timeout;
  } else if (USI->gstats->to.srtt > 0) {
    /* OK, we'll use this one instead */
    return USI->gstats->to.timeout;
  } else {
    return target->to.timeout; /* It comes with a default */
  }
}

  /* How long I'll wait until completely giving up on a probe.
     Timedout probes are often marked as such (and sometimes
     considered a drop), but kept in the list just in case they come
     really late.  But after probeExpireTime(), I don't waste time
     keeping them around. Give in MICROseconds. The expiry time can
     depend on the type of probe. Pass NULL to get the default time. */
unsigned long HostScanStats::probeExpireTime(const UltraProbe *probe) {
  if (probe == NULL || probe->type == UltraProbe::UP_CONNECT)
    /* timedout probes close socket -- late resp. impossible */
    return probeTimeout();
  else
    /* Wait a bit longer after probeTimeout. */
    return MIN(10000000, probeTimeout() * 10);
}

/* Returns OK if sending a new probe to this host is OK (to avoid
   flooding). If when is non-NULL, fills it with the time that sending
   will be OK assuming no pending probes are resolved by responses
   (call it again if they do).  when will become now if it returns
   true. */
bool HostScanStats::sendOK(struct timeval *when) {
  struct ultra_timing_vals tmng;
  list<UltraProbe *>::iterator probeI;
  struct timeval probe_to, earliest_to, sendTime;
  long tdiff;

  if (target->timedOut(&USI->now) || completed()) {
    if (when) *when = USI->now;
    return false;
  }

  /* If the group stats say we need to send a probe to enforce a minimum
     scanning rate, then we need to step up and send a probe. */
  if (o.min_packet_send_rate != 0.0) {
    if (TIMEVAL_SUBTRACT(USI->gstats->send_no_later_than, USI->now) <= 0) {
      if (when)
        *when = USI->now;
      return true;
    }
  }

  if (rld.rld_waiting) {
    if (TIMEVAL_AFTER(rld.rld_waittime, USI->now)) {
      if (when)
        *when = rld.rld_waittime;
      return false;
    } else {
      if (when)
        *when = USI->now;
      return true;
    }
  }

  if (sdn.delayms) {
    if (TIMEVAL_MSEC_SUBTRACT(USI->now, lastprobe_sent) < (int) sdn.delayms) {
      if (when) { TIMEVAL_MSEC_ADD(*when, lastprobe_sent, sdn.delayms); }
      return false;
    }
  }

  getTiming(&tmng);
  if (tmng.cwnd >= num_probes_active + .5 && 
      (freshPortsLeft() || num_probes_waiting_retransmit || !retry_stack.empty())) {
    if (when) *when = USI->now;
    return true;
  }

  if (!when)
    return false;

  TIMEVAL_MSEC_ADD(earliest_to, USI->now, 10000);

  // Any timeouts coming up?
  for(probeI = probes_outstanding.begin(); probeI != probes_outstanding.end();
      probeI++) {
    if (!(*probeI)->timedout) {
      TIMEVAL_MSEC_ADD(probe_to, (*probeI)->sent, probeTimeout() / 1000);
      if (TIMEVAL_SUBTRACT(probe_to, earliest_to) < 0) {
	earliest_to = probe_to;
      }
    }
  }

  // Will any scan delay affect this?
  if (sdn.delayms) {    
    TIMEVAL_MSEC_ADD(sendTime, lastprobe_sent, sdn.delayms);
    if (TIMEVAL_BEFORE(sendTime, USI->now))
      sendTime = USI->now;
    tdiff = TIMEVAL_MSEC_SUBTRACT(earliest_to, sendTime);
    
    /* Timeouts previous to the sendTime requirement are pointless,
       and those later than sendTime are not needed if we can send a
       new packet at sendTime */
    if (tdiff < 0) {
      earliest_to = sendTime;
    } else {
      getTiming(&tmng);
      if (tdiff > 0 && tmng.cwnd > num_probes_active + .5) {
	earliest_to = sendTime;
      }
    }
  }

  *when = earliest_to;
  return false;
}

/* If there are pending probe timeouts, fills in when with the time of
   the earliest one and returns true.  Otherwise returns false and
   puts now in when. */
bool HostScanStats::nextTimeout(struct timeval *when) {
  struct timeval probe_to, earliest_to;
  list<UltraProbe *>::iterator probeI;
  bool firstgood = true;

  assert(when);
  memset(&probe_to, 0, sizeof(probe_to));
  memset(&earliest_to, 0, sizeof(earliest_to));

  for(probeI = probes_outstanding.begin(); probeI != probes_outstanding.end();
      probeI++) {
    if (!(*probeI)->timedout) {
      TIMEVAL_ADD(probe_to, (*probeI)->sent, probeTimeout());
      if (firstgood || TIMEVAL_SUBTRACT(probe_to, earliest_to) < 0) {
	earliest_to = probe_to;
	firstgood = false;
      }
    }
  }

  *when = (firstgood)? USI->now : earliest_to;
  return (firstgood)? false : true;
}

  /* gives the maximum try number (try numbers start at zero and
     increments for each retransmission) that may be used, based on
     the scan type, observed network reliability, timing mode, etc.
     This may change during the scan based on network traffic.  If
     capped is not null, it will be filled with true if the tryno is
     at its upper limit.  That often calls for a warning to be issued,
     and marking of remaining timedout ports firewalled or whatever is
     appropriate.  If mayincrease is non-NULL, it is set to whether
     the allowedTryno may increase again.  If it is false, any probes
     which have reached the given limit may be dealth with. */
unsigned int HostScanStats::allowedTryno(bool *capped, bool *mayincrease) {
  list<UltraProbe *>::iterator probeI;
  UltraProbe *probe = NULL;
  bool allfinished = true;
  unsigned int maxval = 0;

  /* TODO: This should perhaps differ by scan type. */
  maxval = MAX(1, max_successful_tryno + 1);
  if (maxval > (unsigned int) USI->perf.tryno_cap) {
    if (capped) *capped = true;
    maxval = USI->perf.tryno_cap;
    tryno_mayincrease = false; /* It never exceeds the cap */
  } else if (capped) *capped = false;

  /* Decide if the tryno can possibly increase.  */
  if (tryno_mayincrease && num_probes_active == 0 && freshPortsLeft() == 0) {
    /* If every outstanding probe is timedout and at maxval, then no further
       retransmits are necessary. */
    for(probeI = probes_outstanding.begin(); 
	probeI != probes_outstanding.end(); probeI++) {
      probe = *probeI;
      assert(probe->timedout);
      if (!probe->retransmitted && !probe->isPing() && probe->tryno < maxval) {
	/* Needs at least one more retransmit. */
	allfinished = false;
	break;
      }
    }
    if (allfinished)
      tryno_mayincrease = false;
  }

  if (mayincrease)
    *mayincrease = tryno_mayincrease;
  
  return maxval;
}


UltraScanInfo::UltraScanInfo() {
}

UltraScanInfo::~UltraScanInfo() {
  while(!incompleteHosts.empty()) {
    delete incompleteHosts.front();
    incompleteHosts.pop_front();
  }
  while(!completedHosts.empty()) {
    delete completedHosts.front();
    completedHosts.pop_front();
  }
  delete gstats;
  delete SPM;
  if (rawsd >= 0) { close(rawsd); rawsd = -1; }
  if (pd) { pcap_close(pd); pd = NULL; }
  if (ethsd) { ethsd = NULL; /* NO need to eth_close it due to caching */ }
}

/* Returns true if this scan is a "raw" scan. A raw scan is ont that requires a
   raw socket or ethernet handle to send, or a pcap sniffer to receive.
   Basically, any scan type except pure TCP connect scans are raw. */
bool UltraScanInfo::isRawScan() {
  return scantype != CONNECT_SCAN
    && (tcp_scan || udp_scan || sctp_scan || prot_scan || ping_scan_arp
      || (ping_scan && (ptech.rawicmpscan || ptech.rawtcpscan || ptech.rawudpscan
        || ptech.rawsctpscan || ptech.rawprotoscan)));
}

 /* A circular buffer of the incompleteHosts.  nextIncompleteHost() gives
     the next one.  The first time it is called, it will give the
     first host in the list.  If incompleteHosts is empty, returns
     NULL. */
HostScanStats *UltraScanInfo::nextIncompleteHost() {
  HostScanStats *nxt;

  if (incompleteHosts.empty())
    return NULL;

  nxt = *nextI;
  nextI++;
  if (nextI == incompleteHosts.end())
    nextI = incompleteHosts.begin();

  return nxt;
}

/* Return a number between 0.0 and 1.0 inclusive indicating how much of the scan
   is done. */
double UltraScanInfo::getCompletionFraction() {
  list<HostScanStats *>::iterator hostI;
  double total;
  
  /* Add 1 for each completed host. */
  total = gstats->numtargets - numIncompleteHosts();
  /* Get the completion fraction for each incomplete host. */
  for(hostI = incompleteHosts.begin(); hostI != incompleteHosts.end(); hostI++) {
    HostScanStats *host = *hostI;
    int maxtries = host->allowedTryno(NULL, NULL) + 1;
    double thishostpercdone;

    // This is inexact (maxtries - 1) because numprobes_sent includes
    // at least one try of ports_finished.
    thishostpercdone = host->ports_finished * (maxtries - 1) + host->numprobes_sent;
    thishostpercdone /= maxtries * gstats->numprobes;
    if (thishostpercdone >= 0.9999)
      thishostpercdone = 0.9999;
    total += thishostpercdone;
  }

  return total / gstats->numtargets;
}

/* This is the function for tuning the major values that affect
   scan performance */
static void init_perf_values(struct ultra_scan_performance_vars *perf) {
  memset(perf, 0, sizeof(*perf));
  /* TODO: I should revisit these values for tuning.  They should probably
     at least be affected by -T. */
  perf->low_cwnd = MAX(o.min_parallelism, 1);
  perf->max_cwnd = o.max_parallelism? o.max_parallelism : 300;
  perf->group_initial_cwnd = box(o.min_parallelism, perf->max_cwnd, 10);
  perf->host_initial_cwnd = perf->group_initial_cwnd;
  perf->slow_incr = 1;
  /* The congestion window grows faster with more aggressive timing. */
  if (o.timing_level < 4)
    perf->ca_incr = 1;
  else
    perf->ca_incr = 2;
  perf->cc_scale_max = 50;
  perf->initial_ssthresh = 75;
  perf->ping_magnifier = 3;
  perf->pingtime = 1250000;
  perf->group_drop_cwnd_divisor = 2.0;
  /* Change the amount that ssthresh drops based on the timing level. */
  double ssthresh_divisor;
  if (o.timing_level <= 3)
    ssthresh_divisor = (3.0 / 2.0);
  else if (o.timing_level <= 4)
    ssthresh_divisor = (4.0 / 3.0);
  else
    ssthresh_divisor = (5.0 / 4.0);
  perf->group_drop_ssthresh_divisor = ssthresh_divisor;
  perf->host_drop_ssthresh_divisor = ssthresh_divisor;
  perf->tryno_cap = o.getMaxRetransmissions();
}

/* Initialize the state for ports that don't receive a response in all the
   targets. */
static void set_default_port_state(vector<Target *> &targets, stype scantype) {
  vector<Target *>::iterator target;

  for (target = targets.begin(); target != targets.end(); target++) {
    switch (scantype) {
    case SYN_SCAN:
    case ACK_SCAN:
    case WINDOW_SCAN:
    case CONNECT_SCAN:
      (*target)->ports.setDefaultPortState(IPPROTO_TCP, PORT_FILTERED);
      break;
    case SCTP_INIT_SCAN:
      (*target)->ports.setDefaultPortState(IPPROTO_SCTP, PORT_FILTERED);
      break;
    case NULL_SCAN:
    case FIN_SCAN:
    case MAIMON_SCAN:
    case XMAS_SCAN:
      (*target)->ports.setDefaultPortState(IPPROTO_TCP, PORT_OPENFILTERED);
      break;
    case UDP_SCAN:
      (*target)->ports.setDefaultPortState(IPPROTO_UDP, PORT_OPENFILTERED);
      break;
    case IPPROT_SCAN:
      (*target)->ports.setDefaultPortState(IPPROTO_IP, PORT_OPENFILTERED);
      break;
    case SCTP_COOKIE_ECHO_SCAN:
      (*target)->ports.setDefaultPortState(IPPROTO_SCTP, PORT_OPENFILTERED);
      break;
    case PING_SCAN:
    case PING_SCAN_ARP:
      break;
    default:
      fatal("Unexpected scan type found in %s()", __func__);
    }
  }
}

/* Order of initializations in this function CAN BE IMPORTANT, so be careful
 mucking with it. */
void UltraScanInfo::Init(vector<Target *> &Targets, struct scan_lists *pts, stype scantp) {
  unsigned int targetno = 0;
  HostScanStats *hss;
  int num_timedout = 0;

  gettimeofday(&now, NULL);

  ports = pts;

  seqmask = get_random_u32();
  scantype = scantp;
  SPM = new ScanProgressMeter(scantype2str(scantype));
  send_rate_meter.start(&now);
  tcp_scan = udp_scan = sctp_scan = prot_scan = false;
  ping_scan = noresp_open_scan = ping_scan_arp = false;
  memset((char *) &ptech, 0, sizeof(ptech));
  switch(scantype) {
  case FIN_SCAN:
  case XMAS_SCAN:
  case MAIMON_SCAN:
  case NULL_SCAN:
    noresp_open_scan = true;
  case ACK_SCAN:
  case CONNECT_SCAN:
  case SYN_SCAN:
  case WINDOW_SCAN:
    tcp_scan = true;
    break;
  case UDP_SCAN:
    noresp_open_scan = true;
    udp_scan = true;
    break;
  case SCTP_INIT_SCAN:
  case SCTP_COOKIE_ECHO_SCAN:
    sctp_scan = true;
    break;
  case IPPROT_SCAN:
    noresp_open_scan = true;
    prot_scan = true;
    break;
  case PING_SCAN:
    ping_scan = true;
    /* What kind of pings are we doing? */
    if (o.pingtype & (PINGTYPE_ICMP_PING|PINGTYPE_ICMP_MASK|PINGTYPE_ICMP_TS)) 
      ptech.rawicmpscan = 1;
    if (o.pingtype & PINGTYPE_UDP) 
      ptech.rawudpscan = 1;
    if (o.pingtype & PINGTYPE_SCTP_INIT)
      ptech.rawsctpscan = 1;
    if (o.pingtype & PINGTYPE_TCP) {
      if (o.isr00t && o.af() == AF_INET)
        ptech.rawtcpscan = 1;
      else
        ptech.connecttcpscan = 1;
    }
    if (o.pingtype & PINGTYPE_PROTO)
      ptech.rawprotoscan = 1;
    if (o.pingtype & PINGTYPE_CONNECTTCP)
      ptech.connecttcpscan = 1;
    break;
  case PING_SCAN_ARP:      
    ping_scan = true;
    ping_scan_arp = true;
    break;
  default:
    break;
  }

  set_default_port_state(Targets, scantype);

  init_perf_values(&perf);

  /* Keep a completed host around for a standard TCP MSL (2 min) */
  completedHostLifetime = 120000;
  memset(&lastCompletedHostRemoval, 0, sizeof(lastCompletedHostRemoval));

  for(targetno = 0; targetno < Targets.size(); targetno++) {
    if (Targets[targetno]->timedOut(&now)) {
      num_timedout++;
      continue;
    }

    hss = new HostScanStats(Targets[targetno], this);
    incompleteHosts.push_back(hss);
  }
  numInitialTargets = Targets.size();
  nextI = incompleteHosts.begin();

  gstats = new GroupScanStats(this); /* Peeks at several elements in USI - careful of order */
  gstats->num_hosts_timedout += num_timedout;

  pd = NULL;
  rawsd = -1;
  ethsd = NULL;

  /* See if we need an ethernet handle or raw socket. Basically, it's if we
     aren't doing a TCP connect scan, or if we're doing a ping scan that
     requires it. */
  if (isRawScan()) {
    if (ping_scan_arp || ((o.sendpref & PACKET_SEND_ETH) && 
			  Targets[0]->ifType() == devt_ethernet)) {
      /* We'll send ethernet packets with dnet */
      ethsd = eth_open_cached(Targets[0]->deviceName());
      if (ethsd == NULL)
	fatal("dnet: Failed to open device %s", Targets[0]->deviceName());
      rawsd = -1;
    } else {
      /* Initialize a raw socket */
#ifdef WIN32
      win32_warn_raw_sockets(Targets[0]->deviceName());
#endif
      if ((rawsd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0 )
	pfatal("socket troubles in %s", __func__);
      /* We do not wan't to unblock the socket since we want to wait 
	 if kernel send buffers fill up rather than get ENOBUF, and
	 we won't be receiving on the socket anyway 
	 unblock_socket(rawsd);*/
      broadcast_socket(rawsd);
#ifndef WIN32
      sethdrinclude(rawsd); 
#endif
      ethsd = NULL;
    }
  }
}

/* Return the total number of probes that may be sent to each host. This never
   changes after initialization. */
unsigned int UltraScanInfo::numProbesPerHost()
{
  unsigned int numprobes = 0;

  if (tcp_scan) {
    numprobes = ports->tcp_count;
  } else if (udp_scan) {
    numprobes = ports->udp_count;
  } else if (sctp_scan) {
    numprobes = ports->sctp_count;
  } else if (prot_scan) {
    numprobes = ports->prot_count;
  } else if (ping_scan_arp) {
    numprobes = 1;
  } else if (ping_scan) {
    numprobes = 0;
    if (ptech.rawtcpscan) {
      if (o.pingtype & PINGTYPE_TCP_USE_ACK)
        numprobes += ports->ack_ping_count;
      if (o.pingtype & PINGTYPE_TCP_USE_SYN)
        numprobes += ports->syn_ping_count;
    }
    if (ptech.rawudpscan)
      numprobes += ports->udp_ping_count;
    if (ptech.rawsctpscan)
      numprobes += ports->sctp_ping_count;
    if (ptech.rawicmpscan) {
      if (o.pingtype & PINGTYPE_ICMP_PING)
        numprobes++;
      if (o.pingtype & PINGTYPE_ICMP_MASK)
        numprobes++;
      if (o.pingtype & PINGTYPE_ICMP_TS)
        numprobes++;
    }
    if (ptech.rawprotoscan)
      numprobes += ports->proto_ping_count;
    if (ptech.connecttcpscan)
      numprobes += ports->syn_ping_count;
  } else assert(0); /* TODO: RPC scan */

  return numprobes;
}

  /* Consults with the group stats, and the hstats for every
     incomplete hosts to determine whether any probes may be sent.
     Returns true if they can be sent immediately.  If when is
     non-NULL, it is filled with the next possible time that probes
     can be sent, assuming no probe responses are received (call it
     again if they are).  when will be now, if the function returns
     true */
bool UltraScanInfo::sendOK(struct timeval *when) {
  struct timeval lowhtime = {0};
  struct timeval tmptv;
  list<HostScanStats *>::iterator host;
  bool ggood = false;
  bool hgood = false;
  bool thisHostGood = false;
  bool foundgood = false;

  ggood = gstats->sendOK(when);

  if (!ggood) {
    if (when) {
      lowhtime = *when;
      // Can't do anything until global is OK - means packet receipt
      // or probe timeout.
      for(host = incompleteHosts.begin(); host != incompleteHosts.end(); 
	  host++) {
	if ((*host)->nextTimeout(&tmptv)) {
	  if (TIMEVAL_SUBTRACT(tmptv, lowhtime) < 0)
	    lowhtime = tmptv;
	}
      }
      *when = lowhtime;
    }
  } else {
    for(host = incompleteHosts.begin(); host != incompleteHosts.end(); host++) {
      thisHostGood = (*host)->sendOK(&tmptv);
      if (ggood && thisHostGood) {
	lowhtime = tmptv;
	hgood = true;
	foundgood = true;
	break;
      }
      
      if (!foundgood || TIMEVAL_SUBTRACT(lowhtime, tmptv) > 0) {
	lowhtime = tmptv;
	foundgood = true;
      }
    }
    
    assert(foundgood);
  }
  
  /* Defer to the group stats if they need a shorter delay to enforce a minimum
     packet sending rate. */
  if (o.min_packet_send_rate != 0.0) {
    if (TIMEVAL_MSEC_SUBTRACT(gstats->send_no_later_than, lowhtime) < 0)
      lowhtime = gstats->send_no_later_than;
  }

  if (TIMEVAL_MSEC_SUBTRACT(lowhtime, now) < 0)
    lowhtime = now;

  if (when) *when = lowhtime;

  return (TIMEVAL_MSEC_SUBTRACT(lowhtime, now) == 0)? true : false;
}

/* Find a HostScanStats by its IP address in the incomplete and completed lists.
   Returns NULL if none are found. */
HostScanStats *UltraScanInfo::findHost(struct sockaddr_storage *ss) {
  list<HostScanStats *>::iterator hss;
  struct sockaddr_in *sin = (struct sockaddr_in *) ss;

  if (sin->sin_family != AF_INET)
    fatal("%s passed a non IPv4 address", __func__);

  for(hss = incompleteHosts.begin(); hss != incompleteHosts.end(); hss++) {
    if ((*hss)->target->v4hostip()->s_addr == sin->sin_addr.s_addr) {
      if (o.debugging > 2)
	log_write(LOG_STDOUT, "Found %s in incomplete hosts list.\n", (*hss)->target->targetipstr());
      return *hss;
    }
  }
  for(hss = completedHosts.begin(); hss != completedHosts.end(); hss++) {
    if ((*hss)->target->v4hostip()->s_addr == sin->sin_addr.s_addr) {
      if (o.debugging > 2)
	log_write(LOG_STDOUT, "Found %s in completed hosts list.\n", (*hss)->target->targetipstr());
      return *hss;
    }
  }

  return NULL;
}

bool UltraScanInfo::numIncompleteHostsLessThan(unsigned int n) {
  std::list<HostScanStats *>::iterator hostI;
  unsigned int count;

  count = 0;
  hostI = incompleteHosts.begin();
  while (count < n && hostI != incompleteHosts.end()) {
    hostI++;
    count++;
  }

  return count < n;
}

static bool pingprobe_is_better(const probespec *new_probe, int new_state,
                                const probespec *old_probe, int old_state);

  /* Removes any hosts that have completed their scans from the incompleteHosts
     list, and remove any hosts from completedHosts which have exceeded their
     lifetime.  Returns the number of hosts removed. */
int UltraScanInfo::removeCompletedHosts() {
  list<HostScanStats *>::iterator hostI, nxt;
  HostScanStats *hss = NULL;
  int hostsRemoved = 0;
  bool timedout = false;

  /* We don't want to run this all of the time */
  if ((unsigned) TIMEVAL_MSEC_SUBTRACT(now, lastCompletedHostRemoval) > completedHostLifetime / 2) {
    for (hostI = completedHosts.begin(); hostI != completedHosts.end(); hostI = nxt) {
      nxt = hostI;
      nxt++;
      hss = (*hostI);

      /* Keep it if it's our port scan ping host */
      if (hss == gstats->pinghost)
        continue;

      if ((unsigned) TIMEVAL_MSEC_SUBTRACT(now, hss->completiontime) > completedHostLifetime) {
        completedHosts.erase(hostI);
        hostsRemoved++;
      }
    }
    lastCompletedHostRemoval = now;
  }

  for(hostI = incompleteHosts.begin(); hostI != incompleteHosts.end();
      hostI = nxt) {
    nxt = hostI;
    nxt++;
    hss = *hostI;
    timedout = hss->target->timedOut(&now);
    if (hss->completed() || timedout) {
      /* A host to remove!  First adjust nextI appropriately */
      if (nextI == hostI && incompleteHosts.size() > 1) {
	nextI++;
	if (nextI == incompleteHosts.end())
	  nextI = incompleteHosts.begin();
      }
      if (o.verbose && gstats->numprobes > 50) {
	int remain = incompleteHosts.size() - 1;
	if (remain && !timedout)
	  log_write(LOG_STDOUT, "Completed %s against %s in %.2fs (%d %s)\n",
		    scantype2str(scantype), hss->target->targetipstr(), 
		    TIMEVAL_MSEC_SUBTRACT(now, SPM->begin) / 1000.0, remain, 
		    (remain == 1)? "host left" : "hosts left");
	else if (timedout)
	  log_write(LOG_STDOUT, "%s timed out during %s (%d %s)\n",
		    hss->target->targetipstr(), scantype2str(scantype), remain,
		    (remain == 1)? "host left" : "hosts left");
      }
      if (o.debugging > 2) {
        unsigned int num_outstanding_probes;
        num_outstanding_probes = hss->num_probes_outstanding();
        log_write(LOG_PLAIN, "Moving %s to completed hosts list with %d outstanding %s.\n",
                  hss->target->targetipstr(), num_outstanding_probes,
                  num_outstanding_probes == 1 ? "probe" : "probes");
        if (o.debugging > 3) {
          char tmpbuf[64];
          std::list<UltraProbe *>::iterator iter;
          for (iter = hss->probes_outstanding.begin(); iter != hss->probes_outstanding.end(); iter++)
            log_write(LOG_PLAIN, "* %s\n", probespec2ascii((probespec *) (*iter)->pspec(), tmpbuf, sizeof(tmpbuf)));
        }
      }
      hss->completiontime = now;
      completedHosts.push_front(hss);
      incompleteHosts.erase(hostI);
      hostsRemoved++;
      /* Consider making this host the new global ping host during its
         retirement in the completed hosts list. */
      HostScanStats *pinghost = gstats->pinghost;
      if ((pinghost == NULL && hss->target->pingprobe.type != PS_NONE)
          || (pinghost != NULL && pinghost->num_probes_active == 0
              && !pingprobe_is_better(&pinghost->target->pingprobe, pinghost->target->pingprobe_state, &hss->target->pingprobe, hss->target->pingprobe_state))) {
        if (o.debugging > 1)
          log_write(LOG_PLAIN, "Changing global ping host to %s.\n", hss->target->targetipstr());
        gstats->pinghost = hss;
      }
      if (timedout) gstats->num_hosts_timedout++;
      hss->target->stopTimeOutClock(&now);
    }
  }
  return hostsRemoved;
}

/* Determines an ideal number of hosts to be scanned (port scan, os
   scan, version detection, etc.) in parallel after the ping scan is
   completed.  This is a balance between efficiency (more hosts in
   parallel often reduces scan time per host) and results latency (you
   need to wait for all hosts to finish before Nmap can spit out the
   results).  Memory consumption usually also increases with the
   number of hosts scanned in parallel, though rarely to significant
   levels. */
int determineScanGroupSize(int hosts_scanned_so_far, 
			   struct scan_lists *ports) {
  int groupsize = 16;

  if (o.UDPScan())
    groupsize = 128;
  else if (o.SCTPScan())
    groupsize = 128;
  else if (o.TCPScan()) {
    groupsize = MAX(1024 / (ports->tcp_count ? ports->tcp_count : 1), 64);
    if (ports->tcp_count > 1000 && o.timing_level <= 4) {
      int quickgroupsz = 4;
      if (o.timing_level == 4) quickgroupsz = 8;
      if (hosts_scanned_so_far == 0)
	groupsize = quickgroupsz; // Give quick results for the very first batch
      else if (hosts_scanned_so_far == quickgroupsz && 
	     groupsize > quickgroupsz * 2)
	/* account for initial quick-scan to keep us aligned
	   on common network boundaries (e.g. /24) */
	groupsize -= quickgroupsz; 
    }
  }

  groupsize = box(o.minHostGroupSz(), o.maxHostGroupSz(), groupsize);

  return groupsize;
}

/* Initialize the ultra_timing_vals structure timing.  The utt must be
   TIMING_HOST or TIMING_GROUP.  If you happen to have the current
   time handy, pass it as now, otherwise pass NULL */
static void init_ultra_timing_vals(ultra_timing_vals *timing, 
				   enum ultra_timing_type utt, 
				   int num_hosts_in_group, 
				   struct ultra_scan_performance_vars *perf,
				   struct timeval *now) {
  timing->cwnd = (utt == TIMING_HOST)? perf->host_initial_cwnd : perf->group_initial_cwnd;
  timing->ssthresh = perf->initial_ssthresh; /* Will be reduced if any packets are dropped anyway */
  timing->num_replies_expected = 0;
  timing->num_replies_received = 0;
  timing->num_updates = 0;
  if (now)
    timing->last_drop = *now;
  else gettimeofday(&timing->last_drop, NULL);
}

/* Returns the next probe to try against target.  Supports many
   different types of probes (see probespec structure).  Returns 0 and
   fills in pspec if there is a new probe, -1 if there are none
   left. */
static int get_next_target_probe(UltraScanInfo *USI, HostScanStats *hss, 
				 probespec *pspec) {
  assert(pspec);

  if (USI->tcp_scan) {
    if (hss->next_portidx >= USI->ports->tcp_count)
      return -1;
    if (USI->scantype == CONNECT_SCAN)
      pspec->type = PS_CONNECTTCP;
    else
      pspec->type = PS_TCP;
    pspec->proto = IPPROTO_TCP;

    pspec->pd.tcp.dport = USI->ports->tcp_ports[hss->next_portidx++];
    if (USI->scantype == CONNECT_SCAN) 
      pspec->pd.tcp.flags = TH_SYN;
    else if (o.scanflags != -1)
      pspec->pd.tcp.flags = o.scanflags;
    else {
      switch(USI->scantype) {
      case SYN_SCAN: pspec->pd.tcp.flags = TH_SYN; break;
      case ACK_SCAN: pspec->pd.tcp.flags = TH_ACK; break;
      case XMAS_SCAN: pspec->pd.tcp.flags = TH_FIN|TH_URG|TH_PUSH; break;
      case NULL_SCAN: pspec->pd.tcp.flags = 0; break;
      case FIN_SCAN: pspec->pd.tcp.flags = TH_FIN; break;
      case MAIMON_SCAN: pspec->pd.tcp.flags = TH_FIN|TH_ACK; break;
      case WINDOW_SCAN: pspec->pd.tcp.flags = TH_ACK; break;
      default:
	assert(0);
	break;
      }
    }
    return 0;
  } else if (USI->udp_scan) {
    if (hss->next_portidx >= USI->ports->udp_count)
      return -1;
    pspec->type = PS_UDP;
    pspec->proto = IPPROTO_UDP;
    pspec->pd.udp.dport = USI->ports->udp_ports[hss->next_portidx++];
    return 0;
  } else if (USI->sctp_scan) {
     if (hss->next_portidx >= USI->ports->sctp_count)
      return -1;
    pspec->type = PS_SCTP;
    pspec->proto = IPPROTO_SCTP;
    pspec->pd.sctp.dport = USI->ports->sctp_ports[hss->next_portidx++];
    switch (USI->scantype) {
      case SCTP_INIT_SCAN:
        pspec->pd.sctp.chunktype = SCTP_INIT;
        break;
      case SCTP_COOKIE_ECHO_SCAN:
        pspec->pd.sctp.chunktype = SCTP_COOKIE_ECHO;
        break;
      default:
        assert(0);
    }
    return 0;
  } else if (USI->prot_scan) {
    if (hss->next_portidx >= USI->ports->prot_count)
      return -1;
    pspec->type = PS_PROTO;
    pspec->proto = USI->ports->prots[hss->next_portidx++];
    return 0;
  } else if (USI->ping_scan_arp) {
    if (hss->sent_arp)
      return -1;
    pspec->type = PS_ARP;
    hss->sent_arp = true;
    return 0;
  } else if (USI->ping_scan) {
    /* This is ordered to try probes of higher effectiveness first:
         -PE -PS -PA -PP -PU
       -PA is slightly better than -PS when combined with -PE, but give -PS an
       edge because it is less likely to be dropped by firewalls. */
    if (USI->ptech.rawicmpscan) {
      pspec->type = PS_ICMP;
      pspec->proto = IPPROTO_ICMP;
      if ((o.pingtype & PINGTYPE_ICMP_PING) && !hss->sent_icmp_ping) {
        hss->sent_icmp_ping = true;
        pspec->pd.icmp.type = ICMP_ECHO;
        pspec->pd.icmp.code = 0;
        return 0;
      }
    }
    if (USI->ptech.rawtcpscan) {
      pspec->type = PS_TCP;
      pspec->proto = IPPROTO_TCP;
      if ((o.pingtype & PINGTYPE_TCP_USE_SYN)
        && hss->next_synportpingidx < USI->ports->syn_ping_count) {
        pspec->pd.tcp.dport = USI->ports->syn_ping_ports[hss->next_synportpingidx++];
        pspec->pd.tcp.flags = TH_SYN;
        return 0;
      }
      if ((o.pingtype & PINGTYPE_TCP_USE_ACK)
        && hss->next_ackportpingidx < USI->ports->ack_ping_count) {
        pspec->pd.tcp.dport = USI->ports->ack_ping_ports[hss->next_ackportpingidx++];
        pspec->pd.tcp.flags = TH_ACK;
        return 0;
      }
    }
    if (USI->ptech.rawicmpscan) {
      pspec->type = PS_ICMP;
      pspec->proto = IPPROTO_ICMP;
      if ((o.pingtype & PINGTYPE_ICMP_TS) && !hss->sent_icmp_ts) {
        hss->sent_icmp_ts = true;
        pspec->pd.icmp.type = ICMP_TSTAMP;
        pspec->pd.icmp.code = 0;
        return 0;
      }
    }
    if (USI->ptech.rawudpscan && hss->next_udpportpingidx < USI->ports->udp_ping_count) {
      pspec->type = PS_UDP;
      pspec->proto = IPPROTO_UDP;
      pspec->pd.udp.dport = USI->ports->udp_ping_ports[hss->next_udpportpingidx++];
      return 0;
    }
    if (USI->ptech.rawsctpscan && hss->next_sctpportpingidx < USI->ports->sctp_ping_count) {
      pspec->type = PS_SCTP;
      pspec->proto = IPPROTO_SCTP;
      pspec->pd.sctp.dport = USI->ports->sctp_ping_ports[hss->next_sctpportpingidx++];
      pspec->pd.sctp.chunktype = SCTP_INIT;
      return 0;
    }
    if (USI->ptech.rawprotoscan) {
      pspec->type = PS_PROTO;
      pspec->proto = USI->ports->proto_ping_ports[hss->next_protoportpingidx++];
      return 0;
    }
    if (USI->ptech.connecttcpscan && hss->next_synportpingidx < USI->ports->syn_ping_count) {
      pspec->type = PS_CONNECTTCP;
      pspec->proto = IPPROTO_TCP;
      pspec->pd.tcp.dport = USI->ports->syn_ping_ports[hss->next_synportpingidx++];
      pspec->pd.tcp.flags = TH_SYN;
      return 0;
    }
    if (USI->ptech.rawicmpscan) {
      pspec->type = PS_ICMP;
      pspec->proto = IPPROTO_ICMP;
      if ((o.pingtype & PINGTYPE_ICMP_MASK) && !hss->sent_icmp_mask) {
        hss->sent_icmp_mask = true;
        pspec->pd.icmp.type = ICMP_MASK;
        pspec->pd.icmp.code = 0;
        return 0;
      }
    }
  }
  assert(0); /* TODO: need to handle other protocols */
  return -1;
}

/* Returns the number of ports remaining to probe */
int HostScanStats::freshPortsLeft() {
  if (USI->tcp_scan) {
    if (next_portidx >= USI->ports->tcp_count)
      return 0;
    return USI->ports->tcp_count - next_portidx;
  } else if (USI->udp_scan) {
    if (next_portidx >= USI->ports->udp_count)
      return 0;
    return USI->ports->udp_count - next_portidx;
  } else if (USI->sctp_scan) {
    if (next_portidx >= USI->ports->sctp_count)
      return 0;
    return USI->ports->sctp_count - next_portidx;
  } else if (USI->prot_scan) {
    if (next_portidx >= USI->ports->prot_count)
      return 0;
    return USI->ports->prot_count - next_portidx;
  } else if (USI->ping_scan_arp) {
    if (sent_arp) return 0;
    return 1;
  } else if (USI->ping_scan) {
    unsigned int num_probes = 0;
    if (USI->ptech.rawtcpscan) {
      if ((o.pingtype & PINGTYPE_TCP_USE_ACK)
        && next_ackportpingidx < USI->ports->ack_ping_count)
        num_probes += USI->ports->ack_ping_count - next_ackportpingidx;
      if ((o.pingtype & PINGTYPE_TCP_USE_SYN)
        && next_synportpingidx < USI->ports->syn_ping_count)
        num_probes += USI->ports->syn_ping_count - next_synportpingidx;
    }
    if (USI->ptech.rawudpscan && next_udpportpingidx < USI->ports->udp_ping_count)
      num_probes += USI->ports->udp_ping_count - next_udpportpingidx;
    if (USI->ptech.rawsctpscan && next_sctpportpingidx < USI->ports->sctp_ping_count)
      num_probes += USI->ports->sctp_ping_count - next_sctpportpingidx;
    if (USI->ptech.rawicmpscan) {
      if ((o.pingtype & PINGTYPE_ICMP_PING) && !sent_icmp_ping)
        num_probes++;
      if ((o.pingtype & PINGTYPE_ICMP_MASK) && !sent_icmp_mask)
        num_probes++;
      if ((o.pingtype & PINGTYPE_ICMP_TS) && !sent_icmp_ts)
        num_probes++;
    }
    if (USI->ptech.rawprotoscan)
      num_probes += USI->ports->proto_ping_count - next_protoportpingidx;
    if (USI->ptech.connecttcpscan && next_synportpingidx < USI->ports->syn_ping_count)
      num_probes += USI->ports->syn_ping_count - next_synportpingidx;
    return num_probes;
  }
  assert(0);
  return 0;
}

  /* Removes a probe from probes_outstanding, adjusts HSS and USS
     active probe stats accordingly, then deletes the probe. */
void HostScanStats::destroyOutstandingProbe(list<UltraProbe *>::iterator probeI) {
  UltraProbe *probe = *probeI;
  assert(!probes_outstanding.empty());
  if (!probe->timedout) {
    assert(num_probes_active > 0);
    num_probes_active--;
    assert(USI->gstats->num_probes_active > 0);
    USI->gstats->num_probes_active--;
  }

  if (!probe->isPing() && probe->timedout && !probe->retransmitted) {
    assert(num_probes_waiting_retransmit > 0);
    num_probes_waiting_retransmit--;
  }

    /* Remove it from scan watch lists, if it exists on them. */
  if (probe->type == UltraProbe::UP_CONNECT && probe->CP()->sd > 0)
    USI->gstats->CSI->clearSD(probe->CP()->sd);

  probes_outstanding.erase(probeI);
  delete probe;
}

/* Removes all probes from probes_outstanding using
   destroyOutstandingProbe. This is used in ping scan to quit waiting
   for responses once a host is known to be up. Invalidates iterators
   pointing into probes_outstanding. */
void HostScanStats::destroyAllOutstandingProbes() {
  while(!probes_outstanding.empty())
    destroyOutstandingProbe(probes_outstanding.begin());
}

/* Adjust host and group timeouts (struct timeout_info) based on a received
   packet. If rcvdtime is NULL, nothing is updated.
   
   This function is called for every probe response received, in order to keep
   an accurate timeout estimate. ultrascan_adjust_timing, on the other hand, is
   not called when a response is not useful for adjusting other timing
   variables. */
static void ultrascan_adjust_timeouts(UltraScanInfo *USI, HostScanStats *hss, 
                                      UltraProbe *probe,
                                      struct timeval *rcvdtime) {
  if (rcvdtime == NULL)
    return;

  adjust_timeouts2(&(probe->sent), rcvdtime, &(hss->target->to));
  adjust_timeouts2(&(probe->sent), rcvdtime, &(USI->gstats->to));

  USI->gstats->lastrcvd = hss->lastrcvd = *rcvdtime;
}

/* Adjust host and group congestion control variables (struct ultra_timing_vals)
   and host send delay (struct send_delay_nfo) based on a received packet. Use
   rcvdtime == NULL to indicate that you have given up on a probe and want to
   count this as a DROPPED PACKET. */
static void ultrascan_adjust_timing(UltraScanInfo *USI, HostScanStats *hss, 
                                    UltraProbe *probe,
                                    struct timeval *rcvdtime) {
  int ping_magnifier = (probe->isPing())? USI->perf.ping_magnifier : 1;

  USI->gstats->timing.num_replies_expected++;
  USI->gstats->timing.num_updates++;

  hss->timing.num_replies_expected++;
  hss->timing.num_updates++;

  if ((probe->tryno > 0 && rcvdtime != NULL)
      || (probe->isPing() && rcvdtime == NULL)) {
    /* We consider it a drop if
       1. We get a positive response to a retransmitted probe, or
       2. We get no response to a timing print probe. */
    if (o.debugging > 1)
      log_write(LOG_PLAIN, "Ultrascan DROPPED %sprobe packet to %s detected\n", probe->isPing()? "PING " : "", hss->target->targetipstr());
    // Drops often come in big batches, but we only want one decrease per batch.
    if (TIMEVAL_AFTER(probe->sent, hss->timing.last_drop)) {
      hss->timing.cwnd = USI->perf.low_cwnd;
      hss->timing.ssthresh = (int) MAX(hss->num_probes_active / USI->perf.host_drop_ssthresh_divisor, 2);
      hss->timing.last_drop = USI->now;
    }
    if (TIMEVAL_AFTER(probe->sent, USI->gstats->timing.last_drop)) {
      USI->gstats->timing.cwnd = MAX(USI->perf.low_cwnd, USI->gstats->timing.cwnd / USI->perf.group_drop_cwnd_divisor);
      USI->gstats->timing.ssthresh = (int) MAX(USI->gstats->num_probes_active / USI->perf.group_drop_ssthresh_divisor, 2);
      USI->gstats->timing.last_drop = USI->now;
    }
  } else if (rcvdtime != NULL) {
    /* Good news -- got a response to first try.  Increase window as 
       appropriate.  */
    USI->gstats->timing.num_replies_received++;
    hss->timing.num_replies_received++;

    if (USI->gstats->timing.cwnd < USI->gstats->timing.ssthresh) {
      /* In slow start mode */
      USI->gstats->timing.cwnd += ping_magnifier * USI->perf.slow_incr * USI->gstats->cc_scale();
      if (USI->gstats->timing.cwnd > USI->gstats->timing.ssthresh)
	USI->gstats->timing.cwnd = USI->gstats->timing.ssthresh;
    } else {
      /* Congestion avoidance mode */
      USI->gstats->timing.cwnd += ping_magnifier * USI->perf.ca_incr / USI->gstats->timing.cwnd * USI->gstats->cc_scale();
    }
    if (USI->gstats->timing.cwnd > USI->perf.max_cwnd)
      USI->gstats->timing.cwnd = USI->perf.max_cwnd;

    if (hss->timing.cwnd < hss->timing.ssthresh) {
      /* In slow start mode */
      hss->timing.cwnd += ping_magnifier * hss->cc_scale();
      if (hss->timing.cwnd > hss->timing.ssthresh)
	hss->timing.cwnd = hss->timing.ssthresh;
    } else {
      /* Congestion avoidance mode */
      hss->timing.cwnd += ping_magnifier / hss->timing.cwnd * hss->cc_scale();
    }
    if (hss->timing.cwnd > USI->perf.max_cwnd)
      hss->timing.cwnd = USI->perf.max_cwnd;
  }
  /* If !probe->isPing() and rcvdtime == NULL, do nothing. */

  /* If packet drops are particularly bad, enforce a delay between
     packet sends (useful for cases such as UDP scan where responses
     are frequently rate limited by dest machines or firewalls) */

  /* First we decide whether this packet counts as a drop for send
     delay calculation purposes.  This statement means if (a ping since last boost failed, or the previous packet was both sent after the last boost and dropped) */
  if ((probe->isPing() && rcvdtime == NULL && TIMEVAL_AFTER(probe->sent, hss->sdn.last_boost)) ||
      (probe->tryno > 0 && rcvdtime != NULL && TIMEVAL_AFTER(probe->prevSent, hss->sdn.last_boost))) {
    hss->sdn.droppedRespSinceDelayChanged++;
    //    printf("SDELAY: increasing drops to %d (good: %d; tryno: %d, sent: %.4fs; prevSent: %.4fs, last_boost: %.4fs\n", hss->sdn.droppedRespSinceDelayChanged, hss->sdn.goodRespSinceDelayChanged, probe->tryno, o.TimeSinceStartMS(&probe->sent) / 1000.0, o.TimeSinceStartMS(&probe->prevSent) / 1000.0, o.TimeSinceStartMS(&hss->sdn.last_boost) / 1000.0);
  } else if (rcvdtime) {
    hss->sdn.goodRespSinceDelayChanged++;
    //    printf("SDELAY: increasing good to %d (bad: %d)\n", hss->sdn.goodRespSinceDelayChanged, hss->sdn.droppedRespSinceDelayChanged);
  }

  /* Now change the send delay if necessary */
  unsigned int oldgood = hss->sdn.goodRespSinceDelayChanged;
  unsigned int oldbad = hss->sdn.droppedRespSinceDelayChanged;
  double threshold = (o.timing_level >= 4)? 0.40 : 0.30;
  if (oldbad > 10 && (oldbad / ((double) oldbad + oldgood) > threshold)) {
    unsigned int olddelay = hss->sdn.delayms;
    hss->boostScanDelay();
    if (o.verbose && hss->sdn.delayms != olddelay)
      log_write(LOG_PLAIN, "Increasing send delay for %s from %d to %d due to %d out of %d dropped probes since last increase.\n", 
		hss->target->targetipstr(), olddelay, hss->sdn.delayms, oldbad, 
		oldbad + oldgood);
  }
}

 /* Mark an outstanding probe as timedout.  Adjusts stats
     accordingly.  For connect scans, this closes the socket. */
void HostScanStats::markProbeTimedout(list<UltraProbe *>::iterator probeI) {
  UltraProbe *probe = *probeI;
  assert(!probe->timedout);
  assert(!probe->retransmitted);
  probe->timedout = true;
  assert(num_probes_active > 0);
  num_probes_active--;
  assert(USI->gstats->num_probes_active > 0);
  USI->gstats->num_probes_active--;
  ultrascan_adjust_timing(USI, this, probe, NULL);
  if (!probe->isPing())
    /* I'll leave it in the queue in case some response ever does come */
    num_probes_waiting_retransmit++;

  if (probe->type == UltraProbe::UP_CONNECT && probe->CP()->sd >= 0 ) {
    /* Free the socket as that is a valuable resource, though it is a shame
       late responses will not be permitted */
    USI->gstats->CSI->clearSD(probe->CP()->sd);
    close(probe->CP()->sd);
    probe->CP()->sd = -1;
  }
}

bool HostScanStats::completed() {
  /* If there are probes active or awaiting retransmission, we are not done. */
  if (num_probes_active != 0 || num_probes_waiting_retransmit != 0
    || !probe_bench.empty() || !retry_stack.empty()) {
    return false;
  }

  /* With ping scan, we are done once we know the host is up or down. */
  if (USI->ping_scan && ((target->flags & HOST_UP)
    || (target->flags & HOST_DOWN) || target->weird_responses)) {
    return true;
  }

  /* With other types of scan, we are done when there are no more ports to
     probe. */
  return freshPortsLeft() == 0;
}

/* The try number or ping sequence number can be encoded into a TCP SEQ or ACK
   field. This returns a 32-bit number which encodes both of these values along
   with a simple checksum. Decoding is done by seq32_decode. */
static u32 seq32_encode(UltraScanInfo *USI, unsigned int trynum, 
                        unsigned int pingseq) {
  u32 seq;
  u16 nfo;

  /* We'll let trynum and pingseq each be 8 bits. */
  nfo = (pingseq << 8) + trynum;
  /* Mirror the data to ensure it is reconstructed correctly. */
  seq = (nfo << 16) + nfo;
  /* Obfuscate it a little */
  seq = seq ^ USI->seqmask;

  return seq;
}

/* Undoes seq32_encode. This extracts a try number and a port number from a
   32-bit value. Returns true if the checksum is correct, false otherwise. */
static bool seq32_decode(const UltraScanInfo *USI, u32 seq,
  unsigned int *trynum, unsigned int *pingseq) {
  if (trynum)
    *trynum = 0;
  if (pingseq)
    *pingseq = 0;

  /* Undo the mask xor. */
  seq = seq ^ USI->seqmask;
  /* Check that both sides are the same. */
  if ((seq >> 16) != (seq & 0xFFFF))
    return false;

  if (trynum) 
    *trynum = seq & 0xFF;
  if (pingseq)
    *pingseq = (seq & 0xFF00) >> 8;

  return true;
}

/* The try number or ping sequence number can be encoded in the source port
   number. This returns a new port number that contains a try number or ping
   sequence number encoded into the given port number. trynum and pingseq may
   not both be non-zero. Decoding is done by sport_decode. */
static u16 sport_encode(UltraScanInfo *USI, u16 portno, unsigned int trynum, 
                        unsigned int pingseq) {
  /* trynum and pingseq both being non-zero is not currently supported. */
  assert(trynum == 0 || pingseq == 0);

  if (pingseq > 0) {
    /* Encode the pingseq. trynum = 0. */
    portno += USI->perf.tryno_cap + pingseq;
  } else {
    /* Encode the trynum. pingseq = 0. */
    portno += trynum;
  }

  return portno;
}

/* Undoes sport_encode. This extracts a try number and ping sequence number from
   a port number given a "magic" original port number (the one given to
   sport_encode). Returns true if the decoded values seem reasonable, false
   otherwise. */
static bool sport_decode(const UltraScanInfo *USI, u16 magic_portno, u16 portno,
                         unsigned int *trynum, unsigned int *pingseq) {
  int t;

  t = portno - magic_portno;
  if (t > USI->perf.tryno_cap + 256) {
    return false;
  } else if (t > USI->perf.tryno_cap) {
    /* The ping sequence number was encoded. */
    if (pingseq)
      *pingseq = t - USI->perf.tryno_cap;
    if (trynum)
      *trynum = 0;
  } else {
    /* The try number was encoded. */
    if (pingseq)
      *pingseq = 0;
    if (trynum)
      *trynum = t;
  }

  return true;
}

static bool tcp_probe_match(const UltraScanInfo *USI, const UltraProbe *probe,
  const HostScanStats *hss, const struct ip *ip) {
  const struct tcp_hdr *tcp;
  const struct probespec_tcpdata *probedata;
  unsigned int tryno, pingseq;
  bool goodseq;

  if (ip->ip_p != IPPROTO_TCP)
    return false;

  tcp = (struct tcp_hdr *) ((u8 *) ip + ip->ip_hl * 4);

  if (o.af() != AF_INET || probe->protocol() != IPPROTO_TCP)
    return false;

  /* Ensure the connection info matches. */
  if (probe->dport() != ntohs(tcp->th_sport)
      || probe->sport() != ntohs(tcp->th_dport)
      || hss->target->v4sourceip()->s_addr != ip->ip_dst.s_addr)
    return false;

  tryno = 0;
  pingseq = 0;
  if (o.magic_port_set) {
    /* We are looking to recover the tryno and pingseq of the probe, which are
       encoded in the ACK field for probes with the ACK flag set and in the SEQ
       field for all other probes. According to RFC 793, section 3.9, under
       "SEGMENT ARRIVES", it's supposed to work like this: If our probe had ACK
       set, our ACK number is reflected in the response's SEQ field. If our
       probe had SYN or FIN set (and not ACK), then our SEQ is one less than the
       returned ACK value because SYN and FIN consume a sequence number (section
       3.3). Otherwise, our SEQ is the returned ACK.
       
       However, nmap-os-db shows that these assumptions can't be relied on, so
       we try all three possibilities for each probe. */
    goodseq = seq32_decode(USI, ntohl(tcp->th_ack) - 1, &tryno, &pingseq)
      || seq32_decode(USI, ntohl(tcp->th_ack), &tryno, &pingseq)
      || seq32_decode(USI, ntohl(tcp->th_seq), &tryno, &pingseq);
  } else {
    /* Get the values from the destination port (our source port). */
    sport_decode(USI, o.magic_port, ntohs(tcp->th_dport), &tryno, &pingseq);
    goodseq = true;
  }

  if (!goodseq) {
    /* TODO: I need to do some testing and find out how often this happens
       and whether other techniques such as the response seq should be
       used in those cases where it happens. Then I should make this just
       a debugging > X statement. */
    if (o.debugging)
      log_write(LOG_PLAIN, "Bad Sequence number from host %s.\n", inet_ntoa(ip->ip_src));
    /* I'll just assume it is a response to this (most recent) probe. */
    tryno = probe->tryno;
    pingseq = probe->pingseq;
  }

  /* Make sure that trynum and pingseq match the values in the probe. */
  if (!probe->check_tryno_pingseq(tryno, pingseq))
    return false;

  /* Make sure we are matching up the right kind of probe, otherwise just the
     ports, address, tryno, and pingseq can be ambiguous, between a SYN and an
     ACK probe during a -PS80 -PA80 scan for example. A SYN/ACK can only be
     matched to a SYN probe. A RST/ACK can only be matched to a SYN or FIN. A
     bare RST cannot be matched to a SYN or FIN. */
  probedata = &probe->pspec()->pd.tcp;
  if ((tcp->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)
      && !(probedata->flags & TH_SYN)) {
    return false;
  }
  if ((tcp->th_flags & (TH_RST | TH_ACK)) == (TH_RST | TH_ACK)
      && !(probedata->flags & (TH_SYN | TH_FIN))) {
    return false;
  }
  if ((tcp->th_flags & (TH_RST | TH_ACK)) == TH_RST
      && (probedata->flags & (TH_SYN | TH_FIN))) {
    return false;
  }

  /* Sometimes we get false results when scanning localhost with -p- because we
     scan localhost with src port = dst port and see our outgoing packet and
     think it is a response. */
  if (probe->dport() == probe->sport()
      && ip->ip_src.s_addr == ip->ip_dst.s_addr
      && probe->ipid() == ntohs(ip->ip_id))
    return false;

  return true;
}

/* This function provides the proper cwnd and ssthresh to use.  It may
   differ from versions in timing member var because when no responses
   have been received for this host, may look at others in the group.
   For CHANGING this host's timing, use the timing memberval
   instead. */
void HostScanStats::getTiming(struct ultra_timing_vals *tmng) {
  assert(tmng);

  /* Use the per-host value if a pingport has been found or very few probes
     have been sent */
  if (target->pingprobe.type != PS_NONE || numprobes_sent < 80) {
    *tmng = timing;
    return;
  }

  /* Otherwise, use the global cwnd stats if it has sufficient responses */
  if (USI->gstats->timing.num_updates > 1) {
    *tmng = USI->gstats->timing;
    return;
  }

  /* Last resort is to use canned values */
  tmng->cwnd = USI->perf.host_initial_cwnd;
  tmng->ssthresh = USI->perf.initial_ssthresh;
  tmng->num_updates = 0;
  return;
}

/* Define a score for a ping probe, for the purposes of deciding whether one
   probe should be preferred to another. The order, from most preferred to least
   preferred, is
      Raw TCP/SCTP (not filtered, not SYN/INIT to an open port)
      ICMP information queries (echo request, timestamp request, netmask req)
      ARP
      Raw TCP/SCTP (SYN/INIT to an open port)
      UDP, IP protocol, or other ICMP (including filtered TCP/SCTP)
      TCP connect
      Anything else
   Raw TCP SYN / SCTP INIT to an open port is given a low preference because of the
   risk of SYN flooding (this is the only case where the port state is considered).
   The probe passed to this function is assumed to have received a positive
   response, that is, it should not have set a port state just by timing out. */
static unsigned int pingprobe_score(const probespec *pspec, int state) {
  unsigned int score;

  switch (pspec->type) {
    case PS_TCP:
      if (state == PORT_FILTERED) /* Received an ICMP error. */
        score = 2;
      else if (pspec->pd.tcp.flags == TH_SYN && (state == PORT_OPEN || state == PORT_UNKNOWN))
        score = 3;
      else
        score = 6;
      break;
    case PS_SCTP:
      if (state == PORT_FILTERED) /* Received an ICMP error. */
        score = 2;
      else if (state == PORT_OPEN || state == PORT_UNKNOWN)
        score = 3;
      else
        score = 6;
      break;
    case PS_ICMP:
      if(pspec->pd.icmp.type==ICMP_ECHO || pspec->pd.icmp.type==ICMP_MASK || pspec->pd.icmp.type==ICMP_TSTAMP)
        score = 5;
      else
        score = 2;
      break;
    case PS_ARP:
      score = 4;
      break;
    case PS_UDP:
    case PS_PROTO:
      score = 2;
      break;
    case PS_CONNECTTCP:
      score = 1;
      break;
    case PS_NONE:
    default:
      score = 0;
      break;
  }

  return score;
}

/* Return true if new_probe and new_state define a better ping probe, as defined
   by pingprobe_score, than do old_probe and old_state. */
static bool pingprobe_is_better(const probespec *new_probe, int new_state,
                                const probespec *old_probe, int old_state) {
  return pingprobe_score(new_probe, new_state) > pingprobe_score(old_probe, old_state);
}

static bool ultrascan_host_pspec_update(UltraScanInfo *USI, HostScanStats *hss,
                                        const probespec *pspec, int newstate);

/* Like ultrascan_port_probe_update(), except it is called with just a
   probespec rather than a whole UltraProbe.  Returns true if the port
   was added or at least the state was changed.  */
static bool ultrascan_port_pspec_update(UltraScanInfo *USI, 
					HostScanStats *hss, 
					const probespec *pspec,
					int newstate) {
  u16 portno = 0;
  u8 proto = 0;
  int oldstate = PORT_TESTING;
  /* Whether no response means a port is open */
  bool noresp_open_scan = USI->noresp_open_scan;

  if (USI->prot_scan) {
    proto = IPPROTO_IP;
    portno = pspec->proto;
  } else if (pspec->type == PS_TCP || pspec->type == PS_CONNECTTCP) {
    proto = IPPROTO_TCP;
    portno = pspec->pd.tcp.dport;
  } else if (pspec->type == PS_UDP) {
    proto = IPPROTO_UDP;
    portno = pspec->pd.udp.dport;
  } else if (pspec->type == PS_SCTP) {
    proto = IPPROTO_SCTP;
    portno = pspec->pd.sctp.dport;
  } else assert(0);
  
  if (hss->target->ports.portIsDefault(portno, proto)) {
    oldstate = PORT_TESTING;
    hss->ports_finished++;
  } else {
    oldstate = hss->target->ports.getPortState(portno, proto);
  }

  /*    printf("TCP port %hu has changed from state %s to %s!\n", portno, statenum2str(oldstate), statenum2str(newstate)); */
  switch(oldstate) {
    /* TODO: I need more code here to determine when a state should
       be overridden, for example PORT_OPEN trumps PORT_FILTERED
       in a SYN scan, but not necessarily for UDP scan */
  case PORT_TESTING:
    /* Brand new port -- add it to the list */
    hss->target->ports.setPortState(portno, proto, newstate);
    break;
  case PORT_OPEN:
    if (newstate != PORT_OPEN) {
      if (noresp_open_scan) {
	hss->target->ports.setPortState(portno, proto, newstate);
      } /* Otherwise The old open takes precendence */
    }
    break;
  case PORT_CLOSED:
    if (newstate != PORT_CLOSED) {
      if (!noresp_open_scan && newstate != PORT_FILTERED)
	hss->target->ports.setPortState(portno, proto, newstate);
    }
    break;
  case PORT_FILTERED:
    if (newstate != PORT_FILTERED) {
      if (!noresp_open_scan || newstate != PORT_OPEN) 
	hss->target->ports.setPortState(portno, proto, newstate);
    }
    break;
  case PORT_UNFILTERED:
    /* This could happen in an ACK scan if I receive a RST and then an
       ICMP filtered message.  I'm gonna stick with unfiltered in that
       case.  I'll change it if the new state is open or closed,
       though I don't expect that to ever happen */
    if (newstate == PORT_OPEN || newstate == PORT_CLOSED)
      hss->target->ports.setPortState(portno, proto, newstate);
    break;
  case PORT_OPENFILTERED:
    if (newstate != PORT_OPENFILTERED) {
      hss->target->ports.setPortState(portno, proto, newstate);
    }
    break;
  default:
    fatal("Unexpected port state: %d\n", oldstate);
    break;
  }

  return oldstate != newstate;
}

/* Returns the scaling factor to use when incrementing the congestion window.
   This is the minimum of num_replies_expected / num_replies_received and
   cc_scale_max. */
double HostScanStats::cc_scale() {
  double ratio;

  assert(timing.num_replies_received > 0);
  ratio = (double) timing.num_replies_expected / timing.num_replies_received;

  return MIN(ratio, USI->perf.cc_scale_max);
}

  /* Boost the scan delay for this host, usually because too many packet
     drops were detected. */
void HostScanStats::boostScanDelay() {
  unsigned int maxAllowed = USI->tcp_scan ? o.maxTCPScanDelay() :
			    USI->udp_scan ? o.maxUDPScanDelay() :
					    o.maxSCTPScanDelay();
  if (sdn.delayms == 0)
    sdn.delayms = (USI->udp_scan)? 50 : 5; // In many cases, a pcap wait takes a minimum of 80ms, so this matters little :(
  else sdn.delayms = MIN(sdn.delayms * 2, MAX(sdn.delayms, 1000));
  sdn.delayms = MIN(sdn.delayms, maxAllowed); 
  sdn.last_boost = USI->now;
  sdn.droppedRespSinceDelayChanged = 0;
  sdn.goodRespSinceDelayChanged = 0;
}

/* Dismiss all probe attempts on bench -- hosts are marked down and ports will
   be set to whatever the default port state is for the scan. */
void HostScanStats::dismissBench() {
  if (probe_bench.empty()) return;
  while(!probe_bench.empty()) {
    if (USI->ping_scan)
      ultrascan_host_pspec_update(USI, this, &probe_bench.back(), HOST_DOWN);
    /* Nothing to do if !USI->ping_scan. ultrascan_port_pspec_update would
       allocate a Port object but we rely on the default port state to save
       memory. */
    probe_bench.pop_back();
  }
  bench_tryno = 0;
}

/* Move all members of bench to retry_stack for probe retransmission */
void HostScanStats::retransmitBench() {
  if (probe_bench.empty()) return;

  /* Move all contents of probe_bench to the end of retry_stack, updating retry_stack_tries accordingly */
  retry_stack.insert(retry_stack.end(), probe_bench.begin(), probe_bench.end());
  retry_stack_tries.insert(retry_stack_tries.end(), probe_bench.size(), 
			   bench_tryno);
  assert(retry_stack.size() == retry_stack_tries.size());
  probe_bench.erase(probe_bench.begin(), probe_bench.end());
  bench_tryno = 0;
}

 /* Moves the given probe from the probes_outstanding list, to
     probe_bench, and decrements num_probes_waiting_retransmit
     accordingly */
void HostScanStats::moveProbeToBench(list<UltraProbe *>::iterator probeI) {
  UltraProbe *probe = *probeI;
  if (!probe_bench.empty()) 
    assert(bench_tryno == probe->tryno);
  else {
    bench_tryno = probe->tryno;
    probe_bench.reserve(128);
  }
  probe_bench.push_back(*probe->pspec());
  probes_outstanding.erase(probeI);
  num_probes_waiting_retransmit--;
  delete probe;
}

/* Called when a ping response is discovered. If adjust_timing is false, timing
   stats are not updated. */
static void ultrascan_ping_update(UltraScanInfo *USI, HostScanStats *hss, 
				  list<UltraProbe *>::iterator probeI,
				  struct timeval *rcvdtime,
				  bool adjust_timing = true) {
  ultrascan_adjust_timeouts(USI, hss, *probeI, rcvdtime);
  if (adjust_timing)
    ultrascan_adjust_timing(USI, hss, *probeI, rcvdtime);
  hss->destroyOutstandingProbe(probeI);
}

static const char *readhoststate(int state) {
  switch(state) {
    case HOST_UNKNOWN:
      return "UNKNOWN";
    case HOST_UP:
      return "HOST_UP";
    case HOST_DOWN:
      return "HOST_DOWN";
    default:
      return "COMBO";
  }

  return NULL;
}

/* Update state of the host in hss based on its current state and newstate.
   Returns true if the state was changed. */
static bool ultrascan_host_pspec_update(UltraScanInfo *USI, HostScanStats *hss,
                                        const probespec *pspec, int newstate) {
  unsigned int oldstate = hss->target->flags;
  /* If the host is already up, ignore any further updates. */
  if (hss->target->flags != HOST_UP) {
    assert(newstate == HOST_UP || newstate == HOST_DOWN);
    hss->target->flags = newstate;
  }
  return hss->target->flags != oldstate;
}

/* Called when a new status is determined for host in hss (eg. it is
   found to be up or down by a ping/ping_arp scan.  The probe that led
   to this new decision is in probeI.  This function needs to update
   timing information and other stats as appropriate. If
   adjust_timing_hint is false, packet stats are not updated. */
static void ultrascan_host_probe_update(UltraScanInfo *USI, HostScanStats *hss, 
				        list<UltraProbe *>::iterator probeI,
				        int newstate, struct timeval *rcvdtime,
				        bool adjust_timing_hint = true) {
  UltraProbe *probe = *probeI;

  if (o.debugging > 1) {
    struct timeval tv;

    gettimeofday(&tv, NULL);
    log_write(LOG_STDOUT, "%s called for machine %s state %s -> %s (trynum %d time: %ld)\n", __func__, hss->target->targetipstr(), readhoststate(hss->target->flags), readhoststate(newstate), probe->tryno, (long) TIMEVAL_SUBTRACT(tv, probe->sent));
  }

  ultrascan_host_pspec_update(USI, hss, probe->pspec(), newstate);

  ultrascan_adjust_timeouts(USI, hss, probe, rcvdtime);

  /* Decide whether to adjust timing. We and together a bunch of conditions.
     First, don't adjust timing if adjust_timing_hint is false. */
  bool adjust_timing = adjust_timing_hint;
  bool adjust_ping = adjust_timing_hint;

  /* If we got a response that meant "down", then it was an ICMP error. These
     are often rate-limited (RFC 1812) or generated by a different host. We only
     allow such responses to increase, not decrease, scanning speed by
     disallowing drops (probe->tryno > 0), and we don't allow changing the ping
     probe to something that's likely to get dropped. */
  if (rcvdtime != NULL && newstate == HOST_DOWN) {
    if (probe->tryno > 0) {
      if (adjust_timing && o.debugging > 1)
        log_write(LOG_PLAIN, "Response for %s means new state is down; not adjusting timing.\n", hss->target->targetipstr());
      adjust_timing = false;
    }
    adjust_ping = false;
  }

  if (adjust_timing)
    ultrascan_adjust_timing(USI, hss, probe, rcvdtime);

  /* If this probe received a positive response, consider making it the new
     timing ping probe. */
  if (rcvdtime != NULL && adjust_ping
      && pingprobe_is_better(probe->pspec(), PORT_UNKNOWN, &hss->target->pingprobe, hss->target->pingprobe_state)) {
    if (o.debugging > 1) {
      char buf[64];
      probespec2ascii(probe->pspec(), buf, sizeof(buf));
      log_write(LOG_PLAIN, "Changing ping technique for %s to %s\n", hss->target->targetipstr(), buf);
    }
    hss->target->pingprobe = *probe->pspec();
    hss->target->pingprobe_state = PORT_UNKNOWN;
  }

  hss->destroyOutstandingProbe(probeI);
}

/* This function is called when a new status is determined for a port.
   the port in the probeI of host hss is now in newstate.  This
   function needs to update timing information, other stats, and the
   Nmap port state table as appropriate.  If rcvdtime is NULL or we got
   unimportant packet, packet stats are not updated.  If you don't have an
   UltraProbe list iterator, you may need to call ultrascan_port_psec_update()
   instead. If adjust_timing_hint is false, packet stats are not
   updated. */
static void ultrascan_port_probe_update(UltraScanInfo *USI, HostScanStats *hss,
 					list<UltraProbe *>::iterator probeI,
					int newstate, struct timeval *rcvdtime,
					bool adjust_timing_hint = true) {
  UltraProbe *probe = *probeI;
  const probespec *pspec = probe->pspec();

  ultrascan_port_pspec_update(USI, hss, pspec, newstate);

  ultrascan_adjust_timeouts(USI, hss, probe, rcvdtime);

  /* Decide whether to adjust timing. We and together a bunch of conditions.
     First, don't adjust timing if adjust_timing_hint is false. */
  bool adjust_timing = adjust_timing_hint;
  bool adjust_ping = adjust_timing_hint;

  /* If we got a response that meant "filtered", then it was an ICMP error.
     These are often rate-limited (RFC 1812) or generated by a different host.
     We only allow such responses to increase, not decrease, scanning speed by
     not considering drops (probe->tryno > 0), and we don't allow changing the
     ping probe to something that's likely to get dropped. */
  if (rcvdtime != NULL && newstate == PORT_FILTERED && !USI->noresp_open_scan) {
    if (probe->tryno > 0) {
      if (adjust_timing && o.debugging > 1)
        log_write(LOG_PLAIN, "Response for %s means new state is filtered; not adjusting timing.\n", hss->target->targetipstr());
      adjust_timing = false;
    }
    adjust_ping = false;
  }
  /* Do not slow down if 
     1)  we are in --defeat-rst-ratelimit mode
     2)  the new state is closed 
     3)  this is not a UDP scan (other scans where noresp_open_scan is true
         aren't possible with the --defeat-rst-ratelimit option)
     We don't care if it's closed because of a RST or a timeout
     because they both mean the same thing. */
  if (rcvdtime != NULL
      && o.defeat_rst_ratelimit && newstate == PORT_CLOSED
      && !USI->noresp_open_scan) {
    if (probe->tryno > 0)
      adjust_timing = false;
    adjust_ping = false;
  }

  if (adjust_timing) {
    ultrascan_adjust_timing(USI, hss, probe, rcvdtime);

    if (rcvdtime != NULL && probe->tryno > hss->max_successful_tryno) {
      /* We got a positive response to a higher tryno than we've seen so far. */
      hss->max_successful_tryno = probe->tryno;
      if (o.debugging)
        log_write(LOG_STDOUT, "Increased max_successful_tryno for %s to %d (packet drop)\n", hss->target->targetipstr(), hss->max_successful_tryno);
      if (hss->max_successful_tryno > ((o.timing_level >= 4)? 4 : 3)) {
        unsigned int olddelay = hss->sdn.delayms;
        hss->boostScanDelay();
        if (o.verbose && hss->sdn.delayms != olddelay) 
           log_write(LOG_STDOUT, "Increasing send delay for %s from %d to %d due to max_successful_tryno increase to %d\n", 
           hss->target->targetipstr(), olddelay, hss->sdn.delayms, 
           hss->max_successful_tryno);
      }
    }
  }

  /* If this probe received a positive response, consider making it the new
     timing ping probe. */
  if (rcvdtime != NULL && adjust_ping
      && pingprobe_is_better(probe->pspec(), newstate, &hss->target->pingprobe, hss->target->pingprobe_state)) {
    if (o.debugging > 1) {
      char buf[64];
      probespec2ascii(probe->pspec(), buf, sizeof(buf));
      log_write(LOG_PLAIN, "Changing ping technique for %s to %s\n", hss->target->targetipstr(), buf);
    }
    hss->target->pingprobe = *probe->pspec();
    hss->target->pingprobe_state = newstate;
  }

  hss->destroyOutstandingProbe(probeI);
}



/* Set the socket lingering so we will RST connections instead of wasting
   bandwidth with the four-step close. Set the source address if needed. */
static void init_socket(int sd) {
  static int bind_failed = 0;
  struct linger l;
  struct sockaddr_storage ss;
  size_t sslen;

  l.l_onoff = 1;
  l.l_linger = 0;

  if (setsockopt(sd, SOL_SOCKET, SO_LINGER, (const char *) &l, sizeof(l)) != 0) {
    error("Problem setting socket SO_LINGER, errno: %d", socket_errno());
    perror("setsockopt");
  }
  if (o.spoofsource && !bind_failed) {
    o.SourceSockAddr(&ss, &sslen);
    if (bind(sd, (struct sockaddr*)&ss, sslen) != 0) {
      error("%s: Problem binding source address (%s), errno: %d", __func__, inet_socktop(&ss), socket_errno());
      perror("bind");
      bind_failed = 1;
    }
  }
}

/* If this is NOT a ping probe, set pingseq to 0.  Otherwise it will be the
   ping sequence number (they start at 1).  The probe sent is returned. */
static UltraProbe *sendConnectScanProbe(UltraScanInfo *USI, HostScanStats *hss,
					u16 destport, u8 tryno, u8 pingseq) {

  UltraProbe *probe = new UltraProbe();
  list<UltraProbe *>::iterator probeI;
  static bool connecterror = false;
  int rc;
  int connect_errno = 0;
  struct sockaddr_storage sock;
  struct sockaddr_in *sin = (struct sockaddr_in *) &sock;
#if HAVE_IPV6
  struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &sock;
#endif
  size_t socklen;
  ConnectProbe *CP;

  probe->tryno = tryno;
  probe->pingseq = pingseq;
  /* First build the probe */
  probe->setConnect(destport);
  CP = probe->CP();
  /* Initiate the connection */
  CP->sd = socket(o.af(), SOCK_STREAM, IPPROTO_TCP);
  if (CP->sd == -1) pfatal("Socket creation in %s", __func__);
  unblock_socket(CP->sd);
  init_socket(CP->sd);
  set_ttl(CP->sd, o.ttl);
  if (o.ipoptionslen)
    set_ipoptions(CP->sd, o.ipoptions, o.ipoptionslen);
  if (hss->target->TargetSockAddr(&sock, &socklen) != 0) {
    fatal("Failed to get target socket address in %s", __func__);
  }
  if (sin->sin_family == AF_INET)
    sin->sin_port = htons(probe->pspec()->pd.tcp.dport);
#if HAVE_IPV6
  else sin6->sin6_port = htons(probe->pspec()->pd.tcp.dport);
#endif
  probe->sent = USI->now;
  /* We don't record a byte count for connect probes. */
  hss->probeSent(0);
  rc = connect(CP->sd, (struct sockaddr *)&sock, socklen);
  gettimeofday(&USI->now, NULL);
  if (rc == -1) connect_errno = socket_errno();
  PacketTrace::traceConnect(IPPROTO_TCP, (sockaddr *) &sock, socklen, rc, 
			    connect_errno, &USI->now);
  /* This counts as probe being sent, so update structures */
  hss->probes_outstanding.push_back(probe);
  probeI = hss->probes_outstanding.end();
  probeI--;
  USI->gstats->num_probes_active++;
  hss->num_probes_active++;

  /* It would be convenient if the connect() call would never succeed
     or permanantly fail here, so related code cood all be localized
     elsewhere.  But the reality is that connect() MAY be finished now. */

  if (rc != -1) {
    /* Connection succeeded! */
    if (USI->ping_scan) {
      ultrascan_host_probe_update(USI, hss, probeI, HOST_UP, &USI->now);
      /* If the host is up, we can forget our other probes. */
      hss->destroyAllOutstandingProbes();
    } else if (probe->isPing()) 
      ultrascan_ping_update(USI, hss, probeI, &USI->now);
    else 
      ultrascan_port_probe_update(USI, hss, probeI, PORT_OPEN, &USI->now);
    probe = NULL;
  } else if (connect_errno == EINPROGRESS || connect_errno == EAGAIN) {
    USI->gstats->CSI->watchSD(CP->sd);
  } else {
    int host_state = HOST_UNKNOWN, port_state = PORT_UNKNOWN;

    switch(connect_errno) {
    /* This can happen on localhost, successful/failing connection immediately
       in non-blocking mode. */
    case ECONNREFUSED:
      host_state = HOST_UP;
      port_state = PORT_CLOSED;
      hss->target->reason.reason_id = ER_CONREFUSED;
      break;
    case ENETUNREACH:
      if (o.debugging)
        log_write(LOG_STDOUT, "Got ENETUNREACH from %s connect()\n", __func__);
      host_state = HOST_DOWN;
      hss->target->reason.reason_id = ER_NETUNREACH;
      break;
    case EACCES:
      if (o.debugging)
	log_write(LOG_STDOUT, "Got EACCES from %s connect()\n", __func__);
      host_state = HOST_DOWN;
      hss->target->reason.reason_id = ER_ACCES;
      break;
    default:
      if (!connecterror) {	
	connecterror = true;
	fprintf(stderr, "Strange error from connect (%d):", connect_errno);
	fflush(stdout);
	fflush(stderr);
	perror("");
      }
      host_state = HOST_DOWN;
      hss->target->reason.reason_id = ER_UNKNOWN;
    }
    if (probe->isPing()) {
      ultrascan_ping_update(USI, hss, probeI, &USI->now);
    } else if (USI->ping_scan && host_state != HOST_UNKNOWN) {
      ultrascan_host_probe_update(USI, hss, probeI, host_state, &USI->now);
      if (host_state == HOST_UP)
        hss->destroyAllOutstandingProbes();
    } else if (!USI->ping_scan && port_state != PORT_UNKNOWN) {
      ultrascan_port_probe_update(USI, hss, probeI, port_state, &USI->now);
    } else {
      hss->destroyOutstandingProbe(probeI);
    }
    probe = NULL;
  }
  gettimeofday(&USI->now, NULL);
  return probe;
}


/* If this is NOT a ping probe, set pingseq to 0.  Otherwise it will be the
   ping sequence number (they start at 1).  The probe sent is returned. */
static UltraProbe *sendArpScanProbe(UltraScanInfo *USI, HostScanStats *hss, 
				    u8 tryno, u8 pingseq) {
  int rc;
  UltraProbe *probe = new UltraProbe();

  /* 3 cheers for libdnet header files */
  u8 frame[ETH_HDR_LEN + ARP_HDR_LEN + ARP_ETHIP_LEN];

  eth_pack_hdr(frame, ETH_ADDR_BROADCAST, *hss->target->SrcMACAddress(),
            ETH_TYPE_ARP);
  arp_pack_hdr_ethip(frame + ETH_HDR_LEN, ARP_OP_REQUEST, 
		     *hss->target->SrcMACAddress(), *hss->target->v4sourceip(),
		     ETH_ADDR_BROADCAST,  *hss->target->v4hostip());
  gettimeofday(&USI->now, NULL);
  probe->sent = USI->now;
  hss->probeSent(sizeof(frame));
  if ((rc = eth_send(USI->ethsd, frame, sizeof(frame))) != sizeof(frame)) {
    int err = socket_errno();
    error("WARNING:  eth_send of ARP packet returned %i rather than expected %d (errno=%i: %s)", rc, (int) sizeof(frame), err, strerror(err));
  }
  PacketTrace::traceArp(PacketTrace::SENT, (u8 *) frame + ETH_HDR_LEN, sizeof(frame) - ETH_HDR_LEN, &USI->now);
  probe->tryno = tryno;
  probe->pingseq = pingseq;
  /* First build the probe */
  probe->setARP(frame, sizeof(frame));
  
  /* Now that the probe has been sent, add it to the Queue for this host */
  hss->probes_outstanding.push_back(probe);
  USI->gstats->num_probes_active++;
  hss->num_probes_active++;

  gettimeofday(&USI->now, NULL);
  return probe;
}

/* If this is NOT a ping probe, set pingseq to 0.  Otherwise it will be the
   ping sequence number (they start at 1).  The probe sent is returned.
   
   This function also handles the sending of decoys. There is no fine-grained
   control of this; all decoys are sent at once on one call of this function.
   This means that decoys do not honor any scan delay and may violate congestion
   control limits. */
static UltraProbe *sendIPScanProbe(UltraScanInfo *USI, HostScanStats *hss, 
			    const probespec *pspec, u8 tryno, u8 pingseq) {
  u8 *packet = NULL;
  u32 packetlen = 0;
  UltraProbe *probe = new UltraProbe();
  int decoy = 0;
  u32 seq = 0;
  u32 ack = 0;
  u16 sport;
  u16 ipid = get_random_u16();
  struct eth_nfo eth;
  struct eth_nfo *ethptr = NULL;
  u8 *tcpops = NULL;
  u16 tcpopslen = 0;
  u32 vtag = 0;
  char *chunk = NULL;
  int chunklen = 0;
  /* Some hosts do not respond to ICMP requests if the identifier is 0. */
  u16 icmp_ident = (get_random_u16() % 0xffff) + 1;

  if (USI->ethsd) {
    memcpy(eth.srcmac, hss->target->SrcMACAddress(), 6);
    memcpy(eth.dstmac, hss->target->NextHopMACAddress(), 6);
    eth.ethsd = USI->ethsd;
    eth.devname[0] = '\0';
    ethptr = &eth;
  }

  if (o.magic_port_set)
    sport = o.magic_port;
  else
    sport = sport_encode(USI, o.magic_port, tryno, pingseq);

  probe->tryno = tryno;
  probe->pingseq = pingseq;
  /* First build the probe */
  if (pspec->type == PS_TCP) {
    assert(USI->scantype != CONNECT_SCAN);

    /* Normally we encode the tryno and pingseq in the SEQ field, because that
       comes back (possibly incremented) in the ACK field of responses. But if
       our probe has the ACK flag set, the response reflects our own ACK number
       instead. */
    if (pspec->pd.tcp.flags & TH_ACK)
      ack = seq32_encode(USI, tryno, pingseq);
    else
      seq = seq32_encode(USI, tryno, pingseq);

    if (pspec->pd.tcp.flags & TH_SYN) {
      tcpops = (u8 *) "\x02\x04\x05\xb4";
      tcpopslen = 4;
    }

    for(decoy = 0; decoy < o.numdecoys; decoy++) {
      packet = build_tcp_raw(&o.decoys[decoy], hss->target->v4hostip(),
      			     o.ttl, ipid, IP_TOS_DEFAULT, false,
      			     o.ipoptions, o.ipoptionslen,
      			     sport, pspec->pd.tcp.dport,
      			     seq, ack, 0, pspec->pd.tcp.flags, 0, 0,
      			     tcpops, tcpopslen,
			     o.extra_payload, o.extra_payload_length, 
			     &packetlen);
      if (decoy == o.decoyturn) {
	probe->setIP(packet, packetlen, pspec);
	probe->sent = USI->now;
      }
      hss->probeSent(packetlen);
      send_ip_packet(USI->rawsd, ethptr, packet, packetlen);
      free(packet);
    }
  } else if (pspec->type == PS_UDP) {
    const char *payload;
    size_t payload_length;

    payload = get_udp_payload(pspec->pd.udp.dport, &payload_length);

    for(decoy = 0; decoy < o.numdecoys; decoy++) {
      packet = build_udp_raw(&o.decoys[decoy], hss->target->v4hostip(),
			     o.ttl, ipid, IP_TOS_DEFAULT, false,
			     o.ipoptions, o.ipoptionslen,
			     sport, pspec->pd.udp.dport,
			     (char *) payload, payload_length,
			     &packetlen);
      if (decoy == o.decoyturn) {
	probe->setIP(packet, packetlen, pspec);
	probe->sent = USI->now;
      }
      hss->probeSent(packetlen);
      send_ip_packet(USI->rawsd, ethptr, packet, packetlen);
      free(packet);
    }
  } else if (pspec->type == PS_SCTP) {
    switch (pspec->pd.sctp.chunktype) {
      case SCTP_INIT:
        chunklen = sizeof(struct sctp_chunkhdr_init);
        chunk = (char*)safe_malloc(chunklen);
        sctp_pack_chunkhdr_init(chunk, SCTP_INIT, 0, chunklen,
                                get_random_u32()/*itag*/,
                                32768, 10, 2048,
                                get_random_u32()/*itsn*/);
        vtag = 0;
        break;
      case SCTP_COOKIE_ECHO:
        chunklen = sizeof(struct sctp_chunkhdr_cookie_echo) + 4;
        chunk = (char*)safe_malloc(chunklen);
        *((u32*)((char*)chunk + sizeof(struct sctp_chunkhdr_cookie_echo))) =
            get_random_u32();
        sctp_pack_chunkhdr_cookie_echo(chunk, SCTP_COOKIE_ECHO, 0, chunklen);
        vtag = get_random_u32();
        break;
      default:
        assert(0);
    }
    for(decoy = 0; decoy < o.numdecoys; decoy++) {
      packet = build_sctp_raw(&o.decoys[decoy], hss->target->v4hostip(),
                              o.ttl, ipid, IP_TOS_DEFAULT, false,
                              o.ipoptions, o.ipoptionslen,
                              sport, pspec->pd.sctp.dport,
                              vtag, chunk, chunklen,
                              o.extra_payload, o.extra_payload_length,
                              &packetlen);
      if (decoy == o.decoyturn) {
        probe->setIP(packet, packetlen, pspec);
        probe->sent = USI->now;
      }
      hss->probeSent(packetlen);
      send_ip_packet(USI->rawsd, ethptr, packet, packetlen);
      free(packet);
    }
    free(chunk);
  } else if (pspec->type == PS_PROTO) {
    for(decoy = 0; decoy < o.numdecoys; decoy++) {
      switch(pspec->proto) {

      case IPPROTO_TCP:
	packet = build_tcp_raw(&o.decoys[decoy], hss->target->v4hostip(),
			       o.ttl, ipid, IP_TOS_DEFAULT, false,
			       o.ipoptions, o.ipoptionslen,
			       sport, o.magic_port,
			       get_random_u32(), get_random_u32(), 0, TH_ACK, 0, 0,
			       NULL,0,
			       o.extra_payload, o.extra_payload_length, 
			       &packetlen);
	break;
      case IPPROTO_ICMP:
	packet = build_icmp_raw(&o.decoys[decoy], hss->target->v4hostip(),
				o.ttl, ipid, IP_TOS_DEFAULT, false,
				o.ipoptions, o.ipoptionslen,
				0, icmp_ident, 8, 0,
				o.extra_payload, o.extra_payload_length,
				&packetlen);
	break;
      case IPPROTO_IGMP:
	packet = build_igmp_raw(&o.decoys[decoy], hss->target->v4hostip(),
				o.ttl, ipid, IP_TOS_DEFAULT, false,
				o.ipoptions, o.ipoptionslen,
				0x11, 0,
				o.extra_payload, o.extra_payload_length,
				&packetlen);
	break;
      case IPPROTO_UDP:
	packet = build_udp_raw(&o.decoys[decoy], hss->target->v4hostip(),
			       o.ttl, ipid, IP_TOS_DEFAULT, false,
			       o.ipoptions, o.ipoptionslen,
			       sport, o.magic_port,
			       o.extra_payload, o.extra_payload_length, 
			       &packetlen);

	break;
      case IPPROTO_SCTP:
	{
	  struct sctp_chunkhdr_init chunk;
	  sctp_pack_chunkhdr_init(&chunk, SCTP_INIT, 0,
				  sizeof(struct sctp_chunkhdr_init),
				  get_random_u32()/*itag*/,
				  32768, 10, 2048,
				  get_random_u32()/*itsn*/);
	  packet = build_sctp_raw(&o.decoys[decoy], hss->target->v4hostip(),
				  o.ttl, ipid, IP_TOS_DEFAULT, false,
				  o.ipoptions, o.ipoptionslen,
				  sport, o.magic_port,
				  0UL, (char*)&chunk,
				  sizeof(struct sctp_chunkhdr_init),
				  o.extra_payload, o.extra_payload_length,
				  &packetlen);
	}
	break;
      default:
	packet = build_ip_raw(&o.decoys[decoy], hss->target->v4hostip(),
			      pspec->proto,
			      o.ttl, ipid, IP_TOS_DEFAULT, false,
			      o.ipoptions, o.ipoptionslen,
			      o.extra_payload, o.extra_payload_length, 
			      &packetlen);
	break;
      }
      if (decoy == o.decoyturn) {
	probe->setIP(packet, packetlen, pspec);
	probe->sent = USI->now;
      }
      hss->probeSent(packetlen);
      send_ip_packet(USI->rawsd, ethptr, packet, packetlen);
      free(packet);
    }
  } else if (pspec->type == PS_ICMP) {
    for(decoy = 0; decoy < o.numdecoys; decoy++) {
      packet = build_icmp_raw(&o.decoys[decoy], hss->target->v4hostip(),
                              o.ttl, ipid, IP_TOS_DEFAULT, false,
                              o.ipoptions, o.ipoptionslen,
                              0, icmp_ident, pspec->pd.icmp.type, pspec->pd.icmp.code,
                              o.extra_payload, o.extra_payload_length,
                              &packetlen);
      if (decoy == o.decoyturn) {
	probe->setIP(packet, packetlen, pspec);
	probe->sent = USI->now;
      }
      hss->probeSent(packetlen);
      send_ip_packet(USI->rawsd, ethptr, packet, packetlen);
      free(packet);
    }
  } else assert(0); /* TODO:  Maybe RPC scan and the like */
  /* Now that the probe has been sent, add it to the Queue for this host */
  hss->probes_outstanding.push_back(probe);
  USI->gstats->num_probes_active++;
  hss->num_probes_active++;

  gettimeofday(&USI->now, NULL);
  return probe;
}


static void sendNextScanProbe(UltraScanInfo *USI, HostScanStats *hss) {
  probespec pspec;
  
  if (get_next_target_probe(USI, hss, &pspec) == -1) {
    fatal("%s: No more probes! Error in Nmap.", __func__);
  }
  hss->numprobes_sent++;
  USI->gstats->probes_sent++;
  if (pspec.type == PS_ARP)
    sendArpScanProbe(USI, hss, 0, 0);
  else if (pspec.type == PS_CONNECTTCP)
    sendConnectScanProbe(USI, hss, pspec.pd.tcp.dport, 0, 0);
  else if (pspec.type == PS_TCP || pspec.type == PS_UDP
    || pspec.type == PS_SCTP || pspec.type == PS_PROTO
    || pspec.type == PS_ICMP)
    sendIPScanProbe(USI, hss, &pspec, 0, 0);
  else
    assert(0);
}

static void sendNextRetryStackProbe(UltraScanInfo *USI, HostScanStats *hss) {
  assert(!hss->retry_stack.empty());
  probespec pspec;
  u8 pspec_tries;
  hss->numprobes_sent++;
  USI->gstats->probes_sent++;

  pspec = hss->retry_stack.back();
  hss->retry_stack.pop_back();
  pspec_tries = hss->retry_stack_tries.back();
  hss->retry_stack_tries.pop_back();

  if (pspec.type == PS_CONNECTTCP)
    sendConnectScanProbe(USI, hss, pspec.pd.tcp.dport, pspec_tries + 1, 0);
  else {
    assert(pspec.type != PS_ARP);
    sendIPScanProbe(USI, hss, &pspec, pspec_tries + 1, 0);
  }
}

static void doAnyNewProbes(UltraScanInfo *USI) {
  HostScanStats *hss, *unableToSend;

  gettimeofday(&USI->now, NULL);

  /* Loop around the list of incomplete hosts and send a probe to each if
     appropriate. Stop once we've been all the way through the list without
     sending a probe. */
  unableToSend = NULL;
  hss = USI->nextIncompleteHost();
  while (hss != NULL && hss != unableToSend && USI->gstats->sendOK(NULL)) {
    if (hss->freshPortsLeft() && hss->sendOK(NULL)) {
      sendNextScanProbe(USI, hss);
      unableToSend = NULL;
    } else if (unableToSend == NULL) {
      /* Mark this as the first host we were not able to send to so we can break
         when we see it again. */
      unableToSend = hss;
    }
    hss = USI->nextIncompleteHost();
  }
}

static void doAnyRetryStackRetransmits(UltraScanInfo *USI) {
  HostScanStats *hss, *unableToSend;

  gettimeofday(&USI->now, NULL);

  /* Loop around the list of incomplete hosts and send a probe to each if
     appropriate. Stop once we've been all the way through the list without
     sending a probe. */
  unableToSend = NULL;
  hss = USI->nextIncompleteHost();
  while (hss != NULL && hss != unableToSend && USI->gstats->sendOK(NULL)) {
    if (!hss->retry_stack.empty() && hss->sendOK(NULL)) {
      sendNextRetryStackProbe(USI, hss);
      unableToSend = NULL;
    } else if (unableToSend == NULL) {
      /* Mark this as the first host we were not able to send to so we can break
         when we see it again. */
      unableToSend = hss;
    }
    hss = USI->nextIncompleteHost();
  }
}

/* Sends a ping probe to the host.  Assumes that caller has already
   checked that sending is OK w/congestion control and that pingprobe is
   available */
static void sendPingProbe(UltraScanInfo *USI, HostScanStats *hss) {
  if (o.debugging > 1) {
    char tmpbuf[64];
    log_write(LOG_PLAIN, "Ultrascan PING SENT to %s [%s]\n", hss->target->targetipstr(), 
	      probespec2ascii(&hss->target->pingprobe, tmpbuf, sizeof(tmpbuf)));
  }
  if (hss->target->pingprobe.type == PS_CONNECTTCP) {
    sendConnectScanProbe(USI, hss, hss->target->pingprobe.pd.tcp.dport, 0, 
			 hss->nextPingSeq(true));
  } else if (hss->target->pingprobe.type == PS_TCP || hss->target->pingprobe.type == PS_UDP
    || hss->target->pingprobe.type == PS_SCTP || hss->target->pingprobe.type == PS_PROTO
    || hss->target->pingprobe.type == PS_ICMP) {
    sendIPScanProbe(USI, hss, &hss->target->pingprobe, 0, hss->nextPingSeq(true));
  } else if (hss->target->pingprobe.type == PS_ARP) {
    sendArpScanProbe(USI, hss, 0, hss->nextPingSeq(true));
  } else if (USI->scantype == RPC_SCAN) {
    assert(0); /* TODO: fill out */
  } else {
    assert(0);
  }
  USI->gstats->probes_sent++;
}

static void sendGlobalPingProbe(UltraScanInfo *USI) {
  HostScanStats *hss;

  hss = USI->gstats->pinghost;
  assert(hss != NULL);

  if (o.debugging > 1) {
    char tmpbuf[64];
    log_write(LOG_PLAIN, "Ultrascan GLOBAL PING SENT to %s [%s]\n", hss->target->targetipstr(), 
	      probespec2ascii(&hss->target->pingprobe, tmpbuf, sizeof(tmpbuf)));
  }
  sendPingProbe(USI, hss);
}

static void doAnyPings(UltraScanInfo *USI) {
  list<HostScanStats *>::iterator hostI;
  HostScanStats *hss = NULL;

  gettimeofday(&USI->now, NULL);
  /* First single host pings */
  for(hostI = USI->incompleteHosts.begin(); 
      hostI != USI->incompleteHosts.end(); hostI++) {
    hss = *hostI;
    if (hss->target->pingprobe.type != PS_NONE && 
	hss->rld.rld_waiting == false && 
	hss->numprobes_sent >= hss->lastping_sent_numprobes + 10 &&
	TIMEVAL_SUBTRACT(USI->now, hss->lastrcvd) > USI->perf.pingtime && 
	TIMEVAL_SUBTRACT(USI->now, hss->lastping_sent) > USI->perf.pingtime &&
	USI->gstats->sendOK(NULL) && hss->sendOK(NULL)) {
      sendPingProbe(USI, hss);
      hss->lastping_sent = USI->now;
      hss->lastping_sent_numprobes = hss->numprobes_sent;
    }    
  }

  /* Next come global pings. We never send more than one of these at at time. */
  if (USI->gstats->pinghost != NULL &&
      USI->gstats->pinghost->target->pingprobe.type != PS_NONE &&
      USI->gstats->pinghost->num_probes_active == 0 &&
      USI->gstats->probes_sent >= USI->gstats->lastping_sent_numprobes + 20 && 
      TIMEVAL_SUBTRACT(USI->now, USI->gstats->lastrcvd) > USI->perf.pingtime && 
      TIMEVAL_SUBTRACT(USI->now, USI->gstats->lastping_sent) > USI->perf.pingtime && 
      USI->gstats->sendOK(NULL)) {
    sendGlobalPingProbe(USI);
    USI->gstats->lastping_sent = USI->now;
    USI->gstats->lastping_sent_numprobes = USI->gstats->probes_sent;
  }
}

/* Retransmit one probe that has presumably been timed out.  Only does
   retransmission, does not mark the probe timed out and such. */
static void retransmitProbe(UltraScanInfo *USI, HostScanStats *hss, 
			    UltraProbe *probe) {
  UltraProbe *newProbe = NULL;
  if (probe->type == UltraProbe::UP_IP) {
    if (USI->prot_scan || USI->ptech.rawprotoscan)
      newProbe = sendIPScanProbe(USI, hss, probe->pspec(), 
				 probe->tryno + 1, 0);
    else if (probe->protocol() == IPPROTO_TCP) {
      newProbe = sendIPScanProbe(USI, hss, probe->pspec(), probe->tryno + 1, 
				 0);
    } else if (probe->protocol() == IPPROTO_UDP) {
      newProbe = sendIPScanProbe(USI, hss, probe->pspec(), probe->tryno + 1,
				 0);
    } else if (probe->protocol() == IPPROTO_SCTP) {
      newProbe = sendIPScanProbe(USI, hss, probe->pspec(), probe->tryno + 1,
				 0);
    } else if (probe->protocol() == IPPROTO_ICMP) {
      newProbe = sendIPScanProbe(USI, hss, probe->pspec(), probe->tryno + 1,
				 0);
    } else {
      assert(0);
    }
  } else if (probe->type == UltraProbe::UP_CONNECT) {
    newProbe = sendConnectScanProbe(USI, hss, probe->pspec()->pd.tcp.dport, probe->tryno + 1, 0);
  } else if (probe->type == UltraProbe::UP_ARP) {
    newProbe = sendArpScanProbe(USI, hss, probe->tryno + 1, 0);
  } else assert(0); /* TODO: Support any other probe types */
  if (newProbe)
    newProbe->prevSent = probe->sent;
  probe->retransmitted = true;
  assert(hss->num_probes_waiting_retransmit > 0);
  hss->num_probes_waiting_retransmit--;
  hss->numprobes_sent++;
  USI->gstats->probes_sent++;
}

  /* Go through the ProbeQueue of each host, identify any
     timed out probes, then try to retransmit them as appropriate */
static void doAnyOutstandingRetransmits(UltraScanInfo *USI) {
  list<HostScanStats *>::iterator hostI;
  list<UltraProbe *>::iterator probeI;
  /* A cache of the last processed probe from each host, to avoid re-examining a
     bunch of probes to find the next one that needs to be retransmitted. */
  map<HostScanStats *, list<UltraProbe *>::iterator> probe_cache;
  HostScanStats *host = NULL;
  UltraProbe *probe = NULL;
  int retrans = 0; /* Number of retransmissions during a loop */
  unsigned int maxtries;

  struct timeval tv_start = {0};

  gettimeofday(&USI->now, NULL);

  if (o.debugging)
    tv_start = USI->now;

  /* Loop until we get through all the hosts without a retransmit or we're not
     OK to send any more. */
  do {
    retrans = 0;
    for (hostI = USI->incompleteHosts.begin();
         hostI != USI->incompleteHosts.end() && USI->gstats->sendOK(NULL);
         hostI++) {
      host = *hostI;
      /* Skip this host if it has nothing to send. */
      if ((host->num_probes_active == 0
           && host->num_probes_waiting_retransmit == 0))
        continue;
      if (!host->sendOK(NULL))
        continue;
      assert(!host->probes_outstanding.empty());

      /* Initialize the probe cache if necessary. */
      if (probe_cache.find(host) == probe_cache.end())
        probe_cache[host] = host->probes_outstanding.end();
      /* Restore the probe iterator from the cache. */
      probeI = probe_cache[host];

      maxtries = host->allowedTryno(NULL, NULL);
      do {
        probeI--;
        probe = *probeI;
        if (probe->timedout && !probe->retransmitted && 
            maxtries > probe->tryno && !probe->isPing()) {
          /* For rate limit detection, we delay the first time a new tryno
             is seen, as long as we are scanning at least 2 ports */
          if (probe->tryno + 1 > (int) host->rld.max_tryno_sent && 
              USI->gstats->numprobes > 1) {
            host->rld.max_tryno_sent = probe->tryno + 1;
            host->rld.rld_waiting = true;
            TIMEVAL_MSEC_ADD(host->rld.rld_waittime, USI->now, 1000);
          } else {
            host->rld.rld_waiting = false;
            retransmitProbe(USI, host, probe);
            retrans++;
          }
          break; /* I only do one probe per host for now to spread load */
        } 
      } while (probeI != host->probes_outstanding.begin());

      /* Wrap the probe iterator around. */
      if (probeI == host->probes_outstanding.begin())
        probeI = host->probes_outstanding.end();
      /* Cache the probe iterator. */
      probe_cache[host] = probeI;
    }
  } while (USI->gstats->sendOK(NULL) && retrans != 0);

  gettimeofday(&USI->now, NULL);
  if (o.debugging) {
    long tv_diff = TIMEVAL_MSEC_SUBTRACT(USI->now, tv_start);
    if (tv_diff > 30) log_write(LOG_PLAIN, "%s took %lims\n", __func__, tv_diff);
  }
}

/* Print occasional remaining time estimates, as well as
   debugging information */
static void printAnyStats(UltraScanInfo *USI) {

  list<HostScanStats *>::iterator hostI;
  HostScanStats *hss;
  struct ultra_timing_vals hosttm;

  /* Print debugging states for each host being scanned */
  if (o.debugging > 2) {
    log_write(LOG_PLAIN, "**TIMING STATS** (%.4fs): IP, probes active/freshportsleft/retry_stack/outstanding/retranwait/onbench, cwnd/ssthresh/delay, timeout/srtt/rttvar/\n", o.TimeSinceStart());
    log_write(LOG_PLAIN, "   Groupstats (%d/%d incomplete): %d/*/*/*/*/* %.2f/%d/* %d/%d/%d\n",
	      USI->numIncompleteHosts(), USI->numInitialHosts(), 
	      USI->gstats->num_probes_active, USI->gstats->timing.cwnd,
	      USI->gstats->timing.ssthresh, USI->gstats->to.timeout, 
	      USI->gstats->to.srtt, USI->gstats->to.rttvar);

    if (o.debugging > 3) {
      for(hostI = USI->incompleteHosts.begin(); 
          hostI != USI->incompleteHosts.end(); hostI++) {
        hss = *hostI;
        hss->getTiming(&hosttm);
        log_write(LOG_PLAIN, "   %s: %d/%d/%d/%d/%d/%d %.2f/%d/%d %li/%d/%d\n", hss->target->targetipstr(),
                  hss->num_probes_active, hss->freshPortsLeft(), 
                  (int) hss->retry_stack.size(),
                  hss->num_probes_outstanding(),
                  hss->num_probes_waiting_retransmit, (int) hss->probe_bench.size(),
                  hosttm.cwnd, hosttm.ssthresh, hss->sdn.delayms, 
                  hss->probeTimeout(), hss->target->to.srtt, 
                  hss->target->to.rttvar);
      }
    }

    USI->log_current_rates(LOG_PLAIN);
    USI->log_overall_rates(LOG_PLAIN);
  }

  if (USI->SPM->mayBePrinted(&USI->now))
    USI->SPM->printStatsIfNecessary(USI->getCompletionFraction(), &USI->now);
}

/* Does a select() call and handles all of the results. This handles both host
   discovery (ping) scans and port scans.  Even if stime is now, it tries a very
   quick select() just in case.  Returns true if at least one good result
   (generally a port state change) is found, false if it times out instead */
static bool do_one_select_round(UltraScanInfo *USI, struct timeval *stime) {
  fd_set fds_rtmp, fds_wtmp, fds_xtmp;
  int selectres;
  struct timeval timeout;
  int timeleft;
  ConnectScanInfo *CSI = USI->gstats->CSI;
  int sd;
  list<HostScanStats *>::iterator hostI;
  HostScanStats *host;
  list<UltraProbe *>::iterator probeI, nextProbeI;
  UltraProbe *probe = NULL;
  unsigned int listsz;
  unsigned int probenum;
  int newportstate = PORT_UNKNOWN;
  int newhoststate = HOST_UNKNOWN;
  int optval;
  recvfrom6_t optlen = sizeof(int);
  int numGoodSD = 0;
  int err = 0;
  u16 pport = 0;
  reason_t current_reason = ER_NORESPONSE;
#ifdef LINUX
  struct sockaddr_storage sin,sout;
  struct sockaddr_in *s_in;
  struct sockaddr_in6 *s_in6;
  recvfrom6_t sinlen = sizeof(sin);
  recvfrom6_t soutlen = sizeof(sout);
#endif

  do {
    timeleft = TIMEVAL_MSEC_SUBTRACT(*stime, USI->now);
    if (timeleft < 0) timeleft = 0;
    fds_rtmp = USI->gstats->CSI->fds_read;
    fds_wtmp = USI->gstats->CSI->fds_write;
    fds_xtmp = USI->gstats->CSI->fds_except;
    timeout.tv_sec = timeleft / 1000;
    timeout.tv_usec = (timeleft % 1000) * 1000;

	if (CSI->numSDs) {
      selectres = select(CSI->maxValidSD + 1, &fds_rtmp, &fds_wtmp, 
			 &fds_xtmp, &timeout);
	  err = socket_errno();
	}
    else {
      /* Apparently Windows returns an WSAEINVAL if you select without watching any SDs.  Lame.  We'll usleep instead in that case */
      usleep(timeleft * 1000);
      selectres = 0;
    }
  } while (selectres == -1 && err == EINTR);

  gettimeofday(&USI->now, NULL);
  
  if (selectres == -1)
    pfatal("select failed in %s()", __func__);
  
  if (!selectres)
    return false;
  
  /* Yay!  Got at least one response back -- loop through outstanding probes
     and find the relevant ones. Note the peculiar structure of the loop--we
     iterate through both incompleteHosts and completedHosts, because global
     timing pings are sent to hosts in completedHosts. */
  list<HostScanStats *>::iterator incompleteHostI, completedHostI;
  incompleteHostI = USI->incompleteHosts.begin();
  completedHostI = USI->completedHosts.begin();
  while ((incompleteHostI != USI->incompleteHosts.end()
          || completedHostI != USI->completedHosts.end())
         && numGoodSD < selectres) {
    if (incompleteHostI != USI->incompleteHosts.end())
      hostI = incompleteHostI++;
    else
      hostI = completedHostI++;

    host = *hostI;
    if (host->num_probes_active == 0) continue;
    
    nextProbeI = probeI = host->probes_outstanding.end();
    listsz = host->num_probes_outstanding();
    if (listsz) nextProbeI--;
    for(probenum = 0; probenum < listsz && numGoodSD < selectres; probenum++) {
      probeI = nextProbeI;
      if (probeI != host->probes_outstanding.begin()) 
	nextProbeI--;
      probe = *probeI;
      /* Assume that we will adjust timing when a response is received. */
      bool adjust_timing = true;
      pport = probe->pspec()->pd.tcp.dport;
      assert(probe->type == UltraProbe::UP_CONNECT);
      sd = probe->CP()->sd;
	/* Let see if anything has happened! */
      if (sd >= 0 && (FD_ISSET(sd, &fds_rtmp)  || FD_ISSET(sd, &fds_wtmp) || 
		      FD_ISSET(sd, &fds_xtmp))) {
	numGoodSD++;
	newportstate = PORT_UNKNOWN;
	if (getsockopt(sd, SOL_SOCKET, SO_ERROR, (char *) &optval, 
		       &optlen) != 0)
	  optval = socket_errno(); /* Stupid Solaris ... */
	switch(optval) {
	case 0:
#ifdef LINUX
	  if (!FD_ISSET(sd, &fds_rtmp)) {
            if (getpeername(sd, (struct sockaddr *) &sin, &sinlen) < 0) {
              pfatal("error in getpeername of connect_results for port %hu", (u16) pport);
            } else {
              s_in = (struct sockaddr_in *) &sin;
              s_in6 = (struct sockaddr_in6 *) &sin;
              if ((o.af() == AF_INET &&
                   pport != ntohs(s_in->sin_port))
#ifdef HAVE_IPV6
                  || (o.af() == AF_INET6 && pport != ntohs(s_in6->sin6_port))
#endif
                  ) {
                error("Mismatch!!!! we think we have port %hu but we really have a different one", (u16) pport);
              }
            }
            
            if (getsockname(sd, (struct sockaddr *) &sout, &soutlen) < 0) {
              pfatal("error in getsockname for port %hu", (u16) pport);
              }
            s_in = (struct sockaddr_in *) &sout;
            s_in6 = (struct sockaddr_in6 *) &sout;
            if ((o.af() == AF_INET && htons(s_in->sin_port) == pport) 
#ifdef HAVE_IPV6
                || (o.af() == AF_INET6 && htons(s_in6->sin6_port) == pport)
#endif
                ) {
              /* Linux 2.2 bug can lead to bogus successful connect()ions
                 in this case -- we treat the port as bogus even though it
                 is POSSIBLE that this is a real connection */
              newportstate = PORT_CLOSED;
            } else {
              newhoststate = HOST_UP;
              newportstate = PORT_OPEN;
            }
	  } else {
	    newhoststate = HOST_UP;
	    newportstate = PORT_OPEN;
	  }
#else
	  newhoststate = HOST_UP;
	  newportstate = PORT_OPEN;
#endif
	  current_reason = (newportstate == PORT_OPEN) ? ER_CONACCEPT : ER_CONREFUSED;
	  break;
	case EACCES:
	  /* Apparently this can be caused by dest unreachable admin
	     prohibited messages sent back, at least from IPv6
	     hosts */
	  newhoststate = HOST_DOWN;
	  newportstate = PORT_FILTERED;
	  current_reason = ER_ADMINPROHIBITED;
	  break;
	case ECONNREFUSED:
	  newhoststate = HOST_UP;
	  newportstate = PORT_CLOSED;
	  current_reason = ER_CONREFUSED;
	  break;
	case EAGAIN:
	  log_write(LOG_STDOUT, "Machine %s MIGHT actually be listening on probe port %d\n", host->target->targetipstr(), USI->ports->syn_ping_ports[probe->dport()]);
	  /* Fall through. */
#ifdef WIN32
	case WSAENOTCONN:
#endif
	  newhoststate = HOST_UP;
	  current_reason = ER_CONACCEPT;
	  break;
#ifdef ENOPROTOOPT
	case ENOPROTOOPT:
#endif
	case EHOSTUNREACH:
	  newhoststate = HOST_DOWN;
	  newportstate = PORT_FILTERED;
	  current_reason = ER_HOSTUNREACH;
	  break;
#ifdef WIN32
	case WSAEADDRNOTAVAIL:
#endif
	case ETIMEDOUT:
	case EHOSTDOWN:
	  newhoststate = HOST_DOWN;
	  /* It could be the host is down, or it could be firewalled.  We
	     will go on the safe side & assume port is closed ... on second
	     thought, lets go firewalled! and see if it causes any trouble */
	  newportstate = PORT_FILTERED;
	  current_reason = ER_NORESPONSE;
	  break;
	case ENETUNREACH:
	  newhoststate = HOST_DOWN;
	  newportstate = PORT_FILTERED;
	  current_reason = ER_NETUNREACH;
	  break;
	case ENETDOWN:
	case ENETRESET:
	case ECONNABORTED:
	  fatal("Strange SO_ERROR from connection to %s (%d - '%s') -- bailing scan", host->target->targetipstr(), optval, strerror(optval));
	  break;
	default:
	  error("Strange read error from %s (%d - '%s')", host->target->targetipstr(), optval, strerror(optval));
	  break;
	}

	if (USI->ping_scan && newhoststate != HOST_UNKNOWN) {
	  if (probe->isPing())
	    ultrascan_ping_update(USI, host, probeI, &USI->now, adjust_timing);
	  else {
	    ultrascan_host_probe_update(USI, host, probeI, newhoststate, &USI->now, adjust_timing);
	    host->target->reason.reason_id = current_reason;
	  }
	} else if (!USI->ping_scan && newportstate != PORT_UNKNOWN) {
	  if (probe->isPing())
	    ultrascan_ping_update(USI, host, probeI, &USI->now, adjust_timing);
	  else {
	    /* Save these values so we can use them after
	       ultrascan_port_probe_update deletes probe. */
	    u8 protocol = probe->protocol();
	    u16 dport = probe->dport();

	    ultrascan_port_probe_update(USI, host, probeI, newportstate, &USI->now, adjust_timing);
	    host->target->ports.setStateReason(dport, protocol, current_reason, 0, 0);
	  }
	}
      }
    }
  }
  return numGoodSD;
}

/* Tries to get one *good* (finishes a probe) ARP response with pcap
   by the (absolute) time given in stime.  Even if stime is now, try
   an ultra-quick pcap read just in case.  Returns true if a "good"
   result was found, false if it timed out instead. */
static bool get_arp_result(UltraScanInfo *USI, struct timeval *stime) {

  gettimeofday(&USI->now, NULL);
  long to_usec;
  int rc;
  u8 rcvdmac[6];
  struct in_addr rcvdIP;
  struct timeval rcvdtime;
  bool timedout = false;
  struct sockaddr_in sin;
  HostScanStats *hss = NULL;
  list<UltraProbe *>::iterator probeI;
  int gotone = 0;

  do {
    to_usec = TIMEVAL_SUBTRACT(*stime, USI->now);
    if (to_usec < 2000) to_usec = 2000;
    rc = read_arp_reply_pcap(USI->pd, rcvdmac, &rcvdIP, to_usec, &rcvdtime, PacketTrace::traceArp);
    gettimeofday(&USI->now, NULL);
    if (rc == -1) fatal("Received -1 response from read_arp_reply_pcap");
    if (rc == 0) {
      if (TIMEVAL_SUBTRACT(*stime, USI->now) < 0) {
	timedout = true;
	break;
      } else continue;
    }     
    if (rc == 1) {
      if (TIMEVAL_SUBTRACT(USI->now, *stime) > 200000) {
	/* While packets are still being received, I'll be generous
	   and give an extra 1/5 sec.  But we have to draw the line
	   somewhere.  Hopefully this response will be a keeper so it
	   won't matter.  */
	timedout = true;
      }

      /* Yay, I got one.  Find whether I asked for it */
      /* Search for this host on the incomplete list */
      memset(&sin, 0, sizeof(sin));
      sin.sin_addr.s_addr = rcvdIP.s_addr;
      sin.sin_family = AF_INET;
      hss = USI->findHost((struct sockaddr_storage *) &sin);
      if (!hss) continue;
      /* Add found HW address for target */
      hss->target->setMACAddress(rcvdmac);
	  hss->target->reason.reason_id = ER_ARPRESPONSE;

      if (hss->probes_outstanding.empty()) {
	continue;
	/* TODO: I suppose I should really mark the @@# host as up */
      }
      probeI = hss->probes_outstanding.end();
      probeI--;
      ultrascan_host_probe_update(USI, hss, probeI, HOST_UP, &rcvdtime);
      /* Now that we know the host is up, we can forget our other probes. */
      hss->destroyAllOutstandingProbes();
      /* TODO: Set target mac */
      gotone = 1;
      //      printf("Marked host %s as up!", hss->target->NameIP());
      break;
    }
  } while(!timedout);

  return gotone;
}




/* Tries to get one *good* (finishes a probe) pcap response by the
   (absolute) time given in stime.  Even if stime is now, try an
   ultra-quick pcap read just in case.  Returns true if a "good" result
   was found, false if it timed out instead. */
static bool get_pcap_result(UltraScanInfo *USI, struct timeval *stime) {
  bool goodone = false;
  bool timedout = false;
  bool adjust_timing = true;
  struct timeval rcvdtime;
  struct ip *ip = NULL;
  struct ip *ip_icmp = NULL;
  struct icmp *icmp = NULL;
  struct link_header linkhdr;
  unsigned int bytes;
  long to_usec;
  HostScanStats *hss = NULL;
  struct sockaddr_in sin;
  list<UltraProbe *>::iterator probeI;
  UltraProbe *probe = NULL;
  int newstate = PORT_UNKNOWN;
  unsigned int probenum;
  unsigned int listsz;
  unsigned int requiredbytes;
  /* Static so that we can detect an ICMP response now, then add it later when
     the icmp probe is made */
  static bool protoscanicmphack = false;
  static struct sockaddr_in protoscanicmphackaddy;
  reason_t current_reason = ER_NORESPONSE;
  u32 reason_sip = 0;
  gettimeofday(&USI->now, NULL);

  do {
    to_usec = TIMEVAL_SUBTRACT(*stime, USI->now);
    if (to_usec < 2000) to_usec = 2000;
    ip = (struct ip *) readip_pcap(USI->pd, &bytes, to_usec, &rcvdtime, &linkhdr, true);
    gettimeofday(&USI->now, NULL);
    if (!ip && TIMEVAL_SUBTRACT(*stime, USI->now) < 0) {
      timedout = true;
      break;
    } else if (!ip)
      continue;

    if (TIMEVAL_SUBTRACT(USI->now, *stime) > 200000) {
      /* While packets are still being received, I'll be generous and give
	 an extra 1/5 sec.  But we have to draw the line somewhere */
      timedout = true;
    }

    /* OK, we got a packet.  Most packet validity tests are taken care
     * of in readip_pcap, so this is simple
     */
    if (bytes < 28)
      continue;

    if (USI->prot_scan) {
      memset(&sin, 0, sizeof(sin));
      sin.sin_addr.s_addr = ip->ip_src.s_addr;
      sin.sin_family = AF_INET;
      hss = USI->findHost((struct sockaddr_storage *) &sin);
      if (hss) {
	setTargetMACIfAvailable(hss->target, &linkhdr, ip, 0);
	if (ip->ip_p == IPPROTO_ICMP) {
	  protoscanicmphack = true;
	  protoscanicmphackaddy = sin;
	  ip_icmp = ip;
	} else {
	  probeI = hss->probes_outstanding.end();
	  listsz = hss->num_probes_outstanding();
	  goodone = false;
	  for(probenum = 0; probenum < listsz && !goodone; probenum++) {
	    probeI--;
	    probe = *probeI;
	    
	    if (probe->protocol() == ip->ip_p) {
	      /* if this is our probe we sent to localhost, then it doesn't count! */
	      if (ip->ip_src.s_addr == ip->ip_dst.s_addr &&
		  probe->ipid() == ntohs(ip->ip_id))
	        continue;

	      /* We got a packet from the dst host in the protocol we looked for, and
		 it wasn't our probe to ourselves, so it must be open */
	      newstate = PORT_OPEN;
          current_reason = ER_PROTORESPONSE;
	      goodone = true;
	    }
	  }
	}
      }
    }

    if (ip->ip_p == IPPROTO_TCP && !USI->prot_scan) {
      struct tcp_hdr *tcp = (struct tcp_hdr *) ((u8 *) ip + ip->ip_hl * 4);
      /* Now ensure this host is even in the incomplete list */
      memset(&sin, 0, sizeof(sin));
      sin.sin_addr.s_addr = ip->ip_src.s_addr;
      sin.sin_family = AF_INET;
      hss = USI->findHost((struct sockaddr_storage *) &sin);
      if (!hss) continue; // Not from a host that interests us
      setTargetMACIfAvailable(hss->target, &linkhdr, ip, 0);
      probeI = hss->probes_outstanding.end();
      listsz = hss->num_probes_outstanding();

      goodone = false;
      
      /* Find the probe that provoked this response. */
      for (probenum = 0; probenum < listsz && !goodone; probenum++) {
	probeI--;
	probe = *probeI;

        if (!tcp_probe_match(USI, probe, hss, ip))
          continue;

	if (!probe->isPing()) {
	  /* Now that response has been matched to a probe, I interpret it */
	  if (USI->scantype == SYN_SCAN && (tcp->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK)) {
	    /* Yeah!  An open port */
	    newstate = PORT_OPEN;
	    current_reason = ER_SYNACK;
	  } else if (tcp->th_flags & TH_RST) {
	    current_reason = ER_RESETPEER;
	    if (USI->scantype == WINDOW_SCAN ) {
	      newstate = (tcp->th_win)? PORT_OPEN : PORT_CLOSED;
	    } else if (USI->scantype == ACK_SCAN) {
	      newstate = PORT_UNFILTERED;
	    } else newstate = PORT_CLOSED;
	  } else if (USI->scantype == SYN_SCAN && (tcp->th_flags & TH_SYN)) {
	    /* A SYN from a TCP Split Handshake - http://nmap.org/misc/split-handshake.pdf - open port */
	    newstate = PORT_OPEN;
	    current_reason = ER_SYN;
	  } else {
	    if (o.debugging)
	      error("Received scan response with unexpected TCP flags: %d", tcp->th_flags);
	    break;
	  }
	}

        goodone = true;
      }
    } else if (ip->ip_p == IPPROTO_SCTP && !USI->prot_scan) {
      struct sctp_hdr *sctp = (struct sctp_hdr *) ((u8 *) ip + ip->ip_hl * 4);
      struct dnet_sctp_chunkhdr *chunk = (struct dnet_sctp_chunkhdr *) ((u8 *) sctp + 12);
      /* Now ensure this host is even in the incomplete list */
      memset(&sin, 0, sizeof(sin));
      sin.sin_addr.s_addr = ip->ip_src.s_addr;
      sin.sin_family = AF_INET;
      hss = USI->findHost((struct sockaddr_storage *) &sin);
      if (!hss) continue; // Not from a host that interests us
      setTargetMACIfAvailable(hss->target, &linkhdr, ip, 0);
      probeI = hss->probes_outstanding.end();
      listsz = hss->num_probes_outstanding();

      goodone = false;
      
      /* Find the probe that provoked this response. */
      for (probenum = 0; probenum < listsz && !goodone; probenum++) {
	probeI--;
	probe = *probeI;

	if (o.af() != AF_INET || probe->protocol() != IPPROTO_SCTP)
	  continue;

	/* Ensure the connection info matches. */
	if (probe->dport() != ntohs(sctp->sh_sport)
            || probe->sport() != ntohs(sctp->sh_dport)
            || hss->target->v4sourceip()->s_addr != ip->ip_dst.s_addr)
	  continue;

	/* Sometimes we get false results when scanning localhost with
	   -p- because we scan localhost with src port = dst port and
	   see our outgoing packet and think it is a response. */
	if (probe->dport() == probe->sport() && 
	    ip->ip_src.s_addr == ip->ip_dst.s_addr && 
	    probe->ipid() == ntohs(ip->ip_id))
	  continue; /* We saw the packet we ourselves sent */

	if (!probe->isPing()) {
	  /* Now that response has been matched to a probe, I interpret it */
	  if (USI->scantype == SCTP_INIT_SCAN) {
	    if (chunk->sch_type == SCTP_INIT_ACK) {
	      newstate = PORT_OPEN;
	      current_reason = ER_INITACK;
	    } else if (chunk->sch_type == SCTP_ABORT) {
	      newstate = PORT_CLOSED;
	      current_reason = ER_ABORT;
	    } else {
	      if (o.debugging)
	        error("Received response with unexpected SCTP chunks: %02x",
	            chunk->sch_type);
	      break;
	    }
	  } else if (USI->scantype == SCTP_COOKIE_ECHO_SCAN) {
	    if (chunk->sch_type == SCTP_ABORT) {
	      newstate = PORT_CLOSED;
	      current_reason = ER_ABORT;
	    } else {
	      if (o.debugging)
	        error("Received response with unexpected SCTP chunks: %02x",
	            chunk->sch_type);
	      break;
	    }
	  }
	}

        goodone = true;
      }
    } else if (ip->ip_p == IPPROTO_ICMP) {
      icmp = (struct icmp *) ((char *)ip + 4 * ip->ip_hl);

      if (icmp->icmp_type != 3)
	continue;

      struct ip *ip2 = (struct ip *) (((char *) ip) + 4 * ip->ip_hl + 8);
      requiredbytes = /* IPlen*/ 4 * ip->ip_hl + 
                      /* ICMPLen */ 8 + 
                      /* IP2 Len */ 4 * ip2->ip_hl;
      if (USI->tcp_scan || USI->udp_scan || USI->sctp_scan) {
	/* UDP hdr, or TCP hdr up to seq #, or SCTP hdr up to vtag */
	requiredbytes += 8;
      }
      /* prot scan has no headers coming back, so we don't reserve the 
	 8 xtra bytes */
      if (bytes < requiredbytes) {
	if (o.debugging) 
	  error("Received short ICMP packet (%d bytes)", bytes);
	continue;
      }
      
      /* Make sure the protocol is right */
      if (USI->tcp_scan && ip2->ip_p != IPPROTO_TCP)
	continue;

      if (USI->udp_scan && ip2->ip_p != IPPROTO_UDP)
	continue;

      if (USI->sctp_scan && ip2->ip_p != IPPROTO_SCTP)
	continue;

      /* ensure this packet relates to a packet to the host
	 we are scanning ... */
      memset(&sin, 0, sizeof(sin));
      sin.sin_addr.s_addr = ip2->ip_dst.s_addr;
      sin.sin_family = AF_INET;
      hss = USI->findHost((struct sockaddr_storage *) &sin);
      if (!hss) continue; // Not from a host that interests us
      probeI = hss->probes_outstanding.end();
      listsz = hss->num_probes_outstanding();
      goodone = false;
      /* Find the matching probe */
      for(probenum = 0; probenum < listsz && !goodone; probenum++) {
	probeI--;
	probe = *probeI;
	assert(o.af() == AF_INET);
	if (probe->protocol() != ip2->ip_p || 
	    hss->target->v4sourceip()->s_addr != ip2->ip_src.s_addr || 
	    hss->target->v4hostip()->s_addr != ip2->ip_dst.s_addr)
	  continue;

	if (ip2->ip_p == IPPROTO_TCP && !USI->prot_scan) {
	  struct tcp_hdr *tcp = (struct tcp_hdr *) ((u8 *) ip2 + ip2->ip_hl * 4);
	  if (ntohs(tcp->th_sport) != probe->sport() || 
	      ntohs(tcp->th_dport) != probe->dport() || 
	      ntohl(tcp->th_seq) != probe->tcpseq())
	    continue;
	} else if (ip2->ip_p == IPPROTO_SCTP && !USI->prot_scan) {
	  struct sctp_hdr *sctp = (struct sctp_hdr *) ((u8 *) ip2 + ip2->ip_hl * 4);
	  if (ntohs(sctp->sh_sport) != probe->sport() || 
	      ntohs(sctp->sh_dport) != probe->dport() ||
	      ntohl(sctp->sh_vtag) != probe->sctpvtag())
	    continue;
	} else if (ip2->ip_p == IPPROTO_UDP && !USI->prot_scan) {
	  /* TODO: IPID verification */
	  struct udp_hdr *udp = (struct udp_hdr *) ((u8 *) ip2 + ip2->ip_hl * 4);
	  if (ntohs(udp->uh_sport) != probe->sport() || 
	      ntohs(udp->uh_dport) != probe->dport())
	    continue;
	} else if (!USI->prot_scan) {
	  assert(0);
	} 

	if (icmp->icmp_type == 3) {
	  switch(icmp->icmp_code) {
	  case 0: /* Network unreachable */
	    newstate = PORT_FILTERED;
	    break;
	  case 1: /* Host Unreachable */
	    newstate = PORT_FILTERED;
	    break;
	  case 2: /* protocol unreachable */
	    if (USI->scantype == IPPROT_SCAN && 
		hss->target->v4hostip()->s_addr == ip->ip_src.s_addr) {
	      newstate = PORT_CLOSED;
	    } else
	      newstate = PORT_FILTERED;
	    break;
	  case 3: /* Port unreach */
	    if (USI->scantype == UDP_SCAN && 
		hss->target->v4hostip()->s_addr == ip->ip_src.s_addr)
	      newstate = PORT_CLOSED;
	    else if (USI->scantype == IPPROT_SCAN && 
		     hss->target->v4hostip()->s_addr == ip->ip_src.s_addr)
	      newstate = PORT_OPEN;
	    else
	      newstate = PORT_FILTERED;
	    break;
	  case 9: /* dest. net admin prohibited */
	  case 10: /* dest host admin prohibited */
	  case 13: /* communication admin. prohibited */
	    newstate = PORT_FILTERED;
	    break;

	  default:
	    error("Unexpected ICMP type/code 3/%d unreachable packet:\n", 
		  icmp->icmp_code);
	      nmap_hexdump((unsigned char *)icmp, ntohs(ip->ip_len) - 
		  sizeof(struct ip));
	    break;
	  }
	  current_reason = icmp->icmp_code+ER_ICMPCODE_MOD;
	  if (newstate == PORT_UNKNOWN) break;
	  goodone = true;
	}
      }
    } else if (ip->ip_p == IPPROTO_UDP && !USI->prot_scan) {
      struct udp_hdr *udp = (struct udp_hdr *) ((u8 *) ip + ip->ip_hl * 4);
      /* Search for this host on the incomplete list */
      memset(&sin, 0, sizeof(sin));
      sin.sin_addr.s_addr = ip->ip_src.s_addr;
      sin.sin_family = AF_INET;
      hss = USI->findHost((struct sockaddr_storage *) &sin);
      if (!hss) continue; // Not from a host that interests us
      probeI = hss->probes_outstanding.end();
      listsz = hss->num_probes_outstanding();
      goodone = false;

      for(probenum = 0; probenum < listsz && !goodone; probenum++) {
	probeI--;
	probe = *probeI;
	newstate = PORT_UNKNOWN;

	if (o.af() != AF_INET || probe->protocol() != IPPROTO_UDP)
	  continue;

	/* Ensure the connection info matches. */
	if (probe->dport() != ntohs(udp->uh_sport) ||
	    probe->sport() != ntohs(udp->uh_dport) ||
	    hss->target->v4sourceip()->s_addr != ip->ip_dst.s_addr)
	  continue;
	
	/* Sometimes we get false results when scanning localhost with
	   -p- because we scan localhost with src port = dst port and
	   see our outgoing packet and think it is a response. */
	if (probe->dport() == probe->sport() && 
	    ip->ip_src.s_addr == ip->ip_dst.s_addr && 
	    probe->ipid() == ntohs(ip->ip_id))
	  continue; /* We saw the packet we ourselves sent */

	newstate = PORT_OPEN;
    current_reason = ER_UDPRESPONSE;
	goodone = true;
      }
    } else continue; /* Unexpected protocol */
  } while (!goodone && !timedout);

  if (goodone) {
    reason_sip = (ip->ip_src.s_addr == hss->target->v4hostip()->s_addr) ? 0 : ip->ip_src.s_addr;
    if (probe->isPing())
      ultrascan_ping_update(USI, hss, probeI, &rcvdtime, adjust_timing);
    else {
      /* Save these values so we can use them after ultrascan_port_probe_update
         deletes probe. */
      u8 protocol = probe->protocol();
      u16 dport = probe->dport();

      ultrascan_port_probe_update(USI, hss, probeI, newstate, &rcvdtime, adjust_timing);
      if(USI->prot_scan)  
         hss->target->ports.setStateReason(protocol, IPPROTO_IP, 
                                          current_reason, ip->ip_ttl, reason_sip);
      else
         hss->target->ports.setStateReason(dport, protocol,
                                           current_reason, ip->ip_ttl, reason_sip);    
    }
  }

  /* If protoicmphack is true, we are doing an IP proto scan and
     discovered that ICMP is open.  This has to be done separately
     because an ICMP response ALSO frequently shows that some other
     protocol is closed/filtered.  So we let that other protocol stuff
     go first, then handle it here */
  if (protoscanicmphack) {
    hss = USI->findHost((struct sockaddr_storage *) &protoscanicmphackaddy);
    if (hss) {
	  probeI = hss->probes_outstanding.end();
	  listsz = hss->num_probes_outstanding();

	  for(probenum = 0; probenum < listsz; probenum++) {
	    probeI--;
	    probe = *probeI;

	    if (probe->protocol() == IPPROTO_ICMP) {
	      if (probe->isPing())
		ultrascan_ping_update(USI, hss, probeI, &rcvdtime, adjust_timing);
	      else {
		ultrascan_port_probe_update(USI, hss, probeI, PORT_OPEN, &rcvdtime, adjust_timing);
		icmp = (struct icmp *) ((char *)ip_icmp + 4 * ip_icmp->ip_hl);
		reason_sip = (ip_icmp->ip_src.s_addr == protoscanicmphackaddy.sin_addr.s_addr) ? 0 : ip_icmp->ip_src.s_addr;
		if(!icmp->icmp_code && !icmp->icmp_type) 
			hss->target->ports.setStateReason(IPPROTO_ICMP, IPPROTO_IP, ER_ECHOREPLY, 
                                              ip_icmp->ip_ttl, reason_sip);
		else 
			hss->target->ports.setStateReason(IPPROTO_ICMP, IPPROTO_IP, icmp->icmp_type+ER_ICMPCODE_MOD, 
                                              ip_icmp->ip_ttl, reason_sip);
	      } 
	      if (!goodone) goodone = true;
	      break;
	    }
	  }
	  protoscanicmphack = false;
    }
  }

  return goodone;
}

/* Tries to get one *good* (finishes a probe) pcap response to a host discovery
   (ping) probe by the (absolute) time given in stime.  Even if stime is now,
   try an ultra-quick pcap read just in case.  Returns true if a "good" result
   was found, false if it timed out instead. */
static int get_ping_pcap_result(UltraScanInfo *USI, struct timeval *stime) {
  bool goodone = false;
  bool timedout = false;
  bool adjust_timing = true;
  struct timeval rcvdtime;
  struct link_header linkhdr;
  struct ip *ip;
  unsigned int bytes;
  struct ppkt {
    unsigned char type;
    unsigned char code;
    unsigned short checksum;
    unsigned short id;
    unsigned short seq;
  } *ping;
  long to_usec;
  HostScanStats *hss = NULL;
  struct sockaddr_in sin;
  list<UltraProbe *>::iterator probeI;
  UltraProbe *probe = NULL;
  unsigned int trynum = 0;
  unsigned int requiredbytes;
  int newstate = HOST_UNKNOWN;
  unsigned int probenum;
  unsigned int listsz;
  reason_t current_reason = ER_NORESPONSE;

  do {
    to_usec = TIMEVAL_SUBTRACT(*stime, USI->now);
    if (to_usec < 2000) to_usec = 2000;
    ip = (struct ip *) readip_pcap(USI->pd, &bytes, to_usec, &rcvdtime, &linkhdr, true);
    gettimeofday(&USI->now, NULL);
    if (!ip) {
      if (TIMEVAL_SUBTRACT(*stime, USI->now) < 0) {
        timedout = true;
        break;
      } else {
        continue;
      }
    }

    if (TIMEVAL_SUBTRACT(USI->now, *stime) > 200000) {
      /* While packets are still being received, I'll be generous and give
	 an extra 1/5 sec.  But we have to draw the line somewhere */
      timedout = true;
    }

    /* OK, we got a packet.  Most packet validity tests are taken care
     * of in readip_pcap, so this is simple
     */
    if (bytes == 0)
      continue;

    /* First check if it is ICMP, TCP, or UDP */
    if (ip->ip_p == IPPROTO_ICMP) {
      /* if it is our response */
      ping = (struct ppkt *) ((ip->ip_hl * 4) + (char *) ip);
      if (bytes < ip->ip_hl * 4 + 8U) {
        if (!ip->ip_off)
           error("Supposed ping packet is only %d bytes long!", bytes);
        continue;
      }

      current_reason = ping->type + ER_ICMPTYPE_MOD;
      if (current_reason == ER_DESTUNREACH)
        current_reason = ping->code + ER_ICMPCODE_MOD;

      /* Echo reply, Timestamp reply, or Address Mask Reply. RFCs 792 and 950. */
      if (USI->ptech.rawicmpscan && (ping->type == 0 || ping->type == 14 || ping->type == 18)) {
        memset(&sin, 0, sizeof(sin));
        sin.sin_addr.s_addr = ip->ip_src.s_addr;
        sin.sin_family = AF_INET;
        hss = USI->findHost((struct sockaddr_storage *) &sin);
        if (!hss) continue; // Not from a host that interests us
        setTargetMACIfAvailable(hss->target, &linkhdr, ip, 0);
        probeI = hss->probes_outstanding.end();
        listsz = hss->num_probes_outstanding();

        /* A check for weird_responses is needed here. This is not currently
           possible because we don't have a good way to look up the original
           target of an ICMP probe based on the response. (massping encoded an
           array index in the ICMP sequence, which won't work here.) Once we've
           found the host that sent the probe that elicited the response, the
           test for weird_responses is
              if (sending_host->v4host().s_addr != ip->ip_src.s_addr)
                hss->target->weird_responses++;
           (That is, the target that sent the probe is not the same one that
           sent the response.)
         */

        goodone = false;

        /* Find the probe that provoked this response. */
        for (probenum = 0; probenum < listsz && !goodone; probenum++) {
          probeI--;
          probe = *probeI;

          if (o.af() != AF_INET || probe->protocol() != IPPROTO_ICMP)
            continue;

          /* Ensure the connection info matches. */
          if (hss->target->v4sourceip()->s_addr != ip->ip_dst.s_addr)
            continue;
          /* Don't match a timestamp request with an echo reply, for example. */
          if ((ping->type == 0 && probe->pspec()->pd.icmp.type != 8) ||
              (ping->type == 14 && probe->pspec()->pd.icmp.type != 13) ||
              (ping->type == 18 && probe->pspec()->pd.icmp.type != 17))
            continue;

          /* Sometimes we get false results when scanning localhost with
             -p- because we scan localhost with src port = dst port and
             see our outgoing packet and think it is a response. */
          if (probe->dport() == probe->sport() && 
              ip->ip_src.s_addr == ip->ip_dst.s_addr && 
              probe->ipid() == ntohs(ip->ip_id))
            continue; /* We saw the packet we ourselves sent */

          goodone = true;
          newstate = HOST_UP;

          if (o.debugging) 
            log_write(LOG_STDOUT, "We got a ping packet back from %s: id = %d seq = %d checksum = %d\n", inet_ntoa(ip->ip_src), ping->id, ping->seq, ping->checksum);
        }
      }
      // Destination unreachable, source quench, or time exceeded 
      else if (ping->type == 3 || ping->type == 4 || ping->type == 11) {
        struct ip *ip2 = (struct ip *) ((char *) ip + ip->ip_hl * 4 + 8);

        requiredbytes = ip->ip_hl * 4 + 8U + ip2->ip_hl * 4 + 8U;

	/* IPProto Scan (generally) sends bare IP headers, so no extra payload */
        if (bytes < requiredbytes && !USI->ptech.rawprotoscan) {
          if (o.debugging)
            error("ICMP (embedded) type %d code %d packet is only %d bytes", ping->type, ping->code, bytes);
          continue;
        }

        /* Bail out early if possible. */
        if (!USI->ptech.rawprotoscan) {
          if (ip2->ip_p == IPPROTO_ICMP && !USI->ptech.rawicmpscan)
            continue;
          if (ip2->ip_p == IPPROTO_TCP && !USI->ptech.rawtcpscan)
            continue;
          if (ip2->ip_p == IPPROTO_UDP && !USI->ptech.rawudpscan)
            continue;
          if (ip2->ip_p == IPPROTO_SCTP && !USI->ptech.rawsctpscan)
            continue;
        }

        memset(&sin, 0, sizeof(sin));
        sin.sin_addr.s_addr = ip2->ip_dst.s_addr;
        sin.sin_family = AF_INET;
        hss = USI->findHost((struct sockaddr_storage *) &sin);
        if (!hss) continue; // Not referring to a host that interests us
        setTargetMACIfAvailable(hss->target, &linkhdr, ip, 0);
        probeI = hss->probes_outstanding.end();
        listsz = hss->num_probes_outstanding();

        /* Find the probe that provoked this response. */
        for (probenum = 0; probenum < listsz; probenum++) {
          probeI--;
          probe = *probeI;

          assert(o.af() == AF_INET);
          if (probe->protocol() != ip2->ip_p || 
              hss->target->v4sourceip()->s_addr != ip->ip_dst.s_addr ||
              hss->target->v4sourceip()->s_addr != ip2->ip_src.s_addr || 
              hss->target->v4hostip()->s_addr != ip2->ip_dst.s_addr)
            continue;

          if (ip2->ip_p == IPPROTO_ICMP && USI->ptech.rawicmpscan) {
            /* The response was based on a ping packet we sent */
          } else if (ip2->ip_p == IPPROTO_TCP && USI->ptech.rawtcpscan) {
            struct tcp_hdr *tcp = (struct tcp_hdr *) (((char *) ip2) + 4 * ip2->ip_hl);
            if (probe->dport() != ntohs(tcp->th_dport) ||
                probe->sport() != ntohs(tcp->th_sport) ||
                probe->tcpseq() != ntohl(tcp->th_seq))
              continue;
          } else if (ip2->ip_p == IPPROTO_UDP && USI->ptech.rawudpscan) {
            struct udp_hdr *udp = (struct udp_hdr *) ((u8 *) ip2 + ip2->ip_hl * 4);
            if (probe->dport() != ntohs(udp->uh_dport) ||
                probe->sport() != ntohs(udp->uh_sport))
              continue;
          } else if (ip2->ip_p == IPPROTO_SCTP && USI->ptech.rawsctpscan) {
            struct sctp_hdr *sctp = (struct sctp_hdr *) ((u8 *) ip2 + ip2->ip_hl * 4);
            if (probe->dport() != ntohs(sctp->sh_dport) ||
                probe->sport() != ntohs(sctp->sh_sport) ||
                probe->sctpvtag() != ntohl(sctp->sh_vtag))
              continue;
          } else if (USI->ptech.rawprotoscan) {
            /* Success; we already know that the address and protocol match. */
          } else {
            assert(0);
          }

          /* If we made it this far, we found it. We don't yet know if it's
             going to change a host state (goodone) or not. */
          break;
        }
        /* Did we fail to find a probe? */
        if (probenum >= listsz)
          continue;

        if (ping->type == 3) {
          /* Destination unreachable. */
          if (hss->target->v4hostip()->s_addr == ip->ip_src.s_addr) {
            /* The ICMP error came directly from the target, so it's up. */
            goodone = true;
            newstate = HOST_UP;
          } else {
            goodone = true;
            newstate = HOST_DOWN;
          }
          if (o.debugging) {
	    if (ping->code == 3)
              log_write(LOG_STDOUT, "Got port unreachable for %s\n", hss->target->targetipstr());
	    else
              log_write(LOG_STDOUT, "Got destination unreachable for %s\n", hss->target->targetipstr());
          }
        } else if (ping->type == 11) {
          if (o.debugging) 
            log_write(LOG_STDOUT, "Got Time Exceeded for %s\n", hss->target->targetipstr());
          goodone = 1;
          newstate = HOST_DOWN;
	  /* I don't want anything to do with timing this. */
	  adjust_timing = false;
        } else if (ping->type == 4) {      
          if (o.debugging) log_write(LOG_STDOUT, "Got ICMP source quench\n");
          usleep(50000);
        } else if (o.debugging) {
          log_write(LOG_STDOUT, "Got ICMP message type %d code %d\n", ping->type, ping->code);
        }
      }
    } else if (ip->ip_p == IPPROTO_TCP && USI->ptech.rawtcpscan) {
      struct tcp_hdr *tcp = (struct tcp_hdr *) (((u8 *) ip) + 4 * ip->ip_hl);
      /* Check that the packet has useful flags. */
      if (!(tcp->th_flags & TH_RST)
        && ((tcp->th_flags & (TH_SYN|TH_ACK)) != (TH_SYN|TH_ACK)))
        continue;
      /* Now ensure this host is even in the incomplete list */
      memset(&sin, 0, sizeof(sin));
      sin.sin_addr.s_addr = ip->ip_src.s_addr;
      sin.sin_family = AF_INET;
      hss = USI->findHost((struct sockaddr_storage *) &sin);
      if (!hss) continue; // Not from a host that interests us
      setTargetMACIfAvailable(hss->target, &linkhdr, ip, 0);
      probeI = hss->probes_outstanding.end();
      listsz = hss->num_probes_outstanding();

      goodone = false;

      /* Find the probe that provoked this response. */
      for (probenum = 0; probenum < listsz && !goodone; probenum++) {
        probeI--;
        probe = *probeI;

        if (!tcp_probe_match(USI, probe, hss, ip))
          continue;

        goodone = true;
        newstate = HOST_UP;

        /* Fill out the reason. */
        if (o.pingtype & PINGTYPE_TCP_USE_SYN) {
          if (tcp->th_flags & TH_RST) {
                current_reason = ER_RESETPEER;
          } else if ((tcp->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK)) {
                current_reason = ER_SYNACK;
          }
        } else if (o.pingtype & PINGTYPE_TCP_USE_ACK) {
          if (tcp->th_flags & TH_RST)
            current_reason = ER_RESETPEER;
        }

        if (o.debugging)
          log_write(LOG_STDOUT, "We got a TCP ping packet back from %s port %hu (trynum = %d)\n", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport), trynum);
      }
    } else if (ip->ip_p == IPPROTO_UDP && USI->ptech.rawudpscan) {
      struct udp_hdr *udp = (struct udp_hdr *) (((char *) ip) + 4 * ip->ip_hl);
      /* Search for this host on the incomplete list */
      memset(&sin, 0, sizeof(sin));
      sin.sin_addr.s_addr = ip->ip_src.s_addr;
      sin.sin_family = AF_INET;
      hss = USI->findHost((struct sockaddr_storage *) &sin);
      if (!hss) continue; // Not from a host that interests us
      probeI = hss->probes_outstanding.end();
      listsz = hss->num_probes_outstanding();
      goodone = false;

      for(probenum = 0; probenum < listsz && !goodone; probenum++) {
	probeI--;
	probe = *probeI;

	if (o.af() != AF_INET || probe->protocol() != IPPROTO_UDP)
	  continue;

	/* Ensure the connection info matches. */
	if (probe->dport() != ntohs(udp->uh_sport) ||
	    probe->sport() != ntohs(udp->uh_dport) ||
	    hss->target->v4sourceip()->s_addr != ip->ip_dst.s_addr)
	  continue;
	
        /* Replace this with a call to probe_check_trynum_pingseq or similar. */
        if (o.magic_port_set) {
          trynum = probe->tryno;
        } else {
          sport_decode(USI, o.magic_port, ntohs(udp->uh_dport), &trynum, NULL);
        }

	/* Sometimes we get false results when scanning localhost with
	   -p- because we scan localhost with src port = dst port and
	   see our outgoing packet and think it is a response. */
	if (probe->dport() == probe->sport() && 
	    ip->ip_src.s_addr == ip->ip_dst.s_addr && 
	    probe->ipid() == ntohs(ip->ip_id))
	  continue; /* We saw the packet we ourselves sent */

        goodone = true;
        newstate = HOST_UP;
        current_reason = ER_UDPRESPONSE;

        if (o.debugging)
          log_write(LOG_STDOUT, "In response to UDP-ping, we got UDP packet back from %s port %hu (trynum = %d)\n", inet_ntoa(ip->ip_src), htons(udp->uh_sport), trynum);
      }
    } else if (ip->ip_p == IPPROTO_SCTP && USI->ptech.rawsctpscan) {
      struct sctp_hdr *sctp = (struct sctp_hdr *) (((char *) ip) + 4 * ip->ip_hl);
      struct dnet_sctp_chunkhdr *chunk = (struct dnet_sctp_chunkhdr *) ((u8 *) sctp + 12);
      /* Search for this host on the incomplete list */
      memset(&sin, 0, sizeof(sin));
      sin.sin_addr.s_addr = ip->ip_src.s_addr;
      sin.sin_family = AF_INET;
      hss = USI->findHost((struct sockaddr_storage *) &sin);
      if (!hss) continue; // Not from a host that interests us
      probeI = hss->probes_outstanding.end();
      listsz = hss->num_probes_outstanding();
      goodone = false;

      for(probenum = 0; probenum < listsz && !goodone; probenum++) {
	probeI--;
	probe = *probeI;

	if (o.af() != AF_INET || probe->protocol() != IPPROTO_SCTP)
	  continue;

	/* Ensure the connection info matches. */
	if (probe->dport() != ntohs(sctp->sh_sport) ||
	    probe->sport() != ntohs(sctp->sh_dport) ||
	    hss->target->v4sourceip()->s_addr != ip->ip_dst.s_addr)
	  continue;

	/* Sometimes we get false results when scanning localhost with
	   -p- because we scan localhost with src port = dst port and
	   see our outgoing packet and think it is a response. */
	if (probe->dport() == probe->sport() && 
	    ip->ip_src.s_addr == ip->ip_dst.s_addr && 
	    probe->ipid() == ntohs(ip->ip_id))
	  continue; /* We saw the packet we ourselves sent */

        goodone = true;
        newstate = HOST_UP;
        if (chunk->sch_type == SCTP_INIT_ACK) {
          current_reason = ER_INITACK;
        } else if (chunk->sch_type == SCTP_ABORT) {
          current_reason = ER_ABORT;
        } else {
          current_reason = ER_UNKNOWN;
          if (o.debugging)
            log_write(LOG_STDOUT, "Received scan response with unexpected SCTP chunks: n/a");
        }
      }
    } else if (!USI->ptech.rawprotoscan) {
      if (o.debugging > 2)
        error("Received packet with protocol %d; ignoring.", ip->ip_p);
    }

    /* Check for a protocol reply */
    if (!goodone && USI->ptech.rawprotoscan) {
      memset(&sin, 0, sizeof(sin));
      sin.sin_addr.s_addr = ip->ip_src.s_addr;
      sin.sin_family = AF_INET;
      hss = USI->findHost((struct sockaddr_storage *) &sin);
      if (!hss) continue;
      setTargetMACIfAvailable(hss->target, &linkhdr, ip, 0);
      probeI = hss->probes_outstanding.end();
      listsz = hss->num_probes_outstanding();
      goodone = false;
      for(probenum = 0; probenum < listsz && !goodone; probenum++) {
	probeI--;
	probe = *probeI;
	    
	if (probe->protocol() == ip->ip_p) {
	  /* if this is our probe we sent to localhost, then it doesn't count! */
	  if (ip->ip_src.s_addr == ip->ip_dst.s_addr &&
	      probe->ipid() == ntohs(ip->ip_id))
	    continue;

	  newstate = HOST_UP;
	  current_reason = ER_PROTORESPONSE;
	  goodone = true;
        }
      }
    }
  } while (!goodone && !timedout);

  if (goodone && newstate != HOST_UNKNOWN) {  
    if (probe->isPing())
      ultrascan_ping_update(USI, hss, probeI, &USI->now, adjust_timing);
    else {
      ultrascan_host_probe_update(USI, hss, probeI, newstate, &rcvdtime, adjust_timing);
      /* If the host is up, we can forget our other probes. */
      if (newstate == HOST_UP)
	hss->destroyAllOutstandingProbes();
      if (newstate == HOST_UP && ip && bytes >= 20)
	setTargetMACIfAvailable(hss->target, &linkhdr, ip, 0);
      hss->target->reason.reason_id = current_reason;
      hss->target->reason.ttl = ip->ip_ttl;
      if(ip->ip_src.s_addr != hss->target->v4host().s_addr)
	hss->target->reason.ip_addr.s_addr = ip->ip_src.s_addr;
    }
  }

  return 0;
}

static void waitForResponses(UltraScanInfo *USI) {
  struct timeval stime;
  bool gotone;
  gettimeofday(&USI->now, NULL);
  USI->gstats->last_wait = USI->now;
  USI->gstats->probes_sent_at_last_wait = USI->gstats->probes_sent;

  do {
    gotone = false;
    USI->sendOK(&stime);
    if (USI->ping_scan_arp) {
      gotone = get_arp_result(USI, &stime);
    } else if (USI->ping_scan) {
      if (USI->pd)
        gotone = get_ping_pcap_result(USI, &stime);
      if (!gotone && USI->ptech.connecttcpscan)
        gotone = do_one_select_round(USI, &stime);
    } else if (USI->pd) {
      gotone = get_pcap_result(USI, &stime);
    } else if (USI->scantype == CONNECT_SCAN) {
      gotone = do_one_select_round(USI, &stime);
    } else assert(0); /* TODO: Must fill this out for maybe rpc scan, etc. */
  } while (gotone && USI->gstats->num_probes_active > 0);

  gettimeofday(&USI->now, NULL);
  USI->gstats->last_wait = USI->now;
}

/* Initiate libpcap or some other sniffer as appropriate to be able to catch
   responses */
static void begin_sniffer(UltraScanInfo *USI, vector<Target *> &Targets) {
  string pcap_filter="";
  /* 20 IPv6 addresses is max (45 byte addy + 14 (" or src host ")) * 20 == 1180 */
  string dst_hosts="";
  unsigned int len = 0;
  unsigned int targetno;
  bool doIndividual = Targets.size() <= 20; // Don't bother IP limits if scanning huge # of hosts

  if (!USI->isRawScan())
    return; /* No sniffer needed! */

  if (doIndividual) {
    for(targetno = 0; targetno < Targets.size(); targetno++) {
      dst_hosts+=(targetno == 0)? "" : " or ";
      dst_hosts+="src host ";
      dst_hosts+=Targets[targetno]->targetipstr();
    }
  }

  if((USI->pd=my_pcap_open_live(Targets[0]->deviceName(), 100,  (o.spoofsource)? 1 : 0, pcap_selectable_fd_valid()? 200 : 2))==NULL)
    fatal("%s", PCAP_OPEN_ERRMSG);
    
  if (USI->ping_scan_arp){
    /* Some OSs including Windows 7 and Solaris 10 have been seen to send their
       ARP replies to the broadcast address, not to the (unicast) address that
       the request came from, therefore listening for ARP packets directed to
       us is not enough. Look inside the ARP reply at the target address field
       instead. The filter string will look like
         arp and arp[18:4] = 0xAABBCCDD and arp[22:2] = 0xEEFF */
    char macstring[2 * ETH_ADDR_LEN + 1];
    const u8 *mac = Targets[0]->SrcMACAddress();
    assert(mac);
    len = Snprintf(macstring, sizeof(macstring), "%02X%02X%02X%02X%02X%02X",
      mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    if (len != sizeof(macstring) - 1)
      fatal("macstring length is %d, should be %u", len, (unsigned)(sizeof(macstring) - 1));
    /* First four bytes of MAC. */
    pcap_filter = "arp and arp[18:4] = 0x";
    pcap_filter.append(macstring, 0, 4 * 2);
    /* Last two bytes. */
    pcap_filter += " and arp[22:2] = 0x";
    pcap_filter.append(macstring, 4 * 2, 2 * 2);
    //its not arp, so lets check if for a protocol scan.
  } else if(USI->prot_scan || (USI->ping_scan && USI->ptech.rawprotoscan)){
    if (doIndividual){
      pcap_filter="dst host ";
      pcap_filter+=inet_ntoa(Targets[0]->v4source());
      pcap_filter+=" and (icmp or (";
      pcap_filter+=dst_hosts;
      pcap_filter+="))";
    }else{
      pcap_filter="dst host ";
      pcap_filter+=inet_ntoa(Targets[0]->v4source());
    }
  } else if(USI->tcp_scan || USI->udp_scan || USI->sctp_scan || USI->ping_scan) {
    /* Handle udp, tcp and sctp with one filter. */
    if (doIndividual){
      pcap_filter="dst host ";
      pcap_filter+=inet_ntoa(Targets[0]->v4source());
      pcap_filter+=" and (icmp or ((tcp or udp or sctp) and (";
      pcap_filter+=dst_hosts;
      pcap_filter+=")))";
    }else{
      pcap_filter="dst host ";
      pcap_filter+=inet_ntoa(Targets[0]->v4source());
      pcap_filter+=" and (icmp or tcp or udp or sctp)";
    }
  }else assert(0);
  if (o.debugging) log_write(LOG_PLAIN, "Packet capture filter (device %s): %s\n", Targets[0]->deviceFullName(), pcap_filter.c_str());
  set_pcap_filter(Targets[0]->deviceFullName(), USI->pd, pcap_filter.c_str());
  /* pcap_setnonblock(USI->pd, 1, NULL); */
  return;
}

/* Go through the data structures, making appropriate changes (such as expiring
   probes, noting when hosts are complete, etc. */
static void processData(UltraScanInfo *USI) {
  list<HostScanStats *>::iterator hostI;
  list<UltraProbe *>::iterator probeI, nextProbeI;
  HostScanStats *host = NULL;
  UltraProbe *probe = NULL;
  unsigned int maxtries = 0;
  bool scanmaybedone = true; /* The whole scan is not yet done */
  int expire_us = 0;

  bool tryno_capped = false, tryno_mayincrease = false;
  struct timeval tv_start = {0};

  gettimeofday(&USI->now, NULL);

  if (o.debugging)
    tv_start = USI->now;

  /* First go through hosts and remove any completed ones from incompleteHosts */
  USI->removeCompletedHosts();
  if (USI->incompleteHostsEmpty())
    return;

  /* Run through probe lists to:
     1) Mark timedout entries as such
     2) Remove long-expired and retransmitted entries
     3) Detect if we are done (we may just have a bunch of probes
        sitting around waiting to see if another round of
        retransmissions will be required).
  */
  for(hostI = USI->incompleteHosts.begin(); 
      hostI != USI->incompleteHosts.end(); hostI++) {
    host = *hostI;
    if (host->num_probes_active != 0 || host->freshPortsLeft() != 0)
      scanmaybedone = false;
    /* Look for timedout or long expired entries */
    maxtries = host->allowedTryno(&tryno_capped, &tryno_mayincrease);

    /* Should we dump everyone off the bench? */
    if (!host->probe_bench.empty()) {
      if (maxtries == host->bench_tryno && !tryno_mayincrease) {
	/* We'll never need to retransmit these suckers!  So they can
	   be treated as done */
	host->dismissBench();	
      } else if (maxtries > host->bench_tryno) {
	// These fellows may be retransmitted now that maxtries has increased
	host->retransmitBench();
      }
    }

    for(probeI = host->probes_outstanding.begin(); 
	probeI != host->probes_outstanding.end(); probeI = nextProbeI) {
      nextProbeI = probeI;
      nextProbeI++;
      probe = *probeI;

      // give up completely after this long
      expire_us = host->probeExpireTime(probe);

      if (!probe->timedout && TIMEVAL_SUBTRACT(USI->now, probe->sent) > 
	  (long) host->probeTimeout()) {
	host->markProbeTimedout(probeI);
	/* Once we've timed out a probe, skip it for this round of processData.
	   We don't want it to move to the bench or anything until the other
	   functions have had a chance to see that it's timed out. In
	   particular, timing out a probe may mean that the tryno can no longer
	   increase, which would make the logic below incorrect. */
	continue;
      }
      
      if (!probe->isPing() && probe->timedout && !probe->retransmitted) {
	if (!tryno_mayincrease && probe->tryno >= maxtries) {
	  if (tryno_capped && !host->retry_capped_warned) {
	    log_write(LOG_PLAIN, "Warning: %s giving up on port because"
              " retransmission cap hit (%d).\n", host->target->targetipstr(),
              probe->tryno);
            host->retry_capped_warned = true;
	  }
	  if (USI->ping_scan) {
	    ultrascan_host_probe_update(USI, host, probeI, HOST_DOWN, NULL);
	    if (host->target->reason.reason_id == ER_UNKNOWN)
	      host->target->reason.reason_id = ER_NORESPONSE;
	  } else {
            /* No ultrascan_port_probe_update because that allocates a Port
               object; the default port state as set by setDefaultPortState
               handles these no-response ports. */
            host->destroyOutstandingProbe(probeI);
          }
	  continue;
	} else if (probe->tryno >= maxtries && 
		   TIMEVAL_SUBTRACT(USI->now, probe->sent) > expire_us) {
	  assert(probe->tryno == maxtries);
	  /* Move it to the bench until it is needed (maxtries
	     increases or is capped */
	  host->moveProbeToBench(probeI);
	  continue;
	}
      }

      if ((probe->isPing() || (probe->timedout && probe->retransmitted)) && 
	  TIMEVAL_SUBTRACT(USI->now, probe->sent) > expire_us) {
	host->destroyOutstandingProbe(probeI);
	continue;
      }
    }
  }

  /* In case any hosts were completed during this run */
  USI->removeCompletedHosts();

  /* Check for expired global pings. */
  HostScanStats *pinghost = USI->gstats->pinghost;
  if (pinghost != NULL) {
    for (probeI = pinghost->probes_outstanding.begin();
         probeI != pinghost->probes_outstanding.end();
         probeI = nextProbeI) {
      nextProbeI = probeI;
      nextProbeI++;
      /* If a global ping probe times out, we want to get rid of it so a new
         host can take its place. */
      if ((*probeI)->isPing()
          && TIMEVAL_SUBTRACT(USI->now, (*probeI)->sent) > (long) pinghost->probeTimeout()) {
        if (o.debugging)
          log_write(LOG_STDOUT, "Destroying timed-out global ping from %s.\n", pinghost->target->targetipstr());
        /* ultrascan_ping_update destroys the probe. */
        ultrascan_ping_update(USI, pinghost, probeI, NULL);
      }
    }
  }

  gettimeofday(&USI->now, NULL);
  if (o.debugging) {
    long tv_diff = TIMEVAL_MSEC_SUBTRACT(USI->now, tv_start);
    if (tv_diff > 30) log_write(LOG_PLAIN, "%s took %lims\n", __func__, tv_diff);
  }
}

/* Start the timeout clocks of any targets that aren't already timedout */
static void startTimeOutClocks(vector<Target *> &Targets) {
  struct timeval tv;
  vector<Target *>::iterator hostI;
  
  gettimeofday(&tv, NULL);
  for(hostI = Targets.begin(); hostI != Targets.end(); hostI++) {
    if (!(*hostI)->timedOut(NULL))
      (*hostI)->startTimeOutClock(&tv);
  }
}

/* 3rd generation Nmap scanning function. Handles most Nmap port scan types.

   The parameter to gives group timing information, and if it is not NULL,
   changed timing information will be stored in it when the function returns. It
   exists so timing can be shared across invocations of this function. If to is
   NULL (its default value), a default timeout_info will be used. */
void ultra_scan(vector<Target *> &Targets, struct scan_lists *ports, 
		stype scantype, struct timeout_info *to) {
  UltraScanInfo *USI = NULL;
  o.current_scantype = scantype;

  init_payloads(); /* Load up _all_ payloads into a mapped table */

  if (Targets.size() == 0) {
    return;
  }

#ifdef WIN32
  if (scantype != CONNECT_SCAN && Targets[0]->ifType() == devt_loopback) {
    log_write(LOG_STDOUT, "Skipping %s against %s because Windows does not support scanning your own machine (localhost) this way.\n", scantype2str(scantype), Targets[0]->NameIP());
    return;
  }
#endif

  // Set the variable for status printing
  o.numhosts_scanning = Targets.size();

  startTimeOutClocks(Targets);
  USI = new UltraScanInfo(Targets, ports, scantype);

  /* Use the requested timeouts. */
  if (to != NULL)
    USI->gstats->to = *to;

  if (o.verbose) {
    char targetstr[128];
    bool plural = (Targets.size() != 1);
    if (!plural) {
      (*(Targets.begin()))->NameIP(targetstr, sizeof(targetstr));
    } else Snprintf(targetstr, sizeof(targetstr), "%d hosts", (int) Targets.size());
    log_write(LOG_STDOUT, "Scanning %s [%d port%s%s]\n", targetstr, USI->gstats->numprobes, (USI->gstats->numprobes != 1)? "s" : "", plural? "/host" : "");
  }

  begin_sniffer(USI, Targets);
  while(!USI->incompleteHostsEmpty()) {
    doAnyPings(USI);
    doAnyOutstandingRetransmits(USI); // Retransmits from probes_outstanding
    /* Retransmits from retry_stack -- goes after OutstandingRetransmits for
       memory consumption reasons */
    doAnyRetryStackRetransmits(USI);
    doAnyNewProbes(USI);
    gettimeofday(&USI->now, NULL);
    // printf("TRACE: Finished doAnyNewProbes() at %.4fs\n", o.TimeSinceStartMS(&USI->now) / 1000.0);
    printAnyStats(USI);
    waitForResponses(USI);
    gettimeofday(&USI->now, NULL);
    // printf("TRACE: Finished waitForResponses() at %.4fs\n", o.TimeSinceStartMS(&USI->now) / 1000.0);
    processData(USI);

    if (keyWasPressed()) {
       // This prints something like
       // SYN Stealth Scan Timing: About 1.14% done; ETC: 15:01 (0:43:23 remaining);
       USI->SPM->printStats(USI->getCompletionFraction(), NULL);
       if (o.debugging) {
         /* Don't update when getting the current rates, otherwise we can get
            anomalies (rates are too low) from having just done a potentially
            long waitForResponses without sending any packets. */
         USI->log_current_rates(LOG_STDOUT, false);
       }
       
       log_flush(LOG_STDOUT);
    }
  }

  USI->send_rate_meter.stop(&USI->now);

  /* Save the computed timeouts. */
  if (to != NULL)
    *to = USI->gstats->to;

  if (o.verbose) {
    char additional_info[128];
    if (USI->gstats->num_hosts_timedout == 0)
      if (USI->ping_scan) {
        Snprintf(additional_info, sizeof(additional_info), "%lu total hosts",
                  (unsigned long) Targets.size());
      } else {
        Snprintf(additional_info, sizeof(additional_info), "%lu total ports",
                  (unsigned long) USI->gstats->numprobes * Targets.size());
      }
    else Snprintf(additional_info, sizeof(additional_info), "%d %s timed out",
		   USI->gstats->num_hosts_timedout, 
		   (USI->gstats->num_hosts_timedout == 1)? "host" : "hosts");
    USI->SPM->endTask(NULL, additional_info);
  }
  if (o.debugging)
    USI->log_overall_rates(LOG_STDOUT);

  if (o.debugging > 2 && USI->pd != NULL)
    pcap_print_stats(LOG_PLAIN, USI->pd);

  delete USI;
  USI = NULL;
}

/* FTP bounce attack scan.  This function is rather lame and should be
   rewritten.  But I don't think it is used much anyway.  If I'm going to
   allow FTP bounce scan, I should really allow SOCKS proxy scan.  */
void bounce_scan(Target *target, u16 *portarray, int numports,
		 struct ftpinfo *ftp) {
   o.current_scantype = BOUNCE_SCAN;

  time_t starttime;
  int res , sd = ftp->sd,  i=0;
  const char *t = (const char *)target->v4hostip(); 
  int retriesleft = FTP_RETRIES;
  char recvbuf[2048]; 
  char targetstr[20];
  char command[512];
  char hostname[1200];
  unsigned short portno,p1,p2;
  int timedout;

  if (! numports) return;		 /* nothing to scan for */

  Snprintf(targetstr, 20, "%d,%d,%d,%d,", UC(t[0]), UC(t[1]), UC(t[2]), UC(t[3]));

  starttime = time(NULL);
  if (o.verbose || o.debugging) {
    struct tm *tm = localtime(&starttime);
    assert(tm);
    log_write(LOG_STDOUT, "Initiating TCP FTP bounce scan against %s at %02d:%02d\n", target->NameIP(hostname, sizeof(hostname)), tm->tm_hour, tm->tm_min );
  }
  for(i=0; i < numports; i++) {

    /* Check for timeout */
    if (target->timedOut(NULL))
      return;

    portno = htons(portarray[i]);
    p1 = ((unsigned char *) &portno)[0];
    p2 = ((unsigned char *) &portno)[1];
    Snprintf(command, 512, "PORT %s%i,%i\r\n", targetstr, p1,p2);
    if (o.debugging) log_write(LOG_STDOUT, "Attempting command: %s", command);
    if (send(sd, command, strlen(command), 0) < 0 ) {
      gh_perror("send in %s", __func__);
      if (retriesleft) {
	if (o.verbose || o.debugging) 
	  log_write(LOG_STDOUT, "Our FTP proxy server hung up on us!  retrying\n");
	retriesleft--;
	close(sd);
	ftp->sd = ftp_anon_connect(ftp);
	if (ftp->sd < 0) return;
	sd = ftp->sd;
	i--;
      }
      else {
	error("Our socket descriptor is dead and we are out of retries. Giving up.");
	close(sd);
	ftp->sd = -1;
	return;
      }
    } else { /* Our send is good */
      res = recvtime(sd, recvbuf, 2048, 15, NULL);
      if (res <= 0) 
	perror("recv problem from FTP bounce server");
  
      else { /* our recv is good */
	recvbuf[res] = '\0';
	if (o.debugging) log_write(LOG_STDOUT, "result of port query on port %i: %s", 
				 portarray[i],  recvbuf);
	if (recvbuf[0] == '5') {
	  if (portarray[i] > 1023) {
	    fatal("Your FTP bounce server sucks, it won't let us feed bogus ports!");
	  }
	  else {
	    error("Your FTP bounce server doesn't allow privileged ports, skipping them.");
	    while(i < numports && portarray[i] < 1024) i++;
	    if (!portarray[i]) {
	      fatal("And you didn't want to scan any unpriviliged ports.  Giving up.");
	    }
	  }  
	}
	else  /* Not an error message */
	  if (send(sd, "LIST\r\n", 6, 0) > 0 ) {
	    res = recvtime(sd, recvbuf, 2048,12, &timedout);
	    if (res < 0) {
	      perror("recv problem from FTP bounce server");
	    } else if (res == 0) {
	      if (timedout)
		target->ports.setPortState(portarray[i], IPPROTO_TCP, PORT_FILTERED);
	      else target->ports.setPortState(portarray[i], IPPROTO_TCP, PORT_CLOSED);
	    } else {
	      recvbuf[res] = '\0';
	      if (o.debugging) log_write(LOG_STDOUT, "result of LIST: %s", recvbuf);
	      if (!strncmp(recvbuf, "500", 3)) {
		/* fuck, we are not aligned properly */
		if (o.verbose || o.debugging)
		  error("FTP command misalignment detected ... correcting.");
		res = recvtime(sd, recvbuf, 2048,10, NULL);
	      }
	      if (recvbuf[0] == '1' || recvbuf[0] == '2') {
		target->ports.setPortState(portarray[i], IPPROTO_TCP, PORT_OPEN);
		if (recvbuf[0] == '1') {
		  res = recvtime(sd, recvbuf, 2048,5, NULL);
		  if (res < 0)
		    perror("recv problem from FTP bounce server");
		  else {
		    recvbuf[res] = '\0';
		    if (res > 0) {
		      if (o.debugging) log_write(LOG_STDOUT, "nxt line: %s", recvbuf);
		      if (recvbuf[0] == '4' && recvbuf[1] == '2' && 
			  recvbuf[2] == '6') {	      	
		        target->ports.forgetPort(portarray[i], IPPROTO_TCP);
		        if (o.debugging || o.verbose)
			  log_write(LOG_STDOUT, "Changed my mind about port %i\n", portarray[i]);
		      }
		    }
		  }
		}
	      } else {
		/* This means the port is closed ... */
		target->ports.setPortState(portarray[i], IPPROTO_TCP, PORT_CLOSED);
	      }
	    }
	  }
      }
    }
  }

  if (o.debugging || o.verbose) 
    log_write(LOG_STDOUT, "Scanned %d ports in %ld seconds via the Bounce scan.\n",
	    numports, (long) time(NULL) - starttime);
  return;
}

/* I want to reverse the order of all PORT_TESTING entries in
   the scan list -- this way if an intermediate router along the
   way got overloaded and dropped the last X packets, they are
   likely to get through (and flag us a problem if responsive)
   if we let them go first in the next round */
static void reverse_testing_order(struct portinfolist *pil, struct portinfo *scanarray) {
  int currentidx, nextidx;
  struct portinfo *current;

  current = pil->testinglist;

  if (current == NULL || current->state != PORT_TESTING)
    return;

  while(1) {
    nextidx = current->next;
    currentidx = current - scanarray;
    /* current->state is always PORT_TESTING here */
    current->next = current->prev; // special case 1st node dealt w/later
    current->prev = nextidx; // special last TESTING node case dealt w/later
    if (nextidx == -1) {
      // Every node was in TESTING state
      current->prev = -1; // New head of list
      pil->testinglist->next = -1;
      pil->testinglist = current;
      break;
    } else if (scanarray[nextidx].state != PORT_TESTING) {
      current->prev = -1; // New head of list
      pil->testinglist->next = nextidx;
      scanarray[nextidx].prev = pil->testinglist - scanarray;
      pil->testinglist = current;
      break;
    }
    current = scanarray + nextidx;
  }
}


/* Used to handle all the "positive-response" scans (where we get a
   response telling us that the port is open based on the probe.  This
   includes SYN Scan, Connect Scan, RPC scan, Window Scan, and ACK
   scan.  Now ultra_scan() does all of those, except for RPC scan,
   which is the only pos_scan now supported.  */
void pos_scan(Target *target, u16 *portarray, int numports, stype scantype) {
   o.current_scantype = scantype;

  struct scanstats ss;
  int senddelay = 0;
  int rpcportsscanned = 0;
  time_t starttime;
  struct timeval starttm;
  struct portinfo *scan = NULL,  *current, *next;
  struct portinfolist pil;
  struct timeval now;
  struct rpcscaninfo rsi;
  unsigned long j;
  struct serviceDeductions sd;
  bool doingOpenFiltered = false;
  Port port;

  ScanProgressMeter *SPM = NULL;

  if (target->timedOut(NULL))
    return;

  if (scantype != RPC_SCAN)
    fatal("%s now handles only rpc scan", __func__);

  if (target->ports.getStateCounts(PORT_OPEN) == 0 && 
      (o.servicescan || target->ports.getStateCounts(PORT_OPENFILTERED) == 0))
    return; // RPC Scan only works against already known-open ports

  if (o.debugging)
    log_write(LOG_STDOUT, "Starting RPC scan against %s\n", target->NameIP());

  gettimeofday(&starttm, NULL);
  target->startTimeOutClock(&starttm);

  ss.packet_incr = 4;
  ss.initial_packet_width = (scantype == RPC_SCAN)? 2 : 30;
  ss.fallback_percent = 0.7;
  ss.numqueries_outstanding = 0;
  ss.ports_left = numports;
  ss.alreadydecreasedqueries = 0;

  memset(&pil, 0, sizeof(pil));

  if (o.max_parallelism) {
    ss.max_width = o.max_parallelism;
  } else {
      ss.max_width = 150;
  }

  if (o.min_parallelism) {
    ss.min_width = o.min_parallelism;
  } else ss.min_width = 1;

  ss.initial_packet_width = box(ss.min_width, ss.max_width, ss.initial_packet_width);
  ss.numqueries_ideal = ss.initial_packet_width;

  get_rpc_procs(&(rsi.rpc_progs), &(rsi.rpc_number));
  scan = (struct portinfo *) safe_malloc(rsi.rpc_number * sizeof(struct portinfo));
  for(j = 0; j < rsi.rpc_number; j++) {
    scan[j].state = PORT_FRESH;
    scan[j].portno = rsi.rpc_progs[j];
    scan[j].trynum = 0;
    scan[j].prev = j-1;
    scan[j].sd[0] = scan[j].sd[1] = scan[j].sd[2] = -1;
    if (j < rsi.rpc_number -1 ) scan[j].next = j+1;
    else scan[j].next = -1;
  }
  current = pil.testinglist = &scan[0]; 
  rsi.rpc_current_port = NULL; 

  starttime = time(NULL);

  do {
    ss.changed = 0;

    if (senddelay > 200000) {
      ss.max_width = MIN(ss.max_width, 5);
      ss.numqueries_ideal = MIN(ss.max_width, ss.numqueries_ideal);
    }

    if (target->timedOut(NULL))
      goto posscan_timedout;

    /* Make sure we have ports left to scan */
    while(1) {
      if (doingOpenFiltered) {
	rsi.rpc_current_port = target->ports.nextPort(rsi.rpc_current_port,
						      &port, TCPANDUDPANDSCTP,
						      PORT_OPENFILTERED);
      } else {
	rsi.rpc_current_port = target->ports.nextPort(rsi.rpc_current_port,
						      &port, TCPANDUDPANDSCTP,
						      PORT_OPEN);
	if (!rsi.rpc_current_port && !o.servicescan) {
	  doingOpenFiltered = true;
	  continue;
	}
      }
      // When service scan is in use, we only want to scan ports that have already
      // been determined to be RPC
      
      if (!rsi.rpc_current_port) 
	break; // done!
      target->ports.getServiceDeductions(rsi.rpc_current_port->portno, rsi.rpc_current_port->proto, &sd);
      if (sd.name && sd.service_tunnel == SERVICE_TUNNEL_NONE && 
	  strcmp(sd.name, "rpcbind") == 0)
	break; // Good - an RPC port for us to scan.
    }
    
    if (!rsi.rpc_current_port) /* Woop!  Done! */ break;
    
    /* Reinit our testinglist so we try each RPC prog */
    pil.testinglist = &scan[0];
    rsi.valid_responses_this_port = 0;
    rsi.rpc_status = RPC_STATUS_UNKNOWN;
    rpcportsscanned++;
  

    // This initial message is way down here because we don't want to print it if
    // no RPC ports need scanning.
    if (!SPM) {
      char scanname[48];
      Snprintf(scanname, sizeof(scanname), "%s against %s", scantype2str(scantype), target->NameIP());
      scanname[sizeof(scanname) - 1] = '\0';
      SPM = new ScanProgressMeter(scanname);
    }
    
    while(pil.testinglist != NULL)  /* While we have live queries or more ports to scan */
      {
         
         if (keyWasPressed()) {
            // We can print out some status here if we want
         }

	/* Check the possible retransmissions first */
	gettimeofday(&now, NULL);
      
	/* Insure we haven't overrun our allotted time ... */
	if (target->timedOut(&now))
	  goto posscan_timedout;

	for( current = pil.testinglist; current ; current = next) {
	  /* For each port or RPC program */
	  next = (current->next > -1)? &scan[current->next] : NULL;
	  if (current->state == PORT_TESTING) {
	    if ( TIMEVAL_SUBTRACT(now, current->sent[current->trynum]) > target->to.timeout) {
	      if (current->trynum > 1) {
		/* No responses !#$!#@$ firewalled? */

		if (rsi.valid_responses_this_port == 0) {	       
		  if (o.debugging) {
		    log_write(LOG_STDOUT, "RPC Scan giving up on port %hu proto %d due to repeated lack of response\n", rsi.rpc_current_port->portno,  rsi.rpc_current_port->proto);
		  }
		  rsi.rpc_status = RPC_STATUS_NOT_RPC;
		  ss.numqueries_outstanding = 0;
		  break;
		}
		else {
		  /* I think I am going to slow down a little */
		  target->to.rttvar = MIN(2000000, (int) (target->to.rttvar * 1.2));
		}	      
		
		if (o.debugging > 2) { log_write(LOG_STDOUT, "Moving port or prog %lu to the potentially firewalled list\n", (unsigned long) current->portno); }
		current->state = PORT_FILTERED; /* For various reasons */
		/* First delete from old list */
		if (current->next > -1) scan[current->next].prev = current->prev;
		if (current->prev > -1) scan[current->prev].next = current->next;
		if (current == pil.testinglist)
		  pil.testinglist = (current->next >= 0)?  &scan[current->next] : NULL;
		current->next = -1;
		current->prev = -1;
		/* Now move into new list */

		ss.numqueries_outstanding--;
	      } else {  /* timeout ... we've got to resend */
		if (o.scan_delay) enforce_scan_delay(NULL);
		if (o.debugging > 2) { log_write(LOG_STDOUT, "Timeout, resending to portno/progno %lu\n", current->portno); }
		current->trynum++;
		gettimeofday(&current->sent[current->trynum], NULL);
		now = current->sent[current->trynum];
		if (send_rpc_query(target, rsi.rpc_current_port->portno,
				   rsi.rpc_current_port->proto, 
				   current->portno, current - scan, 
				   current->trynum) == -1) {
		  /* Futz, I'll give up on this guy ... */
		  rsi.rpc_status = RPC_STATUS_NOT_RPC;
		  break;
		}

		if (senddelay) usleep(senddelay);
	      }
	    }
	  } else { 
	    if (current->state != PORT_FRESH) 
	      fatal("State mismatch!!@ %d", current->state);
	    /* current->state == PORT_FRESH */
	    /* OK, now we have gone through our list of in-transit queries, so now
	       we try to send off new queries if we can ... */
	    if (ss.numqueries_outstanding >= (int) ss.numqueries_ideal) break;
	    if (o.scan_delay) enforce_scan_delay(NULL);
	    if (o.debugging > 2) 
	      log_write(LOG_STDOUT, "Sending initial query to port/prog %lu\n", current->portno);
	    /* Otherwise lets send a packet! */
	    current->state = PORT_TESTING;
	    current->trynum = 0;
	    /*	if (!testinglist) testinglist = current; */
	    ss.numqueries_outstanding++;
	    gettimeofday(&current->sent[0], NULL);
	    if (send_rpc_query(target, 
			       rsi.rpc_current_port->portno,
			       rsi.rpc_current_port->proto, current->portno,
			       current - scan, current->trynum) == -1) {
	      /* Futz, I'll give up on this guy ... */
	      rsi.rpc_status = RPC_STATUS_NOT_RPC;
	      break;
	    }
	    if (senddelay) usleep(senddelay);
	  }
	}
	if (o.debugging > 1) log_write(LOG_STDOUT, "Ideal number of queries: %d outstanding: %d max %d ports_left %d timeout %d senddelay: %dus\n", (int) ss.numqueries_ideal, ss.numqueries_outstanding, ss.max_width, ss.ports_left, target->to.timeout, senddelay);

	/* Now that we have sent the packets we wait for responses */
	ss.alreadydecreasedqueries = 0;
	/* We only bother worrying about responses if we haven't reached
	   a conclusion yet */
	if (rsi.rpc_status == RPC_STATUS_UNKNOWN) {	  
	  get_rpc_results(target, scan, &ss, &pil, &rsi);
	}
	if (rsi.rpc_status != RPC_STATUS_UNKNOWN)
	  break;

	/* I want to reverse the order of all PORT_TESTING entries in
           the list -- this way if an intermediate router along the
           way got overloaded and dropped the last X packets, they are
           likely to get through (and flag us a problem if responsive)
           if we let them go first in the next round */
	reverse_testing_order(&pil, scan);

	/* If we timed out while trying to get results -- we're outta here! */
	if (target->timedOut(NULL))
	  goto posscan_timedout;
      }

    /* Now we figure out the results of the port we just RPC scanned */
    
    target->ports.setRPCProbeResults(rsi.rpc_current_port->portno, rsi.rpc_current_port->proto,
                                             rsi.rpc_status, rsi.rpc_program, 
					     rsi.rpc_lowver, rsi.rpc_highver);
    
    /* Time to put our RPC program scan list back together for the
       next port ... */
    for(j = 0; j < rsi.rpc_number; j++) {
      scan[j].state = PORT_FRESH;
      scan[j].trynum = 0;
      scan[j].prev = j-1;
      if (j < rsi.rpc_number -1 ) scan[j].next = j+1;
      else scan[j].next = -1;
    }
    current = pil.testinglist = &scan[0]; 
    pil.firewalled = NULL;

    if (o.debugging) {
      log_write(LOG_STDOUT, "Finished round. Current stats: numqueries_ideal: %d; min_width: %d; max_width: %d; packet_incr: %d; senddelay: %dus; fallback: %.f%%\n", (int) ss.numqueries_ideal, ss.min_width, ss.max_width, ss.packet_incr, senddelay, floor(100 * ss.fallback_percent));
    }
    ss.numqueries_ideal = ss.initial_packet_width;
  } while(pil.testinglist);
  
  numports = rpcportsscanned;
  if (SPM && o.verbose && (numports > 0)) {
    char scannedportsstr[14];
    Snprintf(scannedportsstr, sizeof(scannedportsstr), "%d %s", numports, (numports > 1)? "ports" : "port");
    SPM->endTask(NULL, scannedportsstr);
  }
 posscan_timedout:
  target->stopTimeOutClock(NULL);
  free(scan);
  close_rpc_query_sockets();
  if (SPM) {
    delete SPM;
    SPM = NULL;
  }
  return;
}
