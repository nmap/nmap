
/***************************************************************************
 * scanengine.cc -- Includes much of the "engine" functions for scanning,  *
 * such as pos_scan and ultra_scan.  It also includes dependant functions  *
 * such as those for collectiong SYN/connect scan responses.               *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2006 Insecure.Com LLC. Nmap is    *
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
 * http://insecure.org/nmap/ to download Nmap.                             *
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

#ifdef WIN32
#include "nmap_winconfig.h"
#endif

#include <dnet.h>

#include "scan_engine.h"
#include "timing.h"
#include "NmapOps.h"
#include "nmap_tty.h"
#include <list>


using namespace std;
extern NmapOps o;
class UltraScanInfo;

struct ultra_scan_performance_vars {
  int low_cwnd;  /* The lowest cwnd (congestion window) allowed */
  int host_initial_cwnd; /* Initial congestion window for ind. hosts */
  int group_initial_cwnd; /* Initial congestion window for all hosts as a group */
  int max_cwnd; /* I should never have more than this many probes
		   outstanding */
  int quick_incr; /* How many probes are incremented for each response
		     in quick start mode */
  int cc_incr; /* How many probes are incremented per (roughly) rtt in 
		  congestion control mode */
  int initial_ccthresh;
  /* When a successful ping response comes back, it counts as this many
     "normal" responses, because the fact that pings are neccessary means
     we aren't getting much input. */
  int ping_magnifier;
/* Try to send a scanping if no response has been received from a target host
   in this many usecs */
  int pingtime; 
  double group_drop_cwnd_divisor; /* all-host group cwnd divided by this
				     value if any packet drop occurs */
  double group_drop_ccthresh_divisor; /* used to drop the group ccthresh when
					 any drop occurs */
  double host_drop_ccthresh_divisor; /* used to drop the host ccthresh when
					 any drop occurs */
  int tryno_cap; /* The maximum trynumber (starts at zero) allowed */
};

/* Some of the algorithms used here are TCP congestion control
   techniques from RFC2581. */
struct ultra_timing_vals {
  double cwnd; /* Congestion window - in probes */
  int ccthresh; /* The threshold after which mode is changed from QUICK_START
		   to CONGESTION_CONTROL */
  int num_updates; /* Number of updates to this utv (generally packet receipts ) */
  /* Last time values were adjusted for a drop (you usually only want
     to adjust again based on probes sent after that adjustment so a
     sudden batch of drops doesn't destroy timing.  Init to now */
  struct timeval last_drop; 
};

struct probespec_tcpdata {
  u16 dport;
  u8 flags;
};

struct probespec_udpdata {
  u16 dport;
};


#define PS_NONE 0
#define PS_TCP 1
#define PS_UDP 2
#define PS_PROTO 3
#define PS_ICMP 4
#define PS_ARP 5

static const char *pspectype2ascii(int type) {
  switch(type) {
  case PS_NONE:
    return "NONE";
  case PS_TCP:
    return "TCP";
  case PS_UDP:
    return "UDP";
  case PS_PROTO:
    return "IP Proto";
  case PS_ICMP:
    return "ICMP";
  case PS_ARP:
    return "ARP";
  default:
    fatal("%s: Unknown type: %d", __FUNCTION__, type);
  }
  return ""; // Unreached
}

/* The size of this structure is critical, since there can be tens of
   thousands of them stored together ... */
typedef struct probespec {
  /* To save space, I changed this from private enum (took 4 bytes) to
     u8 that uses #defines above */
  u8 type;
  u8 proto; /* If not PS_ARP -- Protocol number ... eg IPPROTO_TCP, etc. */
  union {
    struct probespec_tcpdata tcp; /* if type is PS_TCP */
    struct probespec_udpdata udp; /* PS_UDP */
    
    /* Commented out for now, but will likely contan icmp type, maybe
       code, used for PS_ICMP */
    // struct probespec_icmpdata icmp;

    /* Nothing needed for PS_ARP, since src mac and target IP are
       avail from target structure anyway */
  } pd;
} probespec;

class ConnectProbe {
public:
  ConnectProbe();
  ~ConnectProbe();
  int sd; /* Socket descriptor used for connection.  -1 if not valid. */
private:
};

struct IPExtraProbeData_tcp {
  u16 sport;
  u32 seq; /* host byte order (like the other fields */
};

struct IPExtraProbeData_udp {
  u16 sport;
};

struct IPExtraProbeData {
  u16 ipid; /* host byte order */
  union {
    struct IPExtraProbeData_tcp tcp;
    struct IPExtraProbeData_udp udp;
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
// source port used if TCP or UDP
  u16 sport() {
    return (mypspec.proto == IPPROTO_TCP)? probes.IP.pd.tcp.sport : probes.IP.pd.udp.sport; }
  // destination port used if TCP or UDP
  u16 dport() { 
    return (mypspec.proto == IPPROTO_TCP)? mypspec.pd.tcp.dport : mypspec.pd.udp.dport; }
  u16 ipid() { return probes.IP.ipid; }
  u32 tcpseq(); // TCP sequence number if protocol is TCP
  /* Number, such as IPPROTO_TCP, IPPROTO_UDP, etc. */
  u8 protocol() { return mypspec.proto; }
  ConnectProbe *CP() { return probes.CP; } // if type == UP_CONNECT
  // Arpprobe removed because not used.
  //  ArpProbe *AP() { return probes.AP; } // if UP_ARP
  // Returns the protocol number, such as IPPROTO_TCP, or IPPROTO_UDP, by 
  // reading the appropriate fields of the probespec.

/* Get general details about the probe */
  const probespec *pspec() { return &mypspec; }
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
  void *internalProbe;
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
private:
};

/* These are ultra_scan() statistics for the whole group of Targets */
class GroupScanStats {
public:
  struct timeval timeout; /* The time at which we abort the scan */
  /* Most recent host tested for sendability */
  struct sockaddr_storage latestip; 
  GroupScanStats(UltraScanInfo *UltraSI);
  ~GroupScanStats();
  /* Returns true if the GLOBAL system says that sending is OK. */
  bool sendOK(); 
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
  struct timeval last_wait; 
  int probes_sent_at_last_wait;
  // number of hosts that timed out during scan, or were already timedout
  int num_hosts_timedout;
  ConnectScanInfo *CSI;
private:
};

struct send_delay_nfo {
  unsigned int delayms; /* Milliseconds to delay between probes */
  /* The number of successful and dropped probes since the last time delayms
     was changed */
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
  /* How long I am currently willing to wait for a probe response
     before considering it timed out.  Uses the host values from
     target if they are available, otherwise from gstats.  Results
     returned in MICROseconds.  */
  unsigned long probeTimeout();

  /* How long I'll wait until completely giving up on a probe.
     Timedout probes are often marked as such (and sometimes
     considered a drop), but kept in the list juts in case they come
     really late.  But after probeExpire(), I don't waste time keeping
     them around. Give in MICROseconds */
  unsigned long probeExpire();
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
     neccessary.  Note that probes on probe_bench are not included
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

  /* This function provides the proper cwnd and ccthresh to use.  It
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
  /* A valid probe for sending scanpings. */
  probespec pingprobe;
  int pingprobestate; /* PORT_UNKNOWN if no pingprobe yet found */
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
  int numpings_sent;
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

  /* Consults with the group stats, and the hstats for every
     incomplete hosts to determine whether any probes may be sent.
     Returns true if they can be sent immediately.  If when is non-NULL,
     it is filled with the next possible time that probes can be sent
     (which will be now, if the function returns true */
  bool sendOK(struct timeval *tv);
  stype scantype;
  bool tcp_scan; /* scantype is a type of TCP scan */
  bool udp_scan;
  bool icmp_scan;
  bool prot_scan;
  bool ping_scan; /* Includes trad. ping scan & arp scan */
  bool ping_scan_arp; /* ONLY includes arp ping scan */
  bool noresp_open_scan; /* Whether no response means a port is open */
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
     list.  Returns the number of hosts removed. */
  int removeCompletedHosts();
  /* Find a HostScanStats by IP its address in the incomplete list.
     Returns NULL if none are found. */
  HostScanStats *findIncompleteHost(struct sockaddr_storage *ss);

  unsigned int numIncompleteHosts() { return incompleteHosts.size(); }
  unsigned int numInitialHosts() { return numInitialTargets; }
  /* Any function which messes with (removes elements from)
     incompleteHosts may have to manipulate nextI */
  list<HostScanStats *> incompleteHosts;

  ScanProgressMeter *SPM;
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

/* Take a buffer, buf, of size bufsz (32 bytes is sufficient) and 
   writes a short description of the probe (arg1) into buf.  It also returns 
   buf. */
static char *probespec2ascii(probespec *pspec, char *buf, unsigned int bufsz) {
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
    snprintf(buf, bufsz, "tcp to port %hu; flags: %s", pspec->pd.tcp.dport, 
	     flagbuf);
    break;
  case PS_UDP:
    snprintf(buf, bufsz, "udp to port %hu", pspec->pd.udp.dport);
    break;
  case PS_PROTO:
    snprintf(buf, bufsz, "protocol %u", (unsigned int) pspec->proto);
    break;
  case PS_ARP:
    snprintf(buf, bufsz, "ARP");
    break;
  default:
    fatal("Unexpected probespec2ascii type encountered");
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

  type = UP_IP;
  if (ipv4->ip_v != 4)
    fatal("Bogus packet passed to %s -- only IPv4 packets allowed", 
	  __FUNCTION__);
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
  }

  mypspec = *pspec;
  return;
}

u32 UltraProbe::tcpseq() {
  if (mypspec.proto == IPPROTO_TCP)
    return probes.IP.pd.tcp.seq;
  else
    fatal("Bogus seq number request to %s -- type is %s", __FUNCTION__, 
	  pspectype2ascii(mypspec.type));

  return 0; // Unreached
}

/* Sets this UltraProbe as type UP_CONNECT, preparing to connect to given
   port number*/
void UltraProbe::setConnect(u16 portno) {
  type = UP_CONNECT;
  probes.CP = new ConnectProbe();
  mypspec.type = PS_TCP;
  mypspec.proto = IPPROTO_TCP;
  mypspec.pd.tcp.dport = portno;
  mypspec.pd.tcp.flags = TH_SYN;
}

ConnectScanInfo::ConnectScanInfo() {
  maxValidSD = -1;
  numSDs = 0;
  maxSocketsAllowed = (o.max_parallelism)? o.max_parallelism : MAX(5, max_sd() - 4);
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
    to.timeout = MIN(o.initialRttTimeout(), 100) * 1000;
  num_probes_active = 0;
  numtargets = USI->numIncompleteHosts(); // They are all incomplete at the beginning
  if (USI->tcp_scan) {
    numprobes = USI->ports->tcp_count;
  } else if (USI->udp_scan) {
    numprobes = USI->ports->udp_count;
  } else if (USI->prot_scan) {
    numprobes = USI->ports->prot_count;
  } else if (USI->ping_scan_arp) {
    numprobes = 1;
  } else assert(0); /* TODO: RPC scan and maybe ping */
  
  if (USI->scantype == CONNECT_SCAN)
    CSI = new ConnectScanInfo;
  else CSI = NULL;
  probes_sent = probes_sent_at_last_wait = 0;
  gettimeofday(&last_wait, NULL);
  num_hosts_timedout = 0;
}

GroupScanStats::~GroupScanStats() {
  delete CSI;
}

  /* Returns true if the GLOBAL system says that sending is OK.*/
bool GroupScanStats::sendOK() {
  int recentsends;

  if (USI->scantype == CONNECT_SCAN && CSI->numSDs >= CSI->maxSocketsAllowed)
    return false;

  /* We need to stop sending if it has been a long time since
     the last listen call, at least for systems such as Windoze that
     don't give us a proper pcap time.  Also for connect scans, since
     we don't get an exact response time with them either. */
  recentsends = USI->gstats->probes_sent - USI->gstats->probes_sent_at_last_wait;
  if (recentsends > 0 && 
      (USI->scantype == CONNECT_SCAN || !pcap_recv_timeval_valid())) {
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

  /* When there is only one target left, let the host congestion
     stuff deal with it. */
  if (USI->numIncompleteHosts() == 1)
    return true;

  if (timing.cwnd >= num_probes_active + 0.5)
    return true;

  return false;
}

/* For the given scan type, this returns the port/host state demonstrated
   by getting no response back */
static int scantype_no_response_means(stype scantype) {
  switch(scantype) {
  case SYN_SCAN:
  case ACK_SCAN:
  case WINDOW_SCAN:
  case CONNECT_SCAN:
    return PORT_FILTERED;
  case UDP_SCAN:
  case IPPROT_SCAN:
  case NULL_SCAN:
  case FIN_SCAN:
  case MAIMON_SCAN:
  case XMAS_SCAN:
    return PORT_OPENFILTERED;
  case PING_SCAN_ARP:
    return HOST_DOWN;
  default:
    fatal("Unexpected scan type found in scantype_no_response_means()");
  }
  return 0; /* Unreached */
}

HostScanStats::HostScanStats(Target *t, UltraScanInfo *UltraSI) { 
  target = t; 
  USI=UltraSI; 
  next_portidx = 0; 
  sent_arp = false;
  num_probes_active = 0; 
  num_probes_waiting_retransmit = 0;
  lastping_sent = lastprobe_sent = lastrcvd = USI->now;
  lastping_sent_numprobes = 0;
  memset(&pingprobe, 0, sizeof(pingprobe));
  pingprobestate = PORT_UNKNOWN;
  nxtpseq = 1;
  max_successful_tryno = 0;
  tryno_mayincrease = true;
  ports_finished = 0;
  numprobes_sent = 0;
  numpings_sent = 0;
  init_ultra_timing_vals(&timing, TIMING_HOST, 1, &(USI->perf), &USI->now);
  bench_tryno = 0;
  memset(&sdn, 0, sizeof(sdn));
  sdn.last_boost = USI->now;
  sdn.delayms = o.scan_delay;
  rld.max_tryno_sent = 0;
  rld.rld_waiting = false;
  rld.rld_waittime = USI->now;
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
     really late.  But after probeExpire(), I don't waste time keeping
     them around. Give in MICROseconds */
unsigned long HostScanStats::probeExpire() {
  if (USI->scantype == CONNECT_SCAN)
    return probeTimeout(); /* timedout probes close socket -- late resp. impossible */
  return MIN(10000000, probeTimeout() * 10);
}

/* Returns OK if sending a new probe to this host is OK (to avoid
   flooding). If when is non-NULL, fills it with the time that sending
   will be OK assuming no pending probes are resolved by responses
   (call it again if they do).  when will become now if it returns
   true. */
bool HostScanStats::sendOK(struct timeval *when) {
  struct ultra_timing_vals tmng;
  int packTime;
  list<UltraProbe *>::iterator probeI;
  struct timeval probe_to, earliest_to, sendTime;
  long tdiff;

  if (target->timedOut(&USI->now) || completed()) {
    if (when) *when = USI->now;
    return false;
  }

  if (rld.rld_waiting) {
    packTime = TIMEVAL_MSEC_SUBTRACT(rld.rld_waittime, USI->now);
    if (packTime <= 0) {
      if (when) *when = USI->now;
      return true;
    }
    if (when) *when = rld.rld_waittime;
    return false;
  }

  if (sdn.delayms) {
    packTime = TIMEVAL_MSEC_SUBTRACT(USI->now, lastprobe_sent);
    if (packTime < (int) sdn.delayms) {
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
    if (TIMEVAL_MSEC_SUBTRACT(sendTime, USI->now) < 0)
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
       retransmits are neccessary. */
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
  delete gstats;
  delete SPM;
  if (rawsd >= 0) { close(rawsd); rawsd = -1; }
  if (pd) { pcap_close(pd); pd = NULL; }
  if (ethsd) { ethsd = NULL; /* NO need to eth_close it due to caching */ }
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
  perf->quick_incr = 1;
  perf->cc_incr = 1;
  perf->initial_ccthresh = 50;
  perf->ping_magnifier = 3;
  perf->pingtime = 5000000;
  perf->group_drop_cwnd_divisor = 2.0;
  perf->group_drop_ccthresh_divisor = (o.timing_level < 4)? 2.0 : 1.5;
  perf->host_drop_ccthresh_divisor = (o.timing_level < 4)? 2.0 : 1.5;
  perf->tryno_cap = o.getMaxRetransmissions();
}

/* Order of initializations in this function CAN BE IMPORTANT, so be careful
 mucking with it. */
void UltraScanInfo::Init(vector<Target *> &Targets, struct scan_lists *pts, stype scantp) {
  unsigned int targetno = 0;
  HostScanStats *hss;
  int num_timedout = 0;

  gettimeofday(&now, NULL);
  init_perf_values(&perf);

  for(targetno = 0; targetno < Targets.size(); targetno++) {
    if (Targets[targetno]->timedOut(&now)) {
      num_timedout++;
      continue;
    }

    hss = new HostScanStats(Targets[targetno], this);
    incompleteHosts.push_back(hss);
  }
  numInitialTargets = Targets.size();

  ports = pts;

  nextI = incompleteHosts.begin();

  seqmask = get_random_u32();
  scantype = scantp;
  SPM = new ScanProgressMeter(scantype2str(scantype));
  tcp_scan = udp_scan = icmp_scan = prot_scan = ping_scan = noresp_open_scan = false;
  ping_scan_arp = false;
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
  case IPPROT_SCAN:
    noresp_open_scan = true;
    prot_scan = true;
    break;
  case PING_SCAN:
    ping_scan = true;
    break;
  case PING_SCAN_ARP:      
    ping_scan = true;
    ping_scan_arp = true;
    break;
  default:
    break;
    /* TODO: Worry about ping scanning if I do that */
  }
  gstats = new GroupScanStats(this); /* Peeks at several elements in USI - careful of order */
  gstats->num_hosts_timedout += num_timedout;
  pd = NULL;
  rawsd = -1;
  ethsd = NULL;

  if ((tcp_scan || udp_scan || prot_scan || ping_scan_arp) && 
      scantype != CONNECT_SCAN) {
    if (ping_scan_arp || ((o.sendpref & PACKET_SEND_ETH) && 
			  Targets[0]->ifType() == devt_ethernet)) {
      /* We'll send ethernet packets with dnet */
      ethsd = eth_open_cached(Targets[0]->deviceName());
      if (ethsd == NULL)
	fatal("dnet: Failed to open device %s", Targets[0]->deviceName());
      rawsd = -1;
    } else {
      /* Initialize a raw socket */
      if ((rawsd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0 )
	pfatal("socket troubles in UltraScanInfo::Init");
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
  ggood = gstats->sendOK();

  if (!ggood) {
    if (when) {
      TIMEVAL_MSEC_ADD(lowhtime, now, 1000); 
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
  
  if (TIMEVAL_MSEC_SUBTRACT(lowhtime, now) < 0)
    lowhtime = now;

  if (when) *when = lowhtime;

  return (TIMEVAL_MSEC_SUBTRACT(lowhtime, now) == 0)? true : false;
}

/* Find a HostScanStats by IP its address in the incomplete list.
   Returns NULL if none are found. */
HostScanStats *UltraScanInfo::findIncompleteHost(struct sockaddr_storage *ss) {
  list<HostScanStats *>::iterator hss;
  struct sockaddr_in *sin = (struct sockaddr_in *) ss;

  if (sin->sin_family != AF_INET)
    fatal("UltraScanInfo::findIncompleteHost passed a non IPv4 address");

  for(hss = incompleteHosts.begin(); hss != incompleteHosts.end(); hss++) {
    if ((*hss)->target->v4hostip()->s_addr == sin->sin_addr.s_addr)
      return *hss;
  }
  return NULL;
}

  /* Removes any hosts that have completed their scans from the incompleteHosts
     list.  Returns the number of hosts removed. */
int UltraScanInfo::removeCompletedHosts() {
  list<HostScanStats *>::iterator hostI, nxt;
  HostScanStats *hss = NULL;
  int hostsRemoved = 0;
  bool timedout = false;
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
      incompleteHosts.erase(hostI);
      hostsRemoved++;
      if (timedout) gstats->num_hosts_timedout++;
      hss->target->stopTimeOutClock(&now);
      delete hss;
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
  int groupsize = 10;

  if (o.UDPScan())
    groupsize = 50;
  else if (o.TCPScan()) {
    groupsize = MAX(1024 / (ports->tcp_count ? ports->tcp_count : 1), 30);
    if (ports->tcp_count > 1000 && hosts_scanned_so_far == 0 && 
	o.timing_level < 4)
      groupsize = 5; // Give quick results for the very first batch
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
  timing->ccthresh = perf->initial_ccthresh; /* Will be reduced if any packets are dropped anyway */
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
    pspec->type = PS_TCP;
    pspec->proto = IPPROTO_TCP;

    pspec->pd.tcp.dport = USI->ports->tcp_ports[hss->next_portidx++];
    if (USI->scantype == CONNECT_SCAN) 
      pspec->pd.tcp.flags = TH_SYN;
    else if (o.scanflags != -1) pspec->pd.tcp.flags = o.scanflags;
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
  } else if (USI->prot_scan) {
    if (next_portidx >= USI->ports->prot_count)
      return 0;
    return USI->ports->prot_count - next_portidx;
  } else if (USI->ping_scan_arp) {
    if (sent_arp) return 0;
    return 1;
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

/* Adjust various timing variables based on pcket receipt.  Pass
   rcvdtime = NULL if you have given up on a probe and want to count
   this as a DROPPED PACKET */
static void ultrascan_adjust_times(UltraScanInfo *USI, HostScanStats *hss, 
		       UltraProbe *probe, struct timeval *rcvdtime) {

  int ping_magnifier = (probe->isPing())? USI->perf.ping_magnifier : 1;

  /* Adjust timing */
  if (rcvdtime) {
    adjust_timeouts2(&(probe->sent), rcvdtime, &(hss->target->to));
    adjust_timeouts2(&(probe->sent), rcvdtime, &(USI->gstats->to));
  
    hss->lastrcvd = *rcvdtime;
  }

  hss->timing.num_updates++;
  USI->gstats->timing.num_updates++;

  /* Adjust window */
  if (probe->tryno > 0 || !rcvdtime) {
    /* A previous probe must have been lost ... */
    if (o.debugging > 1)
      printf("Ultrascan DROPPED %sprobe packet to %s detected\n", probe->isPing()? "PING " : "", hss->target->targetipstr());
    // Drops often come in big batches, but we only want one decrease per batch.
    if (TIMEVAL_SUBTRACT(probe->sent, hss->timing.last_drop) > 0) {
      hss->timing.cwnd = USI->perf.low_cwnd;
      hss->timing.ccthresh = (int) MAX(hss->num_probes_active / USI->perf.host_drop_ccthresh_divisor, 2);
      hss->timing.last_drop = USI->now;
    }
    if (TIMEVAL_SUBTRACT(probe->sent, USI->gstats->timing.last_drop) > 0) {
      USI->gstats->timing.cwnd = MAX(USI->perf.low_cwnd, USI->gstats->timing.cwnd / USI->perf.group_drop_cwnd_divisor);
      USI->gstats->timing.ccthresh = (int) MAX(USI->gstats->num_probes_active / USI->perf.group_drop_ccthresh_divisor, 2);
      USI->gstats->timing.last_drop = USI->now;
    }
  } else {
    /* Good news -- got a response to first try.  Increase window as 
       appropriate.  */
    if (hss->timing.cwnd <= hss->timing.ccthresh) {
      /* In quick start mode */
      hss->timing.cwnd += ping_magnifier * USI->perf.quick_incr;
    } else {
      /* Congestion control mode */
      hss->timing.cwnd += ping_magnifier * USI->perf.cc_incr / hss->timing.cwnd;
    }
    if (hss->timing.cwnd > USI->perf.max_cwnd)
      hss->timing.cwnd = USI->perf.max_cwnd;

    if (USI->gstats->timing.cwnd <= USI->gstats->timing.ccthresh) {
      /* In quick start mode */
      USI->gstats->timing.cwnd += ping_magnifier * USI->perf.quick_incr;
    } else {
      /* Congestion control mode */
      USI->gstats->timing.cwnd += ping_magnifier * USI->perf.cc_incr / USI->gstats->timing.cwnd;
    }
    if (USI->gstats->timing.cwnd > USI->perf.max_cwnd)
      USI->gstats->timing.cwnd = USI->perf.max_cwnd;
  }

  /* If packet drops are particularly bad, enforce a delay between
     packet sends (useful for cases such as UDP scan where responses
     are frequently rate limited by dest machines or firewalls) */

  /* First we decide whether this packet counts as a drop for send
     delay calculation purposes.  This statement means if (a ping since last boost failed, or the previous packet was both sent after the last boost and dropped) */
  if ((!rcvdtime && TIMEVAL_SUBTRACT(probe->sent, hss->sdn.last_boost) > 0) ||
      (probe->tryno > 0 && TIMEVAL_SUBTRACT(probe->prevSent, hss->sdn.last_boost) > 0)) {
    hss->sdn.droppedRespSinceDelayChanged++;
    //    printf("SDELAY: increasing drops to %d (good: %d; tryno: %d, sent: %.4fs; prevSent: %.4fs, last_boost: %.4fs\n", hss->sdn.droppedRespSinceDelayChanged, hss->sdn.goodRespSinceDelayChanged, probe->tryno, o.TimeSinceStartMS(&probe->sent) / 1000.0, o.TimeSinceStartMS(&probe->prevSent) / 1000.0, o.TimeSinceStartMS(&hss->sdn.last_boost) / 1000.0);
  } else if (rcvdtime) {
    hss->sdn.goodRespSinceDelayChanged++;
    //    printf("SDELAY: increasing good to %d (bad: %d)\n", hss->sdn.goodRespSinceDelayChanged, hss->sdn.droppedRespSinceDelayChanged);
  }

  /* Now change the send delay if neccessary */
  unsigned int oldgood = hss->sdn.goodRespSinceDelayChanged;
  unsigned int oldbad = hss->sdn.droppedRespSinceDelayChanged;
  double threshold = (o.timing_level >= 4)? 0.40 : 0.30;
  if (oldbad > 10 && (oldbad / ((double) oldbad + oldgood) > threshold)) {
    unsigned int olddelay = hss->sdn.delayms;
    hss->boostScanDelay();
    if (o.verbose && hss->sdn.delayms != olddelay)
      printf("Increasing send delay for %s from %d to %d due to %d out of %d dropped probes since last increase.\n", 
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
  if (probe->isPing()) {
    ultrascan_adjust_times(USI, this, probe, NULL);
    /* I'll leave it in the queue in case some response ever does
       come */
  } else num_probes_waiting_retransmit++;

  if (probe->type == UltraProbe::UP_CONNECT && probe->CP()->sd >= 0 ) {
    /* Free the socket as that is a valuable resource, though it is a shame
       late responses will not be permitted */
    USI->gstats->CSI->clearSD(probe->CP()->sd);
    close(probe->CP()->sd);
    probe->CP()->sd = -1;
  }
}

bool HostScanStats::completed() {
  return num_probes_active == 0 && num_probes_waiting_retransmit == 0 && 
    probe_bench.empty() && retry_stack.empty() && freshPortsLeft() == 0;
}

/* Encode the trynum into a 32-bit value.  A simple checksum is also included
   to verify whether a received version is correct. */
static u32 seq32_encode(UltraScanInfo *USI, unsigned int trynum, 
			unsigned int pingseq) {
  u32 seq = 0;
  u16 nfo;

  /* We'll let pingseq and trynum each be 8 bits */
  nfo = (pingseq << 8) + trynum;
  seq = (nfo << 16) + nfo; /* Mirror the data to ensure it is reconstructed correctly */
  /* Obfuscate it a little */
  seq = seq ^ USI->seqmask;
  return seq;
}

/* This function provides the proper cwnd and ccthresh to use.  It may
   differ from versions in timing member var because when no responses
   have been received for this host, may look at others in the group.
   For CHANGING this host's timing, use the timing memberval
   instead. */
void HostScanStats::getTiming(struct ultra_timing_vals *tmng) {
  assert(tmng);

  /* Use the per-host value if a pingport has been found or very few probes
     have been sent */
  if (pingprobestate != PORT_UNKNOWN || numprobes_sent < 80) {
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
  tmng->ccthresh = USI->perf.initial_ccthresh;
  tmng->num_updates = 0;
  return;
}

/* Like ultrascan_port_probe_update(), except it is called with just a
   probespec rather than a whole UltraProbe.  Returns true if the port
   was added or at least the state was changed.  */
static bool ultrascan_port_pspec_update(UltraScanInfo *USI, 
					HostScanStats *hss, 
					const probespec *pspec,
					int newstate) {
  u16 portno;
  u8 proto = 0;
  int oldstate = PORT_TESTING;
  Port *currentp;
  bool swappingport = false;
  /* Whether no response means a port is open */
  bool noresp_open_scan = USI->noresp_open_scan;

  if (USI->prot_scan) {
    proto = IPPROTO_IP;
    portno = pspec->proto;
  } else if (pspec->type == PS_TCP) {
    proto = IPPROTO_TCP;
    portno = pspec->pd.tcp.dport;
  } else if (pspec->type == PS_UDP) {
    proto = IPPROTO_UDP;
    portno = pspec->pd.udp.dport;
  } else assert(0);
  
  /* First figure out the current state */
  currentp = hss->target->ports.getPortEntry(portno, proto);
  if (!currentp) {
    oldstate = PORT_TESTING;
    hss->ports_finished++;
  }
  else oldstate = currentp->state;

  /*    printf("TCP port %hi has changed from state %s to %s!\n", portno, statenum2str(oldstate), statenum2str(newstate)); */
  switch(oldstate) {
    /* TODO: I need more code here to determine when a state should
       be overridden, for example PORT_OPEN trumps PORT_FIREWALLED
       in a SYN scan, but not neccessarily for UDP scan */
  case PORT_TESTING:
    /* Brand new port -- add it to the list */
    hss->target->ports.addPort(portno, proto, NULL, newstate);
    break;
  case PORT_OPEN:
    if (newstate != PORT_OPEN) {
      if (noresp_open_scan) {
	hss->target->ports.addPort(portno, proto, NULL, newstate);
      } /* Otherwise The old open takes precendence */
    }
    break;
  case PORT_CLOSED:
    if (newstate != PORT_CLOSED) {
      if (!noresp_open_scan && newstate != PORT_FILTERED)
	hss->target->ports.addPort(portno, proto, NULL, newstate);
    }
    break;
  case PORT_FILTERED:
    if (newstate != PORT_FILTERED) {
      if (!noresp_open_scan || newstate != PORT_OPEN)
	hss->target->ports.addPort(portno, proto, NULL, newstate);
    }
    break;
  case PORT_UNFILTERED:
    /* This could happen in an ACK scan if I receive a RST and then an
       ICMP filtered message.  I'm gonna stick with unfiltered in that
       case.  I'll change it if the new state is open or closed,
       though I don't expect that to ever happen */
    if (newstate == PORT_OPEN || newstate == PORT_CLOSED)
      hss->target->ports.addPort(portno, proto, NULL, newstate);
    break;
  case PORT_OPENFILTERED:
    if (newstate != PORT_OPENFILTERED) {
      hss->target->ports.addPort(portno, proto, NULL, newstate);
    }
    break;
  default:
    fatal("Unexpected port state: %d\n", oldstate);
    break;
  }

  /* Consider changing the ping port */
  if (hss->pingprobestate != newstate) {
    /* TODO: UDP scan and such will have different preferences -- add them */
    if (noresp_open_scan) {
      if (newstate == PORT_CLOSED || (hss->pingprobestate == PORT_UNKNOWN && newstate == PORT_FILTERED))
	swappingport = true;
    } else {
      if (hss->pingprobestate == PORT_UNKNOWN && 
	  (newstate == PORT_OPEN || newstate == PORT_CLOSED || newstate == PORT_UNFILTERED))
	swappingport = true;
      else if (hss->pingprobestate == PORT_OPEN && (newstate == PORT_CLOSED || newstate == PORT_UNFILTERED))
	swappingport = true;
    }

    if (swappingport) {
      if (o.debugging > 1) 
	printf("Changing ping technique for %s to %s\n", hss->target->targetipstr(), pspectype2ascii(pspec->type));
      hss->pingprobe = *pspec;
      hss->pingprobestate = newstate;
    }
  }
  return oldstate != newstate;
}

  /* Boost the scan delay for this host, usually because too many packet
     drops were detected. */
void HostScanStats::boostScanDelay() {
  unsigned int maxAllowed = (USI->tcp_scan)? o.maxTCPScanDelay() : o.maxUDPScanDelay();
  if (sdn.delayms == 0)
    sdn.delayms = (USI->udp_scan)? 50 : 5; // In many cases, a pcap wait takes a minimum of 80ms, so this matters little :(
  else sdn.delayms = MIN(sdn.delayms * 2, MAX(sdn.delayms, 1000));
  sdn.delayms = MIN(sdn.delayms, maxAllowed); 
  sdn.last_boost = USI->now;
  sdn.droppedRespSinceDelayChanged = 0;
  sdn.goodRespSinceDelayChanged = 0;
}

/* Dismiss all probe attempts on bench -- the ports are marked
     'filtered' or whatever is appropriate for having no response */
void HostScanStats::dismissBench() {
  int newstate;

  if (probe_bench.empty()) return;
  newstate = scantype_no_response_means(USI->scantype);
  while(!probe_bench.empty()) {
    ultrascan_port_pspec_update(USI, this, &probe_bench.back(), newstate);
    probe_bench.pop_back();
  }
  bench_tryno = 0;
}

/* Move all members of bench to retry_stack for probe retransmission */
void HostScanStats::retransmitBench() {
  int newstate;
  if (probe_bench.empty()) return;

  /* Move all contents of probe_bench to the end of retry_stack, updating retry_stack_tries accordingly */
  retry_stack.insert(retry_stack.end(), probe_bench.begin(), probe_bench.end());
  retry_stack_tries.insert(retry_stack_tries.end(), probe_bench.size(), 
			   bench_tryno);
  assert(retry_stack.size() == retry_stack_tries.size());
  probe_bench.erase(probe_bench.begin(), probe_bench.end());
  newstate = scantype_no_response_means(USI->scantype);
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

/* Undoes seq32_encode.  Returns true if the checksum is correct and
   thus trynum was decoded properly.  In that case, trynum (if not
   null) is filled with the decoded value.  If pingseq is not null, it
   is filled with the scanping sequence number, which is 0 if this is
   not a ping. */

static bool seq32_decode(UltraScanInfo *USI, u32 seq, unsigned int *trynum,
			 unsigned int *pingseq) {
  if (trynum) *trynum = 0;
  if (pingseq) *pingseq = 0;

  /* Undo the mask xor */
  seq = seq ^ USI->seqmask;
  /* Check that both sides are the same */
  if ((seq >> 16) != (seq & 0xFFFF))
    return false;

  if (trynum) 
    *trynum = seq & 0xFF;

  if (pingseq)
    *pingseq = (seq & 0xFF00) >> 8;

  return true;
}

/* Sometimes the trynumber and/or pingseq are stored in a source
   portnumber of probes instead.  This takes a port number in HOST
   BYTE ORDER.  Returns true if the numbers seem reasonable, false if
   they are bogus. */
static bool sport_decode(UltraScanInfo *USI, u16 portno, unsigned int *trynum, 
		  unsigned int *pingseq) {
  int tryval;
  tryval = portno - o.magic_port;
  if (tryval <= USI->perf.tryno_cap) {
    if (pingseq) *pingseq = 0;
    if (trynum) *trynum = tryval;
  } else {
    if (pingseq) *pingseq = tryval - USI->perf.tryno_cap;
    if (trynum) *trynum = 0;
  }
  if (tryval > USI->perf.tryno_cap + 256)
    return false;
  return true;
}


/* Called when a ping response is discovered. */
static void ultrascan_ping_update(UltraScanInfo *USI, HostScanStats *hss, 
				  list<UltraProbe *>::iterator probeI,
				  struct timeval *rcvdtime) {
  ultrascan_adjust_times(USI, hss, *probeI, rcvdtime);
  hss->destroyOutstandingProbe(probeI);
}


/* Called when a new status is determined for host in hss (eg. it is
   found to be up or down by a ping/ping_arp scan.  The probe that led
   to this new decision is in probeI.  This function needs to update
   timing information and other stats as appropriate.If rcvdtime is
   NULL, packet stats are not updated. */
static void ultrascan_host_update(UltraScanInfo *USI, HostScanStats *hss, 
				  list<UltraProbe *>::iterator probeI,
				  int newstate, struct timeval *rcvdtime) {
  UltraProbe *probe = *probeI;
  if (rcvdtime) ultrascan_adjust_times(USI, hss, probe, rcvdtime);

  /* Adjust the target flags to note the new state. */
  if ((hss->target->flags & HOST_UP) == 0) {
    if (newstate == HOST_UP) {
      /* Clear any HOST_DOWN or HOST_FIREWALLED flags */
      hss->target->flags &= ~(HOST_DOWN|HOST_FIREWALLED);
      hss->target->flags |= HOST_UP;
    } else if (newstate == HOST_DOWN) {
      hss->target->flags &= ~HOST_FIREWALLED;
      hss->target->flags |= HOST_DOWN;
    } else assert(0);
  }

  /* Kill outstanding probes */
  while(!hss->probes_outstanding.empty())
    hss->destroyOutstandingProbe(hss->probes_outstanding.begin());
}


/* This function is called when a new status is determined for a port.
   the port in the probeI of host hss is now in newstate.  This
   function needs to update timing information, other stats, and the
   Nmap port state table as appropriate.  If rcvdtime is NULL or we got
   unimportant packet, packet stats are not updated.  If you don't have an
   UltraProbe list iterator, you may need to call ultrascan_port_psec_update()
   instead */
static void ultrascan_port_probe_update(UltraScanInfo *USI, HostScanStats *hss,
 					list<UltraProbe *>::iterator probeI,
					int newstate, struct timeval *rcvdtime) {
  UltraProbe *probe = *probeI;
  const probespec *pspec = probe->pspec();
  bool changed = false;

  changed = ultrascan_port_pspec_update(USI, hss, pspec, newstate);

  /* The rcvdtime check is because this func is called that way when
     we give up on a probe because of too many retransmissions. */
  if (rcvdtime &&
  /* If we are not in "noresp_open_scan" and got something back and the
   * newstate is PORT_FILTERED then we got ICMP error response.
   * ICMP errors are often rate-limited (RFC1812) and/or generated by
   * middle-box. No reason to slow down the scan. */
  /* We try to defeat ratelimit only when -T4 or -T5 is used */
  /* We only care ICMP errors timing when we get them during first probe to a port */
     ((changed && newstate != PORT_FILTERED) || USI->noresp_open_scan || probe->tryno == 0 || o.timing_level < 4) &&
  /* If we are in --defeat-rst-ratelimit mode, we do not care whether we got RST back or not
   * because RST and "no response" both mean PORT_CLOSEDFILTERED. Do not slow down */
     !(o.defeat_rst_ratelimit && newstate == PORT_CLOSEDFILTERED && probe->tryno > 0)) { /* rcvdtime is interesting */
    ultrascan_adjust_times(USI, hss, probe, rcvdtime);
    if (probe->tryno > hss->max_successful_tryno) {
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

  hss->destroyOutstandingProbe(probeI);
}




/* If this is NOT a ping probe, set pingseq to 0.  Otherwise it will be the
   ping sequence number (they start at 1).  The probe sent is returned. */
static UltraProbe *sendConnectScanProbe(UltraScanInfo *USI, HostScanStats *hss,
					u16 destport, u8 tryno, u8 pingseq) {

  UltraProbe *probe = new UltraProbe();
  list<UltraProbe *>::iterator probeI;
  static bool connecterror = false;
  u16 sport;
  int rc;
  int connect_errno = 0;
  struct sockaddr_storage sock;
  struct sockaddr_in *sin = (struct sockaddr_in *) &sock;
#if HAVE_IPV6
  struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &sock;
#endif
  size_t socklen;
  ConnectProbe *CP;

  if (pingseq > 0) {
    if (tryno > 0) assert(0); /* tryno + pingseq not currently supported */
    sport = o.magic_port_set? o.magic_port : o.magic_port + USI->perf.tryno_cap + pingseq;
  } else {
    /* Tunnel tryno instead of pingseq in the src port */
    sport = o.magic_port_set? o.magic_port : o.magic_port + tryno;
  }

  probe->tryno = tryno;
  probe->pingseq = pingseq;
  /* First build the probe */
  probe->setConnect(destport);
  CP = probe->CP();
  /* Initiate the connection */
  CP->sd = socket(o.af(), SOCK_STREAM, IPPROTO_TCP);
  if (CP->sd == 1) pfatal("Socket creation in sendConnectScanProbe");
  unblock_socket(CP->sd);
  init_socket(CP->sd);
  if (hss->target->TargetSockAddr(&sock, &socklen) != 0) {
    fatal("Failed to get target socket address in pos_scan");
  }
  if (sin->sin_family == AF_INET)
    sin->sin_port = htons(probe->pspec()->pd.tcp.dport);
#if HAVE_IPV6
  else sin6->sin6_port = htons(probe->pspec()->pd.tcp.dport);
#endif
  hss->lastprobe_sent = probe->sent = USI->now;
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
    if (probe->isPing()) 
      ultrascan_ping_update(USI, hss, probeI, &USI->now);
    else 
      ultrascan_port_probe_update(USI, hss, probeI, PORT_OPEN, &USI->now);
    probe = NULL;
  } else {
    switch(connect_errno) {
    case EINPROGRESS:
    case EAGAIN:
      USI->gstats->CSI->watchSD(CP->sd);
      break;
    default:
      if (!connecterror) {	
	connecterror = true;
	fprintf(stderr, "Strange error from connect (%d):", connect_errno);
	fflush(stdout);
	fflush(stderr);
	perror(""); /*falling through intentionally*/
      }
    case ECONNREFUSED:
      if (probe->isPing())
	ultrascan_ping_update(USI, hss, probeI, &USI->now);
      else 
	ultrascan_port_probe_update(USI, hss, probeI, PORT_CLOSED, &USI->now);
      break;
    }
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
  hss->lastprobe_sent = probe->sent = USI->now;
  if ((rc = eth_send(USI->ethsd, frame, sizeof(frame))) != sizeof(frame)) {
    int err = socket_errno();
    error("WARNING:  eth_send of ARP packet returned %i rather than expected %d (errno=%i: %s)\n", rc, (int) sizeof(frame), err, strerror(err));
  }
  PacketTrace::traceArp(PacketTrace::SENT, (u8 *) frame, sizeof(frame), &USI->now);
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
   ping sequence number (they start at 1).  The probe sent is returned. */
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

  if (USI->ethsd) {
    memcpy(eth.srcmac, hss->target->SrcMACAddress(), 6);
    memcpy(eth.dstmac, hss->target->NextHopMACAddress(), 6);
    eth.ethsd = USI->ethsd;
    eth.devname[0] = '\0';
    ethptr = &eth;
  }
  if (pingseq > 0) {
    if (tryno > 0) assert(0); /* tryno + pingseq not currently supported */
    sport = o.magic_port_set? o.magic_port : o.magic_port + USI->perf.tryno_cap + pingseq;
  } else {
    /* Tunnel tryno instead of pingseq in the src port */
    sport = o.magic_port_set? o.magic_port : o.magic_port + tryno;
  }

  probe->tryno = tryno;
  probe->pingseq = pingseq;
  /* First build the probe */
  if (USI->tcp_scan) {
    assert(USI->scantype != CONNECT_SCAN);

    seq = seq32_encode(USI, tryno, pingseq);
    if (pspec->pd.tcp.flags & TH_ACK)
	  ack = rand();

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
	hss->lastprobe_sent = probe->sent = USI->now;
      }
      send_ip_packet(USI->rawsd, ethptr, packet, packetlen);
      free(packet);
    }
  } else if (USI->udp_scan) {
    for(decoy = 0; decoy < o.numdecoys; decoy++) {
      packet = build_udp_raw(&o.decoys[decoy], hss->target->v4hostip(),
			     o.ttl, ipid, IP_TOS_DEFAULT, false,
			     o.ipoptions, o.ipoptionslen,
			     sport, pspec->pd.udp.dport,
			     o.extra_payload, o.extra_payload_length, 
			     &packetlen);
      if (decoy == o.decoyturn) {
	probe->setIP(packet, packetlen, pspec);
	hss->lastprobe_sent = probe->sent = USI->now;
      }
      send_ip_packet(USI->rawsd, ethptr, packet, packetlen);
      free(packet);
    }
  } else if (USI->prot_scan) {
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
				0, 0, 8, 0,
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
	hss->lastprobe_sent = probe->sent = USI->now;
      }
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
    fatal("sendNextScanProbe: No more probes! Error in Nmap.");
  }
  hss->numprobes_sent++;
  USI->gstats->probes_sent++;
  if (USI->ping_scan_arp)
    sendArpScanProbe(USI, hss, 0, 0);
  else if (USI->scantype == CONNECT_SCAN)
    sendConnectScanProbe(USI, hss, pspec.pd.tcp.dport, 0, 0);
  else
    sendIPScanProbe(USI, hss, &pspec, 0, 0);
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

  if (USI->scantype == CONNECT_SCAN)
    sendConnectScanProbe(USI, hss, pspec.pd.tcp.dport, pspec_tries + 1, 0);
  else {
    assert(pspec.type != PS_ARP);
    sendIPScanProbe(USI, hss, &pspec, pspec_tries + 1, 0);
  }
}

static void doAnyNewProbes(UltraScanInfo *USI) {
  HostScanStats *hss;
  unsigned int unableToSend = 0; /* # of times in a row that hosts were unable to send probe */

  gettimeofday(&USI->now, NULL);

  /* Go through each incomplete target and send a probe if appropriate */
  while (unableToSend < USI->numIncompleteHosts() && USI->gstats->sendOK()) {
    hss = USI->nextIncompleteHost();
    if (!hss) break;
    if (hss->freshPortsLeft() && hss->sendOK(NULL)) {
      sendNextScanProbe(USI, hss);
      unableToSend = 0;
    } else {
      unableToSend++;
    }
  }
}

static void doAnyRetryStackRetransmits(UltraScanInfo *USI) {
  HostScanStats *hss;
  unsigned int unableToSend = 0; /* # of times in a row that hosts were unable to send probe */

  gettimeofday(&USI->now, NULL);

  /* Go through each incomplete target and send a probe if appropriate */
  while (unableToSend < USI->numIncompleteHosts() && USI->gstats->sendOK()) {
    hss = USI->nextIncompleteHost();
    if (!hss) break;
    if (!hss->retry_stack.empty() && hss->sendOK(NULL)) {
      sendNextRetryStackProbe(USI, hss);
      unableToSend = 0;
    } else {
      unableToSend++;
    }
  }
}

/* Sends a ping probe to the host.  Assumes that caller has already
   checked that sending is OK w/congestion control and that pingprobe is
   available */
static void sendPingProbe(UltraScanInfo *USI, HostScanStats *hss) {
  if (o.debugging > 1) {
    char tmpbuf[32];
    printf("Ultrascan PING SENT to %s [%s]\n", hss->target->targetipstr(), 
	   probespec2ascii(&hss->pingprobe, tmpbuf, sizeof(tmpbuf)));
  }
  if (USI->scantype == CONNECT_SCAN) {
    sendConnectScanProbe(USI, hss, hss->pingprobe.pd.tcp.dport, 0, 
			 hss->nextPingSeq(true));
  } else if (USI->scantype == RPC_SCAN) {
    assert(0); /* TODO: fill out */
  } else {
    sendIPScanProbe(USI, hss, &hss->pingprobe, 0, hss->nextPingSeq(true));
  }
  hss->numpings_sent++;
  USI->gstats->probes_sent++;
}


static void doAnyPings(UltraScanInfo *USI) {
  list<HostScanStats *>::iterator hostI;
  HostScanStats *hss = NULL;

  gettimeofday(&USI->now, NULL);
  /* First single host pings */
  for(hostI = USI->incompleteHosts.begin(); 
      hostI != USI->incompleteHosts.end(); hostI++) {
    hss = *hostI;
    if (hss->pingprobestate != PORT_UNKNOWN && 
	hss->rld.rld_waiting == false && 
	hss->numprobes_sent >= hss->lastping_sent_numprobes + 10 &&
	TIMEVAL_SUBTRACT(USI->now, hss->lastrcvd) > USI->perf.pingtime && 
	TIMEVAL_SUBTRACT(USI->now, hss->lastping_sent) > USI->perf.pingtime &&
	USI->gstats->sendOK() && hss->sendOK(NULL)) {
      sendPingProbe(USI, hss);
      hss->lastping_sent = USI->now;
      hss->lastping_sent_numprobes = hss->numprobes_sent;
    }    
  }

  /* Next come global pings */
  /****NOT IMPLEMENTED YET *****
  if (USI->gstats->numprobes < 30 && 
      USI->gstats->lastping_sent_numprobes + 20 && 
      TIMEVAL_SUBTRACT(USI->now, USI-gstats->lastrcvd) > USI->perf.pingtime && 
      TIMEVAL_SUBTRACT(USI->now, USI-gstats->lastping_sent) > USI->perf.pingtime && 
      USI->gstats->sendOK()) {
    sendGlobalPingProbe(USI);
    } ***/

}

/* Retransmit one probe that has presumably been timed out.  Only does
   retransmission, does not mark the probe timed out and such. */
static void retransmitProbe(UltraScanInfo *USI, HostScanStats *hss, 
			    UltraProbe *probe) {
  UltraProbe *newProbe = NULL;
  if (probe->type == UltraProbe::UP_IP) {
    if (USI->prot_scan)
      newProbe = sendIPScanProbe(USI, hss, probe->pspec(), 
				 probe->tryno + 1, 0);
    else if (probe->protocol() == IPPROTO_TCP) {
      newProbe = sendIPScanProbe(USI, hss, probe->pspec(), probe->tryno + 1, 
				 0);
    } else {
      assert(probe->protocol() == IPPROTO_UDP);
      newProbe = sendIPScanProbe(USI, hss, probe->pspec(), probe->tryno + 1,
				 0);
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
  HostScanStats *host = NULL;
  UltraProbe *probe = NULL;
  int retrans = 0; /* Number of retransmissions during a loop */
  unsigned int maxtries;

  gettimeofday(&USI->now, NULL);

  /* Retransmit as permitted by congestion control and tryno limits */
  while(USI->gstats->sendOK()) {
    retrans = 0;
    for(hostI = USI->incompleteHosts.begin(); 
	hostI != USI->incompleteHosts.end(); hostI++) {
      host = *hostI;
      if ((host->num_probes_active > 0 || 
	   host->num_probes_waiting_retransmit > 0) && host->sendOK(NULL)) {
	/* Doing the probe list backwards gives a decent efficiency
	   boost.  Probe retransmissions may be reordered from the
	   original transmissions, but mixing things up like that can
	   be beneficial */
	probeI = host->probes_outstanding.end();
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
      }
    }
    if (retrans == 0) break; /* Went through all hosts -- nothing to send */
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
    printf("**TIMING STATS**: IP, probes active/freshportsleft/retry_stack/outstanding/retranwait/onbench, cwnd/ccthresh/delay, timeout/srtt/rttvar/\n");
    printf("   Groupstats (%d/%d incomplete): %d/*/*/*/*/* %.2f/%d/* %d/%d/%d\n",
	   USI->numIncompleteHosts(), USI->numInitialHosts(), 
	   USI->gstats->num_probes_active, USI->gstats->timing.cwnd,
	   USI->gstats->timing.ccthresh, USI->gstats->to.timeout, 
	   USI->gstats->to.srtt, USI->gstats->to.rttvar);

    for(hostI = USI->incompleteHosts.begin(); 
	hostI != USI->incompleteHosts.end(); hostI++) {
      hss = *hostI;
      hss->getTiming(&hosttm);
      printf("   %s: %d/%d/%d/%d/%d/%d %.2f/%d/%d %li/%d/%d\n", hss->target->targetipstr(),
	     hss->num_probes_active, hss->freshPortsLeft(), 
	     (int) hss->retry_stack.size(),
	     hss->num_probes_outstanding(), 
	     hss->num_probes_waiting_retransmit, (int) hss->probe_bench.size(),
	     hosttm.cwnd, hosttm.ccthresh, hss->sdn.delayms, 
	     hss->probeTimeout(), hss->target->to.srtt, 
	     hss->target->to.rttvar);
    }
  }

  /* Now time to figure out how close we are to completion ... */
  if (USI->SPM->mayBePrinted(&USI->now)) {
    list<HostScanStats *>::iterator hostI;
    HostScanStats *host = NULL;
    int maxtries;
    double thishostpercdone;
    double avgdone = USI->gstats->numtargets - USI->numIncompleteHosts();
    /* next for the partially finished hosts */
    for(hostI = USI->incompleteHosts.begin(); 
        hostI != USI->incompleteHosts.end(); hostI++) {
      host = *hostI;
      maxtries = host->allowedTryno(NULL, NULL) + 1;
      // This is inexact (maxtries - 1) because of numprobes_sent includes
      // at least one try of ports_finished.
      thishostpercdone = host->ports_finished * (maxtries -1) + host->numprobes_sent;
      thishostpercdone /= maxtries * USI->gstats->numprobes;
      if (thishostpercdone >= .9999) thishostpercdone = .9999;
      avgdone += thishostpercdone;
    }
    avgdone /= USI->gstats->numtargets;
    USI->SPM->printStatsIfNeccessary(avgdone, &USI->now);
    //    printf("The scan is %.2f%% done!\n", avgdone * 100);
  }
}

/* Does a select() call and handles all of the results.  Even if stime
   is now, it tries a very quick select() just in case.  Returns true
   if at least one good result (generally a port state change) is
   found, false if it times out instead */
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
  int newstate = PORT_UNKNOWN;
  int optval;
  recvfrom6_t optlen = sizeof(int);
  char buf[128];
  int numGoodSD = 0;
  int err = 0;
  u16 pport = 0;
#ifdef LINUX
  int res;
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
    pfatal("select failed in do_one_select_round()");
  
  if (!selectres)
    return false;
  
  /* Yay!  Got at least one response back -- loop through outstanding probes
     and find the relevant ones */
  for(hostI = USI->incompleteHosts.begin(); 
      hostI != USI->incompleteHosts.end() && numGoodSD < selectres; hostI++) {
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
      pport = probe->pspec()->pd.tcp.dport;
      assert(probe->type == UltraProbe::UP_CONNECT);
      sd = probe->CP()->sd;
	/* Let see if anything has happened! */
      if (sd >= 0 && (FD_ISSET(sd, &fds_rtmp)  || FD_ISSET(sd, &fds_wtmp) || 
		      FD_ISSET(sd, &fds_xtmp))) {
	numGoodSD++;
	newstate = PORT_UNKNOWN;
	if (getsockopt(sd, SOL_SOCKET, SO_ERROR, (char *) &optval, 
		       &optlen) != 0)
	  optval = socket_errno(); /* Stupid Solaris ... */
	switch(optval) {
	case 0:
#ifdef LINUX
	  if (!FD_ISSET(sd, &fds_rtmp)) {
	    /* Linux goofiness -- We need to actually test that it is writeable */
	    res = send(sd, "", 0, 0);
	    
	    if (res < 0 ) {
	      if (o.debugging > 1) {
		log_write(LOG_STDOUT, "Bad port %hi caught by 0-byte write: ",
			  pport);
		perror("");
	      }
	      newstate = PORT_CLOSED;
	    } else {
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
		newstate = PORT_CLOSED;
	      } else {
		newstate = PORT_OPEN;
	      }
	    }
	  } else {
	    newstate = PORT_OPEN;
	  }
#else
	  newstate = PORT_OPEN;
#endif
	  break;
	case EACCES:
	  /* Apparently this can be caused by dest unreachable admin
	     prohibited messages sent back, at least from IPv6
	     hosts */
	  newstate = PORT_FILTERED;
	  break;
	case ECONNREFUSED:
	  newstate = PORT_CLOSED;
	  break;
#ifdef ENOPROTOOPT
	case ENOPROTOOPT:
#endif
	case EHOSTUNREACH:
	case ETIMEDOUT:
	case EHOSTDOWN:
	case ENETUNREACH:
	  /* It could be the host is down, or it could be firewalled.  We
	     will go on the safe side & assume port is closed ... on second
	     thought, lets go firewalled! and see if it causes any trouble */
	  newstate = PORT_FILTERED;
	  break;
	case ENETDOWN:
	case ENETRESET:
	case ECONNABORTED:
	  snprintf(buf, sizeof(buf), "Strange SO_ERROR from connection to %s (%d - '%s') -- bailing scan", host->target->targetipstr(), optval, strerror(optval) );
	  pfatal(buf);
	  break;
	default:
	  snprintf(buf, sizeof(buf), "Strange read error from %s (%d - '%s')", host->target->targetipstr(), optval, strerror(optval));
	  perror(buf);
	  break;
	}
	
	if (newstate != PORT_UNKNOWN) {
	  if (probe->isPing())
	    ultrascan_ping_update(USI, host, probeI, &USI->now);
	  else
	    ultrascan_port_probe_update(USI, host, probeI, newstate, &USI->now);
	}
      }
    }
  }
  return numGoodSD;
}

/* ICMP error messages generally return the IP header they were sent
   with.  That provides the opportunity to look at the IPID to
   determine which probe the packet matches up with.  Unfortunately,
   this doesn't always work.  Some systems screw up the IPID in the
   process of sending, and remote systems can screw it up as well.
   This function is a "soft" match, that returns true if hey really do
   match, or if matching seems to be broken for one reason or
   another.  You can send in HBO or NBO, just as
   long as the two values are in the same byte order. */
static bool allow_ipid_match(u16 ipid_sent, u16 ipid_rcvd) {
  static int numvalid = 0;
  static int numbogus = 0;

  /* TODO: I should check if this applies to more recent Solaris releases */
  /* These systems seem to hose sent IPID */
#if defined(SOLARIS) || defined(SUNOS) || defined(IRIX) || defined(HPUX)
  return true;
#endif

  if (ipid_sent == ipid_rcvd) {
    numvalid++;
    return true;
  } else numbogus++;

  if (numbogus >= 2 && numvalid == 0)
    return true; /* Test does not seem to be working */

  /* This test is because sometimes a valid will come by luck */
  if (numbogus / (numbogus + numvalid) > .8)
    return true;

  return false;

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
    rc = read_arp_reply_pcap(USI->pd, rcvdmac, &rcvdIP, to_usec, &rcvdtime);
    gettimeofday(&USI->now, NULL);
    if (rc == -1) fatal("Received -1 response from readarp_reply_pcap");
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
      hss = USI->findIncompleteHost((struct sockaddr_storage *) &sin);
      if (!hss) continue;
      /* Add found HW address for target */
      hss->target->setMACAddress(rcvdmac);

      if (hss->probes_outstanding.empty()) {
	continue;
	/* TODO: I suppose I should really mark the @@# host as up */
      }
      probeI = hss->probes_outstanding.end();
      probeI--;
      ultrascan_host_update(USI, hss, probeI, HOST_UP, &rcvdtime);
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
  struct timeval rcvdtime;
  struct ip *ip = NULL, *ip2 = NULL;
  struct tcp_hdr *tcp = NULL;
  struct icmp *icmp = NULL;
  struct udp_hdr *udp = NULL;
  struct link_header linkhdr;
  unsigned int bytes;
  long to_usec;
  HostScanStats *hss = NULL;
  struct sockaddr_in sin;
  list<UltraProbe *>::iterator probeI;
  UltraProbe *probe = NULL;
  unsigned int trynum = 0;
  unsigned int pingseq = 0;
  bool goodseq;
  int newstate = PORT_UNKNOWN;
  unsigned int probenum;
  unsigned int listsz;
  unsigned int requiredbytes;
  /* Static so that we can detect an ICMP response now, then add it later when
     the icmp probe is made */
  static bool protoscanicmphack = false;
  static struct sockaddr_in protoscanicmphackaddy;
  gettimeofday(&USI->now, NULL);

  do {
    to_usec = TIMEVAL_SUBTRACT(*stime, USI->now);
    if (to_usec < 2000) to_usec = 2000;
    ip = (struct ip *) readip_pcap(USI->pd, &bytes, to_usec, &rcvdtime, &linkhdr);
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

    /* OK, we got a packet.  Let's make sure it is well-formed */
    if (bytes < 28)
      continue;
    if (ip->ip_v != 4)
      continue;
    if (ip->ip_hl < 5)
      continue;

    if (USI->prot_scan) {
      memset(&sin, 0, sizeof(sin));
      sin.sin_addr.s_addr = ip->ip_src.s_addr;
      sin.sin_family = AF_INET;
      hss = USI->findIncompleteHost((struct sockaddr_storage *) &sin);
      if (hss) {
	setTargetMACIfAvailable(hss->target, &linkhdr, ip, 0);
	if (ip->ip_p == IPPROTO_ICMP) {
	  protoscanicmphack = true;
	  protoscanicmphackaddy = sin;
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
	      goodone = true;
	    }
	  }
	}
      }
    }

    if (ip->ip_p == IPPROTO_TCP && !USI->prot_scan) {
      if ((unsigned) ip->ip_hl * 4 + 20 > bytes)
	continue;
      tcp = (struct tcp_hdr *) ((u8 *) ip + ip->ip_hl * 4);
      /* Now ensure this host is even in the incomplete list */
      memset(&sin, 0, sizeof(sin));
      sin.sin_addr.s_addr = ip->ip_src.s_addr;
      sin.sin_family = AF_INET;
      hss = USI->findIncompleteHost((struct sockaddr_storage *) &sin);
      if (!hss) continue; // Not from a host that interests us
      setTargetMACIfAvailable(hss->target, &linkhdr, ip, 0);
      probeI = hss->probes_outstanding.end();
      listsz = hss->num_probes_outstanding();
      u16 tsp = ntohs(tcp->th_sport);

      goodone = false;
      
      for(probenum = 0; probenum < listsz && !goodone; probenum++) {
	probeI--;
	probe = *probeI;
	goodseq = false; 
	newstate = PORT_UNKNOWN;

	if (o.af() != AF_INET || probe->protocol() != IPPROTO_TCP)
	  continue;

	/* Ensure the connection info matches.  No ntohs()-style
	   conversion necc. b/c all in net bo */
	if (probe->dport() != tsp ||
	    probe->sport() != ntohs(tcp->th_dport) ||
	    hss->target->v4sourceip()->s_addr != ip->ip_dst.s_addr)
	  continue;
	
	if (!o.magic_port_set) {
	  sport_decode(USI, ntohs(tcp->th_dport), &trynum, &pingseq);
	  goodseq = true;
	} else {
	  /* Let us now try to get the try number from the ACK.  Try
	     ack-1 because some probes include SYN or FIN packet and
	     thus call for increment */
	  goodseq = seq32_decode(USI, ntohl(tcp->th_ack) - 1, &trynum, &pingseq);
	  if (!goodseq)
	    goodseq = seq32_decode(USI, ntohl(tcp->th_ack), &trynum, &pingseq);
	}

	if (goodseq && pingseq == 0 && trynum < probe->tryno)
	  continue; /* It must be from a different (previous) probe */
	else if (goodseq && pingseq > 0 && pingseq != probe->pingseq)
	  continue; /* Wrong ping probe, apparently */
	else if (!goodseq) {
	  /* TODO: I need to do some testing and find out how often this
	     happens and whether other techniques such as the response seq should
	     be used in those cases where it happens.  Then I should make this just
   	     a debugging > X statement. */
	  if (o.debugging)
	    printf("Bad Sequence number from host %s.\n", inet_ntoa(ip->ip_src));
	  /* I'll just assume it is a response to this (most recent) probe. */
	  if (probe->isPing()) {
	    pingseq = probe->pingseq;
	    trynum = 0;
	  } else {
	    trynum = probe->tryno;
	    pingseq = 0;
	  }
	}

	if (probe->isPing()) {
	  goodone = true;
	} else {
	  /* Now that response has been matched to a probe, I interpret it */
	  if (USI->scantype == SYN_SCAN && tcp->th_flags == (TH_SYN|TH_ACK)) {
	    /* Yeah!  An open port */
	    newstate = PORT_OPEN;
	  } else if (tcp->th_flags & TH_RST) {
	    if (USI->scantype == WINDOW_SCAN ) {
	      newstate = (tcp->th_win)? PORT_OPEN : PORT_CLOSED;
	    } else if (USI->scantype == ACK_SCAN) {
	      newstate = PORT_UNFILTERED;
	    } else newstate = PORT_CLOSED;
	  } else if (probe->dport() == probe->sport() &&
		     ip->ip_src.s_addr == ip->ip_dst.s_addr &&
		     probe->ipid() == ntohs(ip->ip_id)) {
	    /* Sometimes we get false results when scanning localhost with
	       -p- because we scan localhost with src port = dst port and
	       see our outgoing packet and think it is a response. */
	    continue;
	  } else {
	    if (o.debugging)
	      error("Received scan response with unexpected TCP flags: %d\n", tcp->th_flags);
	    break;
	  }
	  goodone = true;
	}
      }
    } else if (ip->ip_p == IPPROTO_ICMP) {

      if ((unsigned) ip->ip_hl * 4 + 28 > bytes)
	continue;

      icmp = (struct icmp *) ((char *)ip + 4 * ip->ip_hl);

      if (icmp->icmp_type != 3)
	continue;

      ip2 = (struct ip *) (((char *) ip) + 4 * ip->ip_hl + 8);
      requiredbytes = /* IPlen*/ 4 * ip->ip_hl + 
                      /* ICMPLen */ 8 + 
                      /* IP2 Len */ 4 * ip2->ip_hl;
      if (USI->tcp_scan || USI->udp_scan)
	bytes += 8; /* UDP hdr, or TCP hdr up to seq # */
      /* prot scan has no headers coming back, so we don't reserve the 
	 8 xtra bytes */
      if (bytes < requiredbytes) {
	if (o.debugging) 
	  error("Received short ICMP packet (%d bytes)\n", bytes);
	continue;
      }
      
      /* Make sure the protocol is right */
      if (USI->tcp_scan && ip2->ip_p != IPPROTO_TCP)
	continue;

      if (USI->udp_scan && ip2->ip_p != IPPROTO_UDP)
	continue;

      /* ensure this packet relates to a packet to the host
	 we are scanning ... */
      memset(&sin, 0, sizeof(sin));
      sin.sin_addr.s_addr = ip2->ip_dst.s_addr;
      sin.sin_family = AF_INET;
      hss = USI->findIncompleteHost((struct sockaddr_storage *) &sin);
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

	/* Checking IPID is a little more complex because you can't always count on it */
	if (!allow_ipid_match(probe->ipid(), ntohs(ip2->ip_id)))
	  continue;

	if (ip2->ip_p == IPPROTO_TCP && !USI->prot_scan) {
	  tcp = (struct tcp_hdr *) ((u8 *) ip2 + ip2->ip_hl * 4);
	  if (ntohs(tcp->th_sport) != probe->sport() || 
	      ntohs(tcp->th_dport) != probe->dport() || 
	      ntohl(tcp->th_seq) != probe->tcpseq())
	    continue;
	} else if (ip2->ip_p == IPPROTO_UDP && !USI->prot_scan) {
	  /* TODO: IPID verification */
	  udp = (struct udp_hdr *) ((u8 *) ip2 + ip->ip_hl * 4);
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
	    if (USI->scantype == IPPROT_SCAN) {
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
	    error("Unexpected ICMP type/code 3/%d unreachable packet:", 
		  icmp->icmp_code);
	    hdump((unsigned char *)icmp, ntohs(ip->ip_len) - 
		  sizeof(struct ip));
	    break;
	  }
	  if (newstate == PORT_UNKNOWN) break;
	  goodone = true;
	}
      }
    } else if (ip->ip_p == IPPROTO_UDP && !USI->prot_scan) {
      if ((unsigned) ip->ip_hl * 4 + 8 > bytes)
	continue;
      udp = (struct udp_hdr *) ((u8 *) ip + ip->ip_hl * 4);
      /* Search for this host on the incomplete list */
      memset(&sin, 0, sizeof(sin));
      sin.sin_addr.s_addr = ip->ip_src.s_addr;
      sin.sin_family = AF_INET;
      hss = USI->findIncompleteHost((struct sockaddr_storage *) &sin);
      if (!hss) continue; // Not from a host that interests us
      probeI = hss->probes_outstanding.end();
      listsz = hss->num_probes_outstanding();
      goodone = false;

      for(probenum = 0; probenum < listsz && !goodone; probenum++) {
	probeI--;
	probe = *probeI;
	goodseq = false; 
	newstate = PORT_UNKNOWN;

	if (o.af() != AF_INET || probe->protocol() != IPPROTO_UDP)
	  continue;

	/* Ensure the connection info matches.  No ntohs()-style
	   conversion necc. b/c all in net bo */
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
	goodone = true;
      }
    } else continue; /* Unexpected protocol */
  } while (!goodone && !timedout);

  if (goodone) {
    if (probe->isPing())
      ultrascan_ping_update(USI, hss, probeI, &rcvdtime);
    else
      ultrascan_port_probe_update(USI, hss, probeI, newstate, &rcvdtime);
  }

  /* If protoicmphack is true, we are doing an IP proto scan and
     discovered that ICMP is open.  This has to be done separately
     because an ICMP response ALSO frequently shows that some other
     protocol is closed/filtered.  So we let that other protocol stuff
     go first, then handle it here */
  if (protoscanicmphack) {
    hss = USI->findIncompleteHost((struct sockaddr_storage *) &protoscanicmphackaddy);
    if (hss) {
	  probeI = hss->probes_outstanding.end();
	  listsz = hss->num_probes_outstanding();

	  for(probenum = 0; probenum < listsz; probenum++) {
	    probeI--;
	    probe = *probeI;

	    if (probe->protocol() == IPPROTO_ICMP) {
	      if (probe->isPing())
		ultrascan_ping_update(USI, hss, probeI, NULL);
	      else
		ultrascan_port_probe_update(USI, hss, probeI, PORT_OPEN, NULL);
	      if (!goodone) goodone = true;
	      break;
	    }
	  }
	  protoscanicmphack = false;
    }
  }

  return goodone;
}

static void waitForResponses(UltraScanInfo *USI) {
  struct timeval stime;
  bool gotone = false;
  gettimeofday(&USI->now, NULL);
  USI->gstats->last_wait = USI->now;
  USI->gstats->probes_sent_at_last_wait = USI->gstats->probes_sent;

  do {
    USI->sendOK(&stime);
    if (USI->ping_scan_arp) {
      gotone = get_arp_result(USI, &stime);
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
  char pcap_filter[2048];
  /* 20 IPv6 addresses is max (45 byte addy + 14 (" or src host ")) * 20 == 1180 */
  char dst_hosts[1200];
  int filterlen = 0;
  int len;
  unsigned int targetno;
  bool doIndividual = Targets.size() <= 20; // Don't bother IP limits if scanning huge # of hosts
  pcap_filter[0] = '\0';

  if (USI->scantype == CONNECT_SCAN)
    return; /* No sniffer needed! */

  if (doIndividual) {
    for(targetno = 0; targetno < Targets.size(); targetno++) {
      len = snprintf(dst_hosts + filterlen, 
		     sizeof(dst_hosts) - filterlen,
		     "%ssrc host %s", (targetno == 0)? "" : " or ",
		     Targets[targetno]->targetipstr());
      if (len < 0 || len + filterlen >= (int) sizeof(dst_hosts))
	fatal("ran out of space in dst_hosts");
      filterlen += len;
    }
  }
  filterlen = 0;

  USI->pd = my_pcap_open_live(Targets[0]->deviceName(), 100,  (o.spoofsource)? 1 : 0, pcap_selectable_fd_valid()? 200 : 2);

  if (USI->tcp_scan || USI->udp_scan) {
    if (doIndividual)
      len = snprintf(pcap_filter, sizeof(pcap_filter), 
		     "dst host %s and (icmp or (%s and (%s)))", 
		     inet_ntoa(Targets[0]->v4source()), 
		     (USI->tcp_scan)? "tcp" : "udp", dst_hosts);
    else len = snprintf(pcap_filter, sizeof(pcap_filter), 
			"dst host %s and (icmp or %s)", 
			inet_ntoa(Targets[0]->v4source()), 
			(USI->tcp_scan)? "tcp" : "udp");
    if (len < 0 || len >= (int) sizeof(pcap_filter))
      fatal("ran out of space in pcap filter");
    filterlen = len;
  } else if (USI->prot_scan) {
    if (doIndividual)
      len = snprintf(pcap_filter, sizeof(pcap_filter), 
		     "dst host %s and (icmp or (%s))", 
		     inet_ntoa(Targets[0]->v4source()), dst_hosts);
    else	
      len = snprintf(pcap_filter, sizeof(pcap_filter), "dst host %s",
		     inet_ntoa(Targets[0]->v4source()));
    if (len < 0 || len >= (int) sizeof(pcap_filter))
      fatal("ran out of space in pcap filter");
    filterlen = len;
  } else if (USI->ping_scan_arp) {
    const u8 *mac = Targets[0]->SrcMACAddress();
    assert(mac);
    len = snprintf(pcap_filter, sizeof(pcap_filter), 
		   "arp and ether dst host %02X:%02X:%02X:%02X:%02X:%02X", 
		   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    if (len < 0 || len >= (int) sizeof(pcap_filter))
      fatal("ran out of space in pcap filter");
    filterlen = len;
  } else assert(0); /* Other scan types? */
  if (o.debugging > 2) printf("Pcap filter: %s\n", pcap_filter);
  set_pcap_filter(Targets[0]->deviceName(), USI->pd, pcap_filter);
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
  static UltraScanInfo *lastRetryCappedWarning = NULL;
  int newstate = PORT_UNKNOWN;
  unsigned int maxtries = 0;
  bool scanmaybedone = true; /* The whole scan is not yet done */
  int expire_us = 0;

  bool tryno_capped = false, tryno_mayincrease = false;
  struct timeval tv_start = {0};
  if (o.debugging) {
    gettimeofday(&USI->now, NULL);
    tv_start = USI->now;
  }
    
  /* First go through hosts and remove any completed ones from incompleteHosts */
  USI->removeCompletedHosts();
  if (USI->numIncompleteHosts() == 0)
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
    expire_us = host->probeExpire(); // give up completely after this long
    maxtries = host->allowedTryno(&tryno_capped, &tryno_mayincrease);

    /* Should we dump everyone off the bench? */
    if (host->probe_bench.size() > 0) {
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
      
      if (!probe->timedout && TIMEVAL_SUBTRACT(USI->now, probe->sent) > 
	  (long) host->probeTimeout()) {
	host->markProbeTimedout(probeI);
      }
      
      if (!probe->isPing() && probe->timedout && !probe->retransmitted) {
	if (!tryno_mayincrease && probe->tryno >= maxtries) {
	  newstate = scantype_no_response_means(USI->scantype);
	  if (USI->scantype == PING_SCAN_ARP)
	    ultrascan_host_update(USI, host, probeI, newstate, NULL);
	  else
	    ultrascan_port_probe_update(USI, host, probeI, newstate, NULL);
	  if (tryno_capped && lastRetryCappedWarning != USI) {
	    /* Perhaps I should give this on a per-host basis.  Oh
	       well, hopefully it is rare anyway. */
	    printf("Warning: Giving up on port early because retransmission cap hit.\n");
	    lastRetryCappedWarning = USI;
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

  if (o.debugging) {
    long tv_diff;
    gettimeofday(&USI->now, NULL);
    tv_diff = TIMEVAL_MSEC_SUBTRACT(USI->now, tv_start);
    if (tv_diff > 30) printf("processData took %lims\n", tv_diff);
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

/* 3rd generation Nmap scanning function.  Handles most Nmap port scan types */
void ultra_scan(vector<Target *> &Targets, struct scan_lists *ports, 
		stype scantype) {
  UltraScanInfo *USI = NULL;
  o.current_scantype = scantype;

  if (Targets.size() == 0) {
    return;
  }

#ifdef WIN32
  if (scantype != CONNECT_SCAN && Targets[0]->ifType() == devt_loopback) {
    log_write(LOG_STDOUT, "Skipping %s against %s because Windows does not support scanning your own machine (localhost) this way.\n", scantype2str(scantype), Targets[0]->NameIP());
    return;
  }
#endif

  startTimeOutClocks(Targets);
  USI = new UltraScanInfo(Targets, ports, scantype);

  if (o.verbose) {
    char targetstr[128];
    bool plural = (Targets.size() != 1);
    if (!plural) {
      (*(Targets.begin()))->NameIP(targetstr, sizeof(targetstr));
    } else snprintf(targetstr, sizeof(targetstr), "%d hosts", (int) Targets.size());
    log_write(LOG_STDOUT, "Scanning %s [%d port%s%s]\n", targetstr, USI->gstats->numprobes, (USI->gstats->numprobes != 1)? "s" : "", plural? "/host" : "");
  }

  begin_sniffer(USI, Targets);
  while(USI->numIncompleteHosts() != 0) {
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
       /* Get the Completion percent */
       
       list<HostScanStats *>::iterator hostI;
       HostScanStats *host = NULL;
       int maxtries;
       double thishostpercdone;
       double avgdone = USI->gstats->numtargets - USI->numIncompleteHosts();
       /* next for the partially finished hosts */
       for(hostI = USI->incompleteHosts.begin(); 
           hostI != USI->incompleteHosts.end(); hostI++) {
          host = *hostI;
          maxtries = host->allowedTryno(NULL, NULL) + 1;
          // This is inexact (maxtries - 1) because of numprobes_sent includes
          // at least one try of ports_finished.
          thishostpercdone = host->ports_finished * (maxtries -1) + host->numprobes_sent;
          thishostpercdone /= maxtries * USI->gstats->numprobes;
          if (thishostpercdone >= .9999) thishostpercdone = .9999;
          avgdone += thishostpercdone;
       }
       avgdone /= USI->gstats->numtargets;
              
       USI->SPM->printStats(avgdone, NULL); // This prints something like SYN Stealth Scan Timing: About 1.14% done; ETC: 15:01 (0:43:23 remaining);
       
       log_flush(LOG_STDOUT);

    }
  }

  if (o.verbose) {
    char additional_info[128];
    if (USI->gstats->num_hosts_timedout == 0)
      snprintf(additional_info, sizeof(additional_info), "%lu total %s",
		(unsigned long) USI->gstats->numprobes * Targets.size(), 
		(scantype == PING_SCAN_ARP)? "hosts" : "ports");
    else snprintf(additional_info, sizeof(additional_info), "%d %s timed out",
		   USI->gstats->num_hosts_timedout, 
		   (USI->gstats->num_hosts_timedout == 1)? "host" : "hosts");
    USI->SPM->endTask(NULL, additional_info);
  }
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

  snprintf(targetstr, 20, "%d,%d,%d,%d,", UC(t[0]), UC(t[1]), UC(t[2]), UC(t[3]));

  starttime = time(NULL);
  if (o.verbose || o.debugging) {
    struct tm *tm = localtime(&starttime);
    assert(tm);
    log_write(LOG_STDOUT, "Initiating TCP ftp bounce scan against %s at %02d:%02d\n", target->NameIP(hostname, sizeof(hostname)), tm->tm_hour, tm->tm_min );
  }
  for(i=0; i < numports; i++) {

    /* Check for timeout */
    if (target->timedOut(NULL))
      return;

    portno = htons(portarray[i]);
    p1 = ((unsigned char *) &portno)[0];
    p2 = ((unsigned char *) &portno)[1];
    snprintf(command, 512, "PORT %s%i,%i\r\n", targetstr, p1,p2);
    if (o.debugging) log_write(LOG_STDOUT, "Attempting command: %s", command);
    if (send(sd, command, strlen(command), 0) < 0 ) {
      perror("send in bounce_scan");
      if (retriesleft) {
	if (o.verbose || o.debugging) 
	  log_write(LOG_STDOUT, "Our ftp proxy server hung up on us!  retrying\n");
	retriesleft--;
	close(sd);
	ftp->sd = ftp_anon_connect(ftp);
	if (ftp->sd < 0) return;
	sd = ftp->sd;
	i--;
      }
      else {
	fprintf(stderr, "Our socket descriptor is dead and we are out of retries. Giving up.\n");
	close(sd);
	ftp->sd = -1;
	return;
      }
    } else { /* Our send is good */
      res = recvtime(sd, recvbuf, 2048, 15, NULL);
      if (res <= 0) 
	perror("recv problem from ftp bounce server\n");
  
      else { /* our recv is good */
	recvbuf[res] = '\0';
	if (o.debugging) log_write(LOG_STDOUT, "result of port query on port %i: %s", 
				 portarray[i],  recvbuf);
	if (recvbuf[0] == '5') {
	  if (portarray[i] > 1023) {
	    fprintf(stderr, "Your ftp bounce server sucks, it won't let us feed bogus ports!\n");
	    exit(1);
	  }
	  else {
	    fprintf(stderr, "Your ftp bounce server doesn't allow privileged ports, skipping them.\n");
	    while(i < numports && portarray[i] < 1024) i++;
	    if (!portarray[i]) {
	      fprintf(stderr, "And you didn't want to scan any unpriviliged ports.  Giving up.\n");
	      exit(1);
	    }
	  }  
	}
	else  /* Not an error message */
	  if (send(sd, "LIST\r\n", 6, 0) > 0 ) {
	    res = recvtime(sd, recvbuf, 2048,12, &timedout);
	    if (res < 0) {
	      perror("recv problem from ftp bounce server\n");
	    } else if (res == 0) {
	      if (timedout)
		target->ports.addPort(portarray[i], IPPROTO_TCP, NULL, 
				      PORT_FILTERED);
	      else target->ports.addPort(portarray[i], IPPROTO_TCP, NULL, 
					 PORT_CLOSED);
	    } else {
	      recvbuf[res] = '\0';
	      if (o.debugging) log_write(LOG_STDOUT, "result of LIST: %s", recvbuf);
	      if (!strncmp(recvbuf, "500", 3)) {
		/* fuck, we are not aligned properly */
		if (o.verbose || o.debugging)
		  fprintf(stderr, "FTP command misalignment detected ... correcting.\n");
		res = recvtime(sd, recvbuf, 2048,10, NULL);
	      }
	      if (recvbuf[0] == '1' || recvbuf[0] == '2') {
		target->ports.addPort(portarray[i], IPPROTO_TCP, NULL, PORT_OPEN);
		if (recvbuf[0] == '1') {
		  res = recvtime(sd, recvbuf, 2048,5, NULL);
		  recvbuf[res] = '\0';
		  if (res > 0) {
		    if (o.debugging) log_write(LOG_STDOUT, "nxt line: %s", recvbuf);
		    if (recvbuf[0] == '4' && recvbuf[1] == '2' && 
			recvbuf[2] == '6') {	      	
		      target->ports.removePort(portarray[i], IPPROTO_TCP);
		      if (o.debugging || o.verbose)
			log_write(LOG_STDOUT, "Changed my mind about port %i\n", portarray[i]);
		    }
		  }
		}
	      } else {
		/* This means the port is closed ... */
		target->ports.addPort(portarray[i], IPPROTO_TCP, NULL, PORT_CLOSED);
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
  int tries = 0;
  time_t starttime;
  struct timeval starttm;
  struct portinfo *scan = NULL,  *current, *next;
  struct portinfolist pil;
  struct timeval now;
  struct connectsockinfo csi;
  struct rpcscaninfo rsi;
  unsigned long j;
  struct serviceDeductions sd;
  bool doingOpenFiltered = false;

  ScanProgressMeter *SPM = NULL;

  if (target->timedOut(NULL))
    return;

  if (scantype != RPC_SCAN)
    fatal("pos_scan now handles only rpc scan");

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

  FD_ZERO(&csi.fds_read);
  FD_ZERO(&csi.fds_write);
  FD_ZERO(&csi.fds_except);
  csi.maxsd = 0;

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

  memset(csi.socklookup, 0, sizeof(csi.socklookup));

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
    if (tries > 3 && tries < 10) {
      senddelay += 10000 * (tries - 3); 
      if (o.verbose) log_write(LOG_STDOUT, "Bumping up senddelay by %d (to %d), due to excessive drops\n", 10000 * (tries - 3), senddelay);
    } else if (tries >= 10) {
      senddelay += 75000; 
      if (o.verbose) log_write(LOG_STDOUT, "Bumping up senddelay by 75000 (to %d), due to excessive drops\n", senddelay);
    }
    
    if (senddelay > 200000) {
      ss.max_width = MIN(ss.max_width, 5);
      ss.numqueries_ideal = MIN(ss.max_width, ss.numqueries_ideal);
    }

    if (target->timedOut(NULL))
      goto posscan_timedout;

    /* Make sure we have ports left to scan */
    while(1) {
      if (doingOpenFiltered) {
	rsi.rpc_current_port = target->ports.nextPort(rsi.rpc_current_port, TCPANDUDP, 
						      PORT_OPENFILTERED);
      } else {
	rsi.rpc_current_port = target->ports.nextPort(rsi.rpc_current_port,
						      TCPANDUDP, PORT_OPEN);
	if (!rsi.rpc_current_port && !o.servicescan) {
	  doingOpenFiltered = true;
	  continue;
	}
      }
      // When service scan is in use, we only want to scan ports that have already
      // been determined to be RPC
      
      if (!o.servicescan)
	break; // We do all open ports if no service scan
      if (!rsi.rpc_current_port) 
	break; // done!
      rsi.rpc_current_port->getServiceDeductions(&sd);
      if (sd.name && sd.service_tunnel == SERVICE_TUNNEL_NONE && 
	  strcmp(sd.name, "rpc") == 0)
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
      char scanname[32];
      snprintf(scanname, sizeof(scanname), "%s against %s", scantype2str(scantype), target->NameIP());
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
		if (send_rpc_query(target->v4hostip(), rsi.rpc_current_port->portno,
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
	    if (send_rpc_query(target->v4hostip(), 
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
    
    rsi.rpc_current_port->setRPCProbeResults(rsi.rpc_status, rsi.rpc_program, 
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
    ss.numqueries_outstanding = 0;
    /* Now we out o' here! */
    continue;
    
    if (ss.numqueries_outstanding != 0) {
      fatal("Bean counting error no. 4321897: ports_left: %d numqueries_outstanding: %d\n", ss.ports_left, ss.numqueries_outstanding);
    }

    tries++;

    if (o.debugging) {
      log_write(LOG_STDOUT, "Finished round #%d. Current stats: numqueries_ideal: %d; min_width: %d; max_width: %d; packet_incr: %d; senddelay: %dus; fallback: %d%%\n", tries, (int) ss.numqueries_ideal, ss.min_width, ss.max_width, ss.packet_incr, senddelay, (int) (100 * ss.fallback_percent));
    }
    ss.numqueries_ideal = ss.initial_packet_width;
    
  } while(pil.testinglist && tries < 20);
  
  if (tries == 20) {
    error("WARNING: GAVE UP ON SCAN AFTER 20 RETRIES");
  }

  numports = rpcportsscanned;
  if (SPM && o.verbose && (numports > 0)) {
    char scannedportsstr[14];
    snprintf(scannedportsstr, sizeof(scannedportsstr), "%d %s", numports, (numports > 1)? "ports" : "port");
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
