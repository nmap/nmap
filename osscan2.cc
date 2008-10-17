
/***************************************************************************
 * osscan2.cc -- Routines used for 2nd Generation OS detection via         *
 * TCP/IP fingerprinting.  * For more information on how this works in     *
 * Nmap, see http://nmap.org/osdetect/                                     *
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

/* $Id: osscan.cc 3636 2006-07-04 23:04:56Z fyodor $ */

#include "osscan.h"
#include "osscan2.h"
#include "timing.h"
#include "NmapOps.h"
#include "Target.h"
#include "utils.h"
#include <dnet.h>
#include <list>

#define NUM_FPTESTS    13
/* The number of tries we normally do.  This may be increased if
   the target looks like a good candidate for fingerprint submission, or fewer
   if the user gave the --max-os-tries option */
#define STANDARD_OS2_TRIES 2

// The minimum (and target) amount of time to wait between probes
// sent to a single host, in milliseconds.
#define OS_PROBE_DELAY 25

// The target amount of time to wait between sequencing probes sent to
// a single host, in milliseconds.  The ideal is 500ms because of the
// common 2Hz timestamp frequencies.  Less than 500ms and we might not
// see any change in the TS counter (and it gets less accurate even if
// we do).  More than 500MS and we risk having two changes (and it
// gets less accurate even if we have just one).  So we delay 100MS
// between probes, leaving 500MS between 1st and 6th.

#define OS_SEQ_PROBE_DELAY 100

using namespace std;
extern NmapOps o;

/* 8 options:
 *  0~5: six options for SEQ/OPS/WIN/T1 probes.
 *  6:   ECN probe.
 *  7-12:   T2~T7 probes.
 *
 * option 0: WScale (10), Nop, MSS (1460), Timestamp, SackP
 * option 1: MSS (1400), WScale (0), SackP, T(0xFFFFFFFF,0x0), EOL
 * option 2: T(0xFFFFFFFF, 0x0), Nop, Nop, WScale (5), Nop, MSS (640)
 * option 3: SackP, T(0xFFFFFFFF,0x0), WScale (10), EOL
 * option 4: MSS (536), SackP, T(0xFFFFFFFF,0x0), WScale (10), EOL
 * option 5: MSS (265), SackP, T(0xFFFFFFFF,0x0)
 * option 6: WScale (10), Nop, MSS (1460), SackP, Nop, Nop
 * option 7-11: WScale (10), Nop, MSS (265), T(0xFFFFFFFF,0x0), SackP
 * option 12: WScale (15), Nop, MSS (265), T(0xFFFFFFFF,0x0), SackP
 */
static struct {
  u8* val;
  int len;
} prbOpts[] = {
  {(u8*) "\003\003\012\001\002\004\005\264\010\012\377\377\377\377\000\000\000\000\004\002", 20},
  {(u8*) "\002\004\005\170\003\003\000\004\002\010\012\377\377\377\377\000\000\000\000\000", 20},
  {(u8*) "\010\012\377\377\377\377\000\000\000\000\001\001\003\003\005\001\002\004\002\200", 20},
  {(u8*) "\004\002\010\012\377\377\377\377\000\000\000\000\003\003\012\000", 16},
  {(u8*) "\002\004\002\030\004\002\010\012\377\377\377\377\000\000\000\000\003\003\012\0", 20},
  {(u8*) "\002\004\001\011\004\002\010\012\377\377\377\377\000\000\000\000", 16},
  {(u8*) "\003\003\012\001\002\004\005\264\004\002\001\001", 12},
  {(u8*) "\003\003\012\001\002\004\001\011\010\012\377\377\377\377\000\000\000\000\004\002", 20},
  {(u8*) "\003\003\012\001\002\004\001\011\010\012\377\377\377\377\000\000\000\000\004\002", 20},
  {(u8*) "\003\003\012\001\002\004\001\011\010\012\377\377\377\377\000\000\000\000\004\002", 20},
  {(u8*) "\003\003\012\001\002\004\001\011\010\012\377\377\377\377\000\000\000\000\004\002", 20},
  {(u8*) "\003\003\012\001\002\004\001\011\010\012\377\377\377\377\000\000\000\000\004\002", 20},
  {(u8*) "\003\003\017\001\002\004\001\011\010\012\377\377\377\377\000\000\000\000\004\002", 20}
};

/* Numbering is the same as for prbOpts[] */
u16 prbWindowSz[] = { 1, 63, 4, 4, 16, 512, 3, 128, 256, 1024, 31337, 32768, 65535 };


/* A global now. Updated after potentially meaningful delays. This can
 * be used to save a call to gettimeofday()
 */
static struct timeval now;

class OFProbe;
class HostOsScanStats;
class HostOsScan;
class HostOsScanInfo;
class OsScanInfo;

/* Performance tuning variable. */
struct os_scan_performance_vars {
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
} perf;

/* Some of the algorithms used here are TCP congestion control
   techniques from RFC2581. */
struct osscan_timing_vals {
  double cwnd; /* Congestion window - in probes */
  
  /* The threshold after which mode is changed from QUICK_START to
     CONGESTION_CONTROL */
  int ccthresh;
  
  /* Number of updates to this utv (generally packet receipts ) */
  int num_updates;
  
  /* Last time values were adjusted for a drop (you usually only want
     to adjust again based on probes sent after that adjustment so a
     sudden batch of drops doesn't destroy timing.  Init to now */
  struct timeval last_drop;
};

typedef enum OFProbeType {
  OFP_UNSET,
  OFP_TSEQ,
  OFP_TOPS,
  OFP_TECN,
  OFP_T1_7,
  OFP_TICMP,
  OFP_TUDP
} OFProbeType;

class OFProbe
{
public:
  OFProbe();
  
  /* The literal string for the current probe type. */
  const char *typestr();

  /* Type of the probe: for what os fingerprinting test? */
  OFProbeType type;

  /* Subid of this probe to separate different tcp/udp/icmp. */
  int subid;

  int tryno; /* Try (retransmission) number of this probe */
  
  /* A packet may be timedout for a while before being retransmitted
     due to packet sending rate limitations */
  bool retransmitted;
  
  struct timeval sent;
  
  /* Time the previous probe was sent, if this is a retransmit (tryno > 0) */
  struct timeval prevSent;
};

/*
 * HostOsScanStats stores the status for a host being scanned 
 * in a scan round.
 */
class HostOsScanStats
{
  friend class HostOsScan;
public:
  HostOsScanStats(Target *t);
  ~HostOsScanStats();
  void initScanStats();
  
  void addNewProbe(OFProbeType type, int subid);
  void removeActiveProbe(list<OFProbe *>::iterator probeI);

/* Get an active probe from active probe list identified by probe type
   and subid.  returns probesActive.end() if there isn't one. */
  list<OFProbe *>::iterator getActiveProbe(OFProbeType type, int subid);
  void moveProbeToActiveList(list<OFProbe *>::iterator probeI);
  void moveProbeToUnSendList(list<OFProbe *>::iterator probeI);
  unsigned int numProbesToSend() {return probesToSend.size();}
  unsigned int numProbesActive() {return probesActive.size();}

  FingerPrint *getFP() {fpPassed = true; return FP;}
  
  Target *target; /* the Target */
  struct seq_info si;
  struct ipid_info ipid;

  /*
   * distance, distance_guess: hop count between us and the target.
   *
   * Possible values of distance:
   *   0: when scan self;
   *   1: when scan a target on the same network segment;
   * >=1: not self, not same network and nmap has got the icmp reply to the U1 probe.
   *  -1: none of the above situations.
   *
   * Possible values of distance_guess:
   *  -1: nmap fails to get a valid ttl by all kinds of probes.
   * >=1: a guessing value based on ttl.
   */
  int distance;
  int distance_guess;
  
  /* Returns the amount of time taken between sending 1st tseq probe
     and the last one.  Zero is
     returned if we didn't send the tseq probes because there was no
     open tcp port */
  double timingRatio();

private:
  /* Ports of the targets used in os fingerprinting. */  
  int openTCPPort, closedTCPPort, closedUDPPort;

  /* Probe list used in tests. At first, probes are linked in
   * probesToSend; when a probe is sent, it will be removed from
   * probesToSend and appended to probesActive. If any probes in
   * probesActive are timedout, they will be moved to probesToSend and
   * sent again till expired.
   */  
  list<OFProbe *> probesToSend;
  list<OFProbe *> probesActive;

  /* A record of total number of probes that have been sent to this
   * host, including restranmited ones. */
  unsigned int num_probes_sent;
  /* Delay between two probes. */
  unsigned int sendDelayMs;
  /* When the last probe is sent. */
  struct timeval lastProbeSent;

  struct osscan_timing_vals timing;

  /*
   * Fingerprint of this target. When a scan is completed, it'll
   * finally be passed to hs->target->FPR->FPs[x].
   */
  FingerPrint *FP;
  FingerPrint *FPtests[NUM_FPTESTS];
#define FP_TSeq  FPtests[0]
#define FP_TOps  FPtests[1]
#define FP_TWin  FPtests[2]
#define FP_TEcn  FPtests[3]
#define FP_T1_7_OFF 4
#define FP_T1    FPtests[4]
#define FP_T2    FPtests[5]
#define FP_T3    FPtests[6]
#define FP_T4    FPtests[7]
#define FP_T5    FPtests[8]
#define FP_T6    FPtests[9]
#define FP_T7    FPtests[10]
#define FP_TUdp  FPtests[11]
#define FP_TIcmp FPtests[12]
  struct AVal *TOps_AVs[6]; /* 6 AVs of TOps */
  struct AVal *TWin_AVs[6]; /* 6 AVs of TWin */

  /* Whether the above FPs is passed. If not and the hss stats is to be
	 deleted, delete the FPs. This happens when the host is timedout
	 during the scan. */
  bool fpPassed;

  /* The following are variables to store temporary results
   * during the os fingerprinting process of this host.
   */
  u16 lastipid;
  struct timeval seq_send_times[NUM_SEQ_SAMPLES];

  int TWinReplyNum; /* how many TWin replies are received. */
  int TOpsReplyNum; /* how many TOps replies are received. Actually it is the same with TOpsReplyNum. */

  struct ip *icmpEchoReply; /* To store one of the two icmp replies */
  int storedIcmpReply; /* Which one of the two icmp replies is stored? */
  
  struct udpprobeinfo upi; /* info of the udp probe we sent */
};

/* These are statistics for the whole group of Targets */
class ScanStats {
public:
  ScanStats();

  /* Returns true if the system says that sending is OK. */
  bool sendOK();

  struct osscan_timing_vals timing;
  struct timeout_info to; /* rtt/timeout info */
  
  /* Total number of active probes */
  int num_probes_active;
  /* Number of probes sent in total. */
  int num_probes_sent;
  int num_probes_sent_at_last_wait;
};

/*
 * HostOsScan does the scan job, setting and using the status of a host in
 * the host's HostOsScanStats.
 */
class HostOsScan
{
public:
  HostOsScan(Target *t); /* OsScan need a target to set eth stuffs */
  ~HostOsScan();
  
  pcap_t *pd;
  ScanStats *stats;
  
  /* (Re)Initial the parameters that will be used during the scan.*/
  void reInitScanSystem();

  void buildSeqProbeList(HostOsScanStats *hss);
  void updateActiveSeqProbes(HostOsScanStats *hss);
  
  void buildTUIProbeList(HostOsScanStats *hss);
  void updateActiveTUIProbes(HostOsScanStats *hss);

  /* send the next probe in the probe list of the hss */
  void sendNextProbe(HostOsScanStats *hss);
  
  /* Process one response.
   * If the response is useful, return true. */
  bool processResp(HostOsScanStats *hss, struct ip *ip, unsigned int len, struct timeval *rcvdtime);
  
  /* Make up the fingerprint. */
  void makeFP(HostOsScanStats *hss);

  /* Check whether the host is sendok. If not, fill _when_ with the
   * time when it will be sendOK and return false; else, fill it with
   * now and return true.
   */
  bool hostSendOK(HostOsScanStats *hss, struct timeval *when);

  /* Check whether it is ok to send the next seq probe to the host. If
   * not, fill _when_ with the time when it will be sendOK and return
   * false; else, fill it with now and return true.
   */
  bool hostSeqSendOK(HostOsScanStats *hss, struct timeval *when);

  
  /* How long I am currently willing to wait for a probe response
     before considering it timed out.  Uses the host values from
     target if they are available, otherwise from gstats.  Results
     returned in MICROseconds.  */
  unsigned long timeProbeTimeout(HostOsScanStats *hss);

  /* If there are pending probe timeouts, fills in when with the time
   * of the earliest one and returns true.  Otherwise returns false
   * and puts now in when.
   */
  bool nextTimeout(HostOsScanStats *hss, struct timeval *when);

  /* Adjust various timing variables based on pcket receipt. */
  void adjust_times(HostOsScanStats *hss, OFProbe *probe, struct timeval *rcvdtime);

private:
  /* Probe send functions. */
  void sendTSeqProbe(HostOsScanStats *hss, int probeNo);
  void sendTOpsProbe(HostOsScanStats *hss, int probeNo);
  void sendTEcnProbe(HostOsScanStats *hss);
  void sendT1_7Probe(HostOsScanStats *hss, int probeNo);
  void sendTUdpProbe(HostOsScanStats *hss, int probeNo);
  void sendTIcmpProbe(HostOsScanStats *hss, int probeNo);
  /* Response process functions. */
  bool processTSeqResp(HostOsScanStats *hss, struct ip *ip, int replyNo);
  bool processTOpsResp(HostOsScanStats *hss, struct tcp_hdr *tcp, int replyNo);
  bool processTWinResp(HostOsScanStats *hss, struct tcp_hdr *tcp, int replyNo);
  bool processTEcnResp(HostOsScanStats *hss, struct ip *ip);
  bool processT1_7Resp(HostOsScanStats *hss, struct ip *ip, int replyNo);
  bool processTUdpResp(HostOsScanStats *hss, struct ip *ip);
  bool processTIcmpResp(HostOsScanStats *hss, struct ip *ip, int replyNo);

  void makeTSeqFP(HostOsScanStats *hss);
  void makeTOpsFP(HostOsScanStats *hss);
  void makeTWinFP(HostOsScanStats *hss);

  bool get_tcpopt_string(struct tcp_hdr *tcp, int mss, char *result, int maxlen);

  int rawsd; /* raw socket descriptor */
  struct eth_nfo eth;
  struct eth_nfo *ethptr; /* for passing to send_ functions */
  
  unsigned int tcpSeqBase, tcpAck; /* Seq&Ack value used in TCP probes */
  int tcpMss; /* tcp Mss value used in TCP probes */
  int udpttl; /* ttl value used in udp probe. */
  unsigned short icmpEchoId, icmpEchoSeq; /* Icmp Echo Id&Seq value used in ICMP probes*/
  
  /* Source port number in TCP probes. Different probe will use
   * arbitrary offset value of it. */
  int tcpPortBase;
  int udpPortBase;
};

/* 
 * The overall os scan information of a host:
 *  - Fingerprints gotten from every scan round;
 *  - Maching results of these fingerprints.
 *  - Is it timeout/completed?
 *  - ...
 */
class HostOsScanInfo
{
public:
  HostOsScanInfo(Target *t, OsScanInfo *OSI);
  ~HostOsScanInfo();
  
  Target *target; /* the Target */
  OsScanInfo *OSI; /* The OSI which contains this HostOsScanInfo */
  FingerPrint **FPs; /* Fingerprints of the host */
  FingerPrintResults *FP_matches; /* Fingerprint-matching results */
  struct seq_info *si;
  bool timedOut;
  bool isCompleted;
  HostOsScanStats *hss; /* Scan status of the host in one scan round */
};

/*
 * Maintain a link of incomplete HostOsScanInfo.
 */
class OsScanInfo
{
public:
  OsScanInfo(vector<Target *> &Targets);
  ~OsScanInfo();
  
  /* If you remove from this, you had better adjust nextI too (or call
     resetHostIterator() afterward). Don't let this list get empty,
     then add to it again, or you may mess up nextI (I'm not sure) */
  list<HostOsScanInfo *> incompleteHosts;
  unsigned int starttimems;

  unsigned int numIncompleteHosts() {return incompleteHosts.size();}
  HostOsScanInfo *findIncompleteHost(struct sockaddr_storage *ss);
  /* A circular buffer of the incompleteHosts.  nextIncompleteHost() gives
     the next one.  The first time it is called, it will give the
     first host in the list.  If incompleteHosts is empty, returns
     NULL. */
  HostOsScanInfo *nextIncompleteHost();
  /* Resets the host iterator used with nextIncompleteHost() to the
     beginning.  If you remove a host from incompleteHosts, call this
     right afterward */
  void resetHostIterator() { nextI = incompleteHosts.begin(); }

  int removeCompletedHosts();
private:
  unsigned int numInitialTargets;
  list<HostOsScanInfo *>::iterator nextI;
};


OFProbe::OFProbe() {
  type = OFP_UNSET;
  subid = 0;
  tryno = -1;
  retransmitted = false;
  memset(&sent, 0, sizeof(sent));
  memset(&prevSent, 0, sizeof(prevSent));
}

const char *OFProbe::typestr() {
  switch(type) {
  case OFP_UNSET:
	return "OFP_UNSET";
  case OFP_TSEQ:
	return "OFP_TSEQ";
  case OFP_TOPS:
	return "OFP_TOPS";
  case OFP_TECN:
	return "OFP_TECN";
  case OFP_T1_7:
	return "OFP_T1_7";
  case OFP_TUDP:
	return "OFP_TUDP";
  case OFP_TICMP:
	return "OFP_TICMP";
  default:
	assert(false);
	return "ERROR";
  }
}

HostOsScanStats::HostOsScanStats(Target * t) {
  int i;
  
  target = t;
  FP = NULL;

  memset(&si, 0, sizeof(si));
  memset(&ipid, 0, sizeof(ipid));

  openTCPPort = -1;
  closedTCPPort = -1;
  closedUDPPort = -1;

  num_probes_sent = 0;
  sendDelayMs = MAX(o.scan_delay, OS_PROBE_DELAY);
  lastProbeSent = now;
  
  /* timing */
  timing.cwnd = perf.host_initial_cwnd;
  timing.ccthresh = perf.initial_ccthresh; /* Will be reduced if any packets are dropped anyway */
  timing.num_updates = 0;
  gettimeofday(&timing.last_drop, NULL);
  
  for (i=0; i<NUM_FPTESTS; i++)
    FPtests[i] = NULL;
  for (i=0; i<6; i++) {
    TOps_AVs[i] = NULL;
    TWin_AVs[i] = NULL;
  }
  fpPassed = true;

  icmpEchoReply = NULL;

  distance = -1;
  distance_guess = -1;
}

HostOsScanStats::~HostOsScanStats() {
  int i;
  
  if(!fpPassed) {
	for(i=0; i<NUM_FPTESTS; i++) {
	  if(FPtests[i]) {
		if(FPtests[i]->results) {
		  free(FPtests[i]->results);
		}
		free(FPtests[i]);
	  }
	}
	for(i=0; i<6; i++) {
	  if(TOps_AVs[i]) free(TOps_AVs[i]);
	  if(TWin_AVs[i]) free(TWin_AVs[i]);
	}
  }
  
  while(!probesToSend.empty()) {
    delete probesToSend.front();
    probesToSend.pop_front();
  }

  while(!probesActive.empty()) {
    delete probesActive.front();
    probesActive.pop_front();
  }

  if (icmpEchoReply) free(icmpEchoReply);
}

void HostOsScanStats::initScanStats() {
  Port *tport = NULL;
  int i;

  /* Lets find an open port to use if we don't already have one */
  openTCPPort = -1;
  /*  target->FPR->osscan_opentcpport = -1;
  target->FPR->osscan_closedtcpport = -1;
  target->FPR->osscan_closedudpport = -1; */
  
  if (target->FPR->osscan_opentcpport > 0)
    openTCPPort = target->FPR->osscan_opentcpport;
  else if ((tport = target->ports.nextPort(NULL, IPPROTO_TCP, PORT_OPEN))) {
    openTCPPort = tport->portno;
    /* If it is zero, let's try another one if there is one ) */
    if (tport->portno == 0)
      if ((tport = target->ports.nextPort(tport, IPPROTO_TCP, PORT_OPEN)))
	openTCPPort = tport->portno;
       
    target->FPR->osscan_opentcpport = openTCPPort;
  }

  /* Now we should find a closed port */
  if (target->FPR->osscan_closedtcpport > 0)
    closedTCPPort = target->FPR->osscan_closedtcpport;
  else if ((tport = target->ports.nextPort(NULL, IPPROTO_TCP, PORT_CLOSED))) {
    closedTCPPort = tport->portno;

    /* If it is zero, let's try another one if there is one ) */
    if (tport->portno == 0)
      if ((tport = target->ports.nextPort(tport, IPPROTO_TCP, PORT_CLOSED)))
	closedTCPPort = tport->portno;

    target->FPR->osscan_closedtcpport = closedTCPPort;
  } else if ((tport = target->ports.nextPort(NULL, IPPROTO_TCP, PORT_UNFILTERED))) {
    /* Well, we will settle for unfiltered */
    closedTCPPort = tport->portno;
    /* But again we'd prefer not to have zero */
    if (tport->portno == 0)
      if ((tport = target->ports.nextPort(tport, IPPROTO_TCP, PORT_UNFILTERED)))
	closedTCPPort = tport->portno;
  } else {
    /* We'll just have to pick one at random :( */
    closedTCPPort = (get_random_uint() % 14781) + 30000;
  }

  /* Now we should find a closed udp port */
  if (target->FPR->osscan_closedudpport > 0)
    closedUDPPort = target->FPR->osscan_closedudpport;
  else if ((tport = target->ports.nextPort(NULL, IPPROTO_UDP, PORT_CLOSED))) {
    closedUDPPort = tport->portno;
    /* Not zero, if possible */
    if (tport->portno == 0)
      if ((tport = target->ports.nextPort(tport, IPPROTO_UDP, PORT_CLOSED)))
	closedUDPPort = tport->portno;
    target->FPR->osscan_closedudpport = closedUDPPort;
  } else if ((tport = target->ports.nextPort(NULL, IPPROTO_UDP, PORT_UNFILTERED))) {
    /* Well, we will settle for unfiltered */
    closedUDPPort = tport->portno;
    /* But not zero, please */
    if (tport->portno == 0)
      if ((tport = target->ports.nextPort(NULL, IPPROTO_UDP, PORT_UNFILTERED)))
	closedUDPPort = tport->portno;
  } else {
    /* Pick one at random.  Shrug. */
    closedUDPPort = (get_random_uint() % 14781) + 30000;
  }

  FP = NULL;
  for (i=0; i<NUM_FPTESTS; i++)
	FPtests[i] = NULL;
  for (i=0; i<6; i++) {
	TOps_AVs[i] = NULL;
	TWin_AVs[i] = NULL;
  }
  
  fpPassed = false;	
  
  TOpsReplyNum = 0;
  TWinReplyNum = 0;

  lastipid = 0;
  memset(&si, 0, sizeof(si));

  for (i=0; i<NUM_SEQ_SAMPLES; i++) {
    ipid.tcp_ipids[i] = -1;
    ipid.icmp_ipids[i] = -1;
  }
  
  memset(&seq_send_times, 0, sizeof(seq_send_times));

  if (icmpEchoReply) {
    free(icmpEchoReply);
    icmpEchoReply = NULL;
  }
  storedIcmpReply = -1;

  memset(&upi, 0, sizeof(upi));  
}

/* Add a probe to the probe list. */
void HostOsScanStats::addNewProbe(OFProbeType type, int subid) {
  OFProbe *probe = new OFProbe();
  probe->type = type;
  probe->subid = subid;
  probesToSend.push_back(probe);
}

/* Remove a probe from the probesActive. */
void HostOsScanStats::removeActiveProbe(list<OFProbe *>::iterator probeI) {
  OFProbe *probe = *probeI;
  probesActive.erase(probeI);
  delete probe;
}

/* Get an active probe from active probe list identified by probe type
   and subid.  Returns probesActive.end() if there isn't one */
list<OFProbe *>::iterator HostOsScanStats::getActiveProbe(OFProbeType type, int subid) {
  list<OFProbe *>::iterator probeI;
  OFProbe *probe = NULL;
  
  for(probeI = probesActive.begin(); probeI != probesActive.end(); probeI++) {
    probe = *probeI;
    if(probe->type == type && probe->subid == subid)
      break;
  }
  
  if(probeI == probesActive.end()) {
    /* not found!? */ 
    if(o.debugging > 1)
      log_write(LOG_PLAIN, "Probe doesn't exist! Probe type: %d. Probe subid: %d\n", type, subid);
    return probesActive.end();
  }
  
  return probeI;
}

/* Move a probe from probesToSend to probesActive. */
void HostOsScanStats::moveProbeToActiveList(list<OFProbe *>::iterator probeI) {
  probesActive.push_back(*probeI);
  probesToSend.erase(probeI);
}

/* Move a probe from probesActive to probesToSend. */
void HostOsScanStats::moveProbeToUnSendList(list<OFProbe *>::iterator probeI) {
  probesToSend.push_back(*probeI);
  probesActive.erase(probeI);
}

 /* Compute the ratio of amount of time taken between sending 1st TSEQ
    probe and 1st ICMP probe compared to the amount of time it should
    have taken.  Ratios far from 1 can cause bogus results */
double HostOsScanStats::timingRatio() {
  if (openTCPPort < 0)
    return 0;
  int msec_ideal = OS_SEQ_PROBE_DELAY * (NUM_SEQ_SAMPLES - 1);
  int msec_taken = TIMEVAL_MSEC_SUBTRACT(seq_send_times[NUM_SEQ_SAMPLES -1 ], 
					 seq_send_times[0]);
  if (o.debugging) {
    log_write(LOG_PLAIN, "OS detection timingRatio() == (%.3f - %.3f) * 1000 / %d == %.3f\n",
	      seq_send_times[NUM_SEQ_SAMPLES - 1].tv_sec + seq_send_times[NUM_SEQ_SAMPLES - 1].tv_usec / 1000000.0, seq_send_times[0].tv_sec + (float) seq_send_times[0].tv_usec / 1000000.0, msec_ideal, (float) msec_taken / msec_ideal);
  }
  return (double) msec_taken / msec_ideal;
}


/* If there are pending probe timeouts, fills in when with the time of
 * the earliest one and returns true.  Otherwise returns false and
 * puts now in when.
 */
bool HostOsScan::nextTimeout(HostOsScanStats *hss, struct timeval *when) {
  assert(hss);
  struct timeval probe_to, earliest_to;
  list<OFProbe *>::iterator probeI;
  bool firstgood = true;

  assert(when);
  memset(&probe_to, 0, sizeof(probe_to));
  memset(&earliest_to, 0, sizeof(earliest_to));

  for(probeI = hss->probesActive.begin(); probeI != hss->probesActive.end(); probeI++) {
    TIMEVAL_ADD(probe_to, (*probeI)->sent, timeProbeTimeout(hss));
    if (firstgood || TIMEVAL_SUBTRACT(probe_to, earliest_to) < 0) {
      earliest_to = probe_to;
      firstgood = false;
    }
  }

  *when = (firstgood)? now : earliest_to;
  return (firstgood)? false : true;
}

void HostOsScan::adjust_times(HostOsScanStats *hss, OFProbe *probe, struct timeval *rcvdtime) {
  assert(hss);
  assert(probe);

  /* Adjust timing */
  if(rcvdtime) {
    adjust_timeouts2(&(probe->sent), rcvdtime, &(hss->target->to));
    adjust_timeouts2(&(probe->sent), rcvdtime, &(stats->to));
  }
  
  hss->timing.num_updates++;
  stats->timing.num_updates++;

  /* Adjust window */
  if (probe->tryno > 0 || !rcvdtime) {
    if (TIMEVAL_SUBTRACT(probe->sent, hss->timing.last_drop) > 0) {
      hss->timing.cwnd = perf.low_cwnd;
      hss->timing.ccthresh = (int) MAX(hss->numProbesActive() / perf.host_drop_ccthresh_divisor, 2);
      hss->timing.last_drop = now;
    }
    if (TIMEVAL_SUBTRACT(probe->sent, stats->timing.last_drop) > 0) {
      stats->timing.cwnd = MAX(perf.low_cwnd, stats->timing.cwnd / perf.group_drop_cwnd_divisor);
      stats->timing.ccthresh = (int) MAX(stats->num_probes_active / perf.group_drop_ccthresh_divisor, 2);
      stats->timing.last_drop = now;
    }
  } else {
    /* Good news -- got a response to first try.  Increase window as 
       appropriate.  */
    if (hss->timing.cwnd <= hss->timing.ccthresh) {
      /* In quick start mode */
      hss->timing.cwnd += perf.quick_incr;
    } else {
      /* Congestion control mode */
      hss->timing.cwnd += perf.cc_incr / hss->timing.cwnd;
    }
    if (hss->timing.cwnd > perf.max_cwnd)
      hss->timing.cwnd = perf.max_cwnd;

    if (stats->timing.cwnd <= stats->timing.ccthresh) {
      /* In quick start mode */
      stats->timing.cwnd += perf.quick_incr;
    } else {
      /* Congestion control mode */
      stats->timing.cwnd += perf.cc_incr / stats->timing.cwnd;
    }
    if (stats->timing.cwnd > perf.max_cwnd)
      stats->timing.cwnd = perf.max_cwnd;
  }
}

ScanStats::ScanStats() {
  /* init timing val */
  timing.cwnd = perf.group_initial_cwnd;
  timing.ccthresh = perf.initial_ccthresh; /* Will be reduced if any packets are dropped anyway */
  timing.num_updates = 0;
  gettimeofday(&timing.last_drop, NULL);
  
  initialize_timeout_info(&to);
  
  num_probes_active = 0;  
  num_probes_sent = num_probes_sent_at_last_wait = 0;
}

/* Returns true if the os scan system says that sending is OK.*/
bool ScanStats::sendOK() {
  if (num_probes_sent - num_probes_sent_at_last_wait >= 50)
    return false;

  if (timing.cwnd < num_probes_active + 0.5)
    return false;
  
  return true;
}

HostOsScan::HostOsScan(Target *t) {
  pd = NULL;
  rawsd = -1;

  if ((o.sendpref & PACKET_SEND_ETH) &&  t->ifType() == devt_ethernet) {
    memcpy(eth.srcmac, t->SrcMACAddress(), 6);
    memcpy(eth.dstmac, t->NextHopMACAddress(), 6);
    if ((eth.ethsd = eth_open_cached(t->deviceName())) == NULL)
      fatal("%s: Failed to open ethernet device (%s)", __func__, t->deviceName());
    rawsd = -1;
    ethptr = &eth;
  } else {
    /* Init our raw socket */
    if ((rawsd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0 )
      pfatal("socket troubles in %s", __func__);
    unblock_socket(rawsd);
    broadcast_socket(rawsd);
#ifndef WIN32
    sethdrinclude(rawsd);
#endif
    ethptr = NULL;
    eth.ethsd = NULL;
  }

  tcpPortBase = o.magic_port_set? o.magic_port : o.magic_port + get_random_u8();
  udpPortBase = o.magic_port_set? o.magic_port : o.magic_port + get_random_u8();
  reInitScanSystem();

  stats = new ScanStats();
}

HostOsScan::~HostOsScan() {
  if (rawsd >= 0) { close(rawsd); rawsd = -1; }
  if (pd) { pcap_close(pd); pd = NULL; }
  /*
   * No need to close ethptr->ethsd due to caching
   * if (eth.ethsd) { eth_close(eth.ethsd); eth.ethsd = NULL; }
   */
  delete stats;
}

void HostOsScan::reInitScanSystem() {
  tcpSeqBase = get_random_u32();
  tcpAck = get_random_u32();
  tcpMss = 265;
  icmpEchoId = get_random_u16();
  icmpEchoSeq = 295;
  udpttl = (time(NULL) % 14) + 51;
}

/* Initiate seq probe list */
void HostOsScan::buildSeqProbeList(HostOsScanStats *hss) {
  assert(hss);
  int i;
  if(hss->openTCPPort == -1) return;
  if(hss->FP_TSeq) return;

  for(i=0; i<NUM_SEQ_SAMPLES; i++)
    hss->addNewProbe(OFP_TSEQ, i);
}

/* Update the seq probes in the active probe list:
 * o Remove the timedout seq probes.
 */
void HostOsScan::updateActiveSeqProbes(HostOsScanStats *hss) {
  assert(hss);
  list<OFProbe *>::iterator probeI, nxt;
  OFProbe *probe = NULL;

  for(probeI = hss->probesActive.begin(); probeI != hss->probesActive.end();
	  probeI = nxt) {
	nxt = probeI;
	nxt++;
    probe = *probeI;
    
    /* Is the probe timedout? */
    if (TIMEVAL_SUBTRACT(now, probe->sent) > (long) timeProbeTimeout(hss)) {
      hss->removeActiveProbe(probeI);
      stats->num_probes_active--;
    }
  }
}

/* initiate the normal tcp/udp/icmp probe list */
void HostOsScan::buildTUIProbeList(HostOsScanStats *hss) {
  assert(hss);
  int i;

  /* The order of these probes are important for ipid generation
   * algorithm test and should not be changed.
   *
   * At doSeqTests we sent 6 TSeq probes to generate 6 tcp replies,
   * and here we follow with 3 probes to generate 3 icmp replies. In
   * this way we can expect to get "good" IPid sequence.
   *
   * **** Should be done in a more elegant way. *****
   */
  
  /* ticmp */
  if(!hss->FP_TIcmp) {
    for(i=0; i<2; i++) {
      hss->addNewProbe(OFP_TICMP, i);
    }
  }

  /* tudp */
  if(!hss->FP_TUdp) {
    hss->addNewProbe(OFP_TUDP, 0);
  }
  
  if(hss->openTCPPort != -1) {
    /* tops/twin probes. We send the probe again if we didn't get a
	   response by the corresponding seq probe.
	 */
    if(!hss->FP_TOps || !hss->FP_TWin) {
      for(i=0; i<6; i++) {
        if(!hss->TOps_AVs[i] || !hss->TWin_AVs[i])
          hss->addNewProbe(OFP_TOPS, i);
      }
    }

    /* tecn */
    if(!hss->FP_TEcn) {
      hss->addNewProbe(OFP_TECN, 0);
    }

    /* t1_7: t1_t4 */
    for(i=0; i<4; i++) {
      if(!hss->FPtests[FP_T1_7_OFF+i]) {
        hss->addNewProbe(OFP_T1_7, i);
      }
    }
  }

  /* t1_7: t5_t7 */
  for(i=4; i<7; i++) {
    if(!hss->FPtests[FP_T1_7_OFF+i]) {
      hss->addNewProbe(OFP_T1_7, i);
    }
  }
}

/* Update the probes in the active probe list:
 * 1) Remove the expired probes (timedout and reached the retry limit);
 * 2) Move timedout probes to probeNeedToSend;
 */
void HostOsScan::updateActiveTUIProbes(HostOsScanStats *hss) {
  assert(hss);
  list<OFProbe *>::iterator probeI, nxt;
  OFProbe *probe = NULL;

  for(probeI = hss->probesActive.begin(); probeI != hss->probesActive.end();
	  probeI = nxt) {
	nxt = probeI;
	nxt++;
    probe = *probeI;
    
    if(TIMEVAL_SUBTRACT(now, probe->sent) > (long) timeProbeTimeout(hss)) {
      if(probe->tryno >= 3) {
        /* The probe is expired. */
        hss->removeActiveProbe(probeI);
        stats->num_probes_active--;
      }
      else {
        /* It is timedout, move it to the sendlist */
        hss->moveProbeToUnSendList(probeI);
        stats->num_probes_active--;
      }
    }
  }
}

/* Check whether the host is sendok. If not, fill _when_ with the time
 * when it will be sendOK and return false; else, fill it with now and
 * return true.
 */
bool HostOsScan::hostSendOK(HostOsScanStats *hss, struct timeval *when) {
  assert(hss);
  list<OFProbe *>::iterator probeI;
  int packTime;
  struct timeval probe_to, earliest_to, sendTime;
  long tdiff;

  if (hss->target->timedOut(&now)) {
    if (when) *when = now;
    return false;
  }

  if (hss->sendDelayMs > 0) {
    packTime = TIMEVAL_MSEC_SUBTRACT(now, hss->lastProbeSent);
    if (packTime < (int) hss->sendDelayMs) {
      if (when) { TIMEVAL_MSEC_ADD(*when, hss->lastProbeSent, hss->sendDelayMs); }
      return false;
    }
  }

  if (hss->timing.cwnd >= hss->numProbesActive() + .5) {
    if (when) *when = now;
    return true;
  }

  if (!when)
    return false;

  TIMEVAL_MSEC_ADD(earliest_to, now, 10000);

  /* Any timeouts coming up? */
  for(probeI = hss->probesActive.begin(); probeI != hss->probesActive.end(); probeI++) {
    TIMEVAL_MSEC_ADD(probe_to, (*probeI)->sent, timeProbeTimeout(hss) / 1000);
    if (TIMEVAL_SUBTRACT(probe_to, earliest_to) < 0) {
      earliest_to = probe_to;
    }
  }
  
  // Will any scan delay affect this?
  if (hss->sendDelayMs > 0) {
    TIMEVAL_MSEC_ADD(sendTime, hss->lastProbeSent, hss->sendDelayMs);
    if (TIMEVAL_MSEC_SUBTRACT(sendTime, now) < 0)
      sendTime = now;
    tdiff = TIMEVAL_MSEC_SUBTRACT(earliest_to, sendTime);
    
    /* Timeouts previous to the sendTime requirement are pointless,
       and those later than sendTime are not needed if we can send a
       new packet at sendTime */
    if (tdiff < 0) {
      earliest_to = sendTime;
    } else {
      if (tdiff > 0 && hss->timing.cwnd > hss->numProbesActive() + .5) {
        earliest_to = sendTime;
      }
    }
  }

  *when = earliest_to;
  return false;
}

/* Check whether it is ok to send the next seq probe to the host. If
 * not, fill _when_ with the time when it will be sendOK and return
 * false; else, fill it with now and return true.
 */
bool HostOsScan::hostSeqSendOK(HostOsScanStats *hss, struct timeval *when) {
  assert(hss);
  list<OFProbe *>::iterator probeI;
  int packTime = 0, maxWait = 0;
  struct timeval probe_to, earliest_to, sendTime;
  long tdiff;

  if (hss->target->timedOut(&now)) {
    if (when) *when = now;
    return false;
  }

  packTime = TIMEVAL_SUBTRACT(now, hss->lastProbeSent);
  
  /*
   * If the user insist a larger sendDelayMs, use it. But
   * the seq result may be inaccurate.
   */
  maxWait = MAX(OS_SEQ_PROBE_DELAY * 1000, hss->sendDelayMs * 1000);
  if (packTime < maxWait) {
    if (when) { TIMEVAL_ADD(*when, hss->lastProbeSent, maxWait); }
    return false;
  }
  
  if (hss->timing.cwnd >= hss->numProbesActive() + .5) {
    if (when) *when = now;
    return true;
  }

  if (!when)
    return false;

  TIMEVAL_MSEC_ADD(earliest_to, now, 10000);

  /* Any timeouts coming up? */
  for(probeI = hss->probesActive.begin(); probeI != hss->probesActive.end(); probeI++) {
    TIMEVAL_MSEC_ADD(probe_to, (*probeI)->sent, timeProbeTimeout(hss) / 1000);
    if (TIMEVAL_SUBTRACT(probe_to, earliest_to) < 0) {
      earliest_to = probe_to;
    }
  }
  
  TIMEVAL_ADD(sendTime, hss->lastProbeSent, maxWait);
  if (TIMEVAL_SUBTRACT(sendTime, now) < 0)
    sendTime = now;
  tdiff = TIMEVAL_SUBTRACT(earliest_to, sendTime);
    
  /* Timeouts previous to the sendTime requirement are pointless,
     and those later than sendTime are not needed if we can send a
     new packet at sendTime */
  if (tdiff < 0) {
    earliest_to = sendTime;
  } else {
    if (tdiff > 0 && hss->timing.cwnd > hss->numProbesActive() + .5) {
      earliest_to = sendTime;
    }
  }

  *when = earliest_to;
  return false;
}

unsigned long HostOsScan::timeProbeTimeout(HostOsScanStats *hss) {
  assert(hss);
  if (hss->target->to.srtt > 0) {
    /* We have at least one timing value to use.  Good enough, I suppose */
    return hss->target->to.timeout;
  } else if (stats->to.srtt > 0) {
    /* OK, we'll use this one instead */
    return stats->to.timeout;
  } else {
    return hss->target->to.timeout; /* It comes with a default */
  }
}

void HostOsScan::sendNextProbe(HostOsScanStats *hss) {
  assert(hss);
  list<OFProbe *>::iterator probeI;
  OFProbe *probe = NULL;
  
  if(hss->probesToSend.empty())
    return;
  
  probeI = hss->probesToSend.begin();  
  probe = *probeI;

  switch(probe->type) {
  case OFP_TSEQ:
    sendTSeqProbe(hss, probe->subid);
    break;
  case OFP_TOPS:
    sendTOpsProbe(hss, probe->subid);
    break;
  case OFP_TECN:
    sendTEcnProbe(hss);
    break;
  case OFP_T1_7:
    sendT1_7Probe(hss, probe->subid);
    break;
  case OFP_TICMP:
    sendTIcmpProbe(hss, probe->subid);
    break;
  case OFP_TUDP:
    sendTUdpProbe(hss, probe->subid);
    break;
  default:
    assert(false);
  }

  probe->tryno++;
  if(probe->tryno > 0) {
    /* This is a retransmiting */
    probe->retransmitted = true;
    probe->prevSent = probe->sent;
  }
  probe->sent = now;
  
  hss->lastProbeSent = now;
  hss->num_probes_sent++;
  stats->num_probes_sent++;

  hss->moveProbeToActiveList(probeI);

  if (o.debugging > 1) {
    log_write(LOG_PLAIN, "Send probe (type: %s, subid: %d) to %s\n",
              probe->typestr(), probe->subid, hss->target->targetipstr());
  }
  
}

void HostOsScan::sendTSeqProbe(HostOsScanStats *hss, int probeNo) {
  assert(hss);
  assert(probeNo >= 0 && probeNo < NUM_SEQ_SAMPLES);

  if(hss->openTCPPort == -1) return;

  send_tcp_raw_decoys(rawsd, ethptr, hss->target->v4hostip(), o.ttl, false, NULL, 0,
                      tcpPortBase + probeNo, hss->openTCPPort,
                      tcpSeqBase + probeNo, tcpAck, 0,
                      TH_SYN, prbWindowSz[probeNo], 0, prbOpts[probeNo].val, prbOpts[probeNo].len,
		      NULL, 0);

  hss->seq_send_times[probeNo] = now;  
}

void HostOsScan::sendTOpsProbe(HostOsScanStats *hss, int probeNo) {
  assert(hss);
  assert(probeNo>=0 && probeNo< NUM_SEQ_SAMPLES);

  if(hss->openTCPPort == -1) return;
  
  send_tcp_raw_decoys(rawsd, ethptr, hss->target->v4hostip(), o.ttl, false, NULL, 0,
                      tcpPortBase + NUM_SEQ_SAMPLES + probeNo, 
		      hss->openTCPPort, tcpSeqBase, tcpAck, 0, TH_SYN, 
		      prbWindowSz[probeNo], 0, prbOpts[probeNo].val, 
		      prbOpts[probeNo].len, NULL, 0);
}

void HostOsScan::sendTEcnProbe(HostOsScanStats *hss) {
  assert(hss);
  
  if(hss->openTCPPort == -1) return;
  
  send_tcp_raw_decoys(rawsd, ethptr, hss->target->v4hostip(), o.ttl, false, NULL, 0,
                      tcpPortBase + NUM_SEQ_SAMPLES + 6, hss->openTCPPort,
		      tcpSeqBase, 0, 8, TH_CWR|TH_ECE|TH_SYN, prbWindowSz[6], 
		      63477, prbOpts[6].val, prbOpts[6].len, NULL, 0);
}

void HostOsScan::sendT1_7Probe(HostOsScanStats *hss, int probeNo) {
  assert(hss);
  assert(probeNo>=0&&probeNo<7);
  
  int port_base = tcpPortBase + NUM_SEQ_SAMPLES + 7;

  switch(probeNo) {
  case 0: /* T1 */
    if(hss->openTCPPort == -1) return;
    send_tcp_raw_decoys(rawsd, ethptr, hss->target->v4hostip(), o.ttl, false, NULL, 0,
                        port_base, hss->openTCPPort, tcpSeqBase, tcpAck, 0,
                        TH_SYN, prbWindowSz[0], 0, prbOpts[0].val, 
			prbOpts[0].len, NULL, 0);
    break;
  case 1: /* T2 */
    if(hss->openTCPPort == -1) return;
    send_tcp_raw_decoys(rawsd, ethptr, hss->target->v4hostip(), o.ttl, true, NULL, 0,
                        port_base + 1, hss->openTCPPort, tcpSeqBase, tcpAck, 0,
                        0, prbWindowSz[7], 0, prbOpts[7].val, 
                        prbOpts[7].len, NULL, 0);
    break;
  case 2: /* T3 */
    if(hss->openTCPPort == -1) return;
    send_tcp_raw_decoys(rawsd, ethptr, hss->target->v4hostip(), o.ttl, false, NULL, 0,
                        port_base + 2, hss->openTCPPort, tcpSeqBase, tcpAck, 0,
                        TH_SYN|TH_FIN|TH_URG|TH_PUSH, prbWindowSz[8], 0, prbOpts[8].val, 
                        prbOpts[8].len, NULL, 0);
    break;
  case 3: /* T4 */
    if(hss->openTCPPort == -1) return;
    send_tcp_raw_decoys(rawsd, ethptr, hss->target->v4hostip(), o.ttl, true, NULL, 0,
                        port_base + 3, hss->openTCPPort, tcpSeqBase, tcpAck, 0,
                        TH_ACK, prbWindowSz[9], 0, prbOpts[9].val, 
			prbOpts[9].len, NULL, 0);
    break;
  case 4: /* T5 */
    if(hss->closedTCPPort == -1) return;
    send_tcp_raw_decoys(rawsd, ethptr, hss->target->v4hostip(), o.ttl, false, NULL, 0,
                        port_base + 4, hss->closedTCPPort, tcpSeqBase, tcpAck,
			0, TH_SYN, prbWindowSz[10], 0, prbOpts[10].val, 
			prbOpts[10].len, NULL, 0);
    break;
  case 5: /* T6 */
    if(hss->closedTCPPort == -1) return;
    send_tcp_raw_decoys(rawsd, ethptr, hss->target->v4hostip(), o.ttl, true, NULL, 0,
                        port_base + 5, hss->closedTCPPort, tcpSeqBase, tcpAck,
			0, TH_ACK, prbWindowSz[11], 0, prbOpts[11].val, 
			prbOpts[11].len, NULL, 0);
    break;
  case 6: /* T7 */
    if(hss->closedTCPPort == -1) return;
    send_tcp_raw_decoys(rawsd, ethptr, hss->target->v4hostip(), o.ttl, false, NULL, 0,
                        port_base + 6, hss->closedTCPPort, tcpSeqBase, tcpAck,
			0, TH_FIN|TH_PUSH|TH_URG, prbWindowSz[12], 0, prbOpts[12].val, 
			prbOpts[12].len, NULL, 0);
    break;
  }
}

void HostOsScan::sendTIcmpProbe(HostOsScanStats *hss, int probeNo) {
  assert(hss);
  assert(probeNo>=0&&probeNo<2);
  if(probeNo==0) {
    send_icmp_echo_probe(rawsd, ethptr, hss->target->v4hostip(), IP_TOS_DEFAULT,
                         true, 9, icmpEchoId, icmpEchoSeq, 120);
  }
  else {
    send_icmp_echo_probe(rawsd, ethptr, hss->target->v4hostip(), IP_TOS_RELIABILITY,
                         false, 0, icmpEchoId+1, icmpEchoSeq+1, 150);
  }
}

void HostOsScan::sendTUdpProbe(HostOsScanStats *hss, int probeNo) {
  assert(hss);
  
  if(hss->closedUDPPort == -1) return;
  send_closedudp_probe_2(hss->upi, rawsd, ethptr, hss->target->v4hostip(),
			 this->udpttl, udpPortBase + probeNo, 
			 hss->closedUDPPort);
}

bool HostOsScan::processResp(HostOsScanStats *hss, struct ip *ip, unsigned int len, struct timeval *rcvdtime) {
  struct ip *ip2;
  struct tcp_hdr *tcp;
  struct icmp *icmp;
  int testno;
  bool isPktUseful = false;
  list<OFProbe *>::iterator probeI;
  OFProbe *probe;

  if (len < 20 || len < (4 * ip->ip_hl) + 4U)
    return false;

  len -= 4 * ip->ip_hl;
  
  if (ip->ip_p == IPPROTO_TCP) {
    if(len < 20) return false;
    tcp = ((struct tcp_hdr *) (((char *) ip) + 4 * ip->ip_hl));
    if(len < (unsigned int)(4 * tcp->th_off)) return false;
    testno = ntohs(tcp->th_dport) - tcpPortBase;
    
    if (testno >= 0 && testno < NUM_SEQ_SAMPLES) {    
      /* TSeq */
      isPktUseful = processTSeqResp(hss, ip, testno);

      if(isPktUseful) {
        hss->ipid.tcp_ipids[testno] = ntohs(ip->ip_id);
        probeI = hss->getActiveProbe(OFP_TSEQ, testno);
		/* printf("tcp ipid = %d\n", ntohs(ip->ip_id)); */
      }

      /* Use the seq response to do other tests. We don't care if it
       * is useful for these tests.
       */
      if (testno == 0) {
        /* the first reply is used to do T1 */
        processT1_7Resp(hss, ip, 0);
      }
      if (testno<6) {
        /* the 1th~6th replies are used to do TOps and TWin */
        processTOpsResp(hss, tcp, testno);
		processTWinResp(hss, tcp, testno);
      }
	  
    } else if (testno>=NUM_SEQ_SAMPLES && testno<NUM_SEQ_SAMPLES+6) {
      
      /* TOps/Twin */
      isPktUseful = processTOpsResp(hss, tcp, testno - NUM_SEQ_SAMPLES);
	  isPktUseful |= processTWinResp(hss, tcp, testno - NUM_SEQ_SAMPLES);
      if(isPktUseful) {
        probeI = hss->getActiveProbe(OFP_TOPS, testno - NUM_SEQ_SAMPLES);
      }
	  
    } else if (testno==NUM_SEQ_SAMPLES+6) {
      
      /* TEcn */
      isPktUseful = processTEcnResp(hss, ip);
      if(isPktUseful) {
        probeI = hss->getActiveProbe(OFP_TECN, 0);
      }
      
    } else if (testno >= NUM_SEQ_SAMPLES+7 && testno<NUM_SEQ_SAMPLES+14) {

	  isPktUseful = processT1_7Resp(hss, ip, testno-NUM_SEQ_SAMPLES-7);
	  
      if(isPktUseful) {
        probeI = hss->getActiveProbe(OFP_T1_7, testno-NUM_SEQ_SAMPLES-7);
      }
    }
  }
  else if (ip->ip_p == IPPROTO_ICMP) {
    if(len < 8) return false;   
    icmp = ((struct icmp *)(((char *) ip) + 4 * ip->ip_hl));

    /* Is it an icmp echo reply? */
    if (icmp->icmp_type == ICMP_ECHOREPLY) {
      testno = ntohs(icmp->icmp_id) - icmpEchoId;
	  if (testno==0 || testno==1) {
		isPktUseful = processTIcmpResp(hss, ip, testno);
		if(isPktUseful) {
		  probeI = hss->getActiveProbe(OFP_TICMP, testno);
		}

		if(isPktUseful && probeI != hss->probesActive.end() && !(*probeI)->retransmitted) { /* Retransmitted ipid is useless. */
		  hss->ipid.icmp_ipids[testno] = ntohs(ip->ip_id);
		  /* printf("icmp ipid = %d\n", ntohs(ip->ip_id)); */
		}		
	  }
    }

    /* Is it a destination port unreachable? */
    if (icmp->icmp_type == 3 && icmp->icmp_code == 3) {
      len -= 8; /* icmp destination unreachable header len. */
      if(len < 28) return false; /* must larger than an ip and an udp header length */
      ip2 = (struct ip*)((char *)icmp + 8);
      len -= 4 * ip2->ip_hl;
      if(len < 8) return false;

      isPktUseful = processTUdpResp(hss, ip);
      if(isPktUseful) {
        probeI = hss->getActiveProbe(OFP_TUDP, 0);
      }
    }

  }

  if (isPktUseful && probeI != hss->probesActive.end()) {
    probe = *probeI;

    if(rcvdtime)
      adjust_times(hss, probe, rcvdtime);

	if(o.debugging > 1)
	  log_write(LOG_PLAIN, "Got a valid response for probe (type: %s subid: %d) from %s\n",
		    probe->typestr(), probe->subid, hss->target->targetipstr());

    /* delete the probe. */
    hss->removeActiveProbe(probeI);
    this->stats->num_probes_active--;

    return true;
  }
  
  return false;
}

void HostOsScan::makeFP(HostOsScanStats *hss) {
  assert(hss);
  
  int i;
  int last;
  FingerPrint *FP;
  struct AVal *pAV;
  
  int ttl;
  
  if(!hss->FP_TSeq)
    makeTSeqFP(hss);

  if(!hss->FP_TOps)
    makeTOpsFP(hss);

  if(!hss->FP_TWin)
    makeTWinFP(hss);
  
  for(i=3; i < NUM_FPTESTS; i++) {
    if (!hss->FPtests[i] &&
		((i>=3 && i<=7 && hss->openTCPPort !=  -1) ||
		 (i>=8 && i<=10 && hss->target->FPR->osscan_closedtcpport != -1) ||
		 i>=11)) {
      /* We create a Resp (response) attribute with value of N (no) because
         it is important here to note whether responses were or were not 
         received */
      hss->FPtests[i] = (FingerPrint *) safe_zalloc(sizeof(FingerPrint));
      pAV = (struct AVal *) safe_zalloc(sizeof(struct AVal));
      pAV->attribute = (char*)"R";
      strcpy(pAV->value, "N");
      pAV->next = NULL;
      hss->FPtests[i]->results = pAV;
      hss->FPtests[i]->name =  (i == 3)? "ECN" : (i == 4)? "T1" : (i == 5)? "T2" : (i == 6)? "T3" : (i == 7)? "T4" : (i == 8)? "T5" : (i == 9)? "T6" : (i == 10)? "T7" : (i == 11)? "U1" : "IE";
    }
	else if(hss->FPtests[i]) {
	  /* Replace TTL with initial TTL. */
	  for(pAV = hss->FPtests[i]->results; pAV; pAV = pAV->next) {
		if(pAV->attribute == (char*)"T") {
		  /* Found TTL item. The value for this attribute is the
		     received TTL encoded in decimal. We replace it with the
		     initial TTL encoded in hex. */
		  ttl = atoi(pAV->value);

		  if(hss->distance_guess == -1)
			hss->distance_guess = get_initial_ttl_guess(ttl) - ttl;

		  if(hss->distance != -1) {
			/* We've gotten response for the UDP probe and thus have
			   the "true" hop count. Add the received TTL to the hop
			   count to get the initial TTL. */
			sprintf(pAV->value, "%hX", ttl + hss->distance);
		  } else {
			/* Guess the initial TTL value */
			pAV->attribute = (char*) "TG";
			sprintf(pAV->value, "%hX", get_initial_ttl_guess(ttl));
		  }
		  break;
		}
	  }
	}
  }

  /* Link them up. */
  last = -1;
  FP = NULL;
  for(i=0; i < NUM_FPTESTS ; i++) {
    if (!hss->FPtests[i]) continue;
    if (!FP) FP = hss->FPtests[i];
    if (last > -1) {
      hss->FPtests[last]->next = hss->FPtests[i];
    }
    last = i;
  }
  if (last != -1) hss->FPtests[last]->next = NULL;

  /*  printf("%s", fp2ascii(FP)); */

  hss->FP = FP;
}

void HostOsScan::makeTSeqFP(HostOsScanStats *hss) {
  if (!hss->si.responses) return;
  
  int i,j;
  u32 seq_diffs[NUM_SEQ_SAMPLES];
  u32 ts_diffs[NUM_SEQ_SAMPLES];
  float seq_rates[NUM_SEQ_SAMPLES];
  unsigned long time_usec_diffs[NUM_SEQ_SAMPLES];
  int avnum;
  double seq_stddev = 0;
  double seq_rate = 0;
  double seq_avg_rate = 0;
  double avg_ts_hz = 0.0; /* Avg. amount that timestamps incr. each second */
  u32 seq_gcd = 1;
  int tcp_ipid_seqclass; /* TCP IPID SEQ TYPE defines in nmap.h */
  int icmp_ipid_seqclass; /* ICMP IPID SEQ TYPE defines in nmap.h */
  int good_tcp_ipid_num, good_icmp_ipid_num;
  int tsnewval = 0;

  struct AVal *seq_AVs;

  /* Now we make sure there are no gaps in our response array ... */
  for(i=0, j=0; i < NUM_SEQ_SAMPLES; i++) {
    if (hss->si.seqs[i] != 0) /* We found a good one */ {
      if (j < i) {
        hss->si.seqs[j] = hss->si.seqs[i];
        hss->si.ipids[j] = hss->si.ipids[i];
        hss->si.timestamps[j] = hss->si.timestamps[i];
        hss->seq_send_times[j] = hss->seq_send_times[i];
      }
      if (j > 0) {
        seq_diffs[j - 1] = MOD_DIFF(hss->si.seqs[j], hss->si.seqs[j - 1]);

        ts_diffs[j - 1] = MOD_DIFF(hss->si.timestamps[j], hss->si.timestamps[j - 1]);
        time_usec_diffs[j - 1] = TIMEVAL_SUBTRACT(hss->seq_send_times[j], hss->seq_send_times[j - 1]);
        if (!time_usec_diffs[j - 1]) time_usec_diffs[j - 1]++; /* We divide by this later */
	/* Rate of ISN increase per second */
	seq_rates[j - 1] = seq_diffs[j-1] * 1000000.0 / time_usec_diffs[j-1];
	seq_avg_rate += seq_rates[j-1];
      }
      j++;
    } /* Otherwise nothing good in this slot to copy */
  }
  
  hss->si.responses = j; /* Just for assurance */
  seq_avg_rate /= hss->si.responses - 1;
  seq_rate = seq_avg_rate;

  /* Now we look at TCP Timestamp sequence prediction */
  /* Battle plan:
     1) Compute average increments per second, and variance in incr. per second 
     2) If any are 0, set to constant
     3) If variance is high, set to random incr. [ skip for now ]
     4) if ~10/second, set to appropriate thing
     5) Same with ~100/sec
  */
  if (hss->si.ts_seqclass == TS_SEQ_UNKNOWN && hss->si.responses >= 2) {
    avg_ts_hz = 0.0;
    for(i=0; i < hss->si.responses - 1; i++) {
      double dhz;

      dhz = (double) ts_diffs[i] / (time_usec_diffs[i] / 1000000.0);
      /*       printf("ts incremented by %d in %li usec -- %fHZ\n", ts_diffs[i], time_usec_diffs[i], dhz); */
      avg_ts_hz += dhz / ( hss->si.responses - 1);
    }

    if (avg_ts_hz > 0 && avg_ts_hz < 5.66) { /* relatively wide range because sampling time so short and frequency so slow */
      hss->si.ts_seqclass = TS_SEQ_2HZ;
      hss->si.lastboot = hss->seq_send_times[0].tv_sec - (hss->si.timestamps[0] / 2); 
    }
    else if (avg_ts_hz > 70 && avg_ts_hz < 150) {
      hss->si.ts_seqclass = TS_SEQ_100HZ;
      hss->si.lastboot = hss->seq_send_times[0].tv_sec - (hss->si.timestamps[0] / 100);
    }
    else if (avg_ts_hz > 724 && avg_ts_hz < 1448) {
      hss->si.ts_seqclass = TS_SEQ_1000HZ;
      hss->si.lastboot = hss->seq_send_times[0].tv_sec - (hss->si.timestamps[0] / 1000); 
    }
    else if (avg_ts_hz > 0) {
      hss->si.ts_seqclass = TS_SEQ_OTHER_NUM;
      hss->si.lastboot = hss->seq_send_times[0].tv_sec - (hss->si.timestamps[0] / (unsigned int)(0.5 + avg_ts_hz));
    }
    
    if (hss->si.lastboot && (hss->seq_send_times[0].tv_sec - hss->si.lastboot > 63072000)) {
      /* Up 2 years?  Perhaps, but they're probably lying. */
      if (o.debugging) {
        error("Ignoring claimed %s uptime of %lu days", 
	      hss->target->targetipstr(),
              (hss->seq_send_times[0].tv_sec - hss->si.lastboot) / 86400);
      }
      hss->si.lastboot = 0;
    }
  }
  
  /* Time to look at the TCP ISN predictability */
  if (hss->si.responses >= 4 && o.scan_delay <= 1000) {

    /* First calculate the GCD */
    seq_gcd = gcd_n_uint(hss->si.responses -1, seq_diffs);

    if (!seq_gcd) {
      /* Constant ISN */
      seq_rate = 0;
      seq_stddev = 0;
      hss->si.index = 0;
    } else {

      /* Finally we take a binary logarithm, multiply by 8, and round
	 to get the final result */
      seq_rate = log(seq_rate) / log(2.0);
      seq_rate = (unsigned int) (seq_rate * 8 + 0.5);

      /* Normally we don't divide by gcd in computing the rate stddev
	 because otherwise we'll get an artificially low value about
	 1/32 of the time if the responses all happen to be even.  On
	 the other hand, if a system inherently uses a large gcd such
	 as 64,000, we want to get rid of it.  So as a compromise, we
	 divide by the gcd if it is at least 9 */

      int div_gcd = 1;
      if (seq_gcd > 9)
	div_gcd = seq_gcd;

      for(i=0; i < hss->si.responses - 1; i++) {     
	double rtmp = seq_rates[i] / div_gcd - seq_avg_rate / div_gcd;
	seq_stddev += rtmp * rtmp;
      }

      /* We divide by ((numelements in seq_diffs) - 1), which is
	 (si.responses - 2), because that gives a better approx of
	 std. dev when you're only looking at a subset of whole
	 population. */
      seq_stddev /= hss->si.responses - 2;

      /* Next we need to take the square root of this value */
      seq_stddev = sqrt(seq_stddev);

      /* Finally we take a binary logarithm, multiply by 8, and round
	 to get the final result */
      if (seq_stddev <= 1)
	hss->si.index = 0;
      else {
	seq_stddev = log(seq_stddev) / log(2.0);
	hss->si.index = (int) (seq_stddev * 8 + 0.5);
      }
    }

    /* Time to generate the SEQ probe line of the fingerprint */
    hss->FP_TSeq = (FingerPrint *) safe_zalloc(sizeof(FingerPrint));
    hss->FP_TSeq->name = "SEQ";
    seq_AVs = (struct AVal *) safe_zalloc(sizeof(struct AVal) * 7);
    hss->FP_TSeq->results = seq_AVs;
    avnum = 0;

    seq_AVs[avnum].attribute = (char*)"SP";
    sprintf(seq_AVs[avnum].value, "%X", hss->si.index);
    seq_AVs[avnum].next = &seq_AVs[avnum+1]; avnum++;
    seq_AVs[avnum].attribute = (char*)"GCD";
    sprintf(seq_AVs[avnum].value, "%X", seq_gcd);
    seq_AVs[avnum].next = &seq_AVs[avnum+1]; avnum++;
    seq_AVs[avnum].attribute = (char*)"ISR";     
    sprintf(seq_AVs[avnum].value, "%X", (unsigned int) seq_rate);

    /* Now it is time to deal with IPIDs */
    good_tcp_ipid_num = 0;
    good_icmp_ipid_num = 0;
    
    for(i=0; i < NUM_SEQ_SAMPLES; i++) {
      if (hss->ipid.tcp_ipids[i] != -1) {
	if (good_tcp_ipid_num < i) {
	  hss->ipid.tcp_ipids[good_tcp_ipid_num] = hss->ipid.tcp_ipids[i];
	}
	good_tcp_ipid_num++;
      }
      
      if (hss->ipid.icmp_ipids[i] != -1) {
	if (good_icmp_ipid_num < i) {
	  hss->ipid.icmp_ipids[good_icmp_ipid_num] = hss->ipid.icmp_ipids[i];
	}
	good_icmp_ipid_num++;
      }
    }
    
    if (good_tcp_ipid_num >= 3) {
      tcp_ipid_seqclass = get_ipid_sequence(good_tcp_ipid_num, hss->ipid.tcp_ipids, islocalhost(hss->target->v4hostip()));
    } else {
      tcp_ipid_seqclass = IPID_SEQ_UNKNOWN;
    }
    /* Only print tcp ipid seqclass in the final report. */
    hss->si.ipid_seqclass = tcp_ipid_seqclass;
    
    if (good_icmp_ipid_num >= 2) {
      icmp_ipid_seqclass = get_ipid_sequence(good_icmp_ipid_num, hss->ipid.icmp_ipids, islocalhost(hss->target->v4hostip()));
    } else {
      icmp_ipid_seqclass = IPID_SEQ_UNKNOWN;
    }
    
    /* TI: TCP IP ID sequence generation algorithm */
    switch(tcp_ipid_seqclass) {
    case IPID_SEQ_CONSTANT:
      seq_AVs[avnum].next = &seq_AVs[avnum+1]; avnum++;
      seq_AVs[avnum].attribute = (char*)"TI";
      sprintf(seq_AVs[avnum].value, "%X", hss->ipid.tcp_ipids[0]);
      break;
    case IPID_SEQ_INCR:
      seq_AVs[avnum].next = &seq_AVs[avnum+1]; avnum++;
      seq_AVs[avnum].attribute = (char*)"TI";
      strcpy(seq_AVs[avnum].value, "I");
      break;
    case IPID_SEQ_BROKEN_INCR:
      seq_AVs[avnum].next = &seq_AVs[avnum+1]; avnum++;
      seq_AVs[avnum].attribute = (char*)"TI";
      strcpy(seq_AVs[avnum].value, "BI");
      break;
    case IPID_SEQ_RPI:
      seq_AVs[avnum].next = &seq_AVs[avnum+1]; avnum++;
      seq_AVs[avnum].attribute = (char*)"TI";
      strcpy(seq_AVs[avnum].value, "RI");
      break;
    case IPID_SEQ_RD:
      seq_AVs[avnum].next = &seq_AVs[avnum+1]; avnum++;
      seq_AVs[avnum].attribute = (char*)"TI";
      strcpy(seq_AVs[avnum].value, "RD");
      break;
    case IPID_SEQ_ZERO:
      seq_AVs[avnum].next = &seq_AVs[avnum+1]; avnum++;
      seq_AVs[avnum].attribute = (char*)"TI";
      strcpy(seq_AVs[avnum].value, "Z");
      break;
    }

    /* II: ICMP IP ID sequence generation algorithm */
    switch(icmp_ipid_seqclass) {
    case IPID_SEQ_CONSTANT:
      seq_AVs[avnum].next = &seq_AVs[avnum+1]; avnum++;
      seq_AVs[avnum].attribute = (char*)"II";
      sprintf(seq_AVs[avnum].value, "%X", hss->ipid.icmp_ipids[0]);
      break;
    case IPID_SEQ_INCR:
      seq_AVs[avnum].next = &seq_AVs[avnum+1]; avnum++;
      seq_AVs[avnum].attribute = (char*)"II";
      strcpy(seq_AVs[avnum].value, "I");
      break;
    case IPID_SEQ_BROKEN_INCR:
      seq_AVs[avnum].next = &seq_AVs[avnum+1]; avnum++;
      seq_AVs[avnum].attribute = (char*)"II";
      strcpy(seq_AVs[avnum].value, "BI");
      break;
    case IPID_SEQ_RPI:
      seq_AVs[avnum].next = &seq_AVs[avnum+1]; avnum++;
      seq_AVs[avnum].attribute = (char*)"II";
      strcpy(seq_AVs[avnum].value, "RI");
      break;
    case IPID_SEQ_RD:
      seq_AVs[avnum].next = &seq_AVs[avnum+1]; avnum++;
      seq_AVs[avnum].attribute = (char*)"II";
      strcpy(seq_AVs[avnum].value, "RD");
      break;
    case IPID_SEQ_ZERO:
      seq_AVs[avnum].next = &seq_AVs[avnum+1]; avnum++;
      seq_AVs[avnum].attribute = (char*)"II";
      strcpy(seq_AVs[avnum].value, "Z");
      break;	  
    }

	/* SS: Shared IP ID sequence boolean */
	if ( (tcp_ipid_seqclass == IPID_SEQ_INCR ||
		  tcp_ipid_seqclass == IPID_SEQ_BROKEN_INCR ||
		  tcp_ipid_seqclass == IPID_SEQ_RPI) &&
		 (icmp_ipid_seqclass == IPID_SEQ_INCR ||
		  icmp_ipid_seqclass == IPID_SEQ_BROKEN_INCR ||
		  icmp_ipid_seqclass == IPID_SEQ_RPI)) {
	  /* Both are incremental. Thus we have "SS" test. Check if they
		 are in the same sequence. */
      seq_AVs[avnum].next = &seq_AVs[avnum+1]; avnum++;
      seq_AVs[avnum].attribute = (char*)"SS";
	  int avg = (hss->ipid.tcp_ipids[good_tcp_ipid_num-1] - hss->ipid.tcp_ipids[0]) / (good_tcp_ipid_num - 1);
	  if ( hss->ipid.icmp_ipids[0] < hss->ipid.tcp_ipids[good_tcp_ipid_num-1] + 3 * avg) {
		strcpy(seq_AVs[avnum].value, "S");
	  } else {
		strcpy(seq_AVs[avnum].value, "O");
	  }
	}

    /* TCP Timestamp option sequencing */
    switch(hss->si.ts_seqclass) {

    case TS_SEQ_ZERO:
      seq_AVs[avnum].next = &seq_AVs[avnum+1]; avnum++;
      seq_AVs[avnum].attribute = (char*)"TS";
      strcpy(seq_AVs[avnum].value, "0");
      break;
    case TS_SEQ_2HZ:
    case TS_SEQ_100HZ:
    case TS_SEQ_1000HZ:
    case TS_SEQ_OTHER_NUM:
      seq_AVs[avnum].next = &seq_AVs[avnum+1]; avnum++;
      seq_AVs[avnum].attribute = (char*)"TS";

      /* Here we "cheat" a little to make the classes correspond more
	 closely to common real-life frequencies (particularly 100)
	 which aren't powers of two. */
      if (avg_ts_hz <= 5.66) {
	/* 1 would normally range from 1.4 - 2.82, but we expand that
	   to 0 - 5.66, so we won't ever even get a value of 2.  Needs
	   to be wide because our test is so fast that it is hard to
	   match slow frequencies exactly.  */
	tsnewval = 1;
      } else if (avg_ts_hz > 70 && avg_ts_hz <= 150) {
	/* mathematically 7 would be 90.51 - 181, but we change to 70-150 to 
	   better align with common freq 100 */
	tsnewval = 7;
      } else if (avg_ts_hz > 150 && avg_ts_hz <= 350) {
	/* would normally be 181 - 362.  Now aligns better with 200 */
	tsnewval = 8;
      } else {
	/* Do a log base2 rounded to nearest int */
	tsnewval = (unsigned int)(0.5 + log(avg_ts_hz)/log(2.0));
      }

      sprintf(seq_AVs[avnum].value, "%X", tsnewval);
      break;
    case TS_SEQ_UNSUPPORTED:
      seq_AVs[avnum].next = &seq_AVs[avnum+1]; avnum++;
      seq_AVs[avnum].attribute = (char*)"TS";
      strcpy(seq_AVs[avnum].value, "U");
      break;
    }
  }
  else {
    log_write(LOG_PLAIN,
			  "Insufficient responses for TCP sequencing (%d), OS detection may be less accurate\n", hss->si.responses);
  }
}

void HostOsScan::makeTOpsFP(HostOsScanStats *hss) {
  assert(hss);
  int i;

  if (hss->TOpsReplyNum!=6) return;
  
  for (i=0; i<6; i++) {
    if (!hss->TOps_AVs[i]) break;
    if (i<5)
      hss->TOps_AVs[i]->next = hss->TOps_AVs[i+1];
  }

  if (i<6) {
    if (o.debugging)
      error("We didn't get all the TOps replies from %s", hss->target->targetipstr());
    return;
  }

  hss->TOps_AVs[5]->next = NULL;

  hss->FP_TOps= (FingerPrint *) safe_zalloc(sizeof(FingerPrint));
  hss->FP_TOps->results = hss->TOps_AVs[0];
  hss->FP_TOps->name = "OPS";
}

void HostOsScan::makeTWinFP(HostOsScanStats *hss) {
  assert(hss);
  int i;

  if (hss->TWinReplyNum!=6) return;
  
  for (i=0; i<6; i++) {
    if (!hss->TWin_AVs[i]) break;
    if (i<5)
      hss->TWin_AVs[i]->next = hss->TWin_AVs[i+1];
  }

  if (i<6) {
    if (o.debugging)
      error("We didn't get all the TOps replies from %s", hss->target->targetipstr());
    return;
  }

  hss->TWin_AVs[5]->next = NULL;

  hss->FP_TWin = (FingerPrint *) safe_zalloc(sizeof(FingerPrint));
  hss->FP_TWin->results = hss->TWin_AVs[0];
  hss->FP_TWin->name = "WIN";
}

bool HostOsScan::processTSeqResp(HostOsScanStats *hss, struct ip *ip, int replyNo) {
  assert(replyNo>=0 && replyNo<NUM_SEQ_SAMPLES);

  struct tcp_hdr *tcp;
  int seq_response_num;  /* response # for sequencing */
  u32 timestamp = 0; /* TCP timestamp we receive back */

  if (hss->lastipid != 0 && ip->ip_id == hss->lastipid) {
    /* Probably a duplicate -- this happens sometimes when scanning localhost */
    return false;
  }
  hss->lastipid = ip->ip_id;
  
  tcp = ((struct tcp_hdr *) (((char *) ip) + 4 * ip->ip_hl));

  if ((tcp->th_flags & TH_RST)) {
    if (hss->si.responses == 0) {     
      error("WARNING:  RST from %s port %d -- is this port really open?",
              hss->target->targetipstr(), hss->openTCPPort);
    }
    return false;
  }

  if ((tcp->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK)) {
    /*  error("DEBUG: response is SYN|ACK to port %hu\n", ntohs(tcp->th_dport)); */
    /*readtcppacket((char *)ip, ntohs(ip->ip_len));*/
    /* We use the ACK value to match up our sent with rcv'd packets */
    seq_response_num = ntohl(tcp->th_ack) - tcpSeqBase - 1;
    /* printf("seq_response_num = %d\treplyNo = %d\n", seq_response_num, replyNo); */

    if (seq_response_num != replyNo) {
      /* BzzT! Value out of range */
      if (o.debugging) {
        error("Unable to associate os scan response with sent packet for %s.",
              hss->target->targetipstr());
        error("Received ack: %lX; sequence sent: %lX. Packet:",
              (unsigned long) ntohl(tcp->th_ack),
              (unsigned long) tcpSeqBase);
        readtcppacket((unsigned char *)ip,ntohs(ip->ip_len));
      }
      seq_response_num = replyNo;
    }
       
    if (hss->si.seqs[seq_response_num] == 0) {
      /* New response found! */
      hss->si.responses++;
      hss->si.seqs[seq_response_num] = ntohl(tcp->th_seq); /* TCP ISN */
      hss->si.ipids[seq_response_num] = ntohs(ip->ip_id);
      
      if ((gettcpopt_ts(tcp, &timestamp, NULL) == 0))
        hss->si.ts_seqclass = TS_SEQ_UNSUPPORTED;
      else {
        if (timestamp == 0) {
          hss->si.ts_seqclass = TS_SEQ_ZERO;
        }
      }
      hss->si.timestamps[seq_response_num] = timestamp;
      /* printf("Response #%d -- ipid=%hu ts=%i\n", seq_response_num, ntohs(ip->ip_id), timestamp); */

      return true;
    }
  }

  return false;
}

bool HostOsScan::processTOpsResp(HostOsScanStats *hss, struct tcp_hdr *tcp, int replyNo) {
  assert(replyNo>=0 || replyNo<6);
  bool opsParseResult;
  
  if (hss->FP_TOps || hss->TOps_AVs[replyNo]) return false;

  hss->TOps_AVs[replyNo] = (struct AVal *) safe_zalloc(sizeof(struct AVal));
  opsParseResult = get_tcpopt_string(tcp, this->tcpMss,
                                     hss->TOps_AVs[replyNo]->value,
                                     sizeof(hss->TOps_AVs[replyNo]->value));

  if (!opsParseResult) {
    if (o.debugging) 
      error("Option parse error for TOps response %d from %s.", replyNo, hss->target->targetipstr());
    hss->TOps_AVs[replyNo]->value[0] = '\0';
  }
  
  switch(replyNo) {
  case 0:
    hss->TOps_AVs[replyNo]->attribute = (char*)"O1";
	break;
  case 1:
    hss->TOps_AVs[replyNo]->attribute = (char*)"O2";
	break;
  case 2:
    hss->TOps_AVs[replyNo]->attribute = (char*)"O3";
	break;
  case 3:
    hss->TOps_AVs[replyNo]->attribute = (char*)"O4";
	break;
  case 4:
    hss->TOps_AVs[replyNo]->attribute = (char*)"O5";
	break;
  case 5:
    hss->TOps_AVs[replyNo]->attribute = (char*)"O6";
	break;
  }
  
  hss->TOpsReplyNum++;
  return true;
}

bool HostOsScan::processTWinResp(HostOsScanStats *hss, struct tcp_hdr *tcp, int replyNo) {
  assert(replyNo>=0 || replyNo<6);
  
  if (hss->FP_TWin || hss->TWin_AVs[replyNo]) return false;

  hss->TWin_AVs[replyNo] = (struct AVal *) safe_zalloc(sizeof(struct AVal));
  sprintf(hss->TWin_AVs[replyNo]->value, "%hX", ntohs(tcp->th_win));

  switch(replyNo) {
  case 0:
	hss->TWin_AVs[replyNo]->attribute = (char*)"W1";
	break;
  case 1:
	hss->TWin_AVs[replyNo]->attribute = (char*)"W2";
	break;
  case 2:
	hss->TWin_AVs[replyNo]->attribute = (char*)"W3";
	break;
  case 3:
	hss->TWin_AVs[replyNo]->attribute = (char*)"W4";
	break;
  case 4:
	hss->TWin_AVs[replyNo]->attribute = (char*)"W5";
	break;
  case 5:
	hss->TWin_AVs[replyNo]->attribute = (char*)"W6";
	break;
  }
  
  hss->TWinReplyNum++;
  return true;
}

bool HostOsScan::processTEcnResp(HostOsScanStats *hss, struct ip *ip) {
  struct AVal *AVs;
  int i;
  char *p;
  int numtests = 7;
  int current_testno = 0;
  struct tcp_hdr *tcp = ((struct tcp_hdr *) (((char *) ip) + 4 * ip->ip_hl));
  bool opsParseResult;

  if (hss->FP_TEcn) return false;
  
  /* Create the Avals */
  AVs = (struct AVal *) safe_zalloc(numtests * sizeof(struct AVal));

  /* Link them together */
  for(i=0; i < numtests - 1; i++)
    AVs[i].next = &AVs[i+1];
  AVs[numtests-1].next = NULL;
  
  AVs[current_testno].attribute = (char*)"R";
  strcpy(AVs[current_testno].value, "Y");

  current_testno++;

  /* don't frag flag */
  AVs[current_testno].attribute = (char*)"DF";
  if(ntohs(ip->ip_off) & IP_DF) {
    strcpy(AVs[current_testno].value,"Y");
  } else strcpy(AVs[current_testno].value, "N");

  current_testno++;

  /* TTL */
  AVs[current_testno].attribute = (char*)"T";
  sprintf(AVs[current_testno].value, "%d", ip->ip_ttl);

  current_testno++;

  /* TCP Window size */
  AVs[current_testno].attribute = (char*)"W";
  sprintf(AVs[current_testno].value, "%hX", ntohs(tcp->th_win));
	
  current_testno++;

  /* Now for the TCP options ... */
  AVs[current_testno].attribute = (char*)"O";
  opsParseResult = get_tcpopt_string(tcp, this->tcpMss,
									 AVs[current_testno].value,
									 sizeof(AVs[current_testno].value));
  if (!opsParseResult) {
	if (o.debugging) 
	  error("Option parse error for ECN response from %s.", hss->target->targetipstr());
	AVs[current_testno].value[0] = '\0';
  }

  current_testno++;
	 
  /* Explicit Congestion Notification support test */
  AVs[current_testno].attribute = (char*)"CC";
  if ((tcp->th_flags & TH_ECE) && (tcp->th_flags & TH_CWR))
    /* echo back */
    strcpy(AVs[current_testno].value,"S");
  else if (tcp->th_flags & TH_ECE)
    /* support */
    strcpy(AVs[current_testno].value,"Y");
  else if (!(tcp->th_flags & TH_CWR))
	/* not support */
    strcpy(AVs[current_testno].value,"N");
  else
	strcpy(AVs[current_testno].value,"O");

  current_testno++;

  /* TCP miscellaneous quirks test */
  AVs[current_testno].attribute = (char*)"Q";
  p = AVs[current_testno].value;
  if (tcp->th_x2) {
    /* Reserved field of TCP is not zero */
    *p++ = 'R';
  }
  if (!(tcp->th_flags & TH_URG) && tcp->th_urp) {
    /* URG pointer value when urg flag not set */
    *p++ = 'U';
  }
  *p++ = '\0';

  hss->FP_TEcn = (FingerPrint *) safe_zalloc(sizeof(FingerPrint));
  hss->FP_TEcn->name = "ECN";
  hss->FP_TEcn->results = AVs;

  return true;
}

bool HostOsScan::processT1_7Resp(HostOsScanStats *hss, struct ip *ip, int replyNo) {

  assert(replyNo>=0 && replyNo<7);
 
  int numtests;
  struct tcp_hdr *tcp = ((struct tcp_hdr *) (((char *) ip) + 4 * ip->ip_hl));
  struct AVal *AVs;
  int current_testno = 0;
  
  int i;
  bool opsParseResult;
  int length;
  char *p;

  if (hss->FPtests[FP_T1_7_OFF+replyNo]) return false;

  if(replyNo == 0) numtests = 8; /* T1 doesn't has 'Win','Ops' tests. */
  else numtests = 10;
  
  /* Create the Avals */
  AVs = (struct AVal *) safe_zalloc(numtests * sizeof(struct AVal));

  /* Link them together */
  for(i=0; i < numtests - 1; i++)
    AVs[i].next = &AVs[i+1];
  AVs[numtests-1].next = NULL;
  
  /* First we give the "response" flag to say we did actually receive
     a packet -- this way we won't match a template with R=N */
  AVs[current_testno].attribute = (char*)"R";
  strcpy(AVs[current_testno].value, "Y");

  current_testno++;

  /* Next we check whether the Don't Fragment bit is set */
  AVs[current_testno].attribute = (char*)"DF";
  if(ntohs(ip->ip_off) & 0x4000) {
    strcpy(AVs[current_testno].value,"Y");
  } else strcpy(AVs[current_testno].value, "N");

  current_testno++;

  /* TTL */
  AVs[current_testno].attribute = (char*)"T";
  sprintf(AVs[current_testno].value, "%d", ip->ip_ttl);

  current_testno++;

  if(replyNo!=0) {
	/* Now we do the TCP Window size */
	AVs[current_testno].attribute = (char*)"W";
	sprintf(AVs[current_testno].value, "%hX", ntohs(tcp->th_win));
	
	current_testno++;
  }

  /* Seq test values:
     Z   = zero
     A   = same as ack
     A+  = ack + 1
     O   = other
  */
  AVs[current_testno].attribute = (char*)"S";
  if (ntohl(tcp->th_seq) == 0)
    strcpy(AVs[current_testno].value, "Z");
  else if (ntohl(tcp->th_seq) == tcpAck)
    strcpy(AVs[current_testno].value, "A");
  else if (ntohl(tcp->th_seq) == tcpAck + 1)
    strcpy(AVs[current_testno].value, "A+");
  else
	strcpy(AVs[current_testno].value, "O");  

  current_testno++;
  
  /* ACK test values:
	 Z   = zero
     S   = same as syn
     S+  = syn + 1
     O   = other
  */
  AVs[current_testno].attribute = (char*)"A";
  if (ntohl(tcp->th_ack) == 0)
    strcpy(AVs[current_testno].value, "Z");
  else if (ntohl(tcp->th_ack) == tcpSeqBase) 
    strcpy(AVs[current_testno].value, "S");
  else if (ntohl(tcp->th_ack) == tcpSeqBase + 1)
    strcpy(AVs[current_testno].value, "S+");
  else
	strcpy(AVs[current_testno].value, "O");

  current_testno++;

  /* Flags. They must be in this order:
     E = ECN Echo
     U = Urgent
     A = Acknowledgement
     P = Push
     R = Reset
     S = Synchronize
     F = Final
  */
  AVs[current_testno].attribute = (char*)"F";
  p = AVs[current_testno].value;
  if (tcp->th_flags & TH_ECE) *p++ = 'E';
  if (tcp->th_flags & TH_URG) *p++ = 'U';
  if (tcp->th_flags & TH_ACK) *p++ = 'A';
  if (tcp->th_flags & TH_PUSH) *p++ = 'P';
  if (tcp->th_flags & TH_RST) *p++ = 'R';
  if (tcp->th_flags & TH_SYN) *p++ = 'S';
  if (tcp->th_flags & TH_FIN) *p++ = 'F';
  *p++ = '\0';

  current_testno++;

  if(replyNo!=0) {
	/* Now for the TCP options ... */
	AVs[current_testno].attribute = (char*)"O";
	opsParseResult = get_tcpopt_string(tcp, this->tcpMss,
									   AVs[current_testno].value,
									   sizeof(AVs[current_testno].value));
	if (!opsParseResult) {
	  if (o.debugging) 
		error("Option parse error for T%d response from %s.", replyNo, hss->target->targetipstr());
	  AVs[current_testno].value[0] = '\0';
	}

	current_testno++;
  }
  
  /* Rst Data CRC16 */
  AVs[current_testno].attribute = (char*)"RD";
  length = (int) ntohs(ip->ip_len) - 4 * ip->ip_hl -4 * tcp->th_off;
  if ((tcp->th_flags & TH_RST) && length>0) {
    sprintf(AVs[current_testno].value, "%08lX", crc16(((u8 *)tcp) + 4 * tcp->th_off, length));
  }
  else {
    strcpy(AVs[current_testno].value, "0");
  }
    
  current_testno++;

  /* TCP miscellaneous quirks test */
  AVs[current_testno].attribute = (char*)"Q";
  p = AVs[current_testno].value;
  if (tcp->th_x2) {
    /* Reserved field of TCP is not zero */
    *p++ = 'R';
  }
  if (!(tcp->th_flags & TH_URG) && tcp->th_urp) {
    /* URG pointer value when urg flag not set */
    *p++ = 'U';
  }
  *p = '\0';

  hss->FPtests[FP_T1_7_OFF+replyNo] = (FingerPrint *) safe_zalloc(sizeof(FingerPrint));
  hss->FPtests[FP_T1_7_OFF+replyNo]->results = AVs;
  hss->FPtests[FP_T1_7_OFF+replyNo]->name = (replyNo == 0)? "T1" : (replyNo == 1)? "T2" : (replyNo == 2)? "T3" : (replyNo == 3)? "T4" : (replyNo == 4)? "T5" : (replyNo == 5)? "T6" : "T7";
  
  return true;
}

bool HostOsScan::processTUdpResp(HostOsScanStats *hss, struct ip *ip) {
  assert(hss);
  assert(ip);

  struct icmp *icmp;
  struct ip *ip2;
  int numtests;
  unsigned short checksum;
  unsigned short *checksumptr;
  struct udp_hdr *udp;
  struct AVal *AVs;
  int i;
  int current_testno = 0;
  unsigned char *datastart, *dataend;

#if !defined(SOLARIS) && !defined(SUNOS) && !defined(IRIX) && !defined(HPUX)
  numtests = 12;
#else
  /* We don't do RID test under these operating systems, thus the
        number of test is 1 less. */
  numtests = 11;
#endif

  if (hss->FP_TUdp) return false;
  
  icmp = ((struct icmp *)(((char *) ip) + 4 * ip->ip_hl));

  /* Make sure this is icmp port unreachable. */  
  assert(icmp->icmp_type == 3 && icmp->icmp_code == 3);
  
  ip2 = (struct ip*)((char *)icmp + 8);
  udp = (struct udp_hdr *)((char *)ip2 + 4 * ip2->ip_hl);

  /* The ports should match. */
  if (ntohs(udp->uh_sport) != hss->upi.sport || ntohs(udp->uh_dport) != hss->upi.dport) {
    return false;
  }

  /* Create the Avals */
  AVs = (struct AVal *) safe_zalloc(numtests * sizeof(struct AVal));

  /* Link them together */
  for(i=0; i < numtests - 1; i++)
    AVs[i].next = &AVs[i+1];
  AVs[numtests-1].next = NULL;
  
  /* First of all, if we got this far the response was yes */
  AVs[current_testno].attribute = (char*)"R";
  strcpy(AVs[current_testno].value, "Y");

  current_testno++;

  /* Also, we now know that the port we reached was closed */
  if (hss->target->FPR->osscan_closedudpport == -1)
    hss->target->FPR->osscan_closedudpport = hss->upi.dport;

  /* Now let us do an easy one, Don't fragment */
  AVs[current_testno].attribute = (char*)"DF";
  if(ntohs(ip->ip_off) & 0x4000) {
    strcpy(AVs[current_testno].value,"Y");
  } else strcpy(AVs[current_testno].value, "N");

  current_testno++;

  /* TTL */
  AVs[current_testno].attribute = (char*)"T";
  sprintf(AVs[current_testno].value, "%d", ip->ip_ttl);

  current_testno++;

  /* TOS of the response */
  AVs[current_testno].attribute = (char*)"TOS";
  sprintf(AVs[current_testno].value, "%hX", ip->ip_tos);

  current_testno++;

  /* Now we look at the IP datagram length that was returned, some
     machines send more of the original packet back than others */
  AVs[current_testno].attribute = (char*)"IPL";
  sprintf(AVs[current_testno].value, "%hX", ntohs(ip->ip_len));

  current_testno++;

  /* unused filed not zero in Destination Unreachable Message */
  AVs[current_testno].attribute = (char*)"UN";
  sprintf(AVs[current_testno].value, "%hX", ntohl(icmp->icmp_void));

  current_testno++;

  /* OK, lets check the returned IP length, some systems @$@ this
     up */
  AVs[current_testno].attribute = (char*)"RIPL";
  if(ntohs(ip2->ip_len) == 328)
	strcpy(AVs[current_testno].value, "G");
  else
	sprintf(AVs[current_testno].value, "%hX", ntohs(ip2->ip_len));

  current_testno++;

  /* This next test doesn't work on Solaris because the lamers
     overwrite our ip_id */
#if !defined(SOLARIS) && !defined(SUNOS) && !defined(IRIX) && !defined(HPUX)

  /* Now lets see how they treated the ID we sent ... */
  AVs[current_testno].attribute = (char*)"RID";
  if (ntohs(ip2->ip_id) == hss->upi.ipid)
    strcpy(AVs[current_testno].value, "G"); /* The good "expected" value */
  else
	sprintf(AVs[current_testno].value, "%hX", ntohs(ip2->ip_id));

  current_testno++;

#endif

  /* Let us see if the IP checksum we got back computes */

  AVs[current_testno].attribute = (char*)"RIPCK";
  /* Thanks to some machines not having struct ip member ip_sum we
     have to go with this BS */
  checksumptr = (unsigned short *)   ((char *) ip2 + 10);
  checksum =   *checksumptr;

  if (checksum == 0)
    strcpy(AVs[current_testno].value, "Z");
  else {
    *checksumptr = 0;
    if (in_cksum((unsigned short *)ip2, 20) == checksum) {
      strcpy(AVs[current_testno].value, "G"); /* The "expected" good value */
    } else {
      strcpy(AVs[current_testno].value, "I"); /* They fucked it up */
    }
    *checksumptr = checksum;
  }

  current_testno++;

  /* UDP checksum */
  AVs[current_testno].attribute = (char*)"RUCK";
  if (udp->uh_sum == hss->upi.udpck)
    strcpy(AVs[current_testno].value, "G"); /* The "expected" good value */
  else
	sprintf(AVs[current_testno].value, "%hX", ntohs(udp->uh_sum));

  current_testno++;

  /* UDP length ... */
  AVs[current_testno].attribute = (char*)"RUL";
  if(ntohs(udp->uh_ulen) == 308)
	strcpy(AVs[current_testno].value, "G"); /* The "expected" good value */
  else
	sprintf(AVs[current_testno].value, "%hX", ntohs(udp->uh_ulen));

  current_testno++;

  /* Finally we ensure the data is OK */
  datastart = ((unsigned char *)udp) + 8;
  dataend = (unsigned char *)  ip + ntohs(ip->ip_len);

  while(datastart < dataend) {
    if (*datastart != hss->upi.patternbyte) break;
    datastart++;
  }
  AVs[current_testno].attribute = (char*)"RUD";
  if (datastart < dataend)
    strcpy(AVs[current_testno].value, "I"); /* They fucked it up */
  else  
    strcpy(AVs[current_testno].value, "G");
  
  hss->FP_TUdp = (FingerPrint *) safe_zalloc(sizeof(FingerPrint));
  hss->FP_TUdp->name = "U1";  
  hss->FP_TUdp->results = AVs;

  /* Count hop count */
  if (hss->distance == -1) {
	hss->distance = this->udpttl - ip2->ip_ttl;
  }
	
  return true;
}

bool HostOsScan::processTIcmpResp(HostOsScanStats *hss, struct ip *ip, int replyNo) {
  assert(replyNo==0 || replyNo==1);

  int numtests = 7;
  struct AVal *AVs;
  struct ip *ip1, *ip2;
  struct icmp *icmp1, *icmp2;
  unsigned short value1, value2;
  int i;
  int current_testno = 0;

  if (hss->FP_TIcmp) return false;
  
  if (hss->icmpEchoReply == NULL) {
    /* This is the first icmp reply we get, store it and return. */
    hss->icmpEchoReply = (struct ip *) safe_malloc(ntohs(ip->ip_len));
    memcpy(hss->icmpEchoReply, ip, ntohs(ip->ip_len));
    hss->storedIcmpReply = replyNo;
    return true;
  }
  else if (hss->storedIcmpReply == replyNo) {
    /* This is a dunplicated icmp reply. */
    return false;
  }

  /* Ok, now we get another reply. */
  if (hss->storedIcmpReply == 0) {
    ip1 = hss->icmpEchoReply;
    ip2 = ip;
  } else {
    ip1 = ip;
    ip2 = hss->icmpEchoReply;
  }

  icmp1 = ((struct icmp *)(((char *) ip1) + 4 * ip1->ip_hl));
  icmp2 = ((struct icmp *)(((char *) ip2) + 4 * ip2->ip_hl));

  assert(icmp1->icmp_type == 0 && icmp2->icmp_type == 0);

  /* Create the Avals */
  AVs = (struct AVal *) safe_zalloc(numtests * sizeof(struct AVal));

  /* Link them together */
  for(i=0; i < numtests - 1; i++)
    AVs[i].next = &AVs[i+1];
  AVs[numtests-1].next = NULL;

  AVs[current_testno].attribute = (char*)"R";
  strcpy(AVs[current_testno].value, "Y");

  current_testno++;

  /* DFI test values:
   * Y. Both set DF;
   * S. Both use the DF that the sender uses;
   * N. Both not set;
   * O. Other(both different with the sender, -_-b).
   */
  AVs[current_testno].attribute = (char*)"DFI";
  value1 = (ntohs(ip1->ip_off) & IP_DF);
  value2 = (ntohs(ip2->ip_off) & IP_DF);
  if (value1 && value2)
    /* both set */
    strcpy(AVs[current_testno].value, "Y");
  else if (value1 && !value2)
    /* echo back */
    strcpy(AVs[current_testno].value, "S");
  else if (!value1 && !value2)
	/* neither set */
    strcpy(AVs[current_testno].value, "N");
  else
    strcpy(AVs[current_testno].value, "O");

  current_testno++;

  /* TTL */
    
  AVs[current_testno].attribute = (char*)"T";
  sprintf(AVs[current_testno].value, "%d", ip1->ip_ttl);
  
  current_testno++;

  /* Type of service. Test values:
   * Z. Both are zero;
   * NN. Both use the same non-zero number;
   * S. Both use the TOS that the sender uses;
   * O. Other.
   */
  AVs[current_testno].attribute = (char*)"TOSI";
  value1 = ip1->ip_tos;
  value2 = ip2->ip_tos;
  if (value1 == value2){
    if (value1 == 0)
      strcpy(AVs[current_testno].value, "Z");
    else
      sprintf(AVs[current_testno].value, "%hX", value1);
  }
  else if (value1 == IP_TOS_DEFAULT && value2 == IP_TOS_RELIABILITY)
    /* the same with sender */
    strcpy(AVs[current_testno].value, "S");
  else
    strcpy(AVs[current_testno].value, "O");

  current_testno++;
    
  /* ICMP Code value. Test values:
   * [Value]. Both set Code to the same value [Value];
   * S. Both use the Code that the sender uses;
   * O. Other.
   */
  AVs[current_testno].attribute = (char*)"CD";
  value1 = icmp1->icmp_code;
  value2 = icmp2->icmp_code;
  if (value1 == value2){
    if (value1 == 0)
      strcpy(AVs[current_testno].value, "Z");
    else
      sprintf(AVs[current_testno].value, "%hX", value1);
  }
  else if (value1 == 9 && value2 == 0)
    /* both the same as in the corresponding probe */
    strcpy(AVs[current_testno].value, "S");
  else  
    strcpy(AVs[current_testno].value, "O");

  current_testno++;

  /* Sequence Number value in Icmp echo reply. SI test values:
   * Z. Both are set to zero;
   * [value]. Both set Seq to the same value [Value];
   * S. Both use the Seq value that the sender uses;
   * O. Other.
   */
  AVs[5].attribute = (char*)"SI";
  value1 = ntohs(icmp1->icmp_seq);
  value2 = ntohs(icmp2->icmp_seq);
  if (value1 == value2) {
    if (value1 == 0)
      strcpy(AVs[current_testno].value, "Z");
    else
      sprintf(AVs[current_testno].value, "%hX", value1);
  }
  else if (value1 == this->icmpEchoSeq && value2 == this->icmpEchoSeq + 1)
    /* Both echo the ones from the probes. */
    strcpy(AVs[current_testno].value, "S");
  else {
    /*
      if (o.debugging)
      printf("Seq value in icmp replies from %s aren't the same with the sender. Seq1 = %d\tSeq2 = %d\n",
      hss->target->targetipstr(), value1, value2);
    */
    strcpy(AVs[current_testno].value, "O");
  }

  current_testno++;

  /* ICMP data length. Pattens:
   * [Value]. Both truncted to a specific value;
   * S. Both the same with the sender;
   * O. Other.
   */
  AVs[current_testno].attribute = (char*)"DLI";
  value1 = ntohs(ip1->ip_len) - 4 * ip1->ip_hl - 8;
  value2 = ntohs(ip2->ip_len) - 4 * ip2->ip_hl - 8;
  if (value1 == value2){
    if (value1 == 0)
      strcpy(AVs[current_testno].value, "Z");
    else
      sprintf(AVs[current_testno].value, "%hX", value1);
  }
  else if (value1 == 120 && value2 == 150)
    /* the same as in the corresponding probe */
    strcpy(AVs[current_testno].value, "S");
  else
	/* */
    strcpy(AVs[current_testno].value, "O");

  hss->FP_TIcmp= (FingerPrint *) safe_zalloc(sizeof(FingerPrint));
  hss->FP_TIcmp->name = "IE";
  hss->FP_TIcmp->results = AVs;
  
  return true;
}

bool HostOsScan::get_tcpopt_string(struct tcp_hdr *tcp, int mss, char *result, int maxlen) {
  char *p,*q;
  u16 tmpshort;
  u32 tmpword;
  int length;
  int opcode;

  p = result;
  length = (tcp->th_off * 4) - sizeof(struct tcp_hdr);
  q = ((char *)tcp) + sizeof(struct tcp_hdr);

  /*
   * Example parsed result: M5B4ST11NW2
   *   MSS, Sack Permitted, Timestamp with both value not zero, Nop, WScale with value 2
   */

  /* Be aware of the max increament value for p in parsing,
   * now is 5 = strlen("Mxxxx") <-> MSS Option
   */
  while(length > 0 && (p - result) < (maxlen - 5)) {
    opcode=*q++;
    if (!opcode) { /* End of List */
      *p++ = 'L';
      length--;
    } else if (opcode == 1) { /* No Op */
      *p++ = 'N';
      length--;
    } else if (opcode == 2) { /* MSS */
      if(length<4)
        break; /* MSS has 4 bytes */
      *p++ = 'M';
      q++;
      memcpy(&tmpshort, q, 2);
	  /*  if(ntohs(tmpshort) == mss) */
	  /*    *p++ = 'E'; */
	  sprintf(p, "%hX", ntohs(tmpshort));
	  p += strlen(p); /* max movement of p is 4 (0xFFFF) */
      q += 2;
      length -= 4;
    } else if (opcode == 3) { /* Window Scale */
      if(length<3)
        break; /* Window Scale option has 3 bytes */
      *p++ = 'W';
      q++;
      sprintf(p, "%hX", *((u8*)q));
      p += strlen(p); /* max movement of p is 2 (max WScale value is 0xFF) */
      q++;
      length -= 3;
    } else if (opcode == 4) { /* SACK permitted */
      if(length<2)
        break; /* SACK permitted option has 2 bytes */
      *p++ = 'S';
      q++;
      length -= 2;
    } else if (opcode == 8) { /* Timestamp */
      if(length<10)
        break; /* Timestamp option has 10 bytes */
      *p++ = 'T';
      q++;
      memcpy(&tmpword, q, 4);
      if(tmpword)
        *p++ = '1';
      else
        *p++ = '0';
      q += 4;
      memcpy(&tmpword, q, 4);
      if(tmpword)
        *p++ = '1';
      else
        *p++ = '0';
      q += 4;
      length -= 10;
    }
  }

  if(length>0) {
    /* We could reach here for one of the two reasons:
     *  1. At least one option is not correct. (Eg. Should have 4 bytes but only has 3 bytes left).
     *  2. The option string is too long.
     */
    *result = '\0';
    return false;
  }
  
  *p = '\0';
  return true;
}

HostOsScanInfo::HostOsScanInfo(Target *t, OsScanInfo *OsSI) {
  target = t;
  OSI = OsSI;

  FPs = (FingerPrint **) safe_zalloc(o.maxOSTries() * sizeof(FingerPrint *));
  FP_matches = (FingerPrintResults *) safe_zalloc(o.maxOSTries() * sizeof(FingerPrintResults));
  si = (struct seq_info *) safe_zalloc(o.maxOSTries() * sizeof(struct seq_info));
  timedOut = false;
  isCompleted = false;

  if (target->FPR == NULL)
    target->FPR = new FingerPrintResults;
  target->osscanSetFlag(OS_PERF);
  
  hss = new HostOsScanStats(t);
}

HostOsScanInfo::~HostOsScanInfo() {
  delete hss;
  free(FPs);
  free(FP_matches);
  free(si);
}

OsScanInfo::OsScanInfo(vector<Target *> &Targets) {
  unsigned int targetno;
  HostOsScanInfo *hsi;
  int num_timedout = 0;

  gettimeofday(&now, NULL);
  
  numInitialTargets=0;
  
  /* build up incompleteHosts list */
  for(targetno = 0; targetno < Targets.size(); targetno++) {
    /* check if Targets[targetno] is good to be scanned
     * if yes, append it to the list
     */
    if (Targets[targetno]->timedOut(&now)) {
      num_timedout++;
      continue;
    }

#ifdef WIN32
    if (Targets[targetno]->ifType() == devt_loopback) {
      log_write(LOG_STDOUT, "Skipping OS Scan against %s because it doesn't work against your own machine (localhost)\n", Targets[targetno]->NameIP());
      continue;
    }
#endif

    if (Targets[targetno]->ports.getStateCounts(IPPROTO_TCP, PORT_OPEN) == 0 ||
        (Targets[targetno]->ports.getStateCounts(IPPROTO_TCP, PORT_CLOSED) == 0 &&
         Targets[targetno]->ports.getStateCounts(IPPROTO_TCP, PORT_UNFILTERED) == 0)) {
      if (o.osscan_limit) {
        if (o.verbose)
          log_write(LOG_PLAIN, "Skipping OS Scan against %s due to absence of open (or perhaps closed) ports\n", Targets[targetno]->NameIP());
        continue;
      } else {   
        Targets[targetno]->osscanSetFlag(OS_PERF_UNREL);
      }
    }

    hsi = new HostOsScanInfo(Targets[targetno], this);
    incompleteHosts.push_back(hsi);
    numInitialTargets++;
  }

  nextI = incompleteHosts.begin();
}

OsScanInfo::~OsScanInfo()
{
  while(!incompleteHosts.empty()) {
    delete incompleteHosts.front();
    incompleteHosts.pop_front();
  }
}

/* Find a HostScanStats by IP its address in the incomplete list.  Returns NULL if
   none are found. */
HostOsScanInfo *OsScanInfo::findIncompleteHost(struct sockaddr_storage *ss) {
  list<HostOsScanInfo *>::iterator hostI;
  struct sockaddr_in *sin = (struct sockaddr_in *) ss;

  if (sin->sin_family != AF_INET)
    fatal("%s passed a non IPv4 address", __func__);

  for(hostI = incompleteHosts.begin(); hostI != incompleteHosts.end(); hostI++) {
    if ((*hostI)->target->v4hostip()->s_addr == sin->sin_addr.s_addr)
      return *hostI;
  }
  return NULL;
}

/* A circular buffer of the incompleteHosts.  nextIncompleteHost() gives
   the next one.  The first time it is called, it will give the
   first host in the list.  If incompleteHosts is empty, returns
   NULL. */
HostOsScanInfo *OsScanInfo::nextIncompleteHost() {
  HostOsScanInfo *nxt;

  if (incompleteHosts.empty())
    return NULL;

  nxt = *nextI;
  nextI++;
  if (nextI == incompleteHosts.end())
    nextI = incompleteHosts.begin();

  return nxt;
}

/* Removes any hosts that have completed their scans from the incompleteHosts
   list.  Returns the number of hosts removed. */
int OsScanInfo::removeCompletedHosts() {
  list<HostOsScanInfo *>::iterator hostI, nxt;
  HostOsScanInfo *hsi = NULL;
  int hostsRemoved = 0;
  bool timedout = false;

  for(hostI = incompleteHosts.begin(); hostI != incompleteHosts.end();
      hostI = nxt) {
    nxt = hostI;
    nxt++;
    hsi = *hostI;
    timedout = hsi->target->timedOut(&now);
    if (hsi->isCompleted || timedout) {
      /* A host to remove!  First adjust nextI appropriately */
      if (nextI == hostI && incompleteHosts.size() > 1) {
        nextI++;
        if (nextI == incompleteHosts.end())
          nextI = incompleteHosts.begin();
      }

      if (o.verbose && numInitialTargets > 50) {
        int remain = incompleteHosts.size() - 1;
        if (remain && !timedout)
          log_write(LOG_STDOUT, "Completed os scan against %s in %.3fs (%d %s)\n",
                    hsi->target->targetipstr(), 
                    (o.TimeSinceStartMS() - this->starttimems) / 1000.0, remain, 
                    (remain == 1)? "host left" : "hosts left");
        else if (timedout)
          log_write(LOG_STDOUT, "%s timed out during os scan (%d %s)\n",
                    hsi->target->targetipstr(), remain,
                    (remain == 1)? "host left" : "hosts left");
      }
      incompleteHosts.erase(hostI);
      hostsRemoved++;
      hsi->target->stopTimeOutClock(&now);
      delete hsi;
    }
  }
  return hostsRemoved;
}

int send_icmp_echo_probe(int sd, struct eth_nfo *eth, 
			 const struct in_addr *victim, u8 tos, bool df,
			 u8 pcode, unsigned short id, u16 seq, u16 datalen) {
  u8 *packet = NULL;
  u32 packetlen = 0;
  int decoy;
  int res = -1;

  for(decoy = 0; decoy < o.numdecoys; decoy++) {
    packet = build_icmp_raw(&o.decoys[decoy], victim,
    			    o.ttl, get_random_u16(), tos, df,
    			    NULL, 0,
    			    seq, id, ICMP_ECHO, pcode,
    			    NULL, datalen, &packetlen);
    if(!packet) return -1;
    res = send_ip_packet(sd, eth, packet, packetlen);
    free(packet);
    if(res==-1) return -1;
  }
  
  return 0;
}

int send_closedudp_probe_2(struct udpprobeinfo &upi, int sd,
                           struct eth_nfo *eth,  const struct in_addr *victim,
						   int ttl, u16 sport, u16 dport) {
  static int myttl = 0;
  static u8 patternbyte = 0x43; /* character 'C' */
  static u16 id = 0x1042; 
  u8 packet[328]; /* 20 IP hdr + 8 UDP hdr + 300 data */
  struct ip *ip = (struct ip *) packet;
  struct udp_hdr *udp = (struct udp_hdr *) (packet + sizeof(struct ip));
  struct in_addr *source;
  int datalen = 300;
  unsigned char *data = packet + 28;
  unsigned short realcheck; /* the REAL checksum */
  int res;
  int decoy;

  /* if (!patternbyte) patternbyte = (get_random_uint() % 60) + 65; */
  memset(data, patternbyte, datalen);

  /*  while(!id) id = get_random_uint(); */

  if (ttl == -1) {
	myttl = (time(NULL) % 14) + 51;
  } else {
	myttl = ttl;
  }

  /* check that required fields are there and not too silly */
  if ( !victim || !sport || !dport || (!eth && sd < 0)) {
    error("%s: One or more of your parameters suck!", __func__);
    return 1;
  }

  for(decoy=0; decoy < o.numdecoys; decoy++) {
    source = &o.decoys[decoy];

    memset((char *) packet, 0, sizeof(struct ip) + sizeof(struct udp_hdr));

    udp->uh_sport = htons(sport);
    udp->uh_dport = htons(dport);
    udp->uh_ulen = htons(8 + datalen);

    /* OK, now we should be able to compute a valid checksum */
    realcheck = magic_tcpudp_cksum(source, victim, IPPROTO_UDP,
				   sizeof(struct udp_hdr) + datalen, (char *) udp);
#if STUPID_SOLARIS_CHECKSUM_BUG
    udp->uh_sum = sizeof(struct udp_hdr) + datalen;
#else
    udp->uh_sum = realcheck;
#endif

    /* Now for the ip header */
    ip->ip_v = 4;
    ip->ip_hl = 5;
    ip->ip_len = htons(sizeof(struct ip) + sizeof(struct udp_hdr) + datalen);
    ip->ip_id = htons(id);
    ip->ip_ttl = myttl;
    ip->ip_p = IPPROTO_UDP;
    ip->ip_src.s_addr = source->s_addr;
    ip->ip_dst.s_addr= victim->s_addr;
  
    upi.ipck = in_cksum((unsigned short *)ip, sizeof(struct ip));
#if HAVE_IP_IP_SUM
    ip->ip_sum = upi.ipck;
#endif
  
    /* OK, now if this is the real she-bang (ie not a decoy) then
       we stick all the inph0 in our upi */
    if (decoy == o.decoyturn) {   
      upi.iptl = 28 + datalen;
      upi.ipid = id;
      upi.sport = sport;
      upi.dport = dport;
      upi.udpck = realcheck;
      upi.udplen = 8 + datalen;
      upi.patternbyte = patternbyte;
      upi.target.s_addr = ip->ip_dst.s_addr;
    }
  
    if ((res = send_ip_packet(sd, eth, packet, ntohs(ip->ip_len))) == -1)
      {
        gh_perror("send_ip_packet in %s", __func__);
        return 1;
      }
  }

  return 0;
}

int get_initial_ttl_guess(u8 ttl) {
  if (ttl <= 32)
    return 32;
  else if (ttl <= 64)
    return 64;
  else if (ttl <= 128)
    return 128;
  else
    return 255;
}

/* This function takes an array of "numSamples" IP IDs and analyzes
 them to determine their sequenceability classification.  It returns
 one of the IPID_SEQ_* classifications defined in nmap.h .  If the
 function cannot determine the sequence, IPID_SEQ_UNKNOWN is returned.
 This islocalhost argument is a boolean specifying whether these
 numbers were generated by scanning localhost.  NOTE: the "ipids" argument
 may be modified if localhost is set to true. */
int get_ipid_sequence(int numSamples, int *ipids, int islocalhost) {
  u16 ipid_diffs[32];
  int i;
  int allipideqz = 1;  /* Flag that means "All IP.IDs returned during
						  sequencing are zero.  This is unset if we
						  find a nonzero */
  int j,k;

  assert(numSamples < (int) (sizeof(ipid_diffs) / 2));
  if (numSamples < 2) return IPID_SEQ_UNKNOWN;

  for(i = 1; i < numSamples; i++) {
    if (ipids[i-1] != 0 || ipids[i] != 0) 
      allipideqz = 0; /* All IP.ID values do *NOT* equal zero */

	if (ipids[i-1] <= ipids[i]) {
	  ipid_diffs[i-1] = ipids[i] - ipids[i-1];
	} else {
	  ipid_diffs[i-1] = (u16) (ipids[i] - ipids[i-1] + 65536);
    }

	/* Random */
    if (numSamples > 2 && ipid_diffs[i-1] > 20000)
      return IPID_SEQ_RD;
  }

  /* ZERO */
  if (allipideqz) return IPID_SEQ_ZERO;

  if (islocalhost) {
    int allgto = 1; /* ALL diffs greater than one */

    for(i=0; i < numSamples - 1; i++) {
      if (ipid_diffs[i] < 2) {
		allgto = 0; break;
      }
	}

    if (allgto) {
      for(i=0; i < numSamples - 1; i++) {
		if (ipid_diffs[i] % 256 == 0) /* Stupid MS */
		  ipid_diffs[i] -= 256;
		else
		  ipid_diffs[i]--; /* Because on localhost the RST sent back use an IPID */
      }
    }
  }

  /* Constant */
  j = 1; /* j is a flag meaning "all differences seen are zero" */
  for(i=0; i < numSamples - 1; i++) {
	if (ipid_diffs[i] != 0) {
	  j = 0;
    break;
	}
  }
  if (j) {
	return IPID_SEQ_CONSTANT;
  }

  /* Random Positive Increments */
  for(i=0; i < numSamples - 1; i++) {
    if (ipid_diffs[i] > 1000 &&
		(ipid_diffs[i] % 256 != 0 ||
		 (ipid_diffs[i] % 256 == 0 && ipid_diffs[i] >= 25600))) {
      return IPID_SEQ_RPI;
      }   
	}

  j = 1; /* j is a flag meaning "all differences seen are < 10" */
  k = 1; /* k is a flag meaning "all difference seen are multiples of
			256 and no greater than 5120" */
  for(i=0; i < numSamples - 1; i++) {
    if (k && (ipid_diffs[i] > 5120 || ipid_diffs[i] % 256 != 0)) {
      k = 0;
    }
	
    if (j && ipid_diffs[i] > 9) {
      j = 0;
	}
  }
  
  /* Broken Increment */
  if (k == 1) {
	return IPID_SEQ_BROKEN_INCR;
  }

  /* Incremental */
  if (j == 1)
	return IPID_SEQ_INCR;

  return IPID_SEQ_UNKNOWN;
}

/* This is the function for tuning the major values that affect
   scan performance */
static void init_perf_values() {
  memset(&perf, 0, sizeof(perf));
  /* TODO: I should revisit these values for tuning.  They should probably
     at least be affected by -T. */
  perf.low_cwnd = MAX(o.min_parallelism, 1);
  perf.max_cwnd = o.max_parallelism? o.max_parallelism : 300;
  perf.group_initial_cwnd = box(o.min_parallelism, perf.max_cwnd, 10);
  perf.host_initial_cwnd = perf.group_initial_cwnd;
  perf.quick_incr = 1;
  perf.cc_incr = 1;
  perf.initial_ccthresh = 50;
  perf.ping_magnifier = 3;
  perf.pingtime = 5000000;
  perf.group_drop_cwnd_divisor = 2.0;
  perf.group_drop_ccthresh_divisor = (o.timing_level < 4)? 2.0 : 1.5;
  perf.host_drop_ccthresh_divisor = (o.timing_level < 4)? 2.0 : 1.5;
  perf.tryno_cap = 12;
}

/* Start the timeout clocks of any targets that aren't already timedout
 */
static void startTimeOutClocks(OsScanInfo *OSI) {
  list<HostOsScanInfo *>::iterator hostI;
  
  gettimeofday(&now, NULL);
  for(hostI = OSI->incompleteHosts.begin(); 
      hostI != OSI->incompleteHosts.end(); hostI++) {
    if (!(*hostI)->target->timedOut(NULL))
      (*hostI)->target->startTimeOutClock(&now);
  }
}

static void begin_sniffer(HostOsScan *HOS, vector<Target *> &Targets) {
  char pcap_filter[2048];
  /* 20 IPv6 addresses is max (45 byte addy + 14 (" or src host ")) * 20 == 1180 */
  char dst_hosts[1200];
  int filterlen = 0;
  int len;
  unsigned int targetno;
  bool doIndividual = Targets.size() <= 20; // Don't bother IP limits if scanning huge # of hosts
  pcap_filter[0] = '\0';

  if (doIndividual) {
    for(targetno = 0; targetno < Targets.size(); targetno++) {
      len = Snprintf(dst_hosts + filterlen, 
                     sizeof(dst_hosts) - filterlen,
                     "%ssrc host %s", (targetno == 0)? "" : " or ",
                     Targets[targetno]->targetipstr());
      if (len < 0 || len + filterlen >= (int) sizeof(dst_hosts))
        fatal("ran out of space in dst_hosts");
      filterlen += len;
    }
    len = Snprintf(dst_hosts + filterlen, sizeof(dst_hosts) - filterlen, ")))");
    if (len < 0 || len + filterlen >= (int) sizeof(dst_hosts))
      fatal("ran out of space in dst_hosts");
  }
  filterlen = 0;

  HOS->pd = my_pcap_open_live(Targets[0]->deviceName(), 8192,  (o.spoofsource)? 1 : 0, pcap_selectable_fd_valid()? 200 : 2);

  if (doIndividual)
    len = Snprintf(pcap_filter, sizeof(pcap_filter), "dst host %s and (icmp or (tcp and (%s", 
                   inet_ntoa(Targets[0]->v4source()), dst_hosts);
  else
    len = Snprintf(pcap_filter, sizeof(pcap_filter), "dst host %s and (icmp or tcp)", 
                   inet_ntoa(Targets[0]->v4source()));
  if (len < 0 || len >= (int) sizeof(pcap_filter))
    fatal("ran out of space in pcap filter");
  filterlen = len;
    
  if (o.debugging > 2) log_write(LOG_PLAIN, "Pcap filter: %s\n", pcap_filter);
  set_pcap_filter(Targets[0]->deviceName(), HOS->pd, pcap_filter);
  
  return;
}

static void startRound(OsScanInfo *OSI, HostOsScan *HOS, int roundNum) {
  list<HostOsScanInfo *>::iterator hostI;
  HostOsScanInfo *hsi = NULL;

  /* Reinitial some parameters of the scan system. */
  HOS->reInitScanSystem();
  
  for(hostI = OSI->incompleteHosts.begin(); hostI != OSI->incompleteHosts.end(); hostI++) {
    hsi = *hostI;
    if(hsi->FPs[roundNum]) {
      delete hsi->FPs[roundNum];
      hsi->FPs[roundNum] = NULL;
    }
    hsi->hss->initScanStats();
  }
}

static void doSeqTests(OsScanInfo *OSI, HostOsScan *HOS) {
  list<HostOsScanInfo *>::iterator hostI;
  HostOsScanInfo *hsi = NULL;
  HostOsScanStats *hss = NULL;
  unsigned int unableToSend; /* # of times in a row that hosts were unable to send probe */
  unsigned int expectReplies;
  long to_usec;
  int timeToSleep = 0;

  struct ip *ip = NULL;
  struct link_header linkhdr;
  struct sockaddr_in sin;
  unsigned int bytes;
  struct timeval rcvdtime;
  
  struct timeval stime, tmptv;
  bool timedout = false;
  bool thisHostGood;
  bool foundgood;
  bool goodResponse;
  int numProbesLeft = 0;

  memset(&stime, 0, sizeof(stime));
  memset(&tmptv, 0, sizeof(tmptv));
  
  for(hostI = OSI->incompleteHosts.begin(); hostI != OSI->incompleteHosts.end(); hostI++) {
    hsi = *hostI;
    hss = hsi->hss;
    HOS->buildSeqProbeList(hss);
  }
  
  do {
    if(timeToSleep > 0) {
      if(o.debugging > 1) {
        log_write(LOG_PLAIN, "Sleep %dus for next sequence probe\n", timeToSleep);
      }
      usleep(timeToSleep);
    }
    
    gettimeofday(&now, NULL);
    expectReplies = 0;
    unableToSend = 0;

    if(o.debugging > 2) {
	  for(hostI = OSI->incompleteHosts.begin(); hostI != OSI->incompleteHosts.end(); hostI++) {
        hss = (*hostI)->hss;
        log_write(LOG_PLAIN, "Host %s. ProbesToSend %d: \tProbesActive %d\n",
                  hss->target->targetipstr(), hss->numProbesToSend(),
                  hss->numProbesActive());
      }
    }
    
    /* Send a seq probe to each host. */
    while(unableToSend < OSI->numIncompleteHosts() && HOS->stats->sendOK()) {
      hsi = OSI->nextIncompleteHost();
      hss = hsi->hss;
      gettimeofday(&now, NULL);
      if (hss->numProbesToSend()>0 && HOS->hostSeqSendOK(hss, NULL)) {
        HOS->sendNextProbe(hss);
        expectReplies++;
        unableToSend = 0;
      } else {
        unableToSend++;
      }
    }

    HOS->stats->num_probes_sent_at_last_wait = HOS->stats->num_probes_sent;

    gettimeofday(&now, NULL);

    /* Count the pcap wait time. */
    if(!HOS->stats->sendOK()) {
      TIMEVAL_MSEC_ADD(stime, now, 1000); 

	  for(hostI = OSI->incompleteHosts.begin(); hostI != OSI->incompleteHosts.end(); hostI++) {
        if (HOS->nextTimeout((*hostI)->hss, &tmptv)) {
          if (TIMEVAL_SUBTRACT(tmptv, stime) < 0)
            stime = tmptv;
        }
      }
    }
    else {
	  foundgood = false;
      for(hostI = OSI->incompleteHosts.begin(); hostI != OSI->incompleteHosts.end(); hostI++) {
        thisHostGood = HOS->hostSeqSendOK((*hostI)->hss, &tmptv);
        if (thisHostGood) {
          stime = tmptv;
          foundgood = true;
          break;
        }
      
        if (!foundgood || TIMEVAL_SUBTRACT(tmptv, stime) < 0) {
          stime = tmptv;
          foundgood = true;
        }
      }
    }

    do {
      to_usec = TIMEVAL_SUBTRACT(stime, now);
      if(to_usec < 2000) to_usec = 2000;
      
      if(o.debugging > 2)
        log_write(LOG_PLAIN, "pcap wait time is %ld.\n", to_usec);
      
      ip = (struct ip*) readip_pcap(HOS->pd, &bytes, to_usec, &rcvdtime, &linkhdr, true);
    
      gettimeofday(&now, NULL);
      
      if (!ip && TIMEVAL_SUBTRACT(stime, now) < 0) {
        timedout = true;
        break;
      } else if (!ip) {
        continue;
      }

      if (TIMEVAL_SUBTRACT(now, stime) > 200000) {
        /* While packets are still being received, I'll be generous and give
           an extra 1/5 sec.  But we have to draw the line somewhere */
        timedout = true;
      }
      
      if(bytes < (4 * ip->ip_hl) + 4U)
        continue;

      memset(&sin, 0, sizeof(sin));
      sin.sin_addr.s_addr = ip->ip_src.s_addr;
      sin.sin_family = AF_INET;
      hsi = OSI->findIncompleteHost((struct sockaddr_storage *) &sin);
      if (!hsi) continue; /* Not from one of our targets. */
      setTargetMACIfAvailable(hsi->target, &linkhdr, ip, 0);
      
      goodResponse = HOS->processResp(hsi->hss, ip, bytes, &rcvdtime);
      
      if(goodResponse)
        expectReplies--;
      
    } while(!timedout && expectReplies > 0);
    
    /* Remove any timeout hosts during the scan. */
    OSI->removeCompletedHosts();
    
    numProbesLeft = 0;  
    for(hostI = OSI->incompleteHosts.begin(); 
        hostI != OSI->incompleteHosts.end(); hostI++) {
      hss = (*hostI)->hss;
      HOS->updateActiveSeqProbes(hss);
      numProbesLeft += hss->numProbesToSend();
      numProbesLeft += hss->numProbesActive();
    }

    gettimeofday(&now, NULL);

    if(expectReplies == 0) {
      timeToSleep = TIMEVAL_SUBTRACT(stime, now);
    } else {
	  timeToSleep = 0;
	}
    
  } while(numProbesLeft > 0);
  
}

/* TCP, UDP, ICMP Tests */
static void doTUITests(OsScanInfo *OSI, HostOsScan *HOS) {
  list<HostOsScanInfo *>::iterator hostI;
  HostOsScanInfo *hsi = NULL;
  HostOsScanStats *hss = NULL;
  unsigned int unableToSend; /* # of times in a row that hosts were unable to send probe */
  unsigned int expectReplies;
  long to_usec;
  int timeToSleep = 0;

  struct ip *ip = NULL;
  struct link_header linkhdr;
  struct sockaddr_in sin;
  unsigned int bytes;
  struct timeval rcvdtime;
  
  struct timeval stime, tmptv;
  
  bool timedout = false;
  bool thisHostGood;
  bool foundgood;
  bool goodResponse;
  int numProbesLeft = 0;

  memset(&stime, 0, sizeof(stime));
  memset(&tmptv, 0, sizeof(tmptv));
  
  for(hostI = OSI->incompleteHosts.begin(); 
      hostI != OSI->incompleteHosts.end(); hostI++) {
    hsi = *hostI;
    hss = hsi->hss;
    HOS->buildTUIProbeList(hss);
  }

  do {

    if(timeToSleep > 0) {
      if(o.debugging > 1) {
        log_write(LOG_PLAIN, "Time to sleep %d. Sleeping. \n", timeToSleep);
      }
    
      usleep(timeToSleep);
    }
    
    gettimeofday(&now, NULL);
    expectReplies = 0;
    unableToSend = 0;

    if(o.debugging > 2) {
      for(hostI = OSI->incompleteHosts.begin(); 
          hostI != OSI->incompleteHosts.end(); hostI++) {
        hss = (*hostI)->hss;
        log_write(LOG_PLAIN, "Host %s. ProbesToSend %d: \tProbesActive %d\n",
                  hss->target->targetipstr(), hss->numProbesToSend(),
                  hss->numProbesActive());
      }
    }
    
    while(unableToSend < OSI->numIncompleteHosts() && HOS->stats->sendOK()) {
      hsi = OSI->nextIncompleteHost();
      hss = hsi->hss;
      gettimeofday(&now, NULL);
      if (hss->numProbesToSend()>0 && HOS->hostSendOK(hss, NULL)) {
        HOS->sendNextProbe(hss);
        expectReplies++;
        unableToSend = 0;
      } else {
        unableToSend++;
      }
    }

    HOS->stats->num_probes_sent_at_last_wait = HOS->stats->num_probes_sent;
    
    gettimeofday(&now, NULL);

    /* Count the pcap wait time. */
    if(!HOS->stats->sendOK()) {
      TIMEVAL_MSEC_ADD(stime, now, 1000); 

      for(hostI = OSI->incompleteHosts.begin(); hostI != OSI->incompleteHosts.end(); 
          hostI++) {
        if (HOS->nextTimeout((*hostI)->hss, &tmptv)) {
          if (TIMEVAL_SUBTRACT(tmptv, stime) < 0)
            stime = tmptv;
        }
      }
    }
    else {
	  foundgood = false;
      for(hostI = OSI->incompleteHosts.begin(); hostI != OSI->incompleteHosts.end(); hostI++) {
        thisHostGood = HOS->hostSendOK((*hostI)->hss, &tmptv);
        if (thisHostGood) {
          stime = tmptv;
          foundgood = true;
          break;
        }
      
        if (!foundgood || TIMEVAL_SUBTRACT(tmptv, stime) < 0) {
          stime = tmptv;
          foundgood = true;
        }
      }
    }

    do {
      to_usec = TIMEVAL_SUBTRACT(stime, now);
      if(to_usec < 2000) to_usec = 2000;
      
      if(o.debugging > 2)
        log_write(LOG_PLAIN, "pcap wait time is %ld.\n", to_usec);
      
      ip = (struct ip*) readip_pcap(HOS->pd, &bytes, to_usec, &rcvdtime, &linkhdr, true);
    
      gettimeofday(&now, NULL);
      
      if (!ip && TIMEVAL_SUBTRACT(stime, now) < 0) {
        timedout = true;
        break;
      } else if (!ip) {
        continue;
      }

      if (TIMEVAL_SUBTRACT(now, stime) > 200000) {
        /* While packets are still being received, I'll be generous and give
           an extra 1/5 sec.  But we have to draw the line somewhere */
        timedout = true;
      }
      
      if(bytes < (4 * ip->ip_hl) + 4U)
        continue;

      memset(&sin, 0, sizeof(sin));
      sin.sin_addr.s_addr = ip->ip_src.s_addr;
      sin.sin_family = AF_INET;
      hsi = OSI->findIncompleteHost((struct sockaddr_storage *) &sin);
      if (!hsi) continue; /* Not from one of our targets. */
      setTargetMACIfAvailable(hsi->target, &linkhdr, ip, 0);
      
      goodResponse = HOS->processResp(hsi->hss, ip, bytes, &rcvdtime);
      
      if(goodResponse)
        expectReplies--;
      
    } while(!timedout && expectReplies > 0);

    /* Remove any timeout hosts during the scan. */
    OSI->removeCompletedHosts();
    
    numProbesLeft = 0;  
    for(hostI = OSI->incompleteHosts.begin(); 
        hostI != OSI->incompleteHosts.end(); hostI++) {
      hss = (*hostI)->hss;
      HOS->updateActiveTUIProbes(hss);
      numProbesLeft += hss->numProbesToSend();
      numProbesLeft += hss->numProbesActive();
    }

    gettimeofday(&now, NULL);
    
    if(expectReplies == 0) {
      timeToSleep = TIMEVAL_SUBTRACT(stime, now);
    } else {
	  timeToSleep = 0;
	}
        
  } while (numProbesLeft > 0);
}

static void endRound(OsScanInfo *OSI, HostOsScan *HOS, int roundNum) {
  list<HostOsScanInfo *>::iterator hostI;
  HostOsScanInfo *hsi = NULL;
  int distance = -1;

  for(hostI = OSI->incompleteHosts.begin(); 
      hostI != OSI->incompleteHosts.end(); hostI++) {
    distance = -1;
    hsi = *hostI;
    HOS->makeFP(hsi->hss);

    hsi->FPs[roundNum] = hsi->hss->getFP();
    hsi->target->FPR->FPs[roundNum] = hsi->FPs[roundNum];
    hsi->target->FPR->numFPs = roundNum + 1;
    double tr = hsi->hss->timingRatio();
    hsi->target->FPR->maxTimingRatio = MAX(hsi->target->FPR->maxTimingRatio, tr);
    match_fingerprint(hsi->FPs[roundNum], &hsi->FP_matches[roundNum],
                      o.reference_FPs, OSSCAN_GUESS_THRESHOLD);

    if (hsi->FP_matches[roundNum].overall_results == OSSCAN_SUCCESS &&
        hsi->FP_matches[roundNum].num_perfect_matches > 0) {
      memcpy(&(hsi->target->seq), &hsi->hss->si, sizeof(struct seq_info));
      if (roundNum > 0) {
        if(o.verbose) error("WARNING:  OS didn't match until try #%d", roundNum + 1);
      }
      hsi->target->FPR->goodFP = roundNum;
      match_fingerprint(hsi->target->FPR->FPs[roundNum], hsi->target->FPR, 
                        o.reference_FPs, OSSCAN_GUESS_THRESHOLD);
      hsi->isCompleted = true;
    }

    if (islocalhost(hsi->target->v4hostip())) {
      /* scanning localhost */
      distance = 0;
    } else if (hsi->target->MACAddress()) {
      /* on the same network segment */
      distance = 1;
    } else if (hsi->hss->distance!=-1) {
      distance = hsi->hss->distance;
    }
    
    hsi->target->distance = hsi->target->FPR->distance = distance;
    hsi->target->FPR->distance_guess = hsi->hss->distance_guess;

  }
  
  OSI->removeCompletedHosts();
}

static void findBestFPs(OsScanInfo *OSI) {
  list<HostOsScanInfo *>::iterator hostI;
  HostOsScanInfo *hsi = NULL;
  int i;

  double bestacc;
  int bestaccidx;

  for(hostI = OSI->incompleteHosts.begin(); 
      hostI != OSI->incompleteHosts.end(); hostI++) {
    hsi = *hostI;
    memcpy(&(hsi->target->seq), &hsi->hss->si, sizeof(struct seq_info));

    /* Now lets find the best match */
    bestacc = 0;
    bestaccidx = 0;
    for(i=0; i < hsi->target->FPR->numFPs; i++) {
      if (hsi->FP_matches[i].overall_results == OSSCAN_SUCCESS &&
          hsi->FP_matches[i].num_matches > 0 &&
          hsi->FP_matches[i].accuracy[0] > bestacc) {
        bestacc = hsi->FP_matches[i].accuracy[0];
        bestaccidx = i;
        if (hsi->FP_matches[i].num_perfect_matches)
          break;
      }
    }

    hsi->target->FPR->goodFP = bestaccidx;

    // Now we redo the match, since target->FPR has various data (such as
    // target->FPR->numFPs) which is not in FP_matches[bestaccidx].  This is
    // kinda ugly.
    if (hsi->target->FPR->goodFP >= 0)
      match_fingerprint(hsi->target->FPR->FPs[bestaccidx], hsi->target->FPR, 
                        o.reference_FPs, OSSCAN_GUESS_THRESHOLD);
  }
}

static void printFP(OsScanInfo *OSI) {
  list<HostOsScanInfo *>::iterator hostI;
  HostOsScanInfo *hsi = NULL;
  FingerPrintResults *FPR;
  
  for(hostI = OSI->incompleteHosts.begin(); 
      hostI != OSI->incompleteHosts.end(); hostI++) {
    hsi = *hostI;
	FPR = hsi->target->FPR;

	log_write(LOG_NORMAL|LOG_SKID_NOXLT|LOG_STDOUT,
		  "No OS matches for %s by new os scan system.\n\nTCP/IP fingerprint:\n%s",
		  hsi->target->targetipstr(),
		  mergeFPs(FPR->FPs, FPR->numFPs, true,
			   hsi->target->v4hostip(), hsi->target->distance, 
			   hsi->target->MACAddress(),
			   FPR->osscan_opentcpport, FPR->osscan_closedtcpport, 
			   FPR->osscan_closedudpport, false));
  }
}

/* Goes through every unmatched host in OSI.  If a host has completed
   the maximum number of OS detection tries allowed for it without
   matching, it is transferred to the passed in unMatchedHosts list.
   Returns the number of hosts moved to unMatchedHosts. */
static int expireUnmatchedHosts(OsScanInfo *OSI, 
				list<HostOsScanInfo *> *unMatchedHosts) {
  list<HostOsScanInfo *>::iterator hostI, nextHost;
  int hostsRemoved = 0;
  HostOsScanInfo *HOS;

  gettimeofday(&now, NULL);
  for(hostI = OSI->incompleteHosts.begin(); 
      hostI != OSI->incompleteHosts.end(); hostI = nextHost) {
    HOS = *hostI;
    nextHost = hostI;
    nextHost++;

    int max_tries = o.maxOSTries(); /* The amt. if print is suitable for submission */
    if (HOS->target->FPR->OmitSubmissionFP())
      max_tries = min(max_tries, STANDARD_OS2_TRIES);

    if (HOS->target->FPR->numFPs >= max_tries) {
      /* We've done all the OS2 tries we're going to do ... move this
	 to unMatchedHosts */
      HOS->target->stopTimeOutClock(&now);
      OSI->incompleteHosts.erase(hostI);
      /* We need to adjust nextI if necessary */
      OSI->resetHostIterator();
      hostsRemoved++;
      unMatchedHosts->push_back(HOS);
    }
  }
  return hostsRemoved;
}


/* You should call os_scan2 rather than this function, as that version handles
   chunking so you don't do too many targets in parallel */
static int os_scan_2(vector<Target *> &Targets) {
  OsScanInfo *OSI;
  HostOsScan *HOS;

  // Hosts which haven't matched and have been removed from
  // incompleteHosts because they have exceeded the number of
  // retransmissions the host is allowed.
  list<HostOsScanInfo *> unMatchedHosts;
  int itry;

  if (Targets.size() == 0) {
    return 1;
  }

  init_perf_values();
  
  OSI = new OsScanInfo(Targets);
  if(OSI->numIncompleteHosts() == 0) {
    /* no one will be scanned */
    delete OSI;
    return 1;
  }
  OSI->starttimems = o.TimeSinceStartMS();
  
  HOS = new HostOsScan(Targets[0]);
  startTimeOutClocks(OSI);
  
  itry = 0;



  begin_sniffer(HOS, Targets); /* initial the pcap session handler in HOS */
  while(OSI->numIncompleteHosts() != 0) {
    if (itry > 0) sleep(1);
    if (itry == 3) usleep(1500000); /* Try waiting a little longer just in case it matters */
    if (o.verbose) {
      char targetstr[128];
      bool plural = (OSI->numIncompleteHosts() != 1);
      if (!plural) {
	(*(OSI->incompleteHosts.begin()))->target->NameIP(targetstr, sizeof(targetstr));
      } else Snprintf(targetstr, sizeof(targetstr), "%d hosts", (int) OSI->numIncompleteHosts());
      log_write(LOG_PLAIN, "%s OS detection (try #%d) against %s\n", (itry == 0)? "Initiating" : "Retrying", itry + 1, targetstr);
      log_flush_all();
    }
    startRound(OSI, HOS, itry);
    doSeqTests(OSI, HOS);
    doTUITests(OSI, HOS);
    endRound(OSI, HOS, itry);
    expireUnmatchedHosts(OSI, &unMatchedHosts);
    itry++;
  }

  /* Now move the unMatchedHosts array back to IncompleteHosts */
  if (!unMatchedHosts.empty())
    OSI->incompleteHosts.splice(OSI->incompleteHosts.begin(), unMatchedHosts);
  
  if (OSI->numIncompleteHosts()) {
    /* For host that doesn't have a perfect match, we do the following
       things. */

    /* Find the most matching item in the db. */
    findBestFPs(OSI);

    /* Print the fp in debug mode.
       Normally let output.cc to print the FP. */
    if(o.debugging > 1)
      printFP(OSI);
  }

  delete HOS;
  delete OSI;
  return 0;
}

/* This is the primary OS detection function.  If many Targets are
   passed in (the threshold is based on timing level), they are
   processed as smaller groups to improve accuracy  */
void os_scan2(vector<Target *> &Targets) {
  unsigned int max_os_group_sz = 20;
  double fudgeratio = 1.2; /* Allow a slightly larger final group rather than finish with a tiny one */
  vector<Target *> tmpTargets;
  unsigned int startidx = 0;

  if (o.timing_level == 4)
    max_os_group_sz = (unsigned int) (max_os_group_sz * 1.5);

  if (o.timing_level > 4 || Targets.size() <= max_os_group_sz * fudgeratio) {
    os_scan_2(Targets);
    return;
  }

  /* We need to split it up */
  while(startidx < Targets.size()) {
    int diff = Targets.size() - startidx;
    if (diff > max_os_group_sz * fudgeratio) {
      diff = max_os_group_sz;
    }
    tmpTargets.assign(Targets.begin() + startidx, 
		      Targets.begin() + startidx + diff);
    os_scan_2(tmpTargets);
    startidx += diff;
  }
  return;
}

