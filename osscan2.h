
/***************************************************************************
 * osscan2.h -- Header info for 2nd Generation OS detection via TCP/IP     *
 * fingerprinting.  For more information on how this works in Nmap, see    *
 * http://insecure.org/osdetect/                                           *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2013 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE CLARIFICATIONS  *
 * AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your right to use,    *
 * modify, and redistribute this software under certain conditions.  If    *
 * you wish to embed Nmap technology into proprietary software, we sell    *
 * alternative licenses (contact sales@insecure.com).  Dozens of software  *
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
 * including the special and conditions of the license text as well.       *
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
 * continued development of Nmap.  Please email sales@insecure.com for     *
 * further information.                                                    *
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
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING         *
 *                                                                         *
 ***************************************************************************/

/* $Id: osscan.h 3636 2006-07-04 23:04:56Z fyodor $ */

#ifndef OSSCAN2_H
#define OSSCAN2_H

#include "nmap.h"
#include "global_structures.h"
#include "nbase.h"
#include <vector>
#include <list>
#include "Target.h"
class Target;


/******************************************************************************
 * CONSTANT DEFINITIONS                                                       *
 ******************************************************************************/

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


/******************************************************************************
 * TYPE AND STRUCTURE DEFINITIONS                                             *
 ******************************************************************************/


typedef enum OFProbeType {
  OFP_UNSET,
  OFP_TSEQ,
  OFP_TOPS,
  OFP_TECN,
  OFP_T1_7,
  OFP_TICMP,
  OFP_TUDP
} OFProbeType;

/******************************************************************************
 * FUNCTION PROTOTYPES                                                        *
 ******************************************************************************/

/* This is the primary OS detection function.  If many Targets are
   passed in (the threshold is based on timing level), they are
   processed as smaller groups to improve accuracy  */
void os_scan2(std::vector<Target *> &Targets);

int get_initial_ttl_guess(u8 ttl);
int get_ipid_sequence(int numSamples, int *ipids, int islocalhost);


/******************************************************************************
 * CLASS DEFINITIONS                                                          *
 ******************************************************************************/
class OFProbe;
class HostOsScanStats;
class HostOsScan;
class HostOsScanInfo;
class OsScanInfo;

/** Represents an OS detection probe. It does not contain the actual packet
 * that is sent to the target but contains enough information to generate
 * it (such as the probe type and its subid). It also stores timing
 * information. */
class OFProbe {

 public:
  OFProbe();

  /* The literal string for the current probe type. */
  const char *typestr();

  /* Type of the probe: for what os fingerprinting test? */
  OFProbeType type;

  /* Subid of this probe to separate different tcp/udp/icmp. */
  int subid;

  /* Try (retransmission) number of this probe */
  int tryno;

  /* A packet may be timedout for a while before being retransmitted
     due to packet sending rate limitations */
  bool retransmitted;

  struct timeval sent;

  /* Time the previous probe was sent, if this is a retransmit (tryno > 0) */
  struct timeval prevSent;
};


/* Stores the status for a host being scanned in a scan round. */
class HostOsScanStats {

 friend class HostOsScan;
 
 public:
  HostOsScanStats(Target *t);
  ~HostOsScanStats();
  void initScanStats();
  struct eth_nfo *fill_eth_nfo(struct eth_nfo *eth, eth_t *ethsd) const;
  void addNewProbe(OFProbeType type, int subid);
  void removeActiveProbe(std::list<OFProbe *>::iterator probeI);
  /* Get an active probe from active probe list identified by probe type
   * and subid.  returns probesActive.end() if there isn't one. */
  std::list<OFProbe *>::iterator getActiveProbe(OFProbeType type, int subid);
  void moveProbeToActiveList(std::list<OFProbe *>::iterator probeI);
  void moveProbeToUnSendList(std::list<OFProbe *>::iterator probeI);
  unsigned int numProbesToSend() {return probesToSend.size();}
  unsigned int numProbesActive() {return probesActive.size();}
  FingerPrint *getFP() {return FP;}

  Target *target; /* the Target */
  struct seq_info si;
  struct ipid_info ipid;

  /* distance, distance_guess: hop count between us and the target.
   *
   * Possible values of distance:
   *   0: when scan self;
   *   1: when scan a target on the same network segment;
   * >=1: not self, not same network and nmap has got the icmp reply to the U1 probe.
   *  -1: none of the above situations.
   *
   * Possible values of distance_guess:
   *  -1: nmap fails to get a valid ttl by all kinds of probes.
   * >=1: a guessing value based on ttl. */
  int distance;
  int distance_guess;

  /* Returns the amount of time taken between sending 1st tseq probe
   * and the last one.  Zero is
   * returned if we didn't send the tseq probes because there was no
   * open tcp port */
  double timingRatio();
  double cc_scale();

 private:
  /* Ports of the targets used in os fingerprinting. */
  int openTCPPort, closedTCPPort, closedUDPPort;

  /* Probe list used in tests. At first, probes are linked in
   * probesToSend; when a probe is sent, it will be removed from
   * probesToSend and appended to probesActive. If any probes in
   * probesActive are timedout, they will be moved to probesToSend and
   * sent again till expired. */
  std::list<OFProbe *> probesToSend;
  std::list<OFProbe *> probesActive;

  /* A record of total number of probes that have been sent to this
   * host, including restranmited ones. */
  unsigned int num_probes_sent;
  /* Delay between two probes.    */
  unsigned int sendDelayMs;
  /* When the last probe is sent. */
  struct timeval lastProbeSent;

  struct ultra_timing_vals timing;

  /* Fingerprint of this target. When a scan is completed, it'll
   * finally be passed to hs->target->FPR->FPs[x]. */
  FingerPrint *FP;
  FingerTest *FPtests[NUM_FPTESTS];
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

  /* The following are variables to store temporary results
   * during the os fingerprinting process of this host. */
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
  bool sendOK(); /* Returns true if the system says that sending is OK. */
  double cc_scale();

  struct ultra_timing_vals timing;
  struct timeout_info to;      /* rtt/timeout info                */
  int num_probes_active;       /* Total number of active probes   */
  int num_probes_sent;         /* Number of probes sent in total. */
  int num_probes_sent_at_last_wait;
};


/* This class does the scan job, setting and using the status of a host in
 * the host's HostOsScanStats. */
class HostOsScan {

 public:
  HostOsScan(Target *t); /* OsScan need a target to set eth stuffs */
  ~HostOsScan();

  pcap_t *pd;
  ScanStats *stats;

  /* (Re)Initialize the parameters that will be used during the scan.*/
  void reInitScanSystem();

  void buildSeqProbeList(HostOsScanStats *hss);
  void updateActiveSeqProbes(HostOsScanStats *hss);

  void buildTUIProbeList(HostOsScanStats *hss);
  void updateActiveTUIProbes(HostOsScanStats *hss);

  /* send the next probe in the probe list of the hss */
  void sendNextProbe(HostOsScanStats *hss);

  /* Process one response. If the response is useful, return true. */
  bool processResp(HostOsScanStats *hss, struct ip *ip, unsigned int len, struct timeval *rcvdtime);

  /* Make up the fingerprint. */
  void makeFP(HostOsScanStats *hss);

  /* Check whether the host is sendok. If not, fill _when_ with the
   * time when it will be sendOK and return false; else, fill it with
   * now and return true. */
  bool hostSendOK(HostOsScanStats *hss, struct timeval *when);

  /* Check whether it is ok to send the next seq probe to the host. If
   * not, fill _when_ with the time when it will be sendOK and return
   * false; else, fill it with now and return true. */
  bool hostSeqSendOK(HostOsScanStats *hss, struct timeval *when);


  /* How long I am currently willing to wait for a probe response
   * before considering it timed out.  Uses the host values from
   * target if they are available, otherwise from gstats.  Results
   * returned in MICROseconds.  */
  unsigned long timeProbeTimeout(HostOsScanStats *hss);

  /* If there are pending probe timeouts, fills in when with the time
   * of the earliest one and returns true.  Otherwise returns false
   * and puts now in when. */
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

  /* Generic sending functions used by the above probe functions. */
  int send_tcp_probe(HostOsScanStats *hss,
                     int ttl, bool df, u8* ipopt, int ipoptlen,
                     u16 sport, u16 dport, u32 seq, u32 ack,
                     u8 reserved, u8 flags, u16 window, u16 urp,
                     u8 *options, int optlen,
                     char *data, u16 datalen);
  int send_icmp_echo_probe(HostOsScanStats *hss,
                           u8 tos, bool df, u8 pcode,
                           unsigned short id, u16 seq, u16 datalen);
  int send_closedudp_probe(HostOsScanStats *hss,
                           int ttl, u16 sport, u16 dport);

  void makeTSeqFP(HostOsScanStats *hss);
  void makeTOpsFP(HostOsScanStats *hss);
  void makeTWinFP(HostOsScanStats *hss);

  bool get_tcpopt_string(struct tcp_hdr *tcp, int mss, char *result, int maxlen);

  int rawsd;    /* Raw socket descriptor */
  eth_t *ethsd; /* Ethernet handle       */

  unsigned int tcpSeqBase;    /* Seq value used in TCP probes                 */
  unsigned int  tcpAck;       /* Ack value used in TCP probes                 */
  int tcpMss;                 /* TCP MSS value used in TCP probes             */
  int udpttl;                 /* TTL value used in the UDP probe              */
  unsigned short icmpEchoId;  /* ICMP Echo Identifier value for ICMP probes   */
  unsigned short icmpEchoSeq; /* ICMP Echo Sequence value used in ICMP probes */

  /* Source port number in TCP probes. Different probes will use an arbitrary
   * offset value of it. */
  int tcpPortBase;
  int udpPortBase;
};



/* Maintains a link of incomplete HostOsScanInfo. */
class OsScanInfo {

 public:
  OsScanInfo(std::vector<Target *> &Targets);
  ~OsScanInfo();
  float starttime;

  /* If you remove from this, you had better adjust nextI too (or call
   * resetHostIterator() afterward). Don't let this list get empty,
   * then add to it again, or you may mess up nextI (I'm not sure) */
  std::list<HostOsScanInfo *> incompleteHosts;

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
  std::list<HostOsScanInfo *>::iterator nextI;
};


/* The overall os scan information of a host:
 *  - Fingerprints gotten from every scan round;
 *  - Maching results of these fingerprints.
 *  - Is it timeout/completed?
 *  - ... */
class HostOsScanInfo {

 public:
  HostOsScanInfo(Target *t, OsScanInfo *OSI);
  ~HostOsScanInfo();

  Target *target;       /* The target                                  */
  FingerPrintResultsIPv4 *FPR;
  OsScanInfo *OSI;      /* The OSI which contains this HostOsScanInfo  */
  FingerPrint **FPs;    /* Fingerprints of the host                    */
  FingerPrintResultsIPv4 *FP_matches; /* Fingerprint-matching results      */
  bool timedOut;        /* Did it time out?                            */
  bool isCompleted;     /* Has the OS detection been completed?        */
  HostOsScanStats *hss; /* Scan status of the host in one scan round   */
};


/** This is the class that performs OS detection (both IPv4 and IPv6).
  * Using it is simple, just call os_scan() passing a list of targets.
  * The results of the detection will be stored inside the supplied
  * target objects. */
class OSScan {

 private:
  int ip_ver;             /* IP version for the OS Scan (4 or 6) */
  int chunk_and_do_scan(std::vector<Target *> &Targets, int family);
  int os_scan_ipv4(std::vector<Target *> &Targets);
  int os_scan_ipv6(std::vector<Target *> &Targets);
        
  public:
   OSScan();
   ~OSScan();
   void reset();
   int os_scan(std::vector<Target *> &Targets);
};

#endif /*OSSCAN2_H*/

