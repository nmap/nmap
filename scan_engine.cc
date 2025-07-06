
/***************************************************************************
 * scan_engine.cc -- Includes much of the "engine" functions for scanning, *
 * such as ultra_scan.  It also includes dependent functions such as those *
 * for collecting SYN/connect scan responses.                              *
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

#ifdef WIN32
#include "nmap_winconfig.h"
#endif
#include "portreasons.h"
#include <dnet.h>
#include "scan_engine.h"
#include "scan_engine_connect.h"
#include "scan_engine_raw.h"
#include "timing.h"
#include "tcpip.h"
#include "NmapOps.h"
#include "nmap_tty.h"
#include "payload.h"
#include "Target.h"
#include "targets.h"
#include "utils.h"
#include "nmap_error.h"
#include "output.h"

#include "struct_ip.h"

#ifndef IPPROTO_SCTP
#include "libnetutil/netutil.h"
#endif

#include <math.h>
#include <list>
#include <map>

extern NmapOps o;

/* How long extra to wait before retransmitting for rate-limit detection */
#define RLD_TIME_MS 1000
/* Keep a completed host around for a standard TCP MSL (2 min) */
#define COMPL_HOST_LIFETIME_MS 120000

int HssPredicate::operator() (const HostScanStats *lhs, const HostScanStats *rhs) const {
  const struct sockaddr_storage *lss, *rss;
  lss = (lhs) ? lhs->target->TargetSockAddr() : ss;
  rss = (rhs) ? rhs->target->TargetSockAddr() : ss;
  return 0 > sockaddr_storage_cmp(lss, rss);
}
const struct sockaddr_storage *HssPredicate::ss = NULL;

void UltraScanInfo::log_overall_rates(int logt) const {
  log_write(logt, "Overall sending rates: %.2f packets / s", send_rate_meter.getOverallPacketRate(&now));
  if (send_rate_meter.getNumBytes() > 0)
    log_write(logt, ", %.2f bytes / s", send_rate_meter.getOverallByteRate(&now));
  log_write(logt, ".\n");
}

void UltraScanInfo::log_current_rates(int logt, bool update) {
  log_write(logt, "Current sending rates: %.2f packets / s", send_rate_meter.getCurrentPacketRate(&now, update));
  if (send_rate_meter.getNumBytes() > 0)
    log_write(logt, ", %.2f bytes / s", send_rate_meter.getCurrentByteRate(&now));
  log_write(logt, ".\n");
}

void ultra_scan_performance_vars::init() {
  scan_performance_vars::init();
  ping_magnifier = 3;
  pingtime = 1250000;
  tryno_cap = o.getMaxRetransmissions();
}

const char *pspectype2ascii(int type) {
  switch (type) {
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
  case PS_ICMPV6:
    return "ICMPv6";
  case PS_ND:
    return "ND";
  case PS_CONNECTTCP:
    return "connect";
  default:
    fatal("%s: Unknown type: %d", __func__, type);
  }
  return ""; // Unreached
}

/* Initialize the ultra_timing_vals structure timing.  The utt must be
   TIMING_HOST or TIMING_GROUP.  If you happen to have the current
   time handy, pass it as now, otherwise pass NULL */
static void init_ultra_timing_vals(ultra_timing_vals *timing,
                                   enum ultra_timing_type utt,
                                   int num_hosts_in_group,
                                   const struct ultra_scan_performance_vars *perf,
                                   const struct timeval *now);

/* Take a buffer, buf, of size bufsz (64 bytes is sufficient) and
   writes a short description of the probe (arg1) into buf.  It also returns
   buf. */
static char *probespec2ascii(const probespec *pspec, char *buf, unsigned int bufsz) {
  char flagbuf[32];
  char *f;
  switch (pspec->type) {
  case PS_TCP:
    if (!pspec->pd.tcp.flags) {
      Strncpy(flagbuf, "(none)", sizeof(flagbuf));
    } else {
      f = flagbuf;
      if (pspec->pd.tcp.flags & TH_SYN)
        *f++ = 'S';
      if (pspec->pd.tcp.flags & TH_FIN)
        *f++ = 'F';
      if (pspec->pd.tcp.flags & TH_RST)
        *f++ = 'R';
      if (pspec->pd.tcp.flags & TH_PUSH)
        *f++ = 'P';
      if (pspec->pd.tcp.flags & TH_ACK)
        *f++ = 'A';
      if (pspec->pd.tcp.flags & TH_URG)
        *f++ = 'U';
      if (pspec->pd.tcp.flags & TH_ECE)
        *f++ = 'E'; /* rfc 2481/3168 */
      if (pspec->pd.tcp.flags & TH_CWR)
        *f++ = 'C'; /* rfc 2481/3168 */
      *f++ = '\0';
    }
    Snprintf(buf, bufsz, "tcp to port %hu; flags: %s", pspec->pd.tcp.dport, flagbuf);
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
  case PS_ICMPV6:
    Snprintf(buf, bufsz, "icmpv6 type %d code %d",
             pspec->pd.icmpv6.type, pspec->pd.icmpv6.code);
    break;
  case PS_ND:
    Snprintf(buf, bufsz, "ND");
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

UltraProbe::UltraProbe() {
  type = UP_UNSET;
  tryno.opaque = 0;
  timedout = false;
  retransmitted = false;
  mypspec.type = PS_NONE;
  memset(&sent, 0, sizeof(prevSent));
  memset(&prevSent, 0, sizeof(prevSent));
}

UltraProbe::~UltraProbe() {
  if (type == UP_CONNECT)
    delete probes.CP;
}

GroupScanStats::GroupScanStats(UltraScanInfo *UltraSI) {
  memset(&latestip, 0, sizeof(latestip));
  memset(&timeout, 0, sizeof(timeout));
  USI = UltraSI;
  init_ultra_timing_vals(&timing, TIMING_GROUP, USI->numIncompleteHosts(), &(USI->perf), &USI->now);
  initialize_timeout_info(&to);
  /* Default timeout should be much lower for arp */
  if (USI->ping_scan_arp)
    to.timeout = box(o.minRttTimeout(), o.initialRttTimeout(), INITIAL_ARP_RTT_TIMEOUT) * 1000;
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

  static time_t max_rate_add = o.max_packet_send_rate != 0.0 ?
    (1000000.0 / o.max_packet_send_rate) : 0;
  static time_t min_rate_add = o.min_packet_send_rate != 0.0 ?
    (1000000.0 / o.min_packet_send_rate) : 0;

  if (o.max_packet_send_rate != 0.0)
      TIMEVAL_ADD(send_no_earlier_than, send_no_earlier_than, max_rate_add);
  /* Allow send_no_earlier_than to slip into the past. This allows the sending
     scheduler to catch up and make up for delays in other parts of the scan
     engine. If we were to update send_no_earlier_than to the present the
     sending rate could be much less than the maximum requested, even if the
     connection is capable of the maximum. */

  if (o.min_packet_send_rate != 0.0) {
      if (TIMEVAL_AFTER(send_no_later_than, USI->now)) {
        /* The next scheduled send is in the future. That means there's slack time
           during which the sending rate could drop. Pull the time back to the
           present to prevent that. */
        send_no_later_than = USI->now;
      }
      TIMEVAL_ADD(send_no_later_than, send_no_later_than, min_rate_add);
  }
}

/* Returns true if the GLOBAL system says that sending is OK.*/
bool GroupScanStats::sendOK(struct timeval *when) const {
  int recentsends;

  /* In case it's not okay to send, arbitrarily say to check back in one
     second. */
  if (when)
    TIMEVAL_MSEC_ADD(*when, USI->now, 1000);

  if (CSI && !CSI->sendOK())
    return false;

  /* We need to stop sending if it has been a long time since
     the last listen call, at least for systems such as Windows that
     don't give us a proper pcap time.  Also for connect scans, since
     we don't get an exact response time with them either. */
  recentsends = USI->gstats->probes_sent - USI->gstats->probes_sent_at_last_wait;
  if (recentsends > 0 &&
      (USI->scantype == CONNECT_SCAN || USI->ptech.connecttcpscan || !pcap_recv_timeval_valid())) {
    int to_ms = MAX(to.srtt * 3 / 4000, 50);
    if (TIMEVAL_MSEC_SUBTRACT(USI->now, last_wait) > to_ms)
      return false;
  }

  /* Enforce a maximum scanning rate, if necessary. If it's too early to send,
     return false. If not, mark now as a good time to send and allow the
     congestion control to override it. */
  if (o.max_packet_send_rate != 0.0) {
    if (TIMEVAL_AFTER(send_no_earlier_than, USI->now)) {
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
    if (TIMEVAL_AFTER(send_no_later_than, USI->now)) {
      if (when)
        *when = send_no_later_than;
    } else {
      if (when)
        *when = USI->now;
      return true;
    }
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

  /* In case the user specifically asked for no group congestion control */
  if (o.nogcc) {
    if (when)
      *when = USI->now;
    return true;
  }

  /* When there is only one target left, let the host congestion
     stuff deal with it. */
  if (USI->numIncompleteHosts() < 2) {
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

/* Return true if pingprobe is an appropriate ping probe for the currently
   running scan. Because ping probes persist between host discovery and port
   scanning stages, it's possible to have a ping probe that is not relevant for
   the scan type, or won't be caught by the pcap filters. Examples of
   inappropriate ping probes are an ARP ping for a TCP scan, or a raw SYN ping
   for a connect scan. */
static bool pingprobe_is_appropriate(const UltraScanInfo *USI,
                                     const probespec *pingprobe) {
  switch (pingprobe->type) {
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
    return ((USI->ping_scan && !USI->ping_scan_arp ) || pingprobe->pd.icmp.type == 3);
  case(PS_ARP):
    return USI->ping_scan_arp;
  case(PS_ND):
    return USI->ping_scan_nd;
  }
  return false;
}

HostScanStats::HostScanStats(Target *t, UltraScanInfo *UltraSI) {
  target = t;
  USI = UltraSI;
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
  ports_finished = 0;
  numprobes_sent = 0;
  memset(&completiontime, 0, sizeof(completiontime));
  init_ultra_timing_vals(&timing, TIMING_HOST, 1, &(USI->perf), &USI->now);
  bench_tryno = 0;
  memset(&sdn, 0, sizeof(sdn));
  sdn.last_boost = USI->now;
  sdn.delayms = o.scan_delay;
  sdn.maxdelay = USI->tcp_scan ? o.maxTCPScanDelay() :
                 USI->udp_scan ? o.maxUDPScanDelay() :
                 o.maxSCTPScanDelay();
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
  std::list<UltraProbe *>::iterator probeI, next;

  /* Move any hosts from the bench to probes_outstanding for easier deletion  */
  for (probeI = probes_outstanding.begin(); probeI != probes_outstanding.end();
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
unsigned long HostScanStats::probeTimeout() const {
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
   depend on the type of probe. */
unsigned long HostScanStats::probeExpireTime(const UltraProbe *probe,
                                             unsigned long to_us) const {
  if (probe->type == UltraProbe::UP_CONNECT)
    /* timedout probes close socket -- late resp. impossible */
    return to_us;
  else
    /* Wait a bit longer after probeTimeout. */
    return 10 * MIN(1000000, to_us);
}

/* Returns OK if sending a new probe to this host is OK (to avoid
   flooding). If when is non-NULL, fills it with the time that sending
   will be OK assuming no pending probes are resolved by responses
   (call it again if they do).  when will become now if it returns
   true. */
bool HostScanStats::sendOK(struct timeval *when) const {
  struct ultra_timing_vals tmng;
  std::list<UltraProbe *>::const_iterator probeI;
  struct timeval probe_to, earliest_to, sendTime;
  long tdiff;

  if ((!USI->ping_scan && target->timedOut(&USI->now)) || completed()) {
    if (when)
      *when = USI->now;
    return false;
  }

  /* If the group stats say we need to send a probe to enforce a minimum
     scanning rate, then we need to step up and send a probe. */
  if (o.min_packet_send_rate != 0.0) {
    if (!TIMEVAL_AFTER(USI->gstats->send_no_later_than, USI->now)) {
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
      if (when) {
        TIMEVAL_MSEC_ADD(*when, lastprobe_sent, sdn.delayms);
      }
      return false;
    }
  }

  getTiming(&tmng);
  if (tmng.cwnd >= num_probes_active + .5 &&
      (freshPortsLeft() || num_probes_waiting_retransmit || !retry_stack.empty())) {
    if (when)
      *when = USI->now;
    return true;
  }

  if (!when)
    return false;

  TIMEVAL_MSEC_ADD(earliest_to, USI->now, 10000);

  // Any timeouts coming up?
  unsigned long msec_to = probeTimeout() / 1000;
  for (probeI = probes_outstanding.begin(); probeI != probes_outstanding.end();
       probeI++) {
    if (!(*probeI)->timedout) {
      TIMEVAL_MSEC_ADD(probe_to, (*probeI)->sent, msec_to);
      if (TIMEVAL_BEFORE(probe_to, earliest_to)) {
        earliest_to = probe_to;
      }
      // probes_outstanding is in order by time sent, so
      // the first one we find is the earliest.
      break;
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

/* If there are pending probe timeouts, compares the earliest one with `when`;
   if it is earlier than `when`, replaces `when` with the time of
   the earliest one and returns true.  Otherwise returns false. */
bool HostScanStats::soonerTimeout(struct timeval *when) const {
  std::list<UltraProbe *>::const_iterator probeI, endI;

  /* For any given invocation, the probe timeout is the same for all probes, so
   * we can get the earliest-sent probe and then add the timeout to that.
   */
  for (probeI = probes_outstanding.begin(), endI = probes_outstanding.end();
      probeI != endI; probeI++) {
    UltraProbe *probe = *probeI;
    if (!probe->timedout) {
      unsigned long usec_to = probeTimeout();
      struct timeval our_when;
      TIMEVAL_ADD(our_when, probe->sent, usec_to);
      // probes_outstanding is in order by time sent, so
      // the first one we find is the earliest.
      if (TIMEVAL_BEFORE(our_when, *when)) {
        // If ours is earlier, replace when.
        *when = our_when;
        return true;
      }
      // regardless, there are no earlier probes, so stop looking.
      break;
    }
  }
  return false;
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
   which have reached the given limit may be dealt with. */
unsigned int HostScanStats::allowedTryno(bool *capped, bool *mayincrease) const {
  std::list<UltraProbe *>::const_iterator probeI;
  UltraProbe *probe = NULL;
  bool allfinished = true;
  bool tryno_mayincrease = true;
  unsigned int maxval = 0;

  /* TODO: This should perhaps differ by scan type. */
  maxval = MAX(1, max_successful_tryno + 1);
  if (maxval > USI->perf.tryno_cap) {
    if (capped)
      *capped = true;
    maxval = USI->perf.tryno_cap;
    tryno_mayincrease = false; /* It never exceeds the cap */
  } else if (capped) *capped = false;

  // Only do this work if the caller needs to know
  if (mayincrease) {
    /* Decide if the tryno can possibly increase.  */
    if (tryno_mayincrease && num_probes_active == 0 && !freshPortsLeft()) {
      /* If every outstanding probe is timedout and at maxval, then no further
         retransmits are necessary. */
      for (probeI = probes_outstanding.begin();
          probeI != probes_outstanding.end(); probeI++) {
        probe = *probeI;
        assert(probe->timedout);
        if (!probe->retransmitted && !probe->isPing() && probe->get_tryno() < maxval) {
          /* Needs at least one more retransmit. */
          allfinished = false;
          break;
        }
      }
      if (allfinished)
        tryno_mayincrease = false;
    }

    *mayincrease = tryno_mayincrease;
  }

  return maxval;
}


UltraScanInfo::UltraScanInfo() {
}

UltraScanInfo::~UltraScanInfo() {
  std::multiset<HostScanStats *, HssPredicate>::iterator hostI;

  for (hostI = incompleteHosts.begin(); hostI != incompleteHosts.end(); hostI++) {
    delete *hostI;
  }

  for (hostI = completedHosts.begin(); hostI != completedHosts.end(); hostI++) {
    delete *hostI;
  }

  incompleteHosts.clear();
  completedHosts.clear();

  delete gstats;
  delete SPM;
  if (rawsd >= 0) {
    close(rawsd);
    rawsd = -1;
  }
  if (pd) {
    pcap_close(pd);
    pd = NULL;
  }
  if (ethsd) {
    ethsd = NULL; /* NO need to eth_close it due to caching */
  }
}

/* Returns true if this scan is a "raw" scan. A raw scan is ont that requires a
   raw socket or ethernet handle to send, or a pcap sniffer to receive.
   Basically, any scan type except pure TCP connect scans are raw. */
bool UltraScanInfo::isRawScan() const {
  return scantype != CONNECT_SCAN
         && (tcp_scan || udp_scan || sctp_scan || prot_scan || ping_scan_arp || ping_scan_nd
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
double UltraScanInfo::getCompletionFraction() const {
  std::multiset<HostScanStats *, HssPredicate>::const_iterator hostI;
  double total;

  /* Add 1 for each completed host. */
  total = gstats->numtargets - numIncompleteHosts();
  /* Get the completion fraction for each incomplete host. */
  for (hostI = incompleteHosts.begin(); hostI != incompleteHosts.end(); hostI++) {
    const HostScanStats *host = *hostI;
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

/* Initialize the state for ports that don't receive a response in all the
   targets. */
static void set_default_port_state(std::vector<Target *> &targets, stype scantype) {
  std::vector<Target *>::iterator target;

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
      (*target)->ports.setDefaultPortState(IPPROTO_UDP,
        o.defeat_icmp_ratelimit ? PORT_CLOSEDFILTERED : PORT_OPENFILTERED);
      break;
    case IPPROT_SCAN:
      (*target)->ports.setDefaultPortState(IPPROTO_IP, PORT_OPENFILTERED);
      break;
    case SCTP_COOKIE_ECHO_SCAN:
      (*target)->ports.setDefaultPortState(IPPROTO_SCTP, PORT_OPENFILTERED);
      break;
    case PING_SCAN:
    case PING_SCAN_ARP:
    case PING_SCAN_ND:
      break;
    default:
      fatal("Unexpected scan type found in %s()", __func__);
    }
  }
}

/* Order of initializations in this function CAN BE IMPORTANT, so be careful
 mucking with it. */
void UltraScanInfo::Init(std::vector<Target *> &Targets, const struct scan_lists *pts, stype scantp) {
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
  ping_scan = noresp_open_scan = ping_scan_arp = ping_scan_nd = false;
  memset((char *) &ptech, 0, sizeof(ptech));
  perf.init();
  switch (scantype) {
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
    if (o.pingtype & (PINGTYPE_ICMP_PING | PINGTYPE_ICMP_MASK | PINGTYPE_ICMP_TS))
      ptech.rawicmpscan = 1;
    if (o.pingtype & PINGTYPE_UDP)
      ptech.rawudpscan = 1;
    if (o.pingtype & PINGTYPE_SCTP_INIT)
      ptech.rawsctpscan = 1;
    if (o.pingtype & PINGTYPE_TCP) {
      if (o.isr00t)
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
    /* For ARP and ND scan, we send pings more frequently. Otherwise we can't
     * notice drops until we start sending retransmits after RLD_TIME_MS. */
    perf.pingtime = RLD_TIME_MS * 1000 / 4;
    break;
  case PING_SCAN_ND:
    ping_scan = true;
    ping_scan_nd = true;
    perf.pingtime = RLD_TIME_MS * 1000 / 4;
    break;
  default:
    break;
  }

  set_default_port_state(Targets, scantype);

  memset(&lastCompletedHostRemoval, 0, sizeof(lastCompletedHostRemoval));

  for (targetno = 0; targetno < Targets.size(); targetno++) {
    if (Targets[targetno]->timedOut(&now)) {
      num_timedout++;
      continue;
    }

    hss = new HostScanStats(Targets[targetno], this);
    incompleteHosts.insert(hss);
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
    /* If eth failed, we can fall back to raw socket. The only exception is
     * ARP ping, which needs Ethernet link. */
    int sendpref = o.sendpref;
    if (ping_scan_arp) {
      assert(!(sendpref & PACKET_SEND_IP_STRONG));
      sendpref = PACKET_SEND_ETH;
    }
    if (!raw_socket_or_eth(sendpref, Targets[0]->deviceName(), &rawsd, &ethsd)) {
      fatal("Couldn't open a raw socket or eth handle.");
    }
    /* Raw scan types also need to know the source IP. */
    Targets[0]->SourceSockAddr(&sourceSockAddr, NULL);
  }
  base_port = UltraScanInfo::increment_base_port();
}

/* Return the total number of probes that may be sent to each host. This never
   changes after initialization. */
unsigned int UltraScanInfo::numProbesPerHost() const {
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
  } else if (ping_scan_nd) {
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
  } else assert(0);

  return numprobes;
}

/* Consults with the group stats, and the hstats for every
   incomplete hosts to determine whether any probes may be sent.
   Returns true if they can be sent immediately.  If when is
   non-NULL, it is filled with the next possible time that probes
   can be sent, assuming no probe responses are received (call it
   again if they are).  when will be now, if the function returns
   true */
bool UltraScanInfo::sendOK(struct timeval *when) const {
  struct timeval lowhtime = {0};
  struct timeval tmptv;
  std::multiset<HostScanStats *, HssPredicate>::const_iterator host;
  bool ggood = false;
  bool thisHostGood = false;
  bool foundgood = false;

  ggood = gstats->sendOK(when);

  if (!ggood) {
    if (when) {
      lowhtime = *when;
      // Can't do anything until global is OK - means packet receipt
      // or probe timeout.
      for (host = incompleteHosts.begin(); host != incompleteHosts.end();
           host++) {
        (*host)->soonerTimeout(&lowhtime);
      }
      *when = lowhtime;
    }
  } else {
    for (host = incompleteHosts.begin(); host != incompleteHosts.end(); host++) {
      thisHostGood = (*host)->sendOK(&tmptv);
      if (ggood && thisHostGood) {
        lowhtime = tmptv;
        foundgood = true;
        break;
      }

      if (!foundgood || TIMEVAL_AFTER(lowhtime, tmptv)) {
        lowhtime = tmptv;
        foundgood = true;
      }
    }

    assert(foundgood);
  }

  /* Defer to the group stats if they need a shorter delay to enforce a minimum
     packet sending rate. */
  if (o.min_packet_send_rate != 0.0) {
    if (TIMEVAL_BEFORE(gstats->send_no_later_than, lowhtime))
      lowhtime = gstats->send_no_later_than;
  }

  if (TIMEVAL_BEFORE(lowhtime, now))
    lowhtime = now;

  if (when)
    *when = lowhtime;

  return (TIMEVAL_MSEC_SUBTRACT(lowhtime, now) == 0);
}

/* Find a HostScanStats by its IP address in the incomplete and completed lists.
   Returns NULL if none are found. */
HostScanStats *UltraScanInfo::findHost(const struct sockaddr_storage *ss) const {
  std::multiset<HostScanStats *, HssPredicate>::const_iterator hss;

  HssPredicate::ss = ss;
  HostScanStats *fakeHss = NULL;

  hss = incompleteHosts.find(fakeHss);
  if (hss != incompleteHosts.end()) {
    if (o.debugging > 2)
      log_write(LOG_STDOUT, "Found %s in incomplete hosts list.\n", (*hss)->target->targetipstr());
    return *hss;
  }

  hss = completedHosts.find(fakeHss);
  if (hss != completedHosts.end()) {
    if (o.debugging > 2)
      log_write(LOG_STDOUT, "Found %s in completed hosts list.\n", (*hss)->target->targetipstr());
    return *hss;
  }

  return NULL;
}

static bool pingprobe_is_better(const probespec *new_probe, int new_state,
                                const probespec *old_probe, int old_state);

/* Removes any hosts that have completed their scans from the incompleteHosts
   set, and remove any hosts from completedHosts which have exceeded their
   lifetime.  Returns the number of hosts removed. */
int UltraScanInfo::removeCompletedHosts() {
  std::multiset<HostScanStats *, HssPredicate>::iterator hostI, nxt;
  HostScanStats *hss = NULL;
  int hostsRemoved = 0;
  bool timedout = false;
  struct timeval compare;

  /* We don't want to run this all of the time */
  TIMEVAL_MSEC_ADD(compare, lastCompletedHostRemoval, COMPL_HOST_LIFETIME_MS / 2);
  if (TIMEVAL_AFTER(now, compare) ) {
    /* Remove any that were completed before this time: */
    TIMEVAL_MSEC_ADD(compare, now, -COMPL_HOST_LIFETIME_MS);
    for (hostI = completedHosts.begin(); hostI != completedHosts.end(); hostI = nxt) {
      nxt = hostI;
      nxt++;
      hss = (*hostI);

      /* Keep it if it's our port scan ping host */
      if (hss == gstats->pinghost)
        continue;

      if (TIMEVAL_BEFORE(hss->completiontime, compare) ) {
        /* Any active probes in completed hosts count against our global
         * cwnd, so be sure to remove them or we can run out of space. */
        hss->destroyAllOutstandingProbes();
        completedHosts.erase(hostI);
        hostsRemoved++;
      }
    }
    lastCompletedHostRemoval = now;
  }

  for (hostI = incompleteHosts.begin(); hostI != incompleteHosts.end();
       hostI = nxt) {
    nxt = hostI;
    nxt++;
    hss = *hostI;
    assert(hss);
    // Don't bother checking timedOut for discovery scans or if the target is already completed.
    if (hss->completed() || (timedout = (!ping_scan) && hss->target->timedOut(&now)) != false) {
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
                    TIMEVAL_FSEC_SUBTRACT(now, SPM->begin), remain,
                    (remain == 1) ? "host left" : "hosts left");
        else if (timedout)
          log_write(LOG_STDOUT, "%s timed out during %s (%d %s)\n",
                    hss->target->targetipstr(), scantype2str(scantype), remain,
                    (remain == 1) ? "host left" : "hosts left");
      }
      if (o.debugging > 2) {
        unsigned int num_outstanding_probes;
        num_outstanding_probes = hss->num_probes_outstanding();
        log_write(LOG_PLAIN, "Moving %s to completed hosts list with %d outstanding %s.\n",
                  hss->target->targetipstr(), num_outstanding_probes,
                  num_outstanding_probes == 1 ? "probe" : "probes");
        if (o.debugging > 3) {
          char tmpbuf[64];
          std::list<UltraProbe *>::const_iterator iter;
          for (iter = hss->probes_outstanding.begin(); iter != hss->probes_outstanding.end(); iter++)
            log_write(LOG_PLAIN, "* %s\n", probespec2ascii((probespec *) (*iter)->pspec(), tmpbuf, sizeof(tmpbuf)));
        }
      }
      hss->completiontime = now;
      completedHosts.insert(hss);
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
      if (timedout)
        gstats->num_hosts_timedout++;
      /* We may have received an ARP response before we sent a probe, which
       * would mean the timeout clock is not running. Avoid an assertion
       * failure here by checking first.  */
      if (hss->target->timeOutClockRunning()) {
        hss->target->stopTimeOutClock(&now);
      }
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
                           const struct scan_lists *ports) {
  int groupsize = 16;

  if (o.UDPScan())
    groupsize = 128;
  else if (o.SCTPScan())
    groupsize = 128;
  else if (o.TCPScan()) {
    groupsize = MAX(1024 / (ports->tcp_count ? ports->tcp_count : 1), 64);
    if (ports->tcp_count > 1000 && o.timing_level <= 4) {
      int quickgroupsz = 4;
      if (o.timing_level == 4)
        quickgroupsz = 8;
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

  if (o.max_ips_to_scan && (o.max_ips_to_scan - hosts_scanned_so_far) < (unsigned int)groupsize)
    // don't scan more randomly generated hosts than was specified
    groupsize = o.max_ips_to_scan - hosts_scanned_so_far;

  return groupsize;
}

/* Initialize the ultra_timing_vals structure timing.  The utt must be
   TIMING_HOST or TIMING_GROUP.  If you happen to have the current
   time handy, pass it as now, otherwise pass NULL */
static void init_ultra_timing_vals(ultra_timing_vals *timing,
                                   enum ultra_timing_type utt,
                                   int num_hosts_in_group,
                                   const struct ultra_scan_performance_vars *perf,
                                   const struct timeval *now) {
  timing->cwnd = (utt == TIMING_HOST) ? perf->host_initial_cwnd : perf->group_initial_cwnd;
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
static int get_next_target_probe(const UltraScanInfo *USI, HostScanStats *hss,
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
      switch (USI->scantype) {
      case SYN_SCAN:
        pspec->pd.tcp.flags = TH_SYN;
        break;
      case ACK_SCAN:
        pspec->pd.tcp.flags = TH_ACK;
        break;
      case XMAS_SCAN:
        pspec->pd.tcp.flags = TH_FIN | TH_URG | TH_PUSH;
        break;
      case NULL_SCAN:
        pspec->pd.tcp.flags = 0;
        break;
      case FIN_SCAN:
        pspec->pd.tcp.flags = TH_FIN;
        break;
      case MAIMON_SCAN:
        pspec->pd.tcp.flags = TH_FIN | TH_ACK;
        break;
      case WINDOW_SCAN:
        pspec->pd.tcp.flags = TH_ACK;
        break;
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
  } else if (USI->ping_scan_nd) {
    if (hss->sent_arp)
      return -1;
    pspec->type = PS_ND;
    hss->sent_arp = true;
    return 0;
  } else if (USI->ping_scan) {
    /* This is ordered to try probes of higher effectiveness first:
         -PE -PS -PA -PP -PU
       -PA is slightly better than -PS when combined with -PE, but give -PS an
       edge because it is less likely to be dropped by firewalls. */
    if (USI->ptech.rawicmpscan) {
      if (hss->target->af() == AF_INET6) {
        pspec->type = PS_ICMPV6;
        pspec->proto = IPPROTO_ICMPV6;
        if ((o.pingtype & PINGTYPE_ICMP_PING) && !hss->sent_icmp_ping) {
          hss->sent_icmp_ping = true;
          pspec->pd.icmp.type = ICMPV6_ECHO;
          pspec->pd.icmp.code = 0;
          return 0;
        }
      }
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
    if (USI->ptech.rawprotoscan && hss->next_protoportpingidx < USI->ports->proto_ping_count) {
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

/* Returns whether there are ports remaining to probe */
bool HostScanStats::freshPortsLeft() const {
  if (USI->tcp_scan) {
    return (next_portidx < USI->ports->tcp_count);
  } else if (USI->udp_scan) {
    return (next_portidx < USI->ports->udp_count);
  } else if (USI->sctp_scan) {
    return (next_portidx < USI->ports->sctp_count);
  } else if (USI->prot_scan) {
    return (next_portidx < USI->ports->prot_count);
  } else if (USI->ping_scan_arp || USI->ping_scan_nd) {
    return !sent_arp;
  } else if (USI->ping_scan) {
    if (USI->ptech.rawtcpscan) {
      if (o.pingtype & PINGTYPE_TCP_USE_ACK && next_ackportpingidx < USI->ports->ack_ping_count)
        return true;
      if (o.pingtype & PINGTYPE_TCP_USE_SYN && next_synportpingidx < USI->ports->syn_ping_count)
        return true;
    }
    if (USI->ptech.rawicmpscan) {
      if ((o.pingtype & PINGTYPE_ICMP_PING) && !sent_icmp_ping)
        return true;
      if ((o.pingtype & PINGTYPE_ICMP_MASK) && !sent_icmp_mask)
        return true;
      if ((o.pingtype & PINGTYPE_ICMP_TS) && !sent_icmp_ts)
        return true;
    }
    if (USI->ptech.connecttcpscan && next_synportpingidx < USI->ports->syn_ping_count)
      return true;
    if (USI->ptech.rawudpscan && next_udpportpingidx < USI->ports->udp_ping_count)
      return true;
    if (USI->ptech.rawsctpscan && next_sctpportpingidx < USI->ports->sctp_ping_count)
      return true;
    if (USI->ptech.rawprotoscan && next_protoportpingidx < USI->ports->proto_ping_count)
      return true;
    return false;
  }
  assert(0);
  return false;
}

/* Returns the number of ports remaining to probe */
int HostScanStats::numFreshPortsLeft() const {
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
    if (sent_arp)
      return 0;
    return 1;
  } else if (USI->ping_scan_nd) {
    if (sent_arp)
      return 0;
    return 1;
  } else if (USI->ping_scan) {
    unsigned int num_probes = 0;
    if (USI->ptech.rawtcpscan) {
      if (o.pingtype & PINGTYPE_TCP_USE_ACK)
        num_probes += USI->ports->ack_ping_count - next_ackportpingidx;
      if (o.pingtype & PINGTYPE_TCP_USE_SYN)
        num_probes += USI->ports->syn_ping_count - next_synportpingidx;
    }
    if (USI->ptech.rawudpscan)
      num_probes += USI->ports->udp_ping_count - next_udpportpingidx;
    if (USI->ptech.rawsctpscan)
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
    if (USI->ptech.connecttcpscan)
      num_probes += USI->ports->syn_ping_count - next_synportpingidx;
    return num_probes;
  }
  assert(0);
  return 0;
}

/* Removes a probe from probes_outstanding, adjusts HSS and USS
   active probe stats accordingly, then deletes the probe. */
void HostScanStats::destroyOutstandingProbe(std::list<UltraProbe *>::iterator probeI) {
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
  while (!probes_outstanding.empty())
    destroyOutstandingProbe(probes_outstanding.begin());
}

/* Adjust host and group timeouts (struct timeout_info) based on a received
   packet. If rcvdtime is NULL, nothing is updated.

   This function is called for every probe response received, in order to keep
   an accurate timeout estimate. ultrascan_adjust_timing, on the other hand, is
   not called when a response is not useful for adjusting other timing
   variables. */
static void ultrascan_adjust_timeouts(UltraScanInfo *USI, HostScanStats *hss,
                                      const UltraProbe *probe,
                                      const struct timeval *rcvdtime) {
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
                                    const UltraProbe *probe,
                                    const struct timeval *rcvdtime) {
  int ping_magnifier = (probe->isPing()) ? USI->perf.ping_magnifier : 1;

  USI->gstats->timing.num_replies_expected++;
  USI->gstats->timing.num_updates++;

  hss->timing.num_replies_expected++;
  hss->timing.num_updates++;

  /* Notice a drop if
     1) We get a response to a retransmitted probe (meaning the first reply was
        dropped), or
     2) We got no response to a timing ping. */
  bool is_drop = (!probe->isPing() && probe->get_tryno() > 0 && rcvdtime != NULL)
                  || (probe->isPing() && rcvdtime == NULL);
  if (is_drop) {
    if (o.debugging > 1)
      log_write(LOG_PLAIN, "Ultrascan DROPPED %sprobe packet to %s detected\n", probe->isPing() ? "PING " : "", hss->target->targetipstr());
    // Drops often come in big batches, but we only want one decrease per batch.
    if (TIMEVAL_AFTER(probe->sent, hss->timing.last_drop))
      hss->timing.drop(hss->num_probes_active, &USI->perf, &USI->now);
    if (TIMEVAL_AFTER(probe->sent, USI->gstats->timing.last_drop))
      USI->gstats->timing.drop_group(USI->gstats->num_probes_active, &USI->perf, &USI->now);
  }
  /* If !probe->isPing() and rcvdtime == NULL, do nothing. */

  /* Increase the window for a positive reply. This can overlap with case (1)
     above. */
  if (rcvdtime != NULL) {
    USI->gstats->timing.ack(&USI->perf, ping_magnifier);
    hss->timing.ack(&USI->perf, ping_magnifier);
  }

  /* If packet drops are particularly bad, enforce a delay between
     packet sends (useful for cases such as UDP scan where responses
     are frequently rate limited by dest machines or firewalls) */

  /* First we decide whether this packet counts as a drop for send
     delay calculation purposes.  This statement means if (a ping since last boost failed, or the previous packet was both sent after the last boost and dropped) */
  if (is_drop && TIMEVAL_AFTER(probe->sent, hss->sdn.last_boost)) {
    hss->sdn.droppedRespSinceDelayChanged++;
    //    printf("SDELAY: increasing drops to %d (good: %d; tryno: %d, sent: %.4fs; prevSent: %.4fs, last_boost: %.4fs\n", hss->sdn.droppedRespSinceDelayChanged, hss->sdn.goodRespSinceDelayChanged, probe->tryno, o.TimeSinceStartMS(&probe->sent) / 1000.0, o.TimeSinceStartMS(&probe->prevSent) / 1000.0, o.TimeSinceStartMS(&hss->sdn.last_boost) / 1000.0);
  } else if (rcvdtime) {
    hss->sdn.goodRespSinceDelayChanged++;
    //    printf("SDELAY: increasing good to %d (bad: %d)\n", hss->sdn.goodRespSinceDelayChanged, hss->sdn.droppedRespSinceDelayChanged);
  }

  /* Now change the send delay if necessary */
  unsigned int oldgood = hss->sdn.goodRespSinceDelayChanged;
  unsigned int oldbad = hss->sdn.droppedRespSinceDelayChanged;
  double threshold = (o.timing_level >= 4) ? 0.40 : 0.30;
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
void HostScanStats::markProbeTimedout(std::list<UltraProbe *>::iterator probeI) {
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

bool HostScanStats::completed() const {
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
  return !freshPortsLeft();
}

/* This function provides the proper cwnd and ssthresh to use.  It may
   differ from versions in timing member var because when no responses
   have been received for this host, may look at others in the group.
   For CHANGING this host's timing, use the timing memberval
   instead. */
void HostScanStats::getTiming(struct ultra_timing_vals *tmng) const {
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
      ARP/ND
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
      score = 20;
    else if (pspec->pd.tcp.flags == TH_SYN && (state == PORT_OPEN || state == PORT_UNKNOWN))
      score = 30;
    else if (pspec->pd.tcp.dport == 25 ||
      pspec->pd.tcp.dport == 113 ||
      pspec->pd.tcp.dport == 135 ||
      pspec->pd.tcp.dport == 139 ||
      pspec->pd.tcp.dport == 445)
      /* Frequently spoofed port numbers */
      score = 50;
    else
      score = 60;
    break;
  case PS_SCTP:
    if (state == PORT_FILTERED) /* Received an ICMP error. */
      score = 20;
    else if (state == PORT_OPEN || state == PORT_UNKNOWN)
      score = 30;
    else
      score = 60;
    break;
  case PS_ICMP:
    if (pspec->pd.icmp.type == ICMP_ECHO || pspec->pd.icmp.type == ICMP_MASK || pspec->pd.icmp.type == ICMP_TSTAMP)
      score = 50;
    else
      score = 20;
    break;
  case PS_ARP:
  case PS_ND:
    score = 40;
    break;
  case PS_UDP:
    // Penalize ports with many payloads, since we can't be sure which one responded.
    score = 20 - udp_payload_count(pspec->pd.udp.dport);
    // But one payload is ok
    if (score == 19)
      score = 20;
    break;
  case PS_PROTO:
    score = 20;
    break;
  case PS_CONNECTTCP:
    score = 10;
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

static bool ultrascan_host_pspec_update(const UltraScanInfo *USI, HostScanStats *hss,
                                        const probespec *pspec, int newstate);

/* Like ultrascan_port_probe_update(), except it is called with just a
   probespec rather than a whole UltraProbe.  Returns true if the port
   was added or at least the state was changed.  */
static bool ultrascan_port_pspec_update(const UltraScanInfo *USI,
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

  // Set new port state, pending checks for valid state transitions
  hss->target->ports.setPortState(portno, proto, newstate, &oldstate);

  /*    printf("TCP port %hu has changed from state %s to %s!\n", portno, statenum2str(oldstate), statenum2str(newstate)); */
  if (newstate != oldstate) {
    // Check for conditions that mean we should ignore newstate (revert to oldstate)
    switch (oldstate) {
      /* TODO: I need more code here to determine when a state should
         be overridden, for example PORT_OPEN trumps PORT_FILTERED
         in a SYN scan, but not necessarily for UDP scan */
      case PORT_TESTING:
        /* Brand new port -- add it to the list */
        hss->ports_finished++;
        break;
      case PORT_OPEN:
        // Changing from open to anything else only valid for noresp_open_scan
        if (!noresp_open_scan) {
          hss->target->ports.setPortState(portno, proto, oldstate);
        }
        break;
      case PORT_CLOSED:
        // Changing from closed to filtered is never allowed.
        // Changing from closed to anything else is never valid for noresp_open_scan
        if (noresp_open_scan || newstate == PORT_FILTERED)
          hss->target->ports.setPortState(portno, proto, oldstate);
        break;
      case PORT_FILTERED:
        // Changing from filtered to open is not allowed for noresp_open_scan
          if (noresp_open_scan && newstate == PORT_OPEN)
            hss->target->ports.setPortState(portno, proto, oldstate);
        break;
      case PORT_UNFILTERED:
        /* This could happen in an ACK scan if I receive a RST and then an
           ICMP filtered message.  I'm gonna stick with unfiltered in that
           case.  I'll change it if the new state is open or closed,
           though I don't expect that to ever happen */
        if (newstate != PORT_OPEN && newstate != PORT_CLOSED)
          hss->target->ports.setPortState(portno, proto, oldstate);
        break;
      case PORT_OPENFILTERED:
        // Always accepted.
        break;
      default:
        fatal("Unexpected port state: %d\n", oldstate);
        break;
    }
  }

  return oldstate != newstate;
}

/* Boost the scan delay for this host, usually because too many packet
   drops were detected. */
void HostScanStats::boostScanDelay() {
  if (sdn.delayms < 1000) {
    if (sdn.delayms == 0)
      sdn.delayms = (USI->udp_scan) ? 50 : 5; // In many cases, a pcap wait takes a minimum of 80ms, so this matters little :(
    else
      sdn.delayms = MIN(sdn.delayms * 2, 1000);
  }
  sdn.delayms = MIN(sdn.delayms, sdn.maxdelay);
  sdn.last_boost = USI->now;
  sdn.droppedRespSinceDelayChanged = 0;
  sdn.goodRespSinceDelayChanged = 0;
}

/* Dismiss all probe attempts on bench -- hosts are marked down and ports will
   be set to whatever the default port state is for the scan. */
void HostScanStats::dismissBench() {
  if (probe_bench.empty())
    return;
  while (!probe_bench.empty()) {
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
  if (probe_bench.empty())
    return;

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
void HostScanStats::moveProbeToBench(std::list<UltraProbe *>::iterator probeI) {
  UltraProbe *probe = *probeI;
  if (!probe_bench.empty())
    assert(bench_tryno == probe->get_tryno());
  else {
    bench_tryno = probe->get_tryno();
    probe_bench.reserve(128);
  }
  probe_bench.push_back(*probe->pspec());
  probes_outstanding.erase(probeI);
  num_probes_waiting_retransmit--;
  delete probe;
}

/* Called when a ping response is discovered. If adjust_timing is false, timing
   stats are not updated. */
void ultrascan_ping_update(UltraScanInfo *USI, HostScanStats *hss,
                                  std::list<UltraProbe *>::iterator probeI,
                                  const struct timeval *rcvdtime,
                                  bool adjust_timing) {
  ultrascan_adjust_timeouts(USI, hss, *probeI, rcvdtime);
  if (adjust_timing)
    ultrascan_adjust_timing(USI, hss, *probeI, rcvdtime);
  hss->destroyOutstandingProbe(probeI);
}

static const char *readhoststate(int state) {
  switch (state) {
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
static bool ultrascan_host_pspec_update(const UltraScanInfo *USI, HostScanStats *hss,
                                        const probespec *pspec, int newstate) {
  int oldstate = hss->target->flags;
  /* If the host is already up, ignore any further updates. */
  if (hss->target->flags != HOST_UP) {
    // don't allow HOST_UNKNOWN to override a known state.
    hss->target->flags = (newstate == HOST_UNKNOWN ? oldstate : newstate);
    /* For port scans (not -sn) where output may be delayed until more scan
     * phases are done, emit a hosthint element during host discovery when a
     * target is found to be up. */
    if (oldstate != newstate && newstate == HOST_UP &&
        !o.noportscan && USI->ping_scan) {
      write_xml_hosthint(hss->target);
    }
  }
  return hss->target->flags != oldstate;
}

static void ultrascan_host_timeout_init(const UltraScanInfo *USI, HostScanStats *hss) {
  // Don't count host discovery time against host timeout clock. For large
  // numbers of targets, we might be busy sending lots of new probes to new
  // targets, and that time shouldn't count against the individual target.
  if (!USI->ping_scan && !hss->target->timeOutClockRunning() && !hss->target->timedOut(NULL)) {
    if (o.debugging > 2) {
      log_write(LOG_STDOUT, "Ultrascan timeout init for %s at %.6f\n", hss->target->targetipstr(), TIMEVAL_SECS(USI->now));
    }
    hss->target->startTimeOutClock(&USI->now);
  }
}

/* Called when a new status is determined for host in hss (eg. it is
   found to be up or down by a ping/ping_arp scan.  The probe that led
   to this new decision is in probeI.  This function needs to update
   timing information and other stats as appropriate. If
   adjust_timing_hint is false, packet stats are not updated. */
void ultrascan_host_probe_update(UltraScanInfo *USI, HostScanStats *hss,
                                        std::list<UltraProbe *>::iterator probeI,
                                        int newstate, const struct timeval *rcvdtime,
                                        bool adjust_timing_hint) {
  const UltraProbe *probe = *probeI;

  if (o.debugging > 1) {
    struct timeval tv;

    gettimeofday(&tv, NULL);
    log_write(LOG_STDOUT, "%s called for machine %s state %s -> %s (trynum %d time: %ld)\n", __func__, hss->target->targetipstr(), readhoststate(hss->target->flags), readhoststate(newstate), probe->get_tryno(), (long) TIMEVAL_SUBTRACT(tv, probe->sent));
  }

  ultrascan_host_pspec_update(USI, hss, probe->pspec(), newstate);

  ultrascan_adjust_timeouts(USI, hss, probe, rcvdtime);

  /* Decide whether to adjust timing. We and together a bunch of conditions.
     First, don't adjust timing if adjust_timing_hint is false. */
  bool adjust_timing = adjust_timing_hint;
  bool adjust_ping = adjust_timing_hint;

  /* If we got a response that meant "down" or "unknown", then it was an ICMP error. These
     are often rate-limited (RFC 1812) or generated by a different host. We only
     allow such responses to increase, not decrease, scanning speed by
     disallowing drops (probe->get_tryno() > 0), and we don't allow changing the ping
     probe to something that's likely to get dropped. */
  if (rcvdtime != NULL && newstate != HOST_UP) {
    if (probe->get_tryno() > 0) {
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
void ultrascan_port_probe_update(UltraScanInfo *USI, HostScanStats *hss,
                                 std::list<UltraProbe *>::iterator probeI,
                                 int newstate, const struct timeval *rcvdtime,
                                 bool adjust_timing_hint) {
  const UltraProbe *probe = *probeI;
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
     not considering drops (probe->get_tryno() > 0), and we don't allow changing the
     ping probe to something that's likely to get dropped. */
  if (rcvdtime != NULL && newstate == PORT_FILTERED && !USI->noresp_open_scan) {
    if (probe->get_tryno() > 0) {
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
    if (probe->get_tryno() > 0)
      adjust_timing = false;
    adjust_ping = false;
  }
  /* Do not slow down if
     1)  we are in --defeat-icmp-ratelimit mode
     2)  the new state is closed or filtered
     3)  this is a UDP scan
     We don't want to adjust timing when we get ICMP response, as the host might
     be ratelimiting them. E.g. the port is actually closed, but the host ratelimiting
     ICMP responses so we had to retransmit the probe several times in order to
     match the (slow) rate limit that the target is using for responses. We
     do not want to waste time on such ports.
     On the other hand if the port is detected to be open it is a good idea to
     adjust timing as we could have done retransmissions due to conjested network */
  if (rcvdtime != NULL
      && o.defeat_icmp_ratelimit
      && (newstate == PORT_CLOSED || newstate == PORT_FILTERED)
      && USI->udp_scan) {
    if (probe->get_tryno() > 0)
      adjust_timing = false;
    adjust_ping = false;
  }

  if (adjust_timing) {
    ultrascan_adjust_timing(USI, hss, probe, rcvdtime);

    if (rcvdtime != NULL && probe->get_tryno() > hss->max_successful_tryno) {
      /* We got a positive response to a higher tryno than we've seen so far. */
      hss->max_successful_tryno = probe->get_tryno();
      if (o.debugging)
        log_write(LOG_STDOUT, "Increased max_successful_tryno for %s to %d (packet drop)\n", hss->target->targetipstr(), hss->max_successful_tryno);
      if (hss->max_successful_tryno > ((o.timing_level >= 4) ? 4 : 3)) {
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
      && pingprobe_is_better(pspec, newstate, &hss->target->pingprobe, hss->target->pingprobe_state)) {
    if (o.debugging > 1) {
      char buf[64];
      probespec2ascii(pspec, buf, sizeof(buf));
      log_write(LOG_PLAIN, "Changing ping technique for %s to %s\n", hss->target->targetipstr(), buf);
    }
    hss->target->pingprobe = *pspec;
    hss->target->pingprobe_state = newstate;
  }

  hss->destroyOutstandingProbe(probeI);
}

static void sendNextScanProbe(UltraScanInfo *USI, HostScanStats *hss) {
  probespec pspec;
  tryno_t tryno = {0};

  if (get_next_target_probe(USI, hss, &pspec) == -1) {
    fatal("%s: No more probes! Error in Nmap.", __func__);
  }
  hss->numprobes_sent++;
  USI->gstats->probes_sent++;
  if (pspec.type == PS_ARP)
    sendArpScanProbe(USI, hss, tryno);
  else if (pspec.type == PS_ND)
    sendNDScanProbe(USI, hss, tryno);
  else if (pspec.type == PS_CONNECTTCP)
    sendConnectScanProbe(USI, hss, pspec.pd.tcp.dport, tryno);
  else if (pspec.type == PS_TCP || pspec.type == PS_UDP
           || pspec.type == PS_SCTP || pspec.type == PS_PROTO
           || pspec.type == PS_ICMP || pspec.type == PS_ICMPV6)
    sendIPScanProbe(USI, hss, &pspec, tryno);
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

  tryno_t tryno = {0};
  tryno.fields.seqnum = pspec_tries + 1;

  if (pspec.type == PS_CONNECTTCP)
    sendConnectScanProbe(USI, hss, pspec.pd.tcp.dport, tryno);
  else {
    assert(pspec.type != PS_ARP && pspec.type != PS_ND);
    sendIPScanProbe(USI, hss, &pspec, tryno);
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
      ultrascan_host_timeout_init(USI, hss);
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
  tryno_t tryno = {0};
  tryno.fields.isPing = 1;
  tryno.fields.seqnum = hss->nextPingSeq();

  probespec *pingprobe = &hss->target->pingprobe;
  switch (pingprobe->type) {
    case PS_CONNECTTCP:
      sendConnectScanProbe(USI, hss, pingprobe->pd.tcp.dport, tryno);
      break;
    case PS_TCP:
    case PS_UDP:
    case PS_SCTP:
    case PS_PROTO:
    case PS_ICMP:
      sendIPScanProbe(USI, hss, pingprobe, tryno);
      break;
    case PS_ARP:
      sendArpScanProbe(USI, hss, tryno);
      break;
    case PS_ND:
      sendNDScanProbe(USI, hss, tryno);
      break;
    default:
      assert(0);
  }
  if (o.debugging > 1) {
    char tmpbuf[64];
    log_write(LOG_PLAIN, "Ultrascan PING SENT to %s [%s]\n", hss->target->targetipstr(),
              probespec2ascii(pingprobe, tmpbuf, sizeof(tmpbuf)));
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
  std::multiset<HostScanStats *, HssPredicate>::iterator hostI;
  HostScanStats *hss = NULL;

  gettimeofday(&USI->now, NULL);
  /* First single host pings */
  for (hostI = USI->incompleteHosts.begin();
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
  tryno_t tryno = probe->tryno;
  tryno.fields.seqnum++;
  if (probe->type == UltraProbe::UP_IP) {
    u8 proto = probe->protocol();
    assert(USI->prot_scan || USI->ptech.rawprotoscan
        || proto == IPPROTO_TCP || proto == IPPROTO_UDP || proto == IPPROTO_SCTP
        || proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6);
    newProbe = sendIPScanProbe(USI, hss, probe->pspec(), tryno);
  } else if (probe->type == UltraProbe::UP_CONNECT) {
    newProbe = sendConnectScanProbe(USI, hss, probe->pspec()->pd.tcp.dport, tryno);
  } else if (probe->type == UltraProbe::UP_ARP) {
    newProbe = sendArpScanProbe(USI, hss, tryno);
  } else if (probe->type == UltraProbe::UP_ND) {
    newProbe = sendNDScanProbe(USI, hss, tryno);
  } else {
    /* TODO: Support any other probe types */
    fatal("%s: unsupported probe type %d", __func__, probe->type);
  }
  if (newProbe)
    newProbe->prevSent = probe->sent;
  probe->retransmitted = true;
  assert(hss->num_probes_waiting_retransmit > 0);
  hss->num_probes_waiting_retransmit--;
  hss->numprobes_sent++;
  USI->gstats->probes_sent++;
}

struct ProbeCacheNode {
  HostScanStats *hss;
  std::list<UltraProbe *>::iterator probeI;
};

/* Go through the ProbeQueue of each host, identify any
   timed out probes, then try to retransmit them as appropriate */
static void doAnyOutstandingRetransmits(UltraScanInfo *USI) {
  std::multiset<HostScanStats *, HssPredicate>::iterator hostI;
  /* A cache of the last processed probe from each host, to avoid re-examining a
     bunch of probes to find the next one that needs to be retransmitted. */
  std::vector<struct ProbeCacheNode> probe_cache;
  HostScanStats *host = NULL;
  UltraProbe *probe = NULL;
  int retrans = 0; /* Number of retransmissions during a loop */
  unsigned int maxtries;

  struct timeval tv_start = {0};

  gettimeofday(&USI->now, NULL);

  if (o.debugging)
    tv_start = USI->now;

  probe_cache.reserve(USI->numIncompleteHosts());
  for (hostI = USI->incompleteHosts.begin();
      hostI != USI->incompleteHosts.end();
      hostI++) {
    struct ProbeCacheNode pcn;
    pcn.hss = *hostI;
    /* Skip this host if it has nothing to send. */
    if (pcn.hss->num_probes_active == 0
          && pcn.hss->num_probes_waiting_retransmit == 0)
      continue;
    assert(!pcn.hss->probes_outstanding.empty());
    pcn.probeI = pcn.hss->probes_outstanding.end();
    probe_cache.push_back(pcn);
  }
  /* Loop until we get through all the hosts without a retransmit or we're not
     OK to send any more. */
  do {
    retrans = 0;
    for (std::vector<struct ProbeCacheNode>::iterator pci = probe_cache.begin();
        pci != probe_cache.end() && USI->gstats->sendOK(NULL);
        pci++) {
      host = pci->hss;
      std::list<UltraProbe *>::iterator &probeI = pci->probeI;
      // Nothing drops off list during this function
      const std::list<UltraProbe *>::const_iterator &beginI = host->probes_outstanding.begin();
      /* Skip this host if it has nothing to send. */
      if ((host->num_probes_active == 0
           && host->num_probes_waiting_retransmit == 0))
        continue;
      if (!host->sendOK(NULL))
        continue;
      assert(!host->probes_outstanding.empty());

      maxtries = host->allowedTryno(NULL, NULL);
      do {
        probeI--;
        probe = *probeI;
        if (probe->retransmitted || probe->isPing()) {
          // Don't retransmit these
          continue;
        }
        // Retransmit if timed out and there are still tries remaining
        if (probe->timedout && maxtries > probe->get_tryno()) {
          /* For rate limit detection, we delay the first time a new tryno
             is seen, as long as we are scanning at least 2 ports */
          if (probe->get_tryno() + 1 > (int) host->rld.max_tryno_sent &&
              (USI->gstats->numprobes > 1 || USI->ping_scan_arp || USI->ping_scan_nd)) {
            host->rld.max_tryno_sent = probe->get_tryno() + 1;
            host->rld.rld_waiting = true;
            TIMEVAL_MSEC_ADD(host->rld.rld_waittime, USI->now, RLD_TIME_MS);
          } else {
            host->rld.rld_waiting = false;
            retransmitProbe(USI, host, probe);
            retrans++;
          }
          break; /* I only do one probe per host for now to spread load */
        }
      } while (probeI != beginI);

      /* Wrap the probe iterator around. */
      if (probeI == beginI)
        probeI = host->probes_outstanding.end();
    }
  } while (USI->gstats->sendOK(NULL) && retrans != 0);

  gettimeofday(&USI->now, NULL);
  if (o.debugging) {
    long tv_diff = TIMEVAL_MSEC_SUBTRACT(USI->now, tv_start);
    if (tv_diff > 30)
      log_write(LOG_PLAIN, "%s took %lims\n", __func__, tv_diff);
  }
}

/* Print occasional remaining time estimates, as well as
   debugging information */
static void printAnyStats(UltraScanInfo *USI) {
  std::multiset<HostScanStats *, HssPredicate>::const_iterator hostI;
  const HostScanStats *hss;
  struct ultra_timing_vals hosttm;

  gettimeofday(&USI->now, NULL);

  /* Print debugging states for each host being scanned */
  if (o.debugging > 2) {
    log_write(LOG_PLAIN, "**TIMING STATS** (%.4fs): IP, probes active/freshportsleft/retry_stack/outstanding/retranwait/onbench, cwnd/ssthresh/delay, timeout/srtt/rttvar/\n", o.TimeSinceStart(&USI->now));
    log_write(LOG_PLAIN, "   Groupstats (%d/%d incomplete): %d/*/*/*/*/* %.2f/%d/* %d/%d/%d\n",
              USI->numIncompleteHosts(), USI->numInitialHosts(),
              USI->gstats->num_probes_active, USI->gstats->timing.cwnd,
              USI->gstats->timing.ssthresh, USI->gstats->to.timeout,
              USI->gstats->to.srtt, USI->gstats->to.rttvar);

    if (o.debugging > 3) {
      for (hostI = USI->incompleteHosts.begin();
           hostI != USI->incompleteHosts.end(); hostI++) {
        hss = *hostI;
        hss->getTiming(&hosttm);
        log_write(LOG_PLAIN, "   %s: %d/%d/%d/%d/%d/%d %.2f/%d/%d %li/%d/%d\n", hss->target->targetipstr(),
                  hss->num_probes_active, hss->numFreshPortsLeft(),
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
    } else if (USI->ping_scan_nd) {
      gotone = get_ns_result(USI, &stime);
    } else if (USI->ping_scan) {
      if (USI->pd)
        gotone = get_ping_pcap_result(USI, &stime);
      if (!gotone && USI->ptech.connecttcpscan)
        gotone = do_one_select_round(USI, &stime);
    } else if (USI->pd) {
      gotone = get_pcap_result(USI, &stime);
    } else if (USI->scantype == CONNECT_SCAN) {
      gotone = do_one_select_round(USI, &stime);
    } else assert(0);
  } while (gotone && USI->gstats->num_probes_active > 0);

  gettimeofday(&USI->now, NULL);
  USI->gstats->last_wait = USI->now;
}

/* Go through the data structures, making appropriate changes (such as expiring
   probes, noting when hosts are complete, etc. */
static void processData(UltraScanInfo *USI) {
  std::multiset<HostScanStats *, HssPredicate>::iterator hostI;
  std::list<UltraProbe *>::iterator probeI, nextProbeI;
  HostScanStats *host = NULL;
  UltraProbe *probe = NULL;
  unsigned int maxtries = 0;
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
  for (hostI = USI->incompleteHosts.begin();
       hostI != USI->incompleteHosts.end(); hostI++) {
    host = *hostI;
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

    for (probeI = host->probes_outstanding.begin();
         probeI != host->probes_outstanding.end(); probeI = nextProbeI) {
      nextProbeI = probeI;
      nextProbeI++;
      probe = *probeI;

      unsigned long to_us = host->probeTimeout();
#ifdef WIN32
      if (USI->scantype == CONNECT_SCAN || USI->ptech.connecttcpscan) {
        // Have to adjust to_us up because of TCP_MAXRT granularity
        if (USI->has_tcp_maxrtms) {
          to_us += (1000 - to_us % 1000); 
        } else {
          to_us += (1000000 - to_us % 1000000); 
        }
      }
#endif
      long probe_age_us = TIMEVAL_SUBTRACT(USI->now, probe->sent);
      // give up completely after this long
      expire_us = host->probeExpireTime(probe, to_us);

      if (!probe->timedout && probe_age_us > (long) to_us) {
        host->markProbeTimedout(probeI);
        /* Once we've timed out a probe, skip it for this round of processData.
           We don't want it to move to the bench or anything until the other
           functions have had a chance to see that it's timed out. In
           particular, timing out a probe may mean that the tryno can no longer
           increase, which would make the logic below incorrect. */
        continue;
      }

      if (probe->timedout && !probe->retransmitted && !probe->isPing()) {
        if (!tryno_mayincrease && probe->get_tryno() >= maxtries) {
          if (tryno_capped && !host->retry_capped_warned) {
            log_write(LOG_PLAIN, "Warning: %s giving up on port because"
                      " retransmission cap hit (%d).\n", host->target->targetipstr(),
                      probe->get_tryno());
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
        } else if (probe->get_tryno() >= maxtries &&
                   probe_age_us > expire_us) {
          assert(probe->get_tryno() == maxtries);
          /* Move it to the bench until it is needed (maxtries
             increases or is capped */
          host->moveProbeToBench(probeI);
          continue;
        }
      }

      if ((probe->isPing() || (probe->timedout && probe->retransmitted)) &&
          probe_age_us > expire_us) {
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
    long to_us = pinghost->probeTimeout();
    for (probeI = pinghost->probes_outstanding.begin();
         probeI != pinghost->probes_outstanding.end();
         probeI = nextProbeI) {
      nextProbeI = probeI;
      nextProbeI++;
      probe = *probeI;
      /* If a global ping probe times out, we want to get rid of it so a new
         host can take its place. */
      if (probe->isPing()) {
        if (TIMEVAL_SUBTRACT(USI->now, probe->sent) > to_us) {
          if (o.debugging)
            log_write(LOG_STDOUT, "Destroying timed-out global ping from %s.\n", pinghost->target->targetipstr());
          /* ultrascan_ping_update destroys the probe. */
          ultrascan_ping_update(USI, pinghost, probeI, NULL);
          // ultrascan_*_update() can change timeout
          to_us = pinghost->probeTimeout();
        }
        else {
          // If this one isn't timed out, no later ones will be either.
          break;
        }
      }
    }
  }

  gettimeofday(&USI->now, NULL);
  if (o.debugging) {
    long tv_diff = TIMEVAL_MSEC_SUBTRACT(USI->now, tv_start);
    if (tv_diff > 30)
      log_write(LOG_PLAIN, "%s took %lims\n", __func__, tv_diff);
  }
}

/* 3rd generation Nmap scanning function. Handles most Nmap port scan types.

   The parameter to gives group timing information, and if it is not NULL,
   changed timing information will be stored in it when the function returns. It
   exists so timing can be shared across invocations of this function. If to is
   NULL (its default value), a default timeout_info will be used. */
void ultra_scan(std::vector<Target *> &Targets, const struct scan_lists *ports,
                stype scantype, struct timeout_info *to) {
  o.current_scantype = scantype;

  if (Targets.size() == 0) {
    return;
  }

#ifdef WIN32
  if (!o.have_pcap && scantype != CONNECT_SCAN && Targets[0]->ifType() == devt_loopback) {
    log_write(LOG_STDOUT, "Skipping %s against %s because Windows does not support scanning your own machine (localhost) this way.\n", scantype2str(scantype), Targets[0]->NameIP());
    return;
  }
#endif

  // Set the variable for status printing
  o.numhosts_scanning = Targets.size();

  UltraScanInfo USI(Targets, ports, scantype);

  /* Load up _all_ payloads into a mapped table. Only needed for raw scans. */
  if (USI.udp_scan || (USI.ping_scan && USI.ptech.rawudpscan) ) {
    init_payloads();
  }

  if (USI.gstats->numprobes <= 0) {
    if (o.debugging) {
      log_write(LOG_STDOUT, "Skipping %s: no probes to send\n", scantype2str(scantype));
    }
    return;
  }

  /* Use the requested timeouts. */
  if (to != NULL)
    USI.gstats->to = *to;

  if (o.verbose) {
    char targetstr[128];
    bool plural = (Targets.size() != 1);
    if (!plural) {
      (*(Targets.begin()))->NameIP(targetstr, sizeof(targetstr));
    } else Snprintf(targetstr, sizeof(targetstr), "%d hosts", (int) Targets.size());
    log_write(LOG_STDOUT, "Scanning %s [%d port%s%s]\n", targetstr, USI.gstats->numprobes, (USI.gstats->numprobes != 1) ? "s" : "", plural ? "/host" : "");
  }

  if (USI.isRawScan())
    begin_sniffer(&USI, Targets);
  /* Otherwise, no sniffer needed! */

  while (!USI.incompleteHostsEmpty()) {
#ifdef WIN32
    // Reset system idle timer to avoid going to sleep
    SetThreadExecutionState(ES_SYSTEM_REQUIRED);
#endif
    doAnyPings(&USI);
    doAnyOutstandingRetransmits(&USI); // Retransmits from probes_outstanding
    /* Retransmits from retry_stack -- goes after OutstandingRetransmits for
       memory consumption reasons */
    doAnyRetryStackRetransmits(&USI);
    doAnyNewProbes(&USI);
    // printf("TRACE: Finished doAnyNewProbes() at %.4fs\n", o.TimeSinceStartMS(&USI.now) / 1000.0);
    printAnyStats(&USI);
    waitForResponses(&USI);
    // printf("TRACE: Finished waitForResponses() at %.4fs\n", o.TimeSinceStartMS(&USI.now) / 1000.0);
    processData(&USI);

    if (keyWasPressed()) {
      // This prints something like
      // SYN Stealth Scan Timing: About 1.14% done; ETC: 15:01 (0:43:23 remaining);
      USI.SPM->printStats(USI.getCompletionFraction(), NULL);
      if (o.debugging) {
        /* Don't update when getting the current rates, otherwise we can get
           anomalies (rates are too low) from having just done a potentially
           long waitForResponses without sending any packets. */
        USI.log_current_rates(LOG_STDOUT, false);
      }

      log_flush(LOG_STDOUT);
    }
  }

  USI.send_rate_meter.stop(&USI.now);

  /* Save the computed timeouts. */
  if (to != NULL)
    *to = USI.gstats->to;

  if (o.verbose) {
    char additional_info[128];
    if (USI.gstats->num_hosts_timedout == 0)
      if (USI.ping_scan) {
        Snprintf(additional_info, sizeof(additional_info), "%lu total hosts",
                 (unsigned long) Targets.size());
      } else {
        Snprintf(additional_info, sizeof(additional_info), "%lu total ports",
                 (unsigned long) USI.gstats->numprobes * Targets.size());
      }
    else Snprintf(additional_info, sizeof(additional_info), "%d %s timed out",
                    USI.gstats->num_hosts_timedout,
                    (USI.gstats->num_hosts_timedout == 1) ? "host" : "hosts");
    USI.SPM->endTask(NULL, additional_info);
  }
  if (o.debugging)
    USI.log_overall_rates(LOG_STDOUT);

  if (o.debugging > 2 && USI.pd != NULL)
    pcap_print_stats(LOG_PLAIN, USI.pd);
}
