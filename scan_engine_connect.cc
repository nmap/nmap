
/***************************************************************************
 * scan_engine_connect.cc -- includes helper functions for scan_engine.cc  *
 * that are related to port scanning using connect() system call.          *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *
 * The Nmap Security Scanner is (C) 1996-2023 Nmap Software LLC ("The Nmap
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
 * Source code also allows you to port Nmap to new platforms, fix bugs, and add
 * new features. You are highly encouraged to submit your changes as a Github PR
 * or by email to the dev@nmap.org mailing list for possible incorporation into
 * the main distribution. Unless you specify otherwise, it is understood that
 * you are offering us very broad rights to use your submissions as described in
 * the Nmap Public Source License Contributor Agreement. This is important
 * because we fund the project by selling licenses with various terms, and also
 * because the inability to relicense code has caused devastating problems for
 * other Free Software projects (such as KDE and NASM).
 *
 * The free version of Nmap is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranties,
 * indemnification and commercial support are all available through the
 * Npcap OEM program--see https://nmap.org/oem/
 *
 ***************************************************************************/

/* $Id$ */

#include "nmap_error.h"
#include "tcpip.h"
#include "Target.h"
#include "scan_engine.h"
#include "scan_engine_connect.h"
#include "libnetutil/netutil.h" /* for max_sd() */
#include "NmapOps.h"

#include <errno.h>

extern NmapOps o;

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
  nextSD = -1;
  if (o.max_parallelism > 0) {
    maxSocketsAllowed = o.max_parallelism;
  }
#ifndef WIN32
  else {
    /* Subtracting 10 from max_sd accounts for
       stdin
       stdout
       stderr
       /dev/tty
       /var/run/utmpx, which is opened on Mac OS X at least
       -oG log file
       -oN log file
       -oS log file
       -oX log file
       perhaps another we've forgotten. */
    maxSocketsAllowed = max_sd() - 10;
    if (maxSocketsAllowed < 5)
      maxSocketsAllowed = 5;
  }
  /* We can't issue a FD_SET operation with a socket descriptor greater than
   * FD_SETSIZE, and we can't stop the OS from handing us ones that are greater
   * than that, either, so leave a buffer here. */
  maxSocketsAllowed = MIN(maxSocketsAllowed, FD_SETSIZE - 10);
#else
  /* Windows does not have an explicit limit, but we have to keep it below
   * FD_SETSIZE or select() will fail. Fortunately, it's about the *number* of
   * sockets, not the socket descriptor number, so we can run right up to that
   * limit. */
  maxSocketsAllowed = MIN(maxSocketsAllowed, FD_SETSIZE - 1);
#endif
  FD_ZERO(&fds_read);
  FD_ZERO(&fds_write);
  FD_ZERO(&fds_except);
}

/* Nothing really to do here. */
ConnectScanInfo::~ConnectScanInfo() {}

bool ConnectScanInfo::sendOK() {
  if (numSDs >= maxSocketsAllowed)
    return false;

  if (nextSD > 0)
    return true;

  nextSD = socket(o.af(), SOCK_STREAM, IPPROTO_TCP);
  if (nextSD == -1)
    pfatal("Socket creation in %s", __func__);
#ifndef WIN32
  /* Check here whether this socket descriptor number will be a problem. If so,
   * close it and tell the engine to slow down. Windows doesn't have this
   * limit, only maxSocketsAllowed. */
  if (nextSD >= FD_SETSIZE) {
    if (o.debugging) {
      log_write(LOG_STDOUT, "Socket descriptor %d greater than FD_SETSIZE: slow down.\n", nextSD);
    }
    close(nextSD);
    nextSD = -1;
    return false;
  }
#endif
  return true;
}

int ConnectScanInfo::getSocket() {
  int sd = nextSD;
  nextSD = -1;
  return sd;
}

/* Watch a socket descriptor (add to fd_sets and maxValidSD).  Returns
   true if the SD was absent from the list, false if you tried to
   watch an SD that was already being watched. */
bool ConnectScanInfo::watchSD(int sd) {
  assert(sd >= 0);
  if (!checked_fd_isset(sd, &fds_read)) {
    checked_fd_set(sd, &fds_read);
    checked_fd_set(sd, &fds_write);
    checked_fd_set(sd, &fds_except);
    numSDs++;
    if (sd > maxValidSD)
      maxValidSD = sd;
    return true;
  } else {
    return false;
  }
}

/* Clear SD from the fd_sets and maxValidSD.  Returns true if the SD
   was in the list, false if you tried to clear an sd that wasn't
   there in the first place. */
bool ConnectScanInfo::clearSD(int sd) {
  assert(sd >= 0);
  if (checked_fd_isset(sd, &fds_read)) {
    checked_fd_clr(sd, &fds_read);
    checked_fd_clr(sd, &fds_write);
    checked_fd_clr(sd, &fds_except);
    assert(numSDs > 0);
    numSDs--;
    if (sd == maxValidSD)
      maxValidSD--;
    return true;
  } else {
    return false;
  }
}

ConnectProbe::ConnectProbe() {
  sd = -1;
}

ConnectProbe::~ConnectProbe() {
  if (sd > 0)
    close(sd);
  sd = -1;
}

static void handleConnectResult(UltraScanInfo *USI, HostScanStats *hss,
                                std::list<UltraProbe *>::iterator probeI,
                                int connect_errno,
                                bool destroy_probe=false) {
  bool adjust_timing = true;
  int newportstate = PORT_UNKNOWN;
  int newhoststate = HOST_UNKNOWN;
  reason_t current_reason = ER_NORESPONSE;
  UltraProbe *probe = *probeI;
  struct sockaddr_storage local;
  socklen_t local_len = sizeof(struct sockaddr_storage);
  struct sockaddr_storage remote;
  size_t remote_len;

  if (hss->target->TargetSockAddr(&remote, &remote_len) != 0) {
    fatal("Failed to get target socket address in %s", __func__);
  }
  if (remote.ss_family == AF_INET)
    ((struct sockaddr_in *) &remote)->sin_port = htons(probe->dport());
#if HAVE_IPV6
  else
    ((struct sockaddr_in6 *) &remote)->sin6_port = htons(probe->dport());
#endif
  PacketTrace::traceConnect(IPPROTO_TCP, (sockaddr *) &remote, remote_len,
      connect_errno, connect_errno, &USI->now);
  switch (connect_errno) {
    case 0:
      newhoststate = HOST_UP;
      newportstate = PORT_OPEN;
      current_reason = ER_CONACCEPT;
      break;
    case EACCES:
      /* Apparently this can be caused by dest unreachable admin
         prohibited messages sent back, at least from IPv6
         hosts */
      newhoststate = HOST_DOWN;
      newportstate = PORT_FILTERED;
      current_reason = ER_ADMINPROHIBITED;
      break;
    /* This can happen on localhost, successful/failing connection immediately
       in non-blocking mode. */
    case ECONNREFUSED:
      if (!o.discovery_ignore_rst) {
        newhoststate = HOST_UP;
      }
      newportstate = PORT_CLOSED;
      current_reason = ER_CONREFUSED;
      break;
    case EAGAIN:
      log_write(LOG_STDOUT, "Machine %s MIGHT actually be listening on probe port %d\n", hss->target->targetipstr(), USI->ports->syn_ping_ports[probe->dport()]);
      /* Fall through. */
#ifdef WIN32
    case WSAENOTCONN:
#endif
      newhoststate = HOST_UP;
      current_reason = ER_CONACCEPT;
      break;
#ifdef ENOPROTOOPT
    case ENOPROTOOPT:
      newhoststate = HOST_DOWN;
      newportstate = PORT_FILTERED;
      current_reason = ER_PROTOUNREACH;
      break;
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
#ifdef ENONET
    case ENONET:
      /* For Linux at least, this means ICMP type 3 code 8, source host isolated */
      newhoststate = HOST_DOWN;
      newportstate = PORT_FILTERED;
      current_reason = ER_DESTUNREACH;
      break;
#endif
    case ENETDOWN:
    case ENETRESET:
    case ECONNABORTED:
      fatal("Strange SO_ERROR from connection to %s (%d - '%s') -- bailing scan", hss->target->targetipstr(), connect_errno, strerror(connect_errno));
      break;
    default:
      error("Strange read error from %s (%d - '%s')", hss->target->targetipstr(), connect_errno, strerror(connect_errno));
      break;
  }
  if (probe->isPing() && newhoststate != HOST_UNKNOWN ) {
    ultrascan_ping_update(USI, hss, probeI, &USI->now, adjust_timing);
  } else if (USI->ping_scan && newhoststate != HOST_UNKNOWN) {
    ultrascan_host_probe_update(USI, hss, probeI, newhoststate, &USI->now, adjust_timing);
    hss->target->reason.reason_id = current_reason;
    /* If the host is up, we can forget our other probes. */
    if (newhoststate == HOST_UP)
      hss->destroyAllOutstandingProbes();
  } else if (!USI->ping_scan && newportstate != PORT_UNKNOWN) {
    /* Save these values so we can use them after
       ultrascan_port_probe_update deletes probe. */
    u8 protocol = probe->protocol();
    u16 dport = probe->dport();
    /* getsockname can fail on AIX when socket is closed
     * and we only care about self-connects for open ports anyway
     */
    if (newportstate == PORT_OPEN) {
      /* Check for self-connected probe */
      if (getsockname(probe->CP()->sd, (struct sockaddr*)&local, &local_len) == 0) {
        if (sockaddr_storage_cmp(&local, &remote) == 0 && (
              (local.ss_family == AF_INET &&
               ((struct sockaddr_in*)&local)->sin_port == htons(dport))
#if HAVE_IPV6
              || (local.ss_family == AF_INET6 &&
                ((struct sockaddr_in6*)&local)->sin6_port == htons(dport))
#endif
              )) {
          if (o.debugging) {
            log_write(LOG_STDOUT, "Detected likely self-connect on port %d\n", probe->dport());
          }
          /* It's not really timed out, but this is a simple way to retry the
           * probe. It shouldn't affect timing too much, since this is quite
           * rare (should average one per scan, for localhost -p 0-65535 scans
           * only) */
          hss->markProbeTimedout(probeI);
        }
        else {
          ultrascan_port_probe_update(USI, hss, probeI, newportstate, &USI->now, adjust_timing);
          hss->target->ports.setStateReason(dport, protocol, current_reason, 0, NULL);
        }
      }
      else {
        gh_perror("getsockname or TargetSockAddr failed");
      }
    }
    else {
      ultrascan_port_probe_update(USI, hss, probeI, newportstate, &USI->now, adjust_timing);
      hss->target->ports.setStateReason(dport, protocol, current_reason, 0, NULL);
    }
  } else if (destroy_probe) {
    hss->destroyOutstandingProbe(probeI);
  }
  return;
}

/* Set the socket lingering so we will RST connections instead of wasting
   bandwidth with the four-step close. Set the source address if needed. Bind to
   a specific interface if needed. */
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
    if (::bind(sd, (struct sockaddr*)&ss, sslen) != 0) {
      error("%s: Problem binding source address (%s), errno: %d", __func__, inet_socktop(&ss), socket_errno());
      perror("bind");
      bind_failed = 1;
    }
  }
  errno = 0;
  if (!socket_bindtodevice(sd, o.device)) {
    /* EPERM is expected when not running as root. */
    if (errno != EPERM) {
      error("Problem binding to interface %s, errno: %d", o.device, socket_errno());
      perror("socket_bindtodevice");
    }
  }
}

/* If this is NOT a ping probe, set tryno.fields.isPing to 0.  Otherwise it will be the
   ping sequence number (they start at 1).  The probe sent is returned. */
UltraProbe *sendConnectScanProbe(UltraScanInfo *USI, HostScanStats *hss,
                                 u16 destport, tryno_t tryno) {

  UltraProbe *probe = new UltraProbe();
  std::list<UltraProbe *>::iterator probeI;
  int rc;
  int connect_errno = 0;
  struct sockaddr_storage sock;
  struct sockaddr_in *sin = (struct sockaddr_in *) &sock;
#if HAVE_IPV6
  struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &sock;
#endif
  size_t socklen;
  ConnectProbe *CP;
  ConnectScanInfo *CSI = USI->gstats->CSI;

  probe->tryno = tryno;
  /* First build the probe */
  probe->setConnect(destport);
  CP = probe->CP();
  /* Initiate the connection */
  CP->sd = CSI->getSocket();
  assert(CP->sd > 0);
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
  if (rc == -1)
    connect_errno = socket_errno();
  /* This counts as probe being sent, so update structures */
  hss->probes_outstanding.push_back(probe);
  probeI = hss->probes_outstanding.end();
  probeI--;
  USI->gstats->num_probes_active++;
  hss->num_probes_active++;

  /* It would be convenient if the connect() call would never succeed
     or permanently fail here, so related code cood all be localized
     elsewhere.  But the reality is that connect() MAY be finished now. */

  if (rc == -1 && (connect_errno == EINPROGRESS || connect_errno == EAGAIN)) {
    PacketTrace::traceConnect(IPPROTO_TCP, (sockaddr *) &sock, socklen, rc,
        connect_errno, &USI->now);
    USI->gstats->CSI->watchSD(CP->sd);
  } else {
    handleConnectResult(USI, hss, probeI, connect_errno, true);
    probe = NULL;
  }
  gettimeofday(&USI->now, NULL);
  return probe;
}

/* Does a select() call and handles all of the results. This handles both host
   discovery (ping) scans and port scans.  Even if stime is now, it tries a very
   quick select() just in case.  Returns true if at least one good result
   (generally a port state change) is found, false if it times out instead */
bool do_one_select_round(UltraScanInfo *USI, struct timeval *stime) {
  fd_set fds_rtmp, fds_wtmp, fds_xtmp;
  int selectres;
  struct timeval timeout;
  int timeleft;
  ConnectScanInfo *CSI = USI->gstats->CSI;
  int sd;
  std::multiset<HostScanStats *, HssPredicate>::iterator hostI;
  HostScanStats *host;
  UltraProbe *probe = NULL;
  int optval;
  recvfrom6_t optlen = sizeof(int);
  int numGoodSD = 0;
  int err = 0;

  do {
    timeleft = TIMEVAL_MSEC_SUBTRACT(*stime, USI->now);
    if (timeleft < 0)
      timeleft = 0;
    fds_rtmp = USI->gstats->CSI->fds_read;
    fds_wtmp = USI->gstats->CSI->fds_write;
    fds_xtmp = USI->gstats->CSI->fds_except;
    timeout.tv_sec = timeleft / 1000;
    timeout.tv_usec = (timeleft % 1000) * 1000;

    if (CSI->numSDs) {
      selectres = select(CSI->maxValidSD + 1, &fds_rtmp, &fds_wtmp,
                         &fds_xtmp, &timeout);
      err = socket_errno();
    } else {
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
  std::multiset<HostScanStats *, HssPredicate>::iterator incompleteHostI, completedHostI;
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
    if (host->num_probes_active == 0)
      continue;

    std::list<UltraProbe *>::iterator nextProbeI;
    for (std::list<UltraProbe *>::iterator probeI = host->probes_outstanding.begin();
        probeI != host->probes_outstanding.end() && numGoodSD < selectres && host->num_probes_outstanding() > 0; probeI = nextProbeI) {
      /* handleConnectResult may remove the probe at probeI, which invalidates
       * the iterator. We copy and increment it here instead of in the for-loop
       * statement to avoid incrementing an invalid iterator */
      nextProbeI = probeI;
      nextProbeI++;
      probe = *probeI;
      assert(probe->type == UltraProbe::UP_CONNECT);
      sd = probe->CP()->sd;
      /* Let see if anything has happened! */
      if (sd >= 0 && (checked_fd_isset(sd, &fds_rtmp) ||
                      checked_fd_isset(sd, &fds_wtmp) ||
                      checked_fd_isset(sd, &fds_xtmp))) {
        numGoodSD++;
        if (getsockopt(sd, SOL_SOCKET, SO_ERROR, (char *) &optval,
                       &optlen) != 0)
          optval = socket_errno(); /* Stupid Solaris ... */

        handleConnectResult(USI, host, probeI, optval);
      }
    }
  }
  return numGoodSD;
}
