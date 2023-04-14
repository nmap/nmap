
/***************************************************************************
 * Target.cc -- The Target class encapsulates much of the information Nmap *
 * has about a host.  Results (such as ping, OS scan, etc) are stored in   *
 * this class as they are determined.                                      *
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

#ifdef WIN32
#include "nmap_winconfig.h"
#endif

#include "Target.h"
#include "FingerPrintResults.h" /* for ~FingerPrintResults() */
#include <dnet.h>
#include "nbase.h"
#include "NmapOps.h"
#include "nmap.h"
#include "nmap_error.h"

extern NmapOps o;

Target::Target() {
  hostname = NULL;
  targetname = NULL;
  memset(&seq, 0, sizeof(seq));
  distance = -1;
  distance_calculation_method = DIST_METHOD_NONE;
  FPR = NULL;
  osscan_flag = OS_NOTPERF;
  weird_responses = flags = 0;
  traceroute_probespec.type = PS_NONE;
  memset(&to, 0, sizeof(to));
  memset(&targetsock, 0, sizeof(targetsock));
  memset(&sourcesock, 0, sizeof(sourcesock));
  memset(&nexthopsock, 0, sizeof(nexthopsock));
  targetsocklen = sourcesocklen = nexthopsocklen = 0;
  directly_connected = -1;
  targetipstring[0] = '\0';
  sourceipstring[0] = '\0';
  nameIPBuf = NULL;
  memset(&MACaddress, 0, sizeof(MACaddress));
  memset(&SrcMACaddress, 0, sizeof(SrcMACaddress));
  memset(&NextHopMACaddress, 0, sizeof(NextHopMACaddress));
  MACaddress_set = SrcMACaddress_set = NextHopMACaddress_set = false;
  htn.msecs_used = 0;
  htn.toclock_running = false;
  htn.host_start = htn.host_end = 0;
  interface_type = devt_other;
  devname[0] = '\0';
  devfullname[0] = '\0';
  mtu = 0;
  state_reason_init(&reason);
  memset(&pingprobe, 0, sizeof(pingprobe));
  pingprobe_state = PORT_UNKNOWN;
}


const char * Target::deviceName() const {
        return (devname[0] != '\0')? devname : NULL;
}

const char * Target::deviceFullName() const {
        return (devfullname[0] != '\0')? devfullname : NULL;
}

Target::~Target() {
  FreeInternal();
#ifndef NOLUA
  for (ScriptResults::iterator it = scriptResults.begin();
      it != scriptResults.end(); it++) {
    delete (*it);
  }
#endif
}

void Target::FreeInternal() {
  /* Free the DNS name if we resolved one */
  if (hostname)
    free(hostname);

  if (targetname)
    free(targetname);

  if (nameIPBuf) {
    free(nameIPBuf);
    nameIPBuf = NULL;
  }

  if (FPR) delete FPR;
  for (std::vector<EarlySvcResponse *>::iterator it=earlySvcResponses.begin();
      it != earlySvcResponses.end(); it++) {
    free(*it);
  }
  earlySvcResponses.clear();
}

/*  Creates a "presentation" formatted string out of the IPv4/IPv6 address.
    Called when the IP changes */
void Target::GenerateTargetIPString() {
  struct sockaddr_in *sin = (struct sockaddr_in *) &targetsock;
#if HAVE_IPV6
  struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &targetsock;
#endif

  if (inet_ntop(sin->sin_family, (sin->sin_family == AF_INET)?
                (char *) &sin->sin_addr :
#if HAVE_IPV6
                (char *) &sin6->sin6_addr,
#else
                (char *) NULL,
#endif
                targetipstring, sizeof(targetipstring)) == NULL) {
    fatal("Failed to convert target address to presentation format!?!  Error: %s", strerror(socket_errno()));
  }
}

/*  Creates a "presentation" formatted string out of the IPv4/IPv6 address.
    Called when the IP changes */
void Target::GenerateSourceIPString() {
  struct sockaddr_in *sin = (struct sockaddr_in *) &sourcesock;
#if HAVE_IPV6
  struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &sourcesock;
#endif

  if (inet_ntop(sin->sin_family, (sin->sin_family == AF_INET)?
                (char *) &sin->sin_addr :
#if HAVE_IPV6
                (char *) &sin6->sin6_addr,
#else
                (char *) NULL,
#endif
                sourceipstring, sizeof(sourceipstring)) == NULL) {
    fatal("Failed to convert source address to presentation format!?!  Error: %s", strerror(socket_errno()));
  }
}

/* Returns the address family of the destination address. */
int Target::af() const {
  return targetsock.ss_family;
}

/* Fills a sockaddr_storage with the AF_INET or AF_INET6 address
     information of the target.  This is a preferred way to get the
     address since it is portable for IPv6 hosts.  Returns 0 for
     success. ss_len must be provided.  It is not examined, but is set
     to the size of the sockaddr copied in. */
int Target::TargetSockAddr(struct sockaddr_storage *ss, size_t *ss_len) const {
  assert(ss);
  assert(ss_len);
  if (targetsocklen <= 0)
    return 1;
  assert(targetsocklen <= sizeof(*ss));
  memcpy(ss, &targetsock, targetsocklen);
  *ss_len = targetsocklen;
  return 0;
}

const struct sockaddr_storage *Target::TargetSockAddr() const {
  return &targetsock;
}

/* Note that it is OK to pass in a sockaddr_in or sockaddr_in6 casted
     to sockaddr_storage */
void Target::setTargetSockAddr(const struct sockaddr_storage *ss, size_t ss_len) {

  assert(ss_len > 0 && ss_len <= sizeof(*ss));
  if (targetsocklen > 0) {
    /* We had an old target sock, so we better blow away the hostname as
       this one may be new. */
    setHostName(NULL);
    setTargetName(NULL);
  }
  memcpy(&targetsock, ss, ss_len);
  targetsocklen = ss_len;
  GenerateTargetIPString();
  /* The ports array needs to know a name too */
  ports.setIdStr(targetipstr());
}

// Returns IPv4 host address or {0} if unavailable.
struct in_addr Target::v4host() const {
  const struct in_addr *addy = v4hostip();
  struct in_addr in;
  if (addy) return *addy;
  in.s_addr = 0;
  return in;
}

// Returns IPv4 host address or NULL if unavailable.
const struct in_addr *Target::v4hostip() const {
  struct sockaddr_in *sin = (struct sockaddr_in *) &targetsock;
  if (sin->sin_family == AF_INET) {
    return &(sin->sin_addr);
  }
  return NULL;
}

const struct in6_addr *Target::v6hostip() const {
  struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &targetsock;
  if (sin6->sin6_family == AF_INET6) {
    return &(sin6->sin6_addr);
  }
  return NULL;
}

 /* The source address used to reach the target */
int Target::SourceSockAddr(struct sockaddr_storage *ss, size_t *ss_len) const {
  if (sourcesocklen <= 0)
    return 1;
  assert(sourcesocklen <= sizeof(*ss));
  if (ss)
    memcpy(ss, &sourcesock, sourcesocklen);
  if (ss_len)
    *ss_len = sourcesocklen;
  return 0;
}

const struct sockaddr_storage *Target::SourceSockAddr() const {
  return &sourcesock;
}

/* Note that it is OK to pass in a sockaddr_in or sockaddr_in6 casted
     to sockaddr_storage */
void Target::setSourceSockAddr(const struct sockaddr_storage *ss, size_t ss_len) {
  assert(ss_len > 0 && ss_len <= sizeof(*ss));
  memcpy(&sourcesock, ss, ss_len);
  sourcesocklen = ss_len;
  GenerateSourceIPString();
}

// Returns IPv4 host address or {0} if unavailable.
struct sockaddr_storage Target::source() const {
  return sourcesock;
}

// Returns IPv4 host address or NULL if unavailable.
const struct in_addr *Target::v4sourceip() const {
  struct sockaddr_in *sin = (struct sockaddr_in *) &sourcesock;
  if (sin->sin_family == AF_INET) {
    return &(sin->sin_addr);
  }
  return NULL;
}

// Returns IPv6 host address or NULL if unavailable.
const struct in6_addr *Target::v6sourceip() const {
  struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &sourcesock;
  if (sin6->sin6_family == AF_INET6) {
    return &(sin6->sin6_addr);
  }
  return NULL;
}

  /* You can set to NULL to erase a name or if it failed to resolve -- or
     just don't call this if it fails to resolve */
void Target::setHostName(const char *name) {
  char *p;
  if (hostname) {
    free(hostname);
    hostname = NULL;
  }
  if (name) {
    p = hostname = strdup(name);
    while (*p) {
      // I think only a-z A-Z 0-9 . and - are allowed, but I'll be a little more
      // generous.
      if (!isalnum((int) (unsigned char) *p) && !strchr(".-+=:_~*", *p)) {
        log_write(LOG_STDOUT, "Illegal character(s) in hostname -- replacing with '*'\n");
        *p = '*';
      }
      p++;
    }
  }
}

void Target::setTargetName(const char *name) {
  if (targetname) {
    free(targetname);
    targetname = NULL;
  }
  if (name) {
    targetname = strdup(name);
  }
}

 /* Generates a printable string consisting of the host's IP
     address and hostname (if available).  Eg "www.insecure.org
     (64.71.184.53)" or "fe80::202:e3ff:fe14:1102".  The name is
     written into the buffer provided, which is also returned.  Results
     that do not fit in buflen will be truncated. */
const char *Target::NameIP(char *buf, size_t buflen) const {
  assert(buf);
  assert(buflen > 8);
  if (targetname)
    Snprintf(buf, buflen, "%s (%s)", targetname, targetipstring);
  else if (hostname)
    Snprintf(buf, buflen, "%s (%s)", hostname, targetipstring);
  else
    Strncpy(buf, targetipstring, buflen);
  return buf;
}

/* This next version returns a static buffer -- so no concurrency */
const char *Target::NameIP() const {
  /* Add 3 characters for the hostname and IP string, hence we allocate
    (FQDN_LEN + INET6_ADDRSTRLEN + 4) octets, with octet for the null terminator */
  if (!nameIPBuf) nameIPBuf = (char *) safe_malloc(FQDN_LEN + INET6_ADDRSTRLEN + 4);
  return NameIP(nameIPBuf, FQDN_LEN + INET6_ADDRSTRLEN + 4);
}

  /* Returns the next hop for sending packets to this host.  Returns true if
     next_hop was filled in.  It might be false, for example, if
     next_hop has never been set */
bool Target::nextHop(struct sockaddr_storage *next_hop, size_t *next_hop_len) const {
  if (nexthopsocklen <= 0)
    return false;
  assert(nexthopsocklen <= sizeof(*next_hop));
  if (next_hop)
    memcpy(next_hop, &nexthopsock, nexthopsocklen);
  if (next_hop_len)
    *next_hop_len = nexthopsocklen;
  return true;
}

  /* If the host is directly connected on a network, set and retrieve
     that information here.  directlyConnected() will abort if it hasn't
     been set yet.  */
void Target::setDirectlyConnected(bool connected) {
  directly_connected = connected? 1 : 0;
}

int Target::directlyConnectedOrUnset() const {
    return directly_connected;
}

bool Target::directlyConnected() const {
  assert(directly_connected == 0 || directly_connected == 1);
  return directly_connected;
}

/* Note that it is OK to pass in a sockaddr_in or sockaddr_in6 casted
     to sockaddr_storage */
void Target::setNextHop(const struct sockaddr_storage *next_hop, size_t next_hop_len) {
  assert(next_hop_len > 0 && next_hop_len <= sizeof(nexthopsock));
  memcpy(&nexthopsock, next_hop, next_hop_len);
  nexthopsocklen = next_hop_len;
}

/* Set MTU (to correspond with devname) */
void Target::setMTU(int devmtu) {
  mtu = devmtu;
}

/* Get MTU (to correspond with devname) */
int Target::MTU(void) const {
  return mtu;
}

  /* Starts the timeout clock for the host running (e.g. you are
     beginning a scan).  If you do not have the current time handy,
     you can pass in NULL.  When done, call stopTimeOutClock (it will
     also automatically be stopped of timedOut() returns true) */
void Target::startTimeOutClock(const struct timeval *now) {
  assert(htn.toclock_running == false);
  htn.toclock_running = true;
  if (now) htn.toclock_start = *now;
  else gettimeofday(&htn.toclock_start, NULL);
  if (!htn.host_start) htn.host_start = htn.toclock_start.tv_sec;
}
  /* The complement to startTimeOutClock. */
void Target::stopTimeOutClock(const struct timeval *now) {
  struct timeval tv;
  assert(htn.toclock_running == true);
  htn.toclock_running = false;
  if (now) tv = *now;
  else gettimeofday(&tv, NULL);
  htn.msecs_used += TIMEVAL_MSEC_SUBTRACT(tv, htn.toclock_start);
  htn.host_end = tv.tv_sec;
}
  /* Returns whether the host is timedout.  If the timeoutclock is
     running, counts elapsed time for that.  Pass NULL if you don't have the
     current time handy.  You might as well also pass NULL if the
     clock is not running, as the func won't need the time. */
bool Target::timedOut(const struct timeval *now) const {
  unsigned long used = htn.msecs_used;
  struct timeval tv;

  if (!o.host_timeout) return false;
  if (htn.toclock_running) {
    if (now) tv = *now;
    else gettimeofday(&tv, NULL);
    used += TIMEVAL_MSEC_SUBTRACT(tv, htn.toclock_start);
  }

  return (used > o.host_timeout);
}


/* Returns zero if MAC address set successfully */
int Target::setMACAddress(const u8 *addy) {
  if (!addy) return 1;
  memcpy(MACaddress, addy, 6);
  MACaddress_set = 1;
  return 0;
}

int Target::setSrcMACAddress(const u8 *addy) {
  if (!addy) return 1;
  memcpy(SrcMACaddress, addy, 6);
  SrcMACaddress_set = 1;
  return 0;
}

int Target::setNextHopMACAddress(const u8 *addy) {
  if (!addy) return 1;
  memcpy(NextHopMACaddress, addy, 6);
  NextHopMACaddress_set = 1;
  return 0;
}

/* Set the device names so that they can be returned by deviceName()
   and deviceFullName().  The normal name may not include alias
   qualifier, while the full name may include it (e.g. "eth1:1").  If
   these are non-null, they will overwrite the stored version */
void Target::setDeviceNames(const char *name, const char *fullname) {
  if (name) Strncpy(devname, name, sizeof(devname));
  if (fullname) Strncpy(devfullname, fullname, sizeof(devfullname));
}

/* Returns the 6-byte long MAC address, or NULL if none has been set */
const u8 *Target::MACAddress() const {
  return (MACaddress_set)? MACaddress : NULL;
}

const u8 *Target::SrcMACAddress() const {
  return (SrcMACaddress_set)? SrcMACaddress : NULL;
}

const u8 *Target::NextHopMACAddress() const {
  return (NextHopMACaddress_set)? NextHopMACaddress : NULL;
}

int Target::osscanPerformed(void) const {
        return osscan_flag;
}

void Target::osscanSetFlag(int flag) {
        if(osscan_flag == OS_PERF_UNREL)
                return;
        else
                osscan_flag = flag;
}
