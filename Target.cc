
/***************************************************************************
 * Target.cc -- The Target class encapsulates much of the information Nmap *
 * has about a host.  Results (such as ping, OS scan, etc) are stored in   *
 * this class as they are determined.                                      *
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

#include "Target.h"
#include <dnet.h>
#include "nbase.h"
#include "NmapOps.h"
#include "utils.h"
#include "nmap_error.h"

extern NmapOps o;

Target::Target() {
  Initialize();
}

void Target::Initialize() {
  hostname = NULL;
  targetname = NULL;
  memset(&seq, 0, sizeof(seq));
  distance = -1;
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

void Target::Recycle() {
  FreeInternal();
  Initialize();
}

Target::~Target() {
  FreeInternal();
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
}

/*  Creates a "presentation" formatted string out of the IPv4/IPv6 address.
    Called when the IP changes */
void Target::GenerateIPString() {
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
  GenerateIPString();
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

/* Note that it is OK to pass in a sockaddr_in or sockaddr_in6 casted
     to sockaddr_storage */
void Target::setSourceSockAddr(const struct sockaddr_storage *ss, size_t ss_len) {
  assert(ss_len > 0 && ss_len <= sizeof(*ss));
  memcpy(&sourcesock, ss, ss_len);
  sourcesocklen = ss_len;
}

// Returns IPv4 host address or {0} if unavailable.
struct in_addr Target::v4source() const {
  const struct in_addr *addy = v4sourceip();
  struct in_addr in;
  if (addy) return *addy;
  in.s_addr = 0;
  return in;
}

// Returns IPv4 host address or NULL if unavailable.
const struct in_addr *Target::v4sourceip() const {
  struct sockaddr_in *sin = (struct sockaddr_in *) &sourcesock;
  if (sin->sin_family == AF_INET) {
    return &(sin->sin_addr);
  }
  return NULL;
}


  /* You can set to NULL to erase a name or if it failed to resolve -- or 
     just don't call this if it fails to resolve */
void Target::setHostName(char *name) {
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
const char *Target::NameIP(char *buf, size_t buflen) {
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
const char *Target::NameIP() {
  if (!nameIPBuf) nameIPBuf = (char *) safe_malloc(MAXHOSTNAMELEN + INET6_ADDRSTRLEN);
  return NameIP(nameIPBuf, MAXHOSTNAMELEN + INET6_ADDRSTRLEN);
}

  /* Returns the next hop for sending packets to this host.  Returns true if
     next_hop was filled in.  It might be false, for example, if
     next_hop has never been set */
bool Target::nextHop(struct sockaddr_storage *next_hop, size_t *next_hop_len) {
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
void Target::setNextHop(struct sockaddr_storage *next_hop, size_t next_hop_len) {
  assert(next_hop_len > 0 && next_hop_len <= sizeof(nexthopsock));
  memcpy(&nexthopsock, next_hop, next_hop_len);
  nexthopsocklen = next_hop_len;
}

/* Set MTU (to correspond with devname) */
void Target::setMTU(int devmtu) {
  mtu = devmtu;
}

/* Get MTU (to correspond with devname) */
int Target::MTU(void) {
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
bool Target::timedOut(const struct timeval *now) {
  unsigned long used = htn.msecs_used;
  struct timeval tv;

  if (!o.host_timeout) return false;
  if (htn.toclock_running) {
    if (now) tv = *now;
    else gettimeofday(&tv, NULL);
    used += TIMEVAL_MSEC_SUBTRACT(tv, htn.toclock_start);
  }

  return (used > o.host_timeout)? true : false;
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

int Target::osscanPerformed(void) {
	return osscan_flag;
}

void Target::osscanSetFlag(int flag) {
	if(osscan_flag == OS_PERF_UNREL)
		return;
	else
		osscan_flag = flag;
}


