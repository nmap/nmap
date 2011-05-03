
/***************************************************************************
 * Target.h -- The Target class encapsulates much of the information Nmap  *
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

#ifndef TARGET_H
#define TARGET_H

#include "nmap.h"
#include "FingerPrintResults.h"
#include "libnetutil/netutil.h"

#ifndef NOLUA
#include "nse_main.h"
#endif

#include "portreasons.h"
#include "portlist.h"
#include "tcpip.h"
#include "scan_engine.h"

#include <list>
#include <string>

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

enum osscan_flags {
	OS_NOTPERF=0, OS_PERF, OS_PERF_UNREL
};

/* The method used to calculate the Target::distance, included in OS
   fingerprints. */
enum dist_calc_method {
	DIST_METHOD_NONE,
	DIST_METHOD_LOCALHOST,
	DIST_METHOD_DIRECT,
	DIST_METHOD_ICMP,
	DIST_METHOD_TRACEROUTE
};

struct host_timeout_nfo {
  unsigned long msecs_used; /* How many msecs has this Target used? */
  bool toclock_running; /* Is the clock running right now? */
  struct timeval toclock_start; /* When did the clock start? */
  time_t host_start, host_end; /* The absolute start and end for this host */
};

struct TracerouteHop {
  struct sockaddr_storage tag;
  bool timedout;
  std::string name;
  struct sockaddr_storage addr;
  int ttl;
  float rtt; /* In milliseconds. */

  int display_name(char *buf, size_t len) {
    if (name.empty())
      return Snprintf(buf, len, "%s", inet_ntop_ez(&addr, sizeof(addr)));
    else
      return Snprintf(buf, len, "%s (%s)", name.c_str(), inet_ntop_ez(&addr, sizeof(addr)));
  }
};

class Target {
 public: /* For now ... a lot of the data members should be made private */
  Target();
  ~Target();
  /* Recycles the object by freeing internal objects and reinitializing
     to default state */
  void Recycle();
  /* Fills a sockaddr_storage with the AF_INET or AF_INET6 address
     information of the target.  This is a preferred way to get the
     address since it is portable for IPv6 hosts.  Returns 0 for
     success. ss_len must be provided.  It is not examined, but is set
     to the size of the sockaddr copied in. */
  int TargetSockAddr(struct sockaddr_storage *ss, size_t *ss_len) const;
  /* Note that it is OK to pass in a sockaddr_in or sockaddr_in6 casted
     to sockaddr_storage */
  void setTargetSockAddr(const struct sockaddr_storage *ss, size_t ss_len);
  // Returns IPv4 target host address or {0} if unavailable.
  struct in_addr v4host() const;
  const struct in_addr *v4hostip() const;
  /* The source address used to reach the target */
  int SourceSockAddr(struct sockaddr_storage *ss, size_t *ss_len) const;
  /* Note that it is OK to pass in a sockaddr_in or sockaddr_in6 casted
     to sockaddr_storage */
  void setSourceSockAddr(const struct sockaddr_storage *ss, size_t ss_len);
  struct in_addr v4source() const;
  const struct in_addr *v4sourceip() const;
  /* The IPv4 or IPv6 literal string for the target host */
  const char *targetipstr() const { return targetipstring; }
  /* Give the name from the last setHostName() call, which should be
   the name obtained from reverse-resolution (PTR query) of the IP (v4
   or v6).  If the name has not been set, or was set to NULL, an empty
   string ("") is returned to make printing easier. */
  const char *HostName() const { return hostname? hostname : "";  }
  /* You can set to NULL to erase a name or if it failed to resolve -- or 
     just don't call this if it fails to resolve.  The hostname is blown
     away when you setTargetSockAddr(), so make sure you do these in proper
     order
  */
  void setHostName(char *name);
  /* Generates a printable string consisting of the host's IP
     address and hostname (if available).  Eg "www.insecure.org
     (64.71.184.53)" or "fe80::202:e3ff:fe14:1102".  The name is
     written into the buffer provided, which is also returned.  Results
     that do not fit in buflen will be truncated. */
  const char *NameIP(char *buf, size_t buflen);
  /* This next version returns a STATIC buffer -- so no concurrency */
  const char *NameIP();

  /* Give the name from the last setTargetName() call, which is the 
   name of the target given on the command line if it's a named
   host. */
  const char *TargetName() { return targetname; }
  /* You can set to NULL to erase a name.  The targetname is blown
     away when you setTargetSockAddr(), so make sure you do these in proper
     order
  */
  void setTargetName(const char *name);

  /* If the host is directly connected on a network, set and retrieve
     that information here.  directlyConnected() will abort if it hasn't
     been set yet.  */
  void setDirectlyConnected(bool connected);
  bool directlyConnected() const;
  int directlyConnectedOrUnset() const; /* 1-directly connected, 0-no, -1-we don't know*/

  /* If the host is NOT directly connected, you can set the next hop
     value here. It is OK to pass in a sockaddr_in or sockaddr_in6
     casted to sockaddr_storage*/
  void setNextHop(struct sockaddr_storage *next_hop, size_t next_hop_len);
  /* Returns the next hop for sending packets to this host.  Returns true if
     next_hop was filled in.  It might be false, for example, if
     next_hop has never been set */
  bool nextHop(struct sockaddr_storage *next_hop, size_t *next_hop_len);

  void setMTU(int devmtu);
  int MTU(void);

  /* Sets the interface type to one of: 
     devt_ethernet, devt_loopback, devt_p2p, devt_other
   */
  void setIfType(devtype iftype) { interface_type = iftype; }
  /* Returns -1 if it has not yet been set with setIfType() */
  devtype ifType() { return interface_type; }
  /* Starts the timeout clock for the host running (e.g. you are
     beginning a scan).  If you do not have the current time handy,
     you can pass in NULL.  When done, call stopTimeOutClock (it will
     also automatically be stopped of timedOut() returns true) */
  void startTimeOutClock(const struct timeval *now);
  /* The complement to startTimeOutClock. */
  void stopTimeOutClock(const struct timeval *now);
  /* Is the timeout clock currently running? */
  bool timeOutClockRunning() { return htn.toclock_running; }
  /* Returns whether the host is timedout.  If the timeoutclock is
     running, counts elapsed time for that.  Pass NULL if you don't have the
     current time handy.  You might as well also pass NULL if the
     clock is not running, as the func won't need the time. */
  bool timedOut(const struct timeval *now);
  /* Return time_t for the start and end time of this host */
  time_t StartTime() { return htn.host_start; }
  time_t EndTime() { return htn.host_end; }

  /* Takes a 6-byte MAC address */
  int setMACAddress(const u8 *addy);
  int setSrcMACAddress(const u8 *addy);
  int setNextHopMACAddress(const u8 *addy); // this should be the target's own MAC if directlyConnected()

  /* Returns a pointer to 6-byte MAC address, or NULL if none is set */
  const u8 *MACAddress() const;
  const u8 *SrcMACAddress() const;
  const u8 *NextHopMACAddress() const;

/* Set the device names so that they can be returned by deviceName()
   and deviceFullName().  The normal name may not include alias
   qualifier, while the full name may include it (e.g. "eth1:1").  If
   these are non-null, they will overwrite the stored version */
  void setDeviceNames(const char *name, const char *fullname);
  const char *deviceName() const;
  const char *deviceFullName() const;

  int osscanPerformed(void);
  void osscanSetFlag(int flag);

  struct seq_info seq;
  int distance;
  enum dist_calc_method distance_calculation_method;
  FingerPrintResults *FPR; /* FP results get by the OS scan system. */
  PortList ports;

  int weird_responses; /* echo responses from other addresses, Ie a network broadcast address */
  unsigned int flags; /* HOST_UNKNOWN, HOST_UP, or HOST_DOWN. */
  struct timeout_info to;
  char *hostname; // Null if unable to resolve or unset
  char * targetname; // The name of the target host given on the commmand line if it is a named host

  struct probespec traceroute_probespec;
  std::list <TracerouteHop> traceroute_hops;

  /* If the address for this target came from a DNS lookup, the list of
     resultant addresses (sometimes there are more than one). The address
     actually used is always the first element in this list. */
  std::list<struct sockaddr_storage> resolved_addrs;

#ifndef NOLUA
  ScriptResults scriptResults;
#endif

  state_reason_t reason;

  /* A probe that is known to receive a response. This is used to hold the
     current timing ping probe type during scanning. */
  probespec pingprobe;
  /* The state the port or protocol entered when the response to pingprobe was
     received. */
  int pingprobe_state;

  private:
  void Initialize();
  void FreeInternal(); // Free memory allocated inside this object
 // Creates a "presentation" formatted string out of the IPv4/IPv6 address
  void GenerateIPString();
  struct sockaddr_storage targetsock, sourcesock, nexthopsock;
  size_t targetsocklen, sourcesocklen, nexthopsocklen;
  int directly_connected; // -1 = unset; 0 = no; 1 = yes
  char targetipstring[INET6_ADDRSTRLEN];
  char *nameIPBuf; /* for the NameIP(void) function to return */
  u8 MACaddress[6], SrcMACaddress[6], NextHopMACaddress[6];  
  bool MACaddress_set, SrcMACaddress_set, NextHopMACaddress_set;
  struct host_timeout_nfo htn;
  devtype interface_type;
  char devname[32];
  char devfullname[32];
  int mtu;
  /* 0 (OS_NOTPERF) if os detection not performed
   * 1 (OS_PERF) if os detection performed 
   * 2 (OS_PERF_UNREL) if an unreliable os detection has been performed */
  int osscan_flag; 
};

#endif /* TARGET_H */
