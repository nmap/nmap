
/***************************************************************************
 * NmapOps.h -- The NmapOps class contains global options, mostly based on *
 * user-provided command-line settings.                                    *
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

#include "nmap.h"
#include "global_structures.h"
#include "output.h"
#include <string>

class NmapOps {
 public:
  NmapOps();
  ~NmapOps();
  void ReInit(); // Reinitialize the class to default state
  void setaf(int af) { addressfamily = af; }
  int af() { return addressfamily; }
  // no setpf() because it is based on setaf() values
  int pf();
  /* Returns 0 for success, nonzero if no source has been set or any other
     failure */
  int SourceSockAddr(struct sockaddr_storage *ss, size_t *ss_len);
  /* Note that it is OK to pass in a sockaddr_in or sockaddr_in6 casted
     to sockaddr_storage */
  void setSourceSockAddr(struct sockaddr_storage *ss, size_t ss_len);

// The time this obj. was instantiated   or last ReInit()ed.
  const struct timeval *getStartTime() { return &start_time; }
  // Number of milliseconds since getStartTime().  The current time is an
  // optional argument to avoid an extra gettimeofday() call.
  int TimeSinceStartMS(const struct timeval *now=NULL); 
  struct in_addr v4source();
  const struct in_addr *v4sourceip();



  bool TCPScan(); /* Returns true if at least one chosen scan type is TCP */
  bool UDPScan(); /* Returns true if at least one chosen scan type is UDP */
  bool SCTPScan(); /* Returns true if at least one chosen scan type is SCTP */

  /* Returns true if at least one chosen scan type uses raw packets.
     It does not currently cover cases such as TCP SYN ping scan which
     can go either way based on whether the user is root or IPv6 is
     being used.  It will return false in those cases where a RawScan
     is not neccessarily used. */
  bool RawScan();
  void ValidateOptions(); /* Checks that the options given are
                             reasonable and consistant.  If they aren't, the
                             function may bail out of Nmap or make small
		             adjustments (quietly or with a warning to the
		             user). */
  int isr00t;
  /* Whether we have pcap functions (can be false on Windows). */
  bool have_pcap;
  int debugging;

#define PACKET_SEND_NOPREF 1
#define PACKET_SEND_ETH_WEAK 2
#define PACKET_SEND_ETH_STRONG 4
#define PACKET_SEND_ETH 6
#define PACKET_SEND_IP_WEAK 8
#define PACKET_SEND_IP_STRONG 16
#define PACKET_SEND_IP 24

  /* How should we send raw IP packets?  Nmap can generally use either
     ethernet or raw ip sockets.  Which is better depends on platform
     and goals.  A _STRONG preference means that Nmap should use the
     preferred method whenever it is possible (obviously it isn't
     always possible -- sending ethernet frames won't work over a PPP
     connection).  This is useful when the other type doesn't work at
     all.  A _WEAK preference means that Nmap may use the other type
     where it is substantially more efficient to do so. For example,
     Nmap will still do an ARP ping scan of a local network even when
     the pref is SEND_IP_WEAK */
  int sendpref;
  bool packetTrace() { return (debugging >= 3)? true : pTrace;  }
  bool versionTrace() { return packetTrace()? true : vTrace;  }
#ifndef NOLUA
  bool scriptTrace() { return packetTrace()? true : scripttrace; }
#endif
  // Note that packetTrace may turn on at high debug levels even if
  // setPacketTrace(false) has been called
  void setPacketTrace(bool pt) { pTrace = pt;  }
  void setVersionTrace(bool vt) { vTrace = vt;  }
  bool openOnly() { return open_only; }
  void setOpenOnly(bool oo) { open_only = oo; }
  int verbose;
  /* The requested minimum packet sending rate, or 0.0 if unset. */
  float min_packet_send_rate;
  /* The requested maximum packet sending rate, or 0.0 if unset. */
  float max_packet_send_rate;
  /* The requested auto stats printing interval, or 0.0 if unset. */
  float stats_interval;
  int randomize_hosts;
  int spoofsource; /* -S used */
  int fastscan;
  char device[64];
  int ping_group_sz;
  int nogcc; /* Turn off group congestion control with --nogcc */
  int generate_random_ips; /* -iR option */
  FingerPrintDB *reference_FPs; /* Used in the new OS scan system. */
  u16 magic_port;
  unsigned short magic_port_set; /* Was this set by user? */

  /* Scan timing/politeness issues */
  int timing_level; // 0-5, corresponding to Paranoid, Sneaky, Polite, Normal, Aggressive, Insane
  int max_parallelism; // 0 means it has not been set
  int min_parallelism; // 0 means it has not been set
  double topportlevel; // -1 means it has not been set

  /* The maximum number of OS detection (gen2) tries we will make
     without any matches before giving up on a host.  We may well give
     up after fewer tries anyway, particularly if the target isn't
     ideal for unknown fingerprint submissions */
  int maxOSTries() { return max_os_tries; }
  void setMaxOSTries(int mot);

  /* These functions retrieve and set the Round Trip Time timeouts, in
   milliseconds.  The set versions do extra processing to insure sane
   values and to adjust each other to insure consistance (e.g. that
   max is always at least as high as min) */
  int maxRttTimeout() { return max_rtt_timeout; }
  int minRttTimeout() { return min_rtt_timeout; }
  int initialRttTimeout() { return initial_rtt_timeout; }
  void setMaxRttTimeout(int rtt);
  void setMinRttTimeout(int rtt);
  void setInitialRttTimeout(int rtt);
  void setMaxRetransmissions(int max_retransmit);
  int getMaxRetransmissions() { return max_retransmissions; }

  /* Similar functions for Host group size */
  int minHostGroupSz() { return min_host_group_sz; }
  int maxHostGroupSz() { return max_host_group_sz; }
  void setMinHostGroupSz(unsigned int sz);
  void setMaxHostGroupSz(unsigned int sz);
  unsigned int maxTCPScanDelay() { return max_tcp_scan_delay; }
  unsigned int maxUDPScanDelay() { return max_udp_scan_delay; }
  unsigned int maxSCTPScanDelay() { return max_sctp_scan_delay; }
  void setMaxTCPScanDelay(unsigned int delayMS) { max_tcp_scan_delay = delayMS; }
  void setMaxUDPScanDelay(unsigned int delayMS) { max_udp_scan_delay = delayMS; }
  void setMaxSCTPScanDelay(unsigned int delayMS) { max_sctp_scan_delay = delayMS; }

  /* Sets the Name of the XML stylesheet to be printed in XML output.
     If this is never called, a default stylesheet distributed with
     Nmap is used.  If you call it with NULL as the xslname, no
     stylesheet line is printed. */
  void setXSLStyleSheet(const char *xslname);
  /* Returns the full path or URL that should be printed in the XML
     output xml-stylesheet element.  Returns NULL if the whole element
     should be skipped */
  char *XSLStyleSheet() { return xsl_stylesheet; }

  /* Sets the spoofed MAC address */
  void setSpoofMACAddress(u8 *mac_data);
  /* Gets the spoofed MAC address, but returns NULL if it hasn't been set */
  const u8 *spoofMACAddress() { return spoof_mac_set? spoof_mac : NULL; }

  int max_ips_to_scan; // Used for Random input (-iR) to specify how 
                       // many IPs to try before stopping. 0 means unlimited.
  int extra_payload_length; /* These two are for --data-length op */
  char *extra_payload;
  unsigned long host_timeout;
  /* Delay between probes, in milliseconds */
  unsigned int scan_delay;
  bool open_only;

  int scanflags; /* if not -1, this value should dictate the TCP flags
		    for the core portscaning routine (eg to change a
		    FIN scan into a PSH scan.  Sort of a hack, but can
		    be very useful sometimes. */

  int defeat_rst_ratelimit; /* Solaris 9 rate-limits RSTs so scanning is very
            slow against it. If we don't distinguish between closed and filtered ports,
            we can get the list of open ports very fast */

  struct in_addr resume_ip; /* The last IP in the log file if user 
			       requested --restore .  Otherwise 
			       restore_ip.s_addr == 0.  Also 
			       target_struct_get will eventually set it 
			       to 0. */

  // Version Detection Options
  int override_excludeports;
  int version_intensity;

  struct in_addr decoys[MAX_DECOYS];
  int osscan_limit; /* Skip OS Scan if no open or no closed TCP ports */
  int osscan_guess;   /* Be more aggressive in guessing OS type */
  int numdecoys;
  int decoyturn;
  int osscan;
  int servicescan;
  int pingtype;
  int listscan;
  int allowall;
  int fragscan; /* 0 or MTU (without IPv4 header size) */
  int ackscan;
  int bouncescan;
  int connectscan;
  int finscan;
  int idlescan;
  int ipprotscan;
  int maimonscan;
  int nullscan;
  int synscan;
  int udpscan;
  int sctpinitscan;
  int sctpcookieechoscan;
  int windowscan;
  int xmasscan;
  int noresolve;
  int noportscan;
  int append_output; /* Append to any output files rather than overwrite */
  FILE *logfd[LOG_NUM_FILES];
  FILE *nmap_stdout; /* Nmap standard output */
  int ttl; // Time to live
  int badsum;
  char *datadir;
  /* A map from abstract data file names like "nmap-services" and "nmap-os-db"
     to paths which have been requested by the user. nmap_fetchfile will return
     the file names defined in this map instead of searching for a matching
     file. */
  std::map<std::string, std::string> requested_data_files;
  /* A map from data file names to the paths at which they were actually found.
     Only files that were actually read should be in this map. */
  std::map<std::string, std::string> loaded_data_files;
  bool mass_dns;
  int resolve_all;
  char *dns_servers;
  bool log_errors;
  bool traceroute;
  bool reason;
  bool adler32;

#ifndef NOLUA
  int script;
  char *scriptargs;
  int scriptversion;
  int scripttrace;
  int scriptupdatedb;
  bool scripthelp;
  void chooseScripts(char* argument);
  std::vector<std::string> chosenScripts;
#endif

  /* ip options used in build_*_raw() */
  u8 *ipoptions;
  int ipoptionslen;
  int ipopt_firsthop;	// offset in ipoptions where is first hop for source/strict routing
  int ipopt_lasthop;	// offset in ipoptions where is space for targets ip for source/strict routing

  // Statistics Options set in nmap.cc
  int numhosts_scanned;
  int numhosts_up;
  int numhosts_scanning;
  stype current_scantype;
  bool noninteractive;

  bool release_memory;	/* suggest to release memory before quitting. used to find memory leaks. */
 private:
  int max_os_tries;
  int max_rtt_timeout;
  int min_rtt_timeout;
  int initial_rtt_timeout;
  int max_retransmissions;
  unsigned int max_tcp_scan_delay;
  unsigned int max_udp_scan_delay;
  unsigned int max_sctp_scan_delay;
  unsigned int min_host_group_sz;
  unsigned int max_host_group_sz;
  void Initialize();
  int addressfamily; /*  Address family:  AF_INET or AF_INET6 */  
  struct sockaddr_storage sourcesock;
  size_t sourcesocklen;
  struct timeval start_time;
  bool pTrace; // Whether packet tracing has been enabled
  bool vTrace; // Whether version tracing has been enabled
  char *xsl_stylesheet;
  u8 spoof_mac[6];
  bool spoof_mac_set;
};
  
