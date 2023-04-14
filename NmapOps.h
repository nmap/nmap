
/***************************************************************************
 * NmapOps.h -- The NmapOps class contains global options, mostly based on *
 * user-provided command-line settings.                                    *
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

#ifndef NMAP_OPS_H
#define NMAP_OPS_H

#include "nmap.h" /* MAX_DECOYS */
#include "scan_lists.h"
#include "output.h" /* LOG_NUM_FILES */
#include <nbase.h>
#include <nsock.h>
#include <string>
#include <map>
#include <vector>

struct FingerPrintDB;
struct FingerMatch;

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
  /* Returns a const pointer to the source address if set, or NULL if unset. */
  const struct sockaddr_storage *SourceSockAddr() const;
  /* Note that it is OK to pass in a sockaddr_in or sockaddr_in6 casted
     to sockaddr_storage */
  void setSourceSockAddr(struct sockaddr_storage *ss, size_t ss_len);

// The time this obj. was instantiated   or last ReInit()ed.
  const struct timeval *getStartTime() { return &start_time; }
  // Number of seconds since getStartTime().  The current time is an
  // optional argument to avoid an extra gettimeofday() call.
  float TimeSinceStart(const struct timeval *now=NULL);



  bool TCPScan(); /* Returns true if at least one chosen scan type is TCP */
  bool UDPScan(); /* Returns true if at least one chosen scan type is UDP */
  bool SCTPScan(); /* Returns true if at least one chosen scan type is SCTP */

  /* Returns true if at least one chosen scan type uses raw packets.
     It does not currently cover cases such as TCP SYN ping scan which
     can go either way based on whether the user is root or IPv6 is
     being used.  It will return false in those cases where a RawScan
     is not necessarily used. */
  bool RawScan();
  void ValidateOptions(); /* Checks that the options given are
                             reasonable and consistent.  If they aren't, the
                             function may bail out of Nmap or make small
                             adjustments (quietly or with a warning to the
                             user). */
  int isr00t;
  /* Whether we have pcap functions (can be false on Windows). */
  bool have_pcap;
  u8 debugging;
  bool resuming;

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
  u8 verbose;
  /* The requested minimum packet sending rate, or 0.0 if unset. */
  float min_packet_send_rate;
  /* The requested maximum packet sending rate, or 0.0 if unset. */
  float max_packet_send_rate;
  /* The requested auto stats printing interval, or 0.0 if unset. */
  float stats_interval;
  bool randomize_hosts;
  bool randomize_ports;
  bool spoofsource; /* -S used */
  bool fastscan;
  char device[64];
  int ping_group_sz;
  bool nogcc; /* Turn off group congestion control with --nogcc */
  bool generate_random_ips; /* -iR option */
  FingerPrintDB *reference_FPs; /* Used in the new OS scan system. */
  std::vector<FingerMatch> os_labels_ipv6;
  u16 magic_port; /* The source port set by -g or --source-port. */
  bool magic_port_set; /* Was this set by user? */

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
   values and to adjust each other to insure consistence (e.g. that
   max is always at least as high as min) */
  int maxRttTimeout() { return max_rtt_timeout; }
  int minRttTimeout() { return min_rtt_timeout; }
  int initialRttTimeout() { return initial_rtt_timeout; }
  void setMaxRttTimeout(int rtt);
  void setMinRttTimeout(int rtt);
  void setInitialRttTimeout(int rtt);
  void setMaxRetransmissions(int max_retransmit);
  unsigned int getMaxRetransmissions() { return max_retransmissions; }

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
  char *XSLStyleSheet();

  /* Sets the spoofed MAC address */
  void setSpoofMACAddress(u8 *mac_data);
  /* Gets the spoofed MAC address, but returns NULL if it hasn't been set */
  const u8 *spoofMACAddress() { return spoof_mac_set? spoof_mac : NULL; }

  unsigned int max_ips_to_scan; // Used for Random input (-iR) to specify how
                       // many IPs to try before stopping. 0 means unlimited.
  int extra_payload_length; /* These two are for --data-length op */
  char *extra_payload;
  unsigned long host_timeout;
  /* Delay between probes, in milliseconds */
  unsigned int scan_delay;
  bool open_only;

  int scanflags; /* if not -1, this value should dictate the TCP flags
                    for the core portscanning routine (eg to change a
                    FIN scan into a PSH scan.  Sort of a hack, but can
                    be very useful sometimes. */

  bool defeat_rst_ratelimit; /* Solaris 9 rate-limits RSTs so scanning is very
            slow against it. If we don't distinguish between closed and filtered ports,
            we can get the list of open ports very fast */

  bool defeat_icmp_ratelimit; /* If a host rate-limits ICMP responses, then scanning
            is very slow against it. This option prevents Nmap to adjust timing
            when it changes the port's state because of ICMP response, as the latter
            might be rate-limited. Doing so we can get scan results faster. */

  struct sockaddr_storage resume_ip; /* The last IP in the log file if user
                               requested --restore .  Otherwise
                               resume_ip.ss_family == AF_UNSPEC.  Also
                               Target::next_target will eventually set it
                               to AF_UNSPEC. */

  // Version Detection Options
  bool override_excludeports;
  int version_intensity;

  struct sockaddr_storage decoys[MAX_DECOYS];
  bool osscan_limit; /* Skip OS Scan if no open or no closed TCP ports */
  bool osscan_guess;   /* Be more aggressive in guessing OS type */
  int numdecoys;
  int decoyturn;
  bool osscan;
  bool servicescan;
  int pingtype;
  int listscan;
  int fragscan; /* 0 or MTU (without IPv4 header size) */
  int ackscan;
  int bouncescan;
  int connectscan;
  int finscan;
  int idlescan;
  char* idleProxy; /* The idle host used to "Proxy" an idle scan */
  int ipprotscan;
  int maimonscan;
  int nullscan;
  int synscan;
  int udpscan;
  int sctpinitscan;
  int sctpcookieechoscan;
  int windowscan;
  int xmasscan;
  bool noresolve;
  bool noportscan;
  bool append_output; /* Append to any output files rather than overwrite */
  FILE *logfd[LOG_NUM_FILES];
  FILE *nmap_stdout; /* Nmap standard output */
  int ttl; // Time to live
  bool badsum;
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
  bool always_resolve;
  bool resolve_all;
  bool unique;
  char *dns_servers;

  /* Do IPv4 ARP or IPv6 ND scan of directly connected Ethernet hosts, even if
     non-ARP host discovery options are used? This is normally more efficient,
     not only because ARP/ND scan is faster, but because we need the MAC
     addresses provided by ARP or ND scan in order to do IP-based host discovery
     anyway. But when a network uses proxy ARP, all hosts will appear to be up
     unless you do an IP host discovery on them. This option is true by default. */
  bool implicitARPPing;

  // If true, write <os><osclass/><osmatch/></os> as in xmloutputversion 1.03
  // rather than <os><osmatch><osclass/></osmatch></os> as in 1.04 and later.
  bool deprecated_xml_osclass;

  bool traceroute;
  bool reason;
  bool adler32;
  FILE *excludefd;
  char *exclude_spec;
  FILE *inputfd;
  char *portlist; /* Ports list specified by user */
  char *exclude_portlist; /* exclude-ports list specified by user */

  nsock_proxychain proxy_chain;
  bool discovery_ignore_rst; /* host discovery should not consider TCP RST packet responses as a live asset */

#ifndef NOLUA
  bool script;
  char *scriptargs;
  char *scriptargsfile;
  bool scriptversion;
  bool scripttrace;
  bool scriptupdatedb;
  bool scripthelp;
  double scripttimeout;
  void chooseScripts(char* argument);
  std::vector<std::string> chosenScripts;
#endif

  /* ip options used in build_*_raw() */
  u8 *ipoptions;
  int ipoptionslen;
  int ipopt_firsthop;	// offset in ipoptions where is first hop for source/strict routing
  int ipopt_lasthop;	// offset in ipoptions where is space for targets ip for source/strict routing

  // Statistics Options set in nmap.cc
  unsigned int numhosts_scanned;
  unsigned int numhosts_up;
  int numhosts_scanning;
  stype current_scantype;
  bool noninteractive;
  char *locale;

  bool release_memory;	/* suggest to release memory before quitting. used to find memory leaks. */
 private:
  int max_os_tries;
  int max_rtt_timeout;
  int min_rtt_timeout;
  int initial_rtt_timeout;
  unsigned int max_retransmissions;
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
  bool xsl_stylesheet_set;
  char *xsl_stylesheet;
  u8 spoof_mac[6];
  bool spoof_mac_set;
};

#endif
