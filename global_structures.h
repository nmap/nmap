
/***************************************************************************
 * global_structures.h -- Common structure definitions used by Nmap        *
 * components.                                                             *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2012 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 with the clarifications and exceptions described  *
 * below.  This guarantees your right to use, modify, and redistribute     *
 * this software under certain conditions.  If you wish to embed Nmap      *
 * technology into proprietary software, we sell alternative licenses      *
 * (contact sales@insecure.com).  Dozens of software vendors already       *
 * license Nmap technology such as host discovery, port scanning, OS       *
 * detection, version detection, and the Nmap Scripting Engine.            *
 *                                                                         *
 * Note that the GPL places important restrictions on "derived works", yet *
 * it does not provide a detailed definition of that term.  To avoid       *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
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
 * works of Nmap, as well as other software we distribute under this       *
 * license such as Zenmap, Ncat, and Nping.  This list is not exclusive,   *
 * but is meant to clarify our interpretation of derived works with some   *
 * common examples.  Our interpretation applies only to Nmap--we don't     *
 * speak for other people's GPL works.                                     *
 *                                                                         *
 * If you have any questions about the GPL licensing restrictions on using *
 * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
 * we also offer alternative license to integrate Nmap into proprietary    *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates.  They also fund the      *
 * continued development of Nmap.  Please email sales@insecure.com for     *
 * further information.                                                    *
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

/* $Id$ */


#ifndef GLOBAL_STRUCTURES_H
#define GLOBAL_STRUCTURES_H

#include <vector>

class TargetGroup;
class Target;

/* Stores "port info" which is TCP/UDP/SCTP ports or RPC program ids */
struct portinfo {
   unsigned long portno; /* TCP/UDP/SCTP port or RPC program id or IP protocool */
   short trynum;
   int sd[3]; /* Socket descriptors for connect_scan */
   struct timeval sent[3]; 
   int state;
   int next; /* not struct portinfo * for historical reasons */
   int prev;
};

struct portinfolist {
   struct portinfo *openlist;
   struct portinfo *firewalled;
   struct portinfo *testinglist;
};

struct udpprobeinfo {
  u16 iptl;
  u16 ipid;
  u16 ipck;
  u16 sport;
  u16 dport;
  u16 udpck;
  u16 udplen;
  u8 patternbyte;
  struct in_addr target;
};

/* The runtime statistics used to decide how fast to proced and how
   many ports we can try at once */
struct scanstats {
  int packet_incr;
  int initial_packet_width; /* Number of queries in parallel we should 
			       start with */
  double fallback_percent;
  int numqueries_outstanding; /* How many unexpired queries are on the 'net
				 right now? */
  double numqueries_ideal; /* How many do we WANT to be on the 'net right now? */
  int max_width; /* What is the MOST we will tolerate at once.  Can be 
		    modified via --max_parallelism */
  int min_width; /* We must always allow at least this many at once.  Can 
		    be modified via --min_parallelism*/
  int ports_left;
  int changed; /* Has anything changed since last round? */
  int alreadydecreasedqueries;
};

struct ftpinfo {
  char user[64];
  char pass[256]; /* methinks you're paranoid if you need this much space */
  char server_name[MAXHOSTNAMELEN + 1];
  struct in_addr server;
  u16 port;
  int sd; /* socket descriptor */
};

struct AVal {
  const char *attribute;
  const char *value;

  bool operator<(const AVal& other) const {
    return strcmp(attribute, other.attribute) < 0;
  }
};

struct OS_Classification {
  const char *OS_Vendor;
  const char *OS_Family;
  const char *OS_Generation; /* Can be NULL if unclassified */
  const char *Device_Type;
  std::vector<const char *> cpe;
};

/* A description of an operating system: a human-readable name and a list of
   classifications. */
struct FingerMatch {
  int line; /* For reference prints, the line # in nmap-os-db */
  char *OS_name;
  std::vector<OS_Classification> OS_class;

  FingerMatch() {
    line = -1;
    OS_name = NULL;
  }
};

struct FingerTest {
  const char *name;
  std::vector<struct AVal> results;
  bool operator<(const FingerTest& other) const {
    return strcmp(name, other.name) < 0;
  }
};

struct FingerPrint {
  FingerMatch match;
  std::vector<FingerTest> tests;
  FingerPrint();
  void sort();
};

/* This structure contains the important data from the fingerprint
   database (nmap-os-db) */
struct FingerPrintDB {
  FingerPrint *MatchPoints;
  std::vector<FingerPrint *> prints;

  FingerPrintDB();
  ~FingerPrintDB();
};

/* Based on TCP congestion control techniques from RFC2581. */
struct ultra_timing_vals {
  double cwnd; /* Congestion window - in probes */
  int ssthresh; /* The threshold above which mode is changed from slow start
		   to congestion avoidance */
  /* The number of replies we would expect if every probe produced a reply. This
     is almost like the total number of probes sent but it is not incremented
     until a reply is received or a probe times out. This and
     num_replies_received are used to scale congestion window increments. */
  int num_replies_expected;
  /* The number of replies we've received to probes of any type. */
  int num_replies_received;
  /* Number of updates to this timing structure (generally packet receipts). */
  int num_updates;
  /* Last time values were adjusted for a drop (you usually only want
     to adjust again based on probes sent after that adjustment so a
     sudden batch of drops doesn't destroy timing.  Init to now */
  struct timeval last_drop;

  double cc_scale(const struct scan_performance_vars *perf);
  void ack(const struct scan_performance_vars *perf, double scale = 1.0);
  void drop(unsigned in_flight,
    const struct scan_performance_vars *perf, const struct timeval *now);
  void drop_group(unsigned in_flight,
    const struct scan_performance_vars *perf, const struct timeval *now);
};

/* These are mainly initializers for ultra_timing_vals. */
struct scan_performance_vars {
  int low_cwnd;  /* The lowest cwnd (congestion window) allowed */
  int host_initial_cwnd; /* Initial congestion window for ind. hosts */
  int group_initial_cwnd; /* Initial congestion window for all hosts as a group */
  int max_cwnd; /* I should never have more than this many probes
		   outstanding */
  int slow_incr; /* How many probes are incremented for each response
		    in slow start mode */
  int ca_incr; /* How many probes are incremented per (roughly) rtt in 
		  congestion avoidance mode */
  int cc_scale_max; /* The maximum scaling factor for congestion window
		       increments. */
  int initial_ssthresh;
  double group_drop_cwnd_divisor; /* all-host group cwnd divided by this
				     value if any packet drop occurs */
  double group_drop_ssthresh_divisor; /* used to drop the group ssthresh when
					 any drop occurs */
  double host_drop_ssthresh_divisor; /* used to drop the host ssthresh when
					 any drop occurs */

  /* Do initialization after the global NmapOps table has been filled in. */
  void init();
};

struct timeout_info {
  int srtt; /* Smoothed rtt estimate (microseconds) */
  int rttvar; /* Rout trip time variance */
  int timeout; /* Current timeout threshold (microseconds) */
};

struct seq_info {
  int responses;
  int ts_seqclass; /* TS_SEQ_* defines in nmap.h */
  int ipid_seqclass; /* IPID_SEQ_* defines in nmap.h */
  u32 seqs[NUM_SEQ_SAMPLES];
  u32 timestamps[NUM_SEQ_SAMPLES];
  int index;
  u16 ipids[NUM_SEQ_SAMPLES];
  long lastboot; /* 0 means unknown */
};

/* Different kinds of Ipids. */
struct ipid_info {
  int tcp_ipids[NUM_SEQ_SAMPLES];
  int tcp_closed_ipids[NUM_SEQ_SAMPLES];
  int icmp_ipids[NUM_SEQ_SAMPLES];
};

/* The various kinds of port/protocol scans we can have
 * Each element is to point to an array of port/protocol numbers
 */
struct scan_lists {
	/* The "synprobes" are also used when doing a connect() ping */
	unsigned short *syn_ping_ports;
	unsigned short *ack_ping_ports;
	unsigned short *udp_ping_ports;
	unsigned short *sctp_ping_ports;
	unsigned short *proto_ping_ports;
	int syn_ping_count;
	int ack_ping_count;
	int udp_ping_count;
	int sctp_ping_count;
	int proto_ping_count;
	//the above fields are only used for host discovery
	//the fields below are only used for port scanning
	unsigned short *tcp_ports;
	int tcp_count;
	unsigned short *udp_ports;
	int udp_count;
	unsigned short *sctp_ports;
	int sctp_count;
	unsigned short *prots;
	int prot_count;
};

typedef enum { STYPE_UNKNOWN, HOST_DISCOVERY, ACK_SCAN, SYN_SCAN, FIN_SCAN, XMAS_SCAN, UDP_SCAN, CONNECT_SCAN, NULL_SCAN, WINDOW_SCAN, SCTP_INIT_SCAN, SCTP_COOKIE_ECHO_SCAN, MAIMON_SCAN, IPPROT_SCAN, PING_SCAN, PING_SCAN_ARP, IDLE_SCAN, BOUNCE_SCAN, SERVICE_SCAN, OS_SCAN, SCRIPT_PRE_SCAN, SCRIPT_SCAN, SCRIPT_POST_SCAN, TRACEROUTE, PING_SCAN_ND }stype;

#endif /*GLOBAL_STRUCTURES_H */
