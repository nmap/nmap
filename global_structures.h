
/***************************************************************************
 * global_structures.h -- Common structure definitions used by Nmap        *
 * components.                                                             *
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
 *   nmap-os-fingerprints or nmap-service-probes.                          *
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
 * listed in the included Copying.OpenSSL file, and distribute linked      *
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
 * General Public License for more details at                              *
 * http://www.gnu.org/copyleft/gpl.html , or in the COPYING file included  *
 * with Nmap.                                                              *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */


#ifndef GLOBAL_STRUCTURES_H
#define GLOBAL_STRUCTURES_H

class TargetGroup;
class Target;

/* Stores "port info" which is TCP/UDP ports or RPC program ids */
struct portinfo {
   unsigned long portno; /* TCP/UDP port or RPC program id or IP protocool */
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
  char *attribute;
  char value[128];
  struct AVal *next;
};

struct OS_Classification {
  char *OS_Vendor;
  char *OS_Family;
  char *OS_Generation; /* Can be NULL if unclassified */
  char *Device_Type;
};

#define MAX_OS_CLASSIFICATIONS_PER_FP 8
typedef struct FingerTest {
  char *OS_name;
  struct OS_Classification OS_class[MAX_OS_CLASSIFICATIONS_PER_FP];
  int num_OS_Classifications;
  int line; /* For reference prints, the line # in nmap-os-db */
  const char *name;
  struct AVal *results;
  struct FingerTest *next;
 } FingerPrint;

/* This structure contains the important data from the fingerprint
   database (nmap-os-db) */
typedef struct FingerPrintDB {
  FingerPrint **prints;
  FingerPrint *MatchPoints;
} FingerPrintDB;

struct timeout_info {
  int srtt; /* Smoothed rtt estimate (microseconds) */
  int rttvar; /* Rout trip time variance */
  int timeout; /* Current timeout threshold (microseconds) */
};

struct seq_info {
  int responses;
  int ts_seqclass; /* TS_SEQ_* defines in nmap.h */
  time_t uptime; /* time of latest system boot (or 0 if unknown ) */
  int ipid_seqclass; /* IPID_SEQ_* defines in nmap.h */
  u32 seqs[NUM_SEQ_SAMPLES];
  u32 timestamps[NUM_SEQ_SAMPLES];
  int index;
  u16 ipids[NUM_SEQ_SAMPLES];
  time_t lastboot; /* 0 means unknown */
};

/* Different kinds of Ipids. */
struct ipid_info {
  int tcp_ipids[NUM_SEQ_SAMPLES];
  int icmp_ipids[NUM_SEQ_SAMPLES];
};

/* The various kinds of port/protocol scans we can have
 * Each element is to point to an array of port/protocol numbers
 */
struct scan_lists {
	unsigned short *tcp_ports;
	int tcp_count;
	unsigned short *udp_ports;
	int udp_count;
	unsigned short *prots;
	int prot_count;
};

typedef enum { STYPE_UNKNOWN, HOST_DISCOVERY, ACK_SCAN, SYN_SCAN, FIN_SCAN, XMAS_SCAN, UDP_SCAN, CONNECT_SCAN, NULL_SCAN, WINDOW_SCAN, RPC_SCAN, MAIMON_SCAN, IPPROT_SCAN, PING_SCAN, PING_SCAN_ARP, IDLE_SCAN, BOUNCE_SCAN, SERVICE_SCAN, OS_SCAN, SCRIPT_SCAN, TRACEROUTE, REF_TRACEROUTE}stype;

#endif /*GLOBAL_STRUCTURES_H */
