/***************************************************************************
 * nmap.cc -- Currently handles some of Nmap's port scanning features as   *
 * well as the command line user interface.  Note that the actual main()   *
 * function is in main.cc                                                  *
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
#include "osscan.h"
#include "osscan2.h"
#include "scan_engine.h"
#include "idle_scan.h"
#include "timing.h"
#include "NmapOps.h"
#include "MACLookup.h"
#include "traceroute.h"
#include "nmap_tty.h"
#include "nmap_dns.h"
#include "services.h"
#include "protocols.h"
#include "targets.h"
#include "TargetGroup.h"
#include "service_scan.h"
#include "charpool.h"
#include "nmap_error.h"
#include "utils.h"
#include "xml.h"

#ifndef NOLUA
#include "nse_main.h"
#endif 

#ifdef WIN32
#include "winfix.h"
#endif

#if HAVE_OPENSSL
#include <openssl/opensslv.h>
#endif

/* To get the version number only. */
#ifdef WIN32
#include "libdnet-stripped/include/dnet_winconfig.h"
#else
#include "libdnet-stripped/include/config.h"
#endif
#define DNET_VERSION VERSION

using namespace std;

/* global options */
extern char *optarg;
extern int optind;
extern NmapOps o;  /* option structure */

/* argv[0] storage from main.cc. */
extern const char *get_program_name(void);
static bool target_needs_new_hostgroup(std::vector<Target *> &targets,
  const Target *target);
static void display_nmap_version();

/* parse the --scanflags argument.  It can be a number >=0 or a string consisting of TCP flag names like "URGPSHFIN".  Returns -1 if the argument is invalid. */
static int parse_scanflags(char *arg) {
  int flagval = 0;
  char *end = NULL;

  if (isdigit((int) (unsigned char) arg[0])) {
    flagval = strtol(arg, &end, 0);
    if (*end || flagval < 0 || flagval > 255) return -1;
  } else {
    if (strcasestr(arg, "FIN")) {
      flagval |= TH_FIN;
    } 
    if (strcasestr(arg, "SYN")) {
      flagval |= TH_SYN;
    } 
    if (strcasestr(arg, "RST") || strcasestr(arg, "RESET")) {
      flagval |= TH_RST;
    } 
    if (strcasestr(arg, "PSH") || strcasestr(arg, "PUSH")) {
      flagval |= TH_PUSH;
    } 
    if (strcasestr(arg, "ACK")) {
      flagval |= TH_ACK;
    } 
    if (strcasestr(arg, "URG")) {
      flagval |= TH_URG;
    } 
    if (strcasestr(arg, "ECE")) {
      flagval |= TH_ECE;
    } 
    if (strcasestr(arg, "CWR")) {
      flagval |= TH_CWR;
    } 
    if (strcasestr(arg, "ALL")) {
      flagval = 255;
    }
    if (strcasestr(arg, "NONE")) {
      flagval = 0;
    }
  }
  return flagval;
}

/* parse a URL stype ftp string of the form user:pass@server:portno */
static int parse_bounce_argument(struct ftpinfo *ftp, char *url) {
  char *p = url,*q, *s;

  if ((q = strrchr(url, '@'))) { /* we have user and/or pass */
    *q++ = '\0';

    if ((s = strchr(p, ':'))) { /* we have user AND pass */
      *s++ = '\0';
      strncpy(ftp->pass, s, 255);
    } else { /* we ONLY have user */
      log_write(LOG_STDOUT, "Assuming %s is a username, and using the default password: %s\n",
          p, ftp->pass);
    }

    strncpy(ftp->user, p, 63);
  } else {
    q = url;
  }

  /* q points to beginning of server name */
  if ((s = strchr(q, ':'))) { /* we have portno */
    *s++ = '\0';
    ftp->port = atoi(s);
  }

  strncpy(ftp->server_name, q, MAXHOSTNAMELEN);

  ftp->user[63] = ftp->pass[255] = ftp->server_name[MAXHOSTNAMELEN] = 0;

  return 1;
}

static void printusage(char *name, int rc) {

printf("%s %s ( %s )\n"
       "Usage: nmap [Scan Type(s)] [Options] {target specification}\n"
       "TARGET SPECIFICATION:\n"
       "  Can pass hostnames, IP addresses, networks, etc.\n"
       "  Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254\n"
       "  -iL <inputfilename>: Input from list of hosts/networks\n"
       "  -iR <num hosts>: Choose random targets\n"
       "  --exclude <host1[,host2][,host3],...>: Exclude hosts/networks\n"
       "  --excludefile <exclude_file>: Exclude list from file\n"
       "HOST DISCOVERY:\n"
       "  -sL: List Scan - simply list targets to scan\n"
       "  -sn: Ping Scan - disable port scan\n"
       "  -Pn: Treat all hosts as online -- skip host discovery\n"
       "  -PS/PA/PU/PY[portlist]: TCP SYN/ACK, UDP or SCTP discovery to given ports\n"
       "  -PE/PP/PM: ICMP echo, timestamp, and netmask request discovery probes\n"
       "  -PO[protocol list]: IP Protocol Ping\n"
       "  -n/-R: Never do DNS resolution/Always resolve [default: sometimes]\n"
       "  --dns-servers <serv1[,serv2],...>: Specify custom DNS servers\n"
       "  --system-dns: Use OS's DNS resolver\n"
       "  --traceroute: Trace hop path to each host\n"
       "SCAN TECHNIQUES:\n"
       "  -sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans\n"
       "  -sU: UDP Scan\n"
       "  -sN/sF/sX: TCP Null, FIN, and Xmas scans\n"
       "  --scanflags <flags>: Customize TCP scan flags\n"
       "  -sI <zombie host[:probeport]>: Idle scan\n"
       "  -sY/sZ: SCTP INIT/COOKIE-ECHO scans\n"
       "  -sO: IP protocol scan\n"
       "  -b <FTP relay host>: FTP bounce scan\n"
       "PORT SPECIFICATION AND SCAN ORDER:\n"
       "  -p <port ranges>: Only scan specified ports\n"
       "    Ex: -p22; -p1-65535; -p U:53,111,137,T:21-25,80,139,8080,S:9\n"
       "  -F: Fast mode - Scan fewer ports than the default scan\n"
       "  -r: Scan ports consecutively - don't randomize\n"
       "  --top-ports <number>: Scan <number> most common ports\n"
       "  --port-ratio <ratio>: Scan ports more common than <ratio>\n"
       "SERVICE/VERSION DETECTION:\n"
       "  -sV: Probe open ports to determine service/version info\n"
       "  --version-intensity <level>: Set from 0 (light) to 9 (try all probes)\n"
       "  --version-light: Limit to most likely probes (intensity 2)\n"
       "  --version-all: Try every single probe (intensity 9)\n"
       "  --version-trace: Show detailed version scan activity (for debugging)\n"
#ifndef NOLUA
       "SCRIPT SCAN:\n"
       "  -sC: equivalent to --script=default\n"
       "  --script=<Lua scripts>: <Lua scripts> is a comma separated list of \n"
       "           directories, script-files or script-categories\n"
       "  --script-args=<n1=v1,[n2=v2,...]>: provide arguments to scripts\n"
       "  --script-trace: Show all data sent and received\n"
       "  --script-updatedb: Update the script database.\n"
#endif
       "OS DETECTION:\n"
       "  -O: Enable OS detection\n"
       "  --osscan-limit: Limit OS detection to promising targets\n"
       "  --osscan-guess: Guess OS more aggressively\n"
       "TIMING AND PERFORMANCE:\n"
       "  Options which take <time> are in seconds, or append 'ms' (milliseconds),\n"
       "  's' (seconds), 'm' (minutes), or 'h' (hours) to the value (e.g. 30m).\n"
       "  -T<0-5>: Set timing template (higher is faster)\n"
       "  --min-hostgroup/max-hostgroup <size>: Parallel host scan group sizes\n"
       "  --min-parallelism/max-parallelism <numprobes>: Probe parallelization\n"
       "  --min-rtt-timeout/max-rtt-timeout/initial-rtt-timeout <time>: Specifies\n"
       "      probe round trip time.\n"
       "  --max-retries <tries>: Caps number of port scan probe retransmissions.\n"
       "  --host-timeout <time>: Give up on target after this long\n"
       "  --scan-delay/--max-scan-delay <time>: Adjust delay between probes\n"
       "  --min-rate <number>: Send packets no slower than <number> per second\n"
       "  --max-rate <number>: Send packets no faster than <number> per second\n"
       "FIREWALL/IDS EVASION AND SPOOFING:\n"
       "  -f; --mtu <val>: fragment packets (optionally w/given MTU)\n"
       "  -D <decoy1,decoy2[,ME],...>: Cloak a scan with decoys\n"
       "  -S <IP_Address>: Spoof source address\n"
       "  -e <iface>: Use specified interface\n"
       "  -g/--source-port <portnum>: Use given port number\n"
       "  --data-length <num>: Append random data to sent packets\n"
       "  --ip-options <options>: Send packets with specified ip options\n"
       "  --ttl <val>: Set IP time-to-live field\n"
       "  --spoof-mac <mac address/prefix/vendor name>: Spoof your MAC address\n"
       "  --badsum: Send packets with a bogus TCP/UDP/SCTP checksum\n"
       "OUTPUT:\n"
       "  -oN/-oX/-oS/-oG <file>: Output scan in normal, XML, s|<rIpt kIddi3,\n"
       "     and Grepable format, respectively, to the given filename.\n"
       "  -oA <basename>: Output in the three major formats at once\n"
       "  -v: Increase verbosity level (use -vv or more for greater effect)\n"
       "  -d: Increase debugging level (use -dd or more for greater effect)\n"
       "  --reason: Display the reason a port is in a particular state\n"
       "  --open: Only show open (or possibly open) ports\n"
       "  --packet-trace: Show all packets sent and received\n"
       "  --iflist: Print host interfaces and routes (for debugging)\n"
       "  --log-errors: Log errors/warnings to the normal-format output file\n"
       "  --append-output: Append to rather than clobber specified output files\n"
       "  --resume <filename>: Resume an aborted scan\n"
       "  --stylesheet <path/URL>: XSL stylesheet to transform XML output to HTML\n"
       "  --webxml: Reference stylesheet from Nmap.Org for more portable XML\n"
       "  --no-stylesheet: Prevent associating of XSL stylesheet w/XML output\n"
       "MISC:\n"
       "  -6: Enable IPv6 scanning\n"
       "  -A: Enable OS detection, version detection, script scanning, and traceroute\n"
       "  --datadir <dirname>: Specify custom Nmap data file location\n"
       "  --send-eth/--send-ip: Send using raw ethernet frames or IP packets\n"
       "  --privileged: Assume that the user is fully privileged\n"
       "  --unprivileged: Assume the user lacks raw socket privileges\n"
       "  -V: Print version number\n"
       "  -h: Print this help summary page.\n"
       "EXAMPLES:\n"
       "  nmap -v -A scanme.nmap.org\n"
       "  nmap -v -sn 192.168.0.0/16 10.0.0.0/8\n"
       "  nmap -v -iR 10000 -Pn -p 80\n"
       "SEE THE MAN PAGE (http://nmap.org/book/man.html) FOR MORE OPTIONS AND EXAMPLES\n", NMAP_NAME, NMAP_VERSION, NMAP_URL);
  exit(rc);
}

static void insert_port_into_merge_list(unsigned short *mlist,
                                        int *merged_port_count,
                                        unsigned short p) {
    int i;
    // make sure the port isn't already in the list
    for (i = 0; i < *merged_port_count; i++) {
        if (mlist[i] == p) {
            return;
        }
    }
    mlist[*merged_port_count] = p;
    (*merged_port_count)++;
}

static unsigned short *merge_port_lists(unsigned short *port_list1, int count1,
                                        unsigned short *port_list2, int count2,
                                        int *merged_port_count) {
    int i;
    unsigned short *merged_port_list = NULL;

    *merged_port_count = 0;

    merged_port_list =
        (unsigned short *) safe_zalloc((count1 + count2) * sizeof(unsigned short));

    for (i = 0; i < count1; i++) {
        insert_port_into_merge_list(merged_port_list,
                            merged_port_count,
                            port_list1[i]);
    }
    for (i = 0; i < count2; i++) {
        insert_port_into_merge_list(merged_port_list,
                            merged_port_count,
                            port_list2[i]);
    }

    // if there were duplicate ports then we can save some memory
    if (*merged_port_count < (count1 + count2)) {
        merged_port_list = (unsigned short*)
            safe_realloc(merged_port_list,
                         (*merged_port_count) * sizeof(unsigned short));
    }

    return merged_port_list;
}

void validate_scan_lists(scan_lists &ports, NmapOps &o){
	if (o.pingtype == PINGTYPE_UNKNOWN) {
		if (o.isr00t && o.pf() == PF_INET) {
			o.pingtype = DEFAULT_PING_TYPES;
			getpts_simple(DEFAULT_PING_ACK_PORT_SPEC, SCAN_TCP_PORT,
				&ports.ack_ping_ports, &ports.ack_ping_count);
			getpts_simple(DEFAULT_PING_SYN_PORT_SPEC, SCAN_TCP_PORT,
				&ports.syn_ping_ports, &ports.syn_ping_count);
		} else {
			o.pingtype = PINGTYPE_TCP; // if nonr00t or IPv6
			getpts_simple(DEFAULT_PING_CONNECT_PORT_SPEC, SCAN_TCP_PORT,
				&ports.syn_ping_ports, &ports.syn_ping_count);
		}
	}

	if ((o.pingtype & PINGTYPE_TCP) && (!o.isr00t || o.pf() != PF_INET)) {
    		// We will have to do a connect() style ping 
		// Pretend we wanted SYN probes all along.
		if (ports.ack_ping_count > 0) { 
			// Combine the ACK and SYN ping port lists since they both reduce to
			// SYN probes in this case
			unsigned short *merged_port_list;
			int merged_port_count;

			merged_port_list = merge_port_lists(
					ports.syn_ping_ports, ports.syn_ping_count,
					ports.ack_ping_ports, ports.ack_ping_count,
					&merged_port_count);

			// clean up a bit
			free(ports.syn_ping_ports);
			free(ports.ack_ping_ports);

			ports.syn_ping_count = merged_port_count;
			ports.syn_ping_ports = merged_port_list;
			ports.ack_ping_count = 0;
			ports.ack_ping_ports = NULL;
		}
		o.pingtype &= ~PINGTYPE_TCP_USE_ACK;
		o.pingtype |= PINGTYPE_TCP_USE_SYN;
	}

	#ifndef WIN32	/*	Win32 has perfectly fine ICMP socket support */
	if (!o.isr00t) {
		if (o.pingtype & (PINGTYPE_ICMP_PING|PINGTYPE_ICMP_MASK|PINGTYPE_ICMP_TS)) {
			error("Warning:  You are not root -- using TCP pingscan rather than ICMP");
			o.pingtype = PINGTYPE_TCP;
			if (ports.syn_ping_count == 0){
				getpts_simple(DEFAULT_TCP_PROBE_PORT_SPEC, SCAN_TCP_PORT, &ports.syn_ping_ports, &ports.syn_ping_count);
				assert(ports.syn_ping_count > 0);
			}
		}
	}
	#endif
}

int nmap_main(int argc, char *argv[]) {
  char *p, *q;
  int i, arg;
  long l;
  double d;
  unsigned int targetno;
  FILE *inputfd = NULL, *excludefd = NULL;
  char *host_spec = NULL, *exclude_spec = NULL;
  short randomize=1;
  short quashargv = 0;
  char **host_exp_group;
  char *idleProxy = NULL; /* The idle host used to "Proxy" an idle scan */
  int num_host_exp_groups;
  char *machinefilename = NULL, *kiddiefilename = NULL,
    *normalfilename = NULL, *xmlfilename = NULL;
  time_t now;
  struct tm *tm;
  HostGroupState *hstate = NULL;
  char *endptr = NULL;
  struct scan_lists ports = { 0 };
#ifndef NOLUA
  /* Pre-Scan and Post-Scan script results datastructure */
  ScriptResults *script_scan_results = NULL;
  /* Only NSE scripts can add targets */
  NewTargets *new_targets = NULL;
#endif
  TargetGroup *exclude_group = NULL;
  char myname[MAXHOSTNAMELEN + 1];
#if (defined(IN_ADDR_DEEPSTRUCT) || defined( SOLARIS))
  /* Note that struct in_addr in solaris is 3 levels deep just to store an
   * unsigned int! */
  struct ftpinfo ftp = { FTPUSER, FTPPASS, "",  { { { 0 } } } , 21, 0};
#else
  struct ftpinfo ftp = { FTPUSER, FTPPASS, "", { 0 }, 21, 0};
#endif
  struct hostent *target = NULL;
  char **fakeargv;
  Target *currenths;
  vector<Target *> Targets;
  char *portlist = NULL; /* Ports list specified by user */
  int sourceaddrwarning = 0; /* Have we warned them yet about unguessable
                                source addresses? */
  unsigned int ideal_scan_group_sz = 0;
  char hostname[MAXHOSTNAMELEN + 1] = "";
  const char *spoofmac = NULL;
  time_t timep;
  char mytime[128];
  char tbuf[128];
  char errstr[256];
  struct sockaddr_storage ss;
  size_t sslen;
  int option_index;
  bool iflist = false;

  // Pre-specified timing parameters.
  // These are stored here during the parsing of the arguments so that we can
  // set the defaults specified by any timing template options (-T2, etc) BEFORE
  // any of these. In other words, these always take precedence over the templates.
  int pre_max_parallelism=-1, pre_scan_delay=-1, pre_max_scan_delay=-1;
  int pre_init_rtt_timeout=-1, pre_min_rtt_timeout=-1, pre_max_rtt_timeout=-1;
  int pre_max_retries=-1;
  long pre_host_timeout=-1;

  struct option long_options[] =
    {
      {"version", no_argument, 0, 'V'},
      {"verbose", no_argument, 0, 'v'},
      {"datadir", required_argument, 0, 0},
      {"servicedb", required_argument, 0, 0},
      {"versiondb", required_argument, 0, 0},
      {"debug", optional_argument, 0, 'd'},
      {"help", no_argument, 0, 'h'},
      {"iflist", no_argument, 0, 0},
      {"release_memory", no_argument, 0, 0},
      {"release-memory", no_argument, 0, 0},
      {"nogcc", no_argument, 0, 0},
      {"max_os_tries", required_argument, 0, 0},
      {"max-os-tries", required_argument, 0, 0},
      {"max_parallelism", required_argument, 0, 'M'},
      {"max-parallelism", required_argument, 0, 'M'},
      {"min_parallelism", required_argument, 0, 0},
      {"min-parallelism", required_argument, 0, 0},
      {"timing", required_argument, 0, 'T'},
      {"max_rtt_timeout", required_argument, 0, 0},
      {"max-rtt-timeout", required_argument, 0, 0},
      {"min_rtt_timeout", required_argument, 0, 0},
      {"min-rtt-timeout", required_argument, 0, 0},
      {"initial_rtt_timeout", required_argument, 0, 0},
      {"initial-rtt-timeout", required_argument, 0, 0},
      {"excludefile", required_argument, 0, 0},
      {"exclude", required_argument, 0, 0},
      {"max_hostgroup", required_argument, 0, 0},
      {"max-hostgroup", required_argument, 0, 0},
      {"min_hostgroup", required_argument, 0, 0},
      {"min-hostgroup", required_argument, 0, 0},
      {"open", no_argument, 0, 0},
      {"scanflags", required_argument, 0, 0},
      {"defeat_rst_ratelimit", no_argument, 0, 0},
      {"defeat-rst-ratelimit", no_argument, 0, 0},
      {"host_timeout", required_argument, 0, 0},
      {"host-timeout", required_argument, 0, 0},
      {"scan_delay", required_argument, 0, 0},
      {"scan-delay", required_argument, 0, 0},
      {"max_scan_delay", required_argument, 0, 0},
      {"max-scan-delay", required_argument, 0, 0},
      {"max_retries", required_argument, 0, 0},
      {"max-retries", required_argument, 0, 0},
      {"oA", required_argument, 0, 0},
      {"oN", required_argument, 0, 0},
      {"oM", required_argument, 0, 0},
      {"oG", required_argument, 0, 0},
      {"oS", required_argument, 0, 0},
      {"oH", required_argument, 0, 0},
      {"oX", required_argument, 0, 0},
      {"iL", required_argument, 0, 'i'},
      {"iR", required_argument, 0, 0},
      {"sI", required_argument, 0, 0},
      {"source_port", required_argument, 0, 'g'},
      {"source-port", required_argument, 0, 'g'},
      {"randomize_hosts", no_argument, 0, 0},
      {"randomize-hosts", no_argument, 0, 0},
      {"osscan_limit", no_argument, 0, 0}, /* skip OSScan if no open ports */
      {"osscan-limit", no_argument, 0, 0}, /* skip OSScan if no open ports */
      {"osscan_guess", no_argument, 0, 0}, /* More guessing flexability */
      {"osscan-guess", no_argument, 0, 0}, /* More guessing flexability */
      {"fuzzy", no_argument, 0, 0}, /* Alias for osscan_guess */
      {"packet_trace", no_argument, 0, 0}, /* Display all packets sent/rcv */
      {"packet-trace", no_argument, 0, 0}, /* Display all packets sent/rcv */
      {"version_trace", no_argument, 0, 0}, /* Display -sV related activity */
      {"version-trace", no_argument, 0, 0}, /* Display -sV related activity */
      {"data_length", required_argument, 0, 0},
      {"data-length", required_argument, 0, 0},
      {"send_eth", no_argument, 0, 0},
      {"send-eth", no_argument, 0, 0},
      {"send_ip", no_argument, 0, 0},
      {"send-ip", no_argument, 0, 0},
      {"stylesheet", required_argument, 0, 0},
      {"no_stylesheet", no_argument, 0, 0},
      {"no-stylesheet", no_argument, 0, 0},
      {"webxml", no_argument, 0, 0},
      {"rH", no_argument, 0, 0},
      {"vv", no_argument, 0, 0},
      {"ff", no_argument, 0, 0},
      {"privileged", no_argument, 0, 0},
      {"unprivileged", no_argument, 0, 0},
      {"mtu", required_argument, 0, 0},
      {"append_output", no_argument, 0, 0},
      {"append-output", no_argument, 0, 0},
      {"noninteractive", no_argument, 0, 0},
      {"spoof_mac", required_argument, 0, 0},
      {"spoof-mac", required_argument, 0, 0},
      {"thc", no_argument, 0, 0},
      {"badsum", no_argument, 0, 0},
      {"ttl", required_argument, 0, 0}, /* Time to live */
      {"traceroute", no_argument, 0, 0},
      {"reason", no_argument, 0, 0},
      {"allports", no_argument, 0, 0},
      {"version_intensity", required_argument, 0, 0},
      {"version-intensity", required_argument, 0, 0},
      {"version_light", no_argument, 0, 0},
      {"version-light", no_argument, 0, 0},
      {"version_all", no_argument, 0, 0},
      {"version-all", no_argument, 0, 0},
      {"system_dns", no_argument, 0, 0},
      {"system-dns", no_argument, 0, 0},
      {"log_errors", no_argument, 0, 0},
      {"log-errors", no_argument, 0, 0},
      {"dns_servers", required_argument, 0, 0},
      {"dns-servers", required_argument, 0, 0},
      {"port-ratio", required_argument, 0, 0},
      {"port_ratio", required_argument, 0, 0},
      {"top-ports", required_argument, 0, 0},
      {"top_ports", required_argument, 0, 0},
#ifndef NOLUA
      {"script", required_argument, 0, 0},
      {"script-trace", no_argument, 0, 0},
      {"script_trace", no_argument, 0, 0},
      {"script-updatedb", no_argument, 0, 0},
      {"script_updatedb", no_argument, 0, 0},
      {"script-args",required_argument,0,0},
      {"script_args",required_argument,0,0},
      {"script-help",required_argument,0,0},
      {"script_help",required_argument,0,0},
#endif
      {"ip_options", required_argument, 0, 0},
      {"ip-options", required_argument, 0, 0},
      {"min_rate", required_argument, 0, 0},
      {"min-rate", required_argument, 0, 0},
      {"max_rate", required_argument, 0, 0},
      {"max-rate", required_argument, 0, 0},
      {"adler32", no_argument, 0, 0},
      {"stats_every", required_argument, 0, 0},
      {"stats-every", required_argument, 0, 0},
      {0, 0, 0, 0}
    };

  /* argv faking silliness */
  fakeargv = (char **) safe_malloc(sizeof(char *) * (argc + 1));
  for(i=0; i < argc; i++) {
    fakeargv[i] = strdup(argv[i]);
  }
  fakeargv[argc] = NULL;

  if (argc < 2 ) printusage(argv[0], -1);

  Targets.reserve(100);
#ifdef WIN32
  win_pre_init();
#endif

  now = time(NULL);
  tm = localtime(&now);

  /* OK, lets parse these args! */
  optind = 1; /* so it can be called multiple times */
  while((arg = getopt_long_only(argc,fakeargv,"6Ab:D:d::e:Ffg:hIi:M:m:nO::o:P:p:qRrS:s:T:Vv::", long_options, &option_index)) != EOF) {
    switch(arg) {
    case 0:
#ifndef NOLUA
      if (strcmp(long_options[option_index].name, "script") == 0) {
              o.script = 1;
              o.chooseScripts(optarg);
      } else if (optcmp(long_options[option_index].name,"script-args")==0){
              o.scriptargs=strdup(optarg);
      } else if (optcmp(long_options[option_index].name, "script-trace") == 0) {
              o.scripttrace = 1;
      } else if (optcmp(long_options[option_index].name, "script-updatedb") == 0){
              o.scriptupdatedb = 1;
      } else if (optcmp(long_options[option_index].name, "script-help") == 0){
              o.scripthelp = true;
              o.chooseScripts(optarg);
      } else
#endif
      if (optcmp(long_options[option_index].name, "max-os-tries") == 0) {
        l = atoi(optarg);
        if (l < 1 || l > 50)
          fatal("Bogus --max-os-tries argument specified, must be between 1 and 50 (inclusive)");
        o.setMaxOSTries(l);
      } else if (optcmp(long_options[option_index].name, "max-rtt-timeout") == 0) {
        l = tval2msecs(optarg);
        if (l < 5)
          fatal("Bogus --max-rtt-timeout argument specified, must be at least 5ms");
        if (l >= 50 * 1000 && tval_unit(optarg) == NULL)
          fatal("Since April 2010, the default unit for --max-rtt-timeout is seconds, so your time of \"%s\" is %g seconds. Use \"%sms\" for %g milliseconds.", optarg, l / 1000.0, optarg, l / 1000.0);
        if (l < 20)
          error("WARNING: You specified a round-trip time timeout (%ld ms) that is EXTRAORDINARILY SMALL.  Accuracy may suffer.", l);
        pre_max_rtt_timeout = l;
      } else if (optcmp(long_options[option_index].name, "min-rtt-timeout") == 0) {
        l = tval2msecs(optarg);
        if (l < 0)
          fatal("Bogus --min-rtt-timeout argument specified");
        if (l >= 50 * 1000 && tval_unit(optarg) == NULL)
          fatal("Since April 2010, the default unit for --min-rtt-timeout is seconds, so your time of \"%s\" is %g seconds. Use \"%sms\" for %g milliseconds.", optarg, l / 1000.0, optarg, l / 1000.0);
        pre_min_rtt_timeout = l;
      } else if (optcmp(long_options[option_index].name, "initial-rtt-timeout") == 0) {
        l = tval2msecs(optarg);
        if (l <= 0)
          fatal("Bogus --initial-rtt-timeout argument specified.  Must be positive");
        if (l >= 50 * 1000 && tval_unit(optarg) == NULL)
          fatal("Since April 2010, the default unit for --initial-rtt-timeout is seconds, so your time of \"%s\" is %g seconds. Use \"%sms\" for %g milliseconds.", optarg, l / 1000.0, optarg, l / 1000.0);
        pre_init_rtt_timeout = l;
      } else if (strcmp(long_options[option_index].name, "excludefile") == 0) {
        if (exclude_spec)
          fatal("--excludefile and --exclude options are mutually exclusive.");
        excludefd = fopen(optarg, "r");
        if (!excludefd) {
          fatal("Failed to open exclude file %s for reading", optarg);
        }
      } else if (strcmp(long_options[option_index].name, "exclude") == 0) {
        if (excludefd)
          fatal("--excludefile and --exclude options are mutually exclusive.");
        exclude_spec = strdup(optarg);
      } else if (optcmp(long_options[option_index].name, "max-hostgroup") == 0) {
        o.setMaxHostGroupSz(atoi(optarg));
      } else if (optcmp(long_options[option_index].name, "min-hostgroup") == 0) {
        o.setMinHostGroupSz(atoi(optarg));
        if (atoi(optarg) > 100)
          error("Warning: You specified a highly aggressive --min-hostgroup.");
      } else if (strcmp(long_options[option_index].name, "open") == 0) {
        o.setOpenOnly(true);
      } else if (strcmp(long_options[option_index].name, "scanflags") == 0) {
        o.scanflags = parse_scanflags(optarg);
        if (o.scanflags < 0) {
          fatal("--scanflags option must be a number between 0 and 255 (inclusive) or a string like \"URGPSHFIN\".");
        }
      } else if (strcmp(long_options[option_index].name, "iflist") == 0 ) {
        iflist = true;
      } else if (strcmp(long_options[option_index].name, "nogcc") == 0 ) {
          o.nogcc = 1;
      } else if (optcmp(long_options[option_index].name, "release-memory") == 0 ) {
        o.release_memory = true;
      } else if (optcmp(long_options[option_index].name, "min-parallelism") == 0 ) {
        o.min_parallelism = atoi(optarg);
        if (o.min_parallelism < 1) fatal("Argument to --min-parallelism must be at least 1!");
        if (o.min_parallelism > 100) {
          error("Warning: Your --min-parallelism option is pretty high!  This can hurt reliability.");
        }
      } else if (optcmp(long_options[option_index].name, "host-timeout") == 0) {
        l = tval2msecs(optarg);
        if (l <= 0)
          fatal("Bogus --host-timeout argument specified");
        if (l >= 10000 * 1000 && tval_unit(optarg) == NULL)
          fatal("Since April 2010, the default unit for --host-timeout is seconds, so your time of \"%s\" is %.1f hours. If this is what you want, use \"%ss\".", optarg, l / 1000.0 / 60 / 60, optarg);
        pre_host_timeout = l;
      } else if (strcmp(long_options[option_index].name, "ttl") == 0) {
        o.ttl = atoi(optarg);
        if (o.ttl < 0 || o.ttl > 255) {
          fatal("ttl option must be a number between 0 and 255 (inclusive)");
        }
      } else if (strcmp(long_options[option_index].name, "datadir") == 0) {
        o.datadir = strdup(optarg);
      } else if (strcmp(long_options[option_index].name, "servicedb") == 0) {
        o.requested_data_files["nmap-services"] = optarg;
        o.fastscan++;
      } else if (strcmp(long_options[option_index].name, "versiondb") == 0) {
        o.requested_data_files["nmap-service-probes"] = optarg;
      } else if (optcmp(long_options[option_index].name, "append-output") == 0) {
        o.append_output = 1;
      } else if (strcmp(long_options[option_index].name, "noninteractive") == 0) {
        o.noninteractive = true;
      } else if (optcmp(long_options[option_index].name, "spoof-mac") == 0) {
        /* I need to deal with this later, once I'm sure that I have output
           files set up, --datadir, etc. */
        spoofmac = optarg;
      } else if (strcmp(long_options[option_index].name, "allports") == 0) {
        o.override_excludeports = 1;
      } else if (optcmp(long_options[option_index].name, "version-intensity") == 0) {
        o.version_intensity = atoi(optarg);
        if (o.version_intensity < 0 || o.version_intensity > 9)
                fatal("version-intensity must be between 0 and 9");
      } else if (optcmp(long_options[option_index].name, "version-light") == 0) {
        o.version_intensity = 2;
      } else if (optcmp(long_options[option_index].name, "version-all") == 0) {
        o.version_intensity = 9;
      } else if (optcmp(long_options[option_index].name, "scan-delay") == 0) {
        l = tval2msecs(optarg);
        if (l < 0)
          fatal("Bogus --scan-delay argument specified.");
        if (l >= 100 * 1000 && tval_unit(optarg) == NULL)
          fatal("Since April 2010, the default unit for --scan-delay is seconds, so your time of \"%s\" is %.1f minutes. Use \"%sms\" for %g milliseconds.", optarg, l / 1000.0 / 60, optarg, l / 1000.0);
        pre_scan_delay = l;
      } else if (optcmp(long_options[option_index].name, "defeat-rst-ratelimit") == 0) {
        o.defeat_rst_ratelimit = 1;
      } else if (optcmp(long_options[option_index].name, "max-scan-delay") == 0) {
        l = tval2msecs(optarg);
        if (l < 0)
          fatal("Bogus --max-scan-delay argument specified.");
        if (l >= 100 * 1000 && tval_unit(optarg) == NULL)
          fatal("Since April 2010, the default unit for --max-scan-delay is seconds, so your time of \"%s\" is %.1f minutes. If this is what you want, use \"%ss\".", optarg, l / 1000.0 / 60, optarg);
        pre_max_scan_delay = l;
      } else if (optcmp(long_options[option_index].name, "max-retries") == 0) {
        pre_max_retries = atoi(optarg);
        if (pre_max_retries < 0)
          fatal("max-retries must be positive");
      } else if (optcmp(long_options[option_index].name, "randomize-hosts") == 0
                 || strcmp(long_options[option_index].name, "rH") == 0) {
        o.randomize_hosts = 1;
        o.ping_group_sz = PING_GROUP_SZ * 4;
      } else if (optcmp(long_options[option_index].name, "osscan-limit")  == 0) {
        o.osscan_limit = 1;
      } else if (optcmp(long_options[option_index].name, "osscan-guess")  == 0
                 || strcmp(long_options[option_index].name, "fuzzy") == 0) {
        o.osscan_guess = 1;
      } else if (optcmp(long_options[option_index].name, "packet-trace") == 0) {
        o.setPacketTrace(true);
#ifndef NOLUA
        o.scripttrace = 1;
#endif
      } else if (optcmp(long_options[option_index].name, "version-trace") == 0) {
        o.setVersionTrace(true);
        o.debugging++;
      } else if (optcmp(long_options[option_index].name, "data-length") == 0) {
        o.extra_payload_length = (int)strtol(optarg, NULL, 10);
        if (o.extra_payload_length < 0 || o.extra_payload_length > MAX_PAYLOAD_ALLOWED)
          fatal("data-length must be between 0 and %d", MAX_PAYLOAD_ALLOWED);
        if (o.extra_payload_length > 1400 ) /* 1500 - IP with opts - TCP with opts. */
          error("WARNING: Payloads bigger than 1400 bytes may not be sent successfully.");
        o.extra_payload = (char *) safe_malloc(MAX(o.extra_payload_length, 1));
        get_random_bytes(o.extra_payload, o.extra_payload_length);
      } else if (optcmp(long_options[option_index].name, "send-eth") == 0) {
        o.sendpref = PACKET_SEND_ETH_STRONG;
      } else if (optcmp(long_options[option_index].name, "send-ip") == 0) {
        o.sendpref = PACKET_SEND_IP_STRONG;
      } else if (strcmp(long_options[option_index].name, "stylesheet") == 0) {
        o.setXSLStyleSheet(optarg);
      } else if (optcmp(long_options[option_index].name, "no-stylesheet") == 0) {
        o.setXSLStyleSheet(NULL);
      } else if (optcmp(long_options[option_index].name, "system-dns") == 0) {
        o.mass_dns = false;
      } else if (optcmp(long_options[option_index].name, "dns-servers") == 0) {
        o.dns_servers = strdup(optarg);
      } else if (optcmp(long_options[option_index].name, "log-errors") == 0) {
        o.log_errors = 1;
      } else if (strcmp(long_options[option_index].name, "webxml") == 0) {
        o.setXSLStyleSheet("http://nmap.org/svn/docs/nmap.xsl");
      } else if (strcmp(long_options[option_index].name, "oN") == 0) {
        normalfilename = logfilename(optarg, tm);
      } else if (strcmp(long_options[option_index].name, "oG") == 0 ||
                 strcmp(long_options[option_index].name, "oM") == 0) {
        machinefilename = logfilename(optarg, tm);
      } else if (strcmp(long_options[option_index].name, "oS") == 0) {
        kiddiefilename = logfilename(optarg, tm);
      } else if (strcmp(long_options[option_index].name, "oH") == 0) {
        fatal("HTML output is not directly supported, though Nmap includes an XSL for transforming XML output into HTML.  See the man page.");
      } else if (strcmp(long_options[option_index].name, "oX") == 0) {
        xmlfilename = logfilename(optarg, tm);
      } else if (strcmp(long_options[option_index].name, "oA") == 0) {
        char buf[MAXPATHLEN];
        Snprintf(buf, sizeof(buf), "%s.nmap", logfilename(optarg, tm));
        normalfilename = strdup(buf);
        Snprintf(buf, sizeof(buf), "%s.gnmap", logfilename(optarg, tm));
        machinefilename = strdup(buf);
        Snprintf(buf, sizeof(buf), "%s.xml", logfilename(optarg, tm));
        xmlfilename = strdup(buf);
      } else if (strcmp(long_options[option_index].name, "thc") == 0) {
        log_write(LOG_STDOUT, "!!Greets to Van Hauser, Plasmoid, Skyper and the rest of THC!!\n");
        exit(0);
      } else if (strcmp(long_options[option_index].name, "badsum") == 0) {
        o.badsum = 1;
      } else if (strcmp(long_options[option_index].name, "iR") == 0) {
        o.generate_random_ips = 1;
        o.max_ips_to_scan = strtoul(optarg, &endptr, 10);
        if (*endptr != '\0') {
          fatal("ERROR: -iR argument must be the maximum number of random IPs you wish to scan (use 0 for unlimited)");
        }
      } else if (strcmp(long_options[option_index].name, "sI") == 0) {
        o.idlescan = 1;
        idleProxy = optarg;
      } else if (strcmp(long_options[option_index].name, "vv") == 0) {
        /* Compatability hack ... ugly */
        o.verbose += 2;
      } else if (strcmp(long_options[option_index].name, "ff") == 0) {
        o.fragscan += 16;
      } else if (strcmp(long_options[option_index].name, "privileged") == 0) {
        o.isr00t = 1;
      } else if (strcmp(long_options[option_index].name, "unprivileged") == 0) {
        o.isr00t = 0;
      } else if (strcmp(long_options[option_index].name, "mtu") == 0) {
        o.fragscan = atoi(optarg);
        if (o.fragscan <= 0 || o.fragscan % 8 != 0)
            fatal("Data payload MTU must be >0 and multiple of 8");
      } else if (optcmp(long_options[option_index].name, "port-ratio") == 0) {
        char *ptr;
        o.topportlevel = strtod(optarg, &ptr);
        if (!ptr || o.topportlevel < 0 || o.topportlevel >= 1)
          fatal("--port-ratio should be between [0 and 1)");
      } else if (optcmp(long_options[option_index].name, "top-ports") == 0) {
        char *ptr;
        o.topportlevel = strtod(optarg, &ptr);
        if (!ptr || o.topportlevel < 1 || ((double)((int)o.topportlevel)) != o.topportlevel)
          fatal("--top-ports should be an integer 1 or greater");
      } else if (optcmp(long_options[option_index].name, "ip-options") == 0){
        o.ipoptions    = (u8*) safe_malloc(4*10+1);
        if( (o.ipoptionslen=parse_ip_options(optarg, o.ipoptions, 4*10+1, &o.ipopt_firsthop, &o.ipopt_lasthop, errstr, sizeof(errstr)))==OP_FAILURE )
            fatal("%s", errstr);
        if(o.ipoptionslen > 4*10)
          fatal("Ip options can't be more than 40 bytes long");
        if(o.ipoptionslen %4 != 0)
          fatal("Ip options must be multiple of 4 (read length is %i bytes)", o.ipoptionslen);
      } else if(strcmp(long_options[option_index].name, "traceroute") == 0) {
        o.traceroute = true;
      } else if(strcmp(long_options[option_index].name, "reason") == 0) {
        o.reason = true;
      } else if(optcmp(long_options[option_index].name, "min-rate") == 0) {
        if (sscanf(optarg, "%f", &o.min_packet_send_rate) != 1 || o.min_packet_send_rate <= 0.0)
          fatal("Argument to --min-rate must be a positive floating-point number");
      } else if(optcmp(long_options[option_index].name, "max-rate") == 0) {
        if (sscanf(optarg, "%f", &o.max_packet_send_rate) != 1 || o.max_packet_send_rate <= 0.0)
          fatal("Argument to --max-rate must be a positive floating-point number");
      } else if (optcmp(long_options[option_index].name, "adler32") == 0) {
        o.adler32 = true;
      } else if(optcmp(long_options[option_index].name, "stats-every") == 0) {
        d = tval2secs(optarg);
        if (d < 0)
          fatal("Argument to --stats-every cannot be negative.");
        o.stats_interval = d;
      } else {
        fatal("Unknown long option (%s) given@#!$#$", long_options[option_index].name);
      }
      break;
    case '6':
#if !HAVE_IPV6
      fatal("I am afraid IPv6 is not available because your host doesn't support it or you chose to compile Nmap w/o IPv6 support.");
#else
      o.setaf(AF_INET6);
#endif /* !HAVE_IPV6 */
      break;
    case 'A':
      o.servicescan = true;
#ifndef NOLUA
      o.script = 1;
#endif
      if (o.isr00t) {
        o.osscan++;
        o.traceroute = true;
      }
      break;
    case 'b':
      o.bouncescan++;
      if (parse_bounce_argument(&ftp, optarg) < 0 ) {
        error("Your argument to -b is b0rked. Use the normal url style:  user:pass@server:port or just use server and use default anon login\n  Use -h for help");
      }
      break;
    case 'D':
      p = optarg;
      do {
        q = strchr(p, ',');
        if (q) *q = '\0';
        if (!strcasecmp(p, "me")) {
          if (o.decoyturn != -1)
            fatal("Can only use 'ME' as a decoy once.\n");
          o.decoyturn = o.numdecoys++;
        } else if (!strcasecmp(p, "rnd") || !strncasecmp(p, "rnd:", 4)) {
          int i = 1;

          /* 'rnd:' is allowed and just gives them one */
          if (strlen(p) > 4)
            i = atoi(&p[4]);

          if (i < 1)
            fatal("Bad 'rnd' decoy \"%s\"", p);

          if (o.numdecoys + i >= MAX_DECOYS - 1)
            fatal("You are only allowed %d decoys (if you need more redefine MAX_DECOYS in nmap.h)", MAX_DECOYS);

          while (i--) {
            do {
              o.decoys[o.numdecoys].s_addr = get_random_u32();
            } while (ip_is_reserved(&o.decoys[o.numdecoys]));
            o.numdecoys++;
          }
        } else {
          if (o.numdecoys >= MAX_DECOYS -1)
            fatal("You are only allowed %d decoys (if you need more redefine MAX_DECOYS in nmap.h)", MAX_DECOYS);
            
          /* Try to resolve it */
          struct sockaddr_in decoytemp;
          size_t decoytemplen=sizeof(struct sockaddr_in);          
          if( resolve(p, 0, 0, (sockaddr_storage*)&decoytemp, &decoytemplen, AF_INET) == 1 ){
            o.decoys[o.numdecoys]=decoytemp.sin_addr;
            o.numdecoys++;
          } else {
            fatal("Failed to resolve decoy host: %s (must be hostname or IP address)", p);
          }
        }
        if (q) {
          *q = ',';
          p = q+1;
        }
      } while(q);
      break;
    case 'd':
      if (optarg && isdigit(optarg[0])) {
        o.debugging = o.verbose = atoi(optarg);
      } else {
        const char *p;
        o.debugging++;
        o.verbose++;
        for (p = optarg != NULL ? optarg : ""; *p == 'd'; p++) {
          o.debugging++;
          o.verbose++;
        }
        if (*p != '\0')
          fatal("Invalid argument to -d: \"%s\".", optarg);
      }
      o.reason = true;
      break;
    case 'e':
      Strncpy(o.device, optarg, sizeof(o.device)); break;
    case 'F': o.fastscan++; break;
    case 'f': o.fragscan += 8; break;
    case 'g':
      o.magic_port = atoi(optarg);
      o.magic_port_set = 1;
      if (o.magic_port == 0) error("WARNING: a source port of zero may not work on all systems.");
      break;
    case 'h': printusage(argv[0], 0); break;
    case '?': printusage(argv[0], -1); break;
    case 'I':
      error("WARNING: identscan (-I) no longer supported.  Ignoring -I");
      break;
      // o.identscan++; break;
    case 'i':
      if (inputfd) {
        fatal("Only one input filename allowed");
      }
      if (!strcmp(optarg, "-")) {
        inputfd = stdin;
      } else {
        inputfd = fopen(optarg, "r");
        if (!inputfd) {
          fatal("Failed to open input file %s for reading", optarg);
        }
      }
      break;
    case 'M':
      pre_max_parallelism = atoi(optarg);
      if (pre_max_parallelism < 1)
        fatal("Argument to -M must be at least 1!");
      if (pre_max_parallelism > 900)
        error("Warning: Your max-parallelism (-M) option is extraordinarily high, which can hurt reliability");
      break;
    case 'm':
      machinefilename = logfilename(optarg, tm);
      break;
    case 'n': o.noresolve++; break;
    case 'O':
      if (!optarg || *optarg == '2')
        o.osscan++;
      else if (*optarg == '1')
        fatal("First-generation OS detection (-O1) is no longer supported. Use -O instead.");
      else
        fatal("Unknown argument to -O.");
      break;
    case 'o':
      normalfilename = logfilename(optarg, tm);
      break;
    case 'P':
      if (*optarg == '\0' || *optarg == 'I' || *optarg == 'E')
        o.pingtype |= PINGTYPE_ICMP_PING;
      else if (*optarg == 'M')
        o.pingtype |= PINGTYPE_ICMP_MASK;
      else if (*optarg == 'P')
        o.pingtype |= PINGTYPE_ICMP_TS;
      else if (*optarg == 'n' || *optarg == '0' || *optarg == 'N' || *optarg == 'D')
        o.pingtype = PINGTYPE_NONE;
      else if (*optarg == 'R')
        o.pingtype |= PINGTYPE_ARP;
      else if (*optarg == 'S') {
        if (ports.syn_ping_count > 0)
          fatal("Only one -PS option is allowed. Combine port ranges with commas.");
        o.pingtype |= (PINGTYPE_TCP|PINGTYPE_TCP_USE_SYN);
        if (*(optarg + 1) != '\0') {
          getpts_simple(optarg + 1, SCAN_TCP_PORT, &ports.syn_ping_ports, &ports.syn_ping_count);
          if (ports.syn_ping_count <= 0)
            fatal("Bogus argument to -PS: %s", optarg + 1);
        } else {
          getpts_simple(DEFAULT_TCP_PROBE_PORT_SPEC, SCAN_TCP_PORT, &ports.syn_ping_ports, &ports.syn_ping_count);
          assert(ports.syn_ping_count > 0);
        }
      }
      else if (*optarg == 'T' || *optarg == 'A') {
        if (ports.ack_ping_count > 0)
          fatal("Only one -PB, -PA, or -PT option is allowed. Combine port ranges with commas.");
        /* validate_scan_lists takes case of changing this to
           to SYN if not root or if IPv6. */
        o.pingtype |= (PINGTYPE_TCP|PINGTYPE_TCP_USE_ACK);
        if (*(optarg + 1) != '\0') {
          getpts_simple(optarg + 1, SCAN_TCP_PORT, &ports.ack_ping_ports, &ports.ack_ping_count);
          if (ports.ack_ping_count <= 0)
            fatal("Bogus argument to -PA: %s", optarg + 1);
        } else {
          getpts_simple(DEFAULT_TCP_PROBE_PORT_SPEC, SCAN_TCP_PORT, &ports.ack_ping_ports, &ports.ack_ping_count);
          assert(ports.ack_ping_count > 0);
        }
      }
      else if (*optarg == 'U') {
        if (ports.udp_ping_count > 0)
          fatal("Only one -PU option is allowed. Combine port ranges with commas.");
        o.pingtype |= (PINGTYPE_UDP);
        if (*(optarg + 1) != '\0') {
          getpts_simple(optarg + 1, SCAN_UDP_PORT, &ports.udp_ping_ports, &ports.udp_ping_count);
          if (ports.udp_ping_count <= 0)
            fatal("Bogus argument to -PU: %s", optarg + 1);
        } else {
          getpts_simple(DEFAULT_UDP_PROBE_PORT_SPEC, SCAN_UDP_PORT, &ports.udp_ping_ports, &ports.udp_ping_count);
          assert(ports.udp_ping_count > 0);
        }
      }
      else if (*optarg == 'Y') {
        if (ports.sctp_ping_count > 0)
          fatal("Only one -PY option is allowed. Combine port ranges with commas.");
        o.pingtype |= (PINGTYPE_SCTP_INIT);
        if (*(optarg + 1) != '\0') {
          getpts_simple(optarg + 1, SCAN_SCTP_PORT, &ports.sctp_ping_ports, &ports.sctp_ping_count);
          if (ports.sctp_ping_count <= 0)
            fatal("Bogus argument to -PY: %s", optarg + 1);
        } else {
          getpts_simple(DEFAULT_SCTP_PROBE_PORT_SPEC, SCAN_SCTP_PORT, &ports.sctp_ping_ports, &ports.sctp_ping_count);
          assert(ports.sctp_ping_count > 0);
        }
      }
      else if (*optarg == 'B') {
        if (ports.ack_ping_count > 0)
          fatal("Only one -PB, -PA, or -PT option is allowed. Combine port ranges with commas.");
        o.pingtype = DEFAULT_PING_TYPES;
        if (*(optarg + 1) != '\0') {
          getpts_simple(optarg + 1, SCAN_TCP_PORT, &ports.ack_ping_ports, &ports.ack_ping_count);
          if (ports.ack_ping_count <= 0)
            fatal("Bogus argument to -PB: %s", optarg + 1);
        } else {
          getpts_simple(DEFAULT_TCP_PROBE_PORT_SPEC, SCAN_TCP_PORT, &ports.ack_ping_ports, &ports.ack_ping_count);
          assert(ports.ack_ping_count > 0);
        }
      } else if (*optarg == 'O') {
        if (ports.proto_ping_count > 0)
          fatal("Only one -PO option is allowed. Combine protocol ranges with commas.");
        o.pingtype |= PINGTYPE_PROTO;
        if (*(optarg + 1) != '\0') {
          getpts_simple(optarg + 1, SCAN_PROTOCOLS, &ports.proto_ping_ports, &ports.proto_ping_count);
          if (ports.proto_ping_count <= 0)
            fatal("Bogus argument to -PO: %s", optarg + 1);
        } else {
          getpts_simple(DEFAULT_PROTO_PROBE_PORT_SPEC, SCAN_PROTOCOLS, &ports.proto_ping_ports, &ports.proto_ping_count);
          assert(ports.proto_ping_count > 0);
        }
      } else {
        fatal("Illegal Argument to -P, use -Pn, -PO, -PI, -PB, -PE, -PM, -PP, -PA, -PU, -PT, -PY, or -PT80 (or whatever number you want for the TCP probe destination port)");
      }
      break;
    case 'p':
      if (portlist)
        fatal("Only 1 -p option allowed, separate multiple ranges with commas.");
      portlist = strdup(optarg);
      break;
    case 'q': quashargv++; break;
    case 'R': o.resolve_all++; break;
    case 'r':
      randomize = 0;
      break;
    case 'S':
      if (o.spoofsource)
        fatal("You can only use the source option once!  Use -D <decoy1> -D <decoy2> etc. for decoys\n");
      if (resolve(optarg, 0, 0, &ss, &sslen, o.af()) == 0) {
        fatal("Failed to resolve/decode supposed %s source address %s. Note that if you are using IPv6, the -6 argument must come before -S", (o.af() == AF_INET)? "IPv4" : "IPv6", optarg);
      }
      o.setSourceSockAddr(&ss, sslen);
      o.spoofsource = 1;
      break;
    case 's':
      if (!*optarg) {
        error("An option is required for -s, most common are -sT (tcp scan), -sS (SYN scan), -sF (FIN scan), -sU (UDP scan) and -sn (Ping scan)");
        printusage(argv[0], -1);
      }
      p = optarg;
      while(*p) {
        switch(*p) {
        case 'n':
        case 'P':
          o.noportscan = 1;
          break;
        case 'A': o.ackscan = 1; break;
        case 'B':  fatal("No scan type 'B', did you mean bounce scan (-b)?"); break;
#ifndef NOLUA
        case 'C':  o.script = 1; break;
#endif
        case 'F':  o.finscan = 1; break;
        case 'L':  o.listscan = 1; o.noportscan = 1; o.pingtype = PINGTYPE_NONE; break;
        case 'M':  o.maimonscan = 1; break;
        case 'N':  o.nullscan = 1; break;
        case 'O':  o.ipprotscan = 1; break;
        /* Alias for -sV since March 2011. */
        case 'R':
          o.servicescan = 1;
          error("WARNING: -sR is now an alias for -sV and activates version detection as well as RPC scan.");
          break;
        case 'S':  o.synscan = 1; break;
        case 'T':  o.connectscan = 1; break;
        case 'U':  o.udpscan++; break;
        case 'V':  o.servicescan = 1; break;
        case 'W':  o.windowscan = 1; break;
        case 'X':  o.xmasscan++; break;
        case 'Y':  o.sctpinitscan = 1; break;
        case 'Z':  o.sctpcookieechoscan = 1; break;
        default:  error("Scantype %c not supported\n",*p); printusage(argv[0], -1); break;
        }
        p++;
      }
      break;
    case 'T':
      if (*optarg == '0' || (strcasecmp(optarg, "Paranoid") == 0)) {
        o.timing_level = 0;
        o.max_parallelism = 1;
        o.scan_delay = 300000;
        o.setInitialRttTimeout(300000);
      } else if (*optarg == '1' || (strcasecmp(optarg, "Sneaky") == 0)) {
        o.timing_level = 1;
        o.max_parallelism = 1;
        o.scan_delay = 15000;
        o.setInitialRttTimeout(15000);
      } else if (*optarg == '2' || (strcasecmp(optarg, "Polite") == 0)) {
        o.timing_level = 2;
        o.max_parallelism = 1;
        o.scan_delay = 400;
      } else if (*optarg == '3' || (strcasecmp(optarg, "Normal") == 0)) {
      } else if (*optarg == '4' || (strcasecmp(optarg, "Aggressive") == 0)) {
        o.timing_level = 4;
        o.setMinRttTimeout(100);
        o.setMaxRttTimeout(1250);
        o.setInitialRttTimeout(500);
        o.setMaxTCPScanDelay(10);
        o.setMaxSCTPScanDelay(10);
        o.setMaxRetransmissions(6);
      } else if (*optarg == '5' || (strcasecmp(optarg, "Insane") == 0)) {
        o.timing_level = 5;
        o.setMinRttTimeout(50);
        o.setMaxRttTimeout(300);
        o.setInitialRttTimeout(250);
        o.host_timeout = 900000;
        o.setMaxTCPScanDelay(5);
        o.setMaxSCTPScanDelay(5);
        o.setMaxRetransmissions(2);
      } else {
        fatal("Unknown timing mode (-T argument).  Use either \"Paranoid\", \"Sneaky\", \"Polite\", \"Normal\", \"Aggressive\", \"Insane\" or a number from 0 (Paranoid) to 5 (Insane)");
      }
      break;
    case 'V':
      display_nmap_version();
      exit(0);
      break;
    case 'v':
      if (optarg && isdigit(optarg[0])) {
        o.verbose = atoi(optarg);
      } else {
        const char *p;
        o.verbose++;
        for (p = optarg != NULL ? optarg : ""; *p == 'v'; p++)
          o.verbose++;
        if (*p != '\0')
          fatal("Invalid argument to -v: \"%s\".", optarg);
      }
      break;
    }
  }

#ifdef WIN32
  win_init();
#endif

  tty_init(); // Put the keyboard in raw mode

  // After the arguments are fully processed we now make any of the timing
  // tweaks the user might've specified:
  if (pre_max_parallelism != -1) o.max_parallelism = pre_max_parallelism;
  if (pre_scan_delay != -1) {
    o.scan_delay = pre_scan_delay;
    if (o.scan_delay > o.maxTCPScanDelay()) o.setMaxTCPScanDelay(o.scan_delay);
    if (o.scan_delay > o.maxUDPScanDelay()) o.setMaxUDPScanDelay(o.scan_delay);
    if (o.scan_delay > o.maxSCTPScanDelay()) o.setMaxSCTPScanDelay(o.scan_delay);
    if (pre_max_parallelism != -1 || o.min_parallelism != 0)
      error("Warning: --min-parallelism and --max-parallelism are ignored with --scan-delay.");
  }
  if (pre_max_scan_delay != -1) {
    o.setMaxTCPScanDelay(pre_max_scan_delay);
    o.setMaxUDPScanDelay(pre_max_scan_delay);
    o.setMaxSCTPScanDelay(pre_max_scan_delay);
  }
  if (pre_init_rtt_timeout != -1) o.setInitialRttTimeout(pre_init_rtt_timeout);
  if (pre_min_rtt_timeout != -1) o.setMinRttTimeout(pre_min_rtt_timeout);
  if (pre_max_rtt_timeout != -1) o.setMaxRttTimeout(pre_max_rtt_timeout);
  if (pre_max_retries != -1) o.setMaxRetransmissions(pre_max_retries);
  if (pre_host_timeout != -1) o.host_timeout = pre_host_timeout;


  if (o.osscan)
    o.reference_FPs = parse_fingerprint_reference_file("nmap-os-db");

  validate_scan_lists(ports,o);
  o.ValidateOptions();

  // print ip options
  if ((o.debugging || o.packetTrace()) && o.ipoptionslen) {
    char buf[256]; // 256 > 5*40
    bintohexstr(buf, sizeof(buf), (char*) o.ipoptions, o.ipoptionslen);
    if (o.ipoptionslen >= 8)       // at least one ip address
      log_write(LOG_STDOUT, "Binary ip options to be send:\n%s", buf);
      log_write(LOG_STDOUT, "Parsed ip options to be send:\n%s\n",
        format_ip_options(o.ipoptions, o.ipoptionslen));
  }

  /* Open the log files, now that we know whether the user wants them appended
     or overwritten */
  if (normalfilename) {
    log_open(LOG_NORMAL, o.append_output, normalfilename);
    free(normalfilename);
  }
  if (machinefilename) {
    log_open(LOG_MACHINE, o.append_output, machinefilename);
    free(machinefilename);
  }
  if (kiddiefilename) {
    log_open(LOG_SKID, o.append_output, kiddiefilename);
    free(kiddiefilename);
  }
  if (xmlfilename) {
    log_open(LOG_XML, o.append_output, xmlfilename);
    free(xmlfilename);
  }

  // ISO 8601 date/time -- http://www.cl.cam.ac.uk/~mgk25/iso-time.html
  if (strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M %Z", tm) <= 0)
    fatal("Unable to properly format time");
  log_write(LOG_STDOUT|LOG_SKID, "\nStarting %s %s ( %s ) at %s\n", NMAP_NAME, NMAP_VERSION, NMAP_URL, tbuf);
  if (o.verbose) {
    if (tm->tm_mon == 8 && tm->tm_mday == 1) {
      log_write(LOG_STDOUT|LOG_SKID, "Happy %dth Birthday to Nmap, may it live to be %d!\n", tm->tm_year - 97, tm->tm_year + 3 );
    } else if (tm->tm_mon == 11 && tm->tm_mday == 25) {
      log_write(LOG_STDOUT|LOG_SKID, "Nmap wishes you a merry Christmas! Specify -sX for Xmas Scan (http://nmap.org/book/man-port-scanning-techniques.html).\n");
    } 
  }
  if (iflist) {
    print_iflist();
    exit(0);
  }

#ifndef NOLUA
  if (o.scripthelp) {
    /* Special-case open_nse for --script-help only. */
    open_nse();
    exit(0);
  }
#endif

#if HAVE_IPV6
  if(o.af() == AF_INET6 && o.traceroute)
     fatal("Traceroute does not support IPv6");
#endif
  if (o.traceroute && !o.isr00t)
    fatal("Traceroute has to be run as root");
  if (o.traceroute && (o.idlescan || o.connectscan))
    fatal("Traceroute does not support idle or connect scan");

  if ((o.noportscan) && (portlist || o.fastscan))
    fatal("You cannot use -F (fast scan) or -p (explicit port selection) when not doing a port scan");

  if (portlist && o.fastscan)
    fatal("You cannot use -F (fast scan) with -p (explicit port selection) but see --top-ports and --port-ratio to fast scan a range of ports");

  if (o.ipprotscan) {
    if (portlist)
      getpts(portlist, &ports);
    else
      getpts((char *) (o.fastscan ? "[P:0-]" : "0-"), &ports);  // Default protocols to scan
  } else if (!o.noportscan) {
    gettoppts(o.topportlevel, portlist, &ports);
  }

  if (portlist) {
    free(portlist);
    portlist = NULL;
  }

  // Uncomment the following line to use the common lisp port spec test suite
  //printf("port spec: (%d %d %d %d)\n", ports.tcp_count, ports.udp_count, ports.stcp_count, ports.prot_count); exit(0);

#ifdef WIN32
  if (o.sendpref & PACKET_SEND_IP) {
    error("WARNING: raw IP (rather than raw ethernet) packet sending attempted on Windows. This probably won't work.  Consider --send-eth next time.");
  }
#endif
  if (spoofmac) {
    u8 mac_data[6];
    int pos = 0; /* Next index of mac_data to fill in */
    char tmphex[3];
    /* A zero means set it all randomly.  Anything that is all digits
       or colons is treated as a prefix, with remaining characters for
       the 6-byte MAC (if any) chosen randomly.  Otherwise, it is
       treated as a vendor string for lookup in nmap-mac-prefixes */
    if (strcmp(spoofmac, "0") == 0) {
      pos = 0;
    } else {
      const char *p = spoofmac;
      while(*p) {
        if (*p == ':') p++;
        if (isxdigit((int) (unsigned char) *p) && isxdigit((int) (unsigned char) *(p+1))) {
          if (pos >= 6) fatal("Bogus --spoof-mac value encountered (%s) -- only up to 6 bytes permitted", spoofmac);
          tmphex[0] = *p; tmphex[1] = *(p+1); tmphex[2] = '\0';
          mac_data[pos] = (u8) strtol(tmphex, NULL, 16);
          pos++;
          p += 2;
        } else break;
      }
      if (*p) {
        /* Failed to parse it as a MAC prefix -- treating as a vendor substring instead */
        if (!MACCorp2Prefix(spoofmac, mac_data))
          fatal("Could not parse as a prefix nor find as a vendor substring the given --spoof-mac argument: %s.  If you are giving hex digits, there must be an even number of them.", spoofmac);
        pos = 3;
      }
    }
    if (pos < 6) {
      get_random_bytes(mac_data + pos, 6 - pos);
    }
    /* Got the new MAC! */
    const char *vend = MACPrefix2Corp(mac_data);
    log_write(LOG_PLAIN,
              "Spoofing MAC address %02X:%02X:%02X:%02X:%02X:%02X (%s)\n",
              mac_data[0], mac_data[1], mac_data[2], mac_data[3], mac_data[4],
              mac_data[5], vend? vend : "No registered vendor");
    o.setSpoofMACAddress(mac_data);

    /* If they want to spoof the MAC address, we should at least make
       some effort to actually send raw ethernet frames rather than IP
       packets (which would use the real IP */
    if (o.sendpref != PACKET_SEND_IP_STRONG)
      o.sendpref = PACKET_SEND_ETH_STRONG;
  }

  /* By now, we've got our port lists.  Give the user a warning if no
   * ports are specified for the type of scan being requested.  Other things
   * (such as OS ident scan) might break cause no ports were specified,  but
   * we've given our warning...
   */
  if ((o.TCPScan()) && ports.tcp_count == 0)
    error("WARNING: a TCP scan type was requested, but no tcp ports were specified.  Skipping this scan type.");
  if (o.SCTPScan() && ports.sctp_count == 0)
    error("WARNING: a SCTP scan type was requested, but no sctp ports were specified.  Skipping this scan type.");
  if (o.UDPScan() && ports.udp_count == 0)
    error("WARNING: UDP scan was requested, but no udp ports were specified.  Skipping this scan type.");
  if (o.ipprotscan && ports.prot_count == 0)
    error("WARNING: protocol scan was requested, but no protocols were specified to be scanned.  Skipping this scan type.");

  /* Set up our array of decoys! */
  if (o.decoyturn == -1) {
    o.decoyturn = (o.numdecoys == 0)?  0 : get_random_uint() % o.numdecoys;
    o.numdecoys++;
    for(i=o.numdecoys-1; i > o.decoyturn; i--)
      o.decoys[i] = o.decoys[i-1];
  }

  /* We need to find what interface to route through if:
   * --None have been specified AND
   * --We are root and doing tcp ping OR
   * --We are doing a raw sock scan and NOT pinging anyone */
  if (o.af() == AF_INET && o.v4sourceip() && !*o.device) {
    if (ipaddr2devname(o.device, o.v4sourceip()) != 0) {
      fatal("Could not figure out what device to send the packet out on with the source address you gave me!  If you are trying to sp00f your scan, this is normal, just give the -e eth0 or -e ppp0 or whatever.  Otherwise you can still use -e, but I find it kindof fishy.");
    }
  }

  if (o.af() == AF_INET && *o.device && !o.v4sourceip()) {
    struct sockaddr_in tmpsock;
    memset(&tmpsock, 0, sizeof(tmpsock));
    if (devname2ipaddr(o.device, &(tmpsock.sin_addr)) == -1) {
      fatal("I cannot figure out what source address to use for device %s, does it even exist?", o.device);
    }
    tmpsock.sin_family = AF_INET;
#if HAVE_SOCKADDR_SA_LEN
    tmpsock.sin_len = sizeof(tmpsock);
#endif
    o.setSourceSockAddr((struct sockaddr_storage *) &tmpsock, sizeof(tmpsock));
  }


  /* If he wants to bounce off of an FTP site, that site better damn well be reachable! */
  if (o.bouncescan) {
    if (!inet_pton(AF_INET, ftp.server_name, &ftp.server)) {
      if ((target = gethostbyname(ftp.server_name)))
        memcpy(&ftp.server, target->h_addr_list[0], 4);
      else {
        fatal("Failed to resolve FTP bounce proxy hostname/IP: %s",
              ftp.server_name);
      }
    } else if (o.verbose) {
      log_write(LOG_STDOUT, "Resolved FTP bounce attack proxy to %s (%s).\n",
                ftp.server_name, inet_ntoa(ftp.server));
    }
  }
  fflush(stdout);
  fflush(stderr);

  timep = time(NULL);

  /* Brief info in case they forget what was scanned */
  Strncpy(mytime, ctime(&timep), sizeof(mytime));
  chomp(mytime);
  char *xslfname = o.XSLStyleSheet();
  xml_start_document();
  if (xslfname) {
    xml_open_pi("xml-stylesheet");
    xml_attribute("href", "%s", xslfname);
    xml_attribute("type", "text/xsl");
    xml_close_pi();
    xml_newline();
  }

  std::string command;
  if (argc > 0)
    command += fakeargv[0];
  for (i = 1; i < argc; i++) {
    command += " ";
    command += fakeargv[i];
  }

  xml_start_comment();
  xml_write_escaped(" %s %s scan initiated %s as: %s ", NMAP_NAME, NMAP_VERSION, mytime, join_quoted(fakeargv, argc).c_str());
  xml_end_comment();
  xml_newline();

  log_write(LOG_NORMAL|LOG_MACHINE, "# ");
  log_write(LOG_NORMAL|LOG_MACHINE, "%s %s scan initiated %s as: ", NMAP_NAME, NMAP_VERSION, mytime);
  log_write(LOG_NORMAL|LOG_MACHINE, "%s", command.c_str());
  log_write(LOG_NORMAL|LOG_MACHINE, "\n");

  xml_open_start_tag("nmaprun");
  xml_attribute("scanner", "nmap");
  xml_attribute("args", "%s", join_quoted(fakeargv, argc).c_str());
  xml_attribute("start", "%lu", (unsigned long) timep);
  xml_attribute("startstr", "%s", mytime);
  xml_attribute("version", "%s", NMAP_VERSION);
  xml_attribute("xmloutputversion", "1.03");
  xml_close_start_tag();
  xml_newline();

  output_xml_scaninfo_records(&ports);

  xml_open_start_tag("verbose");
  xml_attribute("level", "%d", o.verbose);
  xml_close_empty_tag();
  xml_newline();
  xml_open_start_tag("debugging");
  xml_attribute("level", "%d", o.debugging);
  xml_close_empty_tag();
  xml_newline();

  /* Before we randomize the ports scanned, lets output them to machine
     parseable output */
  if (o.verbose)
    output_ports_to_machine_parseable_output(&ports, o.TCPScan(), o.UDPScan(), o.SCTPScan(), o.ipprotscan);

  /* more fakeargv junk, BTW malloc'ing extra space in argv[0] doesn't work */
  if (quashargv) {
    size_t fakeargvlen = strlen(FAKE_ARGV), argvlen = strlen(argv[0]);
    if (argvlen < fakeargvlen)
      fatal("If you want me to fake your argv, you need to call the program with a longer name.  Try the full pathname, or rename it fyodorssuperdedouperportscanner");
    strncpy(argv[0], FAKE_ARGV, fakeargvlen);
    memset(&argv[0][fakeargvlen], '\0', strlen(&argv[0][fakeargvlen]));
    for(i=1; i < argc; i++)
      memset(argv[i], '\0', strlen(argv[i]));
  }

#if defined(HAVE_SIGNAL) && defined(SIGPIPE)
  signal(SIGPIPE, SIG_IGN); /* ignore SIGPIPE so our program doesn't crash because
                               of it, but we really shouldn't get an unexpected
                               SIGPIPE */
#endif

  if (o.max_parallelism && (i = max_sd()) && i < o.max_parallelism) {
    error("WARNING:  Your specified max_parallel_sockets of %d, but your system says it might only give us %d.  Trying anyway", o.max_parallelism, i);
  }

  if (o.debugging > 1) log_write(LOG_STDOUT, "The max # of sockets we are using is: %d\n", o.max_parallelism);

  // At this point we should fully know our timing parameters
  if (o.debugging) {
    log_write(LOG_PLAIN, "--------------- Timing report ---------------\n");
    log_write(LOG_PLAIN, "  hostgroups: min %d, max %d\n", o.minHostGroupSz(), o.maxHostGroupSz());
    log_write(LOG_PLAIN, "  rtt-timeouts: init %d, min %d, max %d\n", o.initialRttTimeout(), o.minRttTimeout(), o.maxRttTimeout());
    log_write(LOG_PLAIN, "  max-scan-delay: TCP %d, UDP %d, SCTP %d\n", o.maxTCPScanDelay(), o.maxUDPScanDelay(), o.maxSCTPScanDelay());
    log_write(LOG_PLAIN, "  parallelism: min %d, max %d\n", o.min_parallelism, o.max_parallelism);
    log_write(LOG_PLAIN, "  max-retries: %d, host-timeout: %ld\n", o.getMaxRetransmissions(), o.host_timeout);
    log_write(LOG_PLAIN, "  min-rate: %g, max-rate: %g\n", o.min_packet_send_rate, o.max_packet_send_rate);
    log_write(LOG_PLAIN, "---------------------------------------------\n");
  }

  /* Before we randomize the ports scanned, we must initialize PortList class. */
  if (o.ipprotscan)
    PortList::initializePortMap(IPPROTO_IP,  ports.prots, ports.prot_count);
  if (o.TCPScan())
    PortList::initializePortMap(IPPROTO_TCP, ports.tcp_ports, ports.tcp_count);
  if (o.UDPScan())
    PortList::initializePortMap(IPPROTO_UDP, ports.udp_ports, ports.udp_count);
  if (o.SCTPScan())
    PortList::initializePortMap(IPPROTO_SCTP, ports.sctp_ports, ports.sctp_count);

  if  (randomize) {
    if (ports.tcp_count) {
      shortfry(ports.tcp_ports, ports.tcp_count);
      // move a few more common ports closer to the beginning to speed scan
      random_port_cheat(ports.tcp_ports, ports.tcp_count);
    }
    if (ports.udp_count)
      shortfry(ports.udp_ports, ports.udp_count);
    if (ports.sctp_count)
      shortfry(ports.sctp_ports, ports.sctp_count);
    if (ports.prot_count)
      shortfry(ports.prots, ports.prot_count);
  }

  /* lets load our exclude list */
  if (excludefd != NULL) {
    exclude_group = load_exclude_file(excludefd);
    fclose(excludefd);
  }
  if (exclude_spec != NULL) {
    /* Simultaneous --excludefile and --exclude are not supported. */
    assert(exclude_group == NULL);
    exclude_group = load_exclude_string(exclude_spec);
    free(exclude_spec);
  }

  if (exclude_group != NULL) {
    if (o.debugging > 3)
      dumpExclude(exclude_group);
  }

#ifndef NOLUA
  if (o.scriptupdatedb) {
    o.max_ips_to_scan = o.numhosts_scanned; // disable warnings?
  }
  if (o.servicescan)
    o.scriptversion = 1;
  if (o.scriptversion || o.script || o.scriptupdatedb)
    open_nse();

  /* Run the script pre-scanning phase */
  if (o.script) {
    new_targets = NewTargets::get();
    script_scan_results = get_script_scan_results_obj();
    script_scan(Targets, SCRIPT_PRE_SCAN);
    printscriptresults(script_scan_results, SCRIPT_PRE_SCAN);
    script_scan_results->clear();
  }
#endif

  /* Time to create a hostgroup state object filled with all the requested
     machines. The list is initially empty. It is refilled inside the loop
     whenever it is empty. */
  host_exp_group = (char **) safe_malloc(o.ping_group_sz * sizeof(char *));
  num_host_exp_groups = 0;

  hstate = new HostGroupState(o.ping_group_sz, o.randomize_hosts,
                  host_exp_group, num_host_exp_groups);

  do {
    ideal_scan_group_sz = determineScanGroupSize(o.numhosts_scanned, &ports);
    while(Targets.size() < ideal_scan_group_sz) {
      o.current_scantype = HOST_DISCOVERY;
      currenths = nexthost(hstate, exclude_group, &ports, o.pingtype);
      if (!currenths) {
        /* Try to refill with any remaining expressions */
        /* First free the old ones */
        for(i=0; i < num_host_exp_groups; i++)
          free(host_exp_group[i]);
        num_host_exp_groups = 0;
        /* Now grab any new expressions */
        while(num_host_exp_groups < o.ping_group_sz && 
          (!o.max_ips_to_scan || o.max_ips_to_scan > o.numhosts_scanned + (int) Targets.size() + num_host_exp_groups) &&
          (host_spec = grab_next_host_spec(inputfd, o.generate_random_ips, argc, fakeargv))) {
            // For purposes of random scan
            host_exp_group[num_host_exp_groups++] = strdup(host_spec);
        }
#ifndef NOLUA
        /* Add the new NSE discovered targets to the scan queue */
        if (o.script) {
          if (new_targets != NULL) {
            while (new_targets->get_queued() > 0 && num_host_exp_groups < o.ping_group_sz) {
              std::string target_spec = new_targets->read();
              if (target_spec.length())
                host_exp_group[num_host_exp_groups++] = strdup(target_spec.c_str());
            }

            if (o.debugging > 3)
              log_write(LOG_PLAIN,
                  "New targets in the scanned cache: %ld, pending ones: %ld.\n",
                  new_targets->get_scanned(), new_targets->get_queued());
          }
        }
#endif
        if (num_host_exp_groups == 0)
          break;
        delete hstate;
        hstate = new HostGroupState(o.ping_group_sz, o.randomize_hosts,host_exp_group,
                        num_host_exp_groups);
      
        /* Try one last time -- with new expressions */
        currenths = nexthost(hstate, exclude_group, &ports, o.pingtype);
        if (!currenths)
          break;
      }
    
      if (currenths->flags & HOST_UP && !o.listscan) 
        o.numhosts_up++;
    
      if ((o.noportscan && !o.traceroute
#ifndef NOLUA
      && !o.script
#endif
          ) || o.listscan) {
        /* We're done with the hosts */
        if (currenths->flags & HOST_UP || o.verbose) {
          xml_start_tag("host");
          write_host_header(currenths);
          printmacinfo(currenths);
          //  if (currenths->flags & HOST_UP)
          //  log_write(LOG_PLAIN,"\n");
          printtimes(currenths);
          xml_end_tag();
          xml_newline();
          log_flush_all();
        }
        delete currenths;
        o.numhosts_scanned++;
        continue;
      }
    
      if (o.spoofsource) {
        o.SourceSockAddr(&ss, &sslen);
        currenths->setSourceSockAddr(&ss, sslen);
      }
    
      /* I used to check that !currenths->weird_responses, but in some
         rare cases, such IPs CAN be port successfully scanned and even
         connected to */
      if (!(currenths->flags & HOST_UP)) {
        if (o.verbose && (!o.openOnly() || currenths->ports.hasOpenPorts())) {
          xml_start_tag("host");
          write_host_header(currenths);
          xml_end_tag();
          xml_newline();
        }
        delete currenths;
        o.numhosts_scanned++;
        continue;
      }

      if (o.af() == AF_INET && o.RawScan()) { 
        if (currenths->SourceSockAddr(NULL, NULL) != 0) {
          if (o.SourceSockAddr(&ss, &sslen) == 0) {
            currenths->setSourceSockAddr(&ss, sslen);
          } else {
            if (gethostname(myname, MAXHOSTNAMELEN) ||
                resolve(myname, 0, 0, &ss, &sslen, o.af()) == 0)
              fatal("Cannot get hostname!  Try using -S <my_IP_address> or -e <interface to scan through>\n"); 
        
            o.setSourceSockAddr(&ss, sslen);
            currenths->setSourceSockAddr(&ss, sslen);
            if (! sourceaddrwarning) {
              error("WARNING:  We could not determine for sure which interface to use, so we are guessing %s .  If this is wrong, use -S <my_IP_address>.",
                  inet_socktop(&ss));
                sourceaddrwarning = 1;
            }
          }
        }

        if (!currenths->deviceName())
          fatal("Do not have appropriate device name for target");

        /* Hosts in a group need to be somewhat homogeneous. Put this host in
           the next group if necessary. See target_needs_new_hostgroup for the
           details of when we need to split. */
        if (target_needs_new_hostgroup(Targets, currenths)) {
          returnhost(hstate);
          o.numhosts_up--;
          break;
        }
        o.decoys[o.decoyturn] = currenths->v4source();
      }
      Targets.push_back(currenths);
    }
    
    if (Targets.size() == 0)
      break; /* Couldn't find any more targets */
    
    // Set the variable for status printing
    o.numhosts_scanning = Targets.size();
    
    // Our source must be set in decoy list because nexthost() call can
    // change it (that issue really should be fixed when possible)
    if (o.af() == AF_INET && o.RawScan())
      o.decoys[o.decoyturn] = Targets[0]->v4source();
    
    /* I now have the group for scanning in the Targets vector */

    if (!o.noportscan) {
      // Ultra_scan sets o.scantype for us so we don't have to worry
      if (o.synscan)
        ultra_scan(Targets, &ports, SYN_SCAN);
      
      if (o.ackscan)
        ultra_scan(Targets, &ports, ACK_SCAN);
      
      if (o.windowscan)
        ultra_scan(Targets, &ports, WINDOW_SCAN);
      
      if (o.finscan)
        ultra_scan(Targets, &ports, FIN_SCAN);
      
      if (o.xmasscan)
        ultra_scan(Targets, &ports, XMAS_SCAN);
      
      if (o.nullscan)
        ultra_scan(Targets, &ports, NULL_SCAN);
      
      if (o.maimonscan)
        ultra_scan(Targets, &ports, MAIMON_SCAN);
      
      if (o.udpscan)
        ultra_scan(Targets, &ports, UDP_SCAN);
      
      if (o.connectscan)
        ultra_scan(Targets, &ports, CONNECT_SCAN);
      
      if (o.sctpinitscan)
        ultra_scan(Targets, &ports, SCTP_INIT_SCAN);
      
      if (o.sctpcookieechoscan)
        ultra_scan(Targets, &ports, SCTP_COOKIE_ECHO_SCAN);
      
      if (o.ipprotscan)
        ultra_scan(Targets, &ports, IPPROT_SCAN);
      
      /* These lame functions can only handle one target at a time */
      if (o.idlescan) {
        for(targetno = 0; targetno < Targets.size(); targetno++) {
           o.current_scantype = IDLE_SCAN;
           keyWasPressed(); // Check if a status message should be printed
           idle_scan(Targets[targetno], ports.tcp_ports, 
                                  ports.tcp_count, idleProxy, &ports);
        }
      }
      if (o.bouncescan) {
        for(targetno = 0; targetno < Targets.size(); targetno++) {
           o.current_scantype = BOUNCE_SCAN;
           keyWasPressed(); // Check if a status message should be printed
          if (ftp.sd <= 0) ftp_anon_connect(&ftp);
          if (ftp.sd > 0) bounce_scan(Targets[targetno], ports.tcp_ports, 
                                      ports.tcp_count, &ftp);
        }
      }

      if (o.servicescan) {
        o.current_scantype = SERVICE_SCAN; 

        service_scan(Targets);
      }

      if (o.servicescan) {
        /* This scantype must be after any TCP or UDP scans since it
         * get's it's port scan list from the open port list of the current
         * host rather than port list the user specified.
         */
        for(targetno = 0; targetno < Targets.size(); targetno++)
          pos_scan(Targets[targetno], NULL, 0, RPC_SCAN);
      }
    }

    if (o.osscan)
      os_scan2(Targets);

    if (o.traceroute)
      traceroute(Targets);

#ifndef NOLUA
    if(o.script || o.scriptversion) {
      script_scan(Targets, SCRIPT_SCAN);
    }
#endif

    for(targetno = 0; targetno < Targets.size(); targetno++) {
      currenths = Targets[targetno];
      /* Now I can do the output and such for each host */
      if (currenths->timedOut(NULL)) {
        write_host_header(currenths);
        log_write(LOG_PLAIN,"Skipping host %s due to host timeout\n",
            currenths->NameIP(hostname, sizeof(hostname)));
        log_write(LOG_MACHINE,"Host: %s (%s)\tStatus: Timeout", 
            currenths->targetipstr(), currenths->HostName());
      } else {
        /* --open means don't show any hosts without open ports. */
        if (o.openOnly() && !currenths->ports.hasOpenPorts())
          continue;

        xml_open_start_tag("host");
        xml_attribute("starttime", "%lu", (unsigned long) currenths->StartTime());
        xml_attribute("endtime", "%lu", (unsigned long) currenths->EndTime());
        xml_close_start_tag();
        write_host_header(currenths);
        printportoutput(currenths, &currenths->ports);
        printmacinfo(currenths);
        printosscanoutput(currenths);
        printserviceinfooutput(currenths);
#ifndef NOLUA
        printhostscriptresults(currenths);
#endif
        if (o.traceroute)
          printtraceroute(currenths);
        printtimes(currenths);
        log_write(LOG_PLAIN|LOG_MACHINE,"\n");
        xml_end_tag(); /* host */
        xml_newline();
      }
    }
    log_flush_all();

    o.numhosts_scanned += Targets.size();
  
    /* Free all of the Targets */
    while(!Targets.empty()) {
      currenths = Targets.back();
      delete currenths;
      Targets.pop_back();
    }
    o.numhosts_scanning = 0;
  } while(!o.max_ips_to_scan || o.max_ips_to_scan > o.numhosts_scanned);

#ifndef NOLUA
  if (o.script) {
    script_scan(Targets, SCRIPT_POST_SCAN);
    printscriptresults(script_scan_results, SCRIPT_POST_SCAN);
    script_scan_results->clear();
    delete new_targets;
    new_targets = NULL;
  }
#endif

  delete hstate;
  if (exclude_group)
    delete[] exclude_group;

  hstate = NULL;

  /* Free host expressions */
  for(i=0; i < num_host_exp_groups; i++)
    free(host_exp_group[i]);
  num_host_exp_groups = 0;
  free(host_exp_group);

  if (inputfd != NULL)
    fclose(inputfd);

  printdatafilepaths();

  printfinaloutput();

  free_scan_lists(&ports);

  eth_close_cached();

  if (o.release_memory) {
    /* Free fake argv */
    for(i=0; i < argc; i++)
      free(fakeargv[i]);
    free(fakeargv);

    nmap_free_mem();
  }
  return 0;
}      

/* Returns true iff this target is incompatible with the other hosts in the host
   group. This happens when:
     1. it uses a different interface, or
     2. it has the same IP address as another target already in the group.
   These restrictions only apply for raw scans. This function is similar to one
   of the same name in targets.cc. That one is for ping scanning, this one is
   for port scanning. */
static bool target_needs_new_hostgroup(std::vector<Target *> &targets,
  const Target *target) {
  std::vector<Target *>::iterator it;

  /* We've just started a new hostgroup, so any target is acceptable. */
  if (targets.empty())
    return false;

  /* Different interface name? */
  if (targets[0]->deviceName() != NULL &&
      target->deviceName() != NULL &&
      strcmp(targets[0]->deviceName(), target->deviceName()) != 0) {
    return true;
  }

  /* Is there already a target with this same IP address? ultra_scan doesn't
     cope with that, because it uses IP addresses to look up targets from
     replies. What happens is one target gets the replies for all probes
     referring to the same IP address. */
  if (o.af() == AF_INET) {
    for (it = targets.begin(); it != targets.end(); it++) {
      if ((*it)->v4host().s_addr == target->v4host().s_addr)
        return true;
    }
  }

  return false;
}
      
// Free some global memory allocations.
// This is used for detecting memory leaks.
void nmap_free_mem() {
  PortList::freePortMap();
  cp_free();
  free_dns_servers();
  free_etchosts();
  free_services();
  if (o.reference_FPs) {
    delete o.reference_FPs;
    o.reference_FPs = NULL;
  }
  AllProbes::service_scan_free();
  if (o.dns_servers) free(o.dns_servers);
  if (o.extra_payload) free(o.extra_payload);
  if (o.ipoptions) free(o.ipoptions);
#ifndef NOLUA
  if (o.scriptversion || o.script)
    close_nse();
  free(o.scriptargs);
#endif
  traceroute_hop_cache_clear();
}

/* Reads in a (normal or machine format) Nmap log file and gathers enough
   state to allow Nmap to continue where it left off.  The important things
   it must gather are:
   1) The last host completed
   2) The command arguments
*/
   
int gather_logfile_resumption_state(char *fname, int *myargc, char ***myargv) {
  char *filestr;
  int filelen;
  char nmap_arg_buffer[1024];
  struct in_addr lastip;
  char *p, *q, *found, *lastipstr; /* I love C! */
  /* We mmap it read/write since we will change the last char to a newline if it is not already */
  filestr = mmapfile(fname, &filelen, O_RDWR);
  if (!filestr) {
    fatal("Could not mmap() %s read/write", fname);
  }

  if (filelen < 20) {
    fatal("Output file %s is too short -- no use resuming", fname);
  }

  /* For now we terminate it with a NUL, but we will terminate the file with
     a '\n' later */
  filestr[filelen - 1] = '\0';

  /* First goal is to find the nmap args */
  if ((p = strstr(filestr, " as: ")))
    p += 5;
  else fatal("Unable to parse supposed log file %s.  Are you sure this is an Nmap output file?", fname);
  while(*p && !isspace((int) (unsigned char) *p))
    p++;
  if (!*p) fatal("Unable to parse supposed log file %s.  Sorry", fname);
  p++; /* Skip the space between program name and first arg */
  if (*p == '\n' || !*p) fatal("Unable to parse supposed log file %s.  Sorry", fname);

  q = strchr(p, '\n');
  if (!q || ((unsigned int) (q - p) >= sizeof(nmap_arg_buffer) - 32))
    fatal("Unable to parse supposed log file %s.  Perhaps the Nmap execution had not finished at least one host?  In that case there is no use \"resuming\"", fname);


  strncpy(nmap_arg_buffer, "nmap --append-output ", sizeof(nmap_arg_buffer));
  if ((q-p) + 21 + 1 >= (int) sizeof(nmap_arg_buffer)) fatal("0verfl0w");
  memcpy(nmap_arg_buffer + 21, p, q-p);
  nmap_arg_buffer[21 + q-p] = '\0';

  if (strstr(nmap_arg_buffer, "--randomize-hosts") != NULL) {
    error("WARNING:  You are attempting to resume a scan which used --randomize-hosts.  Some hosts in the last randomized batch may be missed and others may be repeated once");
  }

  *myargc = arg_parse(nmap_arg_buffer, myargv);
  if (*myargc == -1) {  
    fatal("Unable to parse supposed log file %s.  Sorry", fname);
  }
     
  /* Now it is time to figure out the last IP that was scanned */
  q = p;
  found = NULL;
  /* Lets see if its a grepable log first (-oG) */
  while((q = strstr(q, "\nHost: ")))
    found = q = q + 7;

  if (found) {
    q = strchr(found, ' ');
    if (!q) fatal("Unable to parse supposed log file %s.  Sorry", fname);
    *q = '\0';
    if (inet_pton(AF_INET, found, &lastip) == 0)
      fatal("Unable to parse supposed log file %s.  Sorry", fname);
    *q = ' ';
  } else {
    /* OK, I guess (hope) it is a normal log then (-oN) */
    q = p;
    found = NULL;
    while((q = strstr(q, "\nNmap scan report for ")))
      found = q = q + 22;

    /*  There may be some later IPs of the form :
        "Nmap scan report for florence (x.x.7.10)" (dns reverse lookup)
        or "Nmap scan report for x.x.7.10".
    */
    if (found) {
      q = strchr(found, '\n');
      if (!q) fatal("Unable to parse supposed log file %s.  Sorry", fname);
      *q = '\0';
      p = strchr(found, '(');
      if (!p) { /* No DNS reverse lookup, found should already contain IP */
        lastipstr = strdup(found);
      } else { /* DNS reverse lookup, IP is between parentheses */
        *q = '\n'; q--; *q = '\0';
        lastipstr = strdup(p + 1);
      }
      *q = p ? ')' : '\n'; /* recover changed chars */
      if (inet_pton(AF_INET, lastipstr, &lastip) == 0)
        fatal("Unable to parse ip (%s) in supposed log file %s.  Sorry", lastipstr, fname);
      free(lastipstr);
    } else {
      error("Warning: You asked for --resume but it doesn't look like any hosts in the log file were successfully scanned.  Starting from the beginning.");
      lastip.s_addr = 0;
    }
  }
  o.resume_ip = lastip;

  /* Ensure the log file ends with a newline */
  filestr[filelen - 1] = '\n';
  munmap(filestr, filelen);
  return 0;
}



/* Convert a string like "-100,n*tp,200-1024,3000-4000,[60000-]" into an array
 * of port numbers. Note that one trailing comma is OK -- this is actually
 * useful for machine generated lists
 *
 * Fyodor - Wrote original
 * William McVey - Added T:, U:, P: directives
 * Doug Hoyte - Added [], name lookups, and wildcard expansion
 *
 * getpts() handles []
 * Any port ranges included inside square brackets will have all
 * their ports looked up in nmap-services or nmap-protocols
 * and will only be included if they are found.
 * Returns a scan_list* with all the ports that should be scanned.
 *
 * getpts() handles service/protocol name lookups and wildcard expansion.
 * The service name can be specified instead of the port number.
 * For example, "ssh" can be used instead of "22". You can use wildcards
 * like "*" and "?". See the function wildtest() for the exact details.
 * For example,
 *
 * nmap -p http* host
 *
 * Will scan http (80), http-mgmt (280), http-proxy (8080), https (443), etc.
 *
 * Matching is case INsensitive but the first character in a match MUST
 * be lowercase so it doesn't conflict with the T:, U:, and P: directives.
 *
 * getpts() is unable to match service names that start with a digit
 * like 3com-tsmux (106/udp). Use a pattern like "?com-*" instead.
 *
 * BE CAREFUL ABOUT SHELL EXPANSIONS!!!
 * If you are trying to match the services nmsp (537/tcp) and nms (1429/tcp)
 * and you execute the command
 *
 * ./nmap -p nm* host
 *
 * You will see
 *
 * Found no matches for the service mask 'nmap' and your specified protocols
 * QUITTING!
 *
 * This is because nm* was expanded to the name of the binary file nmap in
 * the current directory by your shell. When unsure, quote your port strings
 * to be safe:
 *
 * ./nmap -p 'nm*' host
 *
 * getpts() is smart enough to keep the T: U: and P: directives nested
 * and working in a logical manner. For instance,
 *
 * nmap -sTU -p [U:1025-],1-1024 host
 *
 * Will scan UDP ports 1025 and up that are found in the service file
 * and all TCP/UDP ports below <= 1024. Notice that the U doesn't affect
 * the outer part of the port expression. It's "closed".
 */

static void getpts_aux(const char *origexpr, int nested, u8 *porttbl, int range_type,
                       int *portwarning, bool change_range_type = true);

void getpts(const char *origexpr, struct scan_lists *ports) {
  u8 *porttbl;
  int range_type = 0;
  int portwarning = 0;
  int i, tcpi, udpi, sctpi, proti;

  if (o.TCPScan())
    range_type |= SCAN_TCP_PORT;
  if (o.UDPScan())
    range_type |= SCAN_UDP_PORT;
  if (o.SCTPScan())
    range_type |= SCAN_SCTP_PORT;
  if (o.ipprotscan)
    range_type |= SCAN_PROTOCOLS;

  porttbl = (u8 *) safe_zalloc(65536);

  getpts_aux(origexpr,      // Pass on the expression
             0,             // Don't start off nested
             porttbl,       // Our allocated port table
             range_type,    // Defaults to TCP/UDP/SCTP/Protos
             &portwarning); // No, we haven't warned them about dup ports yet

  ports->tcp_count = 0;
  ports->udp_count = 0;
  ports->sctp_count = 0;
  ports->prot_count = 0;
  for(i = 0; i <= 65535; i++) {
    if (porttbl[i] & SCAN_TCP_PORT)
      ports->tcp_count++;
    if (porttbl[i] & SCAN_UDP_PORT)
      ports->udp_count++;
    if (porttbl[i] & SCAN_SCTP_PORT)
      ports->sctp_count++;
    if (porttbl[i] & SCAN_PROTOCOLS && i < 256)
      ports->prot_count++;
  }

  if (range_type != 0 && 0 == (ports->tcp_count + ports->udp_count + ports->sctp_count + ports->prot_count))
    fatal("No ports specified -- If you really don't want to scan any ports use ping scan...");

  if (ports->tcp_count) {
    ports->tcp_ports = (unsigned short *)safe_zalloc(ports->tcp_count * sizeof(unsigned short));
  }
  if (ports->udp_count) {
    ports->udp_ports = (unsigned short *)safe_zalloc(ports->udp_count * sizeof(unsigned short));
  }
  if (ports->sctp_count) {
    ports->sctp_ports = (unsigned short *)safe_zalloc(ports->sctp_count * sizeof(unsigned short));
  }
  if (ports->prot_count) {
    ports->prots = (unsigned short *)safe_zalloc(ports->prot_count * sizeof(unsigned short));
  }

  for(i=tcpi=udpi=sctpi=proti=0; i <= 65535; i++) {
    if (porttbl[i] & SCAN_TCP_PORT)
      ports->tcp_ports[tcpi++] = i;
    if (porttbl[i] & SCAN_UDP_PORT)
      ports->udp_ports[udpi++] = i;
    if (porttbl[i] & SCAN_SCTP_PORT)
      ports->sctp_ports[sctpi++] = i;
    if (porttbl[i] & SCAN_PROTOCOLS && i < 256)
      ports->prots[proti++] = i;
  }

  free(porttbl);
}

/* This function is like getpts except it only allocates space for and stores
  values into one unsigned short array, instead of an entire scan_lists struct
  For that reason, T:, U:, S: and P: restrictions are not allowed and only one
  bit in range_type may be set. */
void getpts_simple(const char *origexpr, int range_type,
                   unsigned short **list, int *count) {
  u8 *porttbl;
  int portwarning = 0;
  int i, j;

  /* Make sure that only one bit in range_type is set (or that range_type is 0,
     which is useless but not incorrect). */
  assert((range_type & (range_type - 1)) == 0);

  porttbl = (u8 *) safe_zalloc(65536);

  /* Get the ports but do not allow changing the type with T:, U:, or P:. */
  getpts_aux(origexpr, 0, porttbl, range_type, &portwarning, false);

  /* Count how many are set. */
  *count = 0;
  for (i = 0; i <= 65535; i++) {
    if (porttbl[i] & range_type)
      (*count)++;
  }

  if (*count == 0){
    free(porttbl);
    return;
  }

  *list = (unsigned short *) safe_zalloc(*count * sizeof(unsigned short));

  /* Fill in the list. */
  for (i = 0, j = 0; i <= 65535; i++) {
    if (porttbl[i] & range_type)
      (*list)[j++] = i;
  }

  free(porttbl);
}

/* getpts() and getpts_simple() (see above) are wrappers for this function */

static void getpts_aux(const char *origexpr, int nested, u8 *porttbl, int range_type, int *portwarning, bool change_range_type) {
  long rangestart = -2343242, rangeend = -9324423;
  const char *current_range;
  char *endptr;
  char servmask[128];  // A protocol name can be up to 127 chars + nul byte
  int i;

  /* An example of proper syntax to use in error messages. */
  const char *syntax_example;
  if (change_range_type)
    syntax_example = "-100,200-1024,T:3000-4000,U:60000-";
  else
    syntax_example = "-100,200-1024,3000-4000,60000-";

  current_range = origexpr;
  do {
    while(isspace((int) (unsigned char) *current_range))
      current_range++; /* I don't know why I should allow spaces here, but I will */

    if (change_range_type) {
      if (*current_range == 'T' && *++current_range == ':') {
          current_range++;
          range_type = SCAN_TCP_PORT;
          continue;
      }
      if (*current_range == 'U' && *++current_range == ':') {
          current_range++;
          range_type = SCAN_UDP_PORT;
          continue;
      }
      if (*current_range == 'S' && *++current_range == ':') {
          current_range++;
          range_type = SCAN_SCTP_PORT;
          continue;
      }
      if (*current_range == 'P' && *++current_range == ':') {
          current_range++;
          range_type = SCAN_PROTOCOLS;
          continue;
      }
    }

    if (*current_range == '[') {
      if (nested)
        fatal("Can't nest [] brackets in port/protocol specification");

      getpts_aux(++current_range, 1, porttbl, range_type, portwarning);

      // Skip past the ']'. This is OK because we can't nest []s
      while(*current_range != ']') current_range++;
      current_range++;

      // Skip over a following ',' so we're ready to keep parsing
      if (*current_range == ',') current_range++;

      continue;
    } else if (*current_range == ']') {
      if (!nested)
        fatal("Unexpected ] character in port/protocol specification");

      return;
    } else if (*current_range == '-') {
      if (range_type & SCAN_PROTOCOLS)
        rangestart = 0;
      else
        rangestart = 1;
    }
    else if (isdigit((int) (unsigned char) *current_range)) {
      rangestart = strtol(current_range, &endptr, 10);
      if (range_type & SCAN_PROTOCOLS) {
        if (rangestart < 0 || rangestart > 255)
	  fatal("Protocols to be scanned must be between 0 and 255 inclusive");
      } else {
        if (rangestart < 0 || rangestart > 65535)
	  fatal("Ports to be scanned must be between 0 and 65535 inclusive");
      }
      current_range = endptr;
      while(isspace((int) (unsigned char) *current_range)) current_range++;
    } else if (islower((int) (unsigned char) *current_range) || *current_range == '*' || *current_range == '?') {
      i = 0;

      while (*current_range && !isspace((int) (unsigned char) *current_range) && *current_range != ',' && *current_range != ']') {
        servmask[i++] = *(current_range++);
        if (i >= ((int)sizeof(servmask)-1))
          fatal("A service mask in the port/protocol specification is either malformed or too long");
      }

      if (*current_range && *current_range != ']') current_range++; // We want the '] character to be picked up on the next pass
      servmask[i] = '\0'; // Finish the string

      i = addportsfromservmask(servmask, porttbl, range_type);
      if (range_type & SCAN_PROTOCOLS) i += addprotocolsfromservmask(servmask, porttbl);

      if (i == 0)
        fatal("Found no matches for the service mask '%s' and your specified protocols", servmask);

      continue;

    } else {
      fatal("Error #485: Your port specifications are illegal.  Example of proper form: \"%s\"", syntax_example);
    }
    /* Now I have a rangestart, time to go after rangeend */
    if (!*current_range || *current_range == ',' || *current_range == ']') {
      /* Single port specification */
      rangeend = rangestart;
    } else if (*current_range == '-') {
      current_range++;
      if (!*current_range || *current_range == ',' || *current_range == ']') {
	/* Ended with a -, meaning up until the last possible port */
        if (range_type & SCAN_PROTOCOLS)
          rangeend = 255;
        else
          rangeend = 65535;
      } else if (isdigit((int) (unsigned char) *current_range)) {
	rangeend = strtol(current_range, &endptr, 10);
        if (range_type & SCAN_PROTOCOLS) {
	  if (rangeend < 0 || rangeend > 255)
	    fatal("Protocols to be scanned must be between 0 and 255 inclusive");
	} else {
	  if (rangeend < 0 || rangeend > 65535)
	    fatal("Ports to be scanned must be between 0 and 65535 inclusive");
	}
	current_range = endptr;
      } else {
	fatal("Error #486: Your port specifications are illegal.  Example of proper form: \"%s\"", syntax_example);
      }
      if (rangeend < rangestart) {
        fatal("Your %s range %ld-%ld is backwards. Did you mean %ld-%ld?",
          (range_type & SCAN_PROTOCOLS) ? "protocol" : "port",
          rangestart, rangeend, rangeend, rangestart);
      }
    } else {
	fatal("Error #487: Your port specifications are illegal.  Example of proper form: \"%s\"", syntax_example);
    }

    /* Now I have a rangestart and a rangeend, so I can add these ports */
    while(rangestart <= rangeend) {
      if (porttbl[rangestart] & range_type) {
        if (!(*portwarning)) {
	  error("WARNING:  Duplicate port number(s) specified.  Are you alert enough to be using Nmap?  Have some coffee or Jolt(tm).");
          (*portwarning)++;
	} 
      } else {      
        if (nested) {
          if ((range_type & SCAN_TCP_PORT) &&
              nmap_getservbyport(htons(rangestart), "tcp")) {
            porttbl[rangestart] |= SCAN_TCP_PORT;
          }
          if ((range_type & SCAN_UDP_PORT) &&
              nmap_getservbyport(htons(rangestart), "udp")) {
            porttbl[rangestart] |= SCAN_UDP_PORT;
          }
          if ((range_type & SCAN_SCTP_PORT) &&
              nmap_getservbyport(htons(rangestart), "sctp")) {
            porttbl[rangestart] |= SCAN_SCTP_PORT;
          }
          if ((range_type & SCAN_PROTOCOLS) &&
              nmap_getprotbynum(htons(rangestart))) {
            porttbl[rangestart] |= SCAN_PROTOCOLS;
          }
        } else {
          porttbl[rangestart] |= range_type;
        }
      }
      rangestart++;
    }
    
    /* Find the next range */
    while(isspace((int) (unsigned char) *current_range)) current_range++;

    if (*current_range == ']') {
      if (!nested) fatal("Unexpected ] character in port/protocol specification");
      return;
    }

    if (*current_range && *current_range != ',') {
      fatal("Error #488: Your port specifications are illegal.  Example of proper form: \"%s\"", syntax_example);
    }
    if (*current_range == ',')
      current_range++;
  } while(current_range && *current_range);

}

void free_scan_lists(struct scan_lists *ports) {
  if (ports->tcp_ports) free(ports->tcp_ports);
  if (ports->udp_ports) free(ports->udp_ports);
  if (ports->sctp_ports) free(ports->sctp_ports);
  if (ports->prots) free(ports->prots);
  if (ports->syn_ping_ports) free(ports->syn_ping_ports);
  if (ports->ack_ping_ports) free(ports->ack_ping_ports);
  if (ports->udp_ping_ports) free(ports->udp_ping_ports);
  if (ports->proto_ping_ports) free(ports->proto_ping_ports);
}

char *seqreport(struct seq_info *seq) {
  static char report[512];

  Snprintf(report, sizeof(report), "TCP Sequence Prediction: Difficulty=%d (%s)\n", seq->index, seqidx2difficultystr(seq->index));
  return report;
}

/* Convert a TCP sequence prediction difficulty index like 1264386
   into a difficulty string like "Worthy Challenge */
const char *seqidx2difficultystr(unsigned long idx) {
  return  (idx < 3)? "Trivial joke" : (idx < 6)? "Easy" : (idx < 11)? "Medium" : (idx < 12)? "Formidable" : (idx < 16)? "Worthy challenge" : "Good luck!";
}

const char *ipidclass2ascii(int seqclass) {
  switch(seqclass) {
  case IPID_SEQ_CONSTANT:
    return "Duplicated ipid (!)";
  case IPID_SEQ_INCR:
    return "Incremental";
  case IPID_SEQ_BROKEN_INCR:
    return "Broken little-endian incremental";
  case IPID_SEQ_RD:
    return "Randomized";
  case IPID_SEQ_RPI:
    return "Random positive increments";
  case IPID_SEQ_ZERO:
    return "All zeros";
  case IPID_SEQ_UNKNOWN:
    return "Busy server or unknown class";
  default:
    return "ERROR, WTF?";
  }
}

const char *tsseqclass2ascii(int seqclass) {
  switch(seqclass) {
  case TS_SEQ_ZERO:
    return "zero timestamp";
  case TS_SEQ_2HZ:
    return "2HZ";
  case TS_SEQ_100HZ:
    return "100HZ";
  case TS_SEQ_1000HZ:
    return "1000HZ";
  case TS_SEQ_OTHER_NUM:
    return "other";
  case TS_SEQ_UNSUPPORTED:
    return "none returned (unsupported)";
  case TS_SEQ_UNKNOWN:
    return "unknown class";
  default:
    return "ERROR, WTF?";
  }
}




/* Just a routine for obtaining a string for printing based on the scantype */
const char *scantype2str(stype scantype) {

  switch(scantype) {
  case STYPE_UNKNOWN: return "Unknown Scan Type"; break;
  case HOST_DISCOVERY: return "Host Discovery"; break;
  case ACK_SCAN: return "ACK Scan"; break;
  case SYN_SCAN: return "SYN Stealth Scan"; break;
  case FIN_SCAN: return "FIN Scan"; break;
  case XMAS_SCAN: return "XMAS Scan"; break;
  case UDP_SCAN: return "UDP Scan"; break;
  case CONNECT_SCAN: return "Connect Scan"; break;
  case NULL_SCAN: return "NULL Scan"; break;
  case WINDOW_SCAN: return "Window Scan"; break;
  case SCTP_INIT_SCAN: return "SCTP INIT Scan"; break;
  case SCTP_COOKIE_ECHO_SCAN: return "SCTP COOKIE-ECHO Scan"; break;
  case RPC_SCAN: return "RPCGrind Scan"; break;
  case MAIMON_SCAN: return "Maimon Scan"; break;
  case IPPROT_SCAN: return "IPProto Scan"; break;
  case PING_SCAN: return "Ping Scan"; break;
  case PING_SCAN_ARP: return "ARP Ping Scan"; break;
  case IDLE_SCAN: return "Idle Scan"; break;
  case BOUNCE_SCAN: return "Bounce Scan"; break;
  case SERVICE_SCAN: return "Service Scan"; break;
  case OS_SCAN: return "OS Scan"; break;
  case SCRIPT_PRE_SCAN: return "Script Pre-Scan"; break;
  case SCRIPT_SCAN: return "Script Scan"; break;
  case SCRIPT_POST_SCAN: return "Script Post-Scan"; break;
  case TRACEROUTE: return "Traceroute" ; break;
  default: assert(0); break;
  }

  return NULL; /* Unreached */

}

const char *statenum2str(int state) {
  switch(state) {
  case PORT_OPEN: return "open"; break;
  case PORT_FILTERED: return "filtered"; break;
  case PORT_UNFILTERED: return "unfiltered"; break;
  case PORT_CLOSED: return "closed"; break;
  case PORT_OPENFILTERED: return "open|filtered"; break;
  case PORT_CLOSEDFILTERED: return "closed|filtered"; break;
  default: return "unknown"; break;
  }
  return "unknown";
}

int ftp_anon_connect(struct ftpinfo *ftp) {
  int sd;
  struct sockaddr_in sock;
  int res;
  char recvbuf[2048];
  char command[512];

  if (o.verbose || o.debugging) 
    log_write(LOG_STDOUT, "Attempting connection to ftp://%s:%s@%s:%i\n", ftp->user, ftp->pass,
	      ftp->server_name, ftp->port);

  if ((sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
    gh_perror("Couldn't create %s socket", __func__);
    return 0;
  }

  sock.sin_family = AF_INET;
  sock.sin_addr.s_addr = ftp->server.s_addr;
  sock.sin_port = htons(ftp->port); 
  res = connect(sd, (struct sockaddr *) &sock, sizeof(struct sockaddr_in));
  if (res < 0 ) {
    fatal("Your FTP bounce proxy server won't talk to us!");
  }
  if (o.verbose || o.debugging) log_write(LOG_STDOUT, "Connected:");
  while ((res = recvtime(sd, recvbuf, sizeof(recvbuf) - 1,7, NULL)) > 0) 
    if (o.debugging || o.verbose) {
      recvbuf[res] = '\0';
      log_write(LOG_STDOUT, "%s", recvbuf);
    }
  if (res < 0) {
    pfatal("recv problem from FTP bounce server");
  }

  Snprintf(command, 511, "USER %s\r\n", ftp->user);

  send(sd, command, strlen(command), 0);
  res = recvtime(sd, recvbuf, sizeof(recvbuf) - 1,12, NULL);
  if (res <= 0) {
    pfatal("recv problem from FTP bounce server");
  }
  recvbuf[res] = '\0';
  if (o.debugging) log_write(LOG_STDOUT, "sent username, received: %s", recvbuf);
  if (recvbuf[0] == '5') {
    fatal("Your FTP bounce server doesn't like the username \"%s\"", ftp->user);
  }

  Snprintf(command, 511, "PASS %s\r\n", ftp->pass);

  send(sd, command, strlen(command), 0);
  res = recvtime(sd, recvbuf, sizeof(recvbuf) - 1,12, NULL);
  if (res < 0) {
    pfatal("recv problem from FTP bounce server");
  }
  if (!res) error("Timeout from bounce server ...");
  else {
    recvbuf[res] = '\0';
    if (o.debugging) log_write(LOG_STDOUT, "sent password, received: %s", recvbuf);
    if (recvbuf[0] == '5') {
      fatal("Your FTP bounce server refused login combo (%s/%s)",
	      ftp->user, ftp->pass);
    }
  }
  while ((res = recvtime(sd, recvbuf, sizeof(recvbuf) - 1,2, NULL)) > 0) 
    if (o.debugging) {
      recvbuf[res] = '\0';
      log_write(LOG_STDOUT, "%s", recvbuf);
    }
  if (res < 0) {
    pfatal("recv problem from FTP bounce server");
  }
  if (o.verbose) log_write(LOG_STDOUT, "Login credentials accepted by FTP server!\n");

  ftp->sd = sd;
  return sd;
}



int nmap_fileexistsandisreadable(const char* pathname) {
	return fileexistsandisreadable(pathname);
}

static char *executable_dir(const char *argv0) {
  char *path, *dir;

  path = executable_path(argv0);
  if (path == NULL)
    return NULL;
  dir = path_get_dirname(path);
  free(path);

  return dir;
}

int nmap_fetchfile(char *filename_returned, int bufferlen, const char *file) {
  char *dirptr;
  int res;
  int foundsomething = 0;
  struct passwd *pw;
  char dot_buffer[512];
  static int warningcount = 0;
  std::map<std::string, std::string>::iterator iter;

  /* First, check the map of requested data file names. If there's an entry for
     file, use it and return.
     Otherwise, we try [--datadir]/file, then $NMAPDIR/file
     next we try ~user/.nmap/file
     then the directory the nmap binary is in
     then we try NMAPDATADIR/file <--NMAPDATADIR 
     finally we try ./file

	 -- or on Windows --

	 --datadir -> $NMAPDIR -> nmap.exe directory -> NMAPDATADIR -> .
  */

  /* Check the map of requested data file names. */
  iter = o.requested_data_files.find(file);
  if (iter != o.requested_data_files.end()) {
    Strncpy(filename_returned, iter->second.c_str(), bufferlen);
    /* If a special file name was requested, we must not return any other file
       name. Return a positive result even if the file doesn't exist or is not
       readable. It is the caller's responsibility to report the error if the
       file can't be accessed. */
    return fileexistsandisreadable(filename_returned) || 1;
  }

  if (o.datadir) {
    res = Snprintf(filename_returned, bufferlen, "%s/%s", o.datadir, file);
    if (res > 0 && res < bufferlen) {
      foundsomething = fileexistsandisreadable(filename_returned);
    }
  }

  if (!foundsomething && (dirptr = getenv("NMAPDIR"))) {
    res = Snprintf(filename_returned, bufferlen, "%s/%s", dirptr, file);
    if (res > 0 && res < bufferlen) {
      foundsomething = fileexistsandisreadable(filename_returned);
    }
  }
#ifndef WIN32
  if (!foundsomething) {
    pw = getpwuid(getuid());
    if (pw) {
      res = Snprintf(filename_returned, bufferlen, "%s/.nmap/%s", pw->pw_dir, file);
      if (res > 0 && res < bufferlen) {
        foundsomething = fileexistsandisreadable(filename_returned);
      }
    }
    if (!foundsomething && getuid() != geteuid()) {
      pw = getpwuid(geteuid());
      if (pw) {
	res = Snprintf(filename_returned, bufferlen, "%s/.nmap/%s", pw->pw_dir, file);
	if (res > 0 && res < bufferlen) {
          foundsomething = fileexistsandisreadable(filename_returned);
	}
      }
    }
  }
#endif
  if (!foundsomething) { /* Try the nMap directory */
    const char *argv0;
    char *dir;

    argv0 = get_program_name();
    assert(argv0 != NULL);
    dir = executable_dir(argv0);
    if (dir != NULL) {
      res = Snprintf(filename_returned, bufferlen, "%s/%s", dir, file);
      if (res > 0 && res < bufferlen) {
        foundsomething = fileexistsandisreadable(filename_returned);
      }
      free(dir);
    }
  }
  if (!foundsomething) {
    res = Snprintf(filename_returned, bufferlen, "%s/%s", NMAPDATADIR, file);
    if (res > 0 && res < bufferlen) {
      foundsomething = fileexistsandisreadable(filename_returned);
    }
  }

  if (foundsomething && (*filename_returned != '.')) {    
    res = Snprintf(dot_buffer, sizeof(dot_buffer), "./%s", file);
    if (res > 0 && res < bufferlen) {
      if (fileexistsandisreadable(dot_buffer)) {
#ifdef WIN32
	if (warningcount++ < 1 && o.debugging)
#else
	if(warningcount++ < 1)
#endif
	  error("Warning: File %s exists, but Nmap is using %s for security and consistency reasons.  set NMAPDIR=. to give priority to files in your local directory (may affect the other data files too).", dot_buffer, filename_returned);
      }
    }
  }

  if (!foundsomething) {
    res = Snprintf(filename_returned, bufferlen, "./%s", file);
    if (res > 0 && res < bufferlen) {
      foundsomething = fileexistsandisreadable(filename_returned);
    }
  }

  if (!foundsomething) {
    filename_returned[0] = '\0';
  }

  if (foundsomething && o.debugging > 1)
    log_write(LOG_PLAIN, "Fetchfile found %s\n", filename_returned);

  return foundsomething;

}

/* Extracts a whitespace-separated word from a string. Returns a zero-length
   string if there are too few words. */
static std::string get_word(const char *str, unsigned int n) {
  const char *p, *q;
  unsigned int i;

  p = str;
  for (i = 0; *p != '\0' && i <= n; i++) {
    while (isspace((int) (unsigned char) *p))
      p++;
    q = p;
    while (*q != '\0' && !isspace((int) (unsigned char) *q))
      q++;
    if (i == n)
      return std::string(p, q - p);
    p = q;
  }

  return std::string();
}

/* Helper for display_nmap_version. Tries to extract a word (presumably a
   version number) from a string, but if that fails, returns the whole string
   enclosed in parentheses as a failsafe. */
static std::string get_word_or_quote(const char *str, unsigned int n) {
  std::string word;

  word = get_word(str, n);
  if (word.length() == 0)
    word = std::string("(") + str + std::string(")");

  return word;
}

static void display_nmap_version() {
  std::vector<std::string> with, without;
  unsigned int i;

#ifndef NOLUA
#ifdef LUA_INCLUDED
  with.push_back(std::string("nmap-liblua-") + get_word_or_quote(LUA_RELEASE, 1));
#else
  with.push_back(std::string("liblua-") + get_word_or_quote(LUA_RELEASE, 1));
#endif
#else
  without.push_back("liblua");
#endif

#if HAVE_OPENSSL
  with.push_back(std::string("openssl-") + get_word_or_quote(OPENSSL_VERSION_TEXT, 1));
#else
  without.push_back("openssl");
#endif

#ifdef PCRE_INCLUDED
  with.push_back(std::string("nmap-libpcre-") + get_word_or_quote(pcre_version(), 0));
#else
  with.push_back(std::string("libpcre-") + get_word_or_quote(pcre_version(), 0));
#endif

#ifdef PCAP_INCLUDED
  with.push_back(std::string("nmap-libpcap-") + get_word_or_quote(pcap_lib_version(), 2));
#else
  with.push_back(std::string("libpcap-") + get_word_or_quote(pcap_lib_version(), 2));
#endif

#ifdef DNET_INCLUDED
  with.push_back(std::string("nmap-libdnet-") + DNET_VERSION);
#else
  with.push_back(std::string("libdnet-") + DNET_VERSION);
#endif

#if HAVE_IPV6
  with.push_back("ipv6");
#else
  without.push_back("ipv6");
#endif

  log_write(LOG_STDOUT, "\n%s version %s ( %s )\n", NMAP_NAME, NMAP_VERSION, NMAP_URL);
  log_write(LOG_STDOUT, "Platform: %s\n", NMAP_PLATFORM);
  log_write(LOG_STDOUT, "Compiled with:");
  for (i = 0; i < with.size(); i++)
    log_write(LOG_STDOUT, " %s", with[i].c_str());
  log_write(LOG_STDOUT, "\n");
  log_write(LOG_STDOUT, "Compiled without:");
  for (i = 0; i < without.size(); i++)
    log_write(LOG_STDOUT, " %s", without[i].c_str());
  log_write(LOG_STDOUT, "\n");
}
