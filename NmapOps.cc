
/***************************************************************************
 * NmapOps.cc -- The NmapOps class contains global options, mostly based   *
 * on user-provided command-line settings.                                 *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2016 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE CLARIFICATIONS  *
 * AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your right to use,    *
 * modify, and redistribute this software under certain conditions.  If    *
 * you wish to embed Nmap technology into proprietary software, we sell    *
 * alternative licenses (contact sales@nmap.com).  Dozens of software      *
 * vendors already license Nmap technology such as host discovery, port    *
 * scanning, OS detection, version detection, and the Nmap Scripting       *
 * Engine.                                                                 *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files, such as Nmap's nmap-os-db   *
 * or nmap-service-probes.                                                 *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * Nmap with other software in compressed or archival form does not        *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * As another special exception to the GPL terms, Insecure.Com LLC grants  *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two.                                  *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * Nmap or grant special permissions to use it in other open source        *
 * software.  Please contact fyodor@nmap.org with any such requests.       *
 * Similarly, we don't incorporate incompatible open source software into  *
 * Covered Software without special permission from the copyright holders. *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * Nmap in other works, are happy to help.  As mentioned above, we also    *
 * offer alternative license to integrate Nmap into proprietary            *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates.  They also fund the      *
 * continued development of Nmap.  Please email sales@nmap.com for further *
 * information.                                                            *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
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
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING)        *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */
#include "nmap.h"
#include "nbase.h"
#include "NmapOps.h"
#include "osscan.h"
#include "services.h"
#include "nmap_error.h"
#ifdef WIN32
#include "winfix.h"
#endif

NmapOps o;

NmapOps::NmapOps() {
  datadir = NULL;
  xsl_stylesheet = NULL;
  Initialize();
}

NmapOps::~NmapOps() {
  if (xsl_stylesheet) {
    free(xsl_stylesheet);
    xsl_stylesheet = NULL;
  }

  if (reference_FPs) {
    delete reference_FPs;
    reference_FPs = NULL;
  }

  if (dns_servers) {
    free(dns_servers);
    dns_servers = NULL;
  }
  if (extra_payload) {
    free(extra_payload);
    extra_payload = NULL;
  }
  if (ipoptions) {
    free(ipoptions);
    ipoptions = NULL;
  }
  if (portlist) {
    free(portlist);
    portlist = NULL;
  }
  if (exclude_portlist) {
    free(exclude_portlist);
    exclude_portlist = NULL;
  }
  if (proxy_chain) {
    nsock_proxychain_delete(proxy_chain);
    proxy_chain = NULL;
  }
  if (exclude_spec) {
    free(exclude_spec);
    exclude_spec = NULL;
  }
  if (idleProxy) {
    free(idleProxy);
    idleProxy = NULL;
  }
  if (datadir) {
    free(datadir);
    datadir = NULL;
  }

#ifndef NOLUA
  if (scriptversion || script)
    close_nse();
  if (scriptargs) {
    free(scriptargs);
    scriptargs = NULL;
  }
#endif
}

void NmapOps::ReInit() {
  Initialize();
}

// no setpf() because it is based on setaf() values
int NmapOps::pf() {
  return (af() == AF_INET)? PF_INET : PF_INET6;
}

int NmapOps::SourceSockAddr(struct sockaddr_storage *ss, size_t *ss_len) {
  if (sourcesocklen <= 0)
    return 1;
  assert(sourcesocklen <= sizeof(*ss));
  if (ss)
    memcpy(ss, &sourcesock, sourcesocklen);
  if (ss_len)
    *ss_len = sourcesocklen;
  return 0;
}

/* Returns a const pointer to the source address if set, or NULL if unset. */
const struct sockaddr_storage *NmapOps::SourceSockAddr() const {
  if (sourcesock.ss_family == AF_UNSPEC)
    return NULL;
  else
    return &sourcesock;
}

/* Note that it is OK to pass in a sockaddr_in or sockaddr_in6 casted
     to sockaddr_storage */
void NmapOps::setSourceSockAddr(struct sockaddr_storage *ss, size_t ss_len) {
  assert(ss_len > 0 && ss_len <= sizeof(*ss));
  memcpy(&sourcesock, ss, ss_len);
  sourcesocklen = ss_len;
}

// Number of seconds since getStartTime().  The current time is an
// optional argument to avoid an extra gettimeofday() call.
float NmapOps::TimeSinceStart(const struct timeval *now) {
  struct timeval tv;
  if (!now)
    gettimeofday(&tv, NULL);
  else tv = *now;

  return TIMEVAL_FSEC_SUBTRACT(tv, start_time);
}

// Convert a filename to a file:// URL. The return value must be freed.
static char *filename_to_url(const char *filename) {
  std::string url(filename);
  char percent_buffer[10];

#if WIN32
  for (std::string::iterator p = url.begin(); p != url.end(); p++) {
    if (*p == '\\')
      *p = '/';
  }
  /* Put a pseudo-root directory before "C:/" or whatever. */
  url = "/" + url;
#endif

  /* Percent-encode any troublesome characters. */
  std::string::size_type i = 0;
  /* See RFC 3986, section 3.3 "Path" for allowed characters. */
  while ((i = url.find_first_of("?#[]%", i)) != std::string::npos) {
    Snprintf(percent_buffer, sizeof(percent_buffer), "%%%02X", url[i]);
    url.replace(i, 1, percent_buffer);
    i += strlen(percent_buffer);
  }

  url = "file://" + url;

  return strdup(url.c_str());
}

void NmapOps::Initialize() {
  setaf(AF_INET);
#if defined WIN32 || defined __amigaos__
  isr00t = 1;
#else
  if (getenv("NMAP_PRIVILEGED"))
    isr00t = 1;
  else if (getenv("NMAP_UNPRIVILEGED"))
    isr00t = 0;
  else
    isr00t = !(geteuid());
#endif
  have_pcap = true;
  debugging = 0;
  verbose = 0;
  min_packet_send_rate = 0.0; /* Unset. */
  max_packet_send_rate = 0.0; /* Unset. */
  stats_interval = 0.0; /* Unset. */
  randomize_hosts = 0;
  randomize_ports = 1;
  sendpref = PACKET_SEND_NOPREF;
  spoofsource = 0;
  fastscan = 0;
  device[0] = '\0';
  ping_group_sz = PING_GROUP_SZ;
  nogcc = 0;
  generate_random_ips = 0;
  reference_FPs = NULL;
  magic_port = 33000 + (get_random_uint() % 31000);
  magic_port_set = false;
  timing_level = 3;
  max_parallelism = 0;
  min_parallelism = 0;
  max_os_tries = 5;
  max_rtt_timeout = MAX_RTT_TIMEOUT;
  min_rtt_timeout = MIN_RTT_TIMEOUT;
  initial_rtt_timeout = INITIAL_RTT_TIMEOUT;
  max_retransmissions = MAX_RETRANSMISSIONS;
  min_host_group_sz = 1;
  max_host_group_sz = 100000; // don't want to be restrictive unless user sets
  max_tcp_scan_delay = MAX_TCP_SCAN_DELAY;
  max_udp_scan_delay = MAX_UDP_SCAN_DELAY;
  max_sctp_scan_delay = MAX_SCTP_SCAN_DELAY;
  max_ips_to_scan = 0;
  extra_payload_length = 0;
  extra_payload = NULL;
  scan_delay = 0;
  open_only = false;
  scanflags = -1;
  defeat_rst_ratelimit = 0;
  resume_ip.s_addr = 0;
  osscan_limit = 0;
  osscan_guess = 0;
  numdecoys = 0;
  decoyturn = -1;
  osscan = 0;
  servicescan = 0;
  override_excludeports = 0;
  version_intensity = 7;
  pingtype = PINGTYPE_UNKNOWN;
  listscan = allowall = ackscan = bouncescan = connectscan = 0;
  nullscan = xmasscan = fragscan = synscan = windowscan = 0;
  maimonscan = idlescan = finscan = udpscan = ipprotscan = 0;
  noportscan = noresolve = 0;
  sctpinitscan = 0;
  sctpcookieechoscan = 0;
  append_output = 0;
  memset(logfd, 0, sizeof(FILE *) * LOG_NUM_FILES);
  ttl = -1;
  badsum = 0;
  nmap_stdout = stdout;
  gettimeofday(&start_time, NULL);
  pTrace = vTrace = false;
  reason = false;
  adler32 = false;
  if (datadir) free(datadir);
  datadir = NULL;
  xsl_stylesheet_set = false;
  if (xsl_stylesheet) free(xsl_stylesheet);
  xsl_stylesheet = NULL;
  spoof_mac_set = false;
  mass_dns = true;
  deprecated_xml_osclass = false;
  resolve_all = 0;
  dns_servers = NULL;
  implicitARPPing = true;
  numhosts_scanned = 0;
  numhosts_up = 0;
  numhosts_scanning = 0;
  noninteractive = false;
  current_scantype = STYPE_UNKNOWN;
  ipoptions = NULL;
  ipoptionslen = 0;
  ipopt_firsthop = 0;
  ipopt_lasthop  = 0;
  release_memory = false;
  topportlevel = -1;
#ifndef NOLUA
  script = 0;
  scriptargs = NULL;
  scriptversion = 0;
  scripttrace = 0;
  scriptupdatedb = 0;
  scripthelp = false;
  chosenScripts.clear();
#endif
  memset(&sourcesock, 0, sizeof(sourcesock));
  sourcesocklen = 0;
  excludefd = NULL;
  exclude_spec = NULL;
  inputfd = NULL;
  idleProxy = NULL;
  portlist = NULL;
  exclude_portlist = NULL;
  proxy_chain = NULL;
}

bool NmapOps::SCTPScan() {
  return sctpinitscan|sctpcookieechoscan;
}

bool NmapOps::TCPScan() {
  return ackscan|bouncescan|connectscan|finscan|idlescan|maimonscan|nullscan|synscan|windowscan|xmasscan;
}

bool NmapOps::UDPScan() {
  return udpscan;
}

bool NmapOps::RawScan() {
  if (ackscan||finscan||idlescan||ipprotscan||maimonscan||nullscan||osscan||synscan||udpscan||windowscan||xmasscan||sctpinitscan||sctpcookieechoscan||traceroute)
    return true;
  if (pingtype & (PINGTYPE_ICMP_PING|PINGTYPE_ICMP_MASK|PINGTYPE_ICMP_TS|PINGTYPE_TCP_USE_ACK|PINGTYPE_UDP|PINGTYPE_SCTP_INIT))
    return true;
  /* A SYN scan will only generate raw packets if nmap is running as root.
     Otherwise, it becomes a connect scan. */
  if ((pingtype & PINGTYPE_TCP_USE_SYN) && isr00t)
    return true;

   return false;
}


void NmapOps::ValidateOptions() {
        const char *privreq = "root privileges.";
#ifdef WIN32
        if (!have_pcap)
                privreq = "WinPcap version 3.1 or higher and\n\
iphlpapi.dll.  You seem to be missing one or both of these.  Winpcap is\n\
available from http://www.winpcap.org.  iphlpapi.dll comes with Win98 and\n\
later operating systems and NT 4.0 with SP4 or greater.  For previous Windows\n\
versions, you may be able to take iphlpapi.dll from another system and place\n\
it in your system32 dir (e.g. c:\\windows\\system32).\n\
On Windows Vista and Windows 7, The WinPcap NPF service must be started by an\n\
administrator before WinPcap can be used.  Running nmap.exe will open a UAC\n\
dialog where you can start NPF if you have administrator privileges.";
#endif


  /* Insure that at least one scantype is selected */
  if (!noportscan && !(TCPScan() || UDPScan() || SCTPScan() || ipprotscan)) {
    if (isr00t)
      synscan++;
    else connectscan++;
    //    if (verbose) error("No TCP, UDP, SCTP or ICMP scantype specified, assuming %s scan. Use -sn if you really don't want to portscan (and just want to see what hosts are up).", synscan? "SYN Stealth" : "vanilla tcp connect()");
  }

  if (pingtype != PINGTYPE_NONE && spoofsource) {
    error("WARNING: If -S is being used to fake your source address, you may also have to use -e <interface> and -Pn .  If you are using it to specify your real source address, you can ignore this warning.");
  }

  if (pingtype != PINGTYPE_NONE && idlescan) {
    error("WARNING: Many people use -Pn w/Idlescan to prevent pings from their true IP.  On the other hand, timing info Nmap gains from pings can allow for faster, more reliable scans.");
    sleep(2); /* Give ppl a chance for ^C :) */
  }

 if (numdecoys > 1 && idlescan) {
    error("WARNING: Your decoys won't be used in the Idlescan portion of your scanning (although all packets sent to the target are spoofed anyway");
  }

 if (connectscan && spoofsource) {
    error("WARNING: -S will only affect the source address used in a connect() scan if you specify one of your own addresses.  Use -sS or another raw scan if you want to completely spoof your source address, but then you need to know what you're doing to obtain meaningful results.");
  }

 if ((pingtype & PINGTYPE_UDP) && (!isr00t)) {
   fatal("Sorry, UDP Ping (-PU) only works if you are root (because we need to read raw responses off the wire)");
 }

 if ((pingtype & PINGTYPE_SCTP_INIT) && (!isr00t)) {
   fatal("Sorry, SCTP INIT Ping (-PY) only works if you are root (because we need to read raw responses off the wire)");
  }

 if ((pingtype & PINGTYPE_PROTO) && (!isr00t)) {
   fatal("Sorry, IPProto Ping (-PO) only works if you are root (because we need to read raw responses off the wire)");
 }

 if (ipprotscan && (TCPScan() || UDPScan() || SCTPScan())) {
   fatal("Sorry, the IPProtoscan (-sO) must currently be used alone rather than combined with other scan types.");
 }

 if (noportscan && (TCPScan() || UDPScan() || SCTPScan() || ipprotscan)) {
   fatal("-sL and -sn (skip port scan) are not valid with any other scan types");
 }

 if (af() == AF_INET6 && (pingtype & (PINGTYPE_ICMP_MASK|PINGTYPE_ICMP_TS))) {
   fatal("ICMP Timestamp and Address Mask pings are only valid for IPv4.");
 }

 if (sendpref == PACKET_SEND_NOPREF) {
#ifdef WIN32
   sendpref = PACKET_SEND_ETH_STRONG;
#else
   sendpref = PACKET_SEND_IP_WEAK;
#endif
 }
/* We start with stuff users should not do if they are not root */
  if (!isr00t) {

    if (ackscan|finscan|idlescan|ipprotscan|maimonscan|nullscan|synscan|udpscan|windowscan|xmasscan|sctpinitscan|sctpcookieechoscan) {
      fatal("You requested a scan type which requires %s", privreq);
    }

    if (numdecoys > 0) {
      fatal("Sorry, but decoys (-D) require %s", privreq);
    }

    if (fragscan) {
      fatal("Sorry, but fragscan requires %s", privreq);
    }

    if (osscan) {
      fatal("TCP/IP fingerprinting (for OS scan) requires %s", privreq);
    }
  }


  if (bouncescan && pingtype != PINGTYPE_NONE)
    log_write(LOG_STDOUT, "Hint: if your bounce scan target hosts aren't reachable from here, remember to use -Pn so we don't try and ping them prior to the scan\n");

  if (ackscan+bouncescan+connectscan+finscan+idlescan+maimonscan+nullscan+synscan+windowscan+xmasscan > 1)
    fatal("You specified more than one type of TCP scan.  Please choose only one of -sA, -b, -sT, -sF, -sI, -sM, -sN, -sS, -sW, and -sX");

  if (numdecoys > 0 && (bouncescan || connectscan)) {
    error("WARNING: Decoys are irrelevant to the bounce or connect scans");
  }

  if (fragscan && !(ackscan|finscan|maimonscan|nullscan|synscan|windowscan|xmasscan) && \
      !(pingtype&(PINGTYPE_ICMP_TS|PINGTYPE_TCP)) && !(fragscan == 8 && pingtype&PINGTYPE_ICMP_MASK) && \
      !(extra_payload_length + 8 > fragscan)) {
    fatal("Fragscan only works with TCP, ICMP Timestamp or ICMP Mask (mtu=8) ping types or ACK, FIN, Maimon, NULL, SYN, Window, and XMAS scan types");
  }

  if (osscan && bouncescan)
    error("Combining bounce scan with OS scan seems silly, but I will let you do whatever you want!");

#if !defined(LINUX) && !defined(OPENBSD) && !defined(FREEBSD) && !defined(NETBSD)
  if (fragscan) {
    error("Warning: Packet fragmentation selected on a host other than Linux, OpenBSD, FreeBSD, or NetBSD.  This may or may not work.");
  }
#endif

  if (osscan && noportscan) {
    fatal("WARNING: OS Scan is unreliable without a port scan.  You need to use a scan type along with it, such as -sS, -sT, -sF, etc instead of -sn");
  }

  if (osscan && ipprotscan) {
    error("WARNING: Disabling OS Scan (-O) as it is incompatible with the IPProto Scan (-sO)");
    osscan = 0;
  }

  if (servicescan && ipprotscan) {
    error("WARNING: Disabling Service Scan (-sV) as it is incompatible with the IPProto Scan (-sO)");
    servicescan = 0;
  }

  if (servicescan && noportscan)
    servicescan = 0;

  if (defeat_rst_ratelimit && !synscan) {
      fatal("Option --defeat-rst-ratelimit works only with a SYN scan (-sS)");
  }

  if (resume_ip.s_addr && generate_random_ips)
    resume_ip.s_addr = 0;

  if (magic_port_set && connectscan) {
    error("WARNING: -g is incompatible with the default connect() scan (-sT).  Use a raw scan such as -sS if you want to set the source port.");
  }

  if (max_parallelism && min_parallelism && (min_parallelism > max_parallelism)) {
    fatal("--min-parallelism=%i must be less than or equal to --max-parallelism=%i",min_parallelism,max_parallelism);
  }

  if (min_packet_send_rate != 0.0 && max_packet_send_rate != 0.0 && min_packet_send_rate > max_packet_send_rate) {
    fatal("--min-rate=%g must be less than or equal to --max-rate=%g", min_packet_send_rate, max_packet_send_rate);
  }

  if (af() == AF_INET6 && (generate_random_ips|bouncescan|fragscan)) {
    fatal("Random targets, FTP bounce scan, and fragmentation are not supported with IPv6.");
  }

  if(ipoptions && osscan)
    error("WARNING: IP options are NOT used while OS scanning!");

#ifndef NOLUA
  /* Make sure nmap.registry.args is available (even if it's empty) */
  if (!scriptargs)
    scriptargs = strdup("");
#endif
}

void NmapOps::setMaxOSTries(int mot) {
  if (mot <= 0)
    fatal("%s: value must be at least 1", __func__);
  max_os_tries = mot;
}

void NmapOps::setMaxRttTimeout(int rtt)
{
  if (rtt <= 0) fatal("%s: maximum round trip time must be greater than 0", __func__);
  max_rtt_timeout = rtt;
  if (rtt < min_rtt_timeout) min_rtt_timeout = rtt;
  if (rtt < initial_rtt_timeout) initial_rtt_timeout = rtt;
}

void NmapOps::setMinRttTimeout(int rtt)
{
  if (rtt < 0) fatal("%s: minimum round trip time must be at least 0", __func__);
  min_rtt_timeout = rtt;
  if (rtt > max_rtt_timeout) max_rtt_timeout = rtt;
  if (rtt > initial_rtt_timeout) initial_rtt_timeout = rtt;
}

void NmapOps::setInitialRttTimeout(int rtt)
{
  if (rtt <= 0) fatal("%s: initial round trip time must be greater than 0", __func__);
  initial_rtt_timeout = rtt;
  if (rtt > max_rtt_timeout) max_rtt_timeout = rtt;
  if (rtt < min_rtt_timeout) min_rtt_timeout = rtt;
}

void NmapOps::setMaxRetransmissions(int max_retransmit)
{
    if (max_retransmit < 0)
        fatal("%s: must be positive", __func__);
    max_retransmissions = max_retransmit;
}


void NmapOps::setMinHostGroupSz(unsigned int sz) {
  if (sz > max_host_group_sz)
    fatal("Minimum host group size may not be set to greater than maximum size (currently %d)\n", max_host_group_sz);
  min_host_group_sz = sz;
}

void NmapOps::setMaxHostGroupSz(unsigned int sz) {
  if (sz < min_host_group_sz)
    fatal("Maximum host group size may not be set to less than the minimum size (currently %d)\n", min_host_group_sz);
  if (sz <= 0)
    fatal("Max host size must be at least 1");
  max_host_group_sz = sz;
}

  /* Sets the Name of the XML stylesheet to be printed in XML output.
     If this is never called, a default stylesheet distributed with
     Nmap is used.  If you call it with NULL as the xslname, no
     stylesheet line is printed. */
void NmapOps::setXSLStyleSheet(const char *xslname) {
  if (xsl_stylesheet) free(xsl_stylesheet);
  xsl_stylesheet = xslname? strdup(xslname) : NULL;
  xsl_stylesheet_set = true;
}

/* Returns the full path or URL that should be printed in the XML
   output xml-stylesheet element.  Returns NULL if the whole element
   should be skipped */
char *NmapOps::XSLStyleSheet() {
  char tmpxsl[MAXPATHLEN];

  if (xsl_stylesheet_set)
    return xsl_stylesheet;

  if (nmap_fetchfile(tmpxsl, sizeof(tmpxsl), "nmap.xsl") == 1) {
    xsl_stylesheet = filename_to_url(tmpxsl);
  } else {
#if WIN32
    /* Use a relative URL on Windows if nmap_fetchfile failed. It won't work,
       but it gives a clue that there is an nmap.xsl somewhere. */
    Strncpy(tmpxsl, "nmap.xsl", sizeof(tmpxsl));
    xsl_stylesheet = strdup(tmpxsl);
#else
    Snprintf(tmpxsl, sizeof(tmpxsl), "%s/nmap.xsl", NMAPDATADIR);
    xsl_stylesheet = filename_to_url(tmpxsl);
#endif
  }

  return xsl_stylesheet;
}

void NmapOps::setSpoofMACAddress(u8 *mac_data) {
  memcpy(spoof_mac, mac_data, 6);
  spoof_mac_set = true;
}

#ifndef NOLUA
void NmapOps::chooseScripts(char* argument) {
        char *p;

        for (;;) {
                p = strchr(argument, ',');
                if (p == NULL) {
                        chosenScripts.push_back(std::string(argument));
                        break;
                } else {
                        chosenScripts.push_back(std::string(argument, p - argument));
                        argument = p + 1;
                }
        }
}
#endif
