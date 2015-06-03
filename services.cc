
/***************************************************************************
 * services.cc -- Various functions relating to reading the nmap-services  *
 * file and port <-> service mapping                                       *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2015 Insecure.Com LLC. Nmap is    *
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
#include "services.h"
#include "NmapOps.h"
#include "charpool.h"
#include "nmap_error.h"
#include "utils.h"

#include <list>
#include <map>

/* This structure is the key for looking up services in the
   port/proto -> service map. */
struct port_spec {
  int portno;
  std::string proto;

  /* Sort in the usual nmap-services order. */
  bool operator<(const port_spec& other) const {
    if (this->portno < other.portno)
      return true;
    else if (this->portno > other.portno)
      return false;
    else
      return this->proto < other.proto;
  }
};

/* This is a servent augmented by a frequency ratio. */
struct service_node : public servent {
public:
  double ratio;
};

/* Compare the ratios of two service nodes for top-ports purposes. Larger ratios
   come before smaller. */
bool service_node_ratio_compare(const service_node& a, const service_node& b) {
  return a.ratio > b.ratio;
}

extern NmapOps o;
static int numtcpports;
static int numudpports;
static int numsctpports;
static std::map<port_spec, service_node> service_table;
static std::list<service_node> services_by_ratio;
static int services_initialized;
static int ratio_format; // 0 = /etc/services no-ratio format. 1 = new nmap format

static int nmap_services_init() {
  if (services_initialized) return 0;

  char filename[512];
  FILE *fp;
  char servicename[128], proto[16];
  u16 portno;
  char *p;
  char line[1024];
  int lineno = 0;
  int res;
  double ratio;
  int ratio_n, ratio_d;
  char ratio_str[32];

  numtcpports = 0;
  numudpports = 0;
  numsctpports = 0;
  service_table.clear();
  services_by_ratio.clear();
  ratio_format = 0;

  if (nmap_fetchfile(filename, sizeof(filename), "nmap-services") != 1) {
#ifndef WIN32
    error("Unable to find nmap-services!  Resorting to /etc/services");
    strcpy(filename, "/etc/services");
#else
        int len, wnt = GetVersion() < 0x80000000;
    error("Unable to find nmap-services!  Resorting to /etc/services");
        if(wnt)
                len = GetSystemDirectory(filename, 480);	//	be safe
        else
                len = GetWindowsDirectory(filename, 480);	//	be safe
        if(!len)
                error("Get%sDirectory failed (%d) @#!#@",
                 wnt ? "System" : "Windows", GetLastError());
        else
        {
                if(wnt)
                        strcpy(filename + len, "\\drivers\\etc\\services");
                else
                        strcpy(filename + len, "\\services");
        }
#endif
  }

  fp = fopen(filename, "r");
  if (!fp) {
    fatal("Unable to open %s for reading service information", filename);
  }
  /* Record where this data file was found. */
  o.loaded_data_files["nmap-services"] = filename;

  while(fgets(line, sizeof(line), fp)) {
    lineno++;
    p = line;
    while(*p && isspace((int) (unsigned char) *p))
      p++;
    if (*p == '#')
      continue;

    res = sscanf(line, "%127s %hu/%15s %31s", servicename, &portno, proto, ratio_str);

    if (res == 3) {
      ratio = 0;
    } else if (res == 4) {
      if (strchr(ratio_str, '/')) {
        res = sscanf(ratio_str, "%d/%d", &ratio_n, &ratio_d);
        if (res != 2)
          fatal("%s:%d contains invalid port ratio string: %s", filename, lineno, ratio_str);

        if (ratio_n < 0 || ratio_d < 0)
          fatal("%s:%d contains an invalid negative value", filename, lineno);

        if (ratio_n > ratio_d)
          fatal("%s:%d has a ratio %g. All ratios must be < 1", filename, lineno, (double)ratio_n/ratio_d);

        if (ratio_d == 0)
          fatal("%s:%d has a ratio denominator of 0 causing a division by 0 error", filename, lineno);

        ratio = (double)ratio_n / ratio_d;
        ratio_format = 1;
      } else if (strncmp(ratio_str, "0.", 2) == 0) {
        /* We assume the ratio is in floating point notation already */
        ratio = strtod(ratio_str, NULL);
        ratio_format = 1;
      } else {
        ratio = 0;
      }
    } else {
      continue;
    }

    port_spec ps;
    ps.portno = portno;
    ps.proto = proto;

    /* Now we make sure our service table doesn't have duplicates */
    std::map<port_spec, service_node>::iterator i;
    i = service_table.find(ps);
    if (i != service_table.end()) {
      if (o.debugging)
        error("Port %d proto %s is duplicated in services file %s", portno, proto, filename);
      continue;
    }

    if (strncasecmp(proto, "tcp", 3) == 0) {
      numtcpports++;
    } else if (strncasecmp(proto, "udp", 3) == 0) {
      numudpports++;
    } else if (strncasecmp(proto, "sctp", 4) == 0) {
      numsctpports++;
    } else if (strncasecmp(proto, "ddp", 3) == 0) {
      /* ddp is some apple thing...we don't "do" that */
    } else if (strncasecmp(proto, "divert", 6) == 0) {
      /* divert sockets are for freebsd's natd */
    } else if (strncasecmp(proto, "#", 1) == 0) {
      /* possibly misplaced comment, but who cares? */
    } else {
      if (o.debugging)
        error("Unknown protocol (%s) on line %d of services file %s.", proto, lineno, filename);
      continue;
    }

    struct service_node sn;

    sn.s_name = cp_strdup(servicename);
    sn.s_port = portno;
    sn.s_proto = cp_strdup(proto);
    sn.s_aliases = NULL;
    sn.ratio = ratio;

    service_table[ps] = sn;

    services_by_ratio.push_back(sn);
  }

  /* Sort the list of ports sorted by frequency for top-ports purposes. */
  services_by_ratio.sort(service_node_ratio_compare);

  fclose(fp);
  services_initialized = 1;
  return 0;
}

void free_services() {
  /* This doesn't free anything, because the service_table is allocated
     statically. It just marks the table as needing to be reinitialized because
     other things have been freed, for example the cp_strdup-allocated members
     of service_node. */
  services_initialized = 0;
}


/* Adds ports whose names match mask and one or more protocols
 * specified by range_type to porttbl. Increases the respective
 * protocol counts in ports.
 * Returns the number of ports added in total.
 */

int addportsfromservmask(char *mask, u8 *porttbl, int range_type) {
  std::map<port_spec, service_node>::iterator i;
  int t = 0;

  if (!services_initialized && nmap_services_init() == -1)
    fatal("%s: Couldn't get port numbers", __func__);

  for (i = service_table.begin(); i != service_table.end(); i++) {
    service_node& current = i->second;
    if (wildtest(mask, current.s_name)) {
      if ((range_type & SCAN_TCP_PORT) && strcmp(current.s_proto, "tcp") == 0) {
        porttbl[current.s_port] |= SCAN_TCP_PORT;
        t++;
      }
      if ((range_type & SCAN_UDP_PORT) && strcmp(current.s_proto, "udp") == 0) {
        porttbl[current.s_port] |= SCAN_UDP_PORT;
        t++;
      }
      if ((range_type & SCAN_SCTP_PORT) && strcmp(current.s_proto, "sctp") == 0) {
        porttbl[current.s_port] |= SCAN_SCTP_PORT;
        t++;
      }
    }
  }

  return t;
}



struct servent *nmap_getservbyport(int port, const char *proto) {
  std::map<port_spec, service_node>::iterator i;
  port_spec ps;

  if (nmap_services_init() == -1)
    return NULL;

  ps.portno = port;
  ps.proto = proto;
  i = service_table.find(ps);
  if (i != service_table.end())
    return &i->second;

  /* Couldn't find it ... oh well. */
  return NULL;
}



static int port_compare(const void *a, const void *b) {
  unsigned short ua = *((unsigned short *) a), ub = *((unsigned short *) b);
  if (ua > ub) return 1;
  else return -1;
}



// is_port_member() returns true if serv is an element of ptsdata.
// This could be implemented MUCH more efficiently but it should only be
// called when you use a non-default top-ports or port-ratio value TOGETHER WITH
// a -p portlist.

static bool is_port_member(const struct scan_lists *ptsdata, const struct service_node *serv) {
  int i;

  if (strcmp(serv->s_proto, "tcp") == 0) {
    for (i=0; i<ptsdata->tcp_count; i++)
      if (serv->s_port == ptsdata->tcp_ports[i])
        return true;
  } else if (strcmp(serv->s_proto, "udp") == 0) {
    for (i=0; i<ptsdata->udp_count; i++)
      if (serv->s_port == ptsdata->udp_ports[i])
        return true;
  } else if (strcmp(serv->s_proto, "sctp") == 0) {
    for (i=0; i<ptsdata->sctp_count; i++)
      if (serv->s_port == ptsdata->sctp_ports[i])
        return true;
  }

  return false;
}

// gettoppts() sets its third parameter, a scan_list, with the most
// common ports scanned by Nmap according to the ratios specified in
// the nmap-services file.
//
// If level is below 1.0 then we treat it as a minimum ratio and we
// add all ports with ratios above level.
//
// If level is 1 or above, we treat it as a "top ports" directive
// and return the N highest ratio ports (where N==level).
//
// If the fourth parameter is not NULL, then the specified ports
// are excluded first and only then are the top N ports taken
//
// This function doesn't support IP protocol scan so only call this
// function if o.TCPScan() || o.UDPScan() || o.SCTPScan()

void gettoppts(double level, char *portlist, struct scan_lists * ports, char *exclude_ports) {
  int ti=0, ui=0, si=0;
  struct scan_lists ptsdata = { 0 };
  bool ptsdata_initialized = false;
  const struct service_node *current;
  std::list<service_node>::iterator i;

  if (!services_initialized && nmap_services_init() == -1)
    fatal("%s: Couldn't get port numbers", __func__);

  if (ratio_format == 0) {
    if (level != -1)
      fatal("Unable to use --top-ports or --port-ratio with an old style (no-ratio) services file");

    if (portlist){
      getpts(portlist, ports);
      return;
    }else if (o.fastscan){
      getpts("[-]", ports);
      return;
    }else{
      getpts("1-1024,[1025-]", ports);
      return;
    }
  }

  // TOP PORT DEFAULTS
  if (level == -1) {
    if (portlist){
      getpts(portlist, ports);
      return;
    }
    if (o.fastscan) level = 100;
    else level = 1000;
  }

  if (portlist){
    getpts(portlist, &ptsdata);
    ptsdata_initialized = true;
  } else if (exclude_ports) {
    getpts("-", &ptsdata);
    ptsdata_initialized = true;
  }

  if (ptsdata_initialized && exclude_ports)
    removepts(exclude_ports, &ptsdata);

  if (level < 1) {
    for (i = services_by_ratio.begin(); i != services_by_ratio.end(); i++) {
      current = &(*i);
      if (ptsdata_initialized && !is_port_member(&ptsdata, current))
        continue;
      if (current->ratio >= level) {
        if (o.TCPScan() && strcmp(current->s_proto, "tcp") == 0)
          ports->tcp_count++;
        else if (o.UDPScan() && strcmp(current->s_proto, "udp") == 0)
          ports->udp_count++;
        else if (o.SCTPScan() && strcmp(current->s_proto, "sctp") == 0)
          ports->sctp_count++;
      } else {
        break;
      }
    }

    if (ports->tcp_count)
      ports->tcp_ports = (unsigned short *)safe_zalloc(ports->tcp_count * sizeof(unsigned short));

    if (ports->udp_count)
      ports->udp_ports = (unsigned short *)safe_zalloc(ports->udp_count * sizeof(unsigned short));

    if (ports->sctp_count)
      ports->sctp_ports = (unsigned short *)safe_zalloc(ports->sctp_count * sizeof(unsigned short));

    ports->prots = NULL;

    for (i = services_by_ratio.begin(); i != services_by_ratio.end(); i++) {
      current = &(*i);
      if (ptsdata_initialized && !is_port_member(&ptsdata, current))
        continue;
      if (current->ratio >= level) {
        if (o.TCPScan() && strcmp(current->s_proto, "tcp") == 0)
          ports->tcp_ports[ti++] = current->s_port;
        else if (o.UDPScan() && strcmp(current->s_proto, "udp") == 0)
          ports->udp_ports[ui++] = current->s_port;
        else if (o.SCTPScan() && strcmp(current->s_proto, "sctp") == 0)
          ports->sctp_ports[si++] = current->s_port;
      } else {
        break;
      }
    }
  } else if (level >= 1) {
    if (level > 65536)
      fatal("Level argument to gettoppts (%g) is too large", level);

    if (o.TCPScan()) {
      ports->tcp_count = MIN((int) level, numtcpports);
      ports->tcp_ports = (unsigned short *)safe_zalloc(ports->tcp_count * sizeof(unsigned short));
    }
    if (o.UDPScan()) {
      ports->udp_count = MIN((int) level, numudpports);
      ports->udp_ports = (unsigned short *)safe_zalloc(ports->udp_count * sizeof(unsigned short));
    }
    if (o.SCTPScan()) {
      ports->sctp_count = MIN((int) level, numsctpports);
      ports->sctp_ports = (unsigned short *)safe_zalloc(ports->sctp_count * sizeof(unsigned short));
    }

    ports->prots = NULL;

    for (i = services_by_ratio.begin(); i != services_by_ratio.end(); i++) {
      current = &(*i);
      if (ptsdata_initialized && !is_port_member(&ptsdata, current))
        continue;
      if (o.TCPScan() && strcmp(current->s_proto, "tcp") == 0 && ti < ports->tcp_count)
        ports->tcp_ports[ti++] = current->s_port;
      else if (o.UDPScan() && strcmp(current->s_proto, "udp") == 0 && ui < ports->udp_count)
        ports->udp_ports[ui++] = current->s_port;
      else if (o.SCTPScan() && strcmp(current->s_proto, "sctp") == 0 && si < ports->sctp_count)
        ports->sctp_ports[si++] = current->s_port;
    }

    if (ti < ports->tcp_count) ports->tcp_count = ti;
    if (ui < ports->udp_count) ports->udp_count = ui;
    if (si < ports->sctp_count) ports->sctp_count = si;
  } else
    fatal("Argument to gettoppts (%g) should be a positive ratio below 1 or an integer of 1 or higher", level);

  if (ptsdata_initialized) {
    free_scan_lists(&ptsdata);
    ptsdata_initialized = false;
  }

  if (ports->tcp_count > 1)
    qsort(ports->tcp_ports, ports->tcp_count, sizeof(unsigned short), &port_compare);

  if (ports->udp_count > 1)
    qsort(ports->udp_ports, ports->udp_count, sizeof(unsigned short), &port_compare);

  if (ports->sctp_count > 1)
    qsort(ports->sctp_ports, ports->sctp_count, sizeof(unsigned short), &port_compare);

  if (o.debugging && level < 1)
    log_write(LOG_STDOUT, "PORTS: Using ports open on %g%% or more average hosts (TCP:%d, UDP:%d, SCTP:%d)\n", level*100, ports->tcp_count, ports->udp_count, ports->sctp_count);
  else if (o.debugging && level >= 1)
    log_write(LOG_STDOUT, "PORTS: Using top %d ports found open (TCP:%d, UDP:%d, SCTP:%d)\n", (int) level, ports->tcp_count, ports->udp_count, ports->sctp_count);
}
