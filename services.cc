
/***************************************************************************
 * services.cc -- Various functions relating to reading the nmap-services  *
 * file and port <-> service mapping                                       *
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

#include "scan_lists.h"
#include "services.h"
#include "protocols.h"
#include "NmapOps.h"
#include "string_pool.h"
#include "nmap_error.h"
#include "utils.h"

#include <list>
#include <map>
#include <iterator>
#include <algorithm>

/* This structure is the key for looking up services in the
   port/proto -> service map. */
union port_spec {
    struct {
      u16 portno;
      u16 proto;
    } p;
    u32 compval;
};

/* This is a nservent augmented by a frequency ratio. */
struct service_node : public nservent {
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
typedef std::map<u32, service_node> ServiceMap;
static ServiceMap service_table;
static std::list<service_node> services_by_ratio;
static int services_initialized;
static int ratio_format; // 0 = /etc/services no-ratio format. 1 = new nmap format

static int nmap_services_init() {
  if (services_initialized) return 0;

  char filename[512];
  FILE *fp;
  char servicename[128] = { 0 }, proto[16] = { 0 };
  u16 portno;
  const char *p;
  char line[1024];
  int lineno = 0;
  int res;
  double ratio;
  int ratio_n, ratio_d;
  char ratio_str[32] = { 0 };

  numtcpports = 0;
  numudpports = 0;
  numsctpports = 0;
  service_table.clear();
  services_by_ratio.clear();
  ratio_format = 0;

  if (nmap_fetchfile(filename, sizeof(filename), "nmap-services") != 1) {
    error("Unable to find nmap-services!  Resorting to /etc/services");
#ifndef WIN32
    strcpy(filename, "/etc/services");
#else
    int len = GetSystemDirectory(filename, 480);	//	be safe
    if(!len)
      fatal("GetSystemDirectory failed (%d) @#!#@", GetLastError());
    else
      strcpy(filename + len, "\\drivers\\etc\\services");
#endif
  }

  fp = fopen(filename, "r");
  if (!fp) {
    pfatal("Unable to open %s for reading service information", filename);
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

    // lowercase in-place
    *(u32 *)proto = (*(u32 *)proto) | 0x20202020;
    if (proto[3] == 0x20) proto[3] = '\0';
    const struct nprotoent *npe = nmap_getprotbyname(proto);
    int *port_count = NULL;
    switch (npe ? npe->p_proto : -1) {
      case IPPROTO_TCP:
        port_count = &numtcpports;
        break;
      case IPPROTO_UDP:
        port_count = &numudpports;
        break;
      case IPPROTO_SCTP:
        port_count = &numsctpports;
        break;
      default:
        // ignore a few known protos from system services files
        if (o.debugging
            && strncasecmp(proto, "ddp", 3) != 0
            /* ddp is some apple thing...we don't "do" that */
            && strncasecmp(proto, "divert", 6) != 0
            /* divert sockets are for freebsd's natd */
            && proto[0] != '#') /* possibly misplaced comment, but who cares? */
        {
          error("Unknown protocol (%s) on line %d of services file %s.", proto, lineno, filename);
        }
        continue;
        break;
    }

    port_spec ps;
    ps.p.portno = portno;
    ps.p.proto = npe->p_proto;


    struct service_node sn;

    if (strcmp(servicename, "unknown") == 0) {
      // there are a ton (15K+) of ports in our db with this service name, and
      // we already write "unknown" if this is NULL, so don't bother allocating
      // space for it.
      sn.s_name = NULL;
    }
    else {
      sn.s_name = string_pool_insert(servicename);
    }
    sn.s_port = portno;
    sn.s_proto = npe->p_name;
    sn.ratio = ratio;

    std::pair<ServiceMap::iterator, bool> status = service_table.insert(
        ServiceMap::value_type(ps.compval, sn));

    if (!status.second) {
      if (o.debugging > 1) {
        error("Port %d proto %s is duplicated in services file %s", portno, proto, filename);
      }
      continue;
    }
    /* Now we make sure our service table doesn't have duplicates */

    *port_count += 1;

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

int addportsfromservmask(const char *mask, u8 *porttbl, int range_type) {
  ServiceMap::const_iterator i;
  const char *name = NULL;
  int t = 0;

  if (!services_initialized && nmap_services_init() == -1)
    fatal("%s: Couldn't get port numbers", __func__);

  for (i = service_table.begin(); i != service_table.end(); i++) {
    const service_node& current = i->second;
    if (!current.s_name)
      name = "unknown";
    else
      name = current.s_name;
    if (wildtest(mask, name)) {
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



const struct nservent *nmap_getservbyport(u16 port, u16 proto) {
  ServiceMap::const_iterator i;
  port_spec ps;

  if (nmap_services_init() == -1)
    return NULL;

  ps.p.portno = port;
  ps.p.proto = proto;
  i = service_table.find(ps.compval);
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


template <typename T>
class C_array_iterator: public std::iterator<std::random_access_iterator_tag, T, std::ptrdiff_t> {
  T *ptr;
  public:
  C_array_iterator(T *_ptr=NULL) : ptr(_ptr) {}
  C_array_iterator(const C_array_iterator &other) : ptr(other.ptr) {}
  C_array_iterator& operator=(T *_ptr) {ptr = _ptr; return *this;}
  C_array_iterator& operator++() {ptr++; return *this;}
  C_array_iterator operator++(int) {C_array_iterator retval = *this; ++(*this); return retval;}
  C_array_iterator& operator--() {ptr--; return *this;}
  C_array_iterator operator--(int) {C_array_iterator retval = *this; --(*this); return retval;}
  bool operator==(const C_array_iterator &other) const {return ptr == other.ptr;}
  bool operator!=(const C_array_iterator &other) const {return !(*this == other);}
  bool operator<(const C_array_iterator &other) const {return ptr < other.ptr;}
  C_array_iterator& operator+=(std::ptrdiff_t n) {ptr += n; return *this;}
  C_array_iterator& operator-=(std::ptrdiff_t n) {ptr -= n; return *this;}
  std::ptrdiff_t operator+(const C_array_iterator &other) {return ptr + other.ptr;}
  std::ptrdiff_t operator-(const C_array_iterator &other) {return ptr - other.ptr;}
  T& operator*() const {return *ptr;}
};

// is_port_member() returns true if serv->s_port is an element of pts.
static bool is_port_member(unsigned short *pts, int count, const struct service_node *serv) {
  C_array_iterator<unsigned short> begin = pts;
  C_array_iterator<unsigned short> end = pts + count;
  return std::binary_search(begin, end, serv->s_port);
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

void gettoppts(double level, const char *portlist, struct scan_lists * ports, const char *exclude_ports) {
  struct scan_lists ptsdata = { 0 };
  bool ptsdata_initialized = false;
  const struct service_node *current;
  std::list<service_node>::const_iterator i;

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

  /* Max number of ports for each protocol cannot be more than the minimum of:
   * 1. all of them (65536)
   * 2. requested ports (ptsdata)
   * 3. the number in services db (numXXXports)
   */
  int tcpmax = o.TCPScan() ? (ptsdata_initialized ? ptsdata.tcp_count : 65536) : 0;
  tcpmax = MIN(tcpmax, numtcpports);
  int udpmax = o.UDPScan() ? (ptsdata_initialized ? ptsdata.udp_count : 65536) : 0;
  udpmax = MIN(udpmax, numudpports);
  int sctpmax = o.SCTPScan() ? (ptsdata_initialized ? ptsdata.sctp_count : 65536) : 0;
  sctpmax = MIN(sctpmax, numsctpports);

  // If level is positive integer, it's the max number of ports.
  if (level >= 1) {
    if (level > 65536)
      fatal("Level argument to gettoppts (%g) is too large", level);
    tcpmax = MIN((int) level, tcpmax);
    udpmax = MIN((int) level, udpmax);
    sctpmax = MIN((int) level, sctpmax);
    // Now force the ratio comparison to always be true:
    level = 0;
  }
  else if (level <= 0) {
    fatal("Argument to gettoppts (%g) should be a positive ratio below 1 or an integer of 1 or higher", level);
  }
  // else level is a ratio between 0 and 1

  // These could be 0/false if the scan type was not requested.
  if (tcpmax) {
    ports->tcp_ports = (unsigned short *)safe_zalloc(tcpmax * sizeof(unsigned short));
  }
  if (udpmax) {
    ports->udp_ports = (unsigned short *)safe_zalloc(udpmax * sizeof(unsigned short));
  }
  if (sctpmax) {
    ports->sctp_ports = (unsigned short *)safe_zalloc(sctpmax * sizeof(unsigned short));
  }

  ports->prots = NULL;

  // Loop until we get enough or run out of candidates
  for (i = services_by_ratio.begin(); i != services_by_ratio.end() && (tcpmax || udpmax || sctpmax); i++) {
    current = &(*i);
    if (current->ratio < level) {
      break;
    }
    switch (current->s_proto[0]) {
      case 't':
        if (tcpmax && strcmp(current->s_proto, "tcp") == 0
            && (!ptsdata_initialized ||
              is_port_member(ptsdata.tcp_ports, ptsdata.tcp_count, current))
           ) {
          ports->tcp_ports[ports->tcp_count++] = current->s_port;
          tcpmax--;
        }
        break;
      case 'u':
        if (udpmax && strcmp(current->s_proto, "udp") == 0
            && (!ptsdata_initialized ||
              is_port_member(ptsdata.udp_ports, ptsdata.udp_count, current))
           ) {
          ports->udp_ports[ports->udp_count++] = current->s_port;
          udpmax--;
        }
        break;
      case 's':
        if (sctpmax && strcmp(current->s_proto, "sctp") == 0
            && (!ptsdata_initialized ||
              is_port_member(ptsdata.sctp_ports, ptsdata.sctp_count, current))
           ) {
          ports->sctp_ports[ports->sctp_count++] = current->s_port;
          sctpmax--;
        }
        break;
      default:
        break;
    }
  }

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
