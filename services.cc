
/***************************************************************************
 * services.cc -- Various functions relating to reading the nmap-services  *
 * file and port <-> service mapping                                       *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2006 Insecure.Com LLC. Nmap is    *
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
 * http://insecure.org/nmap/ to download Nmap.                             *
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
 * distribution.  By sending these changes to Fyodor or one the            *
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

#include "services.h"
#include "NmapOps.h"
#include "charpool.h"
#include "nmap_error.h"
#include "utils.h"

extern NmapOps o;
static int numtcpports = 0;
static int numudpports = 0;
static struct service_list *service_table[SERVICE_TABLE_SIZE];
static struct service_list *sorted_services = NULL;
static int services_initialized = 0;
static int ratio_format = 0; // 0 = /etc/services no-ratio format. 1 = new nmap format

static int nmap_services_init() {
  if (services_initialized) return 0;

  char filename[512];
  FILE *fp;
  char servicename[128], proto[16];
  u16 portno;
  char *p;
  char line[1024];
  int lineno = 0;
  struct service_list *current, *previous, *sp;
  int res;
  double ratio;
  int ratio_n, ratio_d;

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
		error("Get%sDirectory failed (%d) @#!#@\n",
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

  memset(service_table, 0, sizeof(service_table));
  
  while(fgets(line, sizeof(line), fp)) {
    lineno++;
    p = line;
    while(*p && isspace((int) *p))
      p++;
    if (*p == '#')
      continue;

    res = sscanf(line, "%127s %hu/%15s %d/%d", servicename, &portno, proto, &ratio_n, &ratio_d);

    if (res == 3) {
      ratio = 0;
    } else if (res == 5) {
      if (ratio_n < 0 || ratio_d < 0)
        fatal("%s:%d contains an invalid negative value", filename, lineno);

      if (ratio_n > ratio_d)
        fatal("%s:%d has a ratio %g. All ratios must be < 1", filename, lineno, (double)ratio_n/ratio_d);

      if (ratio_d == 0)
        fatal("%s:%d has a ratio denominator of 0 causing a division by 0 error", filename, lineno);

      ratio = (double)ratio_n / ratio_d;
      ratio_format = 1;
    } else {
      continue;
    }

    portno = htons(portno);

    /* Now we make sure our service table doesn't have duplicates */
    for(current = service_table[portno % SERVICE_TABLE_SIZE], previous = NULL;
	current; current = current->next) {
      if (portno == (u16) current->servent->s_port &&
	  strcasecmp(proto, current->servent->s_proto) == 0) {
	if (o.debugging) {
	  error("Port %d proto %s is duplicated in services file %s", ntohs(portno), proto, filename);
	}
	break;
      }
      previous = current;
    }
    /* Current service in the file was a duplicate, get another one */
    if (current)
      continue;

    if (strncasecmp(proto, "tcp", 3) == 0) {
      numtcpports++;
    } else if (strncasecmp(proto, "udp", 3) == 0) {
      numudpports++;
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

    current = (struct service_list *) cp_alloc(sizeof(struct service_list));
    current->servent = (struct servent *) cp_alloc(sizeof(struct servent));
    current->ratio = ratio;
    current->next = NULL;
    if (previous == NULL) {
      service_table[portno % SERVICE_TABLE_SIZE] = current;
    } else {
      previous->next = current;
    }
    current->servent->s_name = cp_strdup(servicename);
    current->servent->s_port = portno;
    current->servent->s_proto = cp_strdup(proto);
    current->servent->s_aliases = NULL;

    sp = (struct service_list *) cp_alloc(sizeof(struct service_list));
    sp->servent = current->servent;
    sp->ratio = current->ratio;
    sp->next = NULL;

    if (sorted_services == NULL || sorted_services->ratio < sp->ratio) {
      sp->next = sorted_services;
      sorted_services = sp;
    } else
      for (current=sorted_services;;current=current->next) {
        if (current->next == NULL) {
          current->next = sp;
          break;
        } else if (current->next->ratio < sp->ratio) {
          sp->next = current->next;
          current->next = sp;
          break;
        }
      }

  }

  fclose(fp);
  services_initialized = 1;
  return 0;
}


  
/* Adds ports whose names match mask and one or more protocols
 * specified by range_type to porttbl. Increases the respective
 * protocol counts in ports.
 * Returns the number of ports added in total.
 */

int addportsfromservmask(char *mask, u8 *porttbl, struct scan_lists *ports, int range_type) {
  struct service_list *current;
  int bucket,t=0;

  if (!services_initialized && nmap_services_init() == -1)
    fatal("%s: Couldn't get port numbers", __func__);
  
  for(bucket = 0; bucket < SERVICE_TABLE_SIZE; bucket++) {
    for(current = service_table[bucket % SERVICE_TABLE_SIZE]; current; current = current->next) {
      if (wildtest(mask, current->servent->s_name)) {

        if ((range_type & SCAN_TCP_PORT) && strcmp(current->servent->s_proto, "tcp") == 0) {
          porttbl[ntohs(current->servent->s_port)] |= SCAN_TCP_PORT;
          ports->tcp_count++;
          t++;
        }

        if ((range_type & SCAN_UDP_PORT) && strcmp(current->servent->s_proto, "udp") == 0) {
          porttbl[ntohs(current->servent->s_port)] |= SCAN_UDP_PORT;
          ports->udp_count++;
          t++;
        }

      }
    }
  }

  return t;

}



struct servent *nmap_getservbyport(int port, const char *proto) {
  struct service_list *current;

  if (nmap_services_init() == -1)
    return NULL;

  for(current = service_table[port % SERVICE_TABLE_SIZE];
	current; current = current->next) {
    if (((u16) port == (u16) current->servent->s_port) &&
	strcmp(proto, current->servent->s_proto) == 0)
      return current->servent;
  }

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

static int is_port_member(struct scan_lists *ptsdata, struct service_list *serv) {
  int i;

  if (serv->servent->s_proto[0] == 't') {
    for (i=0; i<ptsdata->tcp_count; i++)
      if (ntohs(serv->servent->s_port) == ptsdata->tcp_ports[i]) return 1;
  } else {
    for (i=0; i<ptsdata->udp_count; i++)
      if (ntohs(serv->servent->s_port) == ptsdata->udp_ports[i]) return 1;
  }

  return 0;
}

// gettoppts() returns a scan_list with the most common ports scanned by
// Nmap according to the ratios specified in the nmap-services file.
//
// If level is below 1.0 then we treat it as a minimum ratio and we
// add all ports with ratios above level.
//
// If level is 1 or above, we treat it as a "top ports" directive
// and return the N highest ratio ports (where N==level).
//
// This function doesn't support IP protocol scan so only call this
// function if o.TCPScan() || o.UDPScan()

struct scan_lists *gettoppts(double level, char *portlist) {
  int ti=0, ui=0;
  struct scan_lists *sl, *ptsdata=NULL;
  struct service_list *current;

  if (!services_initialized && nmap_services_init() == -1)
    fatal("%s: Couldn't get port numbers", __func__);

  if (ratio_format == 0) {
    if (level != -1)
      fatal("Unable to use --top-ports or --port-ratio with an old style (no-ratio) services file");

    if (portlist)
      return getpts(portlist);
    else if (o.fastscan)
      return getpts("[-]");
    else
      return getpts("1-1024,[1025-]");
  }

  // TOP PORT DEFAULTS
  if (level == -1) {
    if (portlist)
      return getpts(portlist);

    if (o.fastscan) level = 100;
    else level = 0.01;
  }

  sl = (struct scan_lists *) safe_zalloc(sizeof(struct scan_lists));
  if (portlist) ptsdata = getpts(portlist);

  if (level < 1) {
    for (current=sorted_services; current; current=current->next) {
      if (ptsdata && !is_port_member(ptsdata, current)) continue;

      if (current->ratio >= level) {
        if (o.TCPScan() && current->servent->s_proto[0] == 't') sl->tcp_count++;
        else if (o.UDPScan() && current->servent->s_proto[0] == 'u') sl->udp_count++;
      } else break;
    }

    if (sl->tcp_count)
      sl->tcp_ports = (unsigned short *)safe_zalloc(sl->tcp_count * sizeof(unsigned short));

    if (sl->udp_count)
      sl->udp_ports = (unsigned short *)safe_zalloc(sl->udp_count * sizeof(unsigned short));

    sl->prots = NULL;

    for (current=sorted_services;current;current=current->next) {
      if (ptsdata && !is_port_member(ptsdata, current)) continue;

      if (current->ratio >= level) {
        if (o.TCPScan() && current->servent->s_proto[0] == 't')
          sl->tcp_ports[ti++] = ntohs(current->servent->s_port);
        else if (o.UDPScan() && current->servent->s_proto[0] == 'u')
          sl->udp_ports[ui++] = ntohs(current->servent->s_port);
      } else break;
    }
  } else if (level >= 1) {
    if (level > 65536)
      fatal("Level argument to gettoppts (%g) is too large", level);

    if (o.TCPScan()) {
      sl->tcp_count = MIN((int) level, numtcpports);
      sl->tcp_ports = (unsigned short *)safe_zalloc(sl->tcp_count * sizeof(unsigned short));
    }

    if (o.UDPScan()) {
      sl->udp_count = MIN((int) level, numudpports);
      sl->udp_ports = (unsigned short *)safe_zalloc(sl->udp_count * sizeof(unsigned short));
    }

    sl->prots = NULL;

    for (current=sorted_services;current && (ti < sl->tcp_count || ui < sl->udp_count);current=current->next) {
      if (ptsdata && !is_port_member(ptsdata, current)) continue;

      if (o.TCPScan() && current->servent->s_proto[0] == 't' && ti < sl->tcp_count)
        sl->tcp_ports[ti++] = ntohs(current->servent->s_port);
      else if (o.UDPScan() && current->servent->s_proto[0] == 'u' && ui < sl->udp_count)
        sl->udp_ports[ui++] = ntohs(current->servent->s_port);
    }

    if (ti < sl->tcp_count) sl->tcp_count = ti;
    if (ui < sl->udp_count) sl->udp_count = ui;
  } else
    fatal("Argument to gettoppts (%g) should be a positive ratio below 1 or an integer of 1 or higher", level);

  if (ptsdata) free_scan_lists(ptsdata);

  if (sl->tcp_count > 1)
    qsort(sl->tcp_ports, sl->tcp_count, sizeof(unsigned short), &port_compare);

  if (sl->udp_count > 1)
    qsort(sl->udp_ports, sl->udp_count, sizeof(unsigned short), &port_compare);

  if (o.debugging && level < 1)
    log_write(LOG_STDOUT, "PORTS: Using ports open on %g%% or more average hosts (TCP:%d, UDP:%d)\n", level*100, sl->tcp_count, sl->udp_count);
  else if (o.debugging && level >= 1)
    log_write(LOG_STDOUT, "PORTS: Using top %d ports found open (TCP:%d, UDP:%d)\n", (int) level, sl->tcp_count, sl->udp_count);

  return sl;
}
