
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

extern NmapOps o;
static int numtcpports = 0;
static int numudpports = 0;
static struct service_list *service_table[SERVICE_TABLE_SIZE];

static int nmap_services_init() {
  static int services_initialized = 0;
  if (services_initialized) return 0;

  char filename[512];
  FILE *fp;
  char servicename[128], proto[16];
  u16 portno;
  char *p;
  char line[1024];
  int lineno = 0;
  struct service_list *current, *previous;
  int res;

  if (nmap_fetchfile(filename, sizeof(filename), "nmap-services") == -1) {
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

  memset(service_table, 0, sizeof(service_table));
  
  while(fgets(line, sizeof(line), fp)) {
    lineno++;
    p = line;
    while(*p && isspace((int) *p))
      p++;
    if (*p == '#')
      continue;
    res = sscanf(line, "%127s %hu/%15s", servicename, &portno, proto);
    if (res !=3)
      continue;
    portno = htons(portno);

    /* Now we make sure our services doesn't have duplicates */
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
  }
  fclose(fp);
  services_initialized = 1;
  return 0;
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

/* Be default we do all ports 1-1024 as well as any higher ports
   that are in the services file */
struct scan_lists *getdefaultports(int tcpscan, int udpscan) {
  int tcpportindex = 0;
  int udpportindex = 0;
  struct scan_lists *ports;
  u8 *usedports;
  struct service_list *current;
  int bucket;
  int tcpportsneeded = 0;
  int udpportsneeded = 0;

  if (nmap_services_init() == -1)
    fatal("Getfastports: Couldn't get port numbers");
  
  usedports = (u8 *) safe_zalloc(sizeof(*usedports) * 65536);

  for(bucket = 1; bucket < 1025; bucket++) {  
    if (tcpscan) {
      usedports[bucket] |= SCAN_TCP_PORT;
      tcpportsneeded++;
    }
    if (udpscan) {
      usedports[bucket] |= SCAN_UDP_PORT;
      udpportsneeded++;
    }
  }

  for(bucket = 0; bucket < SERVICE_TABLE_SIZE; bucket++) {  
    for(current = service_table[bucket % SERVICE_TABLE_SIZE];
	current; current = current->next) {
      if (tcpscan &&
	  ! (usedports[ntohs(current->servent->s_port)] & SCAN_TCP_PORT) &&
          ! strncmp(current->servent->s_proto, "tcp", 3)) {
	usedports[ntohs(current->servent->s_port)] |= SCAN_TCP_PORT;
	tcpportsneeded++;
      }
      if (udpscan && 
	  ! (usedports[ntohs(current->servent->s_port)] & SCAN_UDP_PORT) &&
	  !strncmp(current->servent->s_proto, "udp", 3)) {      
	usedports[ntohs(current->servent->s_port)] |= SCAN_UDP_PORT;
	udpportsneeded++;
      }
    }
  }

  ports = (struct scan_lists *) safe_zalloc(sizeof(struct scan_lists));
  if (tcpscan) 
    ports->tcp_ports = (unsigned short *) safe_zalloc((tcpportsneeded) * sizeof(unsigned short));
  if (udpscan) 
    ports->udp_ports = (unsigned short *) safe_zalloc((udpportsneeded) * sizeof(unsigned short));
  ports->tcp_count= tcpportsneeded;
  ports->udp_count= udpportsneeded;

  for(bucket = 0; bucket < 65536; bucket++) {
    if (usedports[bucket] & SCAN_TCP_PORT) 
      ports->tcp_ports[tcpportindex++] = bucket;
    if (usedports[bucket] & SCAN_UDP_PORT) 
      ports->udp_ports[udpportindex++] = bucket;
  }

  free(usedports);
  return ports;
}

struct scan_lists *getfastports(int tcpscan, int udpscan) {
  int tcpportindex = 0;
  int udpportindex = 0;
  struct scan_lists *ports;
  u8 *usedports;
  struct service_list *current;
  int bucket;
  int tcpportsneeded = 0;
  int udpportsneeded = 0;

  if (nmap_services_init() == -1)
    fatal("Getfastports: Couldn't get port numbers");
  
  usedports = (u8 *) safe_zalloc(sizeof(*usedports) * 65536);

  for(bucket = 0; bucket < SERVICE_TABLE_SIZE; bucket++) {  
    for(current = service_table[bucket % SERVICE_TABLE_SIZE];
	current; current = current->next) {
      if (tcpscan  &&
	  ! (usedports[ntohs(current->servent->s_port)] & SCAN_TCP_PORT) &&
	  !strncmp(current->servent->s_proto, "tcp", 3)) {
	usedports[ntohs(current->servent->s_port)] |= SCAN_TCP_PORT;
	tcpportsneeded++;
      }
      if (udpscan &&
	  ! (usedports[ntohs(current->servent->s_port)] & SCAN_UDP_PORT) &&
	  !strncmp(current->servent->s_proto, "udp", 3)) {      
	usedports[ntohs(current->servent->s_port)] |= SCAN_UDP_PORT;
	udpportsneeded++;
      }
    }
  }

  ports = (struct scan_lists *) safe_zalloc(sizeof(struct scan_lists));
  if (tcpscan) 
    ports->tcp_ports = (unsigned short *) safe_zalloc((tcpportsneeded) * sizeof(unsigned short));
  if (udpscan)
    ports->udp_ports = (unsigned short *) safe_zalloc((udpportsneeded) * sizeof(unsigned short));
  ports->tcp_count= tcpportsneeded;
  ports->udp_count= udpportsneeded;

  for(bucket = 0; bucket < 65536; bucket++) {
    if (usedports[bucket] & SCAN_TCP_PORT) 
      ports->tcp_ports[tcpportindex++] = bucket;
    if (usedports[bucket] & SCAN_UDP_PORT) 
      ports->udp_ports[udpportindex++] = bucket;
  }

  free(usedports);
  return ports;
}

