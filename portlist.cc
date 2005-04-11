
/***************************************************************************
 * portlist.cc -- Functions for manipulating various lists of ports        *
 * maintained internally by Nmap.                                          *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2004 Insecure.Com LLC. Nmap       *
 * is also a registered trademark of Insecure.Com LLC.  This program is    *
 * free software; you may redistribute and/or modify it under the          *
 * terms of the GNU General Public License as published by the Free        *
 * Software Foundation; Version 2.  This guarantees your right to use,     *
 * modify, and redistribute this software under certain conditions.  If    *
 * you wish to embed Nmap technology into proprietary software, we may be  *
 * willing to sell alternative licenses (contact sales@insecure.com).      *
 * Many security scanner vendors already license Nmap technology such as  *
 * our remote OS fingerprinting database and code, service/version         *
 * detection system, and port scanning code.                               *
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
 * http://www.insecure.org/nmap/ to download Nmap.                         *
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
 * applications and appliances.  These contracts have been sold to many    *
 * security vendors, and generally include a perpetual license as well as  *
 * providing for priority support and updates as well as helping to fund   *
 * the continued development of Nmap technology.  Please email             *
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


#include "portlist.h"
#include "nmap_error.h"
#include "nmap.h"
#include "NmapOps.h"

#if HAVE_STRINGS_H
#include <strings.h>
#endif /* HAVE_STRINGS_H */

extern NmapOps o;  /* option structure */

Port::Port() {
  portno = proto = 0;
  owner = NULL;
  rpc_status = RPC_STATUS_UNTESTED;
  rpc_program = rpc_lowver = rpc_highver = 0;
  state = confidence = 0;
  next = NULL;
  serviceprobe_results = PROBESTATE_INITIAL;
  serviceprobe_service = NULL;
  serviceprobe_product = serviceprobe_version = serviceprobe_extrainfo = NULL;
  serviceprobe_tunnel = SERVICE_TUNNEL_NONE;
  serviceprobe_fp = NULL;
}

Port::~Port() {
 if (owner)
   free(owner);
 if (serviceprobe_product)
   free(serviceprobe_product);
 if (serviceprobe_version)
   free(serviceprobe_version);
 if (serviceprobe_extrainfo)
   free(serviceprobe_extrainfo);
 if (serviceprobe_service)
   free(serviceprobe_service);
 if (serviceprobe_fp)
   free(serviceprobe_fp);
}

// Uses the sd->{product,version,extrainfo} if available to fill
// out sd->fullversion.  If unavailable, it will be set to zero length.
static void populateFullVersionString(struct serviceDeductions *sd) {
  char *dst = sd->fullversion;
  char *end = sd->fullversion + sizeof(sd->fullversion);
  int len;

  if (sd->product) {
    len = strlen(sd->product);
    len = MIN((int) sizeof(sd->fullversion) - 1, len);
    memcpy(dst, sd->product, len);
    dst += len;
  }

  if (sd->version && dst < end - 1) {
    if (dst != sd->fullversion)
      *(dst++) = ' ';
    len = strlen(sd->version);
    len = MIN(len, end - dst - 1);
    memcpy(dst, sd->version, len);
    dst += len;
  }

  if (sd->extrainfo && dst < end) {
    len = strlen(sd->extrainfo);
    if (len < end - dst - 4) { // 4 == " ()\0"
      if (dst != sd->fullversion)
	*(dst++) = ' ';
      *(dst++) = '(';
      memcpy(dst, sd->extrainfo, len);
      dst += len;
      *(dst++) = ')';
    }
  }

  *(dst++) = '\0'; // Will always have space
}


// pass in an allocated struct serviceDeductions (don't wory about
// initializing, and you don't have to free any inernal ptrs.  See the
// serviceDeductions definition for the fields that are populated.
// Returns 0 if at least a name is available.
int Port::getServiceDeductions(struct serviceDeductions *sd) {
  struct servent *service;

  assert(sd);
  memset(sd, 0, sizeof(struct serviceDeductions));
  sd->service_fp = serviceprobe_fp;
  sd->service_tunnel = serviceprobe_tunnel;
  sd->rpc_status = rpc_status;
  sd->rpc_program = rpc_program;
  sd->rpc_lowver = rpc_lowver;
  sd->rpc_highver = rpc_highver;

  // First priority is RPC
  if (rpc_status == RPC_STATUS_UNKNOWN || rpc_status == RPC_STATUS_GOOD_PROG ) {
    assert(serviceprobe_service);
    sd->name = serviceprobe_service;
    sd->name_confidence = (rpc_status == RPC_STATUS_UNKNOWN)? 8 : 10;
    sd->dtype = SERVICE_DETECTION_PROBED; // RPC counts as probed
    sd->version = serviceprobe_version;
    sd->extrainfo = serviceprobe_extrainfo;
    populateFullVersionString(sd);
    return 0;
  } else if (serviceprobe_results == PROBESTATE_FINISHED_HARDMATCHED
	     || serviceprobe_results == PROBESTATE_FINISHED_SOFTMATCHED) {
    assert(serviceprobe_service);
    sd->dtype = SERVICE_DETECTION_PROBED;
    sd->name = serviceprobe_service;
    sd->name_confidence = 10;
    sd->product = serviceprobe_product;
    sd->version = serviceprobe_version;
    sd->extrainfo = serviceprobe_extrainfo;
    populateFullVersionString(sd);
    return 0;
  } else if (serviceprobe_results == PROBESTATE_FINISHED_TCPWRAPPED) {
    sd->dtype = SERVICE_DETECTION_PROBED;
    sd->name = "tcpwrapped";
    sd->name_confidence = 8;
    return 0;
  }

  // So much for service detection or RPC.  Maybe we can find it in the file
  service = nmap_getservbyport(htons(portno), (proto == IPPROTO_TCP)? "tcp" : "udp");
  if (service) {
    sd->dtype = SERVICE_DETECTION_TABLE;
    sd->name = service->s_name;
    sd->name_confidence = 3;
    return 0;
  }
  
  // Couldn't find it.  [shrug]
  return -1;

}


// sname should be NULL if sres is not
// PROBESTATE_FINISHED_MATCHED. product,version, and/or extrainfo
// will be NULL if unavailable. Note that this function makes its
// own copy of sname and product/version/extrainfo.  This function
// also takes care of truncating the version strings to a
// 'reasonable' length if neccessary, and cleaning up any unprinable
// chars. (these tests are to avoid annoying DOS (or other) attacks
// by malicious services).  The fingerprint should be NULL unless
// one is available and the user should submit it.  tunnel must be
// SERVICE_TUNNEL_NULL (normal) or SERVICE_TUNNEL_SSL (means ssl was
// detected and we tried to tunnel through it ).
void Port::setServiceProbeResults(enum serviceprobestate sres, 
				  const char *sname,	
				  enum service_tunnel_type tunnel, 
				  const char *product, const char *version, 
				  const char *extrainfo,
				  const char *fingerprint) {

  int slen;
  serviceprobe_results = sres;
  unsigned char *p;
  serviceprobe_tunnel = tunnel;
  if (sname) serviceprobe_service = strdup(sname);
  if (fingerprint) serviceprobe_fp = strdup(fingerprint);

  if (product) {
    slen = strlen(product);
    if (slen > 64) slen = 64;
    serviceprobe_product = (char *) safe_malloc(slen + 1);
    memcpy(serviceprobe_product, product, slen);
    serviceprobe_product[slen] = '\0';
    p = (unsigned char *) serviceprobe_product;
    while(*p) {
      if (!isprint((int)*p)) *p = '.';
      p++;
    }
  }

  if (version) {
    slen = strlen(version);
    if (slen > 64) slen = 64;
    serviceprobe_version = (char *) safe_malloc(slen + 1);
    memcpy(serviceprobe_version, version, slen);
    serviceprobe_version[slen] = '\0';
    p = (unsigned char *) serviceprobe_version;
    while(*p) {
      if (!isprint((int)*p)) *p = '.';
      p++;
    }
  }

  if (extrainfo) {
    slen = strlen(extrainfo);
    if (slen > 128) slen = 128;
    serviceprobe_extrainfo = (char *) safe_malloc(slen + 1);
    memcpy(serviceprobe_extrainfo, extrainfo, slen);
    serviceprobe_extrainfo[slen] = '\0';
    p = (unsigned char *) serviceprobe_extrainfo;
    while(*p) {
      if (!isprint((int)*p)) *p = '.';
      p++;
    }
  }

}

/* Sets the results of an RPC scan.  if rpc_status is not
   RPC_STATUS_GOOD_PROGRAM, pass 0 for the other args.  This function
   takes care of setting the port's service and version appropriately. */
void Port::setRPCProbeResults(int rpcs, unsigned long rpcp, 
			unsigned int rpcl, unsigned int rpch) {
  rpc_status = rpcs;
  const char *newsvc;
  char verbuf[128];

  rpc_status = rpcs;
  if (rpc_status == RPC_STATUS_GOOD_PROG) {
    rpc_program = rpcp;
    rpc_lowver = rpcl;
    rpc_highver = rpch;

    // Now set the service/version info
    newsvc = nmap_getrpcnamebynum(rpcp);
    if (!newsvc) newsvc = "rpc.unknownprog"; // should never happen
    if (serviceprobe_service)
      free(serviceprobe_service);
    serviceprobe_service = strdup(newsvc);
    serviceprobe_product = strdup(newsvc);
    if (rpc_lowver == rpc_highver)
      snprintf(verbuf, sizeof(verbuf), "%i", rpc_lowver);
    else
      snprintf(verbuf, sizeof(verbuf), "%i-%i", rpc_lowver, rpc_highver);
    serviceprobe_version = strdup(verbuf);
    snprintf(verbuf, sizeof(verbuf), "rpc #%li", rpc_program);
    serviceprobe_extrainfo = strdup(verbuf);
  } else if (rpc_status == RPC_STATUS_UNKNOWN) {
    if (serviceprobe_service)
      free(serviceprobe_service);
    
    serviceprobe_service = strdup("rpc.unknown");
  }
}

PortList::PortList() {
  udp_ports = tcp_ports = ip_prots = NULL;
  memset(state_counts, 0, sizeof(state_counts));
  memset(state_counts_udp, 0, sizeof(state_counts_udp));
  memset(state_counts_tcp, 0, sizeof(state_counts_tcp));
  memset(state_counts_ip, 0, sizeof(state_counts_ip));
  numports = 0;
  idstr = NULL;
}

PortList::~PortList() {
  int i;

  if (tcp_ports) {  
    for(i=0; i < 65536; i++) {
      if (tcp_ports[i])
	delete tcp_ports[i];
    }
    free(tcp_ports);
    tcp_ports = NULL;
  }

  if (udp_ports) {  
    for(i=0; i < 65536; i++) {
      if (udp_ports[i])
	delete udp_ports[i];
    }
    free(udp_ports);
    udp_ports = NULL;
  }

  if (ip_prots) {
    for(i=0; i < 256; ++i) {
      if (ip_prots[i])
	delete ip_prots[i];
    }
    free(ip_prots);
    ip_prots = NULL;
  }

  if (idstr) { 
    free(idstr);
    idstr = NULL;
  }

}


int PortList::addPort(u16 portno, u8 protocol, char *owner, int state) {
  Port *current = NULL;
  Port **portarray = NULL;
  char msg[128];

  assert(state < PORT_HIGHEST_STATE);

  if ((state == PORT_OPEN && o.verbose) || (o.debugging > 1)) {
    if (owner && *owner) {
      snprintf(msg, sizeof(msg), " (owner: %s)", owner);
    } else msg[0] = '\0';
    
    log_write(LOG_STDOUT, "Discovered %s port %hu/%s%s%s\n",
	      statenum2str(state), portno, 
	      proto2ascii(protocol), msg, idstr? idstr : "");
    log_flush(LOG_STDOUT);
    
    /* Write out add port messages for XML format so wrapper libraries
       can use it and not have to parse LOG_STDOUT ;), which is a
       pain! REMOVED now that Nmap scans multiple hosts in parallel.
       This addport does not even tell which host the new port was
       on. */    
    //    log_write(LOG_XML, "<addport state=\"%s\" portid=\"%hu\" protocol=\"%s\" owner=\"%s\"/>\n", statenum2str(state), portno, proto2ascii(protocol), ((owner && *owner) ? owner : ""));
    log_flush(LOG_XML); 
  }


/* Make sure state is OK */
  if (state != PORT_OPEN && state != PORT_CLOSED && state != PORT_FILTERED &&
      state != PORT_UNFILTERED && state != PORT_OPENFILTERED && 
      state != PORT_CLOSEDFILTERED)
    fatal("addPort: attempt to add port number %d with illegal state %d\n", portno, state);

  if (protocol == IPPROTO_TCP) {
    if (!tcp_ports) {
      tcp_ports = (Port **) safe_zalloc(65536 * sizeof(Port *));
    }
    portarray = tcp_ports;
  } else if (protocol == IPPROTO_UDP) {
    if (!udp_ports) {
      udp_ports = (Port **) safe_zalloc(65536 * sizeof(Port *));
    }
    portarray = udp_ports;
  } else if (protocol == IPPROTO_IP) {
    assert(portno < 256);
    if (!ip_prots) {
      ip_prots = (Port **) safe_zalloc(256 * sizeof(Port *));
    }
    portarray = ip_prots;
  } else fatal("addPort: attempted port insertion with invalid protocol");

  if (portarray[portno]) {
    /* We must discount our statistics from the old values.  Also warn
       if a complete duplicate */
    current = portarray[portno];    
    if (o.debugging && current->state == state && (!owner || !*owner)) {
      error("Duplicate port (%hu/%s)\n", portno, proto2ascii(protocol));
    } 
    state_counts[current->state]--;
    if (current->proto == IPPROTO_TCP) {
      state_counts_tcp[current->state]--;
    } else if (current->proto == IPPROTO_UDP) {
      state_counts_udp[current->state]--;
    } else
      state_counts_ip[current->state]--;
  } else {
    portarray[portno] = new Port();
    current = portarray[portno];
    numports++;
    current->portno = portno;
  }
  
  state_counts[state]++;
  current->state = state;
  if (protocol == IPPROTO_TCP) {
    state_counts_tcp[state]++;
  } else if (protocol == IPPROTO_UDP) {
    state_counts_udp[state]++;
  } else
    state_counts_ip[state]++;
  current->proto = protocol;

  if (owner && *owner) {
    if (current->owner)
      free(current->owner);
    current->owner = strdup(owner);
  }

  return 0; /*success */
}

int PortList::removePort(u16 portno, u8 protocol) {
  Port *answer = NULL;

  if (protocol == IPPROTO_TCP && tcp_ports) {
   answer = tcp_ports[portno];
   tcp_ports[portno] = NULL;
  }

  if (protocol == IPPROTO_UDP && udp_ports) {  
    answer = udp_ports[portno];
    udp_ports[portno] = NULL;
  } else if (protocol == IPPROTO_IP && ip_prots) {
    answer = ip_prots[portno] = NULL;
  }

  if (!answer)
    return -1;

  if (o.verbose) {  
    log_write(LOG_STDOUT, "Deleting port %hu/%s, which we thought was %s\n",
	      portno, proto2ascii(answer->proto),
	      statenum2str(answer->state));
    log_flush(LOG_STDOUT);
  }    

  delete answer;
  return 0;
}

  /* Saves an identification string for the target containing these
     ports (an IP addrss might be a good example, but set what you
     want).  Only used when printing new port updates.  Optional.  A
     copy is made. */
void PortList::setIdStr(const char *id) {
  int len = 0;
  if (idstr) free(idstr);
  if (!id) { idstr = NULL; return; }
  len = strlen(id);
  len += 5; // " on " + \0
  idstr = (char *) safe_malloc(len);
  snprintf(idstr, len, " on %s", id);
}

Port *PortList::lookupPort(u16 portno, u8 protocol) {

  if (protocol == IPPROTO_TCP && tcp_ports)
    return tcp_ports[portno];

  if (protocol == IPPROTO_UDP && udp_ports)
    return udp_ports[portno];

  if (protocol == IPPROTO_IP && ip_prots)
    return ip_prots[portno];

  return NULL;
}

int PortList::getIgnoredPortState() {
  int ignored = PORT_UNKNOWN;
  int ignoredNum = 0;
  int i;
  for(i=0; i < PORT_HIGHEST_STATE; i++) {
    if (i == PORT_OPEN || i == PORT_UNKNOWN || i == PORT_TESTING || 
	i == PORT_FRESH) continue; /* Cannot be ignored */
    if (state_counts[i] > ignoredNum) {
      ignored = i;
      ignoredNum = state_counts[i];
    }
  }

  if (state_counts[ignored] < 15)
    ignored = PORT_UNKNOWN;

  return ignored;
}

/* A function for iterating through the ports.  Give NULL for the
   first "afterthisport".  Then supply the most recent returned port
   for each subsequent call.  When no more matching ports remain, NULL
   will be returned.  To restrict returned ports to just one protocol,
   specify IPPROTO_TCP or IPPROTO_UDP for allowed_protocol.  A 0 for
   allowed_protocol matches either.  allowed_state works in the same
   fashion as allowed_protocol. This function returns ports in numeric
   order from lowest to highest, except that if you ask for both TCP &
   UDP, every TCP port will be returned before we start returning UDP
   ports.  */

Port *PortList::nextPort(Port *afterthisport, 
			 u8 allowed_protocol, int allowed_state, 
			 bool allow_portzero) {

  /* These two are chosen because they come right "before" port 1/tcp */
unsigned int current_portno = 0;
unsigned int current_proto = IPPROTO_TCP;

if (afterthisport) {
  current_portno = afterthisport->portno;
  current_proto = afterthisport->proto;  /* (afterthisport->proto == IPPROTO_TCP)? IPPROTO_TCP : IPPROTO_UDP; */
  current_portno++; /* Start on the port after the one we were given */ 
} 

 if (!allow_portzero && current_portno == 0) current_portno++;

/* First we look for TCP ports ... */
if (current_proto == IPPROTO_TCP) {
 if ((allowed_protocol == 0 || allowed_protocol == IPPROTO_TCP) && 
    current_proto == IPPROTO_TCP && tcp_ports)
  for(; current_portno < 65536; current_portno++) {
    if (tcp_ports[current_portno] &&
	(!allowed_state || tcp_ports[current_portno]->state == allowed_state))
      return tcp_ports[current_portno];
  }

  /*  Uh-oh.  We have tried all tcp ports, lets move to udp */
  current_portno = 0;
  current_proto = IPPROTO_UDP;
}

if ((allowed_protocol == 0 || allowed_protocol == IPPROTO_UDP) && 
    current_proto == IPPROTO_UDP && udp_ports) {
  for(; current_portno < 65536; current_portno++) {
    if (udp_ports[current_portno] &&
	(!allowed_state || udp_ports[current_portno]->state == allowed_state))
      return udp_ports[current_portno];
  }
}

/*  No more ports */
return NULL;
}

// Move some popular TCP ports to the beginning of the portlist, because
// that can speed up certain scans.  You should have already done any port
// randomization, this should prevent the ports from always coming out in the
// same order.
void random_port_cheat(u16 *ports, int portcount) {
  int allportidx = 0;
  int popportidx = 0;
  int earlyreplidx = 0;
  u16 pop_ports[] = { 21, 22, 23, 25, 53, 80, 113, 256, 389, 443, 554, 636, 1723, 3389 };
  int num_pop_ports = sizeof(pop_ports) / sizeof(u16);

  for(allportidx = 0; allportidx < portcount; allportidx++) {
    // see if the currentport is a popular port
    for(popportidx = 0; popportidx < num_pop_ports; popportidx++) {
      if (ports[allportidx] == pop_ports[popportidx]) {
	// This one is popular!  Swap it near to the beginning.
	if (allportidx != earlyreplidx) {
	  ports[allportidx] = ports[earlyreplidx];
	  ports[earlyreplidx] = pop_ports[popportidx];
	}
	earlyreplidx++;
	break;
      }
    }
  }
}

