/***************************************************************************
 * portlist.cc -- Functions for manipulating various lists of ports        *
 * maintained internally by Nmap.                                          *
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
#include "portlist.h"
#include "nmap_error.h"
#include "NmapOps.h"
#include "services.h"
#include "protocols.h"
#include "nmap_rpc.h"
#include "tcpip.h"
#include "libnetutil/netutil.h"

using namespace std;

#if HAVE_STRINGS_H
#include <strings.h>
#endif /* HAVE_STRINGS_H */

extern NmapOps o;  /* option structure */

Port::Port() {
  portno = proto = 0;
  state = 0;
  service = NULL;
  state_reason_init(&reason);
}

void Port::freeService() {
  if (service != NULL) {
    if (service->name)
      free(service->name);
    if (service->product)
      free(service->product);
    if (service->version)
      free(service->version);
    if (service->extrainfo)
      free(service->extrainfo);
    if (service->hostname)
      free(service->hostname);
    if (service->ostype)
      free(service->ostype);
    if (service->devicetype)
      free(service->devicetype);
    if (service->service_fp)
      free(service->service_fp);
    delete service;
  }
}

/* Fills in namebuf (as long as there is space in buflen) with the
   Name nmap normal output will use to describe the port.  This takes
   into account to confidence level, any SSL tunneling, etc.  Truncates
   namebuf to 0 length if there is no room.*/
void Port::getNmapServiceName(char *namebuf, int buflen, const char *rpcinfo) const {
  const char *tunnel_prefix;
  const char *service_name;
  int len;

  if (service != NULL && service->service_tunnel == SERVICE_TUNNEL_SSL)
    tunnel_prefix = "ssl/";
  else
    tunnel_prefix = "";

  if (service != NULL && service->name != NULL) {
    service_name = service->name;
  } else {
    struct servent *service;

    service = nmap_getservbyport(htons(portno), IPPROTO2STR(proto));
    if (service != NULL)
      service_name = service->s_name;
    else
      service_name = NULL;
  }

  if (service_name != NULL && strcmp(service_name, "unknown") != 0) {
    /* The port has a name and the name is not "unknown". How confident are we? */
    if (o.servicescan && state == PORT_OPEN && (service == NULL || service->name_confidence <= 5))
      len = Snprintf(namebuf, buflen, "%s%s?", tunnel_prefix, service_name);
    else
      len = Snprintf(namebuf, buflen, "%s%s", tunnel_prefix, service_name);
  } else {
    len = Snprintf(namebuf, buflen, "%sunknown", tunnel_prefix);
  }
  if (len >= buflen || len < 0) {
    namebuf[0] = '\0';
    return;
  }

  if (rpcinfo != NULL && rpcinfo[0] != '\0') {
    namebuf += len;
    buflen -= len;
    len = Snprintf(namebuf, buflen, " %s", rpcinfo);
    if (len >= buflen || len < 0) {
      namebuf[0] = '\0';
      return;
    }
  }
}

serviceDeductions::serviceDeductions() {
  name = NULL;
  name_confidence = 0;
  product = NULL;
  version = NULL;
  extrainfo = NULL;
  hostname = NULL;
  ostype = NULL;
  devicetype = NULL;
  service_tunnel = SERVICE_TUNNEL_NONE;
  service_fp = NULL;
  dtype = SERVICE_DETECTION_TABLE;
  rpc_status = RPC_STATUS_UNTESTED;
  rpc_program = 0;
  rpc_lowver = 0;
  rpc_highver = 0;
}

// Uses the sd->{product,version,extrainfo} if available to fill
// out sd->fullversion.  If unavailable, it will be set to zero length.
void serviceDeductions::populateFullVersionString(char *buf, size_t n) const {
  char *dst = buf;
  unsigned int spaceleft = n - 1; // Leave room for \0
  int needpad = 0;  // Do we need to pad a space between the next template?

  dst[0] = '\0';

  /* Sometimes there is really great product/version/extra information
   * available that won't quite fit.  Rather than just drop that information
   * this routine will truncate the string that is too long with "...".
   * If there are fewer than 8 characters left don't bother and just skip
   * that bit of information.
   */

  if (product && spaceleft >= 8) {
    if (spaceleft < strlen(product)) {
      strncat(dst, product, spaceleft - 3);  // Leave room for "..."
      strncat(dst, "...", spaceleft);
      spaceleft = 0;
    }
    else {
      strncat(dst, product, spaceleft);
      spaceleft -= strlen(product);
    }
    needpad = 1;
  }

  if (version && spaceleft >= 8) {
    if (needpad) {
      strncat(dst, " ", spaceleft);
      spaceleft--;
    }
    
    if (spaceleft < strlen(version)) {
      strncat(dst, version, spaceleft - 3);
      strncat(dst, "...", spaceleft);
      spaceleft = 0;
    }
    else {
      strncat(dst, version, spaceleft);
      spaceleft -= strlen(version);
    }
    needpad = 1;
  }

  if (extrainfo && spaceleft >= 8) {
    if (needpad) {
      strncat(dst, " ", spaceleft);
      spaceleft--;
    }
    // This time we need to trucate inside of the () so we have spaceleft - 2
    strncat(dst, "(", spaceleft);
    if (spaceleft - 2 < strlen(extrainfo)) {
      strncat(dst, extrainfo, spaceleft - 5);
      strncat(dst, "...", spaceleft - 2);
      spaceleft = 1;  // Fit the paren
    }
    else {
      strncat(dst, extrainfo, spaceleft);
      spaceleft -= (strlen(extrainfo) + 2);
    }
    strncat(dst, ")", spaceleft);
    spaceleft--;
  }

}


// pass in an allocated struct serviceDeductions (don't worry about
// initializing, and you don't have to free any internal ptrs.  See the
// serviceDeductions definition for the fields that are populated.
// Returns 0 if at least a name is available.
const void PortList::getServiceDeductions(u16 portno, int protocol, struct serviceDeductions *sd) const {
  const Port *port;

  port = lookupPort(portno, protocol);
  if (port == NULL || port->service == NULL) {
    struct servent *service;

    /* Look up the service name. */
    *sd = serviceDeductions();
    service = nmap_getservbyport(htons(portno), IPPROTO2STR(protocol));
    if (service != NULL)
      sd->name = service->s_name;
    else
      sd->name = NULL;
    sd->name_confidence = 3;
  } else {
    *sd = *port->service;
  }
}


// sname should be NULL if sres is not
// PROBESTATE_FINISHED_MATCHED. product,version, and/or extrainfo
// will be NULL if unavailable. Note that this function makes its
// own copy of sname and product/version/extrainfo.  This function
// also takes care of truncating the version strings to a
// 'reasonable' length if necessary, and cleaning up any unprintable
// chars. (these tests are to avoid annoying DOS (or other) attacks
// by malicious services).  The fingerprint should be NULL unless
// one is available and the user should submit it.  tunnel must be
// SERVICE_TUNNEL_NULL (normal) or SERVICE_TUNNEL_SSL (means ssl was
// detected and we tried to tunnel through it ).
static char *cstringSanityCheck(const char* string, int len) {
  char *result;
  int slen;

  if(!string)
	  return NULL;

  slen = strlen(string);
  if (slen > len) slen = len;
  result = (char *) safe_malloc(slen + 1);
  memcpy(result, string, slen);
  result[slen] = '\0';
  replacenonprintable(result, slen, '.'); 
  return result;
}

void PortList::setServiceProbeResults(u16 portno, int protocol,
  enum serviceprobestate sres, const char *sname,
  enum service_tunnel_type tunnel, const char *product, const char *version,
  const char *extrainfo, const char *hostname, const char *ostype,
  const char *devicetype, const char *fingerprint) {
  Port *port;

  port = createPort(portno, protocol);
  if (port->service == NULL)
    port->service = new serviceDeductions;

  if (sres == PROBESTATE_FINISHED_HARDMATCHED
      || sres == PROBESTATE_FINISHED_SOFTMATCHED) {
    port->service->dtype = SERVICE_DETECTION_PROBED;
    port->service->name_confidence = 10;
  } else if (sres == PROBESTATE_FINISHED_TCPWRAPPED) {
    port->service->dtype = SERVICE_DETECTION_PROBED;
    if (sname == NULL)
      sname = "tcpwrapped";
    port->service->name_confidence = 8;
  } else {
    /* PROBESTATE_FINISHED_NOMATCH, PROBESTATE_EXCLUDED, PROBESTATE_INCOMPLETE.
       Just look up the service name if none is provided. */
    if (sname == NULL) {
      struct servent *service;
      service = nmap_getservbyport(htons(portno), IPPROTO2STR(protocol));
      if (service != NULL)
        sname = service->s_name;
    }
    port->service->dtype = SERVICE_DETECTION_TABLE;
    port->service->name_confidence = 3;  // Since we didn't even check it, we aren't very confident
  }

  // port->serviceprobe_results = sres;
  port->service->service_tunnel = tunnel;

  if (sname) 
    port->service->name = strdup(sname);
  else
    port->service->name = NULL;

  if (fingerprint) 
    port->service->service_fp = strdup(fingerprint);
  else 
    port->service->service_fp = NULL;

  port->service->product = cstringSanityCheck(product, 80);
  port->service->version = cstringSanityCheck(version, 80);
  port->service->extrainfo = cstringSanityCheck(extrainfo, 256);
  port->service->hostname = cstringSanityCheck(hostname, 80);
  port->service->ostype = cstringSanityCheck(ostype, 32);
  port->service->devicetype = cstringSanityCheck(devicetype, 32);
}

/* Sets the results of an RPC scan.  if rpc_status is not
   RPC_STATUS_GOOD_PROGRAM, pass 0 for the other args.  This function
   takes care of setting the port's service and version appropriately. */
void PortList::setRPCProbeResults(u16 portno, int proto, int rpcs, unsigned long rpcp, 
			unsigned int rpcl, unsigned int rpch) {
  Port *port;
  const char *newsvc;
  char verbuf[128];

  port = createPort(portno, proto);
  if (port->service == NULL)
    port->service = new serviceDeductions;

  port->service->rpc_status = rpcs;
  if (port->service->rpc_status == RPC_STATUS_GOOD_PROG) {
    port->service->rpc_program = rpcp;
    port->service->rpc_lowver = rpcl;
    port->service->rpc_highver = rpch;

    // Now set the service/version info
    newsvc = nmap_getrpcnamebynum(rpcp);
    if (!newsvc) newsvc = "rpc.unknownprog"; // should never happen
    if (port->service->name)
      free(port->service->name);
    port->service->name = strdup(newsvc);
    if (port->service->rpc_lowver == port->service->rpc_highver)
      Snprintf(verbuf, sizeof(verbuf), "%i", port->service->rpc_lowver);
    else
      Snprintf(verbuf, sizeof(verbuf), "%i-%i", port->service->rpc_lowver, port->service->rpc_highver);
    port->service->version = strdup(verbuf);
    Snprintf(verbuf, sizeof(verbuf), "rpc #%li", port->service->rpc_program);
    port->service->extrainfo = strdup(verbuf);
    port->service->name_confidence = 10;
    port->service->dtype = SERVICE_DETECTION_PROBED;
  } else if (port->service->rpc_status == RPC_STATUS_UNKNOWN) {
    if (port->service->name)
      free(port->service->name);
    
    port->service->name = strdup("rpc.unknown");
    port->service->name_confidence = 8;
    port->service->dtype = SERVICE_DETECTION_PROBED;
  }
}


#ifndef NOLUA
void PortList::addScriptResult(u16 portno, int protocol, ScriptResult& sr) {
  Port *port;

  port = createPort(portno, protocol);

  port->scriptResults.push_back(sr);
}
#endif

/*****************************************************************************/
/* Convert protocol name from in.h to enum portlist_proto.
 * So IPPROTO_TCP will be changed to PORTLIST_PROTO_TCP and so on. */
#define INPROTO2PORTLISTPROTO(p)		\
  ((p)==IPPROTO_TCP ? PORTLIST_PROTO_TCP :	\
   (p)==IPPROTO_UDP ? PORTLIST_PROTO_UDP :	\
   (p)==IPPROTO_SCTP ? PORTLIST_PROTO_SCTP :	\
   PORTLIST_PROTO_IP)

#define PORTLISTPROTO2INPROTO(p)		\
  ((p)==PORTLIST_PROTO_TCP ? IPPROTO_TCP :	\
   (p)==PORTLIST_PROTO_UDP ? IPPROTO_UDP :	\
   (p)==PORTLIST_PROTO_SCTP ? IPPROTO_SCTP :	\
   IPPROTO_IP)


PortList::PortList() {
  int proto;
  memset(state_counts_proto, 0, sizeof(state_counts_proto));
  memset(port_list, 0, sizeof(port_list));

  for(proto=0; proto < PORTLIST_PROTO_MAX; proto++) {
    if(port_list_count[proto] > 0)
      port_list[proto] = (Port**) safe_zalloc(sizeof(Port*)*port_list_count[proto]);
    default_port_state[proto].proto = PORTLISTPROTO2INPROTO(proto);
    default_port_state[proto].reason.reason_id = ER_NORESPONSE;
    state_counts_proto[proto][default_port_state[proto].state] = port_list_count[proto];
  }

  numscriptresults = 0;
  idstr = NULL;
}

PortList::~PortList() {
  int proto, i;

  if (idstr) { 
    free(idstr);
    idstr = NULL;
  }

  for(proto=0; proto < PORTLIST_PROTO_MAX; proto++) { // for every protocol
    if(port_list[proto]) {
      for(i=0; i < port_list_count[proto]; i++) { // free every Port 
        if(port_list[proto][i]) {
          port_list[proto][i]->freeService();
          delete port_list[proto][i];
        }
      }
      free(port_list[proto]);
    }
  }
}

void PortList::setDefaultPortState(u8 protocol, int state) {
  int proto = INPROTO2PORTLISTPROTO(protocol);
  int i;

  for (i = 0; i < port_list_count[proto]; i++) {
    if (port_list[proto][i] == NULL) {
      state_counts_proto[proto][default_port_state[proto].state]--;
      state_counts_proto[proto][state]++;
    }
  }

  default_port_state[proto].state = state;
}

void PortList::setPortState(u16 portno, u8 protocol, int state) {
  const Port *oldport;
  Port *current;
  int proto = INPROTO2PORTLISTPROTO(protocol);

  assert(state < PORT_HIGHEST_STATE);

  if ((state == PORT_OPEN && o.verbose) || (o.debugging > 1)) {
    log_write(LOG_STDOUT, "Discovered %s port %hu/%s%s\n",
	      statenum2str(state), portno, 
	      proto2ascii_lowercase(protocol), idstr? idstr : "");
    log_flush(LOG_STDOUT);
  }


  /* Make sure state is OK */
  if (state != PORT_OPEN && state != PORT_CLOSED && state != PORT_FILTERED &&
      state != PORT_UNFILTERED && state != PORT_OPENFILTERED && 
      state != PORT_CLOSEDFILTERED)
    fatal("%s: attempt to add port number %d with illegal state %d\n", __func__, portno, state);

  assert(protocol!=IPPROTO_IP || portno<256);

  oldport = lookupPort(portno, protocol);
  if (oldport != NULL) {
    /* We must discount our statistics from the old values.  Also warn
       if a complete duplicate */
    if (o.debugging && oldport->state == state) {
      error("Duplicate port (%hu/%s)", portno, proto2ascii_lowercase(protocol));
    } 
    state_counts_proto[proto][oldport->state]--;
  } else {
    state_counts_proto[proto][default_port_state[proto].state]--;
  }
  current = createPort(portno, protocol);
  
  current->state = state;
  state_counts_proto[proto][state]++;
 
  if(state == PORT_FILTERED || state == PORT_OPENFILTERED)
  	setStateReason(portno, protocol, ER_NORESPONSE, 0, 0); 
  return;
}

int PortList::getPortState(u16 portno, u8 protocol) {
  const Port *port;

  port = lookupPort(portno, protocol);
  if (port == NULL)
    return default_port_state[INPROTO2PORTLISTPROTO(protocol)].state;

  return port->state;
}

/* Return true if nothing special is known about this port; i.e., it's in the
   default state as defiend by setDefaultPortState and every other data field is
   unset. */
bool PortList::portIsDefault(u16 portno, u8 protocol) {
  return lookupPort(portno, protocol) == NULL;
}

  /* Saves an identification string for the target containing these
     ports (an IP address might be a good example, but set what you
     want).  Only used when printing new port updates.  Optional.  A
     copy is made. */
void PortList::setIdStr(const char *id) {
  int len = 0;
  if (idstr) free(idstr);
  if (!id) { idstr = NULL; return; }
  len = strlen(id);
  len += 5; // " on " + \0
  idstr = (char *) safe_malloc(len);
  Snprintf(idstr, len, " on %s", id);
}


int PortList::getStateCounts(int protocol, int state) const {
  return state_counts_proto[INPROTO2PORTLISTPROTO(protocol)][state];
}

int PortList::getStateCounts(int state) const {
  int sum=0, proto;
  for(proto=0; proto < PORTLIST_PROTO_MAX; proto++)
    sum += getStateCounts(PORTLISTPROTO2INPROTO(proto), state);
  return(sum);
}

  /* A function for iterating through the ports.  Give NULL for the
   first "afterthisport".  Then supply the most recent returned port
   for each subsequent call.  When no more matching ports remain, NULL
   will be returned.  To restrict returned ports to just one protocol,
   specify IPPROTO_TCP, IPPROTO_UDP or IPPROTO_SCTP for
   allowed_protocol. A TCPANDUDPANDSCTP for allowed_protocol matches
   either. A 0 for allowed_state matches all possible states. This
   function returns ports in numeric order from lowest to highest,
   except that if you ask for both TCP, UDP & SCTP, every TCP port
   will be returned before we start returning UDP and SCTP ports */
Port *PortList::nextPort(const Port *cur, Port *next,
			 int allowed_protocol, int allowed_state) {
  int proto;
  int mapped_pno;
  Port *port;
  
  if (cur) {
    proto = INPROTO2PORTLISTPROTO(cur->proto);
    assert(port_map[proto]!=NULL); // Hmm, it's not posible to handle port that doesn't have anything in map
    assert(cur->proto!=IPPROTO_IP || cur->portno<256);
    mapped_pno = port_map[proto][cur->portno];
    mapped_pno++; //  we're interested in next port after current
  } else { // running for the first time
    if (allowed_protocol == TCPANDUDPANDSCTP)
      proto = INPROTO2PORTLISTPROTO(IPPROTO_TCP);
    else if (allowed_protocol == UDPANDSCTP)
      proto = INPROTO2PORTLISTPROTO(IPPROTO_UDP);
    else
      proto = INPROTO2PORTLISTPROTO(allowed_protocol);
    mapped_pno = 0;
  }
  
  if(port_list[proto] != NULL) {
    for(;mapped_pno < port_list_count[proto]; mapped_pno++) {
      port = port_list[proto][mapped_pno];
      if (port && (allowed_state==0 || port->state==allowed_state)) {
        *next = *port;
        return next;
      }
      if (!port && (allowed_state==0 || default_port_state[proto].state==allowed_state)) {
        *next = default_port_state[proto];
        next->portno = port_map_rev[proto][mapped_pno];
        return next;
      }
    }
  }
  
  /* if all protocols, than after TCP search UDP & SCTP */
  if((!cur && allowed_protocol == TCPANDUDPANDSCTP) ||
      (cur && proto == INPROTO2PORTLISTPROTO(IPPROTO_TCP)))
    return(nextPort(NULL, next, UDPANDSCTP, allowed_state));

  /* if all protocols, than after UDP search SCTP */
  if((!cur && allowed_protocol == UDPANDSCTP) ||
      (cur && proto == INPROTO2PORTLISTPROTO(IPPROTO_UDP)))
    return(nextPort(NULL, next, IPPROTO_SCTP, allowed_state));
  
  return(NULL); 
}

/* Convert portno and protocol into the internal indices used to index
   port_list. Returns false on error, true otherwise. */
bool PortList::mapPort(u16 *portno, u8 *protocol) const {
  int mapped_portno, mapped_protocol;

  mapped_protocol = INPROTO2PORTLISTPROTO(*protocol);

  if (*protocol == IPPROTO_IP)
    assert(*portno < 256);
  if(port_map[mapped_protocol]==NULL || port_list[mapped_protocol]==NULL) {
    assert(0);
    fatal("%s(%i,%i): you're trying to access uninitialized protocol", __func__, *portno, *protocol);
  }
  mapped_portno = port_map[mapped_protocol][*portno];

  assert(mapped_portno < port_list_count[mapped_protocol]);
  assert(mapped_portno >= 0);
  
  *portno = mapped_portno;
  *protocol = mapped_protocol;

  return true;
}

const Port *PortList::lookupPort(u16 portno, u8 protocol) const {
  if (!mapPort(&portno, &protocol))
    return NULL;

  return port_list[protocol][portno];
}

/* Create the port if it doesn't exist; otherwise this is like lookupPort. */
Port *PortList::createPort(u16 portno, u8 protocol) {
  Port *p;
  u16 mapped_portno;
  u8 mapped_protocol;

  mapped_portno = portno;
  mapped_protocol = protocol;
  if (!mapPort(&mapped_portno, &mapped_protocol))
    return NULL;

  p = port_list[mapped_protocol][mapped_portno];
  if (p == NULL) {
    p = new Port();
    p->portno = portno;
    p->proto = protocol;
    p->state = default_port_state[mapped_protocol].state;
    p->reason.reason_id = ER_NORESPONSE;
    port_list[mapped_protocol][mapped_portno] = p;
  }

  return port_list[mapped_protocol][mapped_portno];
}

int PortList::forgetPort(u16 portno, u8 protocol) {
  Port *answer = NULL;

  log_write(LOG_PLAIN, "Removed %d\n", portno);

  if (!mapPort(&portno, &protocol))
    return -1;

  answer = port_list[protocol][portno];
  if (answer == NULL)
    return -1;

  state_counts_proto[protocol][answer->state]--;
  state_counts_proto[protocol][default_port_state[protocol].state]++;
    
  delete answer;

  port_list[protocol][portno] = NULL;

  if (o.verbose) {  
    log_write(LOG_STDOUT, "Deleting port %hu/%s, which we thought was %s\n",
	      portno, proto2ascii_lowercase(answer->proto),
	      statenum2str(answer->state));
    log_flush(LOG_STDOUT);
  }    

  return 0;
}

/* Just free memory used by PortList::port_map[]. Should be done somewhere 
 * before closing nmap. */
void PortList::freePortMap() {
  int proto;

  for (proto=0; proto < PORTLIST_PROTO_MAX; proto++) {
    if (port_map[proto]) {
      free(port_map[proto]);
      port_map[proto] = NULL;
    }
    if (port_map_rev[proto]) {
      free(port_map_rev[proto]);
      port_map_rev[proto] = NULL;
    }
    port_list_count[proto] = 0;
  }
}
  

u16 *PortList::port_map[PORTLIST_PROTO_MAX];
u16 *PortList::port_map_rev[PORTLIST_PROTO_MAX];
int PortList::port_list_count[PORTLIST_PROTO_MAX];

/* This function must be runned before any PortList object is created.
 * It must be runned for every used protocol. The data in "ports" 
 * should be sorted. */
void PortList::initializePortMap(int protocol, u16 *ports, int portcount) {
  int i;
  int ports_max = (protocol == IPPROTO_IP) ? 256 : 65536;
  int proto = INPROTO2PORTLISTPROTO(protocol);
  
  if (port_map[proto] != NULL || port_map_rev[proto] != NULL)
    fatal("%s: portmap for protocol %i already initialized", __func__, protocol);

  assert(port_list_count[proto]==0);
  
  /* this memory will never be freed, but this is the way it has to be. */
  port_map[proto] = (u16 *) safe_zalloc(sizeof(u16) * ports_max);
  port_map_rev[proto] = (u16 *) safe_zalloc(sizeof(u16) * portcount);

  port_list_count[proto] = portcount;
  
  for(i=0; i < portcount; i++) {
    port_map[proto][ports[i]] = i;
    port_map_rev[proto][i] = ports[i];
  }
  /* So now port_map should have such structure (lets scan 2nd,4th and 6th port):
   * 	port_map[0,0,1,0,2,0,3,...]	        <- indexes to port_list structure
   * 	port_list[port_2,port_4,port_6] */
}

  /* Cycles through the 0 or more "ignored" ports which should be
   consolidated for Nmap output.  They are returned sorted by the
   number of prots in the state, starting with the most common.  It
   should first be called with PORT_UNKNOWN to obtain the most popular
   ignored state (if any).  Then call with that state to get the next
   most popular one.  Returns the state if there is one, but returns
   PORT_UNKNOWN if there are no (more) states which qualify for
   consolidation */
int PortList::nextIgnoredState(int prevstate) {

  int beststate = PORT_UNKNOWN;
  
  for(int state=0; state < PORT_HIGHEST_STATE; state++) {
    /* The state must be ignored */
    if (!isIgnoredState(state)) 
      continue;

    /* We can't give the same state again ... */
    if (state == prevstate) continue;

    /* If a previous state was given, we must have fewer ports than
       that one, or be tied but be a larger state number */
    if (prevstate != PORT_UNKNOWN && 
	(getStateCounts(state) > getStateCounts(prevstate) ||
	 (getStateCounts(state) == getStateCounts(prevstate) && state <= prevstate)))
      continue;

    /* We only qualify if we have more ports than the current best */
    if (beststate != PORT_UNKNOWN && getStateCounts(beststate) >= getStateCounts(state))
      continue;

    /* Yay!  We found the best state so far ... */
    beststate = state;
  }

  return beststate;
}

/* Returns true if a state should be ignored (consolidated), false otherwise */
bool PortList::isIgnoredState(int state) {

  if (o.debugging > 2)
    return false;

  if (state == PORT_OPEN || state == PORT_UNKNOWN || state == PORT_TESTING ||
      state == PORT_FRESH)
    return false; /* Cannot be ignored */

  if (state == PORT_OPENFILTERED && (o.verbose > 2 || o.debugging > 2))
    return false;

  /* If openonly, we always ignore states that don't at least have open
     as a possibility. */
  if (o.openOnly() && state != PORT_OPENFILTERED && state != PORT_UNFILTERED 
      && getStateCounts(state) > 0)
    return true;

  int max_per_state = 25; // Ignore states with more ports than this
  /* We will show more ports when verbosity is requested */
  if (o.verbose || o.debugging) {
    if (o.ipprotscan)
      max_per_state *= (o.verbose + 3 * o.debugging);
    else
      max_per_state *= (o.verbose + 20 * o.debugging);
  }

  if (getStateCounts(state) > max_per_state)
    return true;

  return false;
}

int PortList::numIgnoredStates() {
  int numstates = 0;
  for(int state=0; state < PORT_HIGHEST_STATE; state++) {
    if (isIgnoredState(state))
      numstates++;
  }
  return numstates;
}

int PortList::numIgnoredPorts() {

  int numports = 0;
  for(int state=0; state < PORT_HIGHEST_STATE; state++) {
    if (isIgnoredState(state))
      numports += getStateCounts(state);
  }
  return numports;
}

int PortList::numPorts() const {
  int proto, num = 0;

  for (proto = 0; proto < PORTLIST_PROTO_MAX; proto++)
    num += port_list_count[proto];

  return num;
}

/* Return true if any of the ports are potentially open. */
bool PortList::hasOpenPorts() const {
  return getStateCounts(PORT_OPEN) != 0 ||
    getStateCounts(PORT_OPENFILTERED) != 0 ||
    getStateCounts(PORT_UNFILTERED) != 0;
}

int PortList::setStateReason(u16 portno, u8 proto, reason_t reason, u8 ttl, u32 ip_addr) {
    Port *answer = NULL;

    if(reason > ER_MAX)
        return -1;
    answer = createPort(portno, proto);

    /* set new reason and increment its count */
    answer->reason.reason_id = reason;
    answer->reason.ip_addr.s_addr = ip_addr;
	answer->reason.ttl = ttl;
    return 0;
}

// Move some popular TCP ports to the beginning of the portlist, because
// that can speed up certain scans.  You should have already done any port
// randomization, this should prevent the ports from always coming out in the
// same order.
void random_port_cheat(u16 *ports, int portcount) {
  int allportidx = 0;
  int popportidx = 0;
  int earlyreplidx = 0;
  /* Updated 2008-12-19 from nmap-services-all.
     Top 25 open TCP ports plus 113, 554, and 256 */
  u16 pop_ports[] = {
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
    143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
    1025, 587, 8888, 199, 1720,
    113, 554, 256
  };
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

