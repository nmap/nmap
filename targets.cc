
/***************************************************************************
 * targets.cc -- Functions relating to "ping scanning" as well as          *
 * determining the exact IPs to hit based on CIDR and other input          *
 * formats.                                                                *
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


#include "nbase/nbase_addrset.h"
#include "targets.h"
#include "timing.h"
#include "NmapOps.h"
#include "TargetGroup.h"
#include "Target.h"
#include "scan_engine.h"
#include "nmap_dns.h"
#include "nmap_tty.h"
#include "utils.h"
#include "xml.h"

extern NmapOps o;
#ifdef WIN32
/* from libdnet's intf-win32.c */
extern "C" int g_has_npcap_loopback;
#endif

/* Conducts an ARP ping sweep of the given hosts to determine which ones
   are up on a local ethernet network */
static void arpping(Target *hostbatch[], int num_hosts) {
  /* First I change hostbatch into a std::vector<Target *>, which is what ultra_scan
     takes.  I remove hosts that cannot be ARP scanned (such as localhost) */
  std::vector<Target *> targets;
  int targetno;
  targets.reserve(num_hosts);

  for (targetno = 0; targetno < num_hosts; targetno++) {
    initialize_timeout_info(&hostbatch[targetno]->to);
    /* Default timout should be much lower for arp */
    hostbatch[targetno]->to.timeout = MAX(o.minRttTimeout(), MIN(o.initialRttTimeout(), INITIAL_ARP_RTT_TIMEOUT)) * 1000;
    if (!hostbatch[targetno]->SrcMACAddress()) {
      bool islocal = islocalhost(hostbatch[targetno]->TargetSockAddr());
      if (islocal) {
        log_write(LOG_STDOUT|LOG_NORMAL,
                  "ARP ping: Considering %s UP because it is a local IP, despite no MAC address for device %s\n",
                  hostbatch[targetno]->NameIP(), hostbatch[targetno]->deviceName());
        hostbatch[targetno]->flags = HOST_UP;
      } else {
        log_write(LOG_STDOUT|LOG_NORMAL,
                  "ARP ping: Considering %s DOWN because no MAC address found for device %s.\n",
                  hostbatch[targetno]->NameIP(),
                  hostbatch[targetno]->deviceName());
        hostbatch[targetno]->flags = HOST_DOWN;
      }
      continue;
    }
    targets.push_back(hostbatch[targetno]);
  }
  if (!targets.empty()) {
    if (targets[0]->af() == AF_INET)
      ultra_scan(targets, NULL, PING_SCAN_ARP);
    else
      ultra_scan(targets, NULL, PING_SCAN_ND);
  }
  return;
}

static void hoststructfry(Target *hostbatch[], int nelem) {
  genfry((unsigned char *)hostbatch, sizeof(Target *), nelem);
  return;
}

/* Returns the last host obtained by nexthost.  It will be given again the next
   time you call nexthost(). */
void returnhost(HostGroupState *hs) {
  assert(hs->next_batch_no > 0);
  hs->next_batch_no--;
}

/* Is the host passed as Target to be excluded? Much of this logic had
   to be rewritten from wam's original code to allow for the objects */
static int hostInExclude(struct sockaddr *checksock, size_t checksocklen,
                  const addrset *exclude_group) {
  if (exclude_group == NULL)
    return 0;

  if (checksock == NULL)
    return 0;

  if (addrset_contains(exclude_group,checksock))
    return 1;
  return 0;
}

/* Load an exclude list from a file for --excludefile. */
int load_exclude_file(addrset *excludelist, FILE *fp) {
  char host_spec[1024];
  size_t n;

  while ((n = read_host_from_file(fp, host_spec, sizeof(host_spec))) > 0) {
    if (n >= sizeof(host_spec))
      fatal("One of your exclude file specifications was too long to read (>= %u chars)", (unsigned int) sizeof(host_spec));
    if(!addrset_add_spec(excludelist, host_spec, o.af(), 1)){
      fatal("Invalid address specification:");
    }
  }

  return 1;
}

/* Load a comma-separated exclude list from a string, the argument to
   --exclude. */
int load_exclude_string(addrset *excludelist, const char *s) {
  const char *begin, *p;

  p = s;
  while (*p != '\0') {
    begin = p;
    while (*p != '\0' && *p != ',')
      p++;
    std::string addr_str = std::string(begin, p - begin);
    if (!addrset_add_spec(excludelist, addr_str.c_str(), o.af(), 1)) {
        fatal("Invalid address specification: %s", addr_str.c_str());
    }
    if (*p == '\0')
      break;
    p++;
  };

  return 1;
}


/* A debug routine to dump some information to stdout. Invoked if debugging is
   set to 4 or higher. */
int dumpExclude(addrset *exclude_group) {
  const struct addrset_elem *elem;

  for (elem = exclude_group->head; elem != NULL; elem = elem->next)
    addrset_elem_print(stdout, elem);

  return 1;
}

static void massping(Target *hostbatch[], int num_hosts, struct scan_lists *ports) {
  static struct timeout_info group_to = { 0, 0, 0 };
  static char prev_device_name[16] = "";
  const char *device_name;
  std::vector<Target *> targets;
  int i;

  /* Get the name of the interface used to send to this group. We assume the
     device used to send to the first target is used to send to all of them. */
  device_name = NULL;
  if (num_hosts > 0)
    device_name = hostbatch[0]->deviceName();
  if (device_name == NULL)
    device_name = "";

  /* group_to is a static variable that keeps track of group timeout values
     between invocations of this function. We reuse timeouts as long as this
     invocation uses the same device as the previous one. Otherwise we
     reinitialize the timeouts. */
  if (group_to.srtt == 0 || group_to.rttvar == 0 || group_to.timeout == 0
    || strcmp(prev_device_name, device_name) != 0) {
    initialize_timeout_info(&group_to);
    Strncpy(prev_device_name, device_name, sizeof(prev_device_name));
  }

  for (i = 0; i < num_hosts; i++) {
    initialize_timeout_info(&hostbatch[i]->to);
    targets.push_back(hostbatch[i]);
  }

  ultra_scan(targets, ports, PING_SCAN, &group_to);
}

/* Returns true iff this target is incompatible with the other hosts in the host
   group. This happens when:
     1. it uses a different interface, or
     2. it uses a different source address, or
     3. it is directly connected when the other hosts are not, or vice versa, or
     4. it has the same IP address as another target already in the group.
   These restrictions only apply for raw scans. This function is similar to one
   of the same name in nmap.cc. That one is for port scanning, this one is for
   ping scanning. */
bool target_needs_new_hostgroup(Target **targets, int targets_sz, const Target *target) {
  int i = 0;

  /* We've just started a new hostgroup, so any target is acceptable. */
  if (targets_sz == 0)
    return false;

  /* There are no restrictions on non-root scans. */
  if (!(o.isr00t && target->deviceName() != NULL))
    return false;

  /* Different address family? */
  if (targets[0]->af() != target->af())
    return true;

  /* Different interface name? */
  if (targets[0]->deviceName() != NULL &&
      target->deviceName() != NULL &&
      strcmp(targets[0]->deviceName(), target->deviceName()) != 0) {
    return true;
  }

  /* Different source address? */
  if (sockaddr_storage_cmp(targets[0]->SourceSockAddr(), target->SourceSockAddr()) != 0)
    return true;

  /* Different direct connectedness? */
  if (targets[0]->directlyConnected() != target->directlyConnected())
    return true;

  /* Is there already a target with this same IP address? ultra_scan doesn't
     cope with that, because it uses IP addresses to look up targets from
     replies. What happens is one target gets the replies for all probes
     referring to the same IP address. */
  for (i = 0; i < targets_sz; i++) {
    if (sockaddr_storage_cmp(targets[i]->TargetSockAddr(), target->TargetSockAddr()) == 0)
      return true;
  }

  return false;
}

TargetGroup::~TargetGroup() {
  if (this->netblock != NULL)
    delete this->netblock;
}

/* Initializes (or reinitializes) the object with a new expression, such
   as 192.168.0.0/16 , 10.1.0-5.1-254 , or fe80::202:e3ff:fe14:1102 .
   Returns 0 for success */
int TargetGroup::parse_expr(const char *target_expr, int af) {
  if (this->netblock != NULL)
    delete this->netblock;
  this->netblock = NetBlock::parse_expr(target_expr, af);
  if (this->netblock != NULL)
    return 0;
  else
    return 1;
}

/* Grab the next host from this expression (if any) and updates its internal
   state to reflect that the IP was given out.  Returns 0 and
   fills in ss if successful.  ss must point to a pre-allocated
   sockaddr_storage structure */
int TargetGroup::get_next_host(struct sockaddr_storage *ss, size_t *sslen) {
  if (this->netblock == NULL)
    return -1;

  /* If all we have at this point is a hostname and netmask, resolve into
     something where we know the address. If we ever have to use strictly the
     hostname, without doing local DNS resolution (like with a proxy scan), this
     has to be made conditional (and perhaps an error if the netmask doesn't
     limit it to exactly one address). */
  NetBlockHostname *netblock_hostname;
  netblock_hostname = dynamic_cast<NetBlockHostname *>(this->netblock);
  if (netblock_hostname != NULL) {
    this->netblock = netblock_hostname->resolve();
    if (this->netblock == NULL) {
      error("Failed to resolve \"%s\".", netblock_hostname->hostname.c_str());
      delete netblock_hostname;
      return -1;
    }
    delete netblock_hostname;
  }

  /* Check for proper address family. Give a specific error message for IPv6
     specifications appearing in IPv4 mode. */
  if (o.af() == AF_INET && dynamic_cast<NetBlockIPv6Netmask *>(this->netblock) != NULL) {
    error("%s looks like an IPv6 target specification -- you have to use the -6 option.",
      this->netblock->str().c_str());
    return -1;
  }
  if ((o.af() == AF_INET && dynamic_cast<NetBlockIPv4Ranges *>(this->netblock) == NULL) ||
      (o.af() == AF_INET6 && dynamic_cast<NetBlockIPv6Netmask *>(this->netblock) == NULL)) {
    error("Address family mismatch in target specification \"%s\".",
      this->netblock->str().c_str());
    return -1;
  }

  if (this->netblock->next(ss, sslen))
    return 0;
  else
    return -1;
}

/* Returns true iff the given address is the one that was resolved to create
   this target group; i.e., not one of the addresses derived from it with a
   netmask. */
bool TargetGroup::is_resolved_address(const struct sockaddr_storage *ss) const {
  return this->netblock->is_resolved_address(ss);
}

/* Return a string of the name or address that was resolved for this group. */
const char *TargetGroup::get_resolved_name(void) const {
  if (this->netblock->hostname.empty())
    return NULL;
  else
    return this->netblock->hostname.c_str();
}

/* Return the list of addresses that the name for this group resolved to, if
   it came from a name resolution. */
const std::list<struct sockaddr_storage> &TargetGroup::get_resolved_addrs(void) const {
  return this->netblock->resolvedaddrs;
}

/* is the current expression a named host */
int TargetGroup::get_namedhost() const {
  return this->get_resolved_name() != NULL;
}

/* Lookahead is the number of hosts that can be
   checked (such as ping scanned) in advance.  Randomize causes each
   group of up to lookahead hosts to be internally shuffled around.
   The target_expressions array MUST REMAIN VALID IN MEMORY as long as
   this class instance is used -- the array is NOT copied.
 */
HostGroupState::HostGroupState(int lookahead, int rnd, int argc, const char **argv) {
  assert(lookahead > 0);
  this->argc = argc;
  this->argv = argv;
  hostbatch = (Target **) safe_zalloc(sizeof(Target *) * lookahead);
  defer_buffer = std::list<Target *>();
  undeferred = std::list<Target *>();
  max_batch_sz = lookahead;
  current_batch_sz = 0;
  next_batch_no = 0;
  randomize = rnd;
}

HostGroupState::~HostGroupState() {
  free(hostbatch);
}

/* Returns true iff the defer buffer is not yet full. */
bool HostGroupState::defer(Target *t) {
  this->defer_buffer.push_back(t);
  return this->defer_buffer.size() < HostGroupState::DEFER_LIMIT;
}

void HostGroupState::undefer() {
  this->undeferred.splice(this->undeferred.end(), this->defer_buffer);
}

const char *HostGroupState::next_expression() {
  if (o.max_ips_to_scan == 0 || o.numhosts_scanned + this->current_batch_sz < o.max_ips_to_scan) {
    const char *expr;
    expr = grab_next_host_spec(o.inputfd, o.generate_random_ips, this->argc, this->argv);
    if (expr != NULL)
      return expr;
  }

#ifndef NOLUA
  /* Add any new NSE discovered targets to the scan queue */
  static char buf[1024];

  NewTargets *new_targets = NewTargets::get();
  if (o.script && new_targets != NULL) {
    if (new_targets->get_queued() > 0) {
      std::string expr_string;
      expr_string = new_targets->read().c_str();
      if (o.debugging > 3) {
        log_write(LOG_PLAIN,
                  "New targets in the scanned cache: %ld, pending ones: %ld.\n",
                  new_targets->get_scanned(), new_targets->get_queued());
      }
      if (!expr_string.empty()) {
        Strncpy(buf, expr_string.c_str(), sizeof(buf));
        return buf;
      }
    }
  }
#endif

  return NULL;
}

/* Add a <target> element to the XML stating that a target specification was
   ignored. This can be because of, for example, a DNS resolution failure, or a
   syntax error. */
static void log_bogus_target(const char *expr) {
  xml_open_start_tag("target");
  xml_attribute("specification", "%s", expr);
  xml_attribute("status", "skipped");
  xml_attribute("reason", "invalid");
  xml_close_empty_tag();
  xml_newline();
}

/* Returns a newly allocated Target with the given address. Handles all the
   details like setting the Target's address and next hop. */
static Target *setup_target(const HostGroupState *hs,
                            const struct sockaddr_storage *ss, size_t sslen,
                            int pingtype) {
  struct route_nfo rnfo;
  Target *t;

  t = new Target();

  t->setTargetSockAddr(ss, sslen);

  /* Special handling for the resolved address (for example whatever
     scanme.nmap.org resolves to in scanme.nmap.org/24). */
  if (hs->current_group.is_resolved_address(ss)) {
    if (hs->current_group.get_namedhost())
      t->setTargetName(hs->current_group.get_resolved_name());
    t->resolved_addrs = hs->current_group.get_resolved_addrs();
  }

  /* We figure out the source IP/device IFF
     1) We are r00t AND
     2) We are doing tcp or udp pingscan OR
     3) We are doing a raw-mode portscan or osscan or traceroute OR
     4) We are on windows and doing ICMP ping */
  if (o.isr00t &&
      ((pingtype & (PINGTYPE_TCP|PINGTYPE_UDP|PINGTYPE_SCTP_INIT|PINGTYPE_PROTO|PINGTYPE_ARP)) || o.RawScan()
#ifdef WIN32
       || (pingtype & (PINGTYPE_ICMP_PING|PINGTYPE_ICMP_MASK|PINGTYPE_ICMP_TS))
#endif // WIN32
      )) {
    if (!nmap_route_dst(ss, &rnfo)) {
      log_bogus_target(inet_ntop_ez(ss, sslen));
      error("%s: failed to determine route to %s", __func__, t->NameIP());
      goto bail;
    }
    if (rnfo.direct_connect) {
      t->setDirectlyConnected(true);
    } else {
      t->setDirectlyConnected(false);
      t->setNextHop(&rnfo.nexthop, sizeof(rnfo.nexthop));
    }
    t->setIfType(rnfo.ii.device_type);
    if (rnfo.ii.device_type == devt_ethernet) {
      if (o.spoofMACAddress())
        t->setSrcMACAddress(o.spoofMACAddress());
      else
        t->setSrcMACAddress(rnfo.ii.mac);
    }
#ifdef WIN32
    else if (g_has_npcap_loopback && rnfo.ii.device_type == devt_loopback) {
      if (o.spoofMACAddress())
        t->setSrcMACAddress(o.spoofMACAddress());
      else
        t->setSrcMACAddress(rnfo.ii.mac);
      t->setNextHopMACAddress(t->SrcMACAddress());
    }
#endif
    t->setSourceSockAddr(&rnfo.srcaddr, sizeof(rnfo.srcaddr));
    if (hs->current_batch_sz == 0) /* Because later ones can have different src addy and be cut off group */
      o.decoys[o.decoyturn] = t->source();
    t->setDeviceNames(rnfo.ii.devname, rnfo.ii.devfullname);
    t->setMTU(rnfo.ii.mtu);
    // printf("Target %s %s directly connected, goes through local iface %s, which %s ethernet\n", t->NameIP(), t->directlyConnected()? "IS" : "IS NOT", t->deviceName(), (t->ifType() == devt_ethernet)? "IS" : "IS NOT");
  }

  return t;

bail:
  delete t;
  return NULL;
}

static Target *next_target(HostGroupState *hs, const addrset *exclude_group,
  struct scan_lists *ports, int pingtype) {
  struct sockaddr_storage ss;
  size_t sslen;
  Target *t;

  /* First handle targets deferred in the last batch. */
  if (!hs->undeferred.empty()) {
    t = hs->undeferred.front();
    hs->undeferred.pop_front();
    return t;
  }

tryagain:

  if (hs->current_group.get_next_host(&ss, &sslen) != 0) {
    const char *expr;
    /* We are going to have to pop in another expression. */
    for (;;) {
      expr = hs->next_expression();
      if (expr == NULL)
        /* That's the last of them. */
        return NULL;
      if (hs->current_group.parse_expr(expr, o.af()) == 0)
        break;
      else
        log_bogus_target(expr);
    }
    goto tryagain;
  }

  assert(ss.ss_family == o.af());

  /* If we are resuming from a previous scan, we have already finished scanning
     up to o.resume_ip.  */
  if (ss.ss_family == AF_INET && o.resume_ip.s_addr) {
    if (o.resume_ip.s_addr == ((struct sockaddr_in *) &ss)->sin_addr.s_addr)
      /* We will continue starting with the next IP. */
      o.resume_ip.s_addr = 0;
    goto tryagain;
  }

  /* Check exclude list. */
  if (hostInExclude((struct sockaddr *) &ss, sslen, exclude_group))
    goto tryagain;

  t = setup_target(hs, &ss, sslen, pingtype);
  if (t == NULL)
    goto tryagain;

  return t;
}

static void refresh_hostbatch(HostGroupState *hs, const addrset *exclude_group,
  struct scan_lists *ports, int pingtype) {
  int i;
  bool arpping_done = false;
  struct timeval now;

  hs->current_batch_sz = hs->next_batch_no = 0;
  hs->undefer();
  while (hs->current_batch_sz < hs->max_batch_sz) {
    Target *t;

    t = next_target(hs, exclude_group, ports, pingtype);
    if (t == NULL)
      break;

    /* Does this target need to go in a separate host group? */
    if (target_needs_new_hostgroup(hs->hostbatch, hs->current_batch_sz, t)) {
      if (hs->defer(t))
        continue;
      else
        break;
    }

    o.decoys[o.decoyturn] = t->source();
    hs->hostbatch[hs->current_batch_sz++] = t;
  }

  if (hs->current_batch_sz == 0)
    return;

  /* OK, now we have our complete batch of entries.  The next step is to
     randomize them (if requested) */
  if (hs->randomize) {
    hoststructfry(hs->hostbatch, hs->current_batch_sz);
  }

  /* First I'll do the ARP ping if all of the machines in the group are
     directly connected over ethernet.  I may need the MAC addresses
     later anyway. */
  if (hs->hostbatch[0]->ifType() == devt_ethernet &&
      hs->hostbatch[0]->af() == AF_INET &&
      hs->hostbatch[0]->directlyConnected() &&
      o.sendpref != PACKET_SEND_IP_STRONG &&
      (pingtype == PINGTYPE_ARP || o.implicitARPPing)) {
    arpping(hs->hostbatch, hs->current_batch_sz);
    arpping_done = true;
  }

  /* No other interface types are supported by ND ping except devt_ethernet
     at the moment. */
  if (hs->hostbatch[0]->ifType() == devt_ethernet &&
      hs->hostbatch[0]->af() == AF_INET6 &&
      hs->hostbatch[0]->directlyConnected() &&
      o.sendpref != PACKET_SEND_IP_STRONG &&
      (pingtype == PINGTYPE_ARP || o.implicitARPPing)) {
    arpping(hs->hostbatch, hs->current_batch_sz);
    arpping_done = true;
  }

  gettimeofday(&now, NULL);
  if ((o.sendpref & PACKET_SEND_ETH) &&
      hs->hostbatch[0]->ifType() == devt_ethernet) {
    for (i=0; i < hs->current_batch_sz; i++) {
      if (!(hs->hostbatch[i]->flags & HOST_DOWN) &&
          !hs->hostbatch[i]->timedOut(&now)) {
        if (!setTargetNextHopMAC(hs->hostbatch[i])) {
          fatal("%s: Failed to determine dst MAC address for target %s",
              __func__, hs->hostbatch[i]->NameIP());
        }
      }
    }
  }

  /* Then we do the mass ping (if required - IP-level pings) */
  if ((pingtype == PINGTYPE_NONE && !arpping_done) || hs->hostbatch[0]->ifType() == devt_loopback) {
    for (i=0; i < hs->current_batch_sz; i++) {
      if (!hs->hostbatch[i]->timedOut(&now)) {
        initialize_timeout_info(&hs->hostbatch[i]->to);
        hs->hostbatch[i]->flags |= HOST_UP; /*hostbatch[i].up = 1;*/
        if (pingtype == PINGTYPE_NONE && !arpping_done)
          hs->hostbatch[i]->reason.reason_id = ER_USER;
        else
          hs->hostbatch[i]->reason.reason_id = ER_LOCALHOST;
      }
    }
  } else if (!arpping_done) {
    massping(hs->hostbatch, hs->current_batch_sz, ports);
  }

  if (!o.noresolve)
    nmap_mass_rdns(hs->hostbatch, hs->current_batch_sz);
}

Target *nexthost(HostGroupState *hs, const addrset *exclude_group,
                 struct scan_lists *ports, int pingtype) {
  if (hs->next_batch_no >= hs->current_batch_sz)
    refresh_hostbatch(hs, exclude_group, ports, pingtype);
  if (hs->next_batch_no >= hs->current_batch_sz)
    return NULL;

  return hs->hostbatch[hs->next_batch_no++];
}
