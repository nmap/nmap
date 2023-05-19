
/***************************************************************************
 * targets.cc -- Functions relating to "ping scanning" as well as          *
 * determining the exact IPs to hit based on CIDR and other input          *
 * formats.                                                                *
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


#include <nbase.h>
#include "targets.h"
#include "timing.h"
#include "tcpip.h"
#include "NmapOps.h"
#include "NewTargets.h"
#include "Target.h"
#include "scan_engine.h"
#include "nmap_dns.h"
#include "utils.h"
#include "nmap_error.h"
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
                  const struct addrset *exclude_group) {
  if (exclude_group == NULL)
    return 0;

  if (checksock == NULL)
    return 0;

  if (addrset_contains(exclude_group,checksock))
    return 1;
  return 0;
}

/* Load an exclude list from a file for --excludefile. */
int load_exclude_file(struct addrset *excludelist, FILE *fp) {
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
int load_exclude_string(struct addrset *excludelist, const char *s) {
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
int dumpExclude(const struct addrset *exclude_group) {
  addrset_print(stdout, exclude_group);
  return 1;
}

static void massping(Target *hostbatch[], int num_hosts, const struct scan_lists *ports) {
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
    if (hostbatch[i]->flags & HOST_DOWN)
      continue;
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
   These restrictions only apply for raw scans, including host discovery. */
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

  if (o.script) {
    unsigned long new_targets = NewTargets::get_queued();
    if (new_targets > 0) {
      std::string expr_string;
      expr_string = NewTargets::read().c_str();
      if (o.debugging > 3) {
        log_write(LOG_PLAIN,
                  "New targets: retrieved one of %ld pending in queue.\n",
                  new_targets);
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
    t->unscanned_addrs = hs->current_group.get_unscanned_addrs();
  }

  /* We figure out the source IP/device IFF
   * the scan type requires us to */
  if (o.RawScan()) {
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

static Target *next_target(HostGroupState *hs, struct addrset *exclude_group,
  const struct scan_lists *ports, int pingtype) {
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
  if (o.resume_ip.ss_family != AF_UNSPEC) {
    if (!sockaddr_storage_cmp(&o.resume_ip, &ss))
      /* We will continue starting with the next IP. */
      o.resume_ip.ss_family = AF_UNSPEC;
    goto tryagain;
  }

  /* Check exclude list. */
  if (hostInExclude((struct sockaddr *) &ss, sslen, exclude_group))
    goto tryagain;

  t = setup_target(hs, &ss, sslen, pingtype);
  if (t == NULL)
    goto tryagain;

  if (o.unique) {
    // Use the exclude list to avoid scanning this IP again if the user requested it.
    addrset_add_spec(exclude_group, t->targetipstr(), o.af(), 0);
  }
  return t;
}

static void refresh_hostbatch(HostGroupState *hs, struct addrset *exclude_group,
  const struct scan_lists *ports, int pingtype) {
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
      o.implicitARPPing) {
    arpping(hs->hostbatch, hs->current_batch_sz);
    arpping_done = true;
  }

  /* No other interface types are supported by ND ping except devt_ethernet
     at the moment. */
  if (hs->hostbatch[0]->ifType() == devt_ethernet &&
      hs->hostbatch[0]->af() == AF_INET6 &&
      hs->hostbatch[0]->directlyConnected() &&
      o.sendpref != PACKET_SEND_IP_STRONG &&
      o.implicitARPPing) {
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
          error("%s: Failed to determine dst MAC address for target %s",
              __func__, hs->hostbatch[i]->NameIP());
          hs->hostbatch[i]->flags = HOST_DOWN;
        }
      }
    }
  }

  /* Then we do the mass ping (if required - IP-level pings) */
  if ((pingtype == PINGTYPE_NONE && !arpping_done) || hs->hostbatch[0]->ifType() == devt_loopback) {
    for (i=0; i < hs->current_batch_sz; i++) {
      if (!(hs->hostbatch[i]->flags & HOST_DOWN || hs->hostbatch[i]->timedOut(&now))) {
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

Target *nexthost(HostGroupState *hs, struct addrset *exclude_group,
                 const struct scan_lists *ports, int pingtype) {
  if (hs->next_batch_no >= hs->current_batch_sz)
    refresh_hostbatch(hs, exclude_group, ports, pingtype);
  if (hs->next_batch_no >= hs->current_batch_sz)
    return NULL;

  return hs->hostbatch[hs->next_batch_no++];
}
