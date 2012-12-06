
/***************************************************************************
 * targets.cc -- Functions relating to "ping scanning" as well as          *
 * determining the exact IPs to hit based on CIDR and other input          *
 * formats.                                                                *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2012 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 with the clarifications and exceptions described  *
 * below.  This guarantees your right to use, modify, and redistribute     *
 * this software under certain conditions.  If you wish to embed Nmap      *
 * technology into proprietary software, we sell alternative licenses      *
 * (contact sales@insecure.com).  Dozens of software vendors already       *
 * license Nmap technology such as host discovery, port scanning, OS       *
 * detection, version detection, and the Nmap Scripting Engine.            *
 *                                                                         *
 * Note that the GPL places important restrictions on "derived works", yet *
 * it does not provide a detailed definition of that term.  To avoid       *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
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
 * works of Nmap, as well as other software we distribute under this       *
 * license such as Zenmap, Ncat, and Nping.  This list is not exclusive,   *
 * but is meant to clarify our interpretation of derived works with some   *
 * common examples.  Our interpretation applies only to Nmap--we don't     *
 * speak for other people's GPL works.                                     *
 *                                                                         *
 * If you have any questions about the GPL licensing restrictions on using *
 * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
 * we also offer alternative license to integrate Nmap into proprietary    *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates.  They also fund the      *
 * continued development of Nmap.  Please email sales@insecure.com for     *
 * further information.                                                    *
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
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING         *
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
static bool target_needs_new_hostgroup(const HostGroupState *hs, const Target *target) {
  int i;

  /* We've just started a new hostgroup, so any target is acceptable. */
  if (hs->current_batch_sz == 0)
    return false;

  /* There are no restrictions on non-root scans. */
  if (!(o.isr00t && target->deviceName() != NULL))
    return false;

  /* Different address family? */
  if (hs->hostbatch[0]->af() != target->af())
    return true;

  /* Different interface name? */
  if (hs->hostbatch[0]->deviceName() != NULL &&
      target->deviceName() != NULL &&
      strcmp(hs->hostbatch[0]->deviceName(), target->deviceName()) != 0) {
    return true;
  }

  /* Different source address? */
  if (sockaddr_storage_cmp(hs->hostbatch[0]->SourceSockAddr(), target->SourceSockAddr()) != 0)
    return true;

  /* Different direct connectedness? */
  if (hs->hostbatch[0]->directlyConnected() != target->directlyConnected())
    return true;

  /* Is there already a target with this same IP address? ultra_scan doesn't
     cope with that, because it uses IP addresses to look up targets from
     replies. What happens is one target gets the replies for all probes
     referring to the same IP address. */
  for (i = 0; i < hs->current_batch_sz; i++) {
    if (sockaddr_storage_cmp(hs->hostbatch[i]->TargetSockAddr(), target->TargetSockAddr()) == 0)
      return true;
  }

  return false;
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

Target *nexthost(HostGroupState *hs, const addrset *exclude_group,
                 struct scan_lists *ports, int pingtype) {
  int i;
  struct sockaddr_storage ss;
  size_t sslen;
  struct route_nfo rnfo;
  bool arpping_done = false;
  struct timeval now;

  if (hs->next_batch_no < hs->current_batch_sz) {
    /* Woop!  This is easy -- we just pass back the next host struct */
    return hs->hostbatch[hs->next_batch_no++];
  }
  /* Doh, we need to refresh our array */
  /* for (i=0; i < hs->max_batch_sz; i++) hs->hostbatch[i] = new Target(); */

  hs->current_batch_sz = hs->next_batch_no = 0;
  do {
    /* Grab anything we have in our current_expression */
    while (hs->current_batch_sz < hs->max_batch_sz && 
        hs->current_expression.get_next_host(&ss, &sslen) == 0) {
      Target *t;

      if (hostInExclude((struct sockaddr *)&ss, sslen, exclude_group)) {
        continue; /* Skip any hosts the user asked to exclude */
      }
      t = new Target();
      t->setTargetSockAddr(&ss, sslen);

      /* Special handling for the resolved address (for example whatever
         scanme.nmap.org resolves to in scanme.nmap.org/24). */
      if (hs->current_expression.is_resolved_address(&ss)) {
        if (hs->current_expression.get_namedhost())
          t->setTargetName(hs->current_expression.get_resolved_name());
        t->resolved_addrs = hs->current_expression.get_resolved_addrs();
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
        t->TargetSockAddr(&ss, &sslen);
        if (!nmap_route_dst(&ss, &rnfo)) {
          log_bogus_target(inet_ntop_ez(&ss, sslen));
          error("%s: failed to determine route to %s", __func__, t->NameIP());
          continue;
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
        t->setSourceSockAddr(&rnfo.srcaddr, sizeof(rnfo.srcaddr));
        if (hs->current_batch_sz == 0) /* Because later ones can have different src addy and be cut off group */
          o.decoys[o.decoyturn] = t->v4source();
        t->setDeviceNames(rnfo.ii.devname, rnfo.ii.devfullname);
        t->setMTU(rnfo.ii.mtu);
        // printf("Target %s %s directly connected, goes through local iface %s, which %s ethernet\n", t->NameIP(), t->directlyConnected()? "IS" : "IS NOT", t->deviceName(), (t->ifType() == devt_ethernet)? "IS" : "IS NOT");
      }

      /* Does this target need to go in a separate host group? */
      if (target_needs_new_hostgroup(hs, t)) {
        /* Cancel everything!  This guy must go in the next group and we are
           out of here */
        hs->current_expression.return_last_host();
        delete t;
        goto batchfull;
      }

      hs->hostbatch[hs->current_batch_sz++] = t;
    }

    if (hs->current_batch_sz < hs->max_batch_sz &&
        hs->next_expression < hs->num_expressions) {
      /* We are going to have to pop in another expression. */
      while (hs->next_expression < hs->num_expressions) {
        const char *expr;
        expr = hs->target_expressions[hs->next_expression++];
        if (hs->current_expression.parse_expr(expr, o.af()) != 0)
          log_bogus_target(expr);
        else
          break;
      }
    } else break;
  } while(1);

batchfull:

  if (hs->current_batch_sz == 0)
    return NULL;

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

  return hs->hostbatch[hs->next_batch_no++];
}
