
/***************************************************************************
 * targets.cc -- Functions relating to "ping scanning" as well as          *
 * determining the exact IPs to hit based on CIDR and other input          *
 * formats.                                                                *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2010 Insecure.Com LLC. Nmap is    *
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
 * listed in the included COPYING.OpenSSL file, and distribute linked      *
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


#include "targets.h"
#include "timing.h"
#include "NmapOps.h"
#include "TargetGroup.h"
#include "Target.h"
#include "scan_engine.h"
#include "nmap_dns.h"
#include "nmap_tty.h"
#include "utils.h"

using namespace std;
extern NmapOps o;

/* Conducts an ARP ping sweep of the given hosts to determine which ones
   are up on a local ethernet network */
static void arpping(Target *hostbatch[], int num_hosts) {
  /* First I change hostbatch into a vector<Target *>, which is what ultra_scan
     takes.  I remove hosts that cannot be ARP scanned (such as localhost) */
  vector<Target *> targets;
  int targetno;
  targets.reserve(num_hosts);

  for (targetno = 0; targetno < num_hosts; targetno++) {
    initialize_timeout_info(&hostbatch[targetno]->to);
    /* Default timout should be much lower for arp */
    hostbatch[targetno]->to.timeout = MIN(o.initialRttTimeout(), 100) * 1000;
    if (!hostbatch[targetno]->SrcMACAddress()) {
      bool islocal = islocalhost(hostbatch[targetno]->v4hostip());
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
  if (!targets.empty())
    ultra_scan(targets, NULL, PING_SCAN_ARP);
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
                  TargetGroup *exclude_group) {
  unsigned long tmpTarget; /* ip we examine */
  int i=0;                 /* a simple index */
  char targets_type;       /* what is the address type of the Target Group */
  struct sockaddr_storage ss; 
  struct sockaddr_in *sin = (struct sockaddr_in *) &ss;
  size_t slen;             /* needed for funct but not used */
  unsigned long mask = 0;  /* our trusty netmask, which we convert to nbo */
  struct sockaddr_in *checkhost_in;

  if ((TargetGroup *)0 == exclude_group)
    return 0;

  checkhost_in = NULL;
  if (checksock->sa_family == AF_INET) {
    assert(checksocklen >= sizeof(struct sockaddr_in));
    checkhost_in = (struct sockaddr_in *) checksock;
  }

  /* First find out what type of addresses are in the target group */
  targets_type = exclude_group[i].get_targets_type();

  /* Lets go through the targets until we reach our uninitialized placeholder */
  while (exclude_group[i].get_targets_type() != TargetGroup::TYPE_NONE) { 
    /* while there are still hosts in the target group */
    while (exclude_group[i].get_next_host(&ss, &slen) == 0) {
      tmpTarget = sin->sin_addr.s_addr; 

      /* For Netmasks simply compare the network bits and move to the next
       * group if it does not compare, we don't care about the individual addrs */
      if (targets_type == TargetGroup::IPV4_NETMASK) {
        if (checkhost_in == NULL)
          break;
        mask = htonl((unsigned long) (0-1) << (32-exclude_group[i].get_mask()));
        if ((tmpTarget & mask) == (checkhost_in->sin_addr.s_addr & mask)) {
          exclude_group[i].rewind();
          return 1;
        } else {
          break;
        }
      } 
      /* For ranges we need to be a little more slick, if we don't find a match
       * we should skip the rest of the addrs in the octet, thank wam for this
       * optimization */
      else if (targets_type == TargetGroup::IPV4_RANGES) {
        if (checkhost_in == NULL)
          break;
        if (tmpTarget == checkhost_in->sin_addr.s_addr) {
          exclude_group[i].rewind();
          return 1;
        } else {
          /* note these are in network byte order */
          if ((tmpTarget & 0x000000ff) != (checkhost_in->sin_addr.s_addr & 0x000000ff))
            exclude_group[i].skip_range(TargetGroup::FIRST_OCTET); 
          else if ((tmpTarget & 0x0000ff00) != (checkhost_in->sin_addr.s_addr & 0x0000ff00))
            exclude_group[i].skip_range(TargetGroup::SECOND_OCTET); 
          else if ((tmpTarget & 0x00ff0000) != (checkhost_in->sin_addr.s_addr & 0x00ff0000))
            exclude_group[i].skip_range(TargetGroup::THIRD_OCTET); 

          continue;
        }
      }
#if HAVE_IPV6
      else if (targets_type == TargetGroup::IPV6_ADDRESS) {
        fatal("exclude file not supported for IPV6 -- If it is important to you, send a mail to fyodor@insecure.org so I can guage support\n");
      }
#endif
    }
    exclude_group[i++].rewind();
  }

  /* we did not find the host */
  return 0;
}

/* Convert a vector of host specifications to an array (allocated with new[]) of
   TargetGroups. The size of the returned array is one greater than the number
   of host specs, to leave on uninitialized member at the end. */
static TargetGroup *specs_to_targetgroups(const std::vector<std::string> &specs) {
  TargetGroup *excludelist;
  unsigned int i;

  excludelist = new TargetGroup[specs.size() + 1];

  for (i = 0; i < specs.size(); i++) {
    if (excludelist[i].parse_expr(specs[i].c_str(), o.af()) == 0) {
      if (o.debugging > 1)
        error("Loaded exclude target of: %s", specs[i].c_str());
    }
  }

  return excludelist;
}

/* Load an exclude list from a file for --excludefile. */
TargetGroup* load_exclude_file(FILE *fp) {
  std::vector<std::string> specs;
  char host_spec[1024];
  size_t n;

  while ((n = read_host_from_file(fp, host_spec, sizeof(host_spec))) > 0) {
    if (n >= sizeof(host_spec))
      fatal("One of your exclude file specifications was too long to read (>= %u chars)", (unsigned int) sizeof(host_spec));
    specs.push_back(host_spec);
  }

  return specs_to_targetgroups(specs);
}

/* Load a comma-separated exclude list from a string, the argument to
   --exclude. */
TargetGroup* load_exclude_string(const char *s) {
  std::vector<std::string> specs;
  const char *begin, *p;

  p = s;
  while (*p != '\0') {
    begin = p;
    while (*p != '\0' && *p != ',')
      p++;
    specs.push_back(std::string(begin, p - begin));
    if (*p == '\0')
      break;
    p++;
  }

  return specs_to_targetgroups(specs);
}

static inline bool is_host_separator(int c) {
  return c == ' ' || c == '\r' || c == '\n' || c == '\t' || c == '\0';
}

/* Read a single host specification from a file, as for -iL and --excludefile.
   It returns the length of the string read; an overflow is indicated when the
   return value is >= n. Returns 0 if there was no specification to be read. The
   buffer is always null-terminated. */
size_t read_host_from_file(FILE *fp, char *buf, size_t n)
{
  int ch;
  size_t i;

  i = 0;
  ch = getc(fp);
  while (is_host_separator(ch) || ch == '#') {
    if (ch == '#') {
      /* Skip comments to the end of the line. */
      while ((ch = getc(fp)) != EOF && ch != '\n')
        ;
    } else {
      ch = getc(fp);
    }
  }
  while (ch != EOF && !(is_host_separator(ch) || ch == '#')) {
    if (i < n)
      buf[i] = ch;
    i++;
    ch = getc(fp);
  }
  if (ch != EOF)
    ungetc(ch, fp);
  if (i < n)
    buf[i] = '\0';
  else if (n > 0)
    /* Null-terminate even though it was too long. */
    buf[n - 1] = '\0';

  return i;
}

/* A debug routine to dump some information to stdout. Invoked if debugging is
   set to 3 or higher. I had to make significant changes from wam's code.
   Although wam displayed much more detail, alot of this is now hidden inside of
   the Target Group Object. Rather than writing a bunch of methods to return
   private attributes, which would only be used for debugging, I went for the
   method below. */
int dumpExclude(TargetGroup *exclude_group) {
  int i=0, debug_save=0, type=TargetGroup::TYPE_NONE;
  unsigned int mask = 0;
  struct sockaddr_storage ss;
  struct sockaddr_in *sin = (struct sockaddr_in *) &ss;
  size_t slen;

  /* shut off debugging for now, this is a debug routine in itself, we don't
     want to see all the debug messages inside of the object */
  debug_save = o.debugging;
  o.debugging = 0;

  while ((type = exclude_group[i].get_targets_type()) != TargetGroup::TYPE_NONE) {
    switch (type) {
      case TargetGroup::IPV4_NETMASK:
        exclude_group[i].get_next_host(&ss, &slen);
        mask = exclude_group[i].get_mask();
        error("exclude host group %d is %s/%d", i, inet_ntoa(sin->sin_addr), mask);
        break;

      case TargetGroup::IPV4_RANGES:
        while (exclude_group[i].get_next_host(&ss, &slen) == 0) 
          error("exclude host group %d is %s", i, inet_ntoa(sin->sin_addr));
        break;

      case TargetGroup::IPV6_ADDRESS:
        fatal("IPV6 addresses are not supported in the exclude file\n");
        break;

      default:
        fatal("Unknown target type in exclude file.\n");
    }
    exclude_group[i++].rewind();
  }

  /* return debugging to what it was */
  o.debugging = debug_save; 
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
     3. it is directly connected when the other hosts are not, or vice versa.
   These restrictions only apply for raw scans. */
static bool target_needs_new_hostgroup(const HostGroupState *hs, const Target *target) {
  return o.af() == AF_INET && o.isr00t && hs->current_batch_sz > 0 && 
    target->deviceName() && 
    (target->v4source().s_addr != target->v4source().s_addr || 
     strcmp(hs->hostbatch[0]->deviceName(), target->deviceName()) != 0 ||
     target->directlyConnected() != target->directlyConnected());
}

Target *nexthost(HostGroupState *hs, TargetGroup *exclude_group,
                 struct scan_lists *ports, int pingtype) {
  int i;
  struct sockaddr_storage ss;
  size_t sslen;
  struct intf_entry *ifentry;
  u32 ifbuf[200] ;
  struct route_nfo rnfo;
  bool arpping_done = false;
  struct timeval now;

  ifentry = (struct intf_entry *) ifbuf; 
  ifentry->intf_len = sizeof(ifbuf); // TODO: May want to use a larger buffer if interface aliases prove important.
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
      if (o.isr00t && o.af() == AF_INET && 
          ((pingtype & (PINGTYPE_TCP|PINGTYPE_UDP|PINGTYPE_SCTP_INIT|PINGTYPE_PROTO|PINGTYPE_ARP)) || o.RawScan()
#ifdef WIN32
           || (pingtype & (PINGTYPE_ICMP_PING|PINGTYPE_ICMP_MASK|PINGTYPE_ICMP_TS))
#endif // WIN32
          )) {
        t->TargetSockAddr(&ss, &sslen);
        if (!route_dst(&ss, &rnfo)) {
          fatal("%s: failed to determine route to %s", __func__, t->NameIP());
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
      while(hs->current_expression.parse_expr(hs->target_expressions[hs->next_expression++], o.af()) != 0) 
        if (hs->next_expression >= hs->num_expressions)
          break;
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
      hs->hostbatch[0]->directlyConnected() && 
      o.sendpref != PACKET_SEND_IP_STRONG) {
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

  /* TODO: Maybe I should allow real ping scan of directly connected
     ethernet hosts? */
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
