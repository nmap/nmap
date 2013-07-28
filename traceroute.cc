/***************************************************************************
 * traceroute.cc -- Parallel multi-protocol traceroute feature             *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2013 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE CLARIFICATIONS  *
 * AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your right to use,    *
 * modify, and redistribute this software under certain conditions.  If    *
 * you wish to embed Nmap technology into proprietary software, we sell    *
 * alternative licenses (contact sales@insecure.com).  Dozens of software  *
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
 * including the special and conditions of the license text as well.       *
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
 * continued development of Nmap.  Please email sales@insecure.com for     *
 * further information.                                                    *
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

/*
Traceroute for Nmap. This traceroute is faster than a traditional traceroute
because it sends several probes in parallel and detects shared traces.

The algorithm works by sending probes with varying TTL values and waiting for
TTL_EXCEEDED messages. As intermediate hops are discovered, they are entered
into a global hop cache that is shared between targets and across host groups.
When a hop is discovered and is found to be already in the cache, the trace for
that target is linked into the cached trace and there is no need to try lower
TTLs. The process results in the building of a tree of Hop structures.

The order in which probes are sent does not matter to the accuracy of the
algorithm but it does matter to the speed. The sooner a shared trace can be
detected, and the higher the TTL at which it is detected, the fewer probes need
to be sent. The ideal situation is to start sending probes with a TTL equal to
the true distance and count downward from there. In that case it may only be
necessary to send two probes per target: one at the distance of the target to
get a response, and one at distance - 1 to get a cache hit. When the distance
isn't known in advance, the algorithm arbitrarily starts at a TTL of 10 and
counts downward, then counts upward from 11 until it reaches the target. So a
typical trace may look like

TTL 10 -> TTL_EXCEEDED
TTL  9 -> TTL_EXCEEDED
TTL  8 -> TTL_EXCEEDED
TTL  7 -> cache hit
TTL 11 -> TTL_EXCEEDED
TTL 12 -> TTL_EXCEEDED
TTL 13 -> SYN/ACK, or whatever is the target's response to the probe

The output for this host would then say "Hops 1-7 are the same as for ...".

The detection of shared traces rests on the assumption that all paths going
through a router at a certain TTL will be identical up to and including the
router. This assumption is not always true. Even if two targets are each one hop
past router X at TTL 10, packets may follow different paths to each host (and
those paths may even change over time). This traceroute algorithm will be fooled
by such a situation, and will report that the paths are identical up to
router X. The only way to be sure is to do a complete trace for each target
individually.
*/

#include "nmap_dns.h"
#include "nmap_error.h"
#include "nmap_tty.h"
#include "osscan2.h"
#include "payload.h"
#include "timing.h"
#include "NmapOps.h"
#include "Target.h"

#include "struct_ip.h"

#include <dnet.h>

#include <algorithm>
#include <list>
#include <map>
#include <set>
#include <vector>

extern NmapOps o;

/* The highest TTL we go up to if the target itself doesn't respond. */
#define MAX_TTL 30
#define MAX_OUTSTANDING_PROBES 10
#define MAX_RESENDS 2
/* In milliseconds. */
#define PROBE_TIMEOUT 1000
/* If the hop cache (including timed-out hops) is bigger than this after a
   round, the hop is cleared and rebuilt from scratch. */
#define MAX_HOP_CACHE_SIZE 1000

struct Hop;
class HostState;
class Probe;

/* An object of this class is a (TTL, address) pair that uniquely identifies a
   hop. Hops in the hop_cache are indexed by this type. */
struct HopIdent {
  u8 ttl;
  struct sockaddr_storage addr;

  HopIdent(u8 ttl, const struct sockaddr_storage &addr) {
    this->addr = addr;
    this->ttl = ttl;
  }

  bool operator<(const struct HopIdent &other) const {
    if (ttl < other.ttl)
      return true;
    else if (ttl > other.ttl)
      return false;
    else
      return sockaddr_storage_cmp(&addr, &other.addr) < 0;
  }
};

/* A global random token used to distinguish this traceroute's probes from
   those of other traceroutes possibly running on the same machine. */
static u16 global_id;
/* A global cache of known hops, indexed by TTL and address. */
static std::map<struct HopIdent, Hop *> hop_cache;
/* A list of timedout hops, which are not kept in hop_cache, so we can delete
   all hops on occasion. */
static std::list<Hop *> timedout_hops;
/* The TTL at which we start sending probes if we don't have a distance
   estimate. This is updated after each host group on the assumption that hosts
   across groups will not differ much in distance. Having this closer to the
   true distance makes the trace faster but is not needed for accuracy. */
static u8 initial_ttl = 10;

static struct timeval get_now(struct timeval *now = NULL);
static const char *ss_to_string(const struct sockaddr_storage *ss);

struct Hop {
  Hop *parent;
  struct sockaddr_storage tag;
  /* When addr.ss_family == 0, this hop represents a timeout. */
  struct sockaddr_storage addr;
  u8 ttl;
  float rtt; /* In milliseconds. */
  std::string hostname;

  Hop() {
    this->parent = NULL;
    this->addr.ss_family = 0;
    this->ttl = 0;
    this->rtt = -1.0;
    this->tag.ss_family = 0;
  }

  Hop(u8 ttl, const struct sockaddr_storage &addr, float rtt) {
    this->parent = NULL;
    this->addr = addr;
    this->ttl = ttl;
    this->rtt = rtt;
    this->tag.ss_family = 0;
  }
};

class HostState {
public:
  enum counting_state { COUNTING_DOWN, COUNTING_UP };

  Target *target;
  /* A bitmap of TTLs that have been sent, to avoid duplicates when we switch
     around the order counting up or down. */
  std::vector<bool> sent_ttls;
  u8 current_ttl;
  enum counting_state state;
  /* If nonzero, the known hop distance to the target. */
  int reached_target;
  struct probespec pspec;
  std::list<Probe *> unanswered_probes;
  std::list<Probe *> active_probes;
  std::list<Probe *> pending_resends;
  Hop *hops;

  HostState(Target *target);
  ~HostState();
  bool has_more_probes() const;
  bool is_finished() const;
  bool send_next_probe(int rawsd, eth_t *ethsd);
  void next_ttl();
  void count_up();
  int cancel_probe(std::list<Probe *>::iterator it);
  int cancel_probes_below(u8 ttl);
  int cancel_probes_above(u8 ttl);
  Hop *insert_hop(u8 ttl, const struct sockaddr_storage *addr, float rtt);
  void link_to(Hop *hop);
  double completion_fraction() const;

private:
  void child_parent_ttl(u8 ttl, Hop **child, Hop **parent);
  static u8 distance_guess(const Target *target);
  static struct probespec get_probe(const Target *target);
};

class Probe {
private:
  /* This is incremented with each instantiated probe. */
  static u16 token_counter;

  unsigned int num_resends;

public:
  HostState *host;
  struct probespec pspec;
  u8 ttl;
  /* The token is used to match up probe replies. */
  u16 token;
  struct timeval sent_time;

  Probe(HostState *host, struct probespec pspec, u8 ttl);
  virtual ~Probe();
  void send(int rawsd, eth_t *ethsd, struct timeval *now = NULL);
  void resend(int rawsd, eth_t *ethsd, struct timeval *now = NULL);
  bool is_timedout(struct timeval *now = NULL) const;
  bool may_resend() const;
  virtual unsigned char *build_packet(const struct sockaddr_storage *source,
    u32 *len) const = 0;

  static Probe *make(HostState *host, struct probespec pspec, u8 ttl);
};
u16 Probe::token_counter = 0x0000;

class TracerouteState {
public:
  std::list<HostState *> active_hosts;
  /* The next send time for enforcing scan delay. */
  struct timeval next_send_time;

  TracerouteState(std::vector<Target *> &targets);
  ~TracerouteState();

  void send_new_probes();
  void read_replies(long timeout);
  void cull_timeouts();
  void remove_finished_hosts();
  void resolve_hops();
  void transfer_hops();

  double completion_fraction() const;

private:
  eth_t *ethsd;
  int rawsd;
  pcap_t *pd;
  int num_active_probes;

  std::vector<HostState *> hosts;
  std::list<HostState *>::iterator next_sending_host;

  void next_active_host();
  Probe *lookup_probe(const struct sockaddr_storage *target_addr, u16 token);
  void set_host_hop(HostState *host, u8 ttl,
    const struct sockaddr_storage *from_addr, float rtt);
  void set_host_hop_timedout(HostState *host, u8 ttl);
};

static Hop *merge_hops(const struct sockaddr_storage *tag, Hop *a, Hop *b);
static Hop *hop_cache_lookup(u8 ttl, const struct sockaddr_storage *addr);
static void hop_cache_insert(Hop *hop);
static unsigned int hop_cache_size();

HostState::HostState(Target *target) : sent_ttls(MAX_TTL + 1, false) {
  this->target = target;
  current_ttl = MIN(MAX(1, HostState::distance_guess(target)), MAX_TTL);
  state = HostState::COUNTING_DOWN;
  reached_target = 0;
  pspec = HostState::get_probe(target);
  hops = NULL;
}

HostState::~HostState() {
  /* active_probes and pending_resends are subsets of unanswered_probes, so we
     delete the allocated probes in unanswered_probes only. */
  while (!unanswered_probes.empty()) {
    delete *unanswered_probes.begin();
    unanswered_probes.pop_front();
  }
  while (!active_probes.empty())
    active_probes.pop_front();
  while (!pending_resends.empty())
    pending_resends.pop_front();
}

bool HostState::has_more_probes() const {
  /* We are done if we are counting up and
     1. we've reached and exceeded the target, or
     2. we've exceeded MAX_TTL. */
  return !(state == HostState::COUNTING_UP
           && ((reached_target > 0 && current_ttl >= reached_target)
               || current_ttl > MAX_TTL));
}

bool HostState::is_finished() const {
  return !this->has_more_probes()
    && active_probes.empty() && pending_resends.empty();
}

bool HostState::send_next_probe(int rawsd, eth_t *ethsd) {
  Probe *probe;

  /* Do a resend if possible. */
  if (!pending_resends.empty()) {
    probe = pending_resends.front();
    pending_resends.pop_front();
    active_probes.push_back(probe);
    probe->resend(rawsd, ethsd);
    return true;
  }

  this->next_ttl();

  if (!this->has_more_probes())
    return false;

  probe = Probe::make(this, pspec, current_ttl);
  unanswered_probes.push_back(probe);
  active_probes.push_back(probe);
  probe->send(rawsd, ethsd);
  sent_ttls[current_ttl] = true;

  return true;
}

/* Find the next TTL we should send to. */
void HostState::next_ttl() {
  assert(current_ttl > 0);
  if (state == HostState::COUNTING_DOWN) {
    while (current_ttl > 1 && sent_ttls[current_ttl])
      current_ttl--;
    if (current_ttl == 1)
      state = HostState::COUNTING_UP;
  }
  /* Note no "else". */
  if (state == HostState::COUNTING_UP) {
    while (current_ttl <= MAX_TTL && sent_ttls[current_ttl])
      current_ttl++;
  }
}

int HostState::cancel_probe(std::list<Probe *>::iterator it) {
  int count;

  count = active_probes.size();
  active_probes.remove(*it);
  count -= active_probes.size();
  pending_resends.remove(*it);
  delete *it;
  unanswered_probes.erase(it);

  return count;
}

int HostState::cancel_probes_below(u8 ttl) {
  std::list<Probe *>::iterator it, next;
  int count;

  count = 0;
  for (it = unanswered_probes.begin(); it != unanswered_probes.end(); it = next) {
    next = it;
    next++;
    if ((*it)->ttl < ttl)
      count += this->cancel_probe(it);
  }

  return count;
}

int HostState::cancel_probes_above(u8 ttl) {
  std::list<Probe *>::iterator it, next;
  int count;

  count = 0;
  for (it = unanswered_probes.begin(); it != unanswered_probes.end(); it = next) {
    next = it;
    next++;
    if ((*it)->ttl > ttl)
      count += this->cancel_probe(it);
  }

  return count;
}

Hop *HostState::insert_hop(u8 ttl, const struct sockaddr_storage *addr,
  float rtt) {
  Hop *hop, *prev, *p;

  this->child_parent_ttl(ttl, &prev, &p);
  if (p != NULL && p->ttl == ttl) {
    hop = p;
    /* Collision with the same TTL and a different address. */
    if (hop->addr.ss_family == 0) {
      /* Hit a timed-out hop. Fill in the missing address and RTT. */
      hop->addr = *addr;
      hop->rtt = rtt;
    } else {
      if (o.debugging) {
        log_write(LOG_STDOUT, "Found existing %s", ss_to_string(&hop->addr));
        log_write(LOG_STDOUT, " while inserting %s at TTL %d for %s\n", 
          ss_to_string(addr), ttl, target->targetipstr());
      }
    }
  } else {
    hop = new Hop(ttl, *addr, rtt);
    hop->parent = p;
    if (prev == NULL) {
      size_t sslen;
      this->hops = hop;
      sslen = sizeof(hop->tag);
      target->TargetSockAddr(&hop->tag, &sslen);
    } else {
      prev->parent = hop;
      hop->tag = prev->tag;
    }
    hop_cache_insert(hop);
  }

  return hop;
}

void HostState::link_to(Hop *hop) {
  Hop *prev, *p;

  this->child_parent_ttl(hop->ttl, &prev, &p);
  if (hop == p) {
    /* Already linked for this host. This can happen a reply for a higher TTL
       results in a merge, and later a reply for a lower TTL comes back. */
    return;
  }
  if (o.debugging > 1) {
    log_write(LOG_STDOUT, "Merging traces below TTL %d for %s",
      hop->ttl, ss_to_string(&hop->tag));
    log_write(LOG_STDOUT, " and %s\n", target->targetipstr());
  }
  hop = merge_hops(&hop->tag, hop, p);
  if (prev == NULL)
    this->hops = hop;
  else
    prev->parent = hop;
}

double HostState::completion_fraction() const {
  std::vector<bool>::iterator it;
  unsigned int i, n;

  if (this->is_finished())
    return 1.0;

  n = 0;
  for (i = 0; i < sent_ttls.size(); i++) {
    if (sent_ttls[i])
      n++;
  }

  return (double) n / sent_ttls.size();
}

void HostState::child_parent_ttl(u8 ttl, Hop **child, Hop **parent) {
  *child = NULL;
  *parent = this->hops;
  while (*parent != NULL && (*parent)->ttl > ttl) {
    *child = *parent;
    *parent = (*parent)->parent;
  }
}

u8 HostState::distance_guess(const Target *target) {
  /* Use the distance from OS detection if we have it. */
  if (target->distance != -1)
    return target->distance;
  else
    /* initial_ttl is a variable with file-level scope. */
    return initial_ttl;
}

/* Get the probe that will be used for the traceroute. This is the
   highest-quality probe found in ping or port scanning, or ICMP echo if no
   responsive probe is known. */
struct probespec HostState::get_probe(const Target *target) {
  struct probespec probe;

  probe = target->pingprobe;
  if (target->af() == AF_INET &&
      (probe.type == PS_TCP || probe.type == PS_UDP || probe.type == PS_SCTP || probe.type == PS_ICMP)) {
    /* Nothing needed. */
  } else if (target->af() == AF_INET6 &&
      (probe.type == PS_TCP || probe.type == PS_UDP || probe.type == PS_SCTP || probe.type == PS_ICMPV6)) {
    /* Nothing needed. */
  } else if (probe.type == PS_PROTO) {
    /* If this is an IP protocol probe, fill in some fields for some common
       protocols. We cheat and store them in the TCP-, UDP-, SCTP- and
       ICMP-specific fields. */
    if (probe.proto == IPPROTO_TCP) {
      probe.pd.tcp.flags = TH_ACK;
      probe.pd.tcp.dport = get_random_u16();
    } else if (probe.proto == IPPROTO_UDP) {
      probe.pd.udp.dport = get_random_u16();
    } else if (probe.proto == IPPROTO_SCTP) {
      probe.pd.sctp.dport = get_random_u16();
    } else if (probe.proto == IPPROTO_ICMP) {
      probe.pd.icmp.type = ICMP_ECHO;
    } else if (probe.proto == IPPROTO_ICMPV6) {
      probe.pd.icmp.type = ICMPV6_ECHO;
    } else {
      fatal("Unknown protocol %d", probe.proto);
    }
  } else {
    /* No responsive probe known? The user probably skipped both ping and
       port scan. Guess ICMP echo as the most likely to get a response. */
    if (target->af() == AF_INET) {
      probe.type = PS_ICMP;
      probe.proto = IPPROTO_ICMP;
      probe.pd.icmp.type = ICMP_ECHO;
      probe.pd.icmp.code = 0;
    } else if (target->af() == AF_INET6) {
      probe.type = PS_ICMPV6;
      probe.proto = IPPROTO_ICMPV6;
      probe.pd.icmp.type = ICMPV6_ECHO;
      probe.pd.icmp.code = 0;
    } else {
      fatal("Unknown address family %d", target->af());
    }
  }

  return probe;
}

Probe::Probe(HostState *host, struct probespec pspec, u8 ttl) {
  this->host = host;
  this->pspec = pspec;
  this->ttl = ttl;
  token = Probe::token_counter++;
  sent_time.tv_sec = 0;
  sent_time.tv_usec = 0;
  num_resends = 0;
}

Probe::~Probe() {
}

void Probe::send(int rawsd, eth_t *ethsd, struct timeval *now) {
  struct eth_nfo eth;
  struct eth_nfo *ethp;
  int decoy;

  /* Set up the Ethernet handle if we're using that. */
  if (ethsd != NULL) {
    memcpy(eth.srcmac, host->target->SrcMACAddress(), 6);
    memcpy(eth.dstmac, host->target->NextHopMACAddress(), 6);
    eth.ethsd = ethsd;
    eth.devname[0] = '\0';
    ethp = &eth;
  } else {
    ethp = NULL;
  }

  for (decoy = 0; decoy < o.numdecoys; decoy++) {
    struct sockaddr_storage source;
    size_t source_len;
    unsigned char *packet;
    u32 packetlen;

    if (decoy == o.decoyturn) {
      source_len = sizeof(source);
      host->target->SourceSockAddr(&source, &source_len);
      sent_time = get_now(now);
    } else {
      if (o.af() == AF_INET) {
        struct sockaddr_in *sin;

        sin = (struct sockaddr_in *) &source;
        sin->sin_family = AF_INET;
        sin->sin_addr = o.decoys[decoy];
      } else {
        /* Decoys are IPv4-only. */
        continue;
      }
    }

    packet = this->build_packet(&source, &packetlen);
    send_ip_packet(rawsd, ethp, host->target->TargetSockAddr(), packet, packetlen);
    free(packet);
  }
}

void Probe::resend(int rawsd, eth_t *ethsd, struct timeval *now) {
  num_resends++;
  this->send(rawsd, ethsd, now);
}

bool Probe::is_timedout(struct timeval *now) const {
  struct timeval tv;

  tv = get_now(now);

  return TIMEVAL_MSEC_SUBTRACT(tv, sent_time) > PROBE_TIMEOUT;
}

bool Probe::may_resend() const {
  return num_resends < MIN(o.getMaxRetransmissions(), MAX_RESENDS);
}

/* Probe is an abstract class with a missing build_packet method. These concrete
   subclasses implement the method for different probe types. */

class ICMPProbe : public Probe
{
public:
  ICMPProbe(HostState *host, struct probespec pspec, u8 ttl)
  : Probe(host, pspec, ttl) {
  }

  unsigned char *build_packet(const struct sockaddr_storage *source, u32 *len) const {
    const struct sockaddr_in *sin;
    assert(source->ss_family == AF_INET);
    sin = (struct sockaddr_in *) source;
    return build_icmp_raw(&sin->sin_addr, host->target->v4hostip(), ttl,
      0x0000, 0x00, false, NULL, 0, token, global_id,
      pspec.pd.icmp.type, pspec.pd.icmp.code,
      o.extra_payload, o.extra_payload_length, len);
  }
};

class TCPProbe : public Probe
{
public:
  TCPProbe(HostState *host, struct probespec pspec, u8 ttl)
  : Probe(host, pspec, ttl) {
  }
  unsigned char *build_packet(const struct sockaddr_storage *source, u32 *len) const {
    const char *tcpopts;
    int tcpoptslen;
    u32 ack;

    tcpopts = NULL;
    tcpoptslen = 0;
    ack = 0;
    if ((pspec.pd.tcp.flags & TH_SYN) == TH_SYN) {
      /* MSS 1460 bytes. */
      tcpopts = "\x02\x04\x05\xb4";
      tcpoptslen = 4;
    } else if ((pspec.pd.tcp.flags & TH_ACK) == TH_ACK) {
      ack = get_random_u32();
    }

    /* For TCP we encode the token in the source port. */
    if (source->ss_family == AF_INET) {
      const struct sockaddr_in *sin = (struct sockaddr_in *) source;
      return build_tcp_raw(&sin->sin_addr, host->target->v4hostip(), ttl,
        get_random_u16(), get_random_u8(), false, NULL, 0,
        token ^ global_id, pspec.pd.tcp.dport, get_random_u32(), ack, 0x00,
        pspec.pd.tcp.flags, get_random_u16(), 0, (const u8 *) tcpopts, tcpoptslen,
        o.extra_payload, o.extra_payload_length, len);
    } else if (source->ss_family == AF_INET6) {
      const struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) source;
      return build_tcp_raw_ipv6(&sin6->sin6_addr, host->target->v6hostip(),
        0, 0, ttl,
        token ^ global_id, pspec.pd.tcp.dport, get_random_u32(), ack, 0x00,
        pspec.pd.tcp.flags, get_random_u16(), 0, (const u8 *) tcpopts, tcpoptslen,
        o.extra_payload, o.extra_payload_length, len);
    } else {
      fatal("Unknown address family %u in %s.", source->ss_family, __func__);
    }
  }
};

class UDPProbe : public Probe
{
public:
  UDPProbe(HostState *host, struct probespec pspec, u8 ttl)
  : Probe(host, pspec, ttl) {
  }
  unsigned char *build_packet(const struct sockaddr_storage *source, u32 *len) const {
    const char *payload;
    size_t payload_length;

    payload = get_udp_payload(pspec.pd.udp.dport, &payload_length);

    /* For UDP we encode the token in the source port. */
    if (source->ss_family == AF_INET) {
      const struct sockaddr_in *sin = (struct sockaddr_in *) source;
      return build_udp_raw(&sin->sin_addr, host->target->v4hostip(), ttl,
        get_random_u16(), get_random_u8(), false, NULL, 0,
        token ^ global_id, pspec.pd.udp.dport,
        payload, payload_length, len);
    } else if (source->ss_family == AF_INET6) {
      const struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) source;
      return build_udp_raw_ipv6(&sin6->sin6_addr, host->target->v6hostip(),
        0, 0, ttl,
        token ^ global_id, pspec.pd.udp.dport,
        payload, payload_length, len);
    } else {
      fatal("Unknown address family %u in %s.", source->ss_family, __func__);
    }
  }
};

class SCTPProbe : public Probe
{
public:
  SCTPProbe(HostState *host, struct probespec pspec, u8 ttl)
  : Probe(host, pspec, ttl) {
  }
  unsigned char *build_packet(const struct sockaddr_storage *source, u32 *len) const {
    struct sctp_chunkhdr_init chunk;

    sctp_pack_chunkhdr_init(&chunk, SCTP_INIT, 0, sizeof(chunk),
      get_random_u32() /*itag*/, 32768, 10, 2048, get_random_u32() /*itsn*/);

    if (source->ss_family == AF_INET) {
      const struct sockaddr_in *sin = (struct sockaddr_in *) source;
      return build_sctp_raw(&sin->sin_addr, host->target->v4hostip(), ttl,
        get_random_u16(), get_random_u8(), false, NULL, 0,
        token ^ global_id, pspec.pd.sctp.dport, 0UL,
        (char *) &chunk, sizeof(chunk),
        o.extra_payload, o.extra_payload_length, len);
    } else if (source->ss_family == AF_INET6) {
      const struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) source;
      return build_sctp_raw_ipv6(&sin6->sin6_addr, host->target->v6hostip(),
        0, 0, ttl,
        token ^ global_id, pspec.pd.sctp.dport, 0UL,
        (char *) &chunk, sizeof(chunk),
        o.extra_payload, o.extra_payload_length, len);
    } else {
      fatal("Unknown address family %u in %s.", source->ss_family, __func__);
    }
  }
};

class IPProtoProbe : public Probe
{
public:
  IPProtoProbe(HostState *host, struct probespec pspec, u8 ttl)
  : Probe(host, pspec, ttl) {
  }
  unsigned char *build_packet(const struct sockaddr_storage *source, u32 *len) const {
    /* For IP proto scan the token is put in the IP ID or flow label. */
    if (source->ss_family == AF_INET) {
      const struct sockaddr_in *sin = (struct sockaddr_in *) source;
      return build_ip_raw(&sin->sin_addr, host->target->v4hostip(), pspec.proto, ttl,
        token ^ global_id, get_random_u8(), false, NULL, 0,
        o.extra_payload, o.extra_payload_length, len);
    } else if (source->ss_family == AF_INET6) {
      const struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) source;
      return build_ipv6_raw(&sin6->sin6_addr, host->target->v6hostip(),
        0, token ^ global_id, pspec.proto, ttl,
        o.extra_payload, o.extra_payload_length, len);
    } else {
      fatal("Unknown address family %u in %s.", source->ss_family, __func__);
    }
  }
};

class ICMPv6Probe : public Probe
{
public:
  ICMPv6Probe(HostState *host, struct probespec pspec, u8 ttl)
  : Probe(host, pspec, ttl) {
  }

  unsigned char *build_packet(const struct sockaddr_storage *source, u32 *len) const {
    const struct sockaddr_in6 *sin6;
    assert(source->ss_family == AF_INET6);
    sin6 = (struct sockaddr_in6 *) source;
    return build_icmpv6_raw(&sin6->sin6_addr, host->target->v6hostip(), 0x00, 0x0000,
      ttl, token, global_id, pspec.pd.icmp.type, pspec.pd.icmp.code,
      o.extra_payload, o.extra_payload_length, len);
  }
};

Probe *Probe::make(HostState *host, struct probespec pspec, u8 ttl)
{
  if (pspec.type == PS_ICMP || (pspec.type == PS_PROTO && pspec.proto == IPPROTO_ICMP))
    return new ICMPProbe(host, pspec, ttl);
  else if (pspec.type == PS_TCP || (pspec.type == PS_PROTO && pspec.proto == IPPROTO_TCP))
    return new TCPProbe(host, pspec, ttl);
  else if (pspec.type == PS_UDP || (pspec.type == PS_PROTO && pspec.proto == IPPROTO_UDP))
    return new UDPProbe(host, pspec, ttl);
  else if (pspec.type == PS_SCTP || (pspec.type == PS_PROTO && pspec.proto == IPPROTO_SCTP))
    return new SCTPProbe(host, pspec, ttl);
  else if (pspec.type == PS_PROTO)
    return new IPProtoProbe(host, pspec, ttl);
  else if (pspec.type == PS_ICMPV6)
    return new ICMPv6Probe(host, pspec, ttl);
  else
    fatal("Unknown probespec type in traceroute");

  return NULL;
}

TracerouteState::TracerouteState(std::vector<Target *> &targets) {
  std::vector<Target *>::iterator it;
  struct sockaddr_storage srcaddr;
  size_t sslen;
  char pcap_filter[128];
  int n;

  assert(targets.size() > 0);

  if ((o.sendpref & PACKET_SEND_ETH) && targets[0]->ifType() == devt_ethernet) {
    ethsd = eth_open_cached(targets[0]->deviceName());
    if (ethsd == NULL)
      fatal("dnet: failed to open device %s", targets[0]->deviceName());
    rawsd = -1;
  } else {
#ifdef WIN32
    win32_fatal_raw_sockets(targets[0]->deviceName());
#endif
    rawsd = nmap_raw_socket();
    if (rawsd < 0)
      pfatal("traceroute: socket troubles");
    ethsd = NULL;
  }

  /* Assume that all the targets share the same device. */
  if((pd=my_pcap_open_live(targets[0]->deviceName(), 128, o.spoofsource, 2))==NULL)
    fatal("%s", PCAP_OPEN_ERRMSG);
  sslen = sizeof(srcaddr);
  targets[0]->SourceSockAddr(&srcaddr, &sslen);
  n = Snprintf(pcap_filter, sizeof(pcap_filter), "(ip or ip6) and dst host %s",
    ss_to_string(&srcaddr));
  assert(n < (int) sizeof(pcap_filter));
  set_pcap_filter(targets[0]->deviceFullName(), pd, pcap_filter);
 if (o.debugging)
   log_write(LOG_STDOUT, "Packet capture filter (device %s): %s\n", targets[0]->deviceFullName(), pcap_filter);
  for (it = targets.begin(); it != targets.end(); it++) {
    HostState *state = new HostState(*it);
    hosts.push_back(state);
    active_hosts.push_back(state);
  }

  num_active_probes = 0;
  next_sending_host = active_hosts.begin();
  next_send_time = get_now();
}

TracerouteState::~TracerouteState() {
  std::vector<HostState *>::iterator it;

  if (rawsd != -1)
    close(rawsd);
  pcap_close(pd);

  for (it = hosts.begin(); it != hosts.end(); it++)
    delete *it;
}

void TracerouteState::next_active_host() {
  assert(next_sending_host != active_hosts.end());
  next_sending_host++;
  if (next_sending_host == active_hosts.end())
    next_sending_host = active_hosts.begin();
}

void TracerouteState::send_new_probes() {
  std::list<HostState *>::iterator failed_host;
  struct timeval now;

  now = get_now();

  assert(!active_hosts.empty());
  failed_host = active_hosts.end();
  while (next_sending_host != failed_host
    && num_active_probes < MAX_OUTSTANDING_PROBES
    && !TIMEVAL_BEFORE(now, next_send_time)) {
    if ((*next_sending_host)->send_next_probe(rawsd, ethsd)) {
      num_active_probes++;
      TIMEVAL_MSEC_ADD(next_send_time, next_send_time, o.scan_delay);
      if (TIMEVAL_BEFORE(next_send_time, now))
        next_send_time = now;
      failed_host = active_hosts.end();
    } else if (failed_host == active_hosts.end()) {
      failed_host = next_sending_host;
    }
    next_active_host();
  }
}

static Hop *hop_cache_lookup(u8 ttl, const struct sockaddr_storage *addr) {
  std::map<struct HopIdent, Hop *>::iterator it;
  HopIdent ident(ttl, *addr);

  it = hop_cache.find(ident);
  if (it == hop_cache.end())
    return NULL;
  else
    return it->second;
}

static void hop_cache_insert(Hop *hop) {
  if (hop->addr.ss_family == 0) {
    timedout_hops.push_back(hop);
  } else {
    hop_cache[HopIdent(hop->ttl, hop->addr)] = hop;
  }
}

static unsigned int hop_cache_size() {
  return hop_cache.size() + timedout_hops.size();
}

void traceroute_hop_cache_clear() {
  std::map<struct HopIdent, Hop *>::iterator map_iter;
  std::list<Hop *>::iterator list_iter;

  for (map_iter = hop_cache.begin(); map_iter != hop_cache.end(); map_iter++)
    delete map_iter->second;
  hop_cache.clear();
  for (list_iter = timedout_hops.begin(); list_iter != timedout_hops.end(); list_iter++)
    delete *list_iter;
  timedout_hops.clear();
}

/* Merge two hop chains together and return the head of the merged chain. This
   is done when a cache hit finds that two targets share the same intermediate
   hop; rather than doing a full trace for each target, one is linked to the
   other. "Merged" means that, for example, if chain a has an hop at TTL 3 and
   chain b has one for TTL 2, the merged chain will include both. Usually, the
   chains will not have hops at the same TTL (that implies different routes to
   the same host), but see the next paragraph for what we do when that happens.
   Each hop in the merged chain will be tagged with the given tag.

   There are many cases that must be handled correctly by this function: a and b
   may be equal; either may be NULL; a and b may be disjoint chains or may be
   joined somewhere. The biggest difficulty is when both of the chains have a
   hop with the same TTL but a different address. When this happens we
   arbitrarily choose one of the hops to unlink, on the presumption that any
   route through the same intermediate host at a given TTL should be the same
   and that differences aren't meaningful. (This has the same effect as if we
   were to send probes strictly serially, because then there would be no parent
   hops to potentially conflict, even if in fact they would if traced to
   completion.) */
static Hop *merge_hops(const struct sockaddr_storage *tag, Hop *a, Hop *b) {
  Hop head, *p;

  p = &head;

  while (a != NULL && b != NULL && a != b) {
    Hop **next;

    if (a->ttl > b->ttl) {
      next = &a;
    } else if (b->ttl > a->ttl) {
      next = &b;
    } else {
      Hop **discard, *parent;

      if (b->addr.ss_family == 0) {
        next = &a;
        discard = &b;
      } else if (a->addr.ss_family == 0) {
        next = &b;
        discard = &a;
      } else {
        next = &a;
        discard = &b;
        if (o.debugging) {
          log_write(LOG_STDOUT, "Warning: %s", ss_to_string(&(*next)->addr));
          log_write(LOG_STDOUT, " doesn't match %s at TTL %d;",
            ss_to_string(&(*discard)->addr), a->ttl);
          log_write(LOG_STDOUT, " arbitrarily discarding %s\n",
            ss_to_string(&(*discard)->addr));
        }
      }
      parent = (*discard)->parent;
      *discard = parent;
    }
    p->parent = *next;
    p->tag = *tag;
    p = p->parent;
    *next = (*next)->parent;
  }
  /* At most one branch of this is taken, even when a == b. */
  if (a != NULL)
    p->parent = a;
  else if (b != NULL)
    p->parent = b;
  for ( ; p != NULL; p = p->parent)
    p->tag = *tag;

  return head.parent;
}

/* Record a hop at the given TTL for the given host. This takes care of linking
   the hop into the host's chain as well as into the global hop tree. */
void TracerouteState::set_host_hop(HostState *host, u8 ttl,
  const struct sockaddr_storage *from_addr, float rtt) {
  Hop *hop;

  if (o.debugging > 1) {
    log_write(LOG_STDOUT, "Set hop %s TTL %d to %s RTT %.2f ms\n",
      host->target->targetipstr(), ttl, ss_to_string(from_addr), rtt);
  }

  hop = hop_cache_lookup(ttl, from_addr);
  if (hop == NULL) {
    /* A new hop, never before seen with this address and TTL. Add it to the
       host's chain and to the global cache. */
    hop = host->insert_hop(ttl, from_addr, rtt);
  } else {
    /* An existing hop at this address and TTL. Link this host's chain to it. */
    if (o.debugging > 1) {
      log_write(LOG_STDOUT, "Traceroute cache hit %s TTL %d while tracing",
        ss_to_string(&hop->addr), hop->ttl);
      log_write(LOG_STDOUT, " %s TTL %d\n", host->target->targetipstr(), ttl);
    }

    host->link_to(hop);

    if (host->state == HostState::COUNTING_DOWN) {
      /* Hit the cache going down. Seek to the end of the chain. If we have the
         tag for the last node, we take responsibility for finishing the trace.
         Otherwise, start counting up. */
      struct sockaddr_storage addr;
      size_t sslen;

      while (hop->parent != NULL) {
        hop = hop->parent;
        /* No need to re-probe any merged hops. */
        host->sent_ttls[hop->ttl] = true;
      }
      sslen = sizeof(addr);
      host->target->TargetSockAddr(&addr, &sslen);
      if (sockaddr_storage_equal(&hop->tag, &addr)) {
        if (o.debugging > 1) {
          log_write(LOG_STDOUT, "%s continuing trace from TTL %d\n",
            host->target->targetipstr(), host->current_ttl);
        }
      } else {
        host->state = HostState::COUNTING_UP;
        num_active_probes -= host->cancel_probes_below(ttl);
      }
    }
  }
}

/* Record that a hop at the given TTL for the given host timed out. */
void TracerouteState::set_host_hop_timedout(HostState *host, u8 ttl) {
  static struct sockaddr_storage EMPTY_ADDR = { 0 };
  host->insert_hop(ttl, &EMPTY_ADDR, -1.0);
}

struct Reply {
  struct timeval rcvdtime;
  struct sockaddr_storage from_addr;
  struct sockaddr_storage target_addr;
  u8 ttl;
  u16 token;
};

static bool parse_encapsulated_reply(const void *ip, unsigned len, Reply *reply) {
  struct abstract_ip_hdr hdr;
  const void *data;

  data = ip_get_data(ip, &len, &hdr);
  if (data == NULL)
    return false;

  if (hdr.version == 4 && hdr.proto == IPPROTO_ICMP) {
    const struct icmp *icmp = (const struct icmp *) data;
    if (len < 8 || ntohs(icmp->icmp_id) != global_id)
      return false;
    reply->token = ntohs(icmp->icmp_seq);
  } else if (hdr.version == 6 && hdr.proto == IPPROTO_ICMPV6) {
    const struct icmpv6_msg_echo *echo = (struct icmpv6_msg_echo *) ((char *) data + sizeof(struct icmpv6_hdr));
    if (len < 8 || ntohs(echo->icmpv6_id) != global_id)
      return false;
    reply->token = ntohs(echo->icmpv6_seq);
  } else if (hdr.proto == IPPROTO_TCP) {
    const struct tcp_hdr *tcp = (const struct tcp_hdr *) data;
    if (len < 2)
      return false;
    reply->token = ntohs(tcp->th_sport) ^ global_id;
  } else if (hdr.proto == IPPROTO_UDP) {
    const struct udp_hdr *udp = (const struct udp_hdr *) data;
    if (len < 2)
      return false;
    reply->token = ntohs(udp->uh_sport) ^ global_id;
  } else if (hdr.proto == IPPROTO_SCTP) {
    const struct sctp_hdr *sctp = (const struct sctp_hdr *) data;
    if (len < 2)
      return false;
    reply->token = ntohs(sctp->sh_sport) ^ global_id;
  } else {
    if (len < 6)
      return false;
    /* Check IP ID for proto scan. */
    reply->token = hdr.ipid ^ global_id;
  }

  reply->target_addr = hdr.dst;

  return true;
}

static bool decode_reply(const void *ip, unsigned int len, Reply *reply) {
  struct abstract_ip_hdr hdr;
  const void *data;

  data = ip_get_data(ip, &len, &hdr);
  if (data == NULL)
    return false;

  reply->from_addr = hdr.src;

  if (hdr.version == 4 && hdr.proto == IPPROTO_ICMP) {
    /* ICMP responses comprise all the TTL exceeded messages we expect from all
       probe types, as well as actual replies from ICMP probes. */
    const struct icmp_hdr *icmp = (const struct icmp_hdr *) data;
    if (len < 8)
      return false;
    if ((icmp->icmp_type == ICMP_TIMEXCEED
         && icmp->icmp_code == ICMP_TIMEXCEED_INTRANS)
        || icmp->icmp_type == ICMP_UNREACH) {
      /* Get the encapsulated IP packet. */
      const void *encaps = icmp_get_data(icmp, &len);
      if (encaps == NULL)
        return false;
      return parse_encapsulated_reply(encaps, len, reply);
    } else if (icmp->icmp_type == ICMP_ECHOREPLY
               || icmp->icmp_type == ICMP_MASKREPLY
               || icmp->icmp_type == ICMP_TSTAMPREPLY) {
      /* Need this alternate form of header for icmp_id and icmp_seq. */
      const struct icmp *icmp = (const struct icmp *) data;

      if (ntohs(icmp->icmp_id) != global_id)
        return false;
      reply->token = ntohs(icmp->icmp_seq);
      /* Reply came directly from the target. */
      reply->target_addr = reply->from_addr;
    } else {
      return false;
    }
  } else if (hdr.version == 6 && hdr.proto == IP_PROTO_ICMPV6) {
    /* ICMPv6 responses comprise all the TTL exceeded messages we expect from
       all probe types, as well as actual replies from ICMP probes. */
    const struct icmpv6_hdr *icmpv6 = (const struct icmpv6_hdr *) data;
    if (len < 2)
      return false;
    /* TIMEXCEED, UNREACH */
    if ((icmpv6->icmpv6_type == ICMPV6_TIMEXCEED
         && icmpv6->icmpv6_code == ICMPV6_TIMEXCEED_INTRANS)
        || icmpv6->icmpv6_type == ICMPV6_UNREACH) {
      /* Get the encapsulated IP packet. */
      const void *encaps = icmpv6_get_data(icmpv6, &len);
      if (encaps == NULL)
        return false;
      return parse_encapsulated_reply(encaps, len, reply);
    } else if (icmpv6->icmpv6_type == ICMPV6_ECHOREPLY) {
      /* MASKREPLY, TSTAMPREPLY */
      const struct icmpv6_msg_echo *echo;

      if (len < sizeof(*icmpv6) + 4)
        return false;
      echo = (struct icmpv6_msg_echo *) ((char *) icmpv6 + sizeof(*icmpv6));
      if (ntohs(echo->icmpv6_id) != global_id)
        return false;
      reply->token = ntohs(echo->icmpv6_seq);
      /* Reply came directly from the target. */
      reply->target_addr = reply->from_addr;
    } else {
      return false;
    }
  } else if (hdr.proto == IPPROTO_TCP) {
    const struct tcp_hdr *tcp = (const struct tcp_hdr *) data;
    if (len < 4)
      return false;
    reply->token = ntohs(tcp->th_dport) ^ global_id;
    reply->target_addr = reply->from_addr;
  } else if (hdr.proto == IPPROTO_UDP) {
    const struct udp_hdr *udp = (const struct udp_hdr *) data;
    if (len < 4)
      return false;
    reply->token = ntohs(udp->uh_dport) ^ global_id;
    reply->target_addr = reply->from_addr;
  } else if (hdr.proto == IPPROTO_SCTP) {
    const struct sctp_hdr *sctp = (const struct sctp_hdr *) data;
    if (len < 4)
      return false;
    reply->token = ntohs(sctp->sh_dport) ^ global_id;
    reply->target_addr = reply->from_addr;
  } else {
    return false;
  }

  return true;
}

static bool read_reply(Reply *reply, pcap_t *pd, long timeout) {
  const struct ip *ip;
  unsigned int iplen;
  struct link_header linkhdr;

  ip = (struct ip *) readip_pcap(pd, &iplen, timeout, &reply->rcvdtime, &linkhdr, true);
  if (ip == NULL)
    return false;
  if (ip->ip_v == 4 || ip->ip_v == 6)
    return decode_reply(ip, iplen, reply);
  else
    return false;
}

void TracerouteState::read_replies(long timeout) {
  struct sockaddr_storage ss;
  struct timeval now;
  size_t sslen;
  Reply reply;

  assert(timeout / 1000 <= (long) o.scan_delay);
  timeout = MAX(timeout, 10000);
  now = get_now();

  while (timeout > 0 && read_reply(&reply, pd, timeout)) {
    std::list<Probe *>::iterator it;
    struct timeval oldnow;
    HostState *host;
    Probe *probe;
    float rtt;

    oldnow = now;
    now = get_now();
    timeout -= TIMEVAL_SUBTRACT(now, oldnow);

    probe = this->lookup_probe(&reply.target_addr, reply.token);
    if (probe == NULL)
      continue;
    host = probe->host;

    sslen = sizeof(ss);
    host->target->TargetSockAddr(&ss, &sslen);
    if (sockaddr_storage_equal(&ss, &reply.from_addr)) {
      adjust_timeouts2(&probe->sent_time, &reply.rcvdtime, &host->target->to);
      if (host->reached_target == 0 || probe->ttl < host->reached_target)
        host->reached_target = probe->ttl;
      if (host->state == HostState::COUNTING_DOWN) {
        /* If this probe was past the target, skip ahead to what we think the
           actual distance is. */
        int distance = get_initial_ttl_guess(reply.ttl) - reply.ttl + 1;
        if (distance > 0 && distance < host->current_ttl)
          host->current_ttl = MIN(distance, MAX_TTL);
      }
      num_active_probes -= host->cancel_probes_above(probe->ttl);
    }

    rtt = TIMEVAL_SUBTRACT(reply.rcvdtime, probe->sent_time) / 1000.0;
    set_host_hop(host, probe->ttl, &reply.from_addr, rtt);

    it = find(host->unanswered_probes.begin(), host->unanswered_probes.end(), probe);
    num_active_probes -= host->cancel_probe(it);
  }
}

void TracerouteState::cull_timeouts() {
  std::list<HostState *>::iterator host_iter;
  struct timeval now;

  now = get_now();

  for (host_iter = active_hosts.begin(); host_iter != active_hosts.end(); host_iter++) {
    while (!(*host_iter)->active_probes.empty()
           && (*host_iter)->active_probes.front()->is_timedout(&now)) {
      Probe *probe;

      probe = (*host_iter)->active_probes.front();
      if (o.debugging > 1) {
        log_write(LOG_STDOUT, "Traceroute probe to %s TTL %d timed out\n",
          probe->host->target->targetipstr(), probe->ttl);
      }
      set_host_hop_timedout(*host_iter, probe->ttl);
      (*host_iter)->active_probes.pop_front();
      num_active_probes--;
      if (probe->may_resend())
        (*host_iter)->pending_resends.push_front(probe);
    }
  }
}

void TracerouteState::remove_finished_hosts() {
  std::list<HostState *>::iterator it, next;

  for (it = active_hosts.begin(); it != active_hosts.end(); it = next) {
    next = it;
    next++;
    if ((*it)->is_finished()) {
      if (next_sending_host == it)
        next_active_host();
      active_hosts.erase(it);
    }
  }
}

/* Dummy class to use sockaddr_storage as a map key. */
struct lt_sockaddr_storage {
  bool operator()(const struct sockaddr_storage& a, const struct sockaddr_storage& b) const {
    return sockaddr_storage_cmp(&a, &b) < 0;
  }
};

/* Find the reverse-DNS names of the hops. */
void TracerouteState::resolve_hops() {
  std::set<sockaddr_storage, lt_sockaddr_storage> addrs;
  std::set<sockaddr_storage, lt_sockaddr_storage>::iterator addr_iter;
  std::vector<HostState *>::iterator host_iter;
  std::map<sockaddr_storage, const char *, lt_sockaddr_storage> name_map;
  Target **targets;
  Hop *hop;
  int i, n;

  /* First, put all the IPv4 addresses in a set to remove duplicates. This
     re-resolves the addresses of the targets themselves, which is a little
     inefficient. */
  for (host_iter = hosts.begin(); host_iter != hosts.end(); host_iter++) {
    for (hop = (*host_iter)->hops; hop != NULL; hop = hop->parent) {
      if (hop->addr.ss_family != AF_UNSPEC)
        addrs.insert(hop->addr);
    }
  }
  n = addrs.size();
  /* Second, make an array of pointer to Target to suit the interface of
     nmap_mass_rdns. */
  targets = (Target **) safe_malloc(sizeof(*targets) * n);
  i = 0;
  addr_iter = addrs.begin();
  while (i < n) {
    targets[i] = new Target();
    targets[i]->setTargetSockAddr(&*addr_iter, sizeof(*addr_iter));
    targets[i]->flags = HOST_UP;
    i++;
    addr_iter++;
  }
  nmap_mass_rdns(targets, n);
  /* Third, make a map from addresses to names for easy lookup. */
  for (i = 0; i < n; i++) {
    struct sockaddr_storage ss;
    size_t ss_len;
    const char *hostname = targets[i]->HostName();
    if (*hostname == '\0')
      hostname = NULL;
    ss_len = sizeof(ss);
    targets[i]->TargetSockAddr(&ss, &ss_len);
    name_map[ss] = hostname;
  }
  /* Finally, copy the names into the hops. */
  for (host_iter = hosts.begin(); host_iter != hosts.end(); host_iter++) {
    for (hop = (*host_iter)->hops; hop != NULL; hop = hop->parent) {
      if (hop->addr.ss_family != AF_UNSPEC) {
        const char *hostname = name_map[hop->addr];
        if (hostname != NULL)
          hop->hostname = hostname;
      }
    }
  }
  for (i = 0; i < n; i++)
    delete targets[i];
  free(targets);
}

void TracerouteState::transfer_hops() {
  std::vector<HostState *>::iterator it;
  Hop *p;

  for (it = hosts.begin(); it != hosts.end(); it++) {
    for (p = (*it)->hops; p != NULL; p = p->parent) {
      TracerouteHop hop;

      /* Trim excessive hops. */
      if ((*it)->reached_target && p->ttl > (*it)->reached_target)
        continue;

      hop.tag = p->tag;
      if (p->addr.ss_family == 0) {
        hop.timedout = true;
      } else {
        hop.timedout = false;
        hop.rtt = p->rtt;
      }
      hop.name = p->hostname;
      hop.addr = p->addr;
      hop.ttl = p->ttl;
      (*it)->target->traceroute_hops.push_front(hop);
    }

    (*it)->target->traceroute_probespec = (*it)->pspec;

    /* Set the hop distance for OS fingerprints. */
    if ((*it)->reached_target) {
      (*it)->target->distance = (*it)->reached_target;
      (*it)->target->distance_calculation_method = DIST_METHOD_TRACEROUTE;
    }
  }
}

Probe *TracerouteState::lookup_probe(
  const struct sockaddr_storage *target_addr, u16 token) {
  std::list<HostState *>::iterator host_iter;
  std::list<Probe *>::iterator probe_iter;

  for (host_iter = active_hosts.begin(); host_iter != active_hosts.end(); host_iter++) {
    struct sockaddr_storage ss;
    size_t sslen;

    sslen = sizeof(ss);
    (*host_iter)->target->TargetSockAddr(&ss, &sslen);
    if (!sockaddr_storage_equal(&ss, target_addr))
      continue;
    for (probe_iter = (*host_iter)->unanswered_probes.begin();
         probe_iter != (*host_iter)->unanswered_probes.end();
         probe_iter++) {
      if ((*probe_iter)->token == token)
        return *probe_iter;
    }
  }

  return NULL;
}

double TracerouteState::completion_fraction() const {
  std::vector<HostState *>::const_iterator it;
  double sum;

  sum = 0.0;
  for (it = hosts.begin(); it != hosts.end(); it++)
    sum += (*it)->completion_fraction();
  return sum / hosts.size();
}

/* This is a special case of traceroute when all the targets are directly
   connected. Because the distance to each target is known to be 1, we send no
   probes at all, only fill in a TracerouteHop structure. */
static int traceroute_direct(std::vector<Target *> targets) {
  std::vector<Target *>::iterator it;

  for (it = targets.begin(); it != targets.end(); it++) {
    TracerouteHop hop;
    const char *hostname;
    size_t sslen;

    sslen = sizeof(hop.tag);
    (*it)->TargetSockAddr(&hop.tag, &sslen);
    hop.timedout = false;
    hop.rtt = (*it)->to.srtt / 1000.0;
    hostname = (*it)->HostName();
    if (hostname != NULL && hostname[0] != '\0')
      hop.name = hostname;
    hop.addr = hop.tag;
    hop.ttl = 1;
    (*it)->traceroute_hops.push_front(hop);
  }

  return 1;
}

static int traceroute_remote(std::vector<Target *> targets) {
  std::vector<Target *>::iterator target_iter;

  if (targets.empty())
    return 1;

  TracerouteState global_state(targets);

  global_id = get_random_u16();

  ScanProgressMeter SPM("Traceroute");

  o.current_scantype = TRACEROUTE;

  while (!global_state.active_hosts.empty()) {
    struct timeval now;
    long int timeout;

    global_state.send_new_probes();
    now = get_now();
    timeout = TIMEVAL_SUBTRACT(global_state.next_send_time, now);
    global_state.read_replies(timeout);
    global_state.cull_timeouts();
    global_state.remove_finished_hosts();

    if (keyWasPressed())
      SPM.printStats(global_state.completion_fraction(), NULL);
  }

  SPM.endTask(NULL, NULL);

  if (!o.noresolve)
    global_state.resolve_hops();
  /* This puts the hops into the targets known by the global_state. */
  global_state.transfer_hops();

  /* Update initial_ttl to be the highest distance seen in this host group, as
     an estimate for the next. */
  initial_ttl = 0;
  for (target_iter = targets.begin();
       target_iter != targets.end();
       target_iter++) {
    initial_ttl = MAX(initial_ttl, (*target_iter)->traceroute_hops.size());
  }

  if (hop_cache_size() > MAX_HOP_CACHE_SIZE) {
    if (o.debugging) {
      log_write(LOG_STDOUT, "Clearing hop cache that has grown to %d\n",
        hop_cache_size());
    }
    traceroute_hop_cache_clear();
  }

  return 1;
}

int traceroute(std::vector<Target *> &Targets) {
  std::vector<Target *> direct, remote;
  std::vector<Target *>::iterator target_iter;

  /* Separate directly connected targets from remote targets. */
  for (target_iter = Targets.begin();
       target_iter != Targets.end();
       target_iter++) {
    if ((*target_iter)->ifType() == devt_loopback)
      ; /* Ignore */
    else if ((*target_iter)->directlyConnected())
      direct.push_back(*target_iter);
    else
      remote.push_back(*target_iter);
  }

  traceroute_direct(direct);
  traceroute_remote(remote);

  return 1;
}

static struct timeval get_now(struct timeval *now) {
  struct timeval tv;

  if (now != NULL)
    return *now;
  gettimeofday(&tv, NULL);

  return tv;
}

/* Convert the address in ss to a string. The result is returned in a static
   buffer so you can't call this twice in arguments to printf, for example. */
static const char *ss_to_string(const struct sockaddr_storage *ss) {
  return inet_ntop_ez(ss, sizeof(*ss));
}
