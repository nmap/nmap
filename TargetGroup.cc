
/***************************************************************************
 * TargetGroup.cc -- The "TargetGroup" class holds a group of IP           *
 * addresses, such as those from a '/16' or '10.*.*.*' specification.  It  *
 * also has a trivial HostGroupState class which handles a bunch of        *
 * expressions that go into TargetGroup classes.                           *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *
 * The Nmap Security Scanner is (C) 1996-2026 Nmap Software LLC ("The Nmap
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
 * Source code also allows you to port Nmap to new platforms, fix bugs, and
 * add new features. You are highly encouraged to submit your changes as a
 * Github PR or by email to the dev@nmap.org mailing list for possible
 * incorporation into the main distribution. Unless you specify otherwise, it
 * is understood that you are offering us very broad rights to use your
 * submissions as described in the Nmap Public Source License Contributor
 * Agreement. This is important because we fund the project by selling licenses
 * with various terms, and also because the inability to relicense code has
 * caused devastating problems for other Free Software projects (such as KDE
 * and NASM).
 *
 * The free version of Nmap is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranties,
 * indemnification and commercial support are all available through the
 * Npcap OEM program--see https://nmap.org/oem/
 *
 ***************************************************************************/

/* $Id$ */

#include "tcpip.h"
#include "TargetGroup.h"
#include "targets.h"
#include "NmapOps.h"
#include "nmap_error.h"
#include "nmap_dns.h"
#include "nmap.h"
#include "libnetutil/netutil.h"
#include "libnetutil/NetBlock.h"

#include <string>
#include <sstream>
#include <vector>
#include <algorithm>
#include <typeinfo>

extern NmapOps o;

TargetGroup::~TargetGroup() {
  for (std::list<NetBlock *>::iterator it = netblocks.begin();
      it != netblocks.end(); it++) {
    delete *it;
  }
}

void TargetGroup::reject_last_host() {
  assert(!netblocks.empty());
  NetBlock *nb = netblocks.front();
  nb->reject_last_host();
}

/* Initializes (or reinitializes) the object with a new expression, such
   as 192.168.0.0/16 , 10.1.0-5.1-254 , or fe80::202:e3ff:fe14:1102 .
    */
bool TargetGroup::load_expressions(HostGroupState *hs, int af) {
  assert(netblocks.empty());
  // This is a wild guess, but we need some sort of limit.
  static const size_t EXPR_PARSE_BATCH_SZ = o.ping_group_sz;
  const char *target_expr = NULL;
  std::vector<DNS::Request> requests;
  requests.reserve(EXPR_PARSE_BATCH_SZ/4);
  while (netblocks.size() < EXPR_PARSE_BATCH_SZ
      && NULL != (target_expr = hs->next_expression())) {
    NetBlock *nb = NetBlock::parse_expr(target_expr, af, requests);
    if (nb == NULL) {
      log_bogus_target(target_expr);
    }
    else {
      netblocks.push_back(nb);
    }
  }
  if (netblocks.empty()) {
    return false;
  }
  if (requests.size() > 0) {
    nmap_mass_dns(requests.data(), requests.size());
  }
  std::list<NetBlock *>::iterator nb_it = netblocks.begin();
  for (std::vector<DNS::Request>::const_iterator rit = requests.begin();
      rit != requests.end(); rit++) {
    const DNS::Request &req = *rit;
    NetBlock *nb_old = (NetBlock *) req.userdata;
    NetBlock *nb_new = nb_old->resolve(req);
    nb_it = std::find(nb_it, netblocks.end(), nb_old);

    if (nb_new == NULL) {
      // Resolution failed; remove the NetBlock
      nb_it = netblocks.erase(nb_it);
      delete nb_old;
    }
    else {
      assert (nb_new != nb_old);
      // Resolution succeeded; replace the NetBlock
      *nb_it = nb_new;
      delete nb_old;
    }
  }
  requests.clear();
  return !netblocks.empty();
}

void TargetGroup::generate_random_ips(unsigned long num_random) {
  NetBlockRandomIPv4 *nbrand = new NetBlockRandomIPv4();
  nbrand->set_num_random(num_random);
  netblocks.push_front(nbrand);
}

/* Grab the next host from this expression (if any) and updates its internal
   state to reflect that the IP was given out.  Returns 0 and
   fills in ss if successful.  ss must point to a pre-allocated
   sockaddr_storage structure */
int TargetGroup::get_next_host(struct sockaddr_storage *ss, size_t *sslen) {
  while (!netblocks.empty()) {

    NetBlock *nb = netblocks.front();
    if (nb->next(ss, sslen)) {
      return 0;
    }
    // Ran out of hosts in that block. Remove it.
    netblocks.pop_front();
    delete nb;
  }
  // Ran out of netblocks
  return -1;
}

/* Returns true iff the given address is the one that was resolved to create
   this target group; i.e., not one of the addresses derived from it with a
   netmask. */
bool TargetGroup::is_resolved_address(const struct sockaddr_storage *ss) const {
  assert(!netblocks.empty());
  NetBlock *nb = netblocks.front();
  return nb->is_resolved_address(ss);
}

/* Return a string of the name or address that was resolved for this group. */
const char *TargetGroup::get_resolved_name(void) const {
  assert(!netblocks.empty());
  NetBlock *nb = netblocks.front();
  if (nb->hostname.empty())
    return NULL;
  else
    return nb->hostname.c_str();
}

/* Return the list of addresses that the name for this group resolved to, but
   which were not scanned, if it came from a name resolution. */
const std::list<struct sockaddr_storage> &TargetGroup::get_unscanned_addrs(void) const {
  assert(!netblocks.empty());
  NetBlock *nb = netblocks.front();
  return nb->unscanned_addrs;
}

/* is the current expression a named host */
int TargetGroup::get_namedhost() const {
  return this->get_resolved_name() != NULL;
}
