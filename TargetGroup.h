
/***************************************************************************
 * TargetGroup.h -- The "TargetGroup" class holds a group of IP addresses, *
 * such as those from a '/16' or '10.*.*.*' specification.  It also has a  *
 * trivial HostGroupState class which handles a bunch of expressions that  *
 * go into TargetGroup classes.                                            *
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

#ifndef TARGETGROUP_H
#define TARGETGROUP_H

#include <list>
#include <cstddef>

class NetBlock;

class TargetGroup {
public:
  NetBlock *netblock;

  TargetGroup() {
    this->netblock = NULL;
  }

  ~TargetGroup();

  /* Initializes (or reinitializes) the object with a new expression,
     such as 192.168.0.0/16 , 10.1.0-5.1-254 , or
     fe80::202:e3ff:fe14:1102 .  The af parameter is AF_INET or
     AF_INET6 Returns 0 for success */
  int parse_expr(const char *target_expr, int af);
  /* Grab the next host from this expression (if any).  Returns 0 and
     fills in ss if successful.  ss must point to a pre-allocated
     sockaddr_storage structure */
  int get_next_host(struct sockaddr_storage *ss, std::size_t *sslen);
  /* Returns true iff the given address is the one that was resolved to create
     this target group; i.e., not one of the addresses derived from it with a
     netmask. */
  bool is_resolved_address(const struct sockaddr_storage *ss) const;
  /* Return a string of the name or address that was resolved for this group. */
  const char *get_resolved_name(void) const;
  /* Return the list of addresses that the name for this group resolved to, but
     which were not scanned, if it came from a name resolution. */
  const std::list<struct sockaddr_storage> &get_unscanned_addrs(void) const;
  /* is the current expression a named host */
  int get_namedhost() const;
};

#endif /* TARGETGROUP_H */

