/***************************************************************************
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
#ifndef NETUTIL_NETBLOCK_H
#define NETUTIL_NETBLOCK_H

#include <string>
#include <list>
#include <vector>
#include "massdns.h"
class NetBlock {
public:
  virtual ~NetBlock() {}
  NetBlock(bool r_a=false, const char *dev=NULL)
    : resolve_all(r_a), device(dev)
  {
    current_addr = resolvedaddrs.begin();
  }
  std::string hostname;
  std::list<struct sockaddr_storage> resolvedaddrs;
  std::list<struct sockaddr_storage> unscanned_addrs;
  std::list<struct sockaddr_storage>::const_iterator current_addr;

  /* Parses an expression such as 192.168.0.0/16, 10.1.0-5.1-254, or
     fe80::202:e3ff:fe14:1102/112 and returns a newly allocated NetBlock. The af
     parameter is AF_INET or AF_INET6. Returns NULL in case of error. */
  static NetBlock *parse_expr(const char *target_expr, int af, std::vector<DNS::Request> &requests, bool resolve_all=false, const char *device=NULL);

  bool is_resolved_address(const struct sockaddr_storage *ss) const;

  /* For NetBlock subclasses that need to "resolve" themselves into a different
   * NetBlock subclass, override this method. Otherwise, it's safe to reassign
   * the return value to the pointer that this method was called through.
   * On error, return NULL. */
  virtual NetBlock *resolve(const DNS::Request &req) { return this; }
  virtual void reject_last_host() {}
  virtual bool next(struct sockaddr_storage *ss, size_t *sslen) = 0;
  virtual void apply_netmask(int bits) = 0;
  virtual std::string str() const = 0;
protected:
  bool resolve_all;
  const char *device;
};

class NetBlockRandomIPv4 : public NetBlock {
public:
  NetBlockRandomIPv4();

  void reject_last_host() { if (!infinite) count++; }
  void set_num_random(unsigned long num) {
    if (num == 0)
      infinite = true;
    else
      count = num;
  }
  bool next(struct sockaddr_storage *ss, size_t *sslen);
  void apply_netmask(int bits) {}
  std::string str() const {return "Random IPv4 addresses";}

private:
  struct sockaddr_in base;
  unsigned long count;
  bool infinite;
};

#endif
