
/***************************************************************************
 * common_modified.h --  This file holds all those functions and classes   *
 * that have been reused from Nmap's code but that needed to be modified   *
 * in order to reuse them.                                                 *
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

#ifndef COMMON_MODIFIED_H
#define COMMON_MODIFIED_H 1

#include "nping.h"
#include "common.h"

/*****************************************************************************
  * STUFF FROM TargetGroup.h
  ****************************************************************************/

class TargetGroup {
 public:
  /* used by get_target_types */
  enum _targets_types { TYPE_NONE, IPV4_NETMASK, IPV4_RANGES, IPV6_ADDRESS };
  /* used as input to skip range */
  enum _octet_nums { FIRST_OCTET, SECOND_OCTET, THIRD_OCTET };
  TargetGroup();

 /* Initializes (or reinitializes) the object with a new expression,
    such as 192.168.0.0/16 , 10.1.0-5.1-254 , or
    fe80::202:e3ff:fe14:1102 .  The af parameter is AF_INET or
    AF_INET6 Returns 0 for success */
  int parse_expr(const char * const target_expr, int af);
  /* Reset the object without reinitializing it */
  int rewind();
  /* Grab the next host from this expression (if any).  Returns 0 and
     fills in ss if successful.  ss must point to a pre-allocated
     sockaddr_storage structure */
  int get_next_host(struct sockaddr_storage *ss, size_t *sslen);
  /* Returns the last given host, so that it will be given again next
     time get_next_host is called.  Obviously, you should only call
     this if you have fetched at least 1 host since parse_expr() was
     called */
  int return_last_host();
  /* return the target type */
  char get_targets_type() {return targets_type;};
  /* get the netmask */
  int get_mask() {return netmask;};
  /* is the current expression a named host */
  int get_namedhost() {return namedhost;};
  /* Skip an octet in the range array */
  int skip_range(_octet_nums octet);
 private:
  enum _targets_types targets_type;
  void Initialize();

#if HAVE_IPV6
  struct sockaddr_in6 ip6;
#endif

  /* These 4 are used for the '/mask' style of specifying target
     net (IPV4_NETMASK) */
  u32 netmask;
  struct in_addr startaddr;
  struct in_addr currentaddr;
  struct in_addr endaddr;

  // These three are for the '138.[1-7,16,91-95,200-].12.1' style (IPV4_RANGES)
  u8 addresses[4][256];
  unsigned int current[4];
  u8 last[4];

/* Number of IPs left in this structure -- set to 0 if
		  the fields are not valid */
  unsigned long long ipsleft;

  // is the current target expression a named host
  int namedhost;
};



/*****************************************************************************
  * STUFF FROM tcpip.cc
  ****************************************************************************/
int devname2ipaddr_alt(char *dev, struct sockaddr_storage *addr);
void getpts_aux(const char *origexpr, int nested, u8 *porttbl, int *portwarning);

#endif
