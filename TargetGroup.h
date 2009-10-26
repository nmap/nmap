
/***************************************************************************
 * TargetGroup.h -- The "TargetGroup" class holds a group of IP addresses, *
 * such as those from a '/16' or '10.*.*.*' specification.  It also has a  *
 * trivial HostGroupState class which handles a bunch of expressions that  *
 * go into TargetGroup classes.                                            *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2009 Insecure.Com LLC. Nmap is    *
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

#ifndef TARGETGROUP_H
#define TARGETGROUP_H

#include <string>

#include "nmap.h"

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
  /* Returns true iff the given address is the one that was resolved to create
     this target group; i.e., not one of the addresses derived from it with a
     netmask. */
  bool is_resolved_address(const struct sockaddr_storage *ss);
  /* Return a string of the name or address that was resolved for this group. */
  const char *get_resolved_name(void);
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

  /* These are used for the '/mask' style of specifying target 
     net (IPV4_NETMASK) */
  u32 netmask;
  std::string resolvedname;
  struct in_addr resolvedaddr;
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

class HostGroupState {
 public:
  HostGroupState(int lookahead, int randomize, char *target_expressions[],
		 int num_expressions);
  ~HostGroupState();
  Target **hostbatch;
  int max_batch_sz; /* The size of the hostbatch[] array */
  int current_batch_sz; /* The number of VALID members of hostbatch[] */
  int next_batch_no; /* The index of the next hostbatch[] member to be given 
			back to the user */
  int randomize; /* Whether each batch should be "shuffled" prior to the ping 
		    scan (they will also be out of order when given back one
		    at a time to the client program */
  char **target_expressions; /* An array of target expression strings, passed
				to us by the client (client is also in charge
				of deleting it AFTER it is done with the 
				hostgroup_state */
  int num_expressions;       /* The number of valid expressions in 
				target_expressions member above */
  int next_expression;   /* The index of the next expression we have
			    to handle */
  TargetGroup current_expression; /* For batch chunking -- targets in queue */
};

#endif /* TARGETGROUP_H */
