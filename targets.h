
/***************************************************************************
 * targets.h -- Functions relating to "ping scanning" as well as           *
 * determining the exact IPs to hit based on CIDR and other input formats. *
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

#ifndef TARGETS_H
#define TARGETS_H

#include "TargetGroup.h"
#include <list>
#include <nbase.h>
class Target;

class HostGroupState {
public:
  /* The maximum number of entries we want to allow storing in defer_buffer. */
  static const unsigned int DEFER_LIMIT = 64;

  HostGroupState(int lookahead, int randomize, int argc, const char *argv[]);
  ~HostGroupState();
  Target **hostbatch;

  /* The defer_buffer is a place to store targets that have previously been
     returned but that can't be used right now. They wait in defer_buffer until
     HostGroupState::undefer is called, at which point they all move to the end
     of the undeferred list. HostGroupState::next_target always pulls from the
     undeferred list before returning anything new. */
  std::list<Target *> defer_buffer;
  std::list<Target *> undeferred;

  int argc;
  const char **argv;
  int max_batch_sz; /* The size of the hostbatch[] array */
  int current_batch_sz; /* The number of VALID members of hostbatch[] */
  int next_batch_no; /* The index of the next hostbatch[] member to be given
                        back to the user */
  int randomize; /* Whether each batch should be "shuffled" prior to the ping
                    scan (they will also be out of order when given back one
                    at a time to the client program */
  TargetGroup current_group; /* For batch chunking -- targets in queue */

  /* Returns true iff the defer buffer is not yet full. */
  bool defer(Target *t);
  void undefer();
  const char *next_expression();
  Target *next_target();
};

/* ports is used to pass information about what ports to use for host discovery */
Target *nexthost(HostGroupState *hs, struct addrset *exclude_group,
                 const struct scan_lists *ports, int pingtype);
int load_exclude_file(struct addrset *exclude_group, FILE *fp);
int load_exclude_string(struct addrset *exclude_group, const char *s);
/* a debugging routine to dump an exclude list to stdout. */
int dumpExclude(const struct addrset *exclude_group);
/* Returns the last host obtained by nexthost.  It will be given again the next
   time you call nexthost(). */
void returnhost(HostGroupState *hs);


bool target_needs_new_hostgroup(Target **targets, int targets_sz, const Target *target);

#endif /* TARGETS_H */

