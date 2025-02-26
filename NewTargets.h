/***************************************************************************
 * NewTargets.h -- The "NewTargets" class allows NSE scripts to add new    *
 * targets to the scan queue.                                              *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *
 * The Nmap Security Scanner is (C) 1996-2025 Nmap Software LLC ("The Nmap
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

#ifndef NEWTARGETS_H
#define NEWTARGETS_H

#include <queue>
#include <set>
#include <string>


/* Adding new targets is for NSE scripts */
class NewTargets {
public:

  /* return a previous inserted target */
  static std::string read (void);

  /* get the number of all new added targets */
  static unsigned long get_number (void);

  /* get the number of queued targets left to scan */
  static unsigned long get_queued (void);

  /* Free the new_targets object. */
  static void free_new_targets (void);

  /* insert targets to the new_targets_queue */
  static unsigned long insert (const char *target);

private:
  NewTargets() {};

  /* A queue to push new targets that were discovered by NSE scripts.
   * Nmap will pop future targets from this queue. */
  std::queue<std::string> queue;

  /* A cache to save scanned targets specifications.
   * (These are targets that were pushed to Nmap scan queue) */
  std::set<std::string> history;

  /* Save new targets onto the queue */
  unsigned long push (const char *target);

  static NewTargets *new_targets;
};

#endif /* NEWTARGETS_H */
