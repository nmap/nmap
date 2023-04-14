/***************************************************************************
 * NewTargets.h -- The "NewTargets" class allows NSE scripts to add new    *
 * targets to the scan queue.                                              *
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

#include "NewTargets.h"
#include "NmapOps.h"
#include "output.h"
#include "nmap_error.h"

extern NmapOps o;  /* option structure */
NewTargets *NewTargets::new_targets = NULL;

void NewTargets::free_new_targets (void) {
  delete new_targets;
}

/* This private method is used to push new targets to the
 * queue. It returns the number of targets in the queue. */
unsigned long NewTargets::push (const char *target) {
  std::pair<std::set<std::string>::iterator, bool> pair_iter;
  std::string tg(target);

  if (tg.length() > 0) {
    /* save targets in the scanned history here (NSE side). */
    pair_iter = history.insert(tg);

    /* A new target */
    if (pair_iter.second == true) {
      /* push target onto the queue for future scans */
      queue.push(tg);

      if (o.debugging > 2)
        log_write(LOG_PLAIN, "New Targets: target %s pushed onto the queue.\n", tg.c_str());
    } else {
      if (o.debugging > 2)
        log_write(LOG_PLAIN, "New Targets: target %s was already added.\n", tg.c_str());
      /* Return 1 when the target is already in the history cache,
       * this will prevent returning 0 when the target queue is
       * empty since no target was added. */
      return 1;
    }
  }

  return queue.size();
}

/* Reads a target from the queue and return it to be pushed
 * onto Nmap scan queue */
std::string NewTargets::read (void) {
  std::string str;

  new_targets = new_targets ? new_targets : new NewTargets();

  /* check to see it there are targets in the queue */
  if (!new_targets->queue.empty()) {
    str = new_targets->queue.front();
    new_targets->queue.pop();
  }

  return str;
}

unsigned long NewTargets::get_number (void) {
  new_targets = new_targets ? new_targets : new NewTargets();
  return new_targets->history.size();
}

unsigned long NewTargets::get_queued (void) {
  new_targets = new_targets ? new_targets : new NewTargets();
  return new_targets->queue.size();
}

/* This is the function that is used by nse_nmaplib.cc to add
 * new targets.
 * Returns the number of targets in the queue on success, or 0 on
 * failures or when the queue is empty. */
unsigned long NewTargets::insert (const char *target) {
  new_targets = new_targets ? new_targets : new NewTargets();
  if (*target) {
    if (o.current_scantype == SCRIPT_POST_SCAN) {
      error("ERROR: adding targets is disabled in the Post-scanning phase.");
      return 0;
    }
    if (strlen(target) >= 1024) {
      error("ERROR: new target is too long (>= 1024), failed to add it.");
      return 0;
    }
  }

  return new_targets->push(target);
}
