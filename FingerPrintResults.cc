
/***************************************************************************
 * FingerPrintResults.cc -- The FingerPrintResults class the results of OS *
 * fingerprint matching against a certain host.                            *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2006 Insecure.Com LLC. Nmap is    *
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
 *   nmap-os-fingerprints or nmap-service-probes.                          *
 * o Executes Nmap and parses the results (as opposed to typical shell or  *
 *   execution-menu apps, which simply display raw Nmap output and so are  *
 *   not derivative works.)                                                * 
 * o Integrates/includes/aggregates Nmap into a proprietary executable     *
 *   installer, such as those produced by InstallShield.                   *
 * o Links to a library or executes a program that does any of the above   *
 *                                                                         *
 * The term "Nmap" should be taken to also include any portions or derived *
 * works of Nmap.  This list is not exclusive, but is just meant to        *
 * clarify our interpretation of derived works with some common examples.  *
 * These restrictions only apply when you actually redistribute Nmap.  For *
 * example, nothing stops you from writing and selling a proprietary       *
 * front-end to Nmap.  Just distribute it by itself, and point people to   *
 * http://insecure.org/nmap/ to download Nmap.                             *
 *                                                                         *
 * We don't consider these to be added restrictions on top of the GPL, but *
 * just a clarification of how we interpret "derived works" as it applies  *
 * to our GPL-licensed Nmap product.  This is similar to the way Linus     *
 * Torvalds has announced his interpretation of how "derived works"        *
 * applies to Linux kernel modules.  Our interpretation refers only to     *
 * Nmap - we don't speak for any other GPL products.                       *
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
 * listed in the included Copying.OpenSSL file, and distribute linked      *
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
 * to fyodor@insecure.org for possible incorporation into the main         *
 * distribution.  By sending these changes to Fyodor or one the            *
 * Insecure.Org development mailing lists, it is assumed that you are      *
 * offering Fyodor and Insecure.Com LLC the unlimited, non-exclusive right *
 * to reuse, modify, and relicense the code.  Nmap will always be          *
 * available Open Source, but this is important because the inability to   *
 * relicense code has caused devastating problems for other Free Software  *
 * projects (such as KDE and NASM).  We also occasionally relicense the    *
 * code to third parties as discussed above.  If you wish to specify       *
 * special license conditions of your contributions, just say so when you  *
 * send them.                                                              *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License for more details at                              *
 * http://www.gnu.org/copyleft/gpl.html , or in the COPYING file included  *
 * with Nmap.                                                              *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */

#include "FingerPrintResults.h"
#include "osscan.h"
#include "NmapOps.h"

extern NmapOps o;

FingerPrintResults::FingerPrintResults() {
  num_perfect_matches = num_matches = 0;
  overall_results = OSSCAN_NOMATCHES;
  memset(accuracy, 0, sizeof(accuracy));
  isClassified = false;
  osscan_opentcpport = osscan_closedtcpport = osscan_closedudpport = -1;
  distance = -1;
  distance_guess = -1;
  /* We keep FPs holding at least 10 records because Gen1 OS detection
     doesn't support maxOSTries() */
  FPs = (FingerPrint **) safe_zalloc(MAX(o.maxOSTries(), 10) * sizeof(FingerPrint *));
  maxTimingRatio = 0;
  maxTimingRatio = 0;
  numFPs = goodFP = 0;
}

FingerPrintResults::~FingerPrintResults() {
  int i;

  /* Free OS fingerprints of OS scanning was done */
  for(i=0; i < numFPs; i++) {
    freeFingerPrint(FPs[i]);
    FPs[i] = NULL;
  }
  numFPs = 0;
  free(FPs);
}

const struct OS_Classification_Results *FingerPrintResults::getOSClassification() {
  if (!isClassified) { populateClassification(); isClassified = true; }
  return &OSR;
}

/* If the fingerprint is of potentially poor quality, we don't want to
   print it and ask the user to submit it.  In that case, the reason
   for skipping the FP is returned as a static string.  If the FP is
   great and should be printed, NULL is returned. */
const char *FingerPrintResults::OmitSubmissionFP() {
  static char reason[128];

  if (o.scan_delay > 500) { // This can screw up the sequence timing
    snprintf(reason, sizeof(reason), "Scan delay (%d) is greater than 500", o.scan_delay);
    return reason;
  }

  if (o.timing_level > 4)
    return "Timing level 5 (Insane) used";

  if (osscan_opentcpport <= 0)
    return "Missing an open TCP port so results incomplete";

  if (osscan_closedtcpport <= 0)
    return "Missing a closed TCP port so results incomplete";

  if (distance > 5) {
    snprintf(reason, sizeof(reason), "Host distance (%d network hops) is greater than five", distance);
    return reason;
  }

  if (maxTimingRatio > 1.4) {
    snprintf(reason, sizeof(reason), "maxTimingRatio (%e) is greater than 1.4", maxTimingRatio);
    return reason;
  }

  if (osscan_closedudpport < 0 && !o.udpscan) {
    /* If we didn't get a U1 response, that might be just
       because we didn't search for an open port rather than
       because this OS doesn't respond to that sort of probe.
       So we don't print FP if U1 response is lacking AND no UDP
       scan was performed. */
    return "Didn't receive UDP response. Please try again with -sSU";
  }

  return NULL;
}


/* Goes through fingerprinting results to populate OSR */
void FingerPrintResults::populateClassification() {
  int printno, classno;

  OSR.OSC_num_perfect_matches = OSR.OSC_num_matches = 0;
  OSR.overall_results = OSSCAN_SUCCESS;

  if (overall_results == OSSCAN_TOOMANYMATCHES) {
    // The normal classification overflowed so we don't even have all the perfect matches,
    // I don't see any good reason to do classification.
    OSR.overall_results = OSSCAN_TOOMANYMATCHES;
    return;
  }

  for(printno = 0; printno < num_matches; printno++) {
    // a single print may have multiple classifications
    for(classno = 0; classno < prints[printno]->num_OS_Classifications; classno++) {
      if (!classAlreadyExistsInResults(&(prints[printno]->OS_class[classno]))) {
	// Then we have to add it ... first ensure we have room
	if (OSR.OSC_num_matches == MAX_FP_RESULTS) {
	  // Out of space ... if the accuracy of this one is 100%, we have a problem
	  if (accuracy[printno] == 1.0) OSR.overall_results = OSSCAN_TOOMANYMATCHES;
	  return;
	}

	// We have space, but do we even want this one?  No point
	// including lesser matches if we have 1 or more perfect
	// matches.
	if (OSR.OSC_num_perfect_matches > 0 && accuracy[printno] < 1.0) {
	  return;
	}

	// OK, we will add the new class
	OSR.OSC[OSR.OSC_num_matches] = &(prints[printno]->OS_class[classno]);
	OSR.OSC_Accuracy[OSR.OSC_num_matches] = accuracy[printno];
	if (accuracy[printno] == 1.0) OSR.OSC_num_perfect_matches++;
	OSR.OSC_num_matches++;
      }
    }
  }

  if (OSR.OSC_num_matches == 0)
    OSR.overall_results = OSSCAN_NOMATCHES;

  return;
}

// Go through any previously enterted classes to see if this is a dupe;
bool FingerPrintResults::classAlreadyExistsInResults(struct OS_Classification *OSC) {
  int i;

  for (i=0; i < OSR.OSC_num_matches; i++) {
    if (!strcmp(OSC->OS_Vendor, OSR.OSC[i]->OS_Vendor)  &&
	!strcmp(OSC->OS_Family, OSR.OSC[i]->OS_Family)  &&
	!strcmp(OSC->Device_Type, OSR.OSC[i]->Device_Type) &&
	!strcmp(OSC->OS_Generation? OSC->OS_Generation : "", 
		OSR.OSC[i]->OS_Generation? OSR.OSC[i]->OS_Generation : "")) {
    // Found a duplicate!
    return true;
    }
  }

  // Went through all the results -- no duplicates found
  return false;
}

