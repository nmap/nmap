
/***************************************************************************
 * FingerPrintResults.h -- The FingerPrintResults class the results of OS  *
 * fingerprint matching against a certain host.                            *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2012 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 with the clarifications and exceptions described  *
 * below.  This guarantees your right to use, modify, and redistribute     *
 * this software under certain conditions.  If you wish to embed Nmap      *
 * technology into proprietary software, we sell alternative licenses      *
 * (contact sales@insecure.com).  Dozens of software vendors already       *
 * license Nmap technology such as host discovery, port scanning, OS       *
 * detection, version detection, and the Nmap Scripting Engine.            *
 *                                                                         *
 * Note that the GPL places important restrictions on "derived works", yet *
 * it does not provide a detailed definition of that term.  To avoid       *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
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
 * works of Nmap, as well as other software we distribute under this       *
 * license such as Zenmap, Ncat, and Nping.  This list is not exclusive,   *
 * but is meant to clarify our interpretation of derived works with some   *
 * common examples.  Our interpretation applies only to Nmap--we don't     *
 * speak for other people's GPL works.                                     *
 *                                                                         *
 * If you have any questions about the GPL licensing restrictions on using *
 * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
 * we also offer alternative license to integrate Nmap into proprietary    *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates.  They also fund the      *
 * continued development of Nmap.  Please email sales@insecure.com for     *
 * further information.                                                    *
 *                                                                         *
 * As a special exception to the GPL terms, Insecure.Com LLC grants        *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two. You must obey the GNU GPL in all *
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

/* $Id$ */

#ifndef FINGERPRINTRESULTS_H
#define FINGERPRINTRESULTS_H

class FingerPrintResults;

#include "nmap.h"
#include "global_structures.h"
#include "FPEngine.h"

/* Maximum number of results allowed in one of these things ... */
#define MAX_FP_RESULTS 36

struct OS_Classification_Results {
  struct OS_Classification *OSC[MAX_FP_RESULTS];
  double OSC_Accuracy[MAX_FP_RESULTS];
  int OSC_num_perfect_matches; // Number of perfect matches in OSC[\]
  int OSC_num_matches; // Number of matches total in OSC[] (and, of course, _accuracy[])
  int overall_results; /* OSSCAN_TOOMANYMATCHES, OSSCAN_NOMATCHES, OSSCAN_SUCCESS, etc */
};

class FingerPrintResults {
 public: /* For now ... a lot of the data members should be made private */
  FingerPrintResults();
  virtual ~FingerPrintResults();

  double accuracy[MAX_FP_RESULTS]; /* Percentage of match (1.0 == perfect 
				      match) in same order as matches[] below */
  FingerMatch *matches[MAX_FP_RESULTS]; /* ptrs to matching references -- 
					      highest accuracy matches first */
  int num_perfect_matches; /* Number of 1.0 accuracy matches in matches[] */
  int num_matches; /* Total number of matches in matches[] */
  int overall_results; /* OSSCAN_TOOMANYMATCHES, OSSCAN_NOMATCHES, 
			  OSSCAN_SUCCESS, etc */

  /* Ensures that the results are available and then returns them.
   You should only call this AFTER all matching has been completed
   (because results are cached and won't change if new matches[] are
   added.)  All OS Classes in the results will be unique, and if there
   are any perfect (accuracy 1.0) matches, only those will be
   returned */
  const struct OS_Classification_Results *getOSClassification();

  int osscan_opentcpport; /* Open TCP port used for scannig (if one found -- 
			  otherwise -1) */
  int osscan_closedtcpport; /* Closed TCP port used for scannig (if one found -- 
			    otherwise -1) */
  int osscan_closedudpport;  /* Closed UDP port used for scannig (if one found -- 
			    otherwise -1) */
  int distance; /* How "far" is this FP gotten from? */
  int distance_guess; /* How "far" is this FP gotten from? by guessing based on ttl. */

  /* The largest ratio we have seen of time taken vs. target time
     between sending 1st tseq probe and sending first ICMP echo probe.
     Zero means we didn't see any ratios (the tseq probes weren't
     sent), 1 is ideal, and larger values are undesirable from a
     consistancy standpoint. */
  double maxTimingRatio;

/* If the fingerprint is of potentially poor quality, we don't want to
   print it and ask the user to submit it.  In that case, the reason
   for skipping the FP is returned as a static string.  If the FP is
   great and should be printed, NULL is returned. */
  virtual const char *OmitSubmissionFP();

  virtual const char *merge_fpr(const Target *currenths, bool isGoodFP, bool wrapit) const = 0;

 private:
  bool isClassified; // Whether populateClassification() has been called
  /* Goes through fingerprinting results to populate OSR */

  void populateClassification();
  bool classAlreadyExistsInResults(struct OS_Classification *OSC);
  struct OS_Classification_Results OSR;
};

class FingerPrintResultsIPv4 : public FingerPrintResults {
public:
  FingerPrint **FPs; /* Fingerprint data obtained from host */
  int numFPs;

  FingerPrintResultsIPv4();
  virtual ~FingerPrintResultsIPv4();
  const char *merge_fpr(const Target *currenths, bool isGoodFP, bool wrapit) const;
};

class FingerPrintResultsIPv6 : public FingerPrintResults {
public:
  FPResponse *fp_responses[NUM_FP_PROBES_IPv6];
  struct timeval begin_time;
  /* The flow label we set in our sent packets, for calculating offsets later. */
  unsigned int flow_label;

  FingerPrintResultsIPv6();
  virtual ~FingerPrintResultsIPv6();
  const char *OmitSubmissionFP();
  const char *merge_fpr(const Target *currenths, bool isGoodFP, bool wrapit) const;
};

#endif /* FINGERPRINTRESULTS_H */
