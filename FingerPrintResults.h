
/***************************************************************************
 * FingerPrintResults.h -- The FingerPrintResults class the results of OS  *
 * fingerprint matching against a certain host.                            *
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

#ifndef FINGERPRINTRESULTS_H
#define FINGERPRINTRESULTS_H

class FingerPrintResults;

#include "FPEngine.h"
#include "osscan.h"
#include "charpool.h"

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

  int osscan_opentcpport; /* Open TCP port used for scanning (if one found --
                          otherwise -1) */
  int osscan_closedtcpport; /* Closed TCP port used for scanning (if one found --
                            otherwise -1) */
  int osscan_closedudpport;  /* Closed UDP port used for scanning (if one found --
                            otherwise -1) */
  int distance; /* How "far" is this FP gotten from? */
  int distance_guess; /* How "far" is this FP gotten from? by guessing based on ttl. */
  enum dist_calc_method distance_calculation_method;

  /* The largest ratio we have seen of time taken vs. target time
     between sending 1st tseq probe and sending first ICMP echo probe.
     Zero means we didn't see any ratios (the tseq probes weren't
     sent), 1 is ideal, and larger values are undesirable from a
     consistency standpoint. */
  double maxTimingRatio;

  bool incomplete; /* Were we unable to send all necessary probes? */

  /* Store small strings in this object's CharPool. */
  const char *cp_hex(u32 val);
  const char *cp_dup(const char *src, int len=-1);

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
  CharPool *cp; /* Holds small strings allocated for the life of this object */
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

