/***************************************************************************
 * osscan.h -- Routines used for OS detection via TCP/IP fingerprinting.   *
 * For more information on how this works in Nmap, see my paper at         *
 * https://nmap.org/osdetect/                                               *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2020 Insecure.Com LLC ("The Nmap  *
 * Project"). Nmap is also a registered trademark of the Nmap Project.     *
 *                                                                         *
 * This program is distributed under the terms of the Nmap Public Source   *
 * License (NPSL). The exact license text applying to a particular Nmap    *
 * release or source code control revision is contained in the LICENSE     *
 * file distributed with that version of Nmap or source code control       *
 * revision. More Nmap copyright/legal information is available from       *
 * https://nmap.org/book/man-legal.html, and further information on the    *
 * NPSL license itself can be found at https://nmap.org/npsl. This header  *
 * summarizes some key points from the Nmap license, but is no substitute  *
 * for the actual license text.                                            *
 *                                                                         *
 * Nmap is generally free for end users to download and use themselves,    *
 * including commercial use. It is available from https://nmap.org.        *
 *                                                                         *
 * The Nmap license generally prohibits companies from using and           *
 * redistributing Nmap in commercial products, but we sell a special Nmap  *
 * OEM Edition with a more permissive license and special features for     *
 * this purpose. See https://nmap.org/oem                                  *
 *                                                                         *
 * If you have received a written Nmap license agreement or contract       *
 * stating terms other than these (such as an Nmap OEM license), you may   *
 * choose to use and redistribute Nmap under those terms instead.          *
 *                                                                         *
 * The official Nmap Windows builds include the Npcap software             *
 * (https://npcap.org) for packet capture and transmission. It is under    *
 * separate license terms which forbid redistribution without special      *
 * permission. So the official Nmap Windows builds may not be              *
 * redistributed without special permission (such as an Nmap OEM           *
 * license).                                                               *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to submit your         *
 * changes as a Github PR or by email to the dev@nmap.org mailing list     *
 * for possible incorporation into the main distribution. Unless you       *
 * specify otherwise, it is understood that you are offering us very       *
 * broad rights to use your submissions as described in the Nmap Public    *
 * Source License Contributor Agreement. This is important because we      *
 * fund the project by selling licenses with various terms, and also       *
 * because the inability to relicense code has caused devastating          *
 * problems for other Free Software projects (such as KDE and NASM).       *
 *                                                                         *
 * The free version of Nmap is distributed in the hope that it will be     *
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of  *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranties,        *
 * indemnification and commercial support are all available through the    *
 * Npcap OEM program--see https://nmap.org/oem.                            *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */

#ifndef OSSCAN_H
#define OSSCAN_H

#include <nbase.h>
#include <vector>

class Target;
class FingerPrintResultsIPv4;

#define OSSCAN_SUCCESS 0
#define OSSCAN_NOMATCHES -1
#define OSSCAN_TOOMANYMATCHES -2

/* We won't even consider matches with a lower accuracy than this */
#define OSSCAN_GUESS_THRESHOLD 0.85

/* The method used to calculate the Target::distance, included in OS
   fingerprints. */
enum dist_calc_method {
        DIST_METHOD_NONE,
        DIST_METHOD_LOCALHOST,
        DIST_METHOD_DIRECT,
        DIST_METHOD_ICMP,
        DIST_METHOD_TRACEROUTE
};

/**********************  STRUCTURES  ***********************************/

struct AVal {
  const char *attribute;
  const char *value;

  bool operator<(const AVal& other) const {
    return strcmp(attribute, other.attribute) < 0;
  }
};

struct OS_Classification {
  const char *OS_Vendor;
  const char *OS_Family;
  const char *OS_Generation; /* Can be NULL if unclassified */
  const char *Device_Type;
  std::vector<const char *> cpe;
};

/* A description of an operating system: a human-readable name and a list of
   classifications. */
struct FingerMatch {
  int line; /* For reference prints, the line # in nmap-os-db */
  /* For IPv6 matches, the number of fingerprints that contributed to this
   * classification group */
  unsigned short numprints;
  char *OS_name;
  std::vector<OS_Classification> OS_class;

  FingerMatch() {
    line = -1;
    OS_name = NULL;
  }
};

struct FingerTest {
  const char *name;
  std::vector<struct AVal> results;
  bool operator<(const FingerTest& other) const {
    return strcmp(name, other.name) < 0;
  }
};

struct FingerPrint {
  FingerMatch match;
  std::vector<FingerTest> tests;
  FingerPrint();
  void sort();
};
/* This structure contains the important data from the fingerprint
   database (nmap-os-db) */
struct FingerPrintDB {
  FingerPrint *MatchPoints;
  std::vector<FingerPrint *> prints;

  FingerPrintDB();
  ~FingerPrintDB();
};

/**********************  PROTOTYPES  ***********************************/

const char *fp2ascii(FingerPrint *FP);

/* Parses a single fingerprint from the memory region given.  If a
 non-null fingerprint is returned, the user is in charge of freeing it
 when done.  This function does not require the fingerprint to be 100%
 complete since it is used by scripts such as scripts/fingerwatch for
 which some partial fingerpritns are OK. */
FingerPrint *parse_single_fingerprint(char *fprint_orig);

/* These functions take a file/db name and open+parse it, returning an
   (allocated) FingerPrintDB containing the results.  They exit with
   an error message in the case of error. */
FingerPrintDB *parse_fingerprint_file(const char *fname);
FingerPrintDB *parse_fingerprint_reference_file(const char *dbname);

void free_fingerprint_file(FingerPrintDB *DB);

/* Compares 2 fingerprints -- a referenceFP (can have expression
   attributes) with an observed fingerprint (no expressions).  If
   verbose is nonzero, differences will be printed.  The comparison
   accuracy (between 0 and 1) is returned).  If MatchPoints is not NULL, it is
   a special "fingerprints" which tells how many points each test is worth. */
double compare_fingerprints(const FingerPrint *referenceFP, const FingerPrint *observedFP,
                            const FingerPrint *MatchPoints, int verbose);

/* Takes a fingerprint and looks for matches inside the passed in
   reference fingerprint DB.  The results are stored in in FPR (which
   must point to an instantiated FingerPrintResultsIPv4 class) -- results
   will be reverse-sorted by accuracy.  No results below
   accuracy_threshold will be included.  The max matches returned is
   the maximum that fits in a FingerPrintResultsIPv4 class.  */
void match_fingerprint(const FingerPrint *FP, FingerPrintResultsIPv4 *FPR,
                       const FingerPrintDB *DB, double accuracy_threshold);

/* Returns true if perfect match -- if num_subtests & num_subtests_succeeded are non_null it updates them.  if shortcircuit is zero, it does all the tests, otherwise it returns when the first one fails */

void freeFingerPrint(FingerPrint *FP);
void WriteSInfo(char *ostr, int ostrlen, bool isGoodFP,
                                const char *engine_id,
                                const struct sockaddr_storage *addr, int distance,
                                enum dist_calc_method distance_calculation_method,
                                const u8 *mac, int openTcpPort,
                                int closedTcpPort, int closedUdpPort);
const char *mergeFPs(FingerPrint *FPs[], int numFPs, bool isGoodFP,
                           const struct sockaddr_storage *addr, int distance,
                           enum dist_calc_method distance_calculation_method,
                           const u8 *mac, int openTcpPort, int closedTcpPort,
                           int closedUdpPort, bool wrapit);

#endif /*OSSCAN_H*/

