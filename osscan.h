/***************************************************************************
 * osscan.h -- Routines used for OS detection via TCP/IP fingerprinting.   *
 * For more information on how this works in Nmap, see my paper at         *
 * https://nmap.org/osdetect/                                               *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2015 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE CLARIFICATIONS  *
 * AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your right to use,    *
 * modify, and redistribute this software under certain conditions.  If    *
 * you wish to embed Nmap technology into proprietary software, we sell    *
 * alternative licenses (contact sales@nmap.com).  Dozens of software      *
 * vendors already license Nmap technology such as host discovery, port    *
 * scanning, OS detection, version detection, and the Nmap Scripting       *
 * Engine.                                                                 *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files, such as Nmap's nmap-os-db   *
 * or nmap-service-probes.                                                 *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * Nmap with other software in compressed or archival form does not        *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * As another special exception to the GPL terms, Insecure.Com LLC grants  *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two.                                  *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * Nmap or grant special permissions to use it in other open source        *
 * software.  Please contact fyodor@nmap.org with any such requests.       *
 * Similarly, we don't incorporate incompatible open source software into  *
 * Covered Software without special permission from the copyright holders. *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * Nmap in other works, are happy to help.  As mentioned above, we also    *
 * offer alternative license to integrate Nmap into proprietary            *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates.  They also fund the      *
 * continued development of Nmap.  Please email sales@nmap.com for further *
 * information.                                                            *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
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
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING)        *
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

/* The OS database consists of many small strings, many of which appear
   thousands of times. It pays to allocate memory only once for each unique
   string, and have all references point at the one allocated value. */
const char *string_pool_insert(const char *s);
const char *string_pool_sprintf(const char *fmt, ...);

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

