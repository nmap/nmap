
/***************************************************************************
 * fingermatch.cc -- A relatively simple utility for determining whether a *
 * given Nmap fingerprint matches (or comes close to matching) any of the  *
 * fingerprints in a collection such as the nmap-os-fingerprints file that *
 * ships with Nmap.                                                        *
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


#include "nbase.h"
#include "nmap.h"
#include "osscan.h"
#include "fingerlib.h"

#define FINGERMATCH_GUESS_THRESHOLD 0.75 /* How low we will still show guesses for */

void usage() {
  printf("Usage: fingermatch <fingerprintfilename>\n"
         "(You will be prompted for the fingerprint data)\n"
	 "\n");
  exit(1);
}

int main(int argc, char *argv[]) {
  char *fingerfile = NULL;
  FingerPrint **reference_FPs = NULL;
  FingerPrint *testFP;
  struct FingerPrintResults FPR;
  char fprint[2048];
  int i, rc;
  char gen[128]; /* temporary buffer for os generation part of classification */
  if (argc != 2)
    usage();

  /* First we read in the fingerprint file provided on the command line */
  fingerfile = argv[1];
  reference_FPs = parse_fingerprint_file(fingerfile);
  if (reference_FPs == NULL) 
    fatal("Could not open or parse Fingerprint file given on the command line: %s", fingerfile);

  /* Now we read in the user-provided fingerprint */
  printf("Enter the fingerprint you would like to match, followed by a blank single-dot line:\n");

  if (readFP(stdin, fprint, sizeof(fprint)) == -1)
    fatal("[ERROR] Failed to read in supposed fingerprint from stdin\n");

  testFP = parse_single_fingerprint(fprint);
  if (!testFP) fatal("Sorry -- failed to parse the so-called fingerprint you entered");

  if ((rc = remove_duplicate_tests(testFP))) {
 printf("[WARN] Adjusted fingerprint due to %d duplicated tests (we only look at the first).\n", rc);
  }

  /* Now we find the matches! */
  match_fingerprint(testFP, &FPR, reference_FPs, FINGERMATCH_GUESS_THRESHOLD);

  switch(FPR.overall_results) {
  case OSSCAN_NOMATCHES:
    printf("**NO MATCHES** found for the entered fingerprint in %s\n", fingerfile);
    break;
  case OSSCAN_TOOMANYMATCHES:
    printf("Found **TOO MANY EXACT MATCHES** to print for entered fingerprint in %s\n", fingerfile);
    break;
  case OSSCAN_SUCCESS:
    if (FPR.num_perfect_matches > 0) {
      printf("Found **%d PERFECT MATCHES** for entered fingerprint in %s:\n", FPR.num_perfect_matches, fingerfile);
      printf("Accu Line# OS (classification)\n");      
      for(i=0; i < FPR.num_matches && FPR.accuracy[i] == 1; i++) {
	if (FPR.prints[i]->OS_class[0].OS_Generation)
	  snprintf(gen, sizeof(gen), " %s ", FPR.prints[i]->OS_class[0].OS_Generation);
	else gen[0] = '\0';	
	printf("100%% %5d %s (%s | %s |%s| %s)\n", FPR.prints[i]->line, FPR.prints[i]->OS_name, FPR.prints[i]->OS_class[0].OS_Vendor, FPR.prints[i]->OS_class[0].OS_Family, gen, FPR.prints[i]->OS_class[0].Device_Type );
      }
    } else {
      printf("No perfect matches found, **GUESSES AVAILABLE** for entered fingerprint in %s:\n", fingerfile);
      printf("Accu Line# OS (classification)\n");
      for(i=0; i < 10 && i < FPR.num_matches; i++) {
	if (FPR.prints[i]->OS_class[0].OS_Generation)
	  snprintf(gen, sizeof(gen), " %s ", FPR.prints[i]->OS_class[0].OS_Generation);
	else gen[0] = '\0';	
	printf("%3d%% %5d %s (%s | %s |%s| %s)\n", (int) (FPR.accuracy[i] * 100), FPR.prints[i]->line, FPR.prints[i]->OS_name, FPR.prints[i]->OS_class[0].OS_Vendor, FPR.prints[i]->OS_class[0].OS_Family, gen, FPR.prints[i]->OS_class[0].Device_Type );
      }
    }
    printf("\n");
    break;
  default:
    fatal("Bogus error.");
    break;
  }

  return 0;
}
