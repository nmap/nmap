
/***************************************************************************
 * fingerdiff.c -- A relatively simple utility for determining the         *
 * differences between a "reference" fingerprint (which can have           *
 * expressions as attributes) and an observed fingerprint (no              *
 * expressions).                                                           *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2006 Insecure.Com LLC. Nmap       *
 * is also a registered trademark of Insecure.Com LLC.  This program is    *
 * free software; you may redistribute and/or modify it under the          *
 * terms of the GNU General Public License as published by the Free        *
 * Software Foundation; Version 2.  This guarantees your right to use,     *
 * modify, and redistribute this software under certain conditions.  If    *
 * you wish to embed Nmap technology into proprietary software, we may be  *
 * willing to sell alternative licenses (contact sales@insecure.com).      *
 * Many security scanner vendors already license Nmap technology such as  *
 * our remote OS fingerprinting database and code, service/version         *
 * detection system, and port scanning code.                               *
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
 * http://insecure.org/nmap/ to download Nmap.                         *
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
 * of security vendors, and generally include a perpetual license as well  *
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

void usage(char *err_fmt, ...) {
  va_list  ap;

  if (err_fmt) {
    va_start(ap, err_fmt);
    fflush(stdout);
    vfprintf(stderr, err_fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
  }
  printf("\nUsage: Use fingerdiff w/o any arguments to read the reference\n"
         " FP front stdin, or give filename:lineno to read it from\n"
         " nmap-os-fingerprints.\n\n");
  exit(1);
}

/* Returns -1 (or exits) for failure */
int readFP(FILE *filep, char *newFP, int newFPsz ) {
  char line[512], lasttestname[64];
  int linelen;
  int lastlinelen = 0;
  int printlen = 0;
  int adjusted = 0; /* Flags if we have adjusted the entered fingerprint */
  char *p;

  if (newFPsz < 50) return -1;
  
  newFP[0] = lasttestname[0] = '\0';

  while((fgets(line, sizeof(line), filep))) {
    if (*line == '\n' || *line == '.')
      break;
    
    linelen = strlen(line);
    /* Check if it is a duplicate testname */
    if (*line == '#')
      continue;
    p = strchr(line, '(');
    if (p) {
      *p = '\0';
      if (strcmp(line, lasttestname) == 0) {
	adjusted = 1;
	if (lastlinelen >= linelen)
	  continue;
	/* The new one is longer (and thus probably better) -- clobber the last
	   line */
	printlen -= lastlinelen;
	newFP[printlen] = '\0';
      }
      Strncpy(lasttestname, line, sizeof(lasttestname));
      lastlinelen = linelen;
      *p = '(';
    } else {
     /* The only legitimate non-comment line that doesn't have a ( is the 
	 initial Fingerprint and the following Class line(s) */
      if (strncmp(line, "Class ", 6) == 0) {
	char *q = line + 6;
	while(*q && isspace(*q)) q++;
	if (!*q) continue; // Empty class line
      } else if (strncmp(line, "Fingerprint ", 12) != 0) {
	printf("Warning: Bogus line skipped\n");
	continue;
      }
    }
    if (printlen + linelen >= newFPsz - 5)
      fatal("Overflow!");
    strcpy(newFP + printlen, line);
    printlen += linelen;
  }
  
  if (adjusted) {
    printf("\n**WARNING**: Adjusted fingerprint due to duplicated tests (we only look at the first).  Results are based on this adjusted fingerprint:\n%s\n",
	   newFP);
  }
  
  /* Now we validate that all elements are present */
  p = newFP;
  if (!strstr(p, "TSeq(") || !strstr(p, "T1(") || !strstr(p, "T2(") || 
      !strstr(p, "T3(") || !strstr(p, "T4(") || !strstr(p, "T5(") || 
      !strstr(p, "T6(") || !strstr(p, "T7(") || !strstr(p, "PU(")) {
    /* This ought to get my attention :) */
    printf("\n"
	 "********************************************************\n"
         "***WARNING: Fingerprint is missing at least 1 element***\n"
         "********************************************************\n"
	  );

  }
  if (printlen < 1)
    return -1;
  return 0;
}

int main(int argc, char *argv[]) {
  FingerPrint *referenceFP;
  FingerPrint *observedFP;
  double accuracy;
  char sourcefile[MAXPATHLEN];
  int sourceline=-1;
  char referenceFPString[2048];
  char observedFPString[2048];
  char line[512];
  char *p, *endptr;
  int i;
  int done=0;
  FILE *fp;

  if (argc < 1 || argc > 2)
    usage(NULL);

  referenceFPString[0] = observedFPString[0] = '\0';

  if (argc == 2) {
    Strncpy(sourcefile, argv[1], sizeof(sourcefile));
    p = strchr(sourcefile, ':');
    if (!p) usage("Filename must be followed by a colon and then line number");
    *p++ = '\0';
    if (!*p) usage(NULL);
    sourceline = strtol(p, &endptr, 10);
    if (*endptr) {
      error("could not parse line number (trailing garbage?)");
    }
    fp = fopen(sourcefile, "r");
    done = 0; i = 1;
    while(i < sourceline) {
      if (fgets(line, sizeof(line), fp) == NULL)
	usage("Failed to read to line %d of %s", sourceline, sourcefile);
      i++;
    }

    if (readFP(fp, referenceFPString, sizeof(referenceFPString)) == -1)
      usage("Failed to read in supposed fingerprint in %s line %d\n", sourcefile, sourceline);
    fclose(fp);
    printf("STEP ONE: Reading REFERENCE FINGERPRINT from %s line %d:\n%s\n"
	   ,sourcefile, sourceline, referenceFPString);    
  } else {
  
    printf("STEP ONE: Enter the **REFERENCE FINGERPRINT**, followed by a blank or single-dot line:\n");

    if (readFP(stdin, referenceFPString, sizeof(referenceFPString)) == -1)
      usage("Failed to read in supposed fingerprint from stdin\n");    
  }

  referenceFP = parse_single_fingerprint(referenceFPString);
  if (!referenceFP) fatal("Sorry -- failed to parse the so-called reference fingerprint you entered");


  printf("STEP TWO: Enter the **OBSERVED FINGERPRINT**, followed by a blank or single-dot line:\n");


  if (readFP(stdin, observedFPString, sizeof(observedFPString)) == -1)
    usage("Failed to read in supposed observed fingerprint from stdin\n");

  observedFP = parse_single_fingerprint(observedFPString);
  if (!observedFP) fatal("Sorry -- failed to parse the so-called reference fingerprint you entered");

  /* OK, now I've got the fingerprints -- I just need to compare them ... */
  accuracy = compare_fingerprints(referenceFP, observedFP, 1);
  if (accuracy == 1)
    printf("PERFECT MATCH!\n");
  else printf("Accuracy of the two prints is %d%% -- see differences above.\n",
	      (int) (accuracy * 100));


  return 0;
}
