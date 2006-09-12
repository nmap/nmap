/***************************************************************************
 * fingerlib.cc/.h -- Some misc. functions related to fingerprint parsing  *
 * and the like to be used by integration-related programs such as         *
 * fingerfix, fingermatch, and fingerdiff                                  *
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


#include "nbase.h"
#include "nmap.h"
#include "fingerlib.h"
#include "MACLookup.h"

static int checkFP(char *FP) {
  char *p;
  char macbuf[16];
  u8 macprefix[3];
  char tmp;
  bool founderr = false;
  int i;

  // SCAN
  p = strstr(FP, "SCAN(");
  if(!p) {
	founderr = true;
	printf("[WARN] SCAN line is missing");
  } else {
	// SCAN.G: whether the fingerprint is good
	p = strstr(FP, "%G=");
	if(!p) p = strstr(FP, "(G=");
	if(!p) {
	  printf("[WARN] Attribute G is missing in SCAN line\n");
	  founderr = true;
	} else {
	  tmp = *(p+3);
	  if(tmp != 'Y') {
		printf("[WARN] One fingerprint is not good\n");
		founderr = true;
	  }
	}
	
	// SCAN.M: mac prefix of the target.
	// if there is a MAC prefix, print the vendor name
	p = strstr(FP, "%M=");
	if(!p) p = strstr(FP, "(M=");
	if(p) {
	  p = p + 3;
	  for(i = 0; i < 6; i++) {
		if(!p[i] || !isxdigit(p[i])) {
		  printf("[WARN] Invalid value (%s) occurs in SCAN.M\n", p);
		  founderr = true;
		  break;
		}
	  }
	  if(!founderr) {
		strncpy(macbuf, p, 6);
		i = strtol(macbuf, NULL, 16);
		macprefix[0] = i >> 16;
		macprefix[1] = (i >> 8) & 0xFF;
		macprefix[2] = i & 0xFF;
		printf("[INFO] Vendor Info: %s\n", MACPrefix2Corp(macprefix));
	  }
	}
  }

  /* Now we validate that all elements are present */
  p = FP;
  if (!strstr(p, "SEQ(") || !strstr(p, "OPS(") || !strstr(p, "WIN(") || 
	  !strstr(p, "ECN(") || !strstr(p, "T1(") || !strstr(p, "T2(") || 
      !strstr(p, "T3(") || !strstr(p, "T4(") || !strstr(p, "T5(") || 
      !strstr(p, "T6(") || !strstr(p, "T7(") || !strstr(p, "U1(") ||
	  !strstr(p, "IE(")) {
    /* This ought to get my attention :) */
	founderr = true;
    printf("[WARN] Fingerprint is missing at least 1 element\n");
  }
  
  if(founderr) return -1;
  return 0;
}


/* Reads a fingerprint in from the filep file descriptor.  The FP may
   be in wrapped or unwrapped format.  Wrapped prints are unrapped
   before being returned in FP.  Returns -1 or exits if it fails. */
int readFP(FILE *filep, char *FP, int FPsz ) {
  char line[512];
  int linelen = 0;
  int lineno = 0;
  char *p, *q;
  char *oneFP;
  char *dst = FP;
  char tmp[16];
  int i;
  bool isInWrappedFP = false; // whether we are currently reading in a
							  // wrapped fingerprint
  
  if(FPsz < 50) return -1;
  FP[0] = '\0';

  while((fgets(line, sizeof(line), filep))) {
	lineno++;
	linelen = strlen(line);
	p = line;
	if (*p == '\n' || *p == '.') {
	  // end of input
	  *dst = '\0';	  

	  if(isInWrappedFP) {
	    // We have just completed reading in a wrapped fp. Because a
	    // wrapped fp is submitted by user, so we check if there is a
	    // SCAN line in it. If yes, look inside the scan line.
	    checkFP(oneFP);
	    isInWrappedFP = false;
	  }  
	  break;
	}
	while(*p && isspace(*p)) p++;
	if (*p == '#') 
	  continue; // skip the comment line

	if (dst - FP + linelen >= FPsz - 5)
	  fatal("[ERRO] Overflow!\n");
	
	if(strncmp(p, "OS:", 3) == 0) {
	  // the line is start with "OS:"
	  if(!isInWrappedFP) {
		// just enter a wrapped fp area
		oneFP = dst;
		isInWrappedFP = true;
	  }
	  p += 3;
	  while(*p != '\r' && *p != '\n') {
	    *dst++ = toupper(*p);
	    if(*p == ')') *dst++ = '\n';
	    p++;
	  }
	  continue;
	}

	// this line is not start with "OS:"
	if(isInWrappedFP) {
	  // We have just completed reading in a wrapped fp. Because a
	  // wrapped fp is submitted by user, so we check if there is a
	  // SCAN line in it. If yes, look inside the scan line.
	  *dst = '\0';
	  checkFP(oneFP);
	  isInWrappedFP = false;
	}

	q = p; i = 0;
	while(q && *q && i<12)
	  tmp[i++] = toupper(*q++);
	tmp[i] = '\0';
	if(strncmp(tmp, "FINGERPRINT", 11) == 0) {
	  q = p + 11;
	  while(*q && isspace(*q)) q++;
	  if (*q) { // this fingeprint line is not empty
		strncpy(dst, "Fingerprint", 11);
		dst += 11;
		p += 11;
		while(*p) *dst++ = *p++;
	  }
	  continue;
	} else if(strncmp(tmp, "CLASS", 5) == 0) {
	  q = p + 5;
	  while(*q && isspace(*q)) q++;
	  if (*q) {// this class line is not empty
		strncpy(dst, "Class", 5);
		dst += 5;
		p += 5;
		while(*p) *dst++ = *p++;
	  }
	  continue;
	} else if(strchr(p, '(')) {
	  while(*p) *dst++ = toupper(*p++);
	} else {
	  printf("[WARN] Skip bogus line: %s\n", p);
	  continue;
	}
  }

  // Now we validate that all elements are present. Though this maybe
  // redundant because we have checked it for those wrapped FPs, it
  // doesn't hurt to give a duplicated warning here.
  p = FP;
  if (!strstr(p, "SEQ(") || !strstr(p, "OPS(") || !strstr(p, "WIN(") || 
	  !strstr(p, "ECN(") || !strstr(p, "T1(") || !strstr(p, "T2(") || 
      !strstr(p, "T3(") || !strstr(p, "T4(") || !strstr(p, "T5(") || 
      !strstr(p, "T6(") || !strstr(p, "T7(") || !strstr(p, "U1(") ||
	  !strstr(p, "IE(")) {
    /* This ought to get my attention :) */
    printf("[WARN] Fingerprint is missing at least 1 element\n");
  }
  
  if (dst - FP < 1)
    return -1;
  return 0;
}

/* When Nmap prints a fingerprint for submission, it sometimes
   includes duplicates of tests because 1 or more elements of that
   test differ.  While this is important for things like fingerfix
   (submission), other scripts can't handle it.  So this function
   removes the duplicates.  Maybe it should have more smarts, but
   currently it just keeps the first instance of each test.  Returns
   the number of duplicate tests (0 if there were none). The function
   quits and prints the problem if there is an error. */
int remove_duplicate_tests(FingerPrint *FP) {
  FingerPrint *outer = FP, *inner, *tmp;
  int dupsfound = 0;
  if (!FP) { fatal("NULL FP passed to %s", __FUNCTION__); }

  for(outer = FP; outer; outer = outer->next) {
    /* We check if this test has any duplicates forward in the list,
       and if so, remove them */
    for(inner = outer; inner->next; inner = inner->next) {
      if (strcmp(outer->name, inner->next->name) == 0) {
	/* DUPLICATE FOUND!  REMOVE IT */
	dupsfound++;
	tmp = inner->next;
	inner->next = inner->next->next;
	free(tmp);
      }
    }
  }

  return dupsfound;
}
