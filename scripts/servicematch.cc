
/***************************************************************************
 * servicematch.cc -- A relatively simple utility for determining whether  *
 * a given Nmap service fingerprint matches (or comes close to any of the  *
 * fingerprints in a collection such as the nmap-service-probes file that  *
 * ships with Nmap.                                                        *
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
#include "service_scan.h"

#include <ctype.h>

void usage() {
  printf("Usage: servicematch <fingerprintfilename>\n"
         "(You will be prompted for the fingerprint data)\n"
	 "\n");
  exit(1);
}

// This function parses the read-in fprint, compares the responses to the
// given tests as if they had been read from a remote system, and prints out
// the first match if any, followed by the fingerprint in single-line format.
// The 'ipaddystr' is either a string of the form " on www.xx.y.zzz" containing the IP
// address of the target from which fprint was obtained, or it is empty (meaning we don't know).
int doMatch(AllProbes *AP, char *fprint, int fplen, char *ipaddystr) {
  u16 portno;
  int proto;
  char *p;
  char *currentprobe = NULL;
  char probename[128];
  char resptext[3048];
  char *endp = NULL;
  unsigned long fullrlen;
  bool trunc = false; // Was at least one response truncated due to length?
  unsigned int resptextlen;
  char *dst;
  ServiceProbe *SP = NULL;
  char softmatch[32] = {0};
  const struct MatchDetails *MD = NULL;
  bool nullprobecheat = false; // We cheated and found a match in the NULL probe to a non-null-probe response

  // First lets find the port number and protocol
  assert(fplen > 10);
  assert(strncmp(fprint, "SF-Port", 7) == 0);
  portno = atoi(fprint + 7);
  p = strchr(fprint, ':');
  assert(p);
  p -= 3;
  if (strncmp(p, "TCP", 3) == 0)
    proto = IPPROTO_TCP;
  else proto = IPPROTO_UDP;

  currentprobe = strstr(p, "%r(");
  while(currentprobe) {
    // move to the probe name
    p = currentprobe + 3;
    dst = probename;
    while(*p && *p != ',') {
      assert((unsigned int) (dst - probename) < sizeof(probename) - 1);
      *dst++ = *p++;
    }
    *dst++ = '\0';

    // Grab
    assert(*p == ',');
    p++;
    assert(isxdigit(*p));
    fullrlen = strtoul(p, &endp, 16);
    p = endp;
    assert(*p == ',');
    p++;
    assert(*p == '"');
    p++;

    dst = resptext;
    while(*p && (*p != '"' || (*(p-1) == '\\' && *(p-2) != '\\'))) {
      assert((unsigned int) (dst - resptext) < sizeof(resptext) - 1);
      *dst++ = *p++;
    }
    *dst++ = '\0';

    // Now we unescape the response into plain binary
    cstring_unescape(resptext, &resptextlen);

    if (resptextlen < fullrlen)
      trunc = true;

    // Finally we try to match this with the appropriate probe from the
    // nmap-service-probes file.
    SP = AP->getProbeByName(probename, proto);

    if (!SP) {
      error("WARNING: Unable to find probe named %s in given probe file.", probename);
    } else {
      nullprobecheat = false;
      MD = SP->testMatch((u8 *) resptext, resptextlen);
      if (!MD && !SP->isNullProbe() && SP->getProbeProtocol() == IPPROTO_TCP && AP->nullProbe) {
	MD = AP->nullProbe->testMatch((u8 *) resptext, resptextlen);
	nullprobecheat = true;
      }
      if (MD && MD->serviceName) {
	if (MD->isSoft) {
	  // We'll just squirrel it away for now
	  if (*softmatch && strcmp(softmatch, MD->serviceName) != 0) {
	    fprintf(stderr, "WARNING:  Soft match for service %s, followed by (ignored) soft match for service %s\n", softmatch, MD->serviceName);
	  } else Strncpy(softmatch, MD->serviceName, sizeof(softmatch));
	} else {
	  // YEAH!  Found a hard match!
	  if (MD->product || MD->version || MD->info || MD->hostname || MD->ostype || MD->devicetype) {
	    printf("MATCHED %ssvc %s", nullprobecheat? "(NULLPROBE CHEAT) " : "", MD->serviceName);
	    if (MD->product) printf(" p|%s|", MD->product);
	    if (MD->version) printf(" v|%s|", MD->version);
	    if (MD->info) printf(" i|%s|", MD->info);
	    if (MD->hostname) printf(" h|%s|", MD->hostname);
	    if (MD->ostype) printf(" o|%s|", MD->ostype);
	    if (MD->devicetype) printf(" d|%s|", MD->devicetype);
	    printf(" %s: %s\n", ipaddystr, fprint);
	  } else
	    printf("MATCHED %ssvc %s (NO VERSION)%s: %s\n", nullprobecheat? "(NULLPROBE CHEAT) " : "", MD->serviceName, ipaddystr, fprint);
	  return 0;
	}
      }
    }
    // Lets find the next probe, if any
    currentprobe = strstr(p, "%r(");
  }
  
  if (trunc) printf("WARNING:  At least one probe response was truncated\n");
  if (*softmatch) printf("SOFT MATCH svc %s (SOFT MATCH)%s: %s\n", softmatch, ipaddystr, fprint);
  else printf("FAILED to match%s: %s\n", ipaddystr, fprint);

  return 1;
}

int cleanfp(char *fprint, int *fplen) {
  char *src = fprint, *dst = fprint;

  while(*src) {
    if (strncmp(src, "\\x20", 4) == 0) {
      *dst++ = ' ';
      src += 4;
      /* } else if (*src == '\\' && (*(src+1) == '"' || *(src+1) == '\\')) {
      *dst++ = *++src;
      src++; */ // We shouldn't do this yet
    } else if (src != dst) {
      *dst++ = *src++;
    } else { dst++; src++; }
  }
  *dst++ = '\0';
  *fplen = dst - fprint - 1;
  return 0;
}


int main(int argc, char *argv[]) {
  AllProbes *AP = new AllProbes();
  char *probefile = NULL;
  char fprint[16384];
  int fplen = 0; // Amount of chars in the current fprint
  char line[512];
  unsigned int linelen;
  char *dst = NULL;
  int lineno;
  char *p, *q;
  bool isInFP = false; // whether we are currently reading in a fingerprint
  struct in_addr ip;
  char lastipbuf[64];

  if (argc != 2)
    usage();

  lastipbuf[0] = '\0';

  /* First we read in the fingerprint file provided on the command line */
  probefile = argv[1];
  parse_nmap_service_probe_file(AP, probefile);

  /* Now we read in the user-provided service fingerprint(s) */

  printf("Enter the service fingerprint(s) you would like to match.  Will read until EOF.  Other Nmap output text (besides fingerprints) is OK too and will be ignored\n");

  while(fgets(line, sizeof(line), stdin)) {
    lineno++;
    linelen = strlen(line);
    p = line;
    while(*p && isspace(*p)) p++;
    if (isInFP) {
      if (strncmp(p, "SF:", 3) == 0) {
	p += 3;
	assert(sizeof(fprint) > fplen + linelen + 1);
	dst = fprint + fplen;
	while(*p != '\r' && *p != '\n' && *p != ' ')
	  *dst++ = *p++;
	fplen = dst - fprint;
	*dst++ = '\0';
      } else {
	fatal("Fingerprint incomplete ending on line #%d", lineno);
      }
    }

    if (strncmp(p, "SF-Port", 7) == 0) {
      if (isInFP) 
	fatal("New service fingerprint started before the previous one was complete -- line %d", lineno);
      assert(sizeof(fprint) > linelen + 1);
      dst = fprint;
      while(*p != '\r' && *p != '\n' && *p != ' ')
	*dst++ = *p++;
      fplen = dst - fprint;
      *dst++ = '\0';
      isInFP = true;
    } else if (strncmp(p, "Interesting port", 16) == 0) {
      q = line + linelen - 1;
      while(*q && (*q == ')' || *q == ':' || *q == '\n'|| *q == '.' || isdigit((int) (unsigned char) *q))) {
	if (*q == ')' || *q == ':' || *q == '\n') *q = '\0';
	q--;
      }
      q++;
      assert(isdigit((int)(unsigned char) *q));
      if (inet_aton(q, &ip) != 0) {
	snprintf(lastipbuf, sizeof(lastipbuf), " on %s", inet_ntoa(ip));
      }
    }

    // Now we test if the fingerprint is complete
    if (isInFP && fplen > 5 && strncmp(fprint + fplen - 3, "\");", 3) == 0) {
      // Yeah!  We have read in the whole fingerprint
      isInFP = false;
      // Cleans the fingerprint up a little, such as replacing \x20 with space and unescaping characters like \\ and \"
      cleanfp(fprint, &fplen);
      doMatch(AP, fprint, fplen, lastipbuf);
    }
  }

  return 0;
}
