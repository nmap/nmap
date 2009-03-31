
/***************************************************************************
 * service_scan.h -- Routines used for service fingerprinting to determine *
 * what application-level protocol is listening on a given port            *
 * (e.g. snmp, http, ftp, smtp, etc.)                                      *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2009 Insecure.Com LLC. Nmap is    *
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
 *   nmap-os-db or nmap-service-probes.                                    *
 * o Executes Nmap and parses the results (as opposed to typical shell or  *
 *   execution-menu apps, which simply display raw Nmap output and so are  *
 *   not derivative works.)                                                * 
 * o Integrates/includes/aggregates Nmap into a proprietary executable     *
 *   installer, such as those produced by InstallShield.                   *
 * o Links to a library or executes a program that does any of the above   *
 *                                                                         *
 * The term "Nmap" should be taken to also include any portions or derived *
 * works of Nmap.  This list is not exclusive, but is meant to clarify our *
 * interpretation of derived works with some common examples.  Our         *
 * interpretation applies only to Nmap--we don't speak for other people's  *
 * GPL works.                                                              *
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
 * listed in the included COPYING.OpenSSL file, and distribute linked      *
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
 * distribution.  By sending these changes to Fyodor or one of the         *
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
 * General Public License v2.0 for more details at                         *
 * http://www.gnu.org/licenses/gpl-2.0.html , or in the COPYING file       *
 * included with Nmap.                                                     *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */

#ifndef SERVICE_SCAN_H
#define SERVICE_SCAN_H

#include "nmap.h"
#include "global_structures.h"
#include "portlist.h"

#include <vector>

#ifdef HAVE_PCRE_PCRE_H
# include <pcre/pcre.h>
#else
# include <pcre.h>
#endif

/**********************  DEFINES/ENUMS ***********************************/
#define DEFAULT_SERVICEWAITMS 5000
#define DEFAULT_CONNECT_TIMEOUT 5000
#define DEFAULT_CONNECT_SSL_TIMEOUT 8000  // includes connect() + ssl negotiation
#define SERVICEMATCH_REGEX 1
// #define SERVICEMATCH_STATIC 2 -- no longer supported

/**********************  STRUCTURES  ***********************************/

// This is returned when we find a match
struct MatchDetails {
// Rather the match is a "soft" service only match, where we should
// continue to look for a better match.
  bool isSoft;

  // The service that was matched (Or NULL) zero-terminated.
  const char *serviceName;

  // The product/verson/info for the service that was matched (Or NULL)
  // zero-terminated.
  const char *product;
  const char *version;
  const char *info;

  // More information from a match. Zero-terminated strings or NULL.
  const char *hostname;
  const char *ostype;
  const char *devicetype;
};

/**********************  CLASSES     ***********************************/

class ServiceProbeMatch {
 public:
  ServiceProbeMatch();
  ~ServiceProbeMatch();

// match text from the nmap-service-probes file.  This must be called
// before you try and do anything with this match.  This function
// should be passed the whole line starting with "match" or
// "softmatch" in nmap-service-probes.  The line number that the text
// is provided so that it can be reported in error messages.  This
// function will abort the program if there is a syntax problem.
  void InitMatch(const char *matchtext, int lineno);

  // If the buf (of length buflen) match the regex in this
  // ServiceProbeMatch, returns the details of the match (service
  // name, version number if applicable, and whether this is a "soft"
  // match.  If the buf doesn't match, the serviceName field in the
  // structure will be NULL.  The MatchDetails returned is only valid
  // until the next time this function is called.  The only exception
  // is that the serviceName field can be saved throughought program
  // execution.  If no version matched, that field will be NULL.
  const struct MatchDetails *testMatch(const u8 *buf, int buflen);
// Returns the service name this matches
  const char *getName() { return servicename; }
  // The Line number where this match string was defined.  Returns
  // -1 if unknown.
  int getLineNo() { return deflineno; }
 private:
  int deflineno; // The line number where this match is defined.
  bool isInitialized; // Has InitMatch yet been called?
  char *servicename;
  int matchtype; // SERVICEMATCH_REGEX or SERVICESCAN_STATIC
  char *matchstr; // Regular expression text, or static string
  int matchstrlen; // Because static strings may have embedded NULs
  pcre *regex_compiled;
  pcre_extra *regex_extra;
  bool matchops_ignorecase;
  bool matchops_dotall;
  bool isSoft; // is this a soft match? ("softmatch" keyword in nmap-service-probes)
  // If any of these 3 are non-NULL, a product, version, or template
  // string was given to deduce the application/version info via
  // substring matches.
  char *product_template;
  char *version_template;
  char *info_template;
  // More templates:
  char *hostname_template;
  char *ostype_template;
  char *devicetype_template;
  // The anchor is for SERVICESCAN_STATIC matches.  If the anchor is not -1, the match must
  // start at that zero-indexed position in the response str.
  int matchops_anchor;
// Details to fill out and return for testMatch() calls
  struct MatchDetails MD_return;

  // Use the six version templates and the match data included here
  // to put the version info into the given strings, (as long as the sizes
  // are sufficient).  Returns zero for success.  If no template is available
  // for a string, that string will have zero length after the function
  // call (assuming the corresponding length passed in is at least 1)
  int getVersionStr(const u8 *subject, int subjectlen, int *ovector, 
		  int nummatches, char *product, int productlen,
		  char *version, int versionlen, char *info, int infolen,
                  char *hostname, int hostnamelen, char *ostype, int ostypelen,
                  char *devicetype, int devicetypelen);
};


class ServiceProbe {
 public:
  ServiceProbe();
  ~ServiceProbe();
  const char *getName() { return probename; }
  // Returns true if this is the "null" probe, meaning it sends no probe and
  // only listens for a banner.  Only TCP services have this.
  bool isNullProbe() { return (probestringlen == 0); }
  bool isProbablePort(u16 portno); // Returns true if the portnumber given was listed
                                   // as a port that is commonly identified by this
                                   // probe (e.g. an SMTP probe would commonly identify port 25)
// Amount of time to wait after a connection succeeds (or packet sent) for a responses.
  int totalwaitms;

  // Parses the "probe " line in the nmap-service-probes file.  Pass the rest of the line
  // after "probe ".  The format better be:
  // [TCP|UDP] [probename] "probetext"
  // the lineno is requested because this function will bail with an error
  // (giving the line number) if it fails to parse the string.
  void setProbeDetails(char *pd, int lineno);

  // obtains the probe string (in raw binary form) and the length.  The string will be 
  // NUL-terminated, but there may be other \0 in the string, so the termination is only
  // done for ease of printing ASCII probes in debugging cases.
  const u8 *getProbeString(int *stringlen) { *stringlen = probestringlen; return probestring; }
  void setProbeString(const u8 *ps, int stringlen);

  /* Protocols are IPPROTO_TCP and IPPROTO_UDP */
  u8 getProbeProtocol() { 
    assert(probeprotocol == IPPROTO_TCP || probeprotocol == IPPROTO_UDP); 
    return probeprotocol;  
  }
  void setProbeProtocol(u8 protocol) { probeprotocol = protocol; }

  // Takes a string as given in the 'ports '/'sslports ' line of
  // nmap-service-probes.  Pass in the list from the appropriate
  // line.  For 'sslports', tunnel should be specified as
  // SERVICE_TUNNEL_SSL.  Otherwise use SERVICE_TUNNEL_NONE.  The line
  // number is requested because this function will bail with an error
  // (giving the line number) if it fails to parse the string.  Ports
  // are a comma separated list of ports and ranges
  // (e.g. 53,80,6000-6010).
  void setProbablePorts(enum service_tunnel_type tunnel,
			const char *portstr, int lineno);

  /* Returns true if the passed in port is on the list of probable
     ports for this probe and tunnel type.  Use a tunnel of
     SERVICE_TUNNEL_SSL or SERVICE_TUNNEL_NONE as appropriate */
  bool portIsProbable(enum service_tunnel_type tunnel, u16 portno);
  // Returns true if the passed in service name is among those that can
  // be detected by the matches in this probe;
  bool serviceIsPossible(const char *sname);

  // Takes a string following a Rarity directive in the probes file.
  // The string should contain a single integer between 1 and 9. The
  // default rarity is 5. This function will bail if the string is invalid.
  void setRarity(const char *portstr, int lineno);

  // Simply returns the rarity of this probe
  const int getRarity() { return rarity; }

  // Takes a match line in a probe description and adds it to the
  // list of matches for this probe.  This function should be passed
  // the whole line starting with "match" or "softmatch" in
  // nmap-service-probes.  The line number is requested because this
  // function will bail with an error (giving the line number) if it
  // fails to parse the string.
  void addMatch(const char *match, int lineno);

  // If the buf (of length buflen) matches one of the regexes in this
  // ServiceProbe, returns the details of the match (service name,
  // version number if applicable, and whether this is a "soft" match.
  // If the buf doesn't match, the serviceName field in the structure
  // will be NULL.  The MatchDetails returned is only valid until the
  // next time this function is called.  The only exception is that the
  // serviceName field can be saved throughought program execution.  If
  // no version matched, that field will be NULL. This function may
  // return NULL if there are no match lines at all in this probe.
  const struct MatchDetails *testMatch(const u8 *buf, int buflen);

  char *fallbackStr;
  ServiceProbe *fallbacks[MAXFALLBACKS+1];

 private:
  void setPortVector(std::vector<u16> *portv, const char *portstr, 
				 int lineno);
  char *probename;

  u8 *probestring;
  int probestringlen;
  std::vector<u16> probableports;
  std::vector<u16> probablesslports;
  int rarity;
  std::vector<const char *> detectedServices;
  int probeprotocol;
  std::vector<ServiceProbeMatch *> matches; // first-ever use of STL in Nmap!
};

class AllProbes {
public:
  AllProbes();
  ~AllProbes();
  // Tries to find the probe in this AllProbes class which have the
  // given name and protocol.  It can return the NULL probe.
  ServiceProbe *getProbeByName(const char *name, int proto);
  std::vector<ServiceProbe *> probes; // All the probes except nullProbe
  ServiceProbe *nullProbe; // No probe text - just waiting for banner

  // Before this function is called, the fallbacks exist as unparsed
  // comma-separated strings in the fallbackStr field of each probe.
  // This function fills out the fallbacks array in each probe with
  // an ordered list of pointers to which probes to try. This is both for
  // efficiency and to deal with odd cases like the NULL probe and falling
  // back to probes later in the file. This function also free()s all the
  // fallbackStrs.
  void compileFallbacks();

  int isExcluded(unsigned short port, int proto);
  bool excluded_seen;
  struct scan_lists excludedports;
  
  static AllProbes *service_scan_init(void);
  static void service_scan_free(void);
protected:
  static AllProbes *global_AP;
};

/**********************  PROTOTYPES  ***********************************/

/* Parses the given nmap-service-probes file into the AP class Must
   NOT be made static because I have external maintenance tools
   (servicematch) which use this */
void parse_nmap_service_probe_file(AllProbes *AP, char *filename);

/* Execute a service fingerprinting scan against all open ports of the
   Targets specified. */
int service_scan(std::vector<Target *> &Targets);

#endif /* SERVICE_SCAN_H */

