
/***************************************************************************
 * service_scan.h -- Routines used for service fingerprinting to determine *
 * what application-level protocol is listening on a given port            *
 * (e.g. snmp, http, ftp, smtp, etc.)                                      *
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

#ifndef SERVICE_SCAN_H
#define SERVICE_SCAN_H

#include "portlist.h"
#include "scan_lists.h"

#include <vector>

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#undef NDEBUG
#include <assert.h>

/**********************  DEFINES/ENUMS ***********************************/
#define DEFAULT_SERVICEWAITMS 5000
#define DEFAULT_TCPWRAPPEDMS 2000   // connections closed after this timeout are not considered "tcpwrapped"
#define DEFAULT_CONNECT_TIMEOUT 5000
#define DEFAULT_CONNECT_SSL_TIMEOUT 8000  // includes connect() + ssl negotiation
#define MAXFALLBACKS 20 /* How many comma separated fallbacks are allowed in the service-probes file? */

/**********************  STRUCTURES  ***********************************/

// This is returned when we find a match
struct MatchDetails {
// Rather the match is a "soft" service only match, where we should
// continue to look for a better match.
  bool isSoft;

  // The service that was matched (Or NULL) zero-terminated.
  const char *serviceName;

  // The line number of this match in nmap-service-probes.
  int lineno;

  // The product/version/info for the service that was matched (Or NULL)
  // zero-terminated.
  const char *product;
  const char *version;
  const char *info;

  // More information from a match. Zero-terminated strings or NULL.
  const char *hostname;
  const char *ostype;
  const char *devicetype;

  // CPE identifiers for application, OS, and hardware type.
  const char *cpe_a;
  const char *cpe_o;
  const char *cpe_h;
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
  // is that the serviceName field can be saved throughout program
  // execution.  If no version matched, that field will be NULL.
  const struct MatchDetails *testMatch(const u8 *buf, int buflen);
// Returns the service name this matches
  const char *getName() const { return servicename; }
  // The Line number where this match string was defined.  Returns
  // -1 if unknown.
  int getLineNo() const { return deflineno; }
 private:
  int deflineno; // The line number where this match is defined.
  bool isInitialized; // Has InitMatch yet been called?
  const char *servicename;
  char *matchstr; // Regular expression text
  pcre2_code *regex_compiled;
  pcre2_match_data *match_data;
  pcre2_match_context *match_context;
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
  std::vector<char *> cpe_templates;
// Details to fill out and return for testMatch() calls
  struct MatchDetails MD_return;

  // Use the six version templates and the match data included here
  // to put the version info into the given strings, (as long as the sizes
  // are sufficient).  Returns zero for success.  If no template is available
  // for a string, that string will have zero length after the function
  // call (assuming the corresponding length passed in is at least 1)
  int getVersionStr(const u8 *subject, size_t subjectlen,
                  char *product, size_t productlen,
                  char *version, size_t versionlen, char *info, size_t infolen,
                  char *hostname, size_t hostnamelen, char *ostype, size_t ostypelen,
                  char *devicetype, size_t devicetypelen,
                  char *cpe_a, size_t cpe_alen,
                  char *cpe_h, size_t cpe_hlen,
                  char *cpe_o, size_t cpe_olen) const;
};


class ServiceProbe {
 public:
  ServiceProbe();
  ~ServiceProbe();
  const char *getName() const { return probename; }
  // Returns true if this is the "null" probe, meaning it sends no probe and
  // only listens for a banner.  Only TCP services have this.
  bool isNullProbe() const { return (probestringlen == 0); }
// Amount of time to wait after a connection succeeds (or packet sent) for a responses.
  int totalwaitms;
  // If the connection succeeds but closes before this time, it's tcpwrapped.
  int tcpwrappedms;

  // Parses the "probe " line in the nmap-service-probes file.  Pass the rest of the line
  // after "probe ".  The format better be:
  // [TCP|UDP] [probename] "probetext"
  // the lineno is requested because this function will bail with an error
  // (giving the line number) if it fails to parse the string.
  void setProbeDetails(char *pd, int lineno);

  // obtains the probe string (in raw binary form) and the length.  The string will be
  // NUL-terminated, but there may be other \0 in the string, so the termination is only
  // done for ease of printing ASCII probes in debugging cases.
  const u8 *getProbeString(int *stringlen) const { *stringlen = probestringlen; return probestring; }
  void setProbeString(const u8 *ps, int stringlen);

  /* Protocols are IPPROTO_TCP and IPPROTO_UDP */
  u8 getProbeProtocol() const {
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
  bool portIsProbable(enum service_tunnel_type tunnel, u16 portno) const;
  // Returns true if the passed in service name is among those that can
  // be detected by the matches in this probe;
  bool serviceIsPossible(const char *sname) const;

  // Takes a string following a Rarity directive in the probes file.
  // The string should contain a single integer between 1 and 9. The
  // default rarity is 5. This function will bail if the string is invalid.
  void setRarity(const char *portstr, int lineno);

  // Simply returns the rarity of this probe
  int getRarity() const { return rarity; }

  // Takes a match line in a probe description and adds it to the
  // list of matches for this probe.  This function should be passed
  // the whole line starting with "match" or "softmatch" in
  // nmap-service-probes.  The line number is requested because this
  // function will bail with an error (giving the line number) if it
  // fails to parse the string.
  void addMatch(const char *match, int lineno);

  // If the buf (of length buflen) matches one of the regexes in this
  // ServiceProbe, returns the details of the nth match (service name,
  // version number if applicable, and whether this is a "soft" match.
  // If the buf doesn't match, the serviceName field in the structure
  // will be NULL.  The MatchDetails returned is only valid until the
  // next time this function is called.  The only exception is that the
  // serviceName field can be saved throughout program execution.  If
  // no version matched, that field will be NULL. This function may
  // return NULL if there are no match lines at all in this probe.
  const struct MatchDetails *testMatch(const u8 *buf, int buflen, int n);

  char *fallbackStr;
  ServiceProbe *fallbacks[MAXFALLBACKS+1];
  std::vector<u16>::const_iterator probablePortsBegin() const {return probableports.begin();}
  std::vector<u16>::const_iterator probablePortsEnd() const {return probableports.end();}
  bool notForPayload;

 private:
  void setPortVector(std::vector<u16> *portv, const char *portstr,
                                 int lineno);
  const char *probename;

  const u8 *probestring;
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
  // given name and protocol. If no match is found for the requested
  // protocol it will try to find matches on any protocol.
  // It can return the NULL probe.
  ServiceProbe *getProbeByName(const char *name, int proto) const;
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

  int isExcluded(unsigned short port, int proto) const;
  bool excluded_seen;
  struct scan_lists excludedports;

  static AllProbes *service_scan_init(void);
  static void service_scan_free(void);
  static int check_excluded_port(unsigned short port, int proto);
protected:
  static AllProbes *global_AP;
};

/**********************  PROTOTYPES  ***********************************/

/* Parses the given nmap-service-probes file into the AP class Must
   NOT be made static because I have external maintenance tools
   (servicematch) which use this */
void parse_nmap_service_probe_file(AllProbes *AP, const char *filename);

/* Execute a service fingerprinting scan against all open ports of the
   Targets specified. */
int service_scan(std::vector<Target *> &Targets);

#endif /* SERVICE_SCAN_H */

