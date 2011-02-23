
/***************************************************************************
 * service_scan.cc -- Routines used for service fingerprinting to determine *
 * what application-level protocol is listening on a given port            *
 * (e.g. snmp, http, ftp, smtp, etc.)                                      *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2011 Insecure.Com LLC. Nmap is    *
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
 * to nmap-dev@insecure.org for possible incorporation into the main       *
 * distribution.  By sending these changes to Fyodor or one of the         *
 * Insecure.Org development mailing lists, it is assumed that you are      *
 * offering the Nmap Project (Insecure.Com LLC) the unlimited,             *
 * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
 * will always be available Open Source, but this is important because the *
 * inability to relicense code has caused devastating problems for other   *
 * Free Software projects (such as KDE and NASM).  We also occasionally    *
 * relicense the code to third parties as discussed above.  If you wish to *
 * specify special license conditions of your contributions, just say so   *
 * when you send them.                                                     *
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


#include "service_scan.h"
#include "timing.h"
#include "NmapOps.h"
#include "nsock.h"
#include "Target.h"
#include "utils.h"
#include "protocols.h"

#include "nmap_tty.h"

#if HAVE_OPENSSL
/* OpenSSL 1.0.0 needs _WINSOCKAPI_ to be defined, otherwise it loads
   <windows.h> (through openssl/dtls1.h), which is incompatible with the
   <winsock2.h> that we use. (It creates errors with the redefinition of struct
   timeval, for example.) _WINSOCKAPI_ should be defined by our inclusion of
   <winsock2.h>, but it appears to be undefined somewhere, possibly in
   libpcap. */
#define _WINSOCKAPI_
#include <openssl/ssl.h>
#endif

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include <algorithm>
#include <list>

/* Workaround for lack of namespace std on HP-UX 11.00 */
namespace std {};
using namespace std;

extern NmapOps o;

// Details on a particular service (open port) we are trying to match
class ServiceNFO {
public:
  ServiceNFO(AllProbes *AP);
  ~ServiceNFO();

  // If a service response to a given probeName, this function adds
  // the response the the fingerprint for that service.  The
  // fingerprint can be printed when nothing matches the service.  You
  // can obtain the fingerprint (if any) via getServiceFingerprint();
  void addToServiceFingerprint(const char *probeName, const u8 *resp, 
			       int resplen);

  // Get the service fingerprint.  It is NULL if there is none, such
  // as if there was a match before any other probes were finished (or
  // if no probes gave back data).  Note that this is plain
  // NUL-terminated ASCII data, although the length is optionally
  // available anyway.  This function terminates the service fingerprint
  // with a semi-colon
  const char *getServiceFingerprint(int *flen);

  // Note that the next 2 members are for convenience and are not destroyed w/the ServiceNFO
  Target *target; // the port belongs to this target host
  // if a match is found, it is placed here.  Otherwise NULL
  const char *probe_matched;
  // If a match is found, any product/version/info/hostname/ostype/devicetype
  // is placed in these 6 strings.  Otherwise the string will be 0 length.
  char product_matched[80];
  char version_matched[80];
  char extrainfo_matched[256];
  char hostname_matched[80];
  char ostype_matched[32];
  char devicetype_matched[32];
  enum service_tunnel_type tunnel; /* SERVICE_TUNNEL_NONE, SERVICE_TUNNEL_SSL */
  // This stores our SSL session id, which will help speed up subsequent
  // SSL connections.  It's overwritten each time.  void* is used so we don't
  // need to #ifdef HAVE_OPENSSL all over.  We'll cast later as needed.
  void *ssl_session;
  // if a match was found (see above), this tells whether it was a "soft"
  // or hard match.  It is always false if no match has been found.
  bool softMatchFound;
  // most recent probe executed (or in progress).  If there has been a match 
  // (probe_matched != NULL), this will be the corresponding ServiceProbe.
  ServiceProbe *currentProbe();
  // computes the next probe to test, and ALSO CHANGES currentProbe() to
  // that!  If newresp is true, the old response info will be lost and
  // invalidated.  Otherwise it remains as if it had been received by
  // the current probe (useful after a NULL probe).
  ServiceProbe *nextProbe(bool newresp);
  // Resets the probes back to the first one. One case where this is useful is
  // when SSL is detected -- we redo all probes through SSL.  If freeFP, any
  // service fingerprint is freed too.
  void resetProbes(bool freefp);
  // Number of milliseconds left to complete the present probe, or 0 if
  // the probe is already expired.  Timeval can omitted, it is just there 
  // as an optimization in case you have it handy.
  int currentprobe_timemsleft(const struct timeval *now = NULL);
  enum serviceprobestate probe_state; // defined in portlist.h
  nsock_iod niod; // The IO Descriptor being used in this probe (or NULL)
  u16 portno; // in host byte order
  u8 proto; // IPPROTO_TCP or IPPROTO_UDP
  // The time that the current probe was executed (meaning TCP connection
  // made or first UDP packet sent
  struct timeval currentprobe_exec_time;
  // Append newly-received data to the current response string (if any)
  void appendtocurrentproberesponse(const u8 *respstr, int respstrlen);
  // Get the full current response string.  Note that this pointer is 
  // INVALIDATED if you call appendtocurrentproberesponse() or nextProbe()
  u8 *getcurrentproberesponse(int *respstrlen);
  AllProbes *AP;
          
private:
  // Adds a character to servicefp.  Takes care of word wrapping if
  // necessary at the given (wrapat) column.  Chars will only be
  // written if there is enough space.  Otherwise it exits.
  void addServiceChar(char c, int wrapat);
  // Like addServiceChar, but for a whole zero-terminated string
  void addServiceString(const char *s, int wrapat);
  vector<ServiceProbe *>::iterator current_probe;
  u8 *currentresp;
  int currentresplen;
  char *servicefp;
  int servicefplen;
  int servicefpalloc;
};

// This holds the service information for a group of Targets being service scanned.
class ServiceGroup {
public:
  ServiceGroup(vector<Target *> &Targets, AllProbes *AP);
  ~ServiceGroup();
  list<ServiceNFO *> services_finished; // Services finished (discovered or not)
  list<ServiceNFO *> services_in_progress; // Services currently being probed
  list<ServiceNFO *> services_remaining; // Probes not started yet
  unsigned int ideal_parallelism; // Max (and desired) number of probes out at once.
  ScanProgressMeter *SPM;
  int num_hosts_timedout; // # of hosts timed out during (or before) scan
};

#define SUBSTARGS_MAX_ARGS 5
#define SUBSTARGS_STRLEN 128
#define SUBSTARGS_ARGTYPE_NONE 0
#define SUBSTARGS_ARGTYPE_STRING 1
#define SUBSTARGS_ARGTYPE_INT 2
struct substargs {
  int num_args; // Total number of arguments found
  char str_args[SUBSTARGS_MAX_ARGS][SUBSTARGS_STRLEN];
  // This is the length of each string arg, since they can contain zeros.
  // The str_args[] are zero-terminated for convenience in the cases where
  // you know they won't contain zero.
  int str_args_len[SUBSTARGS_MAX_ARGS]; 
  int int_args[SUBSTARGS_MAX_ARGS];
  // The type of each argument -- see #define's above.
  int arg_types[SUBSTARGS_MAX_ARGS];
};

/********************   PROTOTYPES *******************/
static void servicescan_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
static void servicescan_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
static void servicescan_connect_handler(nsock_pool nsp, nsock_event nse, void *mydata);
static void end_svcprobe(nsock_pool nsp, enum serviceprobestate probe_state, ServiceGroup *SG, ServiceNFO *svc, nsock_iod nsi);

ServiceProbeMatch::ServiceProbeMatch() {
  deflineno = -1;
  servicename = NULL;
  matchstr = NULL;
  product_template = version_template = info_template = NULL;
  hostname_template = ostype_template = devicetype_template = NULL;
  regex_compiled = NULL;
  regex_extra = NULL;
  isInitialized = false;
  matchops_ignorecase = false;
  matchops_dotall = false;
  isSoft = false;
}

ServiceProbeMatch::~ServiceProbeMatch() {
  if (!isInitialized) return;
  if (servicename) free(servicename);
  if (matchstr) free(matchstr);
  if (product_template) free(product_template);
  if (version_template) free(version_template);
  if (info_template) free(info_template);
  if (hostname_template) free(hostname_template);
  if (ostype_template) free(ostype_template);
  if (devicetype_template) free(devicetype_template);
  matchstrlen = 0;
  if (regex_compiled) pcre_free(regex_compiled);
  if (regex_extra) pcre_free(regex_extra);
  isInitialized = false;
  matchops_anchor = -1;
}

// match text from the nmap-service-probes file.  This must be called
// before you try and do anything with this match.  This function
// should be passed the whole line starting with "match" or
// "softmatch" in nmap-service-probes.  The line number that the text
// is provided so that it can be reported in error messages.  This
// function will abort the program if there is a syntax problem.
void ServiceProbeMatch::InitMatch(const char *matchtext, int lineno) {
  const char *p;
  char *tmptemplate;
  char delimchar, modechar;
  int pcre_compile_ops = 0;
  const char *pcre_errptr = NULL;
  int pcre_erroffset = 0;
  unsigned int tmpbuflen = 0;
  char **curr_tmp = NULL;

  if (isInitialized) fatal("Sorry ... %s does not yet support reinitializion", __func__);
  if (!matchtext || !*matchtext) 
    fatal("%s: no matchtext passed in (line %d of nmap-service-probes)", __func__, lineno);
  isInitialized = true;

  deflineno = lineno;
  while(isspace((int) (unsigned char) *matchtext)) matchtext++;

  // first we find whether this is a "soft" or normal match
  if (strncmp(matchtext, "softmatch ", 10) == 0) {
    isSoft = true;
    matchtext += 10;
  } else if (strncmp(matchtext, "match ", 6) == 0) {
    isSoft = false;
    matchtext += 6;
  } else 
    fatal("%s: parse error on line %d of nmap-service-probes - must begin with \"match\" or \"softmatch\"", __func__, lineno);

  // next comes the service name
  p = strchr(matchtext, ' ');
  if (!p) fatal("%s: parse error on line %d of nmap-service-probes: could not find service name", __func__, lineno);

  servicename = (char *) safe_malloc(p - matchtext + 1);
  memcpy(servicename, matchtext, p - matchtext);
  servicename[p - matchtext]  = '\0';

  // The next part is a perl style regular expression specifier, like:
  // m/^220 .*smtp/i Where 'm' means a normal regular expressions is
  // used, the char after m can be anything (within reason, slash in
  // this case) and tells us what delieates the end of the regex.
  // After the delineating character are any single-character
  // options. ('i' means "case insensitive", 's' means that . matches
  // newlines (both are just as in perl)
  matchtext = p;
  while(isspace((int) (unsigned char) *matchtext)) matchtext++;
  if (*matchtext == 'm') {
    if (!*(matchtext+1))
      fatal("%s: parse error on line %d of nmap-service-probes: matchtext must begin with 'm'", __func__, lineno);
    matchtype = SERVICEMATCH_REGEX;
    delimchar = *(++matchtext);
    ++matchtext;
    // find the end of the regex
    p = strchr(matchtext, delimchar);
    if (!p) fatal("%s: parse error on line %d of nmap-service-probes: could not find end delimiter for regex", __func__, lineno);
    matchstrlen = p - matchtext;
    matchstr = (char *) safe_malloc(matchstrlen + 1);
    memcpy(matchstr, matchtext, matchstrlen);
    matchstr[matchstrlen]  = '\0';
    
    matchtext = p + 1; // skip past the delim
    // any options?
    while(*matchtext && !isspace((int) (unsigned char) *matchtext)) {
      if (*matchtext == 'i')
	matchops_ignorecase = true;
      else if (*matchtext == 's')
	matchops_dotall = true;
      else fatal("%s: illegal regexp option on line %d of nmap-service-probes", __func__, lineno);
      matchtext++;
    }

    // Next we compile and study the regular expression to match
    if (matchops_ignorecase)
      pcre_compile_ops |= PCRE_CASELESS;

    if (matchops_dotall)
      pcre_compile_ops |= PCRE_DOTALL;
    
    regex_compiled = pcre_compile(matchstr, pcre_compile_ops, &pcre_errptr, 
				     &pcre_erroffset, NULL);
    
    if (regex_compiled == NULL)
      fatal("%s: illegal regexp on line %d of nmap-service-probes (at regexp offset %d): %s\n", __func__, lineno, pcre_erroffset, pcre_errptr);
    
    
    // Now study the regexp for greater efficiency
    regex_extra = pcre_study(regex_compiled, 0, &pcre_errptr);
    if (pcre_errptr != NULL)
      fatal("%s: failed to pcre_study regexp on line %d of nmap-service-probes: %s\n", __func__, lineno, pcre_errptr);
  } else {
    /* Invalid matchtext */
    fatal("%s: parse error on line %d of nmap-service-probes: match string must begin with 'm'", __func__, lineno);
  }

  /* OK! Now we look for any templates of the form ?/.../
   * where ? is either p, v, i, h, o, or d. / is any
   * delimiter character and ... is a template */

  while(1) {
  while(isspace((int) (unsigned char) *matchtext)) matchtext++;
    if (*matchtext == '\0' || *matchtext == '\r' || *matchtext == '\n') break;

    modechar = *(matchtext++);
    if (*matchtext == 0 || *matchtext == '\r' || *matchtext == '\n')
      fatal("%s: parse error on line %d of nmap-service-probes", __func__, lineno);

    delimchar = *(matchtext++);

    p = strchr(matchtext, delimchar);
    if (!p) fatal("%s: parse error on line %d of nmap-service-probes", __func__, lineno);

    tmptemplate = NULL;
    tmpbuflen = p - matchtext;
    if (tmpbuflen > 0) {
      tmptemplate = (char *) safe_malloc(tmpbuflen + 1);
      memcpy(tmptemplate, matchtext, tmpbuflen);
      tmptemplate[tmpbuflen] = '\0';
    }

    switch(modechar){
    case 'p': curr_tmp = &product_template; break;
    case 'v': curr_tmp = &version_template; break;
    case 'i': curr_tmp = &info_template; break;
    case 'h': curr_tmp = &hostname_template; break;
    case 'o': curr_tmp = &ostype_template; break;
    case 'd': curr_tmp = &devicetype_template; break;
    default:
    	fatal("%s: Unknown template specifier '%c' on line %d of nmap-service-probes", __func__, modechar, lineno);
    }
    if(*curr_tmp){
      if(o.debugging)
        error("WARNING: Template \"%c/%s/\" replaced with \"%c/%s/\" on line %d of nmap-service-probes",
        	modechar,
    	  	*curr_tmp,
        	modechar,
    	  	tmptemplate,
    	  	lineno);
    	free(*curr_tmp);
      }
    *curr_tmp = tmptemplate;

    matchtext = p + 1;
  }

  isInitialized = 1;
}

  // If the buf (of length buflen) match the regex in this
  // ServiceProbeMatch, returns the details of the match (service
  // name, version number if applicable, and whether this is a "soft"
  // match.  If the buf doesn't match, the serviceName field in the
  // structure will be NULL.  The MatchDetails sructure returned is
  // only valid until the next time this function is called. The only
  // exception is that the serviceName field can be saved throughought
  // program execution.  If no version matched, that field will be
  // NULL.
const struct MatchDetails *ServiceProbeMatch::testMatch(const u8 *buf, int buflen) {
  int rc;
  int i;
  static char product[80];
  static char version[80];
  static char info[256];  /* We will truncate with ... later */
  static char hostname[80];
  static char ostype[32];
  static char devicetype[32];
  char *bufc = (char *) buf;
  int ovector[150]; // allows 50 substring matches (including the overall match)
  assert(isInitialized);

  assert (matchtype == SERVICEMATCH_REGEX);

  // Clear out the output struct
  memset(&MD_return, 0, sizeof(MD_return));
  MD_return.isSoft = isSoft;

  rc = pcre_exec(regex_compiled, regex_extra, bufc, buflen, 0, 0, ovector, sizeof(ovector) / sizeof(*ovector));
  if (rc < 0) {
#ifdef PCRE_ERROR_MATCHLIMIT  // earlier PCRE versions lack this
    if (rc == PCRE_ERROR_MATCHLIMIT) {
      if (o.debugging || o.verbose > 1) 
	error("Warning: Hit PCRE_ERROR_MATCHLIMIT when probing for service %s with the regex '%s'", servicename, matchstr);
    } else
#endif // PCRE_ERROR_MATCHLIMIT
      if (rc != PCRE_ERROR_NOMATCH) {
	fatal("Unexpected PCRE error (%d) when probing for service %s with the regex '%s'", rc, servicename, matchstr);
      }
  } else {
    // Yeah!  Match apparently succeeded.
    // Now lets get the version number if available
    i = getVersionStr(buf, buflen, ovector, rc, product, sizeof(product), version, sizeof(version), info, sizeof(info),
                      hostname, sizeof(hostname), ostype, sizeof(ostype), devicetype, sizeof(devicetype));    
    if (*product) MD_return.product = product;
    if (*version) MD_return.version = version;
    if (*info) MD_return.info = info;
    if (*hostname) MD_return.hostname = hostname;
    if (*ostype) MD_return.ostype = ostype;
    if (*devicetype) MD_return.devicetype = devicetype;
  
    MD_return.serviceName = servicename;
    MD_return.lineno = getLineNo();
  }

  return &MD_return;
}

// This simple function parses arguments out of a string.  The string
// starts with the first argument.  Each argument can be a string or
// an integer.  Strings must be enclosed in double quotes ("").  Most
// standard C-style escapes are supported.  If this is successful, the
// number of args found is returned, args is filled appropriately, and
// args_end (if non-null) is set to the character after the closing
// ')'.  Otherwise we return -1 and the values of args and args_end
// are undefined.
static int getsubstcommandargs(struct substargs *args, char *args_start, 
			char **args_end) {
  char *p;
  unsigned int len;
  if (!args || !args_start) return -1;

  memset(args, 0, sizeof(*args));

  while(*args_start && *args_start != ')') {
    // Find the next argument.
    while(isspace((int) (unsigned char) *args_start)) args_start++;
    if (*args_start == ')')
      break;
    else if (*args_start == '"') {
      // OK - it is a string
      // Do we have space for another arg?
      if (args->num_args == SUBSTARGS_MAX_ARGS)
	return -1;
      do {
	args_start++;
	if (*args_start == '"' && (*(args_start - 1) != '\\' || *(args_start - 2) == '\\'))
	  break;
	len = args->str_args_len[args->num_args];
	if (len >= SUBSTARGS_STRLEN - 1)
	  return -1;
	args->str_args[args->num_args][len] = *args_start;
	args->str_args_len[args->num_args]++;
      } while(*args_start);
      len = args->str_args_len[args->num_args];
      args->str_args[args->num_args][len] = '\0';
      // Now handle escaped characters and such
      if (!cstring_unescape(args->str_args[args->num_args], &len))
	return -1;
      args->str_args_len[args->num_args] = len;
      args->arg_types[args->num_args] = SUBSTARGS_ARGTYPE_STRING;
      args->num_args++;
      args_start++;
      args_start = strpbrk(args_start, ",)");
      if (!args_start) return -1;
      if (*args_start == ',') args_start++;
    } else {
      // Must be an integer argument
      args->int_args[args->num_args] = (int) strtol(args_start, &p, 0);
      if (p <= args_start) return -1;
      args_start = p;
      args->arg_types[args->num_args] = SUBSTARGS_ARGTYPE_INT;
      args->num_args++;
      args_start = strpbrk(args_start, ",)");
      if (!args_start) return -1;
      if (*args_start == ',') args_start++;
    }
  }

  if (*args_start == ')') args_start++;
  if (args_end) *args_end = args_start;
  return args->num_args;
}

// This function does the actual substitution of a placeholder like $2
// or $P(4) into the given buffer.  It returns the number of chars
// written, or -1 if it fails.  tmplvar is a template variable, such
// as "$P(2)".  We determine the appropriate string representing that,
// and place it in newstr (as long as it doesn't exceed newstrlen).
// We then set *tmplvarend to the character after the
// variable. subject, subjectlen, ovector, and nummatches mean the
// same as in dotmplsubst().
static int substvar(char *tmplvar, char **tmplvarend, char *newstr, 
	     int newstrlen, const u8 *subject, int subjectlen, int *ovector,
	     int nummatches) {
  char substcommand[16];
  char *p = NULL;
  char *p_end;
  int len;
  int subnum = 0;
  int offstart, offend;
  int byteswritten = 0; // for return val
  int rc;
  int i;
  struct substargs command_args;
  // skip the '$'
  if (*tmplvar != '$') return -1;
  tmplvar++;

  if (!isdigit((int) (unsigned char) *tmplvar)) {
    /* This is a command like $P(1). */
    p = strchr(tmplvar, '(');
    if (!p) return -1;
    len = p - tmplvar;
    if (!len || len >= (int) sizeof(substcommand))
      return -1;
    memcpy(substcommand, tmplvar, len);
    substcommand[len] = '\0';
    tmplvar = p+1;
    // Now we grab the arguments.
    rc = getsubstcommandargs(&command_args, tmplvar, &p_end);
    if (rc <= 0) return -1;
    tmplvar = p_end;
  } else {
    /* This is a placeholder like $2. */
    substcommand[0] = '\0';
    subnum = *tmplvar - '0';
    tmplvar++;
  }

  if (tmplvarend) *tmplvarend = tmplvar;

  if (!*substcommand) {
    /* Handler for a placeholder like $2. */
    if (subnum > 9 || subnum <= 0) return -1;
    if (subnum >= nummatches) return -1;
    offstart = ovector[subnum * 2];
    offend = ovector[subnum * 2 + 1];
    assert(offstart >= 0 && offstart < subjectlen);
    assert(offend >= 0 && offend <= subjectlen);
    len = offend - offstart;
    // A plain-jane copy
    if (newstrlen <= len - 1)
      return -1;
    memcpy(newstr, subject + offstart, len);
    byteswritten = len;
  } else if (strcmp(substcommand, "P") == 0) {
    if (command_args.num_args != 1 ||
        command_args.arg_types[0] != SUBSTARGS_ARGTYPE_INT) {
      return -1;
    }
    subnum = command_args.int_args[0];
    if (subnum > 9 || subnum <= 0) return -1;
    if (subnum >= nummatches) return -1;
    offstart = ovector[subnum * 2];
    offend = ovector[subnum * 2 + 1];
    assert(offstart >= 0 && offstart < subjectlen);
    assert(offend >= 0 && offend <= subjectlen);
    // This filter only includes printable characters.  It is particularly
    // useful for collapsing unicode text that looks like 
    // "W\0O\0R\0K\0G\0R\0O\0U\0P\0"
    for(i=offstart; i < offend; i++)
      if (isprint((int) subject[i])) {
	if (byteswritten >= newstrlen - 1)
	  return -1;
	newstr[byteswritten++] = subject[i];
      }
  } else if (strcmp(substcommand, "SUBST") == 0) {
    char *findstr, *replstr;
    int findstrlen, replstrlen;
    if (command_args.num_args != 3 ||
        command_args.arg_types[0] != SUBSTARGS_ARGTYPE_INT ||
        command_args.arg_types[1] != SUBSTARGS_ARGTYPE_STRING ||
	command_args.arg_types[2] != SUBSTARGS_ARGTYPE_STRING) {
      return -1;
    }
    subnum = command_args.int_args[0];
    if (subnum > 9 || subnum <= 0) return -1;
    if (subnum >= nummatches) return -1;
    offstart = ovector[subnum * 2];
    offend = ovector[subnum * 2 + 1];
    assert(offstart >= 0 && offstart < subjectlen);
    assert(offend >= 0 && offend <= subjectlen);
    findstr = command_args.str_args[1];
    findstrlen = command_args.str_args_len[1];
    replstr = command_args.str_args[2];
    replstrlen = command_args.str_args_len[2];
    for(i=offstart; i < offend; ) {
      if (byteswritten >= newstrlen - 1)
	return -1;
      if (offend - i < findstrlen)
	newstr[byteswritten++] = subject[i++]; // No room for match
      else if (memcmp(subject + i, findstr, findstrlen) != 0)
	newstr[byteswritten++] = subject[i++]; // no match
      else {
	// The find string was found, copy it to newstring
	if (newstrlen - 1 - byteswritten < replstrlen)
	  return -1;
	memcpy(newstr + byteswritten, replstr, replstrlen);
	byteswritten += replstrlen;
	i += findstrlen;
      }
    }
  } else return -1; // Unknown command

  if (byteswritten >= newstrlen) return -1;
  newstr[byteswritten] = '\0';
  return byteswritten;
}



// This function takes a template string (tmpl) which can have
// placeholders in it such as $1 for substring matches in a regexp
// that was run against subject, and subjectlen, with the 'nummatches'
// matches in ovector.  The NUL-terminated newly composted string is
// placed into 'newstr', as long as it doesn't exceed 'newstrlen'
// bytes.  Trailing whitespace and commas are removed.  Returns zero for success
static int dotmplsubst(const u8 *subject, int subjectlen, 
		       int *ovector, int nummatches, char *tmpl, char *newstr,
		       int newstrlen) {
  int newlen;
  char *srcstart=tmpl, *srcend;
  char *dst = newstr;
  char *newstrend = newstr + newstrlen; // Right after the final char

  if (!newstr || !tmpl) return -1;
  if (newstrlen < 3) return -1; // fuck this!
  
  while(*srcstart) {
    // First do any literal text before '$'
    srcend = strchr(srcstart, '$');
    if (!srcend) {
      // Only literal text remain!
      while(*srcstart) {
	if (dst >= newstrend - 1)
	  return -1;
	*dst++ = *srcstart++;
      }
      *dst = '\0';
      while (--dst >= newstr) {
	if (isspace((int) (unsigned char) *dst) || *dst == ',') 
	  *dst = '\0';
	else break;
      }
      return 0;
    } else {
      // Copy the literal text up to the '$', then do the substitution
      newlen = srcend - srcstart;
      if (newlen > 0) {
	if (newstrend - dst <= newlen - 1)
	  return -1;
	memcpy(dst, srcstart, newlen);
	dst += newlen;
      }
      srcstart = srcend;
      newlen = substvar(srcstart, &srcend, dst, newstrend - dst, subject, 
		    subjectlen, ovector, nummatches);
      if (newlen == -1) return -1;
      dst += newlen;
      srcstart = srcend;
    }
  }

  if (dst >= newstrend - 1)
    return -1;
  *dst = '\0';
  while (--dst >= newstr) {
    if (isspace((int) (unsigned char) *dst) || *dst == ',') 
      *dst = '\0';
    else break;
  }
  return 0;

}


// Use the six version templates and the match data included here
// to put the version info into the given strings, (as long as the sizes
// are sufficient).  Returns zero for success.  If no template is available
// for a string, that string will have zero length after the function
// call (assuming the corresponding length passed in is at least 1)

int ServiceProbeMatch::getVersionStr(const u8 *subject, int subjectlen, 
	    int *ovector, int nummatches, char *product, int productlen,
	    char *version, int versionlen, char *info, int infolen,
                  char *hostname, int hostnamelen, char *ostype, int ostypelen,
                  char *devicetype, int devicetypelen) {

  int rc;
  assert(productlen >= 0 && versionlen >= 0 && infolen >= 0 &&
         hostnamelen >= 0 && ostypelen >= 0 && devicetypelen >= 0);
  
  if (productlen > 0) *product = '\0';
  if (versionlen > 0) *version = '\0';
  if (infolen > 0) *info = '\0';
  if (hostnamelen > 0) *hostname = '\0';
  if (ostypelen > 0) *ostype = '\0';
  if (devicetypelen > 0) *devicetype = '\0';
  int retval = 0;

  // Now lets get this started!  We begin with the product name
  if (product_template) {
    rc = dotmplsubst(subject, subjectlen, ovector, nummatches, product_template, product, productlen);
    if (rc != 0) {
      error("Warning: Servicescan failed to fill product_template (subjectlen: %d, productlen: %d). Capture exceeds length? Match string was line %d: v/%s/%s/%s", subjectlen, productlen, deflineno,
	    (product_template)? product_template : "",
	    (version_template)? version_template : "",
	    (info_template)? info_template : "");
      if (productlen > 0) *product = '\0';
      retval = -1;
    }
  }

  if (version_template) {
    rc = dotmplsubst(subject, subjectlen, ovector, nummatches, version_template, version, versionlen);
    if (rc != 0) {
      error("Warning: Servicescan failed to fill version_template (subjectlen: %d, versionlen: %d). Capture exceeds length? Match string was line %d: v/%s/%s/%s", subjectlen, versionlen, deflineno,
	    (product_template)? product_template : "",
	    (version_template)? version_template : "",
	    (info_template)? info_template : "");
      if (versionlen > 0) *version = '\0';
      retval = -1;
    }
  }

  if (info_template) {
    rc = dotmplsubst(subject, subjectlen, ovector, nummatches, info_template, info, infolen);
    if (rc != 0) {
      error("Warning: Servicescan failed to fill info_template (subjectlen: %d, infolen: %d). Capture exceeds length? Match string was line %d: v/%s/%s/%s", subjectlen, infolen, deflineno,
	    (product_template)? product_template : "",
	    (version_template)? version_template : "",
	    (info_template)? info_template : "");
      if (infolen > 0) *info = '\0';
      retval = -1;
    }
  }
  
  if (hostname_template) {
    rc = dotmplsubst(subject, subjectlen, ovector, nummatches, hostname_template, hostname, hostnamelen);
    if (rc != 0) {
      error("Warning: Servicescan failed to fill hostname_template (subjectlen: %d, hostnamelen: %d). Capture exceeds length? Match string was line %d: h/%s/", subjectlen, hostnamelen, deflineno,
	    (hostname_template)? hostname_template : "");
      if (hostnamelen > 0) *hostname = '\0';
      retval = -1;
    }
  }

  if (ostype_template) {
    rc = dotmplsubst(subject, subjectlen, ovector, nummatches, ostype_template, ostype, ostypelen);
    if (rc != 0) {
      error("Warning: Servicescan failed to fill ostype_template (subjectlen: %d, ostypelen: %d). Capture exceeds length? Match string was line %d: p/%s/", subjectlen, ostypelen, deflineno,
	    (ostype_template)? ostype_template : "");
      if (ostypelen > 0) *ostype = '\0';
      retval = -1;
    }
  }

  if (devicetype_template) {
    rc = dotmplsubst(subject, subjectlen, ovector, nummatches, devicetype_template, devicetype, devicetypelen);
    if (rc != 0) {
      error("Warning: Servicescan failed to fill devicetype_template (subjectlen: %d, devicetypelen: %d). Too long? Match string was line %d: d/%s/", subjectlen, devicetypelen, deflineno,
	    (devicetype_template)? devicetype_template : "");
      if (devicetypelen > 0) *devicetype = '\0';
      retval = -1;
    }
  }
  
  return retval;
}


ServiceProbe::ServiceProbe() {
  int i;
  probename = NULL;
  probestring = NULL;
  totalwaitms = DEFAULT_SERVICEWAITMS;
  probestringlen = 0; probeprotocol = -1;
  // The default rarity level for a probe without a rarity
  // directive - should almost never have to be relied upon.
  rarity = 5;
  fallbackStr = NULL;
  for (i=0; i<MAXFALLBACKS+1; i++) fallbacks[i] = NULL;
}

ServiceProbe::~ServiceProbe() {
  vector<ServiceProbeMatch *>::iterator vi;

  if (probename) free(probename);
  if (probestring) free(probestring);

  for(vi = matches.begin(); vi != matches.end(); vi++) {
    delete *vi;
  }

  if (fallbackStr) free(fallbackStr);
}

  // Parses the "probe " line in the nmap-service-probes file.  Pass the rest of the line
  // after "probe ".  The format better be:
  // [TCP|UDP] [probename] q|probetext|
  // Note that the delimiter (|) of the probetext can be anything (within reason)
  // the lineno is requested because this function will bail with an error
  // (giving the line number) if it fails to parse the string.
void ServiceProbe::setProbeDetails(char *pd, int lineno) {
  char *p;
  unsigned int len;
  char delimiter;

  if (!pd || !*pd)
    fatal("Parse error on line %d of nmap-service-probes: no arguments found!", lineno);

  // First the protocol
  if (strncmp(pd, "TCP ", 4) == 0)
      probeprotocol = IPPROTO_TCP;
  else if (strncmp(pd, "UDP ", 4) == 0)
      probeprotocol = IPPROTO_UDP;
  else fatal("Parse error on line %d of nmap-service-probes: invalid protocol", lineno);
  pd += 4;

  // Next the service name
  if (!isalnum((int) (unsigned char) *pd)) fatal("Parse error on line %d of nmap-service-probes - bad probe name", lineno);
  p = strchr(pd, ' ');
  if (!p) fatal("Parse error on line %d of nmap-service-probes - nothing after probe name", lineno);
  len = p - pd;
  probename = (char *) safe_malloc(len + 1);
  memcpy(probename, pd, len);
  probename[len]  = '\0';

  // Now for the probe itself
  pd = p+1;

  if (*pd != 'q') fatal("Parse error on line %d of nmap-service-probes - probe string must begin with 'q'", lineno);
  delimiter = *(++pd);
  p = strchr(++pd, delimiter);
  if (!p) fatal("Parse error on line %d of nmap-service-probes -- no ending delimiter for probe string", lineno);
  *p = '\0';
  if (!cstring_unescape(pd, &len)) {
    fatal("Parse error on line %d of nmap-service-probes: bad probe string escaping", lineno);
  }
  setProbeString((const u8 *)pd, len);
}

void ServiceProbe::setProbeString(const u8 *ps, int stringlen) {
  if (probestringlen) free(probestring);
  probestringlen = stringlen;
  if (stringlen > 0) {
    probestring = (u8 *) safe_malloc(stringlen + 1);
    memcpy(probestring, ps, stringlen);
    probestring[stringlen] = '\0'; // but note that other \0 may be in string
  } else probestring = NULL;
}

void ServiceProbe::setPortVector(vector<u16> *portv, const char *portstr, 
				 int lineno) {
  const char *current_range;
  char *endptr;
  long int rangestart = 0, rangeend = 0;

  current_range = portstr;

  do {
    while(*current_range && isspace((int) (unsigned char) *current_range)) current_range++;
    if (isdigit((int) (unsigned char) *current_range)) {
      rangestart = strtol(current_range, &endptr, 10);
      if (rangestart < 0 || rangestart > 65535) {
	fatal("Parse error on line %d of nmap-service-probes: Ports must be between 0 and 65535 inclusive", lineno);
      }
      current_range = endptr;
      while(isspace((int) (unsigned char) *current_range)) current_range++;
    } else {
      fatal("Parse error on line %d of nmap-service-probes: An example of proper portlist form is \"21-25,53,80\"", lineno);
    }

    /* Now I have a rangestart, time to go after rangeend */
    if (!*current_range || *current_range == ',') {
      /* Single port specification */
      rangeend = rangestart;
    } else if (*current_range == '-') {
      current_range++;
      if (isdigit((int) (unsigned char) *current_range)) {
	rangeend = strtol(current_range, &endptr, 10);
	if (rangeend < 0 || rangeend > 65535 || rangeend < rangestart) {
	  fatal("Parse error on line %d of nmap-service-probes: Ports must be between 0 and 65535 inclusive", lineno);
	}
	current_range = endptr;
      } else {
	fatal("Parse error on line %d of nmap-service-probes: An example of proper portlist form is \"21-25,53,80\"", lineno);
      }
    } else {
      fatal("Parse error on line %d of nmap-service-probes: An example of proper portlist form is \"21-25,53,80\"", lineno);
    }

    /* Now I have a rangestart and a rangeend, so I can add these ports */
    while(rangestart <= rangeend) {
      portv->push_back(rangestart);
      rangestart++;
    }
    
    /* Find the next range */
    while(isspace((int) (unsigned char) *current_range)) current_range++;
    if (*current_range && *current_range != ',') {
      fatal("Parse error on line %d of nmap-service-probes: An example of proper portlist form is \"21-25,53,80\"", lineno);
    }
    if (*current_range == ',')
      current_range++;
  } while(current_range && *current_range);
}

  // Takes a string as given in the 'ports '/'sslports ' line of
  // nmap-service-probes.  Pass in the list from the appropriate
  // line.  For 'sslports', tunnel should be specified as
  // SERVICE_TUNNEL_SSL.  Otherwise use SERVICE_TUNNEL_NONE.  The line
  // number is requested because this function will bail with an error
  // (giving the line number) if it fails to parse the string.  Ports
  // are a comma separated list of ports and ranges
  // (e.g. 53,80,6000-6010).
void ServiceProbe::setProbablePorts(enum service_tunnel_type tunnel,
				    const char *portstr, int lineno) {
  if (tunnel == SERVICE_TUNNEL_NONE)
    setPortVector(&probableports, portstr, lineno);
  else {
    assert(tunnel == SERVICE_TUNNEL_SSL);
    setPortVector(&probablesslports, portstr, lineno);
  }
}

  /* Returns true if the passed in port is on the list of probable
     ports for this probe and tunnel type.  Use a tunnel of
     SERVICE_TUNNEL_SSL or SERVICE_TUNNEL_NONE as appropriate */
bool ServiceProbe::portIsProbable(enum service_tunnel_type tunnel, u16 portno) {
  vector<u16> *portv;

  portv = (tunnel == SERVICE_TUNNEL_SSL)? &probablesslports : &probableports;
  
  if (find(portv->begin(), portv->end(), portno) == portv->end())
    return false;
  return true;
}

 // Returns true if the passed in service name is among those that can
  // be detected by the matches in this probe;
bool ServiceProbe::serviceIsPossible(const char *sname) {
  vector<const char *>::iterator vi;

  for(vi = detectedServices.begin(); vi != detectedServices.end(); vi++) {
    if (strcmp(*vi, sname) == 0)
      return true;
  }
  return false;
}


// Takes a string following a Rarity directive in the probes file.
// The string should contain a single integer between 1 and 9. The
// default rarity is 5. This function will bail if the string is invalid.
void ServiceProbe::setRarity(const char *portstr, int lineno) {
  int tp;

  tp = atoi(portstr);

  if (tp < 1 || tp > 9)
    fatal("%s: Rarity directive on line %d of nmap-service-probes must be between 1 and 9", __func__, lineno);

  rarity = tp;
}


  // Takes a match line in a probe description and adds it to the
  // list of matches for this probe.  This function should be passed
  // the whole line starting with "match" or "softmatch" in
  // nmap-service-probes.  The line number is requested because this
  // function will bail with an error (giving the line number) if it
  // fails to parse the string.
void ServiceProbe::addMatch(const char *match, int lineno) {
  const char *sname;
  ServiceProbeMatch *newmatch = new ServiceProbeMatch();
  newmatch->InitMatch(match, lineno);
  sname = newmatch->getName();
  if (!serviceIsPossible(sname))
    detectedServices.push_back(sname);
  matches.push_back(newmatch);
}

/* Parses the given nmap-service-probes file into the AP class Must
   NOT be made static because I have external maintenance tools
   (servicematch) which use this */
void parse_nmap_service_probe_file(AllProbes *AP, char *filename) {
  ServiceProbe *newProbe = NULL;
  char line[2048];
  int lineno = 0;
  FILE *fp;

  // We better start by opening the file
  fp = fopen(filename, "r");
  if (!fp) 
    fatal("Failed to open nmap-service-probes file %s for reading", filename);

  while(fgets(line, sizeof(line), fp)) {
    lineno++;
    
    if (*line == '\n' || *line == '#')
      continue;
  
    if (strncmp(line, "Exclude ", 8) == 0) {
      if (AP->excluded_seen)
        fatal("Only 1 Exclude directive is allowed in the nmap-service-probes file");
      getpts(line+8, &AP->excludedports);
      AP->excluded_seen = true;
      continue;
    }
  
  anotherprobe:
  
    if (strncmp(line, "Probe ", 6) != 0)
      fatal("Parse error on line %d of nmap-service-probes file: %s -- line was expected to begin with \"Probe \" or \"Exclude \"", lineno, filename);
    
    newProbe = new ServiceProbe();
    newProbe->setProbeDetails(line + 6, lineno);
    
    // Now we read the rest of the probe info
    while(fgets(line, sizeof(line), fp)) {
      lineno++;
      if (*line == '\n' || *line == '#')
	continue;
      
      if (strncmp(line, "Probe ", 6) == 0) {
	if (newProbe->isNullProbe()) {
	  assert(!AP->nullProbe);
	  AP->nullProbe = newProbe;
	} else {
	  AP->probes.push_back(newProbe);
	}
	goto anotherprobe;
      } else if (strncmp(line, "ports ", 6) == 0) {
	newProbe->setProbablePorts(SERVICE_TUNNEL_NONE, line + 6, lineno);
      } else if (strncmp(line, "sslports ", 9) == 0) {
	newProbe->setProbablePorts(SERVICE_TUNNEL_SSL, line + 9, lineno);
      } else if (strncmp(line, "rarity ", 7) == 0) {
	newProbe->setRarity(line + 7, lineno);
      } else if (strncmp(line, "fallback ", 9) == 0) {
	newProbe->fallbackStr = strdup(line + 9);
      } else if (strncmp(line, "totalwaitms ", 12) == 0) {
	long waitms = strtol(line + 12, NULL, 10);
	if (waitms < 100 || waitms > 300000)
	  fatal("Error on line %d of nmap-service-probes file (%s): bad totalwaitms value.  Must be between 100 and 300000 milliseconds", lineno, filename);
	newProbe->totalwaitms = waitms;
      } else if (strncmp(line, "match ", 6) == 0 || strncmp(line, "softmatch ", 10) == 0) {
	newProbe->addMatch(line, lineno);
      } else if (strncmp(line, "Exclude ", 8) == 0) {
        fatal("The Exclude directive must precede all Probes in nmap-service-probes");
      } else fatal("Parse error on line %d of nmap-service-probes file: %s -- unknown directive", lineno, filename);
    }
  }

  if (newProbe != NULL) {
    if (newProbe->isNullProbe()) {
      assert(!AP->nullProbe);
      AP->nullProbe = newProbe;
    } else {
      AP->probes.push_back(newProbe);
    }
  }
  fclose(fp);

  AP->compileFallbacks();
}

// Parses the nmap-service-probes file, and adds each probe to
// the already-created 'probes' vector.
static void parse_nmap_service_probes(AllProbes *AP) {
  char filename[256];

  if (nmap_fetchfile(filename, sizeof(filename), "nmap-service-probes") != 1){
    fatal("Service scan requested but I cannot find nmap-service-probes file.  It should be in %s, ~/.nmap/ or .", NMAPDATADIR);
  }

  parse_nmap_service_probe_file(AP, filename);
  /* Record where this data file was found. */
  o.loaded_data_files["nmap-service-probes"] = filename;
}

AllProbes *AllProbes::global_AP;
AllProbes *AllProbes::service_scan_init(void)
{
  if(global_AP)
    return global_AP;
  global_AP = new AllProbes();
  parse_nmap_service_probes(global_AP);

  return global_AP;
}

void AllProbes::service_scan_free(void)
{
  if(global_AP){
    delete global_AP;
    global_AP = NULL;
  }
}

// Function that calls isExcluded() function to check if the port
// is in the excludedports list.
int AllProbes::check_excluded_port(unsigned short portno, int proto)
{
  int excluded;

  // Check if the -sV version scan option was specified
  // or if the --allports option was used
  if (!o.servicescan || o.override_excludeports)
    return 0;

  if (global_AP == NULL)
    fatal("Failed to check the list of excluded ports: %s", __func__);

  if ((excluded = global_AP->isExcluded(portno, proto))) {
    if (o.debugging)
      log_write(LOG_PLAIN, "EXCLUDING %d/%s\n",
                           portno, IPPROTO2STR(proto));
  }

  return excluded;
}

// If the buf (of length buflen) matches one of the regexes in this
// ServiceProbe, returns the details of nth match (service name,
// version number if applicable, and whether this is a "soft" match.
// If the buf doesn't match, the serviceName field in the structure
// will be NULL.  The MatchDetails returned is only valid until the
// next time this function is called.  The only exception is that the
// serviceName field can be saved throughought program execution.  If
// no version matched, that field will be NULL. This function may
// return NULL if there are no match lines at all in this probe.
const struct MatchDetails *ServiceProbe::testMatch(const u8 *buf, int buflen, int n = 0) {
  vector<ServiceProbeMatch *>::iterator vi;
  const struct MatchDetails *MD;

  for(vi = matches.begin(); vi != matches.end(); vi++) {
    MD = (*vi)->testMatch(buf, buflen);
    if (MD->serviceName) {
      if (n == 0)
        return MD;
      n--;
    }
  }

  return NULL;
}

AllProbes::AllProbes() {
  nullProbe = NULL;
  excluded_seen = false;
  memset(&excludedports, 0, sizeof(excludedports));
}

AllProbes::~AllProbes() {
  vector<ServiceProbe *>::iterator vi;

  // Delete all the ServiceProbe's inside the probes vector
  for(vi = probes.begin(); vi != probes.end(); vi++) {
    delete *vi;
  }
  if(nullProbe)
    delete nullProbe;
  free_scan_lists(&excludedports);
}

  // Tries to find the probe in this AllProbes class which have the
  // given name and protocol.  It can return the NULL probe.
ServiceProbe *AllProbes::getProbeByName(const char *name, int proto) {
  vector<ServiceProbe *>::iterator vi;

  if (proto == IPPROTO_TCP && nullProbe && strcmp(nullProbe->getName(), name) == 0)
    return nullProbe;

  for(vi = probes.begin(); vi != probes.end(); vi++) {
    if ((*vi)->getProbeProtocol() == proto &&
	strcmp(name, (*vi)->getName()) == 0)
      return *vi;
  }

  return NULL;
}



// Returns nonzero if port was specified in the excludeports
// directive in nmap-service-probes. Zero otherwise.
// Proto should be IPPROTO_TCP for TCP and IPPROTO_UDP for UDP
// Note that although getpts() can set protocols (for protocol
// scanning), this is ignored here because you can't version
// scan protocols.
int AllProbes::isExcluded(unsigned short port, int proto) {
  unsigned short *p=NULL;
  int count=-1,i;

  if (!excluded_seen) return 0;

  if (proto == IPPROTO_TCP) {
    p = excludedports.tcp_ports;
    count = excludedports.tcp_count;
  } else if (proto == IPPROTO_UDP) {
    p = excludedports.udp_ports;
    count = excludedports.udp_count;
  } else if (proto == IPPROTO_SCTP) {
    p = excludedports.sctp_ports;
    count = excludedports.sctp_count;
  } else {
    fatal("Bad proto number (%d) specified in %s", proto, __func__);
  }

  for (i=0; i<count; i++)
    if (p[i] == port)
           return 1;

  return 0;
}


// Before this function is called, the fallbacks exist as unparsed
// comma-separated strings in the fallbackStr field of each probe.
// This function fills out the fallbacks array in each probe with
// an ordered list of pointers to which probes to try. This is both for
// efficiency and to deal with odd cases like the NULL probe and falling
// back to probes later in the file. This function also free()s all the
// fallbackStrs.
void AllProbes::compileFallbacks() {
  vector<ServiceProbe *>::iterator curr;
  char *tp;
  int i;

  curr = probes.begin();

  // The NULL probe is a special case:
  if (nullProbe != NULL)
    nullProbe->fallbacks[0] = nullProbe;

  while (curr != probes.end()) {

    if ((*curr)->fallbackStr == NULL) {
      // A non-NULL probe without a fallback directive. We
      // just use "Itself,NULL" unless it's UDP, then just "Itself".

      (*curr)->fallbacks[0] = *curr;
      if ((*curr)->getProbeProtocol() == IPPROTO_TCP)
        (*curr)->fallbacks[1] = nullProbe;
    } else {
      // A non-NULL probe *with* a fallback directive. We use:
      // TCP: "Itself,<directive1>,...,<directiveN>,NULL"
      // UDP: "Itself,<directive1>,...,<directiveN>"

      (*curr)->fallbacks[0] = *curr;
      i = 1;
      tp = strtok((*curr)->fallbackStr, ",\r\n\t "); // \r and \n because string will be terminated with them

      while (tp != NULL && i<(MAXFALLBACKS-1)) {
        (*curr)->fallbacks[i] = getProbeByName(tp, (*curr)->getProbeProtocol());
	if ((*curr)->fallbacks[i] == NULL)
          fatal("%s: Unknown fallback specified in Probe %s: '%s'", __func__, (*curr)->getName(), tp);
	i++;
	tp = strtok(NULL, ",\r\n\t ");
      }

      if (i == MAXFALLBACKS-1)
        fatal("%s: MAXFALLBACKS exceeded on probe '%s'", __func__, (*curr)->getName());

      if ((*curr)->getProbeProtocol() == IPPROTO_TCP)
        (*curr)->fallbacks[i] = nullProbe;
    }

    if ((*curr)->fallbackStr) free((*curr)->fallbackStr);
    (*curr)->fallbackStr = NULL;

    curr++;
  }

}



ServiceNFO::ServiceNFO(AllProbes *newAP) {
  target = NULL;
  probe_matched = NULL;
  niod = NULL;
  probe_state = PROBESTATE_INITIAL;
  portno = proto = 0;
  AP = newAP;
  currentresp = NULL; 
  currentresplen = 0;
  product_matched[0] = version_matched[0] = extrainfo_matched[0] = '\0';
  hostname_matched[0] = ostype_matched[0] = devicetype_matched[0] = '\0';
  tunnel = SERVICE_TUNNEL_NONE;
  ssl_session = NULL;
  softMatchFound = false;
  servicefplen = servicefpalloc = 0;
  servicefp = NULL;
  memset(&currentprobe_exec_time, 0, sizeof(currentprobe_exec_time));
}

ServiceNFO::~ServiceNFO() {
  if (currentresp) free(currentresp);
  if (servicefp) free(servicefp);
  servicefp = NULL;
  servicefpalloc = servicefplen = 0;
#if HAVE_OPENSSL
  if (ssl_session)
    SSL_SESSION_free((SSL_SESSION*)ssl_session);
  ssl_session=NULL;
#endif
}

  // Adds a character to servicefp.  Takes care of word wrapping if
  // necessary at the given (wrapat) column.  Chars will only be
  // written if there is enough space.  Otherwise it exits.
void ServiceNFO::addServiceChar(const char c, int wrapat) {

  if (servicefpalloc - servicefplen < 6)
    fatal("%s - out of space for servicefp", __func__);

  if (servicefplen % (wrapat+1) == wrapat) {
    // we need to start a new line
    memcpy(servicefp + servicefplen, "\nSF:", 4);
    servicefplen += 4;
  }

  servicefp[servicefplen++] = c;
}

// Like addServiceChar, but for a whole zero-terminated string
void ServiceNFO::addServiceString(const char *s, int wrapat) {
  while(*s) 
    addServiceChar(*s++, wrapat);
}

// If a service response to a given probeName, this function adds the
// resonse the the fingerprint for that service.  The fingerprint can
// be printed when nothing matches the service.  You can obtain the
// fingerprint (if any) via getServiceFingerprint();
void ServiceNFO::addToServiceFingerprint(const char *probeName, const u8 *resp, 
					 int resplen) {
  int spaceleft = servicefpalloc - servicefplen;
  int servicewrap=74; // Wrap after 74 chars / line
  int respused = MIN(resplen, (o.debugging)? 1300 : 900); // truncate to reasonable size
  // every char could require \xHH escape, plus there is the matter of 
  // "\nSF:" for each line, plus "%r(probename,probelen,"") Oh, and 
  // the SF-PortXXXX-TCP stuff, etc
  int spaceneeded = respused * 5 + strlen(probeName) + 128;  
  int srcidx;
  struct tm *ltime;
  time_t timep;
  char buf[128];
  int len;

  assert(resplen);
  assert(probeName);

  if (servicefplen > (o.debugging? 10000 : 2200))
    return; // it is large enough.

  if (spaceneeded >= spaceleft) {
    spaceneeded = MAX(spaceneeded, 512); // No point in tiny allocations
    spaceneeded += servicefpalloc;

    servicefp = (char *) safe_realloc(servicefp, spaceneeded);
    servicefpalloc = spaceneeded;
  }
  spaceleft = servicefpalloc - servicefplen;

  if (servicefplen == 0) {
    timep = time(NULL);
    ltime = localtime(&timep);
    len = Snprintf(buf, sizeof(buf), "SF-Port%hu-%s:V=%s%s%%I=%d%%D=%d/%d%%Time=%X%%P=%s", portno, proto2ascii_uppercase(proto), NMAP_VERSION, (tunnel == SERVICE_TUNNEL_SSL)? "%T=SSL" : "", o.version_intensity, ltime->tm_mon + 1, ltime->tm_mday, (int) timep, NMAP_PLATFORM);
    addServiceString(buf, servicewrap);
  }

  // Note that we give the total length of the response, even though we 
  // may truncate
  len = Snprintf(buf, sizeof(buf), "%%r(%s,%X,\"", probeName, resplen);
  addServiceString(buf, servicewrap);

  // Now for the probe response itself ...
  for(srcidx=0; srcidx < respused; srcidx++) {
    // A run of this can take up to 8 chars: "\n  \x20"
    assert( servicefpalloc - servicefplen > 8);
 
    if (isalnum((int)resp[srcidx]))
      addServiceChar((char) resp[srcidx], servicewrap);
    else if (resp[srcidx] == '\0') {
      /* We need to be careful with this, because if it is followed by
	 an ASCII number, PCRE will treat it differently. */
      if (srcidx + 1 >= respused || !isdigit((int) resp[srcidx + 1]))
	addServiceString("\\0", servicewrap);
      else addServiceString("\\x00", servicewrap);
    } else if (strchr("\\?\"[]().*+$^|", resp[srcidx])) {
      addServiceChar('\\', servicewrap);
      addServiceChar(resp[srcidx], servicewrap);
    } else if (ispunct((int)resp[srcidx])) {
      addServiceChar((char) resp[srcidx], servicewrap);
    } else if (resp[srcidx] == '\r') {
      addServiceString("\\r", servicewrap);
    } else if (resp[srcidx] == '\n') {
      addServiceString("\\n", servicewrap);
    } else if (resp[srcidx] == '\t') {
      addServiceString("\\t", servicewrap);
    } else {
      addServiceChar('\\', servicewrap);
      addServiceChar('x', servicewrap);
      Snprintf(buf, sizeof(buf), "%02x", resp[srcidx]);
      addServiceChar(*buf, servicewrap);
      addServiceChar(*(buf+1), servicewrap);
    }
  }

  addServiceChar('"', servicewrap);
  addServiceChar(')', servicewrap);
  assert(servicefpalloc - servicefplen > 1);
  servicefp[servicefplen] = '\0';
}

// Get the service fingerprint.  It is NULL if there is none, such
// as if there was a match before any other probes were finished (or
// if no probes gave back data).  Note that this is plain
// NUL-terminated ASCII data, although the length is optionally
// available anyway.  This function terminates the service fingerprint
// with a semi-colon
const char *ServiceNFO::getServiceFingerprint(int *flen) {

  if (servicefplen == 0) {
    if (flen) *flen = 0;
    return NULL;
  }

  // Ensure we have enough space for the terminating semi-colon and \0
  if (servicefplen + 2 > servicefpalloc) {
    servicefpalloc = servicefplen + 20;
    servicefp = (char *) safe_realloc(servicefp, servicefpalloc);
  }

  if (flen) *flen = servicefplen + 1;
  // We terminate with a semi-colon, which is never wrapped.
  servicefp[servicefplen] = ';';
  servicefp[servicefplen + 1] = '\0';
  return servicefp;
}

ServiceProbe *ServiceNFO::currentProbe() {
  if (probe_state == PROBESTATE_INITIAL) {
    return nextProbe(true);
  } else if (probe_state == PROBESTATE_NULLPROBE) {
    assert(AP->nullProbe);
    return AP->nullProbe;
  } else if (probe_state == PROBESTATE_MATCHINGPROBES || 
	     probe_state == PROBESTATE_NONMATCHINGPROBES) {
    return *current_probe;
  }
  return NULL;
}

// computes the next probe to test, and ALSO CHANGES currentProbe() to
// that!  If newresp is true, the old response info will be lost and
// invalidated.  Otherwise it remains as if it had been received by
// the current probe (useful after a NULL probe).
ServiceProbe *ServiceNFO::nextProbe(bool newresp) {
bool dropdown = false;

// This invalidates the probe response string if any
 if (newresp) { 
   if (currentresp) free(currentresp);
   currentresp = NULL; currentresplen = 0;
 }

 if (probe_state == PROBESTATE_INITIAL) {
   probe_state = PROBESTATE_NULLPROBE;
   // This is the very first probe -- so we try to use the NULL probe
   // but obviously NULL probe only works with TCP
   if (proto == IPPROTO_TCP && AP->nullProbe)
     return AP->nullProbe;
   
   // No valid NULL probe -- we'll drop to the next state
 }
 
 if (probe_state == PROBESTATE_NULLPROBE) {
   // There can only be one (or zero) NULL probe.  So now we go through the
   // list looking for matching probes
   probe_state = PROBESTATE_MATCHINGPROBES;
   dropdown = true;
   current_probe = AP->probes.begin();
 }

 if (probe_state == PROBESTATE_MATCHINGPROBES) {
   if (!dropdown && current_probe != AP->probes.end()) current_probe++;
   while (current_probe != AP->probes.end()) {
     // For the first run, we only do probes that match this port number
     if ((proto == (*current_probe)->getProbeProtocol()) && 
	 (*current_probe)->portIsProbable(tunnel, portno)) {
       // This appears to be a valid probe.  Let's do it!
       return *current_probe;
     }
     current_probe++;
   }
   // Tried all MATCHINGPROBES -- now we must move to nonmatching
   probe_state = PROBESTATE_NONMATCHINGPROBES;
   dropdown = true;
   current_probe = AP->probes.begin();
 }

 if (probe_state == PROBESTATE_NONMATCHINGPROBES) {
   if (!dropdown && current_probe != AP->probes.end()) current_probe++;
   while (current_probe != AP->probes.end()) {
     // The protocol must be right, it must be a nonmatching port ('cause we did those),
     // and we better either have no soft match yet, or the soft service match must
     // be available via this probe. Also, the Probe's rarity must be <= to our
     // version detection intensity level.
     if ((proto == (*current_probe)->getProbeProtocol()) && 
	 !(*current_probe)->portIsProbable(tunnel, portno) &&
	 (*current_probe)->getRarity() <= o.version_intensity &&
	 (!softMatchFound || (*current_probe)->serviceIsPossible(probe_matched))) {
       // Valid, probe.  Let's do it!
       return *current_probe;
     }
     current_probe++;
   }

   // Tried all NONMATCHINGPROBES -- we're finished
   probe_state = (softMatchFound)? PROBESTATE_FINISHED_SOFTMATCHED : PROBESTATE_FINISHED_NOMATCH;
   return NULL; 
 }

 fatal("%s called for probe in state (%d)", __func__, (int) probe_state);
 return NULL;
}

  // Resets the probes back to the first one. One case where this is useful is
  // when SSL is detected -- we redo all probes through SSL.  If freeFP, any
  // service fingerprint is freed too.
void ServiceNFO::resetProbes(bool freefp) {

  if (currentresp) free(currentresp);

  if (freefp) {
    if (servicefp) { free(servicefp); servicefp = NULL; }
    servicefplen = servicefpalloc = 0;
  }

  currentresp = NULL; currentresplen = 0;

  probe_state = PROBESTATE_INITIAL;
}


int ServiceNFO::currentprobe_timemsleft(const struct timeval *now) {
  int timeused, timeleft;

  if (now)
    timeused = TIMEVAL_MSEC_SUBTRACT(*now, currentprobe_exec_time);
  else {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    timeused = TIMEVAL_MSEC_SUBTRACT(tv, currentprobe_exec_time);
  }

  timeleft = currentProbe()->totalwaitms - timeused;
  return (timeleft < 0)? 0 : timeleft;
}

void ServiceNFO::appendtocurrentproberesponse(const u8 *respstr, int respstrlen) {
  currentresp = (u8 *) safe_realloc(currentresp, currentresplen + respstrlen);
  memcpy(currentresp + currentresplen, respstr, respstrlen);
  currentresplen += respstrlen;
}

// Get the full current response string.  Note that this pointer is 
// INVALIDATED if you call appendtocurrentproberesponse() or nextProbe()
u8 *ServiceNFO::getcurrentproberesponse(int *respstrlen) {
  *respstrlen = currentresplen;
  return currentresp;
}


ServiceGroup::ServiceGroup(vector<Target *> &Targets, AllProbes *AP) {
  unsigned int targetno;
  ServiceNFO *svc;
  Port *nxtport;
  Port port;
  int desired_par;
  struct timeval now;
  num_hosts_timedout = 0;
  gettimeofday(&now, NULL);

  for(targetno = 0 ; targetno < Targets.size(); targetno++) {
    nxtport = NULL;
    if (Targets[targetno]->timedOut(&now)) {
      num_hosts_timedout++;
      continue;
    }
    while((nxtport = Targets[targetno]->ports.nextPort(nxtport, &port, TCPANDUDPANDSCTP, PORT_OPEN))) {
      svc = new ServiceNFO(AP);
      svc->target = Targets[targetno];
      svc->portno = nxtport->portno;
      svc->proto = nxtport->proto;
      services_remaining.push_back(svc);
    }
  }

  /* Use a whole new loop for PORT_OPENFILTERED so that we try all the
     known open ports first before bothering with this speculative
     stuff */
  for(targetno = 0 ; targetno < Targets.size(); targetno++) {
    nxtport = NULL;
    if (Targets[targetno]->timedOut(&now)) {
      continue;
    }
    while((nxtport = Targets[targetno]->ports.nextPort(nxtport, &port, TCPANDUDPANDSCTP, PORT_OPENFILTERED))) {
      svc = new ServiceNFO(AP);
      svc->target = Targets[targetno];
      svc->portno = nxtport->portno;
      svc->proto = nxtport->proto;
      services_remaining.push_back(svc);
    }
  }

  SPM = new ScanProgressMeter("Service scan");
  desired_par = 1;
  if (o.timing_level == 3) desired_par = 20;
  if (o.timing_level == 4) desired_par = 30;
  if (o.timing_level >= 5) desired_par = 40;
  // TODO: Come up with better ways to determine ideal_parallelism
  ideal_parallelism = box(o.min_parallelism, o.max_parallelism? o.max_parallelism : 100, desired_par);
}

ServiceGroup::~ServiceGroup() {
  list<ServiceNFO *>::iterator i;

  for(i = services_finished.begin(); i != services_finished.end(); i++)
    delete *i;

  for(i = services_in_progress.begin(); i != services_in_progress.end(); i++)
    delete *i;

  for(i = services_remaining.begin(); i != services_remaining.end(); i++)
    delete *i;

  delete SPM;
}

/* Called if data is read for a service or a TCP connection made. Sets the port
   state to PORT_OPEN. */
static void adjustPortStateIfNecessary(ServiceNFO *svc) {
  int oldstate;
  char host[128];

  oldstate = svc->target->ports.getPortState(svc->portno, svc->proto);
  if (oldstate != PORT_OPEN) {
    svc->target->ports.setPortState(svc->portno, svc->proto, PORT_OPEN);
    if (svc->proto == IPPROTO_TCP) 
        svc->target->ports.setStateReason(svc->portno, svc->proto, ER_TCPRESPONSE, 0, 0);
    if (svc->proto == IPPROTO_UDP)
        svc->target->ports.setStateReason(svc->portno, svc->proto, ER_UDPRESPONSE, 0, 0);

    if (o.verbose || o.debugging > 1) {
      svc->target->NameIP(host, sizeof(host));

      log_write(LOG_STDOUT, "Discovered %s port %hu/%s on %s is actually open\n",
         statenum2str(oldstate), svc->portno, proto2ascii_lowercase(svc->proto), host);
      log_flush(LOG_STDOUT);
    }
  }

  return;
}

  // Sends probe text to an open connection.  In the case of a NULL probe, there
  // may be no probe text
  static int send_probe_text(nsock_pool nsp, nsock_iod nsi, ServiceNFO *svc,
			     ServiceProbe *probe) {
    const u8 *probestring;
    int probestringlen;

    // Report data as probes are sent if --version-trace has been requested 
    if (o.debugging > 1 || o.versionTrace()) {
      log_write(LOG_PLAIN, "Service scan sending probe %s to %s:%hu (%s)\n", probe->getName(), svc->target->targetipstr(), svc->portno, proto2ascii_lowercase(svc->proto));
    }	

    assert(probe);
    if (probe->isNullProbe())
      return 0; // No need to send anything for a NULL probe;
    probestring = probe->getProbeString(&probestringlen);
    assert(probestringlen > 0);
    // Now we write the string to the IOD
    nsock_write(nsp, nsi, servicescan_write_handler, svc->currentprobe_timemsleft(), svc,
		(const char *) probestring, probestringlen);
    return 0;
  }

// This simple helper function is used to start the next probe.  If
// the probe exists, execution begins (and the previous one is cleaned
// up if necessary) .  Otherwise, the service is listed as finished
// and moved to the finished list.  If you pass 'true' for alwaysrestart, a
// new connection will be made even if the previous probe was the NULL probe.
// You would do this, for example, if the other side has closed the connection.
static void startNextProbe(nsock_pool nsp, nsock_iod nsi, ServiceGroup *SG, 
			   ServiceNFO *svc, bool alwaysrestart) {
  bool isInitial = svc->probe_state == PROBESTATE_INITIAL;
  ServiceProbe *probe = svc->currentProbe();
  struct sockaddr_storage ss;
  size_t ss_len;

  if (!alwaysrestart && probe->isNullProbe()) {
    // The difference here is that we can reuse the same (TCP) connection
    // if the last probe was the NULL probe.
    probe = svc->nextProbe(false);
    if (probe) {
      svc->currentprobe_exec_time = *nsock_gettimeofday();
      send_probe_text(nsp, nsi, svc, probe);
      nsock_read(nsp, nsi, servicescan_read_handler, 
		 svc->currentprobe_timemsleft(nsock_gettimeofday()), svc);
    } else {
      // Should only happen if someone has a highly perverse nmap-service-probes
      // file.  Null scan should generally never be the only probe.
      end_svcprobe(nsp, (svc->softMatchFound)? PROBESTATE_FINISHED_SOFTMATCHED : PROBESTATE_FINISHED_NOMATCH, SG, svc, NULL);
    }
  } else {
    // The finisehd probe was not a NULL probe.  So we close the
    // connection, and if further probes are available, we launch the
    // next one.
    if (!isInitial)
      probe = svc->nextProbe(true); // if was initial, currentProbe() returned the right one to execute.
    if (probe) {
      // For a TCP probe, we start by requesting a new connection to the target
      if (svc->proto == IPPROTO_TCP) {
	nsi_delete(nsi, NSOCK_PENDING_SILENT);
	if ((svc->niod = nsi_new(nsp, svc)) == NULL) {
	  fatal("Failed to allocate Nsock I/O descriptor in %s()", __func__);
	}
	if (o.spoofsource) {
	  o.SourceSockAddr(&ss, &ss_len);
	  nsi_set_localaddr(svc->niod, &ss, ss_len);
	}
	if (o.ipoptionslen)
	  nsi_set_ipoptions(svc->niod, o.ipoptions, o.ipoptionslen);
        if (svc->target->TargetName()) {
          if (nsi_set_hostname(svc->niod, svc->target->TargetName()) == -1)
	    fatal("nsi_set_hostname(\"%s\" failed in %s()", svc->target->TargetName(), __func__);
        }
	svc->target->TargetSockAddr(&ss, &ss_len);
	if (svc->tunnel == SERVICE_TUNNEL_NONE) {
	  nsock_connect_tcp(nsp, svc->niod, servicescan_connect_handler, 
			    DEFAULT_CONNECT_TIMEOUT, svc, 
			    (struct sockaddr *) &ss, ss_len,
			    svc->portno);
	} else {
	  assert(svc->tunnel == SERVICE_TUNNEL_SSL);
	  nsock_connect_ssl(nsp, svc->niod, servicescan_connect_handler, 
			    DEFAULT_CONNECT_SSL_TIMEOUT, svc, 
			    (struct sockaddr *) &ss,
			    ss_len, svc->proto, svc->portno, svc->ssl_session);
	}
      } else {
	assert(svc->proto == IPPROTO_UDP);
	/* Can maintain the same UDP "connection" */
	svc->currentprobe_exec_time = *nsock_gettimeofday();
	send_probe_text(nsp, nsi, svc, probe);
	// Now let us read any results
	nsock_read(nsp, nsi, servicescan_read_handler, 
		   svc->currentprobe_timemsleft(nsock_gettimeofday()), svc);
      }
    } else {
      // No more probes remaining!  Failed to match
      nsi_delete(nsi, NSOCK_PENDING_SILENT);
      end_svcprobe(nsp, (svc->softMatchFound)? PROBESTATE_FINISHED_SOFTMATCHED : PROBESTATE_FINISHED_NOMATCH, SG, svc, NULL);
    }
  }
  return;
}

/* Sometimes the normal service scan will detect a
   tunneling/encryption protocol such as SSL.  Instead of just
   reporting "ssl", we can make an SSL connection and try to determine
   the service that is really sitting behind the SSL.  This function
   will take a service that has just been detected (hard match only),
   and see if we can dig deeper through tunneling.  Nonzero is
   returned if we can do more.  Otherwise 0 is returned and the caller
   should end the service with its successful match.  If the tunnel
   results can be determined with no more effort, 0 is also returned.
   For example, a service that already matched as "ssl/ldap" will be
   chaned to "ldap" with the tunnel being SSL and 0 will be returned.
   That is a special case.
*/

static int scanThroughTunnel(nsock_pool nsp, nsock_iod nsi, ServiceGroup *SG, 
			     ServiceNFO *svc) {

  if (svc->probe_matched && strncmp(svc->probe_matched, "ssl/", 4) == 0) {
    /* The service has been detected without having to make an SSL connection */
    svc->tunnel = SERVICE_TUNNEL_SSL;
    svc->probe_matched += 4;
    return 0;
  }

#ifdef HAVE_OPENSSL
  if (svc->tunnel != SERVICE_TUNNEL_NONE) {
    // Another tunnel type has already been tried.  Let's not go recursive.
    return 0;
  }

  if (svc->proto != IPPROTO_TCP || 
      !svc->probe_matched || strcmp(svc->probe_matched, "ssl") != 0)
    return 0; // Not SSL

  // Alright!  We are going to start the tests over using SSL
  // printf("DBG: Found SSL service on %s:%hu - starting SSL scan\n", svc->target->NameIP(), svc->portno);
  svc->tunnel = SERVICE_TUNNEL_SSL;
  svc->probe_matched = NULL;
  svc->product_matched[0] = svc->version_matched[0] = svc->extrainfo_matched[0] = '\0';
  svc->hostname_matched[0] = svc->ostype_matched[0] = svc->devicetype_matched[0] = '\0';
  svc->softMatchFound = false;
   svc->resetProbes(true);
  startNextProbe(nsp, nsi, SG, svc, true);
  return 1;
#else
  return 0;
#endif
}

/* Prints completion estimates and the like when appropriate */
static void considerPrintingStats(ServiceGroup *SG) {
   /* Check for status requests */
   if (keyWasPressed()) {
      SG->SPM->printStats(SG->services_finished.size() /
                          ((double)SG->services_remaining.size() + SG->services_in_progress.size() + 
                           SG->services_finished.size()), nsock_gettimeofday());
   }


  /* Perhaps this should be made more complex, but I suppose it should be
     good enough for now. */
  if (SG->SPM->mayBePrinted(nsock_gettimeofday())) {
    SG->SPM->printStatsIfNecessary(SG->services_finished.size() / ((double)SG->services_remaining.size() + SG->services_in_progress.size() + SG->services_finished.size()), nsock_gettimeofday());
  }
}

/* Check if target is done (no more probes remaining for it in service group),
   and responds appropriately if so */
static void handleHostIfDone(ServiceGroup *SG, Target *target) {
  list<ServiceNFO *>::iterator svcI;
  bool found = false;

  for(svcI = SG->services_in_progress.begin(); 
      svcI != SG->services_in_progress.end(); svcI++) {
    if ((*svcI)->target == target) {
      found = true;
      break;
    }
  }

  for(svcI = SG->services_remaining.begin(); 
      !found && svcI != SG->services_remaining.end(); svcI++) {
    if ((*svcI)->target == target) {
      found = true;
      break;
    }
  }

  if (!found) {
    target->stopTimeOutClock(nsock_gettimeofday());
    if (target->timedOut(NULL)) {
      SG->num_hosts_timedout++;
    }
  }
}

// A simple helper function to cancel further work on a service and
// set it to the given probe_state pass NULL for nsi if you don't want
// it to be deleted (for example, if you already have done so).
static void end_svcprobe(nsock_pool nsp, enum serviceprobestate probe_state, ServiceGroup *SG, ServiceNFO *svc, nsock_iod nsi) {
  list<ServiceNFO *>::iterator member;
  Target *target = svc->target;

  svc->probe_state = probe_state;
  member = find(SG->services_in_progress.begin(), SG->services_in_progress.end(),
		  svc);
  if (member != SG->services_in_progress.end()) {
    assert(*member == svc);
    SG->services_in_progress.erase(member);
  } else {
    /* A probe can finish from services_remaining if the host times out before the
       probe has even started */
    member = find(SG->services_remaining.begin(), SG->services_remaining.end(),
		  svc);
    assert(member != SG->services_remaining.end());
    assert(*member == svc);
    SG->services_remaining.erase(member);
  }

  SG->services_finished.push_back(svc);

  considerPrintingStats(SG);

  if (nsi) {
    nsi_delete(nsi, NSOCK_PENDING_SILENT);
  }

  handleHostIfDone(SG, target);
  return;
}

// This function consults the ServiceGroup to determine whether any
// more probes can be launched at this time.  If so, it determines the
// appropriate ones and then starts them up.
static int launchSomeServiceProbes(nsock_pool nsp, ServiceGroup *SG) {
  ServiceNFO *svc;
  ServiceProbe *nextprobe;
  struct sockaddr_storage ss;
  size_t ss_len;
  static int warn_no_scanning=1;

  while (SG->services_in_progress.size() < SG->ideal_parallelism &&
	 !SG->services_remaining.empty()) {
    // Start executing a probe from the new list and move it to in_progress
    svc = SG->services_remaining.front();
    if (svc->target->timedOut(nsock_gettimeofday())) {
      end_svcprobe(nsp, PROBESTATE_INCOMPLETE, SG, svc, NULL);
      continue;
    }
    nextprobe = svc->nextProbe(true);

    if (nextprobe == NULL) {
      if (warn_no_scanning && o.debugging) {
        log_write(LOG_PLAIN, "Service scan: Not probing some ports due to low intensity\n");
        warn_no_scanning=0;
      }
      end_svcprobe(nsp, PROBESTATE_FINISHED_NOMATCH, SG, svc, NULL);
      continue;
    }

    // We start by requesting a connection to the target
    if ((svc->niod = nsi_new(nsp, svc)) == NULL) {
      fatal("Failed to allocate Nsock I/O descriptor in %s()", __func__);
    }
    if (o.debugging > 1) {
      log_write(LOG_PLAIN, "Starting probes against new service: %s:%hu (%s)\n", svc->target->targetipstr(), svc->portno, proto2ascii_lowercase(svc->proto));
    }
    if (o.spoofsource) {
      o.SourceSockAddr(&ss, &ss_len);
      nsi_set_localaddr(svc->niod, &ss, ss_len);
    }
    if (o.ipoptionslen)
      nsi_set_ipoptions(svc->niod, o.ipoptions, o.ipoptionslen);
    svc->target->TargetSockAddr(&ss, &ss_len);
    if (svc->proto == IPPROTO_TCP)
      nsock_connect_tcp(nsp, svc->niod, servicescan_connect_handler, 
			DEFAULT_CONNECT_TIMEOUT, svc, 
			(struct sockaddr *)&ss, ss_len,
			svc->portno);
    else {
      assert(svc->proto == IPPROTO_UDP);
      nsock_connect_udp(nsp, svc->niod, servicescan_connect_handler, 
			svc, (struct sockaddr *) &ss, ss_len,
			svc->portno);
    }
    // Now remove it from the remaining service list
    SG->services_remaining.pop_front();
    // And add it to the in progress list
    SG->services_in_progress.push_back(svc);
  }
  return 0;
}


static void servicescan_connect_handler(nsock_pool nsp, nsock_event nse, void *mydata) {
  nsock_iod nsi = nse_iod(nse);
  enum nse_status status = nse_status(nse);
  enum nse_type type = nse_type(nse);
  ServiceNFO *svc = (ServiceNFO *) mydata;
  ServiceProbe *probe = svc->currentProbe();
  ServiceGroup *SG = (ServiceGroup *) nsp_getud(nsp);

  assert(type == NSE_TYPE_CONNECT || type == NSE_TYPE_CONNECT_SSL);

  if (svc->target->timedOut(nsock_gettimeofday())) {
    end_svcprobe(nsp, PROBESTATE_INCOMPLETE, SG, svc, nsi);
  } else if (status == NSE_STATUS_SUCCESS) {

#if HAVE_OPENSSL
    // Snag our SSL_SESSION from the nsi for use in subsequent connections.
    if (nsi_checkssl(nsi)) {
      if ( svc->ssl_session ) {
	if (svc->ssl_session == (SSL_SESSION *)(nsi_get0_ssl_session(nsi))) {
	  //nada
	} else {
          SSL_SESSION_free((SSL_SESSION*)svc->ssl_session);
          svc->ssl_session = (SSL_SESSION *)(nsi_get1_ssl_session(nsi));
        }
      } else {
        svc->ssl_session = (SSL_SESSION *)(nsi_get1_ssl_session(nsi));
      }
    }
#endif

    /* If the port is TCP, it is now known to be open rather than openfiltered */
    if (svc->proto == IPPROTO_TCP)
      adjustPortStateIfNecessary(svc);

    // Yeah!  Connection made to the port.  Send the appropriate probe
    // text (if any is needed -- might be NULL probe)
    svc->currentprobe_exec_time = *nsock_gettimeofday();
    send_probe_text(nsp, nsi, svc, probe);
    // Now let us read any results
    nsock_read(nsp, nsi, servicescan_read_handler, svc->currentprobe_timemsleft(nsock_gettimeofday()), svc);
  } else if (status == NSE_STATUS_TIMEOUT || status == NSE_STATUS_ERROR) {
      // This is not good.  The connect() really shouldn't generally
      // be timing out like that.  We'll mark this svc as incomplete
      // and move it to the finished bin.
    if (o.debugging)
      error("Got nsock CONNECT response with status %s - aborting this service", nse_status2str(status));
    end_svcprobe(nsp, PROBESTATE_INCOMPLETE, SG, svc, nsi);
  } else if (status == NSE_STATUS_KILL) {
    /* User probablby specified host_timeout and so the service scan is
       shutting down */
    end_svcprobe(nsp, PROBESTATE_INCOMPLETE, SG, svc, nsi);
    return;
  } else fatal("Unexpected nsock status (%d) returned for connection attempt", (int) status);

  // We may have room for more pr0bes!
  launchSomeServiceProbes(nsp, SG);

  return;
}

static void servicescan_write_handler(nsock_pool nsp, nsock_event nse, void *mydata) {
  enum nse_status status = nse_status(nse);
  nsock_iod nsi;
  ServiceNFO *svc = (ServiceNFO *)mydata;
  ServiceGroup *SG;
  int err;

  SG = (ServiceGroup *) nsp_getud(nsp);
  nsi = nse_iod(nse);

  // Check if a status message was requsted
  if (keyWasPressed()) {
     SG->SPM->printStats(SG->services_finished.size() /
                         ((double)SG->services_remaining.size() + SG->services_in_progress.size() + 
                          SG->services_finished.size()), nsock_gettimeofday());
  }
  

  if (svc->target->timedOut(nsock_gettimeofday())) {
    end_svcprobe(nsp, PROBESTATE_INCOMPLETE, SG, svc, nsi);
    return;
  }

  if (status == NSE_STATUS_SUCCESS)
    return;

  if (status == NSE_STATUS_KILL) {
    /* User probablby specified host_timeout and so the service scan is
       shutting down */
    end_svcprobe(nsp, PROBESTATE_INCOMPLETE, SG, svc, nsi);
    return;
  }

  if (status == NSE_STATUS_ERROR) {
	err = nse_errorcode(nse);
	error("Got nsock WRITE error #%d (%s)", err, strerror(err));
  }

  // Uh-oh.  Some sort of write failure ... maybe the connection closed
  // on us unexpectedly?
  if (o.debugging) 
    error("Got nsock WRITE response with status %s - aborting this service", nse_status2str(status));
  end_svcprobe(nsp, PROBESTATE_INCOMPLETE, SG, svc, nsi);
  
  // We may have room for more pr0bes!
  launchSomeServiceProbes(nsp, SG);
  
  return;
}

static void servicescan_read_handler(nsock_pool nsp, nsock_event nse, void *mydata) {
  nsock_iod nsi = nse_iod(nse);
  enum nse_status status = nse_status(nse);
  enum nse_type type = nse_type(nse);
  ServiceNFO *svc = (ServiceNFO *) mydata;
  ServiceProbe *probe = svc->currentProbe();
  ServiceGroup *SG = (ServiceGroup *) nsp_getud(nsp);
  const u8 *readstr;
  int readstrlen;
  const struct MatchDetails *MD;
  int fallbackDepth=0;

  assert(type == NSE_TYPE_READ);

  if (svc->target->timedOut(nsock_gettimeofday())) {
    end_svcprobe(nsp, PROBESTATE_INCOMPLETE, SG, svc, nsi);
  } else if (status == NSE_STATUS_SUCCESS) {
    // w00p, w00p, we read something back from the port.
    readstr = (u8 *) nse_readbuf(nse, &readstrlen);
    adjustPortStateIfNecessary(svc); /* A response means PORT_OPENFILTERED is really PORT_OPEN */
    svc->appendtocurrentproberesponse(readstr, readstrlen);
    // now get the full version
    readstr = svc->getcurrentproberesponse(&readstrlen);

    for (MD = NULL; probe->fallbacks[fallbackDepth] != NULL; fallbackDepth++) {
      MD = (probe->fallbacks[fallbackDepth])->testMatch(readstr, readstrlen);
      if (MD && MD->serviceName) break; // Found one!
    }

    if (MD && MD->serviceName) {
      // WOO HOO!!!!!!  MATCHED!  But might be soft
      if (MD->isSoft && svc->probe_matched) {
	if (strcmp(svc->probe_matched, MD->serviceName) != 0)
	  error("WARNING: Service %s:%hu had already soft-matched %s, but now soft-matched %s; ignoring second value", svc->target->targetipstr(), svc->portno, svc->probe_matched, MD->serviceName);
	// No error if its the same - that happens frequently.  For
	// example, if we read more data for the same probe response
	// it will probably still match.
      } else {
	if (o.debugging > 1 || o.versionTrace()) {
	  if (MD->product || MD->version || MD->info)
	    log_write(LOG_PLAIN, "Service scan match (Probe %s matched with %s line %d): %s:%hu is %s%s.  Version: |%s|%s|%s|\n",
                      probe->getName(), (*probe->fallbacks[fallbackDepth]).getName(),
		      MD->lineno,
		      svc->target->targetipstr(), svc->portno, (svc->tunnel == SERVICE_TUNNEL_SSL)? "SSL/" : "", 
		      MD->serviceName, (MD->product)? MD->product : "", (MD->version)? MD->version : "", 
		      (MD->info)? MD->info : "");
	  else
	    log_write(LOG_PLAIN, "Service scan %s match (Probe %s matched with %s): %s:%hu is %s%s\n",
                      (MD->isSoft)? "soft" : "hard",
                      probe->getName(), (*probe->fallbacks[fallbackDepth]).getName(),
		      svc->target->targetipstr(), svc->portno, (svc->tunnel == SERVICE_TUNNEL_SSL)? "SSL/" : "", MD->serviceName);
	}
	svc->probe_matched = MD->serviceName;
	if (MD->product)
	  Strncpy(svc->product_matched, MD->product, sizeof(svc->product_matched));
	if (MD->version) 
	  Strncpy(svc->version_matched, MD->version, sizeof(svc->version_matched));
	if (MD->info) 
	  Strncpy(svc->extrainfo_matched, MD->info, sizeof(svc->extrainfo_matched));
	if (MD->hostname) 
	  Strncpy(svc->hostname_matched, MD->hostname, sizeof(svc->hostname_matched));
	if (MD->ostype) 
	  Strncpy(svc->ostype_matched, MD->ostype, sizeof(svc->ostype_matched));
	if (MD->devicetype) 
	  Strncpy(svc->devicetype_matched, MD->devicetype, sizeof(svc->devicetype_matched));
	svc->softMatchFound = MD->isSoft;
	if (!svc->softMatchFound) {
	  // We might be able to continue scan through a tunnel protocol 
	  // like SSL
	  if (scanThroughTunnel(nsp, nsi, SG, svc) == 0) 
	    end_svcprobe(nsp, PROBESTATE_FINISHED_HARDMATCHED, SG, svc, nsi);
	}
      }
    }

    if (!MD || !MD->serviceName || MD->isSoft) {
      // Didn't match... maybe reading more until timeout will help
      // TODO: For efficiency I should be able to test if enough data
      // has been received rather than always waiting for the reading
      // to timeout.  For now I'll limit it to 4096 bytes just to
      // avoid reading megs from services like chargen.  But better
      // approach is needed.
      if (svc->currentprobe_timemsleft() > 0 && readstrlen < 4096) { 
	nsock_read(nsp, nsi, servicescan_read_handler, svc->currentprobe_timemsleft(), svc);
      } else {
	// Failed -- lets go to the next probe.
	if (readstrlen > 0)
	  svc->addToServiceFingerprint(svc->currentProbe()->getName(), readstr, 
				       readstrlen);
	startNextProbe(nsp, nsi, SG, svc, false);
      }
    }
  } else if (status == NSE_STATUS_TIMEOUT) {
    // Failed to read enough to make a match in the given amount of time.  So we
    // move on to the next probe.  If this was a NULL probe, we can simply
    // send the new probe text immediately.  Otherwise we make a new connection.

    readstr = svc->getcurrentproberesponse(&readstrlen);
    if (readstrlen > 0)
      svc->addToServiceFingerprint(svc->currentProbe()->getName(), readstr, 
				   readstrlen);
    startNextProbe(nsp, nsi, SG, svc, false);
    
  } else if (status == NSE_STATUS_EOF) {
    // The jerk closed on us during read request!
    // If this was during the NULL probe, let's (for now) assume
    // the port is TCP wrapped.  Otherwise, we'll treat it as a nomatch
    readstr = svc->getcurrentproberesponse(&readstrlen);
    if (readstrlen > 0)
      svc->addToServiceFingerprint(svc->currentProbe()->getName(), readstr, 
				   readstrlen);
    if (probe->isNullProbe() && readstrlen == 0) {
      // TODO:  Perhaps should do further verification before making this assumption
      end_svcprobe(nsp, PROBESTATE_FINISHED_TCPWRAPPED, SG, svc, nsi);
    } else {

      // Perhaps this service didn't like the particular probe text.
      // We'll try the next one
      startNextProbe(nsp, nsi, SG, svc, true);
    }
  } else if (status == NSE_STATUS_ERROR) {
    // Errors might happen in some cases ... I'll worry about later
    int err = nse_errorcode(nse);
    switch(err) {
    case ECONNRESET:
    case ECONNREFUSED: // weird to get this on a connected socket (shrug) but 
                       // BSD sometimes gives it
    case ECONNABORTED:
      // Jerk hung up on us.  Probably didn't like our probe.  We treat it as with EOF above.
      if (probe->isNullProbe()) {
	// TODO:  Perhaps should do further verification before making this assumption
	end_svcprobe(nsp, PROBESTATE_FINISHED_TCPWRAPPED, SG, svc, nsi);
      } else {
	// Perhaps this service didn't like the particular probe text.  We'll try the 
	// next one
	startNextProbe(nsp, nsi, SG, svc, true);
      }
      break;
    case EHOSTUNREACH:
      // That is funny.  The port scanner listed the port as open.  Maybe it got unplugged, or firewalled us, or did
      // something else nasty during the scan.  Shrug.  I'll give up on this port
      end_svcprobe(nsp, PROBESTATE_INCOMPLETE, SG, svc, nsi);
      break;
#ifndef WIN32
    case EPIPE:
#endif
#ifdef EPROTO
    case EPROTO:
      // EPROTO is suspected to be caused by an active IDS/IPS that forges ICMP
      // type-12 errors ("Parameter problem"). It's been seen in response to the
      // Sqlping probe.
#endif
    case EIO:
      // Usually an SSL error of some sort (those are presently
      // hardcoded to EIO).  I'll just try the next probe.
      startNextProbe(nsp, nsi, SG, svc, true);
      break;
    default:
      fatal("Unexpected error in NSE_TYPE_READ callback.  Error code: %d (%s)", err,
	    strerror(err));
    }
  } else if (status == NSE_STATUS_KILL) {
    /* User probablby specified host_timeout and so the service scan is 
       shutting down */
    end_svcprobe(nsp, PROBESTATE_INCOMPLETE, SG, svc, nsi);
    return;
  } else {
    fatal("Unexpected status (%d) in NSE_TYPE_READ callback.", (int) status);
  }
  
  // We may have room for more pr0bes!
  launchSomeServiceProbes(nsp, SG);
  return;
}


// This is used in processResults to determine whether a FP
// should be printed based on type of match, version intensity, etc.
static int shouldWePrintFingerprint(ServiceNFO *svc) {
  // Never print FP if hardmatched
  if (svc->probe_state == PROBESTATE_FINISHED_HARDMATCHED)
    return 0;

  // If we were called with a version_intensity less than
  // the default, don't bother printing.
  if (o.version_intensity < 7) return 0;

  return 1;
}

// This is passed a completed ServiceGroup which contains the scanning results for every service.
// The function iterates through each finished service and adds the results to Target structure for
// Nmap to output later.

static void processResults(ServiceGroup *SG) {
list<ServiceNFO *>::iterator svc;

 for(svc = SG->services_finished.begin(); svc != SG->services_finished.end(); svc++) {
   if ((*svc)->probe_state != PROBESTATE_FINISHED_NOMATCH) {
     (*svc)->target->ports.setServiceProbeResults((*svc)->portno, (*svc)->proto,
					  (*svc)->probe_state, 
					  (*svc)->probe_matched,
					  (*svc)->tunnel,
					  *(*svc)->product_matched? (*svc)->product_matched : NULL, 
					  *(*svc)->version_matched? (*svc)->version_matched : NULL, 
					  *(*svc)->extrainfo_matched? (*svc)->extrainfo_matched : NULL, 
					  *(*svc)->hostname_matched? (*svc)->hostname_matched : NULL, 
					  *(*svc)->ostype_matched? (*svc)->ostype_matched : NULL, 
					  *(*svc)->devicetype_matched? (*svc)->devicetype_matched : NULL, 
					  shouldWePrintFingerprint(*svc) ? (*svc)->getServiceFingerprint(NULL) : NULL);
   }  else {
       (*svc)->target->ports.setServiceProbeResults((*svc)->portno, (*svc)->proto,
					    (*svc)->probe_state, NULL,
					    (*svc)->tunnel, NULL, NULL, NULL, NULL, NULL, NULL,
					    (*svc)->getServiceFingerprint(NULL));
   }
 }
}

/* Start the timeout clocks of any targets that have probes.  Assumes
   that this is called before any probes have been launched (so they
   are all in services_remaining */
static void startTimeOutClocks(ServiceGroup *SG) {
  list<ServiceNFO *>::iterator svcI;
  Target *target = NULL;
  struct timeval tv;

  gettimeofday(&tv, NULL);
  for(svcI = SG->services_remaining.begin(); 
      svcI != SG->services_remaining.end(); svcI++) {
    target = (*svcI)->target;
    if (!target->timeOutClockRunning())
      target->startTimeOutClock(&tv);
  }
}



// We iterate through SG->services_remaining and remove any with port/protocol
// pairs that are excluded. We use AP->isExcluded() to determine which ports
// are excluded.
static void remove_excluded_ports(AllProbes *AP, ServiceGroup *SG) {
  list<ServiceNFO *>::iterator i, nxt;
  ServiceNFO *svc;

  for(i = SG->services_remaining.begin(); i != SG->services_remaining.end(); i=nxt) {
    nxt = i;
    nxt++;

    svc = *i;
    if (AP->isExcluded(svc->portno, svc->proto)) {

      if (o.debugging) log_write(LOG_PLAIN, "EXCLUDING %d/%s\n", svc->portno,
          IPPROTO2STR(svc->proto));

      svc->target->ports.setServiceProbeResults(svc->portno, svc->proto,
					PROBESTATE_EXCLUDED, NULL, 
					SERVICE_TUNNEL_NONE,
                                        "Excluded from version scan", NULL,
					NULL, NULL, NULL, NULL, NULL);

      SG->services_remaining.erase(i);
      SG->services_finished.push_back(svc);
    }
  }

}


/* Execute a service fingerprinting scan against all open ports of the
   Targets specified. */
int service_scan(vector<Target *> &Targets) {
  // int service_scan(Target *targets[], int num_targets)
  AllProbes *AP;
  ServiceGroup *SG;
  nsock_pool nsp;
  struct timeval now;
  int timeout;
  enum nsock_loopstatus looprc;
  time_t starttime;
  struct timeval starttv;

  if (Targets.size() == 0)
    return 1;

  AP = AllProbes::service_scan_init();


  // Now I convert the targets into a new ServiceGroup
  SG = new ServiceGroup(Targets, AP);

  if (o.override_excludeports) {
    if (o.debugging || o.verbose) log_write(LOG_PLAIN, "Overriding exclude ports option! Some undesirable ports may be version scanned!\n");
  } else {
    remove_excluded_ports(AP, SG);
  }

  startTimeOutClocks(SG);

  if (SG->services_remaining.size() == 0) {
    delete SG;
    return 1;
  }
  
  gettimeofday(&starttv, NULL);
  starttime = time(NULL);
  if (o.verbose) {
    char targetstr[128];
    bool plural = (Targets.size() != 1);
    if (!plural) {
      (*(Targets.begin()))->NameIP(targetstr, sizeof(targetstr));
    } else Snprintf(targetstr, sizeof(targetstr), "%u hosts", (unsigned) Targets.size());

    log_write(LOG_STDOUT, "Scanning %u %s on %s\n", 
	      (unsigned) SG->services_remaining.size(), 
	      (SG->services_remaining.size() == 1)? "service" : "services", 
	      targetstr);
  }

  // Lets create a nsock pool for managing all the concurrent probes
  // Store the servicegroup in there for availability in callbacks
  if ((nsp = nsp_new(SG)) == NULL) {
    fatal("%s() failed to create new nsock pool.", __func__);
  }

  if (o.versionTrace()) {
    nsp_settrace(nsp, NULL, NSOCK_TRACE_LEVEL, o.getStartTime());
  }

#if HAVE_OPENSSL
  /* We don't care about connection security in version detection. */
  nsp_ssl_init_max_speed(nsp);
#endif

  launchSomeServiceProbes(nsp, SG);

  // How long do we have before timing out?
  gettimeofday(&now, NULL);
  timeout = -1;

  // OK!  Lets start our main loop!
  looprc = nsock_loop(nsp, timeout);
  if (looprc == NSOCK_LOOP_ERROR) {
    int err = nsp_geterrorcode(nsp);
    fatal("Unexpected nsock_loop error.  Error code %d (%s)", err, strerror(err));
  }

  nsp_delete(nsp);

  if (o.verbose) {
    char additional_info[128];
    if (SG->num_hosts_timedout == 0)
      Snprintf(additional_info, sizeof(additional_info), "%u %s on %u %s",
		(unsigned) SG->services_finished.size(),  
		(SG->services_finished.size() == 1)? "service" : "services", 
		(unsigned) Targets.size(), (Targets.size() == 1)? "host" : "hosts");
    else Snprintf(additional_info, sizeof(additional_info), "%u %s timed out", 
		   SG->num_hosts_timedout, 
		   (SG->num_hosts_timedout == 1)? "host" : "hosts");
    SG->SPM->endTask(NULL, additional_info);
  }

  // Yeah - done with the service scan.  Now I go through the results
  // discovered, store the important info away, and free up everything
  // else.
  processResults(SG);

  delete SG;

  return 0;
}

