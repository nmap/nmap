
/***************************************************************************
 * output.cc -- Handles the Nmap output system.  This currently involves   *
 * console-style human readable output, XML output, Script |<iddi3         *
 * output, and the legacy greppable output (used to be called "machine     *
 * readable").  I expect that future output forms (such as HTML) may be    *
 * created by a different program, library, or script using the XML        *
 * output.                                                                 *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2004 Insecure.Com LLC. Nmap       *
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
 * http://www.insecure.org/nmap/ to download Nmap.                         *
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
 * applications and appliances.  These contracts have been sold to many    *
 * security vendors, and generally include a perpetual license as well as  *
 * providing for priority support and updates as well as helping to fund   *
 * the continued development of Nmap technology.  Please email             *
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

#include "output.h"
#include "osscan.h"
#include "NmapOps.h"
#include "NmapOutputTable.h"
#include "MACLookup.h"

#include <string>

/* Workaround for lack of namespace std on HP-UX 11.00 */
namespace std {};
using namespace std;

extern NmapOps o;
static char *logtypes[LOG_TYPES]=LOG_NAMES;


// Creates an XML <service> element for the information given in
// serviceDeduction.  It will be 0-length if none is neccessary.
// returns 0 for success.
static int getServiceXMLBuf(struct serviceDeductions *sd, char *xmlbuf, 
		     unsigned int xmlbuflen) {
  string versionxmlstring;
  char rpcbuf[128];
  char *xml_product = NULL, *xml_version = NULL, *xml_extrainfo = NULL;

  if (xmlbuflen < 1) return -1;
  xmlbuf[0] = '\0';
  if (!sd->name) return 0;

  if (sd->product) {
    xml_product = xml_convert(sd->product);
    versionxmlstring += " product=\"";
    versionxmlstring += xml_product;
    free(xml_product); xml_product = NULL;
    versionxmlstring += '\"';
  }

  if (sd->version) {
    xml_version = xml_convert(sd->version);
    versionxmlstring += " version=\"";
    versionxmlstring += xml_version;
    free(xml_version); xml_version = NULL;
    versionxmlstring += '\"';
  }

  if (sd->extrainfo) {
    xml_extrainfo = xml_convert(sd->extrainfo);
    versionxmlstring += " extrainfo=\"";
    versionxmlstring += xml_extrainfo;
    free(xml_extrainfo); xml_extrainfo = NULL;
    versionxmlstring += '\"';
  }

  if (o.rpcscan && sd->rpc_status == RPC_STATUS_GOOD_PROG) {
    snprintf(rpcbuf, sizeof(rpcbuf), 
	     " rpcnum=\"%li\" lowver=\"%i\" highver=\"%i\" proto=\"rpc\"", 
	     sd->rpc_program, sd->rpc_lowver, sd->rpc_highver);
  } else rpcbuf[0] = '\0';

  snprintf(xmlbuf, xmlbuflen, 
	   "<service name=\"%s\"%s %smethod=\"%s\" conf=\"%d\"%s />", 
	   sd->name,
	   versionxmlstring.c_str(),
	   (sd->service_tunnel == SERVICE_TUNNEL_SSL)? "tunnel=\"ssl\" " : "",
	   (sd->dtype == SERVICE_DETECTION_TABLE)? "table" : "probed", 

	   sd->name_confidence, rpcbuf);

  return 0;
}

/* Fills in namebuf (as long as there is space in buflen) with the
   Name nmap normal output will use to describe the port.  This takes
   into account to confidence level, any SSL tunneling, etc.  Truncates
   namebuf to 0 length if there is no room.*/
static void getNmapServiceName(struct serviceDeductions *sd, int state, 
			       char *namebuf, int buflen) {
  char *dst = namebuf;
  int lenremaining = buflen;
  int len;

  if (buflen < 1) return;

  if (sd->service_tunnel == SERVICE_TUNNEL_SSL) {
    if (lenremaining < 5) goto overflow;
    strncpy(dst, "ssl/", lenremaining);
    dst += 4;
    lenremaining -= 4;
  } 

  if (sd->name && (sd->service_tunnel != SERVICE_TUNNEL_SSL || 
		   sd->dtype == SERVICE_DETECTION_PROBED)) {
    if (o.servicescan && state == PORT_OPEN && sd->name_confidence <= 5) 
      len = snprintf(dst, lenremaining, "%s?", sd->name);
    else len = snprintf(dst, lenremaining, "%s", sd->name);
  } else {
    len = snprintf(dst, lenremaining, "%s", "unknown");
  }
  if (len > lenremaining || len < 0) goto overflow;
  dst += len;
  lenremaining -= len;

  if (lenremaining < 1) goto overflow;
  *dst = '\0';
  return;

 overflow:
  *namebuf = '\0';  
}

/* Prints the familiar Nmap tabular output showing the "interesting"
   ports found on the machine.  It also handles the Machine/Greppable
   output and the XML output.  It is pretty ugly -- in particular I
   should write helper functions to handle the table creation */
void printportoutput(Target *currenths, PortList *plist) {
  char protocol[4];
  char rpcinfo[64];
  char rpcmachineinfo[64];
  char portinfo[64];
  char xmlbuf[512];
  char grepvers[256];
  char grepown[64];
  char *p;
  char *state;
  char serviceinfo[64];
  char *name=NULL;
  int i;
  int first = 1;
  struct protoent *proto;
  Port *current;
  int numignoredports;
  int portno, protocount;
  Port **protoarrays[2];
  char hostname[1200];
  int istate = plist->getIgnoredPortState();
  numignoredports = plist->state_counts[istate];
  struct serviceDeductions sd;
  NmapOutputTable *Tbl = NULL;
  int portcol = -1; // port or IP protocol #
  int statecol = -1; // port/protocol state
  int servicecol = -1; // service or protocol name
  int versioncol = -1;
  //  int ownercol = -1; // Used for ident scan
  int colno = 0;
  unsigned int rowno;
  int numrows;
  vector<const char *> saved_servicefps;

  assert(numignoredports <= plist->numports);


  log_write(LOG_XML, "<ports><extraports state=\"%s\" count=\"%d\" />\n", 
	    statenum2str(istate), 
	    numignoredports);

  if (numignoredports == plist->numports) {
    log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,
              "%s %d scanned %s on %s %s: %s\n",
	      (numignoredports == 1)? "The" : "All", numignoredports,
	      (numignoredports == 1)? "port" : "ports", 
	      currenths->NameIP(hostname, sizeof(hostname)), 
	      (numignoredports == 1)? "is" : "are", statenum2str(istate));
    log_write(LOG_MACHINE,"Host: %s (%s)\tStatus: Up", 
	      currenths->targetipstr(), currenths->HostName());
    log_write(LOG_XML, "</ports>\n");
    return;
  }

  log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"Interesting %s on %s:\n",
	    (o.ipprotscan)? "protocols" : "ports", 
	    currenths->NameIP(hostname, sizeof(hostname)));
  log_write(LOG_MACHINE,"Host: %s (%s)", currenths->targetipstr(), 
	    currenths->HostName());
  
  if (numignoredports > 0) {
    log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"(The %d %s%s scanned but not shown below %s in state: %s)\n", numignoredports, o.ipprotscan?"protocol":"port", (numignoredports == 1)? "" : "s", (numignoredports == 1)? "is" : "are", statenum2str(istate));
  }

  /* OK, now it is time to deal with the service table ... */
  colno = 0;
  portcol = colno++;
  statecol = colno++;
  servicecol = colno++;
  /*  if (o.identscan)
      ownercol = colno++; */
  if (o.servicescan || o.rpcscan)
    versioncol = colno++;

  numrows = plist->state_counts[PORT_CLOSED] + 
    plist->state_counts[PORT_OPEN] + plist->state_counts[PORT_FILTERED] + 
    plist->state_counts[PORT_UNFILTERED] + 
    plist->state_counts[PORT_OPENFILTERED] + 
    plist->state_counts[PORT_CLOSEDFILTERED];
  if (istate != PORT_UNKNOWN)
    numrows -=  plist->state_counts[istate];
  assert(numrows > 0);
  numrows++; // The header counts as a row

  Tbl = new NmapOutputTable(numrows, colno);

  // Lets start with the headers
  if (o.ipprotscan)
    Tbl->addItem(0, portcol, false, "PROTOCOL", 8);
  else Tbl->addItem(0, portcol, false, "PORT", 4);

  Tbl->addItem(0, statecol, false, "STATE", 5);
  Tbl->addItem(0, servicecol, false, "SERVICE", 7);
  if (versioncol > 0)
    Tbl->addItem(0, versioncol, false, "VERSION", 7);
  /*  if (ownercol > 0)
      Tbl->addItem(0, ownercol, false, "OWNER", 5); */

  log_write(LOG_MACHINE,"\t%s: ", (o.ipprotscan)? "Protocols" : "Ports" );
  
  protoarrays[0] = plist->tcp_ports;
  protoarrays[1] = plist->udp_ports;
  current = NULL;
  rowno = 1;
  if (o.ipprotscan) {
    for (portno = 0; portno < 256; portno++) {
      if (!plist->ip_prots[portno]) continue;
      current = plist->ip_prots[portno];
      if (current->state != istate) {
	if (!first) log_write(LOG_MACHINE,", ");
	else first = 0;
	state = statenum2str(current->state);
	proto = nmap_getprotbynum(htons(current->portno));
	snprintf(portinfo, sizeof(portinfo), "%-24s",
		 proto?proto->p_name: "unknown");
	Tbl->addItemFormatted(rowno, portcol, "%d", portno);
	Tbl->addItem(rowno, statecol, true, state);
	Tbl->addItem(rowno, servicecol, true, portinfo);
	log_write(LOG_MACHINE,"%d/%s/%s/", current->portno, state, 
		  (proto)? proto->p_name : "");
	log_write(LOG_XML, "<port protocol=\"ip\" portid=\"%d\"><state state=\"%s\" />", current->portno, state);
	if (proto && proto->p_name && *proto->p_name)
	  log_write(LOG_XML, "\n<service name=\"%s\" conf=\"8\" method=\"table\" />", proto->p_name);
	log_write(LOG_XML, "</port>\n");
	rowno++;
      }
    }
  } else {
   for(portno = 0; portno < 65536; portno++) {
    for(protocount = 0; protocount < 2; protocount++) {
      if (protoarrays[protocount] && protoarrays[protocount][portno]) 
	current = protoarrays[protocount][portno];
      else continue;
      
      if (current->state != istate) {    
	if (!first) log_write(LOG_MACHINE,", ");
	else first = 0;
	strcpy(protocol,(current->proto == IPPROTO_TCP)? "tcp": "udp");
	snprintf(portinfo, sizeof(portinfo), "%d/%s", current->portno, protocol);
	state = statenum2str(current->state);
	current->getServiceDeductions(&sd);
	if (sd.service_fp && saved_servicefps.size() <= 8)
	  saved_servicefps.push_back(sd.service_fp);

	if (o.rpcscan) {
	  switch(sd.rpc_status) {
	  case RPC_STATUS_UNTESTED:
	    rpcinfo[0] = '\0';
	    strcpy(rpcmachineinfo, "");
	    break;
	  case RPC_STATUS_UNKNOWN:
	    strcpy(rpcinfo, "(RPC (Unknown Prog #))");
	    strcpy(rpcmachineinfo, "R");
	    break;
	  case RPC_STATUS_NOT_RPC:
	    rpcinfo[0] = '\0';
	    strcpy(rpcmachineinfo, "N");
	    break;
	  case RPC_STATUS_GOOD_PROG:
	    name = nmap_getrpcnamebynum(sd.rpc_program);
	    snprintf(rpcmachineinfo, sizeof(rpcmachineinfo), "(%s:%li*%i-%i)", (name)? name : "", sd.rpc_program, sd.rpc_lowver, sd.rpc_highver);
	    if (!name) {
	      snprintf(rpcinfo, sizeof(rpcinfo), "(#%li (unknown) V%i-%i)", sd.rpc_program, sd.rpc_lowver, sd.rpc_highver);
	    } else {
	      if (sd.rpc_lowver == sd.rpc_highver) {
		snprintf(rpcinfo, sizeof(rpcinfo), "(%s V%i)", name, sd.rpc_lowver);
	      } else 
		snprintf(rpcinfo, sizeof(rpcinfo), "(%s V%i-%i)", name, sd.rpc_lowver, sd.rpc_highver);
	    }
	    break;
	  default:
	    fatal("Unknown rpc_status %d", sd.rpc_status);
	    break;
	  }
	  snprintf(serviceinfo, sizeof(serviceinfo), "%s%s%s", (sd.name)? sd.name : ((*rpcinfo)? "" : "unknown"), (sd.name)? " " : "",  rpcinfo);
	} else {
	  getNmapServiceName(&sd, current->state, serviceinfo, sizeof(serviceinfo));
	  rpcmachineinfo[0] = '\0';
	}
	Tbl->addItem(rowno, portcol, true, portinfo);
	Tbl->addItem(rowno, statecol, false, state);
	Tbl->addItem(rowno, servicecol, true, serviceinfo);
	/*	if (current->owner)
		Tbl->addItem(rowno, ownercol, true, current->owner); */
	if (*sd.fullversion)
	  Tbl->addItem(rowno, versioncol, true, sd.fullversion);

	// How should we escape illegal chars in grepable output?
	// Well, a reasonably clean way would be backslash escapes
	// such as \/ and \\ .  // But that makes it harder to pick
	// out fields with awk, cut, and such.  So I'm gonna use the
	// ugly hat (fitting to grepable output) or replacing the '/'
	// character with '|' in the version and owner fields.
	Strncpy(grepvers, sd.fullversion, 
		sizeof(grepvers) / sizeof(*grepvers));
	p = grepvers;
	while((p = strchr(p, '/'))) {
	  *p = '|';
	  p++;
	}
	if (!current->owner) *grepown = '\0';
	else {
	  Strncpy(grepown, current->owner, 
		  sizeof(grepown) / sizeof(*grepown));
	  p = grepown;
	  while((p = strchr(p, '/'))) {
	    *p = '|';
	    p++;
	  }
	}
	if (!sd.name) serviceinfo[0] = '\0';
	else {
	  p = serviceinfo;
	  while((p = strchr(p, '/'))) {
	    *p = '|';
	    p++;
	  }
	}
	log_write(LOG_MACHINE,"%d/%s/%s/%s/%s/%s/%s/", current->portno, state, 
		  protocol, grepown, serviceinfo, rpcmachineinfo, grepvers);    
	
	log_write(LOG_XML, "<port protocol=\"%s\" portid=\"%d\">", protocol, current->portno);
	log_write(LOG_XML, "<state state=\"%s\" />", state);
	if (current->owner && *current->owner) {
	  log_write(LOG_XML, "<owner name=\"%s\" />", current->owner);
	}
	if (getServiceXMLBuf(&sd, xmlbuf, sizeof(xmlbuf)) == 0)
	  if (*xmlbuf)
	    log_write(LOG_XML, "%s", xmlbuf);
	log_write(LOG_XML, "</port>\n");
	rowno++;
      }
    }
   }
  }
  /*  log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"\n"); */
  if (plist->state_counts[istate] > 0)
    log_write(LOG_MACHINE, "\tIgnored State: %s (%d)", statenum2str(istate), plist->state_counts[istate]);
  log_write(LOG_XML, "</ports>\n");

  // Now we write the table for the user
  log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT, "%s", Tbl->printableTable(NULL));
  delete Tbl;

  // There may be service fingerprints I would like the user to submit
  if (saved_servicefps.size() > 0) {
    int numfps = saved_servicefps.size();
log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT, "%d service%s unrecognized despite returning data. If you know the service/version, please submit the following fingerprint%s at http://www.insecure.org/cgi-bin/servicefp-submit.cgi :\n", numfps, (numfps > 1)? "s" : "", (numfps > 1)? "s" : "");
    for(i=0; i < numfps; i++) {
      if (numfps > 1)
	log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT, "==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============\n");
      log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT, "%s\n", saved_servicefps[i]);
    }
  }

}

char* xml_convert (const char* str) {
  char *temp, ch=0, prevch = 0, *p;
  temp = (char *) malloc(strlen(str)*6+1);
  for (p = temp;(prevch = ch, ch = *str);str++) {
    char *a;
    switch (ch) {
    case '<':
      a = "&lt;";
      break;
    case '>':
      a = "&gt;";
      break;
    case '&':
      a =  "&amp;";
      break;
    case '"':
      a = "&quot;";
      break;
    case '\'':
      a = "&apos;";
      break;
    case '-': 
      if (prevch == '-') { /* Must escape -- for comments */
        a =  "&#45;";
        break;
      }
    default:
      *p++ = ch;
      continue;
    }
    strcpy(p,a); p += strlen(a);
  }
  *p = 0;
  temp = (char *) realloc(temp,strlen(temp)+1);
  return temp;
}

/* Write some information (printf style args) to the given log stream(s).
 Remember to watch out for format string bugs.  */
void log_write(int logt, const char *fmt, ...)
{
  va_list  ap;
  int i,l=logt,skid=1;
  char b[4096];
  char *buf = b;
  int bufsz = sizeof(b);
  bool buf_alloced = false;
  int rc = 0;

  if (l & LOG_STDOUT) {
    va_start(ap, fmt);
    vfprintf(o.nmap_stdout, fmt, ap);
    va_end(ap);
    l-=LOG_STDOUT;
  }
  if (l & LOG_SKID_NOXLT) { skid=0; l -= LOG_SKID_NOXLT; l |= LOG_SKID; }
  if (l<0 || l>LOG_MASK) return;
  for (i=0;l;l>>=1,i++)
    {
      if (!o.logfd[i] || !(l&1)) continue;
      while(1) {
	va_start(ap, fmt);
	rc = vsnprintf(buf,bufsz, fmt, ap);
	va_end(ap);
	if (rc >= 0 && rc < bufsz)
	  break; // Successful
	// D'oh!  Apparently not enough space - lets try a bigger buffer
	bufsz = (rc > bufsz)? rc + 1 : bufsz * 2;
	buf = (char *) safe_realloc(buf_alloced? buf : NULL, bufsz);
	buf_alloced = true;
      } 
      if (skid && ((1<<i)&LOG_SKID)) skid_output(buf);
      fwrite(buf,1,strlen(buf),o.logfd[i]);
    }

  if (buf_alloced)
    free(buf);
}

/* Close the given log stream(s) */
void log_close(int logt)
{
  int i;
  if (logt<0 || logt>LOG_MASK) return;
  for (i=0;logt;logt>>=1,i++) if (o.logfd[i] && (logt&1)) fclose(o.logfd[i]);
}

/* Flush the given log stream(s).  In other words, all buffered output
   is written to the log immediately */
void log_flush(int logt) {
  int i;

  if (logt & LOG_STDOUT) {
    fflush(o.nmap_stdout);
    logt -= LOG_STDOUT;
  }
  if (logt & LOG_SKID_NOXLT)
    fatal("You are not allowed to log_flush() with LOG_SKID_NOXLT");

  if (logt<0 || logt>LOG_MASK) return;

  for (i=0;logt;logt>>=1,i++)
    {
      if (!o.logfd[i] || !(logt&1)) continue;
      fflush(o.logfd[i]);
    }

}

/* Flush every single log stream -- all buffered output is written to the
   corresponding logs immediately */
void log_flush_all() {
  int fileno;

  for(fileno = 0; fileno < LOG_TYPES; fileno++) {
    if (o.logfd[fileno]) fflush(o.logfd[fileno]);
  }
  fflush(stdout);
  fflush(stderr);
}

/* Open a log descriptor of the type given to the filename given.  If 
   append is nonzero, the file will be appended instead of clobbered if
   it already exists.  If the file does not exist, it will be created */
int log_open(int logt, int append, char *filename)
{
  int i=0;
  if (logt<=0 || logt>LOG_MASK) return -1;
  while ((logt&1)==0) { i++; logt>>=1; }
  if (o.logfd[i]) fatal("Only one %s output filename allowed",logtypes[i]);
  if (*filename == '-' && *(filename + 1) == '\0')
    {
      o.logfd[i]=stdout;
      o.nmap_stdout = fopen(DEVNULL, "w");
      if (!o.nmap_stdout)
	fatal("Could not assign %s to stdout for writing", DEVNULL);
  }
  else
    {
      if (o.append_output)
	o.logfd[i] = fopen(filename, "a");
      else
	o.logfd[i] = fopen(filename, "w");
      if (!o.logfd[i])
	fatal("Failed to open %s output file %s for writing", logtypes[i], filename);
    }
  return 1;
}

/* Used in creating skript kiddie style output.  |<-R4d! */
void skid_output(char *s)
{
  int i;
  for (i=0;s[i];i++)
    if (rand()%2==0)
      /* Substitutions commented out are not known to me, but maybe look nice */
      switch(s[i])
	{
	case 'A': s[i]='4'; break;
	  /*	case 'B': s[i]='8'; break;
	 	case 'b': s[i]='6'; break;
	        case 'c': s[i]='k'; break;
	        case 'C': s[i]='K'; break; */
	case 'e':
	case 'E': s[i]='3'; break;
	case 'i':
	case 'I': s[i]="!|1"[rand()%3]; break;
	  /*      case 'k': s[i]='c'; break;
	        case 'K': s[i]='C'; break;*/
	case 'o':
	case 'O': s[i]='0'; break;
	case 's':
	case 'S': 
	  if (s[i+1] && !isalnum((int) s[i+1])) 
	    s[i] = 'z';
	  else s[i] = '$';
	  break;
	case 'z': s[i]='s'; break;
	case 'Z': s[i]='S'; break;
	}  
    else
      {
	if (s[i]>='A' && s[i]<='Z' && (rand()%3==0)) s[i]+='a'-'A';
	else if (s[i]>='a' && s[i]<='z' && (rand()%3==0)) s[i]-='a'-'A';
      }
}

/* The items in ports should be
   in sequential order for space savings and easier to read output.  Outputs
   the rangelist to the log stream given (such as LOG_MACHINE or LOG_XML) */
void output_rangelist_given_ports(int logt, unsigned short *ports,
						    int numports) {
int i, previous_port = -2, range_start = -2, port;
char outpbuf[128];

 for(i=0; i <= numports; i++) {
   port = (i < numports)? ports[i] : 0xABCDE;
   if (port != previous_port + 1) {
     outpbuf[0] = '\0';
     if (range_start != previous_port && range_start != -2)
       sprintf(outpbuf, "-%hu", previous_port);
     if (port != 0xABCDE) {
       if (range_start != -2)
	 strcat(outpbuf, ",");
       sprintf(outpbuf + strlen(outpbuf), "%hu", port);
     }
     log_write(logt, "%s", outpbuf);
     range_start = port;
   }
   previous_port = port;
 }
}

/* Output the list of ports scanned to the top of machine parseable
   logs (in a comment, unfortunately).  The items in ports should be
   in sequential order for space savings and easier to read output */
void output_ports_to_machine_parseable_output(struct scan_lists *ports, 
					      int tcpscan, int udpscan,
					      int protscan) {
  int tcpportsscanned = ports->tcp_count;
  int udpportsscanned = ports->udp_count;
  int protsscanned = ports->prot_count;
 log_write(LOG_MACHINE, "# Ports scanned: TCP(%d;", tcpportsscanned);
 if (tcpportsscanned)
   output_rangelist_given_ports(LOG_MACHINE, ports->tcp_ports, tcpportsscanned);
 log_write(LOG_MACHINE, ") UDP(%d;", udpportsscanned);
 if (udpportsscanned)
   output_rangelist_given_ports(LOG_MACHINE, ports->udp_ports, udpportsscanned);
 log_write(LOG_MACHINE, ") PROTOCOLS(%d;", protsscanned);
 if (protsscanned)
   output_rangelist_given_ports(LOG_MACHINE, ports->prots, protsscanned);
 log_write(LOG_MACHINE, ")\n");
}

/* Simple helper function for output_xml_scaninfo_records */
static void doscaninfo(char *type, char *proto, unsigned short *ports, 
		  int numports) {
  log_write(LOG_XML, "<scaninfo type=\"%s\" protocol=\"%s\" numservices=\"%d\" services=\"", type, proto, numports);
  output_rangelist_given_ports(LOG_XML, ports, numports);
  log_write(LOG_XML, "\" />\n");
}

/* Similar to output_ports_to_machine_parseable_output, this function
   outputs the XML version, which is scaninfo records of each scan
   requested and the ports which it will scan for */
void output_xml_scaninfo_records(struct scan_lists *scanlist) {
  if (o.synscan) 
    doscaninfo("syn", "tcp", scanlist->tcp_ports, scanlist->tcp_count);
  if (o.ackscan) 
    doscaninfo("ack", "tcp", scanlist->tcp_ports, scanlist->tcp_count);
  if (o.bouncescan) 
    doscaninfo("bounce", "tcp", scanlist->tcp_ports, scanlist->tcp_count);
  if (o.connectscan)
    doscaninfo("connect", "tcp", scanlist->tcp_ports, scanlist->tcp_count);
  if (o.nullscan)
    doscaninfo("null", "tcp", scanlist->tcp_ports, scanlist->tcp_count);
  if (o.xmasscan)
    doscaninfo("xmas", "tcp", scanlist->tcp_ports, scanlist->tcp_count);
  if (o.windowscan)
    doscaninfo("window", "tcp", scanlist->tcp_ports, scanlist->tcp_count);
  if (o.maimonscan) 
    doscaninfo("maimon", "tcp", scanlist->tcp_ports, scanlist->tcp_count);
  if (o.finscan) 
    doscaninfo("fin", "tcp", scanlist->tcp_ports, scanlist->tcp_count);
  if (o.udpscan) 
    doscaninfo("udp", "udp", scanlist->udp_ports, scanlist->udp_count);
  if (o.ipprotscan) 
    doscaninfo("ipproto", "ip", scanlist->prots, scanlist->prot_count); 
}

/* Helper function to write the status and address/hostname info of a host 
   into the XML log */
static void write_xml_initial_hostinfo(Target *currenths,
				  const char *status) {
  
  log_write(LOG_XML, "<status state=\"%s\" />\n<address addr=\"%s\" addrtype=\"%s\" />\n", status,currenths->targetipstr(), (o.af() == AF_INET)? "ipv4" : "ipv6");
  print_MAC_XML_Info(currenths);
  if (*currenths->HostName()) {
    log_write(LOG_XML, "<hostnames><hostname name=\"%s\" type=\"PTR\" /></hostnames>\n", currenths->HostName());
  } else /* If machine is up, put blank hostname so front ends know that
	    no name resolution is forthcoming */
    if (strcmp(status, "up") == 0) log_write(LOG_XML, "<hostnames />\n");
}

/* Writes host status info to the log streams (including STDOUT).  An
   example is "Host: 10.11.12.13 (foo.bar.example.com)\tStatus: Up\n" to 
   machine log.  resolve_all should be passed nonzero if the user asked
   for all hosts (even down ones) to be resolved */
void write_host_status(Target *currenths, int resolve_all) {
  char hostname[1200];

  if (o.listscan) {
    /* write "unknown" to stdout, machine, and xml */
    log_write(LOG_STDOUT|LOG_NORMAL|LOG_SKID, "Host %s not scanned\n", currenths->NameIP(hostname, sizeof(hostname)));
    log_write(LOG_MACHINE, "Host: %s (%s)\tStatus: Unknown\n", currenths->targetipstr(), currenths->HostName());
    write_xml_initial_hostinfo(currenths, "unknown");
  } 

  else if (currenths->wierd_responses) { /* SMURF ADDRESS */
    /* Write xml "down" or "up" based on flags and the smurf info */
    write_xml_initial_hostinfo(currenths, 
			       (currenths->flags & HOST_UP)? "up" : "down");
    log_write(LOG_XML, "<smurf responses=\"%d\" />\n", 
	      currenths->wierd_responses);
    log_write(LOG_MACHINE,"Host: %s (%s)\tStatus: Smurf (%d responses)\n",  currenths->targetipstr(), currenths->HostName(), currenths->wierd_responses);
    
    if (o.pingscan)
      log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"Host %s seems to be a subnet broadcast address (returned %d extra pings).%s\n",  currenths->NameIP(hostname, sizeof(hostname)), currenths->wierd_responses, 
		(currenths->flags & HOST_UP)? " Note -- the actual IP also responded." : "");
    else {
      log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"Host %s seems to be a subnet broadcast address (returned %d extra pings). %s.\n",  
		currenths->NameIP(hostname, sizeof(hostname)),
		currenths->wierd_responses,
	       (currenths->flags & HOST_UP)? 
		" Still scanning it due to ping response from its own IP" 
		: "Skipping host");
    }
  } 

  else if (o.pingscan) {
    write_xml_initial_hostinfo(currenths, 
			       (currenths->flags & HOST_UP)? "up" : "down");
    if (currenths->flags & HOST_UP) {
      log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"Host %s appears to be up.\n", currenths->NameIP(hostname, sizeof(hostname)));
      log_write(LOG_MACHINE,"Host: %s (%s)\tStatus: Up\n", currenths->targetipstr(), currenths->HostName());
    } else if (o.verbose || resolve_all) {
      if (resolve_all)
	log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"Host %s appears to be down.\n", currenths->NameIP(hostname, sizeof(hostname)));
      else log_write(LOG_STDOUT,"Host %s appears to be down.\n", currenths->NameIP(hostname, sizeof(hostname)));
      log_write(LOG_MACHINE, "Host: %s (%s)\tStatus: Down\n", currenths->targetipstr(), currenths->HostName());
    }
  } 

  else {   /* Normal case (non ping/list scan or smurf address) */
    write_xml_initial_hostinfo(currenths, 
			       (currenths->flags & HOST_UP)? "up" : "down");
    if (o.verbose) {
      if (currenths->flags & HOST_UP) {
	log_write(LOG_STDOUT, "Host %s appears to be up ... good.\n", 
		  currenths->NameIP(hostname, sizeof(hostname)));
      } else {

	if (resolve_all) {   
	  log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"Host %s appears to be down, skipping it.\n", currenths->NameIP(hostname, sizeof(hostname)));
	}
	else {
	  log_write(LOG_STDOUT,"Host %s appears to be down, skipping it.\n", currenths->NameIP(hostname, sizeof(hostname)));
	}
	log_write(LOG_MACHINE, "Host: %s (%s)\tStatus: Down\n", currenths->targetipstr(), currenths->HostName());
      }
    }
  }
}

/* Returns -1 if adding the entry is not possible because it would
   overflow.  Otherwise it returns the new number of entries.  Note
   that only unique entries are added.  Also note that *numentries is
   incremented if the candidate is added.  arrsize is the number of
   char * members that fit into arr */
static int addtochararrayifnew(char *arr[], int *numentries, int arrsize, char *candidate) {
  int i;

  // First lets see if the member already exists
  for(i=0; i < *numentries; i++) {
    if (strcmp(arr[i], candidate) == 0)
      return *numentries;
  }

  // Not already there... do we have room for a new one?
  if (*numentries >= arrsize )
    return -1;

  // OK, not already there and we have room, so we'll add it.
  arr[*numentries] = candidate;
  (*numentries)++;
  return *numentries;
}

/* guess is true if we should print guesses */
#define MAX_OS_CLASSMEMBERS 8
static void printosclassificationoutput(const struct OS_Classification_Results *OSR, bool guess) {
  int classno, i, familyno;
   int overflow = 0; /* Whether we have too many devices to list */
  char *types[MAX_OS_CLASSMEMBERS];
  char fullfamily[MAX_OS_CLASSMEMBERS][128]; // "[vendor] [os family]"
  double familyaccuracy[MAX_OS_CLASSMEMBERS]; // highest accuracy for this fullfamily
  char familygenerations[MAX_OS_CLASSMEMBERS][48]; // example: "4.X|5.X|6.X"
  int numtypes = 0, numfamilies=0;
  char tmpbuf[1024];

  for(i=0; i < MAX_OS_CLASSMEMBERS; i++) {
    familygenerations[i][0] = '\0';
    familyaccuracy[i] = 0.0;
  }

  if (OSR->overall_results == OSSCAN_SUCCESS) {

    /* Print the OS Classification results to XML output */
    for (classno=0; classno < OSR->OSC_num_matches; classno++) {
      // Because the OS_Generation filed is optional
      if (OSR->OSC[classno]->OS_Generation) {
	snprintf(tmpbuf, sizeof(tmpbuf), " osgen=\"%s\"", OSR->OSC[classno]->OS_Generation);
      } else tmpbuf[0] = '\0';
      {
	char *xml_type, *xml_vendor, *xml_class;
	xml_type = xml_convert(OSR->OSC[classno]->Device_Type);
	xml_vendor = xml_convert(OSR->OSC[classno]->OS_Vendor);
	xml_class = xml_convert(OSR->OSC[classno]->OS_Family);
	log_write(LOG_XML, "<osclass type=\"%s\" vendor=\"%s\" osfamily=\"%s\"%s accuracy=\"%d\" />\n", xml_type, xml_vendor, xml_class, tmpbuf, (int) (OSR->OSC_Accuracy[classno] * 100));
	free(xml_type);
	free(xml_vendor);
	free(xml_class);
      }
    }

    // Now to create the fodder for normal output
    for (classno=0; classno < OSR->OSC_num_matches; classno++) {
      /* We have processed enough if any of the following are true */
      if (!guess && OSR->OSC_Accuracy[classno] < 1.0 ||
	  OSR->OSC_Accuracy[classno] <= OSR->OSC_Accuracy[0] - 0.1 ||
	  OSR->OSC_Accuracy[classno] < 1.0 && classno > 9)
	break;
      if (addtochararrayifnew(types, &numtypes, MAX_OS_CLASSMEMBERS, OSR->OSC[classno]->Device_Type) == -1)
	overflow = 1;
      
      // If family and vendor names are the same, no point being redundant
      if (strcmp(OSR->OSC[classno]->OS_Vendor, OSR->OSC[classno]->OS_Family) == 0)
	Strncpy(tmpbuf, OSR->OSC[classno]->OS_Family, sizeof(tmpbuf));
      else snprintf(tmpbuf, sizeof(tmpbuf), "%s %s", OSR->OSC[classno]->OS_Vendor, OSR->OSC[classno]->OS_Family);
      
      
      // Let's see if it is already in the array
      for(familyno = 0; familyno < numfamilies; familyno++) {
	if (strcmp(fullfamily[familyno], tmpbuf) == 0) {
	  // got a match ... do we need to add the generation?
	  if (OSR->OSC[classno]->OS_Generation && !strstr(familygenerations[familyno], OSR->OSC[classno]->OS_Generation)) {
	    // We add it, preceded by | if something is already there
	    if (strlen(familygenerations[familyno]) + 2 + strlen(OSR->OSC[classno]->OS_Generation) >= 48) fatal("buffer 0verfl0w of familygenerations");
	    if (*familygenerations[familyno]) strcat(familygenerations[familyno], "|");
	    strcat(familygenerations[familyno], OSR->OSC[classno]->OS_Generation);
	  }
	  break;
	}
      }
      
      if (familyno == numfamilies) {
	// Looks like the new family is not in the list yet.  Do we have room to add it?
	if (numfamilies >= MAX_OS_CLASSMEMBERS) {
	  overflow = 1;
	  break;
	}
	
	// Have space, time to add...
	Strncpy(fullfamily[numfamilies], tmpbuf, 128);
	if (OSR->OSC[classno]->OS_Generation)
	  Strncpy(familygenerations[numfamilies], OSR->OSC[classno]->OS_Generation, 48);
	familyaccuracy[numfamilies] = OSR->OSC_Accuracy[classno];
	numfamilies++;
      }
    }
    
    if (!overflow && numfamilies >= 1) {
      log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT, "Device type: ");
      for(classno=0; classno < numtypes; classno++)
	log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT, "%s%s", types[classno], (classno < numtypes - 1)? "|" : "");
      log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT, "\nRunning%s: ", (familyaccuracy[0] < 1.0)? " (JUST GUESSING) " : "");
      for(familyno = 0; familyno < numfamilies; familyno++) {
	if (familyno > 0) log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT, ", ");
	log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT, "%s", fullfamily[familyno]);
	if (*familygenerations[familyno]) log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT, " %s", familygenerations[familyno]);
	if (familyaccuracy[familyno] < 1.0) log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT, " (%d%%)", (int) (familyaccuracy[familyno] * 100));
      }
      log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT, "\n");
    }
  }
  return;
}

/* Prints the MAC address if one was found for the target (generally
   this means that the target is directly connected on an ethernet
   network.  This only prints to human output -- XML is handled by a
   separate call ( print_MAC_XML_Info ) because it needs to be printed
   in a certain place to conform to DTD. */
void printmacinfo(Target *currenths) {
  const u8 *mac = currenths->MACAddress();
  char macascii[32];

  if (mac) {
    const char *macvendor = MACPrefix2Corp(mac);
    snprintf(macascii, sizeof(macascii), "%02X:%02X:%02X:%02X:%02X:%02X",  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT, "MAC Address: %s (%s)\n", macascii, macvendor? macvendor : "Unknown");
  }
}

/* Prints the MAC address (if discovered) to XML output */
void print_MAC_XML_Info(Target *currenths) {
  const u8 *mac = currenths->MACAddress();
  char macascii[32];
  char vendorstr[128];
  char *xml_mac = NULL;

  if (mac) {
    const char *macvendor = MACPrefix2Corp(mac);
    snprintf(macascii, sizeof(macascii), "%02X:%02X:%02X:%02X:%02X:%02X",
	     mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    if (macvendor) {
      xml_mac = xml_convert(macvendor);
      snprintf(vendorstr, sizeof(vendorstr), " vendor=\"%s\"", xml_mac);
      free(xml_mac);
    } else vendorstr[0] = '\0';
    log_write(LOG_XML, "<address addr=\"%s\" addrtype=\"mac\"%s />\n", macascii, vendorstr);
  }
}


/* Prints the formatted OS Scan output to stdout, logfiles, etc (but only
   if an OS Scan was performed */
void printosscanoutput(Target *currenths) {
  int i;
  char numlst[512]; /* For creating lists of numbers */
  char *p; /* Used in manipulating numlst above */

  if (currenths->osscan_performed && currenths->FPR != NULL) {
    log_write(LOG_XML, "<os>");
    if (currenths->FPR->osscan_opentcpport > 0) {
      log_write(LOG_XML, 
		"<portused state=\"open\" proto=\"tcp\" portid=\"%hu\" />\n",
		currenths->FPR->osscan_opentcpport);
    }
    if (currenths->FPR->osscan_closedtcpport > 0) {
      log_write(LOG_XML, 
		"<portused state=\"closed\" proto=\"tcp\" portid=\"%hu\" />\n",
		currenths->FPR->osscan_closedtcpport);
    }

    // If the FP can't be submitted anyway, might as well make a guess.
    printosclassificationoutput(currenths->FPR->getOSClassification(), 
				o.osscan_guess || !currenths->FPR->fingerprintSuitableForSubmission());
    
    if (currenths->FPR->overall_results == OSSCAN_SUCCESS && currenths->FPR->num_perfect_matches <= 8) {
      if (currenths->FPR->num_perfect_matches > 0) {
        char *p;
	log_write(LOG_MACHINE,"\tOS: %s",  currenths->FPR->prints[0]->OS_name);
	log_write(LOG_XML, "<osmatch name=\"%s\" accuracy=\"100\" />\n", 
		  p = xml_convert(currenths->FPR->prints[0]->OS_name));
        free(p);
	i = 1;
	while(currenths->FPR->accuracy[i] == 1 ) {
	  log_write(LOG_MACHINE,"|%s", currenths->FPR->prints[i]->OS_name);
	  log_write(LOG_XML, "<osmatch name=\"%s\" accuracy=\"100\" />\n", 
		    p = xml_convert(currenths->FPR->prints[i]->OS_name));
          free(p);
	  i++;
	}
	
	if (currenths->FPR->num_perfect_matches == 1)
	  log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,
		    "OS details: %s", 
		    currenths->FPR->prints[0]->OS_name);
	
	else {
	  log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,
		    "OS details: %s", 
		    currenths->FPR->prints[0]->OS_name);
	  i = 1;
	  while(currenths->FPR->accuracy[i] == 1) {
	    log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,", %s", 
		      currenths->FPR->prints[i]->OS_name);
	    i++;
	  }
	}
      } else {
	if ((o.osscan_guess || !currenths->FPR->fingerprintSuitableForSubmission()) && 
	    currenths->FPR->num_matches > 0) {
	  /* Print the best guesses available */
	  log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"Aggressive OS guesses: %s (%d%%)", currenths->FPR->prints[0]->OS_name, (int) (currenths->FPR->accuracy[0] * 100));
	  for(i=1; i < 10 && currenths->FPR->num_matches > i &&
		currenths->FPR->accuracy[i] > 
		currenths->FPR->accuracy[0] - 0.10; i++) {
            char *p;
	    log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,", %s (%d%%)", currenths->FPR->prints[i]->OS_name, (int) (currenths->FPR->accuracy[i] * 100));
	    log_write(LOG_XML, "<osmatch name=\"%s\" accuracy=\"%d\" />\n", 
		      p = xml_convert(currenths->FPR->prints[i]->OS_name),  
		      (int) (currenths->FPR->accuracy[i] * 100));
            free(p);
	  }
	  log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT, "\n");
	}
	if (currenths->FPR->fingerprintSuitableForSubmission()) {
	  log_write(LOG_NORMAL|LOG_SKID_NOXLT|LOG_STDOUT,"No exact OS matches for host (If you know what OS is running on it, see http://www.insecure.org/cgi-bin/nmap-submit.cgi).\nTCP/IP fingerprint:\n%s\n", mergeFPs(currenths->FPR->FPs, currenths->FPR->numFPs, currenths->FPR->osscan_opentcpport, currenths->FPR->osscan_closedtcpport, currenths->MACAddress()));
	} else {
	  log_write(LOG_NORMAL|LOG_SKID_NOXLT|LOG_STDOUT,"No exact OS matches for host (test conditions non-ideal).");
	  if (o.verbose > 1)
	    log_write(LOG_NORMAL|LOG_SKID_NOXLT|LOG_STDOUT, "\nTCP/IP fingerprint:\n%s", mergeFPs(currenths->FPR->FPs, currenths->FPR->numFPs, currenths->FPR->osscan_opentcpport, currenths->FPR->osscan_closedtcpport, currenths->MACAddress()));
	}
      }
      
      log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"\n");	  
      if (currenths->FPR->goodFP >= 0 && (o.debugging || o.verbose > 1) && currenths->FPR->num_perfect_matches > 0 ) {
	log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"OS Fingerprint:\n%s\n", fp2ascii(currenths->FPR->FPs[currenths->FPR->goodFP]));
      }
    } else if (currenths->FPR->overall_results == OSSCAN_NOMATCHES) {
      if (o.scan_delay < 500  && currenths->FPR->osscan_opentcpport > 0 &&
	  currenths->FPR->osscan_closedtcpport > 0 ) {
	log_write(LOG_NORMAL|LOG_SKID_NOXLT|LOG_STDOUT,"No OS matches for host (If you know what OS is running on it, see http://www.insecure.org/cgi-bin/nmap-submit.cgi).\nTCP/IP fingerprint:\n%s\n", mergeFPs(currenths->FPR->FPs, currenths->FPR->numFPs, currenths->FPR->osscan_opentcpport, currenths->FPR->osscan_closedtcpport, currenths->MACAddress()));
      } else {
	log_write(LOG_NORMAL|LOG_SKID_NOXLT|LOG_STDOUT,"No OS matches for host (test conditions non-ideal).\nTCP/IP fingerprint:\n%s\n", mergeFPs(currenths->FPR->FPs, currenths->FPR->numFPs, currenths->FPR->osscan_opentcpport, currenths->FPR->osscan_closedtcpport, currenths->MACAddress()));
      }
    } else if (currenths->FPR->overall_results == OSSCAN_TOOMANYMATCHES || currenths->FPR->num_perfect_matches > 8)
      {
	log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"Too many fingerprints match this host to give specific OS details\n");
	if (o.debugging || o.verbose) {
	  log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"TCP/IP fingerprint:\n%s",  mergeFPs(currenths->FPR->FPs, currenths->FPR->numFPs, currenths->FPR->osscan_opentcpport, currenths->FPR->osscan_closedtcpport, currenths->MACAddress()));
	}
      } else { assert(0); }
    
    log_write(LOG_XML, "</os>\n");

     if (currenths->seq.lastboot) {
       char tmbuf[128];
       struct timeval tv;
       gettimeofday(&tv, NULL);
       strncpy(tmbuf, ctime(&(currenths->seq.lastboot)), sizeof(tmbuf));
       chomp(tmbuf);
       log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"Uptime %.3f days (since %s)\n", (double) (tv.tv_sec - currenths->seq.lastboot) / 86400, tmbuf);
       log_write(LOG_XML, "<uptime seconds=\"%li\" lastboot=\"%s\" />\n", tv.tv_sec - currenths->seq.lastboot, tmbuf);
     }

     if (currenths->seq.responses > 3) {
       p=numlst;
       for(i=0; i < currenths->seq.responses; i++) {
	 if (p - numlst > (int) (sizeof(numlst) - 15)) 
	   fatal("STRANGE ERROR #3877 -- please report to fyodor@insecure.org\n");
	 if (p != numlst) *p++=',';
	 sprintf(p, "%X", currenths->seq.seqs[i]);
	 while(*p) p++;
       }

       log_write(LOG_XML, "<tcpsequence index=\"%li\" class=\"%s\" difficulty=\"%s\" values=\"%s\" />\n", (long) currenths->seq.index, seqclass2ascii(currenths->seq.seqclass), seqidx2difficultystr(currenths->seq.index), numlst); 
       if (o.verbose)
	 log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"%s", seqreport(&(currenths->seq)));
       log_write(LOG_MACHINE,"\tSeq Index: %d", currenths->seq.index);
     }

     if (currenths->seq.responses > 2) {
       p=numlst;
       for(i=0; i < currenths->seq.responses; i++) {
	 if (p - numlst > (int) (sizeof(numlst) - 15)) 
	   fatal("STRANGE ERROR #3876 -- please report to fyodor@insecure.org\n");
	 if (p != numlst) *p++=',';
	 sprintf(p, "%hX", currenths->seq.ipids[i]);
	 while(*p) p++;
       }
       log_write(LOG_XML, "<ipidsequence class=\"%s\" values=\"%s\" />\n", ipidclass2ascii(currenths->seq.ipid_seqclass), numlst);
       if (o.verbose)
	 log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"IPID Sequence Generation: %s\n", ipidclass2ascii(currenths->seq.ipid_seqclass));
       log_write(LOG_MACHINE,"\tIPID Seq: %s", ipidclass2ascii(currenths->seq.ipid_seqclass));

       p=numlst;
       for(i=0; i < currenths->seq.responses; i++) {
	 if (p - numlst > (int) (sizeof(numlst) - 15)) 
	   fatal("STRANGE ERROR #3877 -- please report to fyodor@insecure.org\n");
	 if (p != numlst) *p++=',';
	 sprintf(p, "%X", currenths->seq.timestamps[i]);
	 while(*p) p++;
       }
       
       log_write(LOG_XML, "<tcptssequence class=\"%s\"", tsseqclass2ascii(currenths->seq.ts_seqclass));
       if (currenths->seq.ts_seqclass != TS_SEQ_UNSUPPORTED) {
	 log_write(LOG_XML, " values=\"%s\"", numlst);
       }
       log_write(LOG_XML, " />\n");
     }
  }
}

/* Prints the statistics and other information that goes at the very end
   of an Nmap run */
void printfinaloutput(int numhosts_scanned, int numhosts_up, 
		      time_t starttime) {
  time_t timep;
  int i;
  char mytime[128];
  struct timeval tv;
  char statbuf[128];
  gettimeofday(&tv, NULL);
  timep = time(NULL);
  i = timep - starttime;
  
  if (numhosts_scanned == 0)
    fprintf(stderr, "WARNING: No targets were specified, so 0 hosts scanned.\n");
  if (numhosts_scanned == 1 && numhosts_up == 0 && !o.listscan)
    log_write(LOG_STDOUT, "Note: Host seems down. If it is really up, but blocking our ping probes, try -P0\n");
  /*  log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"\n"); */
  log_write(LOG_STDOUT|LOG_SKID, "Nmap finished: %d %s (%d %s up) scanned in %.3f seconds\n", numhosts_scanned, (numhosts_scanned == 1)? "IP address" : "IP addresses", numhosts_up, (numhosts_up == 1)? "host" : "hosts",  o.TimeSinceStartMS(&tv) / 1000.0);
  if (o.verbose && o.isr00t && o.RawScan()) 
    log_write(LOG_STDOUT|LOG_SKID, "               %s\n", 
	      getFinalPacketStats(statbuf, sizeof(statbuf)));

  Strncpy(mytime, ctime(&timep), sizeof(mytime));
  chomp(mytime);
  
  log_write(LOG_XML, "<runstats><finished time=\"%lu\" timestr=\"%s\"/><hosts up=\"%d\" down=\"%d\" total=\"%d\" />\n", (unsigned long) timep, mytime, numhosts_up, numhosts_scanned - numhosts_up, numhosts_scanned);

  log_write(LOG_XML, "<!-- Nmap run completed at %s; %d %s (%d %s up) scanned in %.3f seconds -->\n", mytime, numhosts_scanned, (numhosts_scanned == 1)? "IP address" : "IP addresses", numhosts_up, (numhosts_up == 1)? "host" : "hosts",  o.TimeSinceStartMS(&tv) / 1000.0 );
  log_write(LOG_NORMAL|LOG_MACHINE, "# Nmap run completed at %s -- %d %s (%d %s up) scanned in %.3f seconds\n", mytime, numhosts_scanned, (numhosts_scanned == 1)? "IP address" : "IP addresses", numhosts_up, (numhosts_up == 1)? "host" : "hosts", o.TimeSinceStartMS(&tv) / 1000.0 );

  log_write(LOG_XML, "</runstats></nmaprun>\n");

}



