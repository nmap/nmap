
/***************************************************************************
 * nmapfe.c -- Handles widget placement for drawing the main NmapFE GUI    *
 * interface.                                                              *
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

/* Original Author: Zach
 * Mail: key@aye.net
 * IRC: EFNet as zach` or key in #bastards or #neatoelito
 * AIM (Aol): GoldMatrix
 *
 * Change the source as you wish, but leave these comments..
 *
 * Long live Aol and pr: Phreak. <grins>
 */

#ifndef NMAP_H
#define NMAP_H

#if MISSING_GTK
#error "Your system does not appear to have GTK (www.gtk.org) installed.  Thus the Nmap X Front End will not compile.  You should still be able to use Nmap the normal way (via text console).  GUIs are for wimps anyway :)"
#endif

#include <nbase.h>
#include <gtk/gtk.h>

/* #define DEBUG(str) { fprintf(stderr, str); fflush(stderr); } */

typedef struct {
    gchar       *scan;
    gint        scantype;
    gboolean    rootonly;
} Entry;


/* main menu entries */
enum {
  NO_MENU,
  SEP_MENU,
  FILE_MENU	= 100,
  FILEOPEN_MENU,
  FILESAVE_MENU,
  FILEQUIT_MENU,
  VIEW_MENU	= 300,
  VIEWMONO_MENU,
  VIEWCOLOR_MENU,
  VIEWAPPEND_MENU,
  HELP_MENU	= 400,
  HELPHELP_MENU,
  HELPVERSION_MENU,
  HELPABOUT_MENU,
};


/* define this > 0 to be able to use the comfortable callback */
#define SCAN_OFFSET  1

/* scan types: used as actions in a factory-generated menu */
enum {
  NO_SCAN,
  CONNECT_SCAN = SCAN_OFFSET,
  SYN_SCAN,
  PING_SCAN,
  UDP_SCAN,
  FIN_SCAN,
  XMAS_SCAN,
  MAIMON_SCAN,
  NULL_SCAN,
  ACK_SCAN,
  WIN_SCAN,
  PROT_SCAN,
  LIST_SCAN,
  IDLE_SCAN,
  BOUNCE_SCAN
};


/* Throttle types */
enum {
  PARANOID_THROTTLE,
  SNEAKY_THROTTLE,
  POLITE_THROTTLE,
  NORMAL_THROTTLE,
  AGRESSIVE_THROTTLE,
  INSANE_THROTTLE,
  NO_THROTTLE
};

/* Reverse resolving options */
enum {
  ALWAYS_RESOLVE,
  DEFAULT_RESOLVE,
  NEVER_RESOLVE,
  NO_RESOLVE
};

/* scanning mode (which ports/protocols) options */
enum {
  DEFAULT_PROTPORT,
  ALL_PROTPORT,
  FAST_PROTPORT,
  GIVEN_PROTPORT,
  NO_PROTPORT
};

/* output format options */
enum {
  NORMAL_OUTPUT,
  GREP_OUTPUT,
  XML_OUTPUT,
  ALL_OUTPUT,
#if GTK_CHECK_VERSION(2,6,0)
  SEPARATOR,
#endif
  SKIDS_OUTPUT
};


struct NmapFEoptions {
  GtkWidget *scanButton;
  GtkTextBuffer *buffer;
  GtkWidget *targetHost;
  GtkWidget *commandEntry;
  gboolean appendLog;
  guint viewValue;
  gboolean isr00t;
  /* scan types */
  GtkWidget *scanType;
  guint scanValue;
  GtkWidget *scanRelayLabel;
  GtkWidget *scanRelay;
  /* Port/Protocol options */
  GtkWidget *protportFrame;
  GtkWidget *protportLabel;
  GtkWidget *protportRange;
  GtkWidget *protportType;
  guint protportValue;
  /* optional scan extensions */
  GtkWidget *RPCInfo;
  GtkWidget *OSInfo;
  GtkWidget *VersionInfo;
  /* ping types */
  GtkWidget *dontPing;
  GtkWidget *icmpechoPing;
  GtkWidget *icmptimePing;
  GtkWidget *icmpmaskPing;
  GtkWidget *tcpPing;
  GtkWidget *tcpPingLabel;
  GtkWidget *tcpPingPorts;
  GtkWidget *synPing;
  GtkWidget *synPingLabel;
  GtkWidget *synPingPorts;
  GtkWidget *udpPing;
  GtkWidget *udpPingLabel;
  GtkWidget *udpPingPorts;
  /* timing_options */
  GtkWidget *throttleType;
  guint throttleValue;
  GtkWidget *startRtt;
  GtkWidget *startRttTime;
  GtkWidget *minRtt;
  GtkWidget *minRttTime;
  GtkWidget *maxRtt;
  GtkWidget *maxRttTime;
  GtkWidget *hostTimeout;
  GtkWidget *hostTimeoutTime;
  GtkWidget *scanDelay;
  GtkWidget *scanDelayTime;
  GtkWidget *ipv4Ttl;
  GtkWidget *ipv4TtlValue;
  GtkWidget *minPar;
  GtkWidget *minParSocks;
  GtkWidget *maxPar;
  GtkWidget *maxParSocks;
  /* file options */
  GtkWidget *useInputFile;
  GtkWidget *inputFilename;
  GtkWidget *inputBrowse;
  GtkWidget *useOutputFile;
  GtkWidget *outputFilename;
  GtkWidget *outputBrowse;
  GtkWidget *outputFormatLabel;
  GtkWidget *outputFormatType;
  GtkWidget *outputAppend;
  guint outputFormatValue;
  /* DNS options */
  GtkWidget *resolveType;
  guint resolveValue;
  /* verbosity/debugging options */
  GtkWidget *verbose;
  GtkWidget *verboseValue;
  GtkWidget *debug;
  GtkWidget *debugValue;
  /* source options */
  GtkWidget *useSourceDevice;
  GtkWidget *SourceDevice;
  GtkWidget *useSourcePort;
  GtkWidget *SourcePort;
  GtkWidget *useSourceIP;
  GtkWidget *SourceIP;
  GtkWidget *useDecoy;
  GtkWidget *Decoy;
  /* misc. options */
  GtkWidget *useFragments;
  GtkWidget *useIPv6;
  GtkWidget *useOrderedPorts;
  GtkWidget *randomizeHosts;
  GtkWidget *packetTrace;
};

GtkWidget* create_main_win (void);
GtkWidget* create_fileSelection(const char *title, char *filename, void (*action)(), GtkEntry *entry);
GtkWidget* create_helpDialog(void);

#endif /* NMAP_H */
