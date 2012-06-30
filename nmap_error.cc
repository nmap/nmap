
/***************************************************************************
 * nmap_error.cc -- Some simple error handling routines.                   *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2012 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 with the clarifications and exceptions described  *
 * below.  This guarantees your right to use, modify, and redistribute     *
 * this software under certain conditions.  If you wish to embed Nmap      *
 * technology into proprietary software, we sell alternative licenses      *
 * (contact sales@insecure.com).  Dozens of software vendors already       *
 * license Nmap technology such as host discovery, port scanning, OS       *
 * detection, version detection, and the Nmap Scripting Engine.            *
 *                                                                         *
 * Note that the GPL places important restrictions on "derived works", yet *
 * it does not provide a detailed definition of that term.  To avoid       *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
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
 * works of Nmap, as well as other software we distribute under this       *
 * license such as Zenmap, Ncat, and Nping.  This list is not exclusive,   *
 * but is meant to clarify our interpretation of derived works with some   *
 * common examples.  Our interpretation applies only to Nmap--we don't     *
 * speak for other people's GPL works.                                     *
 *                                                                         *
 * If you have any questions about the GPL licensing restrictions on using *
 * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
 * we also offer alternative license to integrate Nmap into proprietary    *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates.  They also fund the      *
 * continued development of Nmap.  Please email sales@insecure.com for     *
 * further information.                                                    *
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License v2.0 for more details at                         *
 * http://www.gnu.org/licenses/gpl-2.0.html , or in the COPYING file       *
 * included with Nmap.                                                     *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */

#include "nmap_error.h"
#include "output.h"
#include "NmapOps.h"
#include "xml.h"

extern NmapOps o;

#ifdef WIN32
#include <windows.h>
#endif /* WIN32 */


void fatal(const char *fmt, ...) {
  time_t timep;
  struct timeval tv;
  va_list  ap;

  gettimeofday(&tv, NULL);
  timep = time(NULL);

  va_start(ap, fmt);
  log_vwrite(LOG_STDERR, fmt, ap);
  va_end(ap);
  va_start(ap, fmt);
  log_vwrite(LOG_NORMAL, fmt, ap);
  va_end(ap);

  log_write(LOG_NORMAL|LOG_STDERR, "\nQUITTING!\n");

  if (xml_tag_open())
    xml_close_start_tag();
  if (!xml_root_written())
    xml_start_tag("nmaprun");
  /* Close all open XML elements but one. */
  while (xml_depth() > 1) {
    xml_end_tag();
    xml_newline();
  }
  if (xml_depth() == 1) {
    char errbuf[1024];

    va_start(ap, fmt);
    Vsnprintf(errbuf, sizeof(errbuf), fmt, ap);
    va_end(ap);

    xml_start_tag("runstats");
    print_xml_finished_open(timep, &tv);
    xml_attribute("exit", "error");
    xml_attribute("errormsg", "%s", errbuf);
    xml_close_empty_tag();

    print_xml_hosts();
    xml_newline();

    xml_end_tag(); /* runstats */
    xml_newline();

    xml_end_tag(); /* nmaprun */
    xml_newline();
  }

  exit(1);
}

void error(const char *fmt, ...) {
  va_list  ap;

  va_start(ap, fmt);
  log_vwrite(LOG_STDERR, fmt, ap);
  va_end(ap);
  va_start(ap, fmt);
    log_vwrite(LOG_NORMAL, fmt, ap);
    va_end(ap);
  log_write(LOG_NORMAL|LOG_STDERR , "\n");
  return;
}

void pfatal(const char *fmt, ...) {
  time_t timep;
  struct timeval tv;
  va_list ap;
  int error_number;
  char errbuf[1024], *strerror_s;

#ifdef WIN32
  error_number = GetLastError();
  FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM, 
		NULL, error_number, MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR) &strerror_s,  0, NULL);
#else
  error_number = errno;
  strerror_s = strerror(error_number);
#endif

  gettimeofday(&tv, NULL);
  timep = time(NULL);

  va_start(ap, fmt);
  Vsnprintf(errbuf, sizeof(errbuf), fmt, ap);
  va_end(ap);

  log_write(LOG_NORMAL|LOG_STDERR, "%s: %s (%d)\n",
	    errbuf, strerror_s, error_number);

  if (xml_tag_open())
    xml_close_start_tag();
  if (!xml_root_written())
    xml_start_tag("nmaprun");
  /* Close all open XML elements but one. */
  while (xml_depth() > 1) {
    xml_end_tag();
    xml_newline();
  }
  if (xml_depth() == 1) {
    xml_start_tag("runstats");
    print_xml_finished_open(timep, &tv);
    xml_attribute("exit", "error");
    xml_attribute("errormsg", "%s: %s (%d)", errbuf, strerror_s, error_number);
    xml_close_empty_tag();

    print_xml_hosts();
    xml_newline();

    xml_end_tag(); /* runstats */
    xml_newline();

    xml_end_tag(); /* nmaprun */
    xml_newline();
  }

#ifdef WIN32
  HeapFree(GetProcessHeap(), 0, strerror_s);
#endif

  log_flush(LOG_NORMAL);
  fflush(stderr);
  exit(1);
}

/* This function is the Nmap version of perror. It is like pfatal, but it
   doesn't write to XML and it only returns, doesn't exit. */
void gh_perror(const char *fmt, ...) {
  va_list ap;
  int error_number;
  char *strerror_s;

#ifdef WIN32
  error_number = GetLastError();
  FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM, 
		NULL, error_number, MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR) &strerror_s,  0, NULL);
#else
  error_number = errno;
  strerror_s = strerror(error_number);
#endif
  
  va_start(ap, fmt);
  log_vwrite(LOG_STDERR, fmt, ap);
  va_end(ap);
  va_start(ap, fmt);
      log_vwrite(LOG_NORMAL, fmt, ap);
      va_end(ap);
  log_write(LOG_NORMAL|LOG_STDERR, ": %s (%d)\n",
    strerror_s, error_number);

#ifdef WIN32
  HeapFree(GetProcessHeap(), 0, strerror_s);
#endif

  log_flush(LOG_NORMAL);
  fflush(stderr);
  return;
}
