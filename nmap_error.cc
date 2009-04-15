
/***************************************************************************
 * nmap_error.cc -- Some simple error handling routines.                   *
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

#include "nmap_error.h"
#include "output.h"
#include "NmapOps.h"

extern NmapOps o;

#ifdef WIN32
#include <windows.h>
#endif /* WIN32 */

void fatal(const char *fmt, ...) {
  va_list  ap;
  va_start(ap, fmt);
  log_vwrite(LOG_STDERR, fmt, ap);
  va_end(ap);
  if (o.log_errors) {
    va_start(ap, fmt);
    log_vwrite(LOG_NORMAL, fmt, ap);
    va_end(ap);
  }
  log_write(o.log_errors? LOG_NORMAL|LOG_STDERR : LOG_STDERR, "\nQUITTING!\n");
  exit(1);
}

void error(const char *fmt, ...) {
  va_list  ap;

  va_start(ap, fmt);
  log_vwrite(LOG_STDERR, fmt, ap);
  va_end(ap);
  
  if (o.log_errors) {
    va_start(ap, fmt);
    log_vwrite(LOG_NORMAL, fmt, ap);
    va_end(ap);
  }
  log_write(o.log_errors? LOG_NORMAL|LOG_STDERR : LOG_STDERR, "\n");
  return;
}

void pfatal(const char *err, ...) {
#ifdef WIN32
  int lasterror =0;
  char *errstr = NULL;
#endif
  va_list ap;
  
  va_start(ap, err);
  log_vwrite(LOG_STDERR, err, ap);
  va_end(ap);

  if (o.log_errors) {
    va_start(ap, err);
    log_vwrite(LOG_NORMAL, err, ap);
    va_end(ap);
  }

#ifdef WIN32
  lasterror = GetLastError();
  FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM, 
		NULL, lasterror, MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR) &errstr,  0, NULL);
  log_write(o.log_errors? LOG_NORMAL|LOG_STDERR : LOG_STDERR, ": %s (%d)\n", 
	    errstr, lasterror);
  HeapFree(GetProcessHeap(), 0, errstr);
#else
  log_write(o.log_errors? LOG_NORMAL|LOG_STDERR : LOG_STDERR, ": %s (%d)\n", 
	    strerror(errno), errno);
#endif /* WIN32 perror() compatability switch */
  if (o.log_errors) log_flush(LOG_NORMAL);
  fflush(stderr);
  exit(1);
}

/* This function is the Nmap version of perror.  It is just copy and
   pasted from pfatal(), except the exit has been replaced with a
   return. */
void gh_perror(const char *err, ...) {
#ifdef WIN32
  int lasterror =0;
  char *errstr = NULL;
#endif
  va_list ap;
  
  va_start(ap, err);
  log_vwrite(LOG_STDERR, err, ap);
  va_end(ap);

  if (o.log_errors) {
    va_start(ap, err);
    log_vwrite(LOG_NORMAL, err, ap);
    va_end(ap);
  }

#ifdef WIN32
  lasterror = GetLastError();
  FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM, 
		NULL, lasterror, MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR) &errstr,  0, NULL);
  log_write(o.log_errors? LOG_NORMAL|LOG_STDERR : LOG_STDERR, ": %s (%d)\n", 
	    errstr, lasterror);
  HeapFree(GetProcessHeap(), 0, errstr);
#else
  log_write(o.log_errors? LOG_NORMAL|LOG_STDERR : LOG_STDERR, ": %s (%d)\n", 
	    strerror(errno), errno);
#endif /* WIN32 perror() compatability switch */
  if (o.log_errors) log_flush(LOG_NORMAL);
  fflush(stderr);
  return;
}
