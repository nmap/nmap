
/***************************************************************************
 * output.h -- Handles the Nmap output system.  This currently involves    *
 * console-style human readable output, XML output, Script |<iddi3         *
 * output, and the legacy greppable output (used to be called "machine     *
 * readable").  I expect that future output forms (such as HTML) may be    *
 * created by a different program, library, or script using the XML        *
 * output.                                                                 *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2008 Insecure.Com LLC. Nmap is    *
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
 * works of Nmap.  This list is not exclusive, but is just meant to        *
 * clarify our interpretation of derived works with some common examples.  *
 * These restrictions only apply when you actually redistribute Nmap.  For *
 * example, nothing stops you from writing and selling a proprietary       *
 * front-end to Nmap.  Just distribute it by itself, and point people to   *
 * http://nmap.org to download Nmap.                                       *
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

#ifndef OUTPUT_H
#define OUTPUT_H

#define LOG_NUM_FILES 4 /* # of values that actual files (they must come first */
#define LOG_FILE_MASK 15 /* The mask for log typs in the file array */
#define LOG_NORMAL 1
#define LOG_MACHINE 2
#define LOG_SKID 4
#define LOG_XML 8
#define LOG_STDOUT 1024
#define LOG_STDERR 2048
#define LOG_SKID_NOXLT 4096
#define LOG_MAX LOG_SKID_NOXLT /* The maximum log type value */

#define LOG_PLAIN LOG_NORMAL|LOG_SKID|LOG_STDOUT

#define LOG_NAMES {"normal", "machine", "$Cr!pT |<!dd!3", "XML"}

#include "portlist.h"
#include "nmap.h"
#include "global_structures.h"

/* Prints the familiar Nmap tabular output showing the "interesting"
   ports found on the machine.  It also handles the Machine/Greppable
   output and the XML output.  It is pretty ugly -- in particular I
   should write helper functions to handle the table creation */
void printportoutput(Target *currenths, PortList *plist);

/* Prints the MAC address if one was found for the target (generally
   this means that the target is directly connected on an ethernet
   network.  This only prints to human output -- XML is handled by a
   separate call ( print_MAC_XML_Info ) because it needs to be printed
   in a certain place to conform to DTD. */
void printmacinfo(Target *currenths);

char *logfilename(const char *str, struct tm *tm);

/* Write some information (printf style args) to the given log stream(s).
   Remember to watch out for format string bugs. */
void log_write(int logt, const char *fmt, ...)
     __attribute__ ((format (printf, 2, 3)));

/* This is the workhorse of the logging functions.  Usually it is
   called through log_write(), but it can be called directly if you
   are dealing with a vfprintf-style va_list.  Unlike log_write, YOU
   CAN ONLY CALL THIS WITH ONE LOG TYPE (not a bitmask full of them).
   In addition, YOU MUST SANDWHICH EACH EXECUTION IF THIS CALL BETWEEN
   va_start() AND va_end() calls. */
void log_vwrite(int logt, const char *fmt, va_list ap);

/* Close the given log stream(s) */
void log_close(int logt);

/* Flush the given log stream(s).  In other words, all buffered output
   is written to the log immediately */
void log_flush(int logt);

/* Flush every single log stream -- all buffered output is written to the
   corresponding logs immediately */
void log_flush_all();

/* Open a log descriptor of the type given to the filename given.  If 
   append is nonzero, the file will be appended instead of clobbered if
   it already exists.  If the file does not exist, it will be created */
int log_open(int logt, int append, char *filename);

/* Output the list of ports scanned to the top of machine parseable
   logs (in a comment, unfortunately).  The items in ports should be
   in sequential order for space savings and easier to read output */
void output_ports_to_machine_parseable_output(struct scan_lists *ports, 
					      int tcpscan, int udpscan,
					      int protscan);

/* Similar to output_ports_to_machine_parseable_output, this function
   outputs the XML version, which is scaninfo records of each scan
   requested and the ports which it will scan for */
void output_xml_scaninfo_records(struct scan_lists *ports);

/* Writes host status info to the log streams (including STDOUT).  An
   example is "Host: 10.11.12.13 (foo.bar.example.com)\tStatus: Up\n" to 
   machine log.  resolve_all should be passed nonzero if the user asked
   for all hosts (even down ones) to be resolved */
void write_host_status(Target *currenths, int resolve_all);

/* Prints the formatted OS Scan output to stdout, logfiles, etc (but only
   if an OS Scan was performed */
void printosscanoutput(Target *currenths);

/* Prints the alternate hostname/OS/device information we got from the
   service scan (if it was performed) */
void printserviceinfooutput(Target *currenths);

void printhostscriptresults(Target *currenths);
char* formatScriptOutput(ScriptResult sr);

/* Print a detailed list of Nmap interfaces and routes to
   normal/skiddy/stdout output */
int print_iflist(void);

/* Prints a status message while the program is running */
void printStatusMessage();

/* Prints the statistics and other information that goes at the very end
   of an Nmap run */
void printfinaloutput();

/* Prints the names of data files that were loaded and the paths at which they
   were found. */
void printdatafilepaths();

char* xml_convert (const char* str);
#endif /* OUTPUT_H */
