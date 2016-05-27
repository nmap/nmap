
/***************************************************************************
 * output.h -- Handles the Nmap output system.  This currently involves    *
 * console-style human readable output, XML output, Script |<iddi3         *
 * output, and the legacy grepable output (used to be called "machine      *
 * readable").  I expect that future output forms (such as HTML) may be    *
 * created by a different program, library, or script using the XML        *
 * output.                                                                 *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2016 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE CLARIFICATIONS  *
 * AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your right to use,    *
 * modify, and redistribute this software under certain conditions.  If    *
 * you wish to embed Nmap technology into proprietary software, we sell    *
 * alternative licenses (contact sales@nmap.com).  Dozens of software      *
 * vendors already license Nmap technology such as host discovery, port    *
 * scanning, OS detection, version detection, and the Nmap Scripting       *
 * Engine.                                                                 *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files, such as Nmap's nmap-os-db   *
 * or nmap-service-probes.                                                 *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * Nmap with other software in compressed or archival form does not        *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * As another special exception to the GPL terms, Insecure.Com LLC grants  *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two.                                  *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * Nmap or grant special permissions to use it in other open source        *
 * software.  Please contact fyodor@nmap.org with any such requests.       *
 * Similarly, we don't incorporate incompatible open source software into  *
 * Covered Software without special permission from the copyright holders. *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * Nmap in other works, are happy to help.  As mentioned above, we also    *
 * offer alternative license to integrate Nmap into proprietary            *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates.  They also fund the      *
 * continued development of Nmap.  Please email sales@nmap.com for further *
 * information.                                                            *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to the dev@nmap.org mailing list for possible incorporation into the    *
 * main distribution.  By sending these changes to Fyodor or one of the    *
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the Nmap      *
 * license file for more details (it's in a COPYING file included with     *
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING)        *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */

#ifndef OUTPUT_H
#define OUTPUT_H

#define LOG_NUM_FILES 4 /* # of values that actual files (they must come first */
#define LOG_FILE_MASK 15 /* The mask for log types in the file array */
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

#define PCAP_OPEN_ERRMSG "Call to pcap_open_live() failed three times. "\
"There are several possible reasons for this, depending on your operating "\
"system:\nLINUX: If you are getting Socket type not supported, try "\
"modprobe af_packet or recompile your kernel with PACKET enabled.\n "\
 "*BSD:  If you are getting device not configured, you need to recompile "\
 "your kernel with Berkeley Packet Filter support.  If you are getting "\
 "No such file or directory, try creating the device (eg cd /dev; "\
 "MAKEDEV <device>; or use mknod).\n*WINDOWS:  Nmap only supports "\
 "ethernet interfaces on Windows for most operations because Microsoft "\
 "disabled raw sockets as of Windows XP SP2.  Depending on the reason for "\
 "this error, it is possible that the --unprivileged command-line argument "\
 "will help.\nSOLARIS:  If you are trying to scan localhost or the "\
 "address of an interface and are getting '/dev/lo0: No such file or "\
 "directory' or 'lo0: No DLPI device found', complain to Sun.  I don't "\
 "think Solaris can support advanced localhost scans.  You can probably "\
 "use \"-Pn -sT localhost\" though.\n\n"

#include "nmap.h"
#ifndef NOLUA
#include "nse_main.h"
#endif
#include <nsock.h>
class PortList;
class Target;

#include <stdarg.h>
#include <string>

#ifdef WIN32
/* Show a fatal error explaining that an interface is not Ethernet and won't
   work on Windows. Do nothing if --send-ip (PACKET_SEND_IP_STRONG) was used. */
void win32_fatal_raw_sockets(const char *devname);
#endif

/* Prints the familiar Nmap tabular output showing the "interesting"
   ports found on the machine.  It also handles the Machine/Grepable
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
   In addition, YOU MUST SANDWICH EACH EXECUTION OF THIS CALL BETWEEN
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
void output_ports_to_machine_parseable_output(struct scan_lists *ports);

/* Return a std::string containing all n strings separated by whitespace, and
   individually quoted if needed. */
std::string join_quoted(const char * const strings[], unsigned int n);

/* Similar to output_ports_to_machine_parseable_output, this function
   outputs the XML version, which is scaninfo records of each scan
   requested and the ports which it will scan for */
void output_xml_scaninfo_records(struct scan_lists *ports);

/* Writes a heading for a full scan report ("Nmap scan report for..."),
   including host status and DNS records. */
void write_host_header(Target *currenths);

/* Writes host status info to the log streams (including STDOUT).  An
   example is "Host: 10.11.12.13 (foo.bar.example.com)\tStatus: Up\n" to
   machine log. */
void write_host_status(Target *currenths);

/* Prints the formatted OS Scan output to stdout, logfiles, etc (but only
   if an OS Scan was performed */
void printosscanoutput(Target *currenths);

/* Prints the alternate hostname/OS/device information we got from the
   service scan (if it was performed) */
void printserviceinfooutput(Target *currenths);

#ifndef NOLUA
std::string protect_xml(const std::string s);

/* Use this function to report NSE_PRE_SCAN and NSE_POST_SCAN results */
void printscriptresults(ScriptResults *scriptResults, stype scantype);

void printhostscriptresults(Target *currenths);
#endif

/* Print a table with traceroute hops. */
void printtraceroute(Target *currenths);

/* Print "times for host" output with latency. */
void printtimes(Target *currenths);

/* Print a detailed list of Nmap interfaces and routes to
   normal/skiddy/stdout output */
int print_iflist(void);

/* Prints a status message while the program is running */
void printStatusMessage();

void print_xml_finished_open(time_t timep, const struct timeval *tv);

void print_xml_hosts();

/* Prints the statistics and other information that goes at the very end
   of an Nmap run */
void printfinaloutput();

/* Prints the names of data files that were loaded and the paths at which they
   were found. */
void printdatafilepaths();

/* nsock logging interface */
void nmap_adjust_loglevel(bool trace);
void nmap_nsock_stderr_logger(const struct nsock_log_rec *rec);

#endif /* OUTPUT_H */

