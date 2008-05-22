
/***************************************************************************
 * utils.h -- Various miscellaneous utility functions which defy           *
 * categorization :)                                                       *
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

#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include "nmap.h"
#ifdef WIN32
#include "mswin32\winclude.h"
#else
#include <sys/types.h>

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <sys/mman.h>
#include "nmap_config.h"
#endif

#if HAVE_UNISTD_H
#include <unistd.h>
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

#include "nbase.h"

#include "nmap_error.h"
#include "global_structures.h"

/* Arithmatic difference modulo 2^32 */
#ifndef MOD_DIFF
#define MOD_DIFF(a,b) ((u32) (MIN((u32)(a) - (u32 ) (b), (u32 )(b) - (u32) (a))))
#endif

/* Arithmatic difference modulo 2^16 */
#ifndef MOD_DIFF_USHORT
#define MOD_DIFF_USHORT(a,b) ((MIN((unsigned short)((unsigned short)(a) - (unsigned short ) (b)), (unsigned short) ((unsigned short )(b) - (unsigned short) (a)))))
#endif
#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

#define NIPQUAD(addr) \
        (((addr) >> 0)  & 0xff), \
        (((addr) >> 8)  & 0xff), \
        (((addr) >> 16) & 0xff), \
        (((addr) >> 24) & 0xff)

#define MAX_PARSE_ARGS 254 /* +1 for integrity checking + 1 for null term */

/* Timeval subtraction in microseconds */
#define TIMEVAL_SUBTRACT(a,b) (((a).tv_sec - (b).tv_sec) * 1000000 + (a).tv_usec - (b).tv_usec)
/* Timeval subtract in milliseconds */
#define TIMEVAL_MSEC_SUBTRACT(a,b) ((((a).tv_sec - (b).tv_sec) * 1000) + ((a).tv_usec - (b).tv_usec) / 1000)
/* Timeval subtract in seconds; truncate towards zero */
#define TIMEVAL_SEC_SUBTRACT(a,b) ((a).tv_sec - (b).tv_sec + (((a).tv_usec < (b).tv_usec) ? - 1 : 0))

/* assign one timeval to another timeval plus some msecs: a = b + msecs */
#define TIMEVAL_MSEC_ADD(a, b, msecs) { (a).tv_sec = (b).tv_sec + ((msecs) / 1000); (a).tv_usec = (b).tv_usec + ((msecs) % 1000) * 1000; (a).tv_sec += (a).tv_usec / 1000000; (a).tv_usec %= 1000000; }
#define TIMEVAL_ADD(a, b, usecs) { (a).tv_sec = (b).tv_sec + ((usecs) / 1000000); (a).tv_usec = (b).tv_usec + ((usecs) % 1000000); (a).tv_sec += (a).tv_usec / 1000000; (a).tv_usec %= 1000000; }

/* Find our if one timeval is before or after another, avoiding the integer
   overflow that can result when doing a TIMEVAL_SUBTRACT on two widely spaced
   timevals. */
#define TIMEVAL_BEFORE(a, b) (((a).tv_sec < (b).tv_sec) || ((a).tv_sec == (b).tv_sec && (a).tv_usec < (b).tv_usec))
#define TIMEVAL_AFTER(a, b) (((a).tv_sec > (b).tv_sec) || ((a).tv_sec == (b).tv_sec && (a).tv_usec > (b).tv_usec))

/* Return num if it is between min and max.  Otherwise return min or
   max (whichever is closest to num), */
template<class T> T box(T bmin, T bmax, T bnum) {
  if (bmin > bmax)
    fatal("box(%d, %d, %d) called (min,max,num)", (int) bmin, (int) bmax, (int) bnum);
  //  assert(bmin <= bmax);
  if (bnum >= bmax)
    return bmax;
  if (bnum <= bmin)
    return bmin;
  return bnum;
}

int wildtest(char *wild, char *test);

void hdump(unsigned char *packet, unsigned int len);
void lamont_hdump(char *cp, unsigned int length);

/* Compare a canonical option name (e.g. "max-scan-delay") with a
   user-generated option such as "max_scan_delay" and returns 0 if the
   two values are considered equivalant (for example, - and _ are
   considered to be the same), nonzero otherwise. */
int optcmp(const char *canonical, const char *instance);

/* Scramble the contents of an array*/
void genfry(unsigned char *arr, int elem_sz, int num_elem);
void shortfry(unsigned short *arr, int num_elem);
/* Like the perl equivialent -- It removes the terminating newline from string
   IF one exists.  It then returns the POSSIBLY MODIFIED string */
char *chomp(char *string);

// Send data to a socket, keep retrying until an error or the full length
// is sent.  Returns -1 if there is an error, or len if the full length was sent.
int Send(int sd, const void *msg, size_t len, int flags);

unsigned int gcd_n_uint(int nvals, unsigned int *val);

int arg_parse(const char *command, char ***argv);
void arg_parse_free(char **argv);

/* Converts an Nmap time specification string into milliseconds.  If
   the string is a plain non-negative number, it is considered to
   already be in milliseconds and is returned.  If it is a number
   followed by 's' (for seconds), 'm' (minutes), or 'h' (hours), the
   number is converted to milliseconds and returned.  If Nmap cannot
   parse the string, it is returned instead. */
long tval2msecs(char *tspec);

/* Convert a string in the format of a roughly C-style string literal
   (e.g. can have \r, \n, \xHH escapes, etc.) into a binary string.
   This is done in-place, and the new (shorter or the same) length is
   stored in newlen.  If parsing fails, NULL is returned, otherwise
   str is returned. */
char *cstring_unescape(char *str, unsigned int *len);

/* This function converts zero-terminated 'txt' string to binary 'data'.
   It is used to parse user input for ip options. Some examples of possible input
   strings and results:
   	'\x01*2\xA2'	-> [0x01,0x01,0xA2]	// with 'x' number is parsed in hex
   	'\01\01\255'	-> [0x01,0x01,0xFF]	// without 'x' its in decimal
   	'\x01\x00*2'	-> [0x01,0x00,0x00]	// '*' is copying char
   	'R'		-> Record Route with 9 slots
   	'S 192.168.0.1 172.16.0.1' -> Strict Route with 2 slots
   	'L 192.168.0.1 172.16.0.1' -> Loose Route with 2 slots
   	'T'		-> Record Timestamp with 9 slots
   	'U'		-> Record Timestamp and Ip Address with 4 slots
*/
int parse_ip_options(char *txt, u8 *data, int datalen, int* firsthopoff, int* lasthopoff);

void bintohexstr(char *buf, int buflen, char *src, int srclen);

char* print_ip_options(u8* ipopt, int ipoptlen);

#ifndef HAVE_STRERROR
char *strerror(int errnum);
#endif

/* mmap() an entire file into the address space.  Returns a pointer
   to the beginning of the file.  The mmap'ed length is returned
   inside the length parameter.  If there is a problem, NULL is
   returned, the value of length is undefined, and errno is set to
   something appropriate.  The user is responsible for doing
   an munmap(ptr, length) when finished with it.  openflags should 
   be O_RDONLY or O_RDWR, or O_WRONLY
*/
char *mmapfile(char *fname, int *length, int openflags);

#ifdef WIN32
int win32_munmap(char *filestr, int filelen);
#endif /* WIN32 */

#endif /* UTILS_H */
