/***************************************************************************
 * utils.h -- Various miscellaneous utility functions which defy           *
 * categorization :)                                                       *
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

#ifndef UTILS_H
#define UTILS_H

#ifndef WIN32
#include <sys/mman.h>
#endif

#include "nbase.h"
#include <assert.h>

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

#define MAX_PARSE_ARGS 254 /* +1 for integrity checking + 1 for null term */

/* Return num if it is between min and max.  Otherwise return min or max
   (whichever is closest to num). */
template<class T> T box(T bmin, T bmax, T bnum) {
  assert(bmin <= bmax);
  if (bnum >= bmax)
    return bmax;
  if (bnum <= bmin)
    return bmin;
  return bnum;
}

int wildtest(const char *wild, const char *test);

void nmap_hexdump(const unsigned char *cp, unsigned int length);

void genfry(unsigned char *arr, int elem_sz, int num_elem);
void shortfry(unsigned short *arr, int num_elem);
char *chomp(char *string);

int Send(int sd, const void *msg, size_t len, int flags);

int arg_parse(const char *command, char ***argv);
void arg_parse_free(char **argv);

char *cstring_unescape(char *str, unsigned int *len);

void bintohexstr(char *buf, int buflen, const char *src, int srclen);

u8 *parse_hex_string(const char *str, size_t *outlen);

int cpe_get_part(const char *cpe);

char *mmapfile(char *fname, s64 *length, int openflags);

#ifdef WIN32
int win32_munmap(char *filestr, int filelen);
#endif /* WIN32 */

#endif /* UTILS_H */

