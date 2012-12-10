
/***************************************************************************
 * nbase_str.c -- string related functings in the nbase library.  These    *
 * were written by fyodor@nmap.org .                                   *
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
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING         *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */

#include "nbase.h"
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#ifndef HAVE_STRCASESTR
char *strcasestr(const char *haystack, const char *pneedle) {
char buf[512];
unsigned int needlelen;
const char *p;
char *needle, *q, *foundto;

/* Should crash if !pneedle -- this is OK */
if (!*pneedle) return (char *) haystack;
if (!haystack) return NULL;

needlelen = (unsigned int) strlen(pneedle);
 if (needlelen >= sizeof(buf)) {
   needle = (char *) safe_malloc(needlelen + 1);
 } else needle = buf;
 p = pneedle; q = needle;
 while((*q++ = tolower((int) (unsigned char) *p++)))
   ;
 p = haystack - 1; foundto = needle;
 while(*++p) {
   if(tolower((int) (unsigned char) *p) == *foundto) {
     if(!*++foundto) {
       /* Yeah, we found it */
       if (needlelen >= sizeof(buf))
         free(needle);
       return (char *) (p - needlelen + 1);
     }
   } else foundto = needle;
 }
 if (needlelen >= sizeof(buf))
   free(needle);
 return NULL;
}
#endif

int Strncpy(char *dest, const char *src, size_t n) {
  strncpy(dest, src, n);
  if (dest[n-1] == '\0')
    return 0;
  dest[n-1] = '\0';
  return -1;
}

int Vsnprintf(char *s, size_t n, const char *fmt, va_list ap)
{
	int ret;

	ret = vsnprintf(s, n, fmt, ap);

	if (ret < 0 || (unsigned) ret >= n)
		s[n - 1] = '\0';

	return ret;
}

int Snprintf(char *s, size_t n, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = Vsnprintf(s, n, fmt, ap);
	va_end(ap);

	return ret;
}

/* vsprintf into a dynamically allocated buffer, similar to asprintf in
   Glibc. Return the length of the buffer or -1 on error. */
int alloc_vsprintf(char **strp, const char *fmt, va_list va) {
  va_list va_tmp;
  char *s;
  int size = 32;
  int n;

  s = NULL;
  size = 32;
  for (;;) {
    s = (char *) safe_realloc(s, size);

#ifdef WIN32
    va_tmp = va;
#else
    va_copy(va_tmp, va);
#endif
    n = vsnprintf(s, size, fmt, va_tmp);

    if (n >= size)
      size = n + 1;
    else if (n < 0)
      size = size * 2;
    else
      break;
  }
  *strp = s;

  return n;
}

/* Trivial function that returns nonzero if all characters in str of length strlength are
   printable (as defined by isprint()) */
int stringisprintable(const char *str, int strlength) {
  int i;
  for(i=0; i < strlength; i++)
    if (!isprint((int) (unsigned char) str[i]))
      return 0;

  return 1;
}

/* Convert non-printable characters to replchar in the string */
void replacenonprintable(char *str, int strlength, char replchar) {
  int i;
  for(i=0; i < strlength; i++)
    if (!isprint((int) (unsigned char) str[i]))
      str[i] = replchar;

  return;
}

/* Returns the position of the last directory separator (slash, also backslash
   on Win32) in a path. Returns -1 if none was found. */
static int find_last_path_separator(const char *path) {
#ifndef WIN32
  const char *PATH_SEPARATORS = "/";
#else
  const char *PATH_SEPARATORS = "\\/";
#endif
  const char *p;

  p = path + strlen(path) - 1;
  while (p >= path) {
    if (strchr(PATH_SEPARATORS, *p) != NULL)
      return (int)(p - path);
    p--;
  }

  return -1;
}

/* Returns the directory name part of a path (everything up to the last
   directory separator). If there is no separator, returns ".". If there is only
   one separator and it is the first character, returns "/". Returns NULL on
   error. The returned string must be freed. */
char *path_get_dirname(const char *path) {
  char *result;
  int i;

  i = find_last_path_separator(path);
  if (i == -1)
    return strdup(".");
  if (i == 0)
    return strdup("/");

  result = (char *) safe_malloc(i + 1);
  strncpy(result, path, i);
  result[i] = '\0';

  return result;
}

/* Returns the file name part of a path (everything after the last directory
   separator). Returns NULL on error. The returned string must be freed. */
char *path_get_basename(const char *path) {
  int i;

  i = find_last_path_separator(path);

  return strdup(path + i + 1);
}
