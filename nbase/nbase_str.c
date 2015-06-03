
/***************************************************************************
 * nbase_str.c -- string related functions in the nbase library.  These    *
 * were written by fyodor@nmap.org .                                       *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2015 Insecure.Com LLC. Nmap is    *
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

#include "nbase.h"
#include <assert.h>
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
  if (!*pneedle)
    return (char *)haystack;
  if (!haystack)
    return NULL;

  needlelen = (unsigned int)strlen(pneedle);
  if (needlelen >= sizeof(buf))
    needle = (char *)safe_malloc(needlelen + 1);
  else
    needle = buf;

  p = pneedle;
  q = needle;

  while ((*q++ = tolower((int)(unsigned char)*p++)))
    ;

  p = haystack - 1;
  foundto = needle;
  while (*++p) {
    if (tolower((int)(unsigned char)*p) == *foundto) {
      if (!*++foundto) {
        /* Yeah, we found it */
        if (needlelen >= sizeof(buf))
          free(needle);
        return (char *)(p - needlelen + 1);
      }
    } else
      foundto = needle;
  }
  if (needlelen >= sizeof(buf))
    free(needle);
  return NULL;
}
#endif

int Strncpy(char *dest, const char *src, size_t n) {
  strncpy(dest, src, n);
  if (dest[n - 1] == '\0')
    return 0;
  dest[n - 1] = '\0';
  return -1;
}

int Vsnprintf(char *s, size_t n, const char *fmt, va_list ap) {
  int ret;

  ret = vsnprintf(s, n, fmt, ap);

  if (ret < 0 || (unsigned)ret >= n)
    s[n - 1] = '\0';

  return ret;
}

int Snprintf(char *s, size_t n, const char *fmt, ...) {
  va_list ap;
  int ret;

  va_start(ap, fmt);
  ret = Vsnprintf(s, n, fmt, ap);
  va_end(ap);

  return ret;
}

/* Make a new allocated null-terminated string from the bytes [start, end). */
char *mkstr(const char *start, const char *end) {
  char *s;

  assert(end >= start);
  s = (char *)safe_malloc(end - start + 1);
  memcpy(s, start, end - start);
  s[end - start] = '\0';

  return s;
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
    s = (char *)safe_realloc(s, size);

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

/* Used by escape_windows_command_arg to append a character to the given buffer
   at a given position, resizing the buffer if necessary. The position gets
   moved by one byte after the call. */
static char* safe_append_char(char* buf, char byte, unsigned int *rpos, unsigned int *rsize)
{
    if (*rpos >= *rsize) {
        *rsize += 512;
        buf = (char*) safe_realloc(buf, *rsize);
    }
    buf[(*rpos)++] = byte;
    return buf;
}

/* Escape a string so that it can be round-tripped into a command line string
   and retrieved by the default C/C++ command line parser. You can escape a list
   of strings with this function, join them with spaces, pass them to
   CreateProcess, and the new process will get the same list of strings in its
   argv array.

   http://msdn.microsoft.com/en-us/library/17w5ykft%28v=vs.85%29.aspx
   http://blogs.msdn.com/b/twistylittlepassagesallalike/archive/2011/04/23/everyone-quotes-arguments-the-wrong-way.aspx

   Returns a dynamically allocated string.

   This function has a test program in test/test-escape_windows_command_arg.c.
   Run that program after making any changes. */
char *escape_windows_command_arg(const char *arg)
{
    const char *p;
    char *ret;
    unsigned int rpos = 0, rsize = 1;

    ret = (char *) safe_malloc(rsize);
    ret = safe_append_char(ret, '"', &rpos, &rsize);

    for (p = arg; *p != '\0'; p++) {
        unsigned int num_backslashes;
        unsigned int i;

        num_backslashes = 0;
        for (; *p == '\\'; p++)
            num_backslashes++;

        if (*p == '\0') {
        /* Escape all backslashes, but let the terminating double quotation
           mark we add below be interpreted as a metacharacter. */
            for (i = 0; i < num_backslashes*2; i++)
                ret = safe_append_char(ret, '\\', &rpos, &rsize);
            break;
        } else if (*p == '"') {
        /* Escape all backslashes and the following double quotation
           mark. */
            for (i = 0; i < num_backslashes*2 + 1; i++)
                ret = safe_append_char(ret, '\\', &rpos, &rsize);
            ret[rpos++] = *p;
        } else {
            /* Backslashes aren't special here. */
            for (i = 0; i < num_backslashes; i++)
                ret = safe_append_char(ret, '\\', &rpos, &rsize);
            ret = safe_append_char(ret, *p, &rpos, &rsize);
        }
    }

    ret = safe_append_char(ret, '"', &rpos, &rsize);
    ret = safe_append_char(ret, '\0', &rpos, &rsize);

    return ret;
}

/* Convert non-printable characters to replchar in the string */
void replacenonprintable(char *str, int strlength, char replchar) {
  int i;

  for (i = 0; i < strlength; i++)
    if (!isprint((int)(unsigned char)str[i]))
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

  result = (char *)safe_malloc(i + 1);
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
