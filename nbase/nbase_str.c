
/***************************************************************************
 * nbase_str.c -- string related functions in the nbase library.  These    *
 * were written by fyodor@nmap.org .                                       *
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
    } else {
      p -= foundto - needle;
      foundto = needle;
    }
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
    s[n - 1] = '\0'; /* technically redundant */

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

/* Like strchr, but don't go past end. Nulls not handled specially. */
const char *strchr_p(const char *str, const char *end, char c) {
  const char *q=str;
  assert(str && end >= str);
  for (; q < end; q++) {
    if (*q == c)
      return q;
  }
  return NULL;
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
    va_end(va_tmp);

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
