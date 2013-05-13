/***************************************************************************
 * utils.cc -- Various miscellaneous utility functions which defy          *
 * categorization :)                                                       *
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

#include "nmap.h"
#include "utils.h"
#include "NmapOps.h"

extern NmapOps o;

/* Test a wildcard mask against a test string. Wildcard mask can include '*' and
   '?' which work the same as they do in /bin/sh (except it's case insensitive).
   Return val of 1 means it DID match. 0 means it DIDN'T. - Doug Hoyte, 2005 */
int wildtest(char *wild, char *test) {
  int i;

  while (*wild != '\0'  ||  *test != '\0') {
    if (*wild == '*') {
      /* --- Deal with multiple asterisks. --- */
      while (wild[1] == '*')
        wild++;

      /* --- Deal with terminating asterisks. --- */
      if (wild[1] == '\0')
        return 1;

      for (i = 0; test[i] != '\0'; i++) {
        if ((tolower((int) (unsigned char) wild[1]) == tolower((int) (unsigned char) test[i]) || wild[1] == '?')
            && wildtest(wild + 1, test + i) == 1) {
          return 1;
        }
      }

      return 0;
    }

    /* --- '?' can't match '\0'. --- */
    if (*wild == '?' && *test == '\0')
      return 0;

    if (*wild != '?' && tolower((int) (unsigned char) *wild) != tolower((int) (unsigned char) *test))
      return 0;
    wild++;
    test++;
  }

  return tolower((int) (unsigned char) *wild) == tolower((int) (unsigned char) *test);
}

/* Wrapper for nbase function hexdump. */
void nmap_hexdump(unsigned char *cp, unsigned int length) {
  char *string = NULL;

  string = hexdump((u8*) cp, length);
  if (string) {
    log_write(LOG_PLAIN, "%s", string);
    free(string);
  }

  return;
}


#ifndef HAVE_STRERROR
char *strerror(int errnum) {
  static char buf[1024];
  sprintf(buf, "your system is too old for strerror of errno %d\n", errnum);
  return buf;
}
#endif

/* Like the perl equivalent, removes the terminating newline from string IF one
   exists. It then returns the POSSIBLY MODIFIED string. */
char *chomp(char *string) {
  int len = strlen(string);
  if (len && string[len - 1] == '\n') {
    if (len > 1 && string[len - 2] == '\r')
      string[len - 2] = '\0';
    else
      string[len - 1] = '\0';
  }
  return string;
}


/* Scramble the contents of an array. */
void genfry(unsigned char *arr, int elem_sz, int num_elem) {
  int i;
  unsigned int pos;
  unsigned char *bytes;
  unsigned char *cptr;
  unsigned short *sptr;
  unsigned int *iptr;
  unsigned char *tmp;
  int bpe;

  if (sizeof(unsigned char) != 1)
    fatal("%s() requires 1 byte chars", __func__);

  if (num_elem < 2)
    return;

  if (elem_sz == sizeof(unsigned short)) {
    shortfry((unsigned short *)arr, num_elem);
    return;
  }

  /* OK, so I am stingy with the random bytes! */
  if (num_elem < 256)
    bpe = sizeof(unsigned char);
  else if (num_elem < 65536)
    bpe = sizeof(unsigned short);
  else
    bpe = sizeof(unsigned int);

  bytes = (unsigned char *) safe_malloc(bpe * num_elem);
  tmp = (unsigned char *) safe_malloc(elem_sz);

  get_random_bytes(bytes, bpe * num_elem);
  cptr = bytes;
  sptr = (unsigned short *)bytes;
  iptr = (unsigned int *) bytes;

  for (i = num_elem - 1; i > 0; i--) {
    if (num_elem < 256) {
      pos = *cptr;
      cptr++;
    } else if (num_elem < 65536) {
      pos = *sptr;
      sptr++;
    } else {
      pos = *iptr;
      iptr++;
    }
    pos %= i + 1;
    if ((unsigned) i != pos) { /* memcpy is undefined when source and dest overlap. */
      memcpy(tmp, arr + elem_sz * i, elem_sz);
      memcpy(arr + elem_sz * i, arr + elem_sz * pos, elem_sz);
      memcpy(arr + elem_sz * pos, tmp, elem_sz);
    }
  }
  free(bytes);
  free(tmp);
}

void shortfry(unsigned short *arr, int num_elem) {
  int num;
  unsigned short tmp;
  int i;

  if (num_elem < 2)
    return;

  for (i = num_elem - 1; i > 0 ; i--) {
    num = get_random_ushort() % (i + 1);
    if (i == num)
      continue;
    tmp = arr[i];
    arr[i] = arr[num];
    arr[num] = tmp;
  }

  return;
}

/* Send data to a socket, keep retrying until an error or the full length is
   sent. Returns -1 if there is an error, or len if the full length was sent. */
int Send(int sd, const void *msg, size_t len, int flags) {
  int res;
  unsigned int sentlen = 0;

  do {
    res = send(sd, (char *) msg + sentlen, len - sentlen, flags);
    if (res > 0)
      sentlen += res;
  } while (sentlen < len && (res != -1 || socket_errno() == EINTR));

  return (res < 0) ? -1 : (int) len;
}

unsigned int gcd_n_uint(int nvals, unsigned int *val) {
  unsigned int a, b, c;

  if (!nvals)
    return 1;
  a = *val;
  for (nvals--; nvals; nvals--) {
    b = *++val;
    if (a < b) {
      c = a;
      a = b;
      b = c;
    }
    while (b) {
      c = a % b;
      a = b;
      b = c;
    }
  }
  return a;
}

/* This function takes a command and the address of an uninitialized char **. It
   parses the command (by separating out whitespace) into an argv[]-style
   char **, which it sets the argv parameter to. The function returns the number
   of items filled up in the array (argc), or -1 in the case of an error. This
   function allocates memory for argv and thus it must be freed -- use
   argv_parse_free() for that. If arg_parse returns <1, then argv does not need
   to be freed. The returned arrays are always terminated with a NULL pointer */
int arg_parse(const char *command, char ***argv) {
  char **myargv = NULL;
  int argc = 0;
  char mycommand[4096];
  char *start, *end;
  char oldend;

  *argv = NULL;
  if (Strncpy(mycommand, command, 4096) == -1)
    return -1;
  myargv = (char **) safe_malloc((MAX_PARSE_ARGS + 2) * sizeof(char *));
  memset(myargv, 0, (MAX_PARSE_ARGS + 2) * sizeof(char *));
  myargv[0] = (char *) 0x123456; /* Integrity checker */
  myargv++;
  start = mycommand;
  while (start && *start) {
    while (*start && isspace((int) (unsigned char) *start))
      start++;
    if (*start == '"') {
      start++;
      end = strchr(start, '"');
    } else if (*start == '\'') {
      start++;
      end = strchr(start, '\'');
    } else if (!*start) {
      continue;
    } else {
      end = start + 1;
      while (*end && !isspace((int) (unsigned char) *end)) {
        end++;
      }
    }
    if (!end) {
      arg_parse_free(myargv);
      return -1;
    }
    if (argc >= MAX_PARSE_ARGS) {
      arg_parse_free(myargv);
      return -1;
    }
    oldend = *end;
    *end = '\0';
    myargv[argc++] = strdup(start);
    if (oldend)
      start = end + 1;
    else
      start = end;
  }
  myargv[argc + 1] = 0;
  *argv = myargv;

  return argc;
}

/* Free an argv allocated inside arg_parse */
void arg_parse_free(char **argv) {
  char **current;
  /* Integrity check */
  argv--;
  assert(argv[0] == (char *) 0x123456);
  current = argv + 1;
  while (*current) {
    free(*current);
    current++;
  }
  free(argv);
}

/* A simple function to form a character from 2 hex digits in ASCII form. */
static unsigned char hex2char(unsigned char a, unsigned char b) {
  int val;

  if (!isxdigit((int) a) || !isxdigit((int) b))
    return 0;
  a = tolower((int) a);
  b = tolower((int) b);
  if (isdigit((int) a))
    val = (a - '0') << 4;
  else
    val = (10 + (a - 'a')) << 4;

  if (isdigit((int) b))
    val += (b - '0');
  else
    val += 10 + (b - 'a');

  return (unsigned char) val;
}

/* Convert a string in the format of a roughly C-style string literal
   (e.g. can have \r, \n, \xHH escapes, etc.) into a binary string.
   This is done in-place, and the new (shorter or the same) length is
   stored in newlen.  If parsing fails, NULL is returned, otherwise
   str is returned. */
char *cstring_unescape(char *str, unsigned int *newlen) {
  char *dst = str, *src = str;
  char newchar;

  while (*src) {
    if (*src == '\\' ) {
      src++;
      switch (*src) {
      case '0':
        newchar = '\0';
        src++;
        break;
      case 'a': // Bell (BEL)
        newchar = '\a';
        src++;
        break;
      case 'b': // Backspace (BS)
        newchar = '\b';
        src++;
        break;
      case 'f': // Formfeed (FF)
        newchar = '\f';
        src++;
        break;
      case 'n': // Linefeed/Newline (LF)
        newchar = '\n';
        src++;
        break;
      case 'r': // Carriage Return (CR)
        newchar = '\r';
        src++;
        break;
      case 't': // Horizontal Tab (TAB)
        newchar = '\t';
        src++;
        break;
      case 'v': // Vertical Tab (VT)
        newchar = '\v';
        src++;
        break;
      case 'x':
        src++;
        if (!*src || !*(src + 1)) return NULL;
        if (!isxdigit((int) (unsigned char) *src) || !isxdigit((int) (unsigned char) * (src + 1))) return NULL;
        newchar = hex2char(*src, *(src + 1));
        src += 2;
        break;
      default:
        if (isalnum((int) (unsigned char) *src))
          return NULL; // I don't really feel like supporting octals such as \015
        // Other characters I'll just copy as is
        newchar = *src;
        src++;
        break;
      }
      *dst = newchar;
      dst++;
    } else {
      if (dst != src)
        *dst = *src;
      dst++;
      src++;
    }
  }
  *dst = '\0'; // terminated, but this string can include other \0, so use newlen
  if (newlen)
    *newlen = dst - str;

  return str;
}


void bintohexstr(char *buf, int buflen, char *src, int srclen) {
  int bp = 0;
  int i;

  for (i = 0; i < srclen; i++) {
    bp += Snprintf(buf + bp, buflen - bp, "\\x%02hhx", src[i]);
    if (bp >= buflen)
      break;
    if (i % 16 == 7) {
      bp += Snprintf(buf + bp, buflen - bp, " ");
      if (bp >= buflen)
        break;
    }
    if (i % 16 == 15) {
      bp += Snprintf(buf + bp, buflen - bp, "\n");
      if (bp >= buflen)
        break;
    }
  }
  if (i % 16 != 0 && bp < buflen)
    bp += Snprintf(buf + bp, buflen - bp, "\n");
}

/* Get the CPE part (first component of the URL, should be "a", "h", or "o") as
   a character: 'a', 'h', or 'o'. Returns -1 on error. */
int cpe_get_part(const char *cpe) {
  const char *PREFIX = "cpe:/";
  char part;

  if (strncmp(cpe, PREFIX, strlen(PREFIX) != 0))
    return -1;
  /* This could be more robust, by decoding character escapes and checking ':'
     boundaries. */
  part = cpe[strlen(PREFIX)];

  if (part == 'a' || part == 'h' || part == 'o')
    return part;
  else
    return -1;
}


/* mmap() an entire file into the address space. Returns a pointer to the
   beginning of the file. The mmap'ed length is returned inside the length
   parameter. If there is a problem, NULL is returned, the value of length is
   undefined, and errno is set to something appropriate. The user is responsible
   for doing an munmap(ptr, length) when finished with it. openflags should be
   O_RDONLY or O_RDWR, or O_WRONLY. */
#ifndef WIN32
char *mmapfile(char *fname, int *length, int openflags) {
  struct stat st;
  int fd;
  char *fileptr;

  if (!length || !fname) {
    errno = EINVAL;
    return NULL;
  }

  *length = -1;

  if (stat(fname, &st) == -1) {
    errno = ENOENT;
    return NULL;
  }

  fd = open(fname, openflags);
  if (fd == -1) {
    return NULL;
  }

  fileptr = (char *)mmap(0, st.st_size, (openflags == O_RDONLY) ? PROT_READ :
                         (openflags == O_RDWR) ? (PROT_READ | PROT_WRITE)
                         : PROT_WRITE, MAP_SHARED, fd, 0);

  close(fd);

#ifdef MAP_FAILED
  if (fileptr == (void *)MAP_FAILED) return NULL;
#else
  if (fileptr == (char *) - 1) return NULL;
#endif

  *length = st.st_size;
  return fileptr;
}
#else /* WIN32 */
/* FIXME:  From the looks of it, this function can only handle one mmaped file
   at a time (note how gmap is used). */
/* I believe this was written by Ryan Permeh (ryan@eeye.com). */

static HANDLE gmap = NULL;

char *mmapfile(char *fname, int *length, int openflags) {
  HANDLE fd;
  DWORD mflags, oflags;
  char *fileptr;

  if (!length || !fname) {
    WSASetLastError(EINVAL);
    return NULL;
  }

  if (openflags == O_RDONLY) {
    oflags = GENERIC_READ;
    mflags = PAGE_READONLY;
  } else {
    oflags = GENERIC_READ | GENERIC_WRITE;
    mflags = PAGE_READWRITE;
  }

  fd = CreateFile(
         fname,
         oflags,                       // open flags
         0,                            // do not share
         NULL,                         // no security
         OPEN_EXISTING,                // open existing
         FILE_ATTRIBUTE_NORMAL,
         NULL);                        // no attr. template
  if (!fd)
    pfatal ("%s(%u): CreateFile()", __FILE__, __LINE__);

  *length = (int) GetFileSize (fd, NULL);

  gmap = CreateFileMapping (fd, NULL, mflags, 0, 0, NULL);
  if (!gmap) {
    pfatal("%s(%u): CreateFileMapping(), file '%s', length %d, mflags %08lX",
           __FILE__, __LINE__, fname, *length, mflags);
  }

  fileptr = (char*) MapViewOfFile (gmap, oflags == GENERIC_READ ? FILE_MAP_READ : FILE_MAP_WRITE, 0, 0, 0);
  if (!fileptr)
    pfatal ("%s(%u): MapViewOfFile()", __FILE__, __LINE__);

  if (o.debugging > 2) {
    log_write(LOG_PLAIN, "%s(): fd %08lX, gmap %08lX, fileptr %08lX, length %d\n",
              __func__, (DWORD)fd, (DWORD)gmap, (DWORD)fileptr, *length);
  }

  CloseHandle (fd);

  return fileptr;
}


/* FIXME:  This only works if the file was mapped by mmapfile (and only
   works if the file is the most recently mapped one */
int win32_munmap(char *filestr, int filelen) {
  if (gmap == 0)
    fatal("%s: no current mapping !\n", __func__);
  FlushViewOfFile(filestr, filelen);
  UnmapViewOfFile(filestr);
  CloseHandle(gmap);
  gmap = NULL;
  return 0;
}
#endif
