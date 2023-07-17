/***************************************************************************
 * utils.cc -- Various miscellaneous utility functions which defy          *
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

#include "nmap.h"
#include "utils.h"
#include "nmap_error.h"
#include "NmapOps.h"

#include <sys/types.h>
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <errno.h>

extern NmapOps o;

/* Test a wildcard mask against a test string. Wildcard mask can include '*' and
   '?' which work the same as they do in /bin/sh (except it's case insensitive).
   Return val of 1 means it DID match. 0 means it DIDN'T. - Doug Hoyte, 2005 */
int wildtest(const char *wild, const char *test) {
  int i;

  assert(wild);
  assert(test);
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
void nmap_hexdump(const unsigned char *cp, unsigned int length) {
  char *string = NULL;

  string = hexdump((u8*) cp, length);
  if (string) {
    log_write(LOG_PLAIN, "%s", string);
    free(string);
  }

  return;
}


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
  size_t bpe;

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


void bintohexstr(char *buf, int buflen, const char *src, int srclen) {
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

/** Returns a buffer that contains the binary equivalent to the supplied
 *  hex spec or NULL in case of error.
 *  @warning Returned pointer points to a static buffer that subsequent calls
 *  will overwrite. */
u8 *parse_hex_string(const char *str, size_t *outlen) {
  char auxbuff[4096];
  static u8 dst[16384];
  size_t dstlen=16384;
  unsigned int i=0, j=0;
  const char *start=NULL;

  if(str==NULL || outlen==NULL)
    return NULL;
  /* This catches the empty string possibility "" */
  if(strlen(str) == 0)
    return NULL;
  else
    memset(auxbuff,0,4096);

  /* String should be treated as a hex number in this format: 0xAABBCCDDEE...
   * We process it the way it is specified, we don't perform byte order
   * conversions so if the users says 0x00AA we write dst[0]=0x00, dst[1]==0xAA
   * no matter the endianness of the host system. */
  if( !strncmp("0x", str, 2) ) {
    /* This catches the case of an empty "0x" */
    if(strlen(str) == 2)
      return NULL;
    start=str+2;
  }
  /* String should be treated as list of hex char in this format: \x00\xFF\x0A*/
  else if( !strncmp("\\x", str, 2) ) {
    /* This catches the case of an empty "\x" */
    if(strlen(str) == 2)
      return NULL;
    /* Copy all interesting bytes to an aux array, discard "\x" */
    for(i=0; i<strlen(str) && j<4095; i++) {
      if( str[i]!='\\' && str[i]!='x' && str[i]!='X')
        auxbuff[j++]=str[i];
    }
    auxbuff[j]='\0'; /* NULL terminate the string */
    start=auxbuff;
  }
  /* It must be a hex number in this format: AABBCCDDEE (without 0x or \x) */
  else {
    start=str;
  }

  /*OK, here we should have "start" pointing to the beginning of a string
   * in the format AABBCCDDEE... */
  /* Check if all we've got are hex chars */
  for(i=0; i<strlen(start); i++) {
    if( !isxdigit(start[i]) )
      return NULL;
  }
  /* Check if we have an even number of hex chars */
  if( strlen(start)%2 != 0 )
    return NULL;

  /* We are ready to parse this string */
  for(i=0, j=0; j<dstlen && i<strlen(start)-1; i+=2) {
    char twobytes[3];
    twobytes[0]=start[i];
    twobytes[1]=start[i+1];
    twobytes[2]='\0';
    dst[j++]=(u8)strtol(twobytes, NULL, 16);
  }
  /* Store final length */
  *outlen=j;
  return dst;
}

/* Get the CPE part (first component of the URL, should be "a", "h", or "o") as
   a character: 'a', 'h', or 'o'. Returns -1 on error. */
int cpe_get_part(const char *cpe) {
  const char *PREFIX = "cpe:/";
  char part;

  if (strncmp(cpe, PREFIX, strlen(PREFIX)) != 0)
    return -1;
  /* This could be more robust, by decoding character escapes and checking ':'
     boundaries. */
  part = cpe[strlen(PREFIX)];

  if (part == 'a' || part == 'h' || part == 'o')
    return part;
  else
    return -1;
}


#ifndef WIN32
static int open2mmap_flags(int open_flags)
{
  switch (open_flags) {
    case O_RDONLY: return PROT_READ;
    case O_RDWR:   return PROT_READ | PROT_WRITE;
    case O_WRONLY: return PROT_WRITE;
    default:
      return -1;
  }
}

/* mmap() an entire file into the address space. Returns a pointer to the
   beginning of the file. The mmap'ed length is returned inside the length
   parameter. If there is a problem, NULL is returned, the value of length is
   undefined, and errno is set to something appropriate. The user is responsible
   for doing an munmap(ptr, length) when finished with it. openflags should be
   O_RDONLY or O_RDWR, or O_WRONLY. */
char *mmapfile(char *fname, s64 *length, int openflags) {
  struct stat st;
  int fd;
  int mmap_flags;
  char *fileptr;

  if (!length || !fname) {
    errno = EINVAL;
    return NULL;
  }

  *length = -1;

  mmap_flags = open2mmap_flags(openflags);
  if (mmap_flags == -1) {
    errno = EINVAL;
    return NULL;
  }

  fd = open(fname, openflags);
  if (fd == -1) {
    return NULL;
  }

  if (fstat(fd, &st) == -1) {
    close(fd);
    return NULL;
  }

  fileptr = (char *)mmap(0, st.st_size, mmap_flags, MAP_SHARED, fd, 0);

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

char *mmapfile(char *fname, s64 *length, int openflags) {
  HANDLE fd;
  DWORD mflags, oflags;
  LARGE_INTEGER filesize;
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

  if (!GetFileSizeEx(fd, &filesize)) {
    pfatal("%s(%u): GetFileSizeEx(), file '%s'", __FILE__, __LINE__, fname);
  }
  *length = (s64)filesize.QuadPart;
  if (*length < 0) {
    fatal("%s(%u): size too large, file '%s'", __FILE__, __LINE__, fname);
  }

  gmap = CreateFileMapping (fd, NULL, mflags, 0, 0, NULL);
  if (!gmap) {
    pfatal("%s(%u): CreateFileMapping(), file '%s', length %I64d, mflags %08lX",
           __FILE__, __LINE__, fname, *length, mflags);
  }

  fileptr = (char*) MapViewOfFile (gmap, oflags == GENERIC_READ ? FILE_MAP_READ : FILE_MAP_WRITE, 0, 0, 0);
  if (!fileptr)
    pfatal ("%s(%u): MapViewOfFile()", __FILE__, __LINE__);

  if (o.debugging > 2) {
    log_write(LOG_PLAIN, "%s(): fd %08lX, gmap %08lX, fileptr %08lX, length %I64d\n",
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
