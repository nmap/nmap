/***************************************************************************
 * filespace.h -- a simple mechanism for storing dynamic amounts of data   *
 * in a simple to use, and quick to append-to structure.                   *
 *                                                                         *
 ***********************IMPORTANT NSOCK LICENSE TERMS***********************
 *                                                                         *
 * The nsock parallel socket event library is (C) 1999-2012 Insecure.Com   *
 * LLC This library is free software; you may redistribute and/or          *
 * modify it under the terms of the GNU General Public License as          *
 * published by the Free Software Foundation; Version 2.  This guarantees  *
 * your right to use, modify, and redistribute this software under certain *
 * conditions.  If this license is unacceptable to you, Insecure.Com LLC   *
 * may be willing to sell alternative licenses (contact                    *
 * sales@insecure.com ).                                                   *
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
 * If you received these files with a written license agreement stating    *
 * terms other than the (GPL) terms above, then that alternative license   *
 * agreement takes precedence over this comment.                           *
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License v2.0 for more details                            *
 * (http://www.gnu.org/licenses/gpl-2.0.html).                             *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */

#ifndef FILESPACE_H
#define FILESPACE_H

#ifdef HAVE_CONFIG_H
#include "nsock_config.h"
#include "nbase_config.h"
#endif

#ifdef WIN32
#include "nbase_winconfig.h"
#endif

#include <stdlib.h>
#include <stdarg.h>
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_STRINGS_H
#include <strings.h>
#endif

#define FILESPACE_LENGTH(fs) ((fs)->current_size)
#define FILESPACE_STR(fs) ((fs)->str)

struct filespace {
  int current_size;
  int current_alloc;

  /* Current position in the filespace */
  char *pos;
  char *str;
};

/* If you want to express a length, use fscat() */
static inline int fs_rputs(const char *str, struct filespace *fs) {
  char *new_str;
  int len;

  len = (int)strlen(str);

  if (len + fs->current_size + 1 > fs->current_alloc) {
    fs->current_alloc =  MAX(fs->current_size * 2, fs->current_size + len  + 1000);

    new_str = (char *)safe_malloc(fs->current_alloc);
    memcpy(new_str, fs->str, fs->current_size);

    fs->pos = (fs->pos - fs->str) + new_str;
    if (fs->str)
      free(fs->str);
    fs->str = new_str;
  }
  memcpy(fs->str + fs->current_size, str, len);
  fs->current_size += len;
  fs->str[fs->current_size] = '\0';

  return 0;
}


static inline int fs_rvputs(struct filespace *fs,...) {
  va_list args;
  const char *x;

  va_start(args, fs);
  for (;;) {
    x = va_arg(args, const char *);
    if (x == NULL)
      break;

    if (fs_rputs(x,fs) == -1) {
      va_end(args);
      return -1;
    }
  }
  va_end(args);
  return 1;
}

/* Concatenate a string to the end of a filespace */
static inline int fscat(struct filespace *fs, const char *str, int len) {
  char *tmpstr;

  if (len < 0)
    return -1;
  if (len == 0)
    return 0;

  /*
  printf("fscat: current_alloc=%d; current_size=%d; len=%d\n", fs->current_alloc, fs->current_size, len);
  */

  if (fs->current_alloc - fs->current_size < len + 2) {
    fs->current_alloc = (int) (fs->current_alloc * 1.4 + 1 );
    fs->current_alloc += 100 + len;

    tmpstr = (char *)safe_malloc(fs->current_alloc);
    memcpy(tmpstr, fs->str, fs->current_size);

    fs->pos = (fs->pos - fs->str) + tmpstr;
    if (fs->str) free(fs->str);
    fs->str = tmpstr;
  }
  memcpy(fs->str + fs->current_size, str, len);

  fs->current_size += len;
  fs->str[fs->current_size] = '\0';
  return 0;
}

static inline int fs_rputc(int ch, struct filespace *fs) {
  char s[2];

  if (fs->current_size + 2 <= fs->current_alloc) {
    fs->str[fs->current_size] = ch;
    fs->current_size++;
    fs->str[fs->current_size] = '\0';
  } else {
    /* otherwise we use the ueber-technique of letting fscat handle it ...  umm
     * actually I don't know why we don't do this in all cases ... */
    s[0] = ch;
    s[1] = '\0';
    fscat(fs, s, 1);
  }
  return 0;
}


int filespace_init(struct filespace *fs, int initial_size);

int fs_prepend(char *str, int len, struct filespace *fs);

int fs_clear(struct filespace *fs);

int fs_free(struct filespace *fs);

#endif /* FILESPACE_H */

