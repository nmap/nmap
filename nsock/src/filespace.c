/***************************************************************************
 * filespace.c -- a simple mechanism for storing dynamic amounts of data   *
 * in a simple to use, and quick to append-to structure.                   *
 *                                                                         *
 ***********************IMPORTANT NSOCK LICENSE TERMS***********************
 *
 * The nsock parallel socket event library is (C) 1999-2023 Nmap Software LLC
 * This library is free software; you may redistribute and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; Version 2. This guarantees your right to use, modify, and
 * redistribute this software under certain conditions. If this license is
 * unacceptable to you, Nmap Software LLC may be willing to sell alternative
 * licenses (contact sales@nmap.com ).
 *
 * As a special exception to the GPL terms, Nmap Software LLC grants permission
 * to link the code of this program with any version of the OpenSSL library
 * which is distributed under a license identical to that listed in the included
 * docs/licenses/OpenSSL.txt file, and distribute linked combinations including
 * the two. You must obey the GNU GPL in all respects for all of the code used
 * other than OpenSSL. If you modify this file, you may extend this exception to
 * your version of the file, but you are not obligated to do so.
 *
 * If you received these files with a written license agreement stating terms
 * other than the (GPL) terms above, then that alternative license agreement
 * takes precedence over this comment.
 *
 * Source is provided to this software because we believe users have a right to
 * know exactly what a program is going to do before they run it. This also
 * allows you to audit the software for security holes.
 *
 * Source code also allows you to port Nmap to new platforms, fix bugs, and add
 * new features. You are highly encouraged to send your changes to the
 * dev@nmap.org mailing list for possible incorporation into the main
 * distribution. By sending these changes to Fyodor or one of the Insecure.Org
 * development mailing lists, or checking them into the Nmap source code
 * repository, it is understood (unless you specify otherwise) that you are
 * offering the Nmap Project (Nmap Software LLC) the unlimited, non-exclusive
 * right to reuse, modify, and relicense the code. Nmap will always be available
 * Open Source, but this is important because the inability to relicense code
 * has caused devastating problems for other Free Software projects (such as KDE
 * and NASM). We also occasionally relicense the code to third parties as
 * discussed above. If you wish to specify special license conditions of your
 * contributions, just say so when you send them.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License v2.0 for more
 * details (http://www.gnu.org/licenses/gpl-2.0.html).
 *
 ***************************************************************************/

/* $Id$ */

#include "nsock_internal.h"
#include "filespace.h"

#include <string.h>

#define FS_INITSIZE_DEFAULT 1024


/* Assumes space for fs has already been allocated */
int filespace_init(struct filespace *fs, int initial_size) {
  memset(fs, 0, sizeof(struct filespace));
  if (initial_size == 0)
    initial_size = FS_INITSIZE_DEFAULT;

  fs->current_alloc = initial_size;
  fs->str = (char *)safe_malloc(fs->current_alloc);
  fs->str[0] = '\0';
  fs->pos = fs->str;
  return 0;
}

int fs_free(struct filespace *fs) {
  if (fs->str)
    free(fs->str);

  fs->current_alloc = fs->current_size = 0;
  fs->pos = fs->str = NULL;
  return 0;
}

/* Concatenate a string to the end of a filespace */
int fs_cat(struct filespace *fs, const char *str, int len) {
  if (len < 0)
    return -1;

  if (len == 0)
    return 0;

  if (fs->current_alloc - fs->current_size < len + 2) {
    char *tmpstr;

    fs->current_alloc = (int)(fs->current_alloc * 1.4 + 1);
    fs->current_alloc += 100 + len;

    tmpstr = (char *)safe_malloc(fs->current_alloc);
    memcpy(tmpstr, fs->str, fs->current_size);

    fs->pos = (fs->pos - fs->str) + tmpstr;

    if (fs->str)
      free(fs->str);

    fs->str = tmpstr;
  }
  memcpy(fs->str + fs->current_size, str, len);

  fs->current_size += len;
  fs->str[fs->current_size] = '\0';
  return 0;
}

