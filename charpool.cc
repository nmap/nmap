
/***************************************************************************
 * charpool.cc -- Handles Nmap's "character pool" memory allocation        *
 * system.                                                                 *
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

#include <stddef.h>
#undef NDEBUG
#include <assert.h>

#include "nbase.h"

/* Character pool memory allocation */
#include "charpool.h"
#include "nmap_error.h"

static CharPool g_charpool (16384);

const char *cp_strndup(const char *src, int len) {
  return g_charpool.dup(src, len);
}
const char *cp_strdup(const char *src) {
  return g_charpool.dup(src);
}
void cp_free(void) {
  return g_charpool.clear();
}

class StrTable {
  public:
  StrTable() {
    memset(table, 0, sizeof(table));
    for (int i = 1; i <= CHAR_MAX; i++) {
      table[i*2] = static_cast<char>(i);
    }
  }
  const char *get(char c) { assert(c >= 0); return &table[c*2]; }
  private:
  char table[2*(CHAR_MAX + 1)];
};
static StrTable g_table;

const char *cp_char2str(char c) {
  return g_table.get(c);
}

CharPool::CharPool(size_t init_sz) {
  assert(init_sz >= 256);
  /* Create our char pool */
  currentbucketsz = init_sz;
  nexti = 0;
  char *b = (char *) safe_malloc(currentbucketsz);
  buckets.push_back(b);
}

void CharPool::clear(void) {
  for (BucketList::iterator it=buckets.begin(); it != buckets.end(); it++) {
    free(*it);
  }
  buckets.clear();
}

const char *CharPool::dup(const char *src, int len) {
  if (len < 0)
    len = strlen(src);
  if (len == 0)
    return g_table.get('\0');
  else if (len == 1)
    return g_table.get(*src);

  int sz = len + 1;
  char *p = buckets.back() + nexti;

  while (nexti + sz > currentbucketsz) {
    /* Doh!  We've got to make room */
    currentbucketsz <<= 1;
    nexti = 0;
    p = (char *) safe_malloc(currentbucketsz);
    buckets.push_back(p);
  }

  nexti += sz;
  p[len] = '\0';
  return (const char *) memcpy(p, src, len);
}
