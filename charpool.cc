
/***************************************************************************
 * charpool.cc -- Handles Nmap's "character pool" memory allocation        *
 * system.                                                                 *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2022 Nmap Software LLC ("The Nmap *
 * Project"). Nmap is also a registered trademark of the Nmap Project.     *
 *                                                                         *
 * This program is distributed under the terms of the Nmap Public Source   *
 * License (NPSL). The exact license text applying to a particular Nmap    *
 * release or source code control revision is contained in the LICENSE     *
 * file distributed with that version of Nmap or source code control       *
 * revision. More Nmap copyright/legal information is available from       *
 * https://nmap.org/book/man-legal.html, and further information on the    *
 * NPSL license itself can be found at https://nmap.org/npsl/ . This       *
 * header summarizes some key points from the Nmap license, but is no      *
 * substitute for the actual license text.                                 *
 *                                                                         *
 * Nmap is generally free for end users to download and use themselves,    *
 * including commercial use. It is available from https://nmap.org.        *
 *                                                                         *
 * The Nmap license generally prohibits companies from using and           *
 * redistributing Nmap in commercial products, but we sell a special Nmap  *
 * OEM Edition with a more permissive license and special features for     *
 * this purpose. See https://nmap.org/oem/                                 *
 *                                                                         *
 * If you have received a written Nmap license agreement or contract       *
 * stating terms other than these (such as an Nmap OEM license), you may   *
 * choose to use and redistribute Nmap under those terms instead.          *
 *                                                                         *
 * The official Nmap Windows builds include the Npcap software             *
 * (https://npcap.com) for packet capture and transmission. It is under    *
 * separate license terms which forbid redistribution without special      *
 * permission. So the official Nmap Windows builds may not be              *
 * redistributed without special permission (such as an Nmap OEM           *
 * license).                                                               *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to submit your         *
 * changes as a Github PR or by email to the dev@nmap.org mailing list     *
 * for possible incorporation into the main distribution. Unless you       *
 * specify otherwise, it is understood that you are offering us very       *
 * broad rights to use your submissions as described in the Nmap Public    *
 * Source License Contributor Agreement. This is important because we      *
 * fund the project by selling licenses with various terms, and also       *
 * because the inability to relicense code has caused devastating          *
 * problems for other Free Software projects (such as KDE and NASM).       *
 *                                                                         *
 * The free version of Nmap is distributed in the hope that it will be     *
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of  *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranties,        *
 * indemnification and commercial support are all available through the    *
 * Npcap OEM program--see https://nmap.org/oem/                            *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */

#include <stddef.h>

#include "nbase.h"

/* Character pool memory allocation */
#include "charpool.h"
#include "nmap_error.h"

static char *charpool[16];
static int currentcharpool;
static size_t currentcharpoolsz;
static size_t nexti;

/* Allocated blocks are allocated to multiples of ALIGN_ON. This is the
   definition used by the malloc in Glibc 2.7, which says that it "suffices for
   nearly all current machines and C compilers." */
#define ALIGN_ON (2 * sizeof(size_t))

static int cp_init(void) {
  static int charpool_initialized = 0;
  if (charpool_initialized) return 0;

  /* Create our char pool */
  currentcharpool = 0;
  currentcharpoolsz = 16384;
  nexti = 0;
  charpool[0] = (char *) safe_malloc(currentcharpoolsz);
  charpool_initialized = 1;
  return 0;
}

void cp_free(void) {
  int ccp;
  for(ccp=0; ccp <= currentcharpool; ccp++)
    if(charpool[ccp]){
      free(charpool[ccp]);
      charpool[ccp] = NULL;
  }
  currentcharpool = 0;
}

static inline void cp_grow(void) {
  /* Doh!  We've got to make room */
  if (++currentcharpool > 15) {
    fatal("Character Pool is out of buckets!");
  }
  currentcharpoolsz <<= 1;

  nexti = 0;
  charpool[currentcharpool] = (char *) safe_malloc(currentcharpoolsz);
}

void *cp_alloc(int sz) {
  char *p;
  int modulus;

  cp_init();

  if ((modulus = sz % ALIGN_ON))
    sz += ALIGN_ON - modulus;

  if (nexti + sz <= currentcharpoolsz) {
    p = charpool[currentcharpool] + nexti;
    nexti += sz;
    return p;
  }
  /* Doh!  We've got to make room */
  cp_grow();

 return cp_alloc(sz);

}

const char *cp_strndup(const char *src, int len) {
  char *dst = (char *) cp_alloc(len + 1); // Additional byte for null terminator
  dst[len] = '\0';
  return (const char *) memcpy(dst, src, len);
}

const char *cp_strdup(const char *src) {
  return cp_strndup(src, strlen(src));
}
