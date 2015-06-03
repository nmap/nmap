
/***************************************************************************
 * nbase_rnd.c -- Some simple routines for obtaining random numbers for    *
 * casual use.  These are pretty secure on systems with /dev/urandom, but  *
 * falls back to poor entropy for seeding on systems without such support. *
 *                                                                         *
 *                   Based on DNET / OpenBSD arc4random().                 *
 *                                                                         *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>                        *
 * Copyright (c) 1996 David Mazieres <dm@lcs.mit.edu>                      *
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
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif /* HAV_SYS_TIME_H */
#ifdef WIN32
#include <wincrypt.h>
#endif /* WIN32 */

/* data for our random state */
struct nrand_handle {
  u8    i, j, s[256], *tmp;
  int   tmplen;
};
typedef struct nrand_handle nrand_h;

static void nrand_addrandom(nrand_h *rand, u8 *buf, int len) {
  int i;
  u8 si;

  /* Mix entropy in buf with s[]...
   *
   * This is the ARC4 key-schedule.  It is rather poor and doesn't mix
   * the key in very well.  This causes a bias at the start of the stream.
   * To eliminate most of this bias, the first N bytes of the stream should
   * be dropped.
   */
  rand->i--;
  for (i = 0; i < 256; i++) {
    rand->i = (rand->i + 1);
    si = rand->s[rand->i];
    rand->j = (rand->j + si + buf[i % len]);
    rand->s[rand->i] = rand->s[rand->j];
    rand->s[rand->j] = si;
  }
  rand->j = rand->i;
}

static u8 nrand_getbyte(nrand_h *r) {
  u8 si, sj;

  /* This is the core of ARC4 and provides the pseudo-randomness */
  r->i = (r->i + 1);
  si = r->s[r->i];
  r->j = (r->j + si);
  sj = r->s[r->j];
  r->s[r->i] = sj; /* The start of the the swap */
  r->s[r->j] = si; /* The other half of the swap */
  return (r->s[(si + sj) & 0xff]);
}

int nrand_get(nrand_h *r, void *buf, size_t len) {
  u8 *p;
  size_t i;

  /* Hand out however many bytes were asked for */
  for (p = buf, i = 0; i < len; i++) {
    p[i] = nrand_getbyte(r);
  }
  return (0);
}

void nrand_init(nrand_h *r) {
  u8 seed[256]; /* Starts out with "random" stack data */
  int i;

  /* Gather seed entropy with best the OS has to offer */
#ifdef WIN32
  HCRYPTPROV hcrypt = 0;

  CryptAcquireContext(&hcrypt, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
  CryptGenRandom(hcrypt, sizeof(seed), seed);
  CryptReleaseContext(hcrypt, 0);
#else
  struct timeval *tv = (struct timeval *)seed;
  int *pid = (int *)(seed + sizeof(*tv));
  int fd;

  gettimeofday(tv, NULL); /* fill lowest seed[] with time */
  *pid = getpid();        /* fill next lowest seed[] with pid */

  /* Try to fill the rest of the state with OS provided entropy */
  if ((fd = open("/dev/urandom", O_RDONLY)) != -1 ||
      (fd = open("/dev/arandom", O_RDONLY)) != -1) {
    ssize_t n;
    do {
      errno = 0;
      n = read(fd, seed + sizeof(*tv) + sizeof(*pid),
               sizeof(seed) - sizeof(*tv) - sizeof(*pid));
    } while (n < 0 && errno == EINTR);
    close(fd);
  }
#endif

  /* Fill up our handle with starter values */
  for (i = 0; i < 256; i++) { r->s[i] = i; };
  r->i = r->j = 0;

  nrand_addrandom(r, seed, 128); /* lower half of seed data for entropy */
  nrand_addrandom(r, seed + 128, 128); /* Now use upper half */
  r->tmp = NULL;
  r->tmplen = 0;

  /* This stream will start biased.  Get rid of 1K of the stream */
  nrand_get(r, seed, 256); nrand_get(r, seed, 256);
  nrand_get(r, seed, 256); nrand_get(r, seed, 256);
}

int get_random_bytes(void *buf, int numbytes) {
  static nrand_h state;
  static int state_init = 0;

  /* Initialize if we need to */
  if (!state_init) {
    nrand_init(&state);
    state_init = 1;
  }

  /* Now fill our buffer */
  nrand_get(&state, buf, numbytes);

  return 0;
}

int get_random_int() {
  int i;
  get_random_bytes(&i, sizeof(int));
  return i;
}

unsigned int get_random_uint() {
  unsigned int i;
  get_random_bytes(&i, sizeof(unsigned int));
  return i;
}

u64 get_random_u64() {
  u64 i;
  get_random_bytes(&i, sizeof(i));
  return i;
}


u32 get_random_u32() {
  u32 i;
  get_random_bytes(&i, sizeof(i));
  return i;
}

u16 get_random_u16() {
  u16 i;
  get_random_bytes(&i, sizeof(i));
  return i;
}

u8 get_random_u8() {
  u8 i;
  get_random_bytes(&i, sizeof(i));
  return i;
}

unsigned short get_random_ushort() {
  unsigned short s;
  get_random_bytes(&s, sizeof(unsigned short));
  return s;
}


/* This function is magic ;-)
 *
 * Sometimes Nmap wants to generate IPs that look random
 * but don't have any duplicates.  The strong RC4 generator
 * can't be used for this purpose because it can generate duplicates
 * if you get enough IPs (birthday paradox).
 *
 * This routine exploits the fact that a LCG won't repeat for the
 * entire duration of its period.  An LCG has some pretty bad
 * properties though so this routine does extra work to try to
 * tweak the LCG output so that is has very good statistics but
 * doesn't repeat.  The tweak used was mostly made up on the spot
 * but is generally based on good ideas and has been moderately
 * tested.  See links and reasoning below.
 */
u32 get_random_unique_u32() {
  static u32 state, tweak1, tweak2, tweak3;
  static int state_init = 0;
  u32 output;

  /* Initialize if we need to */
  if (!state_init) {
    get_random_bytes(&state, sizeof(state));
    get_random_bytes(&tweak1, sizeof(tweak1));
    get_random_bytes(&tweak2, sizeof(tweak2));
    get_random_bytes(&tweak3, sizeof(tweak3));

    state_init = 1;
  }

  /* What is this math crap?
   *
   * The whole idea behind this generator is that an LCG can be constructed
   * with a period of exactly 2^32.  As long as the LCG is fed back onto
   * itself the period will be 2^32.  The tweak after the LCG is just
   * a good permutation in GF(2^32).
   *
   * To accomplish the tweak the notion of rounds and round keys from
   * block ciphers has been borrowed.  The only special aspect of this
   * block cipher is that the first round short-circuits the LCG.
   *
   * This block cipher uses three rounds.  Each round is as follows:
   *
   * 1) Affine transform in GF(2^32)
   * 2) Rotate left by round constant
   * 3) XOR with round key
   *
   * For round one the affine transform is used as an LCG.
   */

  /* Reasoning:
   *
   * Affine transforms were chosen both to make a LCG and also
   * to try to introduce non-linearity.
   *
   * The rotate up each round was borrowed from SHA-1 and was introduced
   * to help obscure the obvious short cycles when you truncate an LCG with
   * a power-of-two period like the one used.
   *
   * The XOR with the round key was borrowed from several different
   * published functions (but see Xorshift)
   * and provides a different sequence for the full LCG.
   * There are 3 32 bit round keys.  This generator can
   * generate 2^96 different sequences of period 2^32.
   *
   * This generator was tested with Dieharder.  It did not fail any test.
   */

  /* See:
   *
   * http://en.wikipedia.org/wiki/Galois_field
   * http://en.wikipedia.org/wiki/Affine_cipher
   * http://en.wikipedia.org/wiki/Linear_congruential_generator
   * http://en.wikipedia.org/wiki/Xorshift
   * http://en.wikipedia.org/wiki/Sha-1
   *
   * http://seclists.org/nmap-dev/2009/q3/0695.html
   */


  /* First off, we need to evolve the state with our LCG
   * We'll use the LCG from Numerical Recipes (m=2^32,
   * a=1664525, c=1013904223).  All by itself this generator
   * pretty bad.  We're going to try to fix that without causing
   * duplicates.
   */
  state = (((state * 1664525) & 0xFFFFFFFF) + 1013904223) & 0xFFFFFFFF;

  output = state;

  /* With a normal LCG, we would just output the state.
   * In this case, though, we are going to try to destroy the
   * linear correlation between IPs by approximating a random permutation
   * in GF(2^32) (collision-free)
   */

  /* Then rotate and XOR */
  output = ((output << 7) | (output >> (32 - 7)));
  output = output ^ tweak1; /* This is the round key */

  /* End round 1, start round 2 */

  /* Then put it through an affine transform (glibc constants) */
  output = (((output * 1103515245) & 0xFFFFFFFF) + 12345) & 0xFFFFFFFF;

  /* Then rotate and XOR some more */
  output = ((output << 15) | (output >> (32 - 15)));
  output = output ^ tweak2;

  /* End round 2, start round 3 */

  /* Then put it through another affine transform (Quick C/C++ constants) */
  output = (((output * 214013) & 0xFFFFFFFF) + 2531011) & 0xFFFFFFFF;

  /* Then rotate and XOR some more */
  output = ((output << 5) | (output >> (32 - 5)));
  output = output ^ tweak3;

  return output;
}
