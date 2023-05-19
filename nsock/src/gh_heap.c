/***************************************************************************
 * gh_heap.c -- heap based priority queue.                                 *
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

#ifdef HAVE_CONFIG_H
#include "nsock_config.h"
#include "nbase_config.h"
#endif

#ifdef WIN32
#include "nbase_winconfig.h"
#endif

#include <nbase.h>
#include "gh_heap.h"

#define GH_SLOTS   128


static gh_hnode_t **hnode_ptr(gh_heap_t *heap, unsigned int index) {
  assert(index <= heap->count);
  gh_hnode_t **ptr = &(heap->slots[index]);
  assert(index == heap->count || (*ptr)->index == index);
  return ptr;
}

gh_hnode_t *gh_heap_find(gh_heap_t *heap, unsigned int index) {
  if (index >= heap->count)
    return NULL;

  return *hnode_ptr(heap, index);
}

static int hnode_up(gh_heap_t *heap, gh_hnode_t *hnode)
{
  unsigned int cur_idx = hnode->index;
  gh_hnode_t **cur_ptr = hnode_ptr(heap, cur_idx);
  unsigned int parent_idx;
  gh_hnode_t **parent_ptr;
  int action = 0;

  assert(*cur_ptr == hnode);

  while (cur_idx > 0) {
    parent_idx = (cur_idx - 1) >> 1;

    parent_ptr = hnode_ptr(heap, parent_idx);

    if (heap->cmp_op(*parent_ptr, hnode))
      break;

    (*parent_ptr)->index = cur_idx;
    *cur_ptr = *parent_ptr;
    cur_ptr = parent_ptr;
    cur_idx = parent_idx;
    action = 1;
  }

  hnode->index = cur_idx;
  *cur_ptr = hnode;

  return action;
}

static int hnode_down(gh_heap_t *heap, gh_hnode_t *hnode)
{
  unsigned int count = heap->count;
  unsigned int ch1_idx, ch2_idx, cur_idx;
  gh_hnode_t **ch1_ptr, **ch2_ptr, **cur_ptr;
  gh_hnode_t  *ch1, *ch2;
  int action = 0;

  cur_idx = hnode->index;
  cur_ptr = hnode_ptr(heap, cur_idx);
  assert(*cur_ptr == hnode);

  while (cur_idx < count) {
    ch1_idx = (cur_idx << 1) + 1;
    if (ch1_idx >= count)
      break;

    ch1_ptr = hnode_ptr(heap, ch1_idx);
    ch1 = *ch1_ptr;

    ch2_idx = ch1_idx + 1;
    if (ch2_idx < count) {
      ch2_ptr = hnode_ptr(heap, ch2_idx);
      ch2 = *ch2_ptr;

      if (heap->cmp_op(ch2, ch1)) {
        ch1_idx = ch2_idx;
        ch1_ptr = ch2_ptr;
        ch1 = ch2;
      }
    }

    assert(ch1->index == ch1_idx);

    if (heap->cmp_op(hnode, ch1))
      break;

    ch1->index = cur_idx;
    *cur_ptr = ch1;
    cur_ptr = ch1_ptr;
    cur_idx = ch1_idx;
    action = 1;
  }

  hnode->index = cur_idx;
  *cur_ptr = hnode;

  return action;
}

static int heap_grow(gh_heap_t *heap) {
  int newsize;

  /* Do we really need to grow? */
  assert(heap->count == heap->highwm);

  newsize = heap->count + GH_SLOTS;
  heap->slots = (gh_hnode_t **)safe_realloc(heap->slots,
                                            newsize * sizeof(gh_hnode_t *));
  heap->highwm += GH_SLOTS;
  memset(heap->slots + heap->count, 0, GH_SLOTS * sizeof(gh_hnode_t *));
  return 0;
}

int gh_heap_init(gh_heap_t *heap, gh_heap_cmp_t cmp_op) {
  int rc;

  if (!cmp_op)
      return -1;

  heap->cmp_op = cmp_op;
  heap->count  = 0;
  heap->highwm = 0;
  heap->slots  = NULL;

  rc = heap_grow(heap);
  if (rc)
    gh_heap_free(heap);

  return rc;
}

void gh_heap_free(gh_heap_t *heap) {
  if (heap->highwm) {
    assert(heap->slots);
    free(heap->slots);
  }
  memset(heap, 0, sizeof(gh_heap_t));
}

int gh_heap_push(gh_heap_t *heap, gh_hnode_t *hnode) {
  gh_hnode_t **new_ptr;
  unsigned int new_index = heap->count;

  assert(!gh_hnode_is_valid(hnode));

  if (new_index == heap->highwm)
    heap_grow(heap);

  hnode->index = new_index;
  new_ptr = hnode_ptr(heap, new_index);
  assert(*new_ptr == NULL);
  heap->count++;
  *new_ptr = hnode;

  hnode_up(heap, hnode);
  return 0;
}

int gh_heap_remove(gh_heap_t *heap, gh_hnode_t *hnode)
{
  unsigned int count = heap->count;
  unsigned int cur_idx = hnode->index;
  gh_hnode_t **cur_ptr;
  gh_hnode_t *last;

  assert(gh_hnode_is_valid(hnode));
  assert(cur_idx < count);

  cur_ptr = hnode_ptr(heap, cur_idx);
  assert(*cur_ptr == hnode);

  count--;
  last = *hnode_ptr(heap, count);
  heap->count = count;
  if (last != hnode)
  {
    last->index = cur_idx;
    *cur_ptr = last;
    if (!hnode_up(heap, *cur_ptr))
      hnode_down(heap, *cur_ptr);
  }

  gh_hnode_invalidate(hnode);
  cur_ptr = hnode_ptr(heap, count);
  *cur_ptr = NULL;
  return 0;
}
