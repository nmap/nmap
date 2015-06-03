/***************************************************************************
 * gh_heap.h -- heap based priority queues.                                *
 *                                                                         *
 ***********************IMPORTANT NSOCK LICENSE TERMS***********************
 *                                                                         *
 * The nsock parallel socket event library is (C) 1999-2015 Insecure.Com   *
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License v2.0 for more details                            *
 * (http://www.gnu.org/licenses/gpl-2.0.html).                             *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */

#ifndef GH_HEAP_H
#define GH_HEAP_H

#ifdef HAVE_CONFIG_H
#include "nsock_config.h"
#include "nbase_config.h"
#endif

#ifdef WIN32
#include "nbase_winconfig.h"
#endif

#include "error.h"
#include <assert.h>


#if !defined(container_of)
#include <stddef.h>

#define container_of(ptr, type, member) \
        ((type *)((char *)(ptr) - offsetof(type, member)))
#endif


typedef struct {
  unsigned int index;
} gh_hnode_t;

/* POISON value, set heap node index to this value to indicate that the node is
 * inactive (not part of a heap) */
#define GH_HEAP_GUARD  0x19890721

/* Node comparison function.
 * Here lies all the intelligence of the tree.
 * Return 1 if hnode1 < hnode2, 0 otherwise. */
typedef int (*gh_heap_cmp_t)(gh_hnode_t *hnode1, gh_hnode_t *hnode2);


typedef struct gh_heap {
  gh_heap_cmp_t cmp_op;
  unsigned int count;
  unsigned int highwm;
  gh_hnode_t **slots;
} gh_heap_t;


int gh_heap_init(gh_heap_t *heap, gh_heap_cmp_t cmp_op);

void gh_heap_free(gh_heap_t *heap);

int gh_heap_push(gh_heap_t *heap, gh_hnode_t *node);

int gh_heap_remove(gh_heap_t *heap, gh_hnode_t *node);

gh_hnode_t *gh_heap_find(gh_heap_t *heap, unsigned int index);


static inline gh_hnode_t *gh_heap_min(gh_heap_t *heap) {
  if (heap->count == 0)
    return NULL;

  return gh_heap_find(heap, 0);
}

static inline gh_hnode_t *gh_heap_pop(gh_heap_t *heap) {
  gh_hnode_t *hnode;

  hnode = gh_heap_find(heap, 0);
  if (hnode != NULL)
    gh_heap_remove(heap, hnode);

  return hnode;
}

static inline size_t gh_heap_count(gh_heap_t *heap) {
  return heap->count;
}

static inline int gh_heap_is_empty(gh_heap_t *heap) {
  return heap->count == 0;
}

static inline void gh_hnode_invalidate(gh_hnode_t *node) {
  node->index = GH_HEAP_GUARD;
}

static inline int gh_hnode_is_valid(const gh_hnode_t *node) {
  return (node && node->index != GH_HEAP_GUARD);
}

#endif /* GH_HEAP_H */
