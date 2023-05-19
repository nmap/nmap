/***************************************************************************
 * gh_list.h -- a simple doubly-linked list implementation.                *
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

#ifndef GH_LIST_H
#define GH_LIST_H

#ifdef HAVE_CONFIG_H
#include "nsock_config.h"
#include "nbase_config.h"
#endif

#ifdef WIN32
#include "nbase_winconfig.h"
#endif

#include "error.h"
#include <assert.h>

#define GH_LIST_MAGIC       0xBADFACE
#ifndef GH_LIST_PARANOID
#define GH_LIST_PARANOID    0
#endif


typedef struct gh_list_node {
  struct gh_list_node *next;
  struct gh_list_node *prev;
} gh_lnode_t;

typedef struct gh_list {
  /* Number of elements in the list */
  unsigned int count;
  gh_lnode_t *first;
  gh_lnode_t *last;
} gh_list_t;


/* That one's an efficiency killer but it should reveal
 * any inconsistency in nsock's lists management. To be
 * called on every list we get and return. */
static inline void paranoid_list_check(gh_list_t *list) {
#if GH_LIST_PARANOID
  switch (list->count) {
    case 0:
      assert(list->first == NULL);
      assert(list->last == NULL);
      break;

    case 1:
      assert(list->first);
      assert(list->last);
      assert(list->first == list->last);
      break;

    default:
      assert(list->first);
      assert(list->last);
      assert(list->first != list->last);
      break;
  }
#endif
}

static inline int gh_list_init(gh_list_t *newlist) {
  newlist->count = 0;
  newlist->first = NULL;
  newlist->last  = NULL;
  return 0;
}

static inline int gh_list_append(gh_list_t *list, gh_lnode_t *lnode) {
  gh_lnode_t *oldlast;

  paranoid_list_check(list);

  oldlast = list->last;
  if (oldlast)
    oldlast->next = lnode;

  lnode->prev = oldlast;
  lnode->next = NULL;

  list->count++;
  list->last = lnode;

  if (list->count == 1)
    list->first = lnode;

  paranoid_list_check(list);
  return 0;
}

static inline int gh_list_prepend(gh_list_t *list, gh_lnode_t *lnode) {
  gh_lnode_t *oldfirst;

  paranoid_list_check(list);

  oldfirst = list->first;
  if (oldfirst)
    oldfirst->prev = lnode;

  lnode->next = oldfirst;
  lnode->prev = NULL;

  list->count++;
  list->first = lnode;

  if (list->count == 1)
    list->last = lnode;

  paranoid_list_check(list);
  return 0;
}

static inline int gh_list_insert_before(gh_list_t *list, gh_lnode_t *before,
                                        gh_lnode_t *lnode) {
  paranoid_list_check(list);

  lnode->prev = before->prev;
  lnode->next = before;

  if (before->prev)
    before->prev->next = lnode;
  else
    list->first = lnode;

  before->prev = lnode;
  list->count++;

  paranoid_list_check(list);
  return 0;
}

static inline gh_lnode_t *gh_list_pop(gh_list_t *list) {
  gh_lnode_t *elem;

  paranoid_list_check(list);

  elem = list->first;
  if (!elem) {
    paranoid_list_check(list);
    return NULL;
  }

  list->first = list->first->next;
  if (list->first)
    list->first->prev = NULL;

  list->count--;

  if (list->count < 2)
    list->last = list->first;

  elem->prev = NULL;
  elem->next = NULL;

  paranoid_list_check(list);
  return elem;
}

static inline int gh_list_remove(gh_list_t *list, gh_lnode_t *lnode) {
  paranoid_list_check(list);

  if (lnode->prev) {
    lnode->prev->next = lnode->next;
  } else {
    assert(list->first == lnode);
    list->first = lnode->next;
  }

  if (lnode->next) {
    lnode->next->prev = lnode->prev;
  } else {
    assert(list->last == lnode);
    list->last = lnode->prev;
  }

  lnode->prev = NULL;
  lnode->next = NULL;

  list->count--;

  paranoid_list_check(list);
  return 0;
}

static inline int gh_list_free(gh_list_t *list) {
  paranoid_list_check(list);

  while (list->count > 0)
    gh_list_pop(list);

  paranoid_list_check(list);
  memset(list, 0, sizeof(gh_list_t));
  return 0;
}

static inline int gh_list_move_front(gh_list_t *list, gh_lnode_t *lnode) {
  paranoid_list_check(list);
  if (list->first == lnode)
    return 0;

  /* remove element from its current position */
  lnode->prev->next = lnode->next;

  if (lnode->next) {
    lnode->next->prev = lnode->prev;
  } else {
    assert(list->last == lnode);
    list->last = lnode->prev;
  }

  /* add element to the beginning of the list */
  list->first->prev = lnode;
  lnode->next = list->first;
  lnode->prev = NULL;
  list->first = lnode;

  paranoid_list_check(list);
  return 0;
}

/* Take a LIST ELEMENT (not just the data) and return the next one */
static inline gh_lnode_t *gh_lnode_next(gh_lnode_t *elem) {
  return elem->next;
}

/* Same as above but return the previous element */
static inline gh_lnode_t *gh_lnode_prev(gh_lnode_t *elem) {
  return elem->prev;
}

/* Take a LIST (not a list element) and return the first element */
static inline gh_lnode_t *gh_list_first_elem(gh_list_t *list) {
  return list->first;
}

/* Same as above but return the last element */
static inline gh_lnode_t *gh_list_last_elem(gh_list_t *list) {
  return list->last;
}

static inline unsigned int gh_list_count(gh_list_t *list) {
  return list->count;
}

#endif /* GH_LIST_H */
