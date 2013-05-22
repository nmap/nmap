/***************************************************************************
 * gh_list.c -- a simple doubly-linked list implementation with a very     *
 * heavy focus on efficiency.                                              *
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

#include "nsock.h"

#include "gh_list.h"

#include <nbase.h>

#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_STRINGS_H
#include <strings.h>
#endif


#define SAFETY_CHECK_LIST(l) do { \
    assert(l); \
    assert((l)->magic == GH_LIST_MAGIC); \
    assert((l)->count == 0 || ((l)->first && (l)->last)); \
    assert((l)->count != 0 || ((l)->first == NULL && (l)->last == NULL)); \
  } while (0)

#define SAFETY_CHECK_ELEM(e) do { \
    assert(e); \
    assert((e)->magic == GH_LIST_MAGIC); \
  } while (0)


static inline struct gh_list_elem *get_free_buffer(struct gh_list *list) {
  struct gh_list_elem *newelem;
  int i;

  if (!list->free) {
    list->last_alloc *= 2;
    list->free = (struct gh_list_elem *)safe_malloc(list->last_alloc * sizeof(struct gh_list_elem));
    memset(list->free, 0, list->last_alloc * sizeof(struct gh_list_elem));
    list->free->allocated = 1;
    for (i=0; i < list->last_alloc - 1; i++) {
      (list->free + i)->next = list->free + i + 1;
    }
  }
  newelem = list->free;
  list->free = list->free->next;
#ifndef NDEBUG
  newelem->magic = GH_LIST_MAGIC;
#endif
  return newelem;
}

int gh_list_init(gh_list *newlist) {
  int i;

  if (!newlist)
    return -1;

  newlist->count = 0;
  newlist->first = newlist->last = NULL;
  newlist->last_alloc = 16;
  newlist->free = (struct gh_list_elem *)safe_malloc(newlist->last_alloc * sizeof(struct gh_list_elem));

  memset(newlist->free, 0, newlist->last_alloc * sizeof(struct gh_list_elem));
  newlist->free->allocated = 1;

  for (i = 0; i < newlist->last_alloc - 1; i++) {
    (newlist->free + i)->next = newlist->free + i + 1;
  }
  /* Not needed (newlist->free + newlist->last_alloc - 1)->next = NULL */
#ifndef NDEBUG
  newlist->magic = GH_LIST_MAGIC;
#endif
  return 0;
}

gh_list_elem *gh_list_append(gh_list *list, void *data) {
  gh_list_elem *newelem;
  gh_list_elem *oldlast;

  SAFETY_CHECK_LIST(list);

  newelem = get_free_buffer(list);
  oldlast = list->last;

  if (oldlast) {
    oldlast->next = newelem;
    newelem->prev = oldlast;
  } else {
    newelem->prev = NULL;
  }

  newelem->next = NULL;
  newelem->data = data;

#ifndef NDEBUG
  newelem->magic = GH_LIST_MAGIC;
#endif

  list->count++;
  list->last = newelem;

  if (list->count == 1)
    list->first = newelem;

  return newelem;
}

gh_list_elem *gh_list_prepend(gh_list *list, void *data) {
  gh_list_elem *newelem;
  gh_list_elem *oldfirst;

  SAFETY_CHECK_LIST(list);

  newelem = get_free_buffer(list);
  oldfirst = list->first;
  if (oldfirst) {
    oldfirst->prev = newelem;
    newelem->next = oldfirst;
  } else {
    newelem->next = NULL;
  }

  newelem->prev = NULL;
  newelem->data = data;

#ifndef NDEBUG
  newelem->magic = GH_LIST_MAGIC;
#endif

  list->count++;
  list->first = newelem;

  if (list->count == 1)
    list->last = newelem;

  return newelem;
}

gh_list_elem *gh_list_insert_before(gh_list *list, gh_list_elem *before, void *data) {
  gh_list_elem *newelem;

  SAFETY_CHECK_LIST(list);
  SAFETY_CHECK_ELEM(before);

  /* create or reuse a new cell */
  newelem = get_free_buffer(list);

  newelem->data = data;
  newelem->prev = before->prev;
  newelem->next = before;
#ifndef NDEBUG
  newelem->magic = GH_LIST_MAGIC;
#endif

  if (before->prev)
    before->prev->next = newelem;
  else
    list->first = newelem;

  before->prev = newelem;

  list->count++;

  return newelem;
}

void *gh_list_pop(gh_list *list) {
  struct gh_list_elem *oldelem;

  SAFETY_CHECK_LIST(list);

  oldelem = list->first;
  if (!oldelem)
    return NULL;

  list->first = list->first->next;
  if (list->first)
    list->first->prev = NULL;

  list->count--;

  if (list->count < 2)
    list->last = list->first;

  oldelem->next = list->free;
  list->free = oldelem;

  return oldelem->data;
}

int gh_list_free(gh_list *list) {
  struct gh_list_elem *current;
  char *free_list[32];
  int free_index = 0;
  int i = 0;

  SAFETY_CHECK_LIST(list);

#ifndef NDEBUG
  list->magic++;
#endif

  for (current = list->first; current; current = current->next) {
#ifndef NDEBUG
    current->magic++;
#endif
    if (current->allocated) {
      assert(free_index < 32);
      free_list[free_index++] = (char *)current;
    }
  }

  for (current = list->free; current; current = current->next)
    if (current->allocated) {
      assert(free_index < 32);
      free_list[free_index++] = (char *)current;
    }

  for (i = 0; i < free_index; i++)
    free(free_list[i]);

  return 0;
}

int gh_list_remove_elem(gh_list *list, gh_list_elem *elem) {
  SAFETY_CHECK_ELEM(elem);
  SAFETY_CHECK_LIST(list);

  if (elem->prev) {
    elem->prev->next = elem->next;
  } else {
    assert(list->first == elem);
    list->first = elem->next;
  }

  if (elem->next) {
    elem->next->prev = elem->prev;
  } else {
    assert(list->last == elem);
    list->last = elem->prev;
  }

#ifndef NDEBUG
  elem->magic++;
#endif

  elem->next = list->free;
  list->free = elem;

  list->count--;
  return 0;
}

int gh_list_move_front(gh_list *list, gh_list_elem *elem) {
  SAFETY_CHECK_LIST(list);
  SAFETY_CHECK_ELEM(elem);

  if (list->first == elem)
      return 0;

  /* remove element from its current position */
  elem->prev->next = elem->next;

  if (elem->next) {
    elem->next->prev = elem->prev;
  } else {
    assert(list->last == elem);
    list->last = elem->prev;
  }

  /* add element to the beginning list */
  list->first->prev = elem;
  elem->next = list->first;
  elem->prev = NULL;
  list->first = elem;

  return 0;
}

int gh_list_remove(gh_list *list, void *data) {
  struct gh_list_elem *current;

  SAFETY_CHECK_LIST(list);

  for (current = list->first; current; current = current->next) {
    if (current->data == data)
      return gh_list_remove_elem(list, current);
  }
  return -1;
}

