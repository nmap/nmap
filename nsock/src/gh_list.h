/***************************************************************************
 * gh_list.h -- a simple doubly-linked list implementation with a very     *
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

#define GH_LIST_MAGIC 0xBADFACE

/* Take a LIST ELEMENT (not just the data) and return the next one */
#define GH_LIST_ELEM_NEXT(x)  ((x)->next)

/* Same as above but return the previous element */
#define GH_LIST_ELEM_PREV(x)  ((x)->prev)

/* Take a LIST (not a list element) and return the first element */
#define GH_LIST_FIRST_ELEM(x) ((x)->first)

/* Same as above but return the last element */
#define GH_LIST_LAST_ELEM(x)  ((x)->last)

/* Obtain the actual data stored in an element */
#define GH_LIST_ELEM_DATA(x)  ((x)->data)

/* Obtain the number of elements in a list */
#define GH_LIST_COUNT(x)      ((x)->count)


typedef struct gh_list_elem {
  void *data;
  struct gh_list_elem *next;
  struct gh_list_elem *prev;

  /* nonzero if this element was the first (or only) in a group that was
   * allocated.  This means we can safely free() it as long as we are OK with
   * freeing others that were freed with it ... */
  int allocated;

#ifndef NDEBUG
  unsigned long magic;
#endif
} gh_list_elem;

typedef struct gh_list {
  /* Number of elements in the list */
  int count;
  struct gh_list_elem *first;
  struct gh_list_elem *last;

  /* Instead of free()ing elements when something is removed from the list, we
   * stick them here for the next insert. */
  struct gh_list_elem *free;

  /* The number of list elements in the most recent malloc */
  int last_alloc;

#ifndef NDEBUG
  unsigned long magic;
#endif
} gh_list;


int gh_list_init(gh_list *newlist);

gh_list_elem *gh_list_append(gh_list *list, void *data);

gh_list_elem *gh_list_prepend(gh_list *list, void *data);

gh_list_elem *gh_list_insert_before(gh_list *list, gh_list_elem *before, void *data);

void *gh_list_pop(gh_list *list);

int gh_list_remove(gh_list *list, void *data);

int gh_list_free(gh_list *list);

int gh_list_move_front(gh_list *list, gh_list_elem *elem);

int gh_list_remove_elem(gh_list *list, gh_list_elem *elem);

#endif /* GH_LIST_H */

