/***************************************************************************
 * nsock_pool.c -- This contains the functions that deal with creating,    *
 * destroying, and otherwise manipulating nsock_pools (and their internal  *
 * struct npool representation).  An nsock_pool aggregates and manages events    *
 * and i/o descriptors                                                     *
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

#include "nsock_internal.h"
#include "nsock_log.h"
#include "gh_list.h"
#include "netutils.h"

#include <string.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <signal.h>


extern struct timeval nsock_tod;

/* To use this library, the first thing they must do is create a pool
 * so we do the initialization during the first pool creation */
static int nsocklib_initialized = 0;


/* defined in nsock_engines.h */
struct io_engine *get_io_engine(void);

/* ---- INTERNAL FUNCTIONS PROTOTYPES ---- */
static void nsock_library_initialize(void);
/* --------------------------------------- */


/* This next function returns the errno style error code -- which is only
 * valid if the status NSOCK_LOOP_ERROR was returned by nsock_loop() */
int nsock_pool_get_error(nsock_pool nsp) {
  struct npool *mt = (struct npool *)nsp;
  return mt->errnum;
}

/* Sometimes it is useful to store a pointer to information inside
 * the NSP so you can retrieve it during a callback. */
void nsock_pool_set_udata(nsock_pool nsp, void *data) {
  struct npool *mt = (struct npool *)nsp;
  mt->userdata = data;
}

/* And the define above wouldn't make much sense if we didn't have a way
 * to retrieve that data ... */
void *nsock_pool_get_udata(nsock_pool nsp) {
  struct npool *mt = (struct npool *)nsp;
  return mt->userdata;
}

/* Turns on or off broadcast support on new sockets. Default is off (0, false)
 * set in nsock_pool_new(). Any non-zero (true) value sets SO_BROADCAST on all new
 * sockets (value of optval will be used directly in the setsockopt() call */
void nsock_pool_set_broadcast(nsock_pool nsp, int optval) {
  struct npool *mt = (struct npool *)nsp;
  mt->broadcast = optval;
}

/* Sets the name of the interface for new sockets to bind to. */
void nsock_pool_set_device(nsock_pool nsp, const char *device) {
  struct npool *mt = (struct npool *)nsp;
  mt->device = device;
}

static int expirable_cmp(gh_hnode_t *n1, gh_hnode_t *n2) {
  struct nevent *nse1;
  struct nevent *nse2;

  nse1 = container_of(n1, struct nevent, expire);
  nse2 = container_of(n2, struct nevent, expire);

  return (TIMEVAL_BEFORE(nse1->timeout, nse2->timeout)) ? 1 : 0;
}

/* And here is how you create an nsock_pool.  This allocates, initializes, and
 * returns an nsock_pool event aggregator.  In the case of error, NULL will be
 * returned.  If you do not wish to immediately associate any userdata, pass in
 * NULL. */
nsock_pool nsock_pool_new(void *userdata) {
  struct npool *nsp;

  /* initialize the library in not already done */
  if (!nsocklib_initialized) {
    nsock_library_initialize();
    nsocklib_initialized = 1;
  }

  nsp = (struct npool *)safe_malloc(sizeof(*nsp));
  memset(nsp, 0, sizeof(*nsp));

  gettimeofday(&nsock_tod, NULL);

  nsp->userdata = userdata;

  nsp->engine = get_io_engine();
  nsock_engine_init(nsp);

  /* initialize IO events lists */
  gh_list_init(&nsp->connect_events);
  gh_list_init(&nsp->read_events);
  gh_list_init(&nsp->write_events);
#if HAVE_PCAP
  gh_list_init(&nsp->pcap_read_events);
#endif

  /* initialize timer heap */
  gh_heap_init(&nsp->expirables, expirable_cmp);

  /* initialize the list of IODs */
  gh_list_init(&nsp->active_iods);

  /* initialize caches */
  gh_list_init(&nsp->free_iods);
  gh_list_init(&nsp->free_events);

  nsp->next_event_serial = 1;

  nsp->device = NULL;

#if HAVE_OPENSSL
  nsp->sslctx = NULL;
#endif

  nsp->px_chain = NULL;

  return (nsock_pool)nsp;
}

/* If nsock_pool_new returned success, you must free the nsp when you are done with it
 * to conserve memory (and in some cases, sockets).  After this call, nsp may no
 * longer be used.  Any pending events are sent an NSE_STATUS_KILL callback and
 * all outstanding iods are deleted. */
void nsock_pool_delete(nsock_pool ms_pool) {
  struct npool *nsp = (struct npool *)ms_pool;
  struct nevent *nse;
  struct niod *nsi;
  int i;
  gh_lnode_t *current, *next;
  gh_list_t *event_lists[] = {
    &nsp->connect_events,
    &nsp->read_events,
    &nsp->write_events,
#if HAVE_PCAP
    &nsp->pcap_read_events,
#endif
    NULL
  };

  assert(nsp);

  /* First I go through all the events sending NSE_STATUS_KILL */
  for (i = 0; event_lists[i] != NULL; i++) {
    while (gh_list_count(event_lists[i]) > 0) {
      gh_lnode_t *lnode = gh_list_pop(event_lists[i]);

      assert(lnode);

#if HAVE_PCAP
      if (event_lists[i] == &nsp->pcap_read_events)
        nse = lnode_nevent2(lnode);
      else
#endif
        nse = lnode_nevent(lnode);

      assert(nse);

      nse->status = NSE_STATUS_KILL;
      nsock_trace_handler_callback(nsp, nse);
      nse->handler(nsp, nse, nse->userdata);

      if (nse->iod) {
        nse->iod->events_pending--;
        assert(nse->iod->events_pending >= 0);
      }
      event_delete(nsp, nse);
    }
    gh_list_free(event_lists[i]);
  }

  /* Kill timers too, they're not in event lists */
  while (gh_heap_count(&nsp->expirables) > 0) {
    gh_hnode_t *hnode;

    hnode = gh_heap_pop(&nsp->expirables);
    nse = container_of(hnode, struct nevent, expire);

    if (nse->type == NSE_TYPE_TIMER) {
      nse->status = NSE_STATUS_KILL;
      nsock_trace_handler_callback(nsp, nse);
      nse->handler(nsp, nse, nse->userdata);
      event_delete(nsp, nse);
      gh_list_append(&nsp->free_events, &nse->nodeq_io);
    }
  }

  gh_heap_free(&nsp->expirables);

  /* foreach struct niod */
  for (current = gh_list_first_elem(&nsp->active_iods);
       current != NULL;
       current = next) {
    next = gh_lnode_next(current);
    nsi = container_of(current, struct niod, nodeq);

    nsock_iod_delete(nsi, NSOCK_PENDING_ERROR);

    gh_list_remove(&nsp->active_iods, current);
    gh_list_prepend(&nsp->free_iods, &nsi->nodeq);
  }

  /* Now we free all the memory in the free iod list */
  while ((current = gh_list_pop(&nsp->free_iods))) {
    nsi = container_of(current, struct niod, nodeq);
    free(nsi);
  }

  while ((current = gh_list_pop(&nsp->free_events))) {
    nse = lnode_nevent(current);
    free(nse);
  }

  gh_list_free(&nsp->active_iods);
  gh_list_free(&nsp->free_iods);
  gh_list_free(&nsp->free_events);

  nsock_engine_destroy(nsp);

#if HAVE_OPENSSL
  if (nsp->sslctx != NULL)
    SSL_CTX_free(nsp->sslctx);
#endif

  free(nsp);
}

void nsock_library_initialize(void) {
  int res;

  /* We want to make darn sure the evil SIGPIPE is ignored */
#ifndef WIN32
  signal(SIGPIPE, SIG_IGN);
#endif

  /* And we're gonna need sockets -- LOTS of sockets ... */
  res = maximize_fdlimit();
#ifndef WIN32
  assert(res > 7);
#endif
}

