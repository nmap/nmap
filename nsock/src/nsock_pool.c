/***************************************************************************
 * nsock_pool.c -- This contains the functions that deal with creating,    *
 * destroying, and otherwise manipulating nsock_pools (and their internal  *
 * mspool representation).  An nsock_pool aggregates and manages events    *
 * and i/o descriptors                                                     *
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

unsigned long nsp_next_id = 2;

/* To use this library, the first thing they must do is create a pool
 * so we do the initialization during the first pool creation */
static int nsocklib_initialized = 0;


/* defined in nsock_engines.h */
struct io_engine *get_io_engine(void);

/* ---- INTERNAL FUNCTIONS PROTOTYPES ---- */
static void nsock_library_initialize(void);
/* --------------------------------------- */


/* Every mst has an ID that is unique across the program execution */
unsigned long nsp_getid(nsock_pool nsp) {
  mspool *mt = (mspool *)nsp;
  return mt->id;
}

/* This next function returns the errno style error code -- which is only
 * valid if the status NSOCK_LOOP_ERROR was returned by nsock_loop() */

int nsp_geterrorcode(nsock_pool nsp) {
  mspool *mt = (mspool *)nsp;
  return mt->errnum;
}

/* Sometimes it is useful to store a pointer to information inside
 * the NSP so you can retrieve it during a callback. */
void nsp_setud(nsock_pool nsp, void *data) {
  mspool *mt = (mspool *)nsp;
  mt->userdata = data;
}

/* And the define above wouldn't make much sense if we didn't have a way
 * to retrieve that data ... */
void *nsp_getud(nsock_pool nsp) {
  mspool *mt = (mspool *)nsp;
  return mt->userdata;
}

/* Turns on or off broadcast support on new sockets. Default is off (0, false)
 * set in nsp_new(). Any non-zero (true) value sets SO_BROADCAST on all new
 * sockets (value of optval will be used directly in the setsockopt() call */
void nsp_setbroadcast(nsock_pool nsp, int optval) {
  mspool *mt = (mspool *)nsp;
  mt->broadcast = optval;
}

/* Sets the name of the interface for new sockets to bind to. */
void nsp_setdevice(nsock_pool nsp, const char *device) {
  mspool *mt = (mspool *)nsp;
  mt->device = device;
}

/* And here is how you create an nsock_pool.  This allocates, initializes, and
 * returns an nsock_pool event aggregator.  In the case of error, NULL will be
 * returned.  If you do not wish to immediately associate any userdata, pass in
 * NULL. */
nsock_pool nsp_new(void *userdata) {
  mspool *nsp;

  /* initialize the library in not already done */
  if (!nsocklib_initialized) {
    nsock_library_initialize();
    nsocklib_initialized = 1;
  }

  nsp = (mspool *)safe_malloc(sizeof(*nsp));
  memset(nsp, 0, sizeof(*nsp));

  gettimeofday(&nsock_tod, NULL);

  nsp->loglevel = NSOCK_LOG_ERROR;
  nsp->logger   = (nsock_logger_t)nsock_stderr_logger;

  nsp->id = nsp_next_id++;

  nsp->userdata = userdata;

  nsp->engine = get_io_engine();
  nsp->engine->init(nsp);

  /* initialize IO events lists */
  gh_list_init(&nsp->connect_events);
  gh_list_init(&nsp->read_events);
  gh_list_init(&nsp->write_events);
#if HAVE_PCAP
  gh_list_init(&nsp->pcap_read_events);
#endif
  /* initialize timer list */
  gh_list_init(&nsp->timer_events);

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

  return (nsock_pool)nsp;
}

/* If nsp_new returned success, you must free the nsp when you are done with it
 * to conserve memory (and in some cases, sockets).  After this call, nsp may no
 * longer be used.  Any pending events are sent an NSE_STATUS_KILL callback and
 * all outstanding iods are deleted. */
void nsp_delete(nsock_pool ms_pool) {
  mspool *nsp = (mspool *)ms_pool;
  msevent *nse;
  msiod *nsi;
  int i;
  gh_list_elem *current, *next;
  gh_list *event_lists[] = {
    &nsp->connect_events,
    &nsp->read_events,
    &nsp->write_events,
    &nsp->timer_events,
#if HAVE_PCAP
    &nsp->pcap_read_events,
#endif
    NULL
  };

  assert(nsp);

  /* First I go through all the events sending NSE_STATUS_KILL */
  for (i = 0; event_lists[i] != NULL; i++) {
    while (GH_LIST_COUNT(event_lists[i]) > 0) {
      nse = (msevent *)gh_list_pop(event_lists[i]);

      assert(nse);
      nse->status = NSE_STATUS_KILL;
      nsock_trace_handler_callback(nsp, nse);
      nse->handler(nsp, nse, nse->userdata);
      if (nse->iod) {
        nse->iod->events_pending--;
        assert(nse->iod->events_pending >= 0);
      }
      msevent_delete(nsp, nse);
    }
    gh_list_free(event_lists[i]);
  }

  /* foreach msiod */
  for (current = GH_LIST_FIRST_ELEM(&nsp->active_iods); current != NULL; current = next) {
    next = GH_LIST_ELEM_NEXT(current);
    nsi = (msiod *)GH_LIST_ELEM_DATA(current);
    nsi_delete(nsi, NSOCK_PENDING_ERROR);

    gh_list_remove_elem(&nsp->active_iods, current);
    gh_list_prepend(&nsp->free_iods, nsi);
  }

  /* Now we free all the memory in the free iod list */
  while ((nsi = (msiod *)gh_list_pop(&nsp->free_iods))) {
    free(nsi);
  }

  while ((nse = (msevent *)gh_list_pop(&nsp->free_events))) {
    free(nse);
  }

  gh_list_free(&nsp->active_iods);
  gh_list_free(&nsp->free_iods);
  gh_list_free(&nsp->free_events);

  nsp->engine->destroy(nsp);

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

