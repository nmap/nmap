/***************************************************************************
 * engine_epoll.c -- epoll(7) based IO engine.                             *
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
 * to nmap-dev@insecure.org for possible incorporation into the main       *
 * distribution.  By sending these changes to Fyodor or one of the         *
 * Insecure.Org development mailing lists, it is assumed that you are      *
 * offering the Nmap Project (Insecure.Com LLC) the unlimited,             *
 * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
 * will always be available Open Source, but this is important because the *
 * inability to relicense code has caused devastating problems for other   *
 * Free Software projects (such as KDE and NASM).  We also occasionally    *
 * relicense the code to third parties as discussed above.  If you wish to *
 * specify special license conditions of your contributions, just say so   *
 * when you send them.                                                     *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License v2.0 for more details                            *
 * (http://www.gnu.org/licenses/gpl-2.0.html).                             *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */

#ifdef HAVE_CONFIG_H
#include "nsock_config.h"
#endif

#if HAVE_EPOLL

#include <sys/epoll.h>
#include <errno.h>

#include "nsock_internal.h"

#if HAVE_PCAP
#include "nsock_pcap.h"
#endif

#define INITIAL_EV_COUNT  128

#define EPOLL_R_FLAGS (EPOLLIN | EPOLLPRI)
#define EPOLL_W_FLAGS EPOLLOUT
#ifdef EPOLLRDHUP
  #define EPOLL_X_FLAGS (EPOLLERR | EPOLLRDHUP| EPOLLHUP)
#else
  /* EPOLLRDHUP was introduced later and might be unavailable on older systems. */
  #define EPOLL_X_FLAGS (EPOLLERR | EPOLLHUP)
#endif /* EPOLLRDHUP */


/* --- ENGINE INTERFACE PROTOTYPES --- */
static int epoll_init(mspool *nsp);
static void epoll_destroy(mspool *nsp);
static int epoll_iod_register(mspool *nsp, msiod *iod, int ev);
static int epoll_iod_unregister(mspool *nsp, msiod *iod);
static int epoll_iod_modify(mspool *nsp, msiod *iod, int ev_set, int ev_clr);
static int epoll_loop(mspool *nsp, int msec_timeout);


/* ---- ENGINE DEFINITION ---- */
struct io_engine engine_epoll = {
  "epoll",
  epoll_init,
  epoll_destroy,
  epoll_iod_register,
  epoll_iod_unregister,
  epoll_iod_modify,
  epoll_loop
};


/* --- INTERNAL PROTOTYPES --- */
static void iterate_through_event_lists(mspool *nsp, int evcount);

/* defined in nsock_core.c */
void process_iod_events(mspool *nsp, msiod *nsi, int ev);
void process_event(mspool *nsp, gh_list *evlist, msevent *nse, int ev);
#if HAVE_PCAP
int pcap_read_on_nonselect(mspool *nsp);
#endif

/* defined in nsock_event.c */
void update_first_events(msevent *nse);


extern struct timeval nsock_tod;


/*
 * Engine specific data structure
 */
struct epoll_engine_info {
  /* file descriptor corresponding to our epoll instance */
  int epfd;
  /* number of epoll_events we can deal with */
  int evlen;
  /* list of epoll events, resized if necessary (when polling over large numbers of IODs) */
  struct epoll_event *events;
};


int epoll_init(mspool *nsp) {
  struct epoll_engine_info *einfo;

  einfo = (struct epoll_engine_info *)safe_malloc(sizeof(struct epoll_engine_info));

  einfo->epfd = epoll_create(10); /* argument is ignored */
  einfo->evlen = INITIAL_EV_COUNT;
  einfo->events = (struct epoll_event *)safe_malloc(einfo->evlen * sizeof(struct epoll_event));

  nsp->engine_data = (void *)einfo;

  return 1;
}

void epoll_destroy(mspool *nsp) {
  struct epoll_engine_info *einfo = (struct epoll_engine_info *)nsp->engine_data;

  assert(einfo != NULL);
  close(einfo->epfd);
  free(einfo->events);
  free(einfo);
}

int epoll_iod_register(mspool *nsp, msiod *iod, int ev) {
  int sd;
  struct epoll_event epev;
  struct epoll_engine_info *einfo = (struct epoll_engine_info *)nsp->engine_data;

  assert(!IOD_PROPGET(iod, IOD_REGISTERED));

  iod->watched_events = ev;

  memset(&epev, 0x00, sizeof(struct epoll_event));
  epev.events = EPOLLET;
  epev.data.ptr = (void *)iod;

  if (ev & EV_READ)
    epev.events |= EPOLL_R_FLAGS;
  if (ev & EV_WRITE)
    epev.events |= EPOLL_W_FLAGS;
  if (ev & EV_EXCEPT)
    epev.events |= EPOLL_X_FLAGS;

  sd = nsi_getsd(iod);
  if (epoll_ctl(einfo->epfd, EPOLL_CTL_ADD, sd, &epev) < 0)
    fatal("Unable to register IOD #%lu: %s", iod->id, strerror(errno));

  IOD_PROPSET(iod, IOD_REGISTERED);
  return 1;
}

int epoll_iod_unregister(mspool *nsp, msiod *iod) {
  iod->watched_events = EV_NONE;

  /* some IODs can be unregistered here if they're associated to an event that was
   * immediately completed */
  if (IOD_PROPGET(iod, IOD_REGISTERED)) {
    struct epoll_engine_info *einfo = (struct epoll_engine_info *)nsp->engine_data;
    int sd;

    sd = nsi_getsd(iod);
    epoll_ctl(einfo->epfd, EPOLL_CTL_DEL, sd, NULL);

    IOD_PROPCLR(iod, IOD_REGISTERED);
  }
  return 1;
}

int epoll_iod_modify(mspool *nsp, msiod *iod, int ev_set, int ev_clr) {
  int sd;
  struct epoll_event epev;
  int new_events;
  struct epoll_engine_info *einfo = (struct epoll_engine_info *)nsp->engine_data;

  assert((ev_set & ev_clr) == 0);

  memset(&epev, 0x00, sizeof(struct epoll_event));
  epev.events = EPOLLET;
  epev.data.ptr = (void *)iod;

  new_events = iod->watched_events;
  new_events |= ev_set;
  new_events &= ~ev_clr;

  if (new_events == iod->watched_events)
    return 1; /* nothing to do */

  iod->watched_events = new_events;

  /* regenerate the current set of events for this IOD */
  if (iod->watched_events & EV_READ)
    epev.events |= EPOLL_R_FLAGS;
  if (iod->watched_events & EV_WRITE)
    epev.events |= EPOLL_W_FLAGS;
  if (iod->watched_events & EV_EXCEPT)
    epev.events |= EPOLL_X_FLAGS;

  sd = nsi_getsd(iod);
  if (epoll_ctl(einfo->epfd, EPOLL_CTL_MOD, sd, &epev) < 0) {
    if (errno == ENOENT) {
      /* This IOD is registered but its associated fd is not in the epoll set.
       * It was probably closed and another one was open (e.g.: reconnect operation).
       * We therefore want to add the new one. */
      epoll_ctl(einfo->epfd, EPOLL_CTL_ADD, sd, &epev);
    } else {
      fatal("Unable to update events for IOD #%lu: %s", iod->id, strerror(errno));
    }
  }
  return 1;
}

int epoll_loop(mspool *nsp, int msec_timeout) {
  int results_left = 0;
  int event_msecs; /* msecs before an event goes off */
  int combined_msecs;
  int sock_err = 0;
  struct epoll_engine_info *einfo = (struct epoll_engine_info *)nsp->engine_data;

  assert(msec_timeout >= -1);

  if (nsp->events_pending == 0)
    return 0; /* No need to wait on 0 events ... */


  if (GH_LIST_COUNT(&nsp->active_iods) > einfo->evlen) {
    einfo->evlen = GH_LIST_COUNT(&nsp->active_iods) * 2;
    einfo->events = (struct epoll_event *)safe_realloc(einfo->events, einfo->evlen * sizeof(struct epoll_event));
  }

  do {
    if (nsp->tracelevel > 6)
      nsock_trace(nsp, "wait_for_events");

    if (nsp->next_ev.tv_sec == 0)
      event_msecs = -1; /* None of the events specified a timeout */
    else
      event_msecs = MAX(0, TIMEVAL_MSEC_SUBTRACT(nsp->next_ev, nsock_tod));

#if HAVE_PCAP
#ifndef PCAP_CAN_DO_SELECT
    /* Force a low timeout when capturing packets on systems where
     * the pcap descriptor is not select()able. */
    if (GH_LIST_COUNT(&nsp->pcap_read_events) > 0)
      if (event_msecs > PCAP_POLL_INTERVAL)
        event_msecs = PCAP_POLL_INTERVAL;
#endif
#endif

    /* We cast to unsigned because we want -1 to be very high (since it means no
     * timeout) */
    combined_msecs = MIN((unsigned)event_msecs, (unsigned)msec_timeout);

#if HAVE_PCAP
    /* do non-blocking read on pcap devices that doesn't support select()
     * If there is anything read, just leave this loop. */
    if (pcap_read_on_nonselect(nsp)) {
      /* okay, something was read. */
    } else
#endif
    {
      if (einfo->evlen)
        results_left = epoll_wait(einfo->epfd, einfo->events, einfo->evlen, combined_msecs);
      else
        results_left = 0;

      if (results_left == -1)
        sock_err = socket_errno();
    }

    gettimeofday(&nsock_tod, NULL); /* Due to epoll delay */
  } while (results_left == -1 && sock_err == EINTR); /* repeat only if signal occurred */

  if (results_left == -1 && sock_err != EINTR) {
    nsock_trace(nsp, "nsock_loop error %d: %s", sock_err, socket_strerror(sock_err));
    nsp->errnum = sock_err;
    return -1;
  }

  iterate_through_event_lists(nsp, results_left);

  return 1;
}


/* ---- INTERNAL FUNCTIONS ---- */

/* Iterate through all the event lists (such as connect_events, read_events,
 * timer_events, etc) and take action for those that have completed (due to
 * timeout, i/o, etc) */
void iterate_through_event_lists(mspool *nsp, int evcount) {
  int n, initial_iod_count;
  struct epoll_engine_info *einfo = (struct epoll_engine_info *)nsp->engine_data;
  gh_list_elem *current, *next, *last, *timer_last, *last_active = NULL;
  msevent *nse;
  msiod *nsi;

  /* Clear it -- We will find the next event as we go through the list */
  nsp->next_ev.tv_sec = 0;

  last = GH_LIST_LAST_ELEM(&nsp->active_iods);
  timer_last = GH_LIST_LAST_ELEM(&nsp->timer_events);

  initial_iod_count = GH_LIST_COUNT(&nsp->active_iods);

  for (n = 0; n < evcount; n++) {
    int evmask = EV_NONE;

    nsi = (msiod *)einfo->events[n].data.ptr;
    assert(nsi);

    if (nsi->entry_in_nsp_active_iods == last)
      last = GH_LIST_ELEM_PREV(nsi->entry_in_nsp_active_iods);

    /* generate the corresponding event mask with nsock event flags */
    if (einfo->events[n].events & EPOLL_R_FLAGS)
      evmask |= EV_READ;
    if (einfo->events[n].events & EPOLL_W_FLAGS)
      evmask |= EV_WRITE;
    if (einfo->events[n].events & EPOLL_X_FLAGS)
      evmask |= (EV_READ | EV_WRITE | EV_EXCEPT);

    /* process all the pending events for this IOD */
    process_iod_events(nsp, nsi, evmask);

    if (nsi->state != NSIOD_STATE_DELETED) {
      gh_list_move_front(&nsp->active_iods, nsi->entry_in_nsp_active_iods);
      if (last_active == NULL)
        last_active = nsi->entry_in_nsp_active_iods;
    } else {
      gh_list_remove_elem(&nsp->active_iods, nsi->entry_in_nsp_active_iods);
      gh_list_prepend(&nsp->free_iods, nsi);
    }
  }

  if (evcount < initial_iod_count) {
    /* some IODs had no active events and need to be processed */
    if (!last_active)
      /* either no IOD had events or all IODs were deleted after event processing */
      current = GH_LIST_FIRST_ELEM(&nsp->active_iods);
    else
      /* IODs that had active events were pushed to the beginning of the list, start after them */
      current = GH_LIST_ELEM_NEXT(last_active);
  } else {
    /* all the IODs had events and were therefore processed */
    current = NULL;
  }

  /* cull timeouts amongst the non active IODs */
  while (current != NULL && GH_LIST_ELEM_PREV(current) != last) {
    msiod *nsi = (msiod *)GH_LIST_ELEM_DATA(current);

    if (nsi->state != NSIOD_STATE_DELETED && nsi->events_pending)
      process_iod_events(nsp, nsi, EV_NONE);

    next = GH_LIST_ELEM_NEXT(current);
    if (nsi->state == NSIOD_STATE_DELETED) {
      gh_list_remove_elem(&nsp->active_iods, current);
      gh_list_prepend(&nsp->free_iods, nsi);
    }
    current = next;
  }

  /* iterate through timers */
  for (current = GH_LIST_FIRST_ELEM(&nsp->timer_events);
      current != NULL && GH_LIST_ELEM_PREV(current) != timer_last; current = next) {

    nse = (msevent *)GH_LIST_ELEM_DATA(current);

    process_event(nsp, &nsp->timer_events, nse, EV_NONE);

    next = GH_LIST_ELEM_NEXT(current);
    if (nse->event_done)
      gh_list_remove_elem(&nsp->timer_events, current);
  }
}

#endif /* HAVE_EPOLL */

