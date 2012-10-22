/***************************************************************************
 * engine_poll.c -- poll(2) based IO engine.                               *
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

#ifndef WIN32
/* Allow the use of POLLRDHUP, if available. */
#define _GNU_SOURCE
#endif

#ifdef HAVE_CONFIG_H
#include "nsock_config.h"
#elif WIN32
#include "nsock_winconfig.h"
#endif

#if HAVE_POLL

#ifndef WIN32
#include <poll.h>
#else
#include <Winsock2.h>
#endif /* ^WIN32 */

#include "nsock_internal.h"

#if HAVE_PCAP
#include "nsock_pcap.h"
#endif

#define EV_LIST_INIT_SIZE 1024

#ifdef WIN32
  #define Poll    WSAPoll
  #define POLLFD  WSAPOLLFD
#else
  #define Poll    poll
  #define POLLFD  struct pollfd
#endif

#define POLL_R_FLAGS (POLLIN | POLLPRI)
#define POLL_W_FLAGS POLLOUT
#ifdef POLLRDHUP
  #define POLL_X_FLAGS (POLLERR | POLLHUP | POLLRDHUP)
#else
  /* POLLRDHUP was introduced later and might be unavailable on older systems. */
  #define POLL_X_FLAGS (POLLERR | POLLHUP)
#endif /* POLLRDHUP */

#define LOWER_MAX_FD(pinfo) \
  do {  \
    pinfo->max_fd--;  \
  } while (pinfo->max_fd >= 0 && pinfo->events[pinfo->max_fd].fd == -1)


/* --- ENGINE INTERFACE PROTOTYPES --- */
static int poll_init(mspool *nsp);
static void poll_destroy(mspool *nsp);
static int poll_iod_register(mspool *nsp, msiod *iod, int ev);
static int poll_iod_unregister(mspool *nsp, msiod *iod);
static int poll_iod_modify(mspool *nsp, msiod *iod, int ev_set, int ev_clr);
static int poll_loop(mspool *nsp, int msec_timeout);


/* ---- ENGINE DEFINITION ---- */
struct io_engine engine_poll = {
  "poll",
  poll_init,
  poll_destroy,
  poll_iod_register,
  poll_iod_unregister,
  poll_iod_modify,
  poll_loop
};


/* --- INTERNAL PROTOTYPES --- */
static void iterate_through_event_lists(mspool *nsp);

/* defined in nsock_core.c */
void process_iod_events(mspool *nsp, msiod *nsi, int ev);
void process_event(mspool *nsp, gh_list *evlist, msevent *nse, int ev);
#if HAVE_PCAP
#ifndef PCAP_CAN_DO_SELECT
int pcap_read_on_nonselect(mspool *nsp);
#endif
#endif

/* defined in nsock_event.c */
void update_first_events(msevent *nse);


extern struct timeval nsock_tod;


/*
 * Engine specific data structure
 */
struct poll_engine_info {
  int capacity;
  int max_fd;
  /* index of the highest poll event */
  POLLFD *events;
};


static inline int evlist_grow(struct poll_engine_info *pinfo) {
  int i;

  i = pinfo->capacity;

  if (pinfo->capacity == 0) {
    pinfo->capacity = EV_LIST_INIT_SIZE;
    pinfo->events = (POLLFD *)safe_malloc(sizeof(POLLFD) * pinfo->capacity);
  } else {
    pinfo->capacity *= 2;
    pinfo->events = (POLLFD *)safe_realloc(pinfo->events, sizeof(POLLFD) * pinfo->capacity);
  }

  while (i < pinfo->capacity) {
    pinfo->events[i].fd = -1;
    pinfo->events[i].events = 0;
    pinfo->events[i].revents = 0;
    i++;
  }
  return pinfo->capacity;
}


int poll_init(mspool *nsp) {
  struct poll_engine_info *pinfo;

  pinfo = (struct poll_engine_info *)safe_malloc(sizeof(struct poll_engine_info));
  pinfo->capacity = 0;
  pinfo->max_fd = -1;
  evlist_grow(pinfo);

  nsp->engine_data = (void *)pinfo;

  return 1;
}

void poll_destroy(mspool *nsp) {
  struct poll_engine_info *pinfo = (struct poll_engine_info *)nsp->engine_data;

  assert(pinfo != NULL);
  free(pinfo->events);
  free(pinfo);
}

int poll_iod_register(mspool *nsp, msiod *iod, int ev) {
  struct poll_engine_info *pinfo = (struct poll_engine_info *)nsp->engine_data;
  int sd;

  assert(!IOD_PROPGET(iod, IOD_REGISTERED));

  iod->watched_events = ev;

  sd = nsi_getsd(iod);
  while (pinfo->capacity < sd + 1)
    evlist_grow(pinfo);

  pinfo->events[sd].fd = sd;
  pinfo->events[sd].events = 0;
  pinfo->events[sd].revents = 0;

  pinfo->max_fd = MAX(pinfo->max_fd, sd);

  if (ev & EV_READ)
    pinfo->events[sd].events |= POLL_R_FLAGS;
  if (ev & EV_WRITE)
    pinfo->events[sd].events |= POLL_W_FLAGS;
  if (ev & EV_EXCEPT)
    pinfo->events[sd].events |= POLL_X_FLAGS;

  IOD_PROPSET(iod, IOD_REGISTERED);
  return 1;
}

int poll_iod_unregister(mspool *nsp, msiod *iod) {
  iod->watched_events = EV_NONE;

  /* some IODs can be unregistered here if they're associated to an event that was
   * immediately completed */
  if (IOD_PROPGET(iod, IOD_REGISTERED)) {
    struct poll_engine_info *pinfo = (struct poll_engine_info *)nsp->engine_data;
    int sd;

    sd = nsi_getsd(iod);
    pinfo->events[sd].fd = -1;
    pinfo->events[sd].events = 0;
    pinfo->events[sd].revents = 0;

    if (pinfo->max_fd == sd) {
      LOWER_MAX_FD(pinfo);
    }

    IOD_PROPCLR(iod, IOD_REGISTERED);
  }
  return 1;
}

int poll_iod_modify(mspool *nsp, msiod *iod, int ev_set, int ev_clr) {
  int sd;
  int new_events;
  struct poll_engine_info *pinfo = (struct poll_engine_info *)nsp->engine_data;

  assert((ev_set & ev_clr) == 0);
  assert(IOD_PROPGET(iod, IOD_REGISTERED));

  new_events = iod->watched_events;
  new_events |= ev_set;
  new_events &= ~ev_clr;

  if (new_events == iod->watched_events)
    return 1; /* nothing to do */

  iod->watched_events = new_events;

  sd = nsi_getsd(iod);

  pinfo->events[sd].fd = sd;
  pinfo->events[sd].events = 0;

  /* regenerate the current set of events for this IOD */
  if (iod->watched_events & EV_READ)
    pinfo->events[sd].events |= POLL_R_FLAGS;
  if (iod->watched_events & EV_WRITE)
    pinfo->events[sd].events |= POLL_W_FLAGS;
  if (iod->watched_events & EV_EXCEPT)
    pinfo->events[sd].events |= POLL_X_FLAGS;

  return 1;
}

int poll_loop(mspool *nsp, int msec_timeout) {
  int results_left = 0;
  int event_msecs; /* msecs before an event goes off */
  int combined_msecs;
  int sock_err = 0;
  struct poll_engine_info *pinfo = (struct poll_engine_info *)nsp->engine_data;

  assert(msec_timeout >= -1);

  if (nsp->events_pending == 0)
    return 0; /* No need to wait on 0 events ... */

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
#ifndef PCAP_CAN_DO_SELECT
    /* do non-blocking read on pcap devices that doesn't support select()
     * If there is anything read, just leave this loop. */
    if (pcap_read_on_nonselect(nsp)) {
      /* okay, something was read. */
    } else
#endif
#endif
    {
      if (pinfo->max_fd > -1)
        results_left = Poll(pinfo->events, pinfo->max_fd + 1, combined_msecs);
      else
        results_left = 0;

      if (results_left == -1)
        sock_err = socket_errno();
    }

    gettimeofday(&nsock_tod, NULL); /* Due to poll delay */
  } while (results_left == -1 && sock_err == EINTR); /* repeat only if signal occurred */

  if (results_left == -1 && sock_err != EINTR) {
    nsock_trace(nsp, "nsock_loop error %d: %s", sock_err, socket_strerror(sock_err));
    nsp->errnum = sock_err;
    return -1;
  }

  iterate_through_event_lists(nsp);

  return 1;
}


/* ---- INTERNAL FUNCTIONS ---- */

static inline int get_evmask(mspool *nsp, msiod *nsi) {
  struct poll_engine_info *pinfo = (struct poll_engine_info *)nsp->engine_data;
  int sd, evmask = EV_NONE;
  POLLFD *pev;

  if (nsi->state != NSIOD_STATE_DELETED
      && nsi->events_pending
      && IOD_PROPGET(nsi, IOD_REGISTERED)) {

#if HAVE_PCAP
      if (nsi->pcap)
        sd = ((mspcap *)nsi->pcap)->pcap_desc;
      else
#endif
        sd = nsi->sd;

      assert(sd < pinfo->capacity);
      pev = &pinfo->events[sd];

      if (pev->revents & POLL_R_FLAGS)
        evmask |= EV_READ;
      if (pev->revents & POLL_W_FLAGS)
        evmask |= EV_WRITE;
      if (pev->events && (pev->revents & POLL_X_FLAGS))
        evmask |= (EV_READ | EV_WRITE | EV_EXCEPT);
  }
  return evmask;
}

/* Iterate through all the event lists (such as connect_events, read_events,
 * timer_events, etc) and take action for those that have completed (due to
 * timeout, i/o, etc) */
void iterate_through_event_lists(mspool *nsp) {
  gh_list_elem *current, *next, *last, *timer_last;

  /* Clear it -- We will find the next event as we go through the list */
  nsp->next_ev.tv_sec = 0;

  last = GH_LIST_LAST_ELEM(&nsp->active_iods);
  timer_last = GH_LIST_LAST_ELEM(&nsp->timer_events);

  for (current = GH_LIST_FIRST_ELEM(&nsp->active_iods);
       current != NULL && GH_LIST_ELEM_PREV(current) != last; current = next) {

    msiod *nsi = (msiod *)GH_LIST_ELEM_DATA(current);

    process_iod_events(nsp, nsi, get_evmask(nsp, nsi));

    next = GH_LIST_ELEM_NEXT(current);
    if (nsi->state == NSIOD_STATE_DELETED) {
      gh_list_remove_elem(&nsp->active_iods, current);
      gh_list_prepend(&nsp->free_iods, nsi);
    }
  }

  /* iterate through timers */
  for (current = GH_LIST_FIRST_ELEM(&nsp->timer_events);
       current != NULL && GH_LIST_ELEM_PREV(current) != timer_last; current = next) {

    msevent *nse = (msevent *)GH_LIST_ELEM_DATA(current);

    process_event(nsp, &nsp->timer_events, nse, EV_NONE);

    next = GH_LIST_ELEM_NEXT(current);
    if (nse->event_done)
      gh_list_remove_elem(&nsp->timer_events, current);
  }
}

#endif /* HAVE_POLL */

