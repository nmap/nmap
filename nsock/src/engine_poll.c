/***************************************************************************
 * engine_poll.c -- poll(2) based IO engine.                               *
 *                                                                         *
 ***********************IMPORTANT NSOCK LICENSE TERMS***********************
 *
 * The nsock parallel socket event library is (C) 1999-2025 Nmap Software LLC
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

#include <errno.h>

#ifndef WIN32
#include <poll.h>
#else
#include <Winsock2.h>
#endif /* ^WIN32 */

#include "nsock_internal.h"
#include "nsock_log.h"

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

#ifdef WIN32
  #define POLL_R_FLAGS (POLLIN)
#else
  #define POLL_R_FLAGS (POLLIN | POLLPRI)
#endif /* WIN32 */

#define POLL_W_FLAGS POLLOUT
#ifdef POLLRDHUP
  #define POLL_X_FLAGS (POLLERR | POLLHUP | POLLRDHUP)
#else
  /* POLLRDHUP was introduced later and might be unavailable on older systems. */
  #define POLL_X_FLAGS (POLLERR | POLLHUP)
#endif /* POLLRDHUP */

extern struct io_operations posix_io_operations;

/* --- ENGINE INTERFACE PROTOTYPES --- */
static int poll_init(struct npool *nsp);
static void poll_destroy(struct npool *nsp);
static int poll_iod_register(struct npool *nsp, struct niod *iod, struct nevent *nse, int ev);
static int poll_iod_unregister(struct npool *nsp, struct niod *iod);
static int poll_iod_modify(struct npool *nsp, struct niod *iod, struct nevent *nse, int ev_set, int ev_clr);
static int poll_loop(struct npool *nsp, int msec_timeout);


/* ---- ENGINE DEFINITION ---- */
struct io_engine engine_poll = {
  "poll",
  poll_init,
  poll_destroy,
  poll_iod_register,
  poll_iod_unregister,
  poll_iod_modify,
  poll_loop,
  &posix_io_operations
};


/* --- INTERNAL PROTOTYPES --- */
static void iterate_through_event_lists(struct npool *nsp);


/*
 * Engine specific data structure
 */
struct poll_engine_info {
  int capacity;
  int used;
  int idx_insert;
  int max_idx;
  POLLFD *events;
  /* Number of IODs incompatible with poll */
  int num_pcap_nonselect;
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


int poll_init(struct npool *nsp) {
  struct poll_engine_info *pinfo;

  pinfo = (struct poll_engine_info *)safe_malloc(sizeof(struct poll_engine_info));
  pinfo->capacity = 0;
  pinfo->used = 0;
  pinfo->idx_insert = 0;
  pinfo->max_idx = -1;
  pinfo->num_pcap_nonselect = 0;
  evlist_grow(pinfo);

  nsp->engine_data = (void *)pinfo;

  return 1;
}

void poll_destroy(struct npool *nsp) {
  struct poll_engine_info *pinfo = (struct poll_engine_info *)nsp->engine_data;

  assert(pinfo != NULL);
  free(pinfo->events);
  free(pinfo);
}

int poll_iod_register(struct npool *nsp, struct niod *iod, struct nevent *nse, int ev) {
  struct poll_engine_info *pinfo = (struct poll_engine_info *)nsp->engine_data;
  int sd;
  int idx;
  POLLFD *pev;

  assert(!IOD_PROPGET(iod, IOD_REGISTERED));

  iod->watched_events = ev;

  sd = nsock_iod_get_sd(iod);

  if (sd == -1) {
    if (iod->pcap)
      pinfo->num_pcap_nonselect++;
    else
      fatal("Unable to get descriptor for IOD #%lu", iod->id);
    iod->engine_info = -1;
  }
  else {
    if (pinfo->used == pinfo->capacity)
      evlist_grow(pinfo);

    idx = pinfo->idx_insert;
    while (pinfo->events[idx].fd != -1) {
      idx = (idx + 1) % pinfo->capacity;
      // XXX: remove this assert after thorough testing.
      assert(idx != pinfo->idx_insert);
    }
    if (idx > pinfo->max_idx)
      pinfo->max_idx = idx;

    iod->engine_info = idx;
    pinfo->idx_insert = (idx + 1) % pinfo->capacity;
    pinfo->used++;

    pev = &pinfo->events[idx];
    pev->fd = sd;
    pev->events = 0;
    pev->revents = 0;

    if (ev & EV_READ)
      pev->events |= POLL_R_FLAGS;
    if (ev & EV_WRITE)
      pev->events |= POLL_W_FLAGS;
    /* POLL_X_FLAGS are output-only. */
  }

  IOD_PROPSET(iod, IOD_REGISTERED);
  return 1;
}

int poll_iod_unregister(struct npool *nsp, struct niod *iod) {
  struct poll_engine_info *pinfo = (struct poll_engine_info *)nsp->engine_data;
  int sd, idx;
  POLLFD *pev;

  iod->watched_events = EV_NONE;

  /* some IODs can be unregistered here if they're associated to an event that was
   * immediately completed */
  if (IOD_PROPGET(iod, IOD_REGISTERED)) {

    sd = nsock_iod_get_sd(iod);
    if (sd == -1) {
      assert(iod->pcap);
      pinfo->num_pcap_nonselect--;
    }
    else {
      idx = iod->engine_info;
      assert(idx >= 0 && idx <= pinfo->max_idx);
      pev = &pinfo->events[idx];
      assert(pev->fd == sd);
      iod->engine_info = -1;

      pev->fd = -1;
      pev->events = 0;
      pev->revents = 0;

      pinfo->used--;
      if (idx == pinfo->max_idx) {
        do {
          pinfo->max_idx--;
        } while (pinfo->max_idx >= 0 && pinfo->events[pinfo->max_idx].fd == -1);
      }
      if (idx < pinfo->idx_insert) {
        pinfo->idx_insert = idx;
      }
      if (pinfo->max_idx < pinfo->idx_insert) {
        pinfo->idx_insert = pinfo->max_idx + 1;
      }

    }
    IOD_PROPCLR(iod, IOD_REGISTERED);
  }
  return 1;
}

int poll_iod_modify(struct npool *nsp, struct niod *iod, struct nevent *nse, int ev_set, int ev_clr) {
  int sd, idx;
  POLLFD *pev;
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

  sd = nsock_iod_get_sd(iod);
  if (sd >= 0) {
    idx = iod->engine_info;
    assert(idx >= 0 && idx <= pinfo->max_idx);

    pev = &pinfo->events[idx];
    pev->fd = sd;
    pev->events = 0;

    /* regenerate the current set of events for this IOD */
    if (iod->watched_events & EV_READ)
      pev->events |= POLL_R_FLAGS;
    if (iod->watched_events & EV_WRITE)
      pev->events |= POLL_W_FLAGS;
  }

  return 1;
}

int poll_loop(struct npool *nsp, int msec_timeout) {
  int results_left = 0;
  int event_msecs; /* msecs before an event goes off */
  int combined_msecs;
  int sock_err = 0;
  unsigned int iod_count;
  struct poll_engine_info *pinfo = (struct poll_engine_info *)nsp->engine_data;

  assert(msec_timeout >= -1);

  if (nsp->events_pending == 0)
    return 0; /* No need to wait on 0 events ... */

  iod_count = gh_list_count(&nsp->active_iods) - pinfo->num_pcap_nonselect;
  do {
    struct nevent *nse;

    nsock_log_debug_all("wait for events");
    results_left = 0;

    nse = next_expirable_event(nsp);
    if (!nse)
      event_msecs = -1; /* None of the events specified a timeout */
    else {
      event_msecs = TIMEVAL_MSEC_SUBTRACT(nse->timeout, nsock_tod);
      event_msecs = MAX(0, event_msecs);
    }

#if HAVE_PCAP
    if (pinfo->num_pcap_nonselect > 0 && gh_list_count(&nsp->pcap_read_events) > 0) {

      /* do non-blocking read on pcap devices that doesn't support select()
       * If there is anything read, just leave this loop. */
      if (pcap_read_on_nonselect(nsp)) {
        /* okay, something was read. */
        // poll engine's iterate_through_event_lists() also handles pcap iods.
        // Make the system call non-blocking
        event_msecs = 0;
      }
      /* Force a low timeout when capturing packets on systems where
       * the pcap descriptor is not select()able. */
      else if (event_msecs > PCAP_POLL_INTERVAL) {
        event_msecs = PCAP_POLL_INTERVAL;
      }
    }
#endif
    /* We cast to unsigned because we want -1 to be very high (since it means no
     * timeout) */
    combined_msecs = MIN((unsigned)event_msecs, (unsigned)msec_timeout);

    assert(iod_count <= pinfo->used);
    assert(pinfo->used < pinfo->max_idx);
    if (iod_count > 0 && pinfo->used > 0) {
      results_left = Poll(pinfo->events, pinfo->max_idx + 1, combined_msecs);
      if (results_left == -1)
        sock_err = socket_errno();
    }
    else if (combined_msecs > 0) {
      // No compatible IODs; sleep the remainder of the wait time.
      usleep(combined_msecs * 1000);
    }


    gettimeofday(&nsock_tod, NULL); /* Due to poll delay */
  } while (results_left == -1 && sock_err == EINTR); /* repeat only if signal occurred */

  if (results_left == -1 && sock_err != EINTR) {
    nsock_log_error("nsock_loop error %d: %s", sock_err, socket_strerror(sock_err));
    nsp->errnum = sock_err;
    return -1;
  }

  iterate_through_event_lists(nsp);

  return 1;
}


/* ---- INTERNAL FUNCTIONS ---- */

static inline int get_evmask(struct npool *nsp, struct niod *nsi) {
  struct poll_engine_info *pinfo = (struct poll_engine_info *)nsp->engine_data;
  int sd, evmask = EV_NONE;
  int idx;
  POLLFD *pev;

  if (nsi->state != NSIOD_STATE_DELETED
      && nsi->events_pending
      && IOD_PROPGET(nsi, IOD_REGISTERED)) {

      sd = nsock_iod_get_sd(nsi);
#if HAVE_PCAP
      // For incompatible pcap handles, we have to just try a non-blocking read.
      if (sd == -1 && nsi->pcap)
        return EV_READ;
#endif

      idx = nsi->engine_info;

      assert(idx >= 0 && idx <= pinfo->max_idx);
      pev = &pinfo->events[idx];
      assert(pev->fd == sd);

      if (pev->revents & POLL_R_FLAGS)
        evmask |= EV_READ;
      if (pev->revents & POLL_W_FLAGS)
        evmask |= EV_WRITE;
      if (pev->revents & POLL_X_FLAGS)
        evmask |= EV_EXCEPT;
  }
  return evmask;
}

/* Iterate through all the event lists (such as connect_events, read_events,
 * timer_events, etc) and take action for those that have completed (due to
 * timeout, i/o, etc) */
void iterate_through_event_lists(struct npool *nsp) {
  gh_lnode_t *current, *next, *last;

  last = gh_list_last_elem(&nsp->active_iods);

  for (current = gh_list_first_elem(&nsp->active_iods);
       current != NULL && gh_lnode_prev(current) != last;
       current = next) {
    struct niod *nsi = container_of(current, struct niod, nodeq);

    process_iod_events(nsp, nsi, get_evmask(nsp, nsi));

    next = gh_lnode_next(current);
    if (nsi->state == NSIOD_STATE_DELETED) {
      gh_list_remove(&nsp->active_iods, current);
      gh_list_prepend(&nsp->free_iods, current);
    }
  }

  /* iterate through timers and expired events */
  process_expired_events(nsp);
}

#endif /* HAVE_POLL */
