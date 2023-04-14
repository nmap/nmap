/***************************************************************************
 * engine_kqueue.c -- BSD kqueue(2) based IO engine.                       *
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
#endif

#if HAVE_KQUEUE

#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <errno.h>

#include "nsock_internal.h"
#include "nsock_log.h"

#if HAVE_PCAP
#include "nsock_pcap.h"
#endif

#define INITIAL_EV_COUNT  128


/* --- ENGINE INTERFACE PROTOTYPES --- */
static int kqueue_init(struct npool *nsp);
static void kqueue_destroy(struct npool *nsp);
static int kqueue_iod_register(struct npool *nsp, struct niod *iod, struct nevent *nse, int ev);
static int kqueue_iod_unregister(struct npool *nsp, struct niod *iod);
static int kqueue_iod_modify(struct npool *nsp, struct niod *iod, struct nevent *nse, int ev_set, int ev_clr);
static int kqueue_loop(struct npool *nsp, int msec_timeout);

extern struct io_operations posix_io_operations;

/* ---- ENGINE DEFINITION ---- */
struct io_engine engine_kqueue = {
  "kqueue",
  kqueue_init,
  kqueue_destroy,
  kqueue_iod_register,
  kqueue_iod_unregister,
  kqueue_iod_modify,
  kqueue_loop,
  &posix_io_operations
};


/* --- INTERNAL PROTOTYPES --- */
static void iterate_through_event_lists(struct npool *nsp, int evcount);

/* defined in nsock_core.c */
void process_iod_events(struct npool *nsp, struct niod *nsi, int ev);
void process_event(struct npool *nsp, gh_list_t *evlist, struct nevent *nse, int ev);
void process_expired_events(struct npool *nsp);
#if HAVE_PCAP
#ifndef PCAP_CAN_DO_SELECT
int pcap_read_on_nonselect(struct npool *nsp);
#endif
#endif

/* defined in nsock_event.c */
void update_first_events(struct nevent *nse);


extern struct timeval nsock_tod;


/*
 * Engine specific data structure
 */
struct kqueue_engine_info {
  int kqfd;
  int maxfd;
  size_t evlen;
  struct kevent *events;
};


int kqueue_init(struct npool *nsp) {
  struct kqueue_engine_info *kinfo;

  kinfo = (struct kqueue_engine_info *)safe_malloc(sizeof(struct kqueue_engine_info));

  kinfo->kqfd = kqueue();
  kinfo->maxfd = -1;
  kinfo->evlen = INITIAL_EV_COUNT;
  kinfo->events = (struct kevent *)safe_malloc(INITIAL_EV_COUNT * sizeof(struct kevent));

  nsp->engine_data = (void *)kinfo;

  return 1;
}

void kqueue_destroy(struct npool *nsp) {
  struct kqueue_engine_info *kinfo = (struct kqueue_engine_info *)nsp->engine_data;

  assert(kinfo != NULL);
  close(kinfo->kqfd);
  free(kinfo->events);
  free(kinfo);
}

int kqueue_iod_register(struct npool *nsp, struct niod *iod, struct nevent *nse, int ev) {
  struct kqueue_engine_info *kinfo = (struct kqueue_engine_info *)nsp->engine_data;

  assert(!IOD_PROPGET(iod, IOD_REGISTERED));

  IOD_PROPSET(iod, IOD_REGISTERED);
  iod->watched_events = EV_NONE;

  kqueue_iod_modify(nsp, iod, nse, ev, EV_NONE);

  if (nsock_iod_get_sd(iod) > kinfo->maxfd)
    kinfo->maxfd = nsock_iod_get_sd(iod);

  return 1;
}

int kqueue_iod_unregister(struct npool *nsp, struct niod *iod) {
  struct kqueue_engine_info *kinfo = (struct kqueue_engine_info *)nsp->engine_data;

  /* some IODs can be unregistered here if they're associated to an event that was
   * immediately completed */
  if (IOD_PROPGET(iod, IOD_REGISTERED)) {
    kqueue_iod_modify(nsp, iod, NULL, EV_NONE, EV_READ|EV_WRITE);
    IOD_PROPCLR(iod, IOD_REGISTERED);

    if (nsock_iod_get_sd(iod) == kinfo->maxfd)
      kinfo->maxfd--;
  }
  iod->watched_events = EV_NONE;
  return 1;
}

#define EV_SETFLAG(_set, _ev) (((_set) & (_ev)) ? (EV_ADD|EV_ENABLE) : (EV_ADD|EV_DISABLE))

int kqueue_iod_modify(struct npool *nsp, struct niod *iod, struct nevent *nse, int ev_set, int ev_clr) {
  struct kevent kev[2];
  int new_events, i;
  struct kqueue_engine_info *kinfo = (struct kqueue_engine_info *)nsp->engine_data;

  assert((ev_set & ev_clr) == 0);
  assert(IOD_PROPGET(iod, IOD_REGISTERED));

  new_events = iod->watched_events;
  new_events |= ev_set;
  new_events &= ~ev_clr;

  if (new_events == iod->watched_events)
    return 1; /* nothing to do */

  i = 0;
  if ((ev_set ^ ev_clr) & EV_READ) {
    EV_SET(&kev[i], nsock_iod_get_sd(iod), EVFILT_READ, EV_SETFLAG(ev_set, EV_READ), 0, 0, (void *)iod);
    i++;
  }
  if ((ev_set ^ ev_clr) & EV_WRITE) {
    EV_SET(&kev[i], nsock_iod_get_sd(iod), EVFILT_WRITE, EV_SETFLAG(ev_set, EV_WRITE), 0, 0, (void *)iod);
    i++;
  }

  if (i > 0 && kevent(kinfo->kqfd, kev, i, NULL, 0, NULL) < 0)
    fatal("Unable to update events for IOD #%lu: %s", iod->id, strerror(errno));

  iod->watched_events = new_events;
  return 1;
}

int kqueue_loop(struct npool *nsp, int msec_timeout) {
  int results_left = 0;
  int event_msecs; /* msecs before an event goes off */
  int combined_msecs;
  struct timespec ts, *ts_p;
  int sock_err = 0;
  struct kqueue_engine_info *kinfo = (struct kqueue_engine_info *)nsp->engine_data;

  assert(msec_timeout >= -1);

  if (nsp->events_pending == 0)
    return 0; /* No need to wait on 0 events ... */


  if (gh_list_count(&nsp->active_iods) > kinfo->evlen) {
    kinfo->evlen = gh_list_count(&nsp->active_iods) * 2;
    kinfo->events = (struct kevent *)safe_realloc(kinfo->events, kinfo->evlen * sizeof(struct kevent));
  }

  do {
    struct nevent *nse;

    nsock_log_debug_all("wait for events");

    nse = next_expirable_event(nsp);
    if (!nse)
      event_msecs = -1; /* None of the events specified a timeout */
    else
      event_msecs = MAX(0, TIMEVAL_MSEC_SUBTRACT(nse->timeout, nsock_tod));

#if HAVE_PCAP
#ifndef PCAP_CAN_DO_SELECT
    /* Force a low timeout when capturing packets on systems where
     * the pcap descriptor is not select()able. */
    if (gh_list_count(&nsp->pcap_read_events) > 0)
      if (event_msecs > PCAP_POLL_INTERVAL)
        event_msecs = PCAP_POLL_INTERVAL;
#endif
#endif

    /* We cast to unsigned because we want -1 to be very high (since it means no
     * timeout) */
    combined_msecs = MIN((unsigned)event_msecs, (unsigned)msec_timeout);

    /* Set up the timeval pointer we will give to kevent() */
    memset(&ts, 0, sizeof(struct timespec));
    if (combined_msecs >= 0) {
      ts.tv_sec = combined_msecs / 1000;
      ts.tv_nsec = (combined_msecs % 1000) * 1000000L;
      ts_p = &ts;
    } else {
      ts_p = NULL;
    }

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
      results_left = kevent(kinfo->kqfd, NULL, 0, kinfo->events, kinfo->evlen, ts_p);
      if (results_left == -1)
        sock_err = socket_errno();
    }

    gettimeofday(&nsock_tod, NULL); /* Due to kevent delay */
  } while (results_left == -1 && sock_err == EINTR); /* repeat only if signal occurred */

  if (results_left == -1 && sock_err != EINTR) {
    nsock_log_error("nsock_loop error %d: %s", sock_err, socket_strerror(sock_err));
    nsp->errnum = sock_err;
    return -1;
  }

  iterate_through_event_lists(nsp, results_left);

  return 1;
}


/* ---- INTERNAL FUNCTIONS ---- */

static inline int get_evmask(struct niod *nsi, const struct kevent *kev) {
  int evmask = EV_NONE;

  /* generate the corresponding event mask with nsock event flags */
  if (kev->flags & EV_ERROR) {
    evmask |= EV_EXCEPT;

    if (kev->data == EPIPE && (nsi->watched_events & EV_READ))
      evmask |= EV_READ;
  } else {
    switch (kev->filter) {
      case EVFILT_READ:
        evmask |= EV_READ;
        break;

      case EVFILT_WRITE:
        evmask |= EV_WRITE;
        break;

      default:
        fatal("Unsupported filter value: %d\n", (int)kev->filter);
    }
  }
  return evmask;
}

/* Iterate through all the event lists (such as connect_events, read_events,
 * timer_events, etc) and take action for those that have completed (due to
 * timeout, i/o, etc) */
void iterate_through_event_lists(struct npool *nsp, int evcount) {
  int n;
  struct kqueue_engine_info *kinfo = (struct kqueue_engine_info *)nsp->engine_data;
  struct niod *nsi;

  for (n = 0; n < evcount; n++) {
    struct kevent *kev = &kinfo->events[n];

    nsi = (struct niod *)kev->udata;

    /* process all the pending events for this IOD */
    process_iod_events(nsp, nsi, get_evmask(nsi, kev));

    IOD_PROPSET(nsi, IOD_PROCESSED);
  }

  for (n = 0; n < evcount; n++) {
    struct kevent *kev = &kinfo->events[n];

    nsi = (struct niod *)kev->udata;

    if (nsi->state == NSIOD_STATE_DELETED) {
      if (IOD_PROPGET(nsi, IOD_PROCESSED)) {
        IOD_PROPCLR(nsi, IOD_PROCESSED);
        gh_list_remove(&nsp->active_iods, &nsi->nodeq);
        gh_list_prepend(&nsp->free_iods, &nsi->nodeq);
      }
    }
  }

  /* iterate through timers and expired events */
  process_expired_events(nsp);
}

#endif /* HAVE_KQUEUE */

