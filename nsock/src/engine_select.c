/***************************************************************************
 * engine_select.c -- select(2) based IO engine.                           *
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
#include <sys/select.h>
#endif

#include <errno.h>

#include "nsock_internal.h"
#include "nsock_log.h"

#if HAVE_PCAP
#include "nsock_pcap.h"
#endif

extern struct io_operations posix_io_operations;


/* --- ENGINE INTERFACE PROTOTYPES --- */
static int select_init(struct npool *nsp);
static void select_destroy(struct npool *nsp);
static int select_iod_register(struct npool *nsp, struct niod *iod, struct nevent *nse, int ev);
static int select_iod_unregister(struct npool *nsp, struct niod *iod);
static int select_iod_modify(struct npool *nsp, struct niod *iod, struct nevent *nse, int ev_set, int ev_clr);
static int select_loop(struct npool *nsp, int msec_timeout);


/* ---- ENGINE DEFINITION ---- */
struct io_engine engine_select = {
  "select",
  select_init,
  select_destroy,
  select_iod_register,
  select_iod_unregister,
  select_iod_modify,
  select_loop,
  &posix_io_operations
};


/* --- INTERNAL PROTOTYPES --- */
static void iterate_through_event_lists(struct npool *nsp);


/*
 * Engine specific data structure
 */
struct select_engine_info {
  /* Descriptors which have pending READ events */
  fd_set fds_master_r;

  /* Descriptors we are trying to WRITE to */
  fd_set fds_master_w;

  /* Looking for exceptional events -- used with connect */
  fd_set fds_master_x;

  /* For keeping track of the select results */
  fd_set fds_results_r, fds_results_w, fds_results_x;

  /* The highest sd we have set in any of our fd_set's (max_sd + 1 is used in
   * select() calls).  Note that it can be -1, when there are no valid sockets */
  int max_sd;
  /* Number of IODs incompatible with select */
  int num_pcap_nonselect;
};


int select_init(struct npool *nsp) {
  struct select_engine_info *sinfo;

  sinfo = (struct select_engine_info *)safe_malloc(sizeof(struct select_engine_info));

  FD_ZERO(&sinfo->fds_master_r);
  FD_ZERO(&sinfo->fds_master_w);
  FD_ZERO(&sinfo->fds_master_x);

  sinfo->max_sd = -1;
  sinfo->num_pcap_nonselect = 0;

  nsp->engine_data = (void *)sinfo;

  return 1;
}

void select_destroy(struct npool *nsp) {
  assert(nsp->engine_data != NULL);
  free(nsp->engine_data);
}

int select_iod_register(struct npool *nsp, struct niod *iod, struct nevent *nse, int ev) {
  struct select_engine_info *sinfo = (struct select_engine_info *)nsp->engine_data;
  assert(!IOD_PROPGET(iod, IOD_REGISTERED));

  if (nsock_iod_get_sd(iod) == -1) {
    sinfo->num_pcap_nonselect++;
  }
  iod->watched_events = ev;
  select_iod_modify(nsp, iod, nse, ev, EV_NONE);
  IOD_PROPSET(iod, IOD_REGISTERED);
  return 1;
}

int select_iod_unregister(struct npool *nsp, struct niod *iod) {
  struct select_engine_info *sinfo = (struct select_engine_info *)nsp->engine_data;

  iod->watched_events = EV_NONE;

  /* some IODs can be unregistered here if they're associated to an event that was
   * immediately completed */
  if (IOD_PROPGET(iod, IOD_REGISTERED)) {
    int sd = nsock_iod_get_sd(iod);
    if (sd == -1) {
      assert(iod->pcap);
      sinfo->num_pcap_nonselect--;
    }
    else {
      checked_fd_clr(sd, &sinfo->fds_master_r);
      checked_fd_clr(sd, &sinfo->fds_master_w);
      checked_fd_clr(sd, &sinfo->fds_master_x);
      checked_fd_clr(sd, &sinfo->fds_results_r);
      checked_fd_clr(sd, &sinfo->fds_results_w);
      checked_fd_clr(sd, &sinfo->fds_results_x);

      if (sinfo->max_sd == sd)
        sinfo->max_sd--;
    }

    IOD_PROPCLR(iod, IOD_REGISTERED);
  }
  return 1;
}

int select_iod_modify(struct npool *nsp, struct niod *iod, struct nevent *nse, int ev_set, int ev_clr) {
  int sd;
  struct select_engine_info *sinfo = (struct select_engine_info *)nsp->engine_data;

  assert((ev_set & ev_clr) == 0);

  iod->watched_events |= ev_set;
  iod->watched_events &= ~ev_clr;

  sd = nsock_iod_get_sd(iod);
  if (sd != -1) {
    if (ev_set & EV_READ)
      checked_fd_set(sd, &sinfo->fds_master_r);
    else if (ev_clr & EV_READ)
      checked_fd_clr(sd, &sinfo->fds_master_r);

    if (ev_set & EV_WRITE)
      checked_fd_set(sd, &sinfo->fds_master_w);
    else if (ev_clr & EV_WRITE)
      checked_fd_clr(sd, &sinfo->fds_master_w);

    // Always set EV_EXCEPT. https://seclists.org/nmap-dev/2017/q1/226
    checked_fd_set(sd, &sinfo->fds_master_x);

    /* -- update max_sd -- */
    if (ev_set != EV_NONE)
      sinfo->max_sd = MAX(sinfo->max_sd, sd);
    else if (ev_clr != EV_NONE && iod->events_pending == 1 && (sinfo->max_sd == sd))
      sinfo->max_sd--;
  }

  return 1;
}

int select_loop(struct npool *nsp, int msec_timeout) {
  int results_left = 0;
  int event_msecs; /* msecs before an event goes off */
  int combined_msecs;
  int sock_err = 0;
  struct timeval select_tv;
  struct timeval *select_tv_p;
  unsigned int iod_count;
  struct select_engine_info *sinfo = (struct select_engine_info *)nsp->engine_data;

  assert(msec_timeout >= -1);

  if (nsp->events_pending == 0)
    return 0; /* No need to wait on 0 events ... */

  iod_count = gh_list_count(&nsp->active_iods) - sinfo->num_pcap_nonselect;

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
    if (sinfo->num_pcap_nonselect > 0 && gh_list_count(&nsp->pcap_read_events) > 0) {

      /* do non-blocking read on pcap devices that doesn't support select()
       * If there is anything read, just leave this loop. */
      if (pcap_read_on_nonselect(nsp)) {
        /* okay, something was read. */
        // select engine's iterate_through_event_lists() also handles pcap iods.
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

    if (iod_count > 0) {
      /* Set up the timeval pointer we will give to select() */
      memset(&select_tv, 0, sizeof(select_tv));
      if (combined_msecs > 0) {
        select_tv.tv_sec = combined_msecs / 1000;
        select_tv.tv_usec = (combined_msecs % 1000) * 1000;
        select_tv_p = &select_tv;
      } else if (combined_msecs == 0) {
        /* we want the tv_sec and tv_usec to be zero but they already are from bzero */
        select_tv_p = &select_tv;
      } else {
        assert(combined_msecs == -1);
        select_tv_p = NULL;
      }

      /* Set up the descriptors for select */
      sinfo->fds_results_r = sinfo->fds_master_r;
      sinfo->fds_results_w = sinfo->fds_master_w;
      sinfo->fds_results_x = sinfo->fds_master_x;

      results_left = fselect(sinfo->max_sd + 1, &sinfo->fds_results_r,
          &sinfo->fds_results_w, &sinfo->fds_results_x, select_tv_p);

      if (results_left == -1)
        sock_err = socket_errno();
    }
    else if (combined_msecs > 0) {
      // No compatible IODs; sleep the remainder of the wait time.
      usleep(combined_msecs * 1000);
    }

    gettimeofday(&nsock_tod, NULL); /* Due to select delay */
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

static inline int get_evmask(const struct npool *nsp, struct niod *nsi) {
  struct select_engine_info *sinfo = (struct select_engine_info *)nsp->engine_data;
  int sd, evmask;

  evmask = EV_NONE;

  sd = nsock_iod_get_sd(nsi);
#if HAVE_PCAP
  /* Always assume readable for a non-blocking read. We can't check checked_fd_isset
     because we don't have a pcap_desc. */
  if (sd == -1 && nsi->pcap)
    return EV_READ;
#endif

  assert(sd >= 0);

  if (checked_fd_isset(sd, &sinfo->fds_results_r))
    evmask |= EV_READ;
  if (checked_fd_isset(sd, &sinfo->fds_results_w))
    evmask |= EV_WRITE;
  if (checked_fd_isset(sd, &sinfo->fds_results_x))
    evmask |= EV_EXCEPT;

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

    if (nsi->state != NSIOD_STATE_DELETED && nsi->events_pending)
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
