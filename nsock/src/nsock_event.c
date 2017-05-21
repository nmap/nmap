/***************************************************************************
 * nsock_event.c -- Functions dealing with nsock_events (and their         *
 * struct nevent internal representation.  An event is created when you do       *
 * various calls (for reading, writing, connecting, timers, etc) and is    *
 * provided back to you in the callback when the call completes or         *
 * fails. It is automatically destroyed after the callback returns         *
 *                                                                         *
 ***********************IMPORTANT NSOCK LICENSE TERMS***********************
 *                                                                         *
 * The nsock parallel socket event library is (C) 1999-2016 Insecure.Com   *
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

#if HAVE_PCAP
#include "nsock_pcap.h"
#endif

#include <string.h>

extern struct timeval nsock_tod;

/* Find the type of an event that spawned a callback */
enum nse_type nse_type(nsock_event nse) {
  struct nevent *me = (struct nevent *)nse;
  return me->type;
}

enum nse_status nse_status(nsock_event nse) {
  struct nevent *me = (struct nevent *)nse;
  return me->status;
}

int nse_eof(nsock_event nse) {
  struct nevent *me = (struct nevent *)nse;
  return me->eof;
}

/* Obtains the nsock_iod (see below) associated with the event.  Note that
 * some events (such as timers) don't have an nsock_iod associated with them */
nsock_iod nse_iod(nsock_event ms_event) {
  struct nevent *nse = (struct nevent *)ms_event;
  return (nsock_iod) nse->iod;
}

/* This next function returns the errno style error code -- which is only valid
 * if the status is NSE_STATUS_ERROR */
int nse_errorcode(nsock_event nse) {
  struct nevent *me = (struct nevent *)nse;
  return me->errnum;
}

/* Every event has an ID which will be unique throughout the program's execution
 * unless you use (literally) billions of them */
nsock_event_id nse_id(nsock_event nse) {
  struct nevent *me = (struct nevent *)nse;
  return me->id;
}

/* If you did a read request, and the result was STATUS_SUCCESS, this function
 * provides the buffer that was read in as well as the number of chars read.
 * The buffer should not be modified or free'd */
char *nse_readbuf(nsock_event nse, int *nbytes) {
  struct nevent *me = (struct nevent *)nse;

  if (nbytes)
    *nbytes = fs_length(&(me->iobuf));
  return fs_str(&(me->iobuf));
}

static void first_ev_next(struct nevent *nse, gh_lnode_t **first, int nodeq2) {
  if (!first || !*first)
    return;

  if (&nse->nodeq_io == *first || &nse->nodeq_pcap == *first) {
    gh_lnode_t *next;

    next = gh_lnode_next(*first);
    if (next) {
      struct nevent *newevent;

      if (nodeq2)
        newevent = lnode_nevent2(next);
      else
        newevent = lnode_nevent(next);

      if (newevent->iod == nse->iod)
        *first = next;
      else
        *first = NULL;
    } else {
      *first = NULL;
    }
  }
}

void update_first_events(struct nevent *nse) {
  switch (get_event_id_type(nse->id)) {
    case NSE_TYPE_CONNECT:
    case NSE_TYPE_CONNECT_SSL:
      first_ev_next(nse, &nse->iod->first_connect, 0);
      break;

    case NSE_TYPE_READ:
      first_ev_next(nse, &nse->iod->first_read, 0);
      break;

    case NSE_TYPE_WRITE:
      first_ev_next(nse, &nse->iod->first_write, 0);
      break;

#if HAVE_PCAP
    case NSE_TYPE_PCAP_READ:
      first_ev_next(nse, &nse->iod->first_read, 0);
      first_ev_next(nse, &nse->iod->first_pcap_read, 1);
      break;
#endif

    case NSE_TYPE_TIMER:
      /* nothing to do */
      break;

    default:
      fatal("Bogus event type in update_first_events");
      break;
  }
}

/* Cancel an event (such as a timer or read request).  If notify is nonzero, the
 * requester will be sent an event CANCELLED status back to the given handler.
 * But in some cases there is no need to do this (like if the function deleting
 * it is the one which created it), in which case 0 can be passed to skip the
 * step.  This function returns zero if the event is not found, nonzero
 * otherwise. */
int nsock_event_cancel(nsock_pool ms_pool, nsock_event_id id, int notify) {
  struct npool *nsp = (struct npool *)ms_pool;
  enum nse_type type;
  unsigned int i;
  gh_list_t *event_list = NULL, *event_list2 = NULL;
  gh_lnode_t *current, *next;
  struct nevent *nse = NULL;

  assert(nsp);

  type = get_event_id_type(id);
  nsock_log_info("Event #%li (type %s) cancelled", id, nse_type2str(type));

  /* First we figure out what list it is in */
  switch (type) {
    case NSE_TYPE_CONNECT:
    case NSE_TYPE_CONNECT_SSL:
      event_list = &nsp->connect_events;
      break;

    case NSE_TYPE_READ:
      event_list = &nsp->read_events;
      break;

    case NSE_TYPE_WRITE:
      event_list = &nsp->write_events;
      break;

    case NSE_TYPE_TIMER:
      for (i = 0; i < gh_heap_count(&nsp->expirables); i++) {
        gh_hnode_t *hnode;

        hnode = gh_heap_find(&nsp->expirables, i);
        nse = container_of(hnode, struct nevent, expire);
        if (nse->id == id)
          return nevent_delete(nsp, nse, NULL, NULL, notify);
      }
      return 0;

#if HAVE_PCAP
    case NSE_TYPE_PCAP_READ:
      event_list  = &nsp->read_events;
      event_list2 = &nsp->pcap_read_events;
      break;
#endif

    default:
      fatal("Bogus event type in nsock_event_cancel"); break;
  }

  /* Now we try to find the event in the list */
  for (current = gh_list_first_elem(event_list); current != NULL; current = next) {
    next = gh_lnode_next(current);
    nse = lnode_nevent(current);
    if (nse->id == id)
      break;
  }

  if (current == NULL && event_list2) {
    event_list = event_list2;
    for (current = gh_list_first_elem(event_list); current != NULL; current = next) {
      next = gh_lnode_next(current);
      nse = lnode_nevent2(current);
      if (nse->id == id)
        break;
    }
  }
  if (current == NULL)
    return 0;

  return nevent_delete(nsp, nse, event_list, current, notify);
}

/* An internal function for cancelling an event when you already have a pointer
 * to the struct nevent (use nsock_event_cancel if you just have an ID). The
 * event_list passed in should correspond to the type of the event. For example,
 * with NSE_TYPE_READ, you would pass in &nsp->read_events;. elem is the list
 * element in event_list which holds the event.  Pass a nonzero for notify if
 * you want the program owning the event to be notified that it has been
 * cancelled */
int nevent_delete(struct npool *nsp, struct nevent *nse, gh_list_t *event_list,
                   gh_lnode_t *elem, int notify) {
  if (nse->event_done) {
    /* This event has already been marked for death somewhere else -- it will be
     * gone soon (and if we try to kill it now all hell will break loose due to
     * reentrancy. */
    return 0;
  }

  nsock_log_info("%s on event #%li (type %s)", __func__, nse->id,
                 nse_type2str(nse->type));

  /* Now that we found the event... we go through the motions of cleanly
   * cancelling it */
  switch (nse->type) {
    case NSE_TYPE_CONNECT:
    case NSE_TYPE_CONNECT_SSL:
      handle_connect_result(nsp, nse, NSE_STATUS_CANCELLED);
      break;

    case NSE_TYPE_READ:
      handle_read_result(nsp, nse, NSE_STATUS_CANCELLED);
      break;

    case NSE_TYPE_WRITE:
      handle_write_result(nsp, nse, NSE_STATUS_CANCELLED);
      break;

    case NSE_TYPE_TIMER:
      handle_timer_result(nsp, nse, NSE_STATUS_CANCELLED);
      break;

#if HAVE_PCAP
    case NSE_TYPE_PCAP_READ:
      handle_pcap_read_result(nsp, nse, NSE_STATUS_CANCELLED);
      break;
#endif

    default:
      fatal("Invalid nsock event type (%d)", nse->type);
  }

  assert(nse->event_done);

  if (nse->timeout.tv_sec)
    gh_heap_remove(&nsp->expirables, &nse->expire);

  if (event_list) {
    update_first_events(nse);
    gh_list_remove(event_list, elem);
  }

  gh_list_append(&nsp->free_events, &nse->nodeq_io);

  nsock_log_debug_all("NSE #%lu: Removing event from list", nse->id);

#if HAVE_PCAP
#if PCAP_BSD_SELECT_HACK
  if (nse->type == NSE_TYPE_PCAP_READ) {
    nsock_log_debug_all("PCAP NSE #%lu: CANCEL TEST pcap=%p read=%p curr=%p sd=%i",
                        nse->id, &nsp->pcap_read_events, &nsp->read_events,
                        event_list,((mspcap *)nse->iod->pcap)->pcap_desc);

    /* If event occurred, and we're in BSD_HACK mode, then this event was added to
     * two queues. read_event and pcap_read_event Of course we should
     * destroy it only once.  I assume we're now in read_event, so just unlink
     * this event from pcap_read_event */
    if (((mspcap *)nse->iod->pcap)->pcap_desc >= 0 && event_list == &nsp->read_events) {
      /* event is done, list is read_events and we're in BSD_HACK mode. So unlink
       * event from pcap_read_events */
      gh_list_remove(&nsp->pcap_read_events, &nse->nodeq_pcap);
      nsock_log_debug_all("PCAP NSE #%lu: Removing event from PCAP_READ_EVENTS", nse->id);
    }

    if (((mspcap *)nse->iod->pcap)->pcap_desc >= 0 && event_list == &nsp->pcap_read_events) {
      /* event is done, list is read_events and we're in BSD_HACK mode.
       * So unlink event from read_events */
      gh_list_remove(&nsp->read_events, &nse->nodeq_io);

      nsock_log_debug_all("PCAP NSE #%lu: Removing event from READ_EVENTS", nse->id);
    }
  }
#endif
#endif
  event_dispatch_and_delete(nsp, nse, notify);
  return 1;
}

/* Adjust various statistics, dispatches the event handler (if notify is
 * nonzero) and then deletes the event.  This function does NOT delete the event
 * from any lists it might be on (eg nsp->read_list etc.) nse->event_done
 * MUST be true when you call this */
void event_dispatch_and_delete(struct npool *nsp, struct nevent *nse, int notify) {
  assert(nsp);
  assert(nse);

  assert(nse->event_done);

  nsp->events_pending--;
  assert(nsp->events_pending >= 0);

  if (nse->iod) {
    nse->iod->events_pending--;
    assert(nse->iod->events_pending >= 0);
  }

  if (notify) {
    nsock_trace_handler_callback(nsp, nse);
    nse->handler(nsp, nse, nse->userdata);
  }

  /* FIXME: We should be updating stats here ... */

  /* Now we clobber the event ... */
  event_delete(nsp, nse);
}

/* OK -- the idea is that we want the type included in the rightmost two bits
 * and the serial number in the leftmost 30 or 62.  But we also want to insure a
 * correct wrap-around in the case of an obscene number of event.  One
 * definition of a "correct" wraparound is that it goes from the highest number
 * back to one (not zero) because we don't want event numbers to ever be zero.
 * */
nsock_event_id get_new_event_id(struct npool *ms, enum nse_type type) {
  int type_code = (int)type;
  unsigned long serial = ms->next_event_serial++;
  unsigned long max_serial_allowed;
  int shiftbits;

  assert(type < NSE_TYPE_MAX);

  shiftbits = sizeof(nsock_event_id) * 8 - TYPE_CODE_NUM_BITS;
  max_serial_allowed = ((unsigned long)1 << shiftbits) - 1;
  if (serial == max_serial_allowed) {
    /* then the next serial will be one because 0 is forbidden */
    ms->next_event_serial = 1;
  }

  return (serial << TYPE_CODE_NUM_BITS) | type_code;
}

/* Take an event ID and return the type (NSE_TYPE_CONNECT, etc */
enum nse_type get_event_id_type(nsock_event_id event_id) {
  return (enum nse_type)((event_id & ((1 << TYPE_CODE_NUM_BITS) - 1)));
}

/* Create a new event structure -- must be deleted later with event_delete,
 * unless it returns NULL (failure).  NULL can be passed in for the struct niod
 * and the userdata if not available */
struct nevent *event_new(struct npool *nsp, enum nse_type type,
                           struct niod *iod, int timeout_msecs,
                           nsock_ev_handler handler, void *userdata) {
  struct nevent *nse;
  gh_lnode_t *lnode;

  /* Bring us up to date for the timeout calculation. */
  gettimeofday(&nsock_tod, NULL);

  if (iod) {
    iod->events_pending++;
    assert(iod->state != NSIOD_STATE_DELETED);
  }

  /* First we check if one is available from the free list ... */
  lnode = gh_list_pop(&nsp->free_events);
  if (!lnode)
    nse = (struct nevent *)safe_malloc(sizeof(*nse));
  else
    nse = lnode_nevent(lnode);

  memset(nse, 0, sizeof(*nse));

  nse->id = get_new_event_id(nsp, type);
  nse->type = type;
  nse->status = NSE_STATUS_NONE;
  gh_hnode_invalidate(&nse->expire);
#if HAVE_OPENSSL
  nse->sslinfo.ssl_desire = SSL_ERROR_NONE;
#endif

  if (type == NSE_TYPE_READ || type ==  NSE_TYPE_WRITE)
    filespace_init(&(nse->iobuf), 1024);

#if HAVE_PCAP
  if (type == NSE_TYPE_PCAP_READ) {
    mspcap *mp;
    int sz;

    assert(iod != NULL);
    mp = (mspcap *)iod->pcap;
    assert(mp);

    sz = mp->snaplen+1 + sizeof(nsock_pcap);
    filespace_init(&(nse->iobuf), sz);
  }
#endif

  if (timeout_msecs != -1) {
    assert(timeout_msecs >= 0);
    TIMEVAL_MSEC_ADD(nse->timeout, nsock_tod, timeout_msecs);
  }

  nse->iod = iod;
  nse->handler = handler;
  nse->userdata = userdata;

  if (nse->iod == NULL)
    nsock_log_debug("%s (IOD #NULL) (EID #%li)", __func__, nse->id);
  else
    nsock_log_debug("%s (IOD #%li) (EID #%li)", __func__, nse->iod->id,
                    nse->id);
  return nse;
}

/* Free an struct nevent which was allocated with event_new, including all internal
 * resources.  Note -- we assume that nse->iod->events_pending (if it exists)
 * has ALREADY been decremented (done during event_dispatch_and_delete) -- so
 * remember to do this if you call event_delete() directly */
void event_delete(struct npool *nsp, struct nevent *nse) {
  if (nse->iod == NULL)
    nsock_log_debug("%s (IOD #NULL) (EID #%li)", __func__, nse->id);
  else
    nsock_log_debug("%s (IOD #%li) (EID #%li)", __func__, nse->iod->id, nse->id);

  /* First free the IOBuf inside it if necessary */
  if (nse->type == NSE_TYPE_READ || nse->type ==  NSE_TYPE_WRITE) {
    fs_free(&nse->iobuf);
  }
  #if HAVE_PCAP
  if (nse->type == NSE_TYPE_PCAP_READ) {
    fs_free(&nse->iobuf);
    nsock_log_debug_all("PCAP removed %lu", nse->id);
  }
  #endif

  /* Now we add the event back into the free pool */
  nse->event_done = 1;
}


/* Takes an nse_type (as returned by nse_type() and returns a static string name
 * that you can use for printing, etc. */
const char *nse_type2str(enum nse_type type) {
  switch (type) {
    case NSE_TYPE_CONNECT: return "CONNECT";
    case NSE_TYPE_CONNECT_SSL: return "SSL-CONNECT";
    case NSE_TYPE_READ: return "READ";
    case NSE_TYPE_WRITE: return "WRITE";
    case NSE_TYPE_TIMER: return "TIMER";
    case NSE_TYPE_PCAP_READ: return "READ-PCAP";
    default:
      return "UNKNOWN!";
  }
}

/* Takes an nse_status (as returned by nse_status() and returns a static string
 * name that you can use for printing, etc. */
const char *nse_status2str(enum nse_status status) {
  switch (status) {
    case NSE_STATUS_NONE: return "NONE";
    case NSE_STATUS_SUCCESS: return "SUCCESS";
    case NSE_STATUS_ERROR: return "ERROR";
    case NSE_STATUS_TIMEOUT: return "TIMEOUT";
    case NSE_STATUS_CANCELLED: return "CANCELLED";
    case NSE_STATUS_KILL: return "KILL";
    case NSE_STATUS_EOF: return "EOF";
    case NSE_STATUS_PROXYERROR: return "PROXY ERROR";
    default:
      return "UNKNOWN!";
  }
}

int event_timedout(struct nevent *nse) {
  if (nse->event_done)
    return 0;

  return (nse->timeout.tv_sec && !TIMEVAL_AFTER(nse->timeout, nsock_tod));
}
