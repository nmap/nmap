/***************************************************************************
 * engine_iocp.c -- I/O Completion Ports based IO engine.                  *
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

#if WIN32
#include "nsock_winconfig.h"
#endif

#if HAVE_IOCP

#include <Winsock2.h>
#include <Mswsock.h>

#include "nsock_internal.h"
#include "nsock_iocp.h"
#include "nsock_log.h"

#if HAVE_PCAP
#include "nsock_pcap.h"
#endif


/* --- ENGINE INTERFACE PROTOTYPES --- */
static int iocp_init(struct npool *nsp);
static void iocp_destroy(struct npool *nsp);
static int iocp_iod_register(struct npool *nsp, struct niod *iod, int ev);
static int iocp_iod_unregister(struct npool *nsp, struct niod *iod);
static int iocp_iod_modify(struct npool *nsp, struct niod *iod, int ev_set, int ev_clr);
static int iocp_loop(struct npool *nsp, int msec_timeout);


/* ---- ENGINE DEFINITION ---- */
struct io_engine engine_iocp = {
  "iocp",
  iocp_init,
  iocp_destroy,
  iocp_iod_register,
  iocp_iod_unregister,
  iocp_iod_modify,
  iocp_loop
};


/* --- INTERNAL PROTOTYPES --- */
static void iterate_through_event_lists(struct npool *nsp);

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

int iocp_init(struct npool *nsp) {
  struct iocp_engine_info *iinfo;

  iinfo = (struct iocp_engine_info *)safe_malloc(sizeof(struct iocp_engine_info));

  iinfo->iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, NULL, 0);
  iinfo->capacity = 10;
  iinfo->eov = NULL;
  iinfo->entries_removed = 0;
  iinfo->eov_list = (OVERLAPPED_ENTRY *)safe_malloc(iinfo->capacity * sizeof(OVERLAPPED_ENTRY));
  nsp->engine_data = (void *)iinfo;

  return 1;
}

void iocp_destroy(struct npool *nsp) {
  struct iocp_engine_info *iinfo = (struct iocp_engine_info *)nsp->engine_data;

  assert(iinfo != NULL);

  CloseHandle(iinfo->iocp);
  free(iinfo->eov_list);

  free(iinfo);
}

int iocp_iod_register(struct npool *nsp, struct niod *iod, int ev) {
  struct iocp_engine_info *iinfo = (struct iocp_engine_info *)nsp->engine_data;
  HANDLE result;

  assert(!IOD_PROPGET(iod, IOD_REGISTERED));
  iod->watched_events = ev;
  result = CreateIoCompletionPort((HANDLE)iod->sd, iinfo->iocp, NULL, 0);
  assert(result);
  
  IOD_PROPSET(iod, IOD_REGISTERED);
  return 1;
}

/* Sadly a socket can't be unassociated with a completion port */
int iocp_iod_unregister(struct npool *nsp, struct niod *iod) {

  if (IOD_PROPGET(iod, IOD_REGISTERED)) {
    /* Nuke all uncompleted operations on that iod */
    CancelIo((HANDLE)iod->sd);
    IOD_PROPCLR(iod, IOD_REGISTERED);
  }
  return 1;
}

/* Can't do much here for IOCP */
int iocp_iod_modify(struct npool *nsp, struct niod *iod, int ev_set, int ev_clr) {
  int new_events;
  struct iocp_engine_info *iinfo = (struct iocp_engine_info *)nsp->engine_data;

  assert((ev_set & ev_clr) == 0);
  assert(IOD_PROPGET(iod, IOD_REGISTERED));

  new_events = iod->watched_events;
  new_events |= ev_set;
  new_events &= ~ev_clr;

  if (new_events == iod->watched_events)
    return 1; /* nothing to do */

  iod->watched_events = new_events;

  return 1;
}

int iocp_loop(struct npool *nsp, int msec_timeout) {
  int event_msecs; /* msecs before an event goes off */
  int combined_msecs;
  int sock_err = 0;
  BOOL bRet;
  int total_events;
  struct iocp_engine_info *iinfo = (struct iocp_engine_info *)nsp->engine_data;

  assert(msec_timeout >= -1);

  if (nsp->events_pending == 0)
    return 0; /* No need to wait on 0 events ... */


  struct nevent *nse;

  /* Make sure the preallocated space for the retrieved events is big enough */
  total_events = gh_list_count(&nsp->connect_events) + gh_list_count(&nsp->read_events) + gh_list_count(&nsp->write_events);
  if (iinfo->capacity < total_events) {
    iinfo->capacity *= 2;
    iinfo->eov_list = (OVERLAPPED_ENTRY *)safe_realloc(iinfo->eov_list, iinfo->capacity * sizeof(OVERLAPPED_ENTRY));
  }

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

#if HAVE_PCAP
#ifndef PCAP_CAN_DO_SELECT
  /* do non-blocking read on pcap devices that doesn't support select()
  * If there is anything read, just leave this loop. */
  if (pcap_read_on_nonselect(nsp)) {
    /* okay, something was read. */
  }
  else
#endif
#endif
  {
    /* It is mandatory these values are reset before calling GetQueuedCompletionStatusEx */
    iinfo->entries_removed = 0;
    memset(iinfo->eov_list, 0, iinfo->capacity * sizeof(OVERLAPPED_ENTRY));
    bRet = GetQueuedCompletionStatusEx(iinfo->iocp, iinfo->eov_list, iinfo->capacity, &iinfo->entries_removed, combined_msecs, FALSE);
  }

  gettimeofday(&nsock_tod, NULL); /* Due to iocp delay */
  if (!bRet) {
    sock_err = socket_errno();
    if (!iinfo->eov && sock_err != WAIT_TIMEOUT) {
      nsock_log_error("nsock_loop error %d: %s", sock_err, socket_strerror(sock_err));
      nsp->errnum = sock_err;
      return -1;
    } 
  }

  iterate_through_event_lists(nsp);

  return 1;
}


/* ---- INTERNAL FUNCTIONS ---- */

/* Iterate through all the event lists (such as connect_events, read_events,
* timer_events, etc) and take action for those that have completed (due to
* timeout, i/o, etc) */
void iterate_through_event_lists(struct npool *nsp) {
  struct iocp_engine_info *iinfo = (struct iocp_engine_info *)nsp->engine_data;

  for (int i = 0; i < iinfo->entries_removed; i++) {

    iinfo->eov = (struct extended_overlapped *)iinfo->eov_list[i].lpOverlapped;
    /* We can't rely on iinfo->entries_removed to tell us the real number of
     * events to process */
    if (!iinfo->eov)
      continue;
    

    /* Is this the eov of an event that expired? */
    if (iinfo->eov->nse->id != iinfo->eov->nse_id || iinfo->eov->nse->event_done) {
      iinfo->eov = NULL;
      continue;
    }
 
    struct niod *nsi = iinfo->eov->nse->iod;
    struct nevent *nse = iinfo->eov->nse;
    gh_list_t *evlist = NULL;
    int ev = 0;

    switch (nse->type) {
      case NSE_TYPE_CONNECT:
      case NSE_TYPE_CONNECT_SSL:
        ev = EV_READ;
        evlist = &nsp->connect_events;
        break;
      case NSE_TYPE_READ:
        ev = EV_READ;
        evlist = &nsp->read_events;
        break;
      case NSE_TYPE_WRITE:
        ev = EV_WRITE;
        evlist = &nsp->write_events;
        break;
    }
    assert(evlist);

    process_event(nsp, evlist, nse, ev);
	
    if (!nse->event_done)
      initiate_overlapped_event(nsp, nse);
    else
      free_eov(nsp, nse->eov);

    if (nse->event_done) {
      /* event is done, remove it from the event list and update IOD pointers
      * to the first events of each kind */
      update_first_events(nse);
      gh_list_remove(evlist, &nse->nodeq_io);
      gh_list_append(&nsp->free_events, &nse->nodeq_io);

      if (nse->timeout.tv_sec)
        gh_heap_remove(&nsp->expirables, &nse->expire);
    }

    if (nsi->state == NSIOD_STATE_DELETED) {
      gh_list_remove(&nsp->active_iods, &nsi->nodeq);
      gh_list_prepend(&nsp->free_iods, &nsi->nodeq);
    }

    iinfo->eov = NULL;
  }

  /* iterate through timers and expired events */
  process_expired_events(nsp);
}

#endif /* HAVE_IOCP */
