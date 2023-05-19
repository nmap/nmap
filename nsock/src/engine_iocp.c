/***************************************************************************
 * engine_iocp.c -- I/O Completion Ports based IO engine.                  *
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

#if WIN32
#include "nsock_winconfig.h"
#endif

#if HAVE_IOCP

#include <Winsock2.h>
#include <Mswsock.h>

#include "nsock_internal.h"
#include "nsock_log.h"

#if HAVE_PCAP
#include "nsock_pcap.h"
#endif


/* --- ENGINE INTERFACE PROTOTYPES --- */
static int iocp_init(struct npool *nsp);
static void iocp_destroy(struct npool *nsp);
static int iocp_iod_register(struct npool *nsp, struct niod *iod, struct nevent *nse, int ev);
static int iocp_iod_unregister(struct npool *nsp, struct niod *iod);
static int iocp_iod_modify(struct npool *nsp, struct niod *iod, struct nevent *nse, int ev_set, int ev_clr);
static int iocp_loop(struct npool *nsp, int msec_timeout);

int iocp_iod_connect(struct npool *nsp, int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int iocp_iod_read(struct npool *nsp, int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
int iocp_iod_write(struct npool *nsp, int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);

struct io_operations iocp_io_operations = {
  iocp_iod_connect,
  iocp_iod_read,
  iocp_iod_write
};

/* ---- ENGINE DEFINITION ---- */
struct io_engine engine_iocp = {
  "iocp",
  iocp_init,
  iocp_destroy,
  iocp_iod_register,
  iocp_iod_unregister,
  iocp_iod_modify,
  iocp_loop,
  &iocp_io_operations
};

/*
* Engine specific data structure
*/
struct iocp_engine_info {
  /* The handle to the Completion Port*/
  HANDLE iocp;

  /* We put the current eov to be processed here in order to be retrieved by nsock_core */
  struct extended_overlapped *eov;

  /* The overlapped_entry list used to retrieve completed packets from the port */
  OVERLAPPED_ENTRY *eov_list;
  unsigned long capacity;

  /* How many Completion Packets we actually retreieved */
  unsigned long entries_removed;

  gh_list_t active_eovs;
  gh_list_t free_eovs;
};

struct extended_overlapped {
  /* Overlapped structure used for overlapped operations */
  OVERLAPPED ov;

  /* Did we get an error when we initiated the operation?
  Put the error code here and post it to the main loop */
  int err;

  /* The event may have expired and was recycled, we can't trust
  a pointer to the nevent structure to tell us the real nevent */
  nsock_event_id nse_id;

  /* A pointer to the event */
  struct nevent *nse;

  /* Needed for WSARecv/WSASend */
  WSABUF wsabuf;

  /* This is the buffer we will read data in */
  char *readbuf;

  /* The struct npool keeps track of EOVs that have been allocated so that it
  * can destroy them if the msp is deleted.  This pointer makes it easy to
  * remove this struct extended_overlapped from the allocated list when necessary */
  gh_lnode_t nodeq;
};

/* --- INTERNAL PROTOTYPES --- */
static void iterate_through_event_lists(struct npool *nsp);
static void iterate_through_pcap_events(struct npool *nsp);
static void terminate_overlapped_event(struct npool *nsp, struct nevent *nse);
static void initiate_overlapped_event(struct npool *nsp, struct nevent *nse);
static int get_overlapped_result(struct npool *nsp, int fd, const void *buffer, size_t count);
static void force_operation(struct npool *nsp, struct nevent *nse);
static void free_eov(struct npool *nsp, struct extended_overlapped *eov);
static int map_faulty_errors(int err);

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

  gh_list_init(&iinfo->active_eovs);
  gh_list_init(&iinfo->free_eovs);

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

  struct extended_overlapped *eov;
  gh_lnode_t *current;

  while ((current = gh_list_pop(&iinfo->active_eovs))) {
    eov = container_of(current, struct extended_overlapped, nodeq);
    if (eov->readbuf) {
      free(eov->readbuf);
      eov->readbuf = NULL;
    }
    free(eov);
  }

  while ((current = gh_list_pop(&iinfo->free_eovs))) {
    eov = container_of(current, struct extended_overlapped, nodeq);
    free(eov);
  }

  gh_list_free(&iinfo->active_eovs);
  gh_list_free(&iinfo->free_eovs);

  CloseHandle(iinfo->iocp);
  free(iinfo->eov_list);

  free(iinfo);
}

int iocp_iod_register(struct npool *nsp, struct niod *iod, struct nevent *nse, int ev) {
  struct iocp_engine_info *iinfo = (struct iocp_engine_info *)nsp->engine_data;
  HANDLE result;

  assert(!IOD_PROPGET(iod, IOD_REGISTERED));
  iod->watched_events = ev;
  result = CreateIoCompletionPort((HANDLE)iod->sd, iinfo->iocp, NULL, 0);
  assert(result);

  IOD_PROPSET(iod, IOD_REGISTERED);

  initiate_overlapped_event(nsp, nse);

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

int iocp_iod_modify(struct npool *nsp, struct niod *iod, struct nevent *nse, int ev_set, int ev_clr) {
  int new_events;
  struct iocp_engine_info *iinfo = (struct iocp_engine_info *)nsp->engine_data;

  assert((ev_set & ev_clr) == 0);
  assert(IOD_PROPGET(iod, IOD_REGISTERED));

  new_events = iod->watched_events;
  new_events |= ev_set;
  new_events &= ~ev_clr;

  if (ev_set != EV_NONE)
    initiate_overlapped_event(nsp, nse);
  else if (ev_clr != EV_NONE)
    terminate_overlapped_event(nsp, nse);

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
  unsigned long total_events;
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
    gettimeofday(&nsock_tod, NULL);
    iterate_through_pcap_events(nsp);
  }
  else
#endif
#endif
  {
    /* It is mandatory these values are reset before calling GetQueuedCompletionStatusEx */
    iinfo->entries_removed = 0;
    memset(iinfo->eov_list, 0, iinfo->capacity * sizeof(OVERLAPPED_ENTRY));
    bRet = GetQueuedCompletionStatusEx(iinfo->iocp, iinfo->eov_list, iinfo->capacity, &iinfo->entries_removed, combined_msecs, FALSE);

    gettimeofday(&nsock_tod, NULL); /* Due to iocp delay */
    if (!bRet) {
      sock_err = socket_errno();
      if (!iinfo->eov && sock_err != WAIT_TIMEOUT) {
        nsock_log_error("nsock_loop error %d: %s", sock_err, socket_strerror(sock_err));
        nsp->errnum = sock_err;
        return -1;
      }
    }
  }

  iterate_through_event_lists(nsp);

  return 1;
}


/* ---- INTERNAL FUNCTIONS ---- */

#if HAVE_PCAP
/* Iterate through pcap events separately, since these are not tracked in iocp_engine_info */
void iterate_through_pcap_events(struct npool *nsp) {
  gh_lnode_t *current, *next, *last;

  last = gh_list_last_elem(&nsp->active_iods);

  for (current = gh_list_first_elem(&nsp->active_iods);
       current != NULL && gh_lnode_prev(current) != last;
       current = next) {
    struct niod *nsi = container_of(current, struct niod, nodeq);

    if (nsi->pcap && nsi->state != NSIOD_STATE_DELETED && nsi->events_pending)
    {
      process_iod_events(nsp, nsi, EV_READ);
    }

    next = gh_lnode_next(current);
    if (nsi->state == NSIOD_STATE_DELETED) {
      gh_list_remove(&nsp->active_iods, current);
      gh_list_prepend(&nsp->free_iods, current);
    }
  }
}
#endif

/* Iterate through all the event lists (such as connect_events, read_events,
* timer_events, etc) and take action for those that have completed (due to
* timeout, i/o, etc) */
void iterate_through_event_lists(struct npool *nsp) {
  struct iocp_engine_info *iinfo = (struct iocp_engine_info *)nsp->engine_data;

  for (unsigned long i = 0; i < iinfo->entries_removed; i++) {

    iinfo->eov = (struct extended_overlapped *)iinfo->eov_list[i].lpOverlapped;
    /* We can't rely on iinfo->entries_removed to tell us the real number of
     * events to process */
    if (!iinfo->eov || !iinfo->eov->nse)
      continue;

    /* We check if this is from a cancelled operation */
    if (iinfo->eov->nse->id != iinfo->eov->nse_id ||
        iinfo->eov->nse->event_done) {
      free_eov(nsp, iinfo->eov);
      iinfo->eov = NULL;
      continue;
    }

    if (!HasOverlappedIoCompleted((OVERLAPPED *)iinfo->eov))
      continue;

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

    /* Setting the connect error for nsock_core to get in handle_connect_result */
    if (nse->type == NSE_TYPE_CONNECT || nse->type == NSE_TYPE_CONNECT_SSL) {
      setsockopt(nse->iod->sd, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);
      DWORD dwRes;
      if (!GetOverlappedResult((HANDLE)nse->iod->sd, (LPOVERLAPPED)iinfo->eov, &dwRes, FALSE)) {
        int err = map_faulty_errors(socket_errno());
        if (err)
          setsockopt(nse->iod->sd, SOL_SOCKET, SO_ERROR, (char *)&err, sizeof(err));
      }
    }

    process_event(nsp, evlist, nse, ev);

    if (nse->event_done) {
      /* event is done, remove it from the event list and update IOD pointers
      * to the first events of each kind */
      update_first_events(nse);
      gh_list_remove(evlist, &nse->nodeq_io);
      gh_list_append(&nsp->free_events, &nse->nodeq_io);

      if (nse->timeout.tv_sec)
        gh_heap_remove(&nsp->expirables, &nse->expire);
    } else
      initiate_overlapped_event(nsp, nse);

    if (nsi->state == NSIOD_STATE_DELETED) {
      gh_list_remove(&nsp->active_iods, &nsi->nodeq);
      gh_list_prepend(&nsp->free_iods, &nsi->nodeq);
    }

    iinfo->eov = NULL;
  }

  /* iterate through timers and expired events */
  process_expired_events(nsp);
}

static int errcode_is_failure(int err) {
#ifndef WIN32
  return err != EINTR && err != EAGAIN && err != EBUSY;
#else
  return err != EINTR && err != EAGAIN && err != WSA_IO_PENDING && err != ERROR_NETNAME_DELETED;
#endif
}

static int map_faulty_errors(int err) {
  /* This actually happens https://svn.boost.org/trac/boost/ticket/10744 */
  switch (err) {
    case ERROR_NETWORK_UNREACHABLE: return WSAENETUNREACH;
    case ERROR_HOST_UNREACHABLE: return WSAEHOSTUNREACH;
    case ERROR_CONNECTION_REFUSED: return WSAECONNREFUSED;
    case ERROR_SEM_TIMEOUT: return WSAETIMEDOUT;
  }
  return err;
}

static struct extended_overlapped *new_eov(struct npool *nsp, struct nevent *nse) {
  struct extended_overlapped *eov;
  gh_lnode_t *lnode;
  struct iocp_engine_info *iinfo = (struct iocp_engine_info *)nsp->engine_data;

  lnode = gh_list_pop(&iinfo->free_eovs);
  if (!lnode)
    eov = (struct extended_overlapped *)safe_malloc(sizeof(struct extended_overlapped));
  else
    eov = container_of(lnode, struct extended_overlapped, nodeq);

  memset(eov, 0, sizeof(struct extended_overlapped));
  nse->eov = eov;
  eov->nse = nse;
  eov->nse_id = nse->id;
  eov->err = 0;
  gh_list_prepend(&iinfo->active_eovs, &eov->nodeq);

  /* Make the read buffer equal to the size of the buffer in do_actual_read() */
  if (nse->type == NSE_TYPE_READ && !eov->readbuf && !nse->iod->ssl)
    eov->readbuf = (char*)safe_malloc(READ_BUFFER_SZ * sizeof(char));

  return eov;
}

/* This needs to be called after getting the overlapped event in */
static void free_eov(struct npool *nsp, struct extended_overlapped *eov) {
  struct iocp_engine_info *iinfo = (struct iocp_engine_info *)nsp->engine_data;
  struct nevent *nse = eov->nse;

  gh_list_remove(&iinfo->active_eovs, &eov->nodeq);

  if (eov->readbuf) {
    free(eov->readbuf);
    eov->readbuf = NULL;
  }

  gh_list_prepend(&iinfo->free_eovs, &eov->nodeq);

  eov->nse = NULL;
  if (nse)
    nse->eov = NULL;
}


static void call_connect_overlapped(struct npool *nsp, struct nevent *nse) {
  BOOL ok;
  DWORD numBytes = 0;
  int one = 1;
  SOCKET sock = nse->iod->sd;
  GUID guid = WSAID_CONNECTEX;
  struct sockaddr_in addr;
  LPFN_CONNECTEX ConnectExPtr = NULL;
  struct iocp_engine_info *iinfo = (struct iocp_engine_info *)nse->iod->nsp->engine_data;
  struct extended_overlapped *eov = new_eov(nsp, nse);
  int ret;
  struct sockaddr_storage *ss = &nse->iod->peer;
  size_t sslen = nse->iod->peerlen;

  if (nse->iod->lastproto != IPPROTO_TCP) {
    if (connect(sock, (struct sockaddr *)ss, sslen) == -1) {
      int err = socket_errno();
      nse->event_done = 1;
      nse->status = NSE_STATUS_ERROR;
      nse->errnum = err;
    } else {
      force_operation(nsp, nse);
    }
    return;
  }

  ret = WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
    (void*)&guid, sizeof(guid), (void*)&ConnectExPtr, sizeof(ConnectExPtr),
    &numBytes, NULL, NULL);
  if (ret)
    fatal("Error initiating event type(%d)", nse->type);

  ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof(one));
  if (ret == -1) {
    int err = socket_errno();
    nse->event_done = 1;
    nse->status = NSE_STATUS_ERROR;
    nse->errnum = err;
    return;
  }

  /* ConnectEx doesn't automatically bind the socket */
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = 0;
  if (!nse->iod->locallen) {
    ret = bind(sock, (SOCKADDR*)&addr, sizeof(addr));
    if (ret) {
      int err = socket_errno();
      nse->event_done = 1;
      nse->status = NSE_STATUS_ERROR;
      nse->errnum = err;
      return;
    }
  }

  ok = ConnectExPtr(sock, (SOCKADDR*)ss, sslen, NULL, 0, NULL, (LPOVERLAPPED)eov);
  if (!ok) {
    int err = socket_errno();
    if (err != ERROR_IO_PENDING) {
      nse->event_done = 1;
      nse->status = NSE_STATUS_ERROR;
      nse->errnum = err;
    }
  }
}

static void call_read_overlapped(struct nevent *nse) {
  DWORD flags = 0;
  int err = 0;
  struct iocp_engine_info *iinfo = (struct iocp_engine_info *)nse->iod->nsp->engine_data;

  struct extended_overlapped *eov = new_eov(nse->iod->nsp, nse);

  eov->wsabuf.buf = eov->readbuf;
  eov->wsabuf.len = READ_BUFFER_SZ;

  err = WSARecvFrom(nse->iod->sd, &eov->wsabuf, 1, NULL, &flags,
    (struct sockaddr *)&nse->iod->peer, (LPINT)&nse->iod->peerlen, (LPOVERLAPPED)eov, NULL);
  if (err) {
    err = socket_errno();
    if (errcode_is_failure(err)) {
      // WSARecvFrom with overlapped I/O may generate ERROR_PORT_UNREACHABLE on ICMP error.
      // We'll translate that so Nsock-using software doesn't have to know about it.
      eov->err = (err == ERROR_PORT_UNREACHABLE ? ECONNREFUSED : err);
      /* Send the error to the main loop to be picked up by the appropriate handler */
      BOOL bRet = PostQueuedCompletionStatus(iinfo->iocp, -1, (ULONG_PTR)nse->iod, (LPOVERLAPPED)eov);
      if (!bRet)
        fatal("Error initiating event type(%d)", nse->type);
    }
  }
}

static void call_write_overlapped(struct nevent *nse) {
  int err;
  char *str;
  int bytesleft;
  struct iocp_engine_info *iinfo = (struct iocp_engine_info *)nse->iod->nsp->engine_data;

  struct extended_overlapped *eov = new_eov(nse->iod->nsp, nse);

  str = fs_str(&nse->iobuf) + nse->writeinfo.written_so_far;
  bytesleft = fs_length(&nse->iobuf) - nse->writeinfo.written_so_far;

  eov->wsabuf.buf = str;
  eov->wsabuf.len = bytesleft;

  if (nse->writeinfo.dest.ss_family == AF_UNSPEC)
    err = WSASend(nse->iod->sd, &eov->wsabuf, 1, NULL, 0, (LPWSAOVERLAPPED)eov, NULL);
  else
    err = WSASendTo(nse->iod->sd, &eov->wsabuf, 1, NULL, 0,
    (struct sockaddr *)&nse->writeinfo.dest, (int)nse->writeinfo.destlen,
    (LPWSAOVERLAPPED)eov, NULL);
  if (err) {
    err = socket_errno();
    if (errcode_is_failure(err)) {
      eov->err = err;
      /* Send the error to the main loop to be picked up by the appropriate handler */
      BOOL bRet = PostQueuedCompletionStatus(iinfo->iocp, -1, (ULONG_PTR)nse->iod, (LPOVERLAPPED)eov);
      if (!bRet)
        fatal("Error initiating event type(%d)", nse->type);
    }
  }
}

/* Anything that isn't an overlapped operation uses this to get processed by the main loop */
static void force_operation(struct npool *nsp, struct nevent *nse) {
  BOOL bRet;
  struct extended_overlapped *eov;

  struct iocp_engine_info *iinfo = (struct iocp_engine_info *)nsp->engine_data;
  eov = new_eov(nse->iod->nsp, nse);

  bRet = PostQueuedCompletionStatus(iinfo->iocp, 0, (ULONG_PTR)nse->iod, (LPOVERLAPPED)eov);
  if (!bRet)
    fatal("Error initiating event type(%d)", nse->type);
}

/* Either initiate a I/O read or force a SSL_read */
static void initiate_read(struct npool *nsp, struct nevent *nse) {
  if (!nse->iod->ssl)
    call_read_overlapped(nse);
  else
    force_operation(nsp, nse);
}

/* Either initiate a I/O write or force a SSL_write */
static void initiate_write(struct npool *nsp, struct nevent *nse) {
  if (!nse->iod->ssl)
    call_write_overlapped(nse);
  else
    force_operation(nsp, nse);
}

/* Force a PCAP read */
static void initiate_pcap_read(struct npool *nsp, struct nevent *nse) {
  force_operation(nsp, nse);
}

static void initiate_connect(struct npool *nsp, struct nevent *nse) {
  int sslconnect_inprogress = 0;
  struct iocp_engine_info *iinfo = (struct iocp_engine_info *)nsp->engine_data;

#if HAVE_OPENSSL
  sslconnect_inprogress = nse->type == NSE_TYPE_CONNECT_SSL && nse->iod &&
    (nse->sslinfo.ssl_desire == SSL_ERROR_WANT_READ ||
    nse->sslinfo.ssl_desire == SSL_ERROR_WANT_WRITE);
#endif

  if (sslconnect_inprogress)
    force_operation(nsp, nse);
  else
    call_connect_overlapped(nsp, nse);
}

/* Start the overlapped I/O operation */
static void initiate_overlapped_event(struct npool *nsp, struct nevent *nse) {
  if (nse->eov)
    terminate_overlapped_event(nsp, nse);

  switch (nse->type) {
  case NSE_TYPE_CONNECT:
  case NSE_TYPE_CONNECT_SSL:
    initiate_connect(nsp, nse);
    break;
  case NSE_TYPE_READ:
    initiate_read(nsp, nse);
    break;
  case NSE_TYPE_WRITE:
    initiate_write(nsp, nse);
    break;
#if HAVE_PCAP
  case NSE_TYPE_PCAP_READ:
    initiate_pcap_read(nsp, nse);
    break;
#endif
  default: fatal("Event type(%d) not supported by engine IOCP\n", nse->type);
  }
}

/* Terminate an overlapped I/O operation that expired */
static void terminate_overlapped_event(struct npool *nsp, struct nevent *nse) {
  bool eov_done = true;

  if (nse->eov) {
    if (!HasOverlappedIoCompleted((LPOVERLAPPED)nse->eov)) {
      CancelIoEx((HANDLE)nse->iod->sd, (LPOVERLAPPED)nse->eov);
      eov_done = false;
    }

    if (eov_done)
      free_eov(nsp, nse->eov);
  }
}

/* Retrieve the amount of bytes transferred or set the appropriate error */
static int get_overlapped_result(struct npool *nsp, int fd, const void *buffer, size_t count) {
  char *buf = (char *)buffer;
  DWORD dwRes = 0;
  int err;
  struct iocp_engine_info *iinfo = (struct iocp_engine_info *)nsp->engine_data;

  struct extended_overlapped *eov = iinfo->eov;
  struct nevent *nse = eov->nse;

  /* If the operation failed at initialization, set the error for nsock_core.c to see */
  if (eov->err) {
    SetLastError(map_faulty_errors(eov->err));
    return -1;
  }

  if (!GetOverlappedResult((HANDLE)fd, (LPOVERLAPPED)eov, &dwRes, FALSE)) {
    err = socket_errno();
    if (errcode_is_failure(err)) {
      SetLastError(map_faulty_errors(err));
      return -1;
    }
  }

  if (nse->type == NSE_TYPE_READ && buf)
    memcpy(buf, eov->wsabuf.buf, dwRes);

  return dwRes;
}

int iocp_iod_connect(struct npool *nsp, int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  return 0;
}

int iocp_iod_read(struct npool *nsp, int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
  return get_overlapped_result(nsp, sockfd, buf, len);
}

int iocp_iod_write(struct npool *nsp, int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
  return get_overlapped_result(nsp, sockfd, buf, len);
}

#endif /* HAVE_IOCP */
