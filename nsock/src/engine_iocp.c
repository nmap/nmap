/***************************************************************************
 * engine_iocp.c -- I/O Completion Ports based IO engine.                  *
 *                                                                         *
 ***********************IMPORTANT NSOCK LICENSE TERMS***********************
 *
 * The nsock parallel socket event library is (C) 1999-2024 Nmap Software LLC
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
  /* Number of IODs incompatible with IO completion ports */
  int num_pcap_nonselect;

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
/* We need a way to mark canceled I/O that doesn't interfere with real NSE IDs.
 * -1 is 0xffffffff, so the lower bits will always be greater than NSE_TYPE_MAX
 * and therefore invalid. 0 is already invalid, so works for the recycled case.
 */
#define NSEID_CANCELED ((nsock_event_id) -1)
#define NSEID_FREED    ((nsock_event_id)  0)

  /* A pointer to the event */
  struct nevent *nse;

  /* Needed for WSARecv/WSASend */
  WSABUF wsabuf;

  /* This is the buffer we will read data in */
  char *readbuf;
  /* WSARecvFrom gives us the peer sockaddr,
     which we can't put into nse->iod->peer until it's retrieved via iod_read */
  struct sockaddr_storage peer;
  socklen_t peerlen;

  /* The struct npool keeps track of EOVs that have been allocated so that it
  * can destroy them if the msp is deleted.  This pointer makes it easy to
  * remove this struct extended_overlapped from the allocated list when necessary */
  gh_lnode_t nodeq;

  /* SSL events are "forced" or posted every time through the event loop. */
  u8 forced_operation;
#define IOCP_NOT_FORCED 0
#define IOCP_FORCED 1
#define IOCP_FORCED_POSTED 2
};

/* --- INTERNAL PROTOTYPES --- */
static void iterate_through_event_lists(struct npool *nsp);
static void terminate_overlapped_event(struct npool *nsp, struct nevent *nse);
static void initiate_overlapped_event(struct npool *nsp, struct nevent *nse);
static int get_overlapped_result(struct npool *nsp, int fd, const void *buffer, size_t count, struct sockaddr* src_addr, socklen_t* addrlen);
static void force_operation(struct npool *nsp, struct nevent *nse);
static void free_eov(struct npool *nsp, struct extended_overlapped *eov);
static int map_faulty_errors(int err);


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
  iinfo->num_pcap_nonselect = 0;
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
  int sd;
  struct iocp_engine_info *iinfo = (struct iocp_engine_info *)nsp->engine_data;
  HANDLE result;

  assert(!IOD_PROPGET(iod, IOD_REGISTERED));
  iod->watched_events = ev;

  sd = nsock_iod_get_sd(iod);
  if (sd == -1) {
    if (iod->pcap)
      iinfo->num_pcap_nonselect++;
    else
      fatal("Unable to get descriptor for IOD #%lu", iod->id);
  }
  else {
    result = CreateIoCompletionPort((HANDLE)sd, iinfo->iocp, NULL, 0);
    assert(result && result == iinfo->iocp);
  }

  IOD_PROPSET(iod, IOD_REGISTERED);

  initiate_overlapped_event(nsp, nse);

  return 1;
}

/* Sadly a socket can't be unassociated with a completion port */
int iocp_iod_unregister(struct npool *nsp, struct niod *iod) {
  int sd;
  struct iocp_engine_info *iinfo = (struct iocp_engine_info *)nsp->engine_data;

  if (IOD_PROPGET(iod, IOD_REGISTERED)) {
    sd = nsock_iod_get_sd(iod);
    if (sd == -1) {
      assert(iod->pcap);
      iinfo->num_pcap_nonselect--;
    }
    else {
      /* Nuke all uncompleted operations on that iod */
      CancelIo((HANDLE)iod->sd);
    }

    IOD_PROPCLR(iod, IOD_REGISTERED);
  }

  return 1;
}

int iocp_iod_modify(struct npool *nsp, struct niod *iod, struct nevent *nse, int ev_set, int ev_clr) {
  struct iocp_engine_info *iinfo = (struct iocp_engine_info *)nsp->engine_data;

  assert((ev_set & ev_clr) == 0);
  assert(IOD_PROPGET(iod, IOD_REGISTERED));

  // Bookkeeping, but we don't care about watched_events:
  iod->watched_events |= ev_set;
  iod->watched_events &= ~ev_clr;

  if (ev_set != EV_NONE) {
      if (!nse->eov)
          initiate_overlapped_event(nsp, nse);
  }
  else /* even if ev_clr is EV_NONE, since other events may preclude that */
    terminate_overlapped_event(nsp, nse);

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
  else {
    event_msecs = TIMEVAL_MSEC_SUBTRACT(nse->timeout, nsock_tod);
    event_msecs = MAX(0, event_msecs);
  }

#if HAVE_PCAP
    if (iinfo->num_pcap_nonselect > 0 && gh_list_count(&nsp->pcap_read_events) > 0) {

      /* do non-blocking read on pcap devices that doesn't support select()
       * If there is anything read, just leave this loop. */
      if (pcap_read_on_nonselect(nsp)) {
        /* okay, something was read. */
        // Check all pcap events that won't be signaled
        gettimeofday(&nsock_tod, NULL);
        iterate_through_pcap_events(nsp);
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

  if (total_events > 0) {
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
    else {
      iterate_through_event_lists(nsp);
    }
  }
  else if (combined_msecs > 0) {
    // No compatible IODs; sleep the remainder of the wait time.
    usleep(combined_msecs * 1000);
  }

  /* iterate through timers and expired events */
  process_expired_events(nsp);

  return 1;
}


/* ---- INTERNAL FUNCTIONS ---- */

/* Iterate through all the event lists (such as connect_events, read_events,
* timer_events, etc) and take action for those that have completed (due to
* timeout, i/o, etc) */
void iterate_through_event_lists(struct npool *nsp) {
  struct iocp_engine_info *iinfo = (struct iocp_engine_info *)nsp->engine_data;

  for (unsigned long i = 0; i < iinfo->entries_removed; i++) {

    iinfo->eov = (struct extended_overlapped *)iinfo->eov_list[i].lpOverlapped;

    assert(iinfo->eov);
    assert(iinfo->eov->nse_id != NSEID_FREED);
    if (!iinfo->eov->nse) {
        // No associated NSE means this was a cancelled operation
        assert(iinfo->eov->nse_id == NSEID_CANCELED);
        free_eov(nsp, iinfo->eov);
        iinfo->eov = NULL;
        continue;
    }
    // If it's a force-pushed completion status, reset to allow it to be pushed again
    if (iinfo->eov->forced_operation) {
        assert(iinfo->eov->forced_operation == IOCP_FORCED_POSTED);
        iinfo->eov->forced_operation = IOCP_FORCED;
    }

    struct niod* nsi = iinfo->eov->nse->iod;
    struct nevent* nse = iinfo->eov->nse;

    if (nsi->state == NSIOD_STATE_DELETED) {
        // All events should have been canceled already
        gh_list_remove(&nsp->active_iods, &nsi->nodeq);
        assert(iinfo->eov->nse_id == NSEID_CANCELED);
        free_eov(nsp, iinfo->eov);
        gh_list_prepend(&nsp->free_iods, &nsi->nodeq);
        iinfo->eov = NULL;
        continue;
    }

    /* Here are more things that should be true */
    assert(iinfo->eov->nse_id == nse->id);
    assert(iinfo->eov == nse->eov);

    if (!iinfo->eov->err && !HasOverlappedIoCompleted((OVERLAPPED*)iinfo->eov)) {
        continue;
    }

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
      if (nse->eov)
          terminate_overlapped_event(nsp, nse);
      nevent_unref(nsp, nse);
    }
    else {
        assert(nse->eov->forced_operation != IOCP_NOT_FORCED);
        if (!event_timedout(nse))
            force_operation(nsp, nse);
    }

    iinfo->eov = NULL;
  }

}

static int errcode_is_failure(int err) {

  return err != EINTR && err != EAGAIN && err != WSA_IO_PENDING && err != ERROR_NETNAME_DELETED;

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

  assert(nse);
  assert(!nse->eov);
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

  eov->nse = NULL;
  eov->nse_id = 0;
  if (nse)
    nse->eov = NULL;
  gh_list_prepend(&iinfo->free_eovs, &eov->nodeq);
}


static void call_connect_overlapped(struct npool *nsp, struct nevent *nse) {
  BOOL ok;
  DWORD numBytes = 0;
  int one = 1;
  SOCKET sock = nse->iod->sd;
  GUID guid = WSAID_CONNECTEX;
  struct sockaddr_storage addr;
  LPFN_CONNECTEX ConnectExPtr = NULL;
  struct iocp_engine_info *iinfo = (struct iocp_engine_info *)nse->iod->nsp->engine_data;
  struct extended_overlapped* eov = NULL;
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
  if (!nse->iod->locallen) {
      memset(&addr, 0, sizeof(addr));
      addr.ss_family = ss->ss_family;
      if (addr.ss_family == AF_INET) {
          ((struct sockaddr_in*)&addr)->sin_addr.s_addr = INADDR_ANY;
          ((struct sockaddr_in*)&addr)->sin_port = 0;
      } else if (addr.ss_family == AF_INET6) {
          ((struct sockaddr_in6*)&addr)->sin6_addr = IN6ADDR_ANY_INIT;
          ((struct sockaddr_in6*)&addr)->sin6_port = 0;
      }
    ret = bind(sock, (SOCKADDR*)&addr, sizeof(addr));
    if (ret) {
      int err = socket_errno();
      nse->event_done = 1;
      nse->status = NSE_STATUS_ERROR;
      nse->errnum = err;
      return;
    }
  }

  eov = new_eov(nsp, nse);
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

  eov->peerlen = sizeof(eov->peer);
  err = WSARecvFrom(nse->iod->sd, &eov->wsabuf, 1, NULL, &flags,
    (struct sockaddr *)&eov->peer, (LPINT)&eov->peerlen, (LPOVERLAPPED)eov, NULL);
  if (err) {
    err = socket_errno();
    if (err != WSA_IO_PENDING) {
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
    if (err != WSA_IO_PENDING) {
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

  if (nse->eov) {
      eov = nse->eov;
      assert(eov->forced_operation != IOCP_NOT_FORCED);
  }
  else {
      eov = new_eov(nse->iod->nsp, nse);
      eov->forced_operation = IOCP_FORCED;
  }
  
  if (eov->forced_operation == IOCP_FORCED) {
      eov->forced_operation = IOCP_FORCED_POSTED;
      bRet = PostQueuedCompletionStatus(iinfo->iocp, 0, (ULONG_PTR)nse->iod, (LPOVERLAPPED)eov);
      if (!bRet)
          fatal("Error initiating event type(%d)", nse->type);
  }
  // else we already posted it this round.
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
  struct extended_overlapped *eov = nse->eov;
  DWORD dwCancelError = 0;

  // If there's no I/O or it's already been canceled, just return.
  if (!eov || eov->nse_id == NSEID_CANCELED) {
    return;
  }

  assert(eov->nse_id != NSEID_FREED);

  // Mark this as canceled
  eov->nse_id = NSEID_CANCELED;
  eov->nse = NULL;
  nse->eov = NULL;

  // If this is a forced operation that's been posted to the queue, we can't
  // delete it yet and there's nothing left to cancel. Let
  // iterate_through_event_lists free it next time through the loop.
  if (eov->forced_operation == IOCP_FORCED_POSTED) {
    return;
  }

  // If there's a pending I/O, cancel it.
  if (!HasOverlappedIoCompleted((LPOVERLAPPED)eov)) {
    // forced operations are never pending
    assert(eov->forced_operation == IOCP_NOT_FORCED);
    // If CancelIoEx succeeds, there will be a completion packet
    if (CancelIoEx((HANDLE)nse->iod->sd, (LPOVERLAPPED)eov) != 0) {
      return;
    }
    // If it failed, it could be there wasn't anything to cancel.
    dwCancelError = GetLastError();
    if (dwCancelError != ERROR_NOT_FOUND) {
      fatal("Unexpected error from CancelIoEx: %08x", dwCancelError);
    }
  }
  else if (eov->forced_operation == IOCP_NOT_FORCED) {
      // real (not forced) IO completed, so this eov is referenced in the queue.
      return;
  }
  // Now there are no more references to this eov, so we can free it.
  free_eov(nsp, eov);
}

/* Retrieve the amount of bytes transferred or set the appropriate error */
static int get_overlapped_result(struct npool *nsp, int fd, const void *buffer, size_t count, struct sockaddr* src_addr, socklen_t* addrlen) {
  char *buf = (char *)buffer;
  DWORD dwRes = 0;
  int err;
  struct iocp_engine_info *iinfo = (struct iocp_engine_info *)nsp->engine_data;

  struct extended_overlapped *eov = iinfo->eov;
  assert(eov->nse);
  struct nevent *nse = eov->nse;
  assert(eov->nse_id == nse->id);

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

  if (nse->type == NSE_TYPE_READ) {
      if (src_addr) {
          *addrlen = MIN(eov->peerlen, *addrlen);
          memcpy(&src_addr, &eov->peer, *addrlen);
      }
      assert(dwRes <= count);
      if (buf)
          memcpy(buf, eov->wsabuf.buf, dwRes);
  }

  return dwRes;
}

int iocp_iod_connect(struct npool *nsp, int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  return 0;
}

int iocp_iod_read(struct npool *nsp, int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
  return get_overlapped_result(nsp, sockfd, buf, len, src_addr, addrlen);
}

int iocp_iod_write(struct npool *nsp, int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
  return get_overlapped_result(nsp, sockfd, buf, len, NULL, NULL);
}

#endif /* HAVE_IOCP */
