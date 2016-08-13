/***************************************************************************
 * nsock_iocp.c --  This contains operations required by IOCP              *
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
  
  if(nse->eov) {
    memset(&nse->eov->ov, 0, sizeof(OVERLAPPED));
    return nse->eov;
  }

  lnode = gh_list_pop(&nsp->free_eovs);
  if (!lnode)
    eov = (struct extended_overlapped *)safe_malloc(sizeof(struct extended_overlapped));
  else
    eov = container_of(lnode, struct extended_overlapped, nodeq);

  memset(eov, 0, sizeof(struct extended_overlapped));
  nse->eov = eov;
  eov->nse = nse;
  eov->nse_id = nse->id;
  eov->err = 0;
  gh_list_prepend(&nsp->active_eovs, &eov->nodeq);

  /* Make the read buffer equal to the size of the buffer in do_actual_read() */
  if (nse->type == NSE_TYPE_READ && !eov->readbuf)
    eov->readbuf = (char*)safe_malloc(READ_BUFFER_SZ * sizeof(char*));

  return eov;
}

static void call_connect_overlapped(struct npool *nsp, struct nevent *nse) {
  BOOL ok;
  DWORD numBytes = 0;
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

      free_eov(nsp, eov);
    } else {
      BOOL bRet = PostQueuedCompletionStatus(*(HANDLE *)iinfo, -1, (ULONG_PTR)nse->iod, (LPOVERLAPPED)eov);
      assert(bRet);
    }
    return;
  }

  ret = WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
    (void*)&guid, sizeof(guid), (void*)&ConnectExPtr, sizeof(ConnectExPtr),
    &numBytes, NULL, NULL);
  assert(!ret);

  /* ConnectEx doesn't automatically bind the socket */
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = 0;
  if (!nse->iod->locallen) {
    ret = bind(sock, (SOCKADDR*)&addr, sizeof(addr));
    if(ret) {
      int err = socket_errno();
      nse->event_done = 1;
      nse->status = NSE_STATUS_ERROR;
      nse->errnum = err;

      free_eov(nsp, eov);
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

      free_eov(nsp, eov);
    }
  }
}

static void call_read_overlapped(struct nevent *nse) {
  DWORD flags = 0;
  int err = 0;
  struct iocp_engine_info *iinfo = (struct iocp_engine_info *)nse->iod->nsp->engine_data;

  struct extended_overlapped *eov = new_eov(nse->iod->nsp, nse);

  eov->wsabuf.buf = eov->readbuf;
  eov->wsabuf.len = 8192;

  err = WSARecvFrom(nse->iod->sd, &eov->wsabuf, 1, NULL, &flags,
    (struct sockaddr *)&nse->iod->peer, (LPINT)&nse->iod->peerlen, (LPOVERLAPPED)eov, NULL);
  if (err) {
    err = socket_errno();
    if (errcode_is_failure(err)) {
      eov->err = err;
      BOOL bRet = PostQueuedCompletionStatus(iinfo->iocp, -1, (ULONG_PTR)nse->iod, (LPOVERLAPPED)eov);
      assert(bRet);
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
      BOOL bRet = PostQueuedCompletionStatus(iinfo->iocp, -1, (ULONG_PTR)nse->iod, (LPOVERLAPPED)eov);
      assert(bRet);
    }
  }
}

/* Either initiate a I/O read or force a SSL_read */
static void initiate_read(struct npool *nsp, struct nevent *nse) {
  BOOL bRet;

  struct extended_overlapped *eov;

  if (!strcmp(nsp->engine->name, "iocp")) {
    if (!nse->iod->ssl)
      call_read_overlapped(nse);
    else {
      struct iocp_engine_info *iinfo = (struct iocp_engine_info *)nsp->engine_data;
      eov = new_eov(nse->iod->nsp, nse);
      bRet = PostQueuedCompletionStatus(iinfo->iocp, 0, (ULONG_PTR)nse->iod, (LPOVERLAPPED)eov);
      assert(bRet);
    }
  }
}

/* Either initiate a I/O write or force a SSL_write */
static void initiate_write(struct npool *nsp, struct nevent *nse) {
  BOOL bRet;

  struct extended_overlapped *eov;

  if (!strcmp(nsp->engine->name, "iocp")) {
    if (!nse->iod->ssl)
      call_write_overlapped(nse);
    else {
      struct iocp_engine_info *iinfo = (struct iocp_engine_info *)nsp->engine_data;
      eov = new_eov(nse->iod->nsp, nse);
      bRet = PostQueuedCompletionStatus(iinfo->iocp, 0, (ULONG_PTR)nse->iod, (LPOVERLAPPED)eov);
      assert(bRet);
    }
  }
}

/* Force a PCAP read */
static void initiate_pcap_read(struct npool *nsp, struct nevent *nse) {
  BOOL bRet;

  struct extended_overlapped *eov;
  struct iocp_engine_info *iinfo = (struct iocp_engine_info *)nsp->engine_data;

  eov = new_eov(nse->iod->nsp, nse);
  bRet = PostQueuedCompletionStatus(iinfo->iocp, 0, (ULONG_PTR)nse->iod, (LPOVERLAPPED)eov);
  assert(bRet);
}

static void initiate_connect(struct npool *nsp, struct nevent *nse) {
  int sslconnect_inprogress = 0;
  BOOL bRet;
  struct extended_overlapped *eov;
  struct iocp_engine_info *iinfo = (struct iocp_engine_info *)nsp->engine_data;

#if HAVE_OPENSSL
  sslconnect_inprogress = nse->type == NSE_TYPE_CONNECT_SSL && nse->iod &&
    (nse->sslinfo.ssl_desire == SSL_ERROR_WANT_READ ||
    nse->sslinfo.ssl_desire == SSL_ERROR_WANT_WRITE);
#endif

  if (sslconnect_inprogress) {
    eov = new_eov(nse->iod->nsp, nse);
    bRet = PostQueuedCompletionStatus(iinfo->iocp, 0, (ULONG_PTR)nse->iod, (LPOVERLAPPED)eov);
    assert(bRet);
  }
  else
    call_connect_overlapped(nsp, nse);
}

/* Start the overlapped I/O operation */
void initiate_overlapped_event(struct npool *nsp, struct nevent *nse) {
  if (!engine_is_iocp(nsp))
    return;

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
void terminate_overlapped_event(struct npool *nsp, struct nevent *nse) {
  if (!HasOverlappedIoCompleted((LPOVERLAPPED)nse->eov))
    CancelIoEx((HANDLE)nse->iod->sd, (LPOVERLAPPED)nse->eov);
}

/* Retrieve the ammount of bytes transferred or set the appropriate error */
int get_overlapped_result(struct niod *iod, struct nevent *nse, char *buf) {
  DWORD dwRes = 0;
  int err;
  struct npool *nsp = nse->iod->nsp;
  static struct extended_overlapped *old_eov = NULL;
  struct iocp_engine_info *iinfo = (struct iocp_engine_info *)nsp->engine_data;

  struct extended_overlapped *eov = iinfo->eov;

  if (eov->err) {
    SetLastError(map_faulty_errors(eov->err));
    return -1;
  }

  if (!GetOverlappedResult((HANDLE)iod->sd, (LPOVERLAPPED)eov, &dwRes, FALSE)) {
    err = socket_errno();
    if (errcode_is_failure(err)) {
      SetLastError(map_faulty_errors(err));
      return -1;
    }
  }

  if (nse->type == NSE_TYPE_READ && buf)
    memcpy(buf, eov->wsabuf.buf, dwRes);

  /* If the read buffer wasn't big enough, subsequent calls from do_actual_read will make us
    read with recvfrom the rest of the returned data */
  if (nse->type == NSE_TYPE_READ && dwRes == eov->wsabuf.len && old_eov == eov) {
    struct sockaddr_storage peer;
    socklen_t peerlen = sizeof(peer);
    dwRes = recvfrom(iod->sd, buf, sizeof(buf), 0, (struct sockaddr *)&peer, &peerlen);
  }

  if (!nse->type == NSE_TYPE_READ || (nse->type == NSE_TYPE_READ && dwRes < eov->wsabuf.len)) {
    old_eov = NULL;
  } else if (nse->type == NSE_TYPE_READ && dwRes == eov->wsabuf.len) {
    old_eov = eov;
  }

  return dwRes;
}

void free_eov(struct npool *nsp, struct extended_overlapped *eov) {
  if (eov->readbuf) {
    free(eov->readbuf);
    eov->readbuf = NULL;
  }
  gh_list_remove(&nsp->active_eovs, &eov->nodeq);
  gh_list_prepend(&nsp->free_eovs, &eov->nodeq);
}

#endif /* HAVE_IOCP */
