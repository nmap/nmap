/***************************************************************************
 * nsock_connect.c -- This contains the functions for requesting TCP       *
 * connections from the nsock parallel socket event library                *
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

#include "nsock.h"
#include "nsock_internal.h"
#include "nsock_log.h"
#include "nsock_proxy.h"
#include "netutils.h"

#include <sys/types.h>
#include <errno.h>
#include <string.h>


static int mksock_bind_addr(struct npool *ms, struct niod *iod) {
  int rc;
  int one = 1;

  rc = setsockopt(iod->sd, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof(one));
  if (rc == -1) {
    int err = socket_errno();

    nsock_log_error("Setting of SO_REUSEADDR failed (#%li): %s (%d)", iod->id,
                    socket_strerror(err), err);
  }

  nsock_log_info("Binding to %s (IOD #%li)", get_localaddr_string(iod), iod->id);
  rc = bind(iod->sd, (struct sockaddr *)&iod->local, (int) iod->locallen);
  if (rc == -1) {
    int err = socket_errno();

    nsock_log_error("Bind to %s failed (IOD #%li): %s (%d)",
                    get_localaddr_string(iod), iod->id,
                    socket_strerror(err), err);
  }
  return 0;
}

static int mksock_set_ipopts(struct npool *ms, struct niod *iod) {
  int rc;

  errno = 0;
  rc = setsockopt(iod->sd, IPPROTO_IP, IP_OPTIONS, (const char *)iod->ipopts,
                  iod->ipoptslen);
  if (rc == -1) {
    int err = socket_errno();

    nsock_log_error("Setting of IP options failed (IOD #%li): %s (%d)",
                    iod->id, socket_strerror(err), err);
  }
  return 0;
}

static int mksock_bind_device(struct npool *ms, struct niod *iod) {
  int rc;

  rc = socket_bindtodevice(iod->sd, ms->device);
  if (!rc) {
    int err = socket_errno();

    if (err != EPERM)
      nsock_log_error("Setting of SO_BINDTODEVICE failed (IOD #%li): %s (%d)",
                      iod->id, socket_strerror(err), err);
    else
      nsock_log_debug_all("Setting of SO_BINDTODEVICE failed (IOD #%li): %s (%d)",
                          iod->id, socket_strerror(err), err);
  }
  return 0;
}

static int mksock_set_broadcast(struct npool *ms, struct niod *iod) {
  int rc;
  int one = 1;

  rc = setsockopt(iod->sd, SOL_SOCKET, SO_BROADCAST,
                  (const char *)&one, sizeof(one));
  if (rc == -1) {
    int err = socket_errno();

    nsock_log_error("Setting of SO_BROADCAST failed (IOD #%li): %s (%d)",
                    iod->id, socket_strerror(err), err);
  }
  return 0;
}
/* Create the actual socket (nse->iod->sd) underlying the iod. This unblocks the
 * socket, binds to the localaddr address, sets IP options, and sets the
 * broadcast flag. Trying to change these functions after making this call will
 * not have an effect. This function needs to be called before you try to read
 * or write on the iod. */
static int nsock_make_socket(struct npool *ms, struct niod *iod, int family, int type, int proto) {

  /* inheritable_socket is from nbase */
  iod->sd = (int)inheritable_socket(family, type, proto);
  if (iod->sd == -1) {
    nsock_log_error("Socket trouble: %s", socket_strerror(socket_errno()));
    return -1;
  }

  unblock_socket(iod->sd);

  iod->lastproto = proto;

  if (iod->locallen)
    mksock_bind_addr(ms, iod);

  if (iod->ipoptslen && family == AF_INET)
    mksock_set_ipopts(ms, iod);

  if (ms->device)
    mksock_bind_device(ms, iod);

  if (ms->broadcast && type != SOCK_STREAM)
    mksock_set_broadcast(ms, iod);

  /* mksock_* functions can raise warnings/errors
   * but we don't let them stop us for now. */
  return iod->sd;
}

int nsock_setup_udp(nsock_pool nsp, nsock_iod ms_iod, int af) {
  struct npool *ms = (struct npool *)nsp;
  struct niod *nsi = (struct niod *)ms_iod;

  assert(nsi->state == NSIOD_STATE_INITIAL || nsi->state == NSIOD_STATE_UNKNOWN);

  nsock_log_info("UDP unconnected socket (IOD #%li)", nsi->id);

  if (nsock_make_socket(ms, nsi, af, SOCK_DGRAM, IPPROTO_UDP) == -1)
    return -1;

  return nsi->sd;
}

/* This does the actual logistics of requesting a TCP connection.  It is shared
 * by nsock_connect_tcp and nsock_connect_ssl */
void nsock_connect_internal(struct npool *ms, struct nevent *nse, int type, int proto, struct sockaddr_storage *ss, size_t sslen,
                            unsigned short port) {

  struct sockaddr_in *sin;
#if HAVE_IPV6
  struct sockaddr_in6 *sin6;
#endif
  struct niod *iod = nse->iod;

  if (iod->px_ctx   /* proxy enabled */
      && proto == IPPROTO_TCP   /* restrict proxying to TCP connections */
      && (nse->handler != nsock_proxy_ev_dispatch)) {   /* for reentrancy */
    struct proxy_node *current;

    nsock_log_debug_all("TCP connection request (EID %lu) redirected through proxy chain",
                        (long)nse->id);

    current = iod->px_ctx->px_current;
    assert(current != NULL);

    memcpy(&iod->px_ctx->target_ss, ss, sslen);
    iod->px_ctx->target_sslen = sslen;
    iod->px_ctx->target_port  = port;

    ss    = &current->ss;
    sslen = current->sslen;
    port  = current->port;

    iod->px_ctx->target_handler = nse->handler;
    nse->handler = nsock_proxy_ev_dispatch;

    iod->px_ctx->target_ev_type = nse->type;
    nse->type = NSE_TYPE_CONNECT;
  }

  sin = (struct sockaddr_in *)ss;
#if HAVE_IPV6
  sin6 = (struct sockaddr_in6 *)ss;
#endif

  /* Now it is time to actually attempt the connection */
  if (nsock_make_socket(ms, iod, ss->ss_family, type, proto) == -1) {
    nse->event_done = 1;
    nse->status = NSE_STATUS_ERROR;
    nse->errnum = socket_errno();
  } else {
    if (ss->ss_family == AF_INET) {
      sin->sin_port = htons(port);
    }
#if HAVE_IPV6
    else if (ss->ss_family == AF_INET6) {
      sin6->sin6_port = htons(port);
    }
#endif
#if HAVE_SYS_UN_H
    else if (ss->ss_family == AF_UNIX) {
    }
#endif
    else {
      fatal("Unknown address family %d\n", ss->ss_family);
    }

    assert(sslen <= sizeof(iod->peer));
    if (&iod->peer != ss)
      memcpy(&iod->peer, ss, sslen);
    iod->peerlen = sslen;

    if (connect(iod->sd, (struct sockaddr *)ss, sslen) == -1) {
      int err = socket_errno();

      if (proto == IPPROTO_UDP || (err != EINPROGRESS && err != EAGAIN)) {
        nse->event_done = 1;
        nse->status = NSE_STATUS_ERROR;
        nse->errnum = err;
      }
    }
    /* The callback handle_connect_result handles the connection once it completes. */
  }
}

#if HAVE_SYS_UN_H

/* Request a UNIX domain sockets connection to the same system (by path to socket).
 * This function connects to the socket of type SOCK_STREAM.  ss should be a
 * sockaddr_storage, sockaddr_un as appropriate (just like what you would pass to
 * connect).  sslen should be the sizeof the structure you are passing in. */
nsock_event_id nsock_connect_unixsock_stream(nsock_pool nsp, nsock_iod nsiod, nsock_ev_handler handler, int timeout_msecs,
                                             void *userdata, struct sockaddr *saddr, size_t sslen) {
  struct niod *nsi = (struct niod *)nsiod;
  struct npool *ms = (struct npool *)nsp;
  struct nevent *nse;
  struct sockaddr_storage *ss = (struct sockaddr_storage *)saddr;

  assert(nsi->state == NSIOD_STATE_INITIAL || nsi->state == NSIOD_STATE_UNKNOWN);

  nse = event_new(ms, NSE_TYPE_CONNECT, nsi, timeout_msecs, handler, userdata);
  assert(nse);

  nsock_log_info("UNIX domain socket (STREAM) connection requested to %s (IOD #%li) EID %li",
                 get_unixsock_path(ss), nsi->id, nse->id);

  nsock_connect_internal(ms, nse, SOCK_STREAM, 0, ss, sslen, 0);
  nsock_pool_add_event(ms, nse);

  return nse->id;

}

/* Request a UNIX domain sockets connection to the same system (by path to socket).
 * This function connects to the socket of type SOCK_DGRAM.  ss should be a
 * sockaddr_storage, sockaddr_un as appropriate (just like what you would pass to
 * connect).  sslen should be the sizeof the structure you are passing in. */
nsock_event_id nsock_connect_unixsock_datagram(nsock_pool nsp, nsock_iod nsiod, nsock_ev_handler handler,
                                               void *userdata, struct sockaddr *saddr, size_t sslen) {
  struct niod *nsi = (struct niod *)nsiod;
  struct npool *ms = (struct npool *)nsp;
  struct nevent *nse;
  struct sockaddr_storage *ss = (struct sockaddr_storage *)saddr;

  assert(nsi->state == NSIOD_STATE_INITIAL || nsi->state == NSIOD_STATE_UNKNOWN);

  nse = event_new(ms, NSE_TYPE_CONNECT, nsi, -1, handler, userdata);
  assert(nse);

  nsock_log_info("UNIX domain socket (DGRAM) connection requested to %s (IOD #%li) EID %li",
                 get_unixsock_path(ss), nsi->id, nse->id);

  nsock_connect_internal(ms, nse, SOCK_DGRAM, 0, ss, sslen, 0);
  nsock_pool_add_event(ms, nse);

  return nse->id;
}

#endif  /* HAVE_SYS_UN_H */

/* Request a TCP connection to another system (by IP address).  The in_addr is
 * normal network byte order, but the port number should be given in HOST BYTE
 * ORDER.  ss should be a sockaddr_storage, sockaddr_in6, or sockaddr_in as
 * appropriate (just like what you would pass to connect).  sslen should be the
 * sizeof the structure you are passing in. */
nsock_event_id nsock_connect_tcp(nsock_pool nsp, nsock_iod ms_iod, nsock_ev_handler handler, int timeout_msecs,
                                 void *userdata, struct sockaddr *saddr, size_t sslen, unsigned short port) {
  struct niod *nsi = (struct niod *)ms_iod;
  struct npool *ms = (struct npool *)nsp;
  struct nevent *nse;
  struct sockaddr_storage *ss = (struct sockaddr_storage *)saddr;

  assert(nsi->state == NSIOD_STATE_INITIAL || nsi->state == NSIOD_STATE_UNKNOWN);

  nse = event_new(ms, NSE_TYPE_CONNECT, nsi, timeout_msecs, handler, userdata);
  assert(nse);

  nsock_log_info("TCP connection requested to %s:%hu (IOD #%li) EID %li",
                 inet_ntop_ez(ss, sslen), port, nsi->id, nse->id);

  /* Do the actual connect() */
  nsock_connect_internal(ms, nse, SOCK_STREAM, IPPROTO_TCP, ss, sslen, port);
  nsock_pool_add_event(ms, nse);

  return nse->id;
}

/* Request an SCTP association to another system (by IP address).  The in_addr
 * is normal network byte order, but the port number should be given in HOST
 * BYTE ORDER.  ss should be a sockaddr_storage, sockaddr_in6, or sockaddr_in as
 * appropriate (just like what you would pass to connect).  sslen should be the
 * sizeof the structure you are passing in. */
nsock_event_id nsock_connect_sctp(nsock_pool nsp, nsock_iod ms_iod, nsock_ev_handler handler, int timeout_msecs,
                                  void *userdata, struct sockaddr *saddr, size_t sslen, unsigned short port) {

  struct niod *nsi = (struct niod *)ms_iod;
  struct npool *ms = (struct npool *)nsp;
  struct nevent *nse;
  struct sockaddr_storage *ss = (struct sockaddr_storage *)saddr;

  assert(nsi->state == NSIOD_STATE_INITIAL || nsi->state == NSIOD_STATE_UNKNOWN);

  nse = event_new(ms, NSE_TYPE_CONNECT, nsi, timeout_msecs, handler, userdata);
  assert(nse);

  nsock_log_info("SCTP association requested to %s:%hu (IOD #%li) EID %li",
                 inet_ntop_ez(ss, sslen), port, nsi->id, nse->id);

  /* Do the actual connect() */
  nsock_connect_internal(ms, nse, SOCK_STREAM, IPPROTO_SCTP, ss, sslen, port);
  nsock_pool_add_event(ms, nse);

  return nse->id;
}

/* Request an SSL over TCP/SCTP connection to another system (by IP address).
 * The in_addr is normal network byte order, but the port number should be given
 * in HOST BYTE ORDER.  This function will call back only after it has made the
 * connection AND done the initial SSL negotiation.  From that point on, you use
 * the normal read/write calls and decryption will happen transparently. ss
 * should be a sockaddr_storage, sockaddr_in6, or sockaddr_in as appropriate
 * (just like what you would pass to connect).  sslen should be the sizeof the
 * structure you are passing in. */
nsock_event_id nsock_connect_ssl(nsock_pool nsp, nsock_iod nsiod, nsock_ev_handler handler, int timeout_msecs,
                                 void *userdata, struct sockaddr *saddr, size_t sslen, int proto, unsigned short port, nsock_ssl_session ssl_session) {

#ifndef HAVE_OPENSSL
  fatal("nsock_connect_ssl called - but nsock was built w/o SSL support.  QUITTING");
  return (nsock_event_id)0; /* UNREACHED */
#else
  struct sockaddr_storage *ss = (struct sockaddr_storage *)saddr;
  struct niod *nsi = (struct niod *)nsiod;
  struct npool *ms = (struct npool *)nsp;
  struct nevent *nse;

  if (!ms->sslctx)
    nsock_pool_ssl_init(ms, 0);

  assert(nsi->state == NSIOD_STATE_INITIAL || nsi->state == NSIOD_STATE_UNKNOWN);

  nse = event_new(ms, NSE_TYPE_CONNECT_SSL, nsi, timeout_msecs, handler, userdata);
  assert(nse);

  /* Set our SSL_SESSION so we can benefit from session-id reuse. */
  nsi_set_ssl_session(nsi, (SSL_SESSION *)ssl_session);

  nsock_log_info("SSL connection requested to %s:%hu/%s (IOD #%li) EID %li",
                 inet_ntop_ez(ss, sslen), port, (proto == IPPROTO_TCP ? "tcp" : "sctp"),
                 nsi->id, nse->id);

  /* Do the actual connect() */
  nsock_connect_internal(ms, nse, SOCK_STREAM, proto, ss, sslen, port);
  nsock_pool_add_event(ms, nse);

  return nse->id;
#endif /* HAVE_OPENSSL */
}

/* Request ssl connection over already established connection.  nsiod must be
 * socket that is already connected to target using nsock_connect_tcp or
 * nsock_connect_sctp.  All parameters have the same meaning as in
 * 'nsock_connect_ssl' */
nsock_event_id nsock_reconnect_ssl(nsock_pool nsp, nsock_iod nsiod, nsock_ev_handler handler, int timeout_msecs,
                                   void *userdata, nsock_ssl_session ssl_session) {

#ifndef HAVE_OPENSSL
  fatal("nsock_reconnect_ssl called - but nsock was built w/o SSL support.  QUITTING");
  return (nsock_event_id) 0; /* UNREACHED */
#else
  struct niod *nsi = (struct niod *)nsiod;
  struct npool *ms = (struct npool *)nsp;
  struct nevent *nse;

  if (!ms->sslctx)
    nsock_pool_ssl_init(ms, 0);

  nse = event_new(ms, NSE_TYPE_CONNECT_SSL, nsi, timeout_msecs, handler, userdata);
  assert(nse);

  /* Set our SSL_SESSION so we can benefit from session-id reuse. */
  nsi_set_ssl_session(nsi, (SSL_SESSION *)ssl_session);

  nsock_log_info("SSL reconnection requested (IOD #%li) EID %li",
                 nsi->id, nse->id);

  /* Do the actual connect() */
  nse->event_done = 0;
  nse->status = NSE_STATUS_SUCCESS;
  nsock_pool_add_event(ms, nse);

  return nse->id;
#endif /* HAVE_OPENSSL */
}

/* Request a UDP "connection" to another system (by IP address).  The in_addr is
 * normal network byte order, but the port number should be given in HOST BYTE
 * ORDER.  Since this is UDP, no packets are actually sent.  The destination IP
 * and port are just associated with the nsiod (an actual OS connect() call is
 * made).  You can then use the normal nsock write calls on the socket.  There
 * is no timeout since this call always calls your callback at the next
 * opportunity.  The advantages to having a connected UDP socket (as opposed to
 * just specifying an address with sendto() are that we can now use a consistent
 * set of write/read calls for TCP/UDP, received packets from the non-partner
 * are automatically dropped by the OS, and the OS can provide asynchronous
 * errors (see Unix Network Programming pp224).  ss should be a
 * sockaddr_storage, sockaddr_in6, or sockaddr_in as appropriate (just like what
 * you would pass to connect).  sslen should be the sizeof the structure you are
 * passing in. */
nsock_event_id nsock_connect_udp(nsock_pool nsp, nsock_iod nsiod, nsock_ev_handler handler, void *userdata,
                                 struct sockaddr *saddr, size_t sslen, unsigned short port) {

  struct niod *nsi = (struct niod *)nsiod;
  struct npool *ms = (struct npool *)nsp;
  struct nevent *nse;
  struct sockaddr_storage *ss = (struct sockaddr_storage *)saddr;

  assert(nsi->state == NSIOD_STATE_INITIAL || nsi->state == NSIOD_STATE_UNKNOWN);

  nse = event_new(ms, NSE_TYPE_CONNECT, nsi, -1, handler, userdata);
  assert(nse);

  nsock_log_info("UDP connection requested to %s:%hu (IOD #%li) EID %li",
                 inet_ntop_ez(ss, sslen), port, nsi->id, nse->id);

  nsock_connect_internal(ms, nse, SOCK_DGRAM, IPPROTO_UDP, ss, sslen, port);
  nsock_pool_add_event(ms, nse);

  return nse->id;
}

/* Returns that host/port/protocol information for the last communication (or
 * comm. attempt) this nsi has been involved with.  By "involved" with I mean
 * interactions like establishing (or trying to) a connection or sending a UDP
 * datagram through an unconnected nsock_iod.  AF is the address family (AF_INET
 * or AF_INET6), Protocl is IPPROTO_TCP or IPPROTO_UDP.  Pass NULL for
 * information you do not need.  If ANY of the information you requested is not
 * available, 0 will be returned and the unavailable sockets are zeroed.  If
 * protocol or af is requested but not available, it will be set to -1 (and 0
 * returned).  The pointers you pass in must be NULL or point to allocated
 * address space.  The sockaddr members should actually be sockaddr_storage,
 * sockaddr_in6, or sockaddr_in with the socklen of them set appropriately (eg
 * sizeof(sockaddr_storage) if that is what you are passing). */
int nsock_iod_get_communication_info(nsock_iod iod, int *protocol, int *af,
                                     struct sockaddr *local,
                                     struct sockaddr *remote, size_t socklen) {
  struct niod *nsi = (struct niod *)iod;
  int ret = 1;
  struct sockaddr_storage ss;
  socklen_t slen = sizeof(ss);
  int res;

  assert(socklen > 0);

  if (nsi->peerlen > 0) {
    if (remote)
      memcpy(remote, &(nsi->peer), MIN((unsigned)socklen, nsi->peerlen));
    if (protocol) {
      *protocol = nsi->lastproto;
      if (*protocol == -1) res = 0;
    }
    if (af) {
      *af = nsi->peer.ss_family;
    }
    if (local) {
      if (nsi->sd >= 0) {
        res = getsockname(nsi->sd, (struct sockaddr *)&ss, &slen);
        if (res == -1) {
          memset(local, 0, socklen);
          ret = 0;
        } else {
          assert(slen > 0);
          memcpy(local, &ss, MIN((unsigned)slen, socklen));
        }
      } else {
        memset(local, 0, socklen);
        ret = 0;
      }
    }
  } else {
    if (local || remote || protocol || af)
      ret = 0;

    if (remote)
      memset(remote, 0, socklen);

    if (local)
      memset(local, 0, socklen);

    if (protocol)
      *protocol = -1;

    if (af)
      *af = -1;
  }
  return ret;
}

