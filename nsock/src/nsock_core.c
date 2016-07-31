/***************************************************************************
 * nsock_core.c -- This contains the core engine routines for the nsock    *
 * parallel socket event library.                                          *
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
#include "gh_list.h"
#include "filespace.h"
#include "nsock_log.h"

#include <assert.h>
#if HAVE_ERRNO_H
#include <errno.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif

#include "netutils.h"

#if HAVE_PCAP
#include "nsock_pcap.h"
#endif


/* Nsock time of day -- we update this at least once per nsock_loop round (and
 * after most calls that are likely to block).  Other nsock files should grab
 * this */
struct timeval nsock_tod;

/* Internal function defined in nsock_event.c
 * Update the nse->iod first events, assuming nse is about to be deleted */
void update_first_events(struct nevent *nse);



/* Each iod has a count of pending socket reads, socket writes, and pcap reads.
 * When a descriptor's count is nonzero, its bit must be set in the appropriate
 * master fd_set, and when the count is zero the bit must be cleared. What we
 * are simulating is an fd_set with a counter for each socket instead of just an
 * on/off switch. The fd_set's bits aren't enough by itself because a descriptor
 * may for example have two reads pending at once, and the bit must not be
 * cleared after the first is completed.
 * The socket_count_* functions return the event to transmit to update_events()
 */
int socket_count_zero(struct niod *iod, struct npool *ms) {
  iod->readsd_count = 0;
  iod->writesd_count = 0;
#if HAVE_PCAP
  iod->readpcapsd_count = 0;
#endif
  return nsock_engine_iod_unregister(ms, iod);
}

static int socket_count_read_inc(struct niod *iod) {
  assert(iod->readsd_count >= 0);
  iod->readsd_count++;
  return EV_READ;
}

static int socket_count_read_dec(struct niod *iod) {
  assert(iod->readsd_count > 0);
  iod->readsd_count--;
  return (iod->readsd_count == 0) ? EV_READ : EV_NONE;
}

static int socket_count_write_inc(struct niod *iod) {
  assert(iod->writesd_count >= 0);
  iod->writesd_count++;
  return EV_WRITE;
}

static int socket_count_write_dec(struct niod *iod) {
  assert(iod->writesd_count > 0);
  iod->writesd_count--;
  return (iod->writesd_count == 0) ? EV_WRITE : EV_NONE;
}

#if HAVE_PCAP
static int socket_count_readpcap_inc(struct niod *iod) {
  assert(iod->readpcapsd_count >= 0);
  iod->readpcapsd_count++;
  return EV_READ;
}

static int socket_count_readpcap_dec(struct niod *iod) {
  assert(iod->readpcapsd_count > 0);
  iod->readpcapsd_count--;
  return (iod->readpcapsd_count == 0) ? EV_READ : EV_NONE;
}
#endif

#if HAVE_OPENSSL
/* Call socket_count_read_dec or socket_count_write_dec on nse->iod depending on
 * the current value of nse->sslinfo.ssl_desire. */
static int socket_count_dec_ssl_desire(struct nevent *nse) {
  assert(nse->iod->ssl != NULL);
  assert(nse->sslinfo.ssl_desire == SSL_ERROR_WANT_READ ||
         nse->sslinfo.ssl_desire == SSL_ERROR_WANT_WRITE);

  if (nse->sslinfo.ssl_desire == SSL_ERROR_WANT_READ)
    return socket_count_read_dec(nse->iod);
  else
    return socket_count_write_dec(nse->iod);
}
#endif

/* Update the events that the IO engine should watch for a given IOD.
 *
 * ev_inc is a set of events for which the event counters should be increased.
 * These events will therefore be watched by the IO engine for this IOD.
 *
 * ev_dec is a set of events for which the event counters should be decreased.
 * If this counter reaches zero, the event won't be watched anymore by the
 * IO engine for this IOD.
 */
static void update_events(struct niod * iod, struct npool *ms, int ev_inc, int ev_dec) {
  int setmask, clrmask, ev_temp;

  /* Filter out events that belong to both sets. */
  ev_temp = ev_inc ^ ev_dec;
  ev_inc = ev_inc & ev_temp;
  ev_dec = ev_dec & ev_temp;

  setmask = ev_inc;
  clrmask = EV_NONE;

  if ((ev_dec & EV_READ) &&
#if HAVE_PCAP
      !iod->readpcapsd_count &&
#endif
      !iod->readsd_count)
    clrmask |= EV_READ;

  if ((ev_dec & EV_WRITE) && !iod->writesd_count)
    clrmask |= EV_WRITE;

  if (ev_dec & EV_EXCEPT)
    clrmask |= EV_EXCEPT;

  if (!IOD_PROPGET(iod, IOD_REGISTERED)) {
    assert(clrmask == EV_NONE);
    nsock_engine_iod_register(ms, iod, setmask);
  } else {
    nsock_engine_iod_modify(ms, iod, setmask, clrmask);
  }
}

/* Add a new event for a given IOD. nevents are stored in separate event lists
 * (in the nsock pool) and are grouped by IOD within each list.
 *
 * This function appends the event _before_ the first similar event we have for
 * the given IOD, or append it to the end of the list if no similar event is
 * already present.
 *
 * Note that adding the event before the similar ones is important for
 * reentrancy, as it will prevent the new event to be processed in the event
 * loop just after its addition.
 */
static int iod_add_event(struct niod *iod, struct nevent *nse) {
  struct npool *nsp = iod->nsp;

  switch (nse->type) {
    case NSE_TYPE_CONNECT:
    case NSE_TYPE_CONNECT_SSL:
      if (iod->first_connect)
        gh_list_insert_before(&nsp->connect_events,
                              iod->first_connect, &nse->nodeq_io);
      else
        gh_list_append(&nsp->connect_events, &nse->nodeq_io);
      iod->first_connect = &nse->nodeq_io;
      break;

    case NSE_TYPE_READ:
      if (iod->first_read)
        gh_list_insert_before(&nsp->read_events, iod->first_read, &nse->nodeq_io);
      else
        gh_list_append(&nsp->read_events, &nse->nodeq_io);
      iod->first_read = &nse->nodeq_io;
      break;

    case NSE_TYPE_WRITE:
      if (iod->first_write)
        gh_list_insert_before(&nsp->write_events, iod->first_write, &nse->nodeq_io);
      else
        gh_list_append(&nsp->write_events, &nse->nodeq_io);
      iod->first_write = &nse->nodeq_io;
      break;

#if HAVE_PCAP
    case NSE_TYPE_PCAP_READ: {
      char add_read = 0, add_pcap_read = 0;

#if PCAP_BSD_SELECT_HACK
      /* BSD hack mode: add event to both read and pcap_read lists */
      add_read = add_pcap_read = 1;
#else
      if (((mspcap *)iod->pcap)->pcap_desc >= 0) {
        add_read = 1;
      } else {
        add_pcap_read = 1;
      }
#endif
      if (add_read) {
        if (iod->first_read)
          gh_list_insert_before(&nsp->read_events, iod->first_read, &nse->nodeq_io);
        else
          gh_list_append(&nsp->read_events, &nse->nodeq_io);
        iod->first_read = &nse->nodeq_io;
      }
      if (add_pcap_read) {
        if (iod->first_pcap_read)
          gh_list_insert_before(&nsp->pcap_read_events, iod->first_pcap_read,
                                &nse->nodeq_pcap);
        else
          gh_list_append(&nsp->pcap_read_events, &nse->nodeq_pcap);
        iod->first_pcap_read = &nse->nodeq_pcap;
      }
      break;
    }
#endif

    default:
      fatal("Unknown event type (%d) for IOD #%lu\n", nse->type, iod->id);
  }
  return 0;
}

/* A handler function is defined for each of the main event types (read, write,
 * connect, timer, etc) -- the handler is called when new information is
 * available for the event.  The handler makes any necessary updates to the
 * event based on any new information available.  If the event becomes ready for
 * delivery, the handler sets nse->event_done and fills out the relevant event
 * fields (status, errnum) as applicable.  The handlers also take care of event
 * type specific teardown (such as clearing socket descriptors from select/poll
 * lists).  If event_done is not set, the handler will be called again in the
 * case of more information or an event timeout */

/* The event type handlers -- the first three arguments of each are the same:
 * struct npool *ms struct nevent *nse -- the event we have new info on enum nse_status --
 * The reason for the call, usually NSE_STATUS_SUCCESS (which generally means a
 * successful I/O call or NSE_STATUS_TIMEOUT or NSE_STATUS_CANCELLED
 *
 *  Some of the event type handlers have other parameters, specific to their
 *  needs.  All the handlers can assume that the calling function has checked
 *  that select or poll said their descriptors were readable/writeable (as
 *  appropriate).
 *
 *  The idea is that each handler will take care of the stuff that is specific
 *  to it and the calling function will handle the stuff that can be generalized
 *  to dispatching/deleting/etc. all events.  But the calling function may use
 *  type-specific info to determine whether the handler should be called at all
 *  (to save CPU time). */

/* handle_connect_results assumes that select or poll have already shown the
 * descriptor to be active */
void handle_connect_result(struct npool *ms, struct nevent *nse, enum nse_status status) {
  int optval;
  socklen_t optlen = sizeof(int);
  struct niod *iod = nse->iod;
  assert(iod != NULL);
#if HAVE_OPENSSL
  int sslerr;
  int rc = 0;
  int sslconnect_inprogress = nse->type == NSE_TYPE_CONNECT_SSL && nse->iod &&
    (nse->sslinfo.ssl_desire == SSL_ERROR_WANT_READ ||
     nse->sslinfo.ssl_desire == SSL_ERROR_WANT_WRITE);
#else
  int sslconnect_inprogress = 0;
#endif

  if (status == NSE_STATUS_TIMEOUT || status == NSE_STATUS_CANCELLED) {
    nse->status = status;
    nse->event_done = 1;
  } else if (sslconnect_inprogress) {
    /* Do nothing */
  } else if (status == NSE_STATUS_SUCCESS) {
    /* First we want to determine whether the socket really is connected */
    if (getsockopt(iod->sd, SOL_SOCKET, SO_ERROR, (char *)&optval, &optlen) != 0)
      optval = socket_errno(); /* Stupid Solaris */

    switch (optval) {
      case 0:
        nse->status = NSE_STATUS_SUCCESS;
        break;
      /* EACCES can be caused by ICMPv6 dest-unreach-admin, or when a port is
         blocked by Windows Firewall (WSAEACCES). */
      case EACCES:
      case ECONNREFUSED:
      case EHOSTUNREACH:
      case ENETDOWN:
      case ENETUNREACH:
      case ENETRESET:
      case ECONNABORTED:
      case ETIMEDOUT:
      case EHOSTDOWN:
      case ECONNRESET:
#ifdef WIN32
      case WSAEADDRINUSE:
      case WSAEADDRNOTAVAIL:
#endif
#ifndef WIN32
      case EPIPE: /* Has been seen after connect on Linux. */
      case ENOPROTOOPT: /* Also seen on Linux, perhaps in response to protocol unreachable. */
#endif
        nse->status = NSE_STATUS_ERROR;
        nse->errnum = optval;
        break;

      default:
        /* I'd like for someone to report it */
        fatal("Strange connect error from %s (%d): %s",
              inet_ntop_ez(&iod->peer, iod->peerlen), optval,
              socket_strerror(optval));
    }

    /* Now special code for the SSL case where the TCP connection was successful. */
    if (nse->type == NSE_TYPE_CONNECT_SSL &&
        nse->status == NSE_STATUS_SUCCESS) {
#if HAVE_OPENSSL
      assert(ms->sslctx != NULL);
      /* Reuse iod->ssl if present. If set, this is the second try at connection
         without the SSL_OP_NO_SSLv2 option set. */
      if (iod->ssl == NULL) {
        iod->ssl = SSL_new(ms->sslctx);
        if (!iod->ssl)
          fatal("SSL_new failed: %s", ERR_error_string(ERR_get_error(), NULL));
      }

#if HAVE_SSL_SET_TLSEXT_HOST_NAME
      if (iod->hostname != NULL) {
        if (SSL_set_tlsext_host_name(iod->ssl, iod->hostname) != 1)
          fatal("SSL_set_tlsext_host_name failed: %s", ERR_error_string(ERR_get_error(), NULL));
      }
#endif

      /* Associate our new SSL with the connected socket.  It will inherit the
       * non-blocking nature of the sd */
      if (SSL_set_fd(iod->ssl, iod->sd) != 1)
        fatal("SSL_set_fd failed: %s", ERR_error_string(ERR_get_error(), NULL));

      /* Event not done -- need to do SSL connect below */
      nse->sslinfo.ssl_desire = SSL_ERROR_WANT_CONNECT;
#endif
    } else {
      /* This is not an SSL connect (in which case we are always done), or the
       * TCP connect() underlying the SSL failed (in which case we are also done */
      nse->event_done = 1;
    }
  } else {
    fatal("Unknown status (%d)", status);
  }

  /* At this point the TCP connection is done, whether successful or not.
   * Therefore decrease the read/write listen counts that were incremented in
   * nsock_pool_add_event. In the SSL case, we may increase one of the counts depending
   * on whether SSL_connect returns an error of SSL_ERROR_WANT_READ or
   * SSL_ERROR_WANT_WRITE. In that case we will re-enter this function, but we
   * don't want to execute this block again. */
  if (iod->sd != -1 && !sslconnect_inprogress) {
    int ev = EV_NONE;

    ev |= socket_count_read_dec(iod);
    ev |= socket_count_write_dec(iod);
    ev |= EV_EXCEPT;
    update_events(iod, ms, EV_NONE, ev);
  }

#if HAVE_OPENSSL
  if (nse->type == NSE_TYPE_CONNECT_SSL && !nse->event_done) {
    /* Lets now start/continue/finish the connect! */
    if (iod->ssl_session) {
      rc = SSL_set_session(iod->ssl, iod->ssl_session);
      if (rc == 0)
        nsock_log_error("Uh-oh: SSL_set_session() failed - please tell dev@nmap.org");
      iod->ssl_session = NULL; /* No need for this any more */
    }

    /* If this is a reinvocation of handle_connect_result, clear out the listen
     * bits that caused it, based on the previous SSL desire. */
    if (sslconnect_inprogress) {
      int ev;

      ev = socket_count_dec_ssl_desire(nse);
      update_events(iod, ms, EV_NONE, ev);
    }

    rc = SSL_connect(iod->ssl);
    if (rc == 1) {
      /* Woop!  Connect is done! */
      nse->event_done = 1;
      /* Check that certificate verification was okay, if requested. */
      if (nsi_ssl_post_connect_verify(iod)) {
        nse->status = NSE_STATUS_SUCCESS;
      } else {
        nsock_log_error("certificate verification error for EID %li: %s",
                        nse->id, ERR_error_string(ERR_get_error(), NULL));
        nse->status = NSE_STATUS_ERROR;
      }
    } else {
      long options = SSL_get_options(iod->ssl);

      sslerr = SSL_get_error(iod->ssl, rc);
      if (rc == -1 && sslerr == SSL_ERROR_WANT_READ) {
        nse->sslinfo.ssl_desire = sslerr;
        socket_count_read_inc(iod);
        update_events(iod, ms, EV_READ, EV_NONE);
      } else if (rc == -1 && sslerr == SSL_ERROR_WANT_WRITE) {
        nse->sslinfo.ssl_desire = sslerr;
        socket_count_write_inc(iod);
        update_events(iod, ms, EV_WRITE, EV_NONE);
      } else if (!(options & SSL_OP_NO_SSLv2)) {
        int saved_ev;

        /* SSLv3-only and TLSv1-only servers can't be connected to when the
         * SSL_OP_NO_SSLv2 option is not set, which is the case when the pool
         * was initialized with nsock_pool_ssl_init_max_speed. Try reconnecting
         * with SSL_OP_NO_SSLv2. Never downgrade a NO_SSLv2 connection to one
         * that might use SSLv2. */
        nsock_log_info("EID %li reconnecting with SSL_OP_NO_SSLv2", nse->id);

        saved_ev = iod->watched_events;
        nsock_engine_iod_unregister(ms, iod);
        close(iod->sd);
        nsock_connect_internal(ms, nse, SOCK_STREAM, iod->lastproto, &iod->peer,
                               iod->peerlen, nsock_iod_get_peerport(iod));
        nsock_engine_iod_register(ms, iod, saved_ev);

        /* Use SSL_free here because SSL_clear keeps session info, which
         * doesn't work when changing SSL versions (as we're clearly trying to
         * do by adding SSL_OP_NO_SSLv2). */
        SSL_free(iod->ssl);
        iod->ssl = SSL_new(ms->sslctx);
        if (!iod->ssl)
          fatal("SSL_new failed: %s", ERR_error_string(ERR_get_error(), NULL));

        SSL_set_options(iod->ssl, options | SSL_OP_NO_SSLv2);
        socket_count_read_inc(nse->iod);
        socket_count_write_inc(nse->iod);
        update_events(iod, ms, EV_READ|EV_WRITE, EV_NONE);
        nse->sslinfo.ssl_desire = SSL_ERROR_WANT_CONNECT;
      } else {
        nsock_log_info("EID %li %s",
                       nse->id, ERR_error_string(ERR_get_error(), NULL));
        nse->event_done = 1;
        nse->status = NSE_STATUS_ERROR;
        nse->errnum = EIO;
      }
    }
  }
#endif
}

static int errcode_is_failure(int err) {
#ifndef WIN32
  return err != EINTR && err != EAGAIN && err != EBUSY;
#else
  return err != EINTR && err != EAGAIN;
#endif
}

void handle_write_result(struct npool *ms, struct nevent *nse, enum nse_status status) {
  int bytesleft;
  char *str;
  int res;
  int err;
  struct niod *iod = nse->iod;

  if (status == NSE_STATUS_TIMEOUT || status == NSE_STATUS_CANCELLED) {
    nse->event_done = 1;
    nse->status = status;
  } else if (status == NSE_STATUS_SUCCESS) {
    str = fs_str(&nse->iobuf) + nse->writeinfo.written_so_far;
    bytesleft = fs_length(&nse->iobuf) - nse->writeinfo.written_so_far;
    if (nse->writeinfo.written_so_far > 0)
      assert(bytesleft > 0);
#if HAVE_OPENSSL
    if (iod->ssl)
      res = SSL_write(iod->ssl, str, bytesleft);
    else
#endif
      if (nse->writeinfo.dest.ss_family == AF_UNSPEC)
        res = send(nse->iod->sd, str, bytesleft, 0);
      else
        res = sendto(nse->iod->sd, str, bytesleft, 0, (struct sockaddr *)&nse->writeinfo.dest, (int)nse->writeinfo.destlen);
    if (res == bytesleft) {
      nse->event_done = 1;
      nse->status = NSE_STATUS_SUCCESS;
    } else if (res >= 0) {
      nse->writeinfo.written_so_far += res;
    } else {
      assert(res == -1);
      if (iod->ssl) {
#if HAVE_OPENSSL
        err = SSL_get_error(iod->ssl, res);
        if (err == SSL_ERROR_WANT_READ) {
          int evclr;

          evclr = socket_count_dec_ssl_desire(nse);
          socket_count_read_inc(iod);
          update_events(iod, ms, EV_READ, evclr);
          nse->sslinfo.ssl_desire = err;
        } else if (err == SSL_ERROR_WANT_WRITE) {
          int evclr;

          evclr = socket_count_dec_ssl_desire(nse);
          socket_count_write_inc(iod);
          update_events(iod, ms, EV_WRITE, evclr);
          nse->sslinfo.ssl_desire = err;
        } else {
          /* Unexpected error */
          nse->event_done = 1;
          nse->status = NSE_STATUS_ERROR;
          nse->errnum = EIO;
        }
#endif
      } else {
        err = socket_errno();
        if (errcode_is_failure(err)) {
          nse->event_done = 1;
          nse->status = NSE_STATUS_ERROR;
          nse->errnum = err;
        }
      }
    }

    if (res >= 0)
      nse->iod->write_count += res;
  }

  if (nse->event_done && nse->iod->sd != -1) {
    int ev = EV_NONE;

#if HAVE_OPENSSL
    if (nse->iod->ssl != NULL)
      ev |= socket_count_dec_ssl_desire(nse);
    else
#endif
      ev |= socket_count_write_dec(nse->iod);
    update_events(nse->iod, ms, EV_NONE, ev);
  }
}

void handle_timer_result(struct npool *ms, struct nevent *nse, enum nse_status status) {
  /* Ooh this is a hard job :) */
  nse->event_done = 1;
  nse->status = status;
}

/* Returns -1 if an error, otherwise the number of newly written bytes */
static int do_actual_read(struct npool *ms, struct nevent *nse) {
  char buf[8192];
  int buflen = 0;
  struct niod *iod = nse->iod;
  int err = 0;
  int max_chunk = NSOCK_READ_CHUNK_SIZE;
  int startlen = fs_length(&nse->iobuf);

  if (nse->readinfo.read_type == NSOCK_READBYTES)
    max_chunk = nse->readinfo.num;

  if (!iod->ssl) {
    do {
      struct sockaddr_storage peer;
      socklen_t peerlen;

      peerlen = sizeof(peer);
      buflen = recvfrom(iod->sd, buf, sizeof(buf), 0, (struct sockaddr *)&peer, &peerlen);

      /* Using recv() was failing, at least on UNIX, for non-network sockets
       * (i.e. stdin) in this case, a read() is done - as on ENOTSOCK we may
       * have a non-network socket */
      if (buflen == -1) {
        if (socket_errno() == ENOTSOCK) {
          peer.ss_family = AF_UNSPEC;
          peerlen = 0;
          buflen = read(iod->sd, buf, sizeof(buf));
        }
      }
      if (buflen == -1) {
        err = socket_errno();
        break;
      }
      /* Windows will ignore src_addr and addrlen arguments to recvfrom on TCP
       * sockets, so peerlen is still sizeof(peer) and peer is junk. Instead,
       * only set this if it's not already set.
       */
      if (peerlen > 0 && iod->peerlen == 0) {
        assert(peerlen <= sizeof(iod->peer));
        memcpy(&iod->peer, &peer, peerlen);
        iod->peerlen = peerlen;
      }
      if (buflen > 0) {
        if (fs_cat(&nse->iobuf, buf, buflen) == -1) {
          nse->event_done = 1;
          nse->status = NSE_STATUS_ERROR;
          nse->errnum = ENOMEM;
          return -1;
        }

        /* Sometimes a service just spews and spews data.  So we return after a
         * somewhat large amount to avoid monopolizing resources and avoid DOS
         * attacks. */
        if (fs_length(&nse->iobuf) > max_chunk)
          return fs_length(&nse->iobuf) - startlen;

        /* No good reason to read again if we we were successful in the read but
         * didn't fill up the buffer.  Especially for UDP, where we want to
         * return only one datagram at a time. The consistency of the above
         * assignment of iod->peer depends on not consolidating more than one
         * UDP read buffer. */
        if (buflen > 0 && buflen < sizeof(buf))
          return fs_length(&nse->iobuf) - startlen;
      }
    } while (buflen > 0 || (buflen == -1 && err == EINTR));

    if (buflen == -1) {
      if (err != EINTR && err != EAGAIN) {
        nse->event_done = 1;
        nse->status = NSE_STATUS_ERROR;
        nse->errnum = err;
        return -1;
      }
    }
  } else {
#if HAVE_OPENSSL
    /* OpenSSL read */
    while ((buflen = SSL_read(iod->ssl, buf, sizeof(buf))) > 0) {

      if (fs_cat(&nse->iobuf, buf, buflen) == -1) {
        nse->event_done = 1;
        nse->status = NSE_STATUS_ERROR;
        nse->errnum = ENOMEM;
        return -1;
      }

      /* Sometimes a service just spews and spews data.  So we return
       * after a somewhat large amount to avoid monopolizing resources
       * and avoid DOS attacks. */
      if (fs_length(&nse->iobuf) > max_chunk)
        return fs_length(&nse->iobuf) - startlen;
    }

    if (buflen == -1) {
      err = SSL_get_error(iod->ssl, buflen);
      if (err == SSL_ERROR_WANT_READ) {
        int evclr;

        evclr = socket_count_dec_ssl_desire(nse);
        socket_count_read_inc(iod);
        update_events(iod, ms, EV_READ, evclr);
        nse->sslinfo.ssl_desire = err;
      } else if (err == SSL_ERROR_WANT_WRITE) {
        int evclr;

        evclr = socket_count_dec_ssl_desire(nse);
        socket_count_write_inc(iod);
        update_events(iod, ms, EV_WRITE, evclr);
        nse->sslinfo.ssl_desire = err;
      } else {
        /* Unexpected error */
        nse->event_done = 1;
        nse->status = NSE_STATUS_ERROR;
        nse->errnum = EIO;
        nsock_log_info("SSL_read() failed for reason %s on NSI %li",
                       ERR_error_string(err, NULL), iod->id);
        return -1;
      }
    }
#endif /* HAVE_OPENSSL */
  }

  if (buflen == 0) {
    nse->event_done = 1;
    nse->eof = 1;
    if (fs_length(&nse->iobuf) > 0) {
      nse->status = NSE_STATUS_SUCCESS;
      return fs_length(&nse->iobuf) - startlen;
    } else {
      nse->status = NSE_STATUS_EOF;
      return 0;
    }
  }

  return fs_length(&nse->iobuf) - startlen;
}


void handle_read_result(struct npool *ms, struct nevent *nse, enum nse_status status) {
  unsigned int count;
  char *str;
  int rc, len;
  struct niod *iod = nse->iod;

  if (status == NSE_STATUS_TIMEOUT) {
    nse->event_done = 1;
    if (fs_length(&nse->iobuf) > 0)
      nse->status = NSE_STATUS_SUCCESS;
    else
      nse->status = NSE_STATUS_TIMEOUT;
  } else if (status == NSE_STATUS_CANCELLED) {
    nse->status = status;
    nse->event_done = 1;
  } else if (status == NSE_STATUS_SUCCESS) {
    rc = do_actual_read(ms, nse);
    /* printf("DBG: Just read %d new bytes%s.\n", rc, iod->ssl? "( SSL!)" : ""); */
    if (rc > 0) {
      nse->iod->read_count += rc;
      /* We decide whether we have read enough to return */
      switch (nse->readinfo.read_type) {
        case NSOCK_READ:
          nse->status = NSE_STATUS_SUCCESS;
          nse->event_done = 1;
          break;
        case NSOCK_READBYTES:
          if (fs_length(&nse->iobuf) >= nse->readinfo.num) {
            nse->status = NSE_STATUS_SUCCESS;
            nse->event_done = 1;
          }
          /* else we are not done */
          break;
        case NSOCK_READLINES:
          /* Lets count the number of lines we have ... */
          count = 0;
          len = fs_length(&nse->iobuf) -1;
          str = fs_str(&nse->iobuf);
          for (count=0; len >= 0; len--) {
            if (str[len] == '\n') {
              count++;
              if ((int)count >= nse->readinfo.num)
                break;
            }
          }
          if ((int) count >= nse->readinfo.num) {
            nse->event_done = 1;
            nse->status = NSE_STATUS_SUCCESS;
          }
          /* Else we are not done */
          break;
        default:
          fatal("Unknown operation type (%d)", (int)nse->readinfo.read_type);
      }
    }
  } else {
    fatal("Unknown status (%d)", status);
  }

  /* If there are no more reads for this IOD, we are done reading on the socket
   * so we can take it off the descriptor list ... */
  if (nse->event_done && iod->sd >= 0) {
    int ev = EV_NONE;

#if HAVE_OPENSSL
    if (nse->iod->ssl != NULL)
      ev |= socket_count_dec_ssl_desire(nse);
    else
#endif
      ev |= socket_count_read_dec(nse->iod);
    update_events(nse->iod, ms, EV_NONE, ev);
  }
}

#if HAVE_PCAP
void handle_pcap_read_result(struct npool *ms, struct nevent *nse, enum nse_status status) {
  struct niod *iod = nse->iod;
  mspcap *mp = (mspcap *)iod->pcap;

  switch (status) {
    case NSE_STATUS_TIMEOUT:
      nse->status = NSE_STATUS_TIMEOUT;
      nse->event_done = 1;
      break;

    case NSE_STATUS_CANCELLED:
      nse->status = NSE_STATUS_CANCELLED;
      nse->event_done = 1;
      break;

    case NSE_STATUS_SUCCESS:
      /* check if we already have something read */
      if (fs_length(&(nse->iobuf)) == 0) {
        nse->status = NSE_STATUS_TIMEOUT;
        nse->event_done = 0;
      } else {
        nse->status = NSE_STATUS_SUCCESS; /* we have full buffer */
        nse->event_done = 1;
      }
      break;

    default:
      fatal("Unknown status (%d) for nsock event #%lu", status, nse->id);
  }

  /* If there are no more read events, we are done reading on the socket so we
   * can take it off the descriptor list... */
  if (nse->event_done && mp->pcap_desc >= 0) {
    int ev;

    ev = socket_count_readpcap_dec(iod);
    update_events(iod, ms, EV_NONE, ev);
  }
}

/* Returns whether something was read */
int pcap_read_on_nonselect(struct npool *nsp) {
  gh_lnode_t *current, *next;
  struct nevent *nse;
  int ret = 0;

  for (current = gh_list_first_elem(&nsp->pcap_read_events);
       current != NULL;
       current = next) {
    nse = lnode_nevent2(current);
    if (do_actual_pcap_read(nse) == 1) {
      /* something received */
      ret++;
      break;
    }
    next = gh_lnode_next(current);
  }
  return ret;
}
#endif /* HAVE_PCAP */

/* Here is the all important looping function that tells the event engine to
 * start up and begin processing events.  It will continue until all events have
 * been delivered (including new ones started from event handlers), or the
 * msec_timeout is reached, or a major error has occurred.  Use -1 if you don't
 * want to set a maximum time for it to run.  A timeout of 0 will return after 1
 * non-blocking loop.  The nsock loop can be restarted again after it returns.
 * For example you could do a series of 15 second runs, allowing you to do other
 * stuff between them */
enum nsock_loopstatus nsock_loop(nsock_pool nsp, int msec_timeout) {
  struct npool *ms = (struct npool *)nsp;
  struct timeval loop_timeout;
  int msecs_left;
  unsigned long loopnum = 0;
  enum nsock_loopstatus quitstatus = NSOCK_LOOP_ERROR;

  gettimeofday(&nsock_tod, NULL);

  if (msec_timeout < -1) {
    ms->errnum = EINVAL;
    return NSOCK_LOOP_ERROR;
  }
  TIMEVAL_MSEC_ADD(loop_timeout, nsock_tod, msec_timeout);
  msecs_left = msec_timeout;

  if (msec_timeout >= 0)
    nsock_log_debug("nsock_loop() started (timeout=%dms). %d events pending",
                    msec_timeout, ms->events_pending);
  else
    nsock_log_debug("nsock_loop() started (no timeout). %d events pending",
                    ms->events_pending);

  while (1) {
    if (ms->quit) {
      /* We've been asked to quit the loop through nsock_loop_quit. */
      ms->quit = 0;
      quitstatus = NSOCK_LOOP_QUIT;
      break;
    }

    if (ms->events_pending == 0) {
      /* if no events at all are pending, then none can be created until
       * we quit nsock_loop() -- so we do that now. */
      quitstatus = NSOCK_LOOP_NOEVENTS;
      break;
    }

    if (msec_timeout >= 0) {
      msecs_left = MAX(0, TIMEVAL_MSEC_SUBTRACT(loop_timeout, nsock_tod));
      if (msecs_left == 0 && loopnum > 0) {
        quitstatus = NSOCK_LOOP_TIMEOUT;
        break;
      }
    }

    if (nsock_engine_loop(ms, msecs_left) == -1) {
      quitstatus = NSOCK_LOOP_ERROR;
      break;
    }

    gettimeofday(&nsock_tod, NULL); /* we do this at end because there is one
                                     * at beginning of function */
    loopnum++;
  }

  return quitstatus;
}

void process_event(struct npool *nsp, gh_list_t *evlist, struct nevent *nse, int ev) {
  int match_r = 0, match_w = 0;
#if HAVE_OPENSSL
  int desire_r = 0, desire_w = 0;
#endif

  nsock_log_debug_all("Processing event %lu (timeout in %ldms, done=%d)",
                      nse->id,
                      (long)TIMEVAL_MSEC_SUBTRACT(nse->timeout, nsock_tod),
                      nse->event_done);

  if (!nse->event_done) {
    switch (nse->type) {
      case NSE_TYPE_CONNECT:
      case NSE_TYPE_CONNECT_SSL:
        if (ev != EV_NONE)
          handle_connect_result(nsp, nse, NSE_STATUS_SUCCESS);
        if (event_timedout(nse))
          handle_connect_result(nsp, nse, NSE_STATUS_TIMEOUT);
        break;

      case NSE_TYPE_READ:
        match_r = ev & EV_READ;
        match_w = ev & EV_WRITE;
#if HAVE_OPENSSL
        desire_r = nse->sslinfo.ssl_desire == SSL_ERROR_WANT_READ;
        desire_w = nse->sslinfo.ssl_desire == SSL_ERROR_WANT_WRITE;
        if (nse->iod->ssl && ((desire_r && match_r) || (desire_w && match_w)))
          handle_read_result(nsp, nse, NSE_STATUS_SUCCESS);
        else
#endif
        if (!nse->iod->ssl && match_r)
          handle_read_result(nsp, nse, NSE_STATUS_SUCCESS);

        if (event_timedout(nse))
          handle_read_result(nsp, nse, NSE_STATUS_TIMEOUT);
        break;

      case NSE_TYPE_WRITE:
        match_r = ev & EV_READ;
        match_w = ev & EV_WRITE;
#if HAVE_OPENSSL
        desire_r = nse->sslinfo.ssl_desire == SSL_ERROR_WANT_READ;
        desire_w = nse->sslinfo.ssl_desire == SSL_ERROR_WANT_WRITE;
        if (nse->iod->ssl && ((desire_r && match_r) || (desire_w && match_w)))
          handle_write_result(nsp, nse, NSE_STATUS_SUCCESS);
        else
#endif
          if (!nse->iod->ssl && match_w)
            handle_write_result(nsp, nse, NSE_STATUS_SUCCESS);

        if (event_timedout(nse))
          handle_write_result(nsp, nse, NSE_STATUS_TIMEOUT);
        break;

      case NSE_TYPE_TIMER:
        if (event_timedout(nse))
          handle_timer_result(nsp, nse, NSE_STATUS_SUCCESS);
        break;

#if HAVE_PCAP
      case NSE_TYPE_PCAP_READ:{
        nsock_log_debug_all("PCAP iterating %lu", nse->id);

        if (ev & EV_READ) {
          /* buffer empty? check it! */
          if (fs_length(&(nse->iobuf)) == 0)
            do_actual_pcap_read(nse);
        }

        /* if already received something */
        if (fs_length(&(nse->iobuf)) > 0)
          handle_pcap_read_result(nsp, nse, NSE_STATUS_SUCCESS);

        if (event_timedout(nse))
          handle_pcap_read_result(nsp, nse, NSE_STATUS_TIMEOUT);

        #if PCAP_BSD_SELECT_HACK
        /* If event occurred, and we're in BSD_HACK mode, then this event was added
         * to two queues. read_event and pcap_read_event
         * Of course we should destroy it only once.
         * I assume we're now in read_event, so just unlink this event from
         * pcap_read_event */
        if (((mspcap *)nse->iod->pcap)->pcap_desc >= 0
            && nse->event_done
            && evlist == &nsp->read_events) {
          /* event is done, list is read_events and we're in BSD_HACK mode.
           * So unlink event from pcap_read_events */
          update_first_events(nse);
          gh_list_remove(&nsp->pcap_read_events, &nse->nodeq_pcap);

          nsock_log_debug_all("PCAP NSE #%lu: Removing event from PCAP_READ_EVENTS",
                              nse->id);
        }
        if (((mspcap *)nse->iod->pcap)->pcap_desc >= 0
            && nse->event_done
            && evlist == &nsp->pcap_read_events) {
          update_first_events(nse);
          gh_list_remove(&nsp->read_events, &nse->nodeq_io);
          nsock_log_debug_all("PCAP NSE #%lu: Removing event from READ_EVENTS",
                              nse->id);
        }
        #endif
        break;
      }
#endif
      default:
        fatal("Event has unknown type (%d)", nse->type);
    }
  }

  if (nse->event_done) {
    /* Security sanity check: don't return a functional SSL iod without
     * setting an SSL data structure. */
    if (nse->type == NSE_TYPE_CONNECT_SSL && nse->status == NSE_STATUS_SUCCESS)
      assert(nse->iod->ssl != NULL);

    nsock_log_debug_all("NSE #%lu: Sending event", nse->id);

    /* WooHoo!  The event is ready to be sent */
    event_dispatch_and_delete(nsp, nse, 1);
  }
}

void process_iod_events(struct npool *nsp, struct niod *nsi, int ev) {
  int i = 0;
  /* store addresses of the pointers to the first elements of each kind instead
   * of storing the values, as a connect can add a read for instance */
  gh_lnode_t **start_elems[] = {
    &nsi->first_connect,
    &nsi->first_read,
    &nsi->first_write,
#if HAVE_PCAP
    &nsi->first_pcap_read,
#endif
    NULL
  };
  gh_list_t *evlists[] = {
    &nsp->connect_events,
    &nsp->read_events,
    &nsp->write_events,
#if HAVE_PCAP
    &nsp->pcap_read_events,
#endif
    NULL
  };

  assert(nsp == nsi->nsp);
  nsock_log_debug_all("Processing events on IOD %lu (ev=%d)", nsi->id, ev);

  /* We keep the events separate because we want to handle them in the
   * order: connect => read => write => timer for several reasons:
   *
   *  1) Makes sure we have gone through all the net i/o events before
   *     a timer expires (would be a shame to timeout after the data was
   *     available but before we delivered the events
   *
   *  2) The connect() results often lead to a read or write that can be
   *     processed in the same cycle.  In the same way, read() often
   *     leads to write().
   */
  for (i = 0; evlists[i] != NULL; i++) {
    gh_lnode_t *current, *next, *last;

    /* for each list, get the last event and don't look past it as an event
     * could add another event in the same list and so on... */
    last = gh_list_last_elem(evlists[i]);

    for (current = *start_elems[i];
         current != NULL && gh_lnode_prev(current) != last;
         current = next) {
      struct nevent *nse;

#if HAVE_PCAP
      if (evlists[i] == &nsi->nsp->pcap_read_events)
        nse = lnode_nevent2(current);
      else
#endif
        nse = lnode_nevent(current);

      /* events are grouped by IOD. Break if we're done with the events for the
       * current IOD */
      if (nse->iod != nsi)
        break;

      process_event(nsp, evlists[i], nse, ev);
      next = gh_lnode_next(current);

      if (nse->event_done) {
        /* event is done, remove it from the event list and update IOD pointers
         * to the first events of each kind */
        update_first_events(nse);
        gh_list_remove(evlists[i], current);
        gh_list_append(&nsp->free_events, &nse->nodeq_io);

        if (nse->timeout.tv_sec)
          gh_heap_remove(&nsp->expirables, &nse->expire);
      }
    }
  }
}

static int nevent_unref(struct npool *nsp, struct nevent *nse) {
  switch (nse->type) {
    case NSE_TYPE_CONNECT:
    case NSE_TYPE_CONNECT_SSL:
      gh_list_remove(&nsp->connect_events, &nse->nodeq_io);
      break;

    case NSE_TYPE_READ:
      gh_list_remove(&nsp->read_events, &nse->nodeq_io);
      break;

    case NSE_TYPE_WRITE:
      gh_list_remove(&nsp->write_events, &nse->nodeq_io);
      break;

#if HAVE_PCAP
    case NSE_TYPE_PCAP_READ: {
      char read = 0;
      char pcap = 0;

#if PCAP_BSD_SELECT_HACK
      read = pcap = 1;
#else
      if (((mspcap *)nse->iod->pcap)->pcap_desc >= 0)
        read = 1;
      else
        pcap = 1;
#endif /* PCAP_BSD_SELECT_HACK */

      if (read)
        gh_list_remove(&nsp->read_events, &nse->nodeq_io);
      if (pcap)
        gh_list_remove(&nsp->pcap_read_events, &nse->nodeq_pcap);

      break;
    }
#endif /* HAVE_PCAP */

    case NSE_TYPE_TIMER:
      /* Nothing to do */
      break;

    default:
      fatal("Unknown event type %d", nse->type);
  }
  gh_list_append(&nsp->free_events, &nse->nodeq_io);
  return 0;
}

void process_expired_events(struct npool *nsp) {
  for (;;) {
    gh_hnode_t *hnode;
    struct nevent *nse;

    hnode = gh_heap_min(&nsp->expirables);
    if (!hnode)
      break;

    nse = container_of(hnode, struct nevent, expire);
    if (!event_timedout(nse))
      break;

    gh_heap_pop(&nsp->expirables);
    process_event(nsp, NULL, nse, EV_NONE);
    assert(nse->event_done);
    update_first_events(nse);
    nevent_unref(nsp, nse);
  }
}

/* Calling this function will cause nsock_loop to quit on its next iteration
 * with a return value of NSOCK_LOOP_QUIT. */
void nsock_loop_quit(nsock_pool nsp) {
  struct npool *ms = (struct npool *)nsp;
  ms->quit = 1;
}

/* Grab the latest time as recorded by the nsock library, which does so at least
 * once per event loop (in main_loop).  Not only does this function (generally)
 * avoid a system call, but in many circumstances it is better to use nsock's
 * time rather than the system time.  If nsock has never obtained the time when
 * you call it, it will do so before returning */
const struct timeval *nsock_gettimeofday() {
  if (nsock_tod.tv_sec == 0)
    gettimeofday(&nsock_tod, NULL);
  return &nsock_tod;
}

/* Adds an event to the appropriate nsp event list, handles housekeeping such as
 * adjusting the descriptor select/poll lists, registering the timeout value,
 * etc. */
void nsock_pool_add_event(struct npool *nsp, struct nevent *nse) {
  nsock_log_debug("NSE #%lu: Adding event (timeout in %ldms)",
                  nse->id,
                  (long)TIMEVAL_MSEC_SUBTRACT(nse->timeout, nsock_tod));

  nsp->events_pending++;

  if (!nse->event_done && nse->timeout.tv_sec) {
    /* This event is expirable, add it to the queue */
    gh_heap_push(&nsp->expirables, &nse->expire);
  }

  /* Now we do the event type specific actions */
  switch (nse->type) {
    case NSE_TYPE_CONNECT:
    case NSE_TYPE_CONNECT_SSL:
      if (!nse->event_done) {
        assert(nse->iod->sd >= 0);
        socket_count_read_inc(nse->iod);
        socket_count_write_inc(nse->iod);
        update_events(nse->iod, nsp, EV_READ|EV_WRITE|EV_EXCEPT, EV_NONE);
      }
      iod_add_event(nse->iod, nse);
      break;

    case NSE_TYPE_READ:
      if (!nse->event_done) {
        assert(nse->iod->sd >= 0);
        socket_count_read_inc(nse->iod);
        update_events(nse->iod, nsp, EV_READ, EV_NONE);
#if HAVE_OPENSSL
        if (nse->iod->ssl)
          nse->sslinfo.ssl_desire = SSL_ERROR_WANT_READ;
#endif
      }
      iod_add_event(nse->iod, nse);
      break;

    case NSE_TYPE_WRITE:
      if (!nse->event_done) {
        assert(nse->iod->sd >= 0);
        socket_count_write_inc(nse->iod);
        update_events(nse->iod, nsp, EV_WRITE, EV_NONE);
#if HAVE_OPENSSL
        if (nse->iod->ssl)
          nse->sslinfo.ssl_desire = SSL_ERROR_WANT_WRITE;
#endif
      }
      iod_add_event(nse->iod, nse);
      break;

    case NSE_TYPE_TIMER:
      /* nothing to do */
      break;

#if HAVE_PCAP
    case NSE_TYPE_PCAP_READ: {
      mspcap *mp = (mspcap *)nse->iod->pcap;

      assert(mp);
      if (mp->pcap_desc >= 0) { /* pcap descriptor present */
        if (!nse->event_done) {
          socket_count_readpcap_inc(nse->iod);
          update_events(nse->iod, nsp, EV_READ, EV_NONE);
        }
        nsock_log_debug_all("PCAP NSE #%lu: Adding event to READ_EVENTS", nse->id);

        #if PCAP_BSD_SELECT_HACK
        /* when using BSD hack we must do pcap_next() after select().
         * Let's insert this pcap to bot queues, to selectable and nonselectable.
         * This will result in doing pcap_next_ex() just before select() */
        nsock_log_debug_all("PCAP NSE #%lu: Adding event to PCAP_READ_EVENTS", nse->id);
        #endif
      } else {
        /* pcap isn't selectable. Add it to pcap-specific queue. */
        nsock_log_debug_all("PCAP NSE #%lu: Adding event to PCAP_READ_EVENTS", nse->id);
      }
      iod_add_event(nse->iod, nse);
      break;
    }
#endif

    default:
      fatal("Unknown nsock event type (%d)", nse->type);
  }

  /* It can happen that the event already completed. In which case we can
   * already deliver it, even though we're probably not inside nsock_loop(). */
  if (nse->event_done) {
    event_dispatch_and_delete(nsp, nse, 1);
    update_first_events(nse);
    nevent_unref(nsp, nse);
  }
}

/* An event has been completed and the handler is about to be called. This
 * function writes out tracing data about the event if necessary */
void nsock_trace_handler_callback(struct npool *ms, struct nevent *nse) {
  struct niod *nsi;
  char *str;
  int strlength = 0;
  char displaystr[256];
  char errstr[256];

  if (NsockLogLevel > NSOCK_LOG_INFO)
    return;

  nsi = nse->iod;

  if (nse->status == NSE_STATUS_ERROR)
    Snprintf(errstr, sizeof(errstr), "[%s (%d)] ", socket_strerror(nse->errnum),
             nse->errnum);
  else
    errstr[0] = '\0';

  /* Some types have special tracing treatment */
  switch (nse->type) {
    case NSE_TYPE_CONNECT:
    case NSE_TYPE_CONNECT_SSL:
      nsock_log_info("Callback: %s %s %sfor EID %li [%s]",
                     nse_type2str(nse->type), nse_status2str(nse->status),
                     errstr, nse->id, get_peeraddr_string(nsi));
      break;

    case NSE_TYPE_READ:
      if (nse->status != NSE_STATUS_SUCCESS) {
        nsock_log_info("Callback: %s %s %sfor EID %li [%s]",
                       nse_type2str(nse->type), nse_status2str(nse->status),
                       errstr, nse->id, get_peeraddr_string(nsi));
      } else {
        str = nse_readbuf(nse, &strlength);
        if (strlength < 80) {
          memcpy(displaystr, ": ", 2);
          memcpy(displaystr + 2, str, strlength);
          displaystr[2 + strlength] = '\0';
          replacenonprintable(displaystr + 2, strlength, '.');
        } else {
          displaystr[0] = '\0';
        }
        nsock_log_info("Callback: %s %s for EID %li [%s] %s(%d bytes)%s",
                       nse_type2str(nse->type), nse_status2str(nse->status),
                       nse->id,
                       get_peeraddr_string(nsi),
                       nse_eof(nse) ? "[EOF]" : "", strlength, displaystr);
      }
      break;

    case NSE_TYPE_WRITE:
      nsock_log_info("Callback: %s %s %sfor EID %li [%s]",
                     nse_type2str(nse->type), nse_status2str(nse->status),
                     errstr, nse->id, get_peeraddr_string(nsi));
      break;

    case NSE_TYPE_TIMER:
      nsock_log_info("Callback: %s %s %sfor EID %li",
                     nse_type2str(nse->type), nse_status2str(nse->status),
                     errstr, nse->id);
      break;

#if HAVE_PCAP
    case NSE_TYPE_PCAP_READ:
      nsock_log_info("Callback: %s %s %sfor EID %li ",
                     nse_type2str(nse->type), nse_status2str(nse->status),
                     errstr, nse->id);
      break;
#endif

    default:
      fatal("Invalid nsock event type (%d)", nse->type);
  }
}

