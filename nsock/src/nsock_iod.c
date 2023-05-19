/***************************************************************************
 * nsock_iod.c -- This contains the functions relating to nsock_iod (and   *
 * its nsock internal manifestation -- nsockiod.  This is is similar to a  *
 * file descriptor in that you create it and then use it to initiate       *
 * connections, read/write data, etc.                                      *
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

#include "nsock.h"
#include "nsock_internal.h"
#include "nsock_log.h"
#include "gh_list.h"
#include "netutils.h"

#if HAVE_PCAP
#include "nsock_pcap.h"
#endif

#include <string.h>


/* nsock_iod is like a "file descriptor" for the nsock library. You use it to
 * request events. And here is how you create an nsock_iod. nsock_iod_new returns
 * NULL if the iod cannot be allocated. Pass NULL as userdata if you don't want
 * to immediately associate any user data with the iod. */
nsock_iod nsock_iod_new(nsock_pool nsockp, void *userdata) {
  return nsock_iod_new2(nsockp, -1, userdata);
}

/* This version allows you to associate an existing sd with the msi so that you
 * can read/write it using the nsock infrastructure.  For example, you may want
 * to watch for data from STDIN_FILENO at the same time as you read/write
 * various sockets.  STDIN_FILENO is a special case, however. Any other sd is
 * dup()ed, so you may close or otherwise manipulate your copy.  The duped copy
 * will be destroyed when the nsi is destroyed. */
nsock_iod nsock_iod_new2(nsock_pool nsockp, int sd, void *userdata) {
  struct npool *nsp = (struct npool *)nsockp;
  gh_lnode_t *lnode;
  struct niod *nsi;

  lnode = gh_list_pop(&nsp->free_iods);
  if (!lnode) {
    nsi = (struct niod *)safe_malloc(sizeof(*nsi));
    memset(nsi, 0, sizeof(*nsi));
  } else {
    nsi = container_of(lnode, struct niod, nodeq);
  }

  if (sd == -1) {
    nsi->sd = -1;
    nsi->state = NSIOD_STATE_INITIAL;
  } else if (sd == STDIN_FILENO) {
    nsi->sd = STDIN_FILENO;
    nsi->state = NSIOD_STATE_UNKNOWN;
  } else {
    nsi->sd = dup_socket(sd);
    if (nsi->sd == -1) {
      free(nsi);
      return NULL;
    }
    unblock_socket(nsi->sd);
    nsi->state = NSIOD_STATE_UNKNOWN;
  }

  nsi->first_connect = NULL;
  nsi->first_read = NULL;
  nsi->first_write = NULL;
#if HAVE_PCAP
  nsi->first_pcap_read = NULL;
  nsi->readpcapsd_count = 0;
#endif
  nsi->readsd_count = 0;
  nsi->write_count = 0;

  nsi->userdata = userdata;
  nsi->nsp = (struct npool *)nsockp;

  nsi->_flags = 0;

  nsi->read_count = 0;
  nsi->write_count = 0;

  nsi->hostname = NULL;

  nsi->ipopts = NULL;
  nsi->ipoptslen = 0;

#if HAVE_OPENSSL
  nsi->ssl_session = NULL;
#endif

  if (nsp->px_chain) {
    nsi->px_ctx = proxy_chain_context_new(nsp);
  } else {
    nsi->px_ctx = NULL;
  }

  nsi->id = nsp->next_iod_serial++;
  if (nsi->id == 0)
    nsi->id = nsp->next_iod_serial++;

  /* The nsp keeps track of active iods so it can delete them if it is deleted */
  gh_list_append(&nsp->active_iods, &nsi->nodeq);

  nsock_log_info("nsock_iod_new (IOD #%lu)", nsi->id);

  return (nsock_iod)nsi;
}

/* Defined in nsock_core.c. */
int socket_count_zero(struct niod *iod, struct npool *ms);

/* If nsock_iod_new returned success, you must free the iod when you are done with
 * it to conserve memory (and in some cases, sockets).  After this call,
 * nsockiod may no longer be used -- you need to create a new one with
 * nsock_iod_new().  pending_response tells what to do with any events that are
 * pending on this nsock_iod.  This can be NSOCK_PENDING_NOTIFY (send a KILL
 * notification to each event), NSOCK_PENDING_SILENT (do not send notification
 * to the killed events), or NSOCK_PENDING_ERROR (print an error message and
 * quit the program) */
void nsock_iod_delete(nsock_iod nsockiod, enum nsock_del_mode pending_response) {
#if HAVE_PCAP
#define NUM_EVT_TYPES 4
#else
#define NUM_EVT_TYPES 3
#endif
  struct niod *nsi = (struct niod *)nsockiod;
  gh_lnode_t *evlist_ar[NUM_EVT_TYPES];
  gh_list_t *corresp_list[NUM_EVT_TYPES];
  int i;
  gh_lnode_t *current, *next;

  assert(nsi);

  if (nsi->state == NSIOD_STATE_DELETED) {
    /* This nsi is already marked as deleted, will probably be removed from the
     * list very soon. Just return to avoid breaking reentrancy. */
    return;
  }

  nsock_log_info("nsock_iod_delete (IOD #%lu)", nsi->id);

  if (nsi->events_pending > 0) {
    /* shit -- they killed the struct niod while an event was still pending on it.
     * Maybe I should store the pending events in the iod.  On the other hand,
     * this should be a pretty rare occurrence and so I'll save space and hassle
     * by just locating the events here by searching through the active events
     * list */
    if (pending_response == NSOCK_PENDING_ERROR)
      fatal("nsock_iod_delete called with argument NSOCK_PENDING_ERROR on a nsock_iod that has %d pending event(s) associated with it", nsi->events_pending);

    assert(pending_response == NSOCK_PENDING_NOTIFY || pending_response == NSOCK_PENDING_SILENT);

    evlist_ar[0] = nsi->first_connect;
    evlist_ar[1] = nsi->first_read;
    evlist_ar[2] = nsi->first_write;
#if HAVE_PCAP
    evlist_ar[3] = nsi->first_pcap_read;
#endif

    corresp_list[0] = &nsi->nsp->connect_events;
    corresp_list[1] = &nsi->nsp->read_events;
    corresp_list[2] = &nsi->nsp->write_events;
#if HAVE_PCAP
    corresp_list[3] = &nsi->nsp->pcap_read_events;
#endif

    for (i = 0; i < NUM_EVT_TYPES && nsi->events_pending > 0; i++) {
      for (current = evlist_ar[i]; current != NULL; current = next) {
        struct nevent *nse;

        next = gh_lnode_next(current);
        nse = lnode_nevent(current);

        /* we're done with this list of events for the current IOD */
        if (nse->iod != nsi)
          break;

        nevent_delete(nsi->nsp, nse, corresp_list[i], current, pending_response == NSOCK_PENDING_NOTIFY);
      }
    }
  }

  if (nsi->events_pending != 0)
    fatal("Trying to delete NSI, but could not find %d of the purportedly pending events on that IOD.\n", nsi->events_pending);

  /* Make sure we no longer select on this socket, in case the socket counts
   * weren't already decremented to zero. */
  if (nsi->sd >= 0)
    socket_count_zero(nsi, nsi->nsp);

  free(nsi->hostname);

#if HAVE_OPENSSL
  /* Close any SSL resources */
  if (nsi->ssl) {
    /* No longer free session because copy nsi stores is not reference counted */
#if 0
    if (nsi->ssl_session)
    SSL_SESSION_free(nsi->ssl_session);
    nsi->ssl_session = NULL;
#endif

    if (SSL_shutdown(nsi->ssl) == -1) {
      nsock_log_info("nsock_iod_delete: SSL shutdown failed (%s) on NSI %li",
                     ERR_reason_error_string(SSL_get_error(nsi->ssl, -1)), nsi->id);
    }

    /* I don't really care if the SSL_shutdown() succeeded politely. I could
     * make the SD blocking temporarily for this, but I'm hoping it will succeed
     * 95% of the time because we can usually write to a socket. */
    SSL_free(nsi->ssl);
    nsi->ssl = NULL;
  }
#endif

  if (nsi->sd >= 0 && nsi->sd != STDIN_FILENO) {
    close(nsi->sd);
    nsi->sd = -1;
  }

  nsi->state = NSIOD_STATE_DELETED;
  nsi->userdata = NULL;

  if (nsi->ipoptslen)
    free(nsi->ipopts);

#if HAVE_PCAP
  if (nsi->pcap){
    mspcap *mp = (mspcap *)nsi->pcap;

    if (mp->pt){
      pcap_close(mp->pt);
      mp->pt = NULL;
    }
    if (mp->pcap_desc) {
      /* pcap_close() will close the associated pcap descriptor */
      mp->pcap_desc = -1;
    }
    if (mp->pcap_device) {
      free(mp->pcap_device);
      mp->pcap_device = NULL;
    }
    free(mp);
    nsi->pcap = NULL;
  }
#endif

  if (nsi->px_ctx)
    proxy_chain_context_delete(nsi->px_ctx);
}

/* Returns the ID of an nsock_iod . This ID is always unique amongst ids for a
 * given nspool (unless you blow through billions of them). */
unsigned long nsock_iod_id(nsock_iod nsockiod) {
  assert(nsockiod);
  return ((struct niod *)nsockiod)->id;
}

/* Returns the SSL object inside an nsock_iod, or NULL if unset. */
nsock_ssl nsock_iod_get_ssl(nsock_iod iod) {
#if HAVE_OPENSSL
  return ((struct niod *)iod)->ssl;
#else
  return NULL;
#endif
}

/* Returns the SSL_SESSION of an nsock_iod.
 * Increments its usage count if inc_ref is not zero. */
nsock_ssl_session nsock_iod_get_ssl_session(nsock_iod iod, int inc_ref) {
#if HAVE_OPENSSL
  if (inc_ref)
    return SSL_get1_session(((struct niod *)iod)->ssl);
  else
    return SSL_get0_session(((struct niod *)iod)->ssl);
#else
  return NULL;
#endif
}

/* sets the ssl session of an nsock_iod, increments usage count. The session
 * should not have been set yet (as no freeing is done) */
#if HAVE_OPENSSL
void nsi_set_ssl_session(struct niod *iod, SSL_SESSION *sessid) {
  if (sessid) {
    iod->ssl_session = sessid;
    /* No reference counting for the copy stored briefly in nsiod */
  }
}
#endif

/* Sometimes it is useful to store a pointer to information inside the struct niod so
 * you can retrieve it during a callback. */
void nsock_iod_set_udata(nsock_iod iod, void *udata) {
  assert(iod);
  ((struct niod *)iod)->userdata = udata;
}

/* And the function above wouldn't make much sense if we didn't have a way to
 * retrieve that data... */
void *nsock_iod_get_udata(nsock_iod iod) {
  assert(iod);
  return ((struct niod *)iod)->userdata;
}

/* Returns 1 if an NSI is communicating via SSL, 0 otherwise. */
int nsock_iod_check_ssl(nsock_iod iod) {
  return (((struct niod *)iod)->ssl) ? 1 : 0;
}

/* Returns the remote peer port (or -1 if unavailable).  Note the return value
 * is a whole int so that -1 can be distinguished from 65535.  Port is returned
 * in host byte order. */
int nsock_iod_get_peerport(nsock_iod iod) {
  struct niod *nsi = (struct niod *)iod;
  int fam;

  if (nsi->peerlen <= 0)
    return -1;

  fam = ((struct sockaddr_in *)&nsi->peer)->sin_family;

  if (fam == AF_INET)
    return ntohs(((struct sockaddr_in *)&nsi->peer)->sin_port);
#if HAVE_IPV6
  else if (fam == AF_INET6)
    return ntohs(((struct sockaddr_in6 *)&nsi->peer)->sin6_port);
#endif

  return -1;
}

/* Sets the local address to bind to before connect() */
int nsock_iod_set_localaddr(nsock_iod iod, struct sockaddr_storage *ss,
                            size_t sslen) {
  struct niod *nsi = (struct niod *)iod;

  assert(nsi);

  if (sslen > sizeof(nsi->local))
    return -1;

  memcpy(&nsi->local, ss, sslen);
  nsi->locallen = sslen;
  return 0;
}

/* Sets IPv4 options to apply before connect(). It makes a copy of the options,
 * so you can free() yours if necessary. This copy is freed when the iod is
 * destroyed. */
int nsock_iod_set_ipoptions(nsock_iod iod, void *opts, size_t optslen) {
  struct niod *nsi = (struct niod *)iod;

  assert(nsi);

  if (optslen > 44)
    return -1;

  nsi->ipopts = safe_malloc(optslen);
  memcpy(nsi->ipopts, opts, optslen);
  nsi->ipoptslen = optslen;
  return 0;
}

/* I didn't want to do this.  Its an ugly hack, but I suspect it will be
 * necessary.  I certainly can't reproduce in nsock EVERYTHING you might want
 * to do with a socket.  So I'm offering you this function to obtain the socket
 * descriptor which is (usually) wrapped in a nsock_iod).  You can do
 * "reasonable" things with it, like setting socket receive buffers.  But don't
 * create havok by closing the descriptor!  If the descriptor you get back is
 * -1, the iod does not currently possess a valid descriptor */
int nsock_iod_get_sd(nsock_iod iod) {
  struct niod *nsi = (struct niod *)iod;

  assert(nsi);

#if HAVE_PCAP
  if (nsi->pcap)
    return ((mspcap *)nsi->pcap)->pcap_desc;
  else
#endif
    return nsi->sd;
}

unsigned long nsock_iod_get_read_count(nsock_iod iod){
  assert(iod);
  return ((struct niod *)iod)->read_count;
}

unsigned long nsock_iod_get_write_count(nsock_iod iod){
  assert(iod);
  return ((struct niod *)iod)->write_count;
}

int nsock_iod_set_hostname(nsock_iod iod, const char *hostname) {
  struct niod *nsi = (struct niod *)iod;

  if (nsi->hostname != NULL)
    free(nsi->hostname);

  nsi->hostname = strdup(hostname);
  if (nsi->hostname == NULL)
    return -1;

  return 0;
}

