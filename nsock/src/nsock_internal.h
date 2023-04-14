/***************************************************************************
 * nsock_internal.h -- PRIVATE interface definitions for the guts of the   *
 * nsock parallel socket event library. Applications calling this library  *
 * should NOT include this. even LOOK at these :).                         *
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

#ifndef NSOCK_INTERNAL_H
#define NSOCK_INTERNAL_H

#include <nbase.h>

#ifdef HAVE_CONFIG_H
#include "nsock_config.h"
#include "nbase_config.h"
#endif

#ifdef WIN32
#include "nbase_winconfig.h"
#include <Winsock2.h>
#endif

#include "gh_list.h"
#include "gh_heap.h"
#include "filespace.h"
#include "nsock.h" /* The public interface -- I need it for some enum defs */
#include "nsock_ssl.h"
#include "nsock_proxy.h"

#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
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
#if HAVE_STRINGS_H
#include <strings.h>
#endif
#if HAVE_SYS_UN_H
#include <sys/un.h>
#endif

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif


/* ------------------- CONSTANTS ------------------- */
#define READ_BUFFER_SZ 8192

enum nsock_read_types {
  NSOCK_READLINES,
  NSOCK_READBYTES,
  NSOCK_READ
};

enum iod_state {
  NSIOD_STATE_DELETED,
  NSIOD_STATE_INITIAL,

  /* sd was provided to us in nsock_iod_new2 (see nsock_iod.c) */
  NSIOD_STATE_UNKNOWN,

  NSIOD_STATE_CONNECTED_TCP,
  NSIOD_STATE_CONNECTED_UDP
};

/* XXX: ensure that these values can be OR'ed when adding new ones */
#define EV_NONE   0x00
#define EV_READ   0x01
#define EV_WRITE  0x02
#define EV_EXCEPT 0x04


/* ------------------- STRUCTURES ------------------- */

struct readinfo {
  enum nsock_read_types read_type;
  /* num lines; num bytes; whatever (depends on read_type) */
  int num;
};

struct writeinfo {
  struct sockaddr_storage dest;
  size_t destlen;
  /* Number of bytes successfully written */
  int written_so_far;
};

/* Remember that callers of this library should NOT be accessing these
 * fields directly */
struct npool {
  /* User data, NULL if unset */
  void *userdata;

  /* IO Engine vtable */
  struct io_engine *engine;
  /* IO Engine internal data */
  void *engine_data;

  /* Active network events */
  gh_list_t connect_events;
  gh_list_t read_events;
  gh_list_t write_events;
#if HAVE_PCAP
  gh_list_t pcap_read_events;
#endif
  gh_heap_t expirables;

  /* Active iods and related lists of events */
  gh_list_t active_iods;

  /* struct niod structures that have been freed for reuse */
  gh_list_t free_iods;
  /* When an event is deleted, we stick it here for later reuse */
  gh_list_t free_events;

  /* Number of events pending (total) on all lists */
  int events_pending;

  /* Serial # of next event (used to create next nsock_event_id */
  unsigned long next_event_serial;
  /* Serial # of next iod to be created */
  unsigned long next_iod_serial;

  /* If nsock_loop() returns NSOCK_LOOP_ERROR, this is where we describe the
   * error (errnum fashion) */
  int errnum;

  /* If true, new sockets will have SO_BROADCAST set */
  int broadcast;

  /* Interface to bind to; only supported on Linux with SO_BINDTODEVICE sockopt. */
  const char *device;

  /* If true, exit the next iteration of nsock_loop with a status of
   * NSOCK_LOOP_QUIT. */
  int quit;

#if HAVE_OPENSSL
  /* The SSL Context (options and such) */
  SSL_CTX *sslctx;
#ifdef HAVE_DTLS_CLIENT_METHOD
  SSL_CTX *dtlsctx;
#endif
#endif

  /* Optional proxy chain (NULL is not set). Can only be set once per NSP (using
   * nsock_proxychain_new() or nsock_pool_set_proxychain(). */
  struct proxy_chain *px_chain;

};


/* nsock_iod is like a "file descriptor" for the nsock library.  You use it to
 * request events. */
struct niod {
  /* The socket descriptor related to the event */
  int sd;

  /* Number of pending events on this iod */
  int events_pending;

  /* Pending events */
  gh_lnode_t *first_connect;
  gh_lnode_t *first_read;
  gh_lnode_t *first_write;
#if HAVE_PCAP
  gh_lnode_t *first_pcap_read;
#endif

  int readsd_count;
  int writesd_count;
#if HAVE_PCAP
  int readpcapsd_count;
#endif

  int watched_events;

  /* The struct npool used to create the iod (used for deletion) */
  struct npool *nsp;

  enum iod_state state;

  /* The host and port we are connected to using sd (saves a call to getpeername) */
  struct sockaddr_storage peer;
  /* The host and port to bind to with sd */
  struct sockaddr_storage local;

  /* The length of peer/local actually used (sizeof(sockaddr_in) or
   * sizeof(sockaddr_in6), SUN_LEN(sockaddr_un), or 0 if peer/local
   * has not been filled in */
  size_t locallen;
  size_t peerlen;

  /* -1 if none yet, otherwise IPPROTO_TCP, etc. */
  int lastproto;

  /* The struct npool keeps track of NIODs that have been allocated so that it
   * can destroy them if the msp is deleted.  This pointer makes it easy to
   * remove this struct niod from the allocated list when necessary */
  gh_lnode_t nodeq;

#define IOD_REGISTERED  0x01
#define IOD_PROCESSED   0x02    /* internally used by engine_kqueue.c */

#define IOD_PROPSET(iod, flag)  ((iod)->_flags |= (flag))
#define IOD_PROPCLR(iod, flag)  ((iod)->_flags &= ~(flag))
#define IOD_PROPGET(iod, flag)  (((iod)->_flags & (flag)) != 0)
  char _flags;

  /* Used for SSL Server Name Indication. */
  char *hostname;

#if HAVE_OPENSSL
  /* An SSL connection (or NULL if none) */
  SSL *ssl;
  /* SSL SESSION ID (or NULL if none) */
  SSL_SESSION *ssl_session;
#else
  /* Because there are many if (nsi->ssl) cases in the code */
  char *ssl;
#endif
  /* Every iod has an id which is always unique for the same nspool (unless you
   * create billions of them) */
  unsigned long id;

  /* No. of bytes read from the sd*/
  unsigned long read_count;
  /* No. of bytes written to the sd */
  unsigned long write_count;

  void *userdata;

  /* IP options to set on socket before connect() */
  void *ipopts;
  int ipoptslen;

  /* Pointer to mspcap struct (used only if pcap support is included) */
  void *pcap;

  struct proxy_chain_context *px_ctx;

};


/* nsock_event_t handles a single event.  Its ID is generally returned when the
 * event is created, and the event is included in callbacks */
struct nevent {
  /* Every event has an ID which is unique for a given nsock unless you blow
   * through more than 500,000,000 events */
  nsock_event_id id;

  enum nse_type type;
  enum nse_status status;

  /* For write events, this is the data to be written, for read events, this is
   * what we will read into */
  struct filespace iobuf;

  /* The timeout of the event -- absolute time
   * except that tv_sec == 0 means no timeout */
  struct timeval timeout;

  /* Info pertaining to READ requests */
  struct readinfo readinfo;
  /* Info pertaining to WRITE requests */
  struct writeinfo writeinfo;

#if HAVE_OPENSSL
  struct sslinfo sslinfo;
#endif

  /* If we return a status of NSE_STATUS_ERROR, this must be set */
  int errnum;

  /* The nsock I/O descriptor related to event (if applicable) */
  struct niod *iod;

  /* The handler to call when event is complete */
  nsock_ev_handler handler;

  /* slot in the expirable binheap */
  gh_hnode_t expire;

  /* For some reasons (see nsock_pcap.c) we register pcap events as both read
   * and pcap_read events when in PCAP_BSD_SELECT_HACK mode. We then need two
   * gh_lnode_t handles. To make code simpler, we _always_ use _nodeq_pcap for
   * pcap_read events and _nodeq_io for the other ones.
   * When not in PCAP_BSD_SELECT_HACK mode we define both handles as members
   * of an union to optimize memory footprint. */
  gh_lnode_t nodeq_io;
  gh_lnode_t nodeq_pcap;

  /* Optional (NULL if unset) pointer to pass to the handler */
  void *userdata;

  /* If this event is all filled out and ready for immediate delivery,
   * event_done is nonzero.  Used when event is finished at unexpected time and
   * we want to dispatch it later to avoid duplicating stat update code and all
   * that other crap */
  unsigned int event_done: 1;
  unsigned int eof: 1;

#if HAVE_IOCP
  struct extended_overlapped *eov;
#endif
};

struct io_operations {
  int(*iod_connect)(struct npool *nsp, int sockfd, const struct sockaddr *addr, socklen_t addrlen);

  int(*iod_read)(struct npool *nsp, int sockfd, void *buf, size_t len, int flags,
    struct sockaddr *src_addr, socklen_t *addrlen);

  int(*iod_write)(struct npool *nsp, int sockfd, const void *buf, size_t len, int flags,
    const struct sockaddr *dest_addr, socklen_t addrlen);
};

struct io_engine {
  /* Human readable identifier for this engine. */
  const char *name;

  /* Engine constructor */
  int (*init)(struct npool *nsp);

  /* Engine destructor */
  void (*destroy)(struct npool *nsp);

  /* Register a new IOD to the engine */
  int(*iod_register)(struct npool *nsp, struct niod *iod, struct nevent *nse, int ev);

  /* Remove a registered IOD */
  int(*iod_unregister)(struct npool *nsp, struct niod *iod);

  /* Modify events for a registered IOD.
   *  - ev_set represent the events to add
   *  - ev_clr represent the events to delete (if set) */
  int (*iod_modify)(struct npool *nsp, struct niod *iod, struct nevent *nse, int ev_set, int ev_clr);

  /* Main engine loop */
  int (*loop)(struct npool *nsp, int msec_timeout);

  /* I/O operations */
  struct io_operations *io_operations;
};

/* ----------- NSOCK I/O ENGINE CONVENIENCE WRAPPERS ------------ */
static inline int nsock_engine_init(struct npool *nsp) {
  return nsp->engine->init(nsp);
}

static inline void nsock_engine_destroy(struct npool *nsp) {
  nsp->engine->destroy(nsp);
  return;
}

static inline int nsock_engine_iod_register(struct npool *nsp, struct niod *iod, struct nevent *nse, int ev) {
  return nsp->engine->iod_register(nsp, iod, nse, ev);
}

static inline int nsock_engine_iod_unregister(struct npool *nsp, struct niod *iod) {
  return nsp->engine->iod_unregister(nsp, iod);
}

static inline int nsock_engine_iod_modify(struct npool *nsp, struct niod *iod, struct nevent *nse, int ev_set, int ev_clr) {
  return nsp->engine->iod_modify(nsp, iod, nse, ev_set, ev_clr);
}

static inline int nsock_engine_loop(struct npool *nsp, int msec_timeout) {
  return nsp->engine->loop(nsp, msec_timeout);
}

/* ------------------- PROTOTYPES ------------------- */

int event_timedout(struct nevent *nse);

/* Get a new nsock_event_id, given a type */
nsock_event_id get_new_event_id(struct npool *nsp, enum nse_type type);

/* Take an event ID and return the type (NSE_TYPE_CONNECT, etc */
enum nse_type get_event_id_type(nsock_event_id event_id);

/* Create a new event structure -- must be deleted later with event_delete,
 * unless it returns NULL (failure).  NULL can be passed in for the struct niod and
 * the userdata if not available. */
struct nevent *event_new(struct npool *nsp, enum nse_type type, struct niod *iod,
                           int timeout_msecs, nsock_ev_handler handler, void *userdata);

/* An internal function for cancelling an event when you already have a pointer
 * to the struct nevent (use nsock_event_cancel if you just have an ID).  The
 * event_list passed in should correspond to the type of the event.  For
 * example, with NSE_TYPE_READ, you would pass in &iod->read_events;.  elem
 * is the list element in event_list which holds the event.  Pass a nonzero for
 * notify if you want the program owning the event to be notified that it has
 * been cancelled */
int nevent_delete(struct npool *nsp, struct nevent *nse, gh_list_t *event_list, gh_lnode_t *elem, int notify);

/* Adjust various statistics, dispatches the event handler (if notify is
 * nonzero) and then deletes the event.  This function does NOT delete the event
 * from any lists it might be on (eg nsp->read_list etc.) nse->event_done
 * MUST be true when you call this */
void event_dispatch_and_delete(struct npool *nsp, struct nevent *nse, int notify);

/* Free an struct nevent which was allocated with event_new, including all internal
 * resources.  Note -- we assume that nse->iod->events_pending (if it exists)
 * has ALREADY been decremented (done during event_dispatch_and_delete) -- so
 * remember to do this if you call event_delete() directly */
void event_delete(struct npool *nsp, struct nevent *nse);

/* Add an event to the appropriate nsp event list, handles housekeeping such as
 * adjusting the descriptor select/poll lists, registering the timeout value,
 * etc. */
void nsock_pool_add_event(struct npool *nsp, struct nevent *nse);

void nsock_connect_internal(struct npool *ms, struct nevent *nse, int type, int proto, struct sockaddr_storage *ss, size_t sslen, unsigned int port);

/* Comments on using the following handle_*_result functions are available in nsock_core.c */

/* handle_connect_results assumes that select or poll have already shown the
 * descriptor to be active */
void handle_connect_result(struct npool *ms, struct nevent *nse, enum nse_status status);

void handle_read_result(struct npool *ms, struct nevent *nse, enum nse_status status);

void handle_write_result(struct npool *ms, struct nevent *nse, enum nse_status status);

void handle_timer_result(struct npool *ms, struct nevent *nse, enum nse_status status);

#if HAVE_PCAP
void handle_pcap_read_result(struct npool *ms, struct nevent *nse, enum nse_status status);
#endif

/* An event has been completed and the handler is about to be called.  This
 * function writes out tracing data about the event if necessary */
void nsock_trace_handler_callback(struct npool *ms, struct nevent *nse);

#if HAVE_OPENSSL
/* Sets the ssl session of an nsock_iod, increments usage count.  The session
 * should not have been set yet (as no freeing is done) */
void nsi_set_ssl_session(struct niod *iod, SSL_SESSION *sessid);
#endif

static inline struct nevent *next_expirable_event(struct npool *nsp) {
  gh_hnode_t *hnode;

  hnode = gh_heap_min(&nsp->expirables);
  if (!hnode)
    return NULL;

  return container_of(hnode, struct nevent, expire);
}

static inline struct nevent *lnode_nevent(gh_lnode_t *lnode) {
  return container_of(lnode, struct nevent, nodeq_io);
}

static inline struct nevent *lnode_nevent2(gh_lnode_t *lnode) {
  return container_of(lnode, struct nevent, nodeq_pcap);
}

#endif /* NSOCK_INTERNAL_H */

