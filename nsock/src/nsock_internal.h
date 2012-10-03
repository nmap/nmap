/***************************************************************************
 * nsock_internal.h -- PRIVATE interface definitions for the guts of the   *
 * nsock paralle socket event library.  Applications calling this library  *
 * should NOT include this. even LOOK at these :).                         *
 *                                                                         *
 ***********************IMPORTANT NSOCK LICENSE TERMS***********************
 *                                                                         *
 * The nsock parallel socket event library is (C) 1999-2012 Insecure.Com   *
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
 * This also allows you to audit the software for security holes (none     *
 * have been found so far).                                                *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to nmap-dev@insecure.org for possible incorporation into the main       *
 * distribution.  By sending these changes to Fyodor or one of the         *
 * Insecure.Org development mailing lists, it is assumed that you are      *
 * offering the Nmap Project (Insecure.Com LLC) the unlimited,             *
 * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
 * will always be available Open Source, but this is important because the *
 * inability to relicense code has caused devastating problems for other   *
 * Free Software projects (such as KDE and NASM).  We also occasionally    *
 * relicense the code to third parties as discussed above.  If you wish to *
 * specify special license conditions of your contributions, just say so   *
 * when you send them.                                                     *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License v2.0 for more details                            *
 * (http://www.gnu.org/licenses/gpl-2.0.html).                             *
 *                                                                         *
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
#include "filespace.h"
#include "nsock.h" /* The public interface -- I need it for some enum defs */
#include "nsock_ssl.h"

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

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif


/* ------------------- CONSTANTS ------------------- */

enum nsock_read_types {
  NSOCK_READLINES,
  NSOCK_READBYTES,
  NSOCK_READ
};

enum msiod_state {
  NSIOD_STATE_DELETED,
  NSIOD_STATE_INITIAL,

  /* sd was provided to us in nsi_new2 (see nsock_pool.c) */
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
typedef struct {

  /* Every msp has a unique (across the program execution) id */
  unsigned long id;

  /* User data, NULL if unset */
  void *userdata;

  /* IO Engine vtable */
  struct io_engine *engine;
  /* IO Engine internal data */
  void *engine_data;

  /* Active network events */
  gh_list connect_events;
  gh_list read_events;
  gh_list write_events;
  gh_list timer_events;
#if HAVE_PCAP
  gh_list pcap_read_events;
#endif

  /* Active iods and related lists of events */
  gh_list active_iods;

  /* msiod structures that have been freed for reuse */
  gh_list free_iods;
  /* When an event is deleted, we stick it here for later reuse */
  gh_list free_events;

  /* The soonest time that either a timer event goes
   * off or a read/write/connect expires.  It is
   * updated each main loop round as we go through
   * the events.  It is an absolute time.  If there
   * are no events, tv_sec is 0 */
  struct timeval next_ev;

  /* Number of events pending (total) on all lists */
  int events_pending;

  /* Serial # of next event (used to create next nsock_event_id */
  unsigned long next_event_serial;
  /* Serial # of next iod to be created */
  unsigned long next_iod_serial;

  /* If nsock_loop() returns NSOCK_LOOP_ERROR, this is where we describe the
   * error (errnum fashion) */
  int errnum;

  /* Trace/debug level - set by nsp_settrace. If positive, trace logs are
   * printted to tracefile. */
  int tracelevel;
  FILE *tracefile;
  /* This time is subtracted from the current time for trace reports */
  struct timeval tracebasetime;

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
#endif
} mspool;


/* nsock_iod is like a "file descriptor" for the nsock library.  You use it to
 * request events. */
typedef struct {
  /* The socket descriptor related to the event */
  int sd;

  /* Number of pending events on this iod */
  int events_pending;

  /* Pending events */
  gh_list_elem *first_connect;
  gh_list_elem *first_read;
  gh_list_elem *first_write;
#if HAVE_PCAP
  gh_list_elem *first_pcap_read;
#endif

  int readsd_count;
  int writesd_count;
#if HAVE_PCAP
  int readpcapsd_count;
#endif

  int watched_events;

  /* The mspool used to create the iod (used for deletion) */
  mspool *nsp;

  enum msiod_state state;

  /* The host and port we are connected to using sd (saves a call to getpeername) */
  struct sockaddr_storage peer;
  /* The host and port to bind to with sd */
  struct sockaddr_storage local;

  /* The length of peer/local actually used (sizeof(sockaddr_in) or
   * sizeof(sockaddr_in6), or 0 if peer/local has not been filled in */
  size_t locallen;
  size_t peerlen;

  /* -1 if none yet, otherwise IPPROTO_TCP, etc. */
  int lastproto;

  /* The mspool keeps track of msiods that have been allocated so that it can
   * destroy them if the msp is deleted.  This pointer makes it easy to remove
   * this msiod from the allocated list when necessary */
  gh_list_elem *entry_in_nsp_active_iods;

#define IOD_REGISTERED  0x01

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
} msiod;


/* nsock_event_t handles a single event.  Its ID is generally returned when the
 * event is created, and the event is included in callbacks */
typedef struct {

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

  int eof;

  /* The nsock I/O descriptor related to event (if applicable) */
  msiod *iod;

  /* The handler to call when event is complete */
  nsock_ev_handler handler;

  /* Optional (NULL if unset) pointer to pass to the handler */
  void *userdata;

  /* If this event is all filled out and ready for immediate delivery,
   * event_done is nonzero.  Used when event is finished at unexpected time and
   * we want to dispatch it later to avoid duplicating stat update code and all
   * that other crap */
  int event_done;

  struct timeval time_created;
} msevent;


struct io_engine {
  /* Human readable identifier for this engine. */
  const char *name;

  /* Engine constructor */
  int (*init)(mspool *nsp);

  /* Engine destructor */
  void (*destroy)(mspool *nsp);

  /* Register a new IOD to the engine */
  int (*iod_register)(mspool *nsp, msiod *iod, int ev);

  /* Remove a registered IOD */
  int (*iod_unregister)(mspool *nsp, msiod *iod);

  /* Modify events for a registered IOD.
   *  - ev_set represent the events to add
   *  - ev_clr represent the events to delete (if set) */
  int (*iod_modify)(mspool *nsp, msiod *iod, int ev_set, int ev_clr);

  /* Main engine loop */
  int (*loop)(mspool *nsp, int msec_timeout);
};


/* ------------------- PROTOTYPES ------------------- */

/* Get a new nsock_event_id, given a type */
nsock_event_id get_new_event_id(mspool *nsp, enum nse_type type);

/* Take an event ID and return the type (NSE_TYPE_CONNECT, etc */
enum nse_type get_event_id_type(nsock_event_id event_id);

/* Create a new event structure -- must be deleted later with msevent_delete,
 * unless it returns NULL (failure).  NULL can be passed in for the msiod and
 * the userdata if not available. */
msevent *msevent_new(mspool *nsp, enum nse_type type, msiod *msiod, int timeout_msecs, nsock_ev_handler handler, void *userdata);

/* An internal function for cancelling an event when you already have a pointer
 * to the msevent (use nsock_event_cancel if you just have an ID).  The
 * event_list passed in should correspond to the type of the event.  For
 * example, with NSE_TYPE_READ, you would pass in &iod->read_events;.  elem
 * is the list element in event_list which holds the event.  Pass a nonzero for
 * notify if you want the program owning the event to be notified that it has
 * been cancelled */
int msevent_cancel(mspool *nsp, msevent *nse, gh_list *event_list, gh_list_elem *elem, int notify);

/* Adjust various statistics, dispatches the event handler (if notify is
 * nonzero) and then deletes the event.  This function does NOT delete the event
 * from any lists it might be on (eg nsp->read_list etc.) nse->event_done
 * MUST be true when you call this */
void msevent_dispatch_and_delete(mspool *nsp, msevent *nse, int notify);

/* Free an msevent which was allocated with msevent_new, including all internal
 * resources.  Note -- we assume that nse->iod->events_pending (if it exists)
 * has ALREADY been decremented (done during msevent_dispatch_and_delete) -- so
 * remember to do this if you call msevent_delete() directly */
void msevent_delete(mspool *nsp, msevent *nse);

/* Add an event to the appropriate nsp event list, handles housekeeping such as
 * adjusting the descriptor select/poll lists, registering the timeout value,
 * etc. */
void nsp_add_event(mspool *nsp, msevent *nse);

void nsock_connect_internal(mspool *ms, msevent *nse, int proto, struct sockaddr_storage *ss, size_t sslen, unsigned short port);

/* Comments on using the following handle_*_result functions are available in nsock_core.c */

/* handle_connect_results assumes that select or poll have already shown the
 * descriptor to be active */
void handle_connect_result(mspool *ms, msevent *nse, enum nse_status status);

void handle_read_result(mspool *ms, msevent *nse, enum nse_status status);

void handle_write_result(mspool *ms, msevent *nse, enum nse_status status);

void handle_timer_result(mspool *ms, msevent *nse, enum nse_status status);

#if HAVE_PCAP
void handle_pcap_read_result(mspool *ms, msevent *nse, enum nse_status status);
#endif

void nsock_trace(mspool *ms, char *fmt, ...) __attribute__ ((format (printf, 2, 3)));

/* An event has been completed and the handler is about to be called.  This
 * function writes out tracing data about the event if necessary */
void nsock_trace_handler_callback(mspool *ms, msevent *nse);

#if HAVE_OPENSSL
/* Sets the ssl session of an nsock_iod, increments usage count.  The session
 * should not have been set yet (as no freeing is done) */
void nsi_set_ssl_session(msiod *iod, SSL_SESSION *sessid);
#endif

#endif /* NSOCK_INTERNAL_H */

