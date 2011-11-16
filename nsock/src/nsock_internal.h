
/***************************************************************************
 * nsock_internal.h -- PRIVATE interface definitions for the guts of the   *
 * nsock paralle socket event library.  Applications calling this library  *
 * should NOT include this. even LOOK at these :).                         *
 *                                                                         *
 ***********************IMPORTANT NSOCK LICENSE TERMS***********************
 *                                                                         *
 * The nsock parallel socket event library is (C) 1999-2011 Insecure.Com   *
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

/*********      STRUCTURES   **************/

/* This is geared to handling state for select calls, perhaps at 
   some point I'll add a USE_POLL_NOT_SELECT define which causes it to
   do poll()s instead. */
struct nsock_io_info {
  fd_set fds_master_r; /* Descriptors from which have pending READ events */
  fd_set fds_master_w; /* Descriptors which we are tryint to WRITE to */
  fd_set fds_master_x; /* looking for exceptional events -- used with connect */

  /* For keeping track of the select results */
  fd_set fds_results_r, fds_results_w, fds_results_x;

/* The highest sd we have set in any of our fd_set's (max_sd + 1 is
   used in select() calls).  Note that it can be -1, when there are no
   valid sockets */
  int max_sd; 
  int results_left; /* The number of descriptors contained in the sets that
		       we have not yet dealt with. */
};

struct event_lists {
  /* We keep the events seperate because we want to handle them in the 
     order: connect => read => write => timer for several reasons:
     1) Makes sure we have gone through all the net i/o events before 
        a timer expires (would be a shame to timeout after the data was 
        available but before we delivered the events
     2) The connect() results often lead to a read or write that can be 
        processed in the same cycle.  In the same way, read() often 
	leads to write().
  */
  gh_list connect_events;
  gh_list read_events;
  gh_list write_events;
  gh_list timer_events;
  #if HAVE_PCAP
  gh_list pcap_read_events;
  #endif 
  gh_list free_events; /* When an event is deleted, we stick it here for
			  later reuse */
  struct timeval next_ev; /* The soonest time that either a timer event goes
			     off or a read/write/connect expires.  It is 
			     updated each main loop round as we go through 
			     the events.  It is an absolute time.  If there
  			     are no events, tv_sec is 0 */
  int events_pending; /* Number of events pending (total) on all lists */

};

enum nsock_read_types { NSOCK_READLINES, NSOCK_READBYTES, NSOCK_READ };

struct readinfo {
  enum nsock_read_types read_type;
  int num; /* num lines; num bytes; whatever (depends on read_type) */
};

struct writeinfo {
  struct sockaddr_storage dest;
  size_t destlen;
  int written_so_far; /* Number of bytes successfully written */
};

/* remember that callers of this library should NOT be accessing these 
   fields directly */
typedef struct  {
  unsigned long id; /* Every mst has a unique (accross the 
		       program execution) id */

  struct nsock_io_info mioi;  /* info for keeping track of select() I/O */
  struct event_lists evl; /* Lists of pending events we are waiting on */
  
  void *userdata; /* User Data, if it has been set.  Otherwise NULL */
  gh_list free_iods; /* msiod structures that have been freed for reuse */
  gh_list active_iods; /* msiod structures that have been allocated */
  unsigned long next_event_serial; /* serial # of next event (used to create
				      next nsock_event_id */
  unsigned long next_iod_serial; /* Serial # of next iod to be created */
  int errnum; /* If nsock_loop() returns NSOCK_LOOP_ERROR, this is where we
		describe the error (errnum fashion) */
  int tracelevel; /* Trace/debug level - set by nsp_settrace. If positive,
                     trace logs are printted to tracefile. */
  FILE *tracefile;
  int broadcast; /* If true, new sockets will have SO_BROADCAST set */
  /* This time is subtracted from the current time for trace reports */
  struct timeval tracebasetime; 

  /* If true, exit the next iteration of nsock_loop with a status of
     NSOCK_LOOP_QUIT. */
  int quit;

#if HAVE_OPENSSL
  SSL_CTX *sslctx; /* The SSL Context (options and such) */
#endif
} mspool;


typedef struct msevent msevent;

typedef struct msiod msiod;

enum msiod_state { NSIOD_STATE_DELETED, NSIOD_STATE_INITIAL, 
		   NSIOD_STATE_UNKNOWN /* sd was provided to us in nsi_new2 */,
		   NSIOD_STATE_CONNECTED_TCP, NSIOD_STATE_CONNECTED_UDP };

/* struct sslinfo defined in nsock_ssl.h */

/* typedef struct msiod msiod; */

/* nsock_iod is like a "file descriptor" for the nsock library.  You
   use it to request events. */
struct msiod {
  int sd; /* The socket descriptor related to the event */
  int events_pending; /* Number of pending events on this iod */
  /* These are counts of how many events are waiting to read from or write to
     the socket. When they are 0 we stop watching the socket for readability or
     writability. */
  int readsd_count;
  int writesd_count;
  int readpcapsd_count;
  mspool *nsp; /* The mspool used to create the iod (used for deletion) */
  enum msiod_state state;
  struct sockaddr_storage peer; /* The host and port we are connected to
				   using sd (saves a call to getpeername) */
  struct sockaddr_storage local; /* The host and port to bind to with sd */

/* The length of peer/local actually used (sizeof(sockaddr_in) or
   sizeof(sockaddr_in6), or 0 if peer/local has not been filled in */
  size_t locallen, peerlen; 
  int lastproto; /* -1 if none yet, otherwise IPPROTO_TCP, etc. */
  gh_list_elem *entry_in_nsp_active_iods; /* The mspool keeps track of
					     msiods that have been
					     allocated so that it can
					     destroy them if the msp
					     is deleted.  This pointer
					     makes it easy to remove
					     this msiod from the
					     allocated list when
					     neccessary */

  /* Used for SSL Server Name Indication. */
  char *hostname;

#if HAVE_OPENSSL
  SSL *ssl; /* An SSL connection (or NULL if none) */
  SSL_SESSION *ssl_session; /* SSL SESSION ID (or NULL if none) */
#else
  char *ssl; /* Because there are many if (nsi->ssl) cases in the code */
#endif
  unsigned long id; /* Every iod has an id which is always unique for the
		       same nspool (unless you create billions of them) */

  unsigned long read_count;  /* No. of bytes read  from the sd*/ 
  unsigned long write_count; /* No. of bytes written to the sd */
  void *userdata;

  /* IP options to set on socket before connect() */
  void *ipopts;
  int ipoptslen;
  
  void *pcap;	   /* Pointer to mspcap struct (used only if pcap support is included) */
};



/* nsock_event_t handles a single event.  Its ID is generally returned when
   the event is created, and the event is included in callbacks */
struct msevent {
  nsock_event_id id; /* Every event has an ID which is unique for a given nsock
		  unless you blow through more than 500,000,000 events */
  enum nse_type type;
  enum nse_status status;

  struct filespace iobuf; /* for write events, this is the data to be written,
			     for read events, this is what we will read into */

  struct timeval timeout; /* The timeout of the event -- absolute time
			     except that tv_sec == 0 means no timeout */
  struct readinfo readinfo; /* Info pertaining to READ requests */
  struct writeinfo writeinfo; /* Info pertaining to WRITE requests */
#if HAVE_OPENSSL
  struct sslinfo sslinfo;
#endif
  int errnum; /* If we return a status of NSE_STATUS_ERROR, this must be set */
  int eof;
  msiod *iod; /* The nsock I/O descriptor related to event (if applicable) */
  nsock_ev_handler handler; /* The handler to call when event is complete */
  void *userdata;
  int event_done; /* If this event is all filled out and ready for
		     immediate delivery, event_done is nonzero.  Used
		     when event is finished at unexpected time and we
		     want to dispatch it later to avoid duplicating
		     stat update code and all that other crap */
  struct timeval time_created;
};



/*********  PROTOTYPES   **************/

/* Get a new nsock_event_id, given a type */
nsock_event_id get_new_event_id(mspool *nsp, enum nse_type type);
/* Take an event ID and return the type (NSE_TYPE_CONNECT, etc */
enum nse_type get_event_id_type(nsock_event_id event_id);

/* Create a new event structure -- must be deleted later with msevent_delete,
 unless it returns NULL (failure).  NULL can be passed in for the
 msiod and the userdata if not available. */
msevent *msevent_new(mspool *nsp, enum nse_type type, msiod *msiod, 
		     int timeout_msecs, nsock_ev_handler handler,
		     void *userdata);

/* An inernal function for cancelling an event when you already have a
   pointer to the msevent (use nsock_event_cancel if you just have an
   ID).  The event_list passed in should correspond to the type of the
   event.  For example, with NSE_TYPE_READ, you would pass in
   &nsp->evl.read_events;.  elem is the list element in event_list
   which holds the event.  Pass a nonzero for notify if you want the
   program owning the event to be notified that it has been cancelled */
int msevent_cancel(mspool *nsp, msevent *nse, gh_list *event_list, 
		   gh_list_elem *elem, int notify);

/* Adjust various statistics, dispatches the event handler (if notify is
   nonzero) and then deletes the event.  This function does NOT delete
   the event from any lists it might be on (eg nsp->evl.read_list etc.) 
   nse->event_done MUST be true when you call this */
void msevent_dispatch_and_delete(mspool *nsp, msevent *nse, int notify);

/* Free an msevent which was allocated with msevent_new, including all
   internal resources.  Note -- we assume that
   nse->iod->events_pending (if it exists) has ALREADY been
   decremented (done during msevent_dispatch_and_delete) -- so
   remember to do this if you call msevent_delete() directly */
void msevent_delete(mspool *nsp, msevent *nse);

/* Adds an event to the appropriate nsp event list, handles housekeeping
   such as adjusting the descriptor select/poll lists, registering the
   timeout value, etc. */
void nsp_add_event(mspool *nsp, msevent *nse);

void nsock_connect_internal(mspool *ms, msevent *nse, int proto,
			    struct sockaddr_storage *ss, size_t sslen,
			    unsigned short port);

/* Comments on using the following handle_*_result functions are available
   in nsock_core.c */
/* handle_connect_results assumes that select or poll have already
   shown the descriptor to be active */
void handle_connect_result(mspool *ms, msevent *nse, 
			   enum nse_status status);

void handle_read_result(mspool *ms, msevent *nse, 
			enum nse_status status);

void handle_write_result(mspool *ms, msevent *nse, 
			  enum nse_status status);

void handle_timer_result(mspool *ms, msevent *nse, 
			 enum nse_status status);

#if HAVE_PCAP
void handle_pcap_read_result(mspool *ms, msevent *nse, 
			       enum nse_status status);
#endif

void nsock_trace(mspool *ms, char *fmt, ...)
     __attribute__ ((format (printf, 2, 3)));

/* An event has been completed and the handler is about to be called.  This function
   writes out tracing data about the event if neccessary */
void nsock_trace_handler_callback(mspool *ms, msevent *nse);

#if HAVE_OPENSSL
/* sets the ssl session of an nsock_iod, increments usage count.  The
 session should not have been set yet (as no freeing is done) */
void nsi_set_ssl_session(msiod *iod, SSL_SESSION *sessid);
#endif

#endif /* NSOCK_INTERNAL_H */









