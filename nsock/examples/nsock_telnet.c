/***************************************************************************
 * nsock_telnet.c -- A simple "telnet" client -- a trivial example of      *
 * using the nsock parallel socket event library                           *
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


#include "nsock.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <sys/time.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
/* #include <nbase.h> */

/* from nbase.h */
int socket_errno();


extern char *optarg;

extern int optind;

struct telnet_state {
  nsock_iod tcp_nsi;
  nsock_iod stdin_nsi;
  nsock_event_id latest_readtcpev;
  nsock_event_id latest_readstdinev;
  void *ssl_session;
};

/* Tries to resolve given hostname and stores
   result in ip .  returns 0 if hostname cannot
   be resolved */
int resolve(char *hostname, struct in_addr *ip) {
  struct hostent *h;

  if (!hostname || !*hostname) {
    fprintf(stderr, "NULL or zero-length hostname passed to resolve().  Quitting.\n");
    exit(1);
  }

  if (inet_aton(hostname, ip))
    return 1;                   /* damn, that was easy ;) */
  if ((h = gethostbyname(hostname))) {
    memcpy(ip, h->h_addr_list[0], sizeof(struct in_addr));
    return 1;
  }
  return 0;
}

void telnet_event_handler(nsock_pool nsp, nsock_event nse, void *mydata) {
  nsock_iod nsi = nse_iod(nse);
  enum nse_status status = nse_status(nse);
  enum nse_type type = nse_type(nse);
  struct sockaddr_in peer;
  struct telnet_state *ts;
  int nbytes;
  char *str;
  int read_timeout = -1;
  int write_timeout = 2000;
  ts = (struct telnet_state *)mydata;

  printf("telnet_event_handler: Received callback of type %s with status %s\n", nse_type2str(type), nse_status2str(status));

  if (status == NSE_STATUS_SUCCESS) {
    switch (type) {
    case NSE_TYPE_CONNECT:
    case NSE_TYPE_CONNECT_SSL:
      nsock_iod_get_communication_info(nsi, NULL, NULL, NULL, (struct sockaddr *)&peer, sizeof peer);
      printf("Successfully connected %sto %s:%hu -- start typing lines\n", (type == NSE_TYPE_CONNECT_SSL) ? "(SSL!) " : "", inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));
      /* First of all, lets add STDIN to our list of watched filehandles */
      if ((ts->stdin_nsi = nsock_iod_new2(nsp, STDIN_FILENO, NULL)) == NULL) {
        fprintf(stderr, "Failed to create stdin msi\n");
        exit(1);
      }

      /* Now lets read from stdin and the network, line buffered (by nsock) */
      ts->latest_readtcpev = nsock_readlines(nsp, ts->tcp_nsi, telnet_event_handler, read_timeout, ts, 1);
      ts->latest_readstdinev = nsock_readlines(nsp, ts->stdin_nsi, telnet_event_handler, read_timeout, ts, 1);
      break;
    case NSE_TYPE_READ:
      str = nse_readbuf(nse, &nbytes);
      if (nsi == ts->tcp_nsi) {
        printf("%s", str);
        /*       printf("Read from tcp socket (%d bytes):\n%s", nbytes, str); */
        ts->latest_readtcpev = nsock_readlines(nsp, ts->tcp_nsi, telnet_event_handler, read_timeout, ts, 1);
      } else {
        /*       printf("Read from  stdin (%d bytes):\n%s", nbytes, str); */
        nsock_write(nsp, ts->tcp_nsi, telnet_event_handler, write_timeout, ts, str, nbytes);
        ts->latest_readstdinev = nsock_readlines(nsp, ts->stdin_nsi, telnet_event_handler, read_timeout, ts, 1);
      }
      break;
    case NSE_TYPE_WRITE:
      /* Nothing to do, really */
      break;
    case NSE_TYPE_TIMER:
      break;
    default:
      fprintf(stderr, "telnet_event_handler: Got bogus type -- quitting\n");
      exit(1);
      break;
    }
  } else if (status == NSE_STATUS_EOF) {
    printf("Got EOF from %s\nCancelling outstanding readevents.\n", (nsi == ts->tcp_nsi) ? "tcp socket" : "stdin");
    /* One of these is the event I am currently handling!  But I wanted to
       be evil when testing this out... */
    if (nsock_event_cancel(nsp, ts->latest_readtcpev, 1) != 0) {
      printf("Cancelled tcp event: %li\n", ts->latest_readtcpev);
    }
    if (nsock_event_cancel(nsp, ts->latest_readstdinev, 1) != 0) {
      printf("Cancelled stdin event: %li\n", ts->latest_readstdinev);
    }
  } else if (status == NSE_STATUS_ERROR) {
    if (nsock_iod_check_ssl(nsi)) {
      printf("SSL %s failed: %s\n", nse_type2str(type), ERR_error_string(ERR_get_error(), NULL));
    } else {
      int err;

      err = nse_errorcode(nse);
      printf("%s failed: (%d) %s\n", nse_type2str(type), err, strerror(err));
    }
  }
  return;
}

void usage() {
  fprintf(stderr, "\nUsage: nsock_telnet [-s] <hostnameorip> [portnum]\n" "       Where -s enables SSL for the connection\n\n");
  exit(1);
}

int main(int argc, char *argv[]) {
  struct in_addr target;
  nsock_pool nsp;
  nsock_event_id ev;
  unsigned short portno;
  enum nsock_loopstatus loopret;
  struct telnet_state ts;
  int c;
  int usessl = 0;
  struct timeval now;
  struct sockaddr_in taddr;

  ts.stdin_nsi = NULL;

  while ((c = getopt(argc, argv, "s")) != -1) {
    switch (c) {
    case 's':
      usessl = 1;
      break;
    default:
      usage();
      break;
    }
  }

  if (argc - optind <= 0 || argc - optind > 2)
    usage();


  if (!resolve(argv[optind], &target)) {
    fprintf(stderr, "Failed to resolve target host: %s\nQUITTING.\n", argv[optind]);
    exit(1);
  }
  optind++;

  if (optind < argc)
    portno = atoi(argv[optind]);
  else
    portno = 23;

  /* OK, we start with creating a p00l */
  if ((nsp = nsock_pool_new(NULL)) == NULL) {
    fprintf(stderr, "Failed to create new pool.  QUITTING.\n");
    exit(1);
  }

  gettimeofday(&now, NULL);

  if ((ts.tcp_nsi = nsock_iod_new(nsp, NULL)) == NULL) {
    fprintf(stderr, "Failed to create new nsock_iod.  QUITTING.\n");
    exit(1);
  }

  taddr.sin_family = AF_INET;
  taddr.sin_addr = target;
  taddr.sin_port = portno;

  if (usessl) {
    ts.ssl_session = NULL;
    ev = nsock_connect_ssl(nsp, ts.tcp_nsi, telnet_event_handler, 10000, &ts, (struct sockaddr *)&taddr, sizeof taddr, IPPROTO_TCP, portno, ts.ssl_session);
  } else
    ev = nsock_connect_tcp(nsp, ts.tcp_nsi, telnet_event_handler, 10000, &ts, (struct sockaddr *)&taddr, sizeof taddr, portno);

  printf("The event id is %lu -- initiating l00p\n", ev);

  /* Now lets get this party started right! */
  loopret = nsock_loop(nsp, -1);

  printf("nsock_loop returned %d\n", (int)loopret);

  return 0;
}
