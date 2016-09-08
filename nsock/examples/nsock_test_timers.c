/***************************************************************************
 * nsock_test_timers.c -- A test program to exercise the nsock timer       *
 * routines.                                                               *
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
#include <time.h>
#include <assert.h>

nsock_event_id ev_ids[2048];

int num_ids = 0;

nsock_event_id request_timer(nsock_pool nsp, nsock_ev_handler handler, int timeout_msecs, void *userdata) {
  nsock_event_id id;

  id = nsock_timer_create(nsp, handler, timeout_msecs, userdata);
  printf("%ld: Created timer ID %li for %d ms from now\n", time(NULL), id, timeout_msecs);

  return id;

}

int try_cancel_timer(nsock_pool nsp, int idx, int notify) {
  int res;

  printf("%ld:Attempting to cancel id %li (idx %d) %s notify.\n", time(NULL), ev_ids[idx], idx, ((notify) ? "WITH" : "WITHOUT"));
  res = nsock_event_cancel(nsp, ev_ids[idx], notify);
  printf("Kill of %li %s\n", ev_ids[idx], (res == 0) ? "FAILED" : "SUCCEEDED");
  return res;
}

void timer_handler(nsock_pool nsp, nsock_event nse, void *mydata) {
  enum nse_status status = nse_status(nse);
  enum nse_type type = nse_type(nse);
  int rnd, rnd2;

  printf("%ld:timer_handler: Received callback of type %s; status %s; id %li\n", time(NULL), nse_type2str(type), nse_status2str(status), nse_id(nse));

  rnd = rand() % num_ids;
  rnd2 = rand() % 3;

  if (num_ids > (sizeof(ev_ids) / sizeof(nsock_event_id)) - 3) {
    printf("\n\nSUCCEEDED DUE TO CREATING ENOUGH EVENTS THAT IT WAS GOING TO OVERFLOW MY BUFFER :)\n\n");
    exit(0);
  }

  if (status == NSE_STATUS_SUCCESS) {
    switch (rnd2) {
    case 0:
      /* do nothing */
      /* Actually I think I'll create two timers :) */
      ev_ids[num_ids++] = request_timer(nsp, timer_handler, rand() % 3000, NULL);
      ev_ids[num_ids++] = request_timer(nsp, timer_handler, rand() % 3000, NULL);
      break;
    case 1:
      /* Kill another id (which may or may not be active */
      try_cancel_timer(nsp, rnd, rand() % 2);
      break;
    case 2:
      /* Create a new timer */
      ev_ids[num_ids++] = request_timer(nsp, timer_handler, rand() % 3000, NULL);
      break;
    default:
      assert(0);
    }
  }
}

int main(int argc, char *argv[]) {
  nsock_pool nsp;
  enum nsock_loopstatus loopret;
  int num_loops = 0;

  srand(time(NULL));
  /* OK, we start with creating a p00l */
  if ((nsp = nsock_pool_new(NULL)) == NULL) {
    fprintf(stderr, "Failed to create new pool.  QUITTING.\n");
    exit(1);
  }

  ev_ids[num_ids++] = request_timer(nsp, timer_handler, 1800, NULL);
  ev_ids[num_ids++] = request_timer(nsp, timer_handler, 800, NULL);
  ev_ids[num_ids++] = request_timer(nsp, timer_handler, 1300, NULL);
  ev_ids[num_ids++] = request_timer(nsp, timer_handler, 0, NULL);
  ev_ids[num_ids++] = request_timer(nsp, timer_handler, 100, NULL);

  /* Now lets get this party started right! */
  while (num_loops++ < 5) {
    loopret = nsock_loop(nsp, 1500);
    if (loopret == NSOCK_LOOP_TIMEOUT)
      printf("Finished l00p #%d due to l00p timeout :)  I may do another\n", num_loops);
    else if (loopret == NSOCK_LOOP_NOEVENTS) {
      printf("SUCCESS -- NO EVENTS LEFT\n");
      exit(0);
    } else {
      printf("nsock_loop FAILED!\n");
      exit(1);
    }
  }
  printf("Trying to kill my msp!\n");
  nsock_pool_delete(nsp);
  printf("SUCCESS -- completed %d l00ps.\n", num_loops);

  return 0;
}
