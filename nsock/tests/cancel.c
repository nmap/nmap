/*
 * Nsock regression test suite
 * Same license as nmap -- see https://nmap.org/book/man-legal.html
 */

#include "test-common.h"


struct basic_test_data {
  nsock_pool nsp;
};


static void cancel_handler(nsock_pool nsp, nsock_event nse, void *udata) {
  int *ev_done = (int *)udata;

  if (nse_status(nse) == NSE_STATUS_CANCELLED)
    *ev_done = 1;
}

static int cancel_setup(void **tdata) {
  struct basic_test_data *btd;

  btd = calloc(1, sizeof(struct basic_test_data));
  if (btd == NULL)
    return -ENOMEM;

  btd->nsp = nsock_pool_new(NULL);

  *tdata = btd;
  return 0;
}

static int cancel_teardown(void *tdata) {
  struct basic_test_data *btd = (struct basic_test_data *)tdata;

  if (tdata) {
    nsock_pool_delete(btd->nsp);
    free(tdata);
  }
  return 0;
}

static int cancel_tcp_run(void *tdata) {
  struct basic_test_data *btd = (struct basic_test_data *)tdata;
  struct sockaddr_in peer;
  nsock_iod iod;
  nsock_event_id id;
  int done = 0;

  iod = nsock_iod_new(btd->nsp, NULL);
  AssertNonNull(iod);

  memset(&peer, 0, sizeof(peer));
  peer.sin_family = AF_INET;
  inet_aton("127.0.0.1", &peer.sin_addr);

  id = nsock_connect_tcp(btd->nsp, iod, cancel_handler, 4000, (void *)&done,
                         (struct sockaddr *)&peer, sizeof(peer), PORT_TCP);
  nsock_event_cancel(btd->nsp, id, 1);

  nsock_iod_delete(iod, NSOCK_PENDING_SILENT);

  return (done == 1) ? 0 : -ENOEXEC;
}

static int cancel_udp_run(void *tdata) {
  struct basic_test_data *btd = (struct basic_test_data *)tdata;
  struct sockaddr_in peer;
  nsock_iod iod;
  nsock_event_id id;
  int done = 0;

  iod = nsock_iod_new(btd->nsp, NULL);
  AssertNonNull(iod);

  memset(&peer, 0, sizeof(peer));
  peer.sin_family = AF_INET;
  inet_aton("127.0.0.1", &peer.sin_addr);

  id = nsock_connect_udp(btd->nsp, iod, cancel_handler, (void *)&done,
                         (struct sockaddr *)&peer, sizeof(peer), PORT_UDP);
  nsock_event_cancel(btd->nsp, id, 1);

  nsock_iod_delete(iod, NSOCK_PENDING_SILENT);

  return (done == 1) ? 0 : -ENOEXEC;
}

static int cancel_ssl_run(void *tdata) {
  struct basic_test_data *btd = (struct basic_test_data *)tdata;
  struct sockaddr_in peer;
  nsock_iod iod;
  nsock_event_id id;
  int done = 0;

  iod = nsock_iod_new(btd->nsp, NULL);
  AssertNonNull(iod);

  memset(&peer, 0, sizeof(peer));
  peer.sin_family = AF_INET;
  inet_aton("127.0.0.1", &peer.sin_addr);

  id = nsock_connect_ssl(btd->nsp, iod, cancel_handler, 4000, (void *)&done,
                         (struct sockaddr *)&peer, sizeof(peer), IPPROTO_TCP,
                         PORT_TCPSSL, NULL);
  nsock_event_cancel(btd->nsp, id, 1);

  nsock_iod_delete(iod, NSOCK_PENDING_SILENT);

  return (done == 1) ? 0 : -ENOEXEC;
}


const struct test_case TestCancelTCP = {
  .t_name     = "schedule and cancel TCP connect",
  .t_setup    = cancel_setup,
  .t_run      = cancel_tcp_run,
  .t_teardown = cancel_teardown
};

const struct test_case TestCancelUDP = {
  .t_name     = "schedule and cancel UDP pseudo-connect",
  .t_setup    = cancel_setup,
  .t_run      = cancel_udp_run,
  .t_teardown = cancel_teardown
};

const struct test_case TestCancelSSL = {
  .t_name     = "schedule and cancel SSL connect",
  .t_setup    = cancel_setup,
  .t_run      = cancel_ssl_run,
  .t_teardown = cancel_teardown
};
