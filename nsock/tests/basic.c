/*
 * Nsock regression test suite
 * Same license as nmap -- see http://nmap.org/book/man-legal.html
 */

#include "test-common.h"


struct basic_test_data {
  nsock_pool nsp;
};

static int basic_setup(void **tdata) {
  struct basic_test_data *btd;

  btd = calloc(1, sizeof(struct basic_test_data));
  if (btd == NULL)
    return -ENOMEM;

  btd->nsp = nsp_new(NULL);

  *tdata = btd;
  return 0;
}

static int basic_teardown(void *tdata) {
  struct basic_test_data *btd = (struct basic_test_data *)tdata;

  if (tdata) {
    nsp_delete(btd->nsp);
    free(tdata);
  }
  return 0;
}

static int basic_udata(void *tdata) {
  struct basic_test_data *btd = (struct basic_test_data *)tdata;

  AssertEqual(nsp_getud(btd->nsp), NULL);
  nsp_setud(btd->nsp, btd);
  AssertEqual(nsp_getud(btd->nsp), btd);
  return 0;
}


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

  btd->nsp = nsp_new(NULL);

  *tdata = btd;
  return 0;
}

static int cancel_teardown(void *tdata) {
  struct basic_test_data *btd = (struct basic_test_data *)tdata;

  if (tdata) {
    nsp_delete(btd->nsp);
    free(tdata);
  }
  return 0;
}

static int cancel_run(void *tdata) {
  struct basic_test_data *btd = (struct basic_test_data *)tdata;
  struct sockaddr_in peer;
  nsock_iod iod;
  nsock_event_id id;
  int done = 0;

  iod = nsi_new(btd->nsp, NULL);
  AssertNonNull(iod);

  memset(&peer, 0, sizeof(peer));
  peer.sin_family = AF_INET;
  inet_aton("127.0.0.1", &peer.sin_addr);

  id = nsock_connect_ssl(btd->nsp, iod, cancel_handler, 4000, (void *)&done,
                         (struct sockaddr *)&peer, sizeof(peer), IPPROTO_TCP,
                         PORT_TCPSSL, NULL);
  nsock_event_cancel(btd->nsp, id, 1);

  nsi_delete(iod, NSOCK_PENDING_SILENT);

  return (done == 1) ? 0 : -ENOEXEC;
}


const struct test_case TestPoolUserData = {
  .t_name     = "nsock pool user data",
  .t_setup    = basic_setup,
  .t_run      = basic_udata,
  .t_teardown = basic_teardown
};

const struct test_case TestCancelSSLOperation = {
  .t_name     = "schedule and cancel SSL connect",
  .t_setup    = cancel_setup,
  .t_run      = cancel_run,
  .t_teardown = cancel_teardown
};

