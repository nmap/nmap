/*
 * Nsock regression test suite
 * Same license as nmap -- see https://nmap.org/book/man-legal.html
 */

#include "test-common.h"


struct connect_test_data {
  nsock_pool nsp;
  nsock_iod  nsi;
  int connect_result;
};


static void connect_handler(nsock_pool nsp, nsock_event nse, void *udata) {
  struct connect_test_data *ctd;

  ctd = (struct connect_test_data *)nsock_pool_get_udata(nsp);

  switch(nse_status(nse)) {
    case NSE_STATUS_SUCCESS:
      ctd->connect_result = 0;
      break;

    case NSE_STATUS_ERROR:
      ctd->connect_result = -(nse_errorcode(nse));
      break;

    case NSE_STATUS_TIMEOUT:
      ctd->connect_result = -ETIMEDOUT;
      break;

    default:
      ctd->connect_result = -EINVAL;
      break;
  }
}

static int connect_setup(void **tdata) {
  struct connect_test_data *ctd;

  ctd = calloc(1, sizeof(struct connect_test_data));
  if (ctd == NULL)
    return -ENOMEM;

  ctd->nsp = nsock_pool_new(ctd);
  AssertNonNull(ctd->nsp);

  ctd->nsi = nsock_iod_new(ctd->nsp, NULL);
  AssertNonNull(ctd->nsi);

  *tdata = ctd;
  return 0;
}

static int connect_teardown(void *tdata) {
  struct connect_test_data *ctd = (struct connect_test_data *)tdata;

  if (tdata) {
    nsock_iod_delete(ctd->nsi, NSOCK_PENDING_SILENT); /* nsock_pool_delete would also handle it */
    nsock_pool_delete(ctd->nsp);
    free(tdata);
  }
  return 0;
}

static int connect_tcp(void *tdata) {
  struct connect_test_data *ctd = (struct connect_test_data *)tdata;
  struct sockaddr_in peer;

  memset(&peer, 0, sizeof(peer));
  peer.sin_family = AF_INET;
  inet_aton("127.0.0.1", &peer.sin_addr);

  nsock_connect_tcp(ctd->nsp, ctd->nsi, connect_handler, 4000, NULL,
                    (struct sockaddr *)&peer, sizeof(peer), PORT_TCP);

  nsock_loop(ctd->nsp, 4000);
  return ctd->connect_result;
}

static int connect_tcp_failure(void *tdata) {
  struct connect_test_data *ctd = (struct connect_test_data *)tdata;
  struct sockaddr_in peer;

  memset(&peer, 0, sizeof(peer));
  peer.sin_family = AF_INET;
  inet_aton("127.0.0.1", &peer.sin_addr);

  /* pass in addrlen == 0 to force connect(2) to fail */
  nsock_connect_tcp(ctd->nsp, ctd->nsi, connect_handler, 4000, NULL,
                    (struct sockaddr *)&peer, 0, PORT_TCP);

  nsock_loop(ctd->nsp, 4000);
  AssertEqual(ctd->connect_result, -EINVAL);
  return 0;
}


const struct test_case TestConnectTCP = {
  .t_name     = "simple tcp connection",
  .t_setup    = connect_setup,
  .t_run      = connect_tcp,
  .t_teardown = connect_teardown
};

const struct test_case TestConnectFailure = {
  .t_name     = "tcp connection failure case",
  .t_setup    = connect_setup,
  .t_run      = connect_tcp_failure,
  .t_teardown = connect_teardown
};
