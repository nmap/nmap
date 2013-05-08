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

const struct test_case TestPoolUserData = {
  .t_name     = "nsock pool user data",
  .t_setup    = basic_setup,
  .t_run      = basic_udata,
  .t_teardown = basic_teardown
};


