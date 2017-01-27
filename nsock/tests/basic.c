/*
 * Nsock regression test suite
 * Same license as nmap -- see https://nmap.org/book/man-legal.html
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

  btd->nsp = nsock_pool_new(NULL);

  *tdata = btd;
  return 0;
}

static int basic_teardown(void *tdata) {
  struct basic_test_data *btd = (struct basic_test_data *)tdata;

  if (tdata) {
    nsock_pool_delete(btd->nsp);
    free(tdata);
  }
  return 0;
}

static int basic_udata(void *tdata) {
  struct basic_test_data *btd = (struct basic_test_data *)tdata;

  AssertEqual(nsock_pool_get_udata(btd->nsp), NULL);
  nsock_pool_set_udata(btd->nsp, btd);
  AssertEqual(nsock_pool_get_udata(btd->nsp), btd);
  return 0;
}



const struct test_case TestPoolUserData = {
  .t_name     = "nsock pool user data",
  .t_setup    = basic_setup,
  .t_run      = basic_udata,
  .t_teardown = basic_teardown
};
