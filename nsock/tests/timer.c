/*
 * Nsock regression test suite
 * Same license as nmap -- see http://nmap.org/book/man-legal.html
 */

#include "test-common.h"
#include <time.h>

#define TIMERS_BUFFLEN  1024


struct timer_test_data {
  nsock_pool nsp;
  nsock_event_id timer_list[TIMERS_BUFFLEN];
  size_t timer_count;
  int stop; /* set to non-zero to stop the test */
};


static void timer_handler(nsock_pool nsp, nsock_event nse, void *tdata);


static void add_timer(struct timer_test_data *ttd, int timeout) {
  nsock_event_id id;

  id = nsock_timer_create(ttd->nsp, timer_handler, timeout, ttd);
  ttd->timer_list[ttd->timer_count++] = id;
}

static void timer_handler(nsock_pool nsp, nsock_event nse, void *tdata) {
  struct timer_test_data *ttd = (struct timer_test_data *)tdata;
  int rnd, rnd2;

  if (nse_status(nse) != NSE_STATUS_SUCCESS) {
    ttd->stop = -nsp_geterrorcode(nsp);
    return;
  }

  if (ttd->timer_count > TIMERS_BUFFLEN - 3)
    return;

  rnd = rand() % ttd->timer_count;
  rnd2 = rand() % 3;

  switch (rnd2) {
    case 0:
      /* Do nothing */
      /* Actually I think I'll create two timers :) */
      add_timer(ttd, rand() % 3000);
      add_timer(ttd, rand() % 3000);
      break;

    case 1:
      /* Try to kill another id (which may or may not be active */
      nsock_event_cancel(nsp, ttd->timer_list[rnd], rand() % 2);
      break;

    case 2:
      /* Create a new timer */
      add_timer(ttd, rand() % 3000);
      break;

    default:
      assert(0);
  }
}

static int timer_setup(void **tdata) {
  struct timer_test_data *ttd;

  srand(time(NULL));

  ttd = calloc(1, sizeof(struct timer_test_data));
  if (ttd == NULL)
    return -ENOMEM;

  ttd->nsp = nsp_new(NULL);
  AssertNonNull(ttd->nsp);

  *tdata = ttd;
  return 0;
}

static int timer_teardown(void *tdata) {
  struct timer_test_data *ttd = (struct timer_test_data *)tdata;

  if (tdata) {
    nsp_delete(ttd->nsp);
    free(tdata);
  }
  return 0;
}

static int timer_totalmess(void *tdata) {
  struct timer_test_data *ttd = (struct timer_test_data *)tdata;
  enum nsock_loopstatus loopret;
  int num_loops = 0;

  add_timer(ttd, 1800);
  add_timer(ttd, 800);
  add_timer(ttd, 1300);
  add_timer(ttd, 0);
  add_timer(ttd, 100);

  /* Now lets get this party started right! */
  while (num_loops++ < 5 && !ttd->stop) {
    loopret = nsock_loop(ttd->nsp, 1500);
    switch (loopret) {
      case NSOCK_LOOP_TIMEOUT:
        /* nothing to do */
        break;

      case NSOCK_LOOP_NOEVENTS:
        return 0;

      default:
        return -(nsp_geterrorcode(ttd->nsp));
    }
  }
  return ttd->stop;
}

const struct test_case TestTimer = {
  .t_name     = "test timer operations",
  .t_setup    = timer_setup,
  .t_run      = timer_totalmess,
  .t_teardown = timer_teardown
};

