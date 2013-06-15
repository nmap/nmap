/*
 * Nsock regression test suite
 * Same license as nmap -- see http://nmap.org/book/man-legal.html
 */


#include "test-common.h"


#define RESET       "\033[0m"
#define BOLDRED     "\033[1m\033[31m"
#define BOLDGREEN   "\033[1m\033[32m"

#define TEST_FAILED "[" BOLDRED "FAILED" RESET "]"
#define TEST_OK     "[" BOLDGREEN "OK" RESET "]"


extern const struct test_case TestPoolUserData;
extern const struct test_case TestTimer;
extern const struct test_case TestLogLevels;
extern const struct test_case TestErrLevels;
extern const struct test_case TestConnectTCP;
extern const struct test_case TestGHLists;


static const struct test_case *TestCases[] = {
  /* ---- basic.c */
  &TestPoolUserData,
  /* ---- timer.c */
  &TestTimer,
  /* ---- logs.c */
  &TestLogLevels,
  &TestErrLevels,
  /* ---- connect.c */
  &TestConnectTCP,
  /* ---- ghlists.c */
  &TestGHLists,
  NULL
};

static int test_case_run(const struct test_case *test) {
  int rc;
  void *tdata = NULL;

  rc = test_setup(test, &tdata);
  if (rc)
    return rc;

  rc = test_run(test, tdata);
  if (rc)
    return rc;

  return test_teardown(test, tdata);
}

int main(int ac, char **av) {
  int rc, i;

  for (i = 0; TestCases[i] != NULL; i++) {
    const struct test_case *current = TestCases[i];
    const char *name = get_test_name(current);

    printf("%-48s", name);
    fflush(stdout);
    rc = test_case_run(current);
    if (rc) {
      printf(TEST_FAILED " (%s)\n", strerror(-rc));
      break;
    }
    printf(TEST_OK "\n");
  }
  return rc;
}

