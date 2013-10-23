/*
 * Nsock regression test suite
 * Same license as nmap -- see http://nmap.org/book/man-legal.html
 */


#include "test-common.h"


#ifndef WIN32
  #define RESET       "\033[0m"
  #define BOLDRED     "\033[1m\033[31m"
  #define BOLDGREEN   "\033[1m\033[32m"
  #define TEST_FAILED "[" BOLDRED "FAILED" RESET "]"
  #define TEST_OK     "[" BOLDGREEN "OK" RESET "]"
#else
  /* WIN32 terminal has no ANSI driver */
  #define TEST_FAILED "[FAILED]"
  #define TEST_OK     "[OK]"
#endif



/* socket_strerror() comes from nbase
 * Declared here to work around a silly inclusion issue until I can fix it. */
char *socket_strerror(int errnum);

extern const struct test_case TestPoolUserData;
extern const struct test_case TestTimer;
extern const struct test_case TestLogLevels;
extern const struct test_case TestErrLevels;
extern const struct test_case TestConnectTCP;
extern const struct test_case TestGHLists;
extern const struct test_case TestGHHeaps;
extern const struct test_case TestHeapOrdering;
extern const struct test_case TestCancelTCP;
extern const struct test_case TestCancelUDP;
extern const struct test_case TestCancelSSL;


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
  /* ---- ghheaps.c */
  &TestGHHeaps,
  &TestHeapOrdering,
  /* ---- cancel.c */
  &TestCancelTCP,
  &TestCancelUDP,
  &TestCancelSSL,
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

#ifdef WIN32
static int win_init(void) {
  WSADATA data;

  rc = WSAStartup(MAKEWORD(2, 2), &data);
  if (rc)
    fatal("Failed to start winsock: %s\n", socket_strerror(rc));

  return 0;
}
#endif

int main(int ac, char **av) {
  int rc, i;

#ifdef WIN32
  win_init();
#endif

  for (i = 0; TestCases[i] != NULL; i++) {
    const struct test_case *current = TestCases[i];
    const char *name = get_test_name(current);

    printf("%-48s", name);
    fflush(stdout);
    rc = test_case_run(current);
    if (rc) {
      printf(TEST_FAILED " (%s)\n", socket_strerror(-rc));
      break;
    }
    printf(TEST_OK "\n");
  }
  return rc;
}

