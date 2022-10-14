/*
 * Nsock regression test suite
 * Same license as nmap -- see https://nmap.org/book/man-legal.html
 */

#include "test-common.h"
#include "../src/nsock_log.h"

struct proxy_test_data {
  int tn;
  nsock_pool nsp;
};
static struct proxy_test_data *GlobalTD;

#define END_OF_TESTS -1
#define GOOD 0
#define BAD 1
struct proxy_test {
  int ttype;
  const char *input;
};

static const struct proxy_test Tests[] = {
  /* single proxy */
  /* http */
  {GOOD, "http://example.com"},
  {GOOD, "http://127.0.0.1/"},
  {GOOD, "http://1/some/crazy.path"},
  {GOOD, "http://127.1/some/path?q=@!weird&other=;"},
  {GOOD, "http://[::1]/"},
  {GOOD, "http://1:80/"},
  {GOOD, "http://1:8080"},
  {GOOD, "http://127.0.0.1:1234/"},
  {GOOD, "http://[::1]:8080/"},
  {GOOD, "http://[::1]:80"},
  /* https not supported! */
  {BAD, "https://example.com/"},
  /* No username/password in URI */
  {BAD, "https://scott:tiger@example.com/"},
  /* Port out of range */
  {BAD, "http://example.com:65536/"},
  /* Bad IPv6 syntax */
  {BAD, "http://::1/"},
  /* Missing host name */
  {BAD, "http://:8080/"},
  /* socks4 */
  {GOOD, "socks4://example.com"},
  {GOOD, "socks4://1"},
  /* socks4 does not support IPv6 */
  {BAD, "socks4://[::1]"},
  /* Does SOCKS4 really support a path like this? */
  {GOOD, "socks4://example.com/path?"},
  /* multiple proxies */
  {GOOD, "http://example.com:8080/,socks4://127.0.0.1/"},
  {GOOD, "http://[::1]/,socks4://example.com:5000/"},
  /* Should fail: socks4 cannot connect to IPv6 proxy */
  {GOOD, "socks4://127.0.0.1/,socks4://example.com/,http://[::1]:9090"},
  /* Dumb stuff */
  {BAD, ""},
  {BAD, ","},
  {BAD, ",,"},
  {BAD, "http://example.com/,"},
  {BAD, "http://example.com/,,"},
  {BAD, ",http://example.com/"},
  {BAD, ",,http://example.com/"},
  {BAD, "socks4://127.0.0.1/,http://example.com/,"},
  {BAD, ",socks4://127.0.0.1/,http://example.com/"},
  {BAD, "socks4://127.0.0.1/,,http://example.com/"},
  {BAD, "http://example.com:-1/"},
  {BAD, "http://example.com:0x80/"},
  {BAD, "http://example.com:0/"},
  {BAD, "http://example.com:2147483648"},
  {BAD, "http://example.com:21474836480"},
  {BAD, "http://:80"},
  {BAD, "http://example.com:80.com"},
  {BAD, "com"},
  {BAD, "example.com"},
  {BAD, "/example.com/"},
  {BAD, "//example.com/"},
  {BAD, "http/example.com/"},
  {BAD, "http//example.com/"},
  {BAD, "http:///example.com"},
  {BAD, "sptth://example.com/"},
  {BAD, " "},
  {BAD, ", "},
  {BAD, " ,"},
  {BAD, ", ,"},
  {BAD, " , , "},
  {BAD, "http://example.com/,asdf"},
  {END_OF_TESTS, NULL}
};

static int parser_test(void *testdata) {
  int result = 0;
  struct proxy_test_data *ptd = (struct proxy_test_data *)testdata;
  const struct proxy_test *pt = &Tests[ptd->tn];
  while (pt->ttype != END_OF_TESTS) {
    nsock_proxychain pxc = NULL;
    if (pt->ttype == BAD)
      nsock_log_info("Expected failure:");
    int ret = nsock_proxychain_new(pt->input, &pxc, NULL);
    nsock_log_debug("Test %d result: %d", ptd->tn, ret);
    if (ret > 0) {
      if (pt->ttype == BAD) {
        fprintf(stderr, "Proxy Test #%d: Failed to reject bad input: %s\n", ptd->tn, pt->input);
        result = -1;
      }
      nsock_proxychain_delete(pxc);
    }
    else if (ret <= 0 && pt->ttype == GOOD) {
      fprintf(stderr, "Proxy Test #%d: Failed to parse good input: %s\n", ptd->tn, pt->input);
      result = -2;
    }
    ptd->tn++;
    pt = &Tests[ptd->tn];
  }
  return result;
}

static void log_handler(const struct nsock_log_rec *rec) {
  /* Only print log messages if we expect the test to succeed. */
  if (Tests[GlobalTD->tn].ttype == GOOD) {
    fprintf(stderr, "Proxy Test #%d: %s(): %s\n", GlobalTD->tn, rec->func, rec->msg);
  }
}

static int proxy_setup(void **tdata) {
  struct proxy_test_data *ptd = calloc(1, sizeof(struct proxy_test_data));
  if (ptd == NULL)
    return -ENOMEM;

  ptd->nsp = nsock_pool_new(ptd);
  AssertNonNull(ptd->nsp);

  nsock_set_log_function(log_handler);

  *tdata = GlobalTD = ptd;
  return 0;
}

static int proxy_teardown(void *tdata) {
  struct proxy_test_data *ptd = (struct proxy_test_data *)tdata;

  if (tdata) {
    nsock_pool_delete(ptd->nsp);
    free(tdata);
  }
  nsock_set_log_function(NULL);
  GlobalTD = NULL;
  return 0;
}


const struct test_case TestProxyParse = {
  .t_name     = "test nsock proxychain parsing",
  .t_setup    = proxy_setup,
  .t_run      = parser_test,
  .t_teardown = proxy_teardown
};
