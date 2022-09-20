/*
 * Nsock regression test suite
 * Same license as nmap -- see https://nmap.org/book/man-legal.html
 */

#include "test-common.h"

#define END_OF_TESTS -1
#define GOOD 0
#define BAD 1
struct proxy_test {
  int ttype;
  const char *input;
}

static const struct proxy_test Tests[] = {
  /* single proxy */
  /* http */
  {GOOD, "http://example.com"},
  {GOOD, "http://example.com/some/crazy.path"},
  {GOOD, "http://example.com/some/path?q=@!weird&other=;"},
  {GOOD, "http://127.0.0.1/"},
  {GOOD, "http://[::1]/"},
  {GOOD, "http://example.com:80/"},
  {GOOD, "http://127.0.0.1:1234/"},
  {GOOD, "http://[::1]:8080/"},
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
  /* Does SOCKS4 really support a path like this? */
  {GOOD, "socks4://example.com/path?"},
  /* multiple proxies */
  {GOOD, "http://example.com:8080/,socks4://127.0.0.1/"},
  {GOOD, "http://[::1]/,socks4://example.com:5000/"},
  {GOOD, "socks4://[::1]/,socks4://example.com/,http://[::1]:9090"},
  /* Dumb stuff */
  {BAD, ""},
  {BAD, "com"},
  {BAD, "example.com"},
  {BAD, "/example.com/"},
  {BAD, "//example.com/"},
  {BAD, "http/example.com/"},
  {BAD, "http//example.com/"},
  {BAD, "sptth://example.com/"},
  {BAD, ","},
  {BAD, ", "},
  {BAD, " ,"},
  {BAD, ",,"},
  {BAD, ", ,"},
  {BAD, " , , "},
  {BAD, "http://example.com/,asdf"},
  {BAD, "http://example.com/,"},
  {BAD, "http://example.com/,,"},
  {BAD, ",http://example.com/"},
  {BAD, ",,http://example.com/"},
  {BAD, "socks4://127.0.0.1/,http://example.com/,"},
  {BAD, "socks4://127.0.0.1/,,http://example.com/"},
  {BAD, ",socks4://127.0.0.1/,http://example.com/"},
  {END_OF_TESTS, NULL}
};

static int parser_test(void *testdata) {
  int tn = 0;
  struct proxy_test *pt = &Tests[tn];
  while (pt->ttype != END_OF_TESTS) {
    nsock_proxychain pxc = NULL;
    int ret = nsock_proxychain_new(pt->input, &pxc, NULL);
    if (ret > 0 && pt->ttype == BAD) {
      return -1;
    }
    else if (ret <= 0 && pt->ttype == GOOD) {
      return -2;
    }
    nsock_proxychain_delete(pxc);
  }
  return 0;
}

const struct test_case TestProxyParse = {
  .t_name     = "test nsock proxychain parsing",
  .t_setup    = NULL,
  .t_run      = parser_test,
  .t_teardown = NULL
};
