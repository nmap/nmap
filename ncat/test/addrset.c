/*
    Usage: ./addrset [<specification> ...]

    This program tests the addrset functions in nbase/nbase_addrset.c,
    the ones that maintain the lists of addresses for --allow and
    --deny. It takes as arguments specifications that are added to an
    addrset. It then reads whitespace-separated host names or IP
    addresses from standard input and echoes only those that are in the
    addrset.

    David Fifield

    Example:
    $ echo "1.2.3.4 1.0.0.5 1.2.3.8" | ./addrset "1.2.3.10/24"
    1.2.3.4
    1.2.3.8
*/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "ncat_core.h"

#ifdef WIN32
#include "../nsock/src/error.h"
#endif


#ifdef WIN32
static void win_init(void)
{
  WSADATA data;
  int rc;

  rc = WSAStartup(MAKEWORD(2,2), &data);
  if (rc)
    fatal("failed to start winsock: %s\n", socket_strerror(rc));
}
#endif

static int resolve_name(const char *name, struct addrinfo **result)
{
    struct addrinfo hints = { 0 };

    hints.ai_protocol = IPPROTO_TCP;
    *result = NULL;

    return getaddrinfo(name, NULL, &hints, result);
}

struct matches_all_pair {
  const char *ipv4;
  const char *ipv6;
};
static struct matches_all_pair matches_all_tests[] = {
    {"0.0.0.0/8", "::/8"},
    {"1.0.0.0/8", "100::/8"},
    {"2.0.0.0/7", "200::/7"},
    {"4.0.0.0/6", "400::/6"},
    {"8.0.0.0/5", "800::/5"},
    {"16.0.0.0/4", "1000::/4"},
    {"32.0.0.0/3", "2000::/3"},
    {"64.0.0.0/2", "4000::/2"},
    {"128.0.0.0/1", "8000::/1"}
};
static const size_t num_matches_all_tests = sizeof(matches_all_tests) / sizeof(matches_all_tests[0]);
static int matches_all_test(struct addrset *set) {
    for (int i = 0; i < num_matches_all_tests; i++) {
      fprintf(stderr, "addrset_add_spec(%s)\n", matches_all_tests[i].ipv4);
        addrset_add_spec(set, matches_all_tests[i].ipv4, AF_INET, 0);
    }
    if (!addrset_matches_all(set, AF_INET)) {
        return 1;
    }
    if (addrset_matches_all(set, AF_INET6)) {
        return 2;
    }
    for (int i = 0; i < num_matches_all_tests; i++) {
      fprintf(stderr, "addrset_add_spec(%s)\n", matches_all_tests[i].ipv6);
        addrset_add_spec(set, matches_all_tests[i].ipv6, AF_INET6, 0);
    }
    if (!addrset_matches_all(set, AF_INET6)) {
        return 3;
    }
    return 0;
}
static int do_matches_all_tests() {
    struct addrset *set = addrset_new();
    int r = matches_all_test(set);
    addrset_free(set);
    if (r != 0) return r;

    /* reverse order */
    for (int i = 0; i*2 < num_matches_all_tests; i++) {
        int j = num_matches_all_tests - (i + 1);
        if (j < i) break;
        struct matches_all_pair tmp = matches_all_tests[i];
        matches_all_tests[i] = matches_all_tests[j];
        matches_all_tests[j] = tmp;
    }
    set = addrset_new();
    r = matches_all_test(set);
    addrset_free(set);
    if (r != 0) return r + 3;

    /* random order */
    srand(time(NULL));
    for (int i = 0; i < num_matches_all_tests; i++) {
        int j = rand() % num_matches_all_tests;
        struct matches_all_pair tmp = matches_all_tests[i];
        matches_all_tests[i] = matches_all_tests[j];
        matches_all_tests[j] = tmp;
    }
    set = addrset_new();
    r = matches_all_test(set);
    addrset_free(set);
    if (r != 0)
      return r + 6;
    return 0;
}

int main(int argc, char *argv[])
{
    struct addrset *set;
    char line[1024];
    int i;
    char o_matches_all = 0;

#ifdef WIN32
    win_init();
#endif

    set = addrset_new();

    options_init();

    for (i = 1; i < argc; i++) {
        if (0 == strcmp(argv[i], "--test-matches-all")) {
          int rc = do_matches_all_tests();
          if (rc != 0) {
            fprintf(stderr, "addrset_matches_all() test failed: %d\n", rc);
          }
          addrset_free(set);
          return rc;
        }
        if (0 == strcmp(argv[i], "--matches-all")) {
          if (i+1 >= argc) {
            fprintf(stderr, "Usage: %s [--matches-all {4|6}]\n", argv[0]);
            addrset_free(set);
            exit(1);
          }
          o_matches_all = argv[++i][0];
        }
        else if (!addrset_add_spec(set, argv[i], o.af, !o.nodns)) {
            fprintf(stderr, "Error adding spec \"%s\".\n", argv[i]);
            addrset_free(set);
            exit(1);
        }
    }

    switch (o_matches_all) {
      case '4':
        if (addrset_matches_all(set, AF_INET)) {
          addrset_free(set);
          return 0;
        }
        addrset_free(set);
        exit(1);
        break;
      case '6':
        if (addrset_matches_all(set, AF_INET6)) {
          addrset_free(set);
          return 0;
        }
        addrset_free(set);
        exit(1);
        break;
      case 0:
        break;
      default:
        fprintf(stderr, "Usage: %s [--matches-all {4|6}]\n", argv[0]);
        addrset_free(set);
        exit(1);
        break;
    }

    while (fgets(line, sizeof(line), stdin) != NULL) {
        char *s, *hostname;
        struct addrinfo *addrs = NULL;

        s = line;
        while ((hostname = strtok(s, " \t\n")) != NULL) {
            int rc;

            s = NULL;

            addrs = NULL;
            rc = resolve_name(hostname, &addrs);
            if (rc != 0) {
                fprintf(stderr, "Error resolving \"%s\": %s.\n", hostname, gai_strerror(rc));
                if (addrs)
                  freeaddrinfo(addrs);
                continue;
            }
            if (addrs == NULL) {
                fprintf(stderr, "No addresses found for \"%s\".\n", hostname);
                continue;
            }

            /* Check just the first address returned. */
            if (addrset_contains(set, addrs->ai_addr))
                    printf("%s\n", hostname);

            freeaddrinfo(addrs);
        }
    }

    addrset_free(set);

    return 0;
}
