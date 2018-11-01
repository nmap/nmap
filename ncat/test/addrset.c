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

int main(int argc, char *argv[])
{
    struct addrset *set;
    char line[1024];
    int i;

#ifdef WIN32
    win_init();
#endif

    set = addrset_new();

    options_init();

    for (i = 1; i < argc; i++) {
        if (!addrset_add_spec(set, argv[i], o.af, !o.nodns)) {
            fprintf(stderr, "Error adding spec \"%s\".\n", argv[i]);
            exit(1);
        }
    }

    while (fgets(line, sizeof(line), stdin) != NULL) {
        char *s, *hostname;
        struct addrinfo *addrs;

        s = line;
        while ((hostname = strtok(s, " \t\n")) != NULL) {
            int rc;

            s = NULL;

            rc = resolve_name(hostname, &addrs);
            if (rc != 0) {
                fprintf(stderr, "Error resolving \"%s\": %s.\n", hostname, gai_strerror(rc));
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
