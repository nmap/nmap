#include "session_fixture.h"

#include <libssh2.h>

#include <stdio.h>

const char *PASSWORD = "my test password"; /* configured in Dockerfile */
const char *WRONG_USERNAME = "i dont exist";

int test(LIBSSH2_SESSION *session)
{
    int rc;

    const char *userauth_list =
        libssh2_userauth_list(session, WRONG_USERNAME, strlen(WRONG_USERNAME));
    if (userauth_list == NULL) {
        print_last_session_error("libssh2_userauth_list");
        return 1;
    }

    if (strstr(userauth_list, "password") == NULL) {
        fprintf(stderr, "'password' was expected in userauth list: %s\n",
                userauth_list);
        return 1;
    }

    rc = libssh2_userauth_password_ex(session, WRONG_USERNAME,
                                      strlen(WRONG_USERNAME), PASSWORD,
                                      strlen(PASSWORD), NULL);
    if (rc == 0) {
        fprintf(stderr, "Password auth succeeded with wrong username\n");
        return 1;
    }

    return 0;
}
