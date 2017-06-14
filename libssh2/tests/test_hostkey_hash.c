#include "session_fixture.h"
#include "libssh2_config.h"

#include <libssh2.h>

#include <stdio.h>

const char *EXPECTED_HOSTKEY =
    "AAAAB3NzaC1yc2EAAAABIwAAAQEArrr/JuJmaZligyfS8vcNur+mWR2ddDQtVdhHzdKU"
    "UoR6/Om6cvxpe61H1YZO1xCpLUBXmkki4HoNtYOpPB2W4V+8U4BDeVBD5crypEOE1+7B"
    "Am99fnEDxYIOZq2/jTP0yQmzCpWYS3COyFmkOL7sfX1wQMeW5zQT2WKcxC6FSWbhDqrB"
    "eNEGi687hJJoJ7YXgY/IdiYW5NcOuqRSWljjGS3dAJsHHWk4nJbhjEDXbPaeduMAwQU9"
    "i6ELfP3r+q6wdu0P4jWaoo3De1aYxnToV/ldXykpipON4NPamsb6Ph2qlJQKypq7J4iQ"
    "gkIIbCU1A31+4ExvcIVoxLQw/aTSbw==";

const char *EXPECTED_MD5_HASH_DIGEST = "0C0ED1A5BB10275F76924CE187CE5C5E";

const char *EXPECTED_SHA1_HASH_DIGEST =
    "F3CD59E2913F4422B80F7B0A82B2B89EAE449387";

const int MD5_HASH_SIZE = 16;
const int SHA1_HASH_SIZE = 20;

static void calculate_digest(const char *hash, size_t hash_len, char *buffer,
                             size_t buffer_len)
{
    size_t i;
    char *p = buffer;
    char *end = buffer + buffer_len;

    for (i = 0; i < hash_len && p < end; ++i) {
        p += snprintf(p, end - p, "%02X", (unsigned char)hash[i]);
    }
}

int test(LIBSSH2_SESSION *session)
{
    char buf[BUFSIZ];

    const char *md5_hash;
    const char *sha1_hash;

    md5_hash = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_MD5);
    if (md5_hash == NULL) {
        print_last_session_error(
            "libssh2_hostkey_hash(LIBSSH2_HOSTKEY_HASH_MD5)");
        return 1;
    }

    calculate_digest(md5_hash, MD5_HASH_SIZE, buf, BUFSIZ);

    if (strcmp(buf, EXPECTED_MD5_HASH_DIGEST) != 0) {
        fprintf(stderr, "MD5 hash not as expected - digest %s != %s\n", buf,
                EXPECTED_MD5_HASH_DIGEST);
        return 1;
    }

    sha1_hash = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);
    if (sha1_hash == NULL) {
        print_last_session_error(
            "libssh2_hostkey_hash(LIBSSH2_HOSTKEY_HASH_SHA1)");
        return 1;
    }

    calculate_digest(sha1_hash, SHA1_HASH_SIZE, buf, BUFSIZ);

    if (strcmp(buf, EXPECTED_SHA1_HASH_DIGEST) != 0) {
        fprintf(stderr, "SHA1 hash not as expected - digest %s != %s\n", buf,
                EXPECTED_SHA1_HASH_DIGEST);
        return 1;
    }

    return 0;
}
