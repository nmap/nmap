/***************************************************************************
 * ncat_digest.c -- HTTP Digest authentication handling.                   *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *
 * The Nmap Security Scanner is (C) 1996-2023 Nmap Software LLC ("The Nmap
 * Project"). Nmap is also a registered trademark of the Nmap Project.
 *
 * This program is distributed under the terms of the Nmap Public Source
 * License (NPSL). The exact license text applying to a particular Nmap
 * release or source code control revision is contained in the LICENSE
 * file distributed with that version of Nmap or source code control
 * revision. More Nmap copyright/legal information is available from
 * https://nmap.org/book/man-legal.html, and further information on the
 * NPSL license itself can be found at https://nmap.org/npsl/ . This
 * header summarizes some key points from the Nmap license, but is no
 * substitute for the actual license text.
 *
 * Nmap is generally free for end users to download and use themselves,
 * including commercial use. It is available from https://nmap.org.
 *
 * The Nmap license generally prohibits companies from using and
 * redistributing Nmap in commercial products, but we sell a special Nmap
 * OEM Edition with a more permissive license and special features for
 * this purpose. See https://nmap.org/oem/
 *
 * If you have received a written Nmap license agreement or contract
 * stating terms other than these (such as an Nmap OEM license), you may
 * choose to use and redistribute Nmap under those terms instead.
 *
 * The official Nmap Windows builds include the Npcap software
 * (https://npcap.com) for packet capture and transmission. It is under
 * separate license terms which forbid redistribution without special
 * permission. So the official Nmap Windows builds may not be redistributed
 * without special permission (such as an Nmap OEM license).
 *
 * Source is provided to this software because we believe users have a
 * right to know exactly what a program is going to do before they run it.
 * This also allows you to audit the software for security holes.
 *
 * Source code also allows you to port Nmap to new platforms, fix bugs, and add
 * new features. You are highly encouraged to submit your changes as a Github PR
 * or by email to the dev@nmap.org mailing list for possible incorporation into
 * the main distribution. Unless you specify otherwise, it is understood that
 * you are offering us very broad rights to use your submissions as described in
 * the Nmap Public Source License Contributor Agreement. This is important
 * because we fund the project by selling licenses with various terms, and also
 * because the inability to relicense code has caused devastating problems for
 * other Free Software projects (such as KDE and NASM).
 *
 * The free version of Nmap is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranties,
 * indemnification and commercial support are all available through the
 * Npcap OEM program--see https://nmap.org/oem/
 *
 ***************************************************************************/

/* $Id$ */

/* Nonces returned by make_nonce have the form
        timestamp-MD5(secret:timestamp)
   using representative values, this may look like
        1263929285.015273-a8e75fae174fc0e6a5df47bf9900beb6
   Sending a timestamp in the clear allows us to compute how long ago the nonce
   was issued without local state. Including microseconds reduces the chance
   that the same nonce will be issued for two different requests. When a nonce
   is received from a client, the time is extracted and then the nonce is
   recalculated locally to make sure they match. This is similar to the strategy
   recommended in section 3.2.1 of RFC 2617.

   When Ncat does Digest authentication as a client, it only does so to make a
   single CONNECT request to a proxy server. Therefore we don't use a differing
   nc (nonce count) but always the constant 00000001. */

#include "ncat.h"
#include "http.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

/* What's a good length for this? I think it exists only to prevent us from
   hashing known plaintext from the server. */
#define CNONCE_LENGTH 8

#define SECRET_LENGTH 16

static unsigned char secret[SECRET_LENGTH];
static int secret_initialized = 0;

static int append_quoted_string(char **buf, size_t *size, size_t *offset, const char *s)
{
    const char *t;

    strbuf_append_str(buf, size, offset, "\"");
    for (;;) {
        t = s;
        while (!((*t >= 0 && *t <= 31) || *t == 127 || *t == '\\'))
            t++;
        strbuf_append(buf, size, offset, s, t - s);
        if (*t == '\0')
            break;
        strbuf_sprintf(buf, size, offset, "\\%c", *t);
        s = t + 1;
    }
    strbuf_append_str(buf, size, offset, "\"");

    return *size;
}

/* n is the size of src. dest must have at least n * 2 + 1 allocated bytes. */
static char *enhex(char *dest, const unsigned char *src, size_t n)
{
    unsigned int i;

    for (i = 0; i < n; i++)
        Snprintf(dest + i * 2, 3, "%02x", src[i]);

    return dest;
}

/* Initialize the server secret used in generating nonces. Return -1 on
   failure. */
int http_digest_init_secret(void)
{
    if (!RAND_status())
        return -1;
    if (RAND_bytes(secret, sizeof(secret)) != 1)
        return -1;
    secret_initialized = 1;

    return 0;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define EVP_MD_CTX_new EVP_MD_CTX_create
#define EVP_MD_CTX_free EVP_MD_CTX_destroy
#endif
static char *make_nonce(const struct timeval *tv)
{
    char *buf = NULL;
    size_t size = 0, offset = 0;
    EVP_MD_CTX *md5;
    unsigned char hashbuf[EVP_MAX_MD_SIZE];
    char hash_hex[EVP_MAX_MD_SIZE * 2 + 1];
    char time_buf[32];
    unsigned int hash_size = 0;

    /* Crash if someone forgot to call http_digest_init_secret. */
    if (!secret_initialized)
        bye("Server secret not initialized for Digest authentication. Call http_digest_init_secret.");

    Snprintf(time_buf, sizeof(time_buf), "%lu.%06lu",
        (long unsigned) tv->tv_sec, (long unsigned) tv->tv_usec);
    md5 = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md5, EVP_md5(), NULL);
    EVP_DigestUpdate(md5, secret, sizeof(secret));
    EVP_DigestUpdate(md5, ":", 1);
    EVP_DigestUpdate(md5, time_buf, strlen(time_buf));
    EVP_DigestFinal_ex(md5, hashbuf, &hash_size);
    enhex(hash_hex, hashbuf, hash_size);

    strbuf_sprintf(&buf, &size, &offset, "%s-%s", time_buf, hash_hex);
    EVP_MD_CTX_free(md5);

    return buf;
}

/* Arguments are assumed to be non-NULL, with the exception of nc and cnonce,
   which may be garbage only if qop == QOP_NONE. */
static void make_response(char buf[EVP_MAX_MD_SIZE * 2 + 1],
    const char *username, const char *realm, const char *password,
    const char *method, const char *uri, const char *nonce,
    enum http_digest_qop qop, const char *nc, const char *cnonce)
{
    char HA1_hex[EVP_MAX_MD_SIZE * 2 + 1], HA2_hex[EVP_MAX_MD_SIZE * 2 + 1];
    unsigned char hashbuf[EVP_MAX_MD_SIZE];
    EVP_MD_CTX *md5;
    unsigned int hash_size = 0;
    const EVP_MD *md = EVP_md5();

    /* Calculate H(A1). */
    md5 = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md5, md, NULL);
    EVP_DigestUpdate(md5, username, strlen(username));
    EVP_DigestUpdate(md5, ":", 1);
    EVP_DigestUpdate(md5, realm, strlen(realm));
    EVP_DigestUpdate(md5, ":", 1);
    EVP_DigestUpdate(md5, password, strlen(password));
    EVP_DigestFinal_ex(md5, hashbuf, &hash_size);
    enhex(HA1_hex, hashbuf, hash_size);

    /* Calculate H(A2). */
    EVP_DigestInit_ex(md5, md, NULL);
    EVP_DigestUpdate(md5, method, strlen(method));
    EVP_DigestUpdate(md5, ":", 1);
    EVP_DigestUpdate(md5, uri, strlen(uri));
    EVP_DigestFinal_ex(md5, hashbuf, &hash_size);
    enhex(HA2_hex, hashbuf, hash_size);

    /* Calculate response. */
    EVP_DigestInit_ex(md5, md, NULL);
    EVP_DigestUpdate(md5, HA1_hex, strlen(HA1_hex));
    EVP_DigestUpdate(md5, ":", 1);
    EVP_DigestUpdate(md5, nonce, strlen(nonce));
    if (qop == QOP_AUTH) {
        EVP_DigestUpdate(md5, ":", 1);
        EVP_DigestUpdate(md5, nc, strlen(nc));
        EVP_DigestUpdate(md5, ":", 1);
        EVP_DigestUpdate(md5, cnonce, strlen(cnonce));
        EVP_DigestUpdate(md5, ":", 1);
        EVP_DigestUpdate(md5, "auth", strlen("auth"));
    }
    EVP_DigestUpdate(md5, ":", 1);
    EVP_DigestUpdate(md5, HA2_hex, strlen(HA2_hex));
    EVP_DigestFinal_ex(md5, hashbuf, &hash_size);

    enhex(buf, hashbuf, hash_size);
    EVP_MD_CTX_free(md5);
}

/* Extract the issuance time from a nonce (without checking other aspects of
   validity. If the time can't be extracted, returns -1, 0 otherwise. */
int http_digest_nonce_time(const char *nonce, struct timeval *tv)
{
    unsigned long sec, usec;

    if (sscanf(nonce, "%lu.%lu", &sec, &usec) != 2)
        return -1;

    tv->tv_sec = sec;
    tv->tv_usec = usec;

    return 0;
}

char *http_digest_proxy_authenticate(const char *realm, int stale)
{
    char *buf = NULL;
    size_t size = 0, offset = 0;
    struct timeval tv;
    char *nonce;

    if (gettimeofday(&tv, NULL) == -1)
        return NULL;

    strbuf_append_str(&buf, &size, &offset, "Digest realm=");
    append_quoted_string(&buf, &size, &offset, realm);

    nonce = make_nonce(&tv);
    strbuf_append_str(&buf, &size, &offset, ", nonce=");
    append_quoted_string(&buf, &size, &offset, nonce);
    free(nonce);
    strbuf_append_str(&buf, &size, &offset, ", qop=\"auth\"");

    if (stale)
        strbuf_append_str(&buf, &size, &offset, ", stale=true");

    return buf;
}

char *http_digest_proxy_authorization(const struct http_challenge *challenge,
    const char *username, const char *password,
    const char *method, const char *uri)
{
    /* For now we authenticate successfully at most once, so we don't need a
       varying client nonce count. */
    static const u32 nc = 0x00000001;

    char response_hex[EVP_MAX_MD_SIZE * 2 + 1];
    unsigned char cnonce[CNONCE_LENGTH];
    char cnonce_buf[CNONCE_LENGTH * 2 + 1];
    char nc_buf[8 + 1];
    char *buf = NULL;
    size_t size = 0, offset = 0;
    enum http_digest_qop qop;

    if (challenge->scheme != AUTH_DIGEST
        || challenge->realm == NULL
        || challenge->digest.nonce == NULL
        || challenge->digest.algorithm != ALGORITHM_MD5)
        return NULL;

    if (challenge->digest.qop & QOP_AUTH) {
        Snprintf(nc_buf, sizeof(nc_buf), "%08x", nc);
        if (!RAND_status())
            return NULL;
        if (RAND_bytes(cnonce, sizeof(cnonce)) != 1)
            return NULL;
        enhex(cnonce_buf, cnonce, sizeof(cnonce));
        qop = QOP_AUTH;
    } else {
        qop = QOP_NONE;
    }

    strbuf_append_str(&buf, &size, &offset, " Digest");
    strbuf_append_str(&buf, &size, &offset, " username=");
    append_quoted_string(&buf, &size, &offset, username);
    strbuf_append_str(&buf, &size, &offset, ", realm=");
    append_quoted_string(&buf, &size, &offset, challenge->realm);
    strbuf_append_str(&buf, &size, &offset, ", nonce=");
    append_quoted_string(&buf, &size, &offset, challenge->digest.nonce);
    strbuf_append_str(&buf, &size, &offset, ", uri=");
    append_quoted_string(&buf, &size, &offset, uri);

    if (qop == QOP_AUTH) {
        strbuf_append_str(&buf, &size, &offset, ", qop=auth");
        strbuf_append_str(&buf, &size, &offset, ", cnonce=");
        append_quoted_string(&buf, &size, &offset, cnonce_buf);
        strbuf_sprintf(&buf, &size, &offset, ", nc=%s", nc_buf);
    }

    make_response(response_hex, username, challenge->realm, password,
        method, uri, challenge->digest.nonce, qop, nc_buf, cnonce_buf);
    strbuf_append_str(&buf, &size, &offset, ", response=");
    append_quoted_string(&buf, &size, &offset, response_hex);

    if (challenge->digest.opaque != NULL) {
        strbuf_append_str(&buf, &size, &offset, ", opaque=");
        append_quoted_string(&buf, &size, &offset, challenge->digest.opaque);
    }

    strbuf_append_str(&buf, &size, &offset, "\r\n");

    return buf;
}

/* Check that a nonce is one that we issued, and that the response is what is
   expected. This doesn't do any checking against the lifetime of the nonce. */
int http_digest_check_credentials(const char *username, const char *realm,
    const char *password, const char *method,
    const struct http_credentials *credentials)
{
    char response_hex[EVP_MAX_MD_SIZE * 2 + 1];
    struct timeval tv;
    char *nonce;

    if (credentials->scheme != AUTH_DIGEST
        || credentials->u.digest.username == NULL
        || credentials->u.digest.realm == NULL
        || credentials->u.digest.nonce == NULL
        || credentials->u.digest.uri == NULL
        || credentials->u.digest.response == NULL
        || credentials->u.digest.algorithm != ALGORITHM_MD5) {
        return 0;
    }
    if (credentials->u.digest.qop != QOP_NONE && credentials->u.digest.qop != QOP_AUTH)
        return 0;
    if (credentials->u.digest.qop == QOP_AUTH
        && (credentials->u.digest.nc == NULL
            || credentials->u.digest.cnonce == NULL)) {
        return 0;
    }

    if (strcmp(username, credentials->u.digest.username) != 0)
        return 0;
    if (strcmp(realm, credentials->u.digest.realm) != 0)
        return 0;

    if (http_digest_nonce_time(credentials->u.digest.nonce, &tv) == -1)
        return 0;

    nonce = make_nonce(&tv);
    if (strcmp(nonce, credentials->u.digest.nonce) != 0) {
        /* We could not have handed out this nonce. */
        free(nonce);
        return 0;
    }
    free(nonce);

    make_response(response_hex, credentials->u.digest.username, realm,
        password, method, credentials->u.digest.uri,
        credentials->u.digest.nonce, credentials->u.digest.qop,
        credentials->u.digest.nc, credentials->u.digest.cnonce);

    return strcmp(response_hex, credentials->u.digest.response) == 0;
}
