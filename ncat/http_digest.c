/***************************************************************************
 * ncat_digest.c -- HTTP Digest authentication handling.                   *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2013 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE CLARIFICATIONS  *
 * AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your right to use,    *
 * modify, and redistribute this software under certain conditions.  If    *
 * you wish to embed Nmap technology into proprietary software, we sell    *
 * alternative licenses (contact sales@insecure.com).  Dozens of software  *
 * vendors already license Nmap technology such as host discovery, port    *
 * scanning, OS detection, version detection, and the Nmap Scripting       *
 * Engine.                                                                 *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files, such as Nmap's nmap-os-db   *
 * or nmap-service-probes.                                                 *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * Nmap with other software in compressed or archival form does not        *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * As another special exception to the GPL terms, Insecure.Com LLC grants  *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two.                                  *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the special and conditions of the license text as well.       *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * Nmap or grant special permissions to use it in other open source        *
 * software.  Please contact fyodor@nmap.org with any such requests.       *
 * Similarly, we don't incorporate incompatible open source software into  *
 * Covered Software without special permission from the copyright holders. *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * Nmap in other works, are happy to help.  As mentioned above, we also    *
 * offer alternative license to integrate Nmap into proprietary            *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates.  They also fund the      *
 * continued development of Nmap.  Please email sales@insecure.com for     *
 * further information.                                                    *
 *                                                                         *
 * If you received these files with a written license agreement or         *
 * contract stating terms other than the terms above, then that            *
 * alternative license agreement takes precedence over these comments.     *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes (none     *
 * have been found so far).                                                *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to the dev@nmap.org mailing list for possible incorporation into the    *
 * main distribution.  By sending these changes to Fyodor or one of the    *
 * Insecure.Org development mailing lists, or checking them into the Nmap  *
 * source code repository, it is understood (unless you specify otherwise) *
 * that you are offering the Nmap Project (Insecure.Com LLC) the           *
 * unlimited, non-exclusive right to reuse, modify, and relicense the      *
 * code.  Nmap will always be available Open Source, but this is important *
 * because the inability to relicense code has caused devastating problems *
 * for other Free Software projects (such as KDE and NASM).  We also       *
 * occasionally relicense the code to third parties as discussed above.    *
 * If you wish to specify special license conditions of your               *
 * contributions, just say so when you send them.                          *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the Nmap      *
 * license file for more details (it's in a COPYING file included with     *
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING         *
 *                                                                         *
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

#include <openssl/md5.h>
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

static char *make_nonce(const struct timeval *tv)
{
    char *buf = NULL;
    size_t size = 0, offset = 0;
    MD5_CTX md5;
    unsigned char hashbuf[MD5_DIGEST_LENGTH];
    char hash_hex[MD5_DIGEST_LENGTH * 2 + 1];
    char time_buf[32];

    /* Crash if someone forgot to call http_digest_init_secret. */
    if (!secret_initialized)
        bye("Server secret not initialized for Digest authentication. Call http_digest_init_secret.");

    Snprintf(time_buf, sizeof(time_buf), "%lu.%06lu",
        (long unsigned) tv->tv_sec, (long unsigned) tv->tv_usec);

    MD5_Init(&md5);
    MD5_Update(&md5, secret, sizeof(secret));
    MD5_Update(&md5, ":", 1);
    MD5_Update(&md5, time_buf, strlen(time_buf));
    MD5_Final(hashbuf, &md5);
    enhex(hash_hex, hashbuf, sizeof(hashbuf));

    strbuf_sprintf(&buf, &size, &offset, "%s-%s", time_buf, hash_hex);

    return buf;
}

/* Arguments are assumed to be non-NULL, with the exception of nc and cnonce,
   which may be garbage only if qop == QOP_NONE. */
static void make_response(char buf[MD5_DIGEST_LENGTH * 2 + 1],
    const char *username, const char *realm, const char *password,
    const char *method, const char *uri, const char *nonce,
    enum http_digest_qop qop, const char *nc, const char *cnonce)
{
    char HA1_hex[MD5_DIGEST_LENGTH * 2 + 1], HA2_hex[MD5_DIGEST_LENGTH * 2 + 1];
    unsigned char hashbuf[MD5_DIGEST_LENGTH];
    MD5_CTX md5;

    /* Calculate H(A1). */
    MD5_Init(&md5);
    MD5_Update(&md5, username, strlen(username));
    MD5_Update(&md5, ":", 1);
    MD5_Update(&md5, realm, strlen(realm));
    MD5_Update(&md5, ":", 1);
    MD5_Update(&md5, password, strlen(password));
    MD5_Final(hashbuf, &md5);
    enhex(HA1_hex, hashbuf, sizeof(hashbuf));

    /* Calculate H(A2). */
    MD5_Init(&md5);
    MD5_Update(&md5, method, strlen(method));
    MD5_Update(&md5, ":", 1);
    MD5_Update(&md5, uri, strlen(uri));
    MD5_Final(hashbuf, &md5);
    enhex(HA2_hex, hashbuf, sizeof(hashbuf));

    /* Calculate response. */
    MD5_Init(&md5);
    MD5_Update(&md5, HA1_hex, strlen(HA1_hex));
    MD5_Update(&md5, ":", 1);
    MD5_Update(&md5, nonce, strlen(nonce));
    if (qop == QOP_AUTH) {
        MD5_Update(&md5, ":", 1);
        MD5_Update(&md5, nc, strlen(nc));
        MD5_Update(&md5, ":", 1);
        MD5_Update(&md5, cnonce, strlen(cnonce));
        MD5_Update(&md5, ":", 1);
        MD5_Update(&md5, "auth", strlen("auth"));
    }
    MD5_Update(&md5, ":", 1);
    MD5_Update(&md5, HA2_hex, strlen(HA2_hex));
    MD5_Final(hashbuf, &md5);

    enhex(buf, hashbuf, sizeof(hashbuf));
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

    char response_hex[MD5_DIGEST_LENGTH * 2 + 1];
    unsigned char cnonce[CNONCE_LENGTH];
    char cnonce_buf[CNONCE_LENGTH * 2 + 1];
    char nc_buf[8 + 1];
    char *buf = NULL;
    size_t size = 0, offset = 0;
    enum http_digest_qop qop;

    if (challenge->scheme != AUTH_DIGEST || challenge->realm == NULL
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
   expected. This doesn't do any checking aginst the lifetime of the nonce. */
int http_digest_check_credentials(const char *username, const char *realm,
    const char *password, const char *method,
    const struct http_credentials *credentials)
{
    char response_hex[MD5_DIGEST_LENGTH * 2 + 1];
    struct timeval tv;
    char *nonce;

    if (credentials->scheme != AUTH_DIGEST
        || credentials->u.digest.username == NULL
        || credentials->u.digest.realm == NULL
        || credentials->u.digest.nonce == NULL
        || credentials->u.digest.uri == NULL
        || credentials->u.digest.response == NULL) {
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
