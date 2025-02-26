/***************************************************************************
 * nsock_ssl.c -- This contains functions that relate somewhat exclusively *
 * to SSL (over TCP) support in nsock.  Where SSL support is incidental,   *
 * it is often in other files where code can be more easily shared between *
 * the SSL and NonSSL paths.                                               *
 *                                                                         *
 ***********************IMPORTANT NSOCK LICENSE TERMS***********************
 *
 * The nsock parallel socket event library is (C) 1999-2025 Nmap Software LLC
 * This library is free software; you may redistribute and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; Version 2. This guarantees your right to use, modify, and
 * redistribute this software under certain conditions. If this license is
 * unacceptable to you, Nmap Software LLC may be willing to sell alternative
 * licenses (contact sales@nmap.com ).
 *
 * As a special exception to the GPL terms, Nmap Software LLC grants permission
 * to link the code of this program with any version of the OpenSSL library
 * which is distributed under a license identical to that listed in the included
 * docs/licenses/OpenSSL.txt file, and distribute linked combinations including
 * the two. You must obey the GNU GPL in all respects for all of the code used
 * other than OpenSSL. If you modify this file, you may extend this exception to
 * your version of the file, but you are not obligated to do so.
 *
 * If you received these files with a written license agreement stating terms
 * other than the (GPL) terms above, then that alternative license agreement
 * takes precedence over this comment.
 *
 * Source is provided to this software because we believe users have a right to
 * know exactly what a program is going to do before they run it. This also
 * allows you to audit the software for security holes.
 *
 * Source code also allows you to port Nmap to new platforms, fix bugs, and add
 * new features. You are highly encouraged to send your changes to the
 * dev@nmap.org mailing list for possible incorporation into the main
 * distribution. By sending these changes to Fyodor or one of the Insecure.Org
 * development mailing lists, or checking them into the Nmap source code
 * repository, it is understood (unless you specify otherwise) that you are
 * offering the Nmap Project (Nmap Software LLC) the unlimited, non-exclusive
 * right to reuse, modify, and relicense the code. Nmap will always be available
 * Open Source, but this is important because the inability to relicense code
 * has caused devastating problems for other Free Software projects (such as KDE
 * and NASM). We also occasionally relicense the code to third parties as
 * discussed above. If you wish to specify special license conditions of your
 * contributions, just say so when you send them.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License v2.0 for more
 * details (http://www.gnu.org/licenses/gpl-2.0.html).
 *
 ***************************************************************************/

/* $Id$ */


#include "nsock.h"
#include "nsock_internal.h"
#include "nsock_log.h"
#include "nsock_ssl.h"
#include "netutils.h"

#if HAVE_OPENSSL
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif

/* Disallow anonymous ciphers (Diffie-Hellman key agreement), low bit-strength
 * ciphers, export-crippled ciphers, and MD5. Prefer ciphers in decreasing order
 * of key size. The cipher list is taken from the book Network Security with
 *  OpenSSL. To see exactly what ciphers are enabled, use the command
 *   openssl ciphers -v '...'
 * where ... is the string below. */
#define CIPHERS_SECURE "ALL:!aNULL:!eNULL:!LOW:!EXP:!RC4:!MD5:@STRENGTH"

/* This list of ciphers is for speed and compatibility, not security. Any cipher
 *  is accepted, and the list is sorted by speed based on Brian Hatch's
 *  (bri@ifokr.org) tests on an Pentium 686 against the ciphers listed. */
#define CIPHERS_FAST "RC4-SHA:RC4-MD5:NULL-SHA:EXP-DES-CBC-SHA:EXP-EDH-RSA-DES-CBC-SHA:EXP-RC4-MD5:NULL-MD5:EDH-RSA-DES-CBC-SHA:EXP-RC2-CBC-MD5:EDH-RSA-DES-CBC3-SHA:EXP-ADH-RC4-MD5:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:EXP-ADH-DES-CBC-SHA:ADH-AES256-SHA:ADH-DES-CBC-SHA:ADH-RC4-MD5:AES256-SHA:DES-CBC-SHA:DES-CBC3-SHA:ADH-DES-CBC3-SHA:AES128-SHA:ADH-AES128-SHA:eNULL:ALL"

#define NSOCK_SSL_STATE_UNINITIALIZED -1
#define NSOCK_SSL_STATE_INITIALIZED 1
#define NSOCK_SSL_STATE_ATEXIT 0
static int nsock_ssl_state = NSOCK_SSL_STATE_UNINITIALIZED;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined LIBRESSL_VERSION_NUMBER
static void nsock_ssl_atexit(void)
{
  nsock_ssl_state = NSOCK_SSL_STATE_ATEXIT;
}
#endif
void nsp_ssl_cleanup(struct npool *nsp)
{
  if (nsock_ssl_state != NSOCK_SSL_STATE_ATEXIT)
  {
    if (nsp->sslctx != NULL)
      SSL_CTX_free(nsp->sslctx);
#ifndef OPENSSL_NO_DTLS
    if (nsp->dtlsctx != NULL)
      SSL_CTX_free(nsp->dtlsctx);
#endif
  }
  nsp->sslctx = NULL;
#ifndef OPENSSL_NO_DTLS
  nsp->dtlsctx = NULL;
#endif
}

static SSL_CTX *ssl_init_helper(const SSL_METHOD *method) {
  SSL_CTX *ctx;

  if (nsock_ssl_state == NSOCK_SSL_STATE_UNINITIALIZED)
  {
    nsock_ssl_state = NSOCK_SSL_STATE_INITIALIZED;
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined LIBRESSL_VERSION_NUMBER
    SSL_load_error_strings();
    SSL_library_init();
#else
    OPENSSL_atexit(nsock_ssl_atexit);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (NULL == OSSL_PROVIDER_load(NULL, "legacy"))
    {
      nsock_log_info("OpenSSL legacy provider failed to load: %s",
          ERR_error_string(ERR_get_error(), NULL));
    }
    if (NULL == OSSL_PROVIDER_load(NULL, "default"))
    {
      nsock_log_error("OpenSSL default provider failed to load: %s",
          ERR_error_string(ERR_get_error(), NULL));
    }
#endif
#endif
  }

  ctx = SSL_CTX_new(method);
  if (!ctx) {
    fatal("OpenSSL failed to create a new SSL_CTX: %s",
          ERR_error_string(ERR_get_error(), NULL));
  }

  /* Our SSL* will always have the SSL_SESSION* inside it, so we neither need to
   * use nor waste memory for the session cache.  (Use '1' because '0' means
   * 'infinite'.)   */
  SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF|SSL_SESS_CACHE_NO_AUTO_CLEAR);
  SSL_CTX_sess_set_cache_size(ctx, 1);
  SSL_CTX_set_timeout(ctx, 3600); /* pretty unnecessary */

  return ctx;
}

/* Create an SSL_CTX and do initialization that is common to all init modes. */
static SSL_CTX *ssl_init_common() {
  return ssl_init_helper(SSLv23_client_method());
}

/* Initializes an Nsock pool to create SSL connections. This sets an internal
 * SSL_CTX, which is like a template that sets options for all connections that
 * are made from it. The connections made from this context will use only secure
 * ciphers but no server certificate verification is done. Returns the SSL_CTX
 * so you can set your own options. */
static nsock_ssl_ctx nsock_pool_ssl_init_helper(SSL_CTX *ctx, int flags) {
  char rndbuf[128];

  /* Get_random_bytes may or may not provide high-quality randomness. Add it to
   * the entropy pool without increasing the entropy estimate (third argument of
   * RAND_add is 0). We rely on OpenSSL's entropy gathering, called implicitly
   * by RAND_status, to give us what we need, or else bail out if it fails. */
  get_random_bytes(rndbuf, sizeof(rndbuf));
  RAND_add(rndbuf, sizeof(rndbuf), 0);

  if (!(flags & NSOCK_SSL_MAX_SPEED)) {
    if (!RAND_status())
      fatal("%s: Failed to seed OpenSSL PRNG"
            " (RAND_status returned false).", __func__);
  }

  /* SSL_OP_ALL sets bug-compatibility for pretty much everything.
   * SSL_OP_NO_SSLv2 disables the less-secure SSLv2 while allowing us to use the
   * SSLv2-compatible SSLv23_client_method. */
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  SSL_CTX_clear_options(ctx, SSL_OP_NO_SSLv2);
  SSL_CTX_set_options(ctx, flags & NSOCK_SSL_MAX_SPEED ?
                                  SSL_OP_ALL : SSL_OP_ALL|SSL_OP_NO_SSLv2);

  if (!SSL_CTX_set_cipher_list(ctx, flags & NSOCK_SSL_MAX_SPEED ?
                                           CIPHERS_FAST : CIPHERS_SECURE))
    fatal("Unable to set OpenSSL cipher list: %s",
          ERR_error_string(ERR_get_error(), NULL));

  return ctx;
}

nsock_ssl_ctx nsock_pool_ssl_init(nsock_pool ms_pool, int flags) {
  struct npool *ms = (struct npool *)ms_pool;

  if (ms->sslctx == NULL)
    ms->sslctx = ssl_init_common();
  return nsock_pool_ssl_init_helper(ms->sslctx, flags);
}

#ifndef OPENSSL_NO_DTLS

/* Create an SSL_CTX and do initialisation, creating a DTLS client */
static SSL_CTX *dtls_init_common() {
  return ssl_init_helper(DTLS_client_method());
}

/* Initializes an Nsock pool to create DTLS connections. Very much similar to
 * nsock_pool_ssl_init, just with DTLS. */
nsock_ssl_ctx nsock_pool_dtls_init(nsock_pool ms_pool, int flags) {
  SSL_CTX *dtls_ctx = NULL;
  struct npool *ms = (struct npool *)ms_pool;

  if (ms->dtlsctx == NULL)
    ms->dtlsctx = dtls_init_common();
  dtls_ctx = (SSL_CTX *) nsock_pool_ssl_init_helper(ms->dtlsctx, flags);

  /* Don't add padding or the ClientHello will fragment and not connect properly. */
  SSL_CTX_clear_options(dtls_ctx, SSL_OP_TLSEXT_PADDING);

  if (!SSL_CTX_set_cipher_list(dtls_ctx, "DEFAULT"))
    fatal("Unable to set OpenSSL cipher list: %s",
          ERR_error_string(ERR_get_error(), NULL));

  return dtls_ctx;
}

#else /* OpenSSL Version does not support DTLS */

nsock_ssl_ctx nsock_pool_dtls_init(nsock_pool ms_pool, int flags) {
  fatal("%s called with no OpenSSL DTLS support", __func__);
}

#endif

/* Check server certificate verification, after a connection is established. We
 * check first that a certificate was even offered, then call
 * SSL_get_verify_result to get the overall status of verification. (Just
 * calling SSL_get_verify_result is not enough because that function returns
 * X509_V_OK when 0 certificates are presented.) If the verification mode of the
 * SSL object is SSL_VERIFY_NONE, or if OpenSSL is disabled, this function
 * always returns true. */
int nsi_ssl_post_connect_verify(const nsock_iod nsockiod) {
  struct niod *iod = (struct niod *)nsockiod;

  assert(iod->ssl != NULL);
  if (SSL_get_verify_mode(iod->ssl) != SSL_VERIFY_NONE) {
    X509 *cert;

    cert = SSL_get_peer_certificate(iod->ssl);
    if (cert == NULL)
      /* No certificate presented. */
      return 0;

    X509_free(cert);

    if (SSL_get_verify_result(iod->ssl) != X509_V_OK)
      /* Something wrong with verification. */
      return 0;
  }
  return 1;
}

#else /* NOT HAVE_OPENSSL */

nsock_ssl_ctx nsock_pool_ssl_init(nsock_pool ms_pool, int flags) {
  fatal("%s called with no OpenSSL support", __func__);
}

nsock_ssl_ctx nsock_pool_dtls_init(nsock_pool ms_pool, int flags) {
  fatal("%s called with no OpenSSL support", __func__);
}

int nsi_ssl_post_connect_verify(const nsock_iod nsockiod) {
  return 1;
}

#endif
