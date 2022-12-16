/* Copyright (C) 2009, 2010 Simon Josefsson
 * Copyright (C) 2006, 2007 The Written Word, Inc.  All rights reserved.
 * Copyright (c) 2004-2006, Sara Golemon <sarag@libssh2.org>
 *
 * Author: Simon Josefsson
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 *   Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials
 *   provided with the distribution.
 *
 *   Neither the name of the copyright holder nor the names
 *   of any other contributors may be used to endorse or
 *   promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

#include "libssh2_priv.h"

#ifdef LIBSSH2_OPENSSL /* compile only if we build with openssl */

#include <string.h>
#include "misc.h"

#ifndef EVP_MAX_BLOCK_LENGTH
#define EVP_MAX_BLOCK_LENGTH 32
#endif

int
read_openssh_private_key_from_memory(void **key_ctx, LIBSSH2_SESSION *session,
                                     const char *key_type,
                                     const char *filedata,
                                     size_t filedata_len,
                                     unsigned const char *passphrase);

static unsigned char *
write_bn(unsigned char *buf, const BIGNUM *bn, int bn_bytes)
{
    unsigned char *p = buf;

    /* Left space for bn size which will be written below. */
    p += 4;

    *p = 0;
    BN_bn2bin(bn, p + 1);
    if(!(*(p + 1) & 0x80)) {
        memmove(p, p + 1, --bn_bytes);
    }
    _libssh2_htonu32(p - 4, bn_bytes);  /* Post write bn size. */

    return p + bn_bytes;
}

int
_libssh2_rsa_new(libssh2_rsa_ctx ** rsa,
                 const unsigned char *edata,
                 unsigned long elen,
                 const unsigned char *ndata,
                 unsigned long nlen,
                 const unsigned char *ddata,
                 unsigned long dlen,
                 const unsigned char *pdata,
                 unsigned long plen,
                 const unsigned char *qdata,
                 unsigned long qlen,
                 const unsigned char *e1data,
                 unsigned long e1len,
                 const unsigned char *e2data,
                 unsigned long e2len,
                 const unsigned char *coeffdata, unsigned long coefflen)
{
    BIGNUM * e;
    BIGNUM * n;
    BIGNUM * d = 0;
    BIGNUM * p = 0;
    BIGNUM * q = 0;
    BIGNUM * dmp1 = 0;
    BIGNUM * dmq1 = 0;
    BIGNUM * iqmp = 0;

    e = BN_new();
    BN_bin2bn(edata, elen, e);

    n = BN_new();
    BN_bin2bn(ndata, nlen, n);

    if(ddata) {
        d = BN_new();
        BN_bin2bn(ddata, dlen, d);

        p = BN_new();
        BN_bin2bn(pdata, plen, p);

        q = BN_new();
        BN_bin2bn(qdata, qlen, q);

        dmp1 = BN_new();
        BN_bin2bn(e1data, e1len, dmp1);

        dmq1 = BN_new();
        BN_bin2bn(e2data, e2len, dmq1);

        iqmp = BN_new();
        BN_bin2bn(coeffdata, coefflen, iqmp);
    }

    *rsa = RSA_new();
#ifdef HAVE_OPAQUE_STRUCTS
    RSA_set0_key(*rsa, n, e, d);
#else
    (*rsa)->e = e;
    (*rsa)->n = n;
    (*rsa)->d = d;
#endif

#ifdef HAVE_OPAQUE_STRUCTS
    RSA_set0_factors(*rsa, p, q);
#else
    (*rsa)->p = p;
    (*rsa)->q = q;
#endif

#ifdef HAVE_OPAQUE_STRUCTS
    RSA_set0_crt_params(*rsa, dmp1, dmq1, iqmp);
#else
    (*rsa)->dmp1 = dmp1;
    (*rsa)->dmq1 = dmq1;
    (*rsa)->iqmp = iqmp;
#endif
    return 0;
}

int
_libssh2_rsa_sha1_verify(libssh2_rsa_ctx * rsactx,
                         const unsigned char *sig,
                         unsigned long sig_len,
                         const unsigned char *m, unsigned long m_len)
{
    unsigned char hash[SHA_DIGEST_LENGTH];
    int ret;

    if(_libssh2_sha1(m, m_len, hash))
        return -1; /* failure */
    ret = RSA_verify(NID_sha1, hash, SHA_DIGEST_LENGTH,
                     (unsigned char *) sig, sig_len, rsactx);
    return (ret == 1) ? 0 : -1;
}

#if LIBSSH2_DSA
int
_libssh2_dsa_new(libssh2_dsa_ctx ** dsactx,
                 const unsigned char *p,
                 unsigned long p_len,
                 const unsigned char *q,
                 unsigned long q_len,
                 const unsigned char *g,
                 unsigned long g_len,
                 const unsigned char *y,
                 unsigned long y_len,
                 const unsigned char *x, unsigned long x_len)
{
    BIGNUM * p_bn;
    BIGNUM * q_bn;
    BIGNUM * g_bn;
    BIGNUM * pub_key;
    BIGNUM * priv_key = NULL;

    p_bn = BN_new();
    BN_bin2bn(p, p_len, p_bn);

    q_bn = BN_new();
    BN_bin2bn(q, q_len, q_bn);

    g_bn = BN_new();
    BN_bin2bn(g, g_len, g_bn);

    pub_key = BN_new();
    BN_bin2bn(y, y_len, pub_key);

    if(x_len) {
        priv_key = BN_new();
        BN_bin2bn(x, x_len, priv_key);
    }

    *dsactx = DSA_new();

#ifdef HAVE_OPAQUE_STRUCTS
    DSA_set0_pqg(*dsactx, p_bn, q_bn, g_bn);
#else
    (*dsactx)->p = p_bn;
    (*dsactx)->g = g_bn;
    (*dsactx)->q = q_bn;
#endif

#ifdef HAVE_OPAQUE_STRUCTS
    DSA_set0_key(*dsactx, pub_key, priv_key);
#else
    (*dsactx)->pub_key = pub_key;
    (*dsactx)->priv_key = priv_key;
#endif
    return 0;
}

int
_libssh2_dsa_sha1_verify(libssh2_dsa_ctx * dsactx,
                         const unsigned char *sig,
                         const unsigned char *m, unsigned long m_len)
{
    unsigned char hash[SHA_DIGEST_LENGTH];
    DSA_SIG * dsasig;
    BIGNUM * r;
    BIGNUM * s;
    int ret = -1;

    r = BN_new();
    BN_bin2bn(sig, 20, r);
    s = BN_new();
    BN_bin2bn(sig + 20, 20, s);

    dsasig = DSA_SIG_new();
#ifdef HAVE_OPAQUE_STRUCTS
    DSA_SIG_set0(dsasig, r, s);
#else
    dsasig->r = r;
    dsasig->s = s;
#endif
    if(!_libssh2_sha1(m, m_len, hash))
        /* _libssh2_sha1() succeeded */
        ret = DSA_do_verify(hash, SHA_DIGEST_LENGTH, dsasig, dsactx);

    DSA_SIG_free(dsasig);

    return (ret == 1) ? 0 : -1;
}
#endif /* LIBSSH_DSA */

#if LIBSSH2_ECDSA

/* _libssh2_ecdsa_get_curve_type
 *
 * returns key curve type that maps to libssh2_curve_type
 *
 */

libssh2_curve_type
_libssh2_ecdsa_get_curve_type(libssh2_ecdsa_ctx *ec_ctx)
{
    const EC_GROUP *group = EC_KEY_get0_group(ec_ctx);
    return EC_GROUP_get_curve_name(group);
}

/* _libssh2_ecdsa_curve_type_from_name
 *
 * returns 0 for success, key curve type that maps to libssh2_curve_type
 *
 */

int
_libssh2_ecdsa_curve_type_from_name(const char *name,
                                    libssh2_curve_type *out_type)
{
    int ret = 0;
    libssh2_curve_type type;

    if(name == NULL || strlen(name) != 19)
        return -1;

    if(strcmp(name, "ecdsa-sha2-nistp256") == 0)
        type = LIBSSH2_EC_CURVE_NISTP256;
    else if(strcmp(name, "ecdsa-sha2-nistp384") == 0)
        type = LIBSSH2_EC_CURVE_NISTP384;
    else if(strcmp(name, "ecdsa-sha2-nistp521") == 0)
        type = LIBSSH2_EC_CURVE_NISTP521;
    else {
        ret = -1;
    }

    if(ret == 0 && out_type) {
        *out_type = type;
    }

    return ret;
}

/* _libssh2_ecdsa_curve_name_with_octal_new
 *
 * Creates a new public key given an octal string, length and type
 *
 */

int
_libssh2_ecdsa_curve_name_with_octal_new(libssh2_ecdsa_ctx ** ec_ctx,
     const unsigned char *k,
     size_t k_len, libssh2_curve_type curve)
{

    int ret = 0;
    const EC_GROUP *ec_group = NULL;
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(curve);
    EC_POINT *point = NULL;

    if(ec_key) {
        ec_group = EC_KEY_get0_group(ec_key);
        point = EC_POINT_new(ec_group);
        ret = EC_POINT_oct2point(ec_group, point, k, k_len, NULL);
        ret = EC_KEY_set_public_key(ec_key, point);

        if(point != NULL)
            EC_POINT_free(point);

        if(ec_ctx != NULL)
            *ec_ctx = ec_key;
    }

    return (ret == 1) ? 0 : -1;
}

#define LIBSSH2_ECDSA_VERIFY(digest_type)                           \
{                                                                   \
    unsigned char hash[SHA##digest_type##_DIGEST_LENGTH];           \
    libssh2_sha##digest_type(m, m_len, hash);                       \
    ret = ECDSA_do_verify(hash, SHA##digest_type##_DIGEST_LENGTH,   \
      ecdsa_sig, ec_key);                                           \
                                                                    \
}

int
_libssh2_ecdsa_verify(libssh2_ecdsa_ctx * ctx,
      const unsigned char *r, size_t r_len,
      const unsigned char *s, size_t s_len,
      const unsigned char *m, size_t m_len)
{
    int ret = 0;
    EC_KEY *ec_key = (EC_KEY*)ctx;
    libssh2_curve_type type = _libssh2_ecdsa_get_curve_type(ec_key);

#ifdef HAVE_OPAQUE_STRUCTS
    ECDSA_SIG *ecdsa_sig = ECDSA_SIG_new();
    BIGNUM *pr = BN_new();
    BIGNUM *ps = BN_new();

    BN_bin2bn(r, r_len, pr);
    BN_bin2bn(s, s_len, ps);
    ECDSA_SIG_set0(ecdsa_sig, pr, ps);

#else
    ECDSA_SIG ecdsa_sig_;
    ECDSA_SIG *ecdsa_sig = &ecdsa_sig_;
    ecdsa_sig_.r = BN_new();
    BN_bin2bn(r, r_len, ecdsa_sig_.r);
    ecdsa_sig_.s = BN_new();
    BN_bin2bn(s, s_len, ecdsa_sig_.s);
#endif

    if(type == LIBSSH2_EC_CURVE_NISTP256) {
        LIBSSH2_ECDSA_VERIFY(256);
    }
    else if(type == LIBSSH2_EC_CURVE_NISTP384) {
        LIBSSH2_ECDSA_VERIFY(384);
    }
    else if(type == LIBSSH2_EC_CURVE_NISTP521) {
        LIBSSH2_ECDSA_VERIFY(512);
    }

#ifdef HAVE_OPAQUE_STRUCTS
    if(ecdsa_sig)
        ECDSA_SIG_free(ecdsa_sig);
#else
    BN_clear_free(ecdsa_sig_.s);
    BN_clear_free(ecdsa_sig_.r);
#endif

    return (ret == 1) ? 0 : -1;
}

#endif /* LIBSSH2_ECDSA */

int
_libssh2_cipher_init(_libssh2_cipher_ctx * h,
                     _libssh2_cipher_type(algo),
                     unsigned char *iv, unsigned char *secret, int encrypt)
{
#ifdef HAVE_OPAQUE_STRUCTS
    *h = EVP_CIPHER_CTX_new();
    return !EVP_CipherInit(*h, algo(), secret, iv, encrypt);
#else
    EVP_CIPHER_CTX_init(h);
    return !EVP_CipherInit(h, algo(), secret, iv, encrypt);
#endif
}

int
_libssh2_cipher_crypt(_libssh2_cipher_ctx * ctx,
                      _libssh2_cipher_type(algo),
                      int encrypt, unsigned char *block, size_t blocksize)
{
    unsigned char buf[EVP_MAX_BLOCK_LENGTH];
    int ret;
    (void) algo;
    (void) encrypt;

#ifdef HAVE_OPAQUE_STRUCTS
    ret = EVP_Cipher(*ctx, buf, block, blocksize);
#else
    ret = EVP_Cipher(ctx, buf, block, blocksize);
#endif
#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
    if(ret != -1) {
#else
    if(ret == 1) {
#endif
        memcpy(block, buf, blocksize);
    }

#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
    return ret != -1 ? 0 : 1;
#else
    return ret == 1 ? 0 : 1;
#endif
}

#if LIBSSH2_AES_CTR && !defined(HAVE_EVP_AES_128_CTR)

#include <openssl/aes.h>
#include <openssl/evp.h>

typedef struct
{
    AES_KEY       key;
    EVP_CIPHER_CTX *aes_ctx;
    unsigned char ctr[AES_BLOCK_SIZE];
} aes_ctr_ctx;

static EVP_CIPHER * aes_128_ctr_cipher = NULL;
static EVP_CIPHER * aes_192_ctr_cipher = NULL;
static EVP_CIPHER * aes_256_ctr_cipher = NULL;

static int
aes_ctr_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
             const unsigned char *iv, int enc) /* init key */
{
    /*
     * variable "c" is leaked from this scope, but is later freed
     * in aes_ctr_cleanup
     */
    aes_ctr_ctx *c;
    const EVP_CIPHER *aes_cipher;
    (void) enc;

    switch(EVP_CIPHER_CTX_key_length(ctx)) {
    case 16:
        aes_cipher = EVP_aes_128_ecb();
        break;
    case 24:
        aes_cipher = EVP_aes_192_ecb();
        break;
    case 32:
        aes_cipher = EVP_aes_256_ecb();
        break;
    default:
        return 0;
    }

    c = malloc(sizeof(*c));
    if(c == NULL)
        return 0;

#ifdef HAVE_OPAQUE_STRUCTS
    c->aes_ctx = EVP_CIPHER_CTX_new();
#else
    c->aes_ctx = malloc(sizeof(EVP_CIPHER_CTX));
#endif
    if(c->aes_ctx == NULL) {
        free(c);
        return 0;
    }

    if(EVP_EncryptInit(c->aes_ctx, aes_cipher, key, NULL) != 1) {
#ifdef HAVE_OPAQUE_STRUCTS
        EVP_CIPHER_CTX_free(c->aes_ctx);
#else
        free(c->aes_ctx);
#endif
        free(c);
        return 0;
    }

    EVP_CIPHER_CTX_set_padding(c->aes_ctx, 0);

    memcpy(c->ctr, iv, AES_BLOCK_SIZE);

    EVP_CIPHER_CTX_set_app_data(ctx, c);

    return 1;
}

static int
aes_ctr_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                  const unsigned char *in,
                  size_t inl) /* encrypt/decrypt data */
{
    aes_ctr_ctx *c = EVP_CIPHER_CTX_get_app_data(ctx);
    unsigned char b1[AES_BLOCK_SIZE];
    int outlen = 0;

    if(inl != 16) /* libssh2 only ever encrypt one block */
        return 0;

    if(c == NULL) {
        return 0;
    }

/*
  To encrypt a packet P=P1||P2||...||Pn (where P1, P2, ..., Pn are each
  blocks of length L), the encryptor first encrypts <X> with <cipher>
  to obtain a block B1.  The block B1 is then XORed with P1 to generate
  the ciphertext block C1.  The counter X is then incremented
*/

    if(EVP_EncryptUpdate(c->aes_ctx, b1, &outlen,
                         c->ctr, AES_BLOCK_SIZE) != 1) {
        return 0;
    }

    _libssh2_xor_data(out, in, b1, AES_BLOCK_SIZE);
    _libssh2_aes_ctr_increment(c->ctr, AES_BLOCK_SIZE);

    return 1;
}

static int
aes_ctr_cleanup(EVP_CIPHER_CTX *ctx) /* cleanup ctx */
{
    aes_ctr_ctx *c = EVP_CIPHER_CTX_get_app_data(ctx);

    if(c == NULL) {
        return 1;
    }

    if(c->aes_ctx != NULL) {
#ifdef HAVE_OPAQUE_STRUCTS
        EVP_CIPHER_CTX_free(c->aes_ctx);
#else
        _libssh2_cipher_dtor(c->aes_ctx);
        free(c->aes_ctx);
#endif
    }

    free(c);

    return 1;
}

static const EVP_CIPHER *
make_ctr_evp (size_t keylen, EVP_CIPHER **aes_ctr_cipher, int type)
{
#ifdef HAVE_OPAQUE_STRUCTS
    *aes_ctr_cipher = EVP_CIPHER_meth_new(type, 16, keylen);
    if(*aes_ctr_cipher) {
        EVP_CIPHER_meth_set_iv_length(*aes_ctr_cipher, 16);
        EVP_CIPHER_meth_set_init(*aes_ctr_cipher, aes_ctr_init);
        EVP_CIPHER_meth_set_do_cipher(*aes_ctr_cipher, aes_ctr_do_cipher);
        EVP_CIPHER_meth_set_cleanup(*aes_ctr_cipher, aes_ctr_cleanup);
    }
#else
    (*aes_ctr_cipher)->nid = type;
    (*aes_ctr_cipher)->block_size = 16;
    (*aes_ctr_cipher)->key_len = keylen;
    (*aes_ctr_cipher)->iv_len = 16;
    (*aes_ctr_cipher)->init = aes_ctr_init;
    (*aes_ctr_cipher)->do_cipher = aes_ctr_do_cipher;
    (*aes_ctr_cipher)->cleanup = aes_ctr_cleanup;
#endif

    return *aes_ctr_cipher;
}

const EVP_CIPHER *
_libssh2_EVP_aes_128_ctr(void)
{
#ifdef HAVE_OPAQUE_STRUCTS
    return !aes_128_ctr_cipher ?
        make_ctr_evp(16, &aes_128_ctr_cipher, NID_aes_128_ctr) :
        aes_128_ctr_cipher;
#else
    static EVP_CIPHER aes_ctr_cipher;
    if(!aes_128_ctr_cipher) {
        aes_128_ctr_cipher = &aes_ctr_cipher;
        make_ctr_evp(16, &aes_128_ctr_cipher, 0);
    }
    return aes_128_ctr_cipher;
#endif
}

const EVP_CIPHER *
_libssh2_EVP_aes_192_ctr(void)
{
#ifdef HAVE_OPAQUE_STRUCTS
    return !aes_192_ctr_cipher ?
        make_ctr_evp(24, &aes_192_ctr_cipher, NID_aes_192_ctr) :
        aes_192_ctr_cipher;
#else
    static EVP_CIPHER aes_ctr_cipher;
    if(!aes_192_ctr_cipher) {
        aes_192_ctr_cipher = &aes_ctr_cipher;
        make_ctr_evp(24, &aes_192_ctr_cipher, 0);
    }
    return aes_192_ctr_cipher;
#endif
}

const EVP_CIPHER *
_libssh2_EVP_aes_256_ctr(void)
{
#ifdef HAVE_OPAQUE_STRUCTS
    return !aes_256_ctr_cipher ?
        make_ctr_evp(32, &aes_256_ctr_cipher, NID_aes_256_ctr) :
        aes_256_ctr_cipher;
#else
    static EVP_CIPHER aes_ctr_cipher;
    if(!aes_256_ctr_cipher) {
        aes_256_ctr_cipher = &aes_ctr_cipher;
        make_ctr_evp(32, &aes_256_ctr_cipher, 0);
    }
    return aes_256_ctr_cipher;
#endif
}

#endif /* LIBSSH2_AES_CTR && !defined(HAVE_EVP_AES_128_CTR) */

void _libssh2_openssl_crypto_init(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(LIBRESSL_VERSION_NUMBER)
#ifndef OPENSSL_NO_ENGINE
    ENGINE_load_builtin_engines();
    ENGINE_register_all_complete();
#endif
#else
    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();
#ifndef OPENSSL_NO_ENGINE
    ENGINE_load_builtin_engines();
    ENGINE_register_all_complete();
#endif
#endif
#if LIBSSH2_AES_CTR && !defined(HAVE_EVP_AES_128_CTR)
    aes_128_ctr_cipher = (EVP_CIPHER *) _libssh2_EVP_aes_128_ctr();
    aes_192_ctr_cipher = (EVP_CIPHER *) _libssh2_EVP_aes_192_ctr();
    aes_256_ctr_cipher = (EVP_CIPHER *) _libssh2_EVP_aes_256_ctr();
#endif
}

void _libssh2_openssl_crypto_exit(void)
{
#if LIBSSH2_AES_CTR && !defined(HAVE_EVP_AES_128_CTR)
#ifdef HAVE_OPAQUE_STRUCTS
    if(aes_128_ctr_cipher) {
        EVP_CIPHER_meth_free(aes_128_ctr_cipher);
    }

    if(aes_192_ctr_cipher) {
        EVP_CIPHER_meth_free(aes_192_ctr_cipher);
    }

    if(aes_256_ctr_cipher) {
        EVP_CIPHER_meth_free(aes_256_ctr_cipher);
    }
#endif

    aes_128_ctr_cipher = NULL;
    aes_192_ctr_cipher = NULL;
    aes_256_ctr_cipher = NULL;
#endif
}

/* TODO: Optionally call a passphrase callback specified by the
 * calling program
 */
static int
passphrase_cb(char *buf, int size, int rwflag, char *passphrase)
{
    int passphrase_len = strlen(passphrase);
    (void) rwflag;

    if(passphrase_len > (size - 1)) {
        passphrase_len = size - 1;
    }
    memcpy(buf, passphrase, passphrase_len);
    buf[passphrase_len] = '\0';

    return passphrase_len;
}

typedef void * (*pem_read_bio_func)(BIO *, void **, pem_password_cb *,
                                    void *u);

static int
read_private_key_from_memory(void **key_ctx,
                             pem_read_bio_func read_private_key,
                             const char *filedata,
                             size_t filedata_len,
                             unsigned const char *passphrase)
{
    BIO * bp;

    *key_ctx = NULL;

    bp = BIO_new_mem_buf((char *)filedata, filedata_len);
    if(!bp) {
        return -1;
    }
    *key_ctx = read_private_key(bp, NULL, (pem_password_cb *) passphrase_cb,
                                (void *) passphrase);

    BIO_free(bp);
    return (*key_ctx) ? 0 : -1;
}



static int
read_private_key_from_file(void **key_ctx,
                           pem_read_bio_func read_private_key,
                           const char *filename,
                           unsigned const char *passphrase)
{
    BIO * bp;

    *key_ctx = NULL;

    bp = BIO_new_file(filename, "r");
    if(!bp) {
        return -1;
    }

    *key_ctx = read_private_key(bp, NULL, (pem_password_cb *) passphrase_cb,
                                (void *) passphrase);

    BIO_free(bp);
    return (*key_ctx) ? 0 : -1;
}

int
_libssh2_rsa_new_private_frommemory(libssh2_rsa_ctx ** rsa,
                                    LIBSSH2_SESSION * session,
                                    const char *filedata, size_t filedata_len,
                                    unsigned const char *passphrase)
{
    int rc;

    pem_read_bio_func read_rsa =
        (pem_read_bio_func) &PEM_read_bio_RSAPrivateKey;

    _libssh2_init_if_needed();

    rc = read_private_key_from_memory((void **) rsa, read_rsa,
                                      filedata, filedata_len, passphrase);

    if(rc) {
        rc = read_openssh_private_key_from_memory((void **)rsa, session,
                        "ssh-rsa", filedata, filedata_len, passphrase);
    }

return rc;
}

static unsigned char *
gen_publickey_from_rsa(LIBSSH2_SESSION *session, RSA *rsa,
                       size_t *key_len)
{
    int            e_bytes, n_bytes;
    unsigned long  len;
    unsigned char *key;
    unsigned char *p;
    const BIGNUM * e;
    const BIGNUM * n;
#ifdef HAVE_OPAQUE_STRUCTS
    RSA_get0_key(rsa, &n, &e, NULL);
#else
    e = rsa->e;
    n = rsa->n;
#endif
    e_bytes = BN_num_bytes(e) + 1;
    n_bytes = BN_num_bytes(n) + 1;

    /* Key form is "ssh-rsa" + e + n. */
    len = 4 + 7 + 4 + e_bytes + 4 + n_bytes;

    key = LIBSSH2_ALLOC(session, len);
    if(key == NULL) {
        return NULL;
    }

    /* Process key encoding. */
    p = key;

    _libssh2_htonu32(p, 7);  /* Key type. */
    p += 4;
    memcpy(p, "ssh-rsa", 7);
    p += 7;

    p = write_bn(p, e, e_bytes);
    p = write_bn(p, n, n_bytes);

    *key_len = (size_t)(p - key);
    return key;
}

static int
gen_publickey_from_rsa_evp(LIBSSH2_SESSION *session,
                           unsigned char **method,
                           size_t *method_len,
                           unsigned char **pubkeydata,
                           size_t *pubkeydata_len,
                           EVP_PKEY *pk)
{
    RSA*           rsa = NULL;
    unsigned char *key;
    unsigned char *method_buf = NULL;
    size_t  key_len;

    _libssh2_debug(session,
                   LIBSSH2_TRACE_AUTH,
                   "Computing public key from RSA private key envelope");

    rsa = EVP_PKEY_get1_RSA(pk);
    if(rsa == NULL) {
        /* Assume memory allocation error... what else could it be ? */
        goto __alloc_error;
    }

    method_buf = LIBSSH2_ALLOC(session, 7);  /* ssh-rsa. */
    if(method_buf == NULL) {
        goto __alloc_error;
    }

    key = gen_publickey_from_rsa(session, rsa, &key_len);
    if(key == NULL) {
        goto __alloc_error;
    }
    RSA_free(rsa);

    memcpy(method_buf, "ssh-rsa", 7);
    *method         = method_buf;
    *method_len     = 7;
    *pubkeydata     = key;
    *pubkeydata_len = key_len;
    return 0;

  __alloc_error:
    if(rsa != NULL) {
        RSA_free(rsa);
    }
    if(method_buf != NULL) {
        LIBSSH2_FREE(session, method_buf);
    }

    return _libssh2_error(session,
                          LIBSSH2_ERROR_ALLOC,
                          "Unable to allocate memory for private key data");
}

static int _libssh2_rsa_new_additional_parameters(RSA *rsa)
{
    BN_CTX *ctx = NULL;
    BIGNUM *aux = NULL;
    BIGNUM *dmp1 = NULL;
    BIGNUM *dmq1 = NULL;
    const BIGNUM *p = NULL;
    const BIGNUM *q = NULL;
    const BIGNUM *d = NULL;
    int rc = 0;

#ifdef HAVE_OPAQUE_STRUCTS
    RSA_get0_key(rsa, NULL, NULL, &d);
    RSA_get0_factors(rsa, &p, &q);
#else
    d = (*rsa).d;
    p = (*rsa).p;
    q = (*rsa).q;
#endif

    ctx = BN_CTX_new();
    if(ctx == NULL)
        return -1;

    aux = BN_new();
    if(aux == NULL) {
        rc = -1;
        goto out;
    }

    dmp1 = BN_new();
    if(dmp1 == NULL) {
        rc = -1;
        goto out;
    }

    dmq1 = BN_new();
    if(dmq1 == NULL) {
        rc = -1;
        goto out;
    }

    if((BN_sub(aux, q, BN_value_one()) == 0) ||
        (BN_mod(dmq1, d, aux, ctx) == 0) ||
        (BN_sub(aux, p, BN_value_one()) == 0) ||
        (BN_mod(dmp1, d, aux, ctx) == 0)) {
        rc = -1;
        goto out;
    }

#ifdef HAVE_OPAQUE_STRUCTS
    RSA_set0_crt_params(rsa, dmp1, dmq1, NULL);
#else
    (*rsa).dmp1 = dmp1;
    (*rsa).dmq1 = dmq1;
#endif

out:
    if(aux)
        BN_clear_free(aux);
    BN_CTX_free(ctx);

    if(rc != 0) {
        if(dmp1)
            BN_clear_free(dmp1);
        if(dmq1)
            BN_clear_free(dmq1);
    }

    return rc;
}

static int
gen_publickey_from_rsa_openssh_priv_data(LIBSSH2_SESSION *session,
                                         struct string_buf *decrypted,
                                         unsigned char **method,
                                         size_t *method_len,
                                         unsigned char **pubkeydata,
                                         size_t *pubkeydata_len,
                                         libssh2_rsa_ctx **rsa_ctx)
{
    int rc = 0;
    size_t nlen, elen, dlen, plen, qlen, coefflen, commentlen;
    unsigned char *n, *e, *d, *p, *q, *coeff, *comment;
    RSA *rsa = NULL;

    _libssh2_debug(session,
                   LIBSSH2_TRACE_AUTH,
                   "Computing RSA keys from private key data");

    /* public key data */
    if(_libssh2_get_bignum_bytes(decrypted, &n, &nlen)) {
        _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                       "RSA no n");
        return -1;
    }

    if(_libssh2_get_bignum_bytes(decrypted, &e, &elen)) {
        _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                       "RSA no e");
        return -1;
    }

    /* private key data */
    if(_libssh2_get_bignum_bytes(decrypted, &d, &dlen)) {
        _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                       "RSA no d");
        return -1;
    }

    if(_libssh2_get_bignum_bytes(decrypted, &coeff, &coefflen)) {
        _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                       "RSA no coeff");
        return -1;
    }

    if(_libssh2_get_bignum_bytes(decrypted, &p, &plen)) {
        _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                       "RSA no p");
        return -1;
    }

    if(_libssh2_get_bignum_bytes(decrypted, &q, &qlen)) {
        _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                       "RSA no q");
        return -1;
    }

    if(_libssh2_get_string(decrypted, &comment, &commentlen)) {
        _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                       "RSA no comment");
        return -1;
    }

    if((rc = _libssh2_rsa_new(&rsa, e, elen, n, nlen, d, dlen, p, plen,
                              q, qlen, NULL, 0, NULL, 0,
                              coeff, coefflen)) != 0) {
        _libssh2_debug(session,
                       LIBSSH2_TRACE_AUTH,
                       "Could not create RSA private key");
        goto fail;
    }

    if(rsa != NULL)
        rc = _libssh2_rsa_new_additional_parameters(rsa);

    if(rsa != NULL && pubkeydata != NULL && method != NULL) {
        EVP_PKEY *pk = EVP_PKEY_new();
        EVP_PKEY_set1_RSA(pk, rsa);

        rc = gen_publickey_from_rsa_evp(session, method, method_len,
                                        pubkeydata, pubkeydata_len,
                                        pk);

        if(pk)
            EVP_PKEY_free(pk);
    }

    if(rsa_ctx != NULL)
        *rsa_ctx = rsa;
    else
        RSA_free(rsa);

    return rc;

fail:

    if(rsa != NULL)
        RSA_free(rsa);

    return _libssh2_error(session,
                          LIBSSH2_ERROR_ALLOC,
                          "Unable to allocate memory for private key data");
}

static int
_libssh2_rsa_new_openssh_private(libssh2_rsa_ctx ** rsa,
                                 LIBSSH2_SESSION * session,
                                 const char *filename,
                                 unsigned const char *passphrase)
{
    FILE *fp;
    int rc;
    unsigned char *buf = NULL;
    struct string_buf *decrypted = NULL;

    if(session == NULL) {
        _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                       "Session is required");
        return -1;
    }

    _libssh2_init_if_needed();

    fp = fopen(filename, "r");
    if(!fp) {
        _libssh2_error(session, LIBSSH2_ERROR_FILE,
                       "Unable to open OpenSSH RSA private key file");
        return -1;
    }

    rc = _libssh2_openssh_pem_parse(session, passphrase, fp, &decrypted);
    fclose(fp);
    if(rc) {
        return rc;
    }

    /* We have a new key file, now try and parse it using supported types  */
    rc = _libssh2_get_string(decrypted, &buf, NULL);

    if(rc != 0 || buf == NULL) {
        _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                       "Public key type in decrypted key data not found");
        return -1;
    }

    if(strcmp("ssh-rsa", (const char *)buf) == 0) {
        rc = gen_publickey_from_rsa_openssh_priv_data(session, decrypted,
                                                      NULL, 0,
                                                      NULL, 0, rsa);
    }
    else {
        rc = -1;
    }

    if(decrypted)
        _libssh2_string_buf_free(session, decrypted);

    return rc;
}

int
_libssh2_rsa_new_private(libssh2_rsa_ctx ** rsa,
                         LIBSSH2_SESSION * session,
                         const char *filename, unsigned const char *passphrase)
{
    int rc;

    pem_read_bio_func read_rsa =
        (pem_read_bio_func) &PEM_read_bio_RSAPrivateKey;

    _libssh2_init_if_needed();

    rc = read_private_key_from_file((void **) rsa, read_rsa,
                                    filename, passphrase);

    if(rc) {
        rc = _libssh2_rsa_new_openssh_private(rsa, session,
                                              filename, passphrase);
    }

    return rc;
}

#if LIBSSH2_DSA
int
_libssh2_dsa_new_private_frommemory(libssh2_dsa_ctx ** dsa,
                                    LIBSSH2_SESSION * session,
                                    const char *filedata, size_t filedata_len,
                                    unsigned const char *passphrase)
{
    int rc;

    pem_read_bio_func read_dsa =
        (pem_read_bio_func) &PEM_read_bio_DSAPrivateKey;

    _libssh2_init_if_needed();

    rc = read_private_key_from_memory((void **)dsa, read_dsa,
                                      filedata, filedata_len, passphrase);

    if(rc) {
        rc = read_openssh_private_key_from_memory((void **)dsa, session,
                            "ssh-dsa", filedata, filedata_len, passphrase);
    }

    return rc;
}

static unsigned char *
gen_publickey_from_dsa(LIBSSH2_SESSION* session, DSA *dsa,
                       size_t *key_len)
{
    int            p_bytes, q_bytes, g_bytes, k_bytes;
    unsigned long  len;
    unsigned char *key;
    unsigned char *p;

    const BIGNUM * p_bn;
    const BIGNUM * q;
    const BIGNUM * g;
    const BIGNUM * pub_key;
#ifdef HAVE_OPAQUE_STRUCTS
    DSA_get0_pqg(dsa, &p_bn, &q, &g);
#else
    p_bn = dsa->p;
    q = dsa->q;
    g = dsa->g;
#endif

#ifdef HAVE_OPAQUE_STRUCTS
    DSA_get0_key(dsa, &pub_key, NULL);
#else
    pub_key = dsa->pub_key;
#endif
    p_bytes = BN_num_bytes(p_bn) + 1;
    q_bytes = BN_num_bytes(q) + 1;
    g_bytes = BN_num_bytes(g) + 1;
    k_bytes = BN_num_bytes(pub_key) + 1;

    /* Key form is "ssh-dss" + p + q + g + pub_key. */
    len = 4 + 7 + 4 + p_bytes + 4 + q_bytes + 4 + g_bytes + 4 + k_bytes;

    key = LIBSSH2_ALLOC(session, len);
    if(key == NULL) {
        return NULL;
    }

    /* Process key encoding. */
    p = key;

    _libssh2_htonu32(p, 7);  /* Key type. */
    p += 4;
    memcpy(p, "ssh-dss", 7);
    p += 7;

    p = write_bn(p, p_bn, p_bytes);
    p = write_bn(p, q, q_bytes);
    p = write_bn(p, g, g_bytes);
    p = write_bn(p, pub_key, k_bytes);

    *key_len = (size_t)(p - key);
    return key;
}

static int
gen_publickey_from_dsa_evp(LIBSSH2_SESSION *session,
                           unsigned char **method,
                           size_t *method_len,
                           unsigned char **pubkeydata,
                           size_t *pubkeydata_len,
                           EVP_PKEY *pk)
{
    DSA*           dsa = NULL;
    unsigned char *key;
    unsigned char *method_buf = NULL;
    size_t  key_len;

    _libssh2_debug(session,
                   LIBSSH2_TRACE_AUTH,
                   "Computing public key from DSA private key envelope");

    dsa = EVP_PKEY_get1_DSA(pk);
    if(dsa == NULL) {
        /* Assume memory allocation error... what else could it be ? */
        goto __alloc_error;
    }

    method_buf = LIBSSH2_ALLOC(session, 7);  /* ssh-dss. */
    if(method_buf == NULL) {
        goto __alloc_error;
    }

    key = gen_publickey_from_dsa(session, dsa, &key_len);
    if(key == NULL) {
        goto __alloc_error;
    }
    DSA_free(dsa);

    memcpy(method_buf, "ssh-dss", 7);
    *method         = method_buf;
    *method_len     = 7;
    *pubkeydata     = key;
    *pubkeydata_len = key_len;
    return 0;

  __alloc_error:
    if(dsa != NULL) {
        DSA_free(dsa);
    }
    if(method_buf != NULL) {
        LIBSSH2_FREE(session, method_buf);
    }

    return _libssh2_error(session,
                          LIBSSH2_ERROR_ALLOC,
                          "Unable to allocate memory for private key data");
}

static int
gen_publickey_from_dsa_openssh_priv_data(LIBSSH2_SESSION *session,
                                         struct string_buf *decrypted,
                                         unsigned char **method,
                                         size_t *method_len,
                                         unsigned char **pubkeydata,
                                         size_t *pubkeydata_len,
                                         libssh2_dsa_ctx **dsa_ctx)
{
    int rc = 0;
    size_t plen, qlen, glen, pub_len, priv_len;
    unsigned char *p, *q, *g, *pub_key, *priv_key;
    DSA *dsa = NULL;

    _libssh2_debug(session,
                   LIBSSH2_TRACE_AUTH,
                   "Computing DSA keys from private key data");

    if(_libssh2_get_bignum_bytes(decrypted, &p, &plen)) {
        _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                       "DSA no p");
        return -1;
    }

    if(_libssh2_get_bignum_bytes(decrypted, &q, &qlen)) {
        _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                       "DSA no q");
        return -1;
    }

    if(_libssh2_get_bignum_bytes(decrypted, &g, &glen)) {
        _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                       "DSA no g");
        return -1;
    }

    if(_libssh2_get_bignum_bytes(decrypted, &pub_key, &pub_len)) {
        _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                       "DSA no public key");
        return -1;
    }

    if(_libssh2_get_bignum_bytes(decrypted, &priv_key, &priv_len)) {
        _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                       "DSA no private key");
        return -1;
    }

    rc = _libssh2_dsa_new(&dsa, p, plen, q, qlen, g, glen, pub_key, pub_len,
                          priv_key, priv_len);
    if(rc != 0) {
        _libssh2_debug(session,
                       LIBSSH2_ERROR_PROTO,
                       "Could not create DSA private key");
        goto fail;
    }

    if(dsa != NULL && pubkeydata != NULL && method != NULL) {
        EVP_PKEY *pk = EVP_PKEY_new();
        EVP_PKEY_set1_DSA(pk, dsa);

        rc = gen_publickey_from_dsa_evp(session, method, method_len,
                                        pubkeydata, pubkeydata_len,
                                        pk);

        if(pk)
            EVP_PKEY_free(pk);
    }

    if(dsa_ctx != NULL)
        *dsa_ctx = dsa;
    else
        DSA_free(dsa);

    return rc;

fail:

    if(dsa != NULL)
        DSA_free(dsa);

    return _libssh2_error(session,
                          LIBSSH2_ERROR_ALLOC,
                          "Unable to allocate memory for private key data");
}

static int
_libssh2_dsa_new_openssh_private(libssh2_dsa_ctx ** dsa,
                                 LIBSSH2_SESSION * session,
                                 const char *filename,
                                 unsigned const char *passphrase)
{
    FILE *fp;
    int rc;
    unsigned char *buf = NULL;
    struct string_buf *decrypted = NULL;

    if(session == NULL) {
        _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                       "Session is required");
        return -1;
    }

    _libssh2_init_if_needed();

    fp = fopen(filename, "r");
    if(!fp) {
        _libssh2_error(session, LIBSSH2_ERROR_FILE,
                       "Unable to open OpenSSH DSA private key file");
        return -1;
    }

    rc = _libssh2_openssh_pem_parse(session, passphrase, fp, &decrypted);
    fclose(fp);
    if(rc) {
        return rc;
    }

    /* We have a new key file, now try and parse it using supported types  */
    rc = _libssh2_get_string(decrypted, &buf, NULL);

    if(rc != 0 || buf == NULL) {
        _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                       "Public key type in decrypted key data not found");
        return -1;
    }

    if(strcmp("ssh-dss", (const char *)buf) == 0) {
        rc = gen_publickey_from_dsa_openssh_priv_data(session, decrypted,
                                                      NULL, 0,
                                                      NULL, 0, dsa);
    }
    else {
        rc = -1;
    }

    if(decrypted)
        _libssh2_string_buf_free(session, decrypted);

    return rc;
}

int
_libssh2_dsa_new_private(libssh2_dsa_ctx ** dsa,
                         LIBSSH2_SESSION * session,
                         const char *filename, unsigned const char *passphrase)
{
    int rc;

    pem_read_bio_func read_dsa =
        (pem_read_bio_func) &PEM_read_bio_DSAPrivateKey;

    _libssh2_init_if_needed();

    rc = read_private_key_from_file((void **) dsa, read_dsa,
                                    filename, passphrase);

    if(rc) {
        rc = _libssh2_dsa_new_openssh_private(dsa, session,
                                              filename, passphrase);
    }

    return rc;
}

#endif /* LIBSSH_DSA */

#if LIBSSH2_ECDSA

int
_libssh2_ecdsa_new_private_frommemory(libssh2_ecdsa_ctx ** ec_ctx,
                                    LIBSSH2_SESSION * session,
                                    const char *filedata, size_t filedata_len,
                                    unsigned const char *passphrase)
{
    int rc;

    pem_read_bio_func read_ec =
        (pem_read_bio_func) &PEM_read_bio_ECPrivateKey;

    _libssh2_init_if_needed();

    rc = read_private_key_from_memory((void **) ec_ctx, read_ec,
                                      filedata, filedata_len, passphrase);

    if(rc) {
        rc = read_openssh_private_key_from_memory((void **)ec_ctx, session,
                                                  "ssh-ecdsa", filedata,
                                                  filedata_len, passphrase);
    }

    return rc;
}

#endif /* LIBSSH2_ECDSA */


#if LIBSSH2_ED25519

int
_libssh2_curve25519_new(LIBSSH2_SESSION *session,
                        unsigned char **out_public_key,
                        unsigned char **out_private_key)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char *priv = NULL, *pub = NULL;
    size_t privLen, pubLen;
    int rc = -1;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if(pctx == NULL)
        return -1;

    if(EVP_PKEY_keygen_init(pctx) != 1 ||
       EVP_PKEY_keygen(pctx, &key) != 1) {
        goto cleanExit;
    }

    if(out_private_key != NULL) {
        privLen = LIBSSH2_ED25519_KEY_LEN;
        priv = LIBSSH2_ALLOC(session, privLen);
        if(priv == NULL)
            goto cleanExit;

        if(EVP_PKEY_get_raw_private_key(key, priv, &privLen) != 1 ||
           privLen != LIBSSH2_ED25519_KEY_LEN) {
            goto cleanExit;
        }

        *out_private_key = priv;
        priv = NULL;
    }

    if(out_public_key != NULL) {
        pubLen = LIBSSH2_ED25519_KEY_LEN;
        pub = LIBSSH2_ALLOC(session, pubLen);
        if(pub == NULL)
            goto cleanExit;

        if(EVP_PKEY_get_raw_public_key(key, pub, &pubLen) != 1 ||
           pubLen != LIBSSH2_ED25519_KEY_LEN) {
            goto cleanExit;
        }

        *out_public_key = pub;
        pub = NULL;
    }

    /* success */
    rc = 0;

cleanExit:

    if(pctx)
        EVP_PKEY_CTX_free(pctx);
    if(key)
        EVP_PKEY_free(key);
    if(priv)
        LIBSSH2_FREE(session, priv);
    if(pub)
        LIBSSH2_FREE(session, pub);

    return rc;
}


static int
gen_publickey_from_ed_evp(LIBSSH2_SESSION *session,
                          unsigned char **method,
                          size_t *method_len,
                          unsigned char **pubkeydata,
                          size_t *pubkeydata_len,
                          EVP_PKEY *pk)
{
    const char methodName[] = "ssh-ed25519";
    unsigned char *methodBuf = NULL;
    size_t rawKeyLen = 0;
    unsigned char *keyBuf = NULL;
    size_t bufLen = 0;
    unsigned char *bufPos = NULL;

    _libssh2_debug(session, LIBSSH2_TRACE_AUTH,
                   "Computing public key from ED private key envelope");

    methodBuf = LIBSSH2_ALLOC(session, sizeof(methodName) - 1);
    if(!methodBuf) {
        _libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                       "Unable to allocate memory for private key data");
        goto fail;
    }
    memcpy(methodBuf, methodName, sizeof(methodName) - 1);

    if(EVP_PKEY_get_raw_public_key(pk, NULL, &rawKeyLen) != 1) {
        _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                       "EVP_PKEY_get_raw_public_key failed");
        goto fail;
    }

    /* Key form is: type_len(4) + type(11) + pub_key_len(4) + pub_key(32). */
    bufLen = 4 + sizeof(methodName) - 1  + 4 + rawKeyLen;
    bufPos = keyBuf = LIBSSH2_ALLOC(session, bufLen);
    if(!keyBuf) {
        _libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                       "Unable to allocate memory for private key data");
        goto fail;
    }

    _libssh2_store_str(&bufPos, methodName, sizeof(methodName) - 1);
    _libssh2_store_u32(&bufPos, rawKeyLen);

    if(EVP_PKEY_get_raw_public_key(pk, bufPos, &rawKeyLen) != 1) {
        _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                       "EVP_PKEY_get_raw_public_key failed");
        goto fail;
    }

    *method         = methodBuf;
    *method_len     = sizeof(methodName) - 1;
    *pubkeydata     = keyBuf;
    *pubkeydata_len = bufLen;
    return 0;

fail:
    if(methodBuf)
        LIBSSH2_FREE(session, methodBuf);
    if(keyBuf)
        LIBSSH2_FREE(session, keyBuf);
    return -1;
}


static int
gen_publickey_from_ed25519_openssh_priv_data(LIBSSH2_SESSION *session,
                                             struct string_buf *decrypted,
                                             unsigned char **method,
                                             size_t *method_len,
                                             unsigned char **pubkeydata,
                                             size_t *pubkeydata_len,
                                             libssh2_ed25519_ctx **out_ctx)
{
    libssh2_ed25519_ctx *ctx = NULL;
    unsigned char *method_buf = NULL;
    unsigned char *key = NULL;
    int i, ret = 0;
    unsigned char *pub_key, *priv_key, *buf;
    size_t key_len = 0, tmp_len = 0;
    unsigned char *p;

    _libssh2_debug(session,
                   LIBSSH2_TRACE_AUTH,
                   "Computing ED25519 keys from private key data");

    if(_libssh2_get_string(decrypted, &pub_key, &tmp_len) ||
       tmp_len != LIBSSH2_ED25519_KEY_LEN) {
        _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                       "Wrong public key length");
        return -1;
    }

    if(_libssh2_get_string(decrypted, &priv_key, &tmp_len) ||
       tmp_len != LIBSSH2_ED25519_PRIVATE_KEY_LEN) {
        _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                       "Wrong private key length");
        ret = -1;
        goto clean_exit;
    }

    /* first 32 bytes of priv_key is the private key, the last 32 bytes are
       the public key */
    ctx = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                       (const unsigned char *)priv_key,
                                       LIBSSH2_ED25519_KEY_LEN);

    /* comment */
    if(_libssh2_get_string(decrypted, &buf, &tmp_len)) {
        _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                       "Unable to read comment");
        ret = -1;
        goto clean_exit;
    }

    if(tmp_len > 0) {
        unsigned char *comment = LIBSSH2_CALLOC(session, tmp_len + 1);
        if(comment != NULL) {
            memcpy(comment, buf, tmp_len);
            memcpy(comment + tmp_len, "\0", 1);

            _libssh2_debug(session, LIBSSH2_TRACE_AUTH, "Key comment: %s",
                           comment);

            LIBSSH2_FREE(session, comment);
        }
    }

    /* Padding */
    i = 1;
    while(decrypted->dataptr < decrypted->data + decrypted->len) {
        if(*decrypted->dataptr != i) {
            _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                           "Wrong padding");
            ret = -1;
            goto clean_exit;
        }
        i++;
        decrypted->dataptr++;
    }

    if(ret == 0) {
        _libssh2_debug(session,
                       LIBSSH2_TRACE_AUTH,
                       "Computing public key from ED25519 "
                       "private key envelope");

        method_buf = LIBSSH2_ALLOC(session, 11);  /* ssh-ed25519. */
        if(method_buf == NULL) {
            _libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                           "Unable to allocate memory for ED25519 key");
            goto clean_exit;
        }

        /* Key form is: type_len(4) + type(11) + pub_key_len(4) +
           pub_key(32). */
        key_len = LIBSSH2_ED25519_KEY_LEN + 19;
        key = LIBSSH2_CALLOC(session, key_len);
        if(key == NULL) {
            _libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                           "Unable to allocate memory for ED25519 key");
            goto clean_exit;
        }

        p = key;

        _libssh2_store_str(&p, "ssh-ed25519", 11);
        _libssh2_store_str(&p, (const char *)pub_key, LIBSSH2_ED25519_KEY_LEN);

        memcpy(method_buf, "ssh-ed25519", 11);

        if(method != NULL)
            *method = method_buf;
        else
            LIBSSH2_FREE(session, method_buf);

        if(method_len != NULL)
            *method_len = 11;

        if(pubkeydata != NULL)
            *pubkeydata = key;
        else
            LIBSSH2_FREE(session, key);

        if(pubkeydata_len != NULL)
            *pubkeydata_len = key_len;

        if(out_ctx != NULL)
            *out_ctx = ctx;
        else if(ctx != NULL)
            _libssh2_ed25519_free(ctx);

        return 0;
    }

clean_exit:

    if(ctx)
        _libssh2_ed25519_free(ctx);

    if(method_buf)
        LIBSSH2_FREE(session, method_buf);

    if(key)
        LIBSSH2_FREE(session, key);

    return -1;
}

int
_libssh2_ed25519_new_private(libssh2_ed25519_ctx ** ed_ctx,
                             LIBSSH2_SESSION * session,
                             const char *filename, const uint8_t *passphrase)
{
    int rc;
    FILE *fp;
    unsigned char *buf;
    struct string_buf *decrypted = NULL;
    libssh2_ed25519_ctx *ctx = NULL;

    if(session == NULL) {
        _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                       "Session is required");
        return -1;
    }

    _libssh2_init_if_needed();

    fp = fopen(filename, "r");
    if(!fp) {
        _libssh2_error(session, LIBSSH2_ERROR_FILE,
                       "Unable to open ED25519 private key file");
        return -1;
    }

    rc = _libssh2_openssh_pem_parse(session, passphrase, fp, &decrypted);
    fclose(fp);
    if(rc) {
        return rc;
    }

    /* We have a new key file, now try and parse it using supported types  */
    rc = _libssh2_get_string(decrypted, &buf, NULL);

    if(rc != 0 || buf == NULL) {
        _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                       "Public key type in decrypted key data not found");
        return -1;
    }

    if(strcmp("ssh-ed25519", (const char *)buf) == 0) {
        rc = gen_publickey_from_ed25519_openssh_priv_data(session,
                                                          decrypted,
                                                          NULL,
                                                          NULL,
                                                          NULL,
                                                          NULL,
                                                          &ctx);
    }
    else {
        rc = -1;
    }

    if(decrypted)
        _libssh2_string_buf_free(session, decrypted);

    if(rc == 0) {
        if(ed_ctx != NULL)
            *ed_ctx = ctx;
        else if(ctx != NULL)
            _libssh2_ed25519_free(ctx);
    }

    return rc;
}

int
_libssh2_ed25519_new_private_frommemory(libssh2_ed25519_ctx ** ed_ctx,
                                        LIBSSH2_SESSION * session,
                                        const char *filedata,
                                        size_t filedata_len,
                                        unsigned const char *passphrase)
{
    libssh2_ed25519_ctx *ctx = NULL;

    _libssh2_init_if_needed();

    if(read_private_key_from_memory((void **)&ctx,
                                    (pem_read_bio_func)
                                    &PEM_read_bio_PrivateKey,
                                    filedata, filedata_len, passphrase) == 0) {
        if(EVP_PKEY_id(ctx) != EVP_PKEY_ED25519) {
            _libssh2_ed25519_free(ctx);
            return _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                                  "Private key is not an ED25519 key");
        }

        *ed_ctx = ctx;
        return 0;
    }

    return read_openssh_private_key_from_memory((void **)ed_ctx, session,
                                                "ssh-ed25519",
                                                filedata, filedata_len,
                                                passphrase);
}

int
_libssh2_ed25519_new_public(libssh2_ed25519_ctx ** ed_ctx,
                            LIBSSH2_SESSION * session,
                            const unsigned char *raw_pub_key,
                            const uint8_t key_len)
{
    libssh2_ed25519_ctx *ctx = NULL;

    if(ed_ctx == NULL)
        return -1;

    ctx = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                      raw_pub_key, key_len);
    if(!ctx)
        return _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                              "could not create ED25519 public key");

    if(ed_ctx != NULL)
        *ed_ctx = ctx;
    else if(ctx)
        _libssh2_ed25519_free(ctx);

    return 0;
}
#endif /* LIBSSH2_ED25519 */


int
_libssh2_rsa_sha1_sign(LIBSSH2_SESSION * session,
                       libssh2_rsa_ctx * rsactx,
                       const unsigned char *hash,
                       size_t hash_len,
                       unsigned char **signature, size_t *signature_len)
{
    int ret;
    unsigned char *sig;
    unsigned int sig_len;

    sig_len = RSA_size(rsactx);
    sig = LIBSSH2_ALLOC(session, sig_len);

    if(!sig) {
        return -1;
    }

    ret = RSA_sign(NID_sha1, hash, hash_len, sig, &sig_len, rsactx);

    if(!ret) {
        LIBSSH2_FREE(session, sig);
        return -1;
    }

    *signature = sig;
    *signature_len = sig_len;

    return 0;
}

#if LIBSSH2_DSA
int
_libssh2_dsa_sha1_sign(libssh2_dsa_ctx * dsactx,
                       const unsigned char *hash,
                       unsigned long hash_len, unsigned char *signature)
{
    DSA_SIG *sig;
    const BIGNUM * r;
    const BIGNUM * s;
    int r_len, s_len;
    (void) hash_len;

    sig = DSA_do_sign(hash, SHA_DIGEST_LENGTH, dsactx);
    if(!sig) {
        return -1;
    }

#ifdef HAVE_OPAQUE_STRUCTS
    DSA_SIG_get0(sig, &r, &s);
#else
    r = sig->r;
    s = sig->s;
#endif
    r_len = BN_num_bytes(r);
    if(r_len < 1 || r_len > 20) {
        DSA_SIG_free(sig);
        return -1;
    }
    s_len = BN_num_bytes(s);
    if(s_len < 1 || s_len > 20) {
        DSA_SIG_free(sig);
        return -1;
    }

    memset(signature, 0, 40);

    BN_bn2bin(r, signature + (20 - r_len));
    BN_bn2bin(s, signature + 20 + (20 - s_len));

    DSA_SIG_free(sig);

    return 0;
}
#endif /* LIBSSH_DSA */

#if LIBSSH2_ECDSA

int
_libssh2_ecdsa_sign(LIBSSH2_SESSION * session, libssh2_ecdsa_ctx * ec_ctx,
    const unsigned char *hash, unsigned long hash_len,
    unsigned char **signature, size_t *signature_len)
{
    int r_len, s_len;
    int rc = 0;
    size_t out_buffer_len = 0;
    unsigned char *sp;
    const BIGNUM *pr = NULL, *ps = NULL;
    unsigned char *temp_buffer = NULL;
    unsigned char *out_buffer = NULL;

    ECDSA_SIG *sig = ECDSA_do_sign(hash, hash_len, ec_ctx);
    if(sig == NULL)
        return -1;
#ifdef HAVE_OPAQUE_STRUCTS
    ECDSA_SIG_get0(sig, &pr, &ps);
#else
    pr = sig->r;
    ps = sig->s;
#endif

    r_len = BN_num_bytes(pr) + 1;
    s_len = BN_num_bytes(ps) + 1;

    temp_buffer = malloc(r_len + s_len + 8);
    if(temp_buffer == NULL) {
        rc = -1;
        goto clean_exit;
    }

    sp = temp_buffer;
    sp = write_bn(sp, pr, r_len);
    sp = write_bn(sp, ps, s_len);

    out_buffer_len = (size_t)(sp - temp_buffer);

    out_buffer = LIBSSH2_CALLOC(session, out_buffer_len);
    if(out_buffer == NULL) {
        rc = -1;
        goto clean_exit;
    }

    memcpy(out_buffer, temp_buffer, out_buffer_len);

    *signature = out_buffer;
    *signature_len = out_buffer_len;

clean_exit:

    if(temp_buffer != NULL)
        free(temp_buffer);

    if(sig)
        ECDSA_SIG_free(sig);

    return rc;
}
#endif /* LIBSSH2_ECDSA */

int
_libssh2_sha1_init(libssh2_sha1_ctx *ctx)
{
#ifdef HAVE_OPAQUE_STRUCTS
    *ctx = EVP_MD_CTX_new();

    if(*ctx == NULL)
        return 0;

    if(EVP_DigestInit(*ctx, EVP_get_digestbyname("sha1")))
        return 1;

    EVP_MD_CTX_free(*ctx);
    *ctx = NULL;

    return 0;
#else
    EVP_MD_CTX_init(ctx);
    return EVP_DigestInit(ctx, EVP_get_digestbyname("sha1"));
#endif
}

int
_libssh2_sha1(const unsigned char *message, unsigned long len,
              unsigned char *out)
{
#ifdef HAVE_OPAQUE_STRUCTS
    EVP_MD_CTX * ctx = EVP_MD_CTX_new();

    if(ctx == NULL)
        return 1; /* error */

    if(EVP_DigestInit(ctx, EVP_get_digestbyname("sha1"))) {
        EVP_DigestUpdate(ctx, message, len);
        EVP_DigestFinal(ctx, out, NULL);
        EVP_MD_CTX_free(ctx);
        return 0; /* success */
    }
    EVP_MD_CTX_free(ctx);
#else
    EVP_MD_CTX ctx;

    EVP_MD_CTX_init(&ctx);
    if(EVP_DigestInit(&ctx, EVP_get_digestbyname("sha1"))) {
        EVP_DigestUpdate(&ctx, message, len);
        EVP_DigestFinal(&ctx, out, NULL);
        return 0; /* success */
    }
#endif
    return 1; /* error */
}

int
_libssh2_sha256_init(libssh2_sha256_ctx *ctx)
{
#ifdef HAVE_OPAQUE_STRUCTS
    *ctx = EVP_MD_CTX_new();

    if(*ctx == NULL)
        return 0;

    if(EVP_DigestInit(*ctx, EVP_get_digestbyname("sha256")))
        return 1;

    EVP_MD_CTX_free(*ctx);
    *ctx = NULL;

    return 0;
#else
    EVP_MD_CTX_init(ctx);
    return EVP_DigestInit(ctx, EVP_get_digestbyname("sha256"));
#endif
}

int
_libssh2_sha256(const unsigned char *message, unsigned long len,
                unsigned char *out)
{
#ifdef HAVE_OPAQUE_STRUCTS
    EVP_MD_CTX * ctx = EVP_MD_CTX_new();

    if(ctx == NULL)
        return 1; /* error */

    if(EVP_DigestInit(ctx, EVP_get_digestbyname("sha256"))) {
        EVP_DigestUpdate(ctx, message, len);
        EVP_DigestFinal(ctx, out, NULL);
        EVP_MD_CTX_free(ctx);
        return 0; /* success */
    }
    EVP_MD_CTX_free(ctx);
#else
    EVP_MD_CTX ctx;

    EVP_MD_CTX_init(&ctx);
    if(EVP_DigestInit(&ctx, EVP_get_digestbyname("sha256"))) {
        EVP_DigestUpdate(&ctx, message, len);
        EVP_DigestFinal(&ctx, out, NULL);
        return 0; /* success */
    }
#endif
    return 1; /* error */
}

int
_libssh2_sha384_init(libssh2_sha384_ctx *ctx)
{
#ifdef HAVE_OPAQUE_STRUCTS
    *ctx = EVP_MD_CTX_new();

    if(*ctx == NULL)
        return 0;

    if(EVP_DigestInit(*ctx, EVP_get_digestbyname("sha384")))
        return 1;

    EVP_MD_CTX_free(*ctx);
    *ctx = NULL;

    return 0;
#else
    EVP_MD_CTX_init(ctx);
    return EVP_DigestInit(ctx, EVP_get_digestbyname("sha384"));
#endif
}

int
_libssh2_sha384(const unsigned char *message, unsigned long len,
    unsigned char *out)
{
#ifdef HAVE_OPAQUE_STRUCTS
    EVP_MD_CTX * ctx = EVP_MD_CTX_new();

    if(ctx == NULL)
        return 1; /* error */

    if(EVP_DigestInit(ctx, EVP_get_digestbyname("sha384"))) {
        EVP_DigestUpdate(ctx, message, len);
        EVP_DigestFinal(ctx, out, NULL);
        EVP_MD_CTX_free(ctx);
        return 0; /* success */
    }
    EVP_MD_CTX_free(ctx);
#else
    EVP_MD_CTX ctx;

    EVP_MD_CTX_init(&ctx);
    if(EVP_DigestInit(&ctx, EVP_get_digestbyname("sha384"))) {
        EVP_DigestUpdate(&ctx, message, len);
        EVP_DigestFinal(&ctx, out, NULL);
        return 0; /* success */
    }
#endif
    return 1; /* error */
}

int
_libssh2_sha512_init(libssh2_sha512_ctx *ctx)
{
#ifdef HAVE_OPAQUE_STRUCTS
    *ctx = EVP_MD_CTX_new();

    if(*ctx == NULL)
        return 0;

    if(EVP_DigestInit(*ctx, EVP_get_digestbyname("sha512")))
        return 1;

    EVP_MD_CTX_free(*ctx);
    *ctx = NULL;

    return 0;
#else
    EVP_MD_CTX_init(ctx);
    return EVP_DigestInit(ctx, EVP_get_digestbyname("sha512"));
#endif
}

int
_libssh2_sha512(const unsigned char *message, unsigned long len,
    unsigned char *out)
{
#ifdef HAVE_OPAQUE_STRUCTS
    EVP_MD_CTX * ctx = EVP_MD_CTX_new();

    if(ctx == NULL)
        return 1; /* error */

    if(EVP_DigestInit(ctx, EVP_get_digestbyname("sha512"))) {
        EVP_DigestUpdate(ctx, message, len);
        EVP_DigestFinal(ctx, out, NULL);
        EVP_MD_CTX_free(ctx);
        return 0; /* success */
    }
    EVP_MD_CTX_free(ctx);
#else
    EVP_MD_CTX ctx;

    EVP_MD_CTX_init(&ctx);
    if(EVP_DigestInit(&ctx, EVP_get_digestbyname("sha512"))) {
        EVP_DigestUpdate(&ctx, message, len);
        EVP_DigestFinal(&ctx, out, NULL);
        return 0; /* success */
    }
#endif
    return 1; /* error */
}

int
_libssh2_md5_init(libssh2_md5_ctx *ctx)
{
    /* MD5 digest is not supported in OpenSSL FIPS mode
     * Trying to init it will result in a latent OpenSSL error:
     * "digital envelope routines:FIPS_DIGESTINIT:disabled for fips"
     * So, just return 0 in FIPS mode
     */
#if OPENSSL_VERSION_NUMBER >= 0x000907000L && \
    defined(OPENSSL_VERSION_MAJOR) && \
    OPENSSL_VERSION_MAJOR < 3 && \
    !defined(LIBRESSL_VERSION_NUMBER)
     if(FIPS_mode() != 0)
         return 0;
#endif

#ifdef HAVE_OPAQUE_STRUCTS
    *ctx = EVP_MD_CTX_new();

    if(*ctx == NULL)
        return 0;

    if(EVP_DigestInit(*ctx, EVP_get_digestbyname("md5")))
        return 1;

    EVP_MD_CTX_free(*ctx);
    *ctx = NULL;

    return 0;
#else
    EVP_MD_CTX_init(ctx);
    return EVP_DigestInit(ctx, EVP_get_digestbyname("md5"));
#endif
}

#if LIBSSH2_ECDSA

static int
gen_publickey_from_ec_evp(LIBSSH2_SESSION *session,
                          unsigned char **method,
                          size_t *method_len,
                          unsigned char **pubkeydata,
                          size_t *pubkeydata_len,
                          EVP_PKEY *pk)
{
    int rc = 0;
    EC_KEY *ec = NULL;
    unsigned char *p;
    unsigned char *method_buf = NULL;
    unsigned char *key;
    size_t  key_len = 0;
    unsigned char *octal_value = NULL;
    size_t octal_len;
    const EC_POINT *public_key;
    const EC_GROUP *group;
    BN_CTX *bn_ctx;
    libssh2_curve_type type;

    _libssh2_debug(session,
       LIBSSH2_TRACE_AUTH,
       "Computing public key from EC private key envelope");

    bn_ctx = BN_CTX_new();
    if(bn_ctx == NULL)
        return -1;

    ec = EVP_PKEY_get1_EC_KEY(pk);
    if(ec == NULL) {
        rc = -1;
        goto clean_exit;
    }

    public_key = EC_KEY_get0_public_key(ec);
    group = EC_KEY_get0_group(ec);
    type = _libssh2_ecdsa_get_curve_type(ec);

    method_buf = LIBSSH2_ALLOC(session, 19);
    if(method_buf == NULL) {
        return _libssh2_error(session, LIBSSH2_ERROR_ALLOC,
            "out of memory");
    }

    if(type == LIBSSH2_EC_CURVE_NISTP256)
        memcpy(method_buf, "ecdsa-sha2-nistp256", 19);
    else if(type == LIBSSH2_EC_CURVE_NISTP384)
        memcpy(method_buf, "ecdsa-sha2-nistp384", 19);
    else if(type == LIBSSH2_EC_CURVE_NISTP521)
        memcpy(method_buf, "ecdsa-sha2-nistp521", 19);
    else {
        _libssh2_debug(session,
            LIBSSH2_TRACE_ERROR,
            "Unsupported EC private key type");
        rc = -1;
        goto clean_exit;
    }

    /* get length */
    octal_len = EC_POINT_point2oct(group, public_key,
                                   POINT_CONVERSION_UNCOMPRESSED,
                                   NULL, 0, bn_ctx);
    if(octal_len > EC_MAX_POINT_LEN) {
        rc = -1;
        goto clean_exit;
    }

    octal_value = malloc(octal_len);
    if(octal_value == NULL) {
        rc = -1;
        goto clean_exit;
    }

    /* convert to octal */
    if(EC_POINT_point2oct(group, public_key, POINT_CONVERSION_UNCOMPRESSED,
       octal_value, octal_len, bn_ctx) != octal_len) {
           rc = -1;
           goto clean_exit;
    }

    /* Key form is: type_len(4) + type(19) + domain_len(4) + domain(8) +
       pub_key_len(4) + pub_key(~65). */
    key_len = 4 + 19 + 4 + 8 + 4 + octal_len;
    key = LIBSSH2_ALLOC(session, key_len);
    if(key == NULL) {
        rc = -1;
        goto  clean_exit;
    }

    /* Process key encoding. */
    p = key;

    /* Key type */
    _libssh2_store_str(&p, (const char *)method_buf, 19);

    /* Name domain */
    _libssh2_store_str(&p, (const char *)method_buf + 11, 8);

    /* Public key */
    _libssh2_store_str(&p, (const char *)octal_value, octal_len);

    *method         = method_buf;
    *method_len     = 19;
    *pubkeydata     = key;
    *pubkeydata_len = key_len;

clean_exit:

    if(ec != NULL)
        EC_KEY_free(ec);

    if(bn_ctx != NULL) {
        BN_CTX_free(bn_ctx);
    }

    if(octal_value != NULL)
        free(octal_value);

    if(rc == 0)
        return 0;

    if(method_buf != NULL)
        LIBSSH2_FREE(session, method_buf);

    return -1;
}

static int
gen_publickey_from_ecdsa_openssh_priv_data(LIBSSH2_SESSION *session,
                                           libssh2_curve_type curve_type,
                                           struct string_buf *decrypted,
                                           unsigned char **method,
                                           size_t *method_len,
                                           unsigned char **pubkeydata,
                                           size_t *pubkeydata_len,
                                           libssh2_ecdsa_ctx **ec_ctx)
{
    int rc = 0;
    size_t curvelen, exponentlen, pointlen;
    unsigned char *curve, *exponent, *point_buf;
    EC_KEY *ec_key = NULL;
    BIGNUM *bn_exponent;

    _libssh2_debug(session,
                   LIBSSH2_TRACE_AUTH,
                   "Computing ECDSA keys from private key data");

    if(_libssh2_get_string(decrypted, &curve, &curvelen) ||
        curvelen == 0) {
        _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                       "ECDSA no curve");
        return -1;
    }

    if(_libssh2_get_string(decrypted, &point_buf, &pointlen)) {
        _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                       "ECDSA no point");
        return -1;
    }

    if(_libssh2_get_bignum_bytes(decrypted, &exponent, &exponentlen)) {
        _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                       "ECDSA no exponent");
        return -1;
    }

    if((rc = _libssh2_ecdsa_curve_name_with_octal_new(&ec_key, point_buf,
        pointlen, curve_type)) != 0) {
        rc = -1;
        _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                       "ECDSA could not create key");
        goto fail;
    }

    bn_exponent = BN_new();
    if(bn_exponent == NULL) {
        rc = -1;
        _libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                       "Unable to allocate memory for private key data");
        goto fail;
    }

    BN_bin2bn(exponent, exponentlen, bn_exponent);
    rc = (EC_KEY_set_private_key(ec_key, bn_exponent) != 1);

    if(rc == 0 && ec_key != NULL && pubkeydata != NULL && method != NULL) {
        EVP_PKEY *pk = EVP_PKEY_new();
        EVP_PKEY_set1_EC_KEY(pk, ec_key);

        rc = gen_publickey_from_ec_evp(session, method, method_len,
                                       pubkeydata, pubkeydata_len,
                                       pk);

        if(pk)
            EVP_PKEY_free(pk);
    }

    if(ec_ctx != NULL)
        *ec_ctx = ec_key;
    else
        EC_KEY_free(ec_key);

    return rc;

fail:
    if(ec_key != NULL)
        EC_KEY_free(ec_key);

    return rc;
}

static int
_libssh2_ecdsa_new_openssh_private(libssh2_ecdsa_ctx ** ec_ctx,
                                   LIBSSH2_SESSION * session,
                                   const char *filename,
                                   unsigned const char *passphrase)
{
    FILE *fp;
    int rc;
    unsigned char *buf = NULL;
    libssh2_curve_type type;
    struct string_buf *decrypted = NULL;

    if(session == NULL) {
        _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                           "Session is required");
        return -1;
    }

    _libssh2_init_if_needed();

    fp = fopen(filename, "r");
    if(!fp) {
        _libssh2_error(session, LIBSSH2_ERROR_FILE,
                       "Unable to open OpenSSH ECDSA private key file");
        return -1;
    }

    rc = _libssh2_openssh_pem_parse(session, passphrase, fp, &decrypted);
    fclose(fp);
    if(rc) {
        return rc;
    }

    /* We have a new key file, now try and parse it using supported types  */
    rc = _libssh2_get_string(decrypted, &buf, NULL);

    if(rc != 0 || buf == NULL) {
        _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                       "Public key type in decrypted key data not found");
        return -1;
    }

    rc = _libssh2_ecdsa_curve_type_from_name((const char *)buf, &type);

    if(rc == 0) {
        rc = gen_publickey_from_ecdsa_openssh_priv_data(session, type,
                                                        decrypted, NULL, 0,
                                                        NULL, 0, ec_ctx);
    }
    else {
        rc = -1;
    }

    if(decrypted)
        _libssh2_string_buf_free(session, decrypted);

    return rc;
}

int
_libssh2_ecdsa_new_private(libssh2_ecdsa_ctx ** ec_ctx,
       LIBSSH2_SESSION * session,
       const char *filename, unsigned const char *passphrase)
{
    int rc;

    pem_read_bio_func read_ec = (pem_read_bio_func) &PEM_read_bio_ECPrivateKey;

    _libssh2_init_if_needed();

    rc = read_private_key_from_file((void **) ec_ctx, read_ec,
      filename, passphrase);

    if(rc) {
        return _libssh2_ecdsa_new_openssh_private(ec_ctx, session,
                                                  filename, passphrase);
    }

    return rc;
}

/*
 * _libssh2_ecdsa_create_key
 *
 * Creates a local private key based on input curve
 * and returns octal value and octal length
 *
 */

int
_libssh2_ecdsa_create_key(LIBSSH2_SESSION *session,
                          _libssh2_ec_key **out_private_key,
                          unsigned char **out_public_key_octal,
                          size_t *out_public_key_octal_len,
                          libssh2_curve_type curve_type)
{
    int ret = 1;
    size_t octal_len = 0;
    unsigned char octal_value[EC_MAX_POINT_LEN];
    const EC_POINT *public_key = NULL;
    EC_KEY *private_key = NULL;
    const EC_GROUP *group = NULL;

    /* create key */
    BN_CTX *bn_ctx = BN_CTX_new();
    if(!bn_ctx)
        return -1;

    private_key = EC_KEY_new_by_curve_name(curve_type);
    group = EC_KEY_get0_group(private_key);

    EC_KEY_generate_key(private_key);
    public_key = EC_KEY_get0_public_key(private_key);

    /* get length */
    octal_len = EC_POINT_point2oct(group, public_key,
                                   POINT_CONVERSION_UNCOMPRESSED,
                                   NULL, 0, bn_ctx);
    if(octal_len > EC_MAX_POINT_LEN) {
        ret = -1;
        goto clean_exit;
    }

    /* convert to octal */
    if(EC_POINT_point2oct(group, public_key, POINT_CONVERSION_UNCOMPRESSED,
       octal_value, octal_len, bn_ctx) != octal_len) {
           ret = -1;
           goto clean_exit;
    }

    if(out_private_key != NULL)
        *out_private_key = private_key;

    if(out_public_key_octal) {
        *out_public_key_octal = LIBSSH2_ALLOC(session, octal_len);
        if(*out_public_key_octal == NULL) {
            ret = -1;
            goto clean_exit;
        }

        memcpy(*out_public_key_octal, octal_value, octal_len);
    }

    if(out_public_key_octal_len != NULL)
        *out_public_key_octal_len = octal_len;

clean_exit:

    if(bn_ctx)
        BN_CTX_free(bn_ctx);

    return (ret == 1) ? 0 : -1;
}

/* _libssh2_ecdh_gen_k
 *
 * Computes the shared secret K given a local private key,
 * remote public key and length
 */

int
_libssh2_ecdh_gen_k(_libssh2_bn **k, _libssh2_ec_key *private_key,
    const unsigned char *server_public_key, size_t server_public_key_len)
{
    int ret = 0;
    int rc;
    size_t secret_len;
    unsigned char *secret = NULL;
    const EC_GROUP *private_key_group;
    EC_POINT *server_public_key_point;

    BN_CTX *bn_ctx = BN_CTX_new();

    if(!bn_ctx)
        return -1;

    if(k == NULL)
        return -1;

    private_key_group = EC_KEY_get0_group(private_key);

    server_public_key_point = EC_POINT_new(private_key_group);
    if(server_public_key_point == NULL)
        return -1;

    rc = EC_POINT_oct2point(private_key_group, server_public_key_point,
                            server_public_key, server_public_key_len, bn_ctx);
    if(rc != 1) {
        ret = -1;
        goto clean_exit;
    }

    secret_len = (EC_GROUP_get_degree(private_key_group) + 7) / 8;
    secret = malloc(secret_len);
    if(!secret) {
        ret = -1;
        goto clean_exit;
    }

    secret_len = ECDH_compute_key(secret, secret_len, server_public_key_point,
                                  private_key, NULL);

    if(secret_len <= 0 || secret_len > EC_MAX_POINT_LEN) {
        ret = -1;
        goto clean_exit;
    }

    BN_bin2bn(secret, secret_len, *k);

clean_exit:

    if(server_public_key_point != NULL)
        EC_POINT_free(server_public_key_point);

    if(bn_ctx != NULL)
        BN_CTX_free(bn_ctx);

    if(secret != NULL)
        free(secret);

    return ret;
}


#endif /* LIBSSH2_ECDSA */

#if LIBSSH2_ED25519

int
_libssh2_ed25519_sign(libssh2_ed25519_ctx *ctx, LIBSSH2_SESSION *session,
                      uint8_t **out_sig, size_t *out_sig_len,
                      const uint8_t *message, size_t message_len)
{
    int rc = -1;
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    size_t sig_len = 0;
    unsigned char *sig = NULL;

    if(md_ctx != NULL) {
        if(EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, ctx) != 1)
            goto clean_exit;
        if(EVP_DigestSign(md_ctx, NULL, &sig_len, message, message_len) != 1)
            goto clean_exit;

        if(sig_len != LIBSSH2_ED25519_SIG_LEN)
            goto clean_exit;

        sig = LIBSSH2_CALLOC(session, sig_len);
        if(sig == NULL)
            goto clean_exit;

        rc = EVP_DigestSign(md_ctx, sig, &sig_len, message, message_len);
    }

    if(rc == 1) {
        *out_sig = sig;
        *out_sig_len = sig_len;
    }
    else {
        *out_sig_len = 0;
        *out_sig = NULL;
        LIBSSH2_FREE(session, sig);
    }

clean_exit:

    if(md_ctx)
        EVP_MD_CTX_free(md_ctx);

    return (rc == 1 ? 0 : -1);
}

int
_libssh2_curve25519_gen_k(_libssh2_bn **k,
                          uint8_t private_key[LIBSSH2_ED25519_KEY_LEN],
                          uint8_t server_public_key[LIBSSH2_ED25519_KEY_LEN])
{
    int rc = -1;
    unsigned char out_shared_key[LIBSSH2_ED25519_KEY_LEN];
    EVP_PKEY *peer_key = NULL, *server_key = NULL;
    EVP_PKEY_CTX *server_key_ctx = NULL;
    BN_CTX *bn_ctx = NULL;
    size_t out_len = 0;

    if(k == NULL || *k == NULL)
        return -1;

    bn_ctx = BN_CTX_new();
    if(bn_ctx == NULL)
        return -1;

    peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                           server_public_key,
                                           LIBSSH2_ED25519_KEY_LEN);

    server_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                              private_key,
                                              LIBSSH2_ED25519_KEY_LEN);

    if(peer_key == NULL || server_key == NULL) {
        goto cleanExit;
    }

    server_key_ctx = EVP_PKEY_CTX_new(server_key, NULL);
    if(server_key_ctx == NULL) {
        goto cleanExit;
    }

    rc = EVP_PKEY_derive_init(server_key_ctx);
    if(rc <= 0) goto cleanExit;

    rc = EVP_PKEY_derive_set_peer(server_key_ctx, peer_key);
    if(rc <= 0) goto cleanExit;

    rc = EVP_PKEY_derive(server_key_ctx, NULL, &out_len);
    if(rc <= 0) goto cleanExit;

    if(out_len != LIBSSH2_ED25519_KEY_LEN) {
        rc = -1;
        goto cleanExit;
    }

    rc = EVP_PKEY_derive(server_key_ctx, out_shared_key, &out_len);

    if(rc == 1 && out_len == LIBSSH2_ED25519_KEY_LEN) {
        BN_bin2bn(out_shared_key, LIBSSH2_ED25519_KEY_LEN, *k);
    }
    else {
        rc = -1;
    }

cleanExit:

    if(server_key_ctx)
        EVP_PKEY_CTX_free(server_key_ctx);
    if(peer_key)
        EVP_PKEY_free(peer_key);
    if(server_key)
        EVP_PKEY_free(server_key);
    if(bn_ctx != NULL)
        BN_CTX_free(bn_ctx);

    return (rc == 1) ? 0 : -1;
}


int
_libssh2_ed25519_verify(libssh2_ed25519_ctx *ctx, const uint8_t *s,
                        size_t s_len, const uint8_t *m, size_t m_len)
{
    int ret = -1;

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if(NULL == md_ctx)
        return -1;

    ret = EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, ctx);
    if(ret != 1)
        goto clean_exit;

    ret = EVP_DigestVerify(md_ctx, s, s_len, m, m_len);

    clean_exit:

    EVP_MD_CTX_free(md_ctx);

    return (ret == 1) ? 0 : -1;
}

#endif /* LIBSSH2_ED25519 */

static int
_libssh2_pub_priv_openssh_keyfile(LIBSSH2_SESSION *session,
                                  unsigned char **method,
                                  size_t *method_len,
                                  unsigned char **pubkeydata,
                                  size_t *pubkeydata_len,
                                  const char *privatekey,
                                  const char *passphrase)
{
    FILE *fp;
    unsigned char *buf = NULL;
    struct string_buf *decrypted = NULL;
    int rc = 0;

    if(session == NULL) {
        _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                       "Session is required");
        return -1;
    }

    _libssh2_init_if_needed();

    fp = fopen(privatekey, "r");
    if(!fp) {
        _libssh2_error(session, LIBSSH2_ERROR_FILE,
                       "Unable to open private key file");
        return -1;
    }

    rc = _libssh2_openssh_pem_parse(session, (const unsigned char *)passphrase,
                                    fp, &decrypted);
    fclose(fp);
    if(rc) {
        _libssh2_error(session, LIBSSH2_ERROR_FILE,
                       "Not an OpenSSH key file");
        return rc;
    }

    /* We have a new key file, now try and parse it using supported types  */
    rc = _libssh2_get_string(decrypted, &buf, NULL);

    if(rc != 0 || buf == NULL) {
        _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                       "Public key type in decrypted key data not found");
        return -1;
    }

    rc = -1;

#if LIBSSH2_ED25519
    if(strcmp("ssh-ed25519", (const char *)buf) == 0) {
        rc = gen_publickey_from_ed25519_openssh_priv_data(session, decrypted,
                                                          method, method_len,
                                                          pubkeydata,
                                                          pubkeydata_len,
                                                          NULL);
    }
#endif
#if LIBSSH2_RSA
    if(strcmp("ssh-rsa", (const char *)buf) == 0) {
        rc = gen_publickey_from_rsa_openssh_priv_data(session, decrypted,
                                                      method, method_len,
                                                      pubkeydata,
                                                      pubkeydata_len,
                                                      NULL);
    }
#endif
#if LIBSSH2_DSA
    if(strcmp("ssh-dss", (const char *)buf) == 0) {
        rc = gen_publickey_from_dsa_openssh_priv_data(session, decrypted,
                                                      method, method_len,
                                                      pubkeydata,
                                                      pubkeydata_len,
                                                      NULL);
    }
#endif
#if LIBSSH2_ECDSA
    {
        libssh2_curve_type type;

        if(_libssh2_ecdsa_curve_type_from_name((const char *)buf,
                                               &type) == 0) {
            rc = gen_publickey_from_ecdsa_openssh_priv_data(session, type,
                                                            decrypted,
                                                            method, method_len,
                                                            pubkeydata,
                                                            pubkeydata_len,
                                                            NULL);
        }
    }
#endif

    if(decrypted)
        _libssh2_string_buf_free(session, decrypted);

    if(rc != 0) {
        _libssh2_error(session, LIBSSH2_ERROR_FILE,
                       "Unsupported OpenSSH key type");
    }

    return rc;
}

int
_libssh2_pub_priv_keyfile(LIBSSH2_SESSION *session,
                          unsigned char **method,
                          size_t *method_len,
                          unsigned char **pubkeydata,
                          size_t *pubkeydata_len,
                          const char *privatekey,
                          const char *passphrase)
{
    int       st;
    BIO*      bp;
    EVP_PKEY* pk;
    int       pktype;
    int       rc;

    _libssh2_debug(session,
                   LIBSSH2_TRACE_AUTH,
                   "Computing public key from private key file: %s",
                   privatekey);

    bp = BIO_new_file(privatekey, "r");
    if(bp == NULL) {
        return _libssh2_error(session,
                              LIBSSH2_ERROR_FILE,
                              "Unable to extract public key from private key "
                              "file: Unable to open private key file");
    }

    BIO_reset(bp);
    pk = PEM_read_bio_PrivateKey(bp, NULL, NULL, (void *)passphrase);
    BIO_free(bp);

    if(pk == NULL) {

        /* Try OpenSSH format */
        rc = _libssh2_pub_priv_openssh_keyfile(session,
                                               method,
                                               method_len,
                                               pubkeydata, pubkeydata_len,
                                               privatekey, passphrase);
        if(rc != 0) {
            return _libssh2_error(session,
                                  LIBSSH2_ERROR_FILE,
                                  "Unable to extract public key "
                                  "from private key file: "
                                  "Wrong passphrase or invalid/unrecognized "
                                  "private key file format");
        }

        return 0;
    }

#ifdef HAVE_OPAQUE_STRUCTS
    pktype = EVP_PKEY_id(pk);
#else
    pktype = pk->type;
#endif

    switch(pktype) {
#if LIBSSH2_ED25519
    case EVP_PKEY_ED25519 :
        st = gen_publickey_from_ed_evp(
            session, method, method_len, pubkeydata, pubkeydata_len, pk);
        break;
#endif /* LIBSSH2_ED25519 */
    case EVP_PKEY_RSA :
        st = gen_publickey_from_rsa_evp(
            session, method, method_len, pubkeydata, pubkeydata_len, pk);
        break;

#if LIBSSH2_DSA
    case EVP_PKEY_DSA :
        st = gen_publickey_from_dsa_evp(
            session, method, method_len, pubkeydata, pubkeydata_len, pk);
        break;
#endif /* LIBSSH_DSA */

#if LIBSSH2_ECDSA
    case EVP_PKEY_EC :
        st = gen_publickey_from_ec_evp(
            session, method, method_len, pubkeydata, pubkeydata_len, pk);
    break;
#endif

    default :
        st = _libssh2_error(session,
                            LIBSSH2_ERROR_FILE,
                            "Unable to extract public key "
                            "from private key file: "
                            "Unsupported private key file format");
        break;
    }

    EVP_PKEY_free(pk);
    return st;
}

static int
_libssh2_pub_priv_openssh_keyfilememory(LIBSSH2_SESSION *session,
                                        void **key_ctx,
                                        const char *key_type,
                                        unsigned char **method,
                                        size_t *method_len,
                                        unsigned char **pubkeydata,
                                        size_t *pubkeydata_len,
                                        const char *privatekeydata,
                                        size_t privatekeydata_len,
                                        unsigned const char *passphrase)
{
    int rc;
    unsigned char *buf = NULL;
    struct string_buf *decrypted = NULL;

    if(key_ctx != NULL)
        *key_ctx = NULL;

    if(session == NULL)
        return _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                              "Session is required");

    if(key_type != NULL && (strlen(key_type) > 11 || strlen(key_type) < 7))
        return _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                              "type is invalid");

    _libssh2_init_if_needed();

    rc = _libssh2_openssh_pem_parse_memory(session, passphrase,
                                           privatekeydata,
                                           privatekeydata_len, &decrypted);

    if(rc)
        return rc;

   /* We have a new key file, now try and parse it using supported types  */
   rc = _libssh2_get_string(decrypted, &buf, NULL);

   if(rc != 0 || buf == NULL)
       return _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                             "Public key type in decrypted "
                             "key data not found");

   rc = LIBSSH2_ERROR_FILE;

#if LIBSSH2_ED25519
    if(strcmp("ssh-ed25519", (const char *)buf) == 0) {
        if(key_type == NULL || strcmp("ssh-ed25519", key_type) == 0) {
            rc = gen_publickey_from_ed25519_openssh_priv_data(session,
                                                              decrypted,
                                                              method,
                                                              method_len,
                                                              pubkeydata,
                                                              pubkeydata_len,
                                              (libssh2_ed25519_ctx**)key_ctx);
        }
   }
#endif
#if LIBSSH2_RSA
    if(strcmp("ssh-rsa", (const char *)buf) == 0) {
        if(key_type == NULL || strcmp("ssh-rsa", key_type) == 0) {
            rc = gen_publickey_from_rsa_openssh_priv_data(session, decrypted,
                                                          method, method_len,
                                                          pubkeydata,
                                                          pubkeydata_len,
                                                (libssh2_rsa_ctx**)key_ctx);
        }
   }
#endif
#if LIBSSH2_DSA
    if(strcmp("ssh-dss", (const char *)buf) == 0) {
        if(key_type == NULL || strcmp("ssh-dss", key_type) == 0) {
            rc = gen_publickey_from_dsa_openssh_priv_data(session, decrypted,
                                                         method, method_len,
                                                          pubkeydata,
                                                          pubkeydata_len,
                                                 (libssh2_dsa_ctx**)key_ctx);
        }
   }
#endif
#if LIBSSH2_ECDSA
{
   libssh2_curve_type type;

   if(_libssh2_ecdsa_curve_type_from_name((const char *)buf, &type) == 0) {
       if(key_type == NULL || strcmp("ssh-ecdsa", key_type) == 0) {
           rc = gen_publickey_from_ecdsa_openssh_priv_data(session, type,
                                                           decrypted,
                                                           method, method_len,
                                                           pubkeydata,
                                                           pubkeydata_len,
                                               (libssh2_ecdsa_ctx**)key_ctx);
        }
    }
}
#endif

    if(rc == LIBSSH2_ERROR_FILE)
        rc = _libssh2_error(session, LIBSSH2_ERROR_FILE,
                         "Unable to extract public key from private key file: "
                         "invalid/unrecognized private key file format");

    if(decrypted)
        _libssh2_string_buf_free(session, decrypted);

    return rc;
}

int
read_openssh_private_key_from_memory(void **key_ctx, LIBSSH2_SESSION *session,
                                     const char *key_type,
                                     const char *filedata,
                                     size_t filedata_len,
                                     unsigned const char *passphrase)
{
    return _libssh2_pub_priv_openssh_keyfilememory(session, key_ctx, key_type,
                                                   NULL, NULL, NULL, NULL,
                                                   filedata, filedata_len,
                                                   passphrase);
}

int
_libssh2_pub_priv_keyfilememory(LIBSSH2_SESSION *session,
                                unsigned char **method,
                                size_t *method_len,
                                unsigned char **pubkeydata,
                                size_t *pubkeydata_len,
                                const char *privatekeydata,
                                size_t privatekeydata_len,
                                const char *passphrase)
{
    int       st;
    BIO*      bp;
    EVP_PKEY* pk;
    int       pktype;

    _libssh2_debug(session,
                   LIBSSH2_TRACE_AUTH,
                   "Computing public key from private key.");

    bp = BIO_new_mem_buf((char *)privatekeydata, privatekeydata_len);
    if(!bp)
        return _libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                              "Unable to allocate memory when"
                              "computing public key");
    BIO_reset(bp);
    pk = PEM_read_bio_PrivateKey(bp, NULL, NULL, (void *)passphrase);
    BIO_free(bp);

    if(pk == NULL) {
        /* Try OpenSSH format */
        st = _libssh2_pub_priv_openssh_keyfilememory(session, NULL, NULL,
                                                     method,
                                                     method_len,
                                                     pubkeydata,
                                                     pubkeydata_len,
                                                     privatekeydata,
                                                     privatekeydata_len,
                                           (unsigned const char *)passphrase);
        if(st != 0)
            return st;
        return 0;
    }

#ifdef HAVE_OPAQUE_STRUCTS
    pktype = EVP_PKEY_id(pk);
#else
    pktype = pk->type;
#endif

    switch(pktype) {
#if LIBSSH2_ED25519
    case EVP_PKEY_ED25519 :
        st = gen_publickey_from_ed_evp(
            session, method, method_len, pubkeydata, pubkeydata_len, pk);
        break;
#endif /* LIBSSH2_ED25519 */
    case EVP_PKEY_RSA :
        st = gen_publickey_from_rsa_evp(session, method, method_len,
                                        pubkeydata, pubkeydata_len, pk);
        break;
#if LIBSSH2_DSA
    case EVP_PKEY_DSA :
        st = gen_publickey_from_dsa_evp(session, method, method_len,
                                        pubkeydata, pubkeydata_len, pk);
        break;
#endif /* LIBSSH_DSA */
#if LIBSSH2_ECDSA
    case EVP_PKEY_EC :
        st = gen_publickey_from_ec_evp(session, method, method_len,
                                       pubkeydata, pubkeydata_len, pk);
        break;
#endif /* LIBSSH2_ECDSA */
    default :
        st = _libssh2_error(session,
                            LIBSSH2_ERROR_FILE,
                            "Unable to extract public key "
                            "from private key file: "
                            "Unsupported private key file format");
        break;
    }

    EVP_PKEY_free(pk);
    return st;
}

void
_libssh2_dh_init(_libssh2_dh_ctx *dhctx)
{
    *dhctx = BN_new();                          /* Random from client */
}

int
_libssh2_dh_key_pair(_libssh2_dh_ctx *dhctx, _libssh2_bn *public,
                     _libssh2_bn *g, _libssh2_bn *p, int group_order,
                     _libssh2_bn_ctx *bnctx)
{
    /* Generate x and e */
    BN_rand(*dhctx, group_order * 8 - 1, 0, -1);
    BN_mod_exp(public, g, *dhctx, p, bnctx);
    return 0;
}

int
_libssh2_dh_secret(_libssh2_dh_ctx *dhctx, _libssh2_bn *secret,
                   _libssh2_bn *f, _libssh2_bn *p,
                   _libssh2_bn_ctx *bnctx)
{
    /* Compute the shared secret */
    BN_mod_exp(secret, f, *dhctx, p, bnctx);
    return 0;
}

void
_libssh2_dh_dtor(_libssh2_dh_ctx *dhctx)
{
    BN_clear_free(*dhctx);
    *dhctx = NULL;
}

#endif /* LIBSSH2_OPENSSL */
