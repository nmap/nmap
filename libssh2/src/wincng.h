/*
 * Copyright (C) 2013-2015 Marc Hoersken <info@marc-hoersken.de>
 * All rights reserved.
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

/* required for cross-compilation against the w64 mingw-runtime package */
#if defined(_WIN32_WINNT) && (_WIN32_WINNT < 0x0600)
#undef _WIN32_WINNT
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include <windows.h>
#include <bcrypt.h>


#define LIBSSH2_MD5 1

#define LIBSSH2_HMAC_RIPEMD 0
#define LIBSSH2_HMAC_SHA256 1
#define LIBSSH2_HMAC_SHA512 1

#define LIBSSH2_AES 1
#define LIBSSH2_AES_CTR 0
#define LIBSSH2_BLOWFISH 0
#define LIBSSH2_RC4 1
#define LIBSSH2_CAST 0
#define LIBSSH2_3DES 1

#define LIBSSH2_RSA 1
#define LIBSSH2_DSA 1

#define MD5_DIGEST_LENGTH 16
#define SHA_DIGEST_LENGTH 20
#define SHA256_DIGEST_LENGTH 32
#define SHA512_DIGEST_LENGTH 64


/*******************************************************************/
/*
 * Windows CNG backend: Global context handles
 */

struct _libssh2_wincng_ctx {
    BCRYPT_ALG_HANDLE hAlgRNG;
    BCRYPT_ALG_HANDLE hAlgHashMD5;
    BCRYPT_ALG_HANDLE hAlgHashSHA1;
    BCRYPT_ALG_HANDLE hAlgHashSHA256;
    BCRYPT_ALG_HANDLE hAlgHashSHA512;
    BCRYPT_ALG_HANDLE hAlgHmacMD5;
    BCRYPT_ALG_HANDLE hAlgHmacSHA1;
    BCRYPT_ALG_HANDLE hAlgHmacSHA256;
    BCRYPT_ALG_HANDLE hAlgHmacSHA512;
    BCRYPT_ALG_HANDLE hAlgRSA;
    BCRYPT_ALG_HANDLE hAlgDSA;
    BCRYPT_ALG_HANDLE hAlgAES_CBC;
    BCRYPT_ALG_HANDLE hAlgRC4_NA;
    BCRYPT_ALG_HANDLE hAlg3DES_CBC;
};

struct _libssh2_wincng_ctx _libssh2_wincng;


/*******************************************************************/
/*
 * Windows CNG backend: Generic functions
 */

void _libssh2_wincng_init(void);
void _libssh2_wincng_free(void);

#define libssh2_crypto_init() \
  _libssh2_wincng_init()
#define libssh2_crypto_exit() \
  _libssh2_wincng_free()

#define _libssh2_random(buf, len) \
  _libssh2_wincng_random(buf, len)

#define libssh2_prepare_iovec(vec, len)  /* Empty. */


/*******************************************************************/
/*
 * Windows CNG backend: Hash structure
 */

typedef struct __libssh2_wincng_hash_ctx {
    BCRYPT_HASH_HANDLE hHash;
    unsigned char *pbHashObject;
    unsigned long dwHashObject;
    unsigned long cbHash;
} _libssh2_wincng_hash_ctx;

/*
 * Windows CNG backend: Hash functions
 */

#define libssh2_sha1_ctx _libssh2_wincng_hash_ctx
#define libssh2_sha1_init(ctx) \
  (_libssh2_wincng_hash_init(ctx, _libssh2_wincng.hAlgHashSHA1, \
                            SHA_DIGEST_LENGTH, NULL, 0) == 0)
#define libssh2_sha1_update(ctx, data, datalen) \
  _libssh2_wincng_hash_update(&ctx, (unsigned char *) data, datalen)
#define libssh2_sha1_final(ctx, hash) \
  _libssh2_wincng_hash_final(&ctx, hash)
#define libssh2_sha1(data, datalen, hash) \
  _libssh2_wincng_hash(data, datalen, _libssh2_wincng.hAlgHashSHA1, \
                       hash, SHA_DIGEST_LENGTH)

#define libssh2_sha256_ctx _libssh2_wincng_hash_ctx
#define libssh2_sha256_init(ctx) \
  (_libssh2_wincng_hash_init(ctx, _libssh2_wincng.hAlgHashSHA256, \
                            SHA256_DIGEST_LENGTH, NULL, 0) == 0)
#define libssh2_sha256_update(ctx, data, datalen) \
  _libssh2_wincng_hash_update(&ctx, (unsigned char *) data, datalen)
#define libssh2_sha256_final(ctx, hash) \
  _libssh2_wincng_hash_final(&ctx, hash)
#define libssh2_sha256(data, datalen, hash) \
  _libssh2_wincng_hash(data, datalen, _libssh2_wincng.hAlgHashSHA256, \
                       hash, SHA256_DIGEST_LENGTH)

#define libssh2_sha512_ctx _libssh2_wincng_hash_ctx
#define libssh2_sha512_init(ctx) \
  (_libssh2_wincng_hash_init(ctx, _libssh2_wincng.hAlgHashSHA512, \
                            SHA512_DIGEST_LENGTH, NULL, 0) == 0)
#define libssh2_sha512_update(ctx, data, datalen) \
  _libssh2_wincng_hash_update(&ctx, (unsigned char *) data, datalen)
#define libssh2_sha512_final(ctx, hash) \
  _libssh2_wincng_hash_final(&ctx, hash)
#define libssh2_sha512(data, datalen, hash) \
  _libssh2_wincng_hash(data, datalen, _libssh2_wincng.hAlgHashSHA512, \
                       hash, SHA512_DIGEST_LENGTH)

#define libssh2_md5_ctx _libssh2_wincng_hash_ctx
#define libssh2_md5_init(ctx) \
  (_libssh2_wincng_hash_init(ctx, _libssh2_wincng.hAlgHashMD5, \
                            MD5_DIGEST_LENGTH, NULL, 0) == 0)
#define libssh2_md5_update(ctx, data, datalen) \
  _libssh2_wincng_hash_update(&ctx, (unsigned char *) data, datalen)
#define libssh2_md5_final(ctx, hash) \
  _libssh2_wincng_hash_final(&ctx, hash)
#define libssh2_md5(data, datalen, hash) \
  _libssh2_wincng_hash(data, datalen, _libssh2_wincng.hAlgHashMD5, \
                       hash, MD5_DIGEST_LENGTH)

/*
 * Windows CNG backend: HMAC functions
 */

#define libssh2_hmac_ctx _libssh2_wincng_hash_ctx
#define libssh2_hmac_ctx_init(ctx)
#define libssh2_hmac_sha1_init(ctx, key, keylen) \
  _libssh2_wincng_hash_init(ctx, _libssh2_wincng.hAlgHmacSHA1, \
                            SHA_DIGEST_LENGTH, key, keylen)
#define libssh2_hmac_md5_init(ctx, key, keylen) \
  _libssh2_wincng_hash_init(ctx, _libssh2_wincng.hAlgHmacMD5, \
                            MD5_DIGEST_LENGTH, key, keylen)
#define libssh2_hmac_ripemd160_init(ctx, key, keylen)
  /* not implemented */
#define libssh2_hmac_sha256_init(ctx, key, keylen) \
  _libssh2_wincng_hash_init(ctx, _libssh2_wincng.hAlgHmacSHA256, \
                            SHA256_DIGEST_LENGTH, key, keylen)
#define libssh2_hmac_sha512_init(ctx, key, keylen) \
  _libssh2_wincng_hash_init(ctx, _libssh2_wincng.hAlgHmacSHA512, \
                            SHA512_DIGEST_LENGTH, key, keylen)
#define libssh2_hmac_update(ctx, data, datalen) \
  _libssh2_wincng_hash_update(&ctx, (unsigned char *) data, datalen)
#define libssh2_hmac_final(ctx, hash) \
  _libssh2_wincng_hmac_final(&ctx, hash)
#define libssh2_hmac_cleanup(ctx) \
  _libssh2_wincng_hmac_cleanup(ctx)


/*******************************************************************/
/*
 * Windows CNG backend: Key Context structure
 */

typedef struct __libssh2_wincng_key_ctx {
    BCRYPT_KEY_HANDLE hKey;
    unsigned char *pbKeyObject;
    unsigned long cbKeyObject;
} _libssh2_wincng_key_ctx;


/*
 * Windows CNG backend: RSA functions
 */

#define libssh2_rsa_ctx _libssh2_wincng_key_ctx
#define _libssh2_rsa_new(rsactx, e, e_len, n, n_len, \
                         d, d_len, p, p_len, q, q_len, \
                         e1, e1_len, e2, e2_len, c, c_len) \
  _libssh2_wincng_rsa_new(rsactx, e, e_len, n, n_len, \
                          d, d_len, p, p_len, q, q_len, \
                          e1, e1_len, e2, e2_len, c, c_len)
#define _libssh2_rsa_new_private(rsactx, s, filename, passphrase) \
  _libssh2_wincng_rsa_new_private(rsactx, s, filename, passphrase)
#define _libssh2_rsa_new_private_frommemory(rsactx, s, filedata, \
                                            filedata_len, passphrase) \
  _libssh2_wincng_rsa_new_private_frommemory(rsactx, s, filedata, \
                                             filedata_len, passphrase)
#define _libssh2_rsa_sha1_sign(s, rsactx, hash, hash_len, sig, sig_len) \
  _libssh2_wincng_rsa_sha1_sign(s, rsactx, hash, hash_len, sig, sig_len)
#define _libssh2_rsa_sha1_verify(rsactx, sig, sig_len, m, m_len) \
  _libssh2_wincng_rsa_sha1_verify(rsactx, sig, sig_len, m, m_len)
#define _libssh2_rsa_free(rsactx) \
  _libssh2_wincng_rsa_free(rsactx)

/*
 * Windows CNG backend: DSA functions
 */

#define libssh2_dsa_ctx _libssh2_wincng_key_ctx
#define _libssh2_dsa_new(dsactx, p, p_len, q, q_len, \
                         g, g_len, y, y_len, x, x_len) \
  _libssh2_wincng_dsa_new(dsactx, p, p_len, q, q_len, \
                          g, g_len, y, y_len, x, x_len)
#define _libssh2_dsa_new_private(dsactx, s, filename, passphrase) \
  _libssh2_wincng_dsa_new_private(dsactx, s, filename, passphrase)
#define _libssh2_dsa_new_private_frommemory(dsactx, s, filedata, \
                                            filedata_len, passphrase) \
  _libssh2_wincng_dsa_new_private_frommemory(dsactx, s, filedata, \
                                             filedata_len, passphrase)
#define _libssh2_dsa_sha1_sign(dsactx, hash, hash_len, sig) \
  _libssh2_wincng_dsa_sha1_sign(dsactx, hash, hash_len, sig)
#define _libssh2_dsa_sha1_verify(dsactx, sig, m, m_len) \
  _libssh2_wincng_dsa_sha1_verify(dsactx, sig, m, m_len)
#define _libssh2_dsa_free(dsactx) \
  _libssh2_wincng_dsa_free(dsactx)

/*
 * Windows CNG backend: Key functions
 */

#define _libssh2_pub_priv_keyfile(s, m, m_len, p, p_len, pk, pw) \
  _libssh2_wincng_pub_priv_keyfile(s, m, m_len, p, p_len, pk, pw)
#define _libssh2_pub_priv_keyfilememory(s, m, m_len, p, p_len, \
                                                     pk, pk_len, pw) \
  _libssh2_wincng_pub_priv_keyfilememory(s, m, m_len, p, p_len, \
                                                      pk, pk_len, pw)


/*******************************************************************/
/*
 * Windows CNG backend: Cipher Context structure
 */

struct _libssh2_wincng_cipher_ctx {
    BCRYPT_KEY_HANDLE hKey;
    unsigned char *pbKeyObject;
    unsigned char *pbIV;
    unsigned long dwKeyObject;
    unsigned long dwIV;
    unsigned long dwBlockLength;
};

#define _libssh2_cipher_ctx struct _libssh2_wincng_cipher_ctx

/*
 * Windows CNG backend: Cipher Type structure
 */

struct _libssh2_wincng_cipher_type {
    BCRYPT_ALG_HANDLE *phAlg;
    unsigned long dwKeyLength;
    unsigned long dwUseIV;
};

#define _libssh2_cipher_type(type) struct _libssh2_wincng_cipher_type type

#define _libssh2_cipher_aes256ctr { NULL, 32, 1 } /* not supported */
#define _libssh2_cipher_aes192ctr { NULL, 24, 1 } /* not supported */
#define _libssh2_cipher_aes128ctr { NULL, 16, 1 } /* not supported */
#define _libssh2_cipher_aes256 { &_libssh2_wincng.hAlgAES_CBC, 32, 1 }
#define _libssh2_cipher_aes192 { &_libssh2_wincng.hAlgAES_CBC, 24, 1 }
#define _libssh2_cipher_aes128 { &_libssh2_wincng.hAlgAES_CBC, 16, 1 }
#define _libssh2_cipher_blowfish { NULL, 16, 0 } /* not supported */
#define _libssh2_cipher_arcfour { &_libssh2_wincng.hAlgRC4_NA, 16, 0 }
#define _libssh2_cipher_cast5 { NULL, 16, 0 } /* not supported */
#define _libssh2_cipher_3des { &_libssh2_wincng.hAlg3DES_CBC, 24, 1 }

/*
 * Windows CNG backend: Cipher functions
 */

#define _libssh2_cipher_init(ctx, type, iv, secret, encrypt) \
  _libssh2_wincng_cipher_init(ctx, type, iv, secret, encrypt)
#define _libssh2_cipher_crypt(ctx, type, encrypt, block, blocklen) \
  _libssh2_wincng_cipher_crypt(ctx, type, encrypt, block, blocklen)
#define _libssh2_cipher_dtor(ctx) \
  _libssh2_wincng_cipher_dtor(ctx)

/*******************************************************************/
/*
 * Windows CNG backend: BigNumber Context
 */

#define _libssh2_bn_ctx int /* not used */
#define _libssh2_bn_ctx_new() 0 /* not used */
#define _libssh2_bn_ctx_free(bnctx) ((void)0) /* not used */


/*******************************************************************/
/*
 * Windows CNG backend: BigNumber structure
 */

struct _libssh2_wincng_bignum {
    unsigned char *bignum;
    unsigned long length;
};

#define _libssh2_bn struct _libssh2_wincng_bignum

/*
 * Windows CNG backend: BigNumber functions
 */

_libssh2_bn *_libssh2_wincng_bignum_init(void);

#define _libssh2_bn_init() \
  _libssh2_wincng_bignum_init()
#define _libssh2_bn_init_from_bin() \
  _libssh2_bn_init()
#define _libssh2_bn_rand(bn, bits, top, bottom) \
  _libssh2_wincng_bignum_rand(bn, bits, top, bottom)
#define _libssh2_bn_mod_exp(r, a, p, m, ctx) \
  _libssh2_wincng_bignum_mod_exp(r, a, p, m, ctx)
#define _libssh2_bn_set_word(bn, word) \
  _libssh2_wincng_bignum_set_word(bn, word)
#define _libssh2_bn_from_bin(bn, len, bin) \
  _libssh2_wincng_bignum_from_bin(bn, len, bin)
#define _libssh2_bn_to_bin(bn, bin) \
  _libssh2_wincng_bignum_to_bin(bn, bin)
#define _libssh2_bn_bytes(bn) bn->length
#define _libssh2_bn_bits(bn) \
  _libssh2_wincng_bignum_bits(bn)
#define _libssh2_bn_free(bn) \
  _libssh2_wincng_bignum_free(bn)

/*******************************************************************/
/*
 * Windows CNG backend: forward declarations
 */
void _libssh2_wincng_init(void);
void _libssh2_wincng_free(void);
int _libssh2_wincng_random(void *buf, int len);
void _libssh2_init_aes_ctr(void);

int
_libssh2_wincng_hash_init(_libssh2_wincng_hash_ctx *ctx,
                          BCRYPT_ALG_HANDLE hAlg, unsigned long hashlen,
                          unsigned char *key, unsigned long keylen);
int
_libssh2_wincng_hash_update(_libssh2_wincng_hash_ctx *ctx,
                            const unsigned char *data, unsigned long datalen);
int
_libssh2_wincng_hash_final(_libssh2_wincng_hash_ctx *ctx,
                           unsigned char *hash);
int
_libssh2_wincng_hash(unsigned char *data, unsigned long datalen,
                     BCRYPT_ALG_HANDLE hAlg,
                     unsigned char *hash, unsigned long hashlen);

int
_libssh2_wincng_hmac_final(_libssh2_wincng_hash_ctx *ctx,
                           unsigned char *hash);
void
_libssh2_wincng_hmac_cleanup(_libssh2_wincng_hash_ctx *ctx);

int
_libssh2_wincng_key_sha1_verify(_libssh2_wincng_key_ctx *ctx,
                                const unsigned char *sig,
                                unsigned long sig_len,
                                const unsigned char *m,
                                unsigned long m_len,
                                unsigned long flags);

int
_libssh2_wincng_rsa_new(libssh2_rsa_ctx **rsa,
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
                        const unsigned char *coeffdata,
                        unsigned long coefflen);
int
_libssh2_wincng_rsa_new_private(libssh2_rsa_ctx **rsa,
                                LIBSSH2_SESSION *session,
                                const char *filename,
                                const unsigned char *passphrase);
int
_libssh2_wincng_rsa_new_private_frommemory(libssh2_rsa_ctx **rsa,
                                           LIBSSH2_SESSION *session,
                                           const char *filedata,
                                           size_t filedata_len,
                                           unsigned const char *passphrase);
int
_libssh2_wincng_rsa_sha1_verify(libssh2_rsa_ctx *rsa,
                                const unsigned char *sig,
                                unsigned long sig_len,
                                const unsigned char *m,
                                unsigned long m_len);
int
_libssh2_wincng_rsa_sha1_sign(LIBSSH2_SESSION *session,
                              libssh2_rsa_ctx *rsa,
                              const unsigned char *hash,
                              size_t hash_len,
                              unsigned char **signature,
                              size_t *signature_len);
void
_libssh2_wincng_rsa_free(libssh2_rsa_ctx *rsa);

#if LIBSSH2_DSA
int
_libssh2_wincng_dsa_new(libssh2_dsa_ctx **dsa,
                        const unsigned char *pdata,
                        unsigned long plen,
                        const unsigned char *qdata,
                        unsigned long qlen,
                        const unsigned char *gdata,
                        unsigned long glen,
                        const unsigned char *ydata,
                        unsigned long ylen,
                        const unsigned char *xdata,
                        unsigned long xlen);
int
_libssh2_wincng_dsa_new_private(libssh2_dsa_ctx **dsa,
                                LIBSSH2_SESSION *session,
                                const char *filename,
                                const unsigned char *passphrase);
int
_libssh2_wincng_dsa_new_private_frommemory(libssh2_dsa_ctx **dsa,
                                           LIBSSH2_SESSION *session,
                                           const char *filedata,
                                           size_t filedata_len,
                                           unsigned const char *passphrase);
int
_libssh2_wincng_dsa_sha1_verify(libssh2_dsa_ctx *dsa,
                                const unsigned char *sig_fixed,
                                const unsigned char *m,
                                unsigned long m_len);
int
_libssh2_wincng_dsa_sha1_sign(libssh2_dsa_ctx *dsa,
                              const unsigned char *hash,
                              unsigned long hash_len,
                              unsigned char *sig_fixed);
void
_libssh2_wincng_dsa_free(libssh2_dsa_ctx *dsa);
#endif

int
_libssh2_wincng_pub_priv_keyfile(LIBSSH2_SESSION *session,
                                 unsigned char **method,
                                 size_t *method_len,
                                 unsigned char **pubkeydata,
                                 size_t *pubkeydata_len,
                                 const char *privatekey,
                                 const char *passphrase);
int
_libssh2_wincng_pub_priv_keyfilememory(LIBSSH2_SESSION *session,
                                       unsigned char **method,
                                       size_t *method_len,
                                       unsigned char **pubkeydata,
                                       size_t *pubkeydata_len,
                                       const char *privatekeydata,
                                       size_t privatekeydata_len,
                                       const char *passphrase);

int
_libssh2_wincng_cipher_init(_libssh2_cipher_ctx *ctx,
                            _libssh2_cipher_type(type),
                            unsigned char *iv,
                            unsigned char *secret,
                            int encrypt);
int
_libssh2_wincng_cipher_crypt(_libssh2_cipher_ctx *ctx,
                             _libssh2_cipher_type(type),
                             int encrypt,
                             unsigned char *block,
                             size_t blocklen);
void
_libssh2_wincng_cipher_dtor(_libssh2_cipher_ctx *ctx);

_libssh2_bn *
_libssh2_wincng_bignum_init(void);
int
_libssh2_wincng_bignum_rand(_libssh2_bn *rnd, int bits, int top, int bottom);
int
_libssh2_wincng_bignum_mod_exp(_libssh2_bn *r,
                               _libssh2_bn *a,
                               _libssh2_bn *p,
                               _libssh2_bn *m,
                               _libssh2_bn_ctx *bnctx);
int
_libssh2_wincng_bignum_set_word(_libssh2_bn *bn, unsigned long word);
unsigned long
_libssh2_wincng_bignum_bits(const _libssh2_bn *bn);
void
_libssh2_wincng_bignum_from_bin(_libssh2_bn *bn, unsigned long len,
                                const unsigned char *bin);
void
_libssh2_wincng_bignum_to_bin(const _libssh2_bn *bn, unsigned char *bin);
void
_libssh2_wincng_bignum_free(_libssh2_bn *bn);
