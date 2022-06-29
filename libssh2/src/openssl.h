#ifndef __LIBSSH2_OPENSSL_H
#define __LIBSSH2_OPENSSL_H
/* Copyright (C) 2009, 2010 Simon Josefsson
 * Copyright (C) 2006, 2007 The Written Word, Inc.  All rights reserved.
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

#include <openssl/opensslconf.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#ifndef OPENSSL_NO_DSA
#include <openssl/dsa.h>
#endif
#ifndef OPENSSL_NO_MD5
#include <openssl/md5.h>
#endif
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(LIBRESSL_VERSION_NUMBER)
# define HAVE_OPAQUE_STRUCTS 1
#endif

#ifdef OPENSSL_NO_RSA
# define LIBSSH2_RSA 0
#else
# define LIBSSH2_RSA 1
#endif

#ifdef OPENSSL_NO_DSA
# define LIBSSH2_DSA 0
#else
# define LIBSSH2_DSA 1
#endif

#ifdef OPENSSL_NO_ECDSA
# define LIBSSH2_ECDSA 0
#else
# define LIBSSH2_ECDSA 1
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10101000L && \
!defined(LIBRESSL_VERSION_NUMBER)
# define LIBSSH2_ED25519 1
#else
# define LIBSSH2_ED25519 0
#endif


#ifdef OPENSSL_NO_MD5
# define LIBSSH2_MD5 0
#else
# define LIBSSH2_MD5 1
#endif

#ifdef OPENSSL_NO_RIPEMD
# define LIBSSH2_HMAC_RIPEMD 0
#else
# define LIBSSH2_HMAC_RIPEMD 1
#endif

#define LIBSSH2_HMAC_SHA256 1
#define LIBSSH2_HMAC_SHA512 1

#if OPENSSL_VERSION_NUMBER >= 0x00907000L && !defined(OPENSSL_NO_AES)
# define LIBSSH2_AES_CTR 1
# define LIBSSH2_AES 1
#else
# define LIBSSH2_AES_CTR 0
# define LIBSSH2_AES 0
#endif

#ifdef OPENSSL_NO_BF
# define LIBSSH2_BLOWFISH 0
#else
# define LIBSSH2_BLOWFISH 1
#endif

#ifdef OPENSSL_NO_RC4
# define LIBSSH2_RC4 0
#else
# define LIBSSH2_RC4 1
#endif

#ifdef OPENSSL_NO_CAST
# define LIBSSH2_CAST 0
#else
# define LIBSSH2_CAST 1
#endif

#ifdef OPENSSL_NO_DES
# define LIBSSH2_3DES 0
#else
# define LIBSSH2_3DES 1
#endif

#define EC_MAX_POINT_LEN ((528 * 2 / 8) + 1)

#define _libssh2_random(buf, len) (RAND_bytes((buf), (len)) == 1 ? 0 : -1)

#define libssh2_prepare_iovec(vec, len)  /* Empty. */

#ifdef HAVE_OPAQUE_STRUCTS
#define libssh2_sha1_ctx EVP_MD_CTX *
#else
#define libssh2_sha1_ctx EVP_MD_CTX
#endif

/* returns 0 in case of failure */
int _libssh2_sha1_init(libssh2_sha1_ctx *ctx);
#define libssh2_sha1_init(x) _libssh2_sha1_init(x)
#ifdef HAVE_OPAQUE_STRUCTS
#define libssh2_sha1_update(ctx, data, len) EVP_DigestUpdate(ctx, data, len)
#define libssh2_sha1_final(ctx, out) do { \
                                         EVP_DigestFinal(ctx, out, NULL); \
                                         EVP_MD_CTX_free(ctx); \
                                     } while(0)
#else
#define libssh2_sha1_update(ctx, data, len) EVP_DigestUpdate(&(ctx), data, len)
#define libssh2_sha1_final(ctx, out) EVP_DigestFinal(&(ctx), out, NULL)
#endif
int _libssh2_sha1(const unsigned char *message, unsigned long len,
                  unsigned char *out);
#define libssh2_sha1(x,y,z) _libssh2_sha1(x,y,z)

#ifdef HAVE_OPAQUE_STRUCTS
#define libssh2_sha256_ctx EVP_MD_CTX *
#else
#define libssh2_sha256_ctx EVP_MD_CTX
#endif

/* returns 0 in case of failure */
int _libssh2_sha256_init(libssh2_sha256_ctx *ctx);
#define libssh2_sha256_init(x) _libssh2_sha256_init(x)
#ifdef HAVE_OPAQUE_STRUCTS
#define libssh2_sha256_update(ctx, data, len) EVP_DigestUpdate(ctx, data, len)
#define libssh2_sha256_final(ctx, out) do { \
                                           EVP_DigestFinal(ctx, out, NULL); \
                                           EVP_MD_CTX_free(ctx); \
                                       } while(0)
#else
#define libssh2_sha256_update(ctx, data, len) \
    EVP_DigestUpdate(&(ctx), data, len)
#define libssh2_sha256_final(ctx, out) EVP_DigestFinal(&(ctx), out, NULL)
#endif
int _libssh2_sha256(const unsigned char *message, unsigned long len,
                  unsigned char *out);
#define libssh2_sha256(x,y,z) _libssh2_sha256(x,y,z)

#ifdef HAVE_OPAQUE_STRUCTS
#define libssh2_sha384_ctx EVP_MD_CTX *
#else
#define libssh2_sha384_ctx EVP_MD_CTX
#endif

/* returns 0 in case of failure */
int _libssh2_sha384_init(libssh2_sha384_ctx *ctx);
#define libssh2_sha384_init(x) _libssh2_sha384_init(x)
#ifdef HAVE_OPAQUE_STRUCTS
#define libssh2_sha384_update(ctx, data, len) EVP_DigestUpdate(ctx, data, len)
#define libssh2_sha384_final(ctx, out) do { \
                                            EVP_DigestFinal(ctx, out, NULL); \
                                            EVP_MD_CTX_free(ctx); \
                                       } while(0)
#else
#define libssh2_sha384_update(ctx, data, len)   \
    EVP_DigestUpdate(&(ctx), data, len)
#define libssh2_sha384_final(ctx, out) EVP_DigestFinal(&(ctx), out, NULL)
#endif
int _libssh2_sha384(const unsigned char *message, unsigned long len,
                    unsigned char *out);
#define libssh2_sha384(x,y,z) _libssh2_sha384(x,y,z)

#ifdef HAVE_OPAQUE_STRUCTS
#define libssh2_sha512_ctx EVP_MD_CTX *
#else
#define libssh2_sha512_ctx EVP_MD_CTX
#endif

/* returns 0 in case of failure */
int _libssh2_sha512_init(libssh2_sha512_ctx *ctx);
#define libssh2_sha512_init(x) _libssh2_sha512_init(x)
#ifdef HAVE_OPAQUE_STRUCTS
#define libssh2_sha512_update(ctx, data, len) EVP_DigestUpdate(ctx, data, len)
#define libssh2_sha512_final(ctx, out) do { \
                                            EVP_DigestFinal(ctx, out, NULL); \
                                            EVP_MD_CTX_free(ctx); \
                                       } while(0)
#else
#define libssh2_sha512_update(ctx, data, len)   \
    EVP_DigestUpdate(&(ctx), data, len)
#define libssh2_sha512_final(ctx, out) EVP_DigestFinal(&(ctx), out, NULL)
#endif
int _libssh2_sha512(const unsigned char *message, unsigned long len,
                    unsigned char *out);
#define libssh2_sha512(x,y,z) _libssh2_sha512(x,y,z)

#ifdef HAVE_OPAQUE_STRUCTS
#define libssh2_md5_ctx EVP_MD_CTX *
#else
#define libssh2_md5_ctx EVP_MD_CTX
#endif

/* returns 0 in case of failure */
int _libssh2_md5_init(libssh2_md5_ctx *ctx);
#define libssh2_md5_init(x) _libssh2_md5_init(x)
#ifdef HAVE_OPAQUE_STRUCTS
#define libssh2_md5_update(ctx, data, len) EVP_DigestUpdate(ctx, data, len)
#define libssh2_md5_final(ctx, out) do { \
                                        EVP_DigestFinal(ctx, out, NULL); \
                                        EVP_MD_CTX_free(ctx); \
                                    } while(0)
#else
#define libssh2_md5_update(ctx, data, len) EVP_DigestUpdate(&(ctx), data, len)
#define libssh2_md5_final(ctx, out) EVP_DigestFinal(&(ctx), out, NULL)
#endif

#ifdef HAVE_OPAQUE_STRUCTS
#define libssh2_hmac_ctx HMAC_CTX *
#define libssh2_hmac_ctx_init(ctx) ctx = HMAC_CTX_new()
#define libssh2_hmac_sha1_init(ctx, key, keylen) \
  HMAC_Init_ex(*(ctx), key, keylen, EVP_sha1(), NULL)
#define libssh2_hmac_md5_init(ctx, key, keylen) \
  HMAC_Init_ex(*(ctx), key, keylen, EVP_md5(), NULL)
#define libssh2_hmac_ripemd160_init(ctx, key, keylen) \
  HMAC_Init_ex(*(ctx), key, keylen, EVP_ripemd160(), NULL)
#define libssh2_hmac_sha256_init(ctx, key, keylen) \
  HMAC_Init_ex(*(ctx), key, keylen, EVP_sha256(), NULL)
#define libssh2_hmac_sha512_init(ctx, key, keylen) \
  HMAC_Init_ex(*(ctx), key, keylen, EVP_sha512(), NULL)

#define libssh2_hmac_update(ctx, data, datalen) \
  HMAC_Update(ctx, data, datalen)
#define libssh2_hmac_final(ctx, data) HMAC_Final(ctx, data, NULL)
#define libssh2_hmac_cleanup(ctx) HMAC_CTX_free(*(ctx))
#else
#define libssh2_hmac_ctx HMAC_CTX
#define libssh2_hmac_ctx_init(ctx) \
  HMAC_CTX_init(&ctx)
#define libssh2_hmac_sha1_init(ctx, key, keylen) \
  HMAC_Init_ex(ctx, key, keylen, EVP_sha1(), NULL)
#define libssh2_hmac_md5_init(ctx, key, keylen) \
  HMAC_Init_ex(ctx, key, keylen, EVP_md5(), NULL)
#define libssh2_hmac_ripemd160_init(ctx, key, keylen) \
  HMAC_Init_ex(ctx, key, keylen, EVP_ripemd160(), NULL)
#define libssh2_hmac_sha256_init(ctx, key, keylen) \
  HMAC_Init_ex(ctx, key, keylen, EVP_sha256(), NULL)
#define libssh2_hmac_sha512_init(ctx, key, keylen) \
  HMAC_Init_ex(ctx, key, keylen, EVP_sha512(), NULL)

#define libssh2_hmac_update(ctx, data, datalen) \
  HMAC_Update(&(ctx), data, datalen)
#define libssh2_hmac_final(ctx, data) HMAC_Final(&(ctx), data, NULL)
#define libssh2_hmac_cleanup(ctx) HMAC_cleanup(ctx)
#endif

extern void _libssh2_openssl_crypto_init(void);
extern void _libssh2_openssl_crypto_exit(void);
#define libssh2_crypto_init() _libssh2_openssl_crypto_init()
#define libssh2_crypto_exit() _libssh2_openssl_crypto_exit()

#define libssh2_rsa_ctx RSA

#define _libssh2_rsa_free(rsactx) RSA_free(rsactx)

#define libssh2_dsa_ctx DSA

#define _libssh2_dsa_free(dsactx) DSA_free(dsactx)

#if LIBSSH2_ECDSA
#define libssh2_ecdsa_ctx EC_KEY
#define _libssh2_ecdsa_free(ecdsactx) EC_KEY_free(ecdsactx)
#define _libssh2_ec_key EC_KEY

typedef enum {
    LIBSSH2_EC_CURVE_NISTP256 = NID_X9_62_prime256v1,
    LIBSSH2_EC_CURVE_NISTP384 = NID_secp384r1,
    LIBSSH2_EC_CURVE_NISTP521 = NID_secp521r1
}
libssh2_curve_type;
#else
#define _libssh2_ec_key void
#endif /* LIBSSH2_ECDSA */

#if LIBSSH2_ED25519
#define libssh2_ed25519_ctx EVP_PKEY

#define _libssh2_ed25519_free(ctx) EVP_PKEY_free(ctx)
#endif /* ED25519 */

#define _libssh2_cipher_type(name) const EVP_CIPHER *(*name)(void)
#ifdef HAVE_OPAQUE_STRUCTS
#define _libssh2_cipher_ctx EVP_CIPHER_CTX *
#else
#define _libssh2_cipher_ctx EVP_CIPHER_CTX
#endif

#define _libssh2_cipher_aes256 EVP_aes_256_cbc
#define _libssh2_cipher_aes192 EVP_aes_192_cbc
#define _libssh2_cipher_aes128 EVP_aes_128_cbc
#ifdef HAVE_EVP_AES_128_CTR
#define _libssh2_cipher_aes128ctr EVP_aes_128_ctr
#define _libssh2_cipher_aes192ctr EVP_aes_192_ctr
#define _libssh2_cipher_aes256ctr EVP_aes_256_ctr
#else
#define _libssh2_cipher_aes128ctr _libssh2_EVP_aes_128_ctr
#define _libssh2_cipher_aes192ctr _libssh2_EVP_aes_192_ctr
#define _libssh2_cipher_aes256ctr _libssh2_EVP_aes_256_ctr
#endif
#define _libssh2_cipher_blowfish EVP_bf_cbc
#define _libssh2_cipher_arcfour EVP_rc4
#define _libssh2_cipher_cast5 EVP_cast5_cbc
#define _libssh2_cipher_3des EVP_des_ede3_cbc

#ifdef HAVE_OPAQUE_STRUCTS
#define _libssh2_cipher_dtor(ctx) EVP_CIPHER_CTX_free(*(ctx))
#else
#define _libssh2_cipher_dtor(ctx) EVP_CIPHER_CTX_cleanup(ctx)
#endif

#define _libssh2_bn BIGNUM
#define _libssh2_bn_ctx BN_CTX
#define _libssh2_bn_ctx_new() BN_CTX_new()
#define _libssh2_bn_ctx_free(bnctx) BN_CTX_free(bnctx)
#define _libssh2_bn_init() BN_new()
#define _libssh2_bn_init_from_bin() _libssh2_bn_init()
#define _libssh2_bn_set_word(bn, val) BN_set_word(bn, val)
#define _libssh2_bn_from_bin(bn, len, val) BN_bin2bn(val, len, bn)
#define _libssh2_bn_to_bin(bn, val) BN_bn2bin(bn, val)
#define _libssh2_bn_bytes(bn) BN_num_bytes(bn)
#define _libssh2_bn_bits(bn) BN_num_bits(bn)
#define _libssh2_bn_free(bn) BN_clear_free(bn)

#define _libssh2_dh_ctx BIGNUM *
#define libssh2_dh_init(dhctx) _libssh2_dh_init(dhctx)
#define libssh2_dh_key_pair(dhctx, public, g, p, group_order, bnctx) \
        _libssh2_dh_key_pair(dhctx, public, g, p, group_order, bnctx)
#define libssh2_dh_secret(dhctx, secret, f, p, bnctx) \
        _libssh2_dh_secret(dhctx, secret, f, p, bnctx)
#define libssh2_dh_dtor(dhctx) _libssh2_dh_dtor(dhctx)
extern void _libssh2_dh_init(_libssh2_dh_ctx *dhctx);
extern int _libssh2_dh_key_pair(_libssh2_dh_ctx *dhctx, _libssh2_bn *public,
                                _libssh2_bn *g, _libssh2_bn *p,
                                int group_order,
                                _libssh2_bn_ctx *bnctx);
extern int _libssh2_dh_secret(_libssh2_dh_ctx *dhctx, _libssh2_bn *secret,
                              _libssh2_bn *f, _libssh2_bn *p,
                              _libssh2_bn_ctx *bnctx);
extern void _libssh2_dh_dtor(_libssh2_dh_ctx *dhctx);

const EVP_CIPHER *_libssh2_EVP_aes_128_ctr(void);
const EVP_CIPHER *_libssh2_EVP_aes_192_ctr(void);
const EVP_CIPHER *_libssh2_EVP_aes_256_ctr(void);

#endif /* __LIBSSH2_OPENSSL_H */
