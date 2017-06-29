#include <stdlib.h>
#include <string.h>

#include <mbedtls/platform.h>
#include <mbedtls/md.h>
#include <mbedtls/rsa.h>
#include <mbedtls/bignum.h>
#include <mbedtls/cipher.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/pk.h>
#include <mbedtls/error.h>

/* Define which features are supported. */
#define LIBSSH2_MD5             1

#define LIBSSH2_HMAC_RIPEMD     1
#define LIBSSH2_HMAC_SHA256     1
#define LIBSSH2_HMAC_SHA512     1

#define LIBSSH2_AES             1
#define LIBSSH2_AES_CTR         1
#define LIBSSH2_BLOWFISH        1
#define LIBSSH2_RC4             1
#define LIBSSH2_CAST            0
#define LIBSSH2_3DES            1

#define LIBSSH2_RSA             1
#define LIBSSH2_DSA             0

#define MD5_DIGEST_LENGTH      16
#define SHA_DIGEST_LENGTH      20
#define SHA256_DIGEST_LENGTH   32
#define SHA512_DIGEST_LENGTH   64

/*******************************************************************/
/*
 * mbedTLS backend: Global context handles
 */

mbedtls_entropy_context  _libssh2_mbedtls_entropy;
mbedtls_ctr_drbg_context _libssh2_mbedtls_ctr_drbg;

/*******************************************************************/
/*
 * mbedTLS backend: Generic functions
 */

#define libssh2_crypto_init() \
  _libssh2_mbedtls_init()
#define libssh2_crypto_exit() \
  _libssh2_mbedtls_free()

#define _libssh2_random(buf, len) \
  _libssh2_mbedtls_random(buf, len)

#define libssh2_prepare_iovec(vec, len)  /* Empty. */


/*******************************************************************/
/*
 * mbedTLS backend: HMAC functions
 */

#define libssh2_hmac_ctx    mbedtls_md_context_t

#define libssh2_hmac_ctx_init(ctx)
#define libssh2_hmac_cleanup(pctx) \
  mbedtls_md_free(pctx)
#define libssh2_hmac_update(ctx, data, datalen) \
  mbedtls_md_hmac_update(&ctx, (unsigned char *) data, datalen)
#define libssh2_hmac_final(ctx, hash) \
  mbedtls_md_hmac_finish(&ctx, hash)

#define libssh2_hmac_sha1_init(pctx, key, keylen) \
  _libssh2_mbedtls_hash_init(pctx, MBEDTLS_MD_SHA1, key, keylen)
#define libssh2_hmac_md5_init(pctx, key, keylen) \
  _libssh2_mbedtls_hash_init(pctx, MBEDTLS_MD_MD5, key, keylen)
#define libssh2_hmac_ripemd160_init(pctx, key, keylen) \
  _libssh2_mbedtls_hash_init(pctx, MBEDTLS_MD_RIPEMD160, key, keylen)
#define libssh2_hmac_sha256_init(pctx, key, keylen) \
  _libssh2_mbedtls_hash_init(pctx, MBEDTLS_MD_SHA256, key, keylen)
#define libssh2_hmac_sha512_init(pctx, key, keylen) \
  _libssh2_mbedtls_hash_init(pctx, MBEDTLS_MD_SHA512, key, keylen)


/*******************************************************************/
/*
 * mbedTLS backend: SHA1 functions
 */

#define libssh2_sha1_ctx      mbedtls_md_context_t

#define libssh2_sha1_init(pctx) \
  _libssh2_mbedtls_hash_init(pctx, MBEDTLS_MD_SHA1, NULL, 0)
#define libssh2_sha1_update(ctx, data, datalen) \
  mbedtls_md_update(&ctx, (unsigned char *) data, datalen)
#define libssh2_sha1_final(ctx, hash) \
  _libssh2_mbedtls_hash_final(&ctx, hash)
#define libssh2_sha1(data, datalen, hash) \
  _libssh2_mbedtls_hash(data, datalen, MBEDTLS_MD_SHA1, hash)

/*******************************************************************/
/*
 * mbedTLS backend: SHA256 functions
 */

#define libssh2_sha256_ctx      mbedtls_md_context_t

#define libssh2_sha256_init(pctx) \
  _libssh2_mbedtls_hash_init(pctx, MBEDTLS_MD_SHA256, NULL, 0)
#define libssh2_sha256_update(ctx, data, datalen) \
  mbedtls_md_update(&ctx, (unsigned char *) data, datalen)
#define libssh2_sha256_final(ctx, hash) \
  _libssh2_mbedtls_hash_final(&ctx, hash)
#define libssh2_sha256(data, datalen, hash) \
  _libssh2_mbedtls_hash(data, datalen, MBEDTLS_MD_SHA256, hash)


/*******************************************************************/
/*
 * mbedTLS backend: SHA512 functions
 */

#define libssh2_sha512_ctx      mbedtls_md_context_t

#define libssh2_sha512_init(pctx) \
  _libssh2_mbedtls_hash_init(pctx, MBEDTLS_MD_SHA512, NULL, 0)
#define libssh2_sha512_update(ctx, data, datalen) \
  mbedtls_md_update(&ctx, (unsigned char *) data, datalen)
#define libssh2_sha512_final(ctx, hash) \
  _libssh2_mbedtls_hash_final(&ctx, hash)
#define libssh2_sha512(data, datalen, hash) \
  _libssh2_mbedtls_hash(data, datalen, MBEDTLS_MD_SHA512, hash)


/*******************************************************************/
/*
 * mbedTLS backend: MD5 functions
 */

#define libssh2_md5_ctx      mbedtls_md_context_t

#define libssh2_md5_init(pctx) \
  _libssh2_mbedtls_hash_init(pctx, MBEDTLS_MD_MD5, NULL, 0)
#define libssh2_md5_update(ctx, data, datalen) \
  mbedtls_md_update(&ctx, (unsigned char *) data, datalen)
#define libssh2_md5_final(ctx, hash) \
  _libssh2_mbedtls_hash_final(&ctx, hash)
#define libssh2_md5(data, datalen, hash) \
  _libssh2_mbedtls_hash(data, datalen, MBEDTLS_MD_MD5, hash)

/*******************************************************************/
/*
 * mbedTLS backend: RSA structure
 */

#define libssh2_rsa_ctx  mbedtls_rsa_context

#define _libssh2_rsa_new(rsactx, e, e_len, n, n_len, \
                         d, d_len, p, p_len, q, q_len, \
                         e1, e1_len, e2, e2_len, c, c_len) \
  _libssh2_mbedtls_rsa_new(rsactx, e, e_len, n, n_len, \
                          d, d_len, p, p_len, q, q_len, \
                          e1, e1_len, e2, e2_len, c, c_len)

#define _libssh2_rsa_new_private(rsactx, s, filename, passphrase) \
  _libssh2_mbedtls_rsa_new_private(rsactx, s, filename, passphrase)

#define _libssh2_rsa_new_private_frommemory(rsactx, s, filedata, \
                                            filedata_len, passphrase) \
  _libssh2_mbedtls_rsa_new_private_frommemory(rsactx, s, filedata, \
                                             filedata_len, passphrase)

#define _libssh2_rsa_sha1_sign(s, rsactx, hash, hash_len, sig, sig_len) \
  _libssh2_mbedtls_rsa_sha1_sign(s, rsactx, hash, hash_len, sig, sig_len)

#define _libssh2_rsa_sha1_verify(rsactx, sig, sig_len, m, m_len) \
  _libssh2_mbedtls_rsa_sha1_verify(rsactx, sig, sig_len, m, m_len)

#define _libssh2_rsa_free(rsactx) \
  _libssh2_mbedtls_rsa_free(rsactx)

/*
 * mbedTLS backend: Key functions
 */

#define _libssh2_pub_priv_keyfile(s, m, m_len, p, p_len, pk, pw) \
  _libssh2_mbedtls_pub_priv_keyfile(s, m, m_len, p, p_len, pk, pw)
#define _libssh2_pub_priv_keyfilememory(s, m, m_len, p, p_len, \
                                                     pk, pk_len, pw) \
  _libssh2_mbedtls_pub_priv_keyfilememory(s, m, m_len, p, p_len, \
                                                      pk, pk_len, pw)


 /*******************************************************************/
/*
 * mbedTLS backend: Cipher Context structure
 */
#define _libssh2_cipher_ctx         mbedtls_cipher_context_t

#define _libssh2_cipher_type(algo)  mbedtls_cipher_type_t algo

#define _libssh2_cipher_aes256ctr MBEDTLS_CIPHER_AES_256_CTR
#define _libssh2_cipher_aes192ctr MBEDTLS_CIPHER_AES_192_CTR
#define _libssh2_cipher_aes128ctr MBEDTLS_CIPHER_AES_128_CTR
#define _libssh2_cipher_aes256    MBEDTLS_CIPHER_AES_256_CBC
#define _libssh2_cipher_aes192    MBEDTLS_CIPHER_AES_192_CBC
#define _libssh2_cipher_aes128    MBEDTLS_CIPHER_AES_128_CBC
#define _libssh2_cipher_blowfish  MBEDTLS_CIPHER_BLOWFISH_CBC
#define _libssh2_cipher_arcfour   MBEDTLS_CIPHER_ARC4_128
#define _libssh2_cipher_cast5     MBEDTLS_CIPHER_NULL
#define _libssh2_cipher_3des      MBEDTLS_CIPHER_DES_EDE3_CBC

/*
 * mbedTLS backend: Cipher functions
 */

#define _libssh2_cipher_init(ctx, type, iv, secret, encrypt) \
  _libssh2_mbedtls_cipher_init(ctx, type, iv, secret, encrypt)
#define _libssh2_cipher_crypt(ctx, type, encrypt, block, blocklen) \
  _libssh2_mbedtls_cipher_crypt(ctx, type, encrypt, block, blocklen)
#define _libssh2_cipher_dtor(ctx) \
  _libssh2_mbedtls_cipher_dtor(ctx)


/*******************************************************************/
/*
 * mbedTLS backend: BigNumber Support
 */

#define _libssh2_bn_ctx int /* not used */
#define _libssh2_bn_ctx_new() 0 /* not used */
#define _libssh2_bn_ctx_free(bnctx) ((void)0) /* not used */

#define _libssh2_bn mbedtls_mpi

#define _libssh2_bn_init() \
  _libssh2_mbedtls_bignum_init()
#define _libssh2_bn_init_from_bin() \
  _libssh2_mbedtls_bignum_init()
#define _libssh2_bn_rand(bn, bits, top, bottom) \
  _libssh2_mbedtls_bignum_random(bn, bits, top, bottom)
#define _libssh2_bn_mod_exp(r, a, p, m, ctx) \
  mbedtls_mpi_exp_mod(r, a, p, m, NULL)
#define _libssh2_bn_set_word(bn, word) \
  mbedtls_mpi_lset(bn, word)
#define _libssh2_bn_from_bin(bn, len, bin) \
  mbedtls_mpi_read_binary(bn, bin, len)
#define _libssh2_bn_to_bin(bn, bin) \
  mbedtls_mpi_write_binary(bn, bin, mbedtls_mpi_size(bn))
#define _libssh2_bn_bytes(bn) \
  mbedtls_mpi_size(bn)
#define _libssh2_bn_bits(bn) \
  mbedtls_mpi_bitlen(bn)
#define _libssh2_bn_free(bn) \
  mbedtls_mpi_free(bn)


/*******************************************************************/
/*
 * mbedTLS backend: forward declarations
 */
void
_libssh2_mbedtls_init(void);

void
_libssh2_mbedtls_free(void);

int
_libssh2_mbedtls_random(unsigned char *buf, int len);

int
_libssh2_mbedtls_cipher_init(_libssh2_cipher_ctx *ctx,
                            _libssh2_cipher_type(type),
                            unsigned char *iv,
                            unsigned char *secret,
                            int encrypt);
int
_libssh2_mbedtls_cipher_crypt(_libssh2_cipher_ctx *ctx,
                             _libssh2_cipher_type(type),
                             int encrypt,
                             unsigned char *block,
                             size_t blocklen);
void
_libssh2_mbedtls_cipher_dtor(_libssh2_cipher_ctx *ctx);

int
_libssh2_mbedtls_hash_init(mbedtls_md_context_t *ctx,
                          mbedtls_md_type_t mdtype,
                          const unsigned char *key, unsigned long keylen);

int
_libssh2_mbedtls_hash_final(mbedtls_md_context_t *ctx, unsigned char *hash);
int
_libssh2_mbedtls_hash(const unsigned char *data, unsigned long datalen,
                      mbedtls_md_type_t mdtype, unsigned char *hash);

_libssh2_bn *
_libssh2_mbedtls_bignum_init(void);

void
_libssh2_mbedtls_bignum_free(_libssh2_bn *bn);

int
_libssh2_mbedtls_bignum_random(_libssh2_bn *bn, int bits, int top, int bottom);

int
_libssh2_mbedtls_rsa_new(libssh2_rsa_ctx **rsa,
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
_libssh2_mbedtls_rsa_new_private(libssh2_rsa_ctx **rsa,
                                LIBSSH2_SESSION *session,
                                const char *filename,
                                const unsigned char *passphrase);

int
_libssh2_mbedtls_rsa_new_private_frommemory(libssh2_rsa_ctx **rsa,
                                           LIBSSH2_SESSION *session,
                                           const char *filedata,
                                           size_t filedata_len,
                                           unsigned const char *passphrase);
int
_libssh2_mbedtls_rsa_sha1_verify(libssh2_rsa_ctx *rsa,
                                const unsigned char *sig,
                                unsigned long sig_len,
                                const unsigned char *m,
                                unsigned long m_len);
int
_libssh2_mbedtls_rsa_sha1_sign(LIBSSH2_SESSION *session,
                              libssh2_rsa_ctx *rsa,
                              const unsigned char *hash,
                              size_t hash_len,
                              unsigned char **signature,
                              size_t *signature_len);
void
_libssh2_mbedtls_rsa_free(libssh2_rsa_ctx *rsa);

int
_libssh2_mbedtls_pub_priv_keyfile(LIBSSH2_SESSION *session,
                                 unsigned char **method,
                                 size_t *method_len,
                                 unsigned char **pubkeydata,
                                 size_t *pubkeydata_len,
                                 const char *privatekey,
                                 const char *passphrase);
int
_libssh2_mbedtls_pub_priv_keyfilememory(LIBSSH2_SESSION *session,
                                       unsigned char **method,
                                       size_t *method_len,
                                       unsigned char **pubkeydata,
                                       size_t *pubkeydata_len,
                                       const char *privatekeydata,
                                       size_t privatekeydata_len,
                                       const char *passphrase);
