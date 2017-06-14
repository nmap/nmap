#include "libssh2_priv.h"

#ifdef LIBSSH2_MBEDTLS /* compile only if we build with mbedtls */

/*******************************************************************/
/*
 * mbedTLS backend: Generic functions
 */

void
_libssh2_mbedtls_init(void)
{
    int ret;

    mbedtls_entropy_init(&_libssh2_mbedtls_entropy);
    mbedtls_ctr_drbg_init(&_libssh2_mbedtls_ctr_drbg);

    ret = mbedtls_ctr_drbg_seed(&_libssh2_mbedtls_ctr_drbg,
                                mbedtls_entropy_func,
                                &_libssh2_mbedtls_entropy, NULL, 0);
    if (ret != 0)
        mbedtls_ctr_drbg_free(&_libssh2_mbedtls_ctr_drbg);
}

void
_libssh2_mbedtls_free(void)
{
    mbedtls_ctr_drbg_free(&_libssh2_mbedtls_ctr_drbg);
    mbedtls_entropy_free(&_libssh2_mbedtls_entropy);
}

int
_libssh2_mbedtls_random(unsigned char *buf, int len)
{
    int ret;
    ret = mbedtls_ctr_drbg_random(&_libssh2_mbedtls_ctr_drbg, buf, len);
    return ret == 0 ? 0 : -1;
}

static void
_libssh2_mbedtls_safe_free(void *buf, int len)
{
#ifndef LIBSSH2_CLEAR_MEMORY
    (void)len;
#endif

    if (!buf)
        return;

#ifdef LIBSSH2_CLEAR_MEMORY
    if (len > 0)
        memset(buf, 0, len);
#endif

    mbedtls_free(buf);
}

int
_libssh2_mbedtls_cipher_init(_libssh2_cipher_ctx *ctx,
                             _libssh2_cipher_type(algo),
                             unsigned char *iv,
                             unsigned char *secret,
                             int encrypt)
{
    const mbedtls_cipher_info_t *cipher_info;
    int ret, op;

    if (!ctx)
        return -1;

    op = encrypt == 0 ? MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT;

    cipher_info = mbedtls_cipher_info_from_type(algo);
    if(!cipher_info)
        return -1;

    mbedtls_cipher_init(ctx);
    ret = mbedtls_cipher_setup(ctx, cipher_info);
    if(!ret)
        ret = mbedtls_cipher_setkey(ctx, secret, cipher_info->key_bitlen, op);

    if(!ret)
        ret = mbedtls_cipher_set_iv(ctx, iv, cipher_info->iv_size);

    return ret == 0 ? 0 : -1;
}

int
_libssh2_mbedtls_cipher_crypt(_libssh2_cipher_ctx *ctx,
                              _libssh2_cipher_type(algo),
                              int encrypt,
                              unsigned char *block,
                              size_t blocklen)
{
    int ret;
    unsigned char *output;
    size_t osize, olen, finish_olen;

    (void) encrypt;
    (void) algo;

    osize = blocklen+mbedtls_cipher_get_block_size(ctx);

    output = (unsigned char *)mbedtls_calloc(osize, sizeof(char));
    if(output)
    {
        ret = mbedtls_cipher_reset(ctx);

        if(!ret)
            ret = mbedtls_cipher_update(ctx, block, blocklen, output, &olen);

        if(!ret)
            ret = mbedtls_cipher_finish(ctx, output + olen, &finish_olen);

        if (!ret) {
            olen += finish_olen;
            memcpy(block, output, olen);
        }

        _libssh2_mbedtls_safe_free(output, osize);
    }
    else
        ret = -1;

    return ret == 0 ? 0 : -1;
}

void
_libssh2_mbedtls_cipher_dtor(_libssh2_cipher_ctx *ctx)
{
    mbedtls_cipher_free(ctx);
}


int
_libssh2_mbedtls_hash_init(mbedtls_md_context_t *ctx,
                          mbedtls_md_type_t mdtype,
                          const unsigned char *key, unsigned long keylen)
{
    const mbedtls_md_info_t *md_info;
    int ret, hmac;

    md_info = mbedtls_md_info_from_type(mdtype);
    if(!md_info)
        return 0;

    hmac = key == NULL ? 0 : 1;

    mbedtls_md_init(ctx);
    ret = mbedtls_md_setup(ctx, md_info, hmac);
    if (!ret){
        if (hmac)
            ret = mbedtls_md_hmac_starts(ctx, key, keylen);
        else
            ret = mbedtls_md_starts(ctx);
    }

    return ret == 0 ? 1 : 0;
}

int
_libssh2_mbedtls_hash_final(mbedtls_md_context_t *ctx, unsigned char *hash)
{
    int ret;

    ret = mbedtls_md_finish(ctx, hash);
    mbedtls_md_free(ctx);

    return ret == 0 ? 0 : -1;
}

int
_libssh2_mbedtls_hash(const unsigned char *data, unsigned long datalen,
                      mbedtls_md_type_t mdtype, unsigned char *hash)
{
    const mbedtls_md_info_t *md_info;
    int ret;

    md_info = mbedtls_md_info_from_type(mdtype);
    if(!md_info)
        return 0;

    ret = mbedtls_md(md_info, data, datalen, hash);

    return ret == 0 ? 0 : -1;
}

/*******************************************************************/
/*
 * mbedTLS backend: BigNumber functions
 */

_libssh2_bn *
_libssh2_mbedtls_bignum_init(void)
{
    _libssh2_bn *bignum;

    bignum = (_libssh2_bn *)mbedtls_calloc(1, sizeof(_libssh2_bn));
    if (bignum) {
        mbedtls_mpi_init(bignum);
    }

    return bignum;
}

int
_libssh2_mbedtls_bignum_random(_libssh2_bn *bn, int bits, int top, int bottom)
{
    size_t len;
    int err;
    int i;

    if (!bn || bits <= 0)
        return -1;

    len = (bits + 7) >> 3;
    err = mbedtls_mpi_fill_random(bn, len, mbedtls_ctr_drbg_random, &_libssh2_mbedtls_ctr_drbg);
    if (err)
        return -1;

    /* Zero unsued bits above the most significant bit*/
    for(i=len*8-1;bits<=i;--i) {
        err = mbedtls_mpi_set_bit(bn, i, 0);
        if (err)
            return -1;
    }

    /* If `top` is -1, the most significant bit of the random number can be zero.
       If top is 0, the most significant bit of the random number is set to 1,
       and if top is 1, the two most significant bits of the number will be set
       to 1, so that the product of two such random numbers will always have 2*bits length.
    */
    for(i=0;i<=top;++i) {
        err = mbedtls_mpi_set_bit(bn, bits-i-1, 1);
        if (err)
            return -1;
    }

    /* make odd by setting first bit in least significant byte */
    if (bottom) {
        err = mbedtls_mpi_set_bit(bn, 0, 1);
        if (err)
            return -1;
    }

    return 0;
}


/*******************************************************************/
/*
 * mbedTLS backend: RSA functions
 */

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
                        unsigned long coefflen)
{
    int ret;
    libssh2_rsa_ctx *ctx;

    ctx = (libssh2_rsa_ctx *) mbedtls_calloc(1, sizeof(libssh2_rsa_ctx));
    if (ctx != NULL) {
        mbedtls_rsa_init(ctx, MBEDTLS_RSA_PKCS_V15, 0);
    }
    else
        return -1;

    if( (ret = mbedtls_mpi_read_binary(&(ctx->E), edata, elen) ) != 0 ||
        (ret = mbedtls_mpi_read_binary(&(ctx->N), ndata, nlen) ) != 0 )
    {
        ret = -1;
    }

    if (!ret)
    {
        ctx->len = mbedtls_mpi_size(&(ctx->N));
    }

    if (!ret && ddata)
    {
        if( (ret = mbedtls_mpi_read_binary(&(ctx->D) , ddata, dlen) ) != 0 ||
            (ret = mbedtls_mpi_read_binary(&(ctx->P) , pdata, plen) ) != 0 ||
            (ret = mbedtls_mpi_read_binary(&(ctx->Q) , qdata, qlen) ) != 0 ||
            (ret = mbedtls_mpi_read_binary(&(ctx->DP), e1data, e1len) ) != 0 ||
            (ret = mbedtls_mpi_read_binary(&(ctx->DQ), e2data, e2len) ) != 0 ||
            (ret = mbedtls_mpi_read_binary(&(ctx->QP), coeffdata, coefflen) ) != 0 )
        {
            ret = -1;
        }
        ret = mbedtls_rsa_check_privkey(ctx);
    }
    else if (!ret)
    {
        ret = mbedtls_rsa_check_pubkey(ctx);
    }

    if (ret && ctx) {
        _libssh2_mbedtls_rsa_free(ctx);
        ctx = NULL;
    }
    *rsa = ctx;
    return ret;
}

int
_libssh2_mbedtls_rsa_new_private(libssh2_rsa_ctx **rsa,
                                LIBSSH2_SESSION *session,
                                const char *filename,
                                const unsigned char *passphrase)
{
    int ret;
    mbedtls_pk_context pkey;

    *rsa = (libssh2_rsa_ctx *) LIBSSH2_ALLOC(session, sizeof(libssh2_rsa_ctx));
    if (*rsa == NULL)
        return -1;

    mbedtls_rsa_init(*rsa, MBEDTLS_RSA_PKCS_V15, 0);
    mbedtls_pk_init(&pkey);

    ret = mbedtls_pk_parse_keyfile(&pkey, filename, (char *)passphrase);
    if( ret != 0 || mbedtls_pk_get_type(&pkey) != MBEDTLS_PK_RSA)
    {
        mbedtls_pk_free(&pkey);
        mbedtls_rsa_free(*rsa);
        LIBSSH2_FREE(session, *rsa);
        *rsa = NULL;
        return -1;
    }

    mbedtls_rsa_context *pk_rsa = mbedtls_pk_rsa(pkey);
    mbedtls_rsa_copy(*rsa, pk_rsa);
    mbedtls_pk_free(&pkey);

    return 0;
}

int
_libssh2_mbedtls_rsa_new_private_frommemory(libssh2_rsa_ctx **rsa,
                                           LIBSSH2_SESSION *session,
                                           const char *filedata,
                                           size_t filedata_len,
                                           unsigned const char *passphrase)
{
    int ret;
    mbedtls_pk_context pkey;

    *rsa = (libssh2_rsa_ctx *) mbedtls_calloc( 1, sizeof( libssh2_rsa_ctx ) );
    if (*rsa == NULL)
        return -1;

    mbedtls_pk_init(&pkey);

    ret = mbedtls_pk_parse_key(&pkey, (unsigned char *)filedata,
                              filedata_len, NULL, 0);
    if( ret != 0 || mbedtls_pk_get_type(&pkey) != MBEDTLS_PK_RSA)
    {
        mbedtls_pk_free(&pkey);
        mbedtls_rsa_free(*rsa);
        LIBSSH2_FREE(session, *rsa);
        *rsa = NULL;
        return -1;
    }

    mbedtls_rsa_context *pk_rsa = mbedtls_pk_rsa(pkey);
    mbedtls_rsa_copy(*rsa, pk_rsa);
    mbedtls_pk_free(&pkey);

    return 0;
}

int
_libssh2_mbedtls_rsa_sha1_verify(libssh2_rsa_ctx *rsa,
                                const unsigned char *sig,
                                unsigned long sig_len,
                                const unsigned char *m,
                                unsigned long m_len)
{
    unsigned char hash[SHA_DIGEST_LENGTH];
    int ret;

    ret = _libssh2_mbedtls_hash(m, m_len, MBEDTLS_MD_SHA1, hash);
    if(ret)
        return -1; /* failure */

    ret = mbedtls_rsa_pkcs1_verify(rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC,
                                   MBEDTLS_MD_SHA1, SHA_DIGEST_LENGTH, hash, sig);

    return (ret == 0) ? 0 : -1;
}

int
_libssh2_mbedtls_rsa_sha1_sign(LIBSSH2_SESSION *session,
                              libssh2_rsa_ctx *rsa,
                              const unsigned char *hash,
                              size_t hash_len,
                              unsigned char **signature,
                              size_t *signature_len)
{
    int ret;
    unsigned char *sig;
    unsigned int sig_len;

    (void)hash_len;

    sig_len = rsa->len;
    sig = LIBSSH2_ALLOC(session, sig_len);
    if (!sig) {
        return -1;
    }

    ret = mbedtls_rsa_pkcs1_sign(rsa, NULL, NULL, MBEDTLS_RSA_PRIVATE,
                                 MBEDTLS_MD_SHA1, SHA_DIGEST_LENGTH,
                                 hash, sig);
    if (ret) {
        LIBSSH2_FREE(session, sig);
        return -1;
    }

    *signature = sig;
    *signature_len = sig_len;

    return (ret == 0) ? 0 : -1;
}

void
_libssh2_mbedtls_rsa_free(libssh2_rsa_ctx *ctx)
{
    mbedtls_rsa_free(ctx);
    mbedtls_free(ctx);
}

static unsigned char *
gen_publickey_from_rsa(LIBSSH2_SESSION *session,
                      mbedtls_rsa_context *rsa,
                      size_t *keylen)
{
    int            e_bytes, n_bytes;
    unsigned long  len;
    unsigned char* key;
    unsigned char* p;

    e_bytes = mbedtls_mpi_size(&rsa->E);
    n_bytes = mbedtls_mpi_size(&rsa->N);

    /* Key form is "ssh-rsa" + e + n. */
    len = 4 + 7 + 4 + e_bytes + 4 + n_bytes;

    key = LIBSSH2_ALLOC(session, len);
    if (!key) {
        return NULL;
    }

    /* Process key encoding. */
    p = key;

    _libssh2_htonu32(p, 7);  /* Key type. */
    p += 4;
    memcpy(p, "ssh-rsa", 7);
    p += 7;

    _libssh2_htonu32(p, e_bytes);
    p += 4;
    mbedtls_mpi_write_binary(&rsa->E, p, e_bytes);

    _libssh2_htonu32(p, n_bytes);
    p += 4;
    mbedtls_mpi_write_binary(&rsa->N, p, n_bytes);

    *keylen = (size_t)(p - key);
    return key;
}

static int
_libssh2_mbedtls_pub_priv_key(LIBSSH2_SESSION *session,
                               unsigned char **method,
                               size_t *method_len,
                               unsigned char **pubkeydata,
                               size_t *pubkeydata_len,
                               mbedtls_pk_context *pkey)
{
    unsigned char *key = NULL, *mth = NULL;
    size_t keylen = 0, mthlen = 0;
    int ret;

    if( mbedtls_pk_get_type(pkey) != MBEDTLS_PK_RSA )
    {
        mbedtls_pk_free(pkey);
        return _libssh2_error(session, LIBSSH2_ERROR_FILE,
                              "Key type not supported");
    }

    // write method
    mthlen = 7;
    mth = LIBSSH2_ALLOC(session, mthlen);
    if (mth) {
        memcpy(mth, "ssh-rsa", mthlen);
    } else {
        ret = -1;
    }

    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(*pkey);
    key = gen_publickey_from_rsa(session, rsa, &keylen);
    if (key == NULL) {
        ret = -1;
    }

    // write output
    if (ret) {
        if (mth)
            LIBSSH2_FREE(session, mth);
        if (key)
            LIBSSH2_FREE(session, key);
    } else {
        *method = mth;
        *method_len = mthlen;
        *pubkeydata = key;
        *pubkeydata_len = keylen;
    }

    return ret;
}

int
_libssh2_mbedtls_pub_priv_keyfile(LIBSSH2_SESSION *session,
                                 unsigned char **method,
                                 size_t *method_len,
                                 unsigned char **pubkeydata,
                                 size_t *pubkeydata_len,
                                 const char *privatekey,
                                 const char *passphrase)
{
    mbedtls_pk_context pkey;
    char buf[1024];
    int ret;

    mbedtls_pk_init(&pkey);
    ret = mbedtls_pk_parse_keyfile(&pkey, privatekey, passphrase);
    if( ret != 0 )
    {
        mbedtls_strerror(ret, (char *)buf, sizeof(buf));
        mbedtls_pk_free(&pkey);
        return _libssh2_error(session, LIBSSH2_ERROR_FILE, buf);
    }

    ret = _libssh2_mbedtls_pub_priv_key(session, method, method_len,
                                       pubkeydata, pubkeydata_len, &pkey);

    mbedtls_pk_free(&pkey);

    return ret;
}

int
_libssh2_mbedtls_pub_priv_keyfilememory(LIBSSH2_SESSION *session,
                                       unsigned char **method,
                                       size_t *method_len,
                                       unsigned char **pubkeydata,
                                       size_t *pubkeydata_len,
                                       const char *privatekeydata,
                                       size_t privatekeydata_len,
                                       const char *passphrase)
{
    mbedtls_pk_context pkey;
    char buf[1024];
    int ret;

    mbedtls_pk_init(&pkey);
    ret = mbedtls_pk_parse_key(&pkey, (unsigned char *)privatekeydata,
                              privatekeydata_len, NULL, 0);
    if( ret != 0 )
    {
        mbedtls_strerror(ret, (char *)buf, sizeof(buf));
        mbedtls_pk_free(&pkey);
        return _libssh2_error(session, LIBSSH2_ERROR_FILE, buf);
    }

    ret = _libssh2_mbedtls_pub_priv_key(session, method, method_len,
                                       pubkeydata, pubkeydata_len, &pkey);

    mbedtls_pk_free(&pkey);

    return ret;
}

void _libssh2_init_aes_ctr(void)
{
    /* no implementation */
}
#endif /* LIBSSH2_MBEDTLS */
