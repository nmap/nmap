/*
Usage: ./test-wildcard

This is a test program for the ssl_post_connect_check function. It generates
certificates with a variety of different combinations of commonNames and
dNSNames, then checks that matching names are accepted and non-matching names
are rejected. The SSL transactions happen over OpenSSL BIO pairs.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "ncat_core.h"

#define KEY_BITS 1024

static int tests_run = 0, tests_passed = 0;

/* A length-delimited string. */
struct lstr {
    size_t len;
    const char *s;
};

/* Make an anonymous struct lstr. */
#define LSTR(s) { sizeof(s) - 1, (s) }

/* Variable-length arrays of struct lstr are terminated with a special sentinel
   value. */
#define LSTR_SENTINEL { -1, NULL }
const struct lstr lstr_sentinel = LSTR_SENTINEL;

int is_sentinel(const struct lstr *name) {
    return name->len == -1;
}

int ssl_post_connect_check(SSL *ssl, const char *hostname);

static struct lstr *check(SSL *ssl, const struct lstr names[]);
static int ssl_ctx_trust_cert(SSL_CTX *ctx, X509 *cert);
static int gen_cert(X509 **cert, EVP_PKEY **key,
    const struct lstr commonNames[], const struct lstr dNSNames[]);
static void print_escaped(const char *s, size_t len);
static void print_array(const struct lstr array[]);
static int arrays_equal(const struct lstr a[], const struct lstr b[]);

/* Returns positive on success, 0 on failure. The various arrays must be
   NULL-terminated. */
static int test(const struct lstr commonNames[], const struct lstr dNSNames[],
    const struct lstr test_names[], const struct lstr expected[])
{
    SSL_CTX *server_ctx, *client_ctx;
    SSL *server_ssl, *client_ssl;
    BIO *server_bio, *client_bio;
    X509 *cert;
    EVP_PKEY *key;
    struct lstr *results;
    int need_accept, need_connect;
    int passed;

    tests_run++;

    ncat_assert(gen_cert(&cert, &key, commonNames, dNSNames) == 1);

    ncat_assert(BIO_new_bio_pair(&server_bio, 0, &client_bio, 0) == 1);

    server_ctx = SSL_CTX_new(SSLv23_server_method());
    ncat_assert(server_ctx != NULL);

    client_ctx = SSL_CTX_new(SSLv23_client_method());
    ncat_assert(client_ctx != NULL);
    SSL_CTX_set_verify(client_ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(client_ctx, 1);
    ssl_ctx_trust_cert(client_ctx, cert);

    server_ssl = SSL_new(server_ctx);
    ncat_assert(server_ssl != NULL);
    SSL_set_accept_state(server_ssl);
    SSL_set_bio(server_ssl, server_bio, server_bio);
    ncat_assert(SSL_use_certificate(server_ssl, cert) == 1);
    ncat_assert(SSL_use_PrivateKey(server_ssl, key) == 1);

    client_ssl = SSL_new(client_ctx);
    ncat_assert(client_ssl != NULL);
    SSL_set_connect_state(client_ssl);
    SSL_set_bio(client_ssl, client_bio, client_bio);

    passed = 0;

    need_accept = 1;
    need_connect = 1;
    do {
        int rc, err;

        if (need_accept) {
            rc = SSL_accept(server_ssl);
            err = SSL_get_error(server_ssl, rc);
            if (rc == 1) {
                need_accept = 0;
            } else {
                if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                    printf("SSL_accept: %s \n",
                        ERR_error_string(ERR_get_error(), NULL));
                    goto end;
                }
            }
        }
        if (need_connect) {
            rc = SSL_connect(client_ssl);
            err = SSL_get_error(client_ssl, rc);
            if (rc == 1) {
                need_connect = 0;
            } else {
                if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                    printf("SSL_connect: %s \n",
                        ERR_error_string(ERR_get_error(), NULL));
                    goto end;
                }
            }
        }
    } while (need_accept || need_connect);

    results = check(client_ssl, test_names);
    if (arrays_equal(results, expected)) {
        tests_passed++;
        passed = 1;
        printf("PASS CN");
        print_array(commonNames);
        printf(" DNS");
        print_array(dNSNames);
        printf("\n");
    } else {
        printf("FAIL CN");
        print_array(commonNames);
        printf(" DNS");
        print_array(dNSNames);
        printf("\n");
        printf("     got ");
        print_array(results);
        printf("\n");
        printf("expected ");
        print_array(expected);
        printf("\n");
    }
    free(results);

end:
    X509_free(cert);
    EVP_PKEY_free(key);

    (void) BIO_destroy_bio_pair(server_bio);

    SSL_CTX_free(server_ctx);
    SSL_CTX_free(client_ctx);

    SSL_free(server_ssl);
    SSL_free(client_ssl);

    return passed;
}

/* Returns a sentinel-terminated malloc-allocated array of names that match ssl
   with ssl_post_connect_check. */
static struct lstr *check(SSL *ssl, const struct lstr names[])
{
    const struct lstr *name;
    struct lstr *results = NULL;
    size_t size = 0, capacity = 0;

    if (names == NULL)
        return NULL;

    for (name = names; !is_sentinel(name); name++) {
        if (ssl_post_connect_check(ssl, name->s)) {
            if (size >= capacity) {
                capacity = (size + 1) * 2;
                results = safe_realloc(results, (capacity + 1) * sizeof(results[0]));
            }
            results[size++] = *name;
        }
    }
    results = safe_realloc(results, (size + 1) * sizeof(results[0]));
    results[size] = lstr_sentinel;

    return results;
}

/* Make a certificate object trusted by an SSL_CTX. I couldn't find a way to do
   this directly, so the certificate is written in PEM format to a temporary
   file and then loaded with SSL_CTX_load_verify_locations. Returns 1 on success
   and 0 on failure. */
static int ssl_ctx_trust_cert(SSL_CTX *ctx, X509 *cert)
{
    char name[] = "ncat-test-XXXXXX";
    int fd;
    FILE *fp;
    int rc;

    fd = mkstemp(name);
    if (fd == -1)
        return 0;
    fp = fdopen(fd, "w");
    if (fp == NULL) {
        close(fd);
        return 0;
    }
    if (PEM_write_X509(fp, cert) == 0) {
        fclose(fp);
        return 0;
    }
    fclose(fp);

    rc = SSL_CTX_load_verify_locations(ctx, name, NULL);
    if (rc == 0) {
        fprintf(stderr, "SSL_CTX_load_verify_locations: %s \n",
            ERR_error_string(ERR_get_error(), NULL));
    }
    if (unlink(name) == -1)
        fprintf(stderr, "unlink(\"%s\"): %s\n", name, strerror(errno));

    return rc;
}

static int set_dNSNames(X509 *cert, const struct lstr dNSNames[])
{
    STACK_OF(GENERAL_NAME) *gen_names;
    GENERAL_NAME *gen_name;
    X509_EXTENSION *ext;
    const struct lstr *name;

    if (dNSNames == NULL || is_sentinel(&dNSNames[0]))
        return 1;

    /* We break the abstraction here a bit because the normal way of setting
       a list of values, using an i2v method, uses a stack of CONF_VALUE that
       doesn't contain the length of each value. We rely on the fact that
       the internal representation (the "i" in "i2d") for
       NID_subject_alt_name is STACK_OF(GENERAL_NAME). */

    gen_names = sk_GENERAL_NAME_new_null();
    if (gen_names == NULL)
        return 0;

    for (name = dNSNames; !is_sentinel(name); name++) {
        gen_name = GENERAL_NAME_new();
        if (gen_name == NULL)
            goto stack_err;
        gen_name->type = GEN_DNS;
    #if OPENSSL_VERSION_NUMBER < 0x10100000L
        gen_name->d.dNSName = M_ASN1_IA5STRING_new();
    #else
        gen_name->d.dNSName = ASN1_IA5STRING_new();
    #endif
        if (gen_name->d.dNSName == NULL)
            goto name_err;
        if (ASN1_STRING_set(gen_name->d.dNSName, name->s, name->len) == 0)
            goto name_err;
        if (sk_GENERAL_NAME_push(gen_names, gen_name) == 0)
            goto name_err;
    }
    ext = X509V3_EXT_i2d(NID_subject_alt_name, 0, gen_names);
    if (ext == NULL)
        goto stack_err;
    if (X509_add_ext(cert, ext, -1) == 0) {
        X509_EXTENSION_free(ext);
        goto stack_err;
    }
    X509_EXTENSION_free(ext);
    sk_GENERAL_NAME_pop_free(gen_names, GENERAL_NAME_free);

    return 1;

name_err:
    GENERAL_NAME_free(gen_name);

stack_err:
    sk_GENERAL_NAME_pop_free(gen_names, GENERAL_NAME_free);

    return 0;
}

static int gen_cert(X509 **cert, EVP_PKEY **key,
    const struct lstr commonNames[], const struct lstr dNSNames[])
{
    RSA *rsa = NULL;
    BIGNUM *bne = NULL;
    int rc, ret=0;

    *cert = NULL;
    *key = NULL;

    /* Generate a private key. */
    *key = EVP_PKEY_new();
    if (*key == NULL)
        goto err;
    do {
        /* Generate RSA key. */
        bne = BN_new();
        ret = BN_set_word(bne, RSA_F4);
        if (ret != 1)
            goto err;

        rsa = RSA_new();
        ret = RSA_generate_key_ex(rsa, KEY_BITS, bne, NULL);
        if (ret != 1)
            goto err;
        /* Check RSA key. */
        rc = RSA_check_key(rsa);
    } while (rc == 0);
    if (rc == -1)
        goto err;
    if (EVP_PKEY_assign_RSA(*key, rsa) == 0) {
        RSA_free(rsa);
        goto err;
    }

    /* Generate a certificate. */
    *cert = X509_new();
    if (*cert == NULL)
        goto err;
    if (X509_set_version(*cert, 2) == 0) /* Version 3. */
        goto err;
    ASN1_INTEGER_set(X509_get_serialNumber(*cert), get_random_u32() & 0x7FFFFFFF);

    /* Set the commonNames. */
    if (commonNames != NULL) {
        X509_NAME *subj;
        const struct lstr *name;

        subj = X509_get_subject_name(*cert);
        for (name = commonNames; !is_sentinel(name); name++) {
            if (X509_NAME_add_entry_by_txt(subj, "commonName", MBSTRING_ASC,
                (unsigned char *) name->s, name->len, -1, 0) == 0) {
                goto err;
            }
        }
    }

    /* Set the dNSNames. */
    if (set_dNSNames(*cert, dNSNames) == 0)
        goto err;

    if (X509_set_issuer_name(*cert, X509_get_subject_name(*cert)) == 0
        || X509_gmtime_adj(X509_get_notBefore(*cert), 0) == 0
        || X509_gmtime_adj(X509_get_notAfter(*cert), 60) == 0
        || X509_set_pubkey(*cert, *key) == 0) {
        goto err;
    }

    /* Sign it. */
    if (X509_sign(*cert, *key, EVP_sha1()) == 0)
        goto err;

    return 1;

err:
    if (*cert != NULL)
        X509_free(*cert);
    if (*key != NULL)
        EVP_PKEY_free(*key);

    return 0;
}

static void print_escaped(const char *s, size_t len)
{
    int c;
    for ( ; len > 0; len--) {
        c = (unsigned char) *s++;
        if (isprint(c) && !isspace(c))
            putchar(c);
        else
            printf("\\%03o", c);
    }
}

static void print_array(const struct lstr array[])
{
    const struct lstr *p;

    if (array == NULL) {
        printf("[]");
        return;
    }
    printf("[");
    for (p = array; !is_sentinel(p); p++) {
        if (p != array)
            printf(" ");
        print_escaped(p->s, p->len);
    }
    printf("]");
}

static int lstr_equal(const struct lstr *a, const struct lstr *b)
{
    return a->len == b->len && memcmp(a->s, b->s, a->len) == 0;
}

static int arrays_equal(const struct lstr a[], const struct lstr b[])
{
    if (a == NULL)
        return b == NULL;
    if (b == NULL)
        return a == NULL;
    while (!is_sentinel(a) && !is_sentinel(b)) {
        if (!lstr_equal(a, b))
            return 0;
        a++;
        b++;
    }

    return is_sentinel(a) && is_sentinel(b);
}

/* This is just a constant used to give a fixed length to the arrays that are
   conceptually variable-length in the test cases. Increase it if some array
   grows too big. */
#define ARR_LEN 10

const struct lstr test_names[] = {
    LSTR("a.com"), LSTR("www.a.com"), LSTR("sub.www.a.com"),
    LSTR("www.example.com"), LSTR("example.co.uk"), LSTR("*.*.com"),
    LSTR_SENTINEL
};

/* These tests just check that matching a single string works properly. */
struct {
    const struct lstr name[ARR_LEN];
    const struct lstr expected[ARR_LEN];
} single_tests[] = {
    { { LSTR_SENTINEL },
      { LSTR_SENTINEL } },
    { { LSTR("a.com"), LSTR_SENTINEL },
      { LSTR("a.com"), LSTR_SENTINEL } },
    { { LSTR("www.a.com"), LSTR_SENTINEL },
      { LSTR("www.a.com"), LSTR_SENTINEL } },
    { { LSTR("*.a.com"), LSTR_SENTINEL },
      { LSTR("www.a.com"), LSTR_SENTINEL } },
    { { LSTR("w*.a.com"), LSTR_SENTINEL },
      { LSTR_SENTINEL } },
    { { LSTR("*w.a.com"), LSTR_SENTINEL },
      { LSTR_SENTINEL } },
    { { LSTR("www.*.com"), LSTR_SENTINEL },
      { LSTR_SENTINEL } },
    { { LSTR("*.com"), LSTR_SENTINEL },
      { LSTR_SENTINEL } },
    { { LSTR("*.com."), LSTR_SENTINEL },
      { LSTR_SENTINEL } },
    { { LSTR("*.*.com"), LSTR_SENTINEL },
      { LSTR_SENTINEL } },
    { { LSTR("a.com\0evil.com"), LSTR_SENTINEL },
      { LSTR_SENTINEL } },
};

/* These test different combinations of commonName and dNSName. */
struct {
    const struct lstr common[ARR_LEN];
    const struct lstr dns[ARR_LEN];
    const struct lstr expected[ARR_LEN];
} double_tests[] = {
    /* Should not match any commonName if any dNSNames exist. */
    { { LSTR("a.com"), LSTR_SENTINEL },
      { LSTR("example.co.uk"), LSTR_SENTINEL },
      { LSTR("example.co.uk"), LSTR_SENTINEL } },
    { { LSTR("a.com"), LSTR_SENTINEL },
      { LSTR("b.com"), LSTR_SENTINEL },
      { LSTR_SENTINEL } },
    /* Should check against all of the dNSNames. */
    { { LSTR_SENTINEL },
      { LSTR("a.com"), LSTR("example.co.uk"), LSTR("b.com"), LSTR_SENTINEL },
      { LSTR("a.com"), LSTR("example.co.uk"), LSTR_SENTINEL } },
};

const struct lstr specificity_test_names[] = {
    LSTR("a.com"),
    LSTR("sub.b.com"), LSTR("sub.c.com"), LSTR("sub.d.com"),
    LSTR("sub.sub.e.com"), LSTR("sub.sub.f.com"), LSTR("sub.sub.g.com"),
    LSTR_SENTINEL
};

/* Validation should check only the "most specific" commonName if multiple
   exist. This "most specific" term is used in RFCs 2818, 4261, and 5018 at
   least, but is not defined anywhere that I can find. Let's interpret it as the
   greatest number of name elements, with wildcard names considered less
   specific than all non-wildcard names. For ties, the name that comes later is
   considered more specific. */
struct {
    const struct lstr patterns[ARR_LEN];
    const struct lstr expected_forward;
    const struct lstr expected_backward;
} specificity_tests[] = {
    { { LSTR("a.com"), LSTR("*.b.com"), LSTR("sub.c.com"), LSTR("sub.d.com"), LSTR("*.sub.e.com"), LSTR("*.sub.f.com"), LSTR("sub.sub.g.com"), LSTR_SENTINEL },
      LSTR("sub.sub.g.com"), LSTR("sub.sub.g.com") },
    { { LSTR("a.com"), LSTR("*.b.com"), LSTR("sub.c.com"), LSTR("sub.d.com"), LSTR("*.sub.e.com"), LSTR("*.sub.f.com"), LSTR_SENTINEL },
      LSTR("sub.d.com"), LSTR("sub.c.com") },
    { { LSTR("a.com"), LSTR("*.b.com"), LSTR("sub.c.com"), LSTR("*.sub.e.com"), LSTR("*.sub.f.com"), LSTR_SENTINEL },
      LSTR("sub.c.com"), LSTR("sub.c.com") },
    { { LSTR("a.com"), LSTR("*.b.com"), LSTR("*.sub.e.com"), LSTR("*.sub.f.com"), LSTR_SENTINEL },
      LSTR("a.com"), LSTR("a.com") },
    { { LSTR("*.b.com"), LSTR("*.sub.e.com"), LSTR("*.sub.f.com"), LSTR_SENTINEL },
      LSTR("sub.sub.f.com"), LSTR("sub.sub.e.com") },
    { { LSTR("*.b.com"), LSTR("*.sub.e.com"), LSTR_SENTINEL },
      LSTR("sub.sub.e.com"), LSTR("sub.sub.e.com") },
};

#define NELEMS(a) (sizeof(a) / sizeof(a[0]))

void reverse(struct lstr a[])
{
    struct lstr tmp;
    unsigned int i, j;

    i = 0;
    for (j = 0; !is_sentinel(&a[j]); j++)
        ;
    if (j == 0)
        return;
    j--;
    while (i < j) {
        tmp = a[i];
        a[i] = a[j];
        a[j] = tmp;
        i++;
        j--;
    }
}

void test_specificity(const struct lstr patterns[],
    const struct lstr test_names[],
    const struct lstr expected_forward[],
    const struct lstr expected_backward[])
{
    struct lstr scratch[ARR_LEN];
    unsigned int i;

    for (i = 0; i < ARR_LEN && !is_sentinel(&patterns[i]); i++)
        scratch[i] = patterns[i];
    ncat_assert(i < ARR_LEN);
    scratch[i] = lstr_sentinel;

    test(scratch, NULL, test_names, expected_forward);
    reverse(scratch);
    test(scratch, NULL, test_names, expected_backward);

    return;
}

int main(void)
{
    unsigned int i;

    SSL_library_init();
    ERR_load_crypto_strings();
    SSL_load_error_strings();

    /* Test single pattens in both the commonName and dNSName positions. */
    for (i = 0; i < NELEMS(single_tests); i++)
        test(single_tests[i].name, NULL, test_names, single_tests[i].expected);
    for (i = 0; i < NELEMS(single_tests); i++)
        test(NULL, single_tests[i].name, test_names, single_tests[i].expected);

    for (i = 0; i < NELEMS(double_tests); i++) {
        test(double_tests[i].common, double_tests[i].dns,
            test_names, double_tests[i].expected);
    }

    for (i = 0; i < NELEMS(specificity_tests); i++) {
        struct lstr expected_forward[2], expected_backward[2];

        /* Put the expected names in arrays for the test. */
        expected_forward[0] = specificity_tests[i].expected_forward;
        expected_forward[1] = lstr_sentinel;
        expected_backward[0] = specificity_tests[i].expected_backward;
        expected_backward[1] = lstr_sentinel;
        test_specificity(specificity_tests[i].patterns,
            specificity_test_names, expected_forward, expected_backward);
    }

    printf("%d / %d tests passed.\n", tests_passed, tests_run);

    return tests_passed == tests_run ? 0 : 1;
}
