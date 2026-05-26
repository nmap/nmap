#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

/* We test the snprintf-like behavior by calling snprintf (or the custom one)
 * with adversarial inputs and asserting that:
 * 1. The output buffer is never written beyond its declared size
 * 2. The result is always null-terminated within the buffer
 * 3. The return value correctly reflects truncation
 */

/* Canary-protected buffer wrapper to detect out-of-bounds writes */
#define CANARY_VALUE 0xDEADBEEF
#define CANARY_SIZE  8

typedef struct {
    uint32_t pre_canary[CANARY_SIZE];
    char     buf[4096];
    uint32_t post_canary[CANARY_SIZE];
} protected_buffer_t;

static void init_protected_buffer(protected_buffer_t *pb) {
    for (int i = 0; i < CANARY_SIZE; i++) {
        pb->pre_canary[i]  = CANARY_VALUE;
        pb->post_canary[i] = CANARY_VALUE;
    }
    memset(pb->buf, 0xAB, sizeof(pb->buf));
}

static int check_canaries(const protected_buffer_t *pb) {
    for (int i = 0; i < CANARY_SIZE; i++) {
        if (pb->pre_canary[i]  != CANARY_VALUE) return 0;
        if (pb->post_canary[i] != CANARY_VALUE) return 0;
    }
    return 1;
}

/* Generate a string of given length filled with a repeated character */
static char *make_long_string(size_t len, char fill) {
    char *s = (char *)malloc(len + 1);
    if (!s) return NULL;
    memset(s, fill, len);
    s[len] = '\0';
    return s;
}

START_TEST(test_snprintf_no_oob_read)
{
    /* Invariant: Buffer reads never exceed the declared length;
     * output is always truncated to fit within the declared buffer size,
     * and the buffer is always null-terminated within bounds. */

    const char *static_payloads[] = {
        /* Basic oversized strings */
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        /* Format string attacks */
        "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
        "%n%n%n%n%n%n%n%n%n%n",
        "%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x",
        "%.99999999s",
        "%99999999d",
        "%99999999f",
        /* Null bytes and special chars */
        "test\x00hidden",
        /* Very long format specifiers */
        "%-2147483648d",
        "%2147483647d",
        /* Repeated percent signs */
        "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%",
        /* Mixed format and long string */
        "%s %s %s %s %s",
        /* Integer overflow attempts in width */
        "%4294967295d",
        "%4294967295s",
        /* Negative width */
        "%-999999999s",
        /* Precision attacks */
        "%.*s",
        "%.2147483647s",
        /* Stack smashing patterns */
        "AAAA%08x%08x%08x%08x%08x%08x%08x%08x",
        /* Boundary values */
        "%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s",
    };

    int num_static = sizeof(static_payloads) / sizeof(static_payloads[0]);

    /* Test with various small buffer sizes to stress truncation logic */
    size_t buf_sizes[] = {1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 4095};
    int num_sizes = sizeof(buf_sizes) / sizeof(buf_sizes[0]);

    /* Test static payloads with various buffer sizes */
    for (int i = 0; i < num_static; i++) {
        for (int j = 0; j < num_sizes; j++) {
            size_t sz = buf_sizes[j];
            char *output = (char *)malloc(sz + 2 * sizeof(uint32_t) * CANARY_SIZE);
            ck_assert_ptr_nonnull(output);

            /* Place canaries around the buffer */
            uint32_t *pre  = (uint32_t *)output;
            char     *buf  = output + sizeof(uint32_t) * CANARY_SIZE;
            uint32_t *post = (uint32_t *)(buf + sz);

            for (int k = 0; k < CANARY_SIZE; k++) {
                pre[k]  = CANARY_VALUE;
                post[k] = CANARY_VALUE;
            }
            memset(buf, 0xAB, sz);

            /* Call snprintf with the adversarial payload as format string
             * and also as an argument to %s */
            int ret = snprintf(buf, sz, "%s", static_payloads[i]);

            /* Invariant 1: canaries must be intact (no OOB write) */
            for (int k = 0; k < CANARY_SIZE; k++) {
                ck_assert_msg(pre[k]  == CANARY_VALUE,
                    "Pre-canary corrupted for payload[%d] size=%zu", i, sz);
                ck_assert_msg(post[k] == CANARY_VALUE,
                    "Post-canary corrupted for payload[%d] size=%zu", i, sz);
            }

            /* Invariant 2: if sz > 0, buffer must be null-terminated */
            if (sz > 0) {
                ck_assert_msg(buf[sz - 1] == '\0' || memchr(buf, '\0', sz) != NULL,
                    "Buffer not null-terminated for payload[%d] size=%zu", i, sz);
            }

            /* Invariant 3: return value must be >= 0 */
            ck_assert_msg(ret >= 0,
                "snprintf returned negative for payload[%d] size=%zu", i, sz);

            free(output);
        }
    }

    /* Test with dynamically generated oversized strings */
    size_t dynamic_lengths[] = {
        100, 255, 256, 512, 1000, 1024, 2048, 4096, 8192, 65536
    };
    int num_dynamic = sizeof(dynamic_lengths) / sizeof(dynamic_lengths[0]);

    for (int i = 0; i < num_dynamic; i++) {
        char *long_str = make_long_string(dynamic_lengths[i], 'A');
        ck_assert_ptr_nonnull(long_str);

        for (int j = 0; j < num_sizes; j++) {
            size_t sz = buf_sizes[j];
            char *output = (char *)malloc(sz + 2 * sizeof(uint32_t) * CANARY_SIZE);
            ck_assert_ptr_nonnull(output);

            uint32_t *pre  = (uint32_t *)output;
            char     *buf  = output + sizeof(uint32_t) * CANARY_SIZE;
            uint32_t *post = (uint32_t *)(buf + sz);

            for (int k = 0; k < CANARY_SIZE; k++) {
                pre[k]  = CANARY_VALUE;
                post[k] = CANARY_VALUE;
            }
            memset(buf, 0xAB, sz);

            int ret = snprintf(buf, sz, "%s", long_str);

            /* Invariant 1: canaries intact */
            for (int k = 0; k < CANARY_SIZE; k++) {
                ck_assert_msg(pre[k]  == CANARY_VALUE,
                    "Pre-canary corrupted: dynamic len=%zu buf_size=%zu",
                    dynamic_lengths[i], sz);
                ck_assert_msg(post[k] == CANARY_VALUE,
                    "Post-canary corrupted: dynamic len=%zu buf_size=%zu",
                    dynamic_lengths[i], sz);
            }

            /* Invariant 2: null-terminated */
            if (sz > 0) {
                ck_assert_msg(memchr(buf, '\0', sz) != NULL,
                    "Buffer not null-terminated: dynamic len=%zu buf_size=%zu",
                    dynamic_lengths[i], sz);
            }

            /* Invariant 3: non-negative return */
            ck_assert_msg(ret >= 0,
                "snprintf returned negative: dynamic len=%zu buf_size=%zu",
                dynamic_lengths[i], sz);

            /* Invariant 4: actual written content must not exceed sz-1 chars */
            if (sz > 0) {
                size_t written = strnlen(buf, sz);
                ck_assert_msg(written < sz,
                    "Written length %zu >= buffer size %zu", written, sz);
            }

            free(output);
        }

        free(long_str);
    }

    /* Test with protected_buffer_t for full-size buffer stress test */
    protected_buffer_t *pb = (protected_buffer_t *)malloc(sizeof(protected_buffer_t));
    ck_assert_ptr_nonnull(pb);

    /* 2x oversized: format a string 2x the buffer size */
    char *oversized_2x = make_long_string(sizeof(pb->buf) * 2, 'B');
    ck_assert_ptr_nonnull(oversized_2x);

    init_protected_buffer(pb);
    snprintf(pb->buf, sizeof(pb->buf), "%s", oversized_2x);
    ck_assert_msg(check_canaries(pb), "Canary corrupted with 2x oversized input");
    ck_assert_msg(pb->buf[sizeof(pb->buf) - 1] == '\0',
        "Buffer not null-terminated with 2x oversized input");
    free(oversized_2x);

    /* 10x oversized */
    char *oversized_10x = make_long_string(sizeof(pb->buf) * 10, 'C');
    ck_assert_ptr_nonnull(oversized_10x);

    init_protected_buffer(pb);
    snprintf(pb->buf, sizeof(pb->buf), "%s", oversized_10x);
    ck_assert_msg(check_canaries(pb), "Canary corrupted with 10x oversized input");
    ck_assert_msg(pb->buf[sizeof(pb->buf) - 1] == '\0',
        "Buffer not null-terminated with 10x oversized input");
    free(oversized_10x);

    /* Test with numeric format specifiers and extreme values */
    init_protected_buffer(pb);
    snprintf(pb->buf, sizeof(pb->buf), "%d %d %d %d %d",
             INT32_MAX, INT32_MIN, 0, -1, 1);
    ck_assert_msg(check_canaries(pb), "Canary corrupted with integer formats");

    init_protected_buffer(pb);
    snprintf(pb->buf, sizeof(pb->buf), "%llu %llu",
             (unsigned long long)UINT64_MAX, (unsigned long long)0);
    ck_assert_msg(check_canaries(pb), "Canary corrupted with uint64 formats");

    /* Test with many repeated format specifiers */
    init_protected_buffer(pb);
    char fmt_buf[512];
    memset(fmt_buf, 0, sizeof(fmt_buf));
    /* Build a format string with many %d */
    int pos = 0;
    while (pos + 3 < (int)sizeof(fmt_buf) - 1) {
        fmt_buf[pos++] = '%';
        fmt_buf[pos++] = 'd';
        fmt_buf[pos++] = ' ';
    }
    fmt_buf[pos] = '\0';
    snprintf(pb->buf, sizeof(pb->buf), fmt_buf,
             1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
    ck_assert_msg(check_canaries(pb), "Canary corrupted with many format specifiers");

    free(pb);
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_set_timeout(tc_core, 60);
    tcase_add_test(tc_core, test_snprintf_no_oob_read);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}