/*
Usage: test-escape_windows_command_arg.exe

This is a test program for the escape_windows_command_arg function from
nbase_str.c. Its code is strictly Windows-specific. Basically, it performs
escape_windows_command_arg on arrays of strings merging its results with spaces
and tests if an attempt to decode them with CommandLineToArgvW results in the
same strings.
*/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "nbase.h"

#include <shellapi.h>

const char *TESTS[][5] = {
    { NULL },
    {"", NULL},
    {"", "", NULL},
    {"1", "2", "3", "4", NULL},
    {"a", "b", "c", NULL},
    {"a b", "c", NULL},
    {"a b c", NULL},
    {"  a  b  c  ", NULL},
    {"\"quote\"", NULL},
    {"back\\slash", NULL},
    {"backslash at end\\", NULL},
    {"double\"\"quote", NULL},
    {" a\nb\tc\rd\ne", NULL},
    {"..\\test\\toupper.lua", NULL},
    {"backslash at end\\", "som\\ething\"af\\te\\r", NULL},
    {"three\\\\\\backslashes", "som\\ething\"af\\te\\r", NULL},
    {"three\"\"\"quotes", "som\\ething\"af\\te\\r", NULL},
};

static LPWSTR utf8_to_wchar(const char *s)
{
    LPWSTR result;
    int size, ret;

    /* Get needed buffer size. */
    size = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (size == 0) {
        fprintf(stderr, "MultiByteToWideChar 1 failed: %d\n", GetLastError());
        exit(1);
    }
    result = (LPWSTR) malloc(sizeof(*result) * size);
    ret = MultiByteToWideChar(CP_UTF8, 0, s, -1, result, size);
    if (ret == 0) {
        fprintf(stderr, "MultiByteToWideChar 2 failed: %d\n", GetLastError());
        exit(1);
    }

    return result;
}

static char *wchar_to_utf8(const LPWSTR s)
{
    char *result;
    int size, ret;

    /* Get needed buffer size. */
    size = WideCharToMultiByte(CP_UTF8, 0, s, -1, NULL, 0, NULL, NULL);
    if (size == 0) {
        fprintf(stderr, "WideCharToMultiByte 1 failed: %d\n", GetLastError());
        exit(1);
    }
    result = (char *) malloc(size);
    ret = WideCharToMultiByte(CP_UTF8, 0, s, -1, result, size, NULL, NULL);
    if (ret == 0) {
        fprintf(stderr, "WideCharToMultiByte 2 failed: %d\n", GetLastError());
        exit(1);
    }

    return result;
}

static char **wchar_to_utf8_array(const LPWSTR a[], unsigned int len)
{
    char **result;
    unsigned int i;

    result = (char **) malloc(sizeof(*result) * len);
    if (result == NULL)
        return NULL;
    for (i = 0; i < len; i++)
        result[i] = wchar_to_utf8(a[i]);

    return result;
}

static unsigned int nullarray_length(const char *a[])
{
    unsigned int i;

    for (i = 0; a[i] != NULL; i++)
        ;

    return i;
}

static char *append(char *p, const char *s)
{
    size_t plen, slen;

    plen = strlen(p);
    slen = strlen(s);
    p = (char *) realloc(p, plen + slen + 1);
    if (p == NULL)
        return NULL;

    return strncat(p, s, plen+slen);
}

/* Turns an array of strings into an escaped flat command line. */
static LPWSTR build_commandline(const char *args[], unsigned int len)
{
    unsigned int i;
    char *result;

    result = strdup("progname");
    for (i = 0; i < len; i++) {
        result = append(result, " ");
        result = append(result, escape_windows_command_arg(args[i]));
    }

    return utf8_to_wchar(result);
}

static int arrays_equal(const char **a, unsigned int alen, const char **b, unsigned int blen)
{
    unsigned int i;

    if (alen != blen)
        return 0;
    for (i = 0; i < alen; i++) {
        if (strcmp(a[i], b[i]) != 0)
            return 0;
    }

    return 1;
}

static char *format_array(const char **args, unsigned int len)
{
    char *result;
    unsigned int i;

    result = strdup("");
    result = append(result, "{");
    for (i = 0; i < len; i++) {
        if (i > 0)
            result = append(result, ", ");
        result = append(result, "[");
        result = append(result, args[i]);
        result = append(result, "]");
    }
    result = append(result, "}");

    return result;
}

static int run_test(const char *args[])
{
    LPWSTR *argvw;
    char **result;
    int args_len, argvw_len, result_len;

    args_len = nullarray_length(args);
    argvw = CommandLineToArgvW(build_commandline(args, args_len), &argvw_len);
    /* Account for added argv[0] in argvw. */
    result = wchar_to_utf8_array(argvw+1, argvw_len-1);
    result_len = argvw_len - 1;

    if (arrays_equal((const char **) result, result_len, args, args_len)) {
        printf("PASS %s\n", format_array(args, args_len));
        return 1;
    } else {
        printf("FAIL got %s\n", format_array((const char **) result, result_len));
        printf("expected %s\n", format_array(args, args_len));
        return 0;
    }
}

int main(int argc, char *argv[])
{
    unsigned int num_tests, num_passed;
    unsigned int i;

    num_tests = 0;
    num_passed = 0;
    for (i = 0; i < sizeof(TESTS) / sizeof(*TESTS); i++) {
        num_tests++;
        if (run_test(TESTS[i]))
            num_passed++;
    }

    printf("%ld / %ld tests passed.\n", num_passed, num_tests);

    return num_passed == num_tests ? 0 : 1;
}
