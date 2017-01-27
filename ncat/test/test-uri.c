#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "ncat_core.h"
#include "http.h"

static long test_count = 0;
static long success_count = 0;

/* Check strings or null pointers for equality. */
int nullstreq(const char *s, const char *t)
{
	if (s == NULL) {
		if (t == NULL)
			return 1;
		else
			return 0;
	} else {
		if (t == NULL)
			return 0;
		else
			return strcmp(s, t) == 0;
	}
}

int test_uri(const char *uri_s, const char *scheme, const char *host, int port, const char *path)
{
	struct uri uri;
	int scheme_match, host_match, port_match, path_match;

	test_count++;

	if (uri_parse(&uri, uri_s) == NULL) {
		printf("FAIL %s: couldn't parse.\n", uri_s);
		return 0;
	}

	scheme_match = nullstreq(uri.scheme, scheme);
	host_match = nullstreq(uri.host, host);
	port_match = uri.port == port;
	path_match = nullstreq(uri.path, path);

	if (scheme_match && host_match && port_match && path_match) {
		printf("PASS %s\n", uri_s);
		uri_free(&uri);
		success_count++;
		return 1;
	} else {
		printf("FAIL %s:", uri_s);
		if (!scheme_match)
			printf(" \"%s\" != \"%s\".", uri.scheme, scheme);
		if (!host_match)
			printf(" \"%s\" != \"%s\".", uri.host, host);
		if (!port_match)
			printf(" %d != %d.", uri.port, port);
		if (!path_match)
			printf(" \"%s\" != \"%s\".", uri.path, path);
		printf("\n");
		uri_free(&uri);
		return 0;
	}
}

int test_fail(const char *uri_s)
{
	struct uri uri;

	test_count++;

	if (uri_parse(&uri, uri_s) != NULL) {
		uri_free(&uri);
		printf("FAIL %s: not expected to parse.\n", uri_s);
		return 0;
	} else {
		printf("PASS %s\n", uri_s);
		success_count++;
		return 0;
	}
}

int main(int argc, char *argv[])
{
	test_uri("http://www.example.com", "http", "www.example.com", 80, "");

	test_uri("HTTP://www.example.com", "http", "www.example.com", 80, "");
	test_uri("http://WWW.EXAMPLE.COM", "http", "WWW.EXAMPLE.COM", 80, "");

	test_uri("http://www.example.com:100", "http", "www.example.com", 100, "");
	test_uri("http://www.example.com:1", "http", "www.example.com", 1, "");
	test_uri("http://www.example.com:65535", "http", "www.example.com", 65535, "");
	test_uri("http://www.example.com:", "http", "www.example.com", 80, "");
	test_uri("http://www.example.com:/", "http", "www.example.com", 80, "/");

	test_uri("http://www.example.com/", "http", "www.example.com", 80, "/");
	test_uri("http://www.example.com:100/", "http", "www.example.com", 100, "/");

	test_uri("http://1.2.3.4", "http", "1.2.3.4", 80, "");
	test_uri("http://1.2.3.4:100", "http", "1.2.3.4", 100, "");
	test_uri("http://[::ffff]", "http", "::ffff", 80, "");
	test_uri("http://[::ffff]:100", "http", "::ffff", 100, "");

	test_uri("http://www.example.com/path?query#frag", "http", "www.example.com", 80, "/path?query#frag");

	test_uri("http://www.exampl%65.com", "http", "www.example.com", 80, "");
	test_uri("http://www.exampl%6a.com", "http", "www.examplj.com", 80, "");
	test_uri("http://www.exampl%6A.com", "http", "www.examplj.com", 80, "");
	test_uri("http://www.exampl%2523.com", "http", "www.exampl%23.com", 80, "");
	test_fail("http://www.example.com:%380");
	test_uri("http://www.example.com/a%23b", "http", "www.example.com", 80, "/a%23b");

	test_uri("unknown://www.example.com", "unknown", "www.example.com", -1, "");

	test_uri("unknown:", "unknown", NULL, -1, "");

	test_fail("");
	test_fail("/dir/file");
	test_fail("http://www.example.com:-1");
	test_fail("http://www.example.com:0");
	test_fail("http://www.example.com:65536");

	/* We explicitly don't support userinfo in the authority. */
	test_fail("http://user@www.example.com");
	test_fail("http://user:pass@www.example.com");

	printf("%ld / %ld tests passed.\n", success_count, test_count);

	return success_count == test_count ? 0 : 1;
}
