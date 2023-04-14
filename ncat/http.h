/***************************************************************************
 * http.h                                                                  *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *
 * The Nmap Security Scanner is (C) 1996-2023 Nmap Software LLC ("The Nmap
 * Project"). Nmap is also a registered trademark of the Nmap Project.
 *
 * This program is distributed under the terms of the Nmap Public Source
 * License (NPSL). The exact license text applying to a particular Nmap
 * release or source code control revision is contained in the LICENSE
 * file distributed with that version of Nmap or source code control
 * revision. More Nmap copyright/legal information is available from
 * https://nmap.org/book/man-legal.html, and further information on the
 * NPSL license itself can be found at https://nmap.org/npsl/ . This
 * header summarizes some key points from the Nmap license, but is no
 * substitute for the actual license text.
 *
 * Nmap is generally free for end users to download and use themselves,
 * including commercial use. It is available from https://nmap.org.
 *
 * The Nmap license generally prohibits companies from using and
 * redistributing Nmap in commercial products, but we sell a special Nmap
 * OEM Edition with a more permissive license and special features for
 * this purpose. See https://nmap.org/oem/
 *
 * If you have received a written Nmap license agreement or contract
 * stating terms other than these (such as an Nmap OEM license), you may
 * choose to use and redistribute Nmap under those terms instead.
 *
 * The official Nmap Windows builds include the Npcap software
 * (https://npcap.com) for packet capture and transmission. It is under
 * separate license terms which forbid redistribution without special
 * permission. So the official Nmap Windows builds may not be redistributed
 * without special permission (such as an Nmap OEM license).
 *
 * Source is provided to this software because we believe users have a
 * right to know exactly what a program is going to do before they run it.
 * This also allows you to audit the software for security holes.
 *
 * Source code also allows you to port Nmap to new platforms, fix bugs, and add
 * new features. You are highly encouraged to submit your changes as a Github PR
 * or by email to the dev@nmap.org mailing list for possible incorporation into
 * the main distribution. Unless you specify otherwise, it is understood that
 * you are offering us very broad rights to use your submissions as described in
 * the Nmap Public Source License Contributor Agreement. This is important
 * because we fund the project by selling licenses with various terms, and also
 * because the inability to relicense code has caused devastating problems for
 * other Free Software projects (such as KDE and NASM).
 *
 * The free version of Nmap is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranties,
 * indemnification and commercial support are all available through the
 * Npcap OEM program--see https://nmap.org/oem/
 *
 ***************************************************************************/

/* $Id$ */

#ifndef _HTTP_H
#define _HTTP_H

#include "ncat_config.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>

/* This is an abstraction over a socket (really a struct fdinfo) that provides
   rudimentary buffering. It is useful for the line-oriented parts of HTTP. */
struct socket_buffer {
    struct fdinfo fdn;
    char buffer[BUFSIZ];
    char *p;
    char *end;
};

void socket_buffer_init(struct socket_buffer *buf, int sd);

int socket_buffer_read(struct socket_buffer *buf, char *out, size_t size);

char *socket_buffer_readline(struct socket_buffer *buf, size_t *n, size_t maxlen);

int socket_buffer_readcount(struct socket_buffer *buf, char *out, size_t size);

char *socket_buffer_remainder(struct socket_buffer *buf, size_t *len);

/* A broken-down URI as defined in RFC 3986, except that the query and fragment
   parts are included in the path. */
struct uri {
    char *scheme;
    char *host;
    int port;
    char *path;
};

void uri_init(struct uri *uri);

void uri_free(struct uri *uri);

struct uri *uri_parse(struct uri *uri, const char *uri_s);

struct uri *uri_parse_authority(struct uri *uri, const char *authority);

enum http_version {
    HTTP_09,
    HTTP_10,
    HTTP_11,
    HTTP_UNKNOWN,
};

struct http_header {
    char *name;
    char *value;
    struct http_header *next;
};

struct http_request {
    char *method;
    struct uri uri;
    enum http_version version;
    struct http_header *header;
    int content_length_set;
    unsigned long content_length;
    unsigned long bytes_transferred;
};

struct http_response {
    enum http_version version;
    int code;
    char *phrase;
    struct http_header *header;
    int content_length_set;
    unsigned long content_length;
    unsigned long bytes_transferred;
};

void http_header_free(struct http_header *header);
char *http_header_get(const struct http_header *header, const char *name);
const struct http_header *http_header_next(const struct http_header *header, const struct http_header *p, const char *name);
char *http_header_get_first(const struct http_header *header, const char *name);
struct http_header *http_header_set(struct http_header *header, const char *name, const char *value);
struct http_header *http_header_remove(struct http_header *header, const char *name);
int http_header_remove_hop_by_hop(struct http_header **header);
char *http_header_to_string(const struct http_header *header, size_t *n);

void http_request_init(struct http_request *request);
void http_request_free(struct http_request *request);
char *http_request_to_string(const struct http_request *request, size_t *n);

void http_response_init(struct http_response *response);
void http_response_free(struct http_response *response);
char *http_response_to_string(const struct http_response *response, size_t *n);

int http_read_header(struct socket_buffer *buf, char **result);
int http_parse_header(struct http_header **result, const char *header);
int http_request_parse_header(struct http_request *request, const char *header);
int http_response_parse_header(struct http_response *response, const char *header);

int http_read_request_line(struct socket_buffer *buf, char **line);
int http_parse_request_line(const char *line, struct http_request *request);

int http_read_status_line(struct socket_buffer *buf, char **line);
int http_parse_status_line(const char *line, struct http_response *response);
int http_parse_status_line_code(const char *line);

enum http_auth_scheme { AUTH_UNKNOWN, AUTH_BASIC, AUTH_DIGEST };
enum http_digest_algorithm { ALGORITHM_MD5, ALGORITHM_UNKNOWN };
enum http_digest_qop { QOP_NONE = 0, QOP_AUTH = 1 << 0, QOP_AUTH_INT = 1 << 1 };

struct http_challenge {
    enum http_auth_scheme scheme;
    char *realm;
    struct {
        char *nonce;
        char *opaque;
        enum http_digest_algorithm algorithm;
        /* A bit mask of supported qop values ("auth", "auth-int", etc.). */
        unsigned char qop;
    } digest;
};

struct http_credentials {
    enum http_auth_scheme scheme;
    union {
        char *basic;
        struct {
            char *username;
            char *realm;
            char *nonce;
            char *uri;
            char *response;
            enum http_digest_algorithm algorithm;
            enum http_digest_qop qop;
            char *nc;
            char *cnonce;
        } digest;
    } u;
};

void http_challenge_init(struct http_challenge *challenge);
void http_challenge_free(struct http_challenge *challenge);
struct http_challenge *http_header_get_proxy_challenge(const struct http_header *header, struct http_challenge *challenge);

void http_credentials_init_basic(struct http_credentials *credentials);
void http_credentials_init_digest(struct http_credentials *credentials);
void http_credentials_free(struct http_credentials *credentials);
struct http_credentials *http_header_get_proxy_credentials(const struct http_header *header, struct http_credentials *credentials);

#if HAVE_HTTP_DIGEST
/* Initialize the server secret used in generating nonces. */
int http_digest_init_secret(void);
int http_digest_nonce_time(const char *nonce, struct timeval *tv);
/* Return a Proxy-Authenticate header. */
char *http_digest_proxy_authenticate(const char *realm, int stale);
/* Return a Proxy-Authorization header answering the given challenge. */
char *http_digest_proxy_authorization(const struct http_challenge *challenge,
    const char *username, const char *password,
    const char *method, const char *uri);
int http_digest_check_credentials(const char *username, const char *realm,
    const char *password, const char *method,
    const struct http_credentials *credentials);
#endif

#endif
