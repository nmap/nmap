/***************************************************************************
 * ncat_proxy.c -- HTTP proxy server.                                      *
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

#include "base64.h"
#include "http.h"
#include "nsock.h"
#include "ncat.h"
#include "sys_wrap.h"

#ifndef WIN32
#include <unistd.h>
#endif

#ifndef WIN32
/* SIG_CHLD handler */
static void proxyreaper(int signo)
{
    while (waitpid(-1, NULL, WNOHANG) > 0)
        ;
}
#endif

/* send a '\0'-terminated string. */
static int send_string(struct fdinfo *fdn, const char *s)
{
    return fdinfo_send(fdn, s, strlen(s));
}

static void http_server_handler(int c);
static int send_proxy_authenticate(struct fdinfo *fdn, int stale);
static char *http_code2str(int code);

static void fork_handler(int s, int c);

static int handle_connect(struct socket_buffer *client_sock,
    struct http_request *request);
static int handle_method(struct socket_buffer *client_sock,
    struct http_request *request);

static int check_auth(const struct http_request *request,
    const struct http_credentials *credentials, int *stale);

/*
 * Simple forking HTTP proxy. It is an HTTP/1.0 proxy with knowledge of
 * HTTP/1.1. (The things lacking for HTTP/1.1 are the chunked transfer encoding
 * and the expect mechanism.) The proxy supports the CONNECT, GET, HEAD, and
 * POST methods. It supports Basic and Digest authentication of clients (use the
 * --proxy-auth option).
 *
 * HTTP/1.1 is defined in RFC 2616. Many comments refer to that document.
 * http://tools.ietf.org/html/rfc2616
 *
 * HTTP authentication is discussed in RFC 2617.
 * http://tools.ietf.org/html/rfc2617
 *
 * The CONNECT method is documented in an Internet draft and is specified as the
 * way to proxy HTTPS in RFC 2817, section 5.
 * http://tools.ietf.org/html/draft-luotonen-web-proxy-tunneling-01
 * http://tools.ietf.org/html/rfc2817#section-5
 *
 * The CONNECT method is not limited to HTTP, but is potentially capable of
 * connecting to any TCP port on any host. The proxy connection is requested
 * with an HTTP request, but after that, the proxy does no interpretation of the
 * data passing through it. See section 6 of the above mentioned draft for the
 * security implications.
 */
int ncat_http_server(void)
{
    int c, i, j;
    int listen_socket[NUM_LISTEN_ADDRS];
    socklen_t sslen;
    union sockaddr_u conn;
    unsigned int num_sockets;

#ifndef WIN32
    Signal(SIGCHLD, proxyreaper);
#endif

#if HAVE_HTTP_DIGEST
    http_digest_init_secret();
#endif

#ifdef HAVE_OPENSSL
    if (o.ssl)
        setup_ssl_listen(SSLv23_server_method());
#endif
    /* Clear the socket list */
    for (i = 0; i < NUM_LISTEN_ADDRS; i++)
        listen_socket[i] = -1;

    /* set for selecting listening sockets */
    fd_set listen_fds;
    fd_list_t listen_fdlist;
    FD_ZERO(&listen_fds);
    init_fdlist(&listen_fdlist, num_listenaddrs);

    /* Listen on each address, set up lists for select */
    num_sockets = 0;
    for (i = 0; i < num_listenaddrs; i++) {
        listen_socket[num_sockets] = do_listen(SOCK_STREAM, IPPROTO_TCP, &listenaddrs[i]);
        if (listen_socket[num_sockets] == -1) {
            if (o.debug > 0)
                logdebug("do_listen(\"%s\"): %s\n", socktop(&listenaddrs[i], 0), socket_strerror(socket_errno()));
            continue;
        }

        /* make us not block on accepts in weird cases. See ncat_listen.c:209 */
        unblock_socket(listen_socket[num_sockets]);

        /* setup select sets and max fd */
        checked_fd_set(listen_socket[num_sockets], &listen_fds);
        add_fd(&listen_fdlist, listen_socket[num_sockets]);

        num_sockets++;
    }
    if (num_sockets == 0) {
        if (num_listenaddrs == 1)
            bye("Unable to open listening socket on %s: %s", socktop(&listenaddrs[0], 0), socket_strerror(socket_errno()));
        else
            bye("Unable to open any listening sockets.");
    }

    for (;;) {
        fd_set read_fds;

        sslen = sizeof(conn.storage);
        /*
         * We just select to get a list of sockets which we can talk to
         */
        if (o.debug > 1)
            logdebug("selecting, fdmax %d\n", listen_fdlist.fdmax);
        read_fds = listen_fds;

        int fds_ready = fselect(listen_fdlist.fdmax + 1, &read_fds, NULL, NULL, NULL);

        if (o.debug > 1)
            logdebug("select returned %d fds ready\n", fds_ready);

        if (fds_ready == 0)
            bye("Idle timeout expired (%d ms).", o.idletimeout);

        for (i = 0; i <= listen_fdlist.fdmax && fds_ready > 0; i++) {
            /* Loop through descriptors until there is something ready */
            if (!checked_fd_isset(i, &read_fds))
                continue;

            /* Check each listening socket */
            for (j = 0; j < num_sockets; j++) {
                if (i == listen_socket[j]) {
                    fds_ready--;
                    c = accept(i, &conn.sockaddr, &sslen);

                    if (c == -1) {
                        if (errno == EINTR)
                            continue;
                        die("accept");
                    }

                    if (!allow_access(&conn)) {
                        Close(c);
                        continue;
                    }
                    if (o.debug > 1)
                        logdebug("forking handler for %d\n", i);
                    fork_handler(i, c);
                }
            }
        }
    }
    return 0;
}

#ifdef WIN32
/* On Windows we don't actually fork but rather start a thread. */

static DWORD WINAPI handler_thread_func(void *data)
{
    http_server_handler(*((int *) data));
    free(data);

    return 0;
}

static void fork_handler(int s, int c)
{
    int *data;
    HANDLE thread;

    data = (int *) safe_malloc(sizeof(int));
    *data = c;
    thread = CreateThread(NULL, 0, handler_thread_func, data, 0, NULL);
    if (thread == NULL) {
        if (o.verbose)
            logdebug("Error in CreateThread: %d\n", GetLastError());
        free(data);
        return;
    }
    CloseHandle(thread);
}
#else
static void fork_handler(int s, int c)
{
    int rc;

    rc = fork();
    if (rc == -1) {
        return;
    } else if (rc == 0) {
        Close(s);

        if (!o.debug) {
            Close(STDIN_FILENO);
            Close(STDOUT_FILENO);
            Close(STDERR_FILENO);
        }

        http_server_handler(c);
        exit(0);
    } else {
        Close(c);
    }
}
#endif

/* Is this one of the methods we can handle? */
static int method_is_known(const char *method)
{
    return strcmp(method, "CONNECT") == 0
        || strcmp(method, "GET") == 0
        || strcmp(method, "HEAD") == 0
        || strcmp(method, "POST") == 0;
}

static void http_server_handler(int c)
{
    int code;
    struct socket_buffer sock;
    struct http_request request;
    char *buf;

    socket_buffer_init(&sock, c);
#if HAVE_OPENSSL
    if (o.ssl) {
        sock.fdn.ssl = new_ssl(sock.fdn.fd);
        if (SSL_accept(sock.fdn.ssl) != 1) {
            loguser("Failed SSL connection: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
            fdinfo_close(&sock.fdn);
            return;
        }
    }
#endif

    code = http_read_request_line(&sock, &buf);
    if (code != 0) {
        if (o.verbose)
            logdebug("Error reading Request-Line.\n");
        send_string(&sock.fdn, http_code2str(code));
        fdinfo_close(&sock.fdn);
        return;
    }
    if (o.debug > 1)
        logdebug("Request-Line: %s", buf);
    code = http_parse_request_line(buf, &request);
    free(buf);
    if (code != 0) {
        if (o.verbose)
            logdebug("Error parsing Request-Line.\n");
        send_string(&sock.fdn, http_code2str(code));
        fdinfo_close(&sock.fdn);
        return;
    }

    if (!method_is_known(request.method)) {
        if (o.debug > 1)
            logdebug("Bad method: %s.\n", request.method);
        http_request_free(&request);
        send_string(&sock.fdn, http_code2str(405));
        fdinfo_close(&sock.fdn);
        return;
    }

    code = http_read_header(&sock, &buf);
    if (code != 0) {
        if (o.verbose)
            logdebug("Error reading header.\n");
        http_request_free(&request);
        send_string(&sock.fdn, http_code2str(code));
        fdinfo_close(&sock.fdn);
        return;
    }
    if (o.debug > 1)
        logdebug("Header:\n%s", buf);
    code = http_request_parse_header(&request, buf);
    free(buf);
    if (code != 0) {
        if (o.verbose)
            logdebug("Error parsing header.\n");
        http_request_free(&request);
        send_string(&sock.fdn, http_code2str(code));
        fdinfo_close(&sock.fdn);
        return;
    }

    /* Check authentication. */
    if (o.proxy_auth) {
        struct http_credentials credentials;
        int ret, stale;

        if (http_header_get_proxy_credentials(request.header, &credentials) == NULL) {
            /* No credentials or a parsing error. */
            send_proxy_authenticate(&sock.fdn, 0);
            http_request_free(&request);
            fdinfo_close(&sock.fdn);
            return;
        }

        ret = check_auth(&request, &credentials, &stale);
        http_credentials_free(&credentials);
        if (!ret) {
            /* Password doesn't match. */
            /* RFC 2617, section 1.2: "If a proxy does not accept the
               credentials sent with a request, it SHOULD return a 407 (Proxy
               Authentication Required). */
            send_proxy_authenticate(&sock.fdn, stale);
            http_request_free(&request);
            fdinfo_close(&sock.fdn);
            return;
        }
    }

    if (strcmp(request.method, "CONNECT") == 0) {
        code = handle_connect(&sock, &request);
    } else if (strcmp(request.method, "GET") == 0
        || strcmp(request.method, "HEAD") == 0
        || strcmp(request.method, "POST") == 0) {
        code = handle_method(&sock, &request);
    } else {
        code = 500;
    }
    http_request_free(&request);

    if (code != 0) {
        send_string(&sock.fdn, http_code2str(code));
        fdinfo_close(&sock.fdn);
        return;
    }

    fdinfo_close(&sock.fdn);
}

static int handle_connect(struct socket_buffer *client_sock,
    struct http_request *request)
{
    union sockaddr_u su;
    size_t sslen = sizeof(su.storage);
    int maxfd, s, rc;
    char *line;
    size_t len;
    fd_set m, r;

    if (request->uri.port == -1) {
        if (o.verbose)
            logdebug("No port number in CONNECT URI.\n");
        return 400;
    }
    if (o.debug > 1)
        logdebug("CONNECT to %s:%d.\n", request->uri.host, request->uri.port);

    rc = resolve(request->uri.host, request->uri.port, &su.storage, &sslen, o.af);
    if (rc != 0) {
        if (o.debug) {
            logdebug("Can't resolve name \"%s\": %s.\n",
                request->uri.host, gai_strerror(rc));
        }
        return 504;
    }

    s = Socket(su.storage.ss_family, SOCK_STREAM, IPPROTO_TCP);

    if (connect(s, &su.sockaddr, sslen) == -1) {
        if (o.debug)
            logdebug("Can't connect to %s: %s.\n", socktop(&su, sslen), socket_strerror(socket_errno()));
        Close(s);
        return 504;
    }

    send_string(&client_sock->fdn, http_code2str(200));

    /* Clear out whatever is left in the socket buffer. The client may have
       already sent the first part of its request to the origin server. */
    line = socket_buffer_remainder(client_sock, &len);
    if (send(s, line, len, 0) < 0) {
        if (o.debug)
            logdebug("Error sending %lu leftover bytes: %s.\n", (unsigned long) len, strerror(errno));
        Close(s);
        return 0;
    }

    maxfd = client_sock->fdn.fd < s ? s : client_sock->fdn.fd;
    FD_ZERO(&m);
    checked_fd_set(client_sock->fdn.fd, &m);
    checked_fd_set(s, &m);

    errno = 0;

    while (!socket_errno() || socket_errno() == EINTR) {
        char buf[DEFAULT_TCP_BUF_LEN];
        int len, rc;

        r = m;

        fselect(maxfd + 1, &r, NULL, NULL, NULL);

        zmem(buf, sizeof(buf));

        if (checked_fd_isset(client_sock->fdn.fd, &r)) {
            do {
                do {
                    len = fdinfo_recv(&client_sock->fdn, buf, sizeof(buf));
                } while (len == -1 && socket_errno() == EINTR);
                if (len <= 0)
                    goto end;

                do {
                    rc = send(s, buf, len, 0);
                } while (rc == -1 && socket_errno() == EINTR);
                if (rc == -1)
                    goto end;
            } while (fdinfo_pending(&client_sock->fdn));
        }

        if (checked_fd_isset(s, &r)) {
            do {
                len = recv(s, buf, sizeof(buf), 0);
            } while (len == -1 && socket_errno() == EINTR);
            if (len <= 0)
                goto end;

            do {
                rc = fdinfo_send(&client_sock->fdn, buf, len);
            } while (rc == -1 && socket_errno() == EINTR);
            if (rc == -1)
                goto end;
        }
    }
end:

    close(s);

    return 0;
}

static int do_transaction(struct http_request *request,
    struct socket_buffer *client_sock, struct socket_buffer *server_sock);

/* Generic handler for GET, HEAD, and POST methods. */
static int handle_method(struct socket_buffer *client_sock,
    struct http_request *request)
{
    struct socket_buffer server_sock;
    union sockaddr_u su;
    size_t sslen = sizeof(su.storage);
    int code;
    int s, rc;

    if (strcmp(request->uri.scheme, "http") != 0) {
        if (o.verbose)
            logdebug("Unknown scheme in URI: %s.\n", request->uri.scheme);
        return 400;
    }
    if (request->uri.port == -1) {
        if (o.verbose)
            logdebug("Unknown port in URI.\n");
        return 400;
    }

    rc = resolve(request->uri.host, request->uri.port, &su.storage, &sslen, o.af);
    if (rc != 0) {
        if (o.debug) {
            logdebug("Can't resolve name %s:%d: %s.\n",
                request->uri.host, request->uri.port, gai_strerror(rc));
        }
        return 504;
    }

    /* RFC 2616, section 5.1.2: "In order to avoid request loops, a proxy MUST
       be able to recognize all of its server names, including any aliases,
       local variations, and the numeric IP address. */
    if (request->uri.port == o.portno && addr_is_local(&su)) {
        if (o.verbose)
            logdebug("Proxy loop detected: %s:%d\n", request->uri.host, request->uri.port);
        return 403;
    }

    s = Socket(su.storage.ss_family, SOCK_STREAM, IPPROTO_TCP);

    if (connect(s, &su.sockaddr, sslen) == -1) {
        if (o.debug)
            logdebug("Can't connect to %s: %s.\n", socktop(&su, sslen), socket_strerror(socket_errno()));
        Close(s);
        return 504;
    }

    socket_buffer_init(&server_sock, s);

    code = do_transaction(request, client_sock, &server_sock);

    fdinfo_close(&server_sock.fdn);

    if (code != 0)
        return code;

    return 0;
}

/* Do a GET, HEAD, or POST transaction. */
static int do_transaction(struct http_request *request,
    struct socket_buffer *client_sock, struct socket_buffer *server_sock)
{
    char buf[BUFSIZ];
    struct http_response response;
    char *line;
    char *request_str, *response_str;
    size_t len;
    int code, n;

    /* We don't handle the chunked transfer encoding, which in the absence of a
       Content-Length is the only way we know the end of a request body. RFC
       2616, section 4.4 says, "If a request contains a message-body and a
       Content-Length is not given, the server SHOULD respond with 400 (bad
       request) if it cannot determine the length of the message, or with 411
       (length required) if it wishes to insist on receiving a valid
       Content-Length." */
    if (strcmp(request->method, "POST") == 0 && !request->content_length_set) {
        if (o.debug)
            logdebug("POST request with no Content-Length.\n");
        return 400;
    }

    /* The version we use to talk to the server. */
    request->version = HTTP_10;

    /* Remove headers that only apply to our connection with the client. */
    code = http_header_remove_hop_by_hop(&request->header);
    if (code != 0) {
        if (o.verbose)
            logdebug("Error removing hop-by-hop headers.\n");
        return code;
    }

    /* Build the Host header. */
    if (request->uri.port == -1 || request->uri.port == 80)
        n = Snprintf(buf, sizeof(buf), "%s", request->uri.host);
    else
        n = Snprintf(buf, sizeof(buf), "%s:%d", request->uri.host, request->uri.port);
    if (n < 0 || n >= sizeof(buf)) {
        /* Request Entity Too Large. */
        return 501;
    }
    request->header = http_header_set(request->header, "Host", buf);

    request->header = http_header_set(request->header, "Connection", "close");

    /* Send the request to the server. */
    request_str = http_request_to_string(request, &len);
    n = send(server_sock->fdn.fd, request_str, len, 0);
    free(request_str);
    if (n < 0)
        return 504;
    /* Send the request body, if any. Count up to Content-Length. */
    while (request->bytes_transferred < request->content_length) {
        n = socket_buffer_read(client_sock, buf, MIN(sizeof(buf), request->content_length - request->bytes_transferred));
        if (n < 0)
            return 504;
        if (n == 0)
            break;
        request->bytes_transferred += n;
        n = send(server_sock->fdn.fd, buf, n, 0);
        if (n < 0)
            return 504;
    }
    if (o.debug && request->bytes_transferred < request->content_length)
        logdebug("Received only %lu request body bytes (Content-Length was %lu).\n", request->bytes_transferred, request->content_length);


    /* Read the response. */
    code = http_read_status_line(server_sock, &line);
    if (o.debug > 1)
        logdebug("Status-Line: %s", line);
    if (code != 0) {
        if (o.verbose)
            logdebug("Error reading Status-Line.\n");
        return 0;
    }
    code = http_parse_status_line(line, &response);
    free(line);
    if (code != 0) {
        if (o.verbose)
            logdebug("Error parsing Status-Line.\n");
        return 0;
    }

    code = http_read_header(server_sock, &line);
    if (code != 0) {
        if (o.verbose)
            logdebug("Error reading header.\n");
        return 0;
    }
    if (o.debug > 1)
        logdebug("Response header:\n%s", line);

    code = http_response_parse_header(&response, line);
    free(line);
    if (code != 0) {
        if (o.verbose)
            logdebug("Error parsing response header.\n");
        return 0;
    }


    /* The version we use to talk to the client. */
    response.version = HTTP_10;

    /* Remove headers that only apply to our connection with the server. */
    code = http_header_remove_hop_by_hop(&response.header);
    if (code != 0) {
        if (o.verbose)
            logdebug("Error removing hop-by-hop headers.\n");
        return code;
    }

    response.header = http_header_set(response.header, "Connection", "close");

    /* Send the response to the client. */
    response_str = http_response_to_string(&response, &len);
    n = fdinfo_send(&client_sock->fdn, response_str, len);
    free(response_str);
    if (n < 0) {
        http_response_free(&response);
        return 504;
    }
    /* If the Content-Length is 0, read until the connection is closed.
       Otherwise read until the Content-Length. At this point it's too late to
       return our own error code so return 0 in case of any error. */
    while (!response.content_length_set
        || response.bytes_transferred < response.content_length) {
        size_t count;

        count = sizeof(buf);
        if (response.content_length_set) {
            size_t remaining = response.content_length - response.bytes_transferred;
            if (remaining < count)
                count = remaining;
        }
        n = socket_buffer_read(server_sock, buf, count);
        if (n <= 0)
            break;
        response.bytes_transferred += n;
        n = fdinfo_send(&client_sock->fdn, buf, n);
        if (n < 0)
            break;
    }

    http_response_free(&response);

    return 0;
}

/* Send a 407 Proxy Authenticate Required response. */
static int send_proxy_authenticate(struct fdinfo *fdn, int stale)
{
    char *buf = NULL;
    size_t size = 0, offset = 0;
    int n;

    strbuf_append_str(&buf, &size, &offset, "HTTP/1.0 407 Proxy Authentication Required\r\n");
    strbuf_append_str(&buf, &size, &offset, "Proxy-Authenticate: Basic realm=\"Ncat\"\r\n");
#if HAVE_HTTP_DIGEST
    {
        char *hdr;

        hdr = http_digest_proxy_authenticate("Ncat", stale);
        strbuf_sprintf(&buf, &size, &offset, "Proxy-Authenticate: %s\r\n", hdr);
        free(hdr);
    }
#endif
    strbuf_append_str(&buf, &size, &offset, "\r\n");

    if (o.debug > 1)
        logdebug("RESPONSE:\n%s", buf);

    n = send_string(fdn, buf);
    free(buf);

    return n;
}

static char *http_code2str(int code)
{
    /* See RFC 2616, section 6.1.1 for status codes. */
    switch (code) {
    case 200:
        return "HTTP/1.0 200 OK\r\n\r\n";
    case 400:
        return "HTTP/1.0 400 Bad Request\r\n\r\n";
    case 403:
        return "HTTP/1.0 403 Forbidden\r\n\r\n";
    case 405:
        /* RFC 2616, section 14.7 for Allow. */
        return "\
HTTP/1.0 405 Method Not Allowed\r\n\
Allow: CONNECT, GET, HEAD, POST\r\n\
\r\n";
    case 413:
        return "HTTP/1.0 413 Request Entity Too Large\r\n\r\n";
    case 501:
        return "HTTP/1.0 501 Not Implemented\r\n\r\n";
    case 504:
        return "HTTP/1.0 504 Gateway Timeout\r\n\r\n";
    default:
        return "HTTP/1.0 500 Internal Server Error\r\n\r\n";
    }

    return NULL;
}

/* userpass is a user:pass string (the argument to --proxy-auth). value is the
   value of the Proxy-Authorization header field. Returns 0 on authentication
   failure and nonzero on success. *stale is set to 1 if HTTP Digest credentials
   are valid but out of date. */
static int check_auth(const struct http_request *request,
    const struct http_credentials *credentials, int *stale)
{
    if (o.proxy_auth == NULL)
        return 1;

    *stale = 0;

    if (credentials->scheme == AUTH_BASIC) {
        char *expected;
        int cmp;

        if (credentials->u.basic == NULL)
            return 0;

        /* We don't decode the received password, we encode the expected
           password and compare the encoded strings. */
        expected = b64enc((unsigned char *) o.proxy_auth, strlen(o.proxy_auth));
        cmp = strcmp(expected, credentials->u.basic);
        free(expected);

        return cmp == 0;
    }
#if HAVE_HTTP_DIGEST
    else if (credentials->scheme == AUTH_DIGEST) {
        char *username, *password;
        char *proxy_auth;
        struct timeval nonce_tv, now;
        int nonce_age;
        int ret;

        /* Split up the proxy auth argument. */
        proxy_auth = Strdup(o.proxy_auth);
        username = proxy_auth;
        password = strchr(proxy_auth, ':');
        if (password == NULL) {
            free(proxy_auth);
            return 0;
        }
        *password++ = '\0';
        ret = http_digest_check_credentials(username, "Ncat", password,
            request->method, credentials);
        free(proxy_auth);

        if (!ret)
            return 0;

        /* The nonce checks out as one we issued and it matches what we expect
           given the credentials. Now check if it's too old. */
        if (credentials->u.digest.nonce == NULL
            || http_digest_nonce_time(credentials->u.digest.nonce, &nonce_tv) == -1)
            return 0;
        gettimeofday(&now, NULL);
        if (TIMEVAL_AFTER(nonce_tv, now))
            return 0;
        nonce_age = TIMEVAL_SEC_SUBTRACT(now, nonce_tv);

        if (nonce_age > HTTP_DIGEST_NONCE_EXPIRY) {
            if (o.verbose)
                loguser("Nonce is %d seconds old; rejecting.\n", nonce_age);
            *stale = 1;
            return 0;
        }

        /* To prevent replays, here we should additionally check against a list
           of recently used nonces, where "recently used nonce" is one that has
           been used to successfully authenticate within the last
           HTTP_DIGEST_NONCE_EXPIRY seconds. (Older than that and we don't need
           to keep it in the list, because the expiry test above will catch it.
           This isn't supported because the fork-and-process architecture of the
           proxy server makes it hard for us to change state in the parent
           process from here in the child. */

        return 1;
    }
#endif
    else {
        return 0;
    }
}
