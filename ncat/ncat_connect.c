/***************************************************************************
 * ncat_connect.c -- Ncat connect mode.                                    *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2012 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 with the clarifications and exceptions described  *
 * below.  This guarantees your right to use, modify, and redistribute     *
 * this software under certain conditions.  If you wish to embed Nmap      *
 * technology into proprietary software, we sell alternative licenses      *
 * (contact sales@insecure.com).  Dozens of software vendors already       *
 * license Nmap technology such as host discovery, port scanning, OS       *
 * detection, version detection, and the Nmap Scripting Engine.            *
 *                                                                         *
 * Note that the GPL places important restrictions on "derived works", yet *
 * it does not provide a detailed definition of that term.  To avoid       *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * "derivative work" for the purpose of this license if it does any of the *
 * following:                                                              *
 * o Integrates source code from Nmap                                      *
 * o Reads or includes Nmap copyrighted data files, such as                *
 *   nmap-os-db or nmap-service-probes.                                    *
 * o Executes Nmap and parses the results (as opposed to typical shell or  *
 *   execution-menu apps, which simply display raw Nmap output and so are  *
 *   not derivative works.)                                                *
 * o Integrates/includes/aggregates Nmap into a proprietary executable     *
 *   installer, such as those produced by InstallShield.                   *
 * o Links to a library or executes a program that does any of the above   *
 *                                                                         *
 * The term "Nmap" should be taken to also include any portions or derived *
 * works of Nmap, as well as other software we distribute under this       *
 * license such as Zenmap, Ncat, and Nping.  This list is not exclusive,   *
 * but is meant to clarify our interpretation of derived works with some   *
 * common examples.  Our interpretation applies only to Nmap--we don't     *
 * speak for other people's GPL works.                                     *
 *                                                                         *
 * If you have any questions about the GPL licensing restrictions on using *
 * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
 * we also offer alternative license to integrate Nmap into proprietary    *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates.  They also fund the      *
 * continued development of Nmap.  Please email sales@insecure.com for     *
 * further information.                                                    *
 *                                                                         *
 * As a special exception to the GPL terms, Insecure.Com LLC grants        *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two. You must obey the GNU GPL in all *
 * respects for all of the code used other than OpenSSL.  If you modify    *
 * this file, you may extend this exception to your version of the file,   *
 * but you are not obligated to do so.                                     *
 *                                                                         *
 * If you received these files with a written license agreement or         *
 * contract stating terms other than the terms above, then that            *
 * alternative license agreement takes precedence over these comments.     *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes (none     *
 * have been found so far).                                                *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to the dev@nmap.org mailing list for possible incorporation into the    *
 * main distribution.  By sending these changes to Fyodor or one of the    *
 * Insecure.Org development mailing lists, or checking them into the Nmap  *
 * source code repository, it is understood (unless you specify otherwise) *
 * that you are offering the Nmap Project (Insecure.Com LLC) the           *
 * unlimited, non-exclusive right to reuse, modify, and relicense the      *
 * code.  Nmap will always be available Open Source, but this is important *
 * because the inability to relicense code has caused devastating problems *
 * for other Free Software projects (such as KDE and NASM).  We also       *
 * occasionally relicense the code to third parties as discussed above.    *
 * If you wish to specify special license conditions of your               *
 * contributions, just say so when you send them.                          *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the Nmap      *
 * license file for more details (it's in a COPYING file included with     *
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING         *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */

#include "base64.h"
#include "nsock.h"
#include "ncat.h"
#include "util.h"
#include "sys_wrap.h"

#include "nbase.h"
#include "http.h"

#ifndef WIN32
#include <unistd.h>
#include <netdb.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#ifdef WIN32
/* Define missing constant for shutdown(2).
 * See:
 * http://msdn.microsoft.com/en-us/library/windows/desktop/ms740481%28v=vs.85%29.aspx
 */
#define SHUT_WR SD_SEND
#endif

struct conn_state {
    nsock_iod sock_nsi;
    nsock_iod stdin_nsi;
    nsock_event_id idle_timer_event_id;
    int crlf_state;
};

static struct conn_state cs = {
    NULL,
    NULL,
    0,
    0
};

static void connect_handler(nsock_pool nsp, nsock_event evt, void *data);
static void post_connect(nsock_pool nsp, nsock_iod iod);
static void read_stdin_handler(nsock_pool nsp, nsock_event evt, void *data);
static void read_socket_handler(nsock_pool nsp, nsock_event evt, void *data);
static void write_socket_handler(nsock_pool nsp, nsock_event evt, void *data);
static void idle_timer_handler(nsock_pool nsp, nsock_event evt, void *data);
static void refresh_idle_timer(nsock_pool nsp);

#ifdef HAVE_OPENSSL
/* This callback is called for every certificate in a chain. ok is true if
   OpenSSL's internal verification has verified the certificate. We don't change
   anything about the verification, we only need access to the certificates to
   provide diagnostics. */
static int verify_callback(int ok, X509_STORE_CTX *store)
{
    X509 *cert = X509_STORE_CTX_get_current_cert(store);
    int err = X509_STORE_CTX_get_error(store);

    /* Print the subject, issuer, and fingerprint depending on the verbosity
       level. */
    if ((!ok && o.verbose) || o.debug > 1) {
        char digest_buf[SHA1_STRING_LENGTH + 1];
        char *fp;

        loguser("Subject: ");
        X509_NAME_print_ex_fp(stderr, X509_get_subject_name(cert), 0, XN_FLAG_COMPAT);
        loguser_noprefix("\n");
        loguser("Issuer: ");
        X509_NAME_print_ex_fp(stderr, X509_get_issuer_name(cert), 0, XN_FLAG_COMPAT);
        loguser_noprefix("\n");

        fp = ssl_cert_fp_str_sha1(cert, digest_buf, sizeof(digest_buf));
        ncat_assert(fp == digest_buf);
        loguser("SHA-1 fingerprint: %s\n", digest_buf);
    }

    if (!ok && o.verbose) {
        loguser("Certificate verification failed (%s).\n",
            X509_verify_cert_error_string(err));
    }

    return ok;
}

static void set_ssl_ctx_options(SSL_CTX *ctx)
{
    if (o.sslverify) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);

        if (o.ssltrustfile == NULL) {
            ssl_load_default_ca_certs(ctx);
        } else {
            if (o.debug)
                logdebug("Using trusted CA certificates from %s.\n", o.ssltrustfile);
            if (SSL_CTX_load_verify_locations(ctx, o.ssltrustfile, NULL) != 1) {
                bye("Could not load trusted certificates from %s.\n%s",
                    o.ssltrustfile, ERR_error_string(ERR_get_error(), NULL));
            }
        }
    } else {
        if (o.ssl && o.debug)
            logdebug("Not doing certificate verification.\n");
    }

    if (o.sslcert != NULL && o.sslkey != NULL) {
        if (SSL_CTX_use_certificate_file(ctx, o.sslcert, SSL_FILETYPE_PEM) != 1)
            bye("SSL_CTX_use_certificate_file(): %s.", ERR_error_string(ERR_get_error(), NULL));
        if (SSL_CTX_use_PrivateKey_file(ctx, o.sslkey, SSL_FILETYPE_PEM) != 1)
            bye("SSL_CTX_use_Privatekey_file(): %s.", ERR_error_string(ERR_get_error(), NULL));
    } else {
        if ((o.sslcert == NULL) != (o.sslkey == NULL))
            bye("The --ssl-key and --ssl-cert options must be used together.");
    }
}
#endif

/* Depending on verbosity, print a message that a connection was established. */
static void connect_report(nsock_iod nsi)
{
    union sockaddr_u peer;
    zmem(&peer, sizeof(peer.storage));

    nsi_getlastcommunicationinfo(nsi, NULL, NULL, NULL,
        &peer.sockaddr, sizeof(peer.storage));

    if (o.verbose) {
#ifdef HAVE_OPENSSL
        if (nsi_checkssl(nsi)) {
            X509 *cert;
            X509_NAME *subject;
            char digest_buf[SHA1_STRING_LENGTH + 1];
            char *fp;

            loguser("SSL connection to %s:%hu.", inet_socktop(&peer), nsi_peerport(nsi));

            cert = SSL_get_peer_certificate((SSL *) nsi_getssl(nsi));
            ncat_assert(cert != NULL);

            subject = X509_get_subject_name(cert);
            if (subject != NULL) {
                char buf[256];
                int n;

                n = X509_NAME_get_text_by_NID(subject, NID_organizationName, buf, sizeof(buf));
                if (n >= 0 && n <= sizeof(buf) - 1)
                    loguser_noprefix(" %s", buf);
            }

            loguser_noprefix("\n");

            fp = ssl_cert_fp_str_sha1(cert, digest_buf, sizeof(digest_buf));
            ncat_assert(fp == digest_buf);
            loguser("SHA-1 fingerprint: %s\n", digest_buf);
        } else {
#if HAVE_SYS_UN_H
            if (peer.sockaddr.sa_family == AF_UNIX)
                loguser("Connected to %s.\n", peer.un.sun_path);
            else
#endif
                loguser("Connected to %s:%hu.\n", inet_socktop(&peer), nsi_peerport(nsi));
        }
#else
#if HAVE_SYS_UN_H
        if (peer.sockaddr.sa_family == AF_UNIX)
            loguser("Connected to %s.\n", peer.un.sun_path);
        else
#endif
            loguser("Connected to %s:%hu.\n", inet_socktop(&peer), nsi_peerport(nsi));
#endif
    }
}

/* Just like inet_socktop, but it puts IPv6 addresses in square brackets. */
static const char *sock_to_url(const union sockaddr_u *su)
{
    static char buf[INET6_ADDRSTRLEN + 32];
    const char *host_str;
    unsigned short port;

    host_str = inet_socktop(su);
    port = inet_port(su);
    if (su->storage.ss_family == AF_INET)
        Snprintf(buf, sizeof(buf), "%s:%hu", host_str, port);
    else if (su->storage.ss_family == AF_INET6)
        Snprintf(buf, sizeof(buf), "[%s]:%hu]", host_str, port);
    else
        bye("Unknown address family in sock_to_url_host.");

    return buf;
}

static int append_connect_request_line(char **buf, size_t *size, size_t *offset,
    const union sockaddr_u *su)
{
    return strbuf_sprintf(buf, size, offset, "CONNECT %s HTTP/1.0\r\n",
        sock_to_url(su));
}

static char *http_connect_request(const union sockaddr_u *su, int *n)
{
    char *buf = NULL;
    size_t size = 0, offset = 0;

    append_connect_request_line(&buf, &size, &offset, su);
    strbuf_append_str(&buf, &size, &offset, "\r\n");
    *n = offset;

    return buf;
}

static char *http_connect_request_auth(const union sockaddr_u *su, int *n,
    struct http_challenge *challenge)
{
    char *buf = NULL;
    size_t size = 0, offset = 0;

    append_connect_request_line(&buf, &size, &offset, su);
    strbuf_append_str(&buf, &size, &offset, "Proxy-Authorization:");
    if (challenge->scheme == AUTH_BASIC) {
        char *auth_str;

        auth_str = b64enc((unsigned char *) o.proxy_auth, strlen(o.proxy_auth));
        strbuf_sprintf(&buf, &size, &offset, " Basic %s\r\n", auth_str);
        free(auth_str);
#if HAVE_HTTP_DIGEST
    } else if (challenge->scheme == AUTH_DIGEST) {
        char *proxy_auth;
        char *username, *password;
        char *response_hdr;

        /* Split up the proxy auth argument. */
        proxy_auth = Strdup(o.proxy_auth);
        username = strtok(proxy_auth, ":");
        password = strtok(NULL, ":");
        if (password == NULL) {
            free(proxy_auth);
            return NULL;
        }
        response_hdr = http_digest_proxy_authorization(challenge,
            username, password, "CONNECT", sock_to_url(&httpconnect));
        if (response_hdr == NULL) {
            free(proxy_auth);
            return NULL;
        }
        strbuf_append_str(&buf, &size, &offset, response_hdr);
        free(proxy_auth);
        free(response_hdr);
#endif
    } else {
        bye("Unknown authentication type.");
    }
    strbuf_append_str(&buf, &size, &offset, "\r\n");
    *n = offset;

    return buf;
}

/* Return a usable socket descriptor after proxy negotiation, or -1 on any
   error. If any bytes are received through the proxy after negotiation, they
   are written to stdout. */
static int do_proxy_http(void)
{
    struct socket_buffer sockbuf;
    char *request;
    char *status_line, *header;
    char *remainder;
    size_t len;
    int sd, code;
    int n;

    sd = do_connect(SOCK_STREAM);
    if (sd == -1) {
        loguser("Proxy connection failed: %s.\n", socket_strerror(socket_errno()));
        return -1;
    }

    status_line = NULL;
    header = NULL;

    /* First try a request with no authentication. */
    request = http_connect_request(&httpconnect, &n);
    if (send(sd, request, n, 0) < 0) {
        loguser("Error sending proxy request: %s.\n", socket_strerror(socket_errno()));
        free(request);
        return -1;
    }
    free(request);

    socket_buffer_init(&sockbuf, sd);

    if (http_read_status_line(&sockbuf, &status_line) != 0) {
        loguser("Error reading proxy response Status-Line.\n");
        goto bail;
    }
    code = http_parse_status_line_code(status_line);
    logdebug("Proxy returned status code %d.\n", code);
    free(status_line);
    status_line = NULL;
    if (http_read_header(&sockbuf, &header) != 0) {
        loguser("Error reading proxy response header.\n");
        goto bail;
    }

    if (code == 407 && o.proxy_auth != NULL) {
        struct http_header *h;
        struct http_challenge challenge;

        close(sd);
        sd = -1;

        if (http_parse_header(&h, header) != 0) {
            loguser("Error parsing proxy response header.\n");
            goto bail;
        }
        free(header);
        header = NULL;

        if (http_header_get_proxy_challenge(h, &challenge) == NULL) {
            loguser("Error getting Proxy-Authenticate challenge.\n");
            http_header_free(h);
            goto bail;
        }
        http_header_free(h);

        sd = do_connect(SOCK_STREAM);
        if (sd == -1) {
            loguser("Proxy reconnection failed: %s.\n", socket_strerror(socket_errno()));
            goto bail;
        }

        request = http_connect_request_auth(&httpconnect, &n, &challenge);
        if (request == NULL) {
            loguser("Error building Proxy-Authorization header.\n");
            http_challenge_free(&challenge);
            goto bail;
        }
        logdebug("Reconnection header:\n%s", request);
        if (send(sd, request, n, 0) < 0) {
            loguser("Error sending proxy request: %s.\n", socket_strerror(socket_errno()));
            free(request);
            http_challenge_free(&challenge);
            goto bail;
        }
        free(request);
        http_challenge_free(&challenge);

        socket_buffer_init(&sockbuf, sd);

        if (http_read_status_line(&sockbuf, &status_line) != 0) {
            loguser("Error reading proxy response Status-Line.\n");
            goto bail;
        }
        code = http_parse_status_line_code(status_line);
        logdebug("Proxy returned status code %d.\n", code);
        free(status_line);
        status_line = NULL;
        if (http_read_header(&sockbuf, &header) != 0) {
            loguser("Error reading proxy response header.\n");
            goto bail;
        }
    }

    free(header);
    header = NULL;

    if (code != 200) {
        loguser("Proxy returned status code %d.\n", code);
        return -1;
    }

    remainder = socket_buffer_remainder(&sockbuf, &len);
    Write(STDOUT_FILENO, remainder, len);

    return sd;

bail:
    if (sd != -1)
        close(sd);
    if (status_line != NULL)
        free(status_line);
    if (header != NULL)
        free(header);

    return -1;
}

int ncat_connect(void)
{
    nsock_pool mypool;
    int rc;

    /* Unless explicitely asked not to do so, ncat uses the
     * fallback nsock engine to maximize compatibility between
     * operating systems and the different use cases.
     */
    if (!o.nsock_engine)
        nsock_set_default_engine("select");

    /* Create an nsock pool */
    if ((mypool = nsp_new(NULL)) == NULL)
        bye("Failed to create nsock_pool.");

    if (o.debug >= 6)
        nsock_set_loglevel(mypool, NSOCK_LOG_DBG_ALL);
    else if (o.debug >= 3)
        nsock_set_loglevel(mypool, NSOCK_LOG_DBG);
    else if (o.debug >= 1)
        nsock_set_loglevel(mypool, NSOCK_LOG_INFO);
    else
        nsock_set_loglevel(mypool, NSOCK_LOG_ERROR);

    /* Allow connections to broadcast addresses. */
    nsp_setbroadcast(mypool, 1);

#ifdef HAVE_OPENSSL
    set_ssl_ctx_options((SSL_CTX *) nsp_ssl_init(mypool));
#endif

    if (httpconnect.storage.ss_family == AF_UNSPEC
             && socksconnect.storage.ss_family == AF_UNSPEC) {
        /* A non-proxy connection. Create an iod for a new socket. */
        cs.sock_nsi = nsi_new(mypool, NULL);
        if (cs.sock_nsi == NULL)
            bye("Failed to create nsock_iod.");

        if (nsi_set_hostname(cs.sock_nsi, o.target) == -1)
            bye("Failed to set hostname on iod.");

#if HAVE_SYS_UN_H
        /* For DGRAM UNIX socket we have to use source socket */
        if (o.af == AF_UNIX && o.udp)
        {
            if (srcaddr.storage.ss_family != AF_UNIX) {
                char *tmp_name = NULL;
                /* If no source socket was specified, we have to create temporary one. */
                if ((tmp_name = tempnam(NULL, "ncat.")) == NULL)
                    bye("Failed to create name for temporary DGRAM source Unix domain socket (tempnam).");

                srcaddr.un.sun_family = AF_UNIX;
                strncpy(srcaddr.un.sun_path, tmp_name, sizeof(srcaddr.un.sun_path));
                free (tmp_name);
            }
            nsi_set_localaddr(cs.sock_nsi, &srcaddr.storage, SUN_LEN((struct sockaddr_un *)&srcaddr.storage));

            if (o.verbose)
                loguser("[%s] used as source DGRAM Unix domain socket.\n", srcaddr.un.sun_path);
        }
        else
#endif
        if (srcaddr.storage.ss_family != AF_UNSPEC)
            nsi_set_localaddr(cs.sock_nsi, &srcaddr.storage, sizeof(srcaddr.storage));

        if (o.numsrcrtes) {
            unsigned char *ipopts = NULL;
            size_t ipoptslen = 0;

            if (o.af != AF_INET)
                bye("Sorry, -g can only currently be used with IPv4.");
            ipopts = buildsrcrte(targetss.in.sin_addr, o.srcrtes, o.numsrcrtes, o.srcrteptr, &ipoptslen);

            nsi_set_ipoptions(cs.sock_nsi, ipopts, ipoptslen);
            free(ipopts); /* Nsock has its own copy */
        }

#if HAVE_SYS_UN_H
        if (o.af == AF_UNIX) {
            if (o.udp) {
                nsock_connect_unixsock_datagram(mypool, cs.sock_nsi, connect_handler, NULL,
                                                &targetss.sockaddr,
                                                SUN_LEN((struct sockaddr_un *)&targetss.sockaddr));
            } else {
                nsock_connect_unixsock_stream(mypool, cs.sock_nsi, connect_handler, o.conntimeout,
                                              NULL, &targetss.sockaddr,
                                              SUN_LEN((struct sockaddr_un *)&targetss.sockaddr));
            }
        } else
#endif
        if (o.udp) {
            nsock_connect_udp(mypool, cs.sock_nsi, connect_handler,
                              NULL, &targetss.sockaddr, targetsslen,
                              inet_port(&targetss));
        }
#ifdef HAVE_OPENSSL
        else if (o.sctp && o.ssl) {
            nsock_connect_ssl(mypool, cs.sock_nsi, connect_handler,
                              o.conntimeout, NULL,
                              &targetss.sockaddr, targetsslen,
                              IPPROTO_SCTP, inet_port(&targetss),
                              NULL);
        }
#endif
        else if (o.sctp) {
            nsock_connect_sctp(mypool, cs.sock_nsi, connect_handler,
                              o.conntimeout, NULL,
                              &targetss.sockaddr, targetsslen,
                              inet_port(&targetss));
        }
#ifdef HAVE_OPENSSL
        else if (o.ssl) {
            nsock_connect_ssl(mypool, cs.sock_nsi, connect_handler,
                              o.conntimeout, NULL,
                              &targetss.sockaddr, targetsslen,
                              IPPROTO_TCP, inet_port(&targetss),
                              NULL);
        }
#endif
        else {
            nsock_connect_tcp(mypool, cs.sock_nsi, connect_handler,
                              o.conntimeout, NULL,
                              &targetss.sockaddr, targetsslen,
                              inet_port(&targetss));
        }
    } else {
        /* A proxy connection. */
        static int connect_socket;
        int len;
        char *line;
        size_t n;

        if (httpconnect.storage.ss_family != AF_UNSPEC) {
            connect_socket = do_proxy_http();
            if (connect_socket == -1)
                return 1;
        } else if (socksconnect.storage.ss_family != AF_UNSPEC) {
            struct socket_buffer stateful_buf;
            struct socks4_data socks4msg;
            char socksbuf[8];

            connect_socket = do_connect(SOCK_STREAM);
            if (connect_socket == -1) {
                loguser("Proxy connection failed: %s.\n", socket_strerror(socket_errno()));
                return 1;
            }

            socket_buffer_init(&stateful_buf, connect_socket);

            if (o.verbose) {
                loguser("Connected to proxy %s:%hu\n", inet_socktop(&targetss),
                    inet_port(&targetss));
            }

            /* Fill the socks4_data struct */
            zmem(&socks4msg, sizeof(socks4msg));
            socks4msg.version = SOCKS4_VERSION;
            socks4msg.type = SOCKS_CONNECT;
            socks4msg.port = socksconnect.in.sin_port;
            socks4msg.address = socksconnect.in.sin_addr.s_addr;
            if (o.proxy_auth)
                Strncpy(socks4msg.username, (char *) o.proxy_auth, sizeof(socks4msg.username));

            len = 8 + strlen(socks4msg.username) + 1;

            if (send(connect_socket, (char *) &socks4msg, len, 0) < 0) {
                loguser("Error sending proxy request: %s.\n", socket_strerror(socket_errno()));
                return 1;
            }
            /* The size of the socks4 response is 8 bytes. So read exactly
               8 bytes from the buffer */
            if (socket_buffer_readcount(&stateful_buf, socksbuf, 8) < 0) {
                loguser("Error: short reponse from proxy.\n");
                return 1;
            }
            if (socksbuf[1] != 90) {
                loguser("Proxy connection failed.\n");
                return 1;
            }

            /* Clear out whatever is left in the socket buffer which may be
               already sent by proxy server along with http response headers. */
            line = socket_buffer_remainder(&stateful_buf, &n);
            /* Write the leftover data to stdout. */
            Write(STDOUT_FILENO, line, n);
        }

        /* Once the proxy negotiation is done, Nsock takes control of the
           socket. */
        cs.sock_nsi = nsi_new2(mypool, connect_socket, NULL);

        /* Create IOD for nsp->stdin */
        if ((cs.stdin_nsi = nsi_new2(mypool, 0, NULL)) == NULL)
            bye("Failed to create stdin nsiod.");

        post_connect(mypool, cs.sock_nsi);
    }

    /* connect */
    rc = nsock_loop(mypool, -1);

    if (o.verbose) {
        struct timeval end_time;
        double time;
        gettimeofday(&end_time, NULL);
        time = TIMEVAL_MSEC_SUBTRACT(end_time, start_time) / 1000.0;
        loguser("%lu bytes sent, %lu bytes received in %.2f seconds.\n",
            nsi_get_write_count(cs.sock_nsi),
            nsi_get_read_count(cs.sock_nsi), time);
    }

#if HAVE_SYS_UN_H
    if (o.af == AF_UNIX && o.udp) {
        if (o.verbose)
            loguser("Deleting source DGRAM Unix domain socket. [%s]\n", srcaddr.un.sun_path);
        unlink(srcaddr.un.sun_path);
    }
#endif

    nsp_delete(mypool);

    return rc == NSOCK_LOOP_ERROR ? 1 : 0;
}

static void connect_handler(nsock_pool nsp, nsock_event evt, void *data)
{
    enum nse_status status = nse_status(evt);
    enum nse_type type = nse_type(evt);

    ncat_assert(type == NSE_TYPE_CONNECT || type == NSE_TYPE_CONNECT_SSL);

    if (status == NSE_STATUS_ERROR) {
        loguser("%s.\n", socket_strerror(nse_errorcode(evt)));
        exit(1);
    } else if (status == NSE_STATUS_TIMEOUT) {
        loguser("%s.\n", socket_strerror(ETIMEDOUT));
        exit(1);
    } else {
        ncat_assert(status == NSE_STATUS_SUCCESS);
    }

#ifdef HAVE_OPENSSL
    if (nsi_checkssl(cs.sock_nsi)) {
        /* Check the domain name. ssl_post_connect_check prints an
           error message if appropriate. */
        if (!ssl_post_connect_check((SSL *) nsi_getssl(cs.sock_nsi), o.target))
            bye("Certificate verification error.");
    }
#endif

    connect_report(cs.sock_nsi);

    /* Create IOD for nsp->stdin */
    if ((cs.stdin_nsi = nsi_new2(nsp, 0, NULL)) == NULL)
        bye("Failed to create stdin nsiod.");

    post_connect(nsp, nse_iod(evt));
}

/* Handle --exec if appropriate, otherwise start the initial read events and set
   the idle timeout. */
static void post_connect(nsock_pool nsp, nsock_iod iod)
{
    /* Command to execute. */
    if (o.cmdexec) {
        struct fdinfo info;

        info.fd = nsi_getsd(iod);
#ifdef HAVE_OPENSSL
        info.ssl = (SSL *) nsi_getssl(iod);
#endif
        /* Convert Nsock's non-blocking socket to an ordinary blocking one. It's
           possible for a program to write fast enough that it will get an
           EAGAIN on write on a non-blocking socket. */
        block_socket(info.fd);
        netexec(&info, o.cmdexec);
    }

    /* Start the initial reads. */

    if (!o.sendonly)
        nsock_read(nsp, cs.sock_nsi, read_socket_handler, -1, NULL);

    if (!o.recvonly)
        nsock_readbytes(nsp, cs.stdin_nsi, read_stdin_handler, -1, NULL, 0);

    /* The --idle-timeout option says to exit after a certain period of
       inactivity. We start a timer here and reset it on every read event; see
       refresh_idle_timer. */
    if (o.idletimeout > 0) {
        cs.idle_timer_event_id =
            nsock_timer_create(nsp, idle_timer_handler, o.idletimeout, NULL);
    }
}

static void read_stdin_handler(nsock_pool nsp, nsock_event evt, void *data)
{
    enum nse_status status = nse_status(evt);
    enum nse_type type = nse_type(evt);
    char *buf, *tmp = NULL;
    int nbytes;

    ncat_assert(type == NSE_TYPE_READ);

    if (status == NSE_STATUS_EOF) {
        shutdown(nsi_getsd(cs.sock_nsi), SHUT_WR);
        /* In --send-only mode, exit after EOF on stdin. */
        if (o.sendonly)
            nsock_loop_quit(nsp);
        return;
    } else if (status == NSE_STATUS_ERROR) {
        loguser("%s.\n", socket_strerror(nse_errorcode(evt)));
        exit(1);
    } else if (status == NSE_STATUS_TIMEOUT) {
        loguser("%s.\n", socket_strerror(ETIMEDOUT));
        exit(1);
    } else if (status == NSE_STATUS_CANCELLED || status == NSE_STATUS_KILL) {
        return;
    } else {
        ncat_assert(status == NSE_STATUS_SUCCESS);
    }

    buf = nse_readbuf(evt, &nbytes);

    /* read from stdin */
    if (o.linedelay)
        ncat_delay_timer(o.linedelay);

    if (o.crlf) {
        if (fix_line_endings(buf, &nbytes, &tmp, &cs.crlf_state))
            buf = tmp;
    }

    nsock_write(nsp, cs.sock_nsi, write_socket_handler, -1, NULL, buf, nbytes);
    ncat_log_send(buf, nbytes);

    if (tmp)
        free(tmp);

    refresh_idle_timer(nsp);
}

static void read_socket_handler(nsock_pool nsp, nsock_event evt, void *data)
{
    enum nse_status status = nse_status(evt);
    enum nse_type type = nse_type(evt);
    char *buf;
    int nbytes;

    ncat_assert(type == NSE_TYPE_READ);

    if (status == NSE_STATUS_EOF) {
        Close(STDOUT_FILENO);
        /* In --recv-only mode, exit after EOF on the socket. */
        if (o.recvonly)
            nsock_loop_quit(nsp);
        return;
    } else if (status == NSE_STATUS_ERROR) {
        loguser("%s.\n", socket_strerror(nse_errorcode(evt)));
        exit(1);
    } else if (status == NSE_STATUS_TIMEOUT) {
        loguser("%s.\n", socket_strerror(ETIMEDOUT));
        exit(1);
    } else if (status == NSE_STATUS_CANCELLED || status == NSE_STATUS_KILL) {
        return;
    } else {
        ncat_assert(status == NSE_STATUS_SUCCESS);
    }

    buf = nse_readbuf(evt, &nbytes);

    if (o.linedelay)
        ncat_delay_timer(o.linedelay);

    if (o.telnet)
        dotelnet(nsi_getsd(nse_iod(evt)), (unsigned char *) buf, nbytes);

    /* Write socket data to stdout */
    Write(STDOUT_FILENO, buf, nbytes);
    ncat_log_recv(buf, nbytes);

    nsock_readbytes(nsp, cs.sock_nsi, read_socket_handler, -1, NULL, 0);

    refresh_idle_timer(nsp);
}

static void write_socket_handler(nsock_pool nsp, nsock_event evt, void *data)
{
    enum nse_status status = nse_status(evt);
    enum nse_type type = nse_type(evt);

    ncat_assert(type == NSE_TYPE_WRITE);

    if (status == NSE_STATUS_ERROR) {
        loguser("%s.\n", socket_strerror(nse_errorcode(evt)));
        exit(1);
    } else if (status == NSE_STATUS_TIMEOUT) {
        loguser("%s.\n", socket_strerror(ETIMEDOUT));
        exit(1);
    } else if (status == NSE_STATUS_CANCELLED || status == NSE_STATUS_KILL) {
        return;
    } else {
        ncat_assert(status == NSE_STATUS_SUCCESS);
    }

    /* The write to the socket was successful. Allow reading more from stdin
       now. */
    nsock_readbytes(nsp, cs.stdin_nsi, read_stdin_handler, -1, NULL, 0);
}

static void idle_timer_handler(nsock_pool nsp, nsock_event evt, void *data)
{
    enum nse_status status = nse_status(evt);
    enum nse_type type = nse_type(evt);

    ncat_assert(type == NSE_TYPE_TIMER);

    if (status == NSE_STATUS_CANCELLED || status == NSE_STATUS_KILL)
        return;

    ncat_assert(status == NSE_STATUS_SUCCESS);

    loguser("Idle timeout expired (%d ms).\n", o.idletimeout);

    exit(1);
}

static void refresh_idle_timer(nsock_pool nsp)
{
    if (o.idletimeout <= 0)
        return;
    nsock_event_cancel(nsp, cs.idle_timer_event_id, 0);
    cs.idle_timer_event_id =
        nsock_timer_create(nsp, idle_timer_handler, o.idletimeout, NULL);
}
