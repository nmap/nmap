/***************************************************************************
 * ncat_connect.c -- Ncat connect mode.                                    *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2016 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE CLARIFICATIONS  *
 * AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your right to use,    *
 * modify, and redistribute this software under certain conditions.  If    *
 * you wish to embed Nmap technology into proprietary software, we sell    *
 * alternative licenses (contact sales@nmap.com).  Dozens of software      *
 * vendors already license Nmap technology such as host discovery, port    *
 * scanning, OS detection, version detection, and the Nmap Scripting       *
 * Engine.                                                                 *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files, such as Nmap's nmap-os-db   *
 * or nmap-service-probes.                                                 *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * Nmap with other software in compressed or archival form does not        *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * As another special exception to the GPL terms, Insecure.Com LLC grants  *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two.                                  *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * Nmap or grant special permissions to use it in other open source        *
 * software.  Please contact fyodor@nmap.org with any such requests.       *
 * Similarly, we don't incorporate incompatible open source software into  *
 * Covered Software without special permission from the copyright holders. *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * Nmap in other works, are happy to help.  As mentioned above, we also    *
 * offer alternative license to integrate Nmap into proprietary            *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates.  They also fund the      *
 * continued development of Nmap.  Please email sales@nmap.com for further *
 * information.                                                            *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
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
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING)        *
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

    if (o.sslverify) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    } else {
        /* Still check verification status and report it */
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, verify_callback);
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

    nsock_iod_get_communication_info(nsi, NULL, NULL, NULL, &peer.sockaddr,
                                     sizeof(peer.storage));
    if (o.verbose) {
#ifdef HAVE_OPENSSL
        if (nsock_iod_check_ssl(nsi)) {
            X509 *cert;
            X509_NAME *subject;
            char digest_buf[SHA1_STRING_LENGTH + 1];
            char *fp;

            loguser("SSL connection to %s:%d.", inet_socktop(&peer),
                    nsock_iod_get_peerport(nsi));

            cert = SSL_get_peer_certificate((SSL *)nsock_iod_get_ssl(nsi));
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
                loguser("Connected to %s:%d.\n", inet_socktop(&peer),
                        nsock_iod_get_peerport(nsi));
        }
#else
#if HAVE_SYS_UN_H
        if (peer.sockaddr.sa_family == AF_UNIX)
            loguser("Connected to %s.\n", peer.un.sun_path);
        else
#endif
            loguser("Connected to %s:%d.\n", inet_socktop(&peer),
                    nsock_iod_get_peerport(nsi));
#endif
    }
}

/* Just like inet_socktop, but it puts IPv6 addresses in square brackets. */
static const char *sock_to_url(char *host_str, unsigned short port)
{
    static char buf[512];

    switch(getaddrfamily(host_str)) {
       case -1:
       case 1:
           Snprintf(buf, sizeof(buf), "%s:%hu", host_str, port);
           break;
       case 2:
           Snprintf(buf, sizeof(buf), "[%s]:%hu]", host_str, port);
    }

    return buf;
}

static int append_connect_request_line(char **buf, size_t *size, size_t *offset,
    char* host_str,unsigned short port)
{
    return strbuf_sprintf(buf, size, offset, "CONNECT %s HTTP/1.0\r\n",
        sock_to_url(host_str,port));
}

static char *http_connect_request(char* host_str, unsigned short port, int *n)
{
    char *buf = NULL;
    size_t size = 0, offset = 0;

    append_connect_request_line(&buf, &size, &offset, host_str, port);
    strbuf_append_str(&buf, &size, &offset, "\r\n");
    *n = offset;

    return buf;
}

static char *http_connect_request_auth(char* host_str, unsigned short port, int *n,
    struct http_challenge *challenge)
{
    char *buf = NULL;
    size_t size = 0, offset = 0;

    append_connect_request_line(&buf, &size, &offset, host_str, port);
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
            username, password, "CONNECT", sock_to_url(o.target,o.portno));
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
    request = http_connect_request(o.target,o.portno, &n);
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
    if (o.debug)
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

        request = http_connect_request_auth(o.target,o.portno, &n, &challenge);
        if (request == NULL) {
            loguser("Error building Proxy-Authorization header.\n");
            http_challenge_free(&challenge);
            goto bail;
        }
        if (o.debug)
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
        if (o.debug)
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


/* SOCKS4a support
 * Return a usable socket descriptor after
 * proxy negotiation, or -1 on any error.
 */
static int do_proxy_socks4(void)
{
    struct socket_buffer stateful_buf;
    struct socks4_data socks4msg;
    char socksbuf[8];
    int sd,len = 9;

    sd = do_connect(SOCK_STREAM);
    if (sd == -1) {
        loguser("Proxy connection failed: %s.\n", socket_strerror(socket_errno()));
        return sd;
    }
    socket_buffer_init(&stateful_buf, sd);

    if (o.verbose) {
        loguser("Connected to proxy %s:%hu\n", inet_socktop(&targetss),
            inet_port(&targetss));
    }

    /* Fill the socks4_data struct */
    zmem(&socks4msg, sizeof(socks4msg));
    socks4msg.version = SOCKS4_VERSION;
    socks4msg.type = SOCKS_CONNECT;
    socks4msg.port = htons(o.portno);

    switch(getaddrfamily(o.target)) {
        case 1: // IPv4 address family
            socks4msg.address = inet_addr(o.target);

            if (o.proxy_auth){
                memcpy(socks4msg.data, o.proxy_auth, strlen(o.proxy_auth));
                len += strlen(o.proxy_auth);
            }
            break;

        case 2: // IPv6 address family

            loguser("Error: IPv6 addresses are not supported with Socks4.\n");
            close(sd);
            return -1;

        case -1: // fqdn

            socks4msg.address = inet_addr("0.0.0.1");

            if (strlen(o.target) > SOCKS_BUFF_SIZE-2) {
                loguser("Error: host name is too long.\n");
                close(sd);
                return -1;
            }

            if (o.proxy_auth){
                if (strlen(o.target)+strlen(o.proxy_auth) > SOCKS_BUFF_SIZE-2) {
                    loguser("Error: host name and username are too long.\n");
                    close(sd);
                    return -1;
                }
                Strncpy(socks4msg.data,o.proxy_auth,sizeof(socks4msg.data));
                len += strlen(o.proxy_auth);
            }
            memcpy(socks4msg.data+(len-8), o.target, strlen(o.target));
            len += strlen(o.target)+1;
    }

    if (send(sd, (char *) &socks4msg, len, 0) < 0) {
        loguser("Error: sending proxy request: %s.\n", socket_strerror(socket_errno()));
        close(sd);
        return -1;
    }

    /* The size of the socks4 response is 8 bytes. So read exactly
       8 bytes from the buffer */
    if (socket_buffer_readcount(&stateful_buf, socksbuf, 8) < 0) {
        loguser("Error: short response from proxy.\n");
        close(sd);
        return -1;
    }

    if (sd != -1 && socksbuf[1] != SOCKS4_CONN_ACC) {
        loguser("Proxy connection failed.\n");
        close(sd);
        return -1;
    }

    return sd;
}

/* SOCKS5 support
 * Return a usable socket descriptor after
 * proxy negotiation, or -1 on any error.
 */
static int do_proxy_socks5(void)
{

    struct socket_buffer stateful_buf;
    struct socks5_connect socks5msg;
    uint32_t inetaddr;
    char inet6addr[16];
    unsigned short proxyport = htons(o.portno);
    char socksbuf[8];
    int sd,len,lenfqdn;
    struct socks5_request socks5msg2;
    struct socks5_auth socks5auth;
    char *proxy_auth;
    char *username;
    char *password;

    sd = do_connect(SOCK_STREAM);
    if (sd == -1) {
        loguser("Proxy connection failed: %s.\n", socket_strerror(socket_errno()));
        return sd;
    }

    socket_buffer_init(&stateful_buf, sd);

    if (o.verbose) {
        loguser("Connected to proxy %s:%hu\n", inet_socktop(&targetss),
            inet_port(&targetss));
    }

    zmem(&socks5msg,sizeof(socks5msg));
    socks5msg.ver = SOCKS5_VERSION;
    socks5msg.nmethods = 1;
    socks5msg.methods[0] = SOCKS5_AUTH_NONE;
    len = 3;

    if (o.proxy_auth){
        socks5msg.nmethods ++;
        socks5msg.methods[1] = SOCKS5_AUTH_USERPASS;
        len ++;
    }

    if (send(sd, (char *) &socks5msg, len, 0) < 0) {
        loguser("Error: proxy request: %s.\n", socket_strerror(socket_errno()));
        close(sd);
        return -1;
    }

    /* first response just two bytes, version and auth method */
    if (socket_buffer_readcount(&stateful_buf, socksbuf, 2) < 0) {
        loguser("Error: malformed first response from proxy.\n");
        close(sd);
        return -1;
    }

    if (socksbuf[0] != 5){
        loguser("Error: got wrong server version in response.\n");
        close(sd);
        return -1;
    }

    switch(socksbuf[1]) {
        case SOCKS5_AUTH_NONE:
            if (o.verbose)
                loguser("No authentication needed.\n");
            break;

        case SOCKS5_AUTH_GSSAPI:
            loguser("GSSAPI authentication method not supported.\n");
            close(sd);
            return -1;

        case SOCKS5_AUTH_USERPASS:
            if (o.verbose)
                loguser("Doing username and password authentication.\n");

            if(!o.proxy_auth){
                loguser("Error: proxy requested to do authentication, but no credentials were provided.\n");
                close(sd);
                return -1;
            }

            if (strlen(o.proxy_auth) > SOCKS_BUFF_SIZE-2){
                loguser("Error: username and password are too long to fit into buffer.\n");
                close(sd);
                return -1;
            }

            /* Split up the proxy auth argument. */
            proxy_auth = Strdup(o.proxy_auth);
            username = strtok(proxy_auth, ":");
            password = strtok(NULL, ":");
            if (password == NULL || username == NULL) {
                free(proxy_auth);
                loguser("Error: empty username or password.\n");
                close(sd);
                return -1;
            }

            /*
             * For username/password authentication the client's authentication request is
             * field 1: version number, 1 byte (must be 0x01 -- version of subnegotiation)
             * field 2: username length, 1 byte
             * field 3: username
             * field 4: password length, 1 byte
             * field 5: password
             *
             * Server response for username/password authentication:
             * field 1: version, 1 byte
             * field 2: status code, 1 byte.
             * 0x00 = success
             * any other value = failure, connection must be closed
             */

            socks5auth.ver = 1;
            socks5auth.data[0] = strlen(username);
            memcpy(socks5auth.data+1,username,strlen(username));
            len = 2 + strlen(username); // (version + strlen) + username

            socks5auth.data[len-1]=strlen(password);
            memcpy(socks5auth.data+len,password,strlen(password));
            len += 1 + strlen(password);

            if (send(sd, (char *) &socks5auth, len, 0) < 0) {
                loguser("Error: sending proxy authentication.\n");
                close(sd);
                return -1;
            }

            if (socket_buffer_readcount(&stateful_buf, socksbuf, 2) < 0) {
                loguser("Error: malformed proxy authentication response.\n");
                close(sd);
                return -1;
            }

            if (socksbuf[0] != 1 || socksbuf[1] != 0) {
                loguser("Error: authentication failed.\n");
                close(sd);
                return -1;
            }

            break;

        default:
            loguser("Error - can't choose any authentication method.\n");
            close(sd);
            return -1;
    }

    zmem(&socks5msg2,sizeof(socks5msg2));
    socks5msg2.ver = SOCKS5_VERSION;
    socks5msg2.cmd = SOCKS_CONNECT;
    socks5msg2.rsv = 0;

    switch(getaddrfamily(o.target)) {

        case 1: // IPv4 address family
            socks5msg2.atyp = SOCKS5_ATYP_IPv4;
            inetaddr = inet_addr(o.target);
            memcpy(socks5msg2.dst, &inetaddr, 4);
            len = 4;
            break;

        case 2: // IPv6 address family
            socks5msg2.atyp = SOCKS5_ATYP_IPv6;
            inet_pton(AF_INET6,o.target,&inet6addr);
            memcpy(socks5msg2.dst, inet6addr,16);
            len = 16;
            break;

        case -1: // FQDN
            socks5msg2.atyp = SOCKS5_ATYP_NAME;
            lenfqdn=strlen(o.target);
            if (lenfqdn > SOCKS_BUFF_SIZE-5){
                loguser("Error: host name too long.\n");
                close(sd);
                return -1;
            }
            socks5msg2.dst[0]=lenfqdn;
            memcpy(socks5msg2.dst+1,o.target,lenfqdn);
            len = 1 + lenfqdn;
    }

    memcpy(socks5msg2.dst+len, &proxyport, sizeof(proxyport));
    len += 2 + 1 + 3;

    if (len > sizeof(socks5msg2)){
        loguser("Error: address information too large.\n");
        close(sd);
        return -1;
    }

    if (send(sd, (char *) &socks5msg2, len, 0) < 0) {
        loguser("Error: sending proxy request: %s.\n", socket_strerror(socket_errno()));
        close(sd);
        return -1;
    }

    /* TODO just two bytes for now, need to read more for bind */
    if (socket_buffer_readcount(&stateful_buf, socksbuf, 2) < 0) {
        loguser("Error: malformed second response from proxy.\n");
        close(sd);
        return -1;
    }

    switch(socksbuf[1]) {
        case 0:
            if (o.verbose)
                loguser("connection succeeded.\n");
            break;
        case 1:
            loguser("Error: general SOCKS server failure.\n");
            close(sd);
            return -1;
        case 2:
            loguser("Error: connection not allowed by ruleset.\n");
            close(sd);
            return -1;
        case 3:
            loguser("Error: Network unreachable.\n");
            close(sd);
            return -1;
        case 4:
            loguser("Error: Host unreachable.\n");
            close(sd);
            return -1;
        case 5:
            loguser("Error: Connection refused.\n");
            close(sd);
            return -1;
        case 6:
            loguser("Error: TTL expired.\n");
            close(sd);
            return -1;
        case 7:
            loguser("Error: Command not supported.\n");
            close(sd);
            return -1;
        case 8:
            loguser("Error: Address type not supported.\n");
            close(sd);
            return -1;
        default:
            loguser("Error: unassigned value in the reply.\n");
            close(sd);
            return -1;
    }

    return(sd);
}


int ncat_connect(void)
{
    nsock_pool mypool;
    int rc;

    /* Unless explicitly asked not to do so, ncat uses the
     * fallback nsock engine to maximize compatibility between
     * operating systems and the different use cases.
     */
    if (!o.nsock_engine)
        nsock_set_default_engine("select");

    /* Create an nsock pool */
    if ((mypool = nsock_pool_new(NULL)) == NULL)
        bye("Failed to create nsock_pool.");

    if (o.debug >= 6)
        nsock_set_loglevel(NSOCK_LOG_DBG_ALL);
    else if (o.debug >= 3)
        nsock_set_loglevel(NSOCK_LOG_DBG);
    else if (o.debug >= 1)
        nsock_set_loglevel(NSOCK_LOG_INFO);
    else
        nsock_set_loglevel(NSOCK_LOG_ERROR);

    /* Allow connections to broadcast addresses. */
    nsock_pool_set_broadcast(mypool, 1);

#ifdef HAVE_OPENSSL
    set_ssl_ctx_options((SSL_CTX *) nsock_pool_ssl_init(mypool, 0));
#endif

    if (!o.proxytype) {
        /* A non-proxy connection. Create an iod for a new socket. */
        cs.sock_nsi = nsock_iod_new(mypool, NULL);
        if (cs.sock_nsi == NULL)
            bye("Failed to create nsock_iod.");

        if (nsock_iod_set_hostname(cs.sock_nsi, o.target) == -1)
            bye("Failed to set hostname on iod.");

#if HAVE_SYS_UN_H
        /* For DGRAM UNIX socket we have to use source socket */
        if (o.af == AF_UNIX && o.proto == IPPROTO_UDP)
        {
            if (srcaddr.storage.ss_family != AF_UNIX) {
                char *tmp_name = NULL;
#if HAVE_MKSTEMP
              char *tmpdir = getenv("TMPDIR");
              size_t size=0, offset=0;
              strbuf_sprintf(&tmp_name, &size, &offset, "%s/ncat.XXXXXX",
                  tmpdir ? tmpdir : "/tmp");
              if (mkstemp(tmp_name) == -1) {
                bye("Failed to create name for temporary DGRAM source Unix domain socket (mkstemp).");
              }
              unlink(tmp_name);
#else
                /* If no source socket was specified, we have to create temporary one. */
                if ((tmp_name = tempnam(NULL, "ncat.")) == NULL)
                    bye("Failed to create name for temporary DGRAM source Unix domain socket (tempnam).");
#endif

                srcaddr.un.sun_family = AF_UNIX;
                strncpy(srcaddr.un.sun_path, tmp_name, sizeof(srcaddr.un.sun_path));
                free (tmp_name);
            }
            nsock_iod_set_localaddr(cs.sock_nsi, &srcaddr.storage,
                                SUN_LEN((struct sockaddr_un *)&srcaddr.storage));

            if (o.verbose)
                loguser("[%s] used as source DGRAM Unix domain socket.\n", srcaddr.un.sun_path);
        }
        else
#endif
        switch (srcaddr.storage.ss_family) {
          case AF_UNSPEC:
            break;
          case AF_INET:
            nsock_iod_set_localaddr(cs.sock_nsi, &srcaddr.storage,
                                    sizeof(srcaddr.in));
            break;
#ifdef AF_INET6
          case AF_INET6:
            nsock_iod_set_localaddr(cs.sock_nsi, &srcaddr.storage,
                                    sizeof(srcaddr.in6));
            break;
#endif
#if HAVE_SYS_UN_H
          case AF_UNIX:
            nsock_iod_set_localaddr(cs.sock_nsi, &srcaddr.storage,
                                    SUN_LEN((struct sockaddr_un *)&srcaddr.storage));
            break;
#endif
          default:
            nsock_iod_set_localaddr(cs.sock_nsi, &srcaddr.storage,
                                    sizeof(srcaddr.storage));
            break;
        }

        if (o.numsrcrtes) {
            unsigned char *ipopts = NULL;
            size_t ipoptslen = 0;

            if (o.af != AF_INET)
                bye("Sorry, -g can only currently be used with IPv4.");
            ipopts = buildsrcrte(targetss.in.sin_addr, o.srcrtes, o.numsrcrtes, o.srcrteptr, &ipoptslen);

            nsock_iod_set_ipoptions(cs.sock_nsi, ipopts, ipoptslen);
            free(ipopts); /* Nsock has its own copy */
        }

#if HAVE_SYS_UN_H
        if (o.af == AF_UNIX) {
            if (o.proto == IPPROTO_UDP) {
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
        if (o.proto == IPPROTO_UDP) {
            nsock_connect_udp(mypool, cs.sock_nsi, connect_handler,
                              NULL, &targetss.sockaddr, targetsslen,
                              inet_port(&targetss));
        }
#ifdef HAVE_OPENSSL
        else if (o.proto == IPPROTO_SCTP && o.ssl) {
            nsock_connect_ssl(mypool, cs.sock_nsi, connect_handler,
                              o.conntimeout, NULL,
                              &targetss.sockaddr, targetsslen,
                              IPPROTO_SCTP, inet_port(&targetss),
                              NULL);
        }
#endif
        else if (o.proto == IPPROTO_SCTP) {
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

	    if (strcmp(o.proxytype, "http") == 0) {
            connect_socket = do_proxy_http();
        } else if (strcmp(o.proxytype, "socks4") == 0) {
            connect_socket = do_proxy_socks4();
        } else if (strcmp(o.proxytype, "socks5") == 0) {
            connect_socket = do_proxy_socks5();
        }

        if (connect_socket == -1)
            return 1;
        /* Clear out whatever is left in the socket buffer which may be
           already sent by proxy server along with http response headers. */
        //line = socket_buffer_remainder(&stateful_buf, &n);
        /* Write the leftover data to stdout. */
        //Write(STDOUT_FILENO, line, n);

        /* Once the proxy negotiation is done, Nsock takes control of the
           socket. */
        cs.sock_nsi = nsock_iod_new2(mypool, connect_socket, NULL);

        /* Create IOD for nsp->stdin */
        if ((cs.stdin_nsi = nsock_iod_new2(mypool, 0, NULL)) == NULL)
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
            nsock_iod_get_write_count(cs.sock_nsi),
            nsock_iod_get_read_count(cs.sock_nsi), time);
    }

#if HAVE_SYS_UN_H
    if (o.af == AF_UNIX && o.proto == IPPROTO_UDP) {
        if (o.verbose)
            loguser("Deleting source DGRAM Unix domain socket. [%s]\n", srcaddr.un.sun_path);
        unlink(srcaddr.un.sun_path);
    }
#endif

    nsock_pool_delete(mypool);

    return rc == NSOCK_LOOP_ERROR ? 1 : 0;
}

static void send_udp_null(nsock_pool nsp)
{
  char *NULL_PROBE = "\0";
  int length = 1;
  nsock_write(nsp, cs.sock_nsi, write_socket_handler, -1, NULL, NULL_PROBE, length);
}

static void connect_handler(nsock_pool nsp, nsock_event evt, void *data)
{
    enum nse_status status = nse_status(evt);
    enum nse_type type = nse_type(evt);

    ncat_assert(type == NSE_TYPE_CONNECT || type == NSE_TYPE_CONNECT_SSL);

    if (status == NSE_STATUS_ERROR) {
        if (!o.zerobyte||o.verbose)
          loguser("%s.\n", socket_strerror(nse_errorcode(evt)));
        exit(1);
    } else if (status == NSE_STATUS_TIMEOUT) {
        if (!o.zerobyte||o.verbose)
          loguser("%s.\n", socket_strerror(ETIMEDOUT));
        exit(1);
    } else {
        ncat_assert(status == NSE_STATUS_SUCCESS);
    }

#ifdef HAVE_OPENSSL
    if (nsock_iod_check_ssl(cs.sock_nsi)) {
        /* Check the domain name. ssl_post_connect_check prints an
           error message if appropriate. */
        if (!ssl_post_connect_check((SSL *)nsock_iod_get_ssl(cs.sock_nsi), o.target))
            bye("Certificate verification error.");
    }
#endif

    if (o.proto != IPPROTO_UDP && o.zerobyte) {
      connect_report(cs.sock_nsi);
      nsock_loop_quit(nsp);
    }

    /* Create IOD for nsp->stdin */
    if ((cs.stdin_nsi = nsock_iod_new2(nsp, 0, NULL)) == NULL)
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

        info.fd = nsock_iod_get_sd(iod);
#ifdef HAVE_OPENSSL
        info.ssl = (SSL *)nsock_iod_get_ssl(iod);
#endif
        /* Convert Nsock's non-blocking socket to an ordinary blocking one. It's
           possible for a program to write fast enough that it will get an
           EAGAIN on write on a non-blocking socket. */
        block_socket(info.fd);
        netexec(&info, o.cmdexec);
    }

    /* Start the initial reads. */

    if (!o.sendonly && !o.zerobyte)
        nsock_read(nsp, cs.sock_nsi, read_socket_handler, -1, NULL);

    if (!o.recvonly && !o.zerobyte)
        nsock_readbytes(nsp, cs.stdin_nsi, read_stdin_handler, -1, NULL, 0);

    if (o.zerobyte && o.proto==IPPROTO_UDP)
      send_udp_null(nsp);

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
        shutdown(nsock_iod_get_sd(cs.sock_nsi), SHUT_WR);
        /* In --send-only mode or non-TCP mode, exit after EOF on stdin. */
        if (o.proto != IPPROTO_TCP || (o.proto == IPPROTO_TCP && o.sendonly))
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
        /* In --recv-only mode or non-TCP mode, exit after EOF on the socket. */
        if (o.proto != IPPROTO_TCP || (o.proto == IPPROTO_TCP && o.recvonly))
            nsock_loop_quit(nsp);
        return;
    } else if (status == NSE_STATUS_ERROR) {
        if (!o.zerobyte||o.verbose)
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
        dotelnet(nsock_iod_get_sd(nse_iod(evt)), (unsigned char *) buf, nbytes);

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

    if (o.zerobyte){
      ncat_assert(o.proto == IPPROTO_UDP);
      nsock_read(nsp, cs.sock_nsi, read_socket_handler, -1, NULL);
      return;
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

    if (o.zerobyte&&o.proto==IPPROTO_UDP){
      if (o.verbose)
        loguser("UDP packet sent successfully\n");
      nsock_loop_quit(nsp);
      return;
    }

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
