/***************************************************************************
 * ncat_ssl.h                                                              *
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
#ifndef NCAT_SSL_H
#define NCAT_SSL_H

#include "ncat_config.h"

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>

#define NCAT_CA_CERTS_FILE "ca-bundle.crt"

enum {
    SHA1_BYTES = 160 / 8,
    /* 40 bytes for hex digits and 9 bytes for ' '. */
    SHA1_STRING_LENGTH = SHA1_BYTES * 2 + (SHA1_BYTES / 2 - 1)
};

/* These status variables are returned by ssl_handshake() to describe the
 * status of a pending non-blocking ssl handshake(SSL_accept()). */
enum {
    NCAT_SSL_HANDSHAKE_COMPLETED      = 0,
    NCAT_SSL_HANDSHAKE_PENDING_READ   = 1,
    NCAT_SSL_HANDSHAKE_PENDING_WRITE  = 2,
    NCAT_SSL_HANDSHAKE_FAILED         = 3
};

extern SSL_CTX *setup_ssl_listen(const SSL_METHOD *method);

extern SSL *new_ssl(int fd);

extern int ssl_post_connect_check(SSL *ssl, const char *hostname);

extern char *ssl_cert_fp_str_sha1(const X509 *cert, char *strbuf, size_t len);

extern int ssl_load_default_ca_certs(SSL_CTX *ctx);

/* Try to complete an ssl handshake in a non-blocking way for the socket given
 * in sinfo. Initialize the socket too with new_ssl() if it hasn't been done
 * already. */
extern int ssl_handshake(struct fdinfo *sinfo);

#endif
#endif
