/*
 * Copyright (c) 2002 - 2003
 * NetGroup, Politecnico di Torino (Italy)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef __SSLUTILS_H__
#define __SSLUTILS_H__

#ifdef HAVE_OPENSSL
#include "pcap/socket.h"  // for SOCKET
#include <openssl/ssl.h>
#include <openssl/err.h>

/*
 * Utility functions
 */

void ssl_set_certfile(const char *certfile);
void ssl_set_keyfile(const char *keyfile);
int ssl_init_once(int is_server, int enable_compression, char *errbuf, size_t errbuflen);
SSL *ssl_promotion(int is_server, SOCKET s, char *errbuf, size_t errbuflen);
void ssl_finish(SSL *ssl);
int ssl_send(SSL *, char const *buffer, int size, char *errbuf, size_t errbuflen);
int ssl_recv(SSL *, char *buffer, int size, char *errbuf, size_t errbuflen);

// The SSL parameters are used
#define _U_NOSSL_

#else   // HAVE_OPENSSL

// This saves us from a lot of ifdefs:
#define SSL void const

// The SSL parameters are unused
#define _U_NOSSL_	_U_

#endif  // HAVE_OPENSSL

#endif  // __SSLUTILS_H__
