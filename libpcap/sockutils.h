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

#ifndef __SOCKUTILS_H__
#define __SOCKUTILS_H__

#ifdef _MSC_VER
#pragma once
#endif

#include <stdarg.h>	/* we declare varargs functions */

#include "pcap/funcattrs.h"

#include "pcap/socket.h"

#ifndef _WIN32
  /* UN*X */
  #include <unistd.h>	/* close() */

  /*!
   * \brief In Winsock, the close() call cannot be used on a socket;
   * closesocket() must be used.
   * We define closesocket() to be a wrapper around close() on UN*X,
   * so that it can be used on both platforms.
   */
  #define closesocket(a) close(a)
#endif

#include "sslutils.h"  // for SSL type, whatever that turns out to be

/*
 * MingW headers include this definition, but only for Windows XP and above.
 * MSDN states that this function is available for most versions on Windows.
 */
#if ((defined(__MINGW32__)) && (_WIN32_WINNT < 0x0501))
int WSAAPI getnameinfo(const struct sockaddr*,socklen_t,char*,DWORD,
	char*,DWORD,int);
#endif

/*
 * \defgroup SockUtils Cross-platform socket utilities (IPv4-IPv6)
 */

/*
 * \addtogroup SockUtils
 * \{
 */

/*
 * \defgroup ExportedStruct Exported Structures and Definitions
 */

/*
 * \addtogroup ExportedStruct
 * \{
 */

/****************************************************
 *                                                  *
 * Exported functions / definitions                 *
 *                                                  *
 ****************************************************/

/* 'checkonly' flag, into the rpsock_bufferize() */
#define SOCKBUF_CHECKONLY 1
/* no 'checkonly' flag, into the rpsock_bufferize() */
#define SOCKBUF_BUFFERIZE 0

/* no 'server' flag; it opens a client socket */
#define SOCKOPEN_CLIENT 0
/* 'server' flag; it opens a server socket */
#define SOCKOPEN_SERVER 1

/*
 * Flags for sock_recv().
 */
#define SOCK_RECEIVEALL_NO	0x00000000	/* Don't wait to receive all data */
#define SOCK_RECEIVEALL_YES	0x00000001	/* Wait to receive all data */

#define SOCK_EOF_ISNT_ERROR	0x00000000	/* Return 0 on EOF */
#define SOCK_EOF_IS_ERROR	0x00000002	/* Return an error on EOF */

#define SOCK_MSG_PEEK		0x00000004	/* Return data but leave it in the socket queue */

/*
 * \}
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * \defgroup ExportedFunc Exported Functions
 */

/*
 * \addtogroup ExportedFunc
 * \{
 */

int sock_init(char *errbuf, int errbuflen);
void sock_cleanup(void);
int sock_geterrcode(void);
void sock_vfmterrmsg(char *errbuf, size_t errbuflen, int errcode,
    PCAP_FORMAT_STRING(const char *fmt), va_list ap) PCAP_PRINTFLIKE(4, 0);
void sock_fmterrmsg(char *errbuf, size_t errbuflen, int errcode,
    PCAP_FORMAT_STRING(const char *fmt), ...) PCAP_PRINTFLIKE(4, 5);
void sock_geterrmsg(char *errbuf, size_t errbuflen,
    PCAP_FORMAT_STRING(const char *fmt), ...)  PCAP_PRINTFLIKE(3, 4);
struct addrinfo *sock_initaddress(const char *address, const char *port,
    struct addrinfo *hints, char *errbuf, int errbuflen);
int sock_recv(PCAP_SOCKET sock, SSL *, void *buffer, size_t size,
    int receiveall, char *errbuf, int errbuflen);
int sock_recv_dgram(PCAP_SOCKET sock, SSL *, void *buffer, size_t size,
    char *errbuf, int errbuflen);
PCAP_SOCKET sock_open(const char *host, struct addrinfo *addrinfo, int server,
    int nconn, char *errbuf, int errbuflen);
int sock_close(PCAP_SOCKET sock, char *errbuf, int errbuflen);

int sock_send(PCAP_SOCKET sock, SSL *, const char *buffer, size_t size,
    char *errbuf, int errbuflen);
int sock_bufferize(const void *data, int size, char *outbuf, int *offset, int totsize, int checkonly, char *errbuf, int errbuflen);
int sock_discard(PCAP_SOCKET sock, SSL *, int size, char *errbuf,
    int errbuflen);
int	sock_check_hostlist(const char *hostlist, const char *sep, struct sockaddr_storage *from, char *errbuf, int errbuflen);
int sock_cmpaddr(struct sockaddr_storage *first, struct sockaddr_storage *second);

int sock_getmyinfo(PCAP_SOCKET sock, char *address, int addrlen, char *port,
    int portlen, int flags, char *errbuf, int errbuflen);

int sock_getascii_addrport(const struct sockaddr_storage *sockaddr, char *address, int addrlen, char *port, int portlen, int flags, char *errbuf, size_t errbuflen);
int sock_present2network(const char *address, struct sockaddr_storage *sockaddr, int addr_family, char *errbuf, int errbuflen);

#ifdef __cplusplus
}
#endif

/*
 * \}
 */

/*
 * \}
 */

#endif
