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
void sock_fmterror(const char *caller, int errcode, char *errbuf, int errbuflen);
void sock_geterror(const char *caller, char *errbuf, int errbufsize);
int sock_initaddress(const char *address, const char *port,
    struct addrinfo *hints, struct addrinfo **addrinfo,
    char *errbuf, int errbuflen);
int sock_recv(SOCKET sock, void *buffer, size_t size, int receiveall,
    char *errbuf, int errbuflen);
int sock_recv_dgram(SOCKET sock, void *buffer, size_t size,
    char *errbuf, int errbuflen);
SOCKET sock_open(struct addrinfo *addrinfo, int server, int nconn, char *errbuf, int errbuflen);
int sock_close(SOCKET sock, char *errbuf, int errbuflen);

int sock_send(SOCKET sock, const char *buffer, size_t size,
    char *errbuf, int errbuflen);
int sock_bufferize(const char *buffer, int size, char *tempbuf, int *offset, int totsize, int checkonly, char *errbuf, int errbuflen);
int sock_discard(SOCKET sock, int size, char *errbuf, int errbuflen);
int	sock_check_hostlist(char *hostlist, const char *sep, struct sockaddr_storage *from, char *errbuf, int errbuflen);
int sock_cmpaddr(struct sockaddr_storage *first, struct sockaddr_storage *second);

int sock_getmyinfo(SOCKET sock, char *address, int addrlen, char *port, int portlen, int flags, char *errbuf, int errbuflen);

int sock_getascii_addrport(const struct sockaddr_storage *sockaddr, char *address, int addrlen, char *port, int portlen, int flags, char *errbuf, int errbuflen);
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
