/*-
 * Copyright (c) 1980, 1983, 1988, 1993
 *     The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)netdb.h	8.1 (Berkeley) 6/2/93
 *      netdb.h,v 1.4 1995/08/14 04:05:04 hjl Exp
 * -
 * Portions Copyright (c) 1993 by Digital Equipment Corporation.
 *
 * Permission to use, copy, modify and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies, and that
 * the name of Digital Equipment Corporation not be used in advertising or
 * publicity pertaining to distribution of the document or software without
 * specific, written prior permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND DIGITAL EQUIPMENT CORP. DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS.   IN NO EVENT SHALL DIGITAL EQUIPMENT
 * CORPORATION BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 * -
 * --Copyright--
 */

#ifndef _NETDB_H_
#define _NETDB_H_

/* MingW64 defines _POSIX_THREAD_SAFE_FUNCTIONS.
 */
#if defined(_POSIX_THREAD_SAFE_FUNCTIONS) || defined(_REENTRANT) && !defined(__MINGW64_VERSION_MAJOR)
#include <stdio.h>
#include <netinet/in.h>
#endif

#include <winsock2.h>
#include <net/paths.h>

#define _PATH_HEQUIV	__PATH_ETC_INET"/hosts.equiv"
#define _PATH_HOSTS	__PATH_ETC_INET"/hosts"
#define _PATH_NETWORKS	__PATH_ETC_INET"/networks"
#define _PATH_PROTOCOLS	__PATH_ETC_INET"/protocols"
#define _PATH_SERVICES	__PATH_ETC_INET"/services"
#define _PATH_RESCONF	__PATH_ETC_INET"/resolv.conf"
#define _PATH_RPC	__PATH_ETC_INET"/rpc"

struct rpcent {
	char	*r_name;	/* name of server for this rpc program */
	char	**r_aliases;	/* alias list */
	int	r_number;	/* rpc program number */
};

#ifndef WIN32
#if defined(_POSIX_THREAD_SAFE_FUNCTIONS) || defined(_REENTRANT)

#define __NETDB_MAXALIASES	35
#define __NETDB_MAXADDRS	35

/*
 * Error return codes from gethostbyname() and gethostbyaddr()
 * (left in extern int h_errno).
 */
#define h_errno		(*__h_errno_location ())
#else
extern int h_errno;
#endif
#endif

#define	NETDB_INTERNAL -1 /* see errno */
#define	NETDB_SUCCESS   0 /* no problem */

//#include <features.h>

void		endhostent (void);
void		endnetent (void);
void		endprotoent (void);
void		endservent (void);
void		endrpcent (void);
struct hostent	*gethostent (void);
struct netent	*getnetbyaddr (long, int); /* u_long? */
struct netent	*getnetbyname (const char *);
struct netent	*getnetent (void);
struct protoent	*getprotoent (void);
struct servent	*getservent (void);
struct rpcent	*getrpcent (void);
struct rpcent	*getrpcbyname (const char *);
struct rpcent	*getrpcbynumber (int);
void		herror (const char *);
void		sethostent (int);
/* void		sethostfile (const char *); */
void		setnetent (int);
void		setprotoent (int);
void		setservent (int);
void		setrpcent (int);

#if defined(_POSIX_THREAD_SAFE_FUNCTIONS) || defined(_REENTRANT)
struct hostent	*gethostbyaddr_r (const char *__addr,
			int __length, int __type,
			struct hostent *__result,
			char *__buffer, int __buflen, int *__h_errnop);
struct hostent	*gethostbyname_r (const char * __name,
			struct hostent *__result, char *__buffer,
			int __buflen, int *__h_errnop);
struct hostent	*gethostent_r (struct hostent *__result,
			char *__buffer, int __buflen, int *__h_errnop);
struct netent	*getnetbyaddr_r (long __net, int __type,
			struct netent *__result, char *__buffer,
			int __buflen);
struct netent	*getnetbyname_r (const char * __name,
			struct netent *__result, char *__buffer,
			int __buflen);
struct netent	*getnetent_r (struct netent *__result,
			char *__buffer, int __buflen);
struct protoent	*getprotobyname_r (const char * __name,
			struct protoent *__result, char *__buffer,
			int __buflen);
struct protoent	*getprotobynumber_r (int __proto,
			struct protoent *__result, char *__buffer,
			int __buflen);
struct protoent	*getprotoent_r (struct protoent *__result,
			char *__buffer, int __buflen);
struct servent	*getservbyname_r (const char * __name,
			const char *__proto, struct servent *__result,
			char *__buffer, int __buflen);
struct servent	*getservbyport_r (int __port,
			const char *__proto, struct servent *__result,
			char *__buffer, int __buflen);
struct servent	*getservent_r (struct servent *__result,
			char *__buffer, int __buflen);

int *__h_errno_location (void);

#endif

#endif /* !_NETDB_H_ */
