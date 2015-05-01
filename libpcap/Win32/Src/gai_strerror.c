/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
#include <sys/cdefs.h>

__FBSDID("$FreeBSD: /repoman/r/ncvs/src/lib/libc/net/gai_strerror.c,v 1.1 2005/04/06 12:45:51 ume Exp $");

*/

#ifdef WIN32

#include <ws2tcpip.h>

#else

#include <netdb.h>

#endif

/* Entries EAI_ADDRFAMILY (1) and EAI_NODATA (7) are obsoleted, but left */
/* for backward compatibility with userland code prior to 2553bis-02 */
static char *ai_errlist[] = {
	"Success",					/* 0 */
	"Address family for hostname not supported",	/* 1 */
	"Temporary failure in name resolution",		/* EAI_AGAIN */
	"Invalid value for ai_flags",			/* EAI_BADFLAGS */
	"Non-recoverable failure in name resolution",	/* EAI_FAIL */
	"ai_family not supported",			/* EAI_FAMILY */
	"Memory allocation failure", 			/* EAI_MEMORY */
	"No address associated with hostname",		/* 7 */
	"hostname nor servname provided, or not known",	/* EAI_NONAME */
	"servname not supported for ai_socktype",	/* EAI_SERVICE */
	"ai_socktype not supported", 			/* EAI_SOCKTYPE */
	"System error returned in errno", 		/* EAI_SYSTEM */
	"Invalid value for hints",			/* EAI_BADHINTS */
	"Resolved protocol is unknown"			/* EAI_PROTOCOL */
};

#ifndef EAI_MAX
#define EAI_MAX (sizeof(ai_errlist)/sizeof(ai_errlist[0]))
#endif

/* on MingW, gai_strerror is available.
   We need to compile gai_strerrorA only for Cygwin
 */
#ifndef gai_strerror

char *
WSAAPI gai_strerrorA(int ecode)
{
	if (ecode >= 0 && ecode < EAI_MAX)
		return ai_errlist[ecode];
	return "Unknown error";
}

#endif /* gai_strerror */