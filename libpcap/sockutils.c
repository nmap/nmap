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

#include <config.h>

/*
 * \file sockutils.c
 *
 * The goal of this file is to provide a common set of primitives for socket
 * manipulation.
 *
 * Although the socket interface defined in the RFC 2553 (and its updates)
 * is excellent, there are still differences between the behavior of those
 * routines on UN*X and Windows, and between UN*Xes.
 *
 * These calls provide an interface similar to the socket interface, but
 * that hides the differences between operating systems.  It does not
 * attempt to significantly improve on the socket interface in other
 * ways.
 */

#include "ftmacros.h"

#include <string.h>
#include <errno.h>	/* for the errno variable */
#include <stdio.h>	/* for the stderr file */
#include <stdlib.h>	/* for malloc() and free() */
#include <limits.h>	/* for INT_MAX */

#include "pcap-int.h"

#include "sockutils.h"
#include "portability.h"

#ifdef _WIN32
  /*
   * Winsock initialization.
   *
   * Ask for Winsock 2.2.
   */
  #define WINSOCK_MAJOR_VERSION 2
  #define WINSOCK_MINOR_VERSION 2

  static int sockcount = 0;	/*!< Variable that allows calling the WSAStartup() only one time */
#endif

/* Some minor differences between UNIX and Win32 */
#ifdef _WIN32
  #define SHUT_WR SD_SEND	/* The control code for shutdown() is different in Win32 */
#endif

/* Size of the buffer that has to keep error messages */
#define SOCK_ERRBUF_SIZE 1024

/* Constants; used in order to keep strings here */
#define SOCKET_NO_NAME_AVAILABLE "No name available"
#define SOCKET_NO_PORT_AVAILABLE "No port available"
#define SOCKET_NAME_NULL_DAD "Null address (possibly DAD Phase)"

/*
 * On UN*X, send() and recv() return ssize_t.
 *
 * On Windows, send() and recv() return an int.
 *
 *   With MSVC, there *is* no ssize_t.
 *
 *   With MinGW, there is an ssize_t type; it is either an int (32 bit)
 *   or a long long (64 bit).
 *
 * So, on Windows, if we don't have ssize_t defined, define it as an
 * int, so we can use it, on all platforms, as the type of variables
 * that hold the return values from send() and recv().
 */
#if defined(_WIN32) && !defined(_SSIZE_T_DEFINED)
typedef int ssize_t;
#endif

/****************************************************
 *                                                  *
 * Locally defined functions                        *
 *                                                  *
 ****************************************************/

static int sock_ismcastaddr(const struct sockaddr *saddr);

/****************************************************
 *                                                  *
 * Function bodies                                  *
 *                                                  *
 ****************************************************/

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
const uint8_t *fuzzBuffer;
size_t fuzzSize;
size_t fuzzPos;

void sock_initfuzz(const uint8_t *Data, size_t Size) {
	fuzzPos = 0;
	fuzzSize = Size;
	fuzzBuffer = Data;
}

static int fuzz_recv(char *bufp, int remaining) {
	if (remaining > fuzzSize - fuzzPos) {
		remaining = fuzzSize - fuzzPos;
	}
	if (fuzzPos < fuzzSize) {
		memcpy(bufp, fuzzBuffer + fuzzPos, remaining);
	}
	fuzzPos += remaining;
	return remaining;
}
#endif

int sock_geterrcode(void)
{
#ifdef _WIN32
	return GetLastError();
#else
	return errno;
#endif
}

/*
 * Format an error message given an errno value (UN*X) or a Winsock error
 * (Windows).
 */
void sock_vfmterrmsg(char *errbuf, size_t errbuflen, int errcode,
    const char *fmt, va_list ap)
{
	if (errbuf == NULL)
		return;

#ifdef _WIN32
	pcapint_vfmt_errmsg_for_win32_err(errbuf, errbuflen, errcode,
	    fmt, ap);
#else
	pcapint_vfmt_errmsg_for_errno(errbuf, errbuflen, errcode,
	    fmt, ap);
#endif
}

void sock_fmterrmsg(char *errbuf, size_t errbuflen, int errcode,
    const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	sock_vfmterrmsg(errbuf, errbuflen, errcode, fmt, ap);
	va_end(ap);
}

/*
 * Format an error message for the last socket error.
 */
void sock_geterrmsg(char *errbuf, size_t errbuflen, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	sock_vfmterrmsg(errbuf, errbuflen, sock_geterrcode(), fmt, ap);
	va_end(ap);
}

/*
 * Types of error.
 *
 * These are sorted by how likely they are to be the "underlying" problem,
 * so that lower-rated errors for a given address in a given family
 * should not overwrite higher-rated errors for another address in that
 * family, and higher-rated errors should overwrite lower-rated errors.
 */
typedef enum {
	SOCK_CONNERR,		/* connection error */
	SOCK_HOSTERR,		/* host error */
	SOCK_NETERR,		/* network error */
	SOCK_AFNOTSUPERR,	/* address family not supported */
	SOCK_UNKNOWNERR,	/* unknown error */
	SOCK_NOERR		/* no error */
} sock_errtype;

static sock_errtype sock_geterrtype(int errcode)
{
	switch (errcode) {

#ifdef _WIN32
	case WSAECONNRESET:
	case WSAECONNABORTED:
	case WSAECONNREFUSED:
#else
	case ECONNRESET:
	case ECONNABORTED:
	case ECONNREFUSED:
#endif
		/*
		 * Connection error; this means the problem is probably
		 * that there's no server set up on the remote machine,
		 * or that it is set up, but it's IPv4-only or IPv6-only
		 * and we're trying the wrong address family.
		 *
		 * These overwrite all other errors, as they indicate
		 * that, even if something else went wrong in another
		 * attempt, this probably wouldn't work even if the
		 * other problems were fixed.
		 */
		return (SOCK_CONNERR);

#ifdef _WIN32
	case WSAENETUNREACH:
	case WSAETIMEDOUT:
	case WSAEHOSTDOWN:
	case WSAEHOSTUNREACH:
#else
	case ENETUNREACH:
	case ETIMEDOUT:
	case EHOSTDOWN:
	case EHOSTUNREACH:
#endif
		/*
		 * Network errors that could be IPv4-specific, IPv6-
		 * specific, or present with both.
		 *
		 * Don't overwrite connection errors, but overwrite
		 * everything else.
		 */
		return (SOCK_HOSTERR);

#ifdef _WIN32
	case WSAENETDOWN:
	case WSAENETRESET:
#else
	case ENETDOWN:
	case ENETRESET:
#endif
		/*
		 * Network error; this means we don't know whether
		 * there's a server set up on the remote machine,
		 * and we don't have a reason to believe that IPv6
		 * any worse or better than IPv4.
		 *
		 * These probably indicate a local failure, e.g.
		 * an interface is down.
		 *
		 * Don't overwrite connection errors or host errors,
		 * but overwrite everything else.
		 */
		return (SOCK_NETERR);

#ifdef _WIN32
	case WSAEAFNOSUPPORT:
#else
	case EAFNOSUPPORT:
#endif
		/*
		 * "Address family not supported" probably means
		 * "No soup^WIPv6 for you!".
		 *
		 * Don't overwrite connection errors, host errors, or
		 * network errors (none of which we should get for this
		 * address family if it's not supported), but overwrite
		 * everything else.
		 */
		return (SOCK_AFNOTSUPERR);

	default:
		/*
		 * Anything else.
		 *
		 * Don't overwrite any errors.
		 */
		return (SOCK_UNKNOWNERR);
	}
}

/*
 * \brief This function initializes the socket mechanism if it hasn't
 * already been initialized or reinitializes it after it has been
 * cleaned up.
 *
 * On UN*Xes, it doesn't need to do anything; on Windows, it needs to
 * initialize Winsock.
 *
 * \param errbuf: a pointer to an user-allocated buffer that will contain
 * the complete error message. This buffer has to be at least 'errbuflen'
 * in length. It can be NULL; in this case no error message is supplied.
 *
 * \param errbuflen: length of the buffer that will contains the error.
 * The error message cannot be larger than 'errbuflen - 1' because the
 * last char is reserved for the string terminator.
 *
 * \return '0' if everything is fine, '-1' if some errors occurred. The
 * error message is returned in the buffer pointed to by 'errbuf' variable.
 */
#ifdef _WIN32
int sock_init(char *errbuf, int errbuflen)
{
	if (sockcount == 0)
	{
		WSADATA wsaData;			/* helper variable needed to initialize Winsock */

		if (WSAStartup(MAKEWORD(WINSOCK_MAJOR_VERSION,
		    WINSOCK_MINOR_VERSION), &wsaData) != 0)
		{
			if (errbuf)
				snprintf(errbuf, errbuflen, "Failed to initialize Winsock\n");
			return -1;
		}
	}

	sockcount++;
	return 0;
}
#else
int sock_init(char *errbuf _U_, int errbuflen _U_)
{
	/*
	 * Nothing to do on UN*Xes.
	 */
	return 0;
}
#endif

/*
 * \brief This function cleans up the socket mechanism if we have no
 * sockets left open.
 *
 * On UN*Xes, it doesn't need to do anything; on Windows, it needs
 * to clean up Winsock.
 *
 * \return No error values.
 */
void sock_cleanup(void)
{
#ifdef _WIN32
	sockcount--;

	if (sockcount == 0)
		WSACleanup();
#endif
}

/*
 * \brief It checks if the sockaddr variable contains a multicast address.
 *
 * \return '0' if the address is multicast, '-1' if it is not.
 */
static int sock_ismcastaddr(const struct sockaddr *saddr)
{
	if (saddr->sa_family == PF_INET)
	{
		struct sockaddr_in *saddr4 = (struct sockaddr_in *) saddr;
		if (IN_MULTICAST(ntohl(saddr4->sin_addr.s_addr))) return 0;
		else return -1;
	}
	else
	{
		struct sockaddr_in6 *saddr6 = (struct sockaddr_in6 *) saddr;
		if (IN6_IS_ADDR_MULTICAST(&saddr6->sin6_addr)) return 0;
		else return -1;
	}
}

struct addr_status {
	struct addrinfo *info;
	int errcode;
	sock_errtype errtype;
};

/*
 * Sort by IPv4 address vs. IPv6 address.
 */
static int compare_addrs_to_try_by_address_family(const void *a, const void *b)
{
	const struct addr_status *addr_a = (const struct addr_status *)a;
	const struct addr_status *addr_b = (const struct addr_status *)b;

	return addr_a->info->ai_family - addr_b->info->ai_family;
}

/*
 * Sort by error type and, within a given error type, by error code and,
 * within a given error code, by IPv4 address vs. IPv6 address.
 */
static int compare_addrs_to_try_by_status(const void *a, const void *b)
{
	const struct addr_status *addr_a = (const struct addr_status *)a;
	const struct addr_status *addr_b = (const struct addr_status *)b;

	if (addr_a->errtype == addr_b->errtype)
	{
		if (addr_a->errcode == addr_b->errcode)
		{
			return addr_a->info->ai_family - addr_b->info->ai_family;
		}
		return addr_a->errcode - addr_b->errcode;
	}

	return addr_a->errtype - addr_b->errtype;
}

static PCAP_SOCKET sock_create_socket(struct addrinfo *addrinfo, char *errbuf,
    int errbuflen)
{
	PCAP_SOCKET sock;
#ifdef SO_NOSIGPIPE
	int on = 1;
#endif

	sock = socket(addrinfo->ai_family, addrinfo->ai_socktype,
	    addrinfo->ai_protocol);
	if (sock == INVALID_SOCKET)
	{
		sock_geterrmsg(errbuf, errbuflen, "socket() failed");
		return INVALID_SOCKET;
	}

	/*
	 * Disable SIGPIPE, if we have SO_NOSIGPIPE.  We don't want to
	 * have to deal with signals if the peer closes the connection,
	 * especially in client programs, which may not even be aware that
	 * they're sending to sockets.
	 */
#ifdef SO_NOSIGPIPE
	if (setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, (char *)&on,
	    sizeof (int)) == -1)
	{
		sock_geterrmsg(errbuf, errbuflen,
		    "setsockopt(SO_NOSIGPIPE) failed");
		closesocket(sock);
		return INVALID_SOCKET;
	}
#endif
	return sock;
}

/*
 * \brief It initializes a network connection both from the client and the server side.
 *
 * In case of a client socket, this function calls socket() and connect().
 * In the meanwhile, it checks for any socket error.
 * If an error occurs, it writes the error message into 'errbuf'.
 *
 * In case of a server socket, the function calls socket(), bind() and listen().
 *
 * This function is usually preceded by the sock_initaddress().
 *
 * \param host: for client sockets, the host name to which we're trying
 * to connect.
 *
 * \param addrinfo: pointer to an addrinfo variable which will be used to
 * open the socket and such. This variable is the one returned by the previous call to
 * sock_initaddress().
 *
 * \param server: '1' if this is a server socket, '0' otherwise.
 *
 * \param nconn: number of the connections that are allowed to wait into the listen() call.
 * This value has no meanings in case of a client socket.
 *
 * \param errbuf: a pointer to an user-allocated buffer that will contain the complete
 * error message. This buffer has to be at least 'errbuflen' in length.
 * It can be NULL; in this case the error cannot be printed.
 *
 * \param errbuflen: length of the buffer that will contains the error. The error message cannot be
 * larger than 'errbuflen - 1' because the last char is reserved for the string terminator.
 *
 * \return the socket that has been opened (that has to be used in the following sockets calls)
 * if everything is fine, INVALID_SOCKET if some errors occurred. The error message is returned
 * in the 'errbuf' variable.
 */
PCAP_SOCKET sock_open(const char *host, struct addrinfo *addrinfo,
    int server, int nconn, char *errbuf, int errbuflen)
{
	PCAP_SOCKET sock;

	/* This is a server socket */
	if (server)
	{
		int on;

		/*
		 * Attempt to create the socket.
		 */
		sock = sock_create_socket(addrinfo, errbuf, errbuflen);
		if (sock == INVALID_SOCKET)
		{
			return INVALID_SOCKET;
		}

		/*
		 * Allow a new server to bind the socket after the old one
		 * exited, even if lingering sockets are still present.
		 *
		 * Don't treat an error as a failure.
		 */
		on = 1;
		(void)setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
		    (char *)&on, sizeof (on));

#if defined(IPV6_V6ONLY) || defined(IPV6_BINDV6ONLY)
		/*
		 * Force the use of IPv6-only addresses.
		 *
		 * RFC 3493 indicates that you can support IPv4 on an
		 * IPv6 socket:
		 *
		 *    https://tools.ietf.org/html/rfc3493#section-3.7
		 *
		 * and that this is the default behavior.  This means
		 * that if we first create an IPv6 socket bound to the
		 * "any" address, it is, in effect, also bound to the
		 * IPv4 "any" address, so when we create an IPv4 socket
		 * and try to bind it to the IPv4 "any" address, it gets
		 * EADDRINUSE.
		 *
		 * Not all network stacks support IPv4 on IPv6 sockets;
		 * pre-NT 6 Windows stacks don't support it, and the
		 * OpenBSD stack doesn't support it for security reasons
		 * (see the OpenBSD inet6(4) man page).  Therefore, we
		 * don't want to rely on this behavior.
		 *
		 * So we try to disable it, using either the IPV6_V6ONLY
		 * option from RFC 3493:
		 *
		 *    https://tools.ietf.org/html/rfc3493#section-5.3
		 *
		 * or the IPV6_BINDV6ONLY option from older UN*Xes.
		 */
#ifndef IPV6_V6ONLY
  /* For older systems */
  #define IPV6_V6ONLY IPV6_BINDV6ONLY
#endif /* IPV6_V6ONLY */
		if (addrinfo->ai_family == PF_INET6)
		{
			on = 1;
			if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY,
			    (char *)&on, sizeof (int)) == -1)
			{
				if (errbuf)
					snprintf(errbuf, errbuflen, "setsockopt(IPV6_V6ONLY)");
				closesocket(sock);
				return INVALID_SOCKET;
			}
		}
#endif /* defined(IPV6_V6ONLY) || defined(IPV6_BINDV6ONLY) */

		/* WARNING: if the address is a mcast one, I should place the proper Win32 code here */
		if (bind(sock, addrinfo->ai_addr, (int) addrinfo->ai_addrlen) != 0)
		{
			sock_geterrmsg(errbuf, errbuflen, "bind() failed");
			closesocket(sock);
			return INVALID_SOCKET;
		}

		if (addrinfo->ai_socktype == SOCK_STREAM)
			if (listen(sock, nconn) == -1)
			{
				sock_geterrmsg(errbuf, errbuflen,
				    "listen() failed");
				closesocket(sock);
				return INVALID_SOCKET;
			}

		/* server side ended */
		return sock;
	}
	else	/* we're the client */
	{
		struct addr_status *addrs_to_try;
		struct addrinfo *tempaddrinfo;
		size_t numaddrinfos;
		size_t i;
		int current_af = AF_UNSPEC;

		/*
		 * We have to loop though all the addrinfos returned.
		 * For instance, we can have both IPv6 and IPv4 addresses,
		 * but the service we're trying to connect to is unavailable
		 * in IPv6, so we have to try in IPv4 as well.
		 *
		 * How many addrinfos do we have?
		 */
		numaddrinfos =  0;
		for (tempaddrinfo = addrinfo; tempaddrinfo != NULL;
		    tempaddrinfo = tempaddrinfo->ai_next)
		{
			numaddrinfos++;
		}

		if (numaddrinfos == 0)
		{
			snprintf(errbuf, errbuflen,
			    "There are no addresses in the address list");
			return INVALID_SOCKET;
		}

		/*
		 * Allocate an array of struct addr_status and fill it in.
		 */
		addrs_to_try = calloc(numaddrinfos, sizeof *addrs_to_try);
		if (addrs_to_try == NULL)
		{
			snprintf(errbuf, errbuflen,
			    "Out of memory connecting to %s", host);
			return INVALID_SOCKET;
		}

		for (tempaddrinfo = addrinfo, i = 0; tempaddrinfo != NULL;
		    tempaddrinfo = tempaddrinfo->ai_next, i++)
		{
			addrs_to_try[i].info = tempaddrinfo;
			addrs_to_try[i].errcode = 0;
			addrs_to_try[i].errtype = SOCK_NOERR;
		}

		/*
		 * Sort the structures to put the IPv4 addresses before the
		 * IPv6 addresses; we will have to create an IPv4 socket
		 * for the IPv4 addresses and an IPv6 socket for the IPv6
		 * addresses (one of the arguments to socket() is the
		 * address/protocol family to use, and IPv4 and IPv6 are
		 * separate address/protocol families).
		 */
		qsort(addrs_to_try, numaddrinfos, sizeof *addrs_to_try,
		    compare_addrs_to_try_by_address_family);

		/* Start out with no socket. */
		sock = INVALID_SOCKET;

		/*
		 * Now try them all.
		 */
		for (i = 0; i < numaddrinfos; i++)
		{
			tempaddrinfo = addrs_to_try[i].info;
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
			break;
#endif
			/*
			 * If we have a socket, but it's for a
			 * different address family, close it.
			 */
			if (sock != INVALID_SOCKET &&
			    current_af != tempaddrinfo->ai_family)
			{
				closesocket(sock);
				sock = INVALID_SOCKET;
			}

			/*
			 * If we don't have a socket, open one
			 * for *this* address's address family.
			 */
			if (sock == INVALID_SOCKET)
			{
				sock = sock_create_socket(tempaddrinfo,
				    errbuf, errbuflen);
				if (sock == INVALID_SOCKET)
				{
					free(addrs_to_try);
					return INVALID_SOCKET;
				}
			}
			if (connect(sock, tempaddrinfo->ai_addr, (int) tempaddrinfo->ai_addrlen) == -1)
			{
				addrs_to_try[i].errcode = sock_geterrcode();
				addrs_to_try[i].errtype =
				   sock_geterrtype(addrs_to_try[i].errcode);
			}
			else
				break;
		}

		/*
		 * Check how we exited from the previous loop.
		 * If tempaddrinfo is equal to NULL, it means that all
		 * the connect() attempts failed.  Construct an
		 * error message.
		 */
		if (i == numaddrinfos)
		{
			int same_error_for_all;
			int first_error;

			closesocket(sock);

			/*
			 * Sort the statuses to group together categories
			 * of errors, errors within categories, and
			 * address families within error sets.
			 */
			qsort(addrs_to_try, numaddrinfos, sizeof *addrs_to_try,
			    compare_addrs_to_try_by_status);

			/*
			 * Are all the errors the same?
			 */
			same_error_for_all = 1;
			first_error = addrs_to_try[0].errcode;
			for (i = 1; i < numaddrinfos; i++)
			{
				if (addrs_to_try[i].errcode != first_error)
				{
					same_error_for_all = 0;
					break;
				}
			}

			if (same_error_for_all) {
				/*
				 * Yes.  No need to show the IP
				 * addresses.
				 */
				if (addrs_to_try[0].errtype == SOCK_CONNERR) {
					/*
					 * Connection error; note that
					 * the daemon might not be set
					 * up correctly, or set up at all.
					 */
					sock_fmterrmsg(errbuf, errbuflen,
					    addrs_to_try[0].errcode,
					    "Is the server properly installed? Cannot connect to %s",
					    host);
				} else {
					sock_fmterrmsg(errbuf, errbuflen,
					    addrs_to_try[0].errcode,
					    "Cannot connect to %s", host);
				}
			} else {
				/*
				 * Show all the errors and the IP addresses
				 * to which they apply.
				 */
				char *errbufptr;
				size_t bufspaceleft;
				size_t msglen;

				snprintf(errbuf, errbuflen,
				    "Connect to %s failed: ", host);

				msglen = strlen(errbuf);
				errbufptr = errbuf + msglen;
				bufspaceleft = errbuflen - msglen;

				for (i = 0; i < numaddrinfos &&
				    addrs_to_try[i].errcode != SOCK_NOERR;
				    i++)
				{
					/*
					 * Get the string for the address
					 * and port that got this error.
					 */
					sock_getascii_addrport((struct sockaddr_storage *) addrs_to_try[i].info->ai_addr,
					    errbufptr, (int)bufspaceleft,
					    NULL, 0, NI_NUMERICHOST, NULL, 0);
					msglen = strlen(errbuf);
					errbufptr = errbuf + msglen;
					bufspaceleft = errbuflen - msglen;

					if (i + 1 < numaddrinfos &&
					    addrs_to_try[i + 1].errcode == addrs_to_try[i].errcode)
					{
						/*
						 * There's another error
						 * after this, and it has
						 * the same error code.
						 *
						 * Append a comma, as the
						 * list of addresses with
						 * this error has another
						 * entry.
						 */
						snprintf(errbufptr, bufspaceleft,
						    ", ");
					}
					else
					{
						/*
						 * Either there are no
						 * more errors after this,
						 * or the next error is
						 * different.
						 *
						 * Append a colon and
						 * the message for tis
						 * error, followed by a
						 * comma if there are
						 * more errors.
						 */
						sock_fmterrmsg(errbufptr,
						    bufspaceleft,
						    addrs_to_try[i].errcode,
						    "%s", "");
						msglen = strlen(errbuf);
						errbufptr = errbuf + msglen;
						bufspaceleft = errbuflen - msglen;

						if (i + 1 < numaddrinfos &&
						    addrs_to_try[i + 1].errcode != SOCK_NOERR)
						{
							/*
							 * More to come.
							 */
							snprintf(errbufptr,
							    bufspaceleft,
							    ", ");
						}
					}
					msglen = strlen(errbuf);
					errbufptr = errbuf + msglen;
					bufspaceleft = errbuflen - msglen;
				}
			}
			free(addrs_to_try);
			return INVALID_SOCKET;
		}
		else
		{
			free(addrs_to_try);
			return sock;
		}
	}
}

/*
 * \brief Closes the present (TCP and UDP) socket connection.
 *
 * This function sends a shutdown() on the socket in order to disable send() calls
 * (while recv() ones are still allowed). Then, it closes the socket.
 *
 * \param sock: the socket identifier of the connection that has to be closed.
 *
 * \param errbuf: a pointer to an user-allocated buffer that will contain the complete
 * error message. This buffer has to be at least 'errbuflen' in length.
 * It can be NULL; in this case the error cannot be printed.
 *
 * \param errbuflen: length of the buffer that will contains the error. The error message cannot be
 * larger than 'errbuflen - 1' because the last char is reserved for the string terminator.
 *
 * \return '0' if everything is fine, '-1' if some errors occurred. The error message is returned
 * in the 'errbuf' variable.
 */
int sock_close(PCAP_SOCKET sock, char *errbuf, int errbuflen)
{
	/*
	 * SHUT_WR: subsequent calls to the send function are disallowed.
	 * For TCP sockets, a FIN will be sent after all data is sent and
	 * acknowledged by the Server.
	 */
	if (shutdown(sock, SHUT_WR))
	{
		sock_geterrmsg(errbuf, errbuflen, "shutdown() failed");
		/* close the socket anyway */
		closesocket(sock);
		return -1;
	}

	closesocket(sock);
	return 0;
}

/*
 * gai_strerror() has some problems:
 *
 * 1) on Windows, Microsoft explicitly says it's not thread-safe;
 * 2) on UN*X, the Single UNIX Specification doesn't say it *is*
 *    thread-safe, so an implementation might use a static buffer
 *    for unknown error codes;
 * 3) the error message for the most likely error, EAI_NONAME, is
 *    truly horrible on several platforms ("nodename nor servname
 *    provided, or not known"?  It's typically going to be "not
 *    known", not "oopsie, I passed null pointers for the host name
 *    and service name", not to mention they forgot the "neither");
 *
 * so we roll our own.
 */
static void
get_gai_errstring(char *errbuf, int errbuflen, const char *prefix, int err,
    const char *hostname, const char *portname)
{
	char hostport[PCAP_ERRBUF_SIZE];

	if (hostname != NULL && portname != NULL)
		snprintf(hostport, PCAP_ERRBUF_SIZE, "host and port %s:%s",
		    hostname, portname);
	else if (hostname != NULL)
		snprintf(hostport, PCAP_ERRBUF_SIZE, "host %s",
		    hostname);
	else if (portname != NULL)
		snprintf(hostport, PCAP_ERRBUF_SIZE, "port %s",
		    portname);
	else
		snprintf(hostport, PCAP_ERRBUF_SIZE, "<no host or port!>");
	switch (err)
	{
#ifdef EAI_ADDRFAMILY
		case EAI_ADDRFAMILY:
			snprintf(errbuf, errbuflen,
			    "%sAddress family for %s not supported",
			    prefix, hostport);
			break;
#endif

		case EAI_AGAIN:
			snprintf(errbuf, errbuflen,
			    "%s%s could not be resolved at this time",
			    prefix, hostport);
			break;

		case EAI_BADFLAGS:
			snprintf(errbuf, errbuflen,
			    "%sThe ai_flags parameter for looking up %s had an invalid value",
			    prefix, hostport);
			break;

		case EAI_FAIL:
			snprintf(errbuf, errbuflen,
			    "%sA non-recoverable error occurred when attempting to resolve %s",
			    prefix, hostport);
			break;

		case EAI_FAMILY:
			snprintf(errbuf, errbuflen,
			    "%sThe address family for looking up %s was not recognized",
			    prefix, hostport);
			break;

		case EAI_MEMORY:
			snprintf(errbuf, errbuflen,
			    "%sOut of memory trying to allocate storage when looking up %s",
			    prefix, hostport);
			break;

		/*
		 * RFC 2553 had both EAI_NODATA and EAI_NONAME.
		 *
		 * RFC 3493 has only EAI_NONAME.
		 *
		 * Some implementations define EAI_NODATA and EAI_NONAME
		 * to the same value, others don't.  If EAI_NODATA is
		 * defined and isn't the same as EAI_NONAME, we handle
		 * EAI_NODATA.
		 */
#if defined(EAI_NODATA) && EAI_NODATA != EAI_NONAME
		case EAI_NODATA:
			snprintf(errbuf, errbuflen,
			    "%sNo address associated with %s",
			    prefix, hostport);
			break;
#endif

		case EAI_NONAME:
			snprintf(errbuf, errbuflen,
			    "%sThe %s couldn't be resolved",
			    prefix, hostport);
			break;

		case EAI_SERVICE:
			snprintf(errbuf, errbuflen,
			    "%sThe service value specified when looking up %s as not recognized for the socket type",
			    prefix, hostport);
			break;

		case EAI_SOCKTYPE:
			snprintf(errbuf, errbuflen,
			    "%sThe socket type specified when looking up %s as not recognized",
			    prefix, hostport);
			break;

#ifdef EAI_SYSTEM
		case EAI_SYSTEM:
			/*
			 * Assumed to be UN*X.
			 */
			pcapint_fmt_errmsg_for_errno(errbuf, errbuflen, errno,
			    "%sAn error occurred when looking up %s",
			    prefix, hostport);
			break;
#endif

#ifdef EAI_BADHINTS
		case EAI_BADHINTS:
			snprintf(errbuf, errbuflen,
			    "%sInvalid value for hints when looking up %s",
			    prefix, hostport);
			break;
#endif

#ifdef EAI_PROTOCOL
		case EAI_PROTOCOL:
			snprintf(errbuf, errbuflen,
			    "%sResolved protocol when looking up %s is unknown",
			    prefix, hostport);
			break;
#endif

#ifdef EAI_OVERFLOW
		case EAI_OVERFLOW:
			snprintf(errbuf, errbuflen,
			    "%sArgument buffer overflow when looking up %s",
			    prefix, hostport);
			break;
#endif

		default:
			snprintf(errbuf, errbuflen,
			    "%sgetaddrinfo() error %d when looking up %s",
			    prefix, err, hostport);
			break;
	}
}

/*
 * \brief Checks that the address, port and flags given are valid and it returns an 'addrinfo' structure.
 *
 * This function basically calls the getaddrinfo() calls, and it performs a set of sanity checks
 * to control that everything is fine (e.g. a TCP socket cannot have a mcast address, and such).
 * If an error occurs, it writes the error message into 'errbuf'.
 *
 * \param host: a pointer to a string identifying the host. It can be
 * a host name, a numeric literal address, or NULL or "" (useful
 * in case of a server socket which has to bind to all addresses).
 *
 * \param port: a pointer to a user-allocated buffer containing the network port to use.
 *
 * \param hints: an addrinfo variable (passed by reference) containing the flags needed to create the
 * addrinfo structure appropriately.
 *
 * \param addrinfo: it represents the true returning value. This is a pointer to an addrinfo variable
 * (passed by reference), which will be allocated by this function and returned back to the caller.
 * This variable will be used in the next sockets calls.
 *
 * \param errbuf: a pointer to an user-allocated buffer that will contain the complete
 * error message. This buffer has to be at least 'errbuflen' in length.
 * It can be NULL; in this case the error cannot be printed.
 *
 * \param errbuflen: length of the buffer that will contains the error. The error message cannot be
 * larger than 'errbuflen - 1' because the last char is reserved for the string terminator.
 *
 * \return a pointer to the first element in a list of addrinfo structures
 * if everything is fine, NULL if some errors occurred. The error message
 * is returned in the 'errbuf' variable.
 *
 * \warning The list of addrinfo structures returned has to be deleted by
 * the programmer by calling freeaddrinfo() when it is no longer needed.
 *
 * \warning This function requires the 'hints' variable as parameter. The semantic of this variable is the same
 * of the one of the corresponding variable used into the standard getaddrinfo() socket function. We suggest
 * the programmer to look at that function in order to set the 'hints' variable appropriately.
 */
struct addrinfo *sock_initaddress(const char *host, const char *port,
    struct addrinfo *hints, char *errbuf, int errbuflen)
{
	struct addrinfo *addrinfo;
	int retval;

	/*
	 * We allow both the host and port to be null, but getaddrinfo()
	 * is not guaranteed to do so; to handle that, if port is null,
	 * we provide "0" as the port number.
	 *
	 * This results in better error messages from get_gai_errstring(),
	 * as those messages won't talk about a problem with the port if
	 * no port was specified.
	 */
	retval = getaddrinfo(host, port == NULL ? "0" : port, hints, &addrinfo);
	if (retval != 0)
	{
		/*
		 * That call failed.
		 * Determine whether the problem is that the host is bad.
		 */
		if (errbuf)
		{
			if (host != NULL && port != NULL) {
				/*
				 * Try with just a host, to distinguish
				 * between "host is bad" and "port is
				 * bad".
				 */
				int try_retval;

				try_retval = getaddrinfo(host, NULL, hints,
				    &addrinfo);
				if (try_retval == 0) {
					/*
					 * Worked with just the host,
					 * so assume the problem is
					 * with the port.
					 *
					 * Free up the address info first.
					 */
					freeaddrinfo(addrinfo);
					get_gai_errstring(errbuf, errbuflen,
					    "", retval, NULL, port);
				} else {
					/*
					 * Didn't work with just the host,
					 * so assume the problem is
					 * with the host; we assume
					 * the original error indicates
					 * the underlying problem.
					 */
					get_gai_errstring(errbuf, errbuflen,
					    "", retval, host, NULL);
				}
			} else {
				/*
				 * Either the host or port was null, so
				 * there's nothing to determine; report
				 * the error from the original call.
				 */
				get_gai_errstring(errbuf, errbuflen, "",
				    retval, host, port);
			}
		}
		return NULL;
	}
	/*
	 * \warning SOCKET: I should check all the accept() in order to bind to all addresses in case
	 * addrinfo has more han one pointers
	 */

	/*
	 * This software only supports PF_INET and PF_INET6.
	 *
	 * XXX - should we just check that at least *one* address is
	 * either PF_INET or PF_INET6, and, when using the list,
	 * ignore all addresses that are neither?  (What, no IPX
	 * support? :-))
	 */
	if ((addrinfo->ai_family != PF_INET) &&
	    (addrinfo->ai_family != PF_INET6))
	{
		if (errbuf)
			snprintf(errbuf, errbuflen, "getaddrinfo(): socket type not supported");
		freeaddrinfo(addrinfo);
		return NULL;
	}

	/*
	 * You can't do multicast (or broadcast) TCP.
	 */
	if ((addrinfo->ai_socktype == SOCK_STREAM) &&
	    (sock_ismcastaddr(addrinfo->ai_addr) == 0))
	{
		if (errbuf)
			snprintf(errbuf, errbuflen, "getaddrinfo(): multicast addresses are not valid when using TCP streams");
		freeaddrinfo(addrinfo);
		return NULL;
	}

	return addrinfo;
}

/*
 * \brief It sends the amount of data contained into 'buffer' on the given socket.
 *
 * This function basically calls the send() socket function and it checks that all
 * the data specified in 'buffer' (of size 'size') will be sent. If an error occurs,
 * it writes the error message into 'errbuf'.
 * In case the socket buffer does not have enough space, it loops until all data
 * has been sent.
 *
 * \param socket: the connected socket currently opened.
 *
 * \param buffer: a char pointer to a user-allocated buffer in which data is contained.
 *
 * \param size: number of bytes that have to be sent.
 *
 * \param errbuf: a pointer to an user-allocated buffer that will contain the complete
 * error message. This buffer has to be at least 'errbuflen' in length.
 * It can be NULL; in this case the error cannot be printed.
 *
 * \param errbuflen: length of the buffer that will contains the error. The error message cannot be
 * larger than 'errbuflen - 1' because the last char is reserved for the string terminator.
 *
 * \return '0' if everything is fine, '-1' if an error other than
 * "connection reset" or "peer has closed the receive side" occurred,
 * '-2' if we got one of those errors.
 * For errors, an error message is returned in the 'errbuf' variable.
 */
int sock_send(PCAP_SOCKET sock, SSL *ssl _U_NOSSL_, const char *buffer,
    size_t size, char *errbuf, int errbuflen)
{
	int remaining;
	ssize_t nsent;

	if (size > INT_MAX)
	{
		if (errbuf)
		{
			snprintf(errbuf, errbuflen,
			    "Can't send more than %u bytes with sock_send",
			    INT_MAX);
		}
		return -1;
	}
	remaining = (int)size;

	do {
#ifdef HAVE_OPENSSL
		if (ssl) return ssl_send(ssl, buffer, remaining, errbuf, errbuflen);
#endif

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
		nsent = remaining;
#else
#ifdef MSG_NOSIGNAL
		/*
		 * Send with MSG_NOSIGNAL, so that we don't get SIGPIPE
		 * on errors on stream-oriented sockets when the other
		 * end breaks the connection.
		 * The EPIPE error is still returned.
		 */
		nsent = send(sock, buffer, remaining, MSG_NOSIGNAL);
#else
		nsent = send(sock, buffer, remaining, 0);
#endif
#endif //FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION

		if (nsent == -1)
		{
			/*
			 * If the client closed the connection out from
			 * under us, there's no need to log that as an
			 * error.
			 */
			int errcode;

#ifdef _WIN32
			errcode = GetLastError();
			if (errcode == WSAECONNRESET ||
			    errcode == WSAECONNABORTED)
			{
				/*
				 * WSAECONNABORTED appears to be the error
				 * returned in Winsock when you try to send
				 * on a connection where the peer has closed
				 * the receive side.
				 */
				return -2;
			}
			sock_fmterrmsg(errbuf, errbuflen, errcode,
			    "send() failed");
#else
			errcode = errno;
			if (errcode == ECONNRESET || errcode == EPIPE)
			{
				/*
				 * EPIPE is what's returned on UN*X when
				 * you try to send on a connection when
				 * the peer has closed the receive side.
				 */
				return -2;
			}
			sock_fmterrmsg(errbuf, errbuflen, errcode,
			    "send() failed");
#endif
			return -1;
		}

		remaining -= nsent;
		buffer += nsent;
	} while (remaining != 0);

	return 0;
}

/*
 * \brief It copies the amount of data contained in 'data' into 'outbuf'.
 * and it checks for buffer overflows.
 *
 * This function basically copies 'size' bytes of data contained in 'data'
 * into 'outbuf', starting at offset 'offset'. Before that, it checks that the
 * resulting buffer will not be larger	than 'totsize'. Finally, it updates
 * the 'offset' variable in order to point to the first empty location of the buffer.
 *
 * In case the function is called with 'checkonly' equal to 1, it does not copy
 * the data into the buffer. It only checks for buffer overflows and it updates the
 * 'offset' variable. This mode can be useful when the buffer already contains the
 * data (maybe because the producer writes directly into the target buffer), so
 * only the buffer overflow check has to be made.
 * In this case, both 'data' and 'outbuf' can be NULL values.
 *
 * This function is useful in case the userland application does not know immediately
 * all the data it has to write into the socket. This function provides a way to create
 * the "stream" step by step, appending the new data to the old one. Then, when all the
 * data has been bufferized, the application can call the sock_send() function.
 *
 * \param data: a void pointer to the data that has to be copied.
 *
 * \param size: number of bytes that have to be copied.
 *
 * \param outbuf: user-allocated buffer (of size 'totsize') into which data
 * has to be copied.
 *
 * \param offset: an index into 'outbuf' which keeps the location of its first
 * empty location.
 *
 * \param totsize: total size of the buffer into which data is being copied.
 *
 * \param checkonly: '1' if we do not want to copy data into the buffer and we
 * want just do a buffer overflow control, '0' if data has to be copied as well.
 *
 * \param errbuf: a pointer to an user-allocated buffer that will contain the complete
 * error message. This buffer has to be at least 'errbuflen' in length.
 * It can be NULL; in this case the error cannot be printed.
 *
 * \param errbuflen: length of the buffer that will contains the error. The error message cannot be
 * larger than 'errbuflen - 1' because the last char is reserved for the string terminator.
 *
 * \return '0' if everything is fine, '-1' if some errors occurred. The error message
 * is returned in the 'errbuf' variable. When the function returns, 'outbuf' will
 * have the new string appended, and 'offset' will keep the length of that buffer.
 * In case of 'checkonly == 1', data is not copied, but 'offset' is updated in any case.
 *
 * \warning This function assumes that the buffer in which data has to be stored is
 * large 'totbuf' bytes.
 *
 * \warning In case of 'checkonly', be carefully to call this function *before* copying
 * the data into the buffer. Otherwise, the control about the buffer overflow is useless.
 */
int sock_bufferize(const void *data, int size, char *outbuf, int *offset, int totsize, int checkonly, char *errbuf, int errbuflen)
{
	if ((*offset + size) > totsize)
	{
		if (errbuf)
			snprintf(errbuf, errbuflen, "Not enough space in the temporary send buffer.");
		return -1;
	}

	if (!checkonly)
		memcpy(outbuf + (*offset), data, size);

	(*offset) += size;

	return 0;
}

/*
 * \brief It waits on a connected socket and it manages to receive data.
 *
 * This function basically calls the recv() socket function and it checks that no
 * error occurred. If that happens, it writes the error message into 'errbuf'.
 *
 * This function changes its behavior according to the 'receiveall' flag: if we
 * want to receive exactly 'size' byte, it loops on the recv()	until all the requested
 * data is arrived. Otherwise, it returns the data currently available.
 *
 * In case the socket does not have enough data available, it cycles on the recv()
 * until the requested data (of size 'size') is arrived.
 * In this case, it blocks until the number of bytes read is equal to 'size'.
 *
 * \param sock: the connected socket currently opened.
 *
 * \param buffer: a char pointer to a user-allocated buffer in which data has to be stored
 *
 * \param size: size of the allocated buffer. WARNING: this indicates the number of bytes
 * that we are expecting to be read.
 *
 * \param flags:
 *
 *   SOCK_RECEIVALL_XXX:
 *
 *	if SOCK_RECEIVEALL_NO, return as soon as some data is ready
 *	if SOCK_RECEIVALL_YES, wait until 'size' data has been
 *	    received (in case the socket does not have enough data available).
 *
 *   SOCK_EOF_XXX:
 *
 *	if SOCK_EOF_ISNT_ERROR, if the first read returns 0, just return 0,
 *	    and return an error on any subsequent read that returns 0;
 *	if SOCK_EOF_IS_ERROR, if any read returns 0, return an error.
 *
 * \param errbuf: a pointer to an user-allocated buffer that will contain the complete
 * error message. This buffer has to be at least 'errbuflen' in length.
 * It can be NULL; in this case the error cannot be printed.
 *
 * \param errbuflen: length of the buffer that will contains the error. The error message cannot be
 * larger than 'errbuflen - 1' because the last char is reserved for the string terminator.
 *
 * \return the number of bytes read if everything is fine, '-1' if some errors occurred.
 * The error message is returned in the 'errbuf' variable.
 */

int sock_recv(PCAP_SOCKET sock, SSL *ssl _U_NOSSL_, void *buffer, size_t size,
    int flags, char *errbuf, int errbuflen)
{
	int recv_flags = 0;
	char *bufp = buffer;
	int remaining;
	ssize_t nread;

	if (size == 0)
	{
		return 0;
	}
	if (size > INT_MAX)
	{
		if (errbuf)
		{
			snprintf(errbuf, errbuflen,
			    "Can't read more than %u bytes with sock_recv",
			    INT_MAX);
		}
		return -1;
	}

	if (flags & SOCK_MSG_PEEK)
		recv_flags |= MSG_PEEK;

	bufp = (char *) buffer;
	remaining = (int) size;

	/*
	 * We don't use MSG_WAITALL because it's not supported in
	 * Win32.
	 */
	for (;;) {
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
		nread = fuzz_recv(bufp, remaining);
#elif defined(HAVE_OPENSSL)
		if (ssl)
		{
			/*
			 * XXX - what about MSG_PEEK?
			 */
			nread = ssl_recv(ssl, bufp, remaining, errbuf, errbuflen);
			if (nread == -2) return -1;
		}
		else
			nread = recv(sock, bufp, remaining, recv_flags);
#else
		nread = recv(sock, bufp, remaining, recv_flags);
#endif

		if (nread == -1)
		{
#ifndef _WIN32
			if (errno == EINTR)
				return -3;
#endif
			sock_geterrmsg(errbuf, errbuflen, "recv() failed");
			return -1;
		}

		if (nread == 0)
		{
			if ((flags & SOCK_EOF_IS_ERROR) ||
			    (remaining != (int) size))
			{
				/*
				 * Either we've already read some data,
				 * or we're always supposed to return
				 * an error on EOF.
				 */
				if (errbuf)
				{
					snprintf(errbuf, errbuflen,
					    "The other host terminated the connection.");
				}
				return -1;
			}
			else
				return 0;
		}

		/*
		 * Do we want to read the amount requested, or just return
		 * what we got?
		 */
		if (!(flags & SOCK_RECEIVEALL_YES))
		{
			/*
			 * Just return what we got.
			 */
			return (int) nread;
		}

		bufp += nread;
		remaining -= nread;

		if (remaining == 0)
			return (int) size;
	}
}

/*
 * Receives a datagram from a socket.
 *
 * Returns the size of the datagram on success or -1 on error.
 */
int sock_recv_dgram(PCAP_SOCKET sock, SSL *ssl _U_NOSSL_, void *buffer,
    size_t size, char *errbuf, int errbuflen)
{
	ssize_t nread;
#ifndef _WIN32
	struct msghdr message;
	struct iovec iov;
#endif

	if (size == 0)
	{
		return 0;
	}
	if (size > INT_MAX)
	{
		if (errbuf)
		{
			snprintf(errbuf, errbuflen,
			    "Can't read more than %u bytes with sock_recv_dgram",
			    INT_MAX);
		}
		return -1;
	}

#ifdef HAVE_OPENSSL
	// TODO: DTLS
	if (ssl)
	{
		snprintf(errbuf, errbuflen, "DTLS not implemented yet");
		return -1;
	}
#endif

	/*
	 * This should be a datagram socket, so we should get the
	 * entire datagram in one recv() or recvmsg() call, and
	 * don't need to loop.
	 */
#ifdef _WIN32
	nread = recv(sock, buffer, (int)size, 0);
	if (nread == SOCKET_ERROR)
	{
		/*
		 * To quote the MSDN documentation for recv(),
		 * "If the datagram or message is larger than
		 * the buffer specified, the buffer is filled
		 * with the first part of the datagram, and recv
		 * generates the error WSAEMSGSIZE. For unreliable
		 * protocols (for example, UDP) the excess data is
		 * lost..."
		 *
		 * So if the message is bigger than the buffer
		 * supplied to us, the excess data is discarded,
		 * and we'll report an error.
		 */
		sock_fmterrmsg(errbuf, errbuflen, sock_geterrcode(),
		    "recv() failed");
		return -1;
	}
#else /* _WIN32 */
	/*
	 * The Single UNIX Specification says that a recv() on
	 * a socket for a message-oriented protocol will discard
	 * the excess data.  It does *not* indicate that the
	 * receive will fail with, for example, EMSGSIZE.
	 *
	 * Therefore, we use recvmsg(), which appears to be
	 * the only way to get a "message truncated" indication
	 * when receiving a message for a message-oriented
	 * protocol.
	 */
	message.msg_name = NULL;	/* we don't care who it's from */
	message.msg_namelen = 0;
	iov.iov_base = buffer;
	iov.iov_len = size;
	message.msg_iov = &iov;
	message.msg_iovlen = 1;
#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
	message.msg_control = NULL;	/* we don't care about control information */
	message.msg_controllen = 0;
#endif
#ifdef HAVE_STRUCT_MSGHDR_MSG_FLAGS
	message.msg_flags = 0;
#endif
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
	nread = fuzz_recv(buffer, size);
#else
	nread = recvmsg(sock, &message, 0);
#endif
	if (nread == -1)
	{
		if (errno == EINTR)
			return -3;
		sock_geterrmsg(errbuf, errbuflen, "recv() failed");
		return -1;
	}
#ifdef HAVE_STRUCT_MSGHDR_MSG_FLAGS
	/*
	 * XXX - Solaris supports this, but only if you ask for the
	 * X/Open version of recvmsg(); should we use that, or will
	 * that cause other problems?
	 */
	if (message.msg_flags & MSG_TRUNC)
	{
		/*
		 * Message was bigger than the specified buffer size.
		 *
		 * Report this as an error, as the Microsoft documentation
		 * implies we'd do in a similar case on Windows.
		 */
		snprintf(errbuf, errbuflen, "recv(): Message too long");
		return -1;
	}
#endif /* HAVE_STRUCT_MSGHDR_MSG_FLAGS */
#endif /* _WIN32 */

	/*
	 * The size we're reading fits in an int, so the return value
	 * will fit in an int.
	 */
	return (int)nread;
}

/*
 * \brief It discards N bytes that are currently waiting to be read on the current socket.
 *
 * This function is useful in case we receive a message we cannot understand (e.g.
 * wrong version number when receiving a network packet), so that we have to discard all
 * data before reading a new message.
 *
 * This function will read 'size' bytes from the socket and discard them.
 * It defines an internal buffer in which data will be copied; however, in case
 * this buffer is not large enough, it will cycle in order to read everything as well.
 *
 * \param sock: the connected socket currently opened.
 *
 * \param size: number of bytes that have to be discarded.
 *
 * \param errbuf: a pointer to an user-allocated buffer that will contain the complete
 * error message. This buffer has to be at least 'errbuflen' in length.
 * It can be NULL; in this case the error cannot be printed.
 *
 * \param errbuflen: length of the buffer that will contains the error. The error message cannot be
 * larger than 'errbuflen - 1' because the last char is reserved for the string terminator.
 *
 * \return '0' if everything is fine, '-1' if some errors occurred.
 * The error message is returned in the 'errbuf' variable.
 */
int sock_discard(PCAP_SOCKET sock, SSL *ssl, int size, char *errbuf,
    int errbuflen)
{
#define TEMP_BUF_SIZE 32768

	char buffer[TEMP_BUF_SIZE];		/* network buffer, to be used when the message is discarded */

	/*
	 * A static allocation avoids the need of a 'malloc()' each time we want to discard a message
	 * Our feeling is that a buffer if 32KB is enough for most of the application;
	 * in case this is not enough, the "while" loop discards the message by calling the
	 * sockrecv() several times.
	 * We do not want to create a bigger variable because this causes the program to exit on
	 * some platforms (e.g. BSD)
	 */
	while (size > TEMP_BUF_SIZE)
	{
		if (sock_recv(sock, ssl, buffer, TEMP_BUF_SIZE, SOCK_RECEIVEALL_YES, errbuf, errbuflen) == -1)
			return -1;

		size -= TEMP_BUF_SIZE;
	}

	/*
	 * If there is still data to be discarded
	 * In this case, the data can fit into the temporary buffer
	 */
	if (size)
	{
		if (sock_recv(sock, ssl, buffer, size, SOCK_RECEIVEALL_YES, errbuf, errbuflen) == -1)
			return -1;
	}

	return 0;
}

/*
 * \brief Checks that one host (identified by the sockaddr_storage structure) belongs to an 'allowed list'.
 *
 * This function is useful after an accept() call in order to check if the connecting
 * host is allowed to connect to me. To do that, we have a buffer that keeps the list of the
 * allowed host; this function checks the sockaddr_storage structure of the connecting host
 * against this host list, and it returns '0' is the host is included in this list.
 *
 * \param hostlist: pointer to a string that contains the list of the allowed host.
 *
 * \param sep: a string that keeps the separators used between the hosts (for example the
 * space character) in the host list.
 *
 * \param from: a sockaddr_storage structure, as it is returned by the accept() call.
 *
 * \param errbuf: a pointer to an user-allocated buffer that will contain the complete
 * error message. This buffer has to be at least 'errbuflen' in length.
 * It can be NULL; in this case the error cannot be printed.
 *
 * \param errbuflen: length of the buffer that will contains the error. The error message cannot be
 * larger than 'errbuflen - 1' because the last char is reserved for the string terminator.
 *
 * \return It returns:
 * - '1' if the host list is empty
 * - '0' if the host belongs to the host list (and therefore it is allowed to connect)
 * - '-1' in case the host does not belong to the host list (and therefore it is not allowed to connect
 * - '-2' in case or error. The error message is returned in the 'errbuf' variable.
 */
int sock_check_hostlist(const char *hostlist, const char *sep, struct sockaddr_storage *from, char *errbuf, int errbuflen)
{
	/* checks if the connecting host is among the ones allowed */
	if ((hostlist) && (hostlist[0]))
	{
		char *token;					/* temp, needed to separate items into the hostlist */
		struct addrinfo *addrinfo, *ai_next;
		char *temphostlist;
		char *lasts;
		int getaddrinfo_failed = 0;

		/*
		 * The problem is that strtok modifies the original variable by putting '0' at the end of each token
		 * So, we have to create a new temporary string in which the original content is kept
		 */
		temphostlist = strdup(hostlist);
		if (temphostlist == NULL)
		{
			sock_geterrmsg(errbuf, errbuflen,
			    "sock_check_hostlist(), malloc() failed");
			return -2;
		}

		token = pcapint_strtok_r(temphostlist, sep, &lasts);

		/* it avoids a warning in the compilation ('addrinfo used but not initialized') */
		addrinfo = NULL;

		while (token != NULL)
		{
			struct addrinfo hints;
			int retval;

			addrinfo = NULL;
			memset(&hints, 0, sizeof(struct addrinfo));
			hints.ai_family = PF_UNSPEC;
			hints.ai_socktype = SOCK_STREAM;

			retval = getaddrinfo(token, NULL, &hints, &addrinfo);
			if (retval != 0)
			{
				if (errbuf)
					get_gai_errstring(errbuf, errbuflen,
					    "Allowed host list error: ",
					    retval, token, NULL);

				/*
				 * Note that at least one call to getaddrinfo()
				 * failed.
				 */
				getaddrinfo_failed = 1;

				/* Get next token */
				token = pcapint_strtok_r(NULL, sep, &lasts);
				continue;
			}

			/* ai_next is required to preserve the content of addrinfo, in order to deallocate it properly */
			ai_next = addrinfo;
			while (ai_next)
			{
				if (sock_cmpaddr(from, (struct sockaddr_storage *) ai_next->ai_addr) == 0)
				{
					free(temphostlist);
					freeaddrinfo(addrinfo);
					return 0;
				}

				/*
				 * If we are here, it means that the current address does not matches
				 * Let's try with the next one in the header chain
				 */
				ai_next = ai_next->ai_next;
			}

			freeaddrinfo(addrinfo);
			addrinfo = NULL;

			/* Get next token */
			token = pcapint_strtok_r(NULL, sep, &lasts);
		}

		if (addrinfo)
		{
			freeaddrinfo(addrinfo);
			addrinfo = NULL;
		}

		free(temphostlist);

		if (getaddrinfo_failed) {
			/*
			 * At least one getaddrinfo() call failed;
			 * treat that as an error, so rpcapd knows
			 * that it should log it locally as well
			 * as telling the client about it.
			 */
			return -2;
		} else {
			/*
			 * All getaddrinfo() calls succeeded, but
			 * the host wasn't in the list.
			 */
			if (errbuf)
				snprintf(errbuf, errbuflen, "The host is not in the allowed host list. Connection refused.");
			return -1;
		}
	}

	/* No hostlist, so we have to return 'empty list' */
	return 1;
}

/*
 * \brief Compares two addresses contained into two sockaddr_storage structures.
 *
 * This function is useful to compare two addresses, given their internal representation,
 * i.e. an sockaddr_storage structure.
 *
 * The two structures do not need to be sockaddr_storage; you can have both 'sockaddr_in' and
 * sockaddr_in6, properly casted in order to be compliant to the function interface.
 *
 * This function will return '0' if the two addresses matches, '-1' if not.
 *
 * \param first: a sockaddr_storage structure, (for example the one that is returned by an
 * accept() call), containing the first address to compare.
 *
 * \param second: a sockaddr_storage structure containing the second address to compare.
 *
 * \return '0' if the addresses are equal, '-1' if they are different.
 */
int sock_cmpaddr(struct sockaddr_storage *first, struct sockaddr_storage *second)
{
	if (first->ss_family == second->ss_family)
	{
		if (first->ss_family == AF_INET)
		{
			if (memcmp(&(((struct sockaddr_in *) first)->sin_addr),
				&(((struct sockaddr_in *) second)->sin_addr),
				sizeof(struct in_addr)) == 0)
				return 0;
		}
		else /* address family is AF_INET6 */
		{
			if (memcmp(&(((struct sockaddr_in6 *) first)->sin6_addr),
				&(((struct sockaddr_in6 *) second)->sin6_addr),
				sizeof(struct in6_addr)) == 0)
				return 0;
		}
	}

	return -1;
}

/*
 * \brief It gets the address/port the system picked for this socket (on connected sockets).
 *
 * It is used to return the address and port the server picked for our socket on the local machine.
 * It works only on:
 * - connected sockets
 * - server sockets
 *
 * On unconnected client sockets it does not work because the system dynamically chooses a port
 * only when the socket calls a send() call.
 *
 * \param sock: the connected socket currently opened.
 *
 * \param address: it contains the address that will be returned by the function. This buffer
 * must be properly allocated by the user. The address can be either literal or numeric depending
 * on the value of 'Flags'.
 *
 * \param addrlen: the length of the 'address' buffer.
 *
 * \param port: it contains the port that will be returned by the function. This buffer
 * must be properly allocated by the user.
 *
 * \param portlen: the length of the 'port' buffer.
 *
 * \param flags: a set of flags (the ones defined into the getnameinfo() standard socket function)
 * that determine if the resulting address must be in numeric / literal form, and so on.
 *
 * \param errbuf: a pointer to an user-allocated buffer that will contain the complete
 * error message. This buffer has to be at least 'errbuflen' in length.
 * It can be NULL; in this case the error cannot be printed.
 *
 * \param errbuflen: length of the buffer that will contains the error. The error message cannot be
 * larger than 'errbuflen - 1' because the last char is reserved for the string terminator.
 *
 * \return It returns '-1' if this function succeeds, '0' otherwise.
 * The address and port corresponding are returned back in the buffers 'address' and 'port'.
 * In any case, the returned strings are '0' terminated.
 *
 * \warning If the socket is using a connectionless protocol, the address may not be available
 * until I/O occurs on the socket.
 */
int sock_getmyinfo(PCAP_SOCKET sock, char *address, int addrlen, char *port,
    int portlen, int flags, char *errbuf, int errbuflen)
{
	struct sockaddr_storage mysockaddr;
	socklen_t sockaddrlen;


	sockaddrlen = sizeof(struct sockaddr_storage);

	if (getsockname(sock, (struct sockaddr *) &mysockaddr, &sockaddrlen) == -1)
	{
		sock_geterrmsg(errbuf, errbuflen, "getsockname() failed");
		return 0;
	}

	/* Returns the numeric address of the host that triggered the error */
	return sock_getascii_addrport(&mysockaddr, address, addrlen, port, portlen, flags, errbuf, errbuflen);
}

/*
 * \brief It retrieves two strings containing the address and the port of a given 'sockaddr' variable.
 *
 * This function is basically an extended version of the inet_ntop(), which does not exist in
 * Winsock because the same result can be obtained by using the getnameinfo().
 * However, differently from inet_ntop(), this function is able to return also literal names
 * (e.g. 'localhost') dependently from the 'Flags' parameter.
 *
 * The function accepts a sockaddr_storage variable (which can be returned by several functions
 * like bind(), connect(), accept(), and more) and it transforms its content into a 'human'
 * form. So, for instance, it is able to translate an hex address (stored in binary form) into
 * a standard IPv6 address like "::1".
 *
 * The behavior of this function depends on the parameters we have in the 'Flags' variable, which
 * are the ones allowed in the standard getnameinfo() socket function.
 *
 * \param sockaddr: a 'sockaddr_in' or 'sockaddr_in6' structure containing the address that
 * need to be translated from network form into the presentation form. This structure must be
 * zero-ed prior using it, and the address family field must be filled with the proper value.
 * The user must cast any 'sockaddr_in' or 'sockaddr_in6' structures to 'sockaddr_storage' before
 * calling this function.
 *
 * \param address: it contains the address that will be returned by the function. This buffer
 * must be properly allocated by the user. The address can be either literal or numeric depending
 * on the value of 'Flags'.
 *
 * \param addrlen: the length of the 'address' buffer.
 *
 * \param port: it contains the port that will be returned by the function. This buffer
 * must be properly allocated by the user.
 *
 * \param portlen: the length of the 'port' buffer.
 *
 * \param flags: a set of flags (the ones defined into the getnameinfo() standard socket function)
 * that determine if the resulting address must be in numeric / literal form, and so on.
 *
 * \param errbuf: a pointer to an user-allocated buffer that will contain the complete
 * error message. This buffer has to be at least 'errbuflen' in length.
 * It can be NULL; in this case the error cannot be printed.
 *
 * \param errbuflen: length of the buffer that will contains the error. The error message cannot be
 * larger than 'errbuflen - 1' because the last char is reserved for the string terminator.
 *
 * \return It returns '-1' if this function succeeds, '0' otherwise.
 * The address and port corresponding to the given SockAddr are returned back in the buffers 'address'
 * and 'port'.
 * In any case, the returned strings are '0' terminated.
 */
int sock_getascii_addrport(const struct sockaddr_storage *sockaddr, char *address, int addrlen, char *port, int portlen, int flags, char *errbuf, size_t errbuflen)
{
	socklen_t sockaddrlen;
	int retval;					/* Variable that keeps the return value; */

	retval = -1;

#ifdef _WIN32
	if (sockaddr->ss_family == AF_INET)
		sockaddrlen = sizeof(struct sockaddr_in);
	else
		sockaddrlen = sizeof(struct sockaddr_in6);
#else
	sockaddrlen = sizeof(struct sockaddr_storage);
#endif

	if ((flags & NI_NUMERICHOST) == 0)	/* Check that we want literal names */
	{
		if ((sockaddr->ss_family == AF_INET6) &&
			(memcmp(&((struct sockaddr_in6 *) sockaddr)->sin6_addr, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", sizeof(struct in6_addr)) == 0))
		{
			if (address)
				pcapint_strlcpy(address, SOCKET_NAME_NULL_DAD, addrlen);
			return retval;
		}
	}

	if (getnameinfo((struct sockaddr *) sockaddr, sockaddrlen, address, addrlen, port, portlen, flags) != 0)
	{
		/* If the user wants to receive an error message */
		if (errbuf)
		{
			sock_geterrmsg(errbuf, errbuflen,
			    "getnameinfo() failed");
			errbuf[errbuflen - 1] = 0;
		}

		if (address)
		{
			pcapint_strlcpy(address, SOCKET_NO_NAME_AVAILABLE, addrlen);
			address[addrlen - 1] = 0;
		}

		if (port)
		{
			pcapint_strlcpy(port, SOCKET_NO_PORT_AVAILABLE, portlen);
			port[portlen - 1] = 0;
		}

		retval = 0;
	}

	return retval;
}

/*
 * \brief It translates an address from the 'presentation' form into the 'network' form.
 *
 * This function basically replaces inet_pton(), which does not exist in Winsock because
 * the same result can be obtained by using the getaddrinfo().
 * An additional advantage is that 'Address' can be both a numeric address (e.g. '127.0.0.1',
 * like in inet_pton() ) and a literal name (e.g. 'localhost').
 *
 * This function does the reverse job of sock_getascii_addrport().
 *
 * \param address: a zero-terminated string which contains the name you have to
 * translate. The name can be either literal (e.g. 'localhost') or numeric (e.g. '::1').
 *
 * \param sockaddr: a user-allocated sockaddr_storage structure which will contains the
 * 'network' form of the requested address.
 *
 * \param addr_family: a constant which can assume the following values:
 * - 'AF_INET' if we want to ping an IPv4 host
 * - 'AF_INET6' if we want to ping an IPv6 host
 * - 'AF_UNSPEC' if we do not have preferences about the protocol used to ping the host
 *
 * \param errbuf: a pointer to an user-allocated buffer that will contain the complete
 * error message. This buffer has to be at least 'errbuflen' in length.
 * It can be NULL; in this case the error cannot be printed.
 *
 * \param errbuflen: length of the buffer that will contains the error. The error message cannot be
 * larger than 'errbuflen - 1' because the last char is reserved for the string terminator.
 *
 * \return '-1' if the translation succeeded, '-2' if there was some non critical error, '0'
 * otherwise. In case it fails, the content of the SockAddr variable remains unchanged.
 * A 'non critical error' can occur in case the 'Address' is a literal name, which can be mapped
 * to several network addresses (e.g. 'foo.bar.com' => '10.2.2.2' and '10.2.2.3'). In this case
 * the content of the SockAddr parameter will be the address corresponding to the first mapping.
 *
 * \warning The sockaddr_storage structure MUST be allocated by the user.
 */
int sock_present2network(const char *address, struct sockaddr_storage *sockaddr, int addr_family, char *errbuf, int errbuflen)
{
	struct addrinfo *addrinfo;
	struct addrinfo hints;

	memset(&hints, 0, sizeof(hints));

	hints.ai_family = addr_family;

	addrinfo = sock_initaddress(address, "22222" /* fake port */, &hints,
	    errbuf, errbuflen);
	if (addrinfo == NULL)
		return 0;

	if (addrinfo->ai_family == PF_INET)
		memcpy(sockaddr, addrinfo->ai_addr, sizeof(struct sockaddr_in));
	else
		memcpy(sockaddr, addrinfo->ai_addr, sizeof(struct sockaddr_in6));

	if (addrinfo->ai_next != NULL)
	{
		freeaddrinfo(addrinfo);

		if (errbuf)
			snprintf(errbuf, errbuflen, "More than one socket requested; using the first one returned");
		return -2;
	}

	freeaddrinfo(addrinfo);
	return -1;
}
