/*
 * Copyright (c) 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 1998
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Name to id translation routines used by the scanner.
 * These functions are not time critical.
 */

#include <config.h>

#ifdef DECNETLIB
#include <sys/types.h>
#include <netdnet/dnetdb.h>
#endif

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else /* _WIN32 */
  #include <sys/param.h>
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <sys/time.h>

  #include <netinet/in.h>

  #ifdef HAVE_ETHER_HOSTTON
    #if defined(NET_ETHERNET_H_DECLARES_ETHER_HOSTTON)
      /*
       * OK, just include <net/ethernet.h>.
       */
      #include <net/ethernet.h>
    #elif defined(NETINET_ETHER_H_DECLARES_ETHER_HOSTTON)
      /*
       * OK, just include <netinet/ether.h>
       */
      #include <netinet/ether.h>
    #elif defined(SYS_ETHERNET_H_DECLARES_ETHER_HOSTTON)
      /*
       * OK, just include <sys/ethernet.h>
       */
      #include <sys/ethernet.h>
    #elif defined(ARPA_INET_H_DECLARES_ETHER_HOSTTON)
      /*
       * OK, just include <arpa/inet.h>
       */
      #include <arpa/inet.h>
    #elif defined(NETINET_IF_ETHER_H_DECLARES_ETHER_HOSTTON)
      /*
       * OK, include <netinet/if_ether.h>, after all the other stuff we
       * need to include or define for its benefit.
       */
      #define NEED_NETINET_IF_ETHER_H
    #else
      /*
       * We'll have to declare it ourselves.
       * If <netinet/if_ether.h> defines struct ether_addr, include
       * it.  Otherwise, define it ourselves.
       */
      #ifdef HAVE_STRUCT_ETHER_ADDR
        #define NEED_NETINET_IF_ETHER_H
      #else /* HAVE_STRUCT_ETHER_ADDR */
	struct ether_addr {
		unsigned char ether_addr_octet[6];
	};
      #endif /* HAVE_STRUCT_ETHER_ADDR */
    #endif /* what declares ether_hostton() */

    #ifdef NEED_NETINET_IF_ETHER_H
      #include <net/if.h>	/* Needed on some platforms */
      #include <netinet/in.h>	/* Needed on some platforms */
      #include <netinet/if_ether.h>
    #endif /* NEED_NETINET_IF_ETHER_H */

    #ifndef HAVE_DECL_ETHER_HOSTTON
      /*
       * No header declares it, so declare it ourselves.
       */
      extern int ether_hostton(const char *, struct ether_addr *);
    #endif /* !defined(HAVE_DECL_ETHER_HOSTTON) */
  #endif /* HAVE_ETHER_HOSTTON */

  #include <arpa/inet.h>
  #include <netdb.h>
#endif /* _WIN32 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "pcap-int.h"

#include "diag-control.h"

#include "gencode.h"
#include <pcap/namedb.h>
#include "nametoaddr.h"

#include "thread-local.h"

#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

#ifndef NTOHL
#define NTOHL(x) (x) = ntohl(x)
#define NTOHS(x) (x) = ntohs(x)
#endif

/*
 *  Convert host name to internet address.
 *  Return 0 upon failure.
 *  XXX - not thread-safe; don't use it inside libpcap.
 */
bpf_u_int32 **
pcap_nametoaddr(const char *name)
{
#ifndef h_addr
	static bpf_u_int32 *hlist[2];
#endif
	bpf_u_int32 **p;
	struct hostent *hp;

	/*
	 * gethostbyname() is deprecated on Windows, perhaps because
	 * it's not thread-safe, or because it doesn't support IPv6,
	 * or both.
	 *
	 * We deprecate pcap_nametoaddr() on all platforms because
	 * it's not thread-safe; we supply it for backwards compatibility,
	 * so suppress the deprecation warning.  We could, I guess,
	 * use getaddrinfo() and construct the array ourselves, but
	 * that's probably not worth the effort, as that wouldn't make
	 * this thread-safe - we can't change the API to require that
	 * our caller free the address array, so we still have to reuse
	 * a local array.
	 */
DIAG_OFF_DEPRECATION
	if ((hp = gethostbyname(name)) != NULL) {
DIAG_ON_DEPRECATION
#ifndef h_addr
		hlist[0] = (bpf_u_int32 *)hp->h_addr;
		NTOHL(hp->h_addr);
		return hlist;
#else
		for (p = (bpf_u_int32 **)hp->h_addr_list; *p; ++p)
			NTOHL(**p);
		return (bpf_u_int32 **)hp->h_addr_list;
#endif
	}
	else
		return 0;
}

struct addrinfo *
pcap_nametoaddrinfo(const char *name)
{
	struct addrinfo hints, *res;
	int error;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;	/*not really*/
	hints.ai_protocol = IPPROTO_TCP;	/*not really*/
	error = getaddrinfo(name, NULL, &hints, &res);
	if (error)
		return NULL;
	else
		return res;
}

/*
 *  Convert net name to internet address.
 *  Return 0 upon failure.
 *  XXX - not guaranteed to be thread-safe!  See below for platforms
 *  on which it is thread-safe and on which it isn't.
 */
#if defined(_WIN32) || defined(__CYGWIN__)
bpf_u_int32
pcap_nametonetaddr(const char *name _U_)
{
	/*
	 * There's no "getnetbyname()" on Windows.
	 *
	 * XXX - I guess we could use the BSD code to read
	 * C:\Windows\System32\drivers\etc/networks, assuming
	 * that's its home on all the versions of Windows
	 * we use, but that file probably just has the loopback
	 * network on 127/24 on 99 44/100% of Windows machines.
	 *
	 * (Heck, these days it probably just has that on 99 44/100%
	 * of *UN*X* machines.)
	 */
	return 0;
}
#else /* _WIN32 */
bpf_u_int32
pcap_nametonetaddr(const char *name)
{
	/*
	 * UN*X.
	 */
	struct netent *np;
  #if defined(HAVE_LINUX_GETNETBYNAME_R)
	/*
	 * We have Linux's reentrant getnetbyname_r().
	 */
	struct netent result_buf;
	char buf[1024];	/* arbitrary size */
	int h_errnoval;
	int err;

	/*
	 * Apparently, the man page at
	 *
	 *    http://man7.org/linux/man-pages/man3/getnetbyname_r.3.html
	 *
	 * lies when it says
	 *
	 *    If the function call successfully obtains a network record,
	 *    then *result is set pointing to result_buf; otherwise, *result
	 *    is set to NULL.
	 *
	 * and, in fact, at least in some versions of GNU libc, it does
	 * *not* always get set if getnetbyname_r() succeeds.
	 */
	np = NULL;
	err = getnetbyname_r(name, &result_buf, buf, sizeof buf, &np,
	    &h_errnoval);
	if (err != 0) {
		/*
		 * XXX - dynamically allocate the buffer, and make it
		 * bigger if we get ERANGE back?
		 */
		return 0;
	}
  #elif defined(HAVE_SOLARIS_IRIX_GETNETBYNAME_R)
	/*
	 * We have Solaris's and IRIX's reentrant getnetbyname_r().
	 */
	struct netent result_buf;
	char buf[1024];	/* arbitrary size */

	np = getnetbyname_r(name, &result_buf, buf, (int)sizeof buf);
  #elif defined(HAVE_AIX_GETNETBYNAME_R)
	/*
	 * We have AIX's reentrant getnetbyname_r().
	 */
	struct netent result_buf;
	struct netent_data net_data;

	if (getnetbyname_r(name, &result_buf, &net_data) == -1)
		np = NULL;
	else
		np = &result_buf;
  #else
	/*
	 * We don't have any getnetbyname_r(); either we have a
	 * getnetbyname() that uses thread-specific data, in which
	 * case we're thread-safe (sufficiently recent FreeBSD,
	 * sufficiently recent Darwin-based OS, sufficiently recent
	 * HP-UX, sufficiently recent Tru64 UNIX), or we have the
	 * traditional getnetbyname() (everything else, including
	 * current NetBSD and OpenBSD), in which case we're not
	 * thread-safe.
	 */
	np = getnetbyname(name);
  #endif
	if (np != NULL)
		return np->n_net;
	else
		return 0;
}
#endif /* _WIN32 */

/*
 * Convert a port name to its port and protocol numbers.
 * We assume only TCP or UDP.
 * Return 0 upon failure.
 */
int
pcap_nametoport(const char *name, int *port, int *proto)
{
	struct addrinfo hints, *res, *ai;
	int error;
	struct sockaddr_in *in4;
#ifdef INET6
	struct sockaddr_in6 *in6;
#endif
	int tcp_port = -1;
	int udp_port = -1;

	/*
	 * We check for both TCP and UDP in case there are
	 * ambiguous entries.
	 */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	error = getaddrinfo(NULL, name, &hints, &res);
	if (error != 0) {
		if (error != EAI_NONAME &&
		    error != EAI_SERVICE) {
			/*
			 * This is a real error, not just "there's
			 * no such service name".
			 * XXX - this doesn't return an error string.
			 */
			return 0;
		}
	} else {
		/*
		 * OK, we found it.  Did it find anything?
		 */
		for (ai = res; ai != NULL; ai = ai->ai_next) {
			/*
			 * Does it have an address?
			 */
			if (ai->ai_addr != NULL) {
				/*
				 * Yes.  Get a port number; we're done.
				 */
				if (ai->ai_addr->sa_family == AF_INET) {
					in4 = (struct sockaddr_in *)ai->ai_addr;
					tcp_port = ntohs(in4->sin_port);
					break;
				}
#ifdef INET6
				if (ai->ai_addr->sa_family == AF_INET6) {
					in6 = (struct sockaddr_in6 *)ai->ai_addr;
					tcp_port = ntohs(in6->sin6_port);
					break;
				}
#endif
			}
		}
		freeaddrinfo(res);
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	error = getaddrinfo(NULL, name, &hints, &res);
	if (error != 0) {
		if (error != EAI_NONAME &&
		    error != EAI_SERVICE) {
			/*
			 * This is a real error, not just "there's
			 * no such service name".
			 * XXX - this doesn't return an error string.
			 */
			return 0;
		}
	} else {
		/*
		 * OK, we found it.  Did it find anything?
		 */
		for (ai = res; ai != NULL; ai = ai->ai_next) {
			/*
			 * Does it have an address?
			 */
			if (ai->ai_addr != NULL) {
				/*
				 * Yes.  Get a port number; we're done.
				 */
				if (ai->ai_addr->sa_family == AF_INET) {
					in4 = (struct sockaddr_in *)ai->ai_addr;
					udp_port = ntohs(in4->sin_port);
					break;
				}
#ifdef INET6
				if (ai->ai_addr->sa_family == AF_INET6) {
					in6 = (struct sockaddr_in6 *)ai->ai_addr;
					udp_port = ntohs(in6->sin6_port);
					break;
				}
#endif
			}
		}
		freeaddrinfo(res);
	}

	/*
	 * We need to check /etc/services for ambiguous entries.
	 * If we find an ambiguous entry, and it has the
	 * same port number, change the proto to PROTO_UNDEF
	 * so both TCP and UDP will be checked.
	 */
	if (tcp_port >= 0) {
		*port = tcp_port;
		*proto = IPPROTO_TCP;
		if (udp_port >= 0) {
			if (udp_port == tcp_port)
				*proto = PROTO_UNDEF;
#ifdef notdef
			else
				/* Can't handle ambiguous names that refer
				   to different port numbers. */
				warning("ambiguous port %s in /etc/services",
					name);
#endif
		}
		return 1;
	}
	if (udp_port >= 0) {
		*port = udp_port;
		*proto = IPPROTO_UDP;
		return 1;
	}
#if defined(ultrix) || defined(__osf__)
	/* Special hack in case NFS isn't in /etc/services */
	if (strcmp(name, "nfs") == 0) {
		*port = 2049;
		*proto = PROTO_UNDEF;
		return 1;
	}
#endif
	return 0;
}

/*
 * Convert a string in the form PPP-PPP, where correspond to ports, to
 * a starting and ending port in a port range.
 * Return 0 on failure.
 */
int
pcap_nametoportrange(const char *name, int *port1, int *port2, int *proto)
{
	char *off, *cpy;
	int save_proto;

	if ((cpy = strdup(name)) == NULL)
		return 0;

	if ((off = strchr(cpy, '-')) == NULL) {
		free(cpy);
		return 0;
	}

	*off = '\0';

	if (pcap_nametoport(cpy, port1, proto) == 0) {
		free(cpy);
		return 0;
	}
	save_proto = *proto;

	if (pcap_nametoport(off + 1, port2, proto) == 0) {
		free(cpy);
		return 0;
	}
	free(cpy);

	if (*proto != save_proto)
		*proto = PROTO_UNDEF;

	return 1;
}

/*
 * XXX - not guaranteed to be thread-safe!  See below for platforms
 * on which it is thread-safe and on which it isn't.
 */
int
pcap_nametoproto(const char *str)
{
	struct protoent *p;
  #if defined(HAVE_LINUX_GETNETBYNAME_R)
	/*
	 * We have Linux's reentrant getprotobyname_r().
	 */
	struct protoent result_buf;
	char buf[1024];	/* arbitrary size */
	int err;

	err = getprotobyname_r(str, &result_buf, buf, sizeof buf, &p);
	if (err != 0) {
		/*
		 * XXX - dynamically allocate the buffer, and make it
		 * bigger if we get ERANGE back?
		 */
		return 0;
	}
  #elif defined(HAVE_SOLARIS_IRIX_GETNETBYNAME_R)
	/*
	 * We have Solaris's and IRIX's reentrant getprotobyname_r().
	 */
	struct protoent result_buf;
	char buf[1024];	/* arbitrary size */

	p = getprotobyname_r(str, &result_buf, buf, (int)sizeof buf);
  #elif defined(HAVE_AIX_GETNETBYNAME_R)
	/*
	 * We have AIX's reentrant getprotobyname_r().
	 */
	struct protoent result_buf;
	struct protoent_data proto_data;

	if (getprotobyname_r(str, &result_buf, &proto_data) == -1)
		p = NULL;
	else
		p = &result_buf;
  #else
	/*
	 * We don't have any getprotobyname_r(); either we have a
	 * getprotobyname() that uses thread-specific data, in which
	 * case we're thread-safe (sufficiently recent FreeBSD,
	 * sufficiently recent Darwin-based OS, sufficiently recent
	 * HP-UX, sufficiently recent Tru64 UNIX, Windows), or we have
	 * the traditional getprotobyname() (everything else, including
	 * current NetBSD and OpenBSD), in which case we're not
	 * thread-safe.
	 */
	p = getprotobyname(str);
  #endif
	if (p != 0)
		return p->p_proto;
	else
		return PROTO_UNDEF;
}

#include "ethertype.h"

struct eproto {
	const char *s;
	u_short p;
};

/*
 * Static data base of ether protocol types.
 * tcpdump used to import this, and it's declared as an export on
 * Debian, at least, so make it a public symbol, even though we
 * don't officially export it by declaring it in a header file.
 * (Programs *should* do this themselves, as tcpdump now does.)
 *
 * We declare it here, right before defining it, to squelch any
 * warnings we might get from compilers about the lack of a
 * declaration.
 */
PCAP_API struct eproto eproto_db[];
PCAP_API_DEF struct eproto eproto_db[] = {
	{ "aarp", ETHERTYPE_AARP },
	{ "arp", ETHERTYPE_ARP },
	{ "atalk", ETHERTYPE_ATALK },
	{ "decnet", ETHERTYPE_DN },
	{ "ip", ETHERTYPE_IP },
#ifdef INET6
	{ "ip6", ETHERTYPE_IPV6 },
#endif
	{ "lat", ETHERTYPE_LAT },
	{ "loopback", ETHERTYPE_LOOPBACK },
	{ "mopdl", ETHERTYPE_MOPDL },
	{ "moprc", ETHERTYPE_MOPRC },
	{ "rarp", ETHERTYPE_REVARP },
	{ "sca", ETHERTYPE_SCA },
	{ (char *)0, 0 }
};

int
pcap_nametoeproto(const char *s)
{
	struct eproto *p = eproto_db;

	while (p->s != 0) {
		if (strcmp(p->s, s) == 0)
			return p->p;
		p += 1;
	}
	return PROTO_UNDEF;
}

#include "llc.h"

/* Static data base of LLC values. */
static struct eproto llc_db[] = {
	{ "iso", LLCSAP_ISONS },
	{ "stp", LLCSAP_8021D },
	{ "ipx", LLCSAP_IPX },
	{ "netbeui", LLCSAP_NETBEUI },
	{ (char *)0, 0 }
};

int
pcap_nametollc(const char *s)
{
	struct eproto *p = llc_db;

	while (p->s != 0) {
		if (strcmp(p->s, s) == 0)
			return p->p;
		p += 1;
	}
	return PROTO_UNDEF;
}

/* Hex digit to 8-bit unsigned integer. */
static inline u_char
pcapint_xdtoi(u_char c)
{
	if (c >= '0' && c <= '9')
		return (u_char)(c - '0');
	else if (c >= 'a' && c <= 'f')
		return (u_char)(c - 'a' + 10);
	else
		return (u_char)(c - 'A' + 10);
}

int
__pcap_atoin(const char *s, bpf_u_int32 *addr)
{
	u_int n;
	int len;

	*addr = 0;
	len = 0;
	for (;;) {
		n = 0;
		while (*s && *s != '.') {
			if (n > 25) {
				/* The result will be > 255 */
				return -1;
			}
			n = n * 10 + *s++ - '0';
		}
		if (n > 255)
			return -1;
		*addr <<= 8;
		*addr |= n & 0xff;
		len += 8;
		if (*s == '\0')
			return len;
		++s;
	}
	/* NOTREACHED */
}

int
__pcap_atodn(const char *s, bpf_u_int32 *addr)
{
#define AREASHIFT 10
#define AREAMASK 0176000
#define NODEMASK 01777

	u_int node, area;

	if (sscanf(s, "%d.%d", &area, &node) != 2)
		return(0);

	*addr = (area << AREASHIFT) & AREAMASK;
	*addr |= (node & NODEMASK);

	return(32);
}

/*
 * libpcap ARCnet address format is "^\$[0-9a-fA-F]{1,2}$" in regexp syntax.
 * Iff the given string is a well-formed ARCnet address, parse the string,
 * store the 8-bit unsigned value into the provided integer and return 1.
 * Otherwise return 0.
 *
 *  --> START -- $ --> DOLLAR -- [0-9a-fA-F] --> HEX1 -- \0 -->-+
 *        |              |                        |             |
 *       [.]            [.]                  [0-9a-fA-F]        |
 *        |              |                        |             |
 *        v              v                        v             v
 *    (invalid) <--------+-<---------------[.]-- HEX2 -- \0 -->-+--> (valid)
 */
int
pcapint_atoan(const char *s, uint8_t *addr)
{
	enum {
		START,
		DOLLAR,
		HEX1,
		HEX2,
	} fsm_state = START;
	uint8_t tmp = 0;

	while (*s) {
		switch (fsm_state) {
		case START:
			if (*s != '$')
				goto invalid;
			fsm_state = DOLLAR;
			break;
		case DOLLAR:
			if (! PCAP_ISXDIGIT(*s))
				goto invalid;
			tmp = pcapint_xdtoi(*s);
			fsm_state = HEX1;
			break;
		case HEX1:
			if (! PCAP_ISXDIGIT(*s))
				goto invalid;
			tmp <<= 4;
			tmp |= pcapint_xdtoi(*s);
			fsm_state = HEX2;
			break;
		case HEX2:
			goto invalid;
		} // switch
		s++;
	} // while
	if (fsm_state == HEX1 || fsm_state == HEX2) {
		*addr = tmp;
		return 1;
	}

invalid:
	return 0;
}

// Man page: "xxxxxxxxxxxx", regexp: "^[0-9a-fA-F]{12}$".
static u_char
pcapint_atomac48_xxxxxxxxxxxx(const char *s, uint8_t *addr)
{
	if (strlen(s) == 12 &&
	    PCAP_ISXDIGIT(s[0]) &&
	    PCAP_ISXDIGIT(s[1]) &&
	    PCAP_ISXDIGIT(s[2]) &&
	    PCAP_ISXDIGIT(s[3]) &&
	    PCAP_ISXDIGIT(s[4]) &&
	    PCAP_ISXDIGIT(s[5]) &&
	    PCAP_ISXDIGIT(s[6]) &&
	    PCAP_ISXDIGIT(s[7]) &&
	    PCAP_ISXDIGIT(s[8]) &&
	    PCAP_ISXDIGIT(s[9]) &&
	    PCAP_ISXDIGIT(s[10]) &&
	    PCAP_ISXDIGIT(s[11])) {
		addr[0] = pcapint_xdtoi(s[0]) << 4 | pcapint_xdtoi(s[1]);
		addr[1] = pcapint_xdtoi(s[2]) << 4 | pcapint_xdtoi(s[3]);
		addr[2] = pcapint_xdtoi(s[4]) << 4 | pcapint_xdtoi(s[5]);
		addr[3] = pcapint_xdtoi(s[6]) << 4 | pcapint_xdtoi(s[7]);
		addr[4] = pcapint_xdtoi(s[8]) << 4 | pcapint_xdtoi(s[9]);
		addr[5] = pcapint_xdtoi(s[10]) << 4 | pcapint_xdtoi(s[11]);
		return 1;
	}
	return 0;
}

// Man page: "xxxx.xxxx.xxxx", regexp: "^[0-9a-fA-F]{4}(\.[0-9a-fA-F]{4}){2}$".
static u_char
pcapint_atomac48_xxxx_3_times(const char *s, uint8_t *addr)
{
	const char sep = '.';
	if (strlen(s) == 14 &&
	    PCAP_ISXDIGIT(s[0]) &&
	    PCAP_ISXDIGIT(s[1]) &&
	    PCAP_ISXDIGIT(s[2]) &&
	    PCAP_ISXDIGIT(s[3]) &&
	    s[4] == sep &&
	    PCAP_ISXDIGIT(s[5]) &&
	    PCAP_ISXDIGIT(s[6]) &&
	    PCAP_ISXDIGIT(s[7]) &&
	    PCAP_ISXDIGIT(s[8]) &&
	    s[9] == sep &&
	    PCAP_ISXDIGIT(s[10]) &&
	    PCAP_ISXDIGIT(s[11]) &&
	    PCAP_ISXDIGIT(s[12]) &&
	    PCAP_ISXDIGIT(s[13])) {
		addr[0] = pcapint_xdtoi(s[0]) << 4 | pcapint_xdtoi(s[1]);
		addr[1] = pcapint_xdtoi(s[2]) << 4 | pcapint_xdtoi(s[3]);
		addr[2] = pcapint_xdtoi(s[5]) << 4 | pcapint_xdtoi(s[6]);
		addr[3] = pcapint_xdtoi(s[7]) << 4 | pcapint_xdtoi(s[8]);
		addr[4] = pcapint_xdtoi(s[10]) << 4 | pcapint_xdtoi(s[11]);
		addr[5] = pcapint_xdtoi(s[12]) << 4 | pcapint_xdtoi(s[13]);
		return 1;
	}
	return 0;
}

/*
 * Man page: "xx:xx:xx:xx:xx:xx", regexp: "^[0-9a-fA-F]{1,2}(:[0-9a-fA-F]{1,2}){5}$".
 * Man page: "xx-xx-xx-xx-xx-xx", regexp: "^[0-9a-fA-F]{1,2}(-[0-9a-fA-F]{1,2}){5}$".
 * Man page: "xx.xx.xx.xx.xx.xx", regexp: "^[0-9a-fA-F]{1,2}(\.[0-9a-fA-F]{1,2}){5}$".
 * (Any "xx" above can be "x", which is equivalent to "0x".)
 *
 * An equivalent (and parametrisable for EUI-64) FSM could be implemented using
 * a smaller graph, but that graph would be neither acyclic nor planar nor
 * trivial to verify.
 *
 *                |
 *    [.]         v
 * +<---------- START
 * |              |
 * |              | [0-9a-fA-F]
 * |  [.]         v
 * +<--------- BYTE0_X ----------+
 * |              |              |
 * |              | [0-9a-fA-F]  |
 * |  [.]         v              |
 * +<--------- BYTE0_XX          | [:\.-]
 * |              |              |
 * |              | [:\.-]       |
 * |  [.]         v              |
 * +<----- BYTE0_SEP_BYTE1 <-----+
 * |              |
 * |              | [0-9a-fA-F]
 * |  [.]         v
 * +<--------- BYTE1_X ----------+
 * |              |              |
 * |              | [0-9a-fA-F]  |
 * |  [.]         v              |
 * +<--------- BYTE1_XX          | <sep>
 * |              |              |
 * |              | <sep>        |
 * |  [.]         v              |
 * +<----- BYTE1_SEP_BYTE2 <-----+
 * |              |
 * |              | [0-9a-fA-F]
 * |  [.]         v
 * +<--------- BYTE2_X ----------+
 * |              |              |
 * |              | [0-9a-fA-F]  |
 * |  [.]         v              |
 * +<--------- BYTE2_XX          | <sep>
 * |              |              |
 * |              | <sep>        |
 * |  [.]         v              |
 * +<----- BYTE2_SEP_BYTE3 <-----+
 * |              |
 * |              | [0-9a-fA-F]
 * |  [.]         v
 * +<--------- BYTE3_X ----------+
 * |              |              |
 * |              | [0-9a-fA-F]  |
 * |  [.]         v              |
 * +<--------- BYTE3_XX          | <sep>
 * |              |              |
 * |              | <sep>        |
 * |  [.]         v              |
 * +<----- BYTE3_SEP_BYTE4 <-----+
 * |              |
 * |              | [0-9a-fA-F]
 * |  [.]         v
 * +<--------- BYTE4_X ----------+
 * |              |              |
 * |              | [0-9a-fA-F]  |
 * |  [.]         v              |
 * +<--------- BYTE4_XX          | <sep>
 * |              |              |
 * |              | <sep>        |
 * |  [.]         v              |
 * +<----- BYTE4_SEP_BYTE5 <-----+
 * |              |
 * |              | [0-9a-fA-F]
 * |  [.]         v
 * +<--------- BYTE5_X ----------+
 * |              |              |
 * |              | [0-9a-fA-F]  |
 * |  [.]         v              |
 * +<--------- BYTE5_XX          | \0
 * |              |              |
 * |              | \0           |
 * |              |              v
 * +--> (reject)  +---------> (accept)
 *
 */
static u_char
pcapint_atomac48_x_xx_6_times(const char *s, uint8_t *addr)
{
	enum {
		START,
		BYTE0_X,
		BYTE0_XX,
		BYTE0_SEP_BYTE1,
		BYTE1_X,
		BYTE1_XX,
		BYTE1_SEP_BYTE2,
		BYTE2_X,
		BYTE2_XX,
		BYTE2_SEP_BYTE3,
		BYTE3_X,
		BYTE3_XX,
		BYTE3_SEP_BYTE4,
		BYTE4_X,
		BYTE4_XX,
		BYTE4_SEP_BYTE5,
		BYTE5_X,
		BYTE5_XX,
	} fsm_state = START;
	uint8_t buf[6];
	const char *seplist = ":.-";
	char sep;

	while (*s) {
		switch (fsm_state) {
		case START:
			if (PCAP_ISXDIGIT(*s)) {
				buf[0] = pcapint_xdtoi(*s);
				fsm_state = BYTE0_X;
				break;
			}
			goto reject;
		case BYTE0_X:
			if (strchr(seplist, *s)) {
				sep = *s;
				fsm_state = BYTE0_SEP_BYTE1;
				break;
			}
			if (PCAP_ISXDIGIT(*s)) {
				buf[0] = buf[0] << 4 | pcapint_xdtoi(*s);
				fsm_state = BYTE0_XX;
				break;
			}
			goto reject;
		case BYTE0_XX:
			if (strchr(seplist, *s)) {
				sep = *s;
				fsm_state = BYTE0_SEP_BYTE1;
				break;
			}
			goto reject;
		case BYTE0_SEP_BYTE1:
			if (PCAP_ISXDIGIT(*s)) {
				buf[1] = pcapint_xdtoi(*s);
				fsm_state = BYTE1_X;
				break;
			}
			goto reject;
		case BYTE1_X:
			if (*s == sep) {
				fsm_state = BYTE1_SEP_BYTE2;
				break;
			}
			if (PCAP_ISXDIGIT(*s)) {
				buf[1] = buf[1] << 4 | pcapint_xdtoi(*s);
				fsm_state = BYTE1_XX;
				break;
			}
			goto reject;
		case BYTE1_XX:
			if (*s == sep) {
				fsm_state = BYTE1_SEP_BYTE2;
				break;
			}
			goto reject;
		case BYTE1_SEP_BYTE2:
			if (PCAP_ISXDIGIT(*s)) {
				buf[2] = pcapint_xdtoi(*s);
				fsm_state = BYTE2_X;
				break;
			}
			goto reject;
		case BYTE2_X:
			if (*s == sep) {
				fsm_state = BYTE2_SEP_BYTE3;
				break;
			}
			if (PCAP_ISXDIGIT(*s)) {
				buf[2] = buf[2] << 4 | pcapint_xdtoi(*s);
				fsm_state = BYTE2_XX;
				break;
			}
			goto reject;
		case BYTE2_XX:
			if (*s == sep) {
				fsm_state = BYTE2_SEP_BYTE3;
				break;
			}
			goto reject;
		case BYTE2_SEP_BYTE3:
			if (PCAP_ISXDIGIT(*s)) {
				buf[3] = pcapint_xdtoi(*s);
				fsm_state = BYTE3_X;
				break;
			}
			goto reject;
		case BYTE3_X:
			if (*s == sep) {
				fsm_state = BYTE3_SEP_BYTE4;
				break;
			}
			if (PCAP_ISXDIGIT(*s)) {
				buf[3] = buf[3] << 4 | pcapint_xdtoi(*s);
				fsm_state = BYTE3_XX;
				break;
			}
			goto reject;
		case BYTE3_XX:
			if (*s == sep) {
				fsm_state = BYTE3_SEP_BYTE4;
				break;
			}
			goto reject;
		case BYTE3_SEP_BYTE4:
			if (PCAP_ISXDIGIT(*s)) {
				buf[4] = pcapint_xdtoi(*s);
				fsm_state = BYTE4_X;
				break;
			}
			goto reject;
		case BYTE4_X:
			if (*s == sep) {
				fsm_state = BYTE4_SEP_BYTE5;
				break;
			}
			if (PCAP_ISXDIGIT(*s)) {
				buf[4] = buf[4] << 4 | pcapint_xdtoi(*s);
				fsm_state = BYTE4_XX;
				break;
			}
			goto reject;
		case BYTE4_XX:
			if (*s == sep) {
				fsm_state = BYTE4_SEP_BYTE5;
				break;
			}
			goto reject;
		case BYTE4_SEP_BYTE5:
			if (PCAP_ISXDIGIT(*s)) {
				buf[5] = pcapint_xdtoi(*s);
				fsm_state = BYTE5_X;
				break;
			}
			goto reject;
		case BYTE5_X:
			if (PCAP_ISXDIGIT(*s)) {
				buf[5] = buf[5] << 4 | pcapint_xdtoi(*s);
				fsm_state = BYTE5_XX;
				break;
			}
			goto reject;
		case BYTE5_XX:
			goto reject;
		} // switch
		s++;
	} // while

	if (fsm_state == BYTE5_X || fsm_state == BYTE5_XX) {
		// accept
		memcpy(addr, buf, sizeof(buf));
		return 1;
	}

reject:
	return 0;
}

// The 'addr' argument must point to an array of at least 6 elements.
static int
pcapint_atomac48(const char *s, uint8_t *addr)
{
	return s && (
	    pcapint_atomac48_xxxxxxxxxxxx(s, addr) ||
	    pcapint_atomac48_xxxx_3_times(s, addr) ||
	    pcapint_atomac48_x_xx_6_times(s, addr)
	);
}

/*
 * If 's' is a MAC-48 address in one of the forms documented in pcap-filter(7)
 * for "ether host", return a pointer to an allocated buffer with the binary
 * value of the address.  Return NULL on any error.
 */
u_char *
pcap_ether_aton(const char *s)
{
	uint8_t tmp[6];
	if (! pcapint_atomac48(s, tmp))
		return (NULL);

	u_char *e = malloc(6);
	if (e == NULL)
		return (NULL);
	memcpy(e, tmp, sizeof(tmp));
	return (e);
}

#ifndef HAVE_ETHER_HOSTTON
/*
 * Roll our own.
 *
 * This should be thread-safe, as we define the static variables
 * we use to be thread-local, and as pcap_next_etherent() does so
 * as well.
 */
u_char *
pcap_ether_hostton(const char *name)
{
	register struct pcap_etherent *ep;
	register u_char *ap;
	static thread_local FILE *fp = NULL;
	static thread_local int init = 0;

	if (!init) {
		fp = fopen(PCAP_ETHERS_FILE, "r");
		++init;
		if (fp == NULL)
			return (NULL);
	} else if (fp == NULL)
		return (NULL);
	else
		rewind(fp);

	while ((ep = pcap_next_etherent(fp)) != NULL) {
		if (strcmp(ep->name, name) == 0) {
			ap = (u_char *)malloc(6);
			if (ap != NULL) {
				memcpy(ap, ep->addr, 6);
				return (ap);
			}
			break;
		}
	}
	return (NULL);
}
#else
/*
 * Use the OS-supplied routine.
 * This *should* be thread-safe; the API doesn't have a static buffer.
 */
u_char *
pcap_ether_hostton(const char *name)
{
	register u_char *ap;
	u_char a[6];
	char namebuf[1024];

	/*
	 * In AIX 7.1 and 7.2: int ether_hostton(char *, struct ether_addr *);
	 */
	pcapint_strlcpy(namebuf, name, sizeof(namebuf));
	ap = NULL;
	if (ether_hostton(namebuf, (struct ether_addr *)a) == 0) {
		ap = (u_char *)malloc(6);
		if (ap != NULL)
			memcpy((char *)ap, (char *)a, 6);
	}
	return (ap);
}
#endif

/*
 * XXX - not guaranteed to be thread-safe!
 */
int
#ifdef	DECNETLIB
__pcap_nametodnaddr(const char *name, u_short *res)
{
	struct nodeent *getnodebyname();
	struct nodeent *nep;

	nep = getnodebyname(name);
	if (nep == ((struct nodeent *)0))
		return(0);

	memcpy((char *)res, (char *)nep->n_addr, sizeof(unsigned short));
	return(1);
#else
__pcap_nametodnaddr(const char *name _U_, u_short *res _U_)
{
	return(0);
#endif
}
