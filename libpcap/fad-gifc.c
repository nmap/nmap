/* -*- Mode: c; tab-width: 8; indent-tabs-mode: 1; c-basic-offset: 8; -*- */
/*
 * Copyright (c) 1994, 1995, 1996, 1997, 1998
 *	The Regents of the University of California.  All rights reserved.
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
 *	This product includes software developed by the Computer Systems
 *	Engineering Group at Lawrence Berkeley Laboratory.
 * 4. Neither the name of the University nor of the Laboratory may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
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
 */

#ifndef lint
static const char rcsid[] _U_ =
    "@(#) $Header: /tcpdump/master/libpcap/fad-gifc.c,v 1.11.2.1 2008-08-06 07:35:01 guy Exp $ (LBL)";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif
#include <sys/time.h>				/* concession to AIX */

struct mbuf;		/* Squelch compiler warnings on some platforms for */
struct rtentry;		/* declarations in <net/if.h> */
#include <net/if.h>
#include <netinet/in.h>

#include <ctype.h>
#include <errno.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pcap-int.h"

#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

/*
 * This is fun.
 *
 * In older BSD systems, socket addresses were fixed-length, and
 * "sizeof (struct sockaddr)" gave the size of the structure.
 * All addresses fit within a "struct sockaddr".
 *
 * In newer BSD systems, the socket address is variable-length, and
 * there's an "sa_len" field giving the length of the structure;
 * this allows socket addresses to be longer than 2 bytes of family
 * and 14 bytes of data.
 *
 * Some commercial UNIXes use the old BSD scheme, some use the RFC 2553
 * variant of the old BSD scheme (with "struct sockaddr_storage" rather
 * than "struct sockaddr"), and some use the new BSD scheme.
 *
 * Some versions of GNU libc use neither scheme, but has an "SA_LEN()"
 * macro that determines the size based on the address family.  Other
 * versions don't have "SA_LEN()" (as it was in drafts of RFC 2553
 * but not in the final version).
 *
 * We assume that a UNIX that doesn't have "getifaddrs()" and doesn't have
 * SIOCGLIFCONF, but has SIOCGIFCONF, uses "struct sockaddr" for the
 * address in an entry returned by SIOCGIFCONF.
 */
#ifndef SA_LEN
#ifdef HAVE_SOCKADDR_SA_LEN
#define SA_LEN(addr)	((addr)->sa_len)
#else /* HAVE_SOCKADDR_SA_LEN */
#define SA_LEN(addr)	(sizeof (struct sockaddr))
#endif /* HAVE_SOCKADDR_SA_LEN */
#endif /* SA_LEN */

/*
 * This is also fun.
 *
 * There is no ioctl that returns the amount of space required for all
 * the data that SIOCGIFCONF could return, and if a buffer is supplied
 * that's not large enough for all the data SIOCGIFCONF could return,
 * on at least some platforms it just returns the data that'd fit with
 * no indication that there wasn't enough room for all the data, much
 * less an indication of how much more room is required.
 *
 * The only way to ensure that we got all the data is to pass a buffer
 * large enough that the amount of space in the buffer *not* filled in
 * is greater than the largest possible entry.
 *
 * We assume that's "sizeof(ifreq.ifr_name)" plus 255, under the assumption
 * that no address is more than 255 bytes (on systems where the "sa_len"
 * field in a "struct sockaddr" is 1 byte, e.g. newer BSDs, that's the
 * case, and addresses are unlikely to be bigger than that in any case).
 */
#define MAX_SA_LEN	255

#ifdef HAVE_PROC_NET_DEV
/*
 * Get from "/proc/net/dev" all interfaces listed there; if they're
 * already in the list of interfaces we have, that won't add another
 * instance, but if they're not, that'll add them.
 *
 * We don't bother getting any addresses for them; it appears you can't
 * use SIOCGIFADDR on Linux to get IPv6 addresses for interfaces, and,
 * although some other types of addresses can be fetched with SIOCGIFADDR,
 * we don't bother with them for now.
 *
 * We also don't fail if we couldn't open "/proc/net/dev"; we just leave
 * the list of interfaces as is.
 */
static int
scan_proc_net_dev(pcap_if_t **devlistp, int fd, char *errbuf)
{
	FILE *proc_net_f;
	char linebuf[512];
	int linenum;
	unsigned char *p;
	char name[512];	/* XXX - pick a size */
	char *q, *saveq;
	struct ifreq ifrflags;
	int ret = 0;

	proc_net_f = fopen("/proc/net/dev", "r");
	if (proc_net_f == NULL)
		return (0);

	for (linenum = 1;
	    fgets(linebuf, sizeof linebuf, proc_net_f) != NULL; linenum++) {
		/*
		 * Skip the first two lines - they're headers.
		 */
		if (linenum <= 2)
			continue;

		p = &linebuf[0];

		/*
		 * Skip leading white space.
		 */
		while (*p != '\0' && isspace(*p))
			p++;
		if (*p == '\0' || *p == '\n')
			continue;	/* blank line */

		/*
		 * Get the interface name.
		 */
		q = &name[0];
		while (*p != '\0' && !isspace(*p)) {
			if (*p == ':') {
				/*
				 * This could be the separator between a
				 * name and an alias number, or it could be
				 * the separator between a name with no
				 * alias number and the next field.
				 *
				 * If there's a colon after digits, it
				 * separates the name and the alias number,
				 * otherwise it separates the name and the
				 * next field.
				 */
				saveq = q;
				while (isdigit(*p))
					*q++ = *p++;
				if (*p != ':') {
					/*
					 * That was the next field,
					 * not the alias number.
					 */
					q = saveq;
				}
				break;
			} else
				*q++ = *p++;
		}
		*q = '\0';

		/*
		 * Get the flags for this interface, and skip it if
		 * it's not up.
		 */
		strncpy(ifrflags.ifr_name, name, sizeof(ifrflags.ifr_name));
		if (ioctl(fd, SIOCGIFFLAGS, (char *)&ifrflags) < 0) {
			if (errno == ENXIO)
				continue;
			(void)snprintf(errbuf, PCAP_ERRBUF_SIZE,
			    "SIOCGIFFLAGS: %.*s: %s",
			    (int)sizeof(ifrflags.ifr_name),
			    ifrflags.ifr_name,
			    pcap_strerror(errno));
			ret = -1;
			break;
		}
		if (!(ifrflags.ifr_flags & IFF_UP))
			continue;

		/*
		 * Add an entry for this interface, with no addresses.
		 */
		if (pcap_add_if(devlistp, name, ifrflags.ifr_flags, NULL,
		    errbuf) == -1) {
			/*
			 * Failure.
			 */
			ret = -1;
			break;
		}
	}
	if (ret != -1) {
		/*
		 * Well, we didn't fail for any other reason; did we
		 * fail due to an error reading the file?
		 */
		if (ferror(proc_net_f)) {
			(void)snprintf(errbuf, PCAP_ERRBUF_SIZE,
			    "Error reading /proc/net/dev: %s",
			    pcap_strerror(errno));
			ret = -1;
		}
	}

	(void)fclose(proc_net_f);
	return (ret);
}
#endif /* HAVE_PROC_NET_DEV */

/*
 * Get a list of all interfaces that are up and that we can open.
 * Returns -1 on error, 0 otherwise.
 * The list, as returned through "alldevsp", may be null if no interfaces
 * were up and could be opened.
 *
 * This is the implementation used on platforms that have SIOCGIFCONF but
 * don't have any other mechanism for getting a list of interfaces.
 *
 * XXX - or platforms that have other, better mechanisms but for which
 * we don't yet have code to use that mechanism; I think there's a better
 * way on Linux, for example.
 */
int
pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf)
{
	pcap_if_t *devlist = NULL;
	register int fd;
	register struct ifreq *ifrp, *ifend, *ifnext;
	int n;
	struct ifconf ifc;
	char *buf = NULL;
	unsigned buf_size;
#if defined (HAVE_SOLARIS) || defined (HAVE_HPUX10_20_OR_LATER)
	char *p, *q;
#endif
	struct ifreq ifrflags, ifrnetmask, ifrbroadaddr, ifrdstaddr;
	struct sockaddr *netmask, *broadaddr, *dstaddr;
	size_t netmask_size, broadaddr_size, dstaddr_size;
	int ret = 0;

	/*
	 * Create a socket from which to fetch the list of interfaces.
	 */
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		(void)snprintf(errbuf, PCAP_ERRBUF_SIZE,
		    "socket: %s", pcap_strerror(errno));
		return (-1);
	}

	/*
	 * Start with an 8K buffer, and keep growing the buffer until
	 * we have more than "sizeof(ifrp->ifr_name) + MAX_SA_LEN"
	 * bytes left over in the buffer or we fail to get the
	 * interface list for some reason other than EINVAL (which is
	 * presumed here to mean "buffer is too small").
	 */
	buf_size = 8192;
	for (;;) {
		buf = malloc(buf_size);
		if (buf == NULL) {
			(void)snprintf(errbuf, PCAP_ERRBUF_SIZE,
			    "malloc: %s", pcap_strerror(errno));
			(void)close(fd);
			return (-1);
		}

		ifc.ifc_len = buf_size;
		ifc.ifc_buf = buf;
		memset(buf, 0, buf_size);
		if (ioctl(fd, SIOCGIFCONF, (char *)&ifc) < 0
		    && errno != EINVAL) {
			(void)snprintf(errbuf, PCAP_ERRBUF_SIZE,
			    "SIOCGIFCONF: %s", pcap_strerror(errno));
			(void)close(fd);
			free(buf);
			return (-1);
		}
		if (ifc.ifc_len < buf_size &&
		    (buf_size - ifc.ifc_len) > sizeof(ifrp->ifr_name) + MAX_SA_LEN)
			break;
		free(buf);
		buf_size *= 2;
	}

	ifrp = (struct ifreq *)buf;
	ifend = (struct ifreq *)(buf + ifc.ifc_len);

	for (; ifrp < ifend; ifrp = ifnext) {
		/*
		 * XXX - what if this isn't an IPv4 address?  Can
		 * we still get the netmask, etc. with ioctls on
		 * an IPv4 socket?
		 *
		 * The answer is probably platform-dependent, and
		 * if the answer is "no" on more than one platform,
		 * the way you work around it is probably platform-
		 * dependent as well.
		 */
		n = SA_LEN(&ifrp->ifr_addr) + sizeof(ifrp->ifr_name);
		if (n < sizeof(*ifrp))
			ifnext = ifrp + 1;
		else
			ifnext = (struct ifreq *)((char *)ifrp + n);

		/*
		 * XXX - The 32-bit compatibility layer for Linux on IA-64
		 * is slightly broken. It correctly converts the structures
		 * to and from kernel land from 64 bit to 32 bit but 
		 * doesn't update ifc.ifc_len, leaving it larger than the 
		 * amount really used. This means we read off the end 
		 * of the buffer and encounter an interface with an 
		 * "empty" name. Since this is highly unlikely to ever 
		 * occur in a valid case we can just finish looking for 
		 * interfaces if we see an empty name.
		 */
		if (!(*ifrp->ifr_name))
			break;

		/*
		 * Skip entries that begin with "dummy".
		 * XXX - what are these?  Is this Linux-specific?
		 * Are there platforms on which we shouldn't do this?
		 */
		if (strncmp(ifrp->ifr_name, "dummy", 5) == 0)
			continue;

		/*
		 * Get the flags for this interface, and skip it if it's
		 * not up.
		 */
		strncpy(ifrflags.ifr_name, ifrp->ifr_name,
		    sizeof(ifrflags.ifr_name));
		if (ioctl(fd, SIOCGIFFLAGS, (char *)&ifrflags) < 0) {
			if (errno == ENXIO)
				continue;
			(void)snprintf(errbuf, PCAP_ERRBUF_SIZE,
			    "SIOCGIFFLAGS: %.*s: %s",
			    (int)sizeof(ifrflags.ifr_name),
			    ifrflags.ifr_name,
			    pcap_strerror(errno));
			ret = -1;
			break;
		}
		if (!(ifrflags.ifr_flags & IFF_UP))
			continue;

		/*
		 * Get the netmask for this address on this interface.
		 */
		strncpy(ifrnetmask.ifr_name, ifrp->ifr_name,
		    sizeof(ifrnetmask.ifr_name));
		memcpy(&ifrnetmask.ifr_addr, &ifrp->ifr_addr,
		    sizeof(ifrnetmask.ifr_addr));
		if (ioctl(fd, SIOCGIFNETMASK, (char *)&ifrnetmask) < 0) {
			if (errno == EADDRNOTAVAIL) {
				/*
				 * Not available.
				 */
				netmask = NULL;
				netmask_size = 0;
			} else {
				(void)snprintf(errbuf, PCAP_ERRBUF_SIZE,
				    "SIOCGIFNETMASK: %.*s: %s",
				    (int)sizeof(ifrnetmask.ifr_name),
				    ifrnetmask.ifr_name,
				    pcap_strerror(errno));
				ret = -1;
				break;
			}
		} else {
			netmask = &ifrnetmask.ifr_addr;
			netmask_size = SA_LEN(netmask);
		}

		/*
		 * Get the broadcast address for this address on this
		 * interface (if any).
		 */
		if (ifrflags.ifr_flags & IFF_BROADCAST) {
			strncpy(ifrbroadaddr.ifr_name, ifrp->ifr_name,
			    sizeof(ifrbroadaddr.ifr_name));
			memcpy(&ifrbroadaddr.ifr_addr, &ifrp->ifr_addr,
			    sizeof(ifrbroadaddr.ifr_addr));
			if (ioctl(fd, SIOCGIFBRDADDR,
			    (char *)&ifrbroadaddr) < 0) {
				if (errno == EADDRNOTAVAIL) {
					/*
					 * Not available.
					 */
					broadaddr = NULL;
					broadaddr_size = 0;
				} else {
					(void)snprintf(errbuf, PCAP_ERRBUF_SIZE,
					    "SIOCGIFBRDADDR: %.*s: %s",
					    (int)sizeof(ifrbroadaddr.ifr_name),
					    ifrbroadaddr.ifr_name,
					    pcap_strerror(errno));
					ret = -1;
					break;
				}
			} else {
				broadaddr = &ifrbroadaddr.ifr_broadaddr;
				broadaddr_size = SA_LEN(broadaddr);
			}
		} else {
			/*
			 * Not a broadcast interface, so no broadcast
			 * address.
			 */
			broadaddr = NULL;
			broadaddr_size = 0;
		}

		/*
		 * Get the destination address for this address on this
		 * interface (if any).
		 */
		if (ifrflags.ifr_flags & IFF_POINTOPOINT) {
			strncpy(ifrdstaddr.ifr_name, ifrp->ifr_name,
			    sizeof(ifrdstaddr.ifr_name));
			memcpy(&ifrdstaddr.ifr_addr, &ifrp->ifr_addr,
			    sizeof(ifrdstaddr.ifr_addr));
			if (ioctl(fd, SIOCGIFDSTADDR,
			    (char *)&ifrdstaddr) < 0) {
				if (errno == EADDRNOTAVAIL) {
					/*
					 * Not available.
					 */
					dstaddr = NULL;
					dstaddr_size = 0;
				} else {
					(void)snprintf(errbuf, PCAP_ERRBUF_SIZE,
					    "SIOCGIFDSTADDR: %.*s: %s",
					    (int)sizeof(ifrdstaddr.ifr_name),
					    ifrdstaddr.ifr_name,
					    pcap_strerror(errno));
					ret = -1;
					break;
				}
			} else {
				dstaddr = &ifrdstaddr.ifr_dstaddr;
				dstaddr_size = SA_LEN(dstaddr);
			}
		} else {
			/*
			 * Not a point-to-point interface, so no destination
			 * address.
			 */
			dstaddr = NULL;
			dstaddr_size = 0;
		}

#if defined (HAVE_SOLARIS) || defined (HAVE_HPUX10_20_OR_LATER)
		/*
		 * If this entry has a colon followed by a number at
		 * the end, it's a logical interface.  Those are just
		 * the way you assign multiple IP addresses to a real
		 * interface, so an entry for a logical interface should
		 * be treated like the entry for the real interface;
		 * we do that by stripping off the ":" and the number.
		 */
		p = strchr(ifrp->ifr_name, ':');
		if (p != NULL) {
			/*
			 * We have a ":"; is it followed by a number?
			 */
			q = p + 1;
			while (isdigit((unsigned char)*q))
				q++;
			if (*q == '\0') {
				/*
				 * All digits after the ":" until the end.
				 * Strip off the ":" and everything after
				 * it.
				 */
				*p = '\0';
			}
		}
#endif

		/*
		 * Add information for this address to the list.
		 */
		if (add_addr_to_iflist(&devlist, ifrp->ifr_name,
		    ifrflags.ifr_flags, &ifrp->ifr_addr,
		    SA_LEN(&ifrp->ifr_addr), netmask, netmask_size,
		    broadaddr, broadaddr_size, dstaddr, dstaddr_size,
		    errbuf) < 0) {
			ret = -1;
			break;
		}
	}
	free(buf);

#ifdef HAVE_PROC_NET_DEV
	if (ret != -1) {
		/*
		 * We haven't had any errors yet; now read "/proc/net/dev",
		 * and add to the list of interfaces all interfaces listed
		 * there that we don't already have, because, on Linux,
		 * SIOCGIFCONF reports only interfaces with IPv4 addresses,
		 * so you need to read "/proc/net/dev" to get the names of
		 * the rest of the interfaces.
		 */
		ret = scan_proc_net_dev(&devlist, fd, errbuf);
	}
#endif
	(void)close(fd);

	if (ret != -1) {
		/*
		 * We haven't had any errors yet; do any platform-specific
		 * operations to add devices.
		 */
		if (pcap_platform_finddevs(&devlist, errbuf) < 0)
			ret = -1;
	}

	if (ret == -1) {
		/*
		 * We had an error; free the list we've been constructing.
		 */
		if (devlist != NULL) {
			pcap_freealldevs(devlist);
			devlist = NULL;
		}
	}

	*alldevsp = devlist;
	return (ret);
}
