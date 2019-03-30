/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 2000
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
 */

#include "varattrs.h"

#ifndef lint
static const char copyright[] _U_ =
    "@(#) Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 2000\n\
The Regents of the University of California.  All rights reserved.\n";
#endif

/*
 * Tests how select() and poll() behave on the selectable file descriptor
 * for a pcap_t.
 *
 * This would be significantly different on Windows, as it'd test
 * how WaitForMultipleObjects() would work on the event handle for a
 * pcap_t.
 */
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#else
#include <sys/time.h>	/* older UN*Xes */
#endif
#include <poll.h>

#include "pcap/funcattrs.h"

static char *program_name;

/* Forwards */
static void countme(u_char *, const struct pcap_pkthdr *, const u_char *);
static void PCAP_NORETURN usage(void);
static void PCAP_NORETURN error(const char *, ...) PCAP_PRINTFLIKE(1, 2);
static void warning(const char *, ...) PCAP_PRINTFLIKE(1, 2);
static char *copy_argv(char **);

static pcap_t *pd;

int
main(int argc, char **argv)
{
	register int op;
	bpf_u_int32 localnet, netmask;
	register char *cp, *cmdbuf, *device;
	int doselect, dopoll, dotimeout, dononblock;
	const char *mechanism;
	struct bpf_program fcode;
	char ebuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *devlist;
	int selectable_fd;
	struct timeval *required_timeout;
	int status;
	int packet_count;

	device = NULL;
	doselect = 0;
	dopoll = 0;
	mechanism = NULL;
	dotimeout = 0;
	dononblock = 0;
	if ((cp = strrchr(argv[0], '/')) != NULL)
		program_name = cp + 1;
	else
		program_name = argv[0];

	opterr = 0;
	while ((op = getopt(argc, argv, "i:sptn")) != -1) {
		switch (op) {

		case 'i':
			device = optarg;
			break;

		case 's':
			doselect = 1;
			mechanism = "select() and pcap_dispatch()";
			break;

		case 'p':
			dopoll = 1;
			mechanism = "poll() and pcap_dispatch()";
			break;

		case 't':
			dotimeout = 1;
			break;

		case 'n':
			dononblock = 1;
			break;

		default:
			usage();
			/* NOTREACHED */
		}
	}

	if (doselect && dopoll) {
		fprintf(stderr, "selpolltest: choose select (-s) or poll (-p), but not both\n");
		return 1;
	}
	if (dotimeout && !doselect && !dopoll) {
		fprintf(stderr, "selpolltest: timeout (-t) requires select (-s) or poll (-p)\n");
		return 1;
	}
	if (device == NULL) {
		if (pcap_findalldevs(&devlist, ebuf) == -1)
			error("%s", ebuf);
		if (devlist == NULL)
			error("no interfaces available for capture");
		device = strdup(devlist->name);
		pcap_freealldevs(devlist);
	}
	*ebuf = '\0';
	pd = pcap_open_live(device, 65535, 0, 1000, ebuf);
	if (pd == NULL)
		error("%s", ebuf);
	else if (*ebuf)
		warning("%s", ebuf);
	if (pcap_lookupnet(device, &localnet, &netmask, ebuf) < 0) {
		localnet = 0;
		netmask = 0;
		warning("%s", ebuf);
	}
	cmdbuf = copy_argv(&argv[optind]);

	if (pcap_compile(pd, &fcode, cmdbuf, 1, netmask) < 0)
		error("%s", pcap_geterr(pd));
	if (pcap_setfilter(pd, &fcode) < 0)
		error("%s", pcap_geterr(pd));

	if (doselect || dopoll) {
		/*
		 * We need either an FD on which to do select()/poll()
		 * or, if there isn't one, a timeout to use in select()/
		 * poll().
		 */
		selectable_fd = pcap_get_selectable_fd(pd);
		if (selectable_fd == -1) {
			printf("Listening on %s, using %s, with a timeout\n",
			    device, mechanism);
			required_timeout = pcap_get_required_select_timeout(pd);
			if (required_timeout == NULL)
				error("select()/poll() isn't supported on %s, even with a timeout",
				    device);

			/*
			 * As we won't be notified by select() or poll()
			 * that a read can be done, we'll have to periodically
			 * try reading from the device every time the required
			 * timeout expires, and we don't want those attempts
			 * to block if nothing has arrived in that interval,
			 * so we want to force non-blocking mode.
			 */
			dononblock = 1;
		} else {
			printf("Listening on %s, using %s\n", device,
			    mechanism);
			required_timeout = NULL;
		}
	} else
		printf("Listening on %s, using pcap_dispatch()\n", device);

	if (dononblock) {
		if (pcap_setnonblock(pd, 1, ebuf) == -1)
			error("pcap_setnonblock failed: %s", ebuf);
	}
	if (doselect) {
		for (;;) {
			fd_set setread, setexcept;
			struct timeval seltimeout;

			FD_ZERO(&setread);
			if (selectable_fd != -1) {
				FD_SET(selectable_fd, &setread);
				FD_ZERO(&setexcept);
				FD_SET(selectable_fd, &setexcept);
			}
			if (dotimeout) {
				seltimeout.tv_sec = 0;
				if (required_timeout != NULL &&
				    required_timeout->tv_usec < 1000)
					seltimeout.tv_usec = required_timeout->tv_usec;
				else
					seltimeout.tv_usec = 1000;
				status = select(selectable_fd + 1, &setread,
				    NULL, &setexcept, &seltimeout);
			} else if (required_timeout != NULL) {
				seltimeout = *required_timeout;
				status = select(selectable_fd + 1, &setread,
				    NULL, &setexcept, &seltimeout);
			} else {
				status = select((selectable_fd == -1) ?
				    0 : selectable_fd + 1, &setread,
				    NULL, &setexcept, NULL);
			}
			if (status == -1) {
				printf("Select returns error (%s)\n",
				    strerror(errno));
			} else {
				if (selectable_fd == -1) {
					if (status != 0)
						printf("Select returned a descriptor\n");
				} else {
					if (status == 0)
						printf("Select timed out: ");
					else
						printf("Select returned a descriptor: ");
					if (FD_ISSET(selectable_fd, &setread))
						printf("readable, ");
					else
						printf("not readable, ");
					if (FD_ISSET(selectable_fd, &setexcept))
						printf("exceptional condition\n");
					else
						printf("no exceptional condition\n");
				}
				packet_count = 0;
				status = pcap_dispatch(pd, -1, countme,
				    (u_char *)&packet_count);
				if (status < 0)
					break;
				/*
				 * Don't report this if we're using a
				 * required timeout and we got no packets,
				 * because that could be a very short timeout,
				 * and we don't want to spam the user with
				 * a ton of "no packets" reports.
				 */
				if (status != 0 || packet_count != 0 ||
				    required_timeout != NULL) {
					printf("%d packets seen, %d packets counted after select returns\n",
					    status, packet_count);
				}
			}
		}
	} else if (dopoll) {
		for (;;) {
			struct pollfd fd;
			int polltimeout;

			fd.fd = selectable_fd;
			fd.events = POLLIN;
			if (dotimeout)
				polltimeout = 1;
			else if (required_timeout != NULL &&
			    required_timeout->tv_usec >= 1000)
				polltimeout = required_timeout->tv_usec/1000;
			else
				polltimeout = -1;
			status = poll(&fd, (selectable_fd == -1) ? 0 : 1, polltimeout);
			if (status == -1) {
				printf("Poll returns error (%s)\n",
				    strerror(errno));
			} else {
				if (selectable_fd == -1) {
					if (status != 0)
						printf("Poll returned a descriptor\n");
				} else {
					if (status == 0)
						printf("Poll timed out\n");
					else {
						printf("Poll returned a descriptor: ");
						if (fd.revents & POLLIN)
							printf("readable, ");
						else
							printf("not readable, ");
						if (fd.revents & POLLERR)
							printf("exceptional condition, ");
						else
							printf("no exceptional condition, ");
						if (fd.revents & POLLHUP)
							printf("disconnect, ");
						else
							printf("no disconnect, ");
						if (fd.revents & POLLNVAL)
							printf("invalid\n");
						else
							printf("not invalid\n");
					}
				}
				packet_count = 0;
				status = pcap_dispatch(pd, -1, countme,
				    (u_char *)&packet_count);
				if (status < 0)
					break;
				/*
				 * Don't report this if we're using a
				 * required timeout and we got no packets,
				 * because that could be a very short timeout,
				 * and we don't want to spam the user with
				 * a ton of "no packets" reports.
				 */
				if (status != 0 || packet_count != 0 ||
				    required_timeout != NULL) {
					printf("%d packets seen, %d packets counted after poll returns\n",
					    status, packet_count);
				}
			}
		}
	} else {
		for (;;) {
			packet_count = 0;
			status = pcap_dispatch(pd, -1, countme,
			    (u_char *)&packet_count);
			if (status < 0)
				break;
			printf("%d packets seen, %d packets counted after pcap_dispatch returns\n",
			    status, packet_count);
		}
	}
	if (status == -2) {
		/*
		 * We got interrupted, so perhaps we didn't
		 * manage to finish a line we were printing.
		 * Print an extra newline, just in case.
		 */
		putchar('\n');
	}
	(void)fflush(stdout);
	if (status == -1) {
		/*
		 * Error.  Report it.
		 */
		(void)fprintf(stderr, "%s: pcap_loop: %s\n",
		    program_name, pcap_geterr(pd));
	}
	pcap_close(pd);
	exit(status == -1 ? 1 : 0);
}

static void
countme(u_char *user, const struct pcap_pkthdr *h _U_, const u_char *sp _U_)
{
	int *counterp = (int *)user;

	(*counterp)++;
}

static void
usage(void)
{
	(void)fprintf(stderr, "Usage: %s [ -sptn ] [ -i interface ] [expression]\n",
	    program_name);
	exit(1);
}

/* VARARGS */
static void
error(const char *fmt, ...)
{
	va_list ap;

	(void)fprintf(stderr, "%s: ", program_name);
	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (*fmt) {
		fmt += strlen(fmt);
		if (fmt[-1] != '\n')
			(void)fputc('\n', stderr);
	}
	exit(1);
	/* NOTREACHED */
}

/* VARARGS */
static void
warning(const char *fmt, ...)
{
	va_list ap;

	(void)fprintf(stderr, "%s: WARNING: ", program_name);
	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (*fmt) {
		fmt += strlen(fmt);
		if (fmt[-1] != '\n')
			(void)fputc('\n', stderr);
	}
}

/*
 * Copy arg vector into a new buffer, concatenating arguments with spaces.
 */
static char *
copy_argv(register char **argv)
{
	register char **p;
	register u_int len = 0;
	char *buf;
	char *src, *dst;

	p = argv;
	if (*p == 0)
		return 0;

	while (*p)
		len += strlen(*p++) + 1;

	buf = (char *)malloc(len);
	if (buf == NULL)
		error("copy_argv: malloc");

	p = argv;
	dst = buf;
	while ((src = *p++) != NULL) {
		while ((*dst++ = *src++) != '\0')
			;
		dst[-1] = ' ';
	}
	dst[-1] = '\0';

	return buf;
}
