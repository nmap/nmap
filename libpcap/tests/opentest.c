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

#ifndef lint
static const char copyright[] =
    "@(#) Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 2000\n\
The Regents of the University of California.  All rights reserved.\n";
#endif

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>

#define MAXIMUM_SNAPLEN		65535

static char *program_name;

/* Forwards */
static void usage(void) __attribute__((noreturn));
static void error(const char *, ...);
static void warning(const char *, ...);

extern int optind;
extern int opterr;
extern char *optarg;

int
main(int argc, char **argv)
{
	register int op;
	register char *cp, *device;
	int dorfmon, dopromisc, snaplen, useactivate, bufsize;
	char ebuf[PCAP_ERRBUF_SIZE];
	pcap_t *pd;
	int status = 0;

	device = NULL;
	dorfmon = 0;
	dopromisc = 0;
	snaplen = MAXIMUM_SNAPLEN;
	bufsize = 0;
	useactivate = 0;
	if ((cp = strrchr(argv[0], '/')) != NULL)
		program_name = cp + 1;
	else
		program_name = argv[0];

	opterr = 0;
	while ((op = getopt(argc, argv, "i:Ips:aB:")) != -1) {
		switch (op) {

		case 'i':
			device = optarg;
			break;

		case 'I':
			dorfmon = 1;
			useactivate = 1;	/* required for rfmon */
			break;

		case 'p':
			dopromisc = 1;
			break;

		case 's': {
			char *end;

			snaplen = strtol(optarg, &end, 0);
			if (optarg == end || *end != '\0'
			    || snaplen < 0 || snaplen > MAXIMUM_SNAPLEN)
				error("invalid snaplen %s", optarg);
			else if (snaplen == 0)
				snaplen = MAXIMUM_SNAPLEN;
			break;
		}

		case 'B':
			bufsize = atoi(optarg)*1024;
			if (bufsize <= 0)
				error("invalid packet buffer size %s", optarg);
			useactivate = 1;	/* required for bufsize */
			break;

		case 'a':
			useactivate = 1;
			break;

		default:
			usage();
			/* NOTREACHED */
		}
	}

	if (useactivate) {
		pd = pcap_create(device, ebuf);
		if (pd == NULL)
			error("%s", ebuf);
		status = pcap_set_snaplen(pd, snaplen);
		if (status != 0)
			error("%s: pcap_set_snaplen failed: %s",
			    device, pcap_statustostr(status));
		if (dopromisc) {
			status = pcap_set_promisc(pd, 1);
			if (status != 0)
				error("%s: pcap_set_promisc failed: %s",
				    device, pcap_statustostr(status));
		}
		if (dorfmon) {
			status = pcap_set_rfmon(pd, 1);
			if (status != 0)
				error("%s: pcap_set_rfmon failed: %s",
				    device, pcap_statustostr(status));
		}
		status = pcap_set_timeout(pd, 1000);
		if (status != 0)
			error("%s: pcap_set_timeout failed: %s",
			    device, pcap_statustostr(status));
		if (bufsize != 0) {
			status = pcap_set_buffer_size(pd, bufsize);
			if (status != 0)
				error("%s: pcap_set_buffer_size failed: %s",
				    device, pcap_statustostr(status));
		}
		status = pcap_activate(pd);
		if (status < 0) {
			/*
			 * pcap_activate() failed.
			 */
			error("%s: %s\n(%s)", device,
			    pcap_statustostr(status), pcap_geterr(pd));
		} else if (status > 0) {
			/*
			 * pcap_activate() succeeded, but it's warning us
			 * of a problem it had.
			 */
			warning("%s: %s\n(%s)", device,
			    pcap_statustostr(status), pcap_geterr(pd));
		}
	} else {
		*ebuf = '\0';
		pd = pcap_open_live(device, 65535, 0, 1000, ebuf);
		if (pd == NULL)
			error("%s", ebuf);
		else if (*ebuf)
			warning("%s", ebuf);
	}
	pcap_close(pd);
	exit(status < 0 ? 1 : 0);
}

static void
usage(void)
{
	(void)fprintf(stderr,
	    "Usage: %s [ -Ipa ] [ -i interface ] [ -s snaplen ] [ -B bufsize ]\n",
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
