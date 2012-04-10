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
#include <sys/types.h>
#include <sys/select.h>
#include <poll.h>

char *program_name;

/* Forwards */
static void countme(u_char *, const struct pcap_pkthdr *, const u_char *);
static void usage(void) __attribute__((noreturn));
static void error(const char *, ...);
static void warning(const char *, ...);
static char *copy_argv(char **);

static pcap_t *pd;

extern int optind;
extern int opterr;
extern char *optarg;

int
main(int argc, char **argv)
{
	register int op;
	bpf_u_int32 localnet, netmask;
	register char *cp, *cmdbuf, *device;
	struct bpf_program fcode;
	char ebuf[PCAP_ERRBUF_SIZE];
	int status;
	int packet_count;

	device = NULL;
	if ((cp = strrchr(argv[0], '/')) != NULL)
		program_name = cp + 1;
	else
		program_name = argv[0];

	opterr = 0;
	while ((op = getopt(argc, argv, "i:")) != -1) {
		switch (op) {

		case 'i':
			device = optarg;
			break;

		default:
			usage();
			/* NOTREACHED */
		}
	}

	if (device == NULL) {
		device = pcap_lookupdev(ebuf);
		if (device == NULL)
			error("%s", ebuf);
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
	if (pcap_setnonblock(pd, 1, ebuf) == -1)
		error("pcap_setnonblock failed: %s", ebuf);
	printf("Listening on %s\n", device);
	for (;;) {
		packet_count = 0;
		status = pcap_dispatch(pd, -1, countme,
		    (u_char *)&packet_count);
		if (status < 0)
			break;
		if (status != 0) {
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
countme(u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
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
