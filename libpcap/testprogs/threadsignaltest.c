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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#ifdef _WIN32
  #include <winsock2.h>
  #include <windows.h>

  #define THREAD_HANDLE			HANDLE
  #define THREAD_FUNC_ARG_TYPE		LPVOID
  #define THREAD_FUNC_RETURN_TYPE	DWORD __stdcall

  #include "getopt.h"
#else
  #include <pthread.h>
  #include <signal.h>
  #include <unistd.h>

  #define THREAD_HANDLE			pthread_t
  #define THREAD_FUNC_ARG_TYPE		void *
  #define THREAD_FUNC_RETURN_TYPE	void *
#endif
#include <errno.h>
#include <sys/types.h>

#include <pcap.h>

#include "pcap/funcattrs.h"

#ifdef _WIN32
  #include "portability.h"
#endif

static char *program_name;

/* Forwards */
static void countme(u_char *, const struct pcap_pkthdr *, const u_char *);
static void PCAP_NORETURN usage(void);
static void PCAP_NORETURN error(const char *, ...) PCAP_PRINTFLIKE(1, 2);
static void warning(const char *, ...) PCAP_PRINTFLIKE(1, 2);
static char *copy_argv(char **);

static pcap_t *pd;

#ifdef _WIN32
/*
 * Generate a string for a Win32-specific error (i.e. an error generated when
 * calling a Win32 API).
 * For errors occurred during standard C calls, we still use pcap_strerror()
 */
#define ERRBUF_SIZE	1024
static const char *
win32_strerror(DWORD error)
{
  static char errbuf[ERRBUF_SIZE+1];
  size_t errlen;

  FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, error, 0, errbuf,
                ERRBUF_SIZE, NULL);

  /*
   * "FormatMessage()" "helpfully" sticks CR/LF at the end of the
   * message.  Get rid of it.
   */
  errlen = strlen(errbuf);
  if (errlen >= 2) {
    errbuf[errlen - 1] = '\0';
    errbuf[errlen - 2] = '\0';
    errlen -= 2;
  }
  return errbuf;
}
#else
static void
catch_sigusr1(int sig _U_)
{
	printf("Got SIGUSR1\n");
}
#endif

static void
sleep_secs(int secs)
{
#ifdef _WIN32
	Sleep(secs*1000);
#else
	unsigned secs_remaining;

	if (secs <= 0)
		return;
	secs_remaining = secs;
	while (secs_remaining != 0)
		secs_remaining = sleep(secs_remaining);
#endif
}

static THREAD_FUNC_RETURN_TYPE
capture_thread_func(THREAD_FUNC_ARG_TYPE arg)
{
	char *device = arg;
	int packet_count;
	int status;
#ifndef _WIN32
	struct sigaction action;
	sigset_t mask;
#endif

#ifndef _WIN32
	sigemptyset(&mask);
	action.sa_handler = catch_sigusr1;
	action.sa_mask = mask;
	action.sa_flags = 0;
	if (sigaction(SIGUSR1, &action, NULL) == -1)
		error("Can't catch SIGUSR1: %s", strerror(errno));
#endif

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
		} else
			printf("No packets seen by pcap_dispatch\n");
	}
	if (status == -2) {
		/*
		 * We got interrupted, so perhaps we didn't
		 * manage to finish a line we were printing.
		 * Print an extra newline, just in case.
		 */
		putchar('\n');
		printf("Loop got broken\n");
	}
	(void)fflush(stdout);
	if (status == -1) {
		/*
		 * Error.  Report it.
		 */
		(void)fprintf(stderr, "%s: pcap_loop: %s\n",
		    program_name, pcap_geterr(pd));
	}
	return 0;
}

int
main(int argc, char **argv)
{
	register int op;
	register char *cp, *cmdbuf, *device;
	int immediate = 0;
	pcap_if_t *devlist;
	bpf_u_int32 localnet, netmask;
	struct bpf_program fcode;
	char ebuf[PCAP_ERRBUF_SIZE];
	int status;
	THREAD_HANDLE capture_thread;
#ifndef _WIN32
	void *retval;
#endif

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
		if (pcap_findalldevs(&devlist, ebuf) == -1)
			error("%s", ebuf);
		if (devlist == NULL)
			error("no interfaces available for capture");
		device = strdup(devlist->name);
		pcap_freealldevs(devlist);
	}
	*ebuf = '\0';
	pd = pcap_create(device, ebuf);
	if (pd == NULL)
		error("%s", ebuf);
	status = pcap_set_snaplen(pd, 65535);
	if (status != 0)
		error("%s: pcap_set_snaplen failed: %s",
			    device, pcap_statustostr(status));
	if (immediate) {
		status = pcap_set_immediate_mode(pd, 1);
		if (status != 0)
			error("%s: pcap_set_immediate_mode failed: %s",
			    device, pcap_statustostr(status));
	}
	status = pcap_set_timeout(pd, 5*60*1000);
	if (status != 0)
		error("%s: pcap_set_timeout failed: %s",
		    device, pcap_statustostr(status));
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

#ifdef _WIN32
	capture_thread = CreateThread(NULL, 0, capture_thread_func, device,
	    0, NULL);
	if (capture_thread == NULL)
		error("Can't create capture thread: %s",
		    win32_strerror(GetLastError()));
#else
	status = pthread_create(&capture_thread, NULL, capture_thread_func,
	    device);
	if (status != 0)
		error("Can't create capture thread: %s", strerror(status));
#endif
	sleep_secs(60);
	pcap_breakloop(pd);
#ifdef _WIN32
	printf("Setting event\n");
	if (!SetEvent(pcap_getevent(pd)))
		error("Can't set event for pcap_t: %s",
		    win32_strerror(GetLastError()));
	if (WaitForSingleObject(capture_thread, INFINITE) == WAIT_FAILED)
		error("Wait for thread termination failed: %s",
		    win32_strerror(GetLastError()));
	CloseHandle(capture_thread);
#else
	printf("Sending SIGUSR1\n");
	status = pthread_kill(capture_thread, SIGUSR1);
	if (status != 0)
		warning("Can't interrupt capture thread: %s", strerror(status));
	status = pthread_join(capture_thread, &retval);
	if (status != 0)
		error("Wait for thread termination failed: %s",
		    strerror(status));
#endif

	pcap_close(pd);
	pcap_freecode(&fcode);
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
	(void)fprintf(stderr, "Usage: %s [ -m ] [ -i interface ] [ -t timeout] [expression]\n",
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
