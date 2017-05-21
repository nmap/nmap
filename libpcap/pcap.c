/*
 * Copyright (c) 1993, 1994, 1995, 1996, 1997, 1998
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef WIN32
#include <pcap-stdinc.h>
#else /* WIN32 */
#if HAVE_INTTYPES_H
#include <inttypes.h>
#elif HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_SYS_BITYPES_H
#include <sys/bitypes.h>
#endif
#include <sys/types.h>
#endif /* WIN32 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_MSC_VER) && !defined(__BORLANDC__) && !defined(__MINGW32__)
#include <unistd.h>
#endif
#include <fcntl.h>
#include <errno.h>

#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

#ifdef MSDOS
#include "pcap-dos.h"
#endif

#include "pcap-int.h"

#ifdef HAVE_DAG_API
#include "pcap-dag.h"
#endif /* HAVE_DAG_API */

#ifdef HAVE_SEPTEL_API
#include "pcap-septel.h"
#endif /* HAVE_SEPTEL_API */

#ifdef HAVE_SNF_API
#include "pcap-snf.h"
#endif /* HAVE_SNF_API */

#ifdef PCAP_SUPPORT_USB
#include "pcap-usb-linux.h"
#endif

#ifdef PCAP_SUPPORT_BT
#include "pcap-bt-linux.h"
#endif

#ifdef PCAP_SUPPORT_BT_MONITOR
#include "pcap-bt-monitor-linux.h"
#endif

#ifdef PCAP_SUPPORT_CAN
#include "pcap-can-linux.h"
#endif

#ifdef PCAP_SUPPORT_CANUSB
#include "pcap-canusb-linux.h"
#endif

#ifdef PCAP_SUPPORT_NETFILTER
#include "pcap-netfilter-linux.h"
#endif

#ifdef PCAP_SUPPORT_DBUS
#include "pcap-dbus.h"
#endif

int
pcap_not_initialized(pcap_t *pcap _U_)
{
	/* this means 'not initialized' */
	return (PCAP_ERROR_NOT_ACTIVATED);
}

#ifdef WIN32
Adapter *
pcap_no_adapter(pcap_t *pcap _U_)
{
	return (NULL);
}
#endif

/*
 * Returns 1 if rfmon mode can be set on the pcap_t, 0 if it can't,
 * a PCAP_ERROR value on an error.
 */
int
pcap_can_set_rfmon(pcap_t *p)
{
	return (p->can_set_rfmon_op(p));
}

/*
 * For systems where rfmon mode is never supported.
 */
static int
pcap_cant_set_rfmon(pcap_t *p _U_)
{
	return (0);
}

/*
 * Sets *tstamp_typesp to point to an array 1 or more supported time stamp
 * types; the return value is the number of supported time stamp types.
 * The list should be freed by a call to pcap_free_tstamp_types() when
 * you're done with it.
 *
 * A return value of 0 means "you don't get a choice of time stamp type",
 * in which case *tstamp_typesp is set to null.
 *
 * PCAP_ERROR is returned on error.
 */
int
pcap_list_tstamp_types(pcap_t *p, int **tstamp_typesp)
{
	if (p->tstamp_type_count == 0) {
		/*
		 * We don't support multiple time stamp types.
		 */
		*tstamp_typesp = NULL;
	} else {
		*tstamp_typesp = (int*)calloc(sizeof(**tstamp_typesp),
		    p->tstamp_type_count);
		if (*tstamp_typesp == NULL) {
			(void)snprintf(p->errbuf, sizeof(p->errbuf),
			    "malloc: %s", pcap_strerror(errno));
			return (PCAP_ERROR);
		}
		(void)memcpy(*tstamp_typesp, p->tstamp_type_list,
		    sizeof(**tstamp_typesp) * p->tstamp_type_count);
	}
	return (p->tstamp_type_count);
}

/*
 * In Windows, you might have a library built with one version of the
 * C runtime library and an application built with another version of
 * the C runtime library, which means that the library might use one
 * version of malloc() and free() and the application might use another
 * version of malloc() and free().  If so, that means something
 * allocated by the library cannot be freed by the application, so we
 * need to have a pcap_free_tstamp_types() routine to free up the list
 * allocated by pcap_list_tstamp_types(), even though it's just a wrapper
 * around free().
 */
void
pcap_free_tstamp_types(int *tstamp_type_list)
{
	free(tstamp_type_list);
}

/*
 * Default one-shot callback; overridden for capture types where the
 * packet data cannot be guaranteed to be available after the callback
 * returns, so that a copy must be made.
 */
void
pcap_oneshot(u_char *user, const struct pcap_pkthdr *h, const u_char *pkt)
{
	struct oneshot_userdata *sp = (struct oneshot_userdata *)user;

	*sp->hdr = *h;
	*sp->pkt = pkt;
}

const u_char *
pcap_next(pcap_t *p, struct pcap_pkthdr *h)
{
	struct oneshot_userdata s;
	const u_char *pkt;

	s.hdr = h;
	s.pkt = &pkt;
	s.pd = p;
	if (pcap_dispatch(p, 1, p->oneshot_callback, (u_char *)&s) <= 0)
		return (0);
	return (pkt);
}

int
pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header,
    const u_char **pkt_data)
{
	struct oneshot_userdata s;

	s.hdr = &p->pcap_header;
	s.pkt = pkt_data;
	s.pd = p;

	/* Saves a pointer to the packet headers */
	*pkt_header= &p->pcap_header;

	if (p->rfile != NULL) {
		int status;

		/* We are on an offline capture */
		status = pcap_offline_read(p, 1, p->oneshot_callback,
		    (u_char *)&s);

		/*
		 * Return codes for pcap_offline_read() are:
		 *   -  0: EOF
		 *   - -1: error
		 *   - >1: OK
		 * The first one ('0') conflicts with the return code of
		 * 0 from pcap_read() meaning "no packets arrived before
		 * the timeout expired", so we map it to -2 so you can
		 * distinguish between an EOF from a savefile and a
		 * "no packets arrived before the timeout expired, try
		 * again" from a live capture.
		 */
		if (status == 0)
			return (-2);
		else
			return (status);
	}

	/*
	 * Return codes for pcap_read() are:
	 *   -  0: timeout
	 *   - -1: error
	 *   - -2: loop was broken out of with pcap_breakloop()
	 *   - >1: OK
	 * The first one ('0') conflicts with the return code of 0 from
	 * pcap_offline_read() meaning "end of file".
	*/
	return (p->read_op(p, 1, p->oneshot_callback, (u_char *)&s));
}

#if defined(DAG_ONLY)
int
pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf)
{
	return (dag_findalldevs(alldevsp, errbuf));
}

pcap_t *
pcap_create(const char *source, char *errbuf)
{
	int is_ours;
	return (dag_create(source, errbuf, &is_ours));
}
#elif defined(SEPTEL_ONLY)
int
pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf)
{
	return (septel_findalldevs(alldevsp, errbuf));
}

pcap_t *
pcap_create(const char *source, char *errbuf)
{
	int is_ours;
	return (septel_create(source, errbuf, &is_ours));
}
#elif defined(SNF_ONLY)
int
pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf)
{
	return (snf_findalldevs(alldevsp, errbuf));
}

pcap_t *
pcap_create(const char *source, char *errbuf)
{
	int is_ours;
	return (snf_create(source, errbuf, &is_ours));
}
#else /* regular pcap */
struct capture_source_type {
	int (*findalldevs_op)(pcap_if_t **, char *);
	pcap_t *(*create_op)(const char *, char *, int *);
} capture_source_types[] = {
#ifdef HAVE_DAG_API
	{ dag_findalldevs, dag_create },
#endif
#ifdef HAVE_SEPTEL_API
	{ septel_findalldevs, septel_create },
#endif
#ifdef HAVE_SNF_API
	{ snf_findalldevs, snf_create },
#endif
#ifdef PCAP_SUPPORT_BT
	{ bt_findalldevs, bt_create },
#endif
#ifdef PCAP_SUPPORT_BT_MONITOR
	{ bt_monitor_findalldevs, bt_monitor_create },
#endif
#if PCAP_SUPPORT_CANUSB
	{ canusb_findalldevs, canusb_create },
#endif
#ifdef PCAP_SUPPORT_CAN
	{ can_findalldevs, can_create },
#endif
#ifdef PCAP_SUPPORT_USB
	{ usb_findalldevs, usb_create },
#endif
#ifdef PCAP_SUPPORT_NETFILTER
	{ netfilter_findalldevs, netfilter_create },
#endif
#ifdef PCAP_SUPPORT_DBUS
	{ dbus_findalldevs, dbus_create },
#endif
	{ NULL, NULL }
};

/*
 * Get a list of all capture sources that are up and that we can open.
 * Returns -1 on error, 0 otherwise.
 * The list, as returned through "alldevsp", may be null if no interfaces
 * were up and could be opened.
 */
int
pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf)
{
	size_t i;

	/*
	 * Get the list of regular interfaces first.
	 */
	if (pcap_findalldevs_interfaces(alldevsp, errbuf) == -1)
		return (-1);	/* failure */

	/*
	 * Add any interfaces that need a platform-specific mechanism
	 * to find.
	 */
	if (pcap_platform_finddevs(alldevsp, errbuf) == -1) {
		/*
		 * We had an error; free the list we've been
		 * constructing.
		 */
		if (*alldevsp != NULL) {
			pcap_freealldevs(*alldevsp);
			*alldevsp = NULL;
		}
		return (-1);
	}

	/*
	 * Ask each of the non-local-network-interface capture
	 * source types what interfaces they have.
	 */
	for (i = 0; capture_source_types[i].findalldevs_op != NULL; i++) {
		if (capture_source_types[i].findalldevs_op(alldevsp, errbuf) == -1) {
			/*
			 * We had an error; free the list we've been
			 * constructing.
			 */
			if (*alldevsp != NULL) {
				pcap_freealldevs(*alldevsp);
				*alldevsp = NULL;
			}
			return (-1);
		}
	}

	return (0);
}

pcap_t *
pcap_create(const char *source, char *errbuf)
{
	size_t i;
	int is_theirs;
	pcap_t *p;

	/*
	 * A null source name is equivalent to the "any" device -
	 * which might not be supported on this platform, but
	 * this means that you'll get a "not supported" error
	 * rather than, say, a crash when we try to dereference
	 * the null pointer.
	 */
	if (source == NULL)
		source = "any";

	/*
	 * Try each of the non-local-network-interface capture
	 * source types until we find one that works for this
	 * device or run out of types.
	 */
	for (i = 0; capture_source_types[i].create_op != NULL; i++) {
		is_theirs = 0;
		p = capture_source_types[i].create_op(source, errbuf, &is_theirs);
		if (is_theirs) {
			/*
			 * The device name refers to a device of the
			 * type in question; either it succeeded,
			 * in which case p refers to a pcap_t to
			 * later activate for the device, or it
			 * failed, in which case p is null and we
			 * should return that to report the failure
			 * to create.
			 */
			return (p);
		}
	}

	/*
	 * OK, try it as a regular network interface.
	 */
	return (pcap_create_interface(source, errbuf));
}
#endif

static void
initialize_ops(pcap_t *p)
{
	/*
	 * Set operation pointers for operations that only work on
	 * an activated pcap_t to point to a routine that returns
	 * a "this isn't activated" error.
	 */
	p->read_op = (read_op_t)pcap_not_initialized;
	p->inject_op = (inject_op_t)pcap_not_initialized;
	p->setfilter_op = (setfilter_op_t)pcap_not_initialized;
	p->setdirection_op = (setdirection_op_t)pcap_not_initialized;
	p->set_datalink_op = (set_datalink_op_t)pcap_not_initialized;
	p->getnonblock_op = (getnonblock_op_t)pcap_not_initialized;
	p->setnonblock_op = (setnonblock_op_t)pcap_not_initialized;
	p->stats_op = (stats_op_t)pcap_not_initialized;
#ifdef WIN32
	p->setbuff_op = (setbuff_op_t)pcap_not_initialized;
	p->setmode_op = (setmode_op_t)pcap_not_initialized;
	p->setmintocopy_op = (setmintocopy_op_t)pcap_not_initialized;
	p->getadapter_op = pcap_no_adapter;
#endif

	/*
	 * Default cleanup operation - implementations can override
	 * this, but should call pcap_cleanup_live_common() after
	 * doing their own additional cleanup.
	 */
	p->cleanup_op = pcap_cleanup_live_common;

	/*
	 * In most cases, the standard one-shot callback can
	 * be used for pcap_next()/pcap_next_ex().
	 */
	p->oneshot_callback = pcap_oneshot;
}

static pcap_t *
pcap_alloc_pcap_t(char *ebuf, size_t size)
{
	char *chunk;
	pcap_t *p;

	/*
	 * Allocate a chunk of memory big enough for a pcap_t
	 * plus a structure following it of size "size".  The
	 * structure following it is a private data structure
	 * for the routines that handle this pcap_t.
	 */
	chunk = malloc(sizeof (pcap_t) + size);
	if (chunk == NULL) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "malloc: %s",
		    pcap_strerror(errno));
		return (NULL);
	}
	memset(chunk, 0, sizeof (pcap_t) + size);

	/*
	 * Get a pointer to the pcap_t at the beginning.
	 */
	p = (pcap_t *)chunk;

#ifndef WIN32
	p->fd = -1;	/* not opened yet */
	p->selectable_fd = -1;
#endif

	if (size == 0) {
		/* No private data was requested. */
		p->priv = NULL;
	} else {
		/*
		 * Set the pointer to the private data; that's the structure
		 * of size "size" following the pcap_t.
		 */
		p->priv = (void *)(chunk + sizeof (pcap_t));
	}

	return (p);
}

pcap_t *
pcap_create_common(const char *source, char *ebuf, size_t size)
{
	pcap_t *p;

	p = pcap_alloc_pcap_t(ebuf, size);
	if (p == NULL)
		return (NULL);

	p->opt.source = strdup(source);
	if (p->opt.source == NULL) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "malloc: %s",
		    pcap_strerror(errno));
		free(p);
		return (NULL);
	}

	/*
	 * Default to "can't set rfmon mode"; if it's supported by
	 * a platform, the create routine that called us can set
	 * the op to its routine to check whether a particular
	 * device supports it.
	 */
	p->can_set_rfmon_op = pcap_cant_set_rfmon;

	initialize_ops(p);

	/* put in some defaults*/
 	pcap_set_snaplen(p, MAXIMUM_SNAPLEN);	/* max packet size */
	p->opt.timeout = 0;			/* no timeout specified */
	p->opt.buffer_size = 0;			/* use the platform's default */
	p->opt.promisc = 0;
	p->opt.rfmon = 0;
	p->opt.immediate = 0;
	p->opt.tstamp_type = -1;	/* default to not setting time stamp type */
	p->opt.tstamp_precision = PCAP_TSTAMP_PRECISION_MICRO;

	/*
	 * Start out with no BPF code generation flags set.
	 */
	p->bpf_codegen_flags = 0;

	return (p);
}

int
pcap_check_activated(pcap_t *p)
{
	if (p->activated) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "can't perform "
			" operation on activated capture");
		return (-1);
	}
	return (0);
}

int
pcap_set_snaplen(pcap_t *p, int snaplen)
{
	if (pcap_check_activated(p))
		return (PCAP_ERROR_ACTIVATED);
	p->snapshot = snaplen;
	return (0);
}

int
pcap_set_promisc(pcap_t *p, int promisc)
{
	if (pcap_check_activated(p))
		return (PCAP_ERROR_ACTIVATED);
	p->opt.promisc = promisc;
	return (0);
}

int
pcap_set_rfmon(pcap_t *p, int rfmon)
{
	if (pcap_check_activated(p))
		return (PCAP_ERROR_ACTIVATED);
	p->opt.rfmon = rfmon;
	return (0);
}

int
pcap_set_timeout(pcap_t *p, int timeout_ms)
{
	if (pcap_check_activated(p))
		return (PCAP_ERROR_ACTIVATED);
	p->opt.timeout = timeout_ms;
	return (0);
}

int
pcap_set_tstamp_type(pcap_t *p, int tstamp_type)
{
	int i;

	if (pcap_check_activated(p))
		return (PCAP_ERROR_ACTIVATED);

	/*
	 * If p->tstamp_type_count is 0, we only support PCAP_TSTAMP_HOST;
	 * the default time stamp type is PCAP_TSTAMP_HOST.
	 */
	if (p->tstamp_type_count == 0) {
		if (tstamp_type == PCAP_TSTAMP_HOST) {
			p->opt.tstamp_type = tstamp_type;
			return (0);
		}
	} else {
		/*
		 * Check whether we claim to support this type of time stamp.
		 */
		for (i = 0; i < p->tstamp_type_count; i++) {
			if (p->tstamp_type_list[i] == tstamp_type) {
				/*
				 * Yes.
				 */
				p->opt.tstamp_type = tstamp_type;
				return (0);
			}
		}
	}

	/*
	 * We don't support this type of time stamp.
	 */
	return (PCAP_WARNING_TSTAMP_TYPE_NOTSUP);
}

int
pcap_set_immediate_mode(pcap_t *p, int immediate)
{
	if (pcap_check_activated(p))
		return (PCAP_ERROR_ACTIVATED);
	p->opt.immediate = immediate;
	return (0);
}

int
pcap_set_buffer_size(pcap_t *p, int buffer_size)
{
	if (pcap_check_activated(p))
		return (PCAP_ERROR_ACTIVATED);
	p->opt.buffer_size = buffer_size;
	return (0);
}

int
pcap_set_tstamp_precision(pcap_t *p, int tstamp_precision)
{
	int i;

	if (pcap_check_activated(p))
		return (PCAP_ERROR_ACTIVATED);

	/*
	 * If p->tstamp_precision_count is 0, we only support setting
	 * the time stamp precision to microsecond precision; every
	 * pcap module *MUST* support microsecond precision, even if
	 * it does so by converting the native precision to
	 * microseconds.
	 */
	if (p->tstamp_precision_count == 0) {
		if (tstamp_precision == PCAP_TSTAMP_PRECISION_MICRO) {
			p->opt.tstamp_precision = tstamp_precision;
			return (0);
		}
	} else {
		/*
		 * Check whether we claim to support this precision of
		 * time stamp.
		 */
		for (i = 0; i < p->tstamp_precision_count; i++) {
			if (p->tstamp_precision_list[i] == tstamp_precision) {
				/*
				 * Yes.
				 */
				p->opt.tstamp_precision = tstamp_precision;
				return (0);
			}
		}
	}

	/*
	 * We don't support this time stamp precision.
	 */
	return (PCAP_ERROR_TSTAMP_PRECISION_NOTSUP);
}

int
pcap_get_tstamp_precision(pcap_t *p)
{
        return (p->opt.tstamp_precision);
}

int
pcap_activate(pcap_t *p)
{
	int status;

	/*
	 * Catch attempts to re-activate an already-activated
	 * pcap_t; this should, for example, catch code that
	 * calls pcap_open_live() followed by pcap_activate(),
	 * as some code that showed up in a Stack Exchange
	 * question did.
	 */
	if (pcap_check_activated(p))
		return (PCAP_ERROR_ACTIVATED);
	status = p->activate_op(p);
	if (status >= 0)
		p->activated = 1;
	else {
		if (p->errbuf[0] == '\0') {
			/*
			 * No error message supplied by the activate routine;
			 * for the benefit of programs that don't specially
			 * handle errors other than PCAP_ERROR, return the
			 * error message corresponding to the status.
			 */
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "%s",
			    pcap_statustostr(status));
		}

		/*
		 * Undo any operation pointer setting, etc. done by
		 * the activate operation.
		 */
		initialize_ops(p);
	}
	return (status);
}

pcap_t *
pcap_open_live(const char *source, int snaplen, int promisc, int to_ms, char *errbuf)
{
	pcap_t *p;
	int status;

	p = pcap_create(source, errbuf);
	if (p == NULL)
		return (NULL);
	status = pcap_set_snaplen(p, snaplen);
	if (status < 0)
		goto fail;
	status = pcap_set_promisc(p, promisc);
	if (status < 0)
		goto fail;
	status = pcap_set_timeout(p, to_ms);
	if (status < 0)
		goto fail;
	/*
	 * Mark this as opened with pcap_open_live(), so that, for
	 * example, we show the full list of DLT_ values, rather
	 * than just the ones that are compatible with capturing
	 * when not in monitor mode.  That allows existing applications
	 * to work the way they used to work, but allows new applications
	 * that know about the new open API to, for example, find out the
	 * DLT_ values that they can select without changing whether
	 * the adapter is in monitor mode or not.
	 */
	p->oldstyle = 1;
	status = pcap_activate(p);
	if (status < 0)
		goto fail;
	return (p);
fail:
	if (status == PCAP_ERROR)
		snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: %s", source,
		    p->errbuf);
	else if (status == PCAP_ERROR_NO_SUCH_DEVICE ||
	    status == PCAP_ERROR_PERM_DENIED ||
	    status == PCAP_ERROR_PROMISC_PERM_DENIED)
		snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: %s (%s)", source,
		    pcap_statustostr(status), p->errbuf);
	else
		snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: %s", source,
		    pcap_statustostr(status));
	pcap_close(p);
	return (NULL);
}

pcap_t *
pcap_open_offline_common(char *ebuf, size_t size)
{
	pcap_t *p;

	p = pcap_alloc_pcap_t(ebuf, size);
	if (p == NULL)
		return (NULL);

	p->opt.tstamp_precision = PCAP_TSTAMP_PRECISION_MICRO;
	p->opt.source = strdup("(savefile)");
	if (p->opt.source == NULL) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "malloc: %s",
		    pcap_strerror(errno));
		free(p);
		return (NULL);
	}

	return (p);
}

int
pcap_dispatch(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
{
	return (p->read_op(p, cnt, callback, user));
}

/*
 * XXX - is this necessary?
 */
int
pcap_read(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
{

	return (p->read_op(p, cnt, callback, user));
}

int
pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
{
	register int n;

	for (;;) {
		if (p->rfile != NULL) {
			/*
			 * 0 means EOF, so don't loop if we get 0.
			 */
			n = pcap_offline_read(p, cnt, callback, user);
		} else {
			/*
			 * XXX keep reading until we get something
			 * (or an error occurs)
			 */
			do {
				n = p->read_op(p, cnt, callback, user);
			} while (n == 0);
		}
		if (n <= 0)
			return (n);
		if (!PACKET_COUNT_IS_UNLIMITED(cnt)) {
			cnt -= n;
			if (cnt <= 0)
				return (0);
		}
	}
}

/*
 * Force the loop in "pcap_read()" or "pcap_read_offline()" to terminate.
 */
void
pcap_breakloop(pcap_t *p)
{
	p->break_loop = 1;
}

int
pcap_datalink(pcap_t *p)
{
	if (!p->activated)
		return (PCAP_ERROR_NOT_ACTIVATED);
	return (p->linktype);
}

int
pcap_datalink_ext(pcap_t *p)
{
	if (!p->activated)
		return (PCAP_ERROR_NOT_ACTIVATED);
	return (p->linktype_ext);
}

int
pcap_list_datalinks(pcap_t *p, int **dlt_buffer)
{
	if (!p->activated)
		return (PCAP_ERROR_NOT_ACTIVATED);
	if (p->dlt_count == 0) {
		/*
		 * We couldn't fetch the list of DLTs, which means
		 * this platform doesn't support changing the
		 * DLT for an interface.  Return a list of DLTs
		 * containing only the DLT this device supports.
		 */
		*dlt_buffer = (int*)malloc(sizeof(**dlt_buffer));
		if (*dlt_buffer == NULL) {
			(void)snprintf(p->errbuf, sizeof(p->errbuf),
			    "malloc: %s", pcap_strerror(errno));
			return (PCAP_ERROR);
		}
		**dlt_buffer = p->linktype;
		return (1);
	} else {
		*dlt_buffer = (int*)calloc(sizeof(**dlt_buffer), p->dlt_count);
		if (*dlt_buffer == NULL) {
			(void)snprintf(p->errbuf, sizeof(p->errbuf),
			    "malloc: %s", pcap_strerror(errno));
			return (PCAP_ERROR);
		}
		(void)memcpy(*dlt_buffer, p->dlt_list,
		    sizeof(**dlt_buffer) * p->dlt_count);
		return (p->dlt_count);
	}
}

/*
 * In Windows, you might have a library built with one version of the
 * C runtime library and an application built with another version of
 * the C runtime library, which means that the library might use one
 * version of malloc() and free() and the application might use another
 * version of malloc() and free().  If so, that means something
 * allocated by the library cannot be freed by the application, so we
 * need to have a pcap_free_datalinks() routine to free up the list
 * allocated by pcap_list_datalinks(), even though it's just a wrapper
 * around free().
 */
void
pcap_free_datalinks(int *dlt_list)
{
	free(dlt_list);
}

int
pcap_set_datalink(pcap_t *p, int dlt)
{
	int i;
	const char *dlt_name;

	if (p->dlt_count == 0 || p->set_datalink_op == NULL) {
		/*
		 * We couldn't fetch the list of DLTs, or we don't
		 * have a "set datalink" operation, which means
		 * this platform doesn't support changing the
		 * DLT for an interface.  Check whether the new
		 * DLT is the one this interface supports.
		 */
		if (p->linktype != dlt)
			goto unsupported;

		/*
		 * It is, so there's nothing we need to do here.
		 */
		return (0);
	}
	for (i = 0; i < p->dlt_count; i++)
		if (p->dlt_list[i] == dlt)
			break;
	if (i >= p->dlt_count)
		goto unsupported;
	if (p->dlt_count == 2 && p->dlt_list[0] == DLT_EN10MB &&
	    dlt == DLT_DOCSIS) {
		/*
		 * This is presumably an Ethernet device, as the first
		 * link-layer type it offers is DLT_EN10MB, and the only
		 * other type it offers is DLT_DOCSIS.  That means that
		 * we can't tell the driver to supply DOCSIS link-layer
		 * headers - we're just pretending that's what we're
		 * getting, as, presumably, we're capturing on a dedicated
		 * link to a Cisco Cable Modem Termination System, and
		 * it's putting raw DOCSIS frames on the wire inside low-level
		 * Ethernet framing.
		 */
		p->linktype = dlt;
		return (0);
	}
	if (p->set_datalink_op(p, dlt) == -1)
		return (-1);
	p->linktype = dlt;
	return (0);

unsupported:
	dlt_name = pcap_datalink_val_to_name(dlt);
	if (dlt_name != NULL) {
		(void) snprintf(p->errbuf, sizeof(p->errbuf),
		    "%s is not one of the DLTs supported by this device",
		    dlt_name);
	} else {
		(void) snprintf(p->errbuf, sizeof(p->errbuf),
		    "DLT %d is not one of the DLTs supported by this device",
		    dlt);
	}
	return (-1);
}

/*
 * This array is designed for mapping upper and lower case letter
 * together for a case independent comparison.  The mappings are
 * based upon ascii character sequences.
 */
static const u_char charmap[] = {
	(u_char)'\000', (u_char)'\001', (u_char)'\002', (u_char)'\003',
	(u_char)'\004', (u_char)'\005', (u_char)'\006', (u_char)'\007',
	(u_char)'\010', (u_char)'\011', (u_char)'\012', (u_char)'\013',
	(u_char)'\014', (u_char)'\015', (u_char)'\016', (u_char)'\017',
	(u_char)'\020', (u_char)'\021', (u_char)'\022', (u_char)'\023',
	(u_char)'\024', (u_char)'\025', (u_char)'\026', (u_char)'\027',
	(u_char)'\030', (u_char)'\031', (u_char)'\032', (u_char)'\033',
	(u_char)'\034', (u_char)'\035', (u_char)'\036', (u_char)'\037',
	(u_char)'\040', (u_char)'\041', (u_char)'\042', (u_char)'\043',
	(u_char)'\044', (u_char)'\045', (u_char)'\046', (u_char)'\047',
	(u_char)'\050', (u_char)'\051', (u_char)'\052', (u_char)'\053',
	(u_char)'\054', (u_char)'\055', (u_char)'\056', (u_char)'\057',
	(u_char)'\060', (u_char)'\061', (u_char)'\062', (u_char)'\063',
	(u_char)'\064', (u_char)'\065', (u_char)'\066', (u_char)'\067',
	(u_char)'\070', (u_char)'\071', (u_char)'\072', (u_char)'\073',
	(u_char)'\074', (u_char)'\075', (u_char)'\076', (u_char)'\077',
	(u_char)'\100', (u_char)'\141', (u_char)'\142', (u_char)'\143',
	(u_char)'\144', (u_char)'\145', (u_char)'\146', (u_char)'\147',
	(u_char)'\150', (u_char)'\151', (u_char)'\152', (u_char)'\153',
	(u_char)'\154', (u_char)'\155', (u_char)'\156', (u_char)'\157',
	(u_char)'\160', (u_char)'\161', (u_char)'\162', (u_char)'\163',
	(u_char)'\164', (u_char)'\165', (u_char)'\166', (u_char)'\167',
	(u_char)'\170', (u_char)'\171', (u_char)'\172', (u_char)'\133',
	(u_char)'\134', (u_char)'\135', (u_char)'\136', (u_char)'\137',
	(u_char)'\140', (u_char)'\141', (u_char)'\142', (u_char)'\143',
	(u_char)'\144', (u_char)'\145', (u_char)'\146', (u_char)'\147',
	(u_char)'\150', (u_char)'\151', (u_char)'\152', (u_char)'\153',
	(u_char)'\154', (u_char)'\155', (u_char)'\156', (u_char)'\157',
	(u_char)'\160', (u_char)'\161', (u_char)'\162', (u_char)'\163',
	(u_char)'\164', (u_char)'\165', (u_char)'\166', (u_char)'\167',
	(u_char)'\170', (u_char)'\171', (u_char)'\172', (u_char)'\173',
	(u_char)'\174', (u_char)'\175', (u_char)'\176', (u_char)'\177',
	(u_char)'\200', (u_char)'\201', (u_char)'\202', (u_char)'\203',
	(u_char)'\204', (u_char)'\205', (u_char)'\206', (u_char)'\207',
	(u_char)'\210', (u_char)'\211', (u_char)'\212', (u_char)'\213',
	(u_char)'\214', (u_char)'\215', (u_char)'\216', (u_char)'\217',
	(u_char)'\220', (u_char)'\221', (u_char)'\222', (u_char)'\223',
	(u_char)'\224', (u_char)'\225', (u_char)'\226', (u_char)'\227',
	(u_char)'\230', (u_char)'\231', (u_char)'\232', (u_char)'\233',
	(u_char)'\234', (u_char)'\235', (u_char)'\236', (u_char)'\237',
	(u_char)'\240', (u_char)'\241', (u_char)'\242', (u_char)'\243',
	(u_char)'\244', (u_char)'\245', (u_char)'\246', (u_char)'\247',
	(u_char)'\250', (u_char)'\251', (u_char)'\252', (u_char)'\253',
	(u_char)'\254', (u_char)'\255', (u_char)'\256', (u_char)'\257',
	(u_char)'\260', (u_char)'\261', (u_char)'\262', (u_char)'\263',
	(u_char)'\264', (u_char)'\265', (u_char)'\266', (u_char)'\267',
	(u_char)'\270', (u_char)'\271', (u_char)'\272', (u_char)'\273',
	(u_char)'\274', (u_char)'\275', (u_char)'\276', (u_char)'\277',
	(u_char)'\300', (u_char)'\341', (u_char)'\342', (u_char)'\343',
	(u_char)'\344', (u_char)'\345', (u_char)'\346', (u_char)'\347',
	(u_char)'\350', (u_char)'\351', (u_char)'\352', (u_char)'\353',
	(u_char)'\354', (u_char)'\355', (u_char)'\356', (u_char)'\357',
	(u_char)'\360', (u_char)'\361', (u_char)'\362', (u_char)'\363',
	(u_char)'\364', (u_char)'\365', (u_char)'\366', (u_char)'\367',
	(u_char)'\370', (u_char)'\371', (u_char)'\372', (u_char)'\333',
	(u_char)'\334', (u_char)'\335', (u_char)'\336', (u_char)'\337',
	(u_char)'\340', (u_char)'\341', (u_char)'\342', (u_char)'\343',
	(u_char)'\344', (u_char)'\345', (u_char)'\346', (u_char)'\347',
	(u_char)'\350', (u_char)'\351', (u_char)'\352', (u_char)'\353',
	(u_char)'\354', (u_char)'\355', (u_char)'\356', (u_char)'\357',
	(u_char)'\360', (u_char)'\361', (u_char)'\362', (u_char)'\363',
	(u_char)'\364', (u_char)'\365', (u_char)'\366', (u_char)'\367',
	(u_char)'\370', (u_char)'\371', (u_char)'\372', (u_char)'\373',
	(u_char)'\374', (u_char)'\375', (u_char)'\376', (u_char)'\377',
};

int
pcap_strcasecmp(const char *s1, const char *s2)
{
	register const u_char	*cm = charmap,
				*us1 = (const u_char *)s1,
				*us2 = (const u_char *)s2;

	while (cm[*us1] == cm[*us2++])
		if (*us1++ == '\0')
			return(0);
	return (cm[*us1] - cm[*--us2]);
}

struct dlt_choice {
	const char *name;
	const char *description;
	int	dlt;
};

#define DLT_CHOICE(code, description) { #code, description, code }
#define DLT_CHOICE_SENTINEL { NULL, NULL, 0 }

static struct dlt_choice dlt_choices[] = {
	DLT_CHOICE(DLT_NULL, "BSD loopback"),
	DLT_CHOICE(DLT_EN10MB, "Ethernet"),
	DLT_CHOICE(DLT_IEEE802, "Token ring"),
	DLT_CHOICE(DLT_ARCNET, "BSD ARCNET"),
	DLT_CHOICE(DLT_SLIP, "SLIP"),
	DLT_CHOICE(DLT_PPP, "PPP"),
	DLT_CHOICE(DLT_FDDI, "FDDI"),
	DLT_CHOICE(DLT_ATM_RFC1483, "RFC 1483 LLC-encapsulated ATM"),
	DLT_CHOICE(DLT_RAW, "Raw IP"),
	DLT_CHOICE(DLT_SLIP_BSDOS, "BSD/OS SLIP"),
	DLT_CHOICE(DLT_PPP_BSDOS, "BSD/OS PPP"),
	DLT_CHOICE(DLT_ATM_CLIP, "Linux Classical IP-over-ATM"),
	DLT_CHOICE(DLT_PPP_SERIAL, "PPP over serial"),
	DLT_CHOICE(DLT_PPP_ETHER, "PPPoE"),
        DLT_CHOICE(DLT_SYMANTEC_FIREWALL, "Symantec Firewall"),
	DLT_CHOICE(DLT_C_HDLC, "Cisco HDLC"),
	DLT_CHOICE(DLT_IEEE802_11, "802.11"),
	DLT_CHOICE(DLT_FRELAY, "Frame Relay"),
	DLT_CHOICE(DLT_LOOP, "OpenBSD loopback"),
	DLT_CHOICE(DLT_ENC, "OpenBSD encapsulated IP"),
	DLT_CHOICE(DLT_LINUX_SLL, "Linux cooked"),
	DLT_CHOICE(DLT_LTALK, "Localtalk"),
	DLT_CHOICE(DLT_PFLOG, "OpenBSD pflog file"),
	DLT_CHOICE(DLT_PFSYNC, "Packet filter state syncing"),
	DLT_CHOICE(DLT_PRISM_HEADER, "802.11 plus Prism header"),
	DLT_CHOICE(DLT_IP_OVER_FC, "RFC 2625 IP-over-Fibre Channel"),
	DLT_CHOICE(DLT_SUNATM, "Sun raw ATM"),
	DLT_CHOICE(DLT_IEEE802_11_RADIO, "802.11 plus radiotap header"),
	DLT_CHOICE(DLT_ARCNET_LINUX, "Linux ARCNET"),
        DLT_CHOICE(DLT_JUNIPER_MLPPP, "Juniper Multi-Link PPP"),
	DLT_CHOICE(DLT_JUNIPER_MLFR, "Juniper Multi-Link Frame Relay"),
        DLT_CHOICE(DLT_JUNIPER_ES, "Juniper Encryption Services PIC"),
        DLT_CHOICE(DLT_JUNIPER_GGSN, "Juniper GGSN PIC"),
	DLT_CHOICE(DLT_JUNIPER_MFR, "Juniper FRF.16 Frame Relay"),
        DLT_CHOICE(DLT_JUNIPER_ATM2, "Juniper ATM2 PIC"),
        DLT_CHOICE(DLT_JUNIPER_SERVICES, "Juniper Advanced Services PIC"),
        DLT_CHOICE(DLT_JUNIPER_ATM1, "Juniper ATM1 PIC"),
	DLT_CHOICE(DLT_APPLE_IP_OVER_IEEE1394, "Apple IP-over-IEEE 1394"),
	DLT_CHOICE(DLT_MTP2_WITH_PHDR, "SS7 MTP2 with Pseudo-header"),
	DLT_CHOICE(DLT_MTP2, "SS7 MTP2"),
	DLT_CHOICE(DLT_MTP3, "SS7 MTP3"),
	DLT_CHOICE(DLT_SCCP, "SS7 SCCP"),
	DLT_CHOICE(DLT_DOCSIS, "DOCSIS"),
	DLT_CHOICE(DLT_LINUX_IRDA, "Linux IrDA"),
	DLT_CHOICE(DLT_IEEE802_11_RADIO_AVS, "802.11 plus AVS radio information header"),
        DLT_CHOICE(DLT_JUNIPER_MONITOR, "Juniper Passive Monitor PIC"),
	DLT_CHOICE(DLT_BACNET_MS_TP, "BACnet MS/TP"),
	DLT_CHOICE(DLT_PPP_PPPD, "PPP for pppd, with direction flag"),
	DLT_CHOICE(DLT_JUNIPER_PPPOE, "Juniper PPPoE"),
	DLT_CHOICE(DLT_JUNIPER_PPPOE_ATM, "Juniper PPPoE/ATM"),
	DLT_CHOICE(DLT_GPRS_LLC, "GPRS LLC"),
	DLT_CHOICE(DLT_GPF_T, "GPF-T"),
	DLT_CHOICE(DLT_GPF_F, "GPF-F"),
	DLT_CHOICE(DLT_JUNIPER_PIC_PEER, "Juniper PIC Peer"),
	DLT_CHOICE(DLT_ERF_ETH,	"Ethernet with Endace ERF header"),
	DLT_CHOICE(DLT_ERF_POS, "Packet-over-SONET with Endace ERF header"),
	DLT_CHOICE(DLT_LINUX_LAPD, "Linux vISDN LAPD"),
	DLT_CHOICE(DLT_JUNIPER_ETHER, "Juniper Ethernet"),
	DLT_CHOICE(DLT_JUNIPER_PPP, "Juniper PPP"),
	DLT_CHOICE(DLT_JUNIPER_FRELAY, "Juniper Frame Relay"),
	DLT_CHOICE(DLT_JUNIPER_CHDLC, "Juniper C-HDLC"),
	DLT_CHOICE(DLT_MFR, "FRF.16 Frame Relay"),
	DLT_CHOICE(DLT_JUNIPER_VP, "Juniper Voice PIC"),
	DLT_CHOICE(DLT_A429, "Arinc 429"),
	DLT_CHOICE(DLT_A653_ICM, "Arinc 653 Interpartition Communication"),
	DLT_CHOICE(DLT_USB, "USB"),
	DLT_CHOICE(DLT_BLUETOOTH_HCI_H4, "Bluetooth HCI UART transport layer"),
	DLT_CHOICE(DLT_IEEE802_16_MAC_CPS, "IEEE 802.16 MAC Common Part Sublayer"),
	DLT_CHOICE(DLT_USB_LINUX, "USB with Linux header"),
	DLT_CHOICE(DLT_CAN20B, "Controller Area Network (CAN) v. 2.0B"),
	DLT_CHOICE(DLT_IEEE802_15_4_LINUX, "IEEE 802.15.4 with Linux padding"),
	DLT_CHOICE(DLT_PPI, "Per-Packet Information"),
	DLT_CHOICE(DLT_IEEE802_16_MAC_CPS_RADIO, "IEEE 802.16 MAC Common Part Sublayer plus radiotap header"),
	DLT_CHOICE(DLT_JUNIPER_ISM, "Juniper Integrated Service Module"),
	DLT_CHOICE(DLT_IEEE802_15_4, "IEEE 802.15.4 with FCS"),
	DLT_CHOICE(DLT_SITA, "SITA pseudo-header"),
	DLT_CHOICE(DLT_ERF, "Endace ERF header"),
	DLT_CHOICE(DLT_RAIF1, "Ethernet with u10 Networks pseudo-header"),
	DLT_CHOICE(DLT_IPMB, "IPMB"),
	DLT_CHOICE(DLT_JUNIPER_ST, "Juniper Secure Tunnel"),
	DLT_CHOICE(DLT_BLUETOOTH_HCI_H4_WITH_PHDR, "Bluetooth HCI UART transport layer plus pseudo-header"),
	DLT_CHOICE(DLT_AX25_KISS, "AX.25 with KISS header"),
	DLT_CHOICE(DLT_IEEE802_15_4_NONASK_PHY, "IEEE 802.15.4 with non-ASK PHY data"),
	DLT_CHOICE(DLT_MPLS, "MPLS with label as link-layer header"),
	DLT_CHOICE(DLT_LINUX_EVDEV, "Linux evdev events"),
	DLT_CHOICE(DLT_USB_LINUX_MMAPPED, "USB with padded Linux header"),
	DLT_CHOICE(DLT_DECT, "DECT"),
	DLT_CHOICE(DLT_AOS, "AOS Space Data Link protocol"),
	DLT_CHOICE(DLT_WIHART, "Wireless HART"),
	DLT_CHOICE(DLT_FC_2, "Fibre Channel FC-2"),
	DLT_CHOICE(DLT_FC_2_WITH_FRAME_DELIMS, "Fibre Channel FC-2 with frame delimiters"),
	DLT_CHOICE(DLT_IPNET, "Solaris ipnet"),
	DLT_CHOICE(DLT_CAN_SOCKETCAN, "CAN-bus with SocketCAN headers"),
	DLT_CHOICE(DLT_IPV4, "Raw IPv4"),
	DLT_CHOICE(DLT_IPV6, "Raw IPv6"),
	DLT_CHOICE(DLT_IEEE802_15_4_NOFCS, "IEEE 802.15.4 without FCS"),
	DLT_CHOICE(DLT_DBUS, "D-Bus"),
	DLT_CHOICE(DLT_JUNIPER_VS, "Juniper Virtual Server"),
	DLT_CHOICE(DLT_JUNIPER_SRX_E2E, "Juniper SRX E2E"),
	DLT_CHOICE(DLT_JUNIPER_FIBRECHANNEL, "Juniper Fibre Channel"),
	DLT_CHOICE(DLT_DVB_CI, "DVB-CI"),
	DLT_CHOICE(DLT_MUX27010, "MUX27010"),
	DLT_CHOICE(DLT_STANAG_5066_D_PDU, "STANAG 5066 D_PDUs"),
	DLT_CHOICE(DLT_JUNIPER_ATM_CEMIC, "Juniper ATM CEMIC"),
	DLT_CHOICE(DLT_NFLOG, "Linux netfilter log messages"),
	DLT_CHOICE(DLT_NETANALYZER, "Ethernet with Hilscher netANALYZER pseudo-header"),
	DLT_CHOICE(DLT_NETANALYZER_TRANSPARENT, "Ethernet with Hilscher netANALYZER pseudo-header and with preamble and SFD"),
	DLT_CHOICE(DLT_IPOIB, "RFC 4391 IP-over-Infiniband"),
	DLT_CHOICE(DLT_MPEG_2_TS, "MPEG-2 transport stream"),
	DLT_CHOICE(DLT_NG40, "ng40 protocol tester Iub/Iur"),
	DLT_CHOICE(DLT_NFC_LLCP, "NFC LLCP PDUs with pseudo-header"),
	DLT_CHOICE(DLT_INFINIBAND, "InfiniBand"),
	DLT_CHOICE(DLT_SCTP, "SCTP"),
	DLT_CHOICE(DLT_USBPCAP, "USB with USBPcap header"),
	DLT_CHOICE(DLT_RTAC_SERIAL, "Schweitzer Engineering Laboratories RTAC packets"),
	DLT_CHOICE(DLT_BLUETOOTH_LE_LL, "Bluetooth Low Energy air interface"),
	DLT_CHOICE(DLT_NETLINK, "Linux netlink"),
	DLT_CHOICE(DLT_BLUETOOTH_LINUX_MONITOR, "Bluetooth Linux Monitor"),
	DLT_CHOICE(DLT_BLUETOOTH_BREDR_BB, "Bluetooth Basic Rate/Enhanced Data Rate baseband packets"),
	DLT_CHOICE(DLT_BLUETOOTH_LE_LL_WITH_PHDR, "Bluetooth Low Energy air interface with pseudo-header"),
	DLT_CHOICE(DLT_PROFIBUS_DL, "PROFIBUS data link layer"),
	DLT_CHOICE(DLT_PKTAP, "Apple DLT_PKTAP"),
	DLT_CHOICE(DLT_EPON, "Ethernet with 802.3 Clause 65 EPON preamble"),
	DLT_CHOICE_SENTINEL
};

int
pcap_datalink_name_to_val(const char *name)
{
	int i;

	for (i = 0; dlt_choices[i].name != NULL; i++) {
		if (pcap_strcasecmp(dlt_choices[i].name + sizeof("DLT_") - 1,
		    name) == 0)
			return (dlt_choices[i].dlt);
	}
	return (-1);
}

const char *
pcap_datalink_val_to_name(int dlt)
{
	int i;

	for (i = 0; dlt_choices[i].name != NULL; i++) {
		if (dlt_choices[i].dlt == dlt)
			return (dlt_choices[i].name + sizeof("DLT_") - 1);
	}
	return (NULL);
}

const char *
pcap_datalink_val_to_description(int dlt)
{
	int i;

	for (i = 0; dlt_choices[i].name != NULL; i++) {
		if (dlt_choices[i].dlt == dlt)
			return (dlt_choices[i].description);
	}
	return (NULL);
}

struct tstamp_type_choice {
	const char *name;
	const char *description;
	int	type;
};

static struct tstamp_type_choice tstamp_type_choices[] = {
	{ "host", "Host", PCAP_TSTAMP_HOST },
	{ "host_lowprec", "Host, low precision", PCAP_TSTAMP_HOST_LOWPREC },
	{ "host_hiprec", "Host, high precision", PCAP_TSTAMP_HOST_HIPREC },
	{ "adapter", "Adapter", PCAP_TSTAMP_ADAPTER },
	{ "adapter_unsynced", "Adapter, not synced with system time", PCAP_TSTAMP_ADAPTER_UNSYNCED },
	{ NULL, NULL, 0 }
};

int
pcap_tstamp_type_name_to_val(const char *name)
{
	int i;

	for (i = 0; tstamp_type_choices[i].name != NULL; i++) {
		if (pcap_strcasecmp(tstamp_type_choices[i].name, name) == 0)
			return (tstamp_type_choices[i].type);
	}
	return (PCAP_ERROR);
}

const char *
pcap_tstamp_type_val_to_name(int tstamp_type)
{
	int i;

	for (i = 0; tstamp_type_choices[i].name != NULL; i++) {
		if (tstamp_type_choices[i].type == tstamp_type)
			return (tstamp_type_choices[i].name);
	}
	return (NULL);
}

const char *
pcap_tstamp_type_val_to_description(int tstamp_type)
{
	int i;

	for (i = 0; tstamp_type_choices[i].name != NULL; i++) {
		if (tstamp_type_choices[i].type == tstamp_type)
			return (tstamp_type_choices[i].description);
	}
	return (NULL);
}

int
pcap_snapshot(pcap_t *p)
{
	if (!p->activated)
		return (PCAP_ERROR_NOT_ACTIVATED);
	return (p->snapshot);
}

int
pcap_is_swapped(pcap_t *p)
{
	if (!p->activated)
		return (PCAP_ERROR_NOT_ACTIVATED);
	return (p->swapped);
}

int
pcap_major_version(pcap_t *p)
{
	if (!p->activated)
		return (PCAP_ERROR_NOT_ACTIVATED);
	return (p->version_major);
}

int
pcap_minor_version(pcap_t *p)
{
	if (!p->activated)
		return (PCAP_ERROR_NOT_ACTIVATED);
	return (p->version_minor);
}

FILE *
pcap_file(pcap_t *p)
{
	return (p->rfile);
}

int
pcap_fileno(pcap_t *p)
{
#ifndef WIN32
	return (p->fd);
#else
	if (p->adapter != NULL)
		return ((int)(DWORD)p->adapter->hFile);
	else
		return (PCAP_ERROR);
#endif
}

#if !defined(WIN32) && !defined(MSDOS)
int
pcap_get_selectable_fd(pcap_t *p)
{
	return (p->selectable_fd);
}
#endif

void
pcap_perror(pcap_t *p, char *prefix)
{
	fprintf(stderr, "%s: %s\n", prefix, p->errbuf);
}

char *
pcap_geterr(pcap_t *p)
{
	return (p->errbuf);
}

int
pcap_getnonblock(pcap_t *p, char *errbuf)
{
	int ret;

	ret = p->getnonblock_op(p, errbuf);
	if (ret == -1) {
		/*
		 * In case somebody depended on the bug wherein
		 * the error message was put into p->errbuf
		 * by pcap_getnonblock_fd().
		 */
		strlcpy(p->errbuf, errbuf, PCAP_ERRBUF_SIZE);
	}
	return (ret);
}

/*
 * Get the current non-blocking mode setting, under the assumption that
 * it's just the standard POSIX non-blocking flag.
 *
 * We don't look at "p->nonblock", in case somebody tweaked the FD
 * directly.
 */
#if !defined(WIN32) && !defined(MSDOS)
int
pcap_getnonblock_fd(pcap_t *p, char *errbuf)
{
	int fdflags;

	fdflags = fcntl(p->fd, F_GETFL, 0);
	if (fdflags == -1) {
		snprintf(errbuf, PCAP_ERRBUF_SIZE, "F_GETFL: %s",
		    pcap_strerror(errno));
		return (-1);
	}
	if (fdflags & O_NONBLOCK)
		return (1);
	else
		return (0);
}
#endif

int
pcap_setnonblock(pcap_t *p, int nonblock, char *errbuf)
{
	int ret;

	ret = p->setnonblock_op(p, nonblock, errbuf);
	if (ret == -1) {
		/*
		 * In case somebody depended on the bug wherein
		 * the error message was put into p->errbuf
		 * by pcap_setnonblock_fd().
		 */
		strlcpy(p->errbuf, errbuf, PCAP_ERRBUF_SIZE);
	}
	return (ret);
}

#if !defined(WIN32) && !defined(MSDOS)
/*
 * Set non-blocking mode, under the assumption that it's just the
 * standard POSIX non-blocking flag.  (This can be called by the
 * per-platform non-blocking-mode routine if that routine also
 * needs to do some additional work.)
 */
int
pcap_setnonblock_fd(pcap_t *p, int nonblock, char *errbuf)
{
	int fdflags;

	fdflags = fcntl(p->fd, F_GETFL, 0);
	if (fdflags == -1) {
		snprintf(errbuf, PCAP_ERRBUF_SIZE, "F_GETFL: %s",
		    pcap_strerror(errno));
		return (-1);
	}
	if (nonblock)
		fdflags |= O_NONBLOCK;
	else
		fdflags &= ~O_NONBLOCK;
	if (fcntl(p->fd, F_SETFL, fdflags) == -1) {
		snprintf(errbuf, PCAP_ERRBUF_SIZE, "F_SETFL: %s",
		    pcap_strerror(errno));
		return (-1);
	}
	return (0);
}
#endif

#ifdef WIN32
/*
 * Generate a string for the last Win32-specific error (i.e. an error generated when
 * calling a Win32 API).
 * For errors occurred during standard C calls, we still use pcap_strerror()
 */
char *
pcap_win32strerror(void)
{
	DWORD error;
	static char errbuf[PCAP_ERRBUF_SIZE+1];
	int errlen;
	char *p;

	error = GetLastError();
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, error, 0, errbuf,
	    PCAP_ERRBUF_SIZE, NULL);

	/*
	 * "FormatMessage()" "helpfully" sticks CR/LF at the end of the
	 * message.  Get rid of it.
	 */
	errlen = strlen(errbuf);
	if (errlen >= 2) {
		errbuf[errlen - 1] = '\0';
		errbuf[errlen - 2] = '\0';
	}
	p = strchr(errbuf, '\0');
	snprintf (p, sizeof(errbuf)-(p-errbuf), " (%lu)", error);
	return (errbuf);
}
#endif

/*
 * Generate error strings for PCAP_ERROR_ and PCAP_WARNING_ values.
 */
const char *
pcap_statustostr(int errnum)
{
	static char ebuf[15+10+1];

	switch (errnum) {

	case PCAP_WARNING:
		return("Generic warning");

	case PCAP_WARNING_TSTAMP_TYPE_NOTSUP:
		return ("That type of time stamp is not supported by that device");

	case PCAP_WARNING_PROMISC_NOTSUP:
		return ("That device doesn't support promiscuous mode");

	case PCAP_ERROR:
		return("Generic error");

	case PCAP_ERROR_BREAK:
		return("Loop terminated by pcap_breakloop");

	case PCAP_ERROR_NOT_ACTIVATED:
		return("The pcap_t has not been activated");

	case PCAP_ERROR_ACTIVATED:
		return ("The setting can't be changed after the pcap_t is activated");

	case PCAP_ERROR_NO_SUCH_DEVICE:
		return ("No such device exists");

	case PCAP_ERROR_RFMON_NOTSUP:
		return ("That device doesn't support monitor mode");

	case PCAP_ERROR_NOT_RFMON:
		return ("That operation is supported only in monitor mode");

	case PCAP_ERROR_PERM_DENIED:
		return ("You don't have permission to capture on that device");

	case PCAP_ERROR_IFACE_NOT_UP:
		return ("That device is not up");

	case PCAP_ERROR_CANTSET_TSTAMP_TYPE:
		return ("That device doesn't support setting the time stamp type");

	case PCAP_ERROR_PROMISC_PERM_DENIED:
		return ("You don't have permission to capture in promiscuous mode on that device");

	case PCAP_ERROR_TSTAMP_PRECISION_NOTSUP:
		return ("That device doesn't support that time stamp precision");
	}
	(void)snprintf(ebuf, sizeof ebuf, "Unknown error: %d", errnum);
	return(ebuf);
}

/*
 * Not all systems have strerror().
 */
const char *
pcap_strerror(int errnum)
{
#ifdef HAVE_STRERROR
	return (strerror(errnum));
#else
	extern int sys_nerr;
	extern const char *const sys_errlist[];
	static char ebuf[15+10+1];

	if ((unsigned int)errnum < sys_nerr)
		return ((char *)sys_errlist[errnum]);
	(void)snprintf(ebuf, sizeof ebuf, "Unknown error: %d", errnum);
	return(ebuf);
#endif
}

int
pcap_setfilter(pcap_t *p, struct bpf_program *fp)
{
	return (p->setfilter_op(p, fp));
}

/*
 * Set direction flag, which controls whether we accept only incoming
 * packets, only outgoing packets, or both.
 * Note that, depending on the platform, some or all direction arguments
 * might not be supported.
 */
int
pcap_setdirection(pcap_t *p, pcap_direction_t d)
{
	if (p->setdirection_op == NULL) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "Setting direction is not implemented on this platform");
		return (-1);
	} else
		return (p->setdirection_op(p, d));
}

int
pcap_stats(pcap_t *p, struct pcap_stat *ps)
{
	return (p->stats_op(p, ps));
}

static int
pcap_stats_dead(pcap_t *p, struct pcap_stat *ps _U_)
{
	snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
	    "Statistics aren't available from a pcap_open_dead pcap_t");
	return (-1);
}

#ifdef WIN32
int
pcap_setbuff(pcap_t *p, int dim)
{
	return (p->setbuff_op(p, dim));
}

static int
pcap_setbuff_dead(pcap_t *p, int dim)
{
	snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
	    "The kernel buffer size cannot be set on a pcap_open_dead pcap_t");
	return (-1);
}

int
pcap_setmode(pcap_t *p, int mode)
{
	return (p->setmode_op(p, mode));
}

static int
pcap_setmode_dead(pcap_t *p, int mode)
{
	snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
	    "impossible to set mode on a pcap_open_dead pcap_t");
	return (-1);
}

int
pcap_setmintocopy(pcap_t *p, int size)
{
	return (p->setmintocopy_op(p, size));
}

Adapter *
pcap_get_adapter(pcap_t *p)
{
	return (p->getadapter_op(p));
}

static int
pcap_setmintocopy_dead(pcap_t *p, int size)
{
	snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
	    "The mintocopy parameter cannot be set on a pcap_open_dead pcap_t");
	return (-1);
}
#endif

/*
 * On some platforms, we need to clean up promiscuous or monitor mode
 * when we close a device - and we want that to happen even if the
 * application just exits without explicitl closing devices.
 * On those platforms, we need to register a "close all the pcaps"
 * routine to be called when we exit, and need to maintain a list of
 * pcaps that need to be closed to clean up modes.
 *
 * XXX - not thread-safe.
 */

/*
 * List of pcaps on which we've done something that needs to be
 * cleaned up.
 * If there are any such pcaps, we arrange to call "pcap_close_all()"
 * when we exit, and have it close all of them.
 */
static struct pcap *pcaps_to_close;

/*
 * TRUE if we've already called "atexit()" to cause "pcap_close_all()" to
 * be called on exit.
 */
static int did_atexit;

static void
pcap_close_all(void)
{
	struct pcap *handle;

	while ((handle = pcaps_to_close) != NULL)
		pcap_close(handle);
}

int
pcap_do_addexit(pcap_t *p)
{
	/*
	 * If we haven't already done so, arrange to have
	 * "pcap_close_all()" called when we exit.
	 */
	if (!did_atexit) {
		if (atexit(pcap_close_all) == -1) {
			/*
			 * "atexit()" failed; let our caller know.
			 */
			strncpy(p->errbuf, "atexit failed",
			    PCAP_ERRBUF_SIZE);
			return (0);
		}
		did_atexit = 1;
	}
	return (1);
}

void
pcap_add_to_pcaps_to_close(pcap_t *p)
{
	p->next = pcaps_to_close;
	pcaps_to_close = p;
}

void
pcap_remove_from_pcaps_to_close(pcap_t *p)
{
	pcap_t *pc, *prevpc;

	for (pc = pcaps_to_close, prevpc = NULL; pc != NULL;
	    prevpc = pc, pc = pc->next) {
		if (pc == p) {
			/*
			 * Found it.  Remove it from the list.
			 */
			if (prevpc == NULL) {
				/*
				 * It was at the head of the list.
				 */
				pcaps_to_close = pc->next;
			} else {
				/*
				 * It was in the middle of the list.
				 */
				prevpc->next = pc->next;
			}
			break;
		}
	}
}

void
pcap_cleanup_live_common(pcap_t *p)
{
	if (p->buffer != NULL) {
		free(p->buffer);
		p->buffer = NULL;
	}
	if (p->dlt_list != NULL) {
		free(p->dlt_list);
		p->dlt_list = NULL;
		p->dlt_count = 0;
	}
	if (p->tstamp_type_list != NULL) {
		free(p->tstamp_type_list);
		p->tstamp_type_list = NULL;
		p->tstamp_type_count = 0;
	}
	if (p->tstamp_precision_list != NULL) {
		free(p->tstamp_precision_list);
		p->tstamp_precision_list = NULL;
		p->tstamp_precision_count = 0;
	}
	pcap_freecode(&p->fcode);
#if !defined(WIN32) && !defined(MSDOS)
	if (p->fd >= 0) {
		close(p->fd);
		p->fd = -1;
	}
	p->selectable_fd = -1;
#endif
}

static void
pcap_cleanup_dead(pcap_t *p _U_)
{
	/* Nothing to do. */
}

pcap_t *
pcap_open_dead_with_tstamp_precision(int linktype, int snaplen, u_int precision)
{
	pcap_t *p;

	switch (precision) {

	case PCAP_TSTAMP_PRECISION_MICRO:
	case PCAP_TSTAMP_PRECISION_NANO:
		break;

	default:
		return NULL;
	}
	p = malloc(sizeof(*p));
	if (p == NULL)
		return NULL;
	memset (p, 0, sizeof(*p));
	p->snapshot = snaplen;
	p->linktype = linktype;
	p->opt.tstamp_precision = precision;
	p->stats_op = pcap_stats_dead;
#ifdef WIN32
	p->setbuff_op = pcap_setbuff_dead;
	p->setmode_op = pcap_setmode_dead;
	p->setmintocopy_op = pcap_setmintocopy_dead;
#endif
	p->cleanup_op = pcap_cleanup_dead;

	/*
	 * A "dead" pcap_t never requires special BPF code generation.
	 */
	p->bpf_codegen_flags = 0;

	p->activated = 1;
	return (p);
}

pcap_t *
pcap_open_dead(int linktype, int snaplen)
{
	return (pcap_open_dead_with_tstamp_precision(linktype, snaplen,
	    PCAP_TSTAMP_PRECISION_MICRO));
}

/*
 * API compatible with WinPcap's "send a packet" routine - returns -1
 * on error, 0 otherwise.
 *
 * XXX - what if we get a short write?
 */
int
pcap_sendpacket(pcap_t *p, const u_char *buf, int size)
{
	if (p->inject_op(p, buf, size) == -1)
		return (-1);
	return (0);
}

/*
 * API compatible with OpenBSD's "send a packet" routine - returns -1 on
 * error, number of bytes written otherwise.
 */
int
pcap_inject(pcap_t *p, const void *buf, size_t size)
{
	return (p->inject_op(p, buf, size));
}

void
pcap_close(pcap_t *p)
{
	if (p->opt.source != NULL)
		free(p->opt.source);
	p->cleanup_op(p);
	free(p);
}

/*
 * Given a BPF program, a pcap_pkthdr structure for a packet, and the raw
 * data for the packet, check whether the packet passes the filter.
 * Returns the return value of the filter program, which will be zero if
 * the packet doesn't pass and non-zero if the packet does pass.
 */
int
pcap_offline_filter(const struct bpf_program *fp, const struct pcap_pkthdr *h,
    const u_char *pkt)
{
	const struct bpf_insn *fcode = fp->bf_insns;

	if (fcode != NULL)
		return (bpf_filter(fcode, pkt, h->len, h->caplen));
	else
		return (0);
}

/*
 * We make the version string static, and return a pointer to it, rather
 * than exporting the version string directly.  On at least some UNIXes,
 * if you import data from a shared library into an program, the data is
 * bound into the program binary, so if the string in the version of the
 * library with which the program was linked isn't the same as the
 * string in the version of the library with which the program is being
 * run, various undesirable things may happen (warnings, the string
 * being the one from the version of the library with which the program
 * was linked, or even weirder things, such as the string being the one
 * from the library but being truncated).
 */
#ifdef HAVE_VERSION_H
#include "version.h"
#else
static const char pcap_version_string[] = "libpcap version 1.x.y";
#endif

#ifdef WIN32
/*
 * XXX - it'd be nice if we could somehow generate the WinPcap and libpcap
 * version numbers when building WinPcap.  (It'd be nice to do so for
 * the packet.dll version number as well.)
 */
static const char wpcap_version_string[] = "4.0";
static const char pcap_version_string_fmt[] =
    "WinPcap version %s, based on %s";
static const char pcap_version_string_packet_dll_fmt[] =
    "WinPcap version %s (packet.dll version %s), based on %s";
static char *full_pcap_version_string;

const char *
pcap_lib_version(void)
{
	char *packet_version_string;
	size_t full_pcap_version_string_len;

	if (full_pcap_version_string == NULL) {
		/*
		 * Generate the version string.
		 */
		packet_version_string = PacketGetVersion();
		if (strcmp(wpcap_version_string, packet_version_string) == 0) {
			/*
			 * WinPcap version string and packet.dll version
			 * string are the same; just report the WinPcap
			 * version.
			 */
			full_pcap_version_string_len =
			    (sizeof pcap_version_string_fmt - 4) +
			    strlen(wpcap_version_string) +
			    strlen(pcap_version_string);
			full_pcap_version_string =
			    malloc(full_pcap_version_string_len);
			if (full_pcap_version_string == NULL)
				return (NULL);
			sprintf(full_pcap_version_string,
			    pcap_version_string_fmt, wpcap_version_string,
			    pcap_version_string);
		} else {
			/*
			 * WinPcap version string and packet.dll version
			 * string are different; that shouldn't be the
			 * case (the two libraries should come from the
			 * same version of WinPcap), so we report both
			 * versions.
			 */
			full_pcap_version_string_len =
			    (sizeof pcap_version_string_packet_dll_fmt - 6) +
			    strlen(wpcap_version_string) +
			    strlen(packet_version_string) +
			    strlen(pcap_version_string);
			full_pcap_version_string = malloc(full_pcap_version_string_len);
			if (full_pcap_version_string == NULL)
				return (NULL);
			sprintf(full_pcap_version_string,
			    pcap_version_string_packet_dll_fmt,
			    wpcap_version_string, packet_version_string,
			    pcap_version_string);
		}
	}
	return (full_pcap_version_string);
}

#elif defined(MSDOS)

static char *full_pcap_version_string;

const char *
pcap_lib_version (void)
{
	char *packet_version_string;
	size_t full_pcap_version_string_len;
	static char dospfx[] = "DOS-";

	if (full_pcap_version_string == NULL) {
		/*
		 * Generate the version string.
		 */
		full_pcap_version_string_len =
		    sizeof dospfx + strlen(pcap_version_string);
		full_pcap_version_string =
		    malloc(full_pcap_version_string_len);
		if (full_pcap_version_string == NULL)
			return (NULL);
		strcpy(full_pcap_version_string, dospfx);
		strcat(full_pcap_version_string, pcap_version_string);
	}
	return (full_pcap_version_string);
}

#else /* UN*X */

const char *
pcap_lib_version(void)
{
	return (pcap_version_string);
}
#endif
