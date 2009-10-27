/*
 * Copyright (c) 1993, 1994, 1995, 1996, 1998
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
static const char rcsid[] _U_ =
    "@(#) $Header: /tcpdump/master/libpcap/pcap-bpf.c,v 1.99.2.17 2008-09-16 18:43:02 guy Exp $ (LBL)";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/param.h>			/* optionally get BSD define */
#ifdef HAVE_ZEROCOPY_BPF
#include <sys/mman.h>
#endif
#include <sys/time.h>
#include <sys/timeb.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>

#ifdef HAVE_ZEROCOPY_BPF
#include <machine/atomic.h>
#endif

#include <net/if.h>

#ifdef _AIX

/*
 * Make "pcap.h" not include "pcap/bpf.h"; we are going to include the
 * native OS version, as we need "struct bpf_config" from it.
 */
#define PCAP_DONT_INCLUDE_PCAP_BPF_H

#include <sys/types.h>

/*
 * Prevent bpf.h from redefining the DLT_ values to their
 * IFT_ values, as we're going to return the standard libpcap
 * values, not IBM's non-standard IFT_ values.
 */
#undef _AIX
#include <net/bpf.h>
#define _AIX

#include <net/if_types.h>		/* for IFT_ values */
#include <sys/sysconfig.h>
#include <sys/device.h>
#include <sys/cfgodm.h>
#include <cf.h>

#ifdef __64BIT__
#define domakedev makedev64
#define getmajor major64
#define bpf_hdr bpf_hdr32
#else /* __64BIT__ */
#define domakedev makedev
#define getmajor major
#endif /* __64BIT__ */

#define BPF_NAME "bpf"
#define BPF_MINORS 4
#define DRIVER_PATH "/usr/lib/drivers"
#define BPF_NODE "/dev/bpf"
static int bpfloadedflag = 0;
static int odmlockid = 0;

#else /* _AIX */

#include <net/bpf.h>

#endif /* _AIX */

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_NET_IF_MEDIA_H
# include <net/if_media.h>
#endif

#include "pcap-int.h"

#ifdef HAVE_DAG_API
#include "pcap-dag.h"
#endif /* HAVE_DAG_API */

#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

#ifdef BIOCGDLTLIST
# if (defined(HAVE_NET_IF_MEDIA_H) && defined(IFM_IEEE80211)) && !defined(__APPLE__)
#define HAVE_BSD_IEEE80211
# endif

# if defined(__APPLE__) || defined(HAVE_BSD_IEEE80211)
static int find_802_11(struct bpf_dltlist *);

#  ifdef HAVE_BSD_IEEE80211
static int monitor_mode(pcap_t *, int);
#  endif

#  if defined(__APPLE__)
static void remove_en(pcap_t *);
static void remove_802_11(pcap_t *);
#  endif

# endif /* defined(__APPLE__) || defined(HAVE_BSD_IEEE80211) */

#endif /* BIOCGDLTLIST */

/*
 * We include the OS's <net/bpf.h>, not our "pcap/bpf.h", so we probably
 * don't get DLT_DOCSIS defined.
 */
#ifndef DLT_DOCSIS
#define DLT_DOCSIS	143
#endif

/*
 * On OS X, we don't even get any of the 802.11-plus-radio-header DLT_'s
 * defined, even though some of them are used by various Airport drivers.
 */
#ifndef DLT_PRISM_HEADER
#define DLT_PRISM_HEADER	119
#endif
#ifndef DLT_AIRONET_HEADER
#define DLT_AIRONET_HEADER	120
#endif
#ifndef DLT_IEEE802_11_RADIO
#define DLT_IEEE802_11_RADIO	127
#endif
#ifndef DLT_IEEE802_11_RADIO_AVS
#define DLT_IEEE802_11_RADIO_AVS 163
#endif

static int pcap_can_set_rfmon_bpf(pcap_t *p);
static int pcap_activate_bpf(pcap_t *p);
static int pcap_setfilter_bpf(pcap_t *p, struct bpf_program *fp);
static int pcap_setdirection_bpf(pcap_t *, pcap_direction_t);
static int pcap_set_datalink_bpf(pcap_t *p, int dlt);

#ifdef HAVE_ZEROCOPY_BPF
/*
 * For zerocopy bpf, we need to override the setnonblock/getnonblock routines
 * so we don't call select(2) if the pcap handle is in non-blocking mode.  We
 * preserve the timeout supplied by pcap_open functions to make sure it
 * does not get clobbered if the pcap handle moves between blocking and non-
 * blocking mode.
 */
static int
pcap_getnonblock_zbuf(pcap_t *p, char *errbuf)
{ 
	/*
	 * Use a negative value for the timeout to represent that the
	 * pcap handle is in non-blocking mode.
	 */
	return (p->md.timeout < 0);
}

static int
pcap_setnonblock_zbuf(pcap_t *p, int nonblock, char *errbuf)
{   
	/*
	 * Map each value to the corresponding 2's complement, to
	 * preserve the timeout value provided with pcap_set_timeout.
	 * (from pcap-linux.c).
	 */
	if (nonblock) {
		if (p->md.timeout > 0)
			p->md.timeout = p->md.timeout * -1 - 1;
	} else
		if (p->md.timeout < 0)
			p->md.timeout = (p->md.timeout + 1) * -1;
	return (0);
}

/*
 * Zero-copy specific close method.  Un-map the shared buffers then call
 * pcap_cleanup_live_common.
 */
static void
pcap_cleanup_zbuf(pcap_t *p)
{
	/*
	 * Delete the mappings.  Note that p->buffer gets initialized to one
	 * of the mmapped regions in this case, so do not try and free it
	 * directly; null it out so that pcap_cleanup_live_common() doesn't
	 * try to free it.
	 */
	if (p->md.zbuf1 != MAP_FAILED && p->md.zbuf1 != NULL)
		(void) munmap(p->md.zbuf1, p->md.zbufsize);
	if (p->md.zbuf2 != MAP_FAILED && p->md.zbuf2 != NULL)
		(void) munmap(p->md.zbuf2, p->md.zbufsize);
	p->buffer = NULL;
	pcap_cleanup_live_common(p);
}

/*
 * Zero-copy BPF buffer routines to check for and acknowledge BPF data in
 * shared memory buffers.
 *
 * pcap_next_zbuf_shm(): Check for a newly available shared memory buffer,
 * and set up p->buffer and cc to reflect one if available.  Notice that if
 * there was no prior buffer, we select zbuf1 as this will be the first
 * buffer filled for a fresh BPF session.
 */
static int
pcap_next_zbuf_shm(pcap_t *p, int *cc)
{
	struct bpf_zbuf_header *bzh;

	if (p->md.zbuffer == p->md.zbuf2 || p->md.zbuffer == NULL) {
		bzh = (struct bpf_zbuf_header *)p->md.zbuf1;
		if (bzh->bzh_user_gen !=
		    atomic_load_acq_int(&bzh->bzh_kernel_gen)) {
			p->md.bzh = bzh;
			p->md.zbuffer = (u_char *)p->md.zbuf1;
			p->buffer = p->md.zbuffer + sizeof(*bzh);
			*cc = bzh->bzh_kernel_len;
			return (1);
		}
	} else if (p->md.zbuffer == p->md.zbuf1) {
		bzh = (struct bpf_zbuf_header *)p->md.zbuf2;
		if (bzh->bzh_user_gen !=
		    atomic_load_acq_int(&bzh->bzh_kernel_gen)) {
			p->md.bzh = bzh;
			p->md.zbuffer = (u_char *)p->md.zbuf2;
  			p->buffer = p->md.zbuffer + sizeof(*bzh);
			*cc = bzh->bzh_kernel_len;
			return (1);
		}
	}
	*cc = 0;
	return (0);
}

/*
 * pcap_next_zbuf() -- Similar to pcap_next_zbuf_shm(), except wait using
 * select() for data or a timeout, and possibly force rotation of the buffer
 * in the event we time out or are in immediate mode.  Invoke the shared
 * memory check before doing system calls in order to avoid doing avoidable
 * work.
 */
static int
pcap_next_zbuf(pcap_t *p, int *cc)
{
	struct bpf_zbuf bz;
	struct timeval tv;
	struct timespec cur;
	fd_set r_set;
	int data, r;
	int expire, tmout;

#define TSTOMILLI(ts) (((ts)->tv_sec * 1000) + ((ts)->tv_nsec / 1000000))
	/*
	 * Start out by seeing whether anything is waiting by checking the
	 * next shared memory buffer for data.
	 */
	data = pcap_next_zbuf_shm(p, cc);
	if (data)
		return (data);
	/*
	 * If a previous sleep was interrupted due to signal delivery, make
	 * sure that the timeout gets adjusted accordingly.  This requires
	 * that we analyze when the timeout should be been expired, and
	 * subtract the current time from that.  If after this operation,
	 * our timeout is less then or equal to zero, handle it like a
	 * regular timeout.
	 */
	tmout = p->md.timeout;
	if (tmout)
		(void) clock_gettime(CLOCK_MONOTONIC, &cur);
	if (p->md.interrupted && p->md.timeout) {
		expire = TSTOMILLI(&p->md.firstsel) + p->md.timeout;
		tmout = expire - TSTOMILLI(&cur);
#undef TSTOMILLI
		if (tmout <= 0) {
			p->md.interrupted = 0;
			data = pcap_next_zbuf_shm(p, cc);
			if (data)
				return (data);
			if (ioctl(p->fd, BIOCROTZBUF, &bz) < 0) {
				(void) snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
				    "BIOCROTZBUF: %s", strerror(errno));
				return (PCAP_ERROR);
			}
			return (pcap_next_zbuf_shm(p, cc));
		}
	}
	/*
	 * No data in the buffer, so must use select() to wait for data or
	 * the next timeout.  Note that we only call select if the handle
	 * is in blocking mode.
	 */
	if (p->md.timeout >= 0) {
		FD_ZERO(&r_set);
		FD_SET(p->fd, &r_set);
		if (tmout != 0) {
			tv.tv_sec = tmout / 1000;
			tv.tv_usec = (tmout * 1000) % 1000000;
		}
		r = select(p->fd + 1, &r_set, NULL, NULL,
		    p->md.timeout != 0 ? &tv : NULL);
		if (r < 0 && errno == EINTR) {
			if (!p->md.interrupted && p->md.timeout) {
				p->md.interrupted = 1;
				p->md.firstsel = cur;
			}
			return (0);
		} else if (r < 0) {
			(void) snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "select: %s", strerror(errno));
			return (PCAP_ERROR);
		}
	}
	p->md.interrupted = 0;
	/*
	 * Check again for data, which may exist now that we've either been
	 * woken up as a result of data or timed out.  Try the "there's data"
	 * case first since it doesn't require a system call.
	 */
	data = pcap_next_zbuf_shm(p, cc);
	if (data)
		return (data);
	/*
	 * Try forcing a buffer rotation to dislodge timed out or immediate
	 * data.
	 */
	if (ioctl(p->fd, BIOCROTZBUF, &bz) < 0) {
		(void) snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "BIOCROTZBUF: %s", strerror(errno));
		return (PCAP_ERROR);
	}
	return (pcap_next_zbuf_shm(p, cc));
}

/*
 * Notify kernel that we are done with the buffer.  We don't reset zbuffer so
 * that we know which buffer to use next time around.
 */
static int
pcap_ack_zbuf(pcap_t *p)
{

	atomic_store_rel_int(&p->md.bzh->bzh_user_gen,
	    p->md.bzh->bzh_kernel_gen);
	p->md.bzh = NULL;
	p->buffer = NULL;
	return (0);
}
#endif

pcap_t *
pcap_create(const char *device, char *ebuf)
{
	pcap_t *p;

#ifdef HAVE_DAG_API
	if (strstr(device, "dag"))
		return (dag_create(device, ebuf));
#endif /* HAVE_DAG_API */

	p = pcap_create_common(device, ebuf);
	if (p == NULL)
		return (NULL);

	p->activate_op = pcap_activate_bpf;
	p->can_set_rfmon_op = pcap_can_set_rfmon_bpf;
	return (p);
}

static int
bpf_open(pcap_t *p)
{
	int fd;
#ifdef HAVE_CLONING_BPF
	static const char device[] = "/dev/bpf";
#else
	int n = 0;
	char device[sizeof "/dev/bpf0000000000"];
#endif

#ifdef _AIX
	/*
	 * Load the bpf driver, if it isn't already loaded,
	 * and create the BPF device entries, if they don't
	 * already exist.
	 */
	if (bpf_load(p->errbuf) == PCAP_ERROR)
		return (PCAP_ERROR);
#endif

#ifdef HAVE_CLONING_BPF
	if ((fd = open(device, O_RDWR)) == -1 &&
	    (errno != EACCES || (fd = open(device, O_RDONLY)) == -1)) {
		if (errno == EACCES)
			fd = PCAP_ERROR_PERM_DENIED;
		else
			fd = PCAP_ERROR;
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		  "(cannot open device) %s: %s", device, pcap_strerror(errno));
	}
#else
	/*
	 * Go through all the minors and find one that isn't in use.
	 */
	do {
		(void)snprintf(device, sizeof(device), "/dev/bpf%d", n++);
		/*
		 * Initially try a read/write open (to allow the inject
		 * method to work).  If that fails due to permission
		 * issues, fall back to read-only.  This allows a
		 * non-root user to be granted specific access to pcap
		 * capabilities via file permissions.
		 *
		 * XXX - we should have an API that has a flag that
		 * controls whether to open read-only or read-write,
		 * so that denial of permission to send (or inability
		 * to send, if sending packets isn't supported on
		 * the device in question) can be indicated at open
		 * time.
		 */
		fd = open(device, O_RDWR);
		if (fd == -1 && errno == EACCES)
			fd = open(device, O_RDONLY);
	} while (fd < 0 && errno == EBUSY);

	/*
	 * XXX better message for all minors used
	 */
	if (fd < 0) {
		if (errno == EACCES)
			fd = PCAP_ERROR_PERM_DENIED;
		else
			fd = PCAP_ERROR;
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "(no devices found) %s: %s",
		    device, pcap_strerror(errno));
	}
#endif

	return (fd);
}

#ifdef BIOCGDLTLIST
static int
get_dlt_list(int fd, int v, struct bpf_dltlist *bdlp, char *ebuf)
{
	memset(bdlp, 0, sizeof(*bdlp));
	if (ioctl(fd, BIOCGDLTLIST, (caddr_t)bdlp) == 0) {
		u_int i;
		int is_ethernet;

		bdlp->bfl_list = (u_int *) malloc(sizeof(u_int) * (bdlp->bfl_len + 1));
		if (bdlp->bfl_list == NULL) {
			(void)snprintf(ebuf, PCAP_ERRBUF_SIZE, "malloc: %s",
			    pcap_strerror(errno));
			return (PCAP_ERROR);
		}

		if (ioctl(fd, BIOCGDLTLIST, (caddr_t)bdlp) < 0) {
			(void)snprintf(ebuf, PCAP_ERRBUF_SIZE,
			    "BIOCGDLTLIST: %s", pcap_strerror(errno));
			free(bdlp->bfl_list);
			return (PCAP_ERROR);
		}

		/*
		 * OK, for real Ethernet devices, add DLT_DOCSIS to the
		 * list, so that an application can let you choose it,
		 * in case you're capturing DOCSIS traffic that a Cisco
		 * Cable Modem Termination System is putting out onto
		 * an Ethernet (it doesn't put an Ethernet header onto
		 * the wire, it puts raw DOCSIS frames out on the wire
		 * inside the low-level Ethernet framing).
		 *
		 * A "real Ethernet device" is defined here as a device
		 * that has a link-layer type of DLT_EN10MB and that has
		 * no alternate link-layer types; that's done to exclude
		 * 802.11 interfaces (which might or might not be the
		 * right thing to do, but I suspect it is - Ethernet <->
		 * 802.11 bridges would probably badly mishandle frames
		 * that don't have Ethernet headers).
		 */
		if (v == DLT_EN10MB) {
			is_ethernet = 1;
			for (i = 0; i < bdlp->bfl_len; i++) {
				if (bdlp->bfl_list[i] != DLT_EN10MB) {
					is_ethernet = 0;
					break;
				}
			}
			if (is_ethernet) {
				/*
				 * We reserved one more slot at the end of
				 * the list.
				 */
				bdlp->bfl_list[bdlp->bfl_len] = DLT_DOCSIS;
				bdlp->bfl_len++;
			}
		}
	} else {
		/*
		 * EINVAL just means "we don't support this ioctl on
		 * this device"; don't treat it as an error.
		 */
		if (errno != EINVAL) {
			(void)snprintf(ebuf, PCAP_ERRBUF_SIZE,
			    "BIOCGDLTLIST: %s", pcap_strerror(errno));
			return (PCAP_ERROR);
		}
	}
	return (0);
}
#endif

static int
pcap_can_set_rfmon_bpf(pcap_t *p)
{
#if defined(__APPLE__)
	struct utsname osinfo;
	struct ifreq ifr;
	int fd;
#ifdef BIOCGDLTLIST
	struct bpf_dltlist bdl;
#endif

	/*
	 * The joys of monitor mode on OS X.
	 *
	 * Prior to 10.4, it's not supported at all.
	 *
	 * In 10.4, if adapter enN supports monitor mode, there's a
	 * wltN adapter corresponding to it; you open it, instead of
	 * enN, to get monitor mode.  You get whatever link-layer
	 * headers it supplies.
	 *
	 * In 10.5, and, we assume, later releases, if adapter enN
	 * supports monitor mode, it offers, among its selectable
	 * DLT_ values, values that let you get the 802.11 header;
	 * selecting one of those values puts the adapter into monitor
	 * mode (i.e., you can't get 802.11 headers except in monitor
	 * mode, and you can't get Ethernet headers in monitor mode).
	 */
	if (uname(&osinfo) == -1) {
		/*
		 * Can't get the OS version; just say "no".
		 */
		return (0);
	}
	/*
	 * We assume osinfo.sysname is "Darwin", because
	 * __APPLE__ is defined.  We just check the version.
	 */
	if (osinfo.release[0] < '8' && osinfo.release[1] == '.') {
		/*
		 * 10.3 (Darwin 7.x) or earlier.
		 * Monitor mode not supported.
		 */
		return (0);
	}
	if (osinfo.release[0] == '8' && osinfo.release[1] == '.') {
		/*
		 * 10.4 (Darwin 8.x).  s/en/wlt/, and check
		 * whether the device exists.
		 */
		if (strncmp(p->opt.source, "en", 2) != 0) {
			/*
			 * Not an enN device; no monitor mode.
			 */
			return (0);
		}
		fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (fd == -1) {
			(void)snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "socket: %s", pcap_strerror(errno));
			return (PCAP_ERROR);
		}
		strlcpy(ifr.ifr_name, "wlt", sizeof(ifr.ifr_name));
		strlcat(ifr.ifr_name, p->opt.source + 2, sizeof(ifr.ifr_name));
		if (ioctl(fd, SIOCGIFFLAGS, (char *)&ifr) < 0) {
			/*
			 * No such device?
			 */
			close(fd);
			return (0);
		}
		close(fd);
		return (1);
	}

#ifdef BIOCGDLTLIST
	/*
	 * Everything else is 10.5 or later; for those,
	 * we just open the enN device, and check whether
	 * we have any 802.11 devices.
	 *
	 * First, open a BPF device.
	 */
	fd = bpf_open(p);
	if (fd < 0)
		return (fd);

	/*
	 * Now bind to the device.
	 */
	(void)strncpy(ifr.ifr_name, p->opt.source, sizeof(ifr.ifr_name));
	if (ioctl(fd, BIOCSETIF, (caddr_t)&ifr) < 0) {
		if (errno == ENETDOWN) {
			/*
			 * Return a "network down" indication, so that
			 * the application can report that rather than
			 * saying we had a mysterious failure and
			 * suggest that they report a problem to the
			 * libpcap developers.
			 */
			close(fd);
			return (PCAP_ERROR_IFACE_NOT_UP);
		} else {
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "BIOCSETIF: %s: %s",
			    p->opt.source, pcap_strerror(errno));
			close(fd);
			return (PCAP_ERROR);
		}
	}

	/*
	 * We know the default link type -- now determine all the DLTs
	 * this interface supports.  If this fails with EINVAL, it's
	 * not fatal; we just don't get to use the feature later.
	 * (We don't care about DLT_DOCSIS, so we pass DLT_NULL
	 * as the default DLT for this adapter.)
	 */
	if (get_dlt_list(fd, DLT_NULL, &bdl, p->errbuf) == PCAP_ERROR) {
		close(fd);
		return (PCAP_ERROR);
	}
	if (find_802_11(&bdl) != -1) {
		/*
		 * We have an 802.11 DLT, so we can set monitor mode.
		 */
		free(bdl.bfl_list);
		close(fd);
		return (1);
	}
	free(bdl.bfl_list);
#endif /* BIOCGDLTLIST */
	return (0);
#elif defined(HAVE_BSD_IEEE80211)
	int ret;

	ret = monitor_mode(p, 0);
	if (ret == PCAP_ERROR_RFMON_NOTSUP)
		return (0);	/* not an error, just a "can't do" */
	if (ret == 0)
		return (1);	/* success */
	return (ret);
#else
	return (0);
#endif
}

static int
pcap_stats_bpf(pcap_t *p, struct pcap_stat *ps)
{
	struct bpf_stat s;

	/*
	 * "ps_recv" counts packets handed to the filter, not packets
	 * that passed the filter.  This includes packets later dropped
	 * because we ran out of buffer space.
	 *
	 * "ps_drop" counts packets dropped inside the BPF device
	 * because we ran out of buffer space.  It doesn't count
	 * packets dropped by the interface driver.  It counts
	 * only packets that passed the filter.
	 *
	 * Both statistics include packets not yet read from the kernel
	 * by libpcap, and thus not yet seen by the application.
	 */
	if (ioctl(p->fd, BIOCGSTATS, (caddr_t)&s) < 0) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "BIOCGSTATS: %s",
		    pcap_strerror(errno));
		return (PCAP_ERROR);
	}

	ps->ps_recv = s.bs_recv;
	ps->ps_drop = s.bs_drop;
	return (0);
}

static int
pcap_read_bpf(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
{
	int cc;
	int n = 0;
	register u_char *bp, *ep;
	u_char *datap;
#ifdef PCAP_FDDIPAD
	register int pad;
#endif
#ifdef HAVE_ZEROCOPY_BPF
	int i;
#endif

 again:
	/*
	 * Has "pcap_breakloop()" been called?
	 */
	if (p->break_loop) {
		/*
		 * Yes - clear the flag that indicates that it
		 * has, and return PCAP_ERROR_BREAK to indicate
		 * that we were told to break out of the loop.
		 */
		p->break_loop = 0;
		return (PCAP_ERROR_BREAK);
	}
	cc = p->cc;
	if (p->cc == 0) {
		/*
		 * When reading without zero-copy from a file descriptor, we
		 * use a single buffer and return a length of data in the
		 * buffer.  With zero-copy, we update the p->buffer pointer
		 * to point at whatever underlying buffer contains the next
		 * data and update cc to reflect the data found in the
		 * buffer.
		 */
#ifdef HAVE_ZEROCOPY_BPF
		if (p->md.zerocopy) {
			if (p->buffer != NULL)
				pcap_ack_zbuf(p);
			i = pcap_next_zbuf(p, &cc);
			if (i == 0)
				goto again;
			if (i < 0)
				return (PCAP_ERROR);
		} else
#endif
		{
			cc = read(p->fd, (char *)p->buffer, p->bufsize);
		}
		if (cc < 0) {
			/* Don't choke when we get ptraced */
			switch (errno) {

			case EINTR:
				goto again;

#ifdef _AIX
			case EFAULT:
				/*
				 * Sigh.  More AIX wonderfulness.
				 *
				 * For some unknown reason the uiomove()
				 * operation in the bpf kernel extension
				 * used to copy the buffer into user
				 * space sometimes returns EFAULT. I have
				 * no idea why this is the case given that
				 * a kernel debugger shows the user buffer
				 * is correct. This problem appears to
				 * be mostly mitigated by the memset of
				 * the buffer before it is first used.
				 * Very strange.... Shaun Clowes
				 *
				 * In any case this means that we shouldn't
				 * treat EFAULT as a fatal error; as we
				 * don't have an API for returning
				 * a "some packets were dropped since
				 * the last packet you saw" indication,
				 * we just ignore EFAULT and keep reading.
				 */
				goto again;
#endif

			case EWOULDBLOCK:
				return (0);
#if defined(sun) && !defined(BSD)
			/*
			 * Due to a SunOS bug, after 2^31 bytes, the kernel
			 * file offset overflows and read fails with EINVAL.
			 * The lseek() to 0 will fix things.
			 */
			case EINVAL:
				if (lseek(p->fd, 0L, SEEK_CUR) +
				    p->bufsize < 0) {
					(void)lseek(p->fd, 0L, SEEK_SET);
					goto again;
				}
				/* fall through */
#endif
			}
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "read: %s",
			    pcap_strerror(errno));
			return (PCAP_ERROR);
		}
		bp = p->buffer;
	} else
		bp = p->bp;

	/*
	 * Loop through each packet.
	 */
#define bhp ((struct bpf_hdr *)bp)
	ep = bp + cc;
#ifdef PCAP_FDDIPAD
	pad = p->fddipad;
#endif
	while (bp < ep) {
		register int caplen, hdrlen;

		/*
		 * Has "pcap_breakloop()" been called?
		 * If so, return immediately - if we haven't read any
		 * packets, clear the flag and return PCAP_ERROR_BREAK
		 * to indicate that we were told to break out of the loop,
		 * otherwise leave the flag set, so that the *next* call
		 * will break out of the loop without having read any
		 * packets, and return the number of packets we've
		 * processed so far.
		 */
		if (p->break_loop) {
			if (n == 0) {
				p->break_loop = 0;
				return (PCAP_ERROR_BREAK);
			} else {
				p->bp = bp;
				p->cc = ep - bp;
				return (n);
			}
		}

		caplen = bhp->bh_caplen;
		hdrlen = bhp->bh_hdrlen;
		datap = bp + hdrlen;
		/*
		 * Short-circuit evaluation: if using BPF filter
		 * in kernel, no need to do it now - we already know
		 * the packet passed the filter.
		 *
#ifdef PCAP_FDDIPAD
		 * Note: the filter code was generated assuming
		 * that p->fddipad was the amount of padding
		 * before the header, as that's what's required
		 * in the kernel, so we run the filter before
		 * skipping that padding.
#endif
		 */
		if (p->md.use_bpf ||
		    bpf_filter(p->fcode.bf_insns, datap, bhp->bh_datalen, caplen)) {
			struct pcap_pkthdr pkthdr;

			pkthdr.ts.tv_sec = bhp->bh_tstamp.tv_sec;
#ifdef _AIX
			/*
			 * AIX's BPF returns seconds/nanoseconds time
			 * stamps, not seconds/microseconds time stamps.
			 */
			pkthdr.ts.tv_usec = bhp->bh_tstamp.tv_usec/1000;
#else
			pkthdr.ts.tv_usec = bhp->bh_tstamp.tv_usec;
#endif
#ifdef PCAP_FDDIPAD
			if (caplen > pad)
				pkthdr.caplen = caplen - pad;
			else
				pkthdr.caplen = 0;
			if (bhp->bh_datalen > pad)
				pkthdr.len = bhp->bh_datalen - pad;
			else
				pkthdr.len = 0;
			datap += pad;
#else
			pkthdr.caplen = caplen;
			pkthdr.len = bhp->bh_datalen;
#endif
			(*callback)(user, &pkthdr, datap);
			bp += BPF_WORDALIGN(caplen + hdrlen);
			if (++n >= cnt && cnt > 0) {
				p->bp = bp;
				p->cc = ep - bp;
				return (n);
			}
		} else {
			/*
			 * Skip this packet.
			 */
			bp += BPF_WORDALIGN(caplen + hdrlen);
		}
	}
#undef bhp
	p->cc = 0;
	return (n);
}

static int
pcap_inject_bpf(pcap_t *p, const void *buf, size_t size)
{
	int ret;

	ret = write(p->fd, buf, size);
#ifdef __APPLE__
	if (ret == -1 && errno == EAFNOSUPPORT) {
		/*
		 * In Mac OS X, there's a bug wherein setting the
		 * BIOCSHDRCMPLT flag causes writes to fail; see,
		 * for example:
		 *
		 *	http://cerberus.sourcefire.com/~jeff/archives/patches/macosx/BIOCSHDRCMPLT-10.3.3.patch
		 *
		 * So, if, on OS X, we get EAFNOSUPPORT from the write, we
		 * assume it's due to that bug, and turn off that flag
		 * and try again.  If we succeed, it either means that
		 * somebody applied the fix from that URL, or other patches
		 * for that bug from
		 *
		 *	http://cerberus.sourcefire.com/~jeff/archives/patches/macosx/
		 *
		 * and are running a Darwin kernel with those fixes, or
		 * that Apple fixed the problem in some OS X release.
		 */
		u_int spoof_eth_src = 0;

		if (ioctl(p->fd, BIOCSHDRCMPLT, &spoof_eth_src) == -1) {
			(void)snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "send: can't turn off BIOCSHDRCMPLT: %s",
			    pcap_strerror(errno));
			return (PCAP_ERROR);
		}

		/*
		 * Now try the write again.
		 */
		ret = write(p->fd, buf, size);
	}
#endif /* __APPLE__ */
	if (ret == -1) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "send: %s",
		    pcap_strerror(errno));
		return (PCAP_ERROR);
	}
	return (ret);
}

#ifdef _AIX
static int
bpf_odminit(char *errbuf)
{
	char *errstr;

	if (odm_initialize() == -1) {
		if (odm_err_msg(odmerrno, &errstr) == -1)
			errstr = "Unknown error";
		snprintf(errbuf, PCAP_ERRBUF_SIZE,
		    "bpf_load: odm_initialize failed: %s",
		    errstr);
		return (PCAP_ERROR);
	}

	if ((odmlockid = odm_lock("/etc/objrepos/config_lock", ODM_WAIT)) == -1) {
		if (odm_err_msg(odmerrno, &errstr) == -1)
			errstr = "Unknown error";
		snprintf(errbuf, PCAP_ERRBUF_SIZE,
		    "bpf_load: odm_lock of /etc/objrepos/config_lock failed: %s",
		    errstr);
		return (PCAP_ERROR);
	}

	return (0);
}

static int
bpf_odmcleanup(char *errbuf)
{
	char *errstr;

	if (odm_unlock(odmlockid) == -1) {
		if (odm_err_msg(odmerrno, &errstr) == -1)
			errstr = "Unknown error";
		snprintf(errbuf, PCAP_ERRBUF_SIZE,
		    "bpf_load: odm_unlock failed: %s",
		    errstr);
		return (PCAP_ERROR);
	}

	if (odm_terminate() == -1) {
		if (odm_err_msg(odmerrno, &errstr) == -1)
			errstr = "Unknown error";
		snprintf(errbuf, PCAP_ERRBUF_SIZE,
		    "bpf_load: odm_terminate failed: %s",
		    errstr);
		return (PCAP_ERROR);
	}

	return (0);
}

static int
bpf_load(char *errbuf)
{
	long major;
	int *minors;
	int numminors, i, rc;
	char buf[1024];
	struct stat sbuf;
	struct bpf_config cfg_bpf;
	struct cfg_load cfg_ld;
	struct cfg_kmod cfg_km;

	/*
	 * This is very very close to what happens in the real implementation
	 * but I've fixed some (unlikely) bug situations.
	 */
	if (bpfloadedflag)
		return (0);

	if (bpf_odminit(errbuf) == PCAP_ERROR)
		return (PCAP_ERROR);

	major = genmajor(BPF_NAME);
	if (major == -1) {
		snprintf(errbuf, PCAP_ERRBUF_SIZE,
		    "bpf_load: genmajor failed: %s", pcap_strerror(errno));
		return (PCAP_ERROR);
	}

	minors = getminor(major, &numminors, BPF_NAME);
	if (!minors) {
		minors = genminor("bpf", major, 0, BPF_MINORS, 1, 1);
		if (!minors) {
			snprintf(errbuf, PCAP_ERRBUF_SIZE,
			    "bpf_load: genminor failed: %s",
			    pcap_strerror(errno));
			return (PCAP_ERROR);
		}
	}

	if (bpf_odmcleanup(errbuf) == PCAP_ERROR)
		return (PCAP_ERROR);

	rc = stat(BPF_NODE "0", &sbuf);
	if (rc == -1 && errno != ENOENT) {
		snprintf(errbuf, PCAP_ERRBUF_SIZE,
		    "bpf_load: can't stat %s: %s",
		    BPF_NODE "0", pcap_strerror(errno));
		return (PCAP_ERROR);
	}

	if (rc == -1 || getmajor(sbuf.st_rdev) != major) {
		for (i = 0; i < BPF_MINORS; i++) {
			sprintf(buf, "%s%d", BPF_NODE, i);
			unlink(buf);
			if (mknod(buf, S_IRUSR | S_IFCHR, domakedev(major, i)) == -1) {
				snprintf(errbuf, PCAP_ERRBUF_SIZE,
				    "bpf_load: can't mknod %s: %s",
				    buf, pcap_strerror(errno));
				return (PCAP_ERROR);
			}
		}
	}

	/* Check if the driver is loaded */
	memset(&cfg_ld, 0x0, sizeof(cfg_ld));
	cfg_ld.path = buf;
	sprintf(cfg_ld.path, "%s/%s", DRIVER_PATH, BPF_NAME);
	if ((sysconfig(SYS_QUERYLOAD, (void *)&cfg_ld, sizeof(cfg_ld)) == -1) ||
	    (cfg_ld.kmid == 0)) {
		/* Driver isn't loaded, load it now */
		if (sysconfig(SYS_SINGLELOAD, (void *)&cfg_ld, sizeof(cfg_ld)) == -1) {
			snprintf(errbuf, PCAP_ERRBUF_SIZE,
			    "bpf_load: could not load driver: %s",
			    strerror(errno));
			return (PCAP_ERROR);
		}
	}

	/* Configure the driver */
	cfg_km.cmd = CFG_INIT;
	cfg_km.kmid = cfg_ld.kmid;
	cfg_km.mdilen = sizeof(cfg_bpf);
	cfg_km.mdiptr = (void *)&cfg_bpf;
	for (i = 0; i < BPF_MINORS; i++) {
		cfg_bpf.devno = domakedev(major, i);
		if (sysconfig(SYS_CFGKMOD, (void *)&cfg_km, sizeof(cfg_km)) == -1) {
			snprintf(errbuf, PCAP_ERRBUF_SIZE,
			    "bpf_load: could not configure driver: %s",
			    strerror(errno));
			return (PCAP_ERROR);
		}
	}

	bpfloadedflag = 1;

	return (0);
}
#endif

/*
 * Turn off rfmon mode if necessary.
 */
static void
pcap_cleanup_bpf(pcap_t *p)
{
#ifdef HAVE_BSD_IEEE80211
	int sock;
	struct ifmediareq req;
	struct ifreq ifr;
#endif

	if (p->md.must_clear != 0) {
		/*
		 * There's something we have to do when closing this
		 * pcap_t.
		 */
#ifdef HAVE_BSD_IEEE80211
		if (p->md.must_clear & MUST_CLEAR_RFMON) {
			/*
			 * We put the interface into rfmon mode;
			 * take it out of rfmon mode.
			 *
			 * XXX - if somebody else wants it in rfmon
			 * mode, this code cannot know that, so it'll take
			 * it out of rfmon mode.
			 */
			sock = socket(AF_INET, SOCK_DGRAM, 0);
			if (sock == -1) {
				fprintf(stderr,
				    "Can't restore interface flags (socket() failed: %s).\n"
				    "Please adjust manually.\n",
				    strerror(errno));
			} else {
				memset(&req, 0, sizeof(req));
				strncpy(req.ifm_name, p->md.device,
				    sizeof(req.ifm_name));
				if (ioctl(sock, SIOCGIFMEDIA, &req) < 0) {
					fprintf(stderr,
					    "Can't restore interface flags (SIOCGIFMEDIA failed: %s).\n"
					    "Please adjust manually.\n",
					    strerror(errno));
				} else {
					if (req.ifm_current & IFM_IEEE80211_MONITOR) {
						/*
						 * Rfmon mode is currently on;
						 * turn it off.
						 */
						memset(&ifr, 0, sizeof(ifr));
						(void)strncpy(ifr.ifr_name,
						    p->md.device,
						    sizeof(ifr.ifr_name));
						ifr.ifr_media =
						    req.ifm_current & ~IFM_IEEE80211_MONITOR;
						if (ioctl(sock, SIOCSIFMEDIA,
						    &ifr) == -1) {
							fprintf(stderr,
							    "Can't restore interface flags (SIOCSIFMEDIA failed: %s).\n"
							    "Please adjust manually.\n",
							    strerror(errno));
						}
					}
				}
				close(sock);
			}
		}
#endif /* HAVE_BSD_IEEE80211 */

		/*
		 * Take this pcap out of the list of pcaps for which we
		 * have to take the interface out of some mode.
		 */
		pcap_remove_from_pcaps_to_close(p);
		p->md.must_clear = 0;
	}

#ifdef HAVE_ZEROCOPY_BPF
	/*
	 * In zero-copy mode, p->buffer is just a pointer into one of the two
	 * memory-mapped buffers, so no need to free it.
	 */
	if (p->md.zerocopy) {
		if (p->md.zbuf1 != MAP_FAILED && p->md.zbuf1 != NULL)
			munmap(p->md.zbuf1, p->md.zbufsize);
		if (p->md.zbuf2 != MAP_FAILED && p->md.zbuf2 != NULL)
			munmap(p->md.zbuf2, p->md.zbufsize);
	}
#endif
	if (p->md.device != NULL) {
		free(p->md.device);
		p->md.device = NULL;
	}
	pcap_cleanup_live_common(p);
}

static int
check_setif_failure(pcap_t *p, int error)
{
#ifdef __APPLE__
	int fd;
	struct ifreq ifr;
	int err;
#endif

	if (error == ENXIO) {
		/*
		 * No such device exists.
		 */
#ifdef __APPLE__
		if (p->opt.rfmon && strncmp(p->opt.source, "wlt", 3) == 0) {
			/*
			 * Monitor mode was requested, and we're trying
			 * to open a "wltN" device.  Assume that this
			 * is 10.4 and that we were asked to open an
			 * "enN" device; if that device exists, return
			 * "monitor mode not supported on the device".
			 */
			fd = socket(AF_INET, SOCK_DGRAM, 0);
			if (fd != -1) {
				strlcpy(ifr.ifr_name, "en",
				    sizeof(ifr.ifr_name));
				strlcat(ifr.ifr_name, p->opt.source + 3,
				    sizeof(ifr.ifr_name));
				if (ioctl(fd, SIOCGIFFLAGS, (char *)&ifr) < 0) {
					/*
					 * We assume this failed because
					 * the underlying device doesn't
					 * exist.
					 */
					err = PCAP_ERROR_NO_SUCH_DEVICE;
					strcpy(p->errbuf, "");
				} else {
					/*
					 * The underlying "enN" device
					 * exists, but there's no
					 * corresponding "wltN" device;
					 * that means that the "enN"
					 * device doesn't support
					 * monitor mode, probably because
					 * it's an Ethernet device rather
					 * than a wireless device.
					 */
					err = PCAP_ERROR_RFMON_NOTSUP;
				}
				close(fd);
			} else {
				/*
				 * We can't find out whether there's
				 * an underlying "enN" device, so
				 * just report "no such device".
				 */
				err = PCAP_ERROR_NO_SUCH_DEVICE;
				strcpy(p->errbuf, "");
			}
			return (err);
		}
#endif
		/*
		 * No such device.
		 */
		strcpy(p->errbuf, "");
		return (PCAP_ERROR_NO_SUCH_DEVICE);
	} else if (errno == ENETDOWN) {
		/*
		 * Return a "network down" indication, so that
		 * the application can report that rather than
		 * saying we had a mysterious failure and
		 * suggest that they report a problem to the
		 * libpcap developers.
		 */
		return (PCAP_ERROR_IFACE_NOT_UP);
	} else {
		/*
		 * Some other error; fill in the error string, and
		 * return PCAP_ERROR.
		 */
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "BIOCSETIF: %s: %s",
		    p->opt.source, pcap_strerror(errno));
		return (PCAP_ERROR);
	}
}

static int
pcap_activate_bpf(pcap_t *p)
{
	int status = 0;
	int fd;
	struct ifreq ifr;
	struct bpf_version bv;
#ifdef __APPLE__
	int sockfd;
	char *wltdev = NULL;
#endif
#ifdef BIOCGDLTLIST
	struct bpf_dltlist bdl;
#if defined(__APPLE__) || defined(HAVE_BSD_IEEE80211)
	int new_dlt;
#endif
#endif /* BIOCGDLTLIST */
#if defined(BIOCGHDRCMPLT) && defined(BIOCSHDRCMPLT)
	u_int spoof_eth_src = 1;
#endif
	u_int v;
	struct bpf_insn total_insn;
	struct bpf_program total_prog;
	struct utsname osinfo;
	int have_osinfo = 0;
#ifdef HAVE_ZEROCOPY_BPF
	struct bpf_zbuf bz;
	u_int bufmode, zbufmax;
#endif

	fd = bpf_open(p);
	if (fd < 0) {
		status = fd;
		goto bad;
	}

	p->fd = fd;

	if (ioctl(fd, BIOCVERSION, (caddr_t)&bv) < 0) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "BIOCVERSION: %s",
		    pcap_strerror(errno));
		status = PCAP_ERROR;
		goto bad;
	}
	if (bv.bv_major != BPF_MAJOR_VERSION ||
	    bv.bv_minor < BPF_MINOR_VERSION) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "kernel bpf filter out of date");
		status = PCAP_ERROR;
		goto bad;
	}

	p->md.device = strdup(p->opt.source);
	if (p->md.device == NULL) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "strdup: %s",
		     pcap_strerror(errno));
		status = PCAP_ERROR;
		goto bad;
	}

	/*
	 * Attempt to find out the version of the OS on which we're running.
	 */
	if (uname(&osinfo) == 0)
		have_osinfo = 1;

#ifdef __APPLE__
	/*
	 * See comment in pcap_can_set_rfmon_bpf() for an explanation
	 * of why we check the version number.
	 */
	if (p->opt.rfmon) {
		if (have_osinfo) {
			/*
			 * We assume osinfo.sysname is "Darwin", because
			 * __APPLE__ is defined.  We just check the version.
			 */
			if (osinfo.release[0] < '8' &&
			    osinfo.release[1] == '.') {
				/*
				 * 10.3 (Darwin 7.x) or earlier.
				 */
				status = PCAP_ERROR_RFMON_NOTSUP;
				goto bad;
			}
			if (osinfo.release[0] == '8' &&
			    osinfo.release[1] == '.') {
				/*
				 * 10.4 (Darwin 8.x).  s/en/wlt/
				 */
				if (strncmp(p->opt.source, "en", 2) != 0) {
					/*
					 * Not an enN device; check
					 * whether the device even exists.
					 */
					sockfd = socket(AF_INET, SOCK_DGRAM, 0);
					if (sockfd != -1) {
						strlcpy(ifr.ifr_name,
						    p->opt.source,
						    sizeof(ifr.ifr_name));
						if (ioctl(sockfd, SIOCGIFFLAGS,
						    (char *)&ifr) < 0) {
							/*
							 * We assume this
							 * failed because
							 * the underlying
							 * device doesn't
							 * exist.
							 */
							status = PCAP_ERROR_NO_SUCH_DEVICE;
							strcpy(p->errbuf, "");
						} else
							status = PCAP_ERROR_RFMON_NOTSUP;
						close(sockfd);
					} else {
						/*
						 * We can't find out whether
						 * the device exists, so just
						 * report "no such device".
						 */
						status = PCAP_ERROR_NO_SUCH_DEVICE;
						strcpy(p->errbuf, "");
					}
					goto bad;
				}
				wltdev = malloc(strlen(p->opt.source) + 2);
				if (wltdev == NULL) {
					(void)snprintf(p->errbuf,
					    PCAP_ERRBUF_SIZE, "malloc: %s",
					    pcap_strerror(errno));
					status = PCAP_ERROR;
					goto bad;
				}
				strcpy(wltdev, "wlt");
				strcat(wltdev, p->opt.source + 2);
				free(p->opt.source);
				p->opt.source = wltdev;
			}
			/*
			 * Everything else is 10.5 or later; for those,
			 * we just open the enN device, and set the DLT.
			 */
		}
	}
#endif /* __APPLE__ */
#ifdef HAVE_ZEROCOPY_BPF
	/*
	 * If the BPF extension to set buffer mode is present, try setting
	 * the mode to zero-copy.  If that fails, use regular buffering.  If
	 * it succeeds but other setup fails, return an error to the user.
	 */
	bufmode = BPF_BUFMODE_ZBUF;
	if (ioctl(fd, BIOCSETBUFMODE, (caddr_t)&bufmode) == 0) {
		/*
		 * We have zerocopy BPF; use it.
		 */
		p->md.zerocopy = 1;

		/*
		 * Set the cleanup and set/get nonblocking mode ops
		 * as appropriate for zero-copy mode.
		 */
		p->cleanup_op = pcap_cleanup_zbuf;
		p->setnonblock_op = pcap_setnonblock_zbuf;
		p->getnonblock_op = pcap_getnonblock_zbuf;

		/*
		 * How to pick a buffer size: first, query the maximum buffer
		 * size supported by zero-copy.  This also lets us quickly
		 * determine whether the kernel generally supports zero-copy.
		 * Then, if a buffer size was specified, use that, otherwise
		 * query the default buffer size, which reflects kernel
		 * policy for a desired default.  Round to the nearest page
		 * size.
		 */
		if (ioctl(fd, BIOCGETZMAX, (caddr_t)&zbufmax) < 0) {
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "BIOCGETZMAX: %s",
			    pcap_strerror(errno));
			goto bad;
		}

		if (p->opt.buffer_size != 0) {
			/*
			 * A buffer size was explicitly specified; use it.
			 */
			v = p->opt.buffer_size;
		} else {
			if ((ioctl(fd, BIOCGBLEN, (caddr_t)&v) < 0) ||
			    v < 32768)
				v = 32768;
		}
#ifndef roundup
#define roundup(x, y)   ((((x)+((y)-1))/(y))*(y))  /* to any y */
#endif
		p->md.zbufsize = roundup(v, getpagesize());
		if (p->md.zbufsize > zbufmax)
			p->md.zbufsize = zbufmax;
		p->md.zbuf1 = mmap(NULL, p->md.zbufsize, PROT_READ | PROT_WRITE,
		    MAP_ANON, -1, 0);
		p->md.zbuf2 = mmap(NULL, p->md.zbufsize, PROT_READ | PROT_WRITE,
		    MAP_ANON, -1, 0);
		if (p->md.zbuf1 == MAP_FAILED || p->md.zbuf2 == MAP_FAILED) {
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "mmap: %s",
			    pcap_strerror(errno));
			goto bad;
		}
		bzero(&bz, sizeof(bz));
		bz.bz_bufa = p->md.zbuf1;
		bz.bz_bufb = p->md.zbuf2;
		bz.bz_buflen = p->md.zbufsize;
		if (ioctl(fd, BIOCSETZBUF, (caddr_t)&bz) < 0) {
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "BIOCSETZBUF: %s",
			    pcap_strerror(errno));
			goto bad;
		}
		(void)strncpy(ifr.ifr_name, p->opt.source, sizeof(ifr.ifr_name));
		if (ioctl(fd, BIOCSETIF, (caddr_t)&ifr) < 0) {
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "BIOCSETIF: %s: %s",
			    p->opt.source, pcap_strerror(errno));
			goto bad;
		}
		v = p->md.zbufsize - sizeof(struct bpf_zbuf_header);
	} else
#endif
	{
		/*
		 * We don't have zerocopy BPF.
		 * Set the buffer size.
		 */
		if (p->opt.buffer_size != 0) {
			/*
			 * A buffer size was explicitly specified; use it.
			 */
			if (ioctl(fd, BIOCSBLEN,
			    (caddr_t)&p->opt.buffer_size) < 0) {
				snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
				    "BIOCSBLEN: %s: %s", p->opt.source,
				    pcap_strerror(errno));
				status = PCAP_ERROR;
				goto bad;
			}

			/*
			 * Now bind to the device.
			 */
			(void)strncpy(ifr.ifr_name, p->opt.source,
			    sizeof(ifr.ifr_name));
			if (ioctl(fd, BIOCSETIF, (caddr_t)&ifr) < 0) {
				status = check_setif_failure(p, errno);
				goto bad;
			}
		} else {
			/*
			 * No buffer size was explicitly specified.
			 *
			 * Try finding a good size for the buffer; 32768 may
			 * be too big, so keep cutting it in half until we
			 * find a size that works, or run out of sizes to try.
			 * If the default is larger, don't make it smaller.
			 */
			if ((ioctl(fd, BIOCGBLEN, (caddr_t)&v) < 0) ||
			    v < 32768)
				v = 32768;
			for ( ; v != 0; v >>= 1) {
				/*
				 * Ignore the return value - this is because the
				 * call fails on BPF systems that don't have
				 * kernel malloc.  And if the call fails, it's
				 * no big deal, we just continue to use the
				 * standard buffer size.
				 */
				(void) ioctl(fd, BIOCSBLEN, (caddr_t)&v);

				(void)strncpy(ifr.ifr_name, p->opt.source,
				    sizeof(ifr.ifr_name));
				if (ioctl(fd, BIOCSETIF, (caddr_t)&ifr) >= 0)
					break;	/* that size worked; we're done */

				if (errno != ENOBUFS) {
					status = check_setif_failure(p, errno);
					goto bad;
				}
			}

			if (v == 0) {
				snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
				    "BIOCSBLEN: %s: No buffer size worked",
				    p->opt.source);
				status = PCAP_ERROR;
				goto bad;
			}
		}
	}

	/* Get the data link layer type. */
	if (ioctl(fd, BIOCGDLT, (caddr_t)&v) < 0) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "BIOCGDLT: %s",
		    pcap_strerror(errno));
		status = PCAP_ERROR;
		goto bad;
	}

#ifdef _AIX
	/*
	 * AIX's BPF returns IFF_ types, not DLT_ types, in BIOCGDLT.
	 */
	switch (v) {

	case IFT_ETHER:
	case IFT_ISO88023:
		v = DLT_EN10MB;
		break;

	case IFT_FDDI:
		v = DLT_FDDI;
		break;

	case IFT_ISO88025:
		v = DLT_IEEE802;
		break;

	case IFT_LOOP:
		v = DLT_NULL;
		break;

	default:
		/*
		 * We don't know what to map this to yet.
		 */
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "unknown interface type %u",
		    v);
		status = PCAP_ERROR;
		goto bad;
	}
#endif
#if _BSDI_VERSION - 0 >= 199510
	/* The SLIP and PPP link layer header changed in BSD/OS 2.1 */
	switch (v) {

	case DLT_SLIP:
		v = DLT_SLIP_BSDOS;
		break;

	case DLT_PPP:
		v = DLT_PPP_BSDOS;
		break;

	case 11:	/*DLT_FR*/
		v = DLT_FRELAY;
		break;

	case 12:	/*DLT_C_HDLC*/
		v = DLT_CHDLC;
		break;
	}
#endif

#ifdef BIOCGDLTLIST
	/*
	 * We know the default link type -- now determine all the DLTs
	 * this interface supports.  If this fails with EINVAL, it's
	 * not fatal; we just don't get to use the feature later.
	 */
	if (get_dlt_list(fd, v, &bdl, p->errbuf) == -1) {
		status = PCAP_ERROR;
		goto bad;
	}
	p->dlt_count = bdl.bfl_len;
	p->dlt_list = bdl.bfl_list;

#ifdef __APPLE__
	/*
	 * Monitor mode fun, continued.
	 *
	 * For 10.5 and, we're assuming, later releases, as noted above,
	 * 802.1 adapters that support monitor mode offer both DLT_EN10MB,
	 * DLT_IEEE802_11, and possibly some 802.11-plus-radio-information
	 * DLT_ value.  Choosing one of the 802.11 DLT_ values will turn
	 * monitor mode on.
	 *
	 * Therefore, if the user asked for monitor mode, we filter out
	 * the DLT_EN10MB value, as you can't get that in monitor mode,
	 * and, if the user didn't ask for monitor mode, we filter out
	 * the 802.11 DLT_ values, because selecting those will turn
	 * monitor mode on.  Then, for monitor mode, if an 802.11-plus-
	 * radio DLT_ value is offered, we try to select that, otherwise
	 * we try to select DLT_IEEE802_11.
	 */
	if (have_osinfo) {
		if (isdigit((unsigned)osinfo.release[0]) &&
		     (osinfo.release[0] == '9' ||
		     isdigit((unsigned)osinfo.release[1]))) {
			/*
			 * 10.5 (Darwin 9.x), or later.
			 */
			new_dlt = find_802_11(&bdl);
			if (new_dlt != -1) {
				/*
				 * We have at least one 802.11 DLT_ value,
				 * so this is an 802.11 interface.
				 * new_dlt is the best of the 802.11
				 * DLT_ values in the list.
				 */
				if (p->opt.rfmon) {
					/*
					 * Our caller wants monitor mode.
					 * Purge DLT_EN10MB from the list
					 * of link-layer types, as selecting
					 * it will keep monitor mode off.
					 */
					remove_en(p);

					/*
					 * If the new mode we want isn't
					 * the default mode, attempt to
					 * select the new mode.
					 */
					if (new_dlt != v) {
						if (ioctl(p->fd, BIOCSDLT,
						    &new_dlt) != -1) {
							/*
							 * We succeeded;
							 * make this the
							 * new DLT_ value.
							 */
							v = new_dlt;
						}
					}
				} else {
					/*
					 * Our caller doesn't want
					 * monitor mode.  Unless this
					 * is being done by pcap_open_live(),
					 * purge the 802.11 link-layer types
					 * from the list, as selecting
					 * one of them will turn monitor
					 * mode on.
					 */
					if (!p->oldstyle)
						remove_802_11(p);
				}
			} else {
				if (p->opt.rfmon) {
					/*
					 * The caller requested monitor
					 * mode, but we have no 802.11
					 * link-layer types, so they
					 * can't have it.
					 */
					status = PCAP_ERROR_RFMON_NOTSUP;
					goto bad;
				}
			}
		}
	}
#elif defined(HAVE_BSD_IEEE80211)
	/*
	 * *BSD with the new 802.11 ioctls.
	 * Do we want monitor mode?
	 */
	if (p->opt.rfmon) {
		/*
		 * Try to put the interface into monitor mode.
		 */
		status = monitor_mode(p, 1);
		if (status != 0) {
			/*
			 * We failed.
			 */
			goto bad;
		}

		/*
		 * We're in monitor mode.
		 * Try to find the best 802.11 DLT_ value and, if we
		 * succeed, try to switch to that mode if we're not
		 * already in that mode.
		 */
		new_dlt = find_802_11(&bdl);
		if (new_dlt != -1) {
			/*
			 * We have at least one 802.11 DLT_ value.
			 * new_dlt is the best of the 802.11
			 * DLT_ values in the list.
			 *
			 * If the new mode we want isn't the default mode,
			 * attempt to select the new mode.
			 */
			if (new_dlt != v) {
				if (ioctl(p->fd, BIOCSDLT, &new_dlt) != -1) {
					/*
					 * We succeeded; make this the
					 * new DLT_ value.
					 */
					v = new_dlt;
				}
			}
		}
	}
#endif /* various platforms */
#endif /* BIOCGDLTLIST */

	/*
	 * If this is an Ethernet device, and we don't have a DLT_ list,
	 * give it a list with DLT_EN10MB and DLT_DOCSIS.  (That'd give
	 * 802.11 interfaces DLT_DOCSIS, which isn't the right thing to
	 * do, but there's not much we can do about that without finding
	 * some other way of determining whether it's an Ethernet or 802.11
	 * device.)
	 */
	if (v == DLT_EN10MB && p->dlt_count == 0) {
		p->dlt_list = (u_int *) malloc(sizeof(u_int) * 2);
		/*
		 * If that fails, just leave the list empty.
		 */
		if (p->dlt_list != NULL) {
			p->dlt_list[0] = DLT_EN10MB;
			p->dlt_list[1] = DLT_DOCSIS;
			p->dlt_count = 2;
		}
	}
#ifdef PCAP_FDDIPAD
	if (v == DLT_FDDI)
		p->fddipad = PCAP_FDDIPAD;
	else
		p->fddipad = 0;
#endif
	p->linktype = v;

#if defined(BIOCGHDRCMPLT) && defined(BIOCSHDRCMPLT)
	/*
	 * Do a BIOCSHDRCMPLT, if defined, to turn that flag on, so
	 * the link-layer source address isn't forcibly overwritten.
	 * (Should we ignore errors?  Should we do this only if
	 * we're open for writing?)
	 *
	 * XXX - I seem to remember some packet-sending bug in some
	 * BSDs - check CVS log for "bpf.c"?
	 */
	if (ioctl(fd, BIOCSHDRCMPLT, &spoof_eth_src) == -1) {
		(void)snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "BIOCSHDRCMPLT: %s", pcap_strerror(errno));
		status = PCAP_ERROR;
		goto bad;
	}
#endif
	/* set timeout */
#ifdef HAVE_ZEROCOPY_BPF
	if (p->md.timeout != 0 && !p->md.zerocopy) {
#else
	if (p->md.timeout) {
#endif
		/*
		 * XXX - is this seconds/nanoseconds in AIX?
		 * (Treating it as such doesn't fix the timeout
		 * problem described below.)
		 */
		struct timeval to;
		to.tv_sec = p->md.timeout / 1000;
		to.tv_usec = (p->md.timeout * 1000) % 1000000;
		if (ioctl(p->fd, BIOCSRTIMEOUT, (caddr_t)&to) < 0) {
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "BIOCSRTIMEOUT: %s",
			    pcap_strerror(errno));
			status = PCAP_ERROR;
			goto bad;
		}
	}

#ifdef _AIX
#ifdef	BIOCIMMEDIATE
	/*
	 * Darren Reed notes that
	 *
	 *	On AIX (4.2 at least), if BIOCIMMEDIATE is not set, the
	 *	timeout appears to be ignored and it waits until the buffer
	 *	is filled before returning.  The result of not having it
	 *	set is almost worse than useless if your BPF filter
	 *	is reducing things to only a few packets (i.e. one every
	 *	second or so).
	 *
	 * so we turn BIOCIMMEDIATE mode on if this is AIX.
	 *
	 * We don't turn it on for other platforms, as that means we
	 * get woken up for every packet, which may not be what we want;
	 * in the Winter 1993 USENIX paper on BPF, they say:
	 *
	 *	Since a process might want to look at every packet on a
	 *	network and the time between packets can be only a few
	 *	microseconds, it is not possible to do a read system call
	 *	per packet and BPF must collect the data from several
	 *	packets and return it as a unit when the monitoring
	 *	application does a read.
	 *
	 * which I infer is the reason for the timeout - it means we
	 * wait that amount of time, in the hopes that more packets
	 * will arrive and we'll get them all with one read.
	 *
	 * Setting BIOCIMMEDIATE mode on FreeBSD (and probably other
	 * BSDs) causes the timeout to be ignored.
	 *
	 * On the other hand, some platforms (e.g., Linux) don't support
	 * timeouts, they just hand stuff to you as soon as it arrives;
	 * if that doesn't cause a problem on those platforms, it may
	 * be OK to have BIOCIMMEDIATE mode on BSD as well.
	 *
	 * (Note, though, that applications may depend on the read
	 * completing, even if no packets have arrived, when the timeout
	 * expires, e.g. GUI applications that have to check for input
	 * while waiting for packets to arrive; a non-zero timeout
	 * prevents "select()" from working right on FreeBSD and
	 * possibly other BSDs, as the timer doesn't start until a
	 * "read()" is done, so the timer isn't in effect if the
	 * application is blocked on a "select()", and the "select()"
	 * doesn't get woken up for a BPF device until the buffer
	 * fills up.)
	 */
	v = 1;
	if (ioctl(p->fd, BIOCIMMEDIATE, &v) < 0) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "BIOCIMMEDIATE: %s",
		    pcap_strerror(errno));
		status = PCAP_ERROR;
		goto bad;
	}
#endif	/* BIOCIMMEDIATE */
#endif	/* _AIX */

	if (p->opt.promisc) {
		/* set promiscuous mode, just warn if it fails */
		if (ioctl(p->fd, BIOCPROMISC, NULL) < 0) {
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "BIOCPROMISC: %s",
			    pcap_strerror(errno));
			status = PCAP_WARNING_PROMISC_NOTSUP;
		}
	}

	if (ioctl(fd, BIOCGBLEN, (caddr_t)&v) < 0) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "BIOCGBLEN: %s",
		    pcap_strerror(errno));
		status = PCAP_ERROR;
		goto bad;
	}
	p->bufsize = v;
#ifdef HAVE_ZEROCOPY_BPF
	if (!p->md.zerocopy) {
#endif
	p->buffer = (u_char *)malloc(p->bufsize);
	if (p->buffer == NULL) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "malloc: %s",
		    pcap_strerror(errno));
		status = PCAP_ERROR;
		goto bad;
	}
#ifdef _AIX
	/* For some strange reason this seems to prevent the EFAULT
	 * problems we have experienced from AIX BPF. */
	memset(p->buffer, 0x0, p->bufsize);
#endif
#ifdef HAVE_ZEROCOPY_BPF
	}
#endif

	/*
	 * If there's no filter program installed, there's
	 * no indication to the kernel of what the snapshot
	 * length should be, so no snapshotting is done.
	 *
	 * Therefore, when we open the device, we install
	 * an "accept everything" filter with the specified
	 * snapshot length.
	 */
	total_insn.code = (u_short)(BPF_RET | BPF_K);
	total_insn.jt = 0;
	total_insn.jf = 0;
	total_insn.k = p->snapshot;

	total_prog.bf_len = 1;
	total_prog.bf_insns = &total_insn;
	if (ioctl(p->fd, BIOCSETF, (caddr_t)&total_prog) < 0) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "BIOCSETF: %s",
		    pcap_strerror(errno));
		status = PCAP_ERROR;
		goto bad;
	}

	/*
	 * On most BPF platforms, either you can do a "select()" or
	 * "poll()" on a BPF file descriptor and it works correctly,
	 * or you can do it and it will return "readable" if the
	 * hold buffer is full but not if the timeout expires *and*
	 * a non-blocking read will, if the hold buffer is empty
	 * but the store buffer isn't empty, rotate the buffers
	 * and return what packets are available.
	 *
	 * In the latter case, the fact that a non-blocking read
	 * will give you the available packets means you can work
	 * around the failure of "select()" and "poll()" to wake up
	 * and return "readable" when the timeout expires by using
	 * the timeout as the "select()" or "poll()" timeout, putting
	 * the BPF descriptor into non-blocking mode, and read from
	 * it regardless of whether "select()" reports it as readable
	 * or not.
	 *
	 * However, in FreeBSD 4.3 and 4.4, "select()" and "poll()"
	 * won't wake up and return "readable" if the timer expires
	 * and non-blocking reads return EWOULDBLOCK if the hold
	 * buffer is empty, even if the store buffer is non-empty.
	 *
	 * This means the workaround in question won't work.
	 *
	 * Therefore, on FreeBSD 4.3 and 4.4, we set "p->selectable_fd"
	 * to -1, which means "sorry, you can't use 'select()' or 'poll()'
	 * here".  On all other BPF platforms, we set it to the FD for
	 * the BPF device; in NetBSD, OpenBSD, and Darwin, a non-blocking
	 * read will, if the hold buffer is empty and the store buffer
	 * isn't empty, rotate the buffers and return what packets are
	 * there (and in sufficiently recent versions of OpenBSD
	 * "select()" and "poll()" should work correctly).
	 *
	 * XXX - what about AIX?
	 */
	p->selectable_fd = p->fd;	/* assume select() works until we know otherwise */
	if (have_osinfo) {
		/*
		 * We can check what OS this is.
		 */
		if (strcmp(osinfo.sysname, "FreeBSD") == 0) {
			if (strncmp(osinfo.release, "4.3-", 4) == 0 ||
			     strncmp(osinfo.release, "4.4-", 4) == 0)
				p->selectable_fd = -1;
		}
	}

	p->read_op = pcap_read_bpf;
	p->inject_op = pcap_inject_bpf;
	p->setfilter_op = pcap_setfilter_bpf;
	p->setdirection_op = pcap_setdirection_bpf;
	p->set_datalink_op = pcap_set_datalink_bpf;
	p->getnonblock_op = pcap_getnonblock_fd;
	p->setnonblock_op = pcap_setnonblock_fd;
	p->stats_op = pcap_stats_bpf;
	p->cleanup_op = pcap_cleanup_bpf;

	return (status);
 bad:
 	pcap_cleanup_bpf(p);
	return (status);
}

int
pcap_platform_finddevs(pcap_if_t **alldevsp, char *errbuf)
{
#ifdef HAVE_DAG_API
	if (dag_platform_finddevs(alldevsp, errbuf) < 0)
		return (-1);
#endif /* HAVE_DAG_API */

	return (0);
}

#ifdef HAVE_BSD_IEEE80211
static int
monitor_mode(pcap_t *p, int set)
{
	int sock;
	struct ifmediareq req;
	int *media_list;
	int i;
	int can_do;
	struct ifreq ifr;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "can't open socket: %s",
		    pcap_strerror(errno));
		return (PCAP_ERROR);
	}

	memset(&req, 0, sizeof req);
	strncpy(req.ifm_name, p->opt.source, sizeof req.ifm_name);

	/*
	 * Find out how many media types we have.
	 */
	if (ioctl(sock, SIOCGIFMEDIA, &req) < 0) {
		/*
		 * Can't get the media types.
		 */
		if (errno == EINVAL) {
			/*
			 * Interface doesn't support SIOC{G,S}IFMEDIA.
			 */
			close(sock);
			return (PCAP_ERROR_RFMON_NOTSUP);
		}
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "SIOCGIFMEDIA 1: %s",
		    pcap_strerror(errno));
		close(sock);
		return (PCAP_ERROR);
	}
	if (req.ifm_count == 0) {
		/*
		 * No media types.
		 */
		close(sock);
		return (PCAP_ERROR_RFMON_NOTSUP);
	}

	/*
	 * Allocate a buffer to hold all the media types, and
	 * get the media types.
	 */
	media_list = malloc(req.ifm_count * sizeof(int));
	if (media_list == NULL) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "malloc: %s",
		    pcap_strerror(errno));
		close(sock);
		return (PCAP_ERROR);
	}
	req.ifm_ulist = media_list;
	if (ioctl(sock, SIOCGIFMEDIA, &req) < 0) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "SIOCGIFMEDIA: %s",
		    pcap_strerror(errno));
		free(media_list);
		close(sock);
		return (PCAP_ERROR);
	}

	/*
	 * Look for an 802.11 "automatic" media type.
	 * We assume that all 802.11 adapters have that media type,
	 * and that it will carry the monitor mode supported flag.
	 */
	can_do = 0;
	for (i = 0; i < req.ifm_count; i++) {
		if (IFM_TYPE(media_list[i]) == IFM_IEEE80211
		    && IFM_SUBTYPE(media_list[i]) == IFM_AUTO) {
			/* OK, does it do monitor mode? */
			if (media_list[i] & IFM_IEEE80211_MONITOR) {
				can_do = 1;
				break;
			}
		}
	}
	free(media_list);
	if (!can_do) {
		/*
		 * This adapter doesn't support monitor mode.
		 */
		close(sock);
		return (PCAP_ERROR_RFMON_NOTSUP);
	}

	if (set) {
		/*
		 * Don't just check whether we can enable monitor mode,
		 * do so, if it's not already enabled.
		 */
		if ((req.ifm_current & IFM_IEEE80211_MONITOR) == 0) {
			/*
			 * Monitor mode isn't currently on, so turn it on,
			 * and remember that we should turn it off when the
			 * pcap_t is closed.
			 */

			/*
			 * If we haven't already done so, arrange to have
			 * "pcap_close_all()" called when we exit.
			 */
			if (!pcap_do_addexit(p)) {
				/*
				 * "atexit()" failed; don't put the interface
				 * in monitor mode, just give up.
				 */
				snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
				     "atexit failed");
				close(sock);
				return (PCAP_ERROR);
			}
			memset(&ifr, 0, sizeof(ifr));
			(void)strncpy(ifr.ifr_name, p->opt.source,
			    sizeof(ifr.ifr_name));
			ifr.ifr_media = req.ifm_current | IFM_IEEE80211_MONITOR;
			if (ioctl(sock, SIOCSIFMEDIA, &ifr) == -1) {
				snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
				     "SIOCSIFMEDIA: %s", pcap_strerror(errno));
				close(sock);
				return (PCAP_ERROR);
			}

			p->md.must_clear |= MUST_CLEAR_RFMON;

			/*
			 * Add this to the list of pcaps to close when we exit.
			 */
			pcap_add_to_pcaps_to_close(p);
		}
	}
	return (0);
}
#endif /* HAVE_BSD_IEEE80211 */

#if defined(BIOCGDLTLIST) && (defined(__APPLE__) || defined(HAVE_BSD_IEEE80211))
/*
 * Check whether we have any 802.11 link-layer types; return the best
 * of the 802.11 link-layer types if we find one, and return -1
 * otherwise.
 *
 * DLT_IEEE802_11_RADIO, with the radiotap header, is considered the
 * best 802.11 link-layer type; any of the other 802.11-plus-radio
 * headers are second-best; 802.11 with no radio information is
 * the least good.
 */
static int
find_802_11(struct bpf_dltlist *bdlp)
{
	int new_dlt;
	int i;

	/*
	 * Scan the list of DLT_ values, looking for 802.11 values,
	 * and, if we find any, choose the best of them.
	 */
	new_dlt = -1;
	for (i = 0; i < bdlp->bfl_len; i++) {
		switch (bdlp->bfl_list[i]) {

		case DLT_IEEE802_11:
			/*
			 * 802.11, but no radio.
			 *
			 * Offer this, and select it as the new mode
			 * unless we've already found an 802.11
			 * header with radio information.
			 */
			if (new_dlt == -1)
				new_dlt = bdlp->bfl_list[i];
			break;

		case DLT_PRISM_HEADER:
		case DLT_AIRONET_HEADER:
		case DLT_IEEE802_11_RADIO_AVS:
			/*
			 * 802.11 with radio, but not radiotap.
			 *
			 * Offer this, and select it as the new mode
			 * unless we've already found the radiotap DLT_.
			 */
			if (new_dlt != DLT_IEEE802_11_RADIO)
				new_dlt = bdlp->bfl_list[i];
			break;

		case DLT_IEEE802_11_RADIO:
			/*
			 * 802.11 with radiotap.
			 *
			 * Offer this, and select it as the new mode.
			 */
			new_dlt = bdlp->bfl_list[i];
			break;

		default:
			/*
			 * Not 802.11.
			 */
			break;
		}
	}

	return (new_dlt);
}
#endif /* defined(BIOCGDLTLIST) && (defined(__APPLE__) || defined(HAVE_BSD_IEEE80211)) */

#if defined(__APPLE__) && defined(BIOCGDLTLIST)
/*
 * Remove DLT_EN10MB from the list of DLT_ values.
 */
static void
remove_en(pcap_t *p)
{
	int i, j;

	/*
	 * Scan the list of DLT_ values and discard DLT_EN10MB.
	 */
	j = 0;
	for (i = 0; i < p->dlt_count; i++) {
		switch (p->dlt_list[i]) {

		case DLT_EN10MB:
			/*
			 * Don't offer this one.
			 */
			continue;

		default:
			/*
			 * Just copy this mode over.
			 */
			break;
		}

		/*
		 * Copy this DLT_ value to its new position.
		 */
		p->dlt_list[j] = p->dlt_list[i];
		j++;
	}

	/*
	 * Set the DLT_ count to the number of entries we copied.
	 */
	p->dlt_count = j;
}

/*
 * Remove DLT_EN10MB from the list of DLT_ values, and look for the
 * best 802.11 link-layer type in that list and return it.
 * Radiotap is better than anything else; 802.11 with any other radio
 * header is better than 802.11 with no radio header.
 */
static void
remove_802_11(pcap_t *p)
{
	int i, j;

	/*
	 * Scan the list of DLT_ values and discard 802.11 values.
	 */
	j = 0;
	for (i = 0; i < p->dlt_count; i++) {
		switch (p->dlt_list[i]) {

		case DLT_IEEE802_11:
		case DLT_PRISM_HEADER:
		case DLT_AIRONET_HEADER:
		case DLT_IEEE802_11_RADIO:
		case DLT_IEEE802_11_RADIO_AVS:
			/*
			 * 802.11.  Don't offer this one.
			 */
			continue;

		default:
			/*
			 * Just copy this mode over.
			 */
			break;
		}

		/*
		 * Copy this DLT_ value to its new position.
		 */
		p->dlt_list[j] = p->dlt_list[i];
		j++;
	}

	/*
	 * Set the DLT_ count to the number of entries we copied.
	 */
	p->dlt_count = j;
}
#endif /* defined(__APPLE__) && defined(BIOCGDLTLIST) */

static int
pcap_setfilter_bpf(pcap_t *p, struct bpf_program *fp)
{
	/*
	 * Free any user-mode filter we might happen to have installed.
	 */
	pcap_freecode(&p->fcode);

	/*
	 * Try to install the kernel filter.
	 */
	if (ioctl(p->fd, BIOCSETF, (caddr_t)fp) == 0) {
		/*
		 * It worked.
		 */
		p->md.use_bpf = 1;	/* filtering in the kernel */

		/*
		 * Discard any previously-received packets, as they might
		 * have passed whatever filter was formerly in effect, but
		 * might not pass this filter (BIOCSETF discards packets
		 * buffered in the kernel, so you can lose packets in any
		 * case).
		 */
		p->cc = 0;
		return (0);
	}

	/*
	 * We failed.
	 *
	 * If it failed with EINVAL, that's probably because the program
	 * is invalid or too big.  Validate it ourselves; if we like it
	 * (we currently allow backward branches, to support protochain),
	 * run it in userland.  (There's no notion of "too big" for
	 * userland.)
	 *
	 * Otherwise, just give up.
	 * XXX - if the copy of the program into the kernel failed,
	 * we will get EINVAL rather than, say, EFAULT on at least
	 * some kernels.
	 */
	if (errno != EINVAL) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "BIOCSETF: %s",
		    pcap_strerror(errno));
		return (-1);
	}

	/*
	 * install_bpf_program() validates the program.
	 *
	 * XXX - what if we already have a filter in the kernel?
	 */
	if (install_bpf_program(p, fp) < 0)
		return (-1);
	p->md.use_bpf = 0;	/* filtering in userland */
	return (0);
}

/*
 * Set direction flag: Which packets do we accept on a forwarding
 * single device? IN, OUT or both?
 */
static int
pcap_setdirection_bpf(pcap_t *p, pcap_direction_t d)
{
#if defined(BIOCSDIRECTION)
	u_int direction;

	direction = (d == PCAP_D_IN) ? BPF_D_IN :
	    ((d == PCAP_D_OUT) ? BPF_D_OUT : BPF_D_INOUT);
	if (ioctl(p->fd, BIOCSDIRECTION, &direction) == -1) {
		(void) snprintf(p->errbuf, sizeof(p->errbuf),
		    "Cannot set direction to %s: %s",
		        (d == PCAP_D_IN) ? "PCAP_D_IN" :
			((d == PCAP_D_OUT) ? "PCAP_D_OUT" : "PCAP_D_INOUT"),
			strerror(errno));
		return (-1);
	}
	return (0);
#elif defined(BIOCSSEESENT)
	u_int seesent;

	/*
	 * We don't support PCAP_D_OUT.
	 */
	if (d == PCAP_D_OUT) {
		snprintf(p->errbuf, sizeof(p->errbuf),
		    "Setting direction to PCAP_D_OUT is not supported on BPF");
		return -1;
	}

	seesent = (d == PCAP_D_INOUT);
	if (ioctl(p->fd, BIOCSSEESENT, &seesent) == -1) {
		(void) snprintf(p->errbuf, sizeof(p->errbuf),
		    "Cannot set direction to %s: %s",
		        (d == PCAP_D_INOUT) ? "PCAP_D_INOUT" : "PCAP_D_IN",
			strerror(errno));
		return (-1);
	}
	return (0);
#else
	(void) snprintf(p->errbuf, sizeof(p->errbuf),
	    "This system doesn't support BIOCSSEESENT, so the direction can't be set");
	return (-1);
#endif
}

static int
pcap_set_datalink_bpf(pcap_t *p, int dlt)
{
#ifdef BIOCSDLT
	if (ioctl(p->fd, BIOCSDLT, &dlt) == -1) {
		(void) snprintf(p->errbuf, sizeof(p->errbuf),
		    "Cannot set DLT %d: %s", dlt, strerror(errno));
		return (-1);
	}
#endif
	return (0);
}
