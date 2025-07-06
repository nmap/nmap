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

#include <config.h>

#include <sys/param.h>			/* optionally get BSD define */
#include <sys/socket.h>
#include <time.h>
/*
 * <net/bpf.h> defines ioctls, but doesn't include <sys/ioccom.h>.
 *
 * We include <sys/ioctl.h> as it might be necessary to declare ioctl();
 * at least on *BSD and macOS, it also defines various SIOC ioctls -
 * we could include <sys/sockio.h>, but if we're already including
 * <sys/ioctl.h>, which includes <sys/sockio.h> on those platforms,
 * there's not much point in doing so.
 *
 * If we have <sys/ioccom.h>, we include it as well, to handle systems
 * such as Solaris which don't arrange to include <sys/ioccom.h> if you
 * include <sys/ioctl.h>
 */
#include <sys/ioctl.h>
#ifdef HAVE_SYS_IOCCOM_H
#include <sys/ioccom.h>
#endif
#include <sys/utsname.h>

#if defined(__FreeBSD__) && defined(SIOCIFCREATE2)
/*
 * Add support for capturing on FreeBSD usbusN interfaces.
 */
static const char usbus_prefix[] = "usbus";
#define USBUS_PREFIX_LEN	(sizeof(usbus_prefix) - 1)
#include <dirent.h>
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

/*
 * If both BIOCROTZBUF and BPF_BUFMODE_ZBUF are defined, we have
 * zero-copy BPF.
 */
#if defined(BIOCROTZBUF) && defined(BPF_BUFMODE_ZBUF)
  #define HAVE_ZEROCOPY_BPF
  #include <sys/mman.h>
  #include <machine/atomic.h>
#endif

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

static int bpf_load(char *errbuf);

#else /* _AIX */

#include <net/bpf.h>

#endif /* _AIX */

#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>

#ifdef SIOCGIFMEDIA
# include <net/if_media.h>
#endif

#include "pcap-int.h"

#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

/*
 * Later versions of NetBSD stick padding in front of FDDI frames
 * to align the IP header on a 4-byte boundary.
 */
#if defined(__NetBSD__) && __NetBSD_Version__ > 106000000
#define       PCAP_FDDIPAD 3
#endif

/*
 * Private data for capturing on BPF devices.
 */
struct pcap_bpf {
#ifdef HAVE_ZEROCOPY_BPF
	/*
	 * Zero-copy read buffer -- for zero-copy BPF.  'buffer' above will
	 * alternative between these two actual mmap'd buffers as required.
	 * As there is a header on the front size of the mmap'd buffer, only
	 * some of the buffer is exposed to libpcap as a whole via bufsize;
	 * zbufsize is the true size.  zbuffer tracks the current zbuf
	 * associated with buffer so that it can be used to decide which the
	 * next buffer to read will be.
	 */
	u_char *zbuf1, *zbuf2, *zbuffer;
	u_int zbufsize;
	u_int zerocopy;
	u_int interrupted;
	struct timespec firstsel;
	/*
	 * If there's currently a buffer being actively processed, then it is
	 * referenced here; 'buffer' is also pointed at it, but offset by the
	 * size of the header.
	 */
	struct bpf_zbuf_header *bzh;
	int nonblock;		/* true if in nonblocking mode */
#endif /* HAVE_ZEROCOPY_BPF */

	char *device;		/* device name */
	int filtering_in_kernel; /* using kernel filter */
	int must_do_on_close;	/* stuff we must do when we close */
};

/*
 * Stuff to do when we close.
 */
#define MUST_CLEAR_RFMON	0x00000001	/* clear rfmon (monitor) mode */
#define MUST_DESTROY_USBUS	0x00000002	/* destroy usbusN interface */

#ifdef BIOCGDLTLIST
# if (defined(HAVE_NET_IF_MEDIA_H) && defined(IFM_IEEE80211)) && !defined(__APPLE__)
#define HAVE_BSD_IEEE80211

/*
 * The ifm_ulist member of a struct ifmediareq is an int * on most systems,
 * but it's a uint64_t on newer versions of OpenBSD.
 *
 * We check this by checking whether IFM_GMASK is defined and > 2^32-1.
 */
#  if defined(IFM_GMASK) && IFM_GMASK > 0xFFFFFFFF
#    define IFM_ULIST_TYPE	uint64_t
#  else
#    define IFM_ULIST_TYPE	int
#  endif
# endif

# if defined(__APPLE__) || defined(HAVE_BSD_IEEE80211)
static int find_802_11(struct bpf_dltlist *);

#  ifdef HAVE_BSD_IEEE80211
static int monitor_mode(pcap_t *, int);
#  endif

#  if defined(__APPLE__)
static void remove_non_802_11(pcap_t *);
static void remove_802_11(pcap_t *);
#  endif

# endif /* defined(__APPLE__) || defined(HAVE_BSD_IEEE80211) */

#endif /* BIOCGDLTLIST */

#if defined(sun) && defined(LIFNAMSIZ) && defined(lifr_zoneid)
#include <zone.h>
#endif

/*
 * We include the OS's <net/bpf.h>, not our "pcap/bpf.h", so we probably
 * don't get DLT_DOCSIS defined.
 */
#ifndef DLT_DOCSIS
#define DLT_DOCSIS	143
#endif

/*
 * In some versions of macOS, we might not even get any of the
 * 802.11-plus-radio-header DLT_'s defined, even though some
 * of them are used by various Airport drivers in those versions.
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

/*
 * For zerocopy bpf, the setnonblock/getnonblock routines need to modify
 * pb->nonblock so we don't call select(2) if the pcap handle is in non-
 * blocking mode.
 */
static int
pcap_getnonblock_bpf(pcap_t *p)
{
#ifdef HAVE_ZEROCOPY_BPF
	struct pcap_bpf *pb = p->priv;

	if (pb->zerocopy)
		return (pb->nonblock);
#endif
	return (pcapint_getnonblock_fd(p));
}

static int
pcap_setnonblock_bpf(pcap_t *p, int nonblock)
{
#ifdef HAVE_ZEROCOPY_BPF
	struct pcap_bpf *pb = p->priv;

	if (pb->zerocopy) {
		pb->nonblock = nonblock;
		return (0);
	}
#endif
	return (pcapint_setnonblock_fd(p, nonblock));
}

#ifdef HAVE_ZEROCOPY_BPF
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
	struct pcap_bpf *pb = p->priv;
	struct bpf_zbuf_header *bzh;

	if (pb->zbuffer == pb->zbuf2 || pb->zbuffer == NULL) {
		bzh = (struct bpf_zbuf_header *)pb->zbuf1;
		if (bzh->bzh_user_gen !=
		    atomic_load_acq_int(&bzh->bzh_kernel_gen)) {
			pb->bzh = bzh;
			pb->zbuffer = (u_char *)pb->zbuf1;
			p->buffer = pb->zbuffer + sizeof(*bzh);
			*cc = bzh->bzh_kernel_len;
			return (1);
		}
	} else if (pb->zbuffer == pb->zbuf1) {
		bzh = (struct bpf_zbuf_header *)pb->zbuf2;
		if (bzh->bzh_user_gen !=
		    atomic_load_acq_int(&bzh->bzh_kernel_gen)) {
			pb->bzh = bzh;
			pb->zbuffer = (u_char *)pb->zbuf2;
			p->buffer = pb->zbuffer + sizeof(*bzh);
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
	struct pcap_bpf *pb = p->priv;
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
	 * our timeout is less than or equal to zero, handle it like a
	 * regular timeout.
	 */
	tmout = p->opt.timeout;
	if (tmout)
		(void) clock_gettime(CLOCK_MONOTONIC, &cur);
	if (pb->interrupted && p->opt.timeout) {
		expire = TSTOMILLI(&pb->firstsel) + p->opt.timeout;
		tmout = expire - TSTOMILLI(&cur);
#undef TSTOMILLI
		if (tmout <= 0) {
			pb->interrupted = 0;
			data = pcap_next_zbuf_shm(p, cc);
			if (data)
				return (data);
			if (ioctl(p->fd, BIOCROTZBUF, &bz) < 0) {
				pcapint_fmt_errmsg_for_errno(p->errbuf,
				    PCAP_ERRBUF_SIZE, errno, "BIOCROTZBUF");
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
	if (!pb->nonblock) {
		FD_ZERO(&r_set);
		FD_SET(p->fd, &r_set);
		if (tmout != 0) {
			tv.tv_sec = tmout / 1000;
			tv.tv_usec = (tmout * 1000) % 1000000;
		}
		r = select(p->fd + 1, &r_set, NULL, NULL,
		    p->opt.timeout != 0 ? &tv : NULL);
		if (r < 0 && errno == EINTR) {
			if (!pb->interrupted && p->opt.timeout) {
				pb->interrupted = 1;
				pb->firstsel = cur;
			}
			return (0);
		} else if (r < 0) {
			pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
			    errno, "select");
			return (PCAP_ERROR);
		}
	}
	pb->interrupted = 0;
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
		pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "BIOCROTZBUF");
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
	struct pcap_bpf *pb = p->priv;

	atomic_store_rel_int(&pb->bzh->bzh_user_gen,
	    pb->bzh->bzh_kernel_gen);
	pb->bzh = NULL;
	p->buffer = NULL;
	return (0);
}
#endif /* HAVE_ZEROCOPY_BPF */

pcap_t *
pcapint_create_interface(const char *device _U_, char *ebuf)
{
	pcap_t *p;

	p = PCAP_CREATE_COMMON(ebuf, struct pcap_bpf);
	if (p == NULL)
		return (NULL);

	p->activate_op = pcap_activate_bpf;
	p->can_set_rfmon_op = pcap_can_set_rfmon_bpf;
#ifdef BIOCSTSTAMP
	/*
	 * We claim that we support microsecond and nanosecond time
	 * stamps.
	 */
	p->tstamp_precision_list = malloc(2 * sizeof(u_int));
	if (p->tstamp_precision_list == NULL) {
		pcapint_fmt_errmsg_for_errno(ebuf, PCAP_ERRBUF_SIZE, errno,
		    "malloc");
		free(p);
		return (NULL);
	}
	p->tstamp_precision_list[0] = PCAP_TSTAMP_PRECISION_MICRO;
	p->tstamp_precision_list[1] = PCAP_TSTAMP_PRECISION_NANO;
	p->tstamp_precision_count = 2;
#endif /* BIOCSTSTAMP */
	return (p);
}

/*
 * On success, returns a file descriptor for a BPF device.
 * On failure, returns a PCAP_ERROR_ value, and sets p->errbuf.
 */
static int
bpf_open(char *errbuf)
{
	int fd = -1;
	static const char cloning_device[] = "/dev/bpf";
	u_int n = 0;
	char device[sizeof "/dev/bpf0000000000"];
	static int no_cloning_bpf = 0;

#ifdef _AIX
	/*
	 * Load the bpf driver, if it isn't already loaded,
	 * and create the BPF device entries, if they don't
	 * already exist.
	 */
	if (bpf_load(errbuf) == PCAP_ERROR)
		return (PCAP_ERROR);
#endif

	/*
	 * First, unless we've already tried opening /dev/bpf and
	 * gotten ENOENT, try opening /dev/bpf.
	 * If it fails with ENOENT, remember that, so we don't try
	 * again, and try /dev/bpfN.
	 */
	if (!no_cloning_bpf &&
	    (fd = open(cloning_device, O_RDWR)) == -1 &&
	    ((errno != EACCES && errno != ENOENT) ||
	     (fd = open(cloning_device, O_RDONLY)) == -1)) {
		if (errno != ENOENT) {
			if (errno == EACCES) {
				fd = PCAP_ERROR_PERM_DENIED;
				snprintf(errbuf, PCAP_ERRBUF_SIZE,
				    "Attempt to open %s failed - root privileges may be required",
				    cloning_device);
			} else {
				fd = PCAP_ERROR;
				pcapint_fmt_errmsg_for_errno(errbuf,
				    PCAP_ERRBUF_SIZE, errno,
				    "(cannot open device) %s", cloning_device);
			}
			return (fd);
		}
		no_cloning_bpf = 1;
	}

	if (no_cloning_bpf) {
		/*
		 * We don't have /dev/bpf.
		 * Go through all the /dev/bpfN minors and find one
		 * that isn't in use.
		 */
		do {
			(void)snprintf(device, sizeof(device), "/dev/bpf%u", n++);
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
	}

	/*
	 * XXX better message for all minors used
	 */
	if (fd < 0) {
		switch (errno) {

		case ENOENT:
			if (n == 1) {
				/*
				 * /dev/bpf0 doesn't exist, which
				 * means we probably have no BPF
				 * devices.
				 */
				fd = PCAP_ERROR_CAPTURE_NOTSUP;
				snprintf(errbuf, PCAP_ERRBUF_SIZE,
				    "(there are no BPF devices)");
			} else {
				/*
				 * We got EBUSY on at least one
				 * BPF device, so we have BPF
				 * devices, but all the ones
				 * that exist are busy.
				 */
				fd = PCAP_ERROR;
				snprintf(errbuf, PCAP_ERRBUF_SIZE,
				    "(all BPF devices are busy)");
			}
			break;

		case EACCES:
			/*
			 * Got EACCES on the last device we tried,
			 * and EBUSY on all devices before that,
			 * if any.
			 */
			fd = PCAP_ERROR_PERM_DENIED;
			snprintf(errbuf, PCAP_ERRBUF_SIZE,
			    "Attempt to open %s failed - root privileges may be required",
			    device);
			break;

		default:
			/*
			 * Some other problem.
			 */
			fd = PCAP_ERROR;
			pcapint_fmt_errmsg_for_errno(errbuf, PCAP_ERRBUF_SIZE,
			    errno, "(cannot open BPF device) %s", device);
			break;
		}
	}

	return (fd);
}

/*
 * Bind a network adapter to a BPF device, given a descriptor for the
 * BPF device and the name of the network adapter.
 *
 * Use BIOCSETLIF if available (meaning "on Solaris"), as it supports
 * longer device names and binding to devices in other zones.
 *
 * If the name is longer than will fit, return PCAP_ERROR_NO_SUCH_DEVICE
 * before trying to bind the interface, as there cannot be such a device.
 *
 * If the attempt succeeds, return BPF_BIND_SUCCEEDED.
 *
 * If the attempt fails:
 *
 *    if it fails with ENOBUFS, return BPF_BIND_BUFFER_TOO_BIG, and
 *    fill in an error message, as the buffer being requested is too
 *    large - our caller may try a smaller buffer if no buffer size
 *    was explicitly specified.
 *
 *    otherwise, return the appropriate PCAP_ERROR_ code and
 *    fill in an error message.
 */
#define BPF_BIND_SUCCEEDED	0
#define BPF_BIND_BUFFER_TOO_BIG	1

static int
bpf_bind(int fd, const char *name, char *errbuf)
{
	int status;
#ifdef LIFNAMSIZ
	struct lifreq ifr;
	const char *ifname = name;

  #if defined(ZONENAME_MAX) && defined(lifr_zoneid)
	char *zonesep;

	/*
	 * We have support for zones.
	 * Retrieve the zoneid of the zone we are currently executing in.
	 */
	if ((ifr.lifr_zoneid = getzoneid()) == -1) {
		pcapint_fmt_errmsg_for_errno(errbuf, PCAP_ERRBUF_SIZE,
		    errno, "getzoneid()");
		return (PCAP_ERROR);
	}

	/*
	 * Check if the given source datalink name has a '/' separated
	 * zonename prefix string.  The zonename prefixed source datalink can
	 * be used by pcap consumers in the Solaris global zone to capture
	 * traffic on datalinks in non-global zones.  Non-global zones
	 * do not have access to datalinks outside of their own namespace.
	 */
	if ((zonesep = strchr(name, '/')) != NULL) {
		char *zname;
		ptrdiff_t znamelen;

		if (ifr.lifr_zoneid != GLOBAL_ZONEID) {
			/*
			 * We treat this as a generic error rather
			 * than as "permission denied" because
			 * this isn't a case of "you don't have
			 * enough permission to capture on this
			 * device, so you'll have to do something
			 * to get that permission" (such as
			 * configuring the system to allow non-root
			 * users to capture traffic), it's a case
			 * of "nobody has permission to do this,
			 * so there's nothing to do to fix it
			 * other than running the capture program
			 * in the global zone or the zone containing
			 * the adapter".
			 *
			 * (And, yes, this is a real issue; for example,
			 * Wireshark might make platform-specific suggestions
			 * on how to fix a PCAP_ERROR_PERM_DENIED problem,
			 * none of which will help here.)
			 */
			snprintf(errbuf, PCAP_ERRBUF_SIZE,
			    "zonename/linkname only valid in global zone.");
			return (PCAP_ERROR);
		}
		znamelen = zonesep - name;
		zname = malloc(znamelen + 1);
		if (zname == NULL) {
			pcapint_fmt_errmsg_for_errno(errbuf, PCAP_ERRBUF_SIZE,
			    errno, "malloc");
			return (PCAP_ERROR);
		}
		memcpy(zname, name, znamelen + 1);
		zname[znamelen] = '\0';
		ifr.lifr_zoneid = getzoneidbyname(zname);
		if (ifr.lifr_zoneid == -1) {
			switch (errno) {

			case EINVAL:
			case ENAMETOOLONG:
				/*
				 * If the name's length exceeds
				 * ZONENAMEMAX, clearly there cannot
				 * be such a zone; it's not clear that
				 * "that name's too long for a zone"
				 * is more informative than "there's
				 * no such zone".
				 */
				snprintf(errbuf, PCAP_ERRBUF_SIZE,
				    "There is no zone named \"%s\"",
				    zname);

				/*
				 * No such zone means the name
				 * refers to a non-existent interface.
				 */
				status = PCAP_ERROR_NO_SUCH_DEVICE;
				break;

			default:
				pcapint_fmt_errmsg_for_errno(errbuf,
				    PCAP_ERRBUF_SIZE, errno,
				    "getzoneidbyname(%s)", zname);
				status = PCAP_ERROR;
				break;
			}
			free(zname);
			return (status);
		}
		free(zname);

		/*
		 * To bind to this interface, we set the ifr.lifr_zoneid
		 * to the zone ID of its zone (done above), and we set
		 * ifr.lifr_name to the name of the interface within that
		 * zone (done below, using ifname).
		 */
		ifname = zonesep + 1;
	}
  #endif

	if (strlen(ifname) >= sizeof(ifr.lifr_name)) {
		/* The name is too long, so it can't possibly exist. */
		return (PCAP_ERROR_NO_SUCH_DEVICE);
	}
	(void)pcapint_strlcpy(ifr.lifr_name, ifname, sizeof(ifr.lifr_name));
	status = ioctl(fd, BIOCSETLIF, (caddr_t)&ifr);
#else
	struct ifreq ifr;

	if (strlen(name) >= sizeof(ifr.ifr_name)) {
		/* The name is too long, so it can't possibly exist. */
		return (PCAP_ERROR_NO_SUCH_DEVICE);
	}
	(void)pcapint_strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
	status = ioctl(fd, BIOCSETIF, (caddr_t)&ifr);
#endif

	if (status < 0) {
		switch (errno) {

#if defined(HAVE_SOLARIS)
		/*
		 * For some reason, Solaris 11 appears to return ESRCH
		 * for unknown devices.
		 */
		case ESRCH:
#else
		/*
		 * The *BSDs (including CupertinoBSD a/k/a Darwin)
		 * return ENXIO for unknown devices.
		 */
		case ENXIO:
#endif
			/*
			 * There's no such device.
			 *
			 * There's nothing more to say, so clear out the
			 * error message.
			 */
			errbuf[0] = '\0';
			return (PCAP_ERROR_NO_SUCH_DEVICE);

		case ENETDOWN:
			/*
			 * Return a "network down" indication, so that
			 * the application can report that rather than
			 * saying we had a mysterious failure and
			 * suggest that they report a problem to the
			 * libpcap developers.
			 */
			return (PCAP_ERROR_IFACE_NOT_UP);

		case ENOBUFS:
			/*
			 * The buffer size is too big.
			 * Return a special indication so that, if we're
			 * trying to crank the buffer size down, we know
			 * we have to continue; add an error message that
			 * tells the user what needs to be fixed.
			 */
			pcapint_fmt_errmsg_for_errno(errbuf, PCAP_ERRBUF_SIZE,
			    errno, "The requested buffer size for %s is too large",
			    name);
			return (BPF_BIND_BUFFER_TOO_BIG);

		default:
			pcapint_fmt_errmsg_for_errno(errbuf, PCAP_ERRBUF_SIZE,
			    errno, "Binding interface %s to BPF device failed",
			    name);
			return (PCAP_ERROR);
		}
	}
	return (BPF_BIND_SUCCEEDED);
}

/*
 * Open and bind to a device; used if we're not actually going to use
 * the device, but are just testing whether it can be opened, or opening
 * it to get information about it.
 *
 * Returns an error code on failure (always negative), and an FD for
 * the now-bound BPF device on success (always non-negative).
 */
static int
bpf_open_and_bind(const char *name, char *errbuf)
{
	int fd;
	int status;

	/*
	 * First, open a BPF device.
	 */
	fd = bpf_open(errbuf);
	if (fd < 0)
		return (fd);	/* fd is the appropriate error code */

	/*
	 * Now bind to the device.
	 */
	status = bpf_bind(fd, name, errbuf);
	if (status != BPF_BIND_SUCCEEDED) {
		close(fd);
		if (status == BPF_BIND_BUFFER_TOO_BIG) {
			/*
			 * We didn't specify a buffer size, so
			 * this *really* shouldn't fail because
			 * there's no buffer space.  Fail.
			 */
			return (PCAP_ERROR);
		}
		return (status);
	}

	/*
	 * Success.
	 */
	return (fd);
}

#ifdef __APPLE__
static int
device_exists(int fd, const char *name, char *errbuf)
{
	int status;
	struct ifreq ifr;

	if (strlen(name) >= sizeof(ifr.ifr_name)) {
		/* The name is too long, so it can't possibly exist. */
		return (PCAP_ERROR_NO_SUCH_DEVICE);
	}
	(void)pcapint_strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
	status = ioctl(fd, SIOCGIFFLAGS, (caddr_t)&ifr);

	if (status < 0) {
		if (errno == ENXIO || errno == EINVAL) {
			/*
			 * macOS and *BSD return one of those two
			 * errors if the device doesn't exist.
			 * Don't fill in an error, as this is
			 * an "expected" condition.
			 */
			return (PCAP_ERROR_NO_SUCH_DEVICE);
		}

		/*
		 * Some other error - provide a message for it, as
		 * it's "unexpected".
		 */
		pcapint_fmt_errmsg_for_errno(errbuf, PCAP_ERRBUF_SIZE, errno,
		    "Can't get interface flags on %s", name);
		return (PCAP_ERROR);
	}

	/*
	 * The device exists.
	 */
	return (0);
}
#endif

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
			pcapint_fmt_errmsg_for_errno(ebuf, PCAP_ERRBUF_SIZE,
			    errno, "malloc");
			return (PCAP_ERROR);
		}

		if (ioctl(fd, BIOCGDLTLIST, (caddr_t)bdlp) < 0) {
			pcapint_fmt_errmsg_for_errno(ebuf, PCAP_ERRBUF_SIZE,
			    errno, "BIOCGDLTLIST");
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
		 *
		 * On Solaris with BPF, Ethernet devices also offer
		 * DLT_IPNET, so we, if DLT_IPNET is defined, we don't
		 * treat it as an indication that the device isn't an
		 * Ethernet.
		 */
		if (v == DLT_EN10MB) {
			is_ethernet = 1;
			for (i = 0; i < bdlp->bfl_len; i++) {
				if (bdlp->bfl_list[i] != DLT_EN10MB
#ifdef DLT_IPNET
				    && bdlp->bfl_list[i] != DLT_IPNET
#endif
				    ) {
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
			pcapint_fmt_errmsg_for_errno(ebuf, PCAP_ERRBUF_SIZE,
			    errno, "BIOCGDLTLIST");
			return (PCAP_ERROR);
		}
	}
	return (0);
}
#endif

#if defined(__APPLE__)
static int
pcap_can_set_rfmon_bpf(pcap_t *p)
{
	struct utsname osinfo;
	int fd;
#ifdef BIOCGDLTLIST
	struct bpf_dltlist bdl;
	int err;
#endif

	/*
	 * The joys of monitor mode on Mac OS X/OS X/macOS.
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
		char *wlt_name;
		int status;

		/*
		 * 10.4 (Darwin 8.x).  s/en/wlt/, and check
		 * whether the device exists.
		 */
		if (strncmp(p->opt.device, "en", 2) != 0) {
			/*
			 * Not an enN device; no monitor mode.
			 */
			return (0);
		}
		fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (fd == -1) {
			pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
			    errno, "socket");
			return (PCAP_ERROR);
		}
		if (pcapint_asprintf(&wlt_name, "wlt%s", p->opt.device + 2) == -1) {
			pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
			    errno, "malloc");
			close(fd);
			return (PCAP_ERROR);
		}
		status = device_exists(fd, wlt_name, p->errbuf);
		free(wlt_name);
		close(fd);
		if (status != 0) {
			if (status == PCAP_ERROR_NO_SUCH_DEVICE)
				return (0);

			/*
			 * Error.
			 */
			return (status);
		}
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
	fd = bpf_open(p->errbuf);
	if (fd < 0)
		return (fd);	/* fd is the appropriate error code */

	/*
	 * Now bind to the device.
	 */
	err = bpf_bind(fd, p->opt.device, p->errbuf);
	if (err != BPF_BIND_SUCCEEDED) {
		close(fd);
		if (err == BPF_BIND_BUFFER_TOO_BIG) {
			/*
			 * We didn't specify a buffer size, so
			 * this *really* shouldn't fail because
			 * there's no buffer space.  Fail.
			 */
			return (PCAP_ERROR);
		}
		return (err);
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
	close(fd);
#endif /* BIOCGDLTLIST */
	return (0);
}
#elif defined(HAVE_BSD_IEEE80211)
static int
pcap_can_set_rfmon_bpf(pcap_t *p)
{
	int ret;

	ret = monitor_mode(p, 0);
	if (ret == PCAP_ERROR_RFMON_NOTSUP)
		return (0);	/* not an error, just a "can't do" */
	if (ret == 0)
		return (1);	/* success */
	return (ret);
}
#else
static int
pcap_can_set_rfmon_bpf(pcap_t *p _U_)
{
	return (0);
}
#endif

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
		pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "BIOCGSTATS");
		return (PCAP_ERROR);
	}

	/*
	 * On illumos, NetBSD and Solaris these values are 64-bit, but struct
	 * pcap_stat is what it is, so the integer precision loss is expected.
	 */
	ps->ps_recv = (u_int)s.bs_recv;
	ps->ps_drop = (u_int)s.bs_drop;
	ps->ps_ifdrop = 0;
	return (0);
}

static int
pcap_read_bpf(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
{
	struct pcap_bpf *pb = p->priv;
	ssize_t cc;
	int n = 0;
	register u_char *bp, *ep;
	u_char *datap;
#ifdef PCAP_FDDIPAD
	register u_int pad;
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
		if (pb->zerocopy) {
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
			cc = read(p->fd, p->buffer, p->bufsize);
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

			case ENXIO:	/* FreeBSD, DragonFly BSD, and Darwin */
			case EIO:	/* OpenBSD */
					/* NetBSD appears not to return an error in this case */
				/*
				 * The device on which we're capturing
				 * went away.
				 *
				 * XXX - we should really return
				 * an appropriate error for that,
				 * but pcap_dispatch() etc. aren't
				 * documented as having error returns
				 * other than PCAP_ERROR or PCAP_ERROR_BREAK.
				 */
				snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
				    "The interface disappeared");
				return (PCAP_ERROR);

#if defined(sun) && !defined(BSD) && !defined(__svr4__) && !defined(__SVR4)
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
			pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
			    errno, "read");
			return (PCAP_ERROR);
		}
		bp = (u_char *)p->buffer;
	} else
		bp = p->bp;

	/*
	 * Loop through each packet.
	 *
	 * This assumes that a single buffer of packets will have
	 * <= INT_MAX packets, so the packet count doesn't overflow.
	 */
#ifdef BIOCSTSTAMP
#define bhp ((struct bpf_xhdr *)bp)
#else
#define bhp ((struct bpf_hdr *)bp)
#endif
	ep = bp + cc;
#ifdef PCAP_FDDIPAD
	pad = p->fddipad;
#endif
	while (bp < ep) {
		register u_int caplen, hdrlen;

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
			p->bp = bp;
			p->cc = (int)(ep - bp);
			/*
			 * ep is set based on the return value of read(),
			 * but read() from a BPF device doesn't necessarily
			 * return a value that's a multiple of the alignment
			 * value for BPF_WORDALIGN().  However, whenever we
			 * increment bp, we round up the increment value by
			 * a value rounded up by BPF_WORDALIGN(), so we
			 * could increment bp past ep after processing the
			 * last packet in the buffer.
			 *
			 * We treat ep < bp as an indication that this
			 * happened, and just set p->cc to 0.
			 */
			if (p->cc < 0)
				p->cc = 0;
			if (n == 0) {
				p->break_loop = 0;
				return (PCAP_ERROR_BREAK);
			} else
				return (n);
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
		if (pb->filtering_in_kernel ||
		    pcapint_filter(p->fcode.bf_insns, datap, bhp->bh_datalen, caplen)) {
			struct pcap_pkthdr pkthdr;
#ifdef BIOCSTSTAMP
			struct bintime bt;

			bt.sec = bhp->bh_tstamp.bt_sec;
			bt.frac = bhp->bh_tstamp.bt_frac;
			if (p->opt.tstamp_precision == PCAP_TSTAMP_PRECISION_NANO) {
				struct timespec ts;

				bintime2timespec(&bt, &ts);
				pkthdr.ts.tv_sec = ts.tv_sec;
				pkthdr.ts.tv_usec = ts.tv_nsec;
			} else {
				struct timeval tv;

				bintime2timeval(&bt, &tv);
				pkthdr.ts.tv_sec = tv.tv_sec;
				pkthdr.ts.tv_usec = tv.tv_usec;
			}
#else
			pkthdr.ts.tv_sec = bhp->bh_tstamp.tv_sec;
#ifdef _AIX
			/*
			 * AIX's BPF returns seconds/nanoseconds time
			 * stamps, not seconds/microseconds time stamps.
			 */
			pkthdr.ts.tv_usec = bhp->bh_tstamp.tv_usec/1000;
#else
			/*
			 * On NetBSD the former (timeval.tv_usec) is an int via
			 * suseconds_t and the latter (bpf_timeval.tv_usec) is
			 * a long.  In any case, the value is supposed to be
			 * within the [0 .. 999999] interval.
			 */
			pkthdr.ts.tv_usec = (suseconds_t)bhp->bh_tstamp.tv_usec;
#endif
#endif /* BIOCSTSTAMP */
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
			if (++n >= cnt && !PACKET_COUNT_IS_UNLIMITED(cnt)) {
				p->bp = bp;
				p->cc = (int)(ep - bp);
				/*
				 * See comment above about p->cc < 0.
				 */
				if (p->cc < 0)
					p->cc = 0;
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
pcap_inject_bpf(pcap_t *p, const void *buf, int size)
{
	int ret;

	ret = (int)write(p->fd, buf, size);
#ifdef __APPLE__
	if (ret == -1 && errno == EAFNOSUPPORT) {
		/*
		 * In some versions of macOS, there's a bug wherein setting
		 * the BIOCSHDRCMPLT flag causes writes to fail; see, for
		 * example:
		 *
		 *	http://cerberus.sourcefire.com/~jeff/archives/patches/macosx/BIOCSHDRCMPLT-10.3.3.patch
		 *
		 * So, if, on macOS, we get EAFNOSUPPORT from the write, we
		 * assume it's due to that bug, and turn off that flag
		 * and try again.  If we succeed, it either means that
		 * somebody applied the fix from that URL, or other patches
		 * for that bug from
		 *
		 *	http://cerberus.sourcefire.com/~jeff/archives/patches/macosx/
		 *
		 * and are running a Darwin kernel with those fixes, or
		 * that Apple fixed the problem in some macOS release.
		 */
		u_int spoof_eth_src = 0;

		if (ioctl(p->fd, BIOCSHDRCMPLT, &spoof_eth_src) == -1) {
			pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
			    errno, "send: can't turn off BIOCSHDRCMPLT");
			return (PCAP_ERROR);
		}

		/*
		 * Now try the write again.
		 */
		ret = (int)write(p->fd, buf, size);
	}
#endif /* __APPLE__ */
	if (ret == -1) {
		pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "send");
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
		(void)odm_terminate();
		return (PCAP_ERROR);
	}

	return (0);
}

static int
bpf_odmcleanup(char *errbuf)
{
	char *errstr;

	if (odm_unlock(odmlockid) == -1) {
		if (errbuf != NULL) {
			if (odm_err_msg(odmerrno, &errstr) == -1)
				errstr = "Unknown error";
			snprintf(errbuf, PCAP_ERRBUF_SIZE,
			    "bpf_load: odm_unlock failed: %s",
			    errstr);
		}
		return (PCAP_ERROR);
	}

	if (odm_terminate() == -1) {
		if (errbuf != NULL) {
			if (odm_err_msg(odmerrno, &errstr) == -1)
				errstr = "Unknown error";
			snprintf(errbuf, PCAP_ERRBUF_SIZE,
			    "bpf_load: odm_terminate failed: %s",
			    errstr);
		}
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
		pcapint_fmt_errmsg_for_errno(errbuf, PCAP_ERRBUF_SIZE,
		    errno, "bpf_load: genmajor failed");
		(void)bpf_odmcleanup(NULL);
		return (PCAP_ERROR);
	}

	minors = getminor(major, &numminors, BPF_NAME);
	if (!minors) {
		minors = genminor("bpf", major, 0, BPF_MINORS, 1, 1);
		if (!minors) {
			pcapint_fmt_errmsg_for_errno(errbuf, PCAP_ERRBUF_SIZE,
			    errno, "bpf_load: genminor failed");
			(void)bpf_odmcleanup(NULL);
			return (PCAP_ERROR);
		}
	}

	if (bpf_odmcleanup(errbuf) == PCAP_ERROR)
		return (PCAP_ERROR);

	rc = stat(BPF_NODE "0", &sbuf);
	if (rc == -1 && errno != ENOENT) {
		pcapint_fmt_errmsg_for_errno(errbuf, PCAP_ERRBUF_SIZE,
		    errno, "bpf_load: can't stat %s", BPF_NODE "0");
		return (PCAP_ERROR);
	}

	if (rc == -1 || getmajor(sbuf.st_rdev) != major) {
		for (i = 0; i < BPF_MINORS; i++) {
			snprintf(buf, sizeof(buf), "%s%d", BPF_NODE, i);
			unlink(buf);
			if (mknod(buf, S_IRUSR | S_IFCHR, domakedev(major, i)) == -1) {
				pcapint_fmt_errmsg_for_errno(errbuf,
				    PCAP_ERRBUF_SIZE, errno,
				    "bpf_load: can't mknod %s", buf);
				return (PCAP_ERROR);
			}
		}
	}

	/* Check if the driver is loaded */
	memset(&cfg_ld, 0x0, sizeof(cfg_ld));
	snprintf(buf, sizeof(buf), "%s/%s", DRIVER_PATH, BPF_NAME);
	cfg_ld.path = buf;
	if ((sysconfig(SYS_QUERYLOAD, (void *)&cfg_ld, sizeof(cfg_ld)) == -1) ||
	    (cfg_ld.kmid == 0)) {
		/* Driver isn't loaded, load it now */
		if (sysconfig(SYS_SINGLELOAD, (void *)&cfg_ld, sizeof(cfg_ld)) == -1) {
			pcapint_fmt_errmsg_for_errno(errbuf, PCAP_ERRBUF_SIZE,
			    errno, "bpf_load: could not load driver");
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
			pcapint_fmt_errmsg_for_errno(errbuf, PCAP_ERRBUF_SIZE,
			    errno, "bpf_load: could not configure driver");
			return (PCAP_ERROR);
		}
	}

	bpfloadedflag = 1;

	return (0);
}
#endif

/*
 * Undo any operations done when opening the device when necessary.
 */
static void
pcap_cleanup_bpf(pcap_t *p)
{
	struct pcap_bpf *pb = p->priv;
#ifdef HAVE_BSD_IEEE80211
	int sock;
	struct ifmediareq req;
	struct ifreq ifr;
#endif

	if (pb->must_do_on_close != 0) {
		/*
		 * There's something we have to do when closing this
		 * pcap_t.
		 */
#ifdef HAVE_BSD_IEEE80211
		if (pb->must_do_on_close & MUST_CLEAR_RFMON) {
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
				pcapint_strlcpy(req.ifm_name, pb->device,
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
						(void)pcapint_strlcpy(ifr.ifr_name,
						    pb->device,
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

#if defined(__FreeBSD__) && defined(SIOCIFCREATE2)
		/*
		 * Attempt to destroy the usbusN interface that we created.
		 */
		if (pb->must_do_on_close & MUST_DESTROY_USBUS) {
			if (if_nametoindex(pb->device) > 0) {
				int s;

				s = socket(AF_LOCAL, SOCK_DGRAM, 0);
				if (s >= 0) {
					pcapint_strlcpy(ifr.ifr_name, pb->device,
					    sizeof(ifr.ifr_name));
					ioctl(s, SIOCIFDESTROY, &ifr);
					close(s);
				}
			}
		}
#endif /* defined(__FreeBSD__) && defined(SIOCIFCREATE2) */
		/*
		 * Take this pcap out of the list of pcaps for which we
		 * have to take the interface out of some mode.
		 */
		pcapint_remove_from_pcaps_to_close(p);
		pb->must_do_on_close = 0;
	}

#ifdef HAVE_ZEROCOPY_BPF
	if (pb->zerocopy) {
		/*
		 * Delete the mappings.  Note that p->buffer gets
		 * initialized to one of the mmapped regions in
		 * this case, so do not try and free it directly;
		 * null it out so that pcapint_cleanup_live_common()
		 * doesn't try to free it.
		 */
		if (pb->zbuf1 != MAP_FAILED && pb->zbuf1 != NULL)
			(void) munmap(pb->zbuf1, pb->zbufsize);
		if (pb->zbuf2 != MAP_FAILED && pb->zbuf2 != NULL)
			(void) munmap(pb->zbuf2, pb->zbufsize);
		p->buffer = NULL;
	}
#endif
	if (pb->device != NULL) {
		free(pb->device);
		pb->device = NULL;
	}
	pcapint_cleanup_live_common(p);
}

#ifdef __APPLE__
static int
check_setif_failure(pcap_t *p, int error)
{
	int fd;
	int err;

	if (error == PCAP_ERROR_NO_SUCH_DEVICE) {
		/*
		 * No such device exists.
		 */
		if (p->opt.rfmon && strncmp(p->opt.device, "wlt", 3) == 0) {
			/*
			 * Monitor mode was requested, and we're trying
			 * to open a "wltN" device.  Assume that this
			 * is 10.4 and that we were asked to open an
			 * "enN" device; if that device exists, return
			 * "monitor mode not supported on the device".
			 */
			fd = socket(AF_INET, SOCK_DGRAM, 0);
			if (fd != -1) {
				char *en_name;

				if (pcapint_asprintf(&en_name, "en%s",
				    p->opt.device + 3) == -1) {
					/*
					 * We can't find out whether there's
					 * an underlying "enN" device, so
					 * just report "no such device".
					 */
					pcapint_fmt_errmsg_for_errno(p->errbuf,
					    PCAP_ERRBUF_SIZE, errno,
					    "malloc");
					close(fd);
					return (PCAP_ERROR_NO_SUCH_DEVICE);
				}
				err = device_exists(fd, en_name, p->errbuf);
				free(en_name);
				if (err != 0) {
					if (err == PCAP_ERROR_NO_SUCH_DEVICE) {
						/*
						 * The underlying "enN" device
						 * exists, but there's no
						 * corresponding "wltN" device;
						 * that means that the "enN"
						 * device doesn't support
						 * monitor mode, probably
						 * because it's an Ethernet
						 * device rather than a
						 * wireless device.
						 */
						err = PCAP_ERROR_RFMON_NOTSUP;
					}
				}
				close(fd);
			} else {
				/*
				 * We can't find out whether there's
				 * an underlying "enN" device, so
				 * just report "no such device".
				 */
				err = PCAP_ERROR_NO_SUCH_DEVICE;
				pcapint_fmt_errmsg_for_errno(p->errbuf,
				    errno, PCAP_ERRBUF_SIZE,
				    "socket() failed");
			}
			return (err);
		}

		/*
		 * No such device.
		 */
		return (PCAP_ERROR_NO_SUCH_DEVICE);
	}

	/*
	 * Just return the error status; it's what we want, and, if it's
	 * PCAP_ERROR, the error string has been filled in.
	 */
	return (error);
}
#else
static int
check_setif_failure(pcap_t *p _U_, int error)
{
	/*
	 * Just return the error status; it's what we want, and, if it's
	 * PCAP_ERROR, the error string has been filled in.
	 */
	return (error);
}
#endif

/*
 * Default capture buffer size.
 * 32K isn't very much for modern machines with fast networks; we
 * pick .5M, as that's the maximum on at least some systems with BPF.
 *
 * However, on AIX 3.5, the larger buffer sized caused unrecoverable
 * read failures under stress, so we leave it as 32K; yet another
 * place where AIX's BPF is broken.
 */
#ifdef _AIX
#define DEFAULT_BUFSIZE	32768
#else
#define DEFAULT_BUFSIZE	524288
#endif

static int
pcap_activate_bpf(pcap_t *p)
{
	struct pcap_bpf *pb = p->priv;
	int status = 0;
#ifdef HAVE_BSD_IEEE80211
	int retv;
#endif
	int fd;
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

	fd = bpf_open(p->errbuf);
	if (fd < 0) {
		status = fd;
		goto bad;
	}

	p->fd = fd;

	if (ioctl(fd, BIOCVERSION, (caddr_t)&bv) < 0) {
		pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "BIOCVERSION");
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

	/*
	 * Turn a negative snapshot value (invalid), a snapshot value of
	 * 0 (unspecified), or a value bigger than the normal maximum
	 * value, into the maximum allowed value.
	 *
	 * If some application really *needs* a bigger snapshot
	 * length, we should just increase MAXIMUM_SNAPLEN.
	 */
	if (p->snapshot <= 0 || p->snapshot > MAXIMUM_SNAPLEN)
		p->snapshot = MAXIMUM_SNAPLEN;

	pb->device = strdup(p->opt.device);
	if (pb->device == NULL) {
		pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "strdup");
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
				if (strncmp(p->opt.device, "en", 2) != 0) {
					/*
					 * Not an enN device; check
					 * whether the device even exists.
					 */
					sockfd = socket(AF_INET, SOCK_DGRAM, 0);
					if (sockfd != -1) {
						status = device_exists(sockfd,
						    p->opt.device, p->errbuf);
						if (status == 0) {
							/*
							 * The device exists,
							 * but it's not an
							 * enN device; that
							 * means it doesn't
							 * support monitor
							 * mode.
							 */
							status = PCAP_ERROR_RFMON_NOTSUP;
						}
						close(sockfd);
					} else {
						/*
						 * We can't find out whether
						 * the device exists, so just
						 * report "no such device".
						 */
						status = PCAP_ERROR_NO_SUCH_DEVICE;
						pcapint_fmt_errmsg_for_errno(p->errbuf,
						    PCAP_ERRBUF_SIZE, errno,
						    "socket() failed");
					}
					goto bad;
				}
				wltdev = malloc(strlen(p->opt.device) + 2);
				if (wltdev == NULL) {
					pcapint_fmt_errmsg_for_errno(p->errbuf,
					    PCAP_ERRBUF_SIZE, errno,
					    "malloc");
					status = PCAP_ERROR;
					goto bad;
				}
				strcpy(wltdev, "wlt");
				strcat(wltdev, p->opt.device + 2);
				free(p->opt.device);
				p->opt.device = wltdev;
			}
			/*
			 * Everything else is 10.5 or later; for those,
			 * we just open the enN device, and set the DLT.
			 */
		}
	}
#endif /* __APPLE__ */

	/*
	 * If this is FreeBSD, and the device name begins with "usbus",
	 * try to create the interface if it's not available.
	 */
#if defined(__FreeBSD__) && defined(SIOCIFCREATE2)
	if (strncmp(p->opt.device, usbus_prefix, USBUS_PREFIX_LEN) == 0) {
		/*
		 * Do we already have an interface with that name?
		 */
		if (if_nametoindex(p->opt.device) == 0) {
			/*
			 * No.  We need to create it, and, if we
			 * succeed, remember that we should destroy
			 * it when the pcap_t is closed.
			 */
			int s;
			struct ifreq ifr;

			/*
			 * Open a socket to use for ioctls to
			 * create the interface.
			 */
			s = socket(AF_LOCAL, SOCK_DGRAM, 0);
			if (s < 0) {
				pcapint_fmt_errmsg_for_errno(p->errbuf,
				    PCAP_ERRBUF_SIZE, errno,
				    "Can't open socket");
				status = PCAP_ERROR;
				goto bad;
			}

			/*
			 * If we haven't already done so, arrange to have
			 * "pcap_close_all()" called when we exit.
			 */
			if (!pcapint_do_addexit(p)) {
				/*
				 * "atexit()" failed; don't create the
				 * interface, just give up.
				 */
				snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
				     "atexit failed");
				close(s);
				status = PCAP_ERROR;
				goto bad;
			}

			/*
			 * Create the interface.
			 */
			pcapint_strlcpy(ifr.ifr_name, p->opt.device, sizeof(ifr.ifr_name));
			if (ioctl(s, SIOCIFCREATE2, &ifr) < 0) {
				if (errno == EINVAL) {
					snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
					    "Invalid USB bus interface %s",
					    p->opt.device);
				} else {
					pcapint_fmt_errmsg_for_errno(p->errbuf,
					    PCAP_ERRBUF_SIZE, errno,
					    "Can't create interface for %s",
					    p->opt.device);
				}
				close(s);
				status = PCAP_ERROR;
				goto bad;
			}

			/*
			 * Make sure we clean this up when we close.
			 */
			pb->must_do_on_close |= MUST_DESTROY_USBUS;

			/*
			 * Add this to the list of pcaps to close when we exit.
			 */
			pcapint_add_to_pcaps_to_close(p);
		}
	}
#endif /* defined(__FreeBSD__) && defined(SIOCIFCREATE2) */

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
		pb->zerocopy = 1;

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
			pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
			    errno, "BIOCGETZMAX");
			status = PCAP_ERROR;
			goto bad;
		}

		if (p->opt.buffer_size != 0) {
			/*
			 * A buffer size was explicitly specified; use it.
			 */
			v = p->opt.buffer_size;
		} else {
			if ((ioctl(fd, BIOCGBLEN, (caddr_t)&v) < 0) ||
			    v < DEFAULT_BUFSIZE)
				v = DEFAULT_BUFSIZE;
		}
#ifndef roundup
#define roundup(x, y)   ((((x)+((y)-1))/(y))*(y))  /* to any y */
#endif
		pb->zbufsize = roundup(v, getpagesize());
		if (pb->zbufsize > zbufmax)
			pb->zbufsize = zbufmax;
		pb->zbuf1 = mmap(NULL, pb->zbufsize, PROT_READ | PROT_WRITE,
		    MAP_ANON, -1, 0);
		pb->zbuf2 = mmap(NULL, pb->zbufsize, PROT_READ | PROT_WRITE,
		    MAP_ANON, -1, 0);
		if (pb->zbuf1 == MAP_FAILED || pb->zbuf2 == MAP_FAILED) {
			pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
			    errno, "mmap");
			status = PCAP_ERROR;
			goto bad;
		}
		memset(&bz, 0, sizeof(bz)); /* bzero() deprecated, replaced with memset() */
		bz.bz_bufa = pb->zbuf1;
		bz.bz_bufb = pb->zbuf2;
		bz.bz_buflen = pb->zbufsize;
		if (ioctl(fd, BIOCSETZBUF, (caddr_t)&bz) < 0) {
			pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
			    errno, "BIOCSETZBUF");
			status = PCAP_ERROR;
			goto bad;
		}
		status = bpf_bind(fd, p->opt.device, ifnamsiz, p->errbuf);
		if (status != BPF_BIND_SUCCEEDED) {
			if (status == BPF_BIND_BUFFER_TOO_BIG) {
				/*
				 * The requested buffer size
				 * is too big.  Fail.
				 *
				 * XXX - should we do the "keep cutting
				 * the buffer size in half" loop here if
				 * we're using the default buffer size?
				 */
				status = PCAP_ERROR;
			}
			goto bad;
		}
		v = pb->zbufsize - sizeof(struct bpf_zbuf_header);
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
				pcapint_fmt_errmsg_for_errno(p->errbuf,
				    PCAP_ERRBUF_SIZE, errno,
				    "BIOCSBLEN: %s", p->opt.device);
				status = PCAP_ERROR;
				goto bad;
			}

			/*
			 * Now bind to the device.
			 */
			status = bpf_bind(fd, p->opt.device, p->errbuf);
			if (status != BPF_BIND_SUCCEEDED) {
				if (status == BPF_BIND_BUFFER_TOO_BIG) {
					/*
					 * The requested buffer size
					 * is too big.  Fail.
					 */
					status = PCAP_ERROR;
					goto bad;
				}

				/*
				 * Special checks on macOS to deal with
				 * the way monitor mode was done on
				 * 10.4 Tiger.
				 */
				status = check_setif_failure(p, status);
				goto bad;
			}
		} else {
			/*
			 * No buffer size was explicitly specified.
			 *
			 * Try finding a good size for the buffer;
			 * DEFAULT_BUFSIZE may be too big, so keep
			 * cutting it in half until we find a size
			 * that works, or run out of sizes to try.
			 * If the default is larger, don't make it smaller.
			 */
			if ((ioctl(fd, BIOCGBLEN, (caddr_t)&v) < 0) ||
			    v < DEFAULT_BUFSIZE)
				v = DEFAULT_BUFSIZE;
			for ( ; v != 0; v >>= 1) {
				/*
				 * Ignore the return value - this is because the
				 * call fails on BPF systems that don't have
				 * kernel malloc.  And if the call fails, it's
				 * no big deal, we just continue to use the
				 * standard buffer size.
				 */
				(void) ioctl(fd, BIOCSBLEN, (caddr_t)&v);

				status = bpf_bind(fd, p->opt.device, p->errbuf);
				if (status == BPF_BIND_SUCCEEDED)
					break;	/* that size worked; we're done */

				/*
				 * If the attempt failed because the
				 * buffer was too big, cut the buffer
				 * size in half and try again.
				 *
				 * Otherwise, fail.
				 */
				if (status != BPF_BIND_BUFFER_TOO_BIG) {
					/*
					 * Special checks on macOS to deal
					 * with the way monitor mode was
					 * done on 10.4 Tiger.
					 */
					status = check_setif_failure(p, status);
					goto bad;
				}
			}

			if (v == 0) {
				snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
				    "BIOCSBLEN: %s: No buffer size worked",
				    p->opt.device);
				status = PCAP_ERROR;
				goto bad;
			}
		}
	}

	/* Get the data link layer type. */
	if (ioctl(fd, BIOCGDLT, (caddr_t)&v) < 0) {
		pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "BIOCGDLT");
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
#if defined(_BSDI_VERSION) && _BSDI_VERSION >= 199510
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
		if (PCAP_ISDIGIT((unsigned)osinfo.release[0]) &&
		     (osinfo.release[0] == '9' ||
		     PCAP_ISDIGIT((unsigned)osinfo.release[1]))) {
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
					remove_non_802_11(p);

					/*
					 * If the new mode we want isn't
					 * the default mode, attempt to
					 * select the new mode.
					 */
					if ((u_int)new_dlt != v) {
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
		retv = monitor_mode(p, 1);
		if (retv != 0) {
			/*
			 * We failed.
			 */
			status = retv;
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
			if ((u_int)new_dlt != v) {
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
		if (p->dlt_list == NULL) {
			pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
			    errno, "malloc");
			status = PCAP_ERROR;
			goto bad;
		}
		p->dlt_list[0] = DLT_EN10MB;
		p->dlt_list[1] = DLT_DOCSIS;
		p->dlt_count = 2;
	}
#ifdef PCAP_FDDIPAD
	if (v == DLT_FDDI)
		p->fddipad = PCAP_FDDIPAD;
	else
#endif
		p->fddipad = 0;
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
		pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "BIOCSHDRCMPLT");
		status = PCAP_ERROR;
		goto bad;
	}
#endif
	/* set timeout */
#ifdef HAVE_ZEROCOPY_BPF
	/*
	 * In zero-copy mode, we just use the timeout in select().
	 * XXX - what if we're in non-blocking mode and the *application*
	 * is using select() or poll() or kqueues or....?
	 */
	if (p->opt.timeout && !pb->zerocopy) {
#else
	if (p->opt.timeout) {
#endif
		/*
		 * XXX - is this seconds/nanoseconds in AIX?
		 * (Treating it as such doesn't fix the timeout
		 * problem described below.)
		 *
		 * XXX - Mac OS X 10.6 mishandles BIOCSRTIMEOUT in
		 * 64-bit userland - it takes, as an argument, a
		 * "struct BPF_TIMEVAL", which has 32-bit tv_sec
		 * and tv_usec, rather than a "struct timeval".
		 *
		 * If this platform defines "struct BPF_TIMEVAL",
		 * we check whether the structure size in BIOCSRTIMEOUT
		 * is that of a "struct timeval" and, if not, we use
		 * a "struct BPF_TIMEVAL" rather than a "struct timeval".
		 * (That way, if the bug is fixed in a future release,
		 * we will still do the right thing.)
		 */
		struct timeval to;
#ifdef HAVE_STRUCT_BPF_TIMEVAL
		struct BPF_TIMEVAL bpf_to;

		if (IOCPARM_LEN(BIOCSRTIMEOUT) != sizeof(struct timeval)) {
			bpf_to.tv_sec = p->opt.timeout / 1000;
			bpf_to.tv_usec = (p->opt.timeout * 1000) % 1000000;
			if (ioctl(p->fd, BIOCSRTIMEOUT, (caddr_t)&bpf_to) < 0) {
				pcapint_fmt_errmsg_for_errno(p->errbuf,
				    errno, PCAP_ERRBUF_SIZE, "BIOCSRTIMEOUT");
				status = PCAP_ERROR;
				goto bad;
			}
		} else {
#endif
			to.tv_sec = p->opt.timeout / 1000;
			to.tv_usec = (p->opt.timeout * 1000) % 1000000;
			if (ioctl(p->fd, BIOCSRTIMEOUT, (caddr_t)&to) < 0) {
				pcapint_fmt_errmsg_for_errno(p->errbuf,
				    errno, PCAP_ERRBUF_SIZE, "BIOCSRTIMEOUT");
				status = PCAP_ERROR;
				goto bad;
			}
#ifdef HAVE_STRUCT_BPF_TIMEVAL
		}
#endif
	}

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
	 * so we always turn BIOCIMMEDIATE mode on if this is AIX.
	 *
	 * For other platforms, we don't turn immediate mode on by default,
	 * as that would mean we get woken up for every packet, which
	 * probably isn't what you want for a packet sniffer.
	 *
	 * We set immediate mode if the caller requested it by calling
	 * pcap_set_immediate() before calling pcap_activate().
	 */
#ifndef _AIX
	if (p->opt.immediate) {
#endif /* _AIX */
		v = 1;
		if (ioctl(p->fd, BIOCIMMEDIATE, &v) < 0) {
			pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
			    errno, "BIOCIMMEDIATE");
			status = PCAP_ERROR;
			goto bad;
		}
#ifndef _AIX
	}
#endif /* _AIX */
#else /* BIOCIMMEDIATE */
	if (p->opt.immediate) {
		/*
		 * We don't support immediate mode.  Fail.
		 */
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "Immediate mode not supported");
		status = PCAP_ERROR;
		goto bad;
	}
#endif /* BIOCIMMEDIATE */

	if (p->opt.promisc) {
		/* set promiscuous mode, just warn if it fails */
		if (ioctl(p->fd, BIOCPROMISC, NULL) < 0) {
			pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
			    errno, "BIOCPROMISC");
			status = PCAP_WARNING_PROMISC_NOTSUP;
		}
	}

#ifdef BIOCSTSTAMP
	v = BPF_T_BINTIME;
	if (ioctl(p->fd, BIOCSTSTAMP, &v) < 0) {
		pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "BIOCSTSTAMP");
		status = PCAP_ERROR;
		goto bad;
	}
#endif /* BIOCSTSTAMP */

	if (ioctl(fd, BIOCGBLEN, (caddr_t)&v) < 0) {
		pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "BIOCGBLEN");
		status = PCAP_ERROR;
		goto bad;
	}
	p->bufsize = v;
#ifdef HAVE_ZEROCOPY_BPF
	if (!pb->zerocopy) {
#endif
	p->buffer = malloc(p->bufsize);
	if (p->buffer == NULL) {
		pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "malloc");
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
		pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "BIOCSETF");
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
	p->getnonblock_op = pcap_getnonblock_bpf;
	p->setnonblock_op = pcap_setnonblock_bpf;
	p->stats_op = pcap_stats_bpf;
	p->cleanup_op = pcap_cleanup_bpf;

	return (status);
 bad:
	pcap_cleanup_bpf(p);
	return (status);
}

/*
 * Not all interfaces can be bound to by BPF, so try to bind to
 * the specified interface; return 0 if we fail with
 * PCAP_ERROR_NO_SUCH_DEVICE (which means we got an ENXIO when we tried
 * to bind, which means this interface isn't in the list of interfaces
 * attached to BPF) and 1 otherwise.
 */
static int
check_bpf_bindable(const char *name)
{
	int fd;
	char errbuf[PCAP_ERRBUF_SIZE];

	/*
	 * On macOS, we don't do this check if the device name begins
	 * with "wlt"; at least some versions of macOS (actually, it
	 * was called "Mac OS X" then...) offer monitor mode capturing
	 * by having a separate "monitor mode" device for each wireless
	 * adapter, rather than by implementing the ioctls that
	 * {Free,Net,Open,DragonFly}BSD provide. Opening that device
	 * puts the adapter into monitor mode, which, at least for
	 * some adapters, causes them to disassociate from the network
	 * with which they're associated.
	 *
	 * Instead, we try to open the corresponding "en" device (so
	 * that we don't end up with, for users without sufficient
	 * privilege to open capture devices, a list of adapters that
	 * only includes the wlt devices).
	 */
#ifdef __APPLE__
	if (strncmp(name, "wlt", 3) == 0) {
		char *en_name;
		size_t en_name_len;

		/*
		 * Try to allocate a buffer for the "en"
		 * device's name.
		 */
		en_name_len = strlen(name) - 1;
		en_name = malloc(en_name_len + 1);
		if (en_name == NULL) {
			pcapint_fmt_errmsg_for_errno(errbuf, PCAP_ERRBUF_SIZE,
			    errno, "malloc");
			return (-1);
		}
		strcpy(en_name, "en");
		strcat(en_name, name + 3);
		fd = bpf_open_and_bind(en_name, errbuf);
		free(en_name);
	} else
#endif /* __APPLE */
	fd = bpf_open_and_bind(name, errbuf);
	if (fd < 0) {
		/*
		 * Error - was it PCAP_ERROR_NO_SUCH_DEVICE?
		 */
		if (fd == PCAP_ERROR_NO_SUCH_DEVICE) {
			/*
			 * Yes, so we can't bind to this because it's
			 * not something supported by BPF.
			 */
			return (0);
		}
		/*
		 * No, so we don't know whether it's supported or not;
		 * say it is, so that the user can at least try to
		 * open it and report the error (which is probably
		 * "you don't have permission to open BPF devices";
		 * reporting those interfaces means users will ask
		 * "why am I getting a permissions error when I try
		 * to capture" rather than "why am I not seeing any
		 * interfaces", making the underlying problem clearer).
		 */
		return (1);
	}

	/*
	 * Success.
	 */
	close(fd);
	return (1);
}

#if defined(__FreeBSD__) && defined(SIOCIFCREATE2)
static int
get_usb_if_flags(const char *name _U_, bpf_u_int32 *flags _U_, char *errbuf _U_)
{
	/*
	 * XXX - if there's a way to determine whether there's something
	 * plugged into a given USB bus, use that to determine whether
	 * this device is "connected" or not.
	 */
	return (0);
}

static int
finddevs_usb(pcap_if_list_t *devlistp, char *errbuf)
{
	DIR *usbdir;
	struct dirent *usbitem;
	size_t name_max;
	char *name;

	/*
	 * We might have USB sniffing support, so try looking for USB
	 * interfaces.
	 *
	 * We want to report a usbusN device for each USB bus, but
	 * usbusN interfaces might, or might not, exist for them -
	 * we create one if there isn't already one.
	 *
	 * So, instead, we look in /dev/usb for all buses and create
	 * a "usbusN" device for each one.
	 */
	usbdir = opendir("/dev/usb");
	if (usbdir == NULL) {
		/*
		 * Just punt.
		 */
		return (0);
	}

	/*
	 * Leave enough room for a 32-bit (10-digit) bus number.
	 * Yes, that's overkill, but we won't be using
	 * the buffer very long.
	 */
	name_max = USBUS_PREFIX_LEN + 10 + 1;
	name = malloc(name_max);
	if (name == NULL) {
		closedir(usbdir);
		return (0);
	}
	while ((usbitem = readdir(usbdir)) != NULL) {
		char *p;
		size_t busnumlen;

		if (strcmp(usbitem->d_name, ".") == 0 ||
		    strcmp(usbitem->d_name, "..") == 0) {
			/*
			 * Ignore these.
			 */
			continue;
		}
		p = strchr(usbitem->d_name, '.');
		if (p == NULL)
			continue;
		busnumlen = p - usbitem->d_name;
		memcpy(name, usbus_prefix, USBUS_PREFIX_LEN);
		memcpy(name + USBUS_PREFIX_LEN, usbitem->d_name, busnumlen);
		*(name + USBUS_PREFIX_LEN + busnumlen) = '\0';
		/*
		 * There's an entry in this directory for every USB device,
		 * not for every bus; if there's more than one device on
		 * the bus, there'll be more than one entry for that bus,
		 * so we need to avoid adding multiple capture devices
		 * for each bus.
		 */
		if (pcapint_find_or_add_dev(devlistp, name, PCAP_IF_UP,
		    get_usb_if_flags, NULL, errbuf) == NULL) {
			free(name);
			closedir(usbdir);
			return (PCAP_ERROR);
		}
	}
	free(name);
	closedir(usbdir);
	return (0);
}
#endif

/*
 * Get additional flags for a device, using SIOCGIFMEDIA.
 */
#ifdef SIOCGIFMEDIA
static int
get_if_flags(const char *name, bpf_u_int32 *flags, char *errbuf)
{
	int sock;
	struct ifmediareq req;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		pcapint_fmt_errmsg_for_errno(errbuf, PCAP_ERRBUF_SIZE, errno,
		    "Can't create socket to get media information for %s",
		    name);
		return (-1);
	}
	memset(&req, 0, sizeof(req));
	pcapint_strlcpy(req.ifm_name, name, sizeof(req.ifm_name));
	if (ioctl(sock, SIOCGIFMEDIA, &req) < 0) {
		if (errno == EOPNOTSUPP || errno == EINVAL || errno == ENOTTY ||
		    errno == ENODEV || errno == EPERM
#ifdef EPWROFF
		    || errno == EPWROFF
#endif
		    ) {
			/*
			 * Not supported, so we can't provide any
			 * additional information.  Assume that
			 * this means that "connected" vs.
			 * "disconnected" doesn't apply.
			 *
			 * The ioctl routine for Apple's pktap devices,
			 * annoyingly, checks for "are you root?" before
			 * checking whether the ioctl is valid, so it
			 * returns EPERM, rather than ENOTSUP, for the
			 * invalid SIOCGIFMEDIA, unless you're root.
			 * So, just as we do for some ethtool ioctls
			 * on Linux, which makes the same mistake, we
			 * also treat EPERM as meaning "not supported".
			 *
			 * And it appears that Apple's llw0 device, which
			 * appears to be part of the Skywalk subsystem:
			 *
			 *    http://newosxbook.com/bonus/vol1ch16.html
			 *
			 * can sometimes return EPWROFF ("Device power
			 * is off") for that ioctl, so we treat *that*
			 * as another indication that we can't get a
			 * connection status.  (If it *isn't* "powered
			 * off", it's reported as a wireless device,
			 * complete with an active/inactive state.)
			 */
			*flags |= PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE;
			close(sock);
			return (0);
		}
		pcapint_fmt_errmsg_for_errno(errbuf, PCAP_ERRBUF_SIZE, errno,
		    "SIOCGIFMEDIA on %s failed", name);
		close(sock);
		return (-1);
	}
	close(sock);

	/*
	 * OK, what type of network is this?
	 */
	switch (IFM_TYPE(req.ifm_active)) {

	case IFM_IEEE80211:
		/*
		 * Wireless.
		 */
		*flags |= PCAP_IF_WIRELESS;
		break;
	}

	/*
	 * Do we know whether it's connected?
	 */
	if (req.ifm_status & IFM_AVALID) {
		/*
		 * Yes.
		 */
		if (req.ifm_status & IFM_ACTIVE) {
			/*
			 * It's connected.
			 */
			*flags |= PCAP_IF_CONNECTION_STATUS_CONNECTED;
		} else {
			/*
			 * It's disconnected.
			 */
			*flags |= PCAP_IF_CONNECTION_STATUS_DISCONNECTED;
		}
	}
	return (0);
}
#else
static int
get_if_flags(const char *name _U_, bpf_u_int32 *flags, char *errbuf _U_)
{
	/*
	 * Nothing we can do other than mark loopback devices as "the
	 * connected/disconnected status doesn't apply".
	 *
	 * XXX - on Solaris, can we do what the dladm command does,
	 * i.e. get a connected/disconnected indication from a kstat?
	 * (Note that you can also get the link speed, and possibly
	 * other information, from a kstat as well.)
	 */
	if (*flags & PCAP_IF_LOOPBACK) {
		/*
		 * Loopback devices aren't wireless, and "connected"/
		 * "disconnected" doesn't apply to them.
		 */
		*flags |= PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE;
		return (0);
	}
	return (0);
}
#endif

int
pcapint_platform_finddevs(pcap_if_list_t *devlistp, char *errbuf)
{
	/*
	 * Get the list of regular interfaces first.
	 */
	if (pcapint_findalldevs_interfaces(devlistp, errbuf, check_bpf_bindable,
	    get_if_flags) == -1)
		return (-1);	/* failure */

#if defined(HAVE_SOLARIS_ANY_DEVICE)
	/*
	 * Add the "any" device.
	 */
	if (pcap_add_any_dev(devlistp, errbuf) == NULL)
		return (-1);
#endif

#if defined(__FreeBSD__) && defined(SIOCIFCREATE2)
	if (finddevs_usb(devlistp, errbuf) == -1)
		return (-1);
#endif

	return (0);
}

#ifdef HAVE_BSD_IEEE80211
static int
monitor_mode(pcap_t *p, int set)
{
	struct pcap_bpf *pb = p->priv;
	int sock;
	struct ifmediareq req;
	IFM_ULIST_TYPE *media_list;
	int i;
	int can_do;
	struct ifreq ifr;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "can't open socket");
		return (PCAP_ERROR);
	}

	memset(&req, 0, sizeof req);
	pcapint_strlcpy(req.ifm_name, p->opt.device, sizeof req.ifm_name);

	/*
	 * Find out how many media types we have.
	 */
	if (ioctl(sock, SIOCGIFMEDIA, &req) < 0) {
		/*
		 * Can't get the media types.
		 */
		switch (errno) {

		case ENXIO:
			/*
			 * There's no such device.
			 *
			 * There's nothing more to say, so clear the
			 * error message.
			 */
			p->errbuf[0] = '\0';
			close(sock);
			return (PCAP_ERROR_NO_SUCH_DEVICE);

		case EINVAL:
			/*
			 * Interface doesn't support SIOC{G,S}IFMEDIA.
			 */
			close(sock);
			return (PCAP_ERROR_RFMON_NOTSUP);

		default:
			pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
			    errno, "SIOCGIFMEDIA");
			close(sock);
			return (PCAP_ERROR);
		}
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
	media_list = malloc(req.ifm_count * sizeof(*media_list));
	if (media_list == NULL) {
		pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "malloc");
		close(sock);
		return (PCAP_ERROR);
	}
	req.ifm_ulist = media_list;
	if (ioctl(sock, SIOCGIFMEDIA, &req) < 0) {
		pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "SIOCGIFMEDIA");
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
			if (!pcapint_do_addexit(p)) {
				/*
				 * "atexit()" failed; don't put the interface
				 * in monitor mode, just give up.
				 */
				close(sock);
				return (PCAP_ERROR);
			}
			memset(&ifr, 0, sizeof(ifr));
			(void)pcapint_strlcpy(ifr.ifr_name, p->opt.device,
			    sizeof(ifr.ifr_name));
			ifr.ifr_media = req.ifm_current | IFM_IEEE80211_MONITOR;
			if (ioctl(sock, SIOCSIFMEDIA, &ifr) == -1) {
				pcapint_fmt_errmsg_for_errno(p->errbuf,
				    PCAP_ERRBUF_SIZE, errno, "SIOCSIFMEDIA");
				close(sock);
				return (PCAP_ERROR);
			}

			pb->must_do_on_close |= MUST_CLEAR_RFMON;

			/*
			 * Add this to the list of pcaps to close when we exit.
			 */
			pcapint_add_to_pcaps_to_close(p);
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
	u_int i;

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

#ifdef DLT_PRISM_HEADER
		case DLT_PRISM_HEADER:
#endif
#ifdef DLT_AIRONET_HEADER
		case DLT_AIRONET_HEADER:
#endif
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
 * Remove non-802.11 header types from the list of DLT_ values, as we're in
 * monitor mode, and those header types aren't supported in monitor mode.
 */
static void
remove_non_802_11(pcap_t *p)
{
	int i, j;

	/*
	 * Scan the list of DLT_ values and discard non-802.11 ones.
	 */
	j = 0;
	for (i = 0; i < p->dlt_count; i++) {
		switch (p->dlt_list[i]) {

		case DLT_EN10MB:
		case DLT_RAW:
			/*
			 * Not 802.11.  Don't offer this one.
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
 * Remove 802.11 link-layer types from the list of DLT_ values, as
 * we're not in monitor mode, and those DLT_ values will switch us
 * to monitor mode.
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
#ifdef DLT_PRISM_HEADER
		case DLT_PRISM_HEADER:
#endif
#ifdef DLT_AIRONET_HEADER
		case DLT_AIRONET_HEADER:
#endif
		case DLT_IEEE802_11_RADIO:
		case DLT_IEEE802_11_RADIO_AVS:
#ifdef DLT_PPI
		case DLT_PPI:
#endif
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
	struct pcap_bpf *pb = p->priv;

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
		pb->filtering_in_kernel = 1;	/* filtering in the kernel */

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
		pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "BIOCSETF");
		return (-1);
	}

	/*
	 * pcapint_install_bpf_program() validates the program.
	 *
	 * XXX - what if we already have a filter in the kernel?
	 */
	if (pcapint_install_bpf_program(p, fp) < 0)
		return (-1);
	pb->filtering_in_kernel = 0;	/* filtering in userland */
	return (0);
}

/*
 * Set direction flag: Which packets do we accept on a forwarding
 * single device? IN, OUT or both?
 */
#if defined(BIOCSDIRECTION)
static int
pcap_setdirection_bpf(pcap_t *p, pcap_direction_t d)
{
	u_int direction;
	const char *direction_name;

	/*
	 * FreeBSD and NetBSD.
	 */
	switch (d) {

	case PCAP_D_IN:
		/*
		 * Incoming, but not outgoing, so accept only
		 * incoming packets.
		 */
		direction = BPF_D_IN;
		direction_name = "\"incoming only\"";
		break;

	case PCAP_D_OUT:
		/*
		 * Outgoing, but not incoming, so accept only
		 * outgoing packets.
		 */
		direction = BPF_D_OUT;
		direction_name = "\"outgoing only\"";
		break;

	default:
		/*
		 * Incoming and outgoing, so accept both
		 * incoming and outgoing packets.
		 *
		 * It's guaranteed, at this point, that d is a valid
		 * direction value, so we know that this is PCAP_D_INOUT
		 * if it's not PCAP_D_IN or PCAP_D_OUT.
		 */
		direction = BPF_D_INOUT;
		direction_name = "\"incoming and outgoing\"";
		break;
	}

	if (ioctl(p->fd, BIOCSDIRECTION, &direction) == -1) {
		pcapint_fmt_errmsg_for_errno(p->errbuf, sizeof(p->errbuf),
		    errno, "Cannot set direction to %s", direction_name);
		return (-1);
	}
	return (0);
}
#elif defined(BIOCSDIRFILT)
static int
pcap_setdirection_bpf(pcap_t *p, pcap_direction_t d)
{
	u_int dirfilt;
	const char *direction_name;

	/*
	 * OpenBSD; same functionality, different names, different
	 * semantics (the flags mean "*don't* capture packets in
	 * that direction", not "*capture only* packets in that
	 * direction").
	 */
	switch (d) {

	case PCAP_D_IN:
		/*
		 * Incoming, but not outgoing, so filter out
		 * outgoing packets.
		 */
		dirfilt = BPF_DIRECTION_OUT;
		direction_name = "\"incoming only\"";
		break;

	case PCAP_D_OUT:
		/*
		 * Outgoing, but not incoming, so filter out
		 * incoming packets.
		 */
		dirfilt = BPF_DIRECTION_IN;
		direction_name = "\"outgoing only\"";
		break;

	default:
		/*
		 * Incoming and outgoing, so don't filter out
		 * any packets based on direction.
		 *
		 * It's guaranteed, at this point, that d is a valid
		 * direction value, so we know that this is PCAP_D_INOUT
		 * if it's not PCAP_D_IN or PCAP_D_OUT.
		 */
		dirfilt = 0;
		direction_name = "\"incoming and outgoing\"";
		break;
	}
	if (ioctl(p->fd, BIOCSDIRFILT, &dirfilt) == -1) {
		pcapint_fmt_errmsg_for_errno(p->errbuf, sizeof(p->errbuf),
		    errno, "Cannot set direction to %s", direction_name);
		return (-1);
	}
	return (0);
}
#elif defined(BIOCSSEESENT)
static int
pcap_setdirection_bpf(pcap_t *p, pcap_direction_t d)
{
	u_int seesent;
	const char *direction_name;

	/*
	 * OS with just BIOCSSEESENT.
	 */
	switch (d) {

	case PCAP_D_IN:
		/*
		 * Incoming, but not outgoing, so we don't want to
		 * see transmitted packets.
		 */
		seesent = 0;
		direction_name = "\"incoming only\"";
		break;

	case PCAP_D_OUT:
		/*
		 * Outgoing, but not incoming; we can't specify that.
		 */
		snprintf(p->errbuf, sizeof(p->errbuf),
		    "Setting direction to \"outgoing only\" is not supported on this device");
		return (-1);

	default:
		/*
		 * Incoming and outgoing, so we want to see transmitted
		 * packets.
		 *
		 * It's guaranteed, at this point, that d is a valid
		 * direction value, so we know that this is PCAP_D_INOUT
		 * if it's not PCAP_D_IN or PCAP_D_OUT.
		 */
		seesent = 1;
		direction_name = "\"incoming and outgoing\"";
		break;
	}

	if (ioctl(p->fd, BIOCSSEESENT, &seesent) == -1) {
		pcapint_fmt_errmsg_for_errno(p->errbuf, sizeof(p->errbuf),
		    errno, "Cannot set direction to %s", direction_name);
		return (-1);
	}
	return (0);
}
#else
static int
pcap_setdirection_bpf(pcap_t *p, pcap_direction_t d _U_)
{
	(void) snprintf(p->errbuf, sizeof(p->errbuf),
	    "Setting direction is not supported on this device");
	return (-1);
}
#endif

#ifdef BIOCSDLT
static int
pcap_set_datalink_bpf(pcap_t *p, int dlt)
{
	if (ioctl(p->fd, BIOCSDLT, &dlt) == -1) {
		pcapint_fmt_errmsg_for_errno(p->errbuf, sizeof(p->errbuf),
		    errno, "Cannot set DLT %d", dlt);
		return (-1);
	}
	return (0);
}
#else
static int
pcap_set_datalink_bpf(pcap_t *p _U_, int dlt _U_)
{
	return (0);
}
#endif

/*
 * Platform-specific information.
 */
const char *
pcap_lib_version(void)
{
#ifdef HAVE_ZEROCOPY_BPF
	return (PCAP_VERSION_STRING " (with zerocopy support)");
#else
	return (PCAP_VERSION_STRING);
#endif
}
