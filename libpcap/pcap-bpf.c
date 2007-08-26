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
    "@(#) $Header: /tcpdump/master/libpcap/pcap-bpf.c,v 1.86.2.12 2007/06/15 17:57:27 guy Exp $ (LBL)";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/param.h>			/* optionally get BSD define */
#include <sys/time.h>
#include <sys/timeb.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>

#include <net/if.h>

#ifdef _AIX

/*
 * Make "pcap.h" not include "pcap-bpf.h"; we are going to include the
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

#include "pcap-int.h"

#ifdef HAVE_DAG_API
#include "pcap-dag.h"
#endif /* HAVE_DAG_API */

#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

#include "gencode.h"	/* for "no_optimize" */

static int pcap_setfilter_bpf(pcap_t *p, struct bpf_program *fp);
static int pcap_setdirection_bpf(pcap_t *, pcap_direction_t);
static int pcap_set_datalink_bpf(pcap_t *p, int dlt);

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
		return (-1);
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
	struct bpf_insn *fcode;
#ifdef PCAP_FDDIPAD
	register int pad;
#endif

	fcode = p->md.use_bpf ? NULL : p->fcode.bf_insns;
 again:
	/*
	 * Has "pcap_breakloop()" been called?
	 */
	if (p->break_loop) {
		/*
		 * Yes - clear the flag that indicates that it
		 * has, and return -2 to indicate that we were
		 * told to break out of the loop.
		 */
		p->break_loop = 0;
		return (-2);
	}
	cc = p->cc;
	if (p->cc == 0) {
		cc = read(p->fd, (char *)p->buffer, p->bufsize);
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
			return (-1);
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
		 * packets, clear the flag and return -2 to indicate
		 * that we were told to break out of the loop, otherwise
		 * leave the flag set, so that the *next* call will break
		 * out of the loop without having read any packets, and
		 * return the number of packets we've processed so far.
		 */
		if (p->break_loop) {
			if (n == 0) {
				p->break_loop = 0;
				return (-2);
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
		 * in kernel, no need to do it now.
		 *
#ifdef PCAP_FDDIPAD
		 * Note: the filter code was generated assuming
		 * that p->fddipad was the amount of padding
		 * before the header, as that's what's required
		 * in the kernel, so we run the filter before
		 * skipping that padding.
#endif
		 */
		if (fcode == NULL ||
		    bpf_filter(fcode, datap, bhp->bh_datalen, caplen)) {
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
			return (-1);
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
		return (-1);
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
		return (-1);
	}

	if ((odmlockid = odm_lock("/etc/objrepos/config_lock", ODM_WAIT)) == -1) {
		if (odm_err_msg(odmerrno, &errstr) == -1)
			errstr = "Unknown error";
		snprintf(errbuf, PCAP_ERRBUF_SIZE,
		    "bpf_load: odm_lock of /etc/objrepos/config_lock failed: %s",
		    errstr);
		return (-1);
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
		return (-1);
	}

	if (odm_terminate() == -1) {
		if (odm_err_msg(odmerrno, &errstr) == -1)
			errstr = "Unknown error";
		snprintf(errbuf, PCAP_ERRBUF_SIZE,
		    "bpf_load: odm_terminate failed: %s",
		    errstr);
		return (-1);
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

	if (bpf_odminit(errbuf) != 0)
		return (-1);

	major = genmajor(BPF_NAME);
	if (major == -1) {
		snprintf(errbuf, PCAP_ERRBUF_SIZE,
		    "bpf_load: genmajor failed: %s", pcap_strerror(errno));
		return (-1);
	}

	minors = getminor(major, &numminors, BPF_NAME);
	if (!minors) {
		minors = genminor("bpf", major, 0, BPF_MINORS, 1, 1);
		if (!minors) {
			snprintf(errbuf, PCAP_ERRBUF_SIZE,
			    "bpf_load: genminor failed: %s",
			    pcap_strerror(errno));
			return (-1);
		}
	}

	if (bpf_odmcleanup(errbuf))
		return (-1);

	rc = stat(BPF_NODE "0", &sbuf);
	if (rc == -1 && errno != ENOENT) {
		snprintf(errbuf, PCAP_ERRBUF_SIZE,
		    "bpf_load: can't stat %s: %s",
		    BPF_NODE "0", pcap_strerror(errno));
		return (-1);
	}

	if (rc == -1 || getmajor(sbuf.st_rdev) != major) {
		for (i = 0; i < BPF_MINORS; i++) {
			sprintf(buf, "%s%d", BPF_NODE, i);
			unlink(buf);
			if (mknod(buf, S_IRUSR | S_IFCHR, domakedev(major, i)) == -1) {
				snprintf(errbuf, PCAP_ERRBUF_SIZE,
				    "bpf_load: can't mknod %s: %s",
				    buf, pcap_strerror(errno));
				return (-1);
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
			return (-1);
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
			return (-1);
		}
	}
	
	bpfloadedflag = 1;

	return (0);
}
#endif

static inline int
bpf_open(pcap_t *p, char *errbuf)
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
	if (bpf_load(errbuf) == -1)
		return (-1);
#endif

#ifdef HAVE_CLONING_BPF
	if ((fd = open(device, O_RDWR)) == -1 &&
	    (errno != EACCES || (fd = open(device, O_RDONLY)) == -1))
		snprintf(errbuf, PCAP_ERRBUF_SIZE,
		  "(cannot open device) %s: %s", device, pcap_strerror(errno));
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
	if (fd < 0)
		snprintf(errbuf, PCAP_ERRBUF_SIZE, "(no devices found) %s: %s",
		    device, pcap_strerror(errno));
#endif

	return (fd);
}

/*
 * We include the OS's <net/bpf.h>, not our "pcap-bpf.h", so we probably
 * don't get DLT_DOCSIS defined.
 */
#ifndef DLT_DOCSIS
#define DLT_DOCSIS	143
#endif

pcap_t *
pcap_open_live(const char *device, int snaplen, int promisc, int to_ms,
    char *ebuf)
{
	int fd;
	struct ifreq ifr;
	struct bpf_version bv;
#ifdef BIOCGDLTLIST
	struct bpf_dltlist bdl;
#endif
#if defined(BIOCGHDRCMPLT) && defined(BIOCSHDRCMPLT)
	u_int spoof_eth_src = 1;
#endif
	u_int v;
	pcap_t *p;
	struct bpf_insn total_insn;
	struct bpf_program total_prog;
	struct utsname osinfo;

#ifdef HAVE_DAG_API
	if (strstr(device, "dag")) {
		return dag_open_live(device, snaplen, promisc, to_ms, ebuf);
	}
#endif /* HAVE_DAG_API */

#ifdef BIOCGDLTLIST
	memset(&bdl, 0, sizeof(bdl));
#endif

	p = (pcap_t *)malloc(sizeof(*p));
	if (p == NULL) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "malloc: %s",
		    pcap_strerror(errno));
		return (NULL);
	}
	memset(p, 0, sizeof(*p));
	fd = bpf_open(p, ebuf);
	if (fd < 0)
		goto bad;

	p->fd = fd;
	p->snapshot = snaplen;

	if (ioctl(fd, BIOCVERSION, (caddr_t)&bv) < 0) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "BIOCVERSION: %s",
		    pcap_strerror(errno));
		goto bad;
	}
	if (bv.bv_major != BPF_MAJOR_VERSION ||
	    bv.bv_minor < BPF_MINOR_VERSION) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE,
		    "kernel bpf filter out of date");
		goto bad;
	}

	/*
	 * Try finding a good size for the buffer; 32768 may be too
	 * big, so keep cutting it in half until we find a size
	 * that works, or run out of sizes to try.  If the default
	 * is larger, don't make it smaller.
	 *
	 * XXX - there should be a user-accessible hook to set the
	 * initial buffer size.
	 */
	if ((ioctl(fd, BIOCGBLEN, (caddr_t)&v) < 0) || v < 32768)
		v = 32768;
	for ( ; v != 0; v >>= 1) {
		/* Ignore the return value - this is because the call fails
		 * on BPF systems that don't have kernel malloc.  And if
		 * the call fails, it's no big deal, we just continue to
		 * use the standard buffer size.
		 */
		(void) ioctl(fd, BIOCSBLEN, (caddr_t)&v);

		(void)strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
		if (ioctl(fd, BIOCSETIF, (caddr_t)&ifr) >= 0)
			break;	/* that size worked; we're done */

		if (errno != ENOBUFS) {
			snprintf(ebuf, PCAP_ERRBUF_SIZE, "BIOCSETIF: %s: %s",
			    device, pcap_strerror(errno));
			goto bad;
		}
	}

	if (v == 0) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE,
			 "BIOCSBLEN: %s: No buffer size worked", device);
		goto bad;
	}

	/* Get the data link layer type. */
	if (ioctl(fd, BIOCGDLT, (caddr_t)&v) < 0) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "BIOCGDLT: %s",
		    pcap_strerror(errno));
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
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "unknown interface type %u",
		    v);
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
#ifdef PCAP_FDDIPAD
	if (v == DLT_FDDI)
		p->fddipad = PCAP_FDDIPAD;
	else
		p->fddipad = 0;
#endif
	p->linktype = v;

#ifdef BIOCGDLTLIST
	/*
	 * We know the default link type -- now determine all the DLTs
	 * this interface supports.  If this fails with EINVAL, it's
	 * not fatal; we just don't get to use the feature later.
	 */
	if (ioctl(fd, BIOCGDLTLIST, (caddr_t)&bdl) == 0) {
		u_int i;
		int is_ethernet;

		bdl.bfl_list = (u_int *) malloc(sizeof(u_int) * (bdl.bfl_len + 1));
		if (bdl.bfl_list == NULL) {
			(void)snprintf(ebuf, PCAP_ERRBUF_SIZE, "malloc: %s",
			    pcap_strerror(errno));
			goto bad;
		}

		if (ioctl(fd, BIOCGDLTLIST, (caddr_t)&bdl) < 0) {
			(void)snprintf(ebuf, PCAP_ERRBUF_SIZE,
			    "BIOCGDLTLIST: %s", pcap_strerror(errno));
			free(bdl.bfl_list);
			goto bad;
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
		if (p->linktype == DLT_EN10MB) {
			is_ethernet = 1;
			for (i = 0; i < bdl.bfl_len; i++) {
				if (bdl.bfl_list[i] != DLT_EN10MB) {
					is_ethernet = 0;
					break;
				}
			}
			if (is_ethernet) {
				/*
				 * We reserved one more slot at the end of
				 * the list.
				 */
				bdl.bfl_list[bdl.bfl_len] = DLT_DOCSIS;
				bdl.bfl_len++;
			}
		}
		p->dlt_count = bdl.bfl_len;
		p->dlt_list = bdl.bfl_list;
	} else {
		if (errno != EINVAL) {
			(void)snprintf(ebuf, PCAP_ERRBUF_SIZE,
			    "BIOCGDLTLIST: %s", pcap_strerror(errno));
			goto bad;
		}
	}
#endif

	/*
	 * If this is an Ethernet device, and we don't have a DLT_ list,
	 * give it a list with DLT_EN10MB and DLT_DOCSIS.  (That'd give
	 * 802.11 interfaces DLT_DOCSIS, which isn't the right thing to
	 * do, but there's not much we can do about that without finding
	 * some other way of determining whether it's an Ethernet or 802.11
	 * device.)
	 */
	if (p->linktype == DLT_EN10MB && p->dlt_count == 0) {
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
		(void)snprintf(ebuf, PCAP_ERRBUF_SIZE,
		    "BIOCSHDRCMPLT: %s", pcap_strerror(errno));
		goto bad;
	}
#endif
	/* set timeout */
	if (to_ms != 0) {
		/*
		 * XXX - is this seconds/nanoseconds in AIX?
		 * (Treating it as such doesn't fix the timeout
		 * problem described below.)
		 */
		struct timeval to;
		to.tv_sec = to_ms / 1000;
		to.tv_usec = (to_ms * 1000) % 1000000;
		if (ioctl(p->fd, BIOCSRTIMEOUT, (caddr_t)&to) < 0) {
			snprintf(ebuf, PCAP_ERRBUF_SIZE, "BIOCSRTIMEOUT: %s",
			    pcap_strerror(errno));
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
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "BIOCIMMEDIATE: %s",
		    pcap_strerror(errno));
		goto bad;
	}
#endif	/* BIOCIMMEDIATE */
#endif	/* _AIX */

	if (promisc) {
		/* set promiscuous mode, okay if it fails */
		if (ioctl(p->fd, BIOCPROMISC, NULL) < 0) {
			snprintf(ebuf, PCAP_ERRBUF_SIZE, "BIOCPROMISC: %s",
			    pcap_strerror(errno));
		}
	}

	if (ioctl(fd, BIOCGBLEN, (caddr_t)&v) < 0) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "BIOCGBLEN: %s",
		    pcap_strerror(errno));
		goto bad;
	}
	p->bufsize = v;
	p->buffer = (u_char *)malloc(p->bufsize);
	if (p->buffer == NULL) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "malloc: %s",
		    pcap_strerror(errno));
		goto bad;
	}
#ifdef _AIX
	/* For some strange reason this seems to prevent the EFAULT 
	 * problems we have experienced from AIX BPF. */
	memset(p->buffer, 0x0, p->bufsize);
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
	total_insn.k = snaplen;

	total_prog.bf_len = 1;
	total_prog.bf_insns = &total_insn;
	if (ioctl(p->fd, BIOCSETF, (caddr_t)&total_prog) < 0) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "BIOCSETF: %s",
		    pcap_strerror(errno));
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
	if (uname(&osinfo) == 0) {
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
	p->close_op = pcap_close_common;

	return (p);
 bad:
	(void)close(fd);
	if (p->dlt_list != NULL)
		free(p->dlt_list);
	free(p);
	return (NULL);
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

static int
pcap_setfilter_bpf(pcap_t *p, struct bpf_program *fp)
{
	/*
	 * It looks that BPF code generated by gen_protochain() is not
	 * compatible with some of kernel BPF code (for example BSD/OS 3.1).
	 * Take a safer side for now.
	 */
	if (no_optimize) {
		/*
		 * XXX - what if we already have a filter in the kernel?
		 */
		if (install_bpf_program(p, fp) < 0)
			return (-1);
		p->md.use_bpf = 0;	/* filtering in userland */
		return (0);
	}

	/*
	 * Free any user-mode filter we might happen to have installed.
	 */
	pcap_freecode(&p->fcode);

	/*
	 * Try to install the kernel filter.
	 */
	if (ioctl(p->fd, BIOCSETF, (caddr_t)fp) < 0) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "BIOCSETF: %s",
		    pcap_strerror(errno));
		return (-1);
	}
	p->md.use_bpf = 1;	/* filtering in the kernel */

	/*
	 * Discard any previously-received packets, as they might have
	 * passed whatever filter was formerly in effect, but might
	 * not pass this filter (BIOCSETF discards packets buffered
	 * in the kernel, so you can lose packets in any case).
	 */
	p->cc = 0;
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
