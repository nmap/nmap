/*
 * Copyright (c) 2006 Paolo Abeni (Italy)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 * products derived from this software without specific prior written
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * USB sniffing API implementation for Linux platform
 * By Paolo Abeni <paolo.abeni@email.it>
 * Modifications: Kris Katterjohn <katterjohn@gmail.com>
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "pcap-int.h"
#include "pcap-usb-linux.h"
#include "pcap-usb-linux-common.h"
#include "pcap/usb.h"

#include "extract.h"

#ifdef NEED_STRERROR_H
#include "strerror.h"
#endif

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <dirent.h>
#include <byteswap.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#ifdef HAVE_LINUX_USBDEVICE_FS_H
/*
 * We might need <linux/compiler.h> to define __user for
 * <linux/usbdevice_fs.h>.
 */
#ifdef HAVE_LINUX_COMPILER_H
#include <linux/compiler.h>
#endif /* HAVE_LINUX_COMPILER_H */
#include <linux/usbdevice_fs.h>
#endif /* HAVE_LINUX_USBDEVICE_FS_H */

#include "diag-control.h"

#define USB_IFACE "usbmon"

#define USBMON_DEV_PREFIX "usbmon"
#define USBMON_DEV_PREFIX_LEN	(sizeof USBMON_DEV_PREFIX - 1)
#define USB_LINE_LEN 4096

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define htols(s) s
#define htoll(l) l
#define htol64(ll) ll
#else
#define htols(s) bswap_16(s)
#define htoll(l) bswap_32(l)
#define htol64(ll) bswap_64(ll)
#endif

struct mon_bin_stats {
	uint32_t queued;
	uint32_t dropped;
};

struct mon_bin_get {
	pcap_usb_header *hdr;
	void *data;
	size_t data_len;   /* Length of data (can be zero) */
};

struct mon_bin_mfetch {
	int32_t *offvec;   /* Vector of events fetched */
	int32_t nfetch;    /* Number of events to fetch (out: fetched) */
	int32_t nflush;    /* Number of events to flush */
};

#define MON_IOC_MAGIC 0x92

#define MON_IOCQ_URB_LEN _IO(MON_IOC_MAGIC, 1)
#define MON_IOCX_URB  _IOWR(MON_IOC_MAGIC, 2, struct mon_bin_hdr)
#define MON_IOCG_STATS _IOR(MON_IOC_MAGIC, 3, struct mon_bin_stats)
#define MON_IOCT_RING_SIZE _IO(MON_IOC_MAGIC, 4)
#define MON_IOCQ_RING_SIZE _IO(MON_IOC_MAGIC, 5)
#define MON_IOCX_GET   _IOW(MON_IOC_MAGIC, 6, struct mon_bin_get)
#define MON_IOCX_MFETCH _IOWR(MON_IOC_MAGIC, 7, struct mon_bin_mfetch)
#define MON_IOCH_MFLUSH _IO(MON_IOC_MAGIC, 8)

#define MON_BIN_SETUP	0x1 /* setup hdr is present*/
#define MON_BIN_SETUP_ZERO	0x2 /* setup buffer is not available */
#define MON_BIN_DATA_ZERO	0x4 /* data buffer is not available */
#define MON_BIN_ERROR	0x8

/*
 * Private data for capturing on Linux USB.
 */
struct pcap_usb_linux {
	u_char *mmapbuf;	/* memory-mapped region pointer */
	size_t mmapbuflen;	/* size of region */
	int bus_index;
	u_int packets_read;
};

/* forward declaration */
static int usb_activate(pcap_t *);
static int usb_stats_linux_bin(pcap_t *, struct pcap_stat *);
static int usb_read_linux_bin(pcap_t *, int , pcap_handler , u_char *);
static int usb_read_linux_mmap(pcap_t *, int , pcap_handler , u_char *);
static int usb_inject_linux(pcap_t *, const void *, int);
static int usb_setdirection_linux(pcap_t *, pcap_direction_t);
static void usb_cleanup_linux_mmap(pcap_t *);

/* facility to add an USB device to the device list*/
static int
usb_dev_add(pcap_if_list_t *devlistp, int n, char *err_str)
{
	char dev_name[10];
	char dev_descr[30];
	snprintf(dev_name, 10, USB_IFACE"%d", n);
	/*
	 * XXX - is there any notion of "up" and "running"?
	 */
	if (n == 0) {
		/*
		 * As this refers to all buses, there's no notion of
		 * "connected" vs. "disconnected", as that's a property
		 * that would apply to a particular USB interface.
		 */
		if (add_dev(devlistp, dev_name,
		    PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE,
		    "Raw USB traffic, all USB buses", err_str) == NULL)
			return -1;
	} else {
		/*
		 * XXX - is there a way to determine whether anything's
		 * plugged into this bus interface or not, and set
		 * PCAP_IF_CONNECTION_STATUS_CONNECTED or
		 * PCAP_IF_CONNECTION_STATUS_DISCONNECTED?
		 */
		snprintf(dev_descr, 30, "Raw USB traffic, bus number %d", n);
		if (add_dev(devlistp, dev_name, 0, dev_descr, err_str) == NULL)
			return -1;
	}

	return 0;
}

int
usb_findalldevs(pcap_if_list_t *devlistp, char *err_str)
{
	struct dirent* data;
	int ret = 0;
	DIR* dir;
	int n;
	char* name;

	/*
	 * We require 2.6.27 or later kernels, so we have binary-mode support.
	 * The devices are of the form /dev/usbmon{N}.
	 * Open /dev and scan it.
	 */
	dir = opendir("/dev");
	if (dir != NULL) {
		while ((ret == 0) && ((data = readdir(dir)) != 0)) {
			name = data->d_name;

			/*
			 * Is this a usbmon device?
			 */
			if (strncmp(name, USBMON_DEV_PREFIX,
			    USBMON_DEV_PREFIX_LEN) != 0)
				continue;	/* no */

			/*
			 * What's the device number?
			 */
			if (sscanf(&name[USBMON_DEV_PREFIX_LEN], "%d", &n) == 0)
				continue;	/* failed */

			ret = usb_dev_add(devlistp, n, err_str);
		}

		closedir(dir);
	}
	return 0;
}

/*
 * Matches what's in mon_bin.c in the Linux kernel.
 */
#define MIN_RING_SIZE	(8*1024)
#define MAX_RING_SIZE	(1200*1024)

static int
usb_set_ring_size(pcap_t* handle, int header_size)
{
	/*
	 * A packet from binary usbmon has:
	 *
	 *  1) a fixed-length header, of size header_size;
	 *  2) descriptors, for isochronous transfers;
	 *  3) the payload.
	 *
	 * The kernel buffer has a size, defaulting to 300KB, with a
	 * minimum of 8KB and a maximum of 1200KB.  The size is set with
	 * the MON_IOCT_RING_SIZE ioctl; the size passed in is rounded up
	 * to a page size.
	 *
	 * No more than {buffer size}/5 bytes worth of payload is saved.
	 * Therefore, if we subtract the fixed-length size from the
	 * snapshot length, we have the biggest payload we want (we
	 * don't worry about the descriptors - if we have descriptors,
	 * we'll just discard the last bit of the payload to get it
	 * to fit).  We multiply that result by 5 and set the buffer
	 * size to that value.
	 */
	int ring_size;

	if (handle->snapshot < header_size)
		handle->snapshot = header_size;
	/* The maximum snapshot size is small enough that this won't overflow */
	ring_size = (handle->snapshot - header_size) * 5;

	/*
	 * Will this get an error?
	 * (There's no wqy to query the minimum or maximum, so we just
	 * copy the value from the kernel source.  We don't round it
	 * up to a multiple of the page size.)
	 */
	if (ring_size > MAX_RING_SIZE) {
		/*
		 * Yes.  Lower the ring size to the maximum, and set the
		 * snapshot length to the value that would give us a
		 * maximum-size ring.
		 */
		ring_size = MAX_RING_SIZE;
		handle->snapshot = header_size + (MAX_RING_SIZE/5);
	} else if (ring_size < MIN_RING_SIZE) {
		/*
		 * Yes.  Raise the ring size to the minimum, but leave
		 * the snapshot length unchanged, so we show the
		 * callback no more data than specified by the
		 * snapshot length.
		 */
		ring_size = MIN_RING_SIZE;
	}

	if (ioctl(handle->fd, MON_IOCT_RING_SIZE, ring_size) == -1) {
		pcap_fmt_errmsg_for_errno(handle->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "Can't set ring size from fd %d", handle->fd);
		return -1;
	}
	return ring_size;
}

static
int usb_mmap(pcap_t* handle)
{
	struct pcap_usb_linux *handlep = handle->priv;
	int len;

	/*
	 * Attempt to set the ring size as appropriate for the snapshot
	 * length, reducing the snapshot length if that'd make the ring
	 * bigger than the kernel supports.
	 */
	len = usb_set_ring_size(handle, (int)sizeof(pcap_usb_header_mmapped));
	if (len == -1) {
		/* Failed.  Fall back on non-memory-mapped access. */
		return 0;
	}

	handlep->mmapbuflen = len;
	handlep->mmapbuf = mmap(0, handlep->mmapbuflen, PROT_READ,
	    MAP_SHARED, handle->fd, 0);
	if (handlep->mmapbuf == MAP_FAILED) {
		/*
		 * Failed.  We don't treat that as a fatal error, we
		 * just try to fall back on non-memory-mapped access.
		 */
		return 0;
	}
	return 1;
}

#ifdef HAVE_LINUX_USBDEVICE_FS_H

#define CTRL_TIMEOUT    (5*1000)        /* milliseconds */

#define USB_DIR_IN		0x80
#define USB_TYPE_STANDARD	0x00
#define USB_RECIP_DEVICE	0x00

#define USB_REQ_GET_DESCRIPTOR	6

#define USB_DT_DEVICE		1
#define USB_DT_CONFIG		2

#define USB_DEVICE_DESCRIPTOR_SIZE	18
#define USB_CONFIG_DESCRIPTOR_SIZE	9

/* probe the descriptors of the devices attached to the bus */
/* the descriptors will end up in the captured packet stream */
/* and be decoded by external apps like wireshark */
/* without these identifying probes packet data can't be fully decoded */
static void
probe_devices(int bus)
{
	struct usbdevfs_ctrltransfer ctrl;
	struct dirent* data;
	int ret = 0;
	char busdevpath[sizeof("/dev/bus/usb/000/") + NAME_MAX];
	DIR* dir;
	uint8_t descriptor[USB_DEVICE_DESCRIPTOR_SIZE];
	uint8_t configdesc[USB_CONFIG_DESCRIPTOR_SIZE];

	/* scan usb bus directories for device nodes */
	snprintf(busdevpath, sizeof(busdevpath), "/dev/bus/usb/%03d", bus);
	dir = opendir(busdevpath);
	if (!dir)
		return;

	while ((ret >= 0) && ((data = readdir(dir)) != 0)) {
		int fd;
		char* name = data->d_name;

		if (name[0] == '.')
			continue;

		snprintf(busdevpath, sizeof(busdevpath), "/dev/bus/usb/%03d/%s", bus, data->d_name);

		fd = open(busdevpath, O_RDWR);
		if (fd == -1)
			continue;

		/*
		 * Sigh.  Different kernels have different member names
		 * for this structure.
		 */
#ifdef HAVE_STRUCT_USBDEVFS_CTRLTRANSFER_BREQUESTTYPE
		ctrl.bRequestType = USB_DIR_IN | USB_TYPE_STANDARD | USB_RECIP_DEVICE;
		ctrl.bRequest = USB_REQ_GET_DESCRIPTOR;
		ctrl.wValue = USB_DT_DEVICE << 8;
		ctrl.wIndex = 0;
		ctrl.wLength = sizeof(descriptor);
#else
		ctrl.requesttype = USB_DIR_IN | USB_TYPE_STANDARD | USB_RECIP_DEVICE;
		ctrl.request = USB_REQ_GET_DESCRIPTOR;
		ctrl.value = USB_DT_DEVICE << 8;
		ctrl.index = 0;
		ctrl.length = sizeof(descriptor);
#endif
		ctrl.data = descriptor;
		ctrl.timeout = CTRL_TIMEOUT;

		ret = ioctl(fd, USBDEVFS_CONTROL, &ctrl);

		/* Request CONFIGURATION descriptor alone to know wTotalLength */
#ifdef HAVE_STRUCT_USBDEVFS_CTRLTRANSFER_BREQUESTTYPE
		ctrl.wValue = USB_DT_CONFIG << 8;
		ctrl.wLength = sizeof(configdesc);
#else
		ctrl.value = USB_DT_CONFIG << 8;
		ctrl.length = sizeof(configdesc);
#endif
		ctrl.data = configdesc;
		ret = ioctl(fd, USBDEVFS_CONTROL, &ctrl);
		if (ret >= 0) {
			uint16_t wtotallength;
			wtotallength = EXTRACT_LE_U_2(&configdesc[2]);
#ifdef HAVE_STRUCT_USBDEVFS_CTRLTRANSFER_BREQUESTTYPE
			ctrl.wLength = wtotallength;
#else
			ctrl.length = wtotallength;
#endif
			ctrl.data = malloc(wtotallength);
			if (ctrl.data) {
				ret = ioctl(fd, USBDEVFS_CONTROL, &ctrl);
				free(ctrl.data);
			}
		}
		close(fd);
	}
	closedir(dir);
}
#endif /* HAVE_LINUX_USBDEVICE_FS_H */

pcap_t *
usb_create(const char *device, char *ebuf, int *is_ours)
{
	const char *cp;
	char *cpend;
	long devnum;
	pcap_t *p;

	/* Does this look like a USB monitoring device? */
	cp = strrchr(device, '/');
	if (cp == NULL)
		cp = device;
	/* Does it begin with USB_IFACE? */
	if (strncmp(cp, USB_IFACE, sizeof USB_IFACE - 1) != 0) {
		/* Nope, doesn't begin with USB_IFACE */
		*is_ours = 0;
		return NULL;
	}
	/* Yes - is USB_IFACE followed by a number? */
	cp += sizeof USB_IFACE - 1;
	devnum = strtol(cp, &cpend, 10);
	if (cpend == cp || *cpend != '\0') {
		/* Not followed by a number. */
		*is_ours = 0;
		return NULL;
	}
	if (devnum < 0) {
		/* Followed by a non-valid number. */
		*is_ours = 0;
		return NULL;
	}

	/* OK, it's probably ours. */
	*is_ours = 1;

	p = PCAP_CREATE_COMMON(ebuf, struct pcap_usb_linux);
	if (p == NULL)
		return (NULL);

	p->activate_op = usb_activate;
	return (p);
}

static int
usb_activate(pcap_t* handle)
{
	struct pcap_usb_linux *handlep = handle->priv;
	char		full_path[USB_LINE_LEN];

	/*
	 * Turn a negative snapshot value (invalid), a snapshot value of
	 * 0 (unspecified), or a value bigger than the normal maximum
	 * value, into the maximum allowed value.
	 *
	 * If some application really *needs* a bigger snapshot
	 * length, we should just increase MAXIMUM_SNAPLEN.
	 */
	if (handle->snapshot <= 0 || handle->snapshot > MAXIMUM_SNAPLEN)
		handle->snapshot = MAXIMUM_SNAPLEN;

	/* Initialize some components of the pcap structure. */
	handle->bufsize = handle->snapshot;
	handle->offset = 0;
	handle->linktype = DLT_USB_LINUX;

	handle->inject_op = usb_inject_linux;
	handle->setfilter_op = install_bpf_program; /* no kernel filtering */
	handle->setdirection_op = usb_setdirection_linux;
	handle->set_datalink_op = NULL;	/* can't change data link type */
	handle->getnonblock_op = pcap_getnonblock_fd;
	handle->setnonblock_op = pcap_setnonblock_fd;

	/*get usb bus index from device name */
	if (sscanf(handle->opt.device, USB_IFACE"%d", &handlep->bus_index) != 1)
	{
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			"Can't get USB bus index from %s", handle->opt.device);
		return PCAP_ERROR;
	}

	/*
	 * We require 2.6.27 or later kernels, so we have binary-mode support.
	 * Try to open the binary interface.
	 */
	snprintf(full_path, USB_LINE_LEN, "/dev/"USBMON_DEV_PREFIX"%d",
	    handlep->bus_index);
	handle->fd = open(full_path, O_RDONLY, 0);
	if (handle->fd < 0)
	{
		/*
		 * The attempt failed; why?
		 */
		switch (errno) {

		case ENOENT:
			/*
			 * The device doesn't exist.
			 * That could either mean that there's
			 * no support for monitoring USB buses
			 * (which probably means "the usbmon
			 * module isn't loaded") or that there
			 * is but that *particular* device
			 * doesn't exist (no "scan all buses"
			 * device if the bus index is 0, no
			 * such bus if the bus index isn't 0).
			 *
			 * For now, don't provide an error message;
			 * if we can determine what the particular
			 * problem is, we should report that.
			 */
			handle->errbuf[0] = '\0';
			return PCAP_ERROR_NO_SUCH_DEVICE;

		case EACCES:
			/*
			 * We didn't have permission to open it.
			 */
DIAG_OFF_FORMAT_TRUNCATION
			snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			    "Attempt to open %s failed with EACCES - root privileges may be required",
			    full_path);
DIAG_ON_FORMAT_TRUNCATION
			return PCAP_ERROR_PERM_DENIED;

		default:
			/*
			 * Something went wrong.
			 */
			pcap_fmt_errmsg_for_errno(handle->errbuf,
			    PCAP_ERRBUF_SIZE, errno,
			    "Can't open USB bus file %s", full_path);
			return PCAP_ERROR;
		}
	}

	if (handle->opt.rfmon)
	{
		/*
		 * Monitor mode doesn't apply to USB devices.
		 */
		close(handle->fd);
		return PCAP_ERROR_RFMON_NOTSUP;
	}

	/* try to use fast mmap access */
	if (usb_mmap(handle))
	{
		/* We succeeded. */
		handle->linktype = DLT_USB_LINUX_MMAPPED;
		handle->stats_op = usb_stats_linux_bin;
		handle->read_op = usb_read_linux_mmap;
		handle->cleanup_op = usb_cleanup_linux_mmap;
#ifdef HAVE_LINUX_USBDEVICE_FS_H
		probe_devices(handlep->bus_index);
#endif

		/*
		 * "handle->fd" is a real file, so
		 * "select()" and "poll()" work on it.
		 */
		handle->selectable_fd = handle->fd;
		return 0;
	}

	/*
	 * We failed; try plain binary interface access.
	 *
	 * Attempt to set the ring size as appropriate for
	 * the snapshot length, reducing the snapshot length
	 * if that'd make the ring bigger than the kernel
	 * supports.
	 */
	if (usb_set_ring_size(handle, (int)sizeof(pcap_usb_header)) == -1) {
		/* Failed. */
		close(handle->fd);
		return PCAP_ERROR;
	}
	handle->stats_op = usb_stats_linux_bin;
	handle->read_op = usb_read_linux_bin;
#ifdef HAVE_LINUX_USBDEVICE_FS_H
	probe_devices(handlep->bus_index);
#endif

	/*
	 * "handle->fd" is a real file, so "select()" and "poll()"
	 * work on it.
	 */
	handle->selectable_fd = handle->fd;

	/* for plain binary access and text access we need to allocate the read
	 * buffer */
	handle->buffer = malloc(handle->bufsize);
	if (!handle->buffer) {
		pcap_fmt_errmsg_for_errno(handle->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "malloc");
		close(handle->fd);
		return PCAP_ERROR;
	}
	return 0;
}

static int
usb_inject_linux(pcap_t *handle, const void *buf _U_, int size _U_)
{
	snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
	    "Packet injection is not supported on USB devices");
	return (-1);
}

static int
usb_setdirection_linux(pcap_t *p, pcap_direction_t d)
{
	/*
	 * It's guaranteed, at this point, that d is a valid
	 * direction value.
	 */
	p->direction = d;
	return 0;
}

static int
usb_stats_linux_bin(pcap_t *handle, struct pcap_stat *stats)
{
	struct pcap_usb_linux *handlep = handle->priv;
	int ret;
	struct mon_bin_stats st;
	ret = ioctl(handle->fd, MON_IOCG_STATS, &st);
	if (ret < 0)
	{
		pcap_fmt_errmsg_for_errno(handle->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "Can't read stats from fd %d", handle->fd);
		return -1;
	}

	stats->ps_recv = handlep->packets_read + st.queued;
	stats->ps_drop = st.dropped;
	stats->ps_ifdrop = 0;
	return 0;
}

/*
 * see <linux-kernel-source>/Documentation/usb/usbmon.txt and
 * <linux-kernel-source>/drivers/usb/mon/mon_bin.c binary ABI
 */
static int
usb_read_linux_bin(pcap_t *handle, int max_packets _U_, pcap_handler callback, u_char *user)
{
	struct pcap_usb_linux *handlep = handle->priv;
	struct mon_bin_get info;
	int ret;
	struct pcap_pkthdr pkth;
	u_int clen = handle->snapshot - sizeof(pcap_usb_header);

	/* the usb header is going to be part of 'packet' data*/
	info.hdr = (pcap_usb_header*) handle->buffer;
	info.data = (u_char *)handle->buffer + sizeof(pcap_usb_header);
	info.data_len = clen;

	/* ignore interrupt system call errors */
	do {
		ret = ioctl(handle->fd, MON_IOCX_GET, &info);
		if (handle->break_loop)
		{
			handle->break_loop = 0;
			return -2;
		}
	} while ((ret == -1) && (errno == EINTR));
	if (ret < 0)
	{
		if (errno == EAGAIN)
			return 0;	/* no data there */

		pcap_fmt_errmsg_for_errno(handle->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "Can't read from fd %d", handle->fd);
		return -1;
	}

	/*
	 * info.hdr->data_len is the number of bytes of isochronous
	 * descriptors (if any) plus the number of bytes of data
	 * provided.  There are no isochronous descriptors here,
	 * because we're using the old 48-byte header.
	 *
	 * If info.hdr->data_flag is non-zero, there's no URB data;
	 * info.hdr->urb_len is the size of the buffer into which
	 * data is to be placed; it does not represent the amount
	 * of data transferred.  If info.hdr->data_flag is zero,
	 * there is URB data, and info.hdr->urb_len is the number
	 * of bytes transmitted or received; it doesn't include
	 * isochronous descriptors.
	 *
	 * The kernel may give us more data than the snaplen; if it did,
	 * reduce the data length so that the total number of bytes we
	 * tell our client we have is not greater than the snaplen.
	 */
	if (info.hdr->data_len < clen)
		clen = info.hdr->data_len;
	info.hdr->data_len = clen;
	pkth.caplen = sizeof(pcap_usb_header) + clen;
	if (info.hdr->data_flag) {
		/*
		 * No data; just base the on-the-wire length on
		 * info.hdr->data_len (so that it's >= the captured
		 * length).
		 */
		pkth.len = sizeof(pcap_usb_header) + info.hdr->data_len;
	} else {
		/*
		 * We got data; base the on-the-wire length on
		 * info.hdr->urb_len, so that it includes data
		 * discarded by the USB monitor device due to
		 * its buffer being too small.
		 */
		pkth.len = sizeof(pcap_usb_header) + info.hdr->urb_len;
	}
	pkth.ts.tv_sec = (time_t)info.hdr->ts_sec;
	pkth.ts.tv_usec = info.hdr->ts_usec;

	if (handle->fcode.bf_insns == NULL ||
	    pcap_filter(handle->fcode.bf_insns, handle->buffer,
	      pkth.len, pkth.caplen)) {
		handlep->packets_read++;
		callback(user, &pkth, handle->buffer);
		return 1;
	}

	return 0;	/* didn't pass filter */
}

/*
 * see <linux-kernel-source>/Documentation/usb/usbmon.txt and
 * <linux-kernel-source>/drivers/usb/mon/mon_bin.c binary ABI
 */
#define VEC_SIZE 32
static int
usb_read_linux_mmap(pcap_t *handle, int max_packets, pcap_handler callback, u_char *user)
{
	struct pcap_usb_linux *handlep = handle->priv;
	struct mon_bin_mfetch fetch;
	int32_t vec[VEC_SIZE];
	struct pcap_pkthdr pkth;
	u_char *bp;
	pcap_usb_header_mmapped* hdr;
	int nflush = 0;
	int packets = 0;
	u_int clen, max_clen;

	max_clen = handle->snapshot - sizeof(pcap_usb_header_mmapped);

	for (;;) {
		int i, ret;
		int limit;

		if (PACKET_COUNT_IS_UNLIMITED(max_packets)) {
			/*
			 * There's no limit on the number of packets
			 * to process, so try to fetch VEC_SIZE packets.
			 */
			limit = VEC_SIZE;
		} else {
			/*
			 * Try to fetch as many packets as we have left
			 * to process, or VEC_SIZE packets, whichever
			 * is less.
			 *
			 * At this point, max_packets > 0 (otherwise,
			 * PACKET_COUNT_IS_UNLIMITED(max_packets)
			 * would be true) and max_packets > packets
			 * (packet starts out as 0, and the test
			 * at the bottom of the loop exits if
			 * max_packets <= packets), so limit is
			 * guaranteed to be > 0.
			 */
			limit = max_packets - packets;
			if (limit > VEC_SIZE)
				limit = VEC_SIZE;
		}

		/*
		 * Try to fetch as many events as possible, up to
		 * the limit, and flush the events we've processed
		 * earlier (nflush) - MON_IOCX_MFETCH does both
		 * (presumably to reduce the number of system
		 * calls in loops like this).
		 */
		fetch.offvec = vec;
		fetch.nfetch = limit;
		fetch.nflush = nflush;
		/* ignore interrupt system call errors */
		do {
			ret = ioctl(handle->fd, MON_IOCX_MFETCH, &fetch);
			if (handle->break_loop)
			{
				handle->break_loop = 0;
				return -2;
			}
		} while ((ret == -1) && (errno == EINTR));
		if (ret < 0)
		{
			if (errno == EAGAIN)
				return 0;	/* no data there */

			pcap_fmt_errmsg_for_errno(handle->errbuf,
			    PCAP_ERRBUF_SIZE, errno, "Can't mfetch fd %d",
			    handle->fd);
			return -1;
		}

		/* keep track of processed events, we will flush them later */
		nflush = fetch.nfetch;
		for (i=0; i<fetch.nfetch; ++i) {
			/*
			 * XXX - we can't check break_loop here, as
			 * we read the indices of packets into a
			 * local variable, so if we're later called
			 * to fetch more packets, those packets will
			 * not be seen - and won't be flushed, either.
			 *
			 * Instead, we would have to keep the array
			 * of indices in our private data, along
			 * with the count of packets to flush - or
			 * would have to flush the already-processed
			 * packets if we break out of the loop here.
			 */

			/* Get a pointer to this packet's buffer */
			bp = &handlep->mmapbuf[vec[i]];

			/* That begins with a metadata header */
			hdr = (pcap_usb_header_mmapped*) bp;

			/* discard filler */
			if (hdr->event_type == '@')
				continue;

			/*
			 * hdr->data_len is the number of bytes of
			 * isochronous descriptors (if any) plus the
			 * number of bytes of data provided.
			 *
			 * If hdr->data_flag is non-zero, there's no
			 * URB data; hdr->urb_len is the size of the
			 * buffer into which data is to be placed; it does
			 * not represent the amount of data transferred.
			 * If hdr->data_flag is zero, there is URB data,
			 * and hdr->urb_len is the number of bytes
			 * transmitted or received; it doesn't include
			 * isochronous descriptors.
			 *
			 * The kernel may give us more data than the
			 * snaplen; if it did, reduce the data length
			 * so that the total number of bytes we
			 * tell our client we have is not greater than
			 * the snaplen.
			 */
			clen = max_clen;
			if (hdr->data_len < clen)
				clen = hdr->data_len;
			pkth.caplen = sizeof(pcap_usb_header_mmapped) + clen;
			if (hdr->data_flag) {
				/*
				 * No data; just base the on-the-wire length
				 * on hdr->data_len (so that it's >= the
				 * captured length).
				 */
				pkth.len = sizeof(pcap_usb_header_mmapped) +
				    hdr->data_len;
			} else {
				/*
				 * We got data; base the on-the-wire length
				 * on hdr->urb_len, so that it includes
				 * data discarded by the USB monitor device
				 * due to its buffer being too small.
				 */
				pkth.len = sizeof(pcap_usb_header_mmapped) +
				    (hdr->ndesc * sizeof (usb_isodesc)) + hdr->urb_len;

				/*
				 * Now clean it up if it's a completion
				 * event for an incoming isochronous
				 * transfer.
				 */
				fix_linux_usb_mmapped_length(&pkth, bp);
			}
			pkth.ts.tv_sec = (time_t)hdr->ts_sec;
			pkth.ts.tv_usec = hdr->ts_usec;

			if (handle->fcode.bf_insns == NULL ||
			    pcap_filter(handle->fcode.bf_insns, (u_char*) hdr,
			      pkth.len, pkth.caplen)) {
				handlep->packets_read++;
				callback(user, &pkth, (u_char*) hdr);
				packets++;
			}
		}

		/*
		 * If max_packets specifiesg "unlimited", we stop after
		 * the first chunk.
		 */
		if (PACKET_COUNT_IS_UNLIMITED(max_packets) ||
		    (packets >= max_packets))
			break;
	}

	/* flush pending events*/
	if (ioctl(handle->fd, MON_IOCH_MFLUSH, nflush) == -1) {
		pcap_fmt_errmsg_for_errno(handle->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "Can't mflush fd %d", handle->fd);
		return -1;
	}
	return packets;
}

static void
usb_cleanup_linux_mmap(pcap_t* handle)
{
	struct pcap_usb_linux *handlep = handle->priv;

	/* if we have a memory-mapped buffer, unmap it */
	if (handlep->mmapbuf != NULL) {
		munmap(handlep->mmapbuf, handlep->mmapbuflen);
		handlep->mmapbuf = NULL;
	}
	pcap_cleanup_live_common(handle);
}
